//! macOS platform command builder；只產生固定 binary 與獨立 argv，不經 shell。

use crate::{CommandOutput, CommandRunner, NetworkExecutor};
use nettool_domain::{DnsConfiguration, IpPrefix, Ipv4Configuration, Ipv6Configuration};
use nettool_error::{ErrorCode, NetToolError};
use nettool_helper_protocol::NetworkDesiredState;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// 固定平台 binary 與 argv；caller 必須交給 whitelist command runner 執行。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlatformCommand {
    /// 絕對 executable path。
    pub program: PathBuf,
    /// 不含 shell syntax 的 argv。
    pub arguments: Vec<String>,
}

/// 可使用 fixed-argv adapter 的平台。
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PlatformBackend {
    /// macOS `networksetup` adapter。
    Macos,
    /// Windows `netsh.exe` adapter。
    Windows,
}

/// 讀取平台目前 typed network state 的抽象；副作用仍由 command runner 負責。
pub trait PlatformStateReader {
    /// 讀取指定介面的完整 desired-state 相容設定。
    ///
    /// # Errors
    ///
    /// 平台狀態無法完整解析時回傳錯誤，不得以部分狀態取代。
    fn read_state(&mut self, interface_id: &str) -> Result<NetworkDesiredState, NetToolError>;
}

#[path = "platform_network_macos.rs"]
mod platform_network_macos;
#[path = "platform_network_windows.rs"]
mod platform_network_windows;

pub use platform_network_macos::build_macos_networksetup_commands;
pub use platform_network_windows::build_windows_netsh_commands;

/// macOS `networksetup` 唯讀 state reader。
///
/// 只接受可完整轉成 [`NetworkDesiredState`] 的輸出；例如非零 gateway 或未知格式
/// 會直接失敗，避免 Safe Apply 以不完整 snapshot 進行 rollback。
pub struct MacosNetworkStateReader<R> {
    runner: R,
}

/// Windows PowerShell JSON 唯讀 state reader。
///
/// Reader 使用固定 absolute PowerShell 與 versioned JSON schema；介面名稱以獨立 argv
/// 傳入，避免依賴會隨 OS 語系改變的 `netsh` 顯示文字。
pub struct WindowsNetshStateReader<R> {
    runner: R,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct PlatformSnapshot {
    version: u32,
    interface_id: String,
    backend: PlatformBackend,
    state: NetworkDesiredState,
}

const PLATFORM_SNAPSHOT_VERSION: u32 = 1;

/// 以平台 state reader、fixed-argv builder 與 runner 組成 Safe Apply executor。
///
/// Reader 必須由各平台實作；此型別集中 snapshot、apply、verify 與 restore，確保
/// rollback 不依賴 caller 在 request 中重新提供舊設定。
pub struct PlatformNetworkExecutor<R, S> {
    runner: R,
    reader: S,
    backend: PlatformBackend,
    snapshot_directory: PathBuf,
}

impl<R, S> PlatformNetworkExecutor<R, S>
where
    R: CommandRunner,
    S: PlatformStateReader,
{
    /// 建立平台 executor；snapshot directory 必須可由 helper 擁有。
    ///
    /// # Errors
    ///
    /// Snapshot directory 建立失敗時回傳錯誤。
    pub fn new(
        runner: R,
        reader: S,
        backend: PlatformBackend,
        snapshot_directory: impl Into<PathBuf>,
    ) -> Result<Self, NetToolError> {
        let snapshot_directory = snapshot_directory.into();
        fs::create_dir_all(&snapshot_directory).map_err(platform_persistence_error)?;
        Ok(Self {
            runner,
            reader,
            backend,
            snapshot_directory,
        })
    }

    fn commands(
        &self,
        interface_id: &str,
        state: &NetworkDesiredState,
    ) -> Result<Vec<PlatformCommand>, NetToolError> {
        match self.backend {
            PlatformBackend::Macos => build_macos_networksetup_commands(interface_id, state),
            PlatformBackend::Windows => build_windows_netsh_commands(interface_id, state),
        }
    }

    fn snapshot_path(&self, snapshot_id: &str) -> Result<PathBuf, NetToolError> {
        if snapshot_id.len() != 64 || !snapshot_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(NetToolError::new(
                ErrorCode::InvalidArgument,
                "platform snapshot ID is invalid",
                false,
            ));
        }
        Ok(self.snapshot_directory.join(format!("{snapshot_id}.json")))
    }

    fn write_snapshot(&self, snapshot: &PlatformSnapshot) -> Result<String, NetToolError> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let bytes = serde_json::to_vec_pretty(snapshot).map_err(platform_snapshot_error)?;
        let mut digest = Sha256::new();
        digest.update(timestamp.to_be_bytes());
        digest.update(&bytes);
        let snapshot_id = format!("{:x}", digest.finalize());
        let path = self.snapshot_path(&snapshot_id)?;
        let temporary = path.with_extension("tmp");
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .map_err(platform_persistence_error)?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(platform_persistence_error)?;
        fs::rename(&temporary, &path).map_err(platform_persistence_error)?;
        sync_parent(&path)?;
        Ok(snapshot_id)
    }
}

#[cfg(unix)]
fn sync_parent(path: &Path) -> Result<(), NetToolError> {
    if let Some(parent) = path.parent() {
        let directory = OpenOptions::new()
            .read(true)
            .open(parent)
            .map_err(platform_persistence_error)?;
        directory.sync_all().map_err(platform_persistence_error)?;
    }
    Ok(())
}

// Windows 沒有與 Unix 目錄 fsync 等價的可攜式操作；檔案在 rename 前已完成 flush。
#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
fn sync_parent(_path: &Path) -> Result<(), NetToolError> {
    Ok(())
}

impl<R, S> NetworkExecutor for PlatformNetworkExecutor<R, S>
where
    R: CommandRunner,
    S: PlatformStateReader,
{
    fn read_state(&mut self, interface_id: &str) -> Result<Value, NetToolError> {
        serde_json::to_value(self.reader.read_state(interface_id)?).map_err(platform_snapshot_error)
    }

    fn snapshot(&mut self, interface_id: &str) -> Result<(String, Value), NetToolError> {
        let state = self.reader.read_state(interface_id)?;
        state
            .validate()
            .map_err(|message| NetToolError::new(ErrorCode::InvalidArgument, message, false))?;
        let snapshot = PlatformSnapshot {
            version: PLATFORM_SNAPSHOT_VERSION,
            interface_id: interface_id.to_owned(),
            backend: self.backend,
            state,
        };
        let snapshot_id = self.write_snapshot(&snapshot)?;
        let state = serde_json::to_value(&snapshot.state).map_err(platform_snapshot_error)?;
        Ok((snapshot_id, state))
    }

    fn apply(
        &mut self,
        interface_id: &str,
        desired_state: &NetworkDesiredState,
    ) -> Result<(), NetToolError> {
        desired_state
            .validate()
            .map_err(|message| NetToolError::new(ErrorCode::InvalidArgument, message, false))?;
        let commands = self.commands(interface_id, desired_state)?;
        execute_platform_commands(&mut self.runner, &commands)
    }

    fn verify(
        &mut self,
        interface_id: &str,
        desired_state: &NetworkDesiredState,
    ) -> Result<(), NetToolError> {
        let actual = self.reader.read_state(interface_id)?;
        if actual != *desired_state {
            return Err(NetToolError::new(
                ErrorCode::HelperExecutionFailed,
                "platform network state does not match requested state",
                false,
            ));
        }
        Ok(())
    }

    fn restore(&mut self, snapshot_id: &str) -> Result<(), NetToolError> {
        let path = self.snapshot_path(snapshot_id)?;
        let bytes = fs::read(path).map_err(platform_persistence_error)?;
        let snapshot: PlatformSnapshot =
            serde_json::from_slice(&bytes).map_err(platform_snapshot_error)?;
        if snapshot.version != PLATFORM_SNAPSHOT_VERSION || snapshot.backend != self.backend {
            return Err(NetToolError::new(
                ErrorCode::ProtocolIncompatible,
                "platform snapshot version or backend is unsupported",
                false,
            ));
        }
        let commands = self.commands(&snapshot.interface_id, &snapshot.state)?;
        execute_platform_commands(&mut self.runner, &commands)
    }
}

/// 驗證平台 command 仍符合固定 executable/argv 邊界。
///
/// # Errors
///
/// Executable 不是已知平台 binary、argv 含 NUL 或 shell control character 時回傳錯誤。
pub fn validate_platform_command(command: &PlatformCommand) -> Result<(), NetToolError> {
    let program = command.program.to_string_lossy();
    if program != "/usr/sbin/networksetup"
        && program != r"C:\Windows\System32\netsh.exe"
        && program != r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    {
        return Err(invalid("platform command executable is not allowlisted"));
    }
    if program == r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" {
        return platform_network_windows::validate_state_query_command(command);
    }
    if command.arguments.is_empty() || command.arguments.len() > 32 {
        return Err(invalid("platform command argument count is invalid"));
    }
    if command.arguments.iter().any(|argument| {
        argument.is_empty()
            || argument.contains('\0')
            || (program != r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
                && (argument
                    .chars()
                    .any(|character| matches!(character, '\n' | '\r'))
                    || argument
                        .chars()
                        .any(|character| matches!(character, ';' | '|' | '&' | '`' | '$'))))
    }) {
        return Err(invalid(
            "platform command argument contains forbidden syntax",
        ));
    }
    Ok(())
}

/// 以 validated fixed argv 執行平台命令；不允許 caller 直接繞過 command boundary。
///
/// # Errors
///
/// Command 不符合 allowlist 或底層 runner 無法啟動程序時回傳錯誤。
pub fn run_validated_platform_command<R: CommandRunner>(
    runner: &mut R,
    command: &PlatformCommand,
) -> Result<CommandOutput, NetToolError> {
    validate_platform_command(command)?;
    runner.run(&command.program, &command.arguments)
}

/// 依序執行固定命令序列；任何一個命令失敗都立即停止後續副作用。
///
/// # Errors
///
/// 命令序列驗證失敗、程序無法啟動或程序回傳非零狀態時回傳錯誤。
pub fn execute_platform_commands<R: CommandRunner>(
    runner: &mut R,
    commands: &[PlatformCommand],
) -> Result<(), NetToolError> {
    validate_commands(commands)?;
    for command in commands {
        let output = run_validated_platform_command(runner, command)?;
        if !output.success {
            return Err(NetToolError::new(
                ErrorCode::HelperExecutionFailed,
                "platform network command failed",
                true,
            ));
        }
    }
    Ok(())
}

fn validate_commands(commands: &[PlatformCommand]) -> Result<(), NetToolError> {
    if commands.is_empty() {
        return Err(invalid("platform command sequence is empty"));
    }
    for command in commands {
        validate_platform_command(command)?;
    }
    Ok(())
}

fn command<const N: usize>(program: &std::path::Path, arguments: [&str; N]) -> PlatformCommand {
    PlatformCommand {
        program: program.to_path_buf(),
        arguments: arguments.into_iter().map(ToOwned::to_owned).collect(),
    }
}

fn validate_interface(interface_id: &str) -> Result<(), NetToolError> {
    if interface_id.is_empty()
        || interface_id.len() > 256
        || interface_id
            .chars()
            .any(|character| character == '\0' || character == '\n' || character == '\r')
    {
        return Err(invalid("interface ID contains unsupported characters"));
    }
    Ok(())
}

fn ipv4_netmask(prefix: u8) -> Result<String, NetToolError> {
    if prefix > 32 {
        return Err(invalid("IPv4 prefix is out of range"));
    }
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    Ok(format!(
        "{}.{}.{}.{}",
        (mask >> 24) & 255,
        (mask >> 16) & 255,
        (mask >> 8) & 255,
        mask & 255
    ))
}

fn invalid(message: impl Into<String>) -> NetToolError {
    NetToolError::new(ErrorCode::InvalidArgument, message, false)
}

#[allow(clippy::needless_pass_by_value)]
fn platform_persistence_error(error: std::io::Error) -> NetToolError {
    NetToolError::new(
        ErrorCode::PersistenceFailed,
        format!("platform snapshot persistence failed: {error}"),
        true,
    )
}

fn platform_reader_error(message: impl Into<String>) -> NetToolError {
    NetToolError::new(ErrorCode::HelperExecutionFailed, message, true)
}

fn platform_snapshot_error(error: impl std::fmt::Display) -> NetToolError {
    NetToolError::new(
        ErrorCode::PersistenceFailed,
        format!("platform snapshot state is invalid: {error}"),
        false,
    )
}

#[cfg(test)]
mod tests {
    use super::platform_network_macos::parse_macos_state;
    use super::{
        PlatformBackend, PlatformCommand, PlatformNetworkExecutor, PlatformStateReader,
        build_macos_networksetup_commands, execute_platform_commands,
        run_validated_platform_command, validate_platform_command,
    };
    use crate::{CommandOutput, CommandRunner, NetworkExecutor};
    use nettool_domain::IpPrefix;
    use nettool_helper_protocol::NetworkDesiredState;
    use serde_json::json;
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::Path;

    #[derive(Default)]
    struct RecordingRunner {
        calls: usize,
        fail_on_call: Option<usize>,
    }

    struct StaticReader {
        state: NetworkDesiredState,
    }

    impl PlatformStateReader for StaticReader {
        fn read_state(
            &mut self,
            _interface_id: &str,
        ) -> Result<NetworkDesiredState, nettool_error::NetToolError> {
            Ok(self.state.clone())
        }
    }

    impl CommandRunner for RecordingRunner {
        fn run(
            &mut self,
            _program: &Path,
            _arguments: &[String],
        ) -> Result<CommandOutput, nettool_error::NetToolError> {
            self.calls += 1;
            if self.fail_on_call == Some(self.calls) {
                return Ok(CommandOutput {
                    success: false,
                    stdout: String::new(),
                    stderr: "failed".to_owned(),
                });
            }
            Ok(CommandOutput {
                success: true,
                stdout: String::new(),
                stderr: String::new(),
            })
        }
    }

    fn desired() -> NetworkDesiredState {
        serde_json::from_value(json!({
            "ipv4":{"mode":"static","addresses":[{"address":"192.0.2.10","prefix_length":24}]},
            "ipv6":{"mode":"automatic"},
            "dns":{"automatic":false,"servers":["192.0.2.53"],"search_domains":[]},
            "routes":[],"mtu":1500
        }))
        .expect("typed desired state")
    }

    #[test]
    fn builds_fixed_absolute_commands_without_shell() {
        let commands = build_macos_networksetup_commands("en0", &desired()).expect("commands");
        assert_eq!(
            commands[0].program,
            std::path::Path::new("/usr/sbin/networksetup")
        );
        assert_eq!(
            commands[0].arguments,
            [
                "-setmanual",
                "en0",
                "192.0.2.10",
                "255.255.255.0",
                "0.0.0.0"
            ]
        );
        assert!(
            commands
                .iter()
                .all(|command| command.arguments.iter().all(|value| !value.contains(';')))
        );
    }

    #[test]
    fn rejects_unsafe_interface_and_routes() {
        assert!(build_macos_networksetup_commands("en0;id", &desired()).is_err());
        let mut state = desired();
        state.routes.push(nettool_domain::RouteConfiguration {
            destination: IpPrefix {
                address: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 0)),
                prefix_length: 24,
            },
            gateway: None,
            metric: None,
        });
        assert!(build_macos_networksetup_commands("en0", &state).is_err());

        let mut search_domain_state = desired();
        search_domain_state
            .dns
            .search_domains
            .push("lab.example".to_owned());
        assert!(build_macos_networksetup_commands("en0", &search_domain_state).is_err());

        let mut multiple_addresses = desired();
        if let nettool_domain::Ipv4Configuration::Static { addresses } =
            &mut multiple_addresses.ipv4
        {
            addresses.push(addresses[0].clone());
        }
        assert!(build_macos_networksetup_commands("en0", &multiple_addresses).is_err());
    }

    #[test]
    fn builds_windows_fixed_netsh_commands() {
        let commands =
            super::build_windows_netsh_commands("Ethernet", &desired()).expect("commands");
        assert_eq!(
            commands[0].program,
            std::path::Path::new(r"C:\Windows\System32\netsh.exe")
        );
        assert_eq!(
            commands[0].arguments[0..5],
            ["interface", "ipv4", "set", "address", "name=Ethernet"]
        );
        assert!(commands.iter().all(|command| {
            command
                .arguments
                .iter()
                .all(|value| !value.contains('|') && !value.contains('&'))
        }));
    }

    #[test]
    fn validates_runner_boundary_before_execution() {
        let valid = PlatformCommand {
            program: std::path::PathBuf::from("/usr/sbin/networksetup"),
            arguments: vec!["-getinfo".to_owned(), "en0".to_owned()],
        };
        assert!(validate_platform_command(&valid).is_ok());

        let invalid_program = PlatformCommand {
            program: std::path::PathBuf::from("/bin/sh"),
            arguments: vec!["-c".to_owned(), "id".to_owned()],
        };
        assert!(validate_platform_command(&invalid_program).is_err());

        let invalid_argument = PlatformCommand {
            program: std::path::PathBuf::from("/usr/sbin/networksetup"),
            arguments: vec!["en0;id".to_owned()],
        };
        assert!(validate_platform_command(&invalid_argument).is_err());

        let arbitrary_powershell = PlatformCommand {
            program: std::path::PathBuf::from(
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            ),
            arguments: vec!["-Command".to_owned(), "Write-Output unsafe".to_owned()],
        };
        assert!(validate_platform_command(&arbitrary_powershell).is_err());

        let mut runner = RecordingRunner::default();
        run_validated_platform_command(&mut runner, &valid).expect("validated execution");
        assert_eq!(runner.calls, 1);
        assert!(run_validated_platform_command(&mut runner, &invalid_argument).is_err());
        assert_eq!(runner.calls, 1, "invalid command must not reach runner");

        let mut failing_runner = RecordingRunner {
            fail_on_call: Some(2),
            ..RecordingRunner::default()
        };
        let commands = vec![valid.clone(), valid];
        assert!(execute_platform_commands(&mut failing_runner, &commands).is_err());
        assert_eq!(failing_runner.calls, 2);
    }

    #[test]
    fn platform_executor_persists_and_restores_typed_snapshot() {
        let snapshot_directory =
            std::env::temp_dir().join(format!("nettool-platform-executor-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&snapshot_directory);
        let state = desired();
        let mut executor = PlatformNetworkExecutor::new(
            RecordingRunner::default(),
            StaticReader {
                state: state.clone(),
            },
            PlatformBackend::Macos,
            &snapshot_directory,
        )
        .expect("executor");
        let (snapshot_id, old_state) = executor.snapshot("en0").expect("snapshot");
        assert_eq!(old_state, serde_json::to_value(&state).expect("state json"));
        executor.apply("en0", &state).expect("apply");
        executor.verify("en0", &state).expect("verify");
        executor.restore(&snapshot_id).expect("restore");
        assert!(
            snapshot_directory
                .join(format!("{snapshot_id}.json"))
                .exists()
        );
        let _ = std::fs::remove_dir_all(snapshot_directory);
    }

    #[test]
    fn parses_complete_macos_networksetup_state_and_rejects_unrepresentable_gateway() {
        let state = parse_macos_state(
            "DHCP Configuration\nIP address: 192.0.2.10\nSubnet mask: 255.255.255.0\nRouter: 0.0.0.0\n",
            "IPv6: Automatic\n",
            "192.0.2.53\n2001:db8::53\n",
            "Active MTU: 1500 (Current Setting: 1500)\n",
        )
        .expect("state");
        assert!(matches!(
            state.ipv4,
            nettool_domain::Ipv4Configuration::Dhcp
        ));
        assert_eq!(state.dns.servers.len(), 2);
        assert_eq!(state.mtu, Some(1500));

        assert!(
            parse_macos_state(
                "IP address: 192.0.2.10\nSubnet mask: 255.255.255.0\nRouter: 192.0.2.1\n",
                "IPv6: Automatic\n",
                "There aren't any DNS Servers set on this service.\n",
                "Active MTU: 1500 (Current Setting: 1500)\n",
            )
            .is_err()
        );
    }

    #[test]
    fn parses_windows_json_state_and_rejects_gateway() {
        let state = super::platform_network_windows::parse_windows_json_state(
            r#"{"schema_version":1,"interface_count":1,"interface_id":"Ethernet","ipv4":{"dhcp":false,"addresses":[{"address":"192.0.2.10","prefix_length":24}]},"ipv6":{"state":"automatic","addresses":[]},"dns":{"servers":["192.0.2.53","2001:db8::53"]},"mtu":1500,"default_gateways":[],"route_count":0}"#,
            "Ethernet",
        )
        .expect("state");
        assert!(matches!(
            state.ipv4,
            nettool_domain::Ipv4Configuration::Static { .. }
        ));
        assert!(matches!(
            state.ipv6,
            nettool_domain::Ipv6Configuration::Automatic
        ));
        assert_eq!(state.dns.servers.len(), 2);
        assert_eq!(state.mtu, Some(1500));

        assert!(super::platform_network_windows::parse_windows_json_state(
            r#"{"schema_version":1,"interface_count":1,"interface_id":"Ethernet","ipv4":{"dhcp":false,"addresses":[{"address":"192.0.2.10","prefix_length":24}]},"ipv6":{"state":"automatic","addresses":[]},"dns":{"servers":[]},"mtu":1500,"default_gateways":["192.0.2.1"],"route_count":1}"#,
            "Ethernet",
        ).is_err());
    }
}

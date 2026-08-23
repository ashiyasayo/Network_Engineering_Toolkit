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
use std::path::PathBuf;
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

/// macOS `networksetup` 唯讀 state reader。
///
/// 只接受可完整轉成 [`NetworkDesiredState`] 的輸出；例如非零 gateway 或未知格式
/// 會直接失敗，避免 Safe Apply 以不完整 snapshot 進行 rollback。
pub struct MacosNetworkStateReader<R> {
    runner: R,
}

/// Windows `netsh.exe` 唯讀 state reader。
///
/// Windows `netsh` 顯示文字會隨 OS 語系改變；parser 只接受可辨識的英文欄位，
/// 其他格式直接 fail closed，避免將不完整資料當成可回復 snapshot。
pub struct WindowsNetshStateReader<R> {
    runner: R,
}

impl<R> WindowsNetshStateReader<R> {
    /// 建立 reader；命令由注入的 runner 執行。
    #[must_use]
    pub const fn new(runner: R) -> Self {
        Self { runner }
    }
}

impl<R: CommandRunner> PlatformStateReader for WindowsNetshStateReader<R> {
    fn read_state(&mut self, interface_id: &str) -> Result<NetworkDesiredState, NetToolError> {
        validate_interface(interface_id)?;
        let ipv4 = self.query([
            "interface",
            "ipv4",
            "show",
            "config",
            &format!("name={interface_id}"),
        ])?;
        let ipv6 = self.query([
            "interface",
            "ipv6",
            "show",
            "config",
            &format!("interface={interface_id}"),
        ])?;
        let dns = self.query([
            "interface",
            "ipv4",
            "show",
            "dnsservers",
            &format!("name={interface_id}"),
        ])?;
        let mtu = self.query([
            "interface",
            "ipv4",
            "show",
            "subinterfaces",
            &format!("name={interface_id}"),
        ])?;
        parse_windows_state(&ipv4, &ipv6, &dns, &mtu)
    }
}

impl<R: CommandRunner> WindowsNetshStateReader<R> {
    fn query<const N: usize>(&mut self, operation: [&str; N]) -> Result<String, NetToolError> {
        let arguments = operation.into_iter().map(str::to_owned).collect::<Vec<_>>();
        let command = PlatformCommand {
            program: PathBuf::from(r"C:\Windows\System32\netsh.exe"),
            arguments,
        };
        let output = run_validated_platform_command(&mut self.runner, &command)?;
        if output.success {
            Ok(output.stdout)
        } else {
            Err(NetToolError::new(
                ErrorCode::HelperExecutionFailed,
                "netsh state query failed",
                true,
            ))
        }
    }
}

fn parse_windows_state(
    ipv4_output: &str,
    ipv6_output: &str,
    dns_output: &str,
    mtu_output: &str,
) -> Result<NetworkDesiredState, NetToolError> {
    let ipv4_dhcp = parse_yes_no_label(ipv4_output, "DHCP enabled:")?;
    let ipv4 = if ipv4_dhcp {
        Ipv4Configuration::Dhcp
    } else {
        let address = parse_first_ip(ipv4_output, "IP Address:")?;
        let prefix = parse_subnet_prefix(ipv4_output)?;
        reject_default_gateway(ipv4_output, "Default Gateway:")?;
        Ipv4Configuration::Static {
            addresses: vec![IpPrefix {
                address: IpAddr::V4(address),
                prefix_length: prefix,
            }],
        }
    };

    let ipv6 = if ipv6_output.contains("Disabled") || ipv6_output.contains("Off") {
        Ipv6Configuration::Disabled
    } else if parse_yes_no_label(ipv6_output, "DHCP enabled:")? {
        Ipv6Configuration::Automatic
    } else {
        let address = parse_first_ipv6(ipv6_output, "IP Address:")?;
        let prefix = parse_subnet_prefix(ipv6_output)?;
        reject_default_gateway(ipv6_output, "Default Gateway:")?;
        Ipv6Configuration::Static {
            addresses: vec![IpPrefix {
                address: IpAddr::V6(address),
                prefix_length: prefix,
            }],
        }
    };

    let servers = parse_windows_dns(dns_output)?;
    let mtu = parse_windows_mtu(mtu_output)?;
    let state = NetworkDesiredState {
        ipv4,
        ipv6,
        dns: DnsConfiguration {
            automatic: servers.is_empty(),
            servers,
            search_domains: Vec::new(),
        },
        routes: Vec::new(),
        mtu: Some(mtu),
    };
    state
        .validate()
        .map_err(|message| NetToolError::new(ErrorCode::ProtocolInvalid, message, false))?;
    Ok(state)
}

fn parse_yes_no_label(output: &str, label: &str) -> Result<bool, NetToolError> {
    let value = output
        .lines()
        .find_map(|line| line.strip_prefix(label).map(str::trim))
        .ok_or_else(|| platform_reader_error(format!("Windows state is missing {label}")))?;
    match value {
        "Yes" => Ok(true),
        "No" => Ok(false),
        _ => Err(platform_reader_error(format!(
            "Windows state has invalid {label}"
        ))),
    }
}

fn parse_first_ip(output: &str, label: &str) -> Result<Ipv4Addr, NetToolError> {
    output
        .lines()
        .find_map(|line| line.strip_prefix(label).map(str::trim))
        .ok_or_else(|| platform_reader_error(format!("Windows state is missing {label}")))?
        .split_whitespace()
        .next()
        .ok_or_else(|| platform_reader_error(format!("Windows state has invalid {label}")))?
        .parse()
        .map_err(|_| platform_reader_error(format!("Windows state has invalid {label}")))
}

fn parse_first_ipv6(output: &str, label: &str) -> Result<Ipv6Addr, NetToolError> {
    let value = output
        .lines()
        .find_map(|line| line.strip_prefix(label).map(str::trim))
        .ok_or_else(|| platform_reader_error(format!("Windows state is missing {label}")))?;
    value
        .split_whitespace()
        .next()
        .ok_or_else(|| platform_reader_error(format!("Windows state has invalid {label}")))?
        .split('%')
        .next()
        .ok_or_else(|| platform_reader_error(format!("Windows state has invalid {label}")))?
        .parse()
        .map_err(|_| platform_reader_error(format!("Windows state has invalid {label}")))
}

fn parse_subnet_prefix(output: &str) -> Result<u8, NetToolError> {
    output
        .lines()
        .find_map(|line| line.split_once('/').map(|(_, value)| value.trim()))
        .and_then(|value| value.split_whitespace().next())
        .ok_or_else(|| platform_reader_error("Windows state is missing subnet prefix"))?
        .parse()
        .map_err(|_| platform_reader_error("Windows subnet prefix is invalid"))
}

fn reject_default_gateway(output: &str, label: &str) -> Result<(), NetToolError> {
    let Some(value) = output
        .lines()
        .find_map(|line| line.strip_prefix(label).map(str::trim))
    else {
        return Ok(());
    };
    let value = value.split_whitespace().next().unwrap_or_default();
    if !value.is_empty() && value != "0.0.0.0" && value != "::" && value != "None" {
        return Err(platform_reader_error(
            "Windows state contains a gateway not representable by this adapter",
        ));
    }
    Ok(())
}

fn parse_windows_dns(output: &str) -> Result<Vec<IpAddr>, NetToolError> {
    let mut servers = Vec::new();
    for line in output.lines() {
        let Some((_, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        if let Ok(address) = value.parse() {
            servers.push(address);
        }
    }
    if servers.len() > 16 {
        return Err(platform_reader_error(
            "Windows DNS server count exceeds limit",
        ));
    }
    Ok(servers)
}

fn parse_windows_mtu(output: &str) -> Result<u32, NetToolError> {
    output
        .lines()
        .find_map(|line| {
            line.split_whitespace()
                .find(|value| value.parse::<u32>().is_ok())
                .and_then(|value| value.parse().ok())
        })
        .filter(|mtu| (576..=65_535).contains(mtu))
        .ok_or_else(|| platform_reader_error("Windows MTU output is invalid"))
}

impl<R> MacosNetworkStateReader<R> {
    /// 建立 reader；實際命令由注入的 runner 執行，方便平台測試與 sandbox 驗證。
    #[must_use]
    pub const fn new(runner: R) -> Self {
        Self { runner }
    }
}

impl<R: CommandRunner> PlatformStateReader for MacosNetworkStateReader<R> {
    fn read_state(&mut self, interface_id: &str) -> Result<NetworkDesiredState, NetToolError> {
        validate_interface(interface_id)?;
        let info = self.query(interface_id, ["-getinfo"])?;
        let v6_info = self.query(interface_id, ["-getv6info"])?;
        let dns_info = self.query(interface_id, ["-getdnsservers"])?;
        let mtu_info = self.query(interface_id, ["-getMTU"])?;
        parse_macos_state(&info, &v6_info, &dns_info, &mtu_info)
    }
}

impl<R: CommandRunner> MacosNetworkStateReader<R> {
    fn query<const N: usize>(
        &mut self,
        interface_id: &str,
        operation: [&str; N],
    ) -> Result<String, NetToolError> {
        let mut arguments = operation.into_iter().map(str::to_owned).collect::<Vec<_>>();
        arguments.push(interface_id.to_owned());
        let command = PlatformCommand {
            program: PathBuf::from("/usr/sbin/networksetup"),
            arguments,
        };
        let output = run_validated_platform_command(&mut self.runner, &command)?;
        if output.success {
            Ok(output.stdout)
        } else {
            Err(NetToolError::new(
                ErrorCode::HelperExecutionFailed,
                "networksetup state query failed",
                true,
            ))
        }
    }
}

fn parse_macos_state(
    info: &str,
    v6_info: &str,
    dns_info: &str,
    mtu_info: &str,
) -> Result<NetworkDesiredState, NetToolError> {
    let ipv4 = if info.contains("DHCP Configuration") {
        Ipv4Configuration::Dhcp
    } else {
        let address = parse_ip_label(info, "IP address:")?;
        let mask = parse_ip_label(info, "Subnet mask:")?;
        let IpAddr::V4(address) = address else {
            return Err(platform_reader_error("macOS IPv4 address has wrong family"));
        };
        let IpAddr::V4(mask) = mask else {
            return Err(platform_reader_error(
                "macOS IPv4 subnet mask has wrong family",
            ));
        };
        let prefix_length = prefix_from_netmask(mask)?;
        if let Some(router) = parse_optional_ip_label(info, "Router:")? {
            if !router.is_unspecified() {
                return Err(platform_reader_error(
                    "macOS state contains a gateway not representable by this adapter",
                ));
            }
        }
        Ipv4Configuration::Static {
            addresses: vec![IpPrefix {
                address: IpAddr::V4(address),
                prefix_length,
            }],
        }
    };

    let ipv6 = if v6_info.contains("Off") || v6_info.contains("Disabled") {
        Ipv6Configuration::Disabled
    } else if v6_info.contains("Automatic") {
        Ipv6Configuration::Automatic
    } else {
        let address = parse_ip_label(v6_info, "IPv6 IP address:")?;
        let IpAddr::V6(address) = address else {
            return Err(platform_reader_error("macOS IPv6 address has wrong family"));
        };
        let prefix_length = parse_u8_label(v6_info, "Prefix Length:")?;
        if let Some(router) = parse_optional_ip_label(v6_info, "IPv6 Router:")? {
            if !router.is_unspecified() {
                return Err(platform_reader_error(
                    "macOS IPv6 state contains a gateway not representable by this adapter",
                ));
            }
        }
        Ipv6Configuration::Static {
            addresses: vec![IpPrefix {
                address: IpAddr::V6(address),
                prefix_length,
            }],
        }
    };

    let dns_servers = parse_macos_dns(dns_info)?;
    let mtu = parse_mtu(mtu_info)?;
    let state = NetworkDesiredState {
        ipv4,
        ipv6,
        dns: DnsConfiguration {
            automatic: dns_servers.is_empty(),
            servers: dns_servers,
            search_domains: Vec::new(),
        },
        routes: Vec::new(),
        mtu: Some(mtu),
    };
    state
        .validate()
        .map_err(|message| NetToolError::new(ErrorCode::ProtocolInvalid, message, false))?;
    Ok(state)
}

fn parse_ip_label(output: &str, label: &str) -> Result<IpAddr, NetToolError> {
    parse_optional_ip_label(output, label)?
        .ok_or_else(|| platform_reader_error(format!("macOS state is missing {label}")))
}

fn parse_optional_ip_label(output: &str, label: &str) -> Result<Option<IpAddr>, NetToolError> {
    let Some(value) = output
        .lines()
        .find_map(|line| line.strip_prefix(label).map(str::trim))
    else {
        return Ok(None);
    };
    if value.is_empty() || value.eq_ignore_ascii_case("none") {
        return Ok(None);
    }
    value
        .parse()
        .map(Some)
        .map_err(|_| platform_reader_error(format!("macOS state has invalid {label}")))
}

fn parse_u8_label(output: &str, label: &str) -> Result<u8, NetToolError> {
    output
        .lines()
        .find_map(|line| line.strip_prefix(label).map(str::trim))
        .ok_or_else(|| platform_reader_error(format!("macOS state is missing {label}")))?
        .parse()
        .map_err(|_| platform_reader_error(format!("macOS state has invalid {label}")))
}

fn prefix_from_netmask(mask: Ipv4Addr) -> Result<u8, NetToolError> {
    let bits = u32::from(mask);
    let prefix = u8::try_from(bits.leading_ones())
        .map_err(|_| platform_reader_error("IPv4 prefix length overflow"))?;
    if bits
        != if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        }
    {
        return Err(platform_reader_error("macOS subnet mask is not contiguous"));
    }
    Ok(prefix)
}

fn parse_macos_dns(output: &str) -> Result<Vec<IpAddr>, NetToolError> {
    if output.contains("There aren't any DNS Servers") || output.trim().is_empty() {
        return Ok(Vec::new());
    }
    output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| {
            line.parse()
                .map_err(|_| platform_reader_error("macOS DNS output is not an IP address"))
        })
        .collect()
}

fn parse_mtu(output: &str) -> Result<u32, NetToolError> {
    output
        .split("Current Setting:")
        .nth(1)
        .and_then(|value| value.split_whitespace().next())
        .map(|value| value.trim_end_matches(')'))
        .ok_or_else(|| platform_reader_error("macOS MTU output is invalid"))?
        .parse()
        .map_err(|_| platform_reader_error("macOS MTU is invalid"))
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
        if let Some(parent) = path.parent() {
            let directory = OpenOptions::new()
                .read(true)
                .open(parent)
                .map_err(platform_persistence_error)?;
            directory.sync_all().map_err(platform_persistence_error)?;
        }
        Ok(snapshot_id)
    }
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
    if program != "/usr/sbin/networksetup" && program != r"C:\Windows\System32\netsh.exe" {
        return Err(invalid("platform command executable is not allowlisted"));
    }
    if command.arguments.is_empty() || command.arguments.len() > 32 {
        return Err(invalid("platform command argument count is invalid"));
    }
    if command.arguments.iter().any(|argument| {
        argument.is_empty()
            || argument.contains('\0')
            || argument
                .chars()
                .any(|character| matches!(character, ';' | '|' | '&' | '`' | '$' | '\n' | '\r'))
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

/// 將 desired state 轉成 macOS `networksetup` command sequence。
///
/// 此 builder 不執行命令；routes 尚未有安全的 `networksetup` 對應操作，因此會明確拒絕。
///
/// # Errors
///
/// Interface ID 不安全、desired state 無效、routes 存在或 macOS 不支援的設定時回傳錯誤。
pub fn build_macos_networksetup_commands(
    interface_id: &str,
    desired: &NetworkDesiredState,
) -> Result<Vec<PlatformCommand>, NetToolError> {
    validate_interface(interface_id)?;
    desired
        .validate()
        .map_err(|message| invalid(message.to_owned()))?;
    if !desired.routes.is_empty() || !desired.dns.search_domains.is_empty() {
        return Err(NetToolError::new(
            ErrorCode::Unsupported,
            "macOS networksetup adapter does not apply routes or DNS search domains",
            false,
        ));
    }
    let program = PathBuf::from("/usr/sbin/networksetup");
    let mut commands = Vec::new();
    match &desired.ipv4 {
        Ipv4Configuration::Dhcp => commands.push(command(&program, ["-setdhcp", interface_id])),
        Ipv4Configuration::Disabled => commands.push(command(
            &program,
            ["-setmanual", interface_id, "0.0.0.0", "0.0.0.0", "0.0.0.0"],
        )),
        Ipv4Configuration::Static { addresses } => {
            if addresses.len() != 1 {
                return Err(invalid(
                    "macOS networksetup requires exactly one IPv4 address",
                ));
            }
            let Some(prefix) = addresses.first() else {
                return Err(invalid("macOS static IPv4 requires an address"));
            };
            let IpAddr::V4(address) = prefix.address else {
                return Err(invalid("macOS IPv4 adapter received a non-IPv4 address"));
            };
            let mask = ipv4_netmask(prefix.prefix_length)?;
            commands.push(command(
                &program,
                [
                    "-setmanual",
                    interface_id,
                    &address.to_string(),
                    &mask,
                    "0.0.0.0",
                ],
            ));
        }
    }
    match &desired.ipv6 {
        Ipv6Configuration::Automatic => {
            commands.push(command(&program, ["-setv6automatic", interface_id]));
        }
        Ipv6Configuration::Disabled => {
            commands.push(command(&program, ["-setv6off", interface_id]));
        }
        Ipv6Configuration::Static { addresses } => {
            if addresses.len() != 1 {
                return Err(invalid(
                    "macOS networksetup requires exactly one IPv6 address",
                ));
            }
            let Some(prefix) = addresses.first() else {
                return Err(invalid("macOS static IPv6 requires an address"));
            };
            let IpAddr::V6(address) = prefix.address else {
                return Err(invalid("macOS IPv6 adapter received a non-IPv6 address"));
            };
            commands.push(command(
                &program,
                [
                    "-setv6manual",
                    interface_id,
                    &address.to_string(),
                    &prefix.prefix_length.to_string(),
                    "::",
                ],
            ));
        }
    }
    if desired.dns.automatic {
        commands.push(command(&program, ["-setdnsservers", interface_id, "Empty"]));
    } else {
        let mut arguments = vec!["-setdnsservers".to_owned(), interface_id.to_owned()];
        arguments.extend(desired.dns.servers.iter().map(ToString::to_string));
        if desired.dns.servers.is_empty() {
            arguments.push("Empty".to_owned());
        }
        commands.push(PlatformCommand {
            program: program.clone(),
            arguments,
        });
    }
    if let Some(mtu) = desired.mtu {
        commands.push(command(
            &program,
            ["-setMTU", interface_id, &mtu.to_string()],
        ));
    }
    validate_commands(&commands)?;
    Ok(commands)
}

/// 將 desired state 轉成 Windows `netsh.exe` command sequence。
///
/// 使用固定 System32 executable 與獨立 argv；不經 PowerShell 或 shell。Routes 與 DNS
/// search domains 尚未具備完整 read-back/rollback 證據時會拒絕。
///
/// # Errors
///
/// 欄位驗證失敗、routes/search domains 存在或平台尚未支援的設定時回傳錯誤。
#[allow(clippy::too_many_lines)]
pub fn build_windows_netsh_commands(
    interface_id: &str,
    desired: &NetworkDesiredState,
) -> Result<Vec<PlatformCommand>, NetToolError> {
    validate_interface(interface_id)?;
    desired
        .validate()
        .map_err(|message| invalid(message.to_owned()))?;
    if !desired.routes.is_empty() || !desired.dns.search_domains.is_empty() {
        return Err(NetToolError::new(
            ErrorCode::Unsupported,
            "Windows netsh adapter does not apply routes or DNS search domains",
            false,
        ));
    }
    let program = PathBuf::from(r"C:\Windows\System32\netsh.exe");
    let mut commands = Vec::new();
    match &desired.ipv4 {
        Ipv4Configuration::Dhcp => commands.push(command(
            &program,
            [
                "interface",
                "ipv4",
                "set",
                "address",
                &format!("name={interface_id}"),
                "source=dhcp",
            ],
        )),
        Ipv4Configuration::Disabled => commands.push(command(
            &program,
            [
                "interface",
                "ipv4",
                "set",
                "address",
                &format!("name={interface_id}"),
                "source=static",
                "addr=0.0.0.0",
                "mask=0.0.0.0",
                "gateway=none",
            ],
        )),
        Ipv4Configuration::Static { addresses } => {
            if addresses.len() != 1 {
                return Err(invalid("Windows netsh requires exactly one IPv4 address"));
            }
            let Some(prefix) = addresses.first() else {
                return Err(invalid("Windows static IPv4 requires an address"));
            };
            let IpAddr::V4(address) = prefix.address else {
                return Err(invalid("Windows IPv4 adapter received a non-IPv4 address"));
            };
            let mask = ipv4_netmask(prefix.prefix_length)?;
            commands.push(command(
                &program,
                [
                    "interface",
                    "ipv4",
                    "set",
                    "address",
                    &format!("name={interface_id}"),
                    "source=static",
                    &format!("addr={address}"),
                    &format!("mask={mask}"),
                    "gateway=none",
                ],
            ));
        }
    }
    match &desired.ipv6 {
        Ipv6Configuration::Automatic => commands.push(command(
            &program,
            [
                "interface",
                "ipv6",
                "set",
                "address",
                &format!("interface={interface_id}"),
                "source=dhcp",
            ],
        )),
        Ipv6Configuration::Disabled => commands.push(command(
            &program,
            [
                "interface",
                "ipv6",
                "set",
                "address",
                &format!("interface={interface_id}"),
                "source=none",
            ],
        )),
        Ipv6Configuration::Static { addresses } => {
            if addresses.len() != 1 {
                return Err(invalid("Windows netsh requires exactly one IPv6 address"));
            }
            let Some(prefix) = addresses.first() else {
                return Err(invalid("Windows static IPv6 requires an address"));
            };
            let IpAddr::V6(address) = prefix.address else {
                return Err(invalid("Windows IPv6 adapter received a non-IPv6 address"));
            };
            commands.push(command(
                &program,
                [
                    "interface",
                    "ipv6",
                    "set",
                    "address",
                    &format!("interface={interface_id}"),
                    &format!("address={address}"),
                    &format!("prefixlength={}", prefix.prefix_length),
                    "store=active",
                ],
            ));
        }
    }
    let mut dns_arguments = vec![
        "interface".to_owned(),
        "ipv4".to_owned(),
        "set".to_owned(),
        "dnsservers".to_owned(),
        format!("name={interface_id}"),
        "source=static".to_owned(),
    ];
    if desired.dns.automatic {
        "source=dhcp".clone_into(&mut dns_arguments[5]);
    } else if let Some(server) = desired.dns.servers.first() {
        dns_arguments.push(format!("address={server}"));
        dns_arguments.push("validate=no".to_owned());
    } else {
        return Err(invalid("Windows static DNS requires at least one server"));
    }
    commands.push(PlatformCommand {
        program: program.clone(),
        arguments: dns_arguments,
    });
    if let Some(mtu) = desired.mtu {
        commands.push(command(
            &program,
            [
                "interface",
                "ipv4",
                "set",
                "subinterface",
                &format!("interface={interface_id}"),
                &format!("mtu={mtu}"),
                "store=active",
            ],
        ));
    }
    validate_commands(&commands)?;
    Ok(commands)
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
        || interface_id.len() > 64
        || !interface_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
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
    use super::{
        PlatformBackend, PlatformCommand, PlatformNetworkExecutor, PlatformStateReader,
        build_macos_networksetup_commands, execute_platform_commands, parse_macos_state,
        parse_windows_state, run_validated_platform_command, validate_platform_command,
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
    fn parses_windows_netsh_state_and_rejects_gateway() {
        let state = parse_windows_state(
            "DHCP enabled: No\nIP Address: 192.0.2.10\nSubnet Prefix: 192.0.2.0/24 (mask 255.255.255.0)\nDefault Gateway: 0.0.0.0\n",
            "DHCP enabled: Yes\n",
            "Statically Configured DNS Servers : 192.0.2.53\n                                      : 2001:db8::53\n",
            "MTU  MediaSenseState   Bytes In  Bytes Out  Interface\n1500  Connected         0          0  Ethernet\n",
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

        assert!(parse_windows_state(
            "DHCP enabled: No\nIP Address: 192.0.2.10\nSubnet Prefix: 192.0.2.0/24\nDefault Gateway: 192.0.2.1\n",
            "DHCP enabled: Yes\n",
            "No DNS servers configured.\n",
            "1500 Ethernet\n",
        )
        .is_err());
    }
}

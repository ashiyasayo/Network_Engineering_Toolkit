use crate::NetworkExecutor;
use nettool_domain::{Ipv4Configuration, Ipv6Configuration, RouteConfiguration};
use nettool_error::{ErrorCode, NetToolError};
use nettool_helper_protocol::NetworkDesiredState;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const SNAPSHOT_VERSION: u32 = 1;
const PROFILE_PROPERTIES: [&str; 13] = [
    "ipv4.method",
    "ipv4.addresses",
    "ipv4.dns",
    "ipv4.dns-search",
    "ipv4.routes",
    "ipv4.ignore-auto-dns",
    "ipv6.method",
    "ipv6.addresses",
    "ipv6.dns",
    "ipv6.dns-search",
    "ipv6.routes",
    "ipv6.ignore-auto-dns",
    "802-3-ethernet.mtu",
];

/// Process runner output；stderr 只在失敗時進入 sanitized error。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandOutput {
    /// Process exit success。
    pub success: bool,
    /// Standard output。
    pub stdout: String,
    /// Standard error。
    pub stderr: String,
}

/// 不經 shell 執行固定 platform binary 的抽象，供 executor 測試。
pub trait CommandRunner {
    /// 執行 binary 與獨立 argv。
    ///
    /// # Errors
    ///
    /// Process 無法啟動或等待時回傳錯誤。
    fn run(&mut self, program: &Path, arguments: &[String]) -> Result<CommandOutput, NetToolError>;
}

/// 使用 `std::process::Command` 的 production runner；不解析 shell syntax。
#[derive(Default)]
pub struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    fn run(&mut self, program: &Path, arguments: &[String]) -> Result<CommandOutput, NetToolError> {
        let output = Command::new(program)
            .args(arguments)
            .output()
            .map_err(|error| {
                execution_error("start NetworkManager command", &error.to_string(), true)
            })?;
        Ok(CommandOutput {
            success: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct NetworkManagerSnapshot {
    version: u32,
    interface_id: String,
    connection_uuid: String,
    properties: BTreeMap<String, String>,
}

/// Linux `NetworkManager` network executor。
pub struct LinuxNetworkManagerExecutor<R> {
    runner: R,
    nmcli_path: PathBuf,
    snapshot_directory: PathBuf,
}

impl<R: CommandRunner> LinuxNetworkManagerExecutor<R> {
    /// 建立 executor；`nmcli_path` 必須是 absolute path，避免特權程序受 PATH 劫持。
    ///
    /// # Errors
    ///
    /// Binary path 非 absolute 或 snapshot directory 無法建立時回傳錯誤。
    pub fn new(
        runner: R,
        nmcli_path: impl Into<PathBuf>,
        snapshot_directory: impl Into<PathBuf>,
    ) -> Result<Self, NetToolError> {
        let nmcli_path = nmcli_path.into();
        if !nmcli_path.is_absolute() {
            return Err(NetToolError::new(
                ErrorCode::InvalidArgument,
                "nmcli path must be absolute",
                false,
            ));
        }
        let snapshot_directory = snapshot_directory.into();
        fs::create_dir_all(&snapshot_directory).map_err(persistence_error)?;
        Ok(Self {
            runner,
            nmcli_path,
            snapshot_directory,
        })
    }

    fn connection_uuid(&mut self, interface_id: &str) -> Result<String, NetToolError> {
        let output = self.run_checked(&[
            "--get-values".into(),
            "GENERAL.CON-UUID".into(),
            "device".into(),
            "show".into(),
            interface_id.into(),
        ])?;
        let uuid = output.trim();
        if uuid.is_empty() || uuid == "--" || uuid.chars().any(char::is_whitespace) {
            return Err(execution_error(
                "resolve active NetworkManager connection UUID",
                "device has no unambiguous active connection",
                false,
            ));
        }
        Ok(uuid.to_owned())
    }

    fn ensure_ethernet(&mut self, interface_id: &str) -> Result<(), NetToolError> {
        let output = self.run_checked(&[
            "--get-values".into(),
            "GENERAL.TYPE".into(),
            "device".into(),
            "show".into(),
            interface_id.into(),
        ])?;
        if output.trim() == "ethernet" {
            Ok(())
        } else {
            Err(NetToolError::new(
                ErrorCode::Unsupported,
                "Linux NetworkManager executor currently supports Ethernet devices only",
                false,
            ))
        }
    }

    fn read_property(&mut self, uuid: &str, property: &str) -> Result<String, NetToolError> {
        Ok(self
            .run_checked(&[
                "--get-values".into(),
                property.into(),
                "connection".into(),
                "show".into(),
                "uuid".into(),
                uuid.into(),
            ])?
            .trim()
            .to_owned())
    }

    fn activate(&mut self, uuid: &str, interface_id: &str) -> Result<(), NetToolError> {
        self.run_checked(&[
            "--wait".into(),
            "30".into(),
            "connection".into(),
            "up".into(),
            "uuid".into(),
            uuid.into(),
            "ifname".into(),
            interface_id.into(),
        ])?;
        Ok(())
    }

    fn modify(
        &mut self,
        uuid: &str,
        properties: &BTreeMap<String, String>,
    ) -> Result<(), NetToolError> {
        let mut arguments = vec![
            "connection".into(),
            "modify".into(),
            "uuid".into(),
            uuid.into(),
        ];
        for (property, value) in properties {
            arguments.push(property.clone());
            arguments.push(value.clone());
        }
        self.run_checked(&arguments)?;
        Ok(())
    }

    fn run_checked(&mut self, arguments: &[String]) -> Result<String, NetToolError> {
        let output = self.runner.run(&self.nmcli_path, arguments)?;
        if output.success {
            Ok(output.stdout)
        } else {
            Err(execution_error(
                "NetworkManager command failed",
                output.stderr.trim(),
                false,
            ))
        }
    }

    fn snapshot_path(&self, snapshot_id: &str) -> Result<PathBuf, NetToolError> {
        if snapshot_id.len() != 64 || !snapshot_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(NetToolError::new(
                ErrorCode::InvalidArgument,
                "snapshot ID is invalid",
                false,
            ));
        }
        Ok(self.snapshot_directory.join(format!("{snapshot_id}.json")))
    }

    fn write_snapshot(&self, snapshot: &NetworkManagerSnapshot) -> Result<String, NetToolError> {
        let mut entropy = [0_u8; 32];
        getrandom::fill(&mut entropy).map_err(|error| {
            NetToolError::new(
                ErrorCode::RandomFailed,
                format!("generate snapshot identifier: {error}"),
                true,
            )
        })?;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let mut digest = Sha256::new();
        digest.update(entropy);
        digest.update(timestamp.to_be_bytes());
        digest.update(snapshot.interface_id.as_bytes());
        let snapshot_id = format!("{:x}", digest.finalize());
        let path = self.snapshot_path(&snapshot_id)?;
        let temporary = path.with_extension("tmp");
        let bytes = serde_json::to_vec_pretty(snapshot).map_err(snapshot_state_error)?;
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .map_err(persistence_error)?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(persistence_error)?;
        fs::rename(&temporary, &path).map_err(persistence_error)?;
        sync_parent(&path)?;
        Ok(snapshot_id)
    }

    fn current_snapshot(
        &mut self,
        interface_id: &str,
    ) -> Result<NetworkManagerSnapshot, NetToolError> {
        self.ensure_ethernet(interface_id)?;
        let connection_uuid = self.connection_uuid(interface_id)?;
        let mut properties = BTreeMap::new();
        for property in PROFILE_PROPERTIES {
            properties.insert(
                property.to_owned(),
                self.read_property(&connection_uuid, property)?,
            );
        }
        Ok(NetworkManagerSnapshot {
            version: SNAPSHOT_VERSION,
            interface_id: interface_id.to_owned(),
            connection_uuid,
            properties,
        })
    }
}

impl<R: CommandRunner> NetworkExecutor for LinuxNetworkManagerExecutor<R> {
    fn read_state(&mut self, interface_id: &str) -> Result<Value, NetToolError> {
        serde_json::to_value(self.current_snapshot(interface_id)?).map_err(snapshot_state_error)
    }

    fn snapshot(&mut self, interface_id: &str) -> Result<(String, Value), NetToolError> {
        let snapshot = self.current_snapshot(interface_id)?;
        let snapshot_id = self.write_snapshot(&snapshot)?;
        let state = serde_json::to_value(&snapshot).map_err(snapshot_state_error)?;
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
        self.ensure_ethernet(interface_id)?;
        let uuid = self.connection_uuid(interface_id)?;
        let properties = build_network_manager_properties(desired_state);
        self.modify(&uuid, &properties)?;
        self.activate(&uuid, interface_id)
    }

    fn verify(
        &mut self,
        interface_id: &str,
        desired_state: &NetworkDesiredState,
    ) -> Result<(), NetToolError> {
        let uuid = self.connection_uuid(interface_id)?;
        let expected = build_network_manager_properties(desired_state);
        for (property, expected_value) in expected {
            let actual = self.read_property(&uuid, &property)?;
            if normalize_property(&actual) != normalize_property(&expected_value) {
                let mut error = execution_error(
                    "verify NetworkManager state",
                    "profile property does not match requested state",
                    false,
                );
                error.details.insert("property".into(), property);
                return Err(error);
            }
        }
        Ok(())
    }

    fn restore(&mut self, snapshot_id: &str) -> Result<(), NetToolError> {
        let path = self.snapshot_path(snapshot_id)?;
        let bytes = fs::read(path).map_err(persistence_error)?;
        let snapshot: NetworkManagerSnapshot =
            serde_json::from_slice(&bytes).map_err(snapshot_state_error)?;
        if snapshot.version != SNAPSHOT_VERSION {
            return Err(NetToolError::new(
                ErrorCode::ProtocolIncompatible,
                "network snapshot version is unsupported",
                false,
            ));
        }
        self.modify(&snapshot.connection_uuid, &snapshot.properties)?;
        self.activate(&snapshot.connection_uuid, &snapshot.interface_id)
    }
}

/// 將 typed desired state 轉成單一 `nmcli connection modify` property set。
#[must_use]
pub fn build_network_manager_properties(state: &NetworkDesiredState) -> BTreeMap<String, String> {
    let mut properties = BTreeMap::new();
    match &state.ipv4 {
        Ipv4Configuration::Dhcp => {
            properties.insert("ipv4.method".into(), "auto".into());
            properties.insert("ipv4.addresses".into(), String::new());
        }
        Ipv4Configuration::Static { addresses } => {
            properties.insert("ipv4.method".into(), "manual".into());
            properties.insert("ipv4.addresses".into(), format_addresses(addresses));
        }
        Ipv4Configuration::Disabled => {
            properties.insert("ipv4.method".into(), "disabled".into());
            properties.insert("ipv4.addresses".into(), String::new());
        }
    }
    match &state.ipv6 {
        Ipv6Configuration::Automatic => {
            properties.insert("ipv6.method".into(), "auto".into());
            properties.insert("ipv6.addresses".into(), String::new());
        }
        Ipv6Configuration::Static { addresses } => {
            properties.insert("ipv6.method".into(), "manual".into());
            properties.insert("ipv6.addresses".into(), format_addresses(addresses));
        }
        Ipv6Configuration::Disabled => {
            properties.insert("ipv6.method".into(), "disabled".into());
            properties.insert("ipv6.addresses".into(), String::new());
        }
    }
    let ipv4_dns = state
        .dns
        .servers
        .iter()
        .filter(|address| address.is_ipv4())
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let ipv6_dns = state
        .dns
        .servers
        .iter()
        .filter(|address| address.is_ipv6())
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    properties.insert("ipv4.dns".into(), ipv4_dns);
    properties.insert("ipv6.dns".into(), ipv6_dns);
    let search = state.dns.search_domains.join(",");
    properties.insert("ipv4.dns-search".into(), search);
    properties.insert("ipv6.dns-search".into(), String::new());
    let ignore_auto = if state.dns.automatic { "no" } else { "yes" };
    properties.insert("ipv4.ignore-auto-dns".into(), ignore_auto.into());
    properties.insert("ipv6.ignore-auto-dns".into(), ignore_auto.into());
    properties.insert("ipv4.routes".into(), format_routes(&state.routes, true));
    properties.insert("ipv6.routes".into(), format_routes(&state.routes, false));
    if let Some(mtu) = state.mtu {
        properties.insert("802-3-ethernet.mtu".into(), mtu.to_string());
    }
    properties
}

fn format_addresses(addresses: &[nettool_domain::IpPrefix]) -> String {
    addresses
        .iter()
        .map(|prefix| format!("{}/{}", prefix.address, prefix.prefix_length))
        .collect::<Vec<_>>()
        .join(",")
}

fn format_routes(routes: &[RouteConfiguration], ipv4: bool) -> String {
    routes
        .iter()
        .filter(|route| route.destination.address.is_ipv4() == ipv4)
        .map(|route| {
            let mut value = format!(
                "{}/{}",
                route.destination.address, route.destination.prefix_length
            );
            if let Some(gateway) = route.gateway {
                value.push(' ');
                value.push_str(&gateway.to_string());
            } else if route.metric.is_some() {
                value.push_str(if ipv4 { " 0.0.0.0" } else { " ::" });
            }
            if let Some(metric) = route.metric {
                value.push(' ');
                value.push_str(&metric.to_string());
            }
            value
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn normalize_property(value: &str) -> String {
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .collect::<Vec<_>>()
        .join(",")
}

fn execution_error(context: &str, detail: &str, retryable: bool) -> NetToolError {
    let detail = if detail.is_empty() {
        "no platform detail"
    } else {
        detail
    };
    NetToolError::new(
        ErrorCode::HelperExecutionFailed,
        format!("{context}: {detail}"),
        retryable,
    )
}

#[allow(clippy::needless_pass_by_value)]
fn persistence_error(error: std::io::Error) -> NetToolError {
    NetToolError::new(
        ErrorCode::PersistenceFailed,
        format!("network snapshot persistence failed: {error}"),
        true,
    )
}

#[allow(clippy::needless_pass_by_value)]
fn snapshot_state_error(error: serde_json::Error) -> NetToolError {
    NetToolError::new(
        ErrorCode::PersistenceFailed,
        format!("network snapshot is invalid: {error}"),
        false,
    )
}

#[cfg(unix)]
fn sync_parent(path: &Path) -> Result<(), NetToolError> {
    if let Some(parent) = path.parent() {
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(persistence_error)?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn sync_parent(_path: &Path) -> Result<(), NetToolError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::build_network_manager_properties;
    use nettool_domain::{
        DnsConfiguration, IpPrefix, Ipv4Configuration, Ipv6Configuration, RouteConfiguration,
    };
    use nettool_helper_protocol::NetworkDesiredState;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn builds_complete_network_manager_property_set_without_shell_text() {
        let state = NetworkDesiredState {
            ipv4: Ipv4Configuration::Static {
                addresses: vec![IpPrefix {
                    address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
                    prefix_length: 24,
                }],
            },
            ipv6: Ipv6Configuration::Static {
                addresses: vec![IpPrefix {
                    address: IpAddr::V6(Ipv6Addr::LOCALHOST),
                    prefix_length: 128,
                }],
            },
            dns: DnsConfiguration {
                automatic: false,
                servers: vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
                search_domains: vec!["lab.example".into()],
            },
            routes: vec![RouteConfiguration {
                destination: IpPrefix {
                    address: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 0)),
                    prefix_length: 24,
                },
                gateway: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
                metric: Some(10),
            }],
            mtu: Some(9000),
        };
        let properties = build_network_manager_properties(&state);
        assert_eq!(properties["ipv4.method"], "manual");
        assert_eq!(properties["ipv4.addresses"], "192.0.2.10/24");
        assert_eq!(properties["ipv4.routes"], "198.51.100.0/24 192.0.2.1 10");
        assert_eq!(properties["ipv4.dns"], "1.1.1.1");
        assert_eq!(properties["ipv4.ignore-auto-dns"], "yes");
        assert_eq!(properties["802-3-ethernet.mtu"], "9000");
    }
}

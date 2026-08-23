//! Privileged helper 的 whitelist-only request contract。

#![forbid(unsafe_code)]

use nettool_domain::{
    DnsConfiguration, IpPrefix, Ipv4Configuration, Ipv6Configuration, RouteConfiguration,
};
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::collections::HashSet;
use std::net::IpAddr;

/// Helper 可套用的封閉網路狀態 schema。
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct NetworkDesiredState {
    /// IPv4 configuration。
    pub ipv4: Ipv4Configuration,
    /// IPv6 configuration。
    pub ipv6: Ipv6Configuration,
    /// DNS configuration。
    pub dns: DnsConfiguration,
    /// Static routes。
    pub routes: Vec<RouteConfiguration>,
    /// Optional MTU；空值代表保持現況。
    pub mtu: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkDesiredStateWire {
    ipv4: Ipv4Configuration,
    ipv6: Ipv6Configuration,
    dns: DnsConfiguration,
    routes: Vec<RouteConfiguration>,
    mtu: Option<u32>,
}

impl<'de> Deserialize<'de> for NetworkDesiredState {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        validate_wire_shape(&value).map_err(D::Error::custom)?;
        let wire: NetworkDesiredStateWire =
            serde_json::from_value(value).map_err(D::Error::custom)?;
        Ok(Self {
            ipv4: wire.ipv4,
            ipv6: wire.ipv6,
            dns: wire.dns,
            routes: wire.routes,
            mtu: wire.mtu,
        })
    }
}

impl NetworkDesiredState {
    /// 驗證 address family、數量上限、route 與 MTU invariants。
    ///
    /// # Errors
    ///
    /// 狀態無法由平台安全、完整地套用時回傳穩定錯誤文字。
    pub fn validate(&self) -> Result<(), &'static str> {
        let ipv4 = match &self.ipv4 {
            Ipv4Configuration::Static { addresses } => addresses.as_slice(),
            Ipv4Configuration::Dhcp | Ipv4Configuration::Disabled => &[],
        };
        let ipv6 = match &self.ipv6 {
            Ipv6Configuration::Static { addresses } => addresses.as_slice(),
            Ipv6Configuration::Automatic | Ipv6Configuration::Disabled => &[],
        };
        if matches!(self.ipv4, Ipv4Configuration::Static { .. }) {
            validate_prefixes(ipv4, true)?;
        }
        if matches!(self.ipv6, Ipv6Configuration::Static { .. }) {
            validate_prefixes(ipv6, false)?;
        }
        if self.routes.len() > 256 {
            return Err("route count exceeds limit");
        }
        let mut routes = HashSet::with_capacity(self.routes.len());
        for route in &self.routes {
            validate_prefix(&route.destination, route.destination.address.is_ipv4())?;
            if route.gateway.is_some_and(|gateway| {
                gateway.is_ipv4() != route.destination.address.is_ipv4() || gateway.is_unspecified()
            }) {
                return Err("route gateway address family is invalid");
            }
            let identity = (
                route.destination.address,
                route.destination.prefix_length,
                route.gateway,
                route.metric,
            );
            if !routes.insert(identity) {
                return Err("duplicate route is not allowed");
            }
        }
        if self.dns.servers.len() > 16 || self.dns.search_domains.len() > 32 {
            return Err("DNS configuration exceeds limit");
        }
        if self.dns.servers.iter().any(IpAddr::is_unspecified) {
            return Err("DNS server must not be unspecified");
        }
        for domain in &self.dns.search_domains {
            if !valid_domain(domain) {
                return Err("DNS search domain is invalid");
            }
        }
        if self.mtu.is_some_and(|mtu| !(576..=65_535).contains(&mtu)) {
            return Err("MTU must be between 576 and 65535");
        }
        Ok(())
    }
}

/// 通過 OS IPC peer authentication 後的 caller identity。
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CallerIdentity {
    /// 平台提供的 user/principal identifier。
    pub principal: String,
    /// 呼叫端 process ID，僅供 audit，不能單獨作為授權依據。
    pub process_id: Option<u32>,
}

/// Helper 驗證後寫入 managed hosts section 的單一 entry。
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ManagedHostsEntry {
    /// IPv4 或 IPv6 address。
    pub address: String,
    /// 不含空白與換行的 hostname。
    pub hostname: String,
    /// 可選註解，不得包含換行。
    pub comment: Option<String>,
    /// 是否啟用；停用項目仍保留在 managed section 供日後恢復。
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

const fn default_enabled() -> bool {
    true
}

/// Helper 唯一允許的 operation 集合。
///
/// 使用封閉 enum 可讓 `shell.execute` 等任意命令在反序列化階段即遭拒絕。
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "name", content = "arguments", rename_all = "snake_case")]
pub enum PrivilegedOperation {
    /// 讀取介面設定。
    NetworkReadState {
        /// 介面 stable ID。
        interface_id: String,
    },
    /// 交易式套用網路設定。
    NetworkApply {
        /// 介面 stable ID。
        interface_id: String,
        /// 經 schema validation 的目標設定。
        desired_state: NetworkDesiredState,
        /// 未確認時 rollback 的 timeout 秒數。
        confirm_timeout_seconds: u64,
    },
    /// 由 snapshot 恢復網路設定。
    NetworkRestore {
        /// Helper-owned snapshot ID。
        snapshot_id: String,
    },
    /// 讀取 hosts file。
    HostsRead,
    /// 將目前 hosts file 保存至 Helper-owned backup。
    HostsBackup,
    /// 從最近一次 Helper-owned backup 原子恢復 hosts file。
    HostsRestore,
    /// 原子取代 `NetTool` managed section。
    HostsAtomicReplace {
        /// 用於 managed section marker 的 profile ID。
        profile_id: String,
        /// 經結構化驗證的 hosts entries。
        entries: Vec<ManagedHostsEntry>,
    },
    /// 準備 DPDK NIC。
    NicPrepareDpdk {
        /// 目標 NIC PCI address。
        pci_address: String,
    },
    /// 恢復 NIC driver。
    NicRestoreDriver {
        /// 目標 NIC PCI address。
        pci_address: String,
        /// 原始 `nic.prepare_dpdk` operation ID；driver 只能由 Helper snapshot 取得。
        prepare_operation_id: String,
    },
    /// 配置 huge pages。
    HugepagePrepare {
        /// NUMA node；空值代表由 policy 自動選擇。
        node: Option<u32>,
        /// Page 數量。
        pages: u64,
        /// 單一 page 大小，單位為 KiB。
        page_size_kib: u64,
    },
    /// 釋放由 operation 配置的 huge pages。
    HugepageRelease {
        /// 原始 prepare operation ID。
        operation_id: String,
    },
    /// 確認 Safe Apply，取消 rollback deadline。
    SafeApplyConfirm {
        /// 要確認的 apply operation ID。
        operation_id: String,
    },
    /// 立即執行 rollback。
    SafeApplyRollback {
        /// 要恢復的 apply operation ID。
        operation_id: String,
    },
    /// 查詢 helper 持有的 pending deadlines。
    SafeApplyListPending,
}

impl PrivilegedOperation {
    /// 回傳 audit 與 authorization policy 使用的穩定名稱。
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::NetworkReadState { .. } => "network.read_state",
            Self::NetworkApply { .. } => "network.apply",
            Self::NetworkRestore { .. } => "network.restore",
            Self::HostsRead => "hosts.read",
            Self::HostsBackup => "hosts.backup",
            Self::HostsRestore => "hosts.restore",
            Self::HostsAtomicReplace { .. } => "hosts.atomic_replace",
            Self::NicPrepareDpdk { .. } => "nic.prepare_dpdk",
            Self::NicRestoreDriver { .. } => "nic.restore_driver",
            Self::HugepagePrepare { .. } => "hugepage.prepare",
            Self::HugepageRelease { .. } => "hugepage.release",
            Self::SafeApplyConfirm { .. } => "safe_apply.confirm",
            Self::SafeApplyRollback { .. } => "safe_apply.rollback",
            Self::SafeApplyListPending => "safe_apply.list_pending",
        }
    }

    /// 檢查不需查詢 OS 狀態即可判斷的輸入限制。
    ///
    /// # Errors
    ///
    /// 參數為空、timeout 或資源數量超過安全界線時回傳穩定錯誤文字。
    pub fn validate(&self) -> Result<(), &'static str> {
        match self {
            Self::NetworkReadState { interface_id }
            | Self::NetworkRestore {
                snapshot_id: interface_id,
            } => non_empty(interface_id),
            Self::NetworkApply {
                interface_id,
                confirm_timeout_seconds,
                desired_state,
            } => {
                non_empty(interface_id)?;
                if !(10..=600).contains(confirm_timeout_seconds) {
                    return Err("confirm timeout must be between 10 and 600 seconds");
                }
                desired_state.validate()
            }
            Self::HostsAtomicReplace {
                profile_id,
                entries,
            } => validate_hosts(profile_id, entries),
            Self::NicPrepareDpdk { pci_address } => validate_pci_address(pci_address),
            Self::NicRestoreDriver {
                pci_address,
                prepare_operation_id,
            } => {
                validate_pci_address(pci_address)?;
                non_empty(prepare_operation_id)
            }
            Self::HugepagePrepare {
                pages,
                page_size_kib,
                ..
            } if *pages == 0 || *page_size_kib == 0 => {
                Err("huge page count and size must be non-zero")
            }
            Self::HugepagePrepare {
                pages,
                page_size_kib,
                ..
            } if pages
                .checked_mul(*page_size_kib)
                .is_none_or(|total_kib| total_kib > 1_073_741_824) =>
            {
                Err("requested huge page capacity exceeds one TiB safety limit")
            }
            Self::HugepageRelease { operation_id }
            | Self::SafeApplyConfirm { operation_id }
            | Self::SafeApplyRollback { operation_id } => non_empty(operation_id),
            _ => Ok(()),
        }
    }
}

/// Wire 上可接受的 request；caller identity 刻意不屬於此 schema。
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrivilegedWireRequest {
    /// 單次 request ID。
    pub request_id: String,
    /// 具副作用操作的冪等 ID。
    pub operation_id: String,
    /// Whitelist operation。
    pub operation: PrivilegedOperation,
    /// 不執行副作用，只回傳 plan。
    pub dry_run: bool,
}

impl PrivilegedWireRequest {
    /// 注入由 transport 驗證的 caller identity。
    #[must_use]
    pub fn authenticate(self, caller_identity: CallerIdentity) -> PrivilegedRequest {
        PrivilegedRequest {
            request_id: self.request_id,
            operation_id: self.operation_id,
            caller_identity,
            operation: self.operation,
            dry_run: self.dry_run,
        }
    }
}

/// 經 authentication 與 authorization 後才可執行的 helper request。
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct PrivilegedRequest {
    /// 單次 request ID。
    pub request_id: String,
    /// 具副作用操作的冪等 ID。
    pub operation_id: String,
    /// 經 IPC peer credential 填入的 caller，不得信任 wire payload 自稱的值。
    pub caller_identity: CallerIdentity,
    /// Whitelist operation。
    pub operation: PrivilegedOperation,
    /// 不執行副作用，只回傳 plan。
    pub dry_run: bool,
}

/// Helper 回應中的 stable structured error。
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivilegedError {
    /// Stable machine-readable error code。
    pub code: String,
    /// 不含 credential 或完整設定的訊息。
    pub message: String,
    /// 稍後重試是否可能成功。
    pub retryable: bool,
}

/// Helper 單一 request response。
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct PrivilegedResponse {
    /// 對應 request ID；frame 無法解析時可為空字串。
    pub request_id: String,
    /// 成功結果；錯誤時為空。
    pub result: Option<Value>,
    /// 結構化錯誤；成功時為空。
    pub error: Option<PrivilegedError>,
}

fn non_empty(value: &str) -> Result<(), &'static str> {
    if value.trim().is_empty()
        || value.len() > 256
        || value
            .chars()
            .any(|character| character == '\0' || character.is_control())
    {
        Err("required identifier is empty")
    } else {
        Ok(())
    }
}

fn validate_prefixes(prefixes: &[IpPrefix], ipv4: bool) -> Result<(), &'static str> {
    if prefixes.is_empty() || prefixes.len() > 16 {
        return Err("static address count must be between one and sixteen");
    }
    let mut unique = HashSet::with_capacity(prefixes.len());
    for prefix in prefixes {
        validate_prefix(prefix, ipv4)?;
        if !unique.insert((prefix.address, prefix.prefix_length)) {
            return Err("duplicate static address is not allowed");
        }
    }
    Ok(())
}

fn validate_prefix(prefix: &IpPrefix, ipv4: bool) -> Result<(), &'static str> {
    let family_matches = prefix.address.is_ipv4() == ipv4;
    let maximum = if ipv4 { 32 } else { 128 };
    if !family_matches || prefix.prefix_length > maximum || prefix.address.is_unspecified() {
        Err("IP prefix address family or length is invalid")
    } else {
        Ok(())
    }
}

fn valid_domain(domain: &str) -> bool {
    !domain.is_empty()
        && domain.len() <= 253
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn validate_wire_shape(value: &Value) -> Result<(), &'static str> {
    validate_keys(value, &["ipv4", "ipv6", "dns", "routes", "mtu"])?;
    let object = value.as_object().ok_or("network state must be an object")?;
    validate_ip_configuration(object.get("ipv4"), true)?;
    validate_ip_configuration(object.get("ipv6"), false)?;
    let dns = object.get("dns").ok_or("DNS configuration is required")?;
    validate_keys(dns, &["automatic", "servers", "search_domains"])?;
    let routes = object
        .get("routes")
        .and_then(Value::as_array)
        .ok_or("routes must be an array")?;
    for route in routes {
        validate_keys(route, &["destination", "gateway", "metric"])?;
        let destination = route
            .get("destination")
            .ok_or("route destination is required")?;
        validate_keys(destination, &["address", "prefix_length"])?;
    }
    Ok(())
}

fn validate_ip_configuration(value: Option<&Value>, ipv4: bool) -> Result<(), &'static str> {
    let value = value.ok_or("IP configuration is required")?;
    let object = value
        .as_object()
        .ok_or("IP configuration must be an object")?;
    let mode = object
        .get("mode")
        .and_then(Value::as_str)
        .ok_or("IP configuration mode is required")?;
    let static_mode = mode == "static";
    let allowed_mode = if ipv4 {
        matches!(mode, "dhcp" | "static" | "disabled")
    } else {
        matches!(mode, "automatic" | "static" | "disabled")
    };
    if !allowed_mode {
        return Err("IP configuration mode is invalid");
    }
    validate_keys(
        value,
        if static_mode {
            &["mode", "addresses"]
        } else {
            &["mode"]
        },
    )?;
    if static_mode {
        let addresses = object
            .get("addresses")
            .and_then(Value::as_array)
            .ok_or("static addresses must be an array")?;
        for address in addresses {
            validate_keys(address, &["address", "prefix_length"])?;
        }
    }
    Ok(())
}

fn validate_keys(value: &Value, allowed: &[&str]) -> Result<(), &'static str> {
    let object = value
        .as_object()
        .ok_or("configuration item must be an object")?;
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        Err("configuration contains an unknown field")
    } else {
        Ok(())
    }
}

fn validate_pci_address(value: &str) -> Result<(), &'static str> {
    let bytes = value.as_bytes();
    let valid = bytes.len() == 12
        && bytes[4] == b':'
        && bytes[7] == b':'
        && bytes[10] == b'.'
        && bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| matches!(index, 4 | 7 | 10) || byte.is_ascii_hexdigit());
    if valid {
        Ok(())
    } else {
        Err("PCI address must use dddd:bb:ss.f format")
    }
}

fn validate_hosts(profile_id: &str, entries: &[ManagedHostsEntry]) -> Result<(), &'static str> {
    if profile_id.is_empty()
        || !profile_id
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
    {
        return Err("hosts profile ID contains unsupported characters");
    }
    if entries.len() > 10_000 {
        return Err("managed hosts entry count exceeds limit");
    }
    for entry in entries {
        if entry.address.parse::<std::net::IpAddr>().is_err() {
            return Err("hosts entry address is invalid");
        }
        if entry.hostname.is_empty()
            || entry.hostname.len() > 253
            || !entry.hostname.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '-' | '.' | '_')
            })
        {
            return Err("hosts entry hostname is invalid");
        }
        if entry
            .comment
            .as_ref()
            .is_some_and(|comment| comment.contains(['\r', '\n']))
        {
            return Err("hosts entry comment contains a newline");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{NetworkDesiredState, PrivilegedOperation};
    use nettool_domain::{DnsConfiguration, Ipv4Configuration, Ipv6Configuration};

    fn desired_state() -> NetworkDesiredState {
        NetworkDesiredState {
            ipv4: Ipv4Configuration::Dhcp,
            ipv6: Ipv6Configuration::Automatic,
            dns: DnsConfiguration {
                automatic: true,
                servers: Vec::new(),
                search_domains: Vec::new(),
            },
            routes: Vec::new(),
            mtu: None,
        }
    }

    #[test]
    fn arbitrary_command_is_not_deserializable() {
        let payload = r#"{"name":"shell_execute","arguments":{"command":"id"}}"#;
        assert!(serde_json::from_str::<PrivilegedOperation>(payload).is_err());
    }

    #[test]
    fn validates_pci_address_and_timeout() {
        assert!(
            PrivilegedOperation::NicPrepareDpdk {
                pci_address: "0000:01:00.0".to_owned()
            }
            .validate()
            .is_ok()
        );
        assert!(
            PrivilegedOperation::NetworkApply {
                interface_id: "eth0".to_owned(),
                desired_state: desired_state(),
                confirm_timeout_seconds: 2
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn rejects_unknown_network_state_fields_and_invalid_family() {
        let unknown = r#"{
            "ipv4":{"mode":"dhcp","command":"id"},
            "ipv6":{"mode":"automatic"},
            "dns":{"automatic":true,"servers":[],"search_domains":[]},
            "routes":[],"mtu":1500
        }"#;
        assert!(serde_json::from_str::<NetworkDesiredState>(unknown).is_err());

        let invalid = r#"{
            "ipv4":{"mode":"static","addresses":[{"address":"2001:db8::1","prefix_length":64}]},
            "ipv6":{"mode":"automatic"},
            "dns":{"automatic":true,"servers":[],"search_domains":[]},
            "routes":[],"mtu":1500
        }"#;
        let invalid: NetworkDesiredState = serde_json::from_str(invalid).expect("known schema");
        assert!(invalid.validate().is_err());
    }
}

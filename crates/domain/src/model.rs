//! 設定、節點、session 與資源管理的核心資料模型。

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::net::IpAddr;

/// 已驗證為 JSON object 的 opaque domain payload。
///
/// Domain 不解讀 backend-specific keys，但不接受 scalar 或 array，避免未驗證的 JSON
/// 形狀穿透到 capability、session 與 benchmark profile 邊界。
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ValidatedJson(Value);

impl ValidatedJson {
    /// 從 JSON value 建立已驗證 payload。
    ///
    /// # Errors
    ///
    /// value 不是 JSON object 時回傳錯誤。
    pub fn try_from_value(value: Value) -> Result<Self, &'static str> {
        if value.is_object() {
            Ok(Self(value))
        } else {
            Err("validated JSON payload must be an object")
        }
    }

    /// 取得唯讀 JSON view；呼叫端不會取得可繞過驗證的 mutable value。
    #[must_use]
    pub fn as_value(&self) -> &Value {
        &self.0
    }

    /// 取出已驗證的 JSON value。
    #[must_use]
    pub fn into_value(self) -> Value {
        self.0
    }
}

impl<'de> Deserialize<'de> for ValidatedJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        Self::try_from_value(value).map_err(serde::de::Error::custom)
    }
}

macro_rules! string_id {
    ($name:ident, $documentation:literal) => {
        #[doc = $documentation]
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(pub String);

        impl $name {
            /// 建立由上層驗證唯一性的識別字。
            #[must_use]
            pub fn new(value: impl Into<String>) -> Self {
                Self(value.into())
            }
        }
    };
}

string_id!(ProfileId, "Network profile 的穩定識別字。");
string_id!(HostsProfileId, "Hosts profile 的穩定識別字。");
string_id!(NodeId, "遠端 Node 的穩定識別字。");
string_id!(SessionId, "測速或封包 session 的唯一識別字。");
string_id!(ReservationId, "硬體資源 reservation 的唯一識別字。");
string_id!(OperationId, "具副作用 operation 的冪等識別字。");

/// 跨平台網路介面識別字。
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InterfaceId {
    /// 平台。
    pub platform: String,
    /// 平台可持續辨識的 ID，不應只使用可變介面名稱。
    pub stable_id: String,
}

/// 網路介面目前可觀察的 metadata。
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Interface {
    /// 跨重啟識別字。
    pub id: InterfaceId,
    /// MAC address；平台無法取得時為空值。
    pub mac_address: Option<String>,
    /// UI 顯示名稱。
    pub friendly_name: Option<String>,
    /// 目前 OS 介面名稱。
    pub current_name: String,
    /// PCI 位址。
    pub pci_address: Option<String>,
    /// OS interface index。
    pub interface_index: Option<u32>,
}

/// Profile 選擇目標介面的條件。
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum InterfaceSelector {
    /// 精確 stable ID。
    StableId(InterfaceId),
    /// 精確 PCI address，適合 DPDK 專用 NIC。
    PciAddress(String),
    /// 精確 MAC address；介面替換後需重新確認。
    MacAddress(String),
}

/// IPv4 設定模式。
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum Ipv4Configuration {
    /// 由 DHCP 取得。
    Dhcp,
    /// 固定 IPv4 addresses。
    Static {
        /// 設定於介面的 IPv4 CIDR addresses。
        addresses: Vec<IpPrefix>,
    },
    /// 不設定 IPv4。
    Disabled,
}

/// IPv6 設定模式。
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum Ipv6Configuration {
    /// 使用平台自動設定。
    Automatic,
    /// 固定 IPv6 addresses。
    Static {
        /// 設定於介面的 IPv6 CIDR addresses。
        addresses: Vec<IpPrefix>,
    },
    /// 不設定 IPv6。
    Disabled,
}

/// CIDR address，prefix 長度由 validation layer 依 address family 檢查。
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IpPrefix {
    /// IP address。
    pub address: IpAddr,
    /// CIDR prefix length。
    pub prefix_length: u8,
}

/// DNS resolver 設定。
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DnsConfiguration {
    /// 是否沿用 DHCP 提供的 resolver。
    pub automatic: bool,
    /// 明確指定的 resolver addresses。
    pub servers: Vec<IpAddr>,
    /// 搜尋網域。
    pub search_domains: Vec<String>,
}

/// 靜態 route 設定。
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouteConfiguration {
    /// 目的網段。
    pub destination: IpPrefix,
    /// Next-hop gateway；on-link route 可為空值。
    pub gateway: Option<IpAddr>,
    /// Route metric。
    pub metric: Option<u32>,
}

/// Safe Apply 完成前的連線驗證方式。
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectivityPolicy {
    /// 只檢查介面與 address 狀態。
    LinkOnly,
    /// 探測指定 targets。
    Targets(Vec<IpAddr>),
    /// 隔離 Lab 明確停用連線探測；仍保留 rollback deadline。
    Disabled,
}

/// 網路設定變更的安全策略。
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SafetyPolicy {
    /// 是否要求 Safe Apply。
    pub safe_apply: bool,
    /// 未確認時自動 rollback 的秒數。
    pub confirm_timeout_seconds: u64,
    /// Apply 後的連線驗證策略。
    pub connectivity_check: ConnectivityPolicy,
}

impl Default for SafetyPolicy {
    fn default() -> Self {
        Self {
            safe_apply: true,
            confirm_timeout_seconds: 60,
            connectivity_check: ConnectivityPolicy::LinkOnly,
        }
    }
}

/// 可版本化保存的 network profile。
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NetworkProfile {
    /// Profile ID。
    pub id: ProfileId,
    /// 使用者顯示名稱。
    pub name: String,
    /// 目標介面條件。
    pub interface_selector: InterfaceSelector,
    /// IPv4 設定。
    pub ipv4: Ipv4Configuration,
    /// IPv6 設定。
    pub ipv6: Ipv6Configuration,
    /// DNS 設定。
    pub dns: DnsConfiguration,
    /// 靜態 routes。
    pub routes: Vec<RouteConfiguration>,
    /// MTU；空值代表不變更。
    pub mtu: Option<u32>,
    /// 套用後關聯的 hosts profile。
    pub hosts_profile: Option<HostsProfileId>,
    /// 變更安全策略。
    pub safety: SafetyPolicy,
}

/// Resource reservation 的生命週期。
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationState {
    /// 已建立但尚未取得全部資源。
    Pending,
    /// 資源已獨占，可啟動 session。
    Active,
    /// 正在釋放資源。
    Releasing,
    /// 資源已全部釋放。
    Released,
    /// Reservation 或釋放流程失敗。
    Failed,
}

/// 高速 session 專用硬體資源集合。
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResourceReservation {
    /// Reservation ID。
    pub id: ReservationId,
    /// 擁有此 reservation 的 session。
    pub session_id: SessionId,
    /// 獨占 NIC PCI addresses。
    pub nic_pci_addresses: Vec<String>,
    /// 獨占 queue IDs。
    pub queues: Vec<u16>,
    /// 綁定的 logical CPU IDs。
    pub cpus: Vec<u32>,
    /// Huge page bytes 配額。
    pub huge_page_bytes: u64,
    /// 目前狀態。
    pub state: ReservationState,
}

/// Hosts profile 中的單一可啟停 entry。
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HostsEntry {
    /// Entry ID。
    pub id: String,
    /// 是否寫入 managed section。
    pub enabled: bool,
    /// IPv4 或 IPv6 address。
    pub address: IpAddr,
    /// Hostname。
    pub hostname: String,
    /// 可選註解。
    pub comment: Option<String>,
    /// Profile 內穩定排序值。
    pub sort_order: i32,
}

/// 可獨立套用或由 network profile 關聯的 Hosts profile。
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HostsProfile {
    /// Profile ID。
    pub id: HostsProfileId,
    /// 顯示名稱。
    pub name: String,
    /// Managed entries。
    pub entries: Vec<HostsEntry>,
}

/// Node 可協商的獨立能力。
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Capability {
    /// Capability registry ID。
    pub id: String,
    /// Capability 自身版本。
    pub version: u32,
    /// 附加限制，例如 backend 或最大 stream 數。
    pub parameters: ValidatedJson,
}

/// 已發現或已配對的遠端 Node。
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Node {
    /// Persistent Node ID。
    pub id: NodeId,
    /// 顯示名稱。
    pub name: String,
    /// 最近使用的 control address。
    pub last_address: Option<String>,
    /// 最近一次協商的 capabilities。
    pub capabilities: Vec<Capability>,
}

/// Node identity 的信任狀態。
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustStatus {
    /// 尚未完成 pairing。
    Unpaired,
    /// Fingerprint 已由使用者確認。
    Trusted,
    /// 管理者已撤銷信任。
    Revoked,
    /// 相同 Node ID 出現不同 fingerprint，必須拒絕連線。
    IdentityChanged,
}

/// Persistent Node trust metadata；不包含 private key。
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NodeTrust {
    /// Node ID。
    pub node_id: NodeId,
    /// Certificate/public-key fingerprint。
    pub fingerprint: String,
    /// 目前信任狀態。
    pub status: TrustStatus,
    /// 首次確認信任的 epoch 秒數。
    pub trusted_at_unix_seconds: Option<u64>,
}

/// 所有長生命週期 session 共用的狀態。
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    /// 已建立但尚未取得資源。
    Created,
    /// 正在取得資源與進行 preflight。
    Preparing,
    /// 已就緒，等待同步開始。
    Ready,
    /// 正在執行。
    Running,
    /// 正在停止。
    Stopping,
    /// 正常完成。
    Completed,
    /// 已取消。
    Canceled,
    /// 發生不可恢復錯誤。
    Failed,
}

/// 通用 session metadata。
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Session {
    /// Session ID。
    pub id: SessionId,
    /// 狀態。
    pub state: SessionState,
    /// 建立時間 epoch 秒數。
    pub created_at_unix_seconds: u64,
    /// 關聯 reservation。
    pub reservation_id: Option<ReservationId>,
}

/// Speed protocol。
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SpeedProtocol {
    /// TCP stream throughput。
    Tcp,
    /// UDP datagram throughput、loss 與 jitter。
    Udp,
    /// Ethernet raw frame benchmark。
    Raw,
}

/// 測試方向。
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// Client 傳送至 server。
    Upload,
    /// Server 傳送至 client。
    Download,
    /// 雙向同時傳輸。
    Bidirectional,
}

/// Speed session 設定與結果索引。
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct SpeedSession {
    /// 通用 session metadata。
    pub session: Session,
    /// 遠端 Node ID。
    pub remote_node: Option<NodeId>,
    /// TCP、UDP 或 raw。
    pub protocol: SpeedProtocol,
    /// Backend registry ID。
    pub backend: String,
    /// 測試方向。
    pub direction: Direction,
    /// Stream 數。
    pub streams: u16,
    /// 測試完成後的 structured result。
    pub result: Option<ValidatedJson>,
}

/// Packet capture mode；預設必須為 `Off`。
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureMode {
    /// 不保存 packet payload。
    #[default]
    Off,
    /// 保存 header-only capture。
    Headers,
    /// 使用者明確啟動的 full packet capture。
    Full,
}

/// Packet analysis/capture session。
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct PacketSession {
    /// 通用 session metadata。
    pub session: Session,
    /// 介面 stable ID。
    pub interface_id: InterfaceId,
    /// Backend registry ID。
    pub backend: String,
    /// Capture mode。
    pub capture_mode: CaptureMode,
    /// 是否啟用即時 analysis。
    pub analysis_enabled: bool,
    /// Final drop counters。
    pub drops: DropCounters,
    /// 分析結果可信度。
    pub confidence: AnalysisConfidence,
}

/// 分類後的 packet drop counters。
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct DropCounters {
    /// NIC hardware drop。
    pub nic: u64,
    /// Capture writer drop。
    pub capture: u64,
    /// Ring overflow drop。
    pub ring: u64,
    /// Analyzer overload drop。
    pub analyzer: u64,
    /// 由 sequence gap 推論的 network loss。
    pub network_inferred_loss: u64,
}

/// Packet analysis 結果可信度。
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum AnalysisConfidence {
    /// Counter 完整且沒有影響分析的 drop。
    High,
    /// 有限度 sampling 或非關鍵資訊缺失。
    Medium,
    /// Drop 或資源壓力已顯著影響結果。
    Low,
    /// 結果不可用於判斷。
    Invalid,
}

/// 可重複 benchmark 的完整設定。
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct BenchmarkProfile {
    /// Profile registry ID。
    pub id: String,
    /// Frame sizes，包含認證所需的 64B、1518B 與 jumbo profiles。
    pub frame_sizes_bytes: Vec<u32>,
    /// Flow cardinalities。
    pub flow_counts: Vec<u64>,
    /// Warmup 秒數。
    pub warmup_seconds: u64,
    /// Measurement 秒數。
    pub measurement_seconds: u64,
    /// Backend-specific parameters。
    pub parameters: ValidatedJson,
}

/// 認證結果綁定的硬體與軟體環境。
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HardwareProfile {
    /// 作業系統與版本。
    pub os: String,
    /// Kernel/build。
    pub kernel: String,
    /// CPU model。
    pub cpu: String,
    /// NUMA topology description。
    pub numa: String,
    /// NIC model。
    pub nic: String,
    /// PCI address。
    pub pci_address: Option<String>,
    /// NIC firmware。
    pub firmware: Option<String>,
    /// Driver 與版本。
    pub driver: String,
    /// Backend 與版本。
    pub backend: String,
}

/// Operation persistence model。
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Operation {
    /// Operation ID。
    pub id: OperationId,
    /// Action registry name。
    pub action: String,
    /// Stable state identifier。
    pub state: String,
    /// Stable error code。
    pub error_code: Option<String>,
}

/// 不含敏感資料的 audit record。
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuditRecord {
    /// Operation ID。
    pub operation_id: Option<OperationId>,
    /// Action name。
    pub action: String,
    /// Target stable ID。
    pub target: Option<String>,
    /// 套用前 state hash。
    pub old_state_hash: Option<String>,
    /// 套用後 state hash。
    pub new_state_hash: Option<String>,
    /// 經驗證的 caller principal。
    pub caller: String,
    /// Stable result identifier。
    pub result: String,
}

#[cfg(test)]
mod tests {
    use super::{SafetyPolicy, ValidatedJson};
    use serde_json::json;

    #[test]
    fn safe_apply_is_enabled_by_default() {
        let policy = SafetyPolicy::default();
        assert!(policy.safe_apply);
        assert!(policy.confirm_timeout_seconds > 0);
    }

    #[test]
    fn validated_json_rejects_non_object_payloads() {
        assert!(ValidatedJson::try_from_value(json!({"backend":"socket"})).is_ok());
        assert!(ValidatedJson::try_from_value(json!(null)).is_err());
        assert!(serde_json::from_value::<ValidatedJson>(json!(["not-an-object"])).is_err());
    }
}

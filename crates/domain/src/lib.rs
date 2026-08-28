//! 與平台及傳輸層無關的核心領域模型。

#![forbid(unsafe_code)]

mod model;

pub use model::*;

/// 執行程式所在的平台。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Platform {
    /// Linux。
    Linux,
    /// macOS。
    MacOs,
    /// Windows。
    Windows,
    /// 尚未支援的平台。
    Unknown,
}

/// 網路介面可由平台證據判定的硬體匯流排分類；目前 Linux 提供實際分類。
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NicBusType {
    /// USB 網路介面。
    Usb,
    /// PCI 網路介面。
    Pci,
    /// 缺少足夠 sysfs 證據，或路徑格式不合法。
    Unknown,
}

impl NicBusType {
    /// 回傳供 CLI 與 JSON 合約使用的穩定英文識別字。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Usb => "usb",
            Self::Pci => "pci",
            Self::Unknown => "unknown",
        }
    }
}

impl Platform {
    /// 回傳供 CLI 與 JSON 合約使用的穩定英文識別字。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::MacOs => "macos",
            Self::Windows => "windows",
            Self::Unknown => "unknown",
        }
    }
}

/// 單一網路介面的環境探測結果。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NicProbe {
    /// 作業系統介面名稱。
    pub name: String,
    /// 目前由作業系統指派的 IP 位址；保留 Windows IPv6 scope suffix，無法取得時為空陣列。
    pub ip_addresses: Vec<String>,
    /// PCI BDF；非 PCI 或無法驗證時為空值。
    pub pci_address: Option<String>,
    /// 由 sysfs 路徑判定的硬體匯流排；無法安全判定時為未知。
    pub bus_type: NicBusType,
    /// 目前驅動程式名稱；無法判斷時為空值。
    pub driver: Option<String>,
    /// 連線速率，單位為 Mbps。
    pub link_speed_mbps: Option<u64>,
    /// 可用 RX queue 數；無法判斷時為空值。
    pub rx_queues: Option<u32>,
    /// 可用 TX queue 數；無法判斷時為空值。
    pub tx_queues: Option<u32>,
    /// 介面所屬 NUMA node；未知時為空值。
    pub numa_node: Option<i32>,
}

/// P0 環境探測的完整快照。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeReport {
    /// Schema 版本，供機器端相容性判斷。
    pub schema_version: &'static str,
    /// 執行平台。
    pub platform: Platform,
    /// 可供程式使用的邏輯 CPU 數。
    pub logical_cpus: usize,
    /// 系統回報的 NUMA node 數。
    pub numa_nodes: Option<u32>,
    /// Huge page 總數。
    pub huge_pages_total: Option<u64>,
    /// Huge page 空閒數。
    pub huge_pages_free: Option<u64>,
    /// Huge page 大小，單位為 KiB。
    pub huge_page_size_kib: Option<u64>,
    /// 找到的網路介面。
    pub nics: Vec<NicProbe>,
    /// 系統是否具備可探測到的 DPDK runtime。
    pub dpdk_capable: bool,
    /// 系統是否具備 `AF_XDP` 的基本核心介面。
    pub af_xdp_capable: bool,
    /// 是否有證據證明目標介面支援 `AF_XDP` zero-copy；未知或未驗證時為 false。
    pub af_xdp_zero_copy_capable: bool,
    /// 無法取得部分資訊時的非致命警告。
    pub warnings: Vec<String>,
}

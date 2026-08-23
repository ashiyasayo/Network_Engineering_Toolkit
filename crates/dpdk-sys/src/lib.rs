//! 集中 `NetTool` 所需的原始 DPDK C ABI；上層不得直接依賴此 crate。

#![allow(unsafe_code)]

use core::ffi::c_void;
#[cfg(feature = "ffi-api")]
use core::ffi::{c_char, c_int, c_uint};

/// Opaque `rte_mempool` handle。
#[repr(C)]
pub struct RteMempool {
    _private: [u8; 0],
}

/// Opaque `rte_mbuf` handle。
#[repr(C)]
pub struct RteMbuf {
    _private: [u8; 0],
}

/// C shim 可回傳的 RX packet metadata。
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RxPacket {
    /// Mbuf ownership；burst 完成後必須釋放。
    pub mbuf: *mut RteMbuf,
    /// 第一個 segment 的 packet bytes。
    pub data: *const u8,
    /// 可見 bytes 長度。
    pub data_len: u32,
    /// 原始 packet 長度。
    pub packet_len: u32,
    /// RSS hash，無效時為零。
    pub rss_hash: u32,
    /// DPDK offload flags。
    pub offload_flags: u64,
}

/// Stable subset of `rte_eth_stats` returned by the C shim.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct PortStats {
    /// Received packets.
    pub ipackets: u64,
    /// Transmitted packets.
    pub opackets: u64,
    /// Received bytes.
    pub ibytes: u64,
    /// Transmitted bytes.
    pub obytes: u64,
    /// Hardware missed packets.
    pub imissed: u64,
    /// Receive errors.
    pub ierrors: u64,
    /// Transmit errors.
    pub oerrors: u64,
    /// Mbuf allocation failures on RX.
    pub rx_nombuf: u64,
}

#[cfg(feature = "ffi-api")]
unsafe extern "C" {
    /// 初始化 EAL。
    pub fn nt_dpdk_eal_init(argc: c_int, argv: *mut *mut c_char) -> c_int;
    /// 清理 EAL。
    pub fn nt_dpdk_eal_cleanup() -> c_int;
    /// 可用 Ethernet port 數量。
    pub fn nt_dpdk_port_count() -> u16;
    /// 以 DPDK device name（例如 PCI address）解析 port ID。
    pub fn nt_dpdk_port_by_name(name: *const c_char, port_id: *mut u16) -> c_int;
    /// 建立 packet mbuf pool。
    pub fn nt_dpdk_mempool_create(
        name: *const c_char,
        count: c_uint,
        cache_size: c_uint,
        data_room_size: u16,
        socket_id: c_int,
    ) -> *mut RteMempool;
    /// 釋放 mempool。
    pub fn nt_dpdk_mempool_free(pool: *mut RteMempool);
    /// 配置 port 與所有 RX/TX queues。
    pub fn nt_dpdk_port_configure(
        port_id: u16,
        rx_queues: u16,
        tx_queues: u16,
        rx_descriptors: u16,
        tx_descriptors: u16,
        pool: *mut RteMempool,
        socket_id: c_uint,
    ) -> c_int;
    /// 啟動 port。
    pub fn nt_dpdk_port_start(port_id: u16) -> c_int;
    /// 停止並關閉 port。
    pub fn nt_dpdk_port_stop_close(port_id: u16);
    /// 取得一個 RX burst，回傳 packet 數量。
    pub fn nt_dpdk_rx_burst(
        port_id: u16,
        queue_id: u16,
        packets: *mut RxPacket,
        capacity: u16,
    ) -> u16;
    /// 從既有 mempool 配置固定 template mbufs 並送出一個 TX burst。
    pub fn nt_dpdk_tx_template_burst(
        port_id: u16,
        queue_id: u16,
        pool: *mut RteMempool,
        data: *const u8,
        data_length: u16,
        count: u16,
    ) -> c_int;
    /// 讀取目前 port hardware counters。
    pub fn nt_dpdk_port_stats_get(port_id: u16, stats: *mut PortStats) -> c_int;
    /// 讀取 DPDK xstats；回傳值為實際項目數，capacity 不足時不寫入資料。
    pub fn nt_dpdk_port_xstats_get(
        port_id: u16,
        names: *mut c_char,
        name_width: c_uint,
        values: *mut u64,
        capacity: c_uint,
    ) -> c_int;
    /// 釋放單一 RX mbuf。
    pub fn nt_dpdk_mbuf_free(mbuf: *mut RteMbuf);
    /// 回傳 `rte_errno` 正值。
    pub fn nt_dpdk_errno() -> c_int;
    /// 將 DPDK error number 轉為 static message。
    pub fn nt_dpdk_strerror(error: c_int) -> *const c_char;
}

/// 讓 opaque FFI declarations 保留 `c_void` ABI dependency，避免 bindings 漂移時誤改。
pub type OpaquePointer = *mut c_void;

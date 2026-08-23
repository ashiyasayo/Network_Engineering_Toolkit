//! DPDK EAL、mempool、port 與 queue 的生命週期安全封裝。

#![allow(unsafe_code)]

#[cfg(not(feature = "ffi-api"))]
use nettool_error::{ErrorCode, NetToolError};
#[cfg(any(test, feature = "ffi-api"))]
use std::cell::RefCell;
#[cfg(any(test, feature = "ffi-api"))]
use std::collections::BTreeSet;

#[cfg(any(test, feature = "ffi-api"))]
#[derive(Default)]
struct QueueOwnership {
    owned: RefCell<BTreeSet<u16>>,
}

#[cfg(any(test, feature = "ffi-api"))]
impl QueueOwnership {
    fn claim(&self, queue_id: u16) -> bool {
        self.owned.borrow_mut().insert(queue_id)
    }

    fn release(&self, queue_id: u16) {
        self.owned.borrow_mut().remove(&queue_id);
    }
}

/// 此 build 是否真正連結 DPDK SDK 與 C shim。
#[must_use]
pub const fn is_native_dpdk_built() -> bool {
    cfg!(feature = "native-dpdk")
}

/// RX packet 的 DPDK metadata；packet bytes 只在 callback 期間有效。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketMetadata {
    /// 原始 packet 長度，可能大於第一個 mbuf segment。
    pub packet_length: u32,
    /// 目前提供給 callback 的連續 bytes 長度。
    pub captured_length: u32,
    /// RX queue ID。
    pub queue_id: u16,
    /// RSS hash。
    pub rss_hash: u32,
    /// 原始 DPDK offload flags。
    pub offload_flags: u64,
}

/// 只在 RX callback 期間借用 mbuf memory 的 packet view。
#[derive(Clone, Copy)]
pub struct PacketView<'a> {
    /// 第一個 mbuf segment 的連續 bytes；不進行額外 copy。
    pub bytes: &'a [u8],
    /// Packet metadata。
    pub metadata: PacketMetadata,
}

/// Mempool 建立參數。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MempoolConfiguration {
    /// DPDK 全域唯一 pool name。
    pub name: String,
    /// Mbuf 數量。
    pub count: u32,
    /// Per-lcore cache size；可為零。
    pub cache_size: u32,
    /// 每個 mbuf data room bytes。
    pub data_room_size: u16,
    /// NUMA socket ID。
    pub socket_id: i32,
}

/// Port/queue 建立參數。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortConfiguration {
    /// DPDK port ID。
    pub port_id: u16,
    /// RX queues。
    pub rx_queues: u16,
    /// TX queues。
    pub tx_queues: u16,
    /// 每個 RX queue descriptor 數。
    pub rx_descriptors: u16,
    /// 每個 TX queue descriptor 數。
    pub tx_descriptors: u16,
    /// NUMA socket ID。
    pub socket_id: u32,
}

/// Native DPDK hardware counters snapshot。
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PortStats {
    /// Received packets。
    pub received_packets: u64,
    /// Transmitted packets。
    pub transmitted_packets: u64,
    /// Received bytes。
    pub received_bytes: u64,
    /// Transmitted bytes。
    pub transmitted_bytes: u64,
    /// Hardware missed packets。
    pub missed_packets: u64,
    /// Receive errors。
    pub receive_errors: u64,
    /// Transmit errors。
    pub transmit_errors: u64,
    /// RX mbuf allocation failures。
    pub rx_mbuf_failures: u64,
}

/// DPDK driver-specific hardware extended statistic。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XStat {
    /// PMD 提供的 stable statistic name，例如 `rx_q0_packets`。
    pub name: String,
    /// 目前 counter value。
    pub value: u64,
}

#[cfg(feature = "ffi-api")]
mod native {
    use super::{
        MempoolConfiguration, PacketMetadata, PacketView, PortConfiguration, PortStats,
        QueueOwnership, XStat,
    };
    use core::ptr;
    use nettool_dpdk_sys as sys;
    use nettool_error::{ErrorCode, NetToolError};
    use std::ffi::{CStr, CString};
    use std::marker::PhantomData;
    use std::rc::Rc;
    use std::sync::atomic::{AtomicBool, Ordering};

    const MAX_BURST: usize = 256;
    const XSTAT_NAME_WIDTH: usize = 128;
    const XSTAT_NAME_WIDTH_U32: u32 = 128;
    static EAL_OWNED: AtomicBool = AtomicBool::new(false);

    /// Process-global DPDK EAL ownership handle。
    pub struct Environment {
        _not_send_or_sync: PhantomData<Rc<()>>,
    }

    impl Environment {
        /// 初始化 process-global EAL；同一 process 同時只允許一個 owner。
        ///
        /// # Errors
        ///
        /// Arguments 含 NUL、EAL 已初始化或 DPDK 初始化失敗時回傳錯誤。
        pub fn initialize(arguments: &[String]) -> Result<Self, NetToolError> {
            if EAL_OWNED
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                return Err(error("DPDK EAL is already owned by this process"));
            }
            let strings = arguments
                .iter()
                .map(|value| CString::new(value.as_str()))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| error("DPDK EAL argument contains NUL"));
            let strings = match strings {
                Ok(strings) => strings,
                Err(failure) => {
                    EAL_OWNED.store(false, Ordering::Release);
                    return Err(failure);
                }
            };
            let mut pointers = strings
                .iter()
                .map(|value| value.as_ptr().cast_mut())
                .collect::<Vec<_>>();
            let argc = i32::try_from(pointers.len()).map_err(|_| {
                EAL_OWNED.store(false, Ordering::Release);
                error("too many DPDK EAL arguments")
            })?;
            // SAFETY: CString storage remains alive for the call and argv has argc entries.
            let result = unsafe { sys::nt_dpdk_eal_init(argc, pointers.as_mut_ptr()) };
            if result < 0 {
                EAL_OWNED.store(false, Ordering::Release);
                return Err(last_error("DPDK EAL initialization failed"));
            }
            Ok(Self {
                _not_send_or_sync: PhantomData,
            })
        }

        /// 目前可用 Ethernet ports 數量。
        #[must_use]
        pub fn port_count(&self) -> u16 {
            // SAFETY: A live Environment proves EAL initialization.
            unsafe { sys::nt_dpdk_port_count() }
        }

        /// 以 DPDK device name（通常是 PCI address）解析 port ID。
        ///
        /// # Errors
        ///
        /// Name 為空、含 NUL 或 DPDK 找不到裝置時回傳錯誤。
        pub fn port_by_name(&self, name: &str) -> Result<u16, NetToolError> {
            if name.is_empty() {
                return Err(error("DPDK device name must not be empty"));
            }
            let name = CString::new(name).map_err(|_| error("DPDK device name contains NUL"))?;
            let mut port_id = 0_u16;
            // SAFETY: Name is NUL-terminated and port_id is a valid writable pointer.
            let result = unsafe { sys::nt_dpdk_port_by_name(name.as_ptr(), &raw mut port_id) };
            if result < 0 {
                return Err(dpdk_result("DPDK device lookup failed", result));
            }
            Ok(port_id)
        }

        /// 在指定 NUMA socket 建立 mbuf pool。
        ///
        /// # Errors
        ///
        /// Configuration 無效、名稱含 NUL 或 DPDK allocation 失敗時回傳錯誤。
        pub fn create_mempool(
            &self,
            configuration: &MempoolConfiguration,
        ) -> Result<Mempool<'_>, NetToolError> {
            validate_mempool(configuration)?;
            let name = CString::new(configuration.name.as_str())
                .map_err(|_| error("DPDK mempool name contains NUL"))?;
            // SAFETY: Validated scalar arguments and a live EAL owner are provided.
            let raw = unsafe {
                sys::nt_dpdk_mempool_create(
                    name.as_ptr(),
                    configuration.count,
                    configuration.cache_size,
                    configuration.data_room_size,
                    configuration.socket_id,
                )
            };
            if raw.is_null() {
                return Err(last_error("DPDK mempool creation failed"));
            }
            Ok(Mempool {
                raw,
                _environment: PhantomData,
                _not_send_or_sync: PhantomData,
            })
        }
    }

    impl Drop for Environment {
        fn drop(&mut self) {
            // SAFETY: This handle exclusively owns the initialized EAL.
            let _ = unsafe { sys::nt_dpdk_eal_cleanup() };
            EAL_OWNED.store(false, Ordering::Release);
        }
    }

    /// NUMA-local packet mbuf pool。
    pub struct Mempool<'environment> {
        raw: *mut sys::RteMempool,
        _environment: PhantomData<&'environment Environment>,
        _not_send_or_sync: PhantomData<Rc<()>>,
    }

    impl Mempool<'_> {
        /// 配置但尚未啟動 Ethernet port。
        ///
        /// # Errors
        ///
        /// Queue/descriptor 設定無效或 PMD 拒絕配置時回傳錯誤。
        pub fn configure_port(
            &self,
            configuration: PortConfiguration,
        ) -> Result<Port<'_, '_>, NetToolError> {
            validate_port(configuration)?;
            // SAFETY: Pool is live and configuration was validated; shim configures all queues.
            let result = unsafe {
                sys::nt_dpdk_port_configure(
                    configuration.port_id,
                    configuration.rx_queues,
                    configuration.tx_queues,
                    configuration.rx_descriptors,
                    configuration.tx_descriptors,
                    self.raw,
                    configuration.socket_id,
                )
            };
            if result < 0 {
                return Err(dpdk_result("DPDK port configuration failed", result));
            }
            Ok(Port {
                configuration,
                started: false,
                owned_rx_queues: QueueOwnership::default(),
                owned_tx_queues: QueueOwnership::default(),
                _pool: PhantomData,
                _not_send_or_sync: PhantomData,
            })
        }
    }

    impl Drop for Mempool<'_> {
        fn drop(&mut self) {
            // SAFETY: Lifetime prevents live Port/RxQueue handles when pool is dropped.
            unsafe { sys::nt_dpdk_mempool_free(self.raw) };
        }
    }

    /// Configured DPDK Ethernet port；Drop 會停止並關閉裝置。
    pub struct Port<'pool, 'environment> {
        configuration: PortConfiguration,
        started: bool,
        owned_rx_queues: QueueOwnership,
        owned_tx_queues: QueueOwnership,
        _pool: PhantomData<&'pool Mempool<'environment>>,
        _not_send_or_sync: PhantomData<Rc<()>>,
    }

    impl Port<'_, '_> {
        /// 讀取 PMD 提供的 hardware counters。
        ///
        /// # Errors
        ///
        /// Port 尚未啟動或 PMD counter query 失敗時回傳錯誤。
        pub fn stats(&self) -> Result<PortStats, NetToolError> {
            if !self.started {
                return Err(error("DPDK port must be started before reading statistics"));
            }
            let mut stats = sys::PortStats::default();
            // SAFETY: stats is a valid writable repr(C) buffer and port ID was configured.
            let result =
                unsafe { sys::nt_dpdk_port_stats_get(self.configuration.port_id, &raw mut stats) };
            if result < 0 {
                return Err(dpdk_result("DPDK port statistics query failed", result));
            }
            Ok(PortStats {
                received_packets: stats.ipackets,
                transmitted_packets: stats.opackets,
                received_bytes: stats.ibytes,
                transmitted_bytes: stats.obytes,
                missed_packets: stats.imissed,
                receive_errors: stats.ierrors,
                transmit_errors: stats.oerrors,
                rx_mbuf_failures: stats.rx_nombuf,
            })
        }

        /// 讀取 PMD 提供的 extended statistics，包含 per-queue counters。
        ///
        /// 名稱由 shim 在 bounded buffer 內複製；Rust fast path 不會以名稱查詢
        /// counter，因此呼叫端可在控制面快取名稱與順序。
        ///
        /// # Errors
        ///
        /// Port 尚未啟動、xstats 數量溢位、名稱 buffer 無法配置或 PMD query 失敗時回傳錯誤。
        pub fn xstats(&self) -> Result<Vec<XStat>, NetToolError> {
            if !self.started {
                return Err(error("DPDK port must be started before reading xstats"));
            }
            let count = unsafe {
                sys::nt_dpdk_port_xstats_get(
                    self.configuration.port_id,
                    ptr::null_mut(),
                    XSTAT_NAME_WIDTH_U32,
                    ptr::null_mut(),
                    0,
                )
            };
            if count < 0 {
                return Err(dpdk_result("DPDK xstats count query failed", count));
            }
            let count = usize::try_from(count).map_err(|_| error("DPDK xstats count overflow"))?;
            if count == 0 {
                return Ok(Vec::new());
            }
            let mut names = vec![0_u8; count.saturating_mul(XSTAT_NAME_WIDTH)];
            let mut values = vec![0_u64; count];
            let measured = unsafe {
                sys::nt_dpdk_port_xstats_get(
                    self.configuration.port_id,
                    names.as_mut_ptr().cast(),
                    XSTAT_NAME_WIDTH_U32,
                    values.as_mut_ptr(),
                    u32::try_from(count).map_err(|_| error("DPDK xstats count exceeds ABI"))?,
                )
            };
            if measured < 0 {
                return Err(dpdk_result("DPDK xstats query failed", measured));
            }
            let measured =
                usize::try_from(measured).map_err(|_| error("DPDK xstats count overflow"))?;
            if measured != count {
                return Err(error("DPDK xstats count changed during query"));
            }
            names
                .chunks_exact(XSTAT_NAME_WIDTH)
                .zip(values)
                .map(|(name, value)| {
                    let end = name
                        .iter()
                        .position(|byte| *byte == 0)
                        .unwrap_or(XSTAT_NAME_WIDTH);
                    let name = String::from_utf8(name[..end].to_vec())
                        .map_err(|_| error("DPDK xstats name is not valid UTF-8"))?;
                    if name.is_empty() {
                        return Err(error("DPDK xstats name is empty"));
                    }
                    Ok(XStat { name, value })
                })
                .collect()
        }

        /// 啟動 PMD port。
        ///
        /// # Errors
        ///
        /// Port 已啟動或 PMD start 失敗時回傳錯誤。
        pub fn start(&mut self) -> Result<(), NetToolError> {
            if self.started {
                return Err(error("DPDK port is already started"));
            }
            // SAFETY: Port was configured successfully and is not started.
            let result = unsafe { sys::nt_dpdk_port_start(self.configuration.port_id) };
            if result < 0 {
                return Err(dpdk_result("DPDK port start failed", result));
            }
            self.started = true;
            Ok(())
        }

        /// 建立指定 RX queue 的唯一 polling handle。
        ///
        /// # Errors
        ///
        /// Port 未啟動、queue 越界或 burst capacity 無效時回傳錯誤。
        pub fn rx_queue(
            &self,
            queue_id: u16,
            burst_capacity: u16,
        ) -> Result<RxQueue<'_>, NetToolError> {
            if !self.started {
                return Err(error(
                    "DPDK port must be started before creating an RX queue",
                ));
            }
            if queue_id >= self.configuration.rx_queues {
                return Err(error("DPDK RX queue ID is out of range"));
            }
            if burst_capacity == 0 || usize::from(burst_capacity) > MAX_BURST {
                return Err(error("DPDK burst capacity must be between 1 and 256"));
            }
            let packets = vec![empty_packet(); usize::from(burst_capacity)];
            if !self.owned_rx_queues.claim(queue_id) {
                return Err(error("DPDK RX queue already has an owner"));
            }
            Ok(RxQueue {
                port_id: self.configuration.port_id,
                queue_id,
                packets,
                ownership: &self.owned_rx_queues,
                _port: PhantomData,
                _not_send_or_sync: PhantomData,
            })
        }

        /// 建立指定 TX queue 的唯一 worker-local handle。
        ///
        /// # Errors
        ///
        /// Port 未啟動、queue 越界或 queue 已由另一 handle 擁有時回傳錯誤。
        pub fn tx_queue<'port, 'environment>(
            &'port self,
            queue_id: u16,
            pool: &'port Mempool<'environment>,
        ) -> Result<TxQueue<'port, 'environment>, NetToolError> {
            if !self.started {
                return Err(error(
                    "DPDK port must be started before creating a TX queue",
                ));
            }
            if queue_id >= self.configuration.tx_queues {
                return Err(error("DPDK TX queue ID is out of range"));
            }
            if !self.owned_tx_queues.claim(queue_id) {
                return Err(error("DPDK TX queue already has an owner"));
            }
            Ok(TxQueue {
                port_id: self.configuration.port_id,
                queue_id,
                pool,
                ownership: &self.owned_tx_queues,
                _not_send_or_sync: PhantomData,
            })
        }
    }

    impl Drop for Port<'_, '_> {
        fn drop(&mut self) {
            // SAFETY: Lifetime prevents live RxQueue handles and this Port owns close.
            unsafe { sys::nt_dpdk_port_stop_close(self.configuration.port_id) };
        }
    }

    /// 單一 RX queue 的唯一 worker-local polling handle。
    pub struct RxQueue<'port> {
        port_id: u16,
        queue_id: u16,
        packets: Vec<sys::RxPacket>,
        ownership: &'port QueueOwnership,
        _port: PhantomData<&'port Port<'port, 'port>>,
        _not_send_or_sync: PhantomData<Rc<()>>,
    }

    impl Drop for RxQueue<'_> {
        fn drop(&mut self) {
            self.ownership.release(self.queue_id);
        }
    }

    /// 單一 TX queue 的唯一 worker-local handle。
    pub struct TxQueue<'port, 'environment> {
        port_id: u16,
        queue_id: u16,
        pool: &'port Mempool<'environment>,
        ownership: &'port QueueOwnership,
        _not_send_or_sync: PhantomData<Rc<()>>,
    }

    impl TxQueue<'_, '_> {
        /// 從預配置 mempool 建立固定 template burst，送出後回報實際接受數量。
        ///
        /// 未被 PMD 接受的 mbufs 由 C shim 立即回收，不轉移給 caller。
        ///
        /// # Errors
        ///
        /// Template 為空或過長、count 超出 1..=256，或 mbuf/PMD 失敗時回傳錯誤。
        pub fn send_template_burst(
            &mut self,
            template: &[u8],
            count: u16,
        ) -> Result<u16, NetToolError> {
            let data_length = u16::try_from(template.len())
                .map_err(|_| error("DPDK TX template exceeds u16 length"))?;
            if data_length == 0 || count == 0 || usize::from(count) > MAX_BURST {
                return Err(error("DPDK TX template/count is invalid"));
            }
            // SAFETY: Template is readable for data_length, pool/port are live, and shim owns
            // every allocated mbuf until sent or explicitly freed.
            let result = unsafe {
                sys::nt_dpdk_tx_template_burst(
                    self.port_id,
                    self.queue_id,
                    self.pool.raw,
                    template.as_ptr(),
                    data_length,
                    count,
                )
            };
            if result < 0 {
                return Err(dpdk_result("DPDK TX burst failed", result));
            }
            u16::try_from(result).map_err(|_| error("DPDK TX result exceeds u16 capacity"))
        }
    }

    impl Drop for TxQueue<'_, '_> {
        fn drop(&mut self) {
            self.ownership.release(self.queue_id);
        }
    }

    impl RxQueue<'_> {
        /// Poll 一個 burst，逐 packet 借用 mbuf memory 並在 callback 後立即釋放。
        ///
        /// # Errors
        ///
        /// Backend 回傳超出預配置容量或無效 pointer/length 時回傳錯誤。
        pub fn receive_burst(
            &mut self,
            mut consumer: impl FnMut(PacketView<'_>),
        ) -> Result<usize, NetToolError> {
            let capacity = u16::try_from(self.packets.len())
                .map_err(|_| error("DPDK burst capacity overflow"))?;
            // SAFETY: packets has capacity initialized entries and queue lifetime proves live port.
            let received = unsafe {
                sys::nt_dpdk_rx_burst(
                    self.port_id,
                    self.queue_id,
                    self.packets.as_mut_ptr(),
                    capacity,
                )
            };
            if received > capacity {
                return Err(error("DPDK RX burst exceeded configured capacity"));
            }
            let burst = BurstGuard {
                packets: &mut self.packets[..usize::from(received)],
            };
            for index in 0..burst.packets.len() {
                let packet = burst.packets[index];
                if packet.mbuf.is_null()
                    || (packet.data.is_null() && packet.data_len != 0)
                    || packet.data_len > packet.packet_len
                {
                    return Err(error("DPDK RX burst returned invalid packet metadata"));
                }
                // SAFETY: PMD owns a live mbuf and guarantees data_len readable bytes until free.
                let bytes =
                    unsafe { core::slice::from_raw_parts(packet.data, packet.data_len as usize) };
                consumer(PacketView {
                    bytes,
                    metadata: PacketMetadata {
                        packet_length: packet.packet_len,
                        captured_length: packet.data_len,
                        queue_id: self.queue_id,
                        rss_hash: packet.rss_hash,
                        offload_flags: packet.offload_flags,
                    },
                });
                // SAFETY: This entry still owns exactly one received mbuf.
                unsafe { sys::nt_dpdk_mbuf_free(packet.mbuf) };
                burst.packets[index] = empty_packet();
            }
            Ok(usize::from(received))
        }
    }

    struct BurstGuard<'a> {
        packets: &'a mut [sys::RxPacket],
    }

    impl Drop for BurstGuard<'_> {
        fn drop(&mut self) {
            for packet in self.packets.iter_mut() {
                if !packet.mbuf.is_null() {
                    // SAFETY: Non-null entries are unconsumed mbufs owned by this burst.
                    unsafe { sys::nt_dpdk_mbuf_free(packet.mbuf) };
                    *packet = empty_packet();
                }
            }
        }
    }

    const fn empty_packet() -> sys::RxPacket {
        sys::RxPacket {
            mbuf: ptr::null_mut(),
            data: ptr::null(),
            data_len: 0,
            packet_len: 0,
            rss_hash: 0,
            offload_flags: 0,
        }
    }

    fn validate_mempool(configuration: &MempoolConfiguration) -> Result<(), NetToolError> {
        if configuration.name.is_empty()
            || configuration.count == 0
            || configuration.data_room_size == 0
            || configuration.cache_size >= configuration.count
            || configuration.socket_id < 0
        {
            return Err(error("invalid DPDK mempool configuration"));
        }
        Ok(())
    }

    fn validate_port(configuration: PortConfiguration) -> Result<(), NetToolError> {
        if configuration.rx_queues == 0
            || configuration.tx_queues == 0
            || configuration.rx_descriptors == 0
            || configuration.tx_descriptors == 0
        {
            return Err(error("invalid DPDK port configuration"));
        }
        Ok(())
    }

    fn dpdk_result(context: &str, result: i32) -> NetToolError {
        let code = result.checked_neg().unwrap_or(result);
        message_for_code(context, code)
    }

    fn last_error(context: &str) -> NetToolError {
        // SAFETY: Reading process-local rte_errno has no pointer preconditions.
        let code = unsafe { sys::nt_dpdk_errno() };
        message_for_code(context, code)
    }

    fn message_for_code(context: &str, code: i32) -> NetToolError {
        // SAFETY: DPDK returns a process-lifetime NUL-terminated static string.
        let pointer = unsafe { sys::nt_dpdk_strerror(code) };
        let detail = if pointer.is_null() {
            "unknown DPDK error".to_owned()
        } else {
            // SAFETY: Non-null result from rte_strerror is NUL-terminated.
            unsafe { CStr::from_ptr(pointer) }
                .to_string_lossy()
                .into_owned()
        };
        NetToolError::new(
            ErrorCode::PreflightFailed,
            format!("{context}: {detail} (errno {code})"),
            false,
        )
    }

    fn error(message: impl Into<String>) -> NetToolError {
        NetToolError::new(ErrorCode::InvalidArgument, message, false)
    }
}

#[cfg(feature = "ffi-api")]
pub use native::{Environment, Mempool, Port, RxQueue, TxQueue};

/// 在未連結 native DPDK 的 build 回傳穩定、不可誤認為 runtime failure 的錯誤。
#[cfg(not(feature = "ffi-api"))]
#[must_use]
pub fn backend_not_built() -> NetToolError {
    NetToolError::new(
        ErrorCode::BackendNotBuilt,
        "DPDK support requires a build with the native-dpdk feature and libdpdk SDK",
        false,
    )
}

#[cfg(test)]
mod tests {
    use super::QueueOwnership;
    #[cfg(not(feature = "ffi-api"))]
    use super::is_native_dpdk_built;

    #[test]
    fn queue_ownership_is_exclusive_until_release() {
        let ownership = QueueOwnership::default();
        assert!(ownership.claim(3));
        assert!(!ownership.claim(3));
        ownership.release(3);
        assert!(ownership.claim(3));
    }

    #[cfg(not(feature = "ffi-api"))]
    #[test]
    fn default_build_does_not_claim_native_dpdk() {
        assert!(!is_native_dpdk_built());
        assert_eq!(
            super::backend_not_built().code.as_str(),
            "DATAPLANE.BACKEND_NOT_BUILT"
        );
    }
}

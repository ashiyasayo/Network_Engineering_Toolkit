//! Native DPDK executor 的 feature-gated 入口。

use nettool_error::{ErrorCode, NetToolError};
use std::time::Duration;
#[cfg(feature = "ffi-api")]
use std::time::Instant;

use crate::QueuePlan;
#[cfg(feature = "ffi-api")]
use crate::{MbufPoolSizing, required_mbufs};

/// Native DPDK burst executor 的已驗證輸入。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeDpdkExecutionRequest {
    /// Canonical NIC PCI BDF。
    pub pci_address: String,
    /// On-wire Ethernet frame bytes。
    pub frame_size: u16,
    /// 單次 bounded burst 的 packet count。
    pub packets: u64,
    /// 已由 resource manager 規劃並保留的 queue ownership。
    pub queue_plan: QueuePlan,
    /// 呼叫端建立且已驗證的 L2 frame template。
    pub frame_template: Vec<u8>,
}

/// Native DPDK TX executor 的實測結果。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeDpdkExecutionResult {
    /// DPDK 接受送出的封包數。
    pub transmitted_packets: u64,
    /// Native port hardware counters。
    pub hardware: nettool_dpdk_safe::PortStats,
    /// PMD-specific extended counters。
    pub xstats: Vec<nettool_dpdk_safe::XStat>,
}

/// Native DPDK RX executor 的已驗證輸入。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeDpdkReceiveRequest {
    /// Canonical NIC PCI BDF。
    pub pci_address: String,
    /// 接收 window；到期後回傳已觀測的計數器。
    pub duration: Duration,
    /// 已由 resource manager 規劃並保留的 queue ownership。
    pub queue_plan: QueuePlan,
}

/// Native DPDK RX executor 的實測結果。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeDpdkReceiveResult {
    /// PMD 交給 RX queue 的封包數。
    pub received_packets: u64,
    /// Native port hardware counters。
    pub hardware: nettool_dpdk_safe::PortStats,
    /// PMD-specific extended counters。
    pub xstats: Vec<nettool_dpdk_safe::XStat>,
}

impl NativeDpdkExecutionRequest {
    /// 驗證 executor 不會接收未解析的 NIC 名稱或空工作量。
    ///
    /// # Errors
    ///
    /// PCI BDF、frame size 或 packet count 不符合 executor 邊界時回傳錯誤。
    pub fn validate(&self) -> Result<(), NetToolError> {
        if !valid_pci_bdf(&self.pci_address)
            || self.frame_size < 64
            || self.packets == 0
            || self.frame_template.len() != usize::from(self.frame_size)
        {
            return Err(NetToolError::new(
                ErrorCode::InvalidArgument,
                "native DPDK executor request is invalid",
                false,
            ));
        }
        self.queue_plan.validate()?;
        Ok(())
    }
}

impl NativeDpdkReceiveRequest {
    /// 驗證 RX executor 的 PCI identity、時間界限與 queue ownership。
    ///
    /// # Errors
    ///
    /// PCI BDF、接收時間或 queue plan 無效時回傳錯誤。
    pub fn validate(&self) -> Result<(), NetToolError> {
        if !valid_pci_bdf(&self.pci_address) || self.duration.is_zero() {
            return Err(NetToolError::new(
                ErrorCode::InvalidArgument,
                "native DPDK receive request is invalid",
                false,
            ));
        }
        self.queue_plan.validate()
    }
}

fn valid_pci_bdf(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 12
        && bytes[4] == b':'
        && bytes[7] == b':'
        && bytes[10] == b'.'
        && bytes[11].is_ascii_digit()
        && bytes[11] <= b'7'
        && bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| matches!(index, 4 | 7 | 10 | 11) || byte.is_ascii_hexdigit())
}

/// 尚未將 native runtime 掛入 executor 時，維持 fail-closed 行為。
#[cfg(not(feature = "ffi-api"))]
#[must_use]
pub fn native_executor_unavailable() -> NetToolError {
    nettool_dpdk_safe::backend_not_built()
}

#[cfg(feature = "ffi-api")]
/// 尚未啟用 native DPDK link feature 時回傳 fail-closed 錯誤。
#[must_use]
pub fn native_executor_unavailable() -> NetToolError {
    NetToolError::new(
        ErrorCode::BackendNotBuilt,
        "DPDK executor requires a build with the native-dpdk feature and libdpdk SDK",
        false,
    )
}

/// 執行已驗證的 native DPDK TX burst。
///
/// # Errors
///
/// 未啟用 `ffi-api`、EAL/port/queue 初始化失敗或 TX 無 forward progress 時回傳錯誤。
#[cfg(feature = "ffi-api")]
pub fn execute_native_tx(
    request: &NativeDpdkExecutionRequest,
) -> Result<NativeDpdkExecutionResult, NetToolError> {
    use nettool_dpdk_safe::{Environment, MempoolConfiguration, PortConfiguration};

    request.validate()?;
    let environment = Environment::initialize(&[
        "nettool-backend-dpdk".to_owned(),
        "--no-telemetry".to_owned(),
        "-a".to_owned(),
        request.pci_address.clone(),
    ])?;
    let port_id = environment.port_by_name(&request.pci_address)?;
    let mbufs = required_mbufs(MbufPoolSizing {
        rx_queues: u32::from(request.queue_plan.rx_queues),
        rx_descriptors_per_queue: 1024,
        tx_queues: u32::from(request.queue_plan.tx_queues),
        tx_descriptors_per_queue: 1024,
        burst_size: 64,
        pipeline_depth: 1,
        capture_buffers: 0,
        safety_margin: 1024,
    })?;
    let pool = environment.create_mempool(&MempoolConfiguration {
        name: format!("nettool_speed_tx_{port_id}"),
        count: u32::try_from(mbufs)
            .map_err(|_| invalid("DPDK mbuf pool size exceeds u32 capacity"))?,
        cache_size: 256,
        data_room_size: 9_600,
        socket_id: request.queue_plan.numa_node,
    })?;
    let mut port = pool.configure_port(PortConfiguration {
        port_id,
        rx_queues: request.queue_plan.rx_queues,
        tx_queues: request.queue_plan.tx_queues,
        rx_descriptors: 1024,
        tx_descriptors: 1024,
        socket_id: u32::try_from(request.queue_plan.numa_node)
            .map_err(|_| invalid("DPDK NUMA socket ID must be non-negative"))?,
    })?;
    port.start()?;
    let mut queue = port.tx_queue(0, &pool)?;
    let mut transmitted_packets = 0_u64;
    while transmitted_packets < request.packets {
        let remaining = request.packets - transmitted_packets;
        let burst = u16::try_from(remaining.min(64)).unwrap_or(64);
        let accepted = u64::from(queue.send_template_burst(&request.frame_template, burst)?);
        if accepted == 0 {
            return Err(NetToolError::new(
                ErrorCode::PreflightFailed,
                "DPDK TX made no forward progress",
                true,
            ));
        }
        transmitted_packets = transmitted_packets.saturating_add(accepted);
    }
    drop(queue);
    let hardware = port.stats()?;
    let xstats = port.xstats()?;
    Ok(NativeDpdkExecutionResult {
        transmitted_packets,
        hardware,
        xstats,
    })
}

/// 執行有時間界限的 native DPDK RX polling。
///
/// # Errors
///
/// 未啟用 `ffi-api`、EAL/port/queue 初始化失敗或 hardware counter 讀取失敗時回傳錯誤。
#[cfg(feature = "ffi-api")]
pub fn execute_native_rx(
    request: &NativeDpdkReceiveRequest,
) -> Result<NativeDpdkReceiveResult, NetToolError> {
    use nettool_dpdk_safe::{Environment, MempoolConfiguration, PortConfiguration};

    request.validate()?;
    let environment = Environment::initialize(&[
        "nettool-backend-dpdk-rx".to_owned(),
        "--no-telemetry".to_owned(),
        "-a".to_owned(),
        request.pci_address.clone(),
    ])?;
    let port_id = environment.port_by_name(&request.pci_address)?;
    let mbufs = required_mbufs(MbufPoolSizing {
        rx_queues: u32::from(request.queue_plan.rx_queues),
        rx_descriptors_per_queue: 1024,
        tx_queues: u32::from(request.queue_plan.tx_queues),
        tx_descriptors_per_queue: 1024,
        burst_size: 64,
        pipeline_depth: 1,
        capture_buffers: 0,
        safety_margin: 1024,
    })?;
    let pool = environment.create_mempool(&MempoolConfiguration {
        name: format!("nettool_speed_rx_{port_id}"),
        count: u32::try_from(mbufs)
            .map_err(|_| invalid("DPDK mbuf pool size exceeds u32 capacity"))?,
        cache_size: 256,
        data_room_size: 9_600,
        socket_id: request.queue_plan.numa_node,
    })?;
    let mut port = pool.configure_port(PortConfiguration {
        port_id,
        rx_queues: request.queue_plan.rx_queues,
        tx_queues: request.queue_plan.tx_queues,
        rx_descriptors: 1024,
        tx_descriptors: 1024,
        socket_id: u32::try_from(request.queue_plan.numa_node)
            .map_err(|_| invalid("DPDK NUMA socket ID must be non-negative"))?,
    })?;
    port.start()?;
    let mut queue = port.rx_queue(0, 64)?;
    let started = Instant::now();
    let mut received_packets = 0_u64;
    while started.elapsed() < request.duration {
        let received = queue.receive_burst(|_| {})?;
        received_packets =
            received_packets.saturating_add(u64::try_from(received).unwrap_or(u64::MAX));
    }
    drop(queue);
    let hardware = port.stats()?;
    let xstats = port.xstats()?;
    Ok(NativeDpdkReceiveResult {
        received_packets,
        hardware,
        xstats,
    })
}

/// 未連結 native DPDK 時維持 fail-closed executor 行為。
///
/// # Errors
///
/// 一律回傳 backend-not-built 錯誤。
#[cfg(not(feature = "ffi-api"))]
pub fn execute_native_tx(
    _request: &NativeDpdkExecutionRequest,
) -> Result<NativeDpdkExecutionResult, NetToolError> {
    Err(native_executor_unavailable())
}

/// 未連結 native DPDK 時維持 fail-closed RX executor 行為。
///
/// # Errors
///
/// 一律回傳 backend-not-built 錯誤。
#[cfg(not(feature = "ffi-api"))]
pub fn execute_native_rx(
    _request: &NativeDpdkReceiveRequest,
) -> Result<NativeDpdkReceiveResult, NetToolError> {
    Err(native_executor_unavailable())
}

#[cfg(feature = "ffi-api")]
fn invalid(message: &'static str) -> NetToolError {
    NetToolError::new(ErrorCode::InvalidArgument, message, false)
}

#[cfg(test)]
mod tests {
    use super::{NativeDpdkExecutionRequest, NativeDpdkReceiveRequest};
    use std::time::Duration;

    #[test]
    fn rejects_invalid_native_executor_request() {
        assert!(
            NativeDpdkExecutionRequest {
                pci_address: String::new(),
                frame_size: 64,
                packets: 1,
                queue_plan: plan(),
                frame_template: vec![0; 64],
            }
            .validate()
            .is_err()
        );
        assert!(
            NativeDpdkReceiveRequest {
                pci_address: "0000:01:00.0".to_owned(),
                duration: Duration::ZERO,
                queue_plan: plan(),
            }
            .validate()
            .is_err()
        );
        assert!(
            NativeDpdkExecutionRequest {
                pci_address: "eth0".to_owned(),
                frame_size: 64,
                packets: 1,
                queue_plan: plan(),
                frame_template: vec![0; 64],
            }
            .validate()
            .is_err()
        );
        assert!(
            NativeDpdkExecutionRequest {
                pci_address: "0000:01:00.0".to_owned(),
                frame_size: 63,
                packets: 1,
                queue_plan: plan(),
                frame_template: vec![0; 63],
            }
            .validate()
            .is_err()
        );
    }

    fn plan() -> crate::QueuePlan {
        crate::QueuePlan {
            numa_node: 0,
            rx_queues: 1,
            tx_queues: 1,
            rx_assignments: vec![crate::RxQueueAssignment {
                queue_id: 0,
                logical_cpu: 0,
            }],
        }
    }
}

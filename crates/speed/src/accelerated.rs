//! Accelerated data-plane executor 的共用 contract。

use crate::SpeedRunRequest;
use nettool_error::{ErrorCode, NetToolError};

/// 可由 accelerated executor 處理的 backend。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcceleratedBackend {
    /// DPDK data plane。
    Dpdk,
    /// Linux `AF_XDP` data plane。
    AfXdp,
    /// Windows Registered I/O data plane。
    Rio,
}

impl AcceleratedBackend {
    /// 由公開 payload 的 backend ID 解析 accelerated backend。
    #[must_use]
    pub fn from_id(value: &str) -> Option<Self> {
        match value {
            "dpdk" => Some(Self::Dpdk),
            "af_xdp" => Some(Self::AfXdp),
            "rio" => Some(Self::Rio),
            _ => None,
        }
    }
}

/// 交給 accelerated executor 的已驗證 session 資訊。
///
/// Agent 必須先完成 pairing、control-plane prepare 與 resource reservation，才可建立此 request。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceleratedExecutionRequest {
    /// 選定的硬體 backend。
    pub backend: AcceleratedBackend,
    /// 對外穩定的 speed payload。
    pub speed: SpeedRunRequest,
    /// 由 control plane 產生的非零 session ID。
    pub session_id: [u8; 16],
}

impl AcceleratedExecutionRequest {
    /// 建立 executor request，避免 socket backend 或空 session 進入硬體資料平面。
    ///
    /// # Errors
    ///
    /// backend 不是 accelerated 類型，或 session ID 為零時回傳錯誤。
    pub fn new(speed: SpeedRunRequest, session_id: [u8; 16]) -> Result<Self, NetToolError> {
        let backend = AcceleratedBackend::from_id(&speed.backend).ok_or_else(|| {
            invalid("accelerated executor requires a DPDK, AF_XDP, or RIO backend")
        })?;
        if session_id == [0; 16] {
            return Err(invalid(
                "accelerated executor requires a non-zero session ID",
            ));
        }
        Ok(Self {
            backend,
            speed,
            session_id,
        })
    }
}

/// 一個 accelerated executor 已完成的本機資料平面量測。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceleratedExecutionResult {
    /// 對應的 session ID。
    pub session_id: [u8; 16],
    /// 本機 monotonic execution duration。
    pub elapsed_nanoseconds: u64,
    /// 已送出的封包數。
    pub transmitted_packets: u64,
    /// 已接收的封包數。
    pub received_packets: u64,
}

/// 能在 Agent 已建立的 session 中執行實際 accelerated data plane 的 backend。
///
/// 此 contract 不提供 synthetic fallback；executor 必須回傳實測 counters 或錯誤。
pub trait AcceleratedSpeedExecutor: Send + Sync {
    /// 此 executor 支援的 backend。
    fn backend(&self) -> AcceleratedBackend;

    /// 在已完成 control-plane 協調後執行本機資料平面。
    ///
    /// # Errors
    ///
    /// 無法完成實測資料平面或無法取得可信 counters 時回傳錯誤。
    fn execute(
        &self,
        request: &AcceleratedExecutionRequest,
    ) -> Result<AcceleratedExecutionResult, NetToolError>;
}

/// 執行前檢查 backend 路由，防止錯誤 executor 產生可被誤認的結果。
///
/// # Errors
///
/// executor 與 request backend 不一致，或 executor 執行失敗時回傳錯誤。
pub fn execute_with<E>(
    executor: &E,
    request: &AcceleratedExecutionRequest,
) -> Result<AcceleratedExecutionResult, NetToolError>
where
    E: AcceleratedSpeedExecutor,
{
    if executor.backend() != request.backend {
        return Err(NetToolError::new(
            ErrorCode::ActionUnsupported,
            "accelerated executor does not match the requested backend",
            false,
        ));
    }
    let result = executor.execute(request)?;
    if result.session_id != request.session_id || result.elapsed_nanoseconds == 0 {
        return Err(NetToolError::new(
            ErrorCode::SpeedFailed,
            "accelerated executor returned an invalid measurement result",
            false,
        ));
    }
    Ok(result)
}

fn invalid(message: &'static str) -> NetToolError {
    NetToolError::new(ErrorCode::InvalidArgument, message, false)
}

#[cfg(test)]
mod tests {
    use super::{
        AcceleratedBackend, AcceleratedExecutionRequest, AcceleratedExecutionResult,
        AcceleratedSpeedExecutor, execute_with,
    };
    use crate::SpeedRunRequest;
    use nettool_domain::{Direction, SpeedProtocol};
    use nettool_error::NetToolError;

    struct FakeExecutor;

    impl AcceleratedSpeedExecutor for FakeExecutor {
        fn backend(&self) -> AcceleratedBackend {
            AcceleratedBackend::Dpdk
        }

        fn execute(
            &self,
            request: &AcceleratedExecutionRequest,
        ) -> Result<AcceleratedExecutionResult, NetToolError> {
            Ok(AcceleratedExecutionResult {
                session_id: request.session_id,
                elapsed_nanoseconds: 1,
                transmitted_packets: 10,
                received_packets: 9,
            })
        }
    }

    fn request(backend: &str) -> SpeedRunRequest {
        SpeedRunRequest {
            node: "node-b".to_owned(),
            protocol: SpeedProtocol::Udp,
            backend: backend.to_owned(),
            direction: Direction::Upload,
            duration_ms: 1_000,
            warmup_ms: 0,
            cooldown_ms: 0,
            streams: Some(1),
            frame_size: None,
            target_rate_bps: Some(1_000_000),
            auto_tune: false,
            latency_under_load: false,
            cpus: None,
            numa_node: None,
            accelerated_pci_address: Some("0000:01:00.0".to_owned()),
            accelerated_interface_name: None,
        }
    }

    #[test]
    fn fake_executor_receives_the_prepared_session() {
        let request = AcceleratedExecutionRequest::new(request("dpdk"), [7; 16])
            .expect("accelerated request");
        let result = execute_with(&FakeExecutor, &request).expect("execution result");
        assert_eq!(result.session_id, [7; 16]);
        assert_eq!(result.transmitted_packets, 10);
    }

    #[test]
    fn rejects_socket_backends_and_mismatched_executors() {
        assert!(AcceleratedExecutionRequest::new(request("socket"), [7; 16]).is_err());
        let request = AcceleratedExecutionRequest::new(request("af_xdp"), [7; 16])
            .expect("accelerated request");
        assert!(execute_with(&FakeExecutor, &request).is_err());
    }
}

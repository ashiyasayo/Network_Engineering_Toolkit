use nettool_error::{ErrorCode, NetToolError};
use nettool_node_protocol::{
    CapabilityMessage, CapabilityResponse, Envelope, HelloRequest, HelloResponse, PROTOCOL_MAJOR,
    PROTOCOL_MINOR, PrepareTest, PrepareTestResponse, ProtocolError, TestStatus, envelope,
};
use nettool_speed::TcpRunConfig;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::{
    CAPABILITY_DPDK, CAPABILITY_RAW_PACKET_GENERATOR, CAPABILITY_TCP_SPEED, CAPABILITY_UDP_SPEED,
    LocalNodeIdentity, PrepareDpdkReceiverRequest, PrepareTcpBidirectionalRequest,
    PrepareTcpRequest, PrepareTcpSenderRequest, PrepareUdpBidirectionalRequest, PrepareUdpRequest,
    PrepareUdpSenderRequest, SessionCoordinator,
};

const DEFAULT_TCP_PAYLOAD_BYTES: usize = 64 * 1024;
const DEFAULT_UDP_DATAGRAM_BYTES: usize = 1_200;
const DEFAULT_UDP_IDLE_TIMEOUT_MILLISECONDS: u64 = 2_000;

/// 單一已驗證 mTLS control connection 的 protocol dispatcher。
///
/// TLS peer certificate 與 pairing fingerprint 必須在建立本型別前完成；dispatcher 再以
/// Hello Node ID 綁定同一 trust record，且在 Hello 成功前拒絕所有 session command。
pub struct NodeControlService {
    local: LocalNodeIdentity,
    expected_peer_node_id: [u8; 16],
    peer_address: IpAddr,
    bind_address: IpAddr,
    selected_minor: Option<u32>,
    coordinator: Arc<Mutex<SessionCoordinator>>,
    dpdk_available: bool,
}

impl NodeControlService {
    /// 建立單一 trusted connection dispatcher。
    #[must_use]
    pub fn new(
        local: LocalNodeIdentity,
        expected_peer_node_id: [u8; 16],
        peer_address: IpAddr,
        bind_address: IpAddr,
    ) -> Self {
        Self {
            local,
            expected_peer_node_id,
            peer_address,
            bind_address,
            selected_minor: None,
            coordinator: Arc::new(Mutex::new(SessionCoordinator::new())),
            dpdk_available: false,
        }
    }

    /// 使用 Agent-owned shared coordinator 建立 connection dispatcher。
    #[must_use]
    pub fn with_coordinator(
        local: LocalNodeIdentity,
        expected_peer_node_id: [u8; 16],
        peer_address: IpAddr,
        bind_address: IpAddr,
        coordinator: Arc<Mutex<SessionCoordinator>>,
    ) -> Self {
        Self {
            local,
            expected_peer_node_id,
            peer_address,
            bind_address,
            selected_minor: None,
            coordinator,
            dpdk_available: false,
        }
    }

    /// 使用 Agent 已驗證的 native DPDK build 狀態建立 shared coordinator dispatcher。
    #[must_use]
    pub fn with_coordinator_and_dpdk(
        local: LocalNodeIdentity,
        expected_peer_node_id: [u8; 16],
        peer_address: IpAddr,
        bind_address: IpAddr,
        coordinator: Arc<Mutex<SessionCoordinator>>,
        dpdk_available: bool,
    ) -> Self {
        Self {
            local,
            expected_peer_node_id,
            peer_address,
            bind_address,
            selected_minor: None,
            coordinator,
            dpdk_available,
        }
    }

    /// 取得 session coordinator，供 scheduler/worker runtime 消費 prepared endpoints。
    #[must_use]
    pub fn coordinator(&self) -> Arc<Mutex<SessionCoordinator>> {
        Arc::clone(&self.coordinator)
    }

    /// 驗證 request envelope，執行一個 typed control command並建立 correlated response。
    ///
    /// Request-level failure 會轉為 `ProtocolError` envelope；只有內部無法建立 response 的
    /// 情況才回傳 `Err`。
    ///
    /// # Errors
    ///
    /// 目前保留給不可恢復的 dispatcher 內部錯誤。
    pub async fn dispatch(
        &mut self,
        request: Envelope,
        now_unix_nanoseconds: u64,
    ) -> Result<Envelope, NetToolError> {
        let request_id = request.request_id.clone();
        let response = self
            .dispatch_message(request, now_unix_nanoseconds)
            .await
            .unwrap_or_else(|error| envelope::ControlMessage::Error(protocol_error(error)));
        Ok(Envelope {
            protocol_major: PROTOCOL_MAJOR,
            protocol_minor: self.selected_minor.unwrap_or(PROTOCOL_MINOR),
            request_id,
            message: Some(response),
        })
    }

    async fn dispatch_message(
        &mut self,
        request: Envelope,
        now_unix_nanoseconds: u64,
    ) -> Result<envelope::ControlMessage, NetToolError> {
        validate_envelope(&request)?;
        let request_minor = request.protocol_minor;
        let message = request
            .message
            .ok_or_else(|| protocol("control request has no message"))?;
        if let envelope::ControlMessage::HelloRequest(hello) = message {
            return self.handle_hello(&hello);
        }
        if self.selected_minor.is_none() {
            return Err(protocol("Hello must complete before control commands"));
        }
        if request_minor > self.selected_minor.unwrap_or(0) {
            return Err(NetToolError::new(
                ErrorCode::ProtocolIncompatible,
                "control request exceeds the negotiated protocol minor",
                false,
            ));
        }
        match message {
            envelope::ControlMessage::CapabilityRequest(_) => Ok(
                envelope::ControlMessage::CapabilityResponse(CapabilityResponse {
                    capabilities: runtime_capabilities(self.dpdk_available),
                }),
            ),
            envelope::ControlMessage::PrepareTest(prepare) => {
                self.handle_prepare(prepare, now_unix_nanoseconds).await
            }
            envelope::ControlMessage::StartTest(start) => {
                let session_id = parse_session_id(&start.session_id)?;
                let state = with_coordinator(&self.coordinator, |coordinator| {
                    coordinator.start(
                        session_id,
                        &start.operation_id,
                        start.start_at_unix_nanoseconds,
                        now_unix_nanoseconds,
                    )
                })
                .await?;
                Ok(envelope::ControlMessage::TestStatus(TestStatus {
                    session_id: session_id.to_vec(),
                    state: state_name(state).to_owned(),
                }))
            }
            envelope::ControlMessage::StopTest(stop) => {
                let session_id = parse_session_id(&stop.session_id)?;
                let state = with_coordinator(&self.coordinator, |coordinator| {
                    coordinator.stop(session_id, &stop.operation_id)
                })
                .await?;
                Ok(envelope::ControlMessage::TestStatus(TestStatus {
                    session_id: session_id.to_vec(),
                    state: state_name(state).to_owned(),
                }))
            }
            envelope::ControlMessage::TestResultRequest(query) => {
                let session_id = parse_session_id(&query.session_id)?;
                with_coordinator(&self.coordinator, |coordinator| {
                    coordinator.test_result(session_id)
                })
                .await
                .map(envelope::ControlMessage::TestResult)
            }
            envelope::ControlMessage::Ping(ping) => Ok(envelope::ControlMessage::Pong(
                nettool_node_protocol::Pong { nonce: ping.nonce },
            )),
            _ => Err(protocol("message type is not valid as a server request")),
        }
    }

    fn handle_hello(
        &mut self,
        hello: &HelloRequest,
    ) -> Result<envelope::ControlMessage, NetToolError> {
        if self.selected_minor.is_some() {
            return Err(protocol("Hello cannot be repeated on an active connection"));
        }
        if hello.node_id.as_slice() != self.expected_peer_node_id {
            return Err(NetToolError::new(
                ErrorCode::NodeTlsFailed,
                "Hello Node ID does not match the authenticated peer",
                false,
            ));
        }
        if hello.node_name.trim().is_empty()
            || hello.min_minor > hello.max_minor
            || hello.min_minor > PROTOCOL_MINOR
        {
            return Err(NetToolError::new(
                ErrorCode::ProtocolIncompatible,
                "Hello version range or Node name is invalid",
                false,
            ));
        }
        let selected_minor = hello.max_minor.min(PROTOCOL_MINOR);
        self.selected_minor = Some(selected_minor);
        Ok(envelope::ControlMessage::HelloResponse(HelloResponse {
            selected_minor,
            node_id: self.local.node_id.to_vec(),
            node_name: self.local.name.clone(),
        }))
    }

    #[allow(clippy::too_many_lines)]
    async fn handle_prepare(
        &mut self,
        prepare: PrepareTest,
        now_unix_nanoseconds: u64,
    ) -> Result<envelope::ControlMessage, NetToolError> {
        let session_id = parse_session_id(&prepare.session_id)?;
        if !matches!(
            prepare.direction.as_str(),
            "upload" | "download" | "bidirectional"
        ) {
            return Err(NetToolError::new(
                ErrorCode::Unsupported,
                "unsupported speed direction",
                false,
            ));
        }
        if prepare.backend == "dpdk" && !self.dpdk_available {
            return Err(NetToolError::new(
                ErrorCode::BackendNotBuilt,
                "Node DPDK runtime is not built",
                false,
            ));
        }
        if matches!(prepare.backend.as_str(), "dpdk" | "af_xdp" | "rio")
            && !valid_pci_bdf(&prepare.accelerated_pci_address)
        {
            return Err(invalid("accelerated prepare requires a valid PCI BDF"));
        }
        if prepare.backend == "dpdk" && !valid_pci_bdf(&prepare.remote_accelerated_pci_address) {
            return Err(invalid("DPDK prepare requires a valid remote PCI BDF"));
        }
        if prepare.backend == "dpdk"
            && prepare.test_type == "raw"
            && !valid_unicast_mac(&prepare.remote_mac_address)
        {
            return Err(invalid(
                "DPDK raw prepare requires a valid remote unicast MAC",
            ));
        }
        let now_unix_seconds = now_unix_nanoseconds / 1_000_000_000;
        let ttl = authorization_ttl(&prepare)?;
        if prepare.backend == "dpdk" && prepare.test_type == "raw" {
            if prepare.direction != "upload" {
                return Err(NetToolError::new(
                    ErrorCode::Unsupported,
                    "DPDK raw receiver is currently supported for upload only",
                    false,
                ));
            }
            let pci_address = prepare.remote_accelerated_pci_address.clone();
            let _plan = self.coordinator.lock().await.prepare_dpdk_receiver(
                PrepareDpdkReceiverRequest {
                    session_id,
                    operation_id: prepare.operation_id,
                    source_node_id: self.expected_peer_node_id,
                    pci_address,
                    duration_milliseconds: prepare.duration_ms,
                    remote_mac_address: prepare.remote_mac_address,
                    authorization_ttl_seconds: ttl,
                },
                now_unix_seconds,
            )?;
            let authorization_tag = self
                .coordinator
                .lock()
                .await
                .authorization(session_id)
                .map(|authorization| authorization.authorization_tag.clone())
                .unwrap_or_default();
            return Ok(envelope::ControlMessage::PrepareTestResponse(
                PrepareTestResponse {
                    ready: true,
                    data_port: 0,
                    authorization_tag,
                    source_data_port: 0,
                },
            ));
        }
        let response = match prepare.test_type.as_str() {
            "tcp" if matches!(prepare.backend.as_str(), "socket" | "native") => {
                let response = self
                    .handle_tcp_prepare(prepare, session_id, now_unix_seconds, ttl)
                    .await?;
                PrepareTestResponse {
                    ready: true,
                    data_port: u32::from(response.data_port),
                    authorization_tag: response.authorization_tag,
                    source_data_port: 0,
                }
            }
            "udp" if matches!(prepare.backend.as_str(), "socket" | "native") => {
                if prepare.direction == "bidirectional" {
                    let source_port = u16::try_from(prepare.source_data_port)
                        .map_err(|_| invalid("UDP source port is outside the valid range"))?;
                    let receive_port = u16::try_from(prepare.receive_data_port)
                        .map_err(|_| invalid("UDP receiver port is outside the valid range"))?;
                    if source_port == 0 || receive_port == 0 {
                        return Err(invalid(
                            "UDP bidirectional requires pre-bound source and receiver ports",
                        ));
                    }
                    let datagram_bytes = usize::try_from(prepare.payload_size)
                        .unwrap_or(usize::MAX)
                        .max(DEFAULT_UDP_DATAGRAM_BYTES);
                    let response = self
                        .coordinator
                        .lock()
                        .await
                        .prepare_udp_bidirectional(
                            PrepareUdpBidirectionalRequest {
                                session_id,
                                operation_id: prepare.operation_id,
                                source_node_id: self.expected_peer_node_id,
                                source_address: SocketAddr::new(self.peer_address, source_port),
                                bind_address: self.bind_address,
                                destination: SocketAddr::new(self.peer_address, receive_port),
                                stream_id: 0,
                                datagram_bytes,
                                measurement_milliseconds: prepare.duration_ms,
                                target_bits_per_second: (prepare.target_rate_bps != 0)
                                    .then_some(prepare.target_rate_bps),
                                authorization_ttl_seconds: ttl,
                            },
                            now_unix_seconds,
                        )
                        .await?;
                    let source_data_port = self
                        .coordinator
                        .lock()
                        .await
                        .authorization(session_id)
                        .map_or(0, |authorization| authorization.destination_port);
                    return Ok(envelope::ControlMessage::PrepareTestResponse(
                        PrepareTestResponse {
                            ready: true,
                            data_port: u32::from(response.data_port),
                            authorization_tag: response.authorization_tag,
                            source_data_port: u32::from(source_data_port),
                        },
                    ));
                }
                if prepare.direction != "upload" {
                    let receive_port = u16::try_from(prepare.receive_data_port)
                        .map_err(|_| invalid("UDP receiver port is outside the valid range"))?;
                    if receive_port == 0 {
                        return Err(invalid("UDP download requires a pre-bound receiver port"));
                    }
                    let datagram_bytes = usize::try_from(prepare.payload_size)
                        .unwrap_or(usize::MAX)
                        .max(DEFAULT_UDP_DATAGRAM_BYTES);
                    let response = self
                        .coordinator
                        .lock()
                        .await
                        .prepare_udp_sender(
                            PrepareUdpSenderRequest {
                                session_id,
                                operation_id: prepare.operation_id,
                                source_node_id: self.local.node_id,
                                source_address: self.bind_address,
                                destination: SocketAddr::new(self.peer_address, receive_port),
                                stream_id: 0,
                                datagram_bytes,
                                measurement_milliseconds: prepare.duration_ms,
                                target_bits_per_second: (prepare.target_rate_bps != 0)
                                    .then_some(prepare.target_rate_bps),
                                authorization_ttl_seconds: ttl,
                            },
                            now_unix_seconds,
                        )
                        .await?;
                    let source_data_port = self
                        .coordinator
                        .lock()
                        .await
                        .authorization(session_id)
                        .and_then(|authorization| authorization.source_port)
                        .unwrap_or(0);
                    return Ok(envelope::ControlMessage::PrepareTestResponse(
                        PrepareTestResponse {
                            ready: true,
                            data_port: 0,
                            authorization_tag: response.authorization_tag,
                            source_data_port: u32::from(source_data_port),
                        },
                    ));
                }
                let source_port = u16::try_from(prepare.source_data_port)
                    .map_err(|_| invalid("UDP source port is outside the valid range"))?;
                let maximum_datagram_bytes = usize::try_from(prepare.payload_size)
                    .unwrap_or(usize::MAX)
                    .max(DEFAULT_UDP_DATAGRAM_BYTES);
                let response = self
                    .coordinator
                    .lock()
                    .await
                    .prepare_udp(
                        PrepareUdpRequest {
                            session_id,
                            operation_id: prepare.operation_id,
                            source_node_id: self.expected_peer_node_id,
                            source_address: SocketAddr::new(self.peer_address, source_port),
                            bind_address: SocketAddr::new(self.bind_address, 0),
                            stream_id: 0,
                            maximum_datagram_bytes,
                            idle_timeout_milliseconds: DEFAULT_UDP_IDLE_TIMEOUT_MILLISECONDS,
                            authorization_ttl_seconds: ttl,
                        },
                        now_unix_seconds,
                    )
                    .await?;
                PrepareTestResponse {
                    ready: true,
                    data_port: u32::from(response.data_port),
                    authorization_tag: response.authorization_tag,
                    source_data_port: 0,
                }
            }
            _ => {
                return Err(NetToolError::new(
                    ErrorCode::Unsupported,
                    "test type/backend is not available in the socket Node runtime",
                    false,
                ));
            }
        };
        Ok(envelope::ControlMessage::PrepareTestResponse(response))
    }

    async fn handle_tcp_prepare(
        &self,
        prepare: PrepareTest,
        session_id: [u8; 16],
        now_unix_seconds: u64,
        ttl: u64,
    ) -> Result<crate::PrepareTcpResponse, NetToolError> {
        let streams = u16::try_from(prepare.streams.max(1))
            .map_err(|_| invalid("TCP stream count is too large"))?;
        let payload_bytes = usize::try_from(prepare.payload_size)
            .unwrap_or(usize::MAX)
            .max(DEFAULT_TCP_PAYLOAD_BYTES);
        let config = TcpRunConfig {
            streams,
            payload_bytes,
            warmup_milliseconds: prepare.warmup_ms,
            measurement_milliseconds: prepare.duration_ms,
        };
        if prepare.direction == "upload" {
            return self
                .coordinator
                .lock()
                .await
                .prepare_tcp(
                    PrepareTcpRequest {
                        session_id,
                        operation_id: prepare.operation_id,
                        source_node_id: self.expected_peer_node_id,
                        source_address: self.peer_address,
                        bind_address: SocketAddr::new(self.bind_address, 0),
                        config,
                        authorization_ttl_seconds: ttl,
                    },
                    now_unix_seconds,
                )
                .await;
        }
        let receive_port = u16::try_from(prepare.receive_data_port)
            .map_err(|_| invalid("TCP receiver port is outside the valid range"))?;
        if receive_port == 0 {
            return Err(invalid("TCP download requires a pre-bound receiver port"));
        }
        if prepare.direction == "bidirectional" {
            return self
                .coordinator
                .lock()
                .await
                .prepare_tcp_bidirectional(
                    PrepareTcpBidirectionalRequest {
                        session_id,
                        operation_id: prepare.operation_id,
                        source_node_id: self.expected_peer_node_id,
                        source_address: self.peer_address,
                        bind_address: SocketAddr::new(self.bind_address, 0),
                        destination: SocketAddr::new(self.peer_address, receive_port),
                        config,
                        authorization_ttl_seconds: ttl,
                    },
                    now_unix_seconds,
                )
                .await;
        }
        self.coordinator.lock().await.prepare_tcp_sender(
            PrepareTcpSenderRequest {
                session_id,
                operation_id: prepare.operation_id,
                source_node_id: self.local.node_id,
                source_address: self.bind_address,
                destination: SocketAddr::new(self.peer_address, receive_port),
                config,
                authorization_ttl_seconds: ttl,
            },
            now_unix_seconds,
        )
    }
}

fn valid_pci_bdf(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 12
        && bytes[4] == b':'
        && bytes[7] == b':'
        && bytes[10] == b'.'
        && bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| matches!(index, 4 | 7 | 10) || byte.is_ascii_hexdigit())
}

fn valid_unicast_mac(value: &str) -> bool {
    let parts: Vec<_> = value.split(':').collect();
    parts.len() == 6
        && parts
            .iter()
            .all(|part| part.len() == 2 && part.bytes().all(|byte| byte.is_ascii_hexdigit()))
        && u8::from_str_radix(parts[0], 16).is_ok_and(|first| first != 0 && first & 1 == 0)
}

async fn with_coordinator<T, F>(
    coordinator: &Arc<Mutex<SessionCoordinator>>,
    operation: F,
) -> Result<T, NetToolError>
where
    F: FnOnce(&mut SessionCoordinator) -> Result<T, NetToolError>,
{
    let mut guard = coordinator.lock().await;
    operation(&mut guard)
}

fn validate_envelope(request: &Envelope) -> Result<(), NetToolError> {
    if request.protocol_major != PROTOCOL_MAJOR || request.protocol_minor > PROTOCOL_MINOR {
        return Err(NetToolError::new(
            ErrorCode::ProtocolIncompatible,
            "control request protocol version is incompatible",
            false,
        ));
    }
    if request.request_id.len() != 16 || request.request_id.iter().all(|byte| *byte == 0) {
        return Err(protocol(
            "control request ID must be non-zero 128-bit bytes",
        ));
    }
    Ok(())
}

fn parse_session_id(value: &[u8]) -> Result<[u8; 16], NetToolError> {
    let session_id: [u8; 16] = value
        .try_into()
        .map_err(|_| protocol("session ID must be 128-bit bytes"))?;
    if session_id == [0; 16] {
        return Err(protocol("session ID must not be zero"));
    }
    Ok(session_id)
}

fn authorization_ttl(prepare: &PrepareTest) -> Result<u64, NetToolError> {
    let total_milliseconds = prepare
        .warmup_ms
        .checked_add(prepare.duration_ms)
        .and_then(|value| value.checked_add(prepare.cooldown_ms))
        .ok_or_else(|| invalid("test duration overflow"))?;
    let seconds = total_milliseconds
        .checked_add(999)
        .ok_or_else(|| invalid("test duration overflow"))?
        / 1_000;
    Ok(seconds.saturating_add(10).clamp(10, 3_600))
}

fn runtime_capabilities(dpdk_available: bool) -> Vec<CapabilityMessage> {
    [
        (CAPABILITY_TCP_SPEED, true),
        (CAPABILITY_UDP_SPEED, true),
        (CAPABILITY_DPDK, dpdk_available),
        (CAPABILITY_RAW_PACKET_GENERATOR, dpdk_available),
    ]
    .into_iter()
    .map(|(id, available)| CapabilityMessage {
        id,
        min_version: 1,
        max_version: 1,
        available,
    })
    .collect()
}

const fn state_name(state: nettool_node_protocol::NodeConnectionState) -> &'static str {
    use nettool_node_protocol::NodeConnectionState::{
        Canceled, Completed, Finalizing, Running, TestReady,
    };
    match state {
        TestReady => "TEST_READY",
        Running => "RUNNING",
        Finalizing => "FINALIZING",
        Completed => "COMPLETED",
        Canceled => "CANCELED",
        _ => "FAILED",
    }
}

fn protocol_error(error: NetToolError) -> ProtocolError {
    ProtocolError {
        code: error.code.as_str().to_owned(),
        message: error.message,
        retryable: error.retryable,
    }
}

fn protocol(message: &'static str) -> NetToolError {
    NetToolError::new(ErrorCode::ProtocolInvalid, message, false)
}

fn invalid(message: &'static str) -> NetToolError {
    NetToolError::new(ErrorCode::InvalidArgument, message, false)
}

#[cfg(test)]
mod tests {
    use super::{NodeControlService, with_coordinator};
    use crate::LocalNodeIdentity;
    use nettool_node_protocol::{
        CapabilityRequest, Envelope, HelloRequest, PROTOCOL_MAJOR, PROTOCOL_MINOR, PrepareTest,
        StartTest, envelope,
    };
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use tokio::sync::{Mutex, oneshot};

    fn service() -> NodeControlService {
        NodeControlService::new(
            LocalNodeIdentity {
                node_id: [2; 16],
                name: "server".to_owned(),
            },
            [1; 16],
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        )
    }

    fn envelope(message: envelope::ControlMessage) -> Envelope {
        Envelope {
            protocol_major: PROTOCOL_MAJOR,
            protocol_minor: PROTOCOL_MINOR,
            request_id: vec![9; 16],
            message: Some(message),
        }
    }

    async fn hello(service: &mut NodeControlService) {
        let response = service
            .dispatch(
                envelope(envelope::ControlMessage::HelloRequest(HelloRequest {
                    node_id: vec![1; 16],
                    node_name: "client".to_owned(),
                    min_minor: 0,
                    max_minor: PROTOCOL_MINOR,
                })),
                1_000_000_000,
            )
            .await
            .expect("dispatch");
        assert!(matches!(
            response.message,
            Some(envelope::ControlMessage::HelloResponse(_))
        ));
    }

    #[tokio::test]
    async fn coordinator_lock_is_released_before_worker_await() {
        let coordinator = Arc::new(Mutex::new(crate::SessionCoordinator::new()));
        let (ready_sender, ready_receiver) = oneshot::channel();
        let (continue_sender, continue_receiver) = oneshot::channel();
        let worker_coordinator = Arc::clone(&coordinator);
        let worker = tokio::spawn(async move {
            let value = with_coordinator(&worker_coordinator, |_coordinator| Ok(42_u8))
                .await
                .expect("coordinator operation");
            ready_sender.send(()).expect("ready receiver");
            continue_receiver.await.expect("continue signal");
            value
        });

        ready_receiver.await.expect("worker entered await");
        let query = with_coordinator(&coordinator, |_coordinator| Ok(7_u8))
            .await
            .expect("query must not wait for worker");
        assert_eq!(query, 7);
        continue_sender.send(()).expect("worker receiver");
        assert_eq!(worker.await.expect("worker task"), 42);
    }

    #[tokio::test]
    async fn requires_hello_and_binds_authenticated_identity() {
        let mut service = service();
        let before_hello = service
            .dispatch(
                envelope(envelope::ControlMessage::CapabilityRequest(
                    CapabilityRequest {},
                )),
                1_000_000_000,
            )
            .await
            .expect("dispatch");
        assert!(matches!(
            before_hello.message,
            Some(envelope::ControlMessage::Error(_))
        ));
        let changed = service
            .dispatch(
                envelope(envelope::ControlMessage::HelloRequest(HelloRequest {
                    node_id: vec![8; 16],
                    node_name: "changed".to_owned(),
                    min_minor: 0,
                    max_minor: PROTOCOL_MINOR,
                })),
                1_000_000_000,
            )
            .await
            .expect("dispatch");
        assert!(matches!(
            changed.message,
            Some(envelope::ControlMessage::Error(_))
        ));
        hello(&mut service).await;
        let capabilities = service
            .dispatch(
                envelope(envelope::ControlMessage::CapabilityRequest(
                    CapabilityRequest {},
                )),
                1_000_000_000,
            )
            .await
            .expect("dispatch");
        let Some(envelope::ControlMessage::CapabilityResponse(capabilities)) = capabilities.message
        else {
            panic!("capability response");
        };
        assert_eq!(capabilities.capabilities.len(), 2);
    }

    #[tokio::test]
    async fn prepares_tcp_download_sender_without_allocating_receiver() {
        let mut service = service();
        hello(&mut service).await;
        let response = service
            .dispatch(
                envelope(envelope::ControlMessage::PrepareTest(PrepareTest {
                    session_id: vec![7; 16],
                    operation_id: "prepare-1".to_owned(),
                    test_type: "tcp".to_owned(),
                    backend: "socket".to_owned(),
                    direction: "download".to_owned(),
                    duration_ms: 1_000,
                    warmup_ms: 100,
                    cooldown_ms: 100,
                    streams: 1,
                    frame_size: 0,
                    payload_size: 0,
                    target_rate_bps: 0,
                    mtu: 0,
                    source_data_port: 0,
                    receive_data_port: 50_000,
                    accelerated_pci_address: String::new(),
                    remote_accelerated_pci_address: String::new(),
                    remote_mac_address: String::new(),
                })),
                1_000_000_000,
            )
            .await
            .expect("dispatch");
        let Some(envelope::ControlMessage::PrepareTestResponse(response)) = response.message else {
            panic!("prepare response");
        };
        assert!(response.ready);
        assert_eq!(response.data_port, 0);
        assert!(!response.authorization_tag.is_empty());
    }

    #[tokio::test]
    #[ignore = "requires permission to bind a loopback TCP socket"]
    async fn prepares_tcp_bidirectional_with_dynamic_receiver_port() {
        let mut service = service();
        hello(&mut service).await;
        let response = service
            .dispatch(
                envelope(envelope::ControlMessage::PrepareTest(PrepareTest {
                    session_id: vec![8; 16],
                    operation_id: "prepare-bidi".to_owned(),
                    test_type: "tcp".to_owned(),
                    backend: "socket".to_owned(),
                    direction: "bidirectional".to_owned(),
                    duration_ms: 1_000,
                    warmup_ms: 100,
                    cooldown_ms: 100,
                    streams: 1,
                    frame_size: 0,
                    payload_size: 0,
                    target_rate_bps: 0,
                    mtu: 0,
                    source_data_port: 0,
                    receive_data_port: 50_001,
                    accelerated_pci_address: String::new(),
                    remote_accelerated_pci_address: String::new(),
                    remote_mac_address: String::new(),
                })),
                1_000_000_000,
            )
            .await
            .expect("dispatch");
        let Some(envelope::ControlMessage::PrepareTestResponse(response)) = response.message else {
            panic!("prepare response");
        };
        assert!(response.ready);
        assert_ne!(response.data_port, 0);
        assert_eq!(response.source_data_port, 0);
    }

    #[tokio::test]
    #[ignore = "requires permission to bind a loopback UDP socket"]
    async fn prepares_udp_and_acknowledges_scheduled_start() {
        let mut service = service();
        hello(&mut service).await;
        let prepared = service
            .dispatch(
                envelope(envelope::ControlMessage::PrepareTest(PrepareTest {
                    session_id: vec![7; 16],
                    operation_id: "prepare-1".to_owned(),
                    test_type: "udp".to_owned(),
                    backend: "socket".to_owned(),
                    direction: "upload".to_owned(),
                    duration_ms: 1_000,
                    warmup_ms: 100,
                    cooldown_ms: 100,
                    streams: 1,
                    frame_size: 0,
                    payload_size: 1_200,
                    target_rate_bps: 1_000_000,
                    mtu: 1_500,
                    source_data_port: 50_000,
                    receive_data_port: 0,
                    accelerated_pci_address: String::new(),
                    remote_accelerated_pci_address: String::new(),
                    remote_mac_address: String::new(),
                })),
                1_000_000_000,
            )
            .await
            .expect("dispatch");
        assert!(matches!(
            prepared.message,
            Some(envelope::ControlMessage::PrepareTestResponse(_))
        ));
        let started = service
            .dispatch(
                envelope(envelope::ControlMessage::StartTest(StartTest {
                    session_id: vec![7; 16],
                    operation_id: "start-1".to_owned(),
                    start_at_unix_nanoseconds: 2_000_000_000,
                })),
                1_500_000_000,
            )
            .await
            .expect("dispatch");
        let Some(envelope::ControlMessage::TestStatus(status)) = started.message else {
            panic!("status");
        };
        assert_eq!(status.state, "TEST_READY");
    }
}

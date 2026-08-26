#[allow(clippy::wildcard_imports)]
use super::*;

impl SessionCoordinator {
    /// 配置同一 UDP socket 的 receiver 與 sender，兩方向共享 authorization tag。
    ///
    /// # Errors
    ///
    /// Request、bind、resource 或 operation ID 無效時回傳錯誤。
    pub async fn prepare_udp_bidirectional(
        &mut self,
        request: PrepareUdpBidirectionalRequest,
        now_unix_seconds: u64,
    ) -> Result<PrepareUdpResponse, NetToolError> {
        if let Some(record) = self.operations.get(&request.operation_id) {
            return match record {
                OperationRecord::PrepareUdpBidirectional {
                    request: stored,
                    response,
                } if *stored == request => Ok(response.clone()),
                _ => Err(operation_conflict()),
            };
        }
        validate_udp_bidirectional_prepare(&request)?;
        if self.session_exists(request.session_id) {
            return Err(NetToolError::new(
                ErrorCode::ResourceConflict,
                "session ID already exists",
                false,
            ));
        }
        let expires_at = now_unix_seconds
            .checked_add(request.authorization_ttl_seconds)
            .ok_or_else(|| invalid("authorization expiration overflow"))?;
        let socket = UdpSocket::bind(SocketAddr::new(request.bind_address, 0))
            .await
            .map_err(io_error)?;
        let local_address = socket.local_addr().map_err(io_error)?;
        let authorization_tag = random_tag()?;
        let reservation_id = format!("udp-bidirectional-{}", hex_session_id(request.session_id));
        self.resources.reserve(ReservationRequest {
            reservation_id: reservation_id.clone(),
            session_id: hex_session_id(request.session_id),
            claims: vec![ResourceClaim {
                resource: ResourceKey::DataPort {
                    protocol: "udp".to_owned(),
                    address: local_address.ip().to_string(),
                    port: local_address.port(),
                },
                mode: ResourceMode::Exclusive,
                units: 1,
            }],
        })?;
        self.resources.activate(&reservation_id)?;
        let response = PrepareUdpResponse {
            session_id: request.session_id,
            data_port: local_address.port(),
            authorization_tag: authorization_tag.clone(),
            expires_at_unix_seconds: expires_at,
            state: NodeConnectionState::TestReady,
        };
        let authorization = DataPlaneAuthorization {
            session_id: request.session_id,
            source_node_id: request.source_node_id,
            source_address: request.source_address.ip(),
            source_port: Some(request.source_address.port()),
            destination_address: local_address.ip(),
            protocol: "udp".to_owned(),
            destination_port: local_address.port(),
            authorization_tag: authorization_tag.clone(),
            expires_at_unix_seconds: expires_at,
        };
        let sender_config = UdpSenderConfig {
            session_id: request.session_id,
            stream_id: request.stream_id,
            datagram_bytes: request.datagram_bytes,
            measurement_milliseconds: request.measurement_milliseconds,
            target_bits_per_second: request.target_bits_per_second,
            maximum_packets_per_burst: 32,
            authorization_tag,
        };
        let mut lifecycle = SpeedTestLifecycle::new();
        lifecycle.negotiated()?;
        lifecycle.mark_ready(BarrierPeer::Local)?;
        self.udp_sessions.insert(
            request.session_id,
            UdpSession {
                response: response.clone(),
                authorization,
                socket: Some(socket),
                stream_id: request.stream_id,
                maximum_datagram_bytes: request.datagram_bytes,
                idle_timeout_milliseconds: 2_000,
                state: NodeConnectionState::TestReady,
                reservation_id,
                lifecycle,
                sender_destination: Some(request.destination),
                sender_config: Some(sender_config),
            },
        );
        self.operations.insert(
            request.operation_id.clone(),
            OperationRecord::PrepareUdpBidirectional {
                request,
                response: response.clone(),
            },
        );
        Ok(response)
    }
}

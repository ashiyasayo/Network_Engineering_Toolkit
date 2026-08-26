#[allow(clippy::wildcard_imports)]
use super::*;

impl SessionCoordinator {
    /// 驗證資源、配置 dynamic UDP port 並建立 endpoint-bound authorization。
    ///
    /// 相同 operation/request 重送回傳原 response，不會配置第二個 socket。
    ///
    /// # Errors
    ///
    /// Request 無效、ID 衝突、bind/resource/random 失敗時回傳錯誤。
    pub async fn prepare_udp(
        &mut self,
        request: PrepareUdpRequest,
        now_unix_seconds: u64,
    ) -> Result<PrepareUdpResponse, NetToolError> {
        if let Some(record) = self.operations.get(&request.operation_id) {
            return match record {
                OperationRecord::PrepareUdp {
                    request: stored,
                    response,
                } if *stored == request => Ok(response.clone()),
                _ => Err(operation_conflict()),
            };
        }
        validate_udp_prepare(&request)?;
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
        let socket = UdpSocket::bind(request.bind_address)
            .await
            .map_err(io_error)?;
        let local_address = socket.local_addr().map_err(io_error)?;
        let authorization_tag = random_tag()?;
        let reservation_id = format!("data-port-{}", hex_session_id(request.session_id));
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
            authorization_tag,
            expires_at_unix_seconds: expires_at,
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
                maximum_datagram_bytes: request.maximum_datagram_bytes,
                idle_timeout_milliseconds: request.idle_timeout_milliseconds,
                state: NodeConnectionState::TestReady,
                reservation_id,
                lifecycle,
                sender_destination: None,
                sender_config: None,
            },
        );
        self.operations.insert(
            request.operation_id.clone(),
            OperationRecord::PrepareUdp {
                request,
                response: response.clone(),
            },
        );
        Ok(response)
    }

    /// 保留 UDP sender socket，等待共同 start time 後傳送至 initiator receiver。
    ///
    /// # Errors
    ///
    /// Request、endpoint、resource、bind 或 operation ID 無效時回傳錯誤。
    pub async fn prepare_udp_sender(
        &mut self,
        request: PrepareUdpSenderRequest,
        now_unix_seconds: u64,
    ) -> Result<PrepareUdpResponse, NetToolError> {
        if let Some(record) = self.operations.get(&request.operation_id) {
            return match record {
                OperationRecord::PrepareUdpSender {
                    request: stored,
                    response,
                } if *stored == request => Ok(response.clone()),
                _ => Err(operation_conflict()),
            };
        }
        validate_udp_sender_prepare(&request)?;
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
        let socket = UdpSocket::bind(SocketAddr::new(request.source_address, 0))
            .await
            .map_err(io_error)?;
        let local_address = socket.local_addr().map_err(io_error)?;
        let authorization_tag = random_tag()?;
        let reservation_id = format!("udp-sender-{}", hex_session_id(request.session_id));
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
            data_port: 0,
            authorization_tag: authorization_tag.clone(),
            expires_at_unix_seconds: expires_at,
            state: NodeConnectionState::TestReady,
        };
        let authorization = DataPlaneAuthorization {
            session_id: request.session_id,
            source_node_id: request.source_node_id,
            source_address: local_address.ip(),
            source_port: Some(local_address.port()),
            destination_address: request.destination.ip(),
            protocol: "udp".to_owned(),
            destination_port: request.destination.port(),
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
            OperationRecord::PrepareUdpSender {
                request,
                response: response.clone(),
            },
        );
        Ok(response)
    }
}

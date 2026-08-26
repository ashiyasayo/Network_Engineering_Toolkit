#[allow(clippy::wildcard_imports)]
use super::*;

impl SessionCoordinator {
    /// 配置同一 session 的 TCP receiver listener 與 sender destination。
    ///
    /// # Errors
    ///
    /// Request、bind、resource 或 operation ID 無效時回傳錯誤。
    pub async fn prepare_tcp_bidirectional(
        &mut self,
        request: PrepareTcpBidirectionalRequest,
        now_unix_seconds: u64,
    ) -> Result<PrepareTcpResponse, NetToolError> {
        if let Some(record) = self.operations.get(&request.operation_id) {
            return match record {
                OperationRecord::PrepareTcpBidirectional {
                    request: stored,
                    response,
                } if *stored == request => Ok(response.clone()),
                _ => Err(operation_conflict()),
            };
        }
        validate_tcp_bidirectional_prepare(&request)?;
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
        let listener = TcpListener::bind(request.bind_address)
            .await
            .map_err(io_error)?;
        let local_address = listener.local_addr().map_err(io_error)?;
        let authorization_tag = random_tag()?;
        let reservation_id = format!("tcp-bidirectional-{}", hex_session_id(request.session_id));
        self.resources.reserve(ReservationRequest {
            reservation_id: reservation_id.clone(),
            session_id: hex_session_id(request.session_id),
            claims: vec![ResourceClaim {
                resource: ResourceKey::DataPort {
                    protocol: "tcp".to_owned(),
                    address: local_address.ip().to_string(),
                    port: local_address.port(),
                },
                mode: ResourceMode::Exclusive,
                units: 1,
            }],
        })?;
        self.resources.activate(&reservation_id)?;
        let response = PrepareTcpResponse {
            session_id: request.session_id,
            data_port: local_address.port(),
            authorization_tag: authorization_tag.clone(),
            expires_at_unix_seconds: expires_at,
            state: NodeConnectionState::TestReady,
        };
        let authorization = DataPlaneAuthorization {
            session_id: request.session_id,
            source_node_id: request.source_node_id,
            source_address: request.source_address,
            source_port: None,
            destination_address: local_address.ip(),
            protocol: "tcp".to_owned(),
            destination_port: local_address.port(),
            authorization_tag,
            expires_at_unix_seconds: expires_at,
        };
        let mut lifecycle = SpeedTestLifecycle::new();
        lifecycle.negotiated()?;
        lifecycle.mark_ready(BarrierPeer::Local)?;
        self.tcp_sessions.insert(
            request.session_id,
            TcpSession {
                response: response.clone(),
                authorization,
                config: request.config,
                listener: Some(listener),
                state: NodeConnectionState::TestReady,
                reservation_id,
                lifecycle,
                sender_destination: Some(request.destination),
                sender_config: Some(request.config),
            },
        );
        self.operations.insert(
            request.operation_id.clone(),
            OperationRecord::PrepareTcpBidirectional {
                request,
                response: response.clone(),
            },
        );
        Ok(response)
    }
}

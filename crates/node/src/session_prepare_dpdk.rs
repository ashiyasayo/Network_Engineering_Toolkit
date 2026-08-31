#[allow(clippy::wildcard_imports)]
use super::*;

impl SessionCoordinator {
    /// 建立 DPDK RX session；硬體 queue 配置延後至 Agent scheduler 到點時建立。
    ///
    /// # Errors
    ///
    /// Request 欄位無效、session/資源衝突、授權期限溢位或資源啟用失敗時回傳錯誤。
    pub fn prepare_dpdk_receiver(
        &mut self,
        request: PrepareDpdkReceiverRequest,
        now_unix_seconds: u64,
    ) -> Result<PreparedDpdkReceiver, NetToolError> {
        if let Some(record) = self.operations.get(&request.operation_id) {
            return match record {
                OperationRecord::PrepareDpdkReceiver {
                    request: stored,
                    plan,
                } if *stored == request => Ok(plan.clone()),
                _ => Err(operation_conflict()),
            };
        }
        if !valid_dpdk_bdf(&request.pci_address) {
            return Err(invalid("DPDK receiver requires a valid PCI BDF"));
        }
        if request.duration_milliseconds == 0 || request.duration_milliseconds > 86_400_000 {
            return Err(invalid("DPDK receiver duration is outside the valid range"));
        }
        if !valid_dpdk_mac(&request.remote_mac_address) {
            return Err(invalid("DPDK receiver requires a valid remote unicast MAC"));
        }
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
        let reservation_id = format!("dpdk-rx-{}", hex_session_id(request.session_id));
        self.resources.reserve(ReservationRequest {
            reservation_id: reservation_id.clone(),
            session_id: hex_session_id(request.session_id),
            claims: vec![ResourceClaim {
                resource: ResourceKey::ManagementInterface(format!("pci:{}", request.pci_address)),
                mode: ResourceMode::Exclusive,
                units: 1,
            }],
        })?;
        self.resources.activate(&reservation_id)?;
        let authorization_tag = random_tag()?;
        let source_address = IpAddr::from([0, 0, 0, 0]);
        let authorization = DataPlaneAuthorization {
            session_id: request.session_id,
            source_node_id: request.source_node_id,
            source_address,
            source_port: None,
            destination_address: source_address,
            protocol: "dpdk-raw".to_owned(),
            destination_port: 0,
            authorization_tag,
            expires_at_unix_seconds: expires_at,
        };
        let mut lifecycle = SpeedTestLifecycle::new();
        lifecycle.negotiated()?;
        lifecycle.mark_ready(BarrierPeer::Local)?;
        let plan = PreparedDpdkReceiver {
            pci_address: request.pci_address.clone(),
            duration_milliseconds: request.duration_milliseconds,
            remote_mac_address: request.remote_mac_address.clone(),
        };
        self.dpdk_sessions.insert(
            request.session_id,
            DpdkSession {
                authorization,
                state: NodeConnectionState::TestReady,
                reservation_id,
                lifecycle,
                plan: Some(plan.clone()),
            },
        );
        self.operations.insert(
            request.operation_id.clone(),
            OperationRecord::PrepareDpdkReceiver {
                request,
                plan: plan.clone(),
            },
        );
        Ok(plan)
    }

    /// 到點後原子取走 DPDK RX 計畫，避免重複 scheduler 啟動兩個 worker。
    ///
    /// # Errors
    ///
    /// Session 不是 DPDK RX、尚未到排定時間或 worker 已被取走時回傳錯誤。
    pub fn begin_and_take_dpdk_receiver(
        &mut self,
        session_id: [u8; 16],
        now_unix_nanoseconds: u64,
    ) -> Result<PreparedDpdkReceiver, NetToolError> {
        if !self.dpdk_sessions.contains_key(&session_id) {
            return Err(invalid_state("session is not a DPDK receiver"));
        }
        self.begin_scheduled(session_id, now_unix_nanoseconds)?;
        let session = self
            .dpdk_sessions
            .get_mut(&session_id)
            .ok_or_else(|| invalid_state("session is not a DPDK receiver"))?;
        session
            .plan
            .take()
            .ok_or_else(|| invalid_state("DPDK receiver worker was already taken"))
    }
}

fn valid_dpdk_bdf(value: &str) -> bool {
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

fn valid_dpdk_mac(value: &str) -> bool {
    let parts: Vec<_> = value.split(':').collect();
    parts.len() == 6
        && parts
            .iter()
            .all(|part| part.len() == 2 && part.bytes().all(|byte| byte.is_ascii_hexdigit()))
        && u8::from_str_radix(parts[0], 16).is_ok_and(|first| first != 0 && first & 1 == 0)
}

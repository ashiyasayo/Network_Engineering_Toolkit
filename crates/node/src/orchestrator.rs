use getrandom::fill as random_fill;
use nettool_domain::{Direction, SpeedProtocol};
use nettool_error::{ErrorCode, NetToolError};
use nettool_node_protocol::{StartTest, StopTest, TestResult, TestStatus};
use nettool_speed::SpeedRunRequest;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{LocalDataPlanePorts, NodeControlClient, SpeedSessionPlan, plan_speed_session};

const STATUS_RUNNING: &str = "RUNNING";
const STATUS_TEST_READY: &str = "TEST_READY";
const STATUS_CANCELED: &str = "CANCELED";

/// 已由遠端 Node 保留資源，並可進入同步 start barrier 的 Speed session。
#[derive(Clone, Debug, PartialEq)]
pub struct PreparedRemoteSpeedSession {
    /// 全控制面與資料平面共用的 128-bit session ID。
    pub session_id: [u8; 16],
    /// 經 capability negotiation 驗證的執行計畫。
    pub plan: SpeedSessionPlan,
    /// Receiver 動態配置的 data-plane port；raw packet test 可為零。
    pub remote_data_port: u16,
    /// Remote sender source port；UDP download/bidirectional 必須比對。
    pub remote_source_data_port: u16,
    /// 遠端簽發且只適用於此 session 的 data-plane authorization tag。
    pub authorization_tag: String,
}

impl PreparedRemoteSpeedSession {
    /// 排定遠端 session 開始，並嚴格驗證回覆的 session 與狀態。
    ///
    /// # Errors
    ///
    /// Operation ID、開始時間、transport 或遠端 status 無效時回傳錯誤。
    pub async fn start<S>(
        &self,
        client: &mut NodeControlClient<S>,
        operation_id: &str,
        start_at_unix_nanoseconds: u64,
    ) -> Result<(), NetToolError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        validate_operation_id(operation_id)?;
        if start_at_unix_nanoseconds == 0 {
            return Err(invalid("scheduled start timestamp must be non-zero"));
        }
        let status = client
            .start_test(StartTest {
                session_id: self.session_id.to_vec(),
                operation_id: operation_id.to_owned(),
                start_at_unix_nanoseconds,
            })
            .await?;
        validate_status_any(
            &status,
            self.session_id,
            &[STATUS_TEST_READY, STATUS_RUNNING],
        )
    }

    /// 取消遠端 session，並嚴格驗證回覆的 session 與狀態。
    ///
    /// # Errors
    ///
    /// Operation ID、transport 或遠端 status 無效時回傳錯誤。
    pub async fn stop<S>(
        &self,
        client: &mut NodeControlClient<S>,
        operation_id: &str,
    ) -> Result<(), NetToolError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        validate_operation_id(operation_id)?;
        let status = client
            .stop_test(StopTest {
                session_id: self.session_id.to_vec(),
                operation_id: operation_id.to_owned(),
            })
            .await?;
        validate_status(&status, self.session_id, STATUS_CANCELED)
    }

    /// 可重試地取得 remote final result；client 會驗證 session 與 checksum。
    ///
    /// # Errors
    ///
    /// Result 尚未就緒、transport、correlation 或 checksum 無效時回傳錯誤。
    pub async fn result<S>(
        &self,
        client: &mut NodeControlClient<S>,
    ) -> Result<TestResult, NetToolError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        client.test_result(self.session_id).await
    }
}

/// 查詢遠端 runtime capability、建立計畫並原子準備 Speed session。
///
/// 本函式不會自行 bind 本機 data-plane。呼叫端必須先配置 endpoint，再傳入實際
/// `source_data_port`，才能避免遠端 UDP authorization 放寬來源限制。
///
/// # Errors
///
/// Capability、計畫、transport 或 Prepare response 無效時回傳錯誤。
pub async fn prepare_remote_speed_session<S>(
    client: &mut NodeControlClient<S>,
    request: &SpeedRunRequest,
    operation_id: &str,
    session_id: [u8; 16],
    local_ports: LocalDataPlanePorts,
) -> Result<PreparedRemoteSpeedSession, NetToolError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let capabilities = client.capabilities().await?;
    let plan = plan_speed_session(
        request,
        operation_id,
        session_id,
        local_ports,
        &capabilities.capabilities,
    )?;
    let response = client.prepare_test(plan.prepare.clone()).await?;
    if !response.ready {
        return Err(NetToolError::new(
            ErrorCode::InvalidState,
            "remote Node did not enter TEST_READY after prepare",
            true,
        ));
    }
    if response.authorization_tag.trim().is_empty() {
        return Err(protocol(
            "prepare response does not contain an authorization tag",
        ));
    }
    let remote_data_port = u16::try_from(response.data_port)
        .map_err(|_| protocol("prepare response data port is outside the valid range"))?;
    let remote_source_data_port = u16::try_from(response.source_data_port)
        .map_err(|_| protocol("prepare response source port is outside the valid range"))?;
    let remote_receives = matches!(
        request.direction,
        Direction::Upload | Direction::Bidirectional
    );
    let remote_sends = matches!(
        request.direction,
        Direction::Download | Direction::Bidirectional
    );
    if request.protocol != SpeedProtocol::Raw && remote_receives && remote_data_port == 0 {
        return Err(protocol(
            "socket prepare response does not contain a dynamic data port",
        ));
    }
    if request.protocol == SpeedProtocol::Udp && remote_sends && remote_source_data_port == 0 {
        return Err(protocol(
            "UDP prepare response does not contain the remote sender source port",
        ));
    }
    Ok(PreparedRemoteSpeedSession {
        session_id,
        plan,
        remote_data_port,
        remote_source_data_port,
        authorization_tag: response.authorization_tag,
    })
}

/// 建立不可預測且不為全零的 128-bit session ID。
///
/// # Errors
///
/// 平台安全亂數來源失敗時回傳錯誤。
pub fn random_session_id() -> Result<[u8; 16], NetToolError> {
    loop {
        let mut value = [0_u8; 16];
        random_fill(&mut value).map_err(|error| {
            NetToolError::new(
                ErrorCode::RandomFailed,
                format!("cannot generate Node session ID: {error}"),
                false,
            )
        })?;
        if value != [0; 16] {
            return Ok(value);
        }
    }
}

fn validate_status(
    status: &TestStatus,
    expected_session_id: [u8; 16],
    expected_state: &'static str,
) -> Result<(), NetToolError> {
    if status.session_id.as_slice() != expected_session_id {
        return Err(protocol("test status session ID mismatch"));
    }
    if status.state != expected_state {
        return Err(NetToolError::new(
            ErrorCode::InvalidState,
            format!(
                "remote Node returned state {} instead of {expected_state}",
                status.state
            ),
            false,
        ));
    }
    Ok(())
}

fn validate_status_any(
    status: &TestStatus,
    expected_session_id: [u8; 16],
    expected_states: &[&str],
) -> Result<(), NetToolError> {
    if status.session_id.as_slice() != expected_session_id {
        return Err(protocol("test status session ID mismatch"));
    }
    if !expected_states.contains(&status.state.as_str()) {
        return Err(NetToolError::new(
            ErrorCode::InvalidState,
            format!("remote Node returned unexpected state {}", status.state),
            false,
        ));
    }
    Ok(())
}

fn validate_operation_id(operation_id: &str) -> Result<(), NetToolError> {
    if operation_id.trim().is_empty() {
        return Err(invalid("Node operation ID must not be empty"));
    }
    Ok(())
}

fn protocol(message: &'static str) -> NetToolError {
    NetToolError::new(ErrorCode::ProtocolInvalid, message, false)
}

fn invalid(message: &'static str) -> NetToolError {
    NetToolError::new(ErrorCode::InvalidArgument, message, false)
}

#[cfg(test)]
mod tests {
    use super::{prepare_remote_speed_session, random_session_id};
    use crate::{
        LocalDataPlanePorts, LocalNodeIdentity, NodeControlClient, read_control_frame,
        write_control_frame,
    };
    use nettool_domain::{Direction, SpeedProtocol};
    use nettool_node_protocol::{
        CapabilityMessage, CapabilityResponse, Envelope, HelloResponse, PROTOCOL_MAJOR,
        PROTOCOL_MINOR, PrepareTestResponse, TestStatus, envelope,
    };
    use nettool_speed::SpeedRunRequest;

    fn request() -> SpeedRunRequest {
        SpeedRunRequest {
            node: "node-b".to_owned(),
            protocol: SpeedProtocol::Udp,
            backend: "socket".to_owned(),
            direction: Direction::Upload,
            duration_ms: 10_000,
            warmup_ms: 1_000,
            cooldown_ms: 1_000,
            streams: Some(2),
            frame_size: None,
            target_rate_bps: Some(1_000_000_000),
            auto_tune: false,
            latency_under_load: false,
            cpus: None,
            numa_node: None,
            accelerated_pci_address: None,
            accelerated_interface_name: None,
        }
    }

    async fn respond(
        stream: &mut tokio::io::DuplexStream,
        message: envelope::ControlMessage,
    ) -> Envelope {
        let request = read_control_frame(stream).await.expect("request");
        write_control_frame(
            stream,
            &Envelope {
                protocol_major: PROTOCOL_MAJOR,
                protocol_minor: PROTOCOL_MINOR,
                request_id: request.request_id.clone(),
                message: Some(message),
            },
        )
        .await
        .expect("response");
        request
    }

    async fn negotiated_client(
        client_stream: tokio::io::DuplexStream,
        remote_id: [u8; 16],
    ) -> NodeControlClient<tokio::io::DuplexStream> {
        NodeControlClient::negotiate(
            client_stream,
            &LocalNodeIdentity {
                node_id: [1; 16],
                name: "local".to_owned(),
            },
            remote_id,
        )
        .await
        .expect("negotiate")
    }

    #[tokio::test]
    async fn prepares_starts_and_stops_correlated_session() {
        let session_id = [7; 16];
        let remote_id = [2; 16];
        let (client_stream, mut server_stream) = tokio::io::duplex(32 * 1024);
        let server = tokio::spawn(async move {
            respond(
                &mut server_stream,
                envelope::ControlMessage::HelloResponse(HelloResponse {
                    selected_minor: PROTOCOL_MINOR,
                    node_id: remote_id.to_vec(),
                    node_name: "remote".to_owned(),
                }),
            )
            .await;
            respond(
                &mut server_stream,
                envelope::ControlMessage::CapabilityResponse(CapabilityResponse {
                    capabilities: vec![CapabilityMessage {
                        id: 0x0002,
                        min_version: 1,
                        max_version: 1,
                        available: true,
                    }],
                }),
            )
            .await;
            let prepare = respond(
                &mut server_stream,
                envelope::ControlMessage::PrepareTestResponse(PrepareTestResponse {
                    ready: true,
                    data_port: 49_152,
                    authorization_tag: "session-secret".to_owned(),
                    source_data_port: 0,
                }),
            )
            .await;
            assert!(matches!(
                prepare.message,
                Some(envelope::ControlMessage::PrepareTest(_))
            ));
            let start = respond(
                &mut server_stream,
                envelope::ControlMessage::TestStatus(TestStatus {
                    session_id: session_id.to_vec(),
                    state: "RUNNING".to_owned(),
                }),
            )
            .await;
            assert!(matches!(
                start.message,
                Some(envelope::ControlMessage::StartTest(_))
            ));
            let stop = respond(
                &mut server_stream,
                envelope::ControlMessage::TestStatus(TestStatus {
                    session_id: session_id.to_vec(),
                    state: "CANCELED".to_owned(),
                }),
            )
            .await;
            assert!(matches!(
                stop.message,
                Some(envelope::ControlMessage::StopTest(_))
            ));
        });
        let mut client = negotiated_client(client_stream, remote_id).await;
        let prepared = prepare_remote_speed_session(
            &mut client,
            &request(),
            "prepare-1",
            session_id,
            LocalDataPlanePorts {
                send: 50_000,
                receive: 0,
            },
        )
        .await
        .expect("prepare");
        assert_eq!(prepared.remote_data_port, 49_152);
        assert_eq!(prepared.authorization_tag, "session-secret");
        prepared
            .start(&mut client, "start-1", 1_800_000_000_000_000_000)
            .await
            .expect("start");
        prepared.stop(&mut client, "stop-1").await.expect("stop");
        server.await.expect("server");
    }

    #[tokio::test]
    async fn rejects_unusable_prepare_response() {
        let remote_id = [2; 16];
        let (client_stream, mut server_stream) = tokio::io::duplex(16 * 1024);
        let server = tokio::spawn(async move {
            respond(
                &mut server_stream,
                envelope::ControlMessage::HelloResponse(HelloResponse {
                    selected_minor: PROTOCOL_MINOR,
                    node_id: remote_id.to_vec(),
                    node_name: "remote".to_owned(),
                }),
            )
            .await;
            respond(
                &mut server_stream,
                envelope::ControlMessage::CapabilityResponse(CapabilityResponse {
                    capabilities: vec![CapabilityMessage {
                        id: 0x0002,
                        min_version: 1,
                        max_version: 1,
                        available: true,
                    }],
                }),
            )
            .await;
            respond(
                &mut server_stream,
                envelope::ControlMessage::PrepareTestResponse(PrepareTestResponse {
                    ready: true,
                    data_port: 0,
                    authorization_tag: "session-secret".to_owned(),
                    source_data_port: 0,
                }),
            )
            .await;
        });
        let mut client = negotiated_client(client_stream, remote_id).await;
        assert!(
            prepare_remote_speed_session(
                &mut client,
                &request(),
                "prepare-1",
                [7; 16],
                LocalDataPlanePorts {
                    send: 50_000,
                    receive: 0,
                }
            )
            .await
            .is_err()
        );
        server.await.expect("server");
    }

    #[test]
    fn creates_nonzero_session_ids() {
        assert_ne!(random_session_id().expect("session ID"), [0; 16]);
    }
}

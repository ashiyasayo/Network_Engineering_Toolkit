use getrandom::fill as random_fill;
use nettool_error::{ErrorCode, NetToolError};
use nettool_node_protocol::{
    CapabilityRequest, CapabilityResponse, Envelope, HelloRequest, HelloResponse, PROTOCOL_MAJOR,
    PROTOCOL_MINOR, Ping, Pong, PrepareTest, PrepareTestResponse, ProtocolError, StartTest,
    StopTest, TestResult, TestResultRequest, TestStatus, TrustDecision, envelope,
    fingerprint_sha256, verify_identity,
};
use rustls::ClientConfig;
use rustls_pki_types::ServerName;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::{TlsConnector, client::TlsStream};

use crate::{read_control_frame, write_control_frame};

const RESULT_QUERY_MINIMUM_MINOR: u32 = 1;

/// 本機 control-plane identity。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalNodeIdentity {
    /// Stable 128-bit Node ID。
    pub node_id: [u8; 16],
    /// Node 顯示名稱。
    pub name: String,
}

/// 已由 pairing store 驗證的遠端 control endpoint。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedNodeEndpoint {
    /// TCP control endpoint。
    pub address: SocketAddr,
    /// TLS server name。
    pub server_name: String,
    /// Pairing record 的 stable Node ID。
    pub node_id: [u8; 16],
    /// Pairing 時保存的完整 `SubjectPublicKeyInfo` DER SHA-256 fingerprint。
    pub public_key_fingerprint: String,
    /// TCP connect、TLS handshake 與 Hello 各階段 timeout。
    pub timeout_milliseconds: u64,
}

/// 已完成 Hello/version/identity negotiation 的 sequential NTCP client。
pub struct NodeControlClient<S> {
    stream: S,
    remote_node_id: [u8; 16],
    negotiated_minor: u32,
}

impl<S> NodeControlClient<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// 在既有安全 stream 上執行 Hello negotiation 並綁定預期 Node ID。
    ///
    /// # Errors
    ///
    /// Identity、version、request ID 或 response type 不符合時回傳錯誤。
    pub async fn negotiate(
        stream: S,
        local: &LocalNodeIdentity,
        expected_remote_node_id: [u8; 16],
    ) -> Result<Self, NetToolError> {
        if local.name.trim().is_empty() {
            return Err(invalid("local Node name must not be empty"));
        }
        let mut client = Self {
            stream,
            remote_node_id: expected_remote_node_id,
            negotiated_minor: PROTOCOL_MINOR,
        };
        let response = client
            .exchange(envelope::ControlMessage::HelloRequest(HelloRequest {
                node_id: local.node_id.to_vec(),
                node_name: local.name.clone(),
                min_minor: 0,
                max_minor: PROTOCOL_MINOR,
            }))
            .await?;
        let envelope::ControlMessage::HelloResponse(HelloResponse {
            selected_minor,
            node_id,
            ..
        }) = response
        else {
            return Err(protocol(
                "Hello request received an unexpected response type",
            ));
        };
        if node_id.as_slice() != expected_remote_node_id {
            return Err(NetToolError::new(
                ErrorCode::NodeTlsFailed,
                "Hello Node ID does not match the paired identity",
                false,
            ));
        }
        if selected_minor > PROTOCOL_MINOR {
            return Err(NetToolError::new(
                ErrorCode::ProtocolIncompatible,
                "peer selected an unsupported protocol minor",
                false,
            ));
        }
        client.negotiated_minor = selected_minor;
        Ok(client)
    }

    /// Negotiated remote Node ID。
    #[must_use]
    pub const fn remote_node_id(&self) -> [u8; 16] {
        self.remote_node_id
    }

    /// Negotiated NTCP minor version。
    #[must_use]
    pub const fn negotiated_minor(&self) -> u32 {
        self.negotiated_minor
    }

    /// 查詢 peer runtime capabilities。
    ///
    /// # Errors
    ///
    /// Transport、correlation 或 response type 無效時回傳錯誤。
    pub async fn capabilities(&mut self) -> Result<CapabilityResponse, NetToolError> {
        match self
            .exchange(envelope::ControlMessage::CapabilityRequest(
                CapabilityRequest {},
            ))
            .await?
        {
            envelope::ControlMessage::CapabilityResponse(response) => Ok(response),
            _ => Err(protocol(
                "capability request received an unexpected response type",
            )),
        }
    }

    /// 要求 peer 原子保留資源並準備 data-plane endpoint。
    ///
    /// # Errors
    ///
    /// Transport、remote error 或 response type 無效時回傳錯誤。
    pub async fn prepare_test(
        &mut self,
        request: PrepareTest,
    ) -> Result<PrepareTestResponse, NetToolError> {
        match self
            .exchange(envelope::ControlMessage::PrepareTest(request))
            .await?
        {
            envelope::ControlMessage::PrepareTestResponse(response) => Ok(response),
            _ => Err(protocol(
                "prepare test received an unexpected response type",
            )),
        }
    }

    /// 排定同步開始時間。
    ///
    /// # Errors
    ///
    /// Transport、remote error 或 status response 無效時回傳錯誤。
    pub async fn start_test(&mut self, request: StartTest) -> Result<TestStatus, NetToolError> {
        match self
            .exchange(envelope::ControlMessage::StartTest(request))
            .await?
        {
            envelope::ControlMessage::TestStatus(response) => Ok(response),
            _ => Err(protocol("start test received an unexpected response type")),
        }
    }

    /// 停止或取消遠端 session。
    ///
    /// # Errors
    ///
    /// Transport、remote error 或 status response 無效時回傳錯誤。
    pub async fn stop_test(&mut self, request: StopTest) -> Result<TestStatus, NetToolError> {
        match self
            .exchange(envelope::ControlMessage::StopTest(request))
            .await?
        {
            envelope::ControlMessage::TestStatus(response) => Ok(response),
            _ => Err(protocol("stop test received an unexpected response type")),
        }
    }

    /// 可重試地取得 final result，並驗證 session correlation 與 SHA-256 checksum。
    ///
    /// # Errors
    ///
    /// Session ID、transport、response type、correlation 或 checksum 無效時回傳錯誤。
    pub async fn test_result(&mut self, session_id: [u8; 16]) -> Result<TestResult, NetToolError> {
        if session_id == [0; 16] {
            return Err(invalid("result session ID must not be zero"));
        }
        if self.negotiated_minor < RESULT_QUERY_MINIMUM_MINOR {
            return Err(NetToolError::new(
                ErrorCode::ProtocolIncompatible,
                "peer does not support retryable test result queries",
                false,
            ));
        }
        let envelope::ControlMessage::TestResult(response) = self
            .exchange(envelope::ControlMessage::TestResultRequest(
                TestResultRequest {
                    session_id: session_id.to_vec(),
                },
            ))
            .await?
        else {
            return Err(protocol(
                "result request received an unexpected response type",
            ));
        };
        validate_test_result(&response, session_id)?;
        Ok(response)
    }

    /// Heartbeat 並驗證 nonce correlation。
    ///
    /// # Errors
    ///
    /// Transport、response type 或 nonce 不符時回傳錯誤。
    pub async fn ping(&mut self, nonce: u64) -> Result<(), NetToolError> {
        match self
            .exchange(envelope::ControlMessage::Ping(Ping { nonce }))
            .await?
        {
            envelope::ControlMessage::Pong(Pong { nonce: response }) if response == nonce => Ok(()),
            envelope::ControlMessage::Pong(_) => Err(protocol("heartbeat nonce mismatch")),
            _ => Err(protocol("heartbeat received an unexpected response type")),
        }
    }

    async fn exchange(
        &mut self,
        message: envelope::ControlMessage,
    ) -> Result<envelope::ControlMessage, NetToolError> {
        let request_id = random_request_id()?;
        write_control_frame(
            &mut self.stream,
            &Envelope {
                protocol_major: PROTOCOL_MAJOR,
                protocol_minor: self.negotiated_minor,
                request_id: request_id.to_vec(),
                message: Some(message),
            },
        )
        .await?;
        let response = read_control_frame(&mut self.stream).await?;
        if response.protocol_major != PROTOCOL_MAJOR
            || response.protocol_minor > self.negotiated_minor
        {
            return Err(NetToolError::new(
                ErrorCode::ProtocolIncompatible,
                "peer response protocol version is incompatible",
                false,
            ));
        }
        if response.request_id.as_slice() != request_id {
            return Err(protocol("peer response request ID mismatch"));
        }
        match response.message {
            Some(envelope::ControlMessage::Error(error)) => Err(remote_error(error)),
            Some(message) => Ok(message),
            None => Err(protocol("peer response does not contain a control message")),
        }
    }
}

/// 建立 TCP+mTLS connection、比對 pairing fingerprint，再完成 NTCP Hello。
///
/// # Errors
///
/// Timeout、TLS、certificate fingerprint 或 Hello identity 驗證失敗時回傳錯誤。
pub async fn connect_control_client(
    endpoint: &TrustedNodeEndpoint,
    tls_config: Arc<ClientConfig>,
    local: &LocalNodeIdentity,
) -> Result<NodeControlClient<TlsStream<TcpStream>>, NetToolError> {
    if endpoint.timeout_milliseconds == 0 || endpoint.public_key_fingerprint.trim().is_empty() {
        return Err(invalid(
            "trusted endpoint timeout and fingerprint must be configured",
        ));
    }
    let limit = Duration::from_millis(endpoint.timeout_milliseconds);
    let tcp = timeout(limit, TcpStream::connect(endpoint.address))
        .await
        .map_err(|_| timed_out("Node TCP connect timed out"))?
        .map_err(transport_error)?;
    let server_name = ServerName::try_from(endpoint.server_name.clone()).map_err(|_| {
        NetToolError::new(
            ErrorCode::NodeTlsFailed,
            "TLS server name is invalid",
            false,
        )
    })?;
    let stream = timeout(
        limit,
        TlsConnector::from(tls_config).connect(server_name, tcp),
    )
    .await
    .map_err(|_| timed_out("Node TLS handshake timed out"))?
    .map_err(|error| {
        NetToolError::new(
            ErrorCode::NodeTlsFailed,
            format!("Node TLS handshake failed: {error}"),
            false,
        )
    })?;
    let certificate = stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certificates| certificates.first())
        .ok_or_else(|| {
            NetToolError::new(
                ErrorCode::NodeTlsFailed,
                "peer did not present a certificate",
                false,
            )
        })?;
    let presented = certificate_public_key_fingerprint(certificate.as_ref())?;
    if verify_identity(Some(&endpoint.public_key_fingerprint), &presented) != TrustDecision::Trusted
    {
        return Err(NetToolError::new(
            ErrorCode::NodeTlsFailed,
            "peer certificate fingerprint changed; re-pairing is required",
            false,
        ));
    }
    timeout(
        limit,
        NodeControlClient::negotiate(stream, local, endpoint.node_id),
    )
    .await
    .map_err(|_| timed_out("Node Hello negotiation timed out"))?
}

/// 從完整 X.509 certificate DER 解析 `SubjectPublicKeyInfo` 並計算 trust fingerprint。
///
/// # Errors
///
/// Certificate DER 無效或含未消耗尾端資料時回傳 TLS identity 錯誤。
pub fn certificate_public_key_fingerprint(certificate_der: &[u8]) -> Result<String, NetToolError> {
    let (remaining, certificate) =
        x509_parser::parse_x509_certificate(certificate_der).map_err(|error| {
            NetToolError::new(
                ErrorCode::NodeTlsFailed,
                format!("cannot parse peer X.509 certificate: {error}"),
                false,
            )
        })?;
    if !remaining.is_empty() {
        return Err(NetToolError::new(
            ErrorCode::NodeTlsFailed,
            "peer X.509 certificate contains trailing data",
            false,
        ));
    }
    Ok(fingerprint_sha256(certificate.public_key().raw))
}

fn random_request_id() -> Result<[u8; 16], NetToolError> {
    let mut value = [0_u8; 16];
    random_fill(&mut value).map_err(|error| {
        NetToolError::new(
            ErrorCode::RandomFailed,
            format!("cannot generate Node request ID: {error}"),
            false,
        )
    })?;
    Ok(value)
}

fn validate_test_result(
    response: &TestResult,
    expected_session_id: [u8; 16],
) -> Result<(), NetToolError> {
    if response.session_id.as_slice() != expected_session_id {
        return Err(protocol("test result session ID mismatch"));
    }
    let expected_checksum: [u8; 32] = Sha256::digest(&response.result_json).into();
    if response.checksum.as_slice() != expected_checksum {
        return Err(protocol("test result checksum mismatch"));
    }
    Ok(())
}

fn remote_error(error: ProtocolError) -> NetToolError {
    let mut result = NetToolError::new(
        ErrorCode::NodeTransportFailed,
        format!("remote Node rejected request: {}", error.message),
        error.retryable,
    );
    result.details.insert("remote_code".to_owned(), error.code);
    result
}

#[allow(clippy::needless_pass_by_value)]
fn transport_error(error: std::io::Error) -> NetToolError {
    NetToolError::new(
        ErrorCode::NodeTransportFailed,
        format!("Node TCP connect failed: {error}"),
        true,
    )
}

fn timed_out(message: &'static str) -> NetToolError {
    NetToolError::new(ErrorCode::NodeTransportFailed, message, true)
}

fn protocol(message: &'static str) -> NetToolError {
    NetToolError::new(ErrorCode::ProtocolInvalid, message, false)
}

fn invalid(message: &'static str) -> NetToolError {
    NetToolError::new(ErrorCode::InvalidArgument, message, false)
}

#[cfg(test)]
mod tests {
    use super::{
        LocalNodeIdentity, NodeControlClient, certificate_public_key_fingerprint,
        validate_test_result,
    };
    use crate::{read_control_frame, write_control_frame};
    use nettool_node_protocol::{
        Envelope, HelloResponse, PROTOCOL_MAJOR, PROTOCOL_MINOR, Pong, TestResult, envelope,
        fingerprint_sha256,
    };
    use rcgen::{CertifiedKey, PublicKeyData, generate_simple_self_signed};
    use sha2::{Digest, Sha256};

    #[test]
    fn certificate_fingerprint_uses_subject_public_key_info() {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["localhost".to_owned()]).expect("certificate");
        assert_eq!(
            certificate_public_key_fingerprint(cert.der()).expect("fingerprint"),
            fingerprint_sha256(&signing_key.subject_public_key_info())
        );
        let mut trailing = cert.der().to_vec();
        trailing.push(0);
        assert!(certificate_public_key_fingerprint(&trailing).is_err());
    }

    #[test]
    fn rejects_result_session_or_checksum_mismatch() {
        let mut result = TestResult {
            session_id: vec![7; 16],
            result_json: br#"{"schema_version":"1.0"}"#.to_vec(),
            checksum: vec![0; 32],
        };
        assert!(validate_test_result(&result, [8; 16]).is_err());
        assert!(validate_test_result(&result, [7; 16]).is_err());
        result.checksum = Sha256::digest(&result.result_json).to_vec();
        validate_test_result(&result, [7; 16]).expect("valid result");
    }

    #[tokio::test]
    async fn negotiates_identity_and_correlates_heartbeat() {
        let local_id = [1_u8; 16];
        let remote_id = [2_u8; 16];
        let (client_stream, mut server_stream) = tokio::io::duplex(16 * 1024);
        let server = tokio::spawn(async move {
            let hello = read_control_frame(&mut server_stream).await.expect("hello");
            assert!(matches!(
                hello.message,
                Some(envelope::ControlMessage::HelloRequest(_))
            ));
            write_control_frame(
                &mut server_stream,
                &Envelope {
                    protocol_major: PROTOCOL_MAJOR,
                    protocol_minor: PROTOCOL_MINOR,
                    request_id: hello.request_id,
                    message: Some(envelope::ControlMessage::HelloResponse(HelloResponse {
                        selected_minor: PROTOCOL_MINOR,
                        node_id: remote_id.to_vec(),
                        node_name: "remote".to_owned(),
                    })),
                },
            )
            .await
            .expect("hello response");
            let ping = read_control_frame(&mut server_stream).await.expect("ping");
            let nonce = match ping.message {
                Some(envelope::ControlMessage::Ping(ping)) => ping.nonce,
                _ => panic!("expected ping"),
            };
            write_control_frame(
                &mut server_stream,
                &Envelope {
                    protocol_major: PROTOCOL_MAJOR,
                    protocol_minor: PROTOCOL_MINOR,
                    request_id: ping.request_id,
                    message: Some(envelope::ControlMessage::Pong(Pong { nonce })),
                },
            )
            .await
            .expect("pong");
        });
        let mut client = NodeControlClient::negotiate(
            client_stream,
            &LocalNodeIdentity {
                node_id: local_id,
                name: "local".to_owned(),
            },
            remote_id,
        )
        .await
        .expect("negotiate");
        assert_eq!(client.remote_node_id(), remote_id);
        client.ping(42).await.expect("heartbeat");
        server.await.expect("server");
    }

    #[tokio::test]
    async fn rejects_hello_identity_change() {
        let (client_stream, mut server_stream) = tokio::io::duplex(4096);
        let server = tokio::spawn(async move {
            let hello = read_control_frame(&mut server_stream).await.expect("hello");
            write_control_frame(
                &mut server_stream,
                &Envelope {
                    protocol_major: PROTOCOL_MAJOR,
                    protocol_minor: PROTOCOL_MINOR,
                    request_id: hello.request_id,
                    message: Some(envelope::ControlMessage::HelloResponse(HelloResponse {
                        selected_minor: 0,
                        node_id: vec![9; 16],
                        node_name: "changed".to_owned(),
                    })),
                },
            )
            .await
            .expect("response");
        });
        let result = NodeControlClient::negotiate(
            client_stream,
            &LocalNodeIdentity {
                node_id: [1; 16],
                name: "local".to_owned(),
            },
            [2; 16],
        )
        .await;
        assert!(result.is_err());
        server.await.expect("server");
    }

    #[tokio::test]
    async fn retrieves_correlated_checksum_verified_result() {
        let remote_id = [2_u8; 16];
        let session_id = [7_u8; 16];
        let result_json = br#"{"schema_version":"1.0","bytes":42}"#.to_vec();
        let checksum = Sha256::digest(&result_json).to_vec();
        let (client_stream, mut server_stream) = tokio::io::duplex(8192);
        let server = tokio::spawn(async move {
            let hello = read_control_frame(&mut server_stream).await.expect("hello");
            write_control_frame(
                &mut server_stream,
                &Envelope {
                    protocol_major: PROTOCOL_MAJOR,
                    protocol_minor: PROTOCOL_MINOR,
                    request_id: hello.request_id,
                    message: Some(envelope::ControlMessage::HelloResponse(HelloResponse {
                        selected_minor: PROTOCOL_MINOR,
                        node_id: remote_id.to_vec(),
                        node_name: "remote".to_owned(),
                    })),
                },
            )
            .await
            .expect("hello response");
            let request = read_control_frame(&mut server_stream)
                .await
                .expect("result request");
            assert!(matches!(
                request.message,
                Some(envelope::ControlMessage::TestResultRequest(_))
            ));
            write_control_frame(
                &mut server_stream,
                &Envelope {
                    protocol_major: PROTOCOL_MAJOR,
                    protocol_minor: PROTOCOL_MINOR,
                    request_id: request.request_id,
                    message: Some(envelope::ControlMessage::TestResult(TestResult {
                        session_id: session_id.to_vec(),
                        result_json,
                        checksum,
                    })),
                },
            )
            .await
            .expect("result response");
        });
        let mut client = NodeControlClient::negotiate(
            client_stream,
            &LocalNodeIdentity {
                node_id: [1; 16],
                name: "local".to_owned(),
            },
            remote_id,
        )
        .await
        .expect("negotiate");
        let result = client.test_result(session_id).await.expect("result");
        assert_eq!(result.session_id, session_id);
        server.await.expect("server");
    }
}

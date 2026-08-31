//! Node TLS 1.3 control transport 與 bounded frame I/O。

#![forbid(unsafe_code)]

mod client;
mod orchestrator;
mod planner;
mod server;
mod session;

pub use client::{
    LocalNodeIdentity, NodeControlClient, TrustedNodeEndpoint, certificate_public_key_fingerprint,
    connect_control_client,
};
pub use orchestrator::{
    PreparedRemoteSpeedSession, prepare_remote_speed_session, random_session_id,
};
pub use planner::{
    CAPABILITY_AF_XDP, CAPABILITY_BIDIRECTIONAL, CAPABILITY_DPDK, CAPABILITY_JUMBO_FRAME,
    CAPABILITY_LATENCY, CAPABILITY_LATENCY_UNDER_LOAD, CAPABILITY_RAW_PACKET_GENERATOR,
    CAPABILITY_RIO, CAPABILITY_TCP_SPEED, CAPABILITY_UDP_SPEED, LocalDataPlanePorts,
    SpeedSessionPlan, plan_speed_session,
};
pub use server::NodeControlService;

pub use session::{
    DataPlaneAttempt, DataPlaneAuthorization, PrepareDpdkReceiverRequest,
    PrepareTcpBidirectionalRequest, PrepareTcpRequest, PrepareTcpResponse, PrepareTcpSenderRequest,
    PrepareUdpBidirectionalRequest, PrepareUdpRequest, PrepareUdpResponse, PrepareUdpSenderRequest,
    PreparedDpdkReceiver, PreparedSocketBidirectional, PreparedSocketReceiver,
    PreparedSocketSender, SessionCoordinator, authorize_data_plane,
};

use nettool_error::{ErrorCode, NetToolError};
use nettool_node_protocol::{
    CONTROL_HEADER_BYTES, Envelope, MAX_CONTROL_PAYLOAD_BYTES, decode_frame, encode_frame,
};
use rustls::{
    ClientConfig, RootCertStore, ServerConfig, server::WebPkiClientVerifier, version::TLS13,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// 建立只允許 TLS 1.3 且要求 client certificate 的 server config。
///
/// # Errors
///
/// Client trust roots 為空/無效，或 server certificate/private key 無效時回傳錯誤。
pub fn tls13_server_config(
    certificate_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
    client_roots: RootCertStore,
) -> Result<ServerConfig, NetToolError> {
    let verifier = WebPkiClientVerifier::builder(Arc::new(client_roots))
        .build()
        .map_err(tls_error)?;
    ServerConfig::builder_with_protocol_versions(&[&TLS13])
        .with_client_cert_verifier(verifier)
        .with_single_cert(certificate_chain, private_key)
        .map_err(tls_error)
}

/// 建立只允許 TLS 1.3、驗證 server 並提供 client identity 的 config。
///
/// # Errors
///
/// Client certificate/private key 無效時回傳錯誤；server root 驗證於 handshake 執行。
pub fn tls13_client_config(
    server_roots: RootCertStore,
    certificate_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
) -> Result<ClientConfig, NetToolError> {
    ClientConfig::builder_with_protocol_versions(&[&TLS13])
        .with_root_certificates(server_roots)
        .with_client_auth_cert(certificate_chain, private_key)
        .map_err(tls_error)
}

/// 將單一 NTCP frame 寫入已完成 TLS 1.3 handshake 的 stream。
///
/// # Errors
///
/// Envelope 無法編碼或 stream write/flush 失敗時回傳錯誤。
pub async fn write_control_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    envelope: &Envelope,
) -> Result<(), NetToolError> {
    let frame = encode_frame(envelope)?;
    writer.write_all(&frame).await.map_err(io_error)?;
    writer.flush().await.map_err(io_error)
}

/// 從已完成 TLS 1.3 handshake 的 stream 讀取一個 bounded NTCP frame。
///
/// 先讀固定 header 並檢查 1 MiB 上限，再配置 payload buffer，避免長度欄位造成
/// 無界記憶體配置。
///
/// # Errors
///
/// Stream 提前結束、payload 過大、I/O 或 frame validation 失敗時回傳錯誤。
pub async fn read_control_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Envelope, NetToolError> {
    let mut header = [0_u8; CONTROL_HEADER_BYTES];
    reader.read_exact(&mut header).await.map_err(io_error)?;
    let payload_length = u32::from_be_bytes(header[8..12].try_into().map_err(|_| {
        NetToolError::new(
            ErrorCode::ProtocolInvalid,
            "control frame length field is invalid",
            false,
        )
    })?) as usize;
    if payload_length > MAX_CONTROL_PAYLOAD_BYTES {
        return Err(NetToolError::new(
            ErrorCode::ControlFrameTooLarge,
            "control payload exceeds 1 MiB",
            false,
        ));
    }
    let mut frame = Vec::with_capacity(CONTROL_HEADER_BYTES + payload_length);
    frame.extend_from_slice(&header);
    frame.resize(CONTROL_HEADER_BYTES + payload_length, 0);
    reader
        .read_exact(&mut frame[CONTROL_HEADER_BYTES..])
        .await
        .map_err(io_error)?;
    decode_frame(&frame)
}

#[allow(clippy::needless_pass_by_value)]
fn io_error(error: std::io::Error) -> NetToolError {
    NetToolError::new(
        ErrorCode::NodeTransportFailed,
        format!("node control I/O failed: {error}"),
        true,
    )
}

#[allow(clippy::needless_pass_by_value)]
fn tls_error(error: impl std::fmt::Display) -> NetToolError {
    NetToolError::new(
        ErrorCode::NodeTlsFailed,
        format!("node TLS configuration failed: {error}"),
        false,
    )
}

#[cfg(test)]
mod tests {
    use super::{
        read_control_frame, tls13_client_config, tls13_server_config, write_control_frame,
    };
    use nettool_node_protocol::{Envelope, PROTOCOL_MAJOR, PROTOCOL_MINOR};
    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use rustls::{ProtocolVersion, RootCertStore};
    use rustls_pki_types::{PrivatePkcs8KeyDer, ServerName};
    use std::sync::Arc;
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    #[tokio::test]
    async fn stream_frame_round_trip() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let envelope = Envelope {
            protocol_major: PROTOCOL_MAJOR,
            protocol_minor: PROTOCOL_MINOR,
            request_id: vec![7; 16],
            message: None,
        };
        let expected = envelope.clone();
        let sender = tokio::spawn(async move { write_control_frame(&mut client, &envelope).await });
        assert_eq!(
            read_control_frame(&mut server).await.expect("frame reads"),
            expected
        );
        sender
            .await
            .expect("sender completes")
            .expect("frame writes");
    }

    #[tokio::test]
    async fn rejects_oversized_length_before_payload_allocation() {
        use tokio::io::AsyncWriteExt;
        let (mut client, mut server) = tokio::io::duplex(64);
        let sender = tokio::spawn(async move {
            let mut header = [0_u8; 12];
            header[..4].copy_from_slice(b"NTCP");
            header[4] = 1;
            header[8..12].copy_from_slice(&(2_u32 * 1024 * 1024).to_be_bytes());
            client.write_all(&header).await.expect("header writes");
        });
        assert!(read_control_frame(&mut server).await.is_err());
        sender.await.expect("sender completes");
    }

    #[tokio::test]
    async fn mutual_tls_negotiates_only_tls13() {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["localhost".to_owned()]).expect("test cert generates");
        let certificate = cert.der().clone();
        let key = PrivatePkcs8KeyDer::from(signing_key.serialize_der());
        let mut roots = RootCertStore::empty();
        roots.add(certificate.clone()).expect("test root is valid");
        let server = tls13_server_config(
            vec![certificate.clone()],
            key.clone_key().into(),
            roots.clone(),
        )
        .expect("server config is valid");
        let client = tls13_client_config(roots, vec![certificate], key.clone_key().into())
            .expect("client config is valid");
        let (client_io, server_io) = tokio::io::duplex(16 * 1024);
        let server_task = tokio::spawn(TlsAcceptor::from(Arc::new(server)).accept(server_io));
        let client_stream = TlsConnector::from(Arc::new(client))
            .connect(
                ServerName::try_from("localhost").expect("valid server name"),
                client_io,
            )
            .await
            .expect("client handshake succeeds");
        let server_stream = server_task
            .await
            .expect("server task completes")
            .expect("server handshake succeeds");
        assert_eq!(
            client_stream.get_ref().1.protocol_version(),
            Some(ProtocolVersion::TLSv1_3)
        );
        assert_eq!(
            server_stream.get_ref().1.protocol_version(),
            Some(ProtocolVersion::TLSv1_3)
        );
    }
}

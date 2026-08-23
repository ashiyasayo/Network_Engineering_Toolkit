//! Privileged Helper 的 authenticated local transport 與 framing。

#![forbid(unsafe_code)]

use nettool_error::{ErrorCode, NetToolError};
use nettool_helper_protocol::{
    CallerIdentity, PrivilegedError, PrivilegedRequest, PrivilegedResponse, PrivilegedWireRequest,
};
use std::collections::BTreeSet;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Helper request/response frame 最大 payload bytes。
pub const MAX_HELPER_FRAME_LENGTH: usize = 1024 * 1024;

/// 經 OS transport 取得的 peer credentials。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerCredentials {
    /// Unix UID 或 Windows principal SID 的 stable string。
    pub principal: String,
    /// Peer process ID；平台不可用時為空。
    pub process_id: Option<u32>,
}

/// Helper caller allowlist；空 allowlist 拒絕所有 callers。
#[derive(Clone, Debug, Default)]
pub struct AuthorizationPolicy {
    allowed_principals: BTreeSet<String>,
}

impl AuthorizationPolicy {
    /// 建立 exact principal allowlist。
    #[must_use]
    pub fn new(principals: impl IntoIterator<Item = String>) -> Self {
        Self {
            allowed_principals: principals.into_iter().collect(),
        }
    }

    /// 驗證 peer principal，不使用 request payload 內的任何 identity。
    ///
    /// # Errors
    ///
    /// Principal 不在 allowlist 時回傳拒絕。
    pub fn authorize(&self, peer: &PeerCredentials) -> Result<CallerIdentity, NetToolError> {
        if !self.allowed_principals.contains(&peer.principal) {
            return Err(NetToolError::new(
                ErrorCode::HelperUnauthorized,
                "helper caller is not authorized",
                false,
            ));
        }
        Ok(CallerIdentity {
            principal: peer.principal.clone(),
            process_id: peer.process_id,
        })
    }
}

/// 已通過 transport authentication 的 request handler。
pub trait PrivilegedRequestHandler {
    /// 執行 whitelist request；handler 不再接受 wire identity。
    fn handle(&mut self, request: PrivilegedRequest) -> PrivilegedResponse;
}

/// 讀取一個 4-byte big-endian length-prefixed JSON request。
///
/// # Errors
///
/// I/O、frame 過大、空 frame、JSON malformed 或 wire schema 不符時回傳錯誤。
pub async fn read_request(
    reader: &mut (impl AsyncRead + Unpin),
) -> Result<PrivilegedWireRequest, NetToolError> {
    let length = reader
        .read_u32()
        .await
        .map_err(|error| transport_error("read helper frame length", error))?;
    let length = usize::try_from(length).unwrap_or(usize::MAX);
    if length == 0 || length > MAX_HELPER_FRAME_LENGTH {
        return Err(NetToolError::new(
            ErrorCode::ControlFrameTooLarge,
            "helper frame length is invalid",
            false,
        ));
    }
    let mut payload = vec![0_u8; length];
    reader
        .read_exact(&mut payload)
        .await
        .map_err(|error| transport_error("read helper frame payload", error))?;
    serde_json::from_slice(&payload).map_err(|error| {
        NetToolError::new(
            ErrorCode::ProtocolInvalid,
            format!("helper request is invalid: {error}"),
            false,
        )
    })
}

/// 寫入一個 length-prefixed JSON response。
///
/// # Errors
///
/// Serialize、frame 上限或 I/O 失敗時回傳錯誤。
pub async fn write_response(
    writer: &mut (impl AsyncWrite + Unpin),
    response: &PrivilegedResponse,
) -> Result<(), NetToolError> {
    let payload = serde_json::to_vec(response).map_err(|error| {
        NetToolError::new(
            ErrorCode::ProtocolInvalid,
            format!("helper response cannot be encoded: {error}"),
            false,
        )
    })?;
    if payload.len() > MAX_HELPER_FRAME_LENGTH {
        return Err(NetToolError::new(
            ErrorCode::ControlFrameTooLarge,
            "helper response exceeds frame limit",
            false,
        ));
    }
    writer
        .write_u32(u32::try_from(payload.len()).unwrap_or(u32::MAX))
        .await
        .map_err(|error| transport_error("write helper frame length", error))?;
    writer
        .write_all(&payload)
        .await
        .map_err(|error| transport_error("write helper frame payload", error))?;
    writer
        .flush()
        .await
        .map_err(|error| transport_error("flush helper frame", error))
}

/// 處理單一已取得 peer credentials 的 request/response exchange。
///
/// # Errors
///
/// Authorization、framing 或 response I/O 失敗時回傳錯誤。
async fn serve_one<S, H>(
    stream: &mut S,
    peer: &PeerCredentials,
    policy: &AuthorizationPolicy,
    handler: &mut H,
) -> Result<(), NetToolError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    H: PrivilegedRequestHandler,
{
    let identity = policy.authorize(peer)?;
    let wire = read_request(stream).await?;
    if wire.request_id.trim().is_empty() || wire.operation_id.trim().is_empty() {
        return Err(NetToolError::new(
            ErrorCode::InvalidArgument,
            "helper request and operation IDs are required",
            false,
        ));
    }
    wire.operation
        .validate()
        .map_err(|message| NetToolError::new(ErrorCode::InvalidArgument, message, false))?;
    let response = handler.handle(wire.authenticate(identity));
    write_response(stream, &response).await
}

/// 將 core error 轉成不洩漏 details 的 wire error。
#[must_use]
pub fn error_response(request_id: impl Into<String>, error: &NetToolError) -> PrivilegedResponse {
    PrivilegedResponse {
        request_id: request_id.into(),
        result: None,
        error: Some(PrivilegedError {
            code: error.code.as_str().to_owned(),
            message: error.message.clone(),
            retryable: error.retryable,
        }),
    }
}

#[allow(clippy::needless_pass_by_value)]
fn transport_error(context: &str, error: std::io::Error) -> NetToolError {
    NetToolError::new(
        ErrorCode::HelperTransportFailed,
        format!("{context}: {error}"),
        error.kind() == std::io::ErrorKind::Interrupted,
    )
}

#[cfg(unix)]
/// 從 Unix socket kernel peer credentials 建立 identity。
///
/// # Errors
///
/// Kernel 無法提供 peer credentials 時回傳錯誤。
pub fn unix_peer_credentials(
    stream: &tokio::net::UnixStream,
) -> Result<PeerCredentials, NetToolError> {
    let credential = stream.peer_cred().map_err(|error| {
        NetToolError::new(
            ErrorCode::HelperTransportFailed,
            format!("read Unix peer credentials: {error}"),
            false,
        )
    })?;
    Ok(PeerCredentials {
        principal: credential.uid().to_string(),
        process_id: credential.pid().and_then(|pid| u32::try_from(pid).ok()),
    })
}

#[cfg(unix)]
/// 從 kernel peer credentials 驗證 caller 並處理單一 Unix socket exchange。
///
/// # Errors
///
/// Kernel credential、authorization、framing或 response I/O 失敗時回傳錯誤。
pub async fn serve_unix_one<H>(
    stream: &mut tokio::net::UnixStream,
    policy: &AuthorizationPolicy,
    handler: &mut H,
) -> Result<(), NetToolError>
where
    H: PrivilegedRequestHandler,
{
    let peer = unix_peer_credentials(stream)?;
    serve_one(stream, &peer, policy, handler).await
}

#[cfg(windows)]
/// 從 Windows Named Pipe kernel token 驗證 caller 並處理單一 exchange。
///
/// Named Pipe ACL 與 token SID 兩層都必須通過；request payload 不可提供 identity。
///
/// # Errors
///
/// Token identity、authorization、framing 或 response I/O 失敗時回傳錯誤。
pub async fn serve_named_pipe_one<H>(
    stream: &mut tokio::net::windows::named_pipe::NamedPipeServer,
    policy: &AuthorizationPolicy,
    handler: &mut H,
) -> Result<(), NetToolError>
where
    H: PrivilegedRequestHandler,
{
    use std::os::windows::io::AsRawHandle;
    let identity = nettool_platform_auth::named_pipe_peer_identity(stream.as_raw_handle())
        .map_err(|message| NetToolError::new(ErrorCode::HelperUnauthorized, message, false))?;
    let peer = PeerCredentials {
        principal: identity.principal,
        process_id: identity.process_id,
    };
    serve_one(stream, &peer, policy, handler).await
}

#[cfg(test)]
mod tests {
    use super::{
        AuthorizationPolicy, MAX_HELPER_FRAME_LENGTH, PeerCredentials, PrivilegedRequestHandler,
        read_request, serve_one,
    };
    use nettool_helper_protocol::{PrivilegedRequest, PrivilegedResponse, PrivilegedWireRequest};
    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct EchoHandler;

    impl PrivilegedRequestHandler for EchoHandler {
        fn handle(&mut self, request: PrivilegedRequest) -> PrivilegedResponse {
            PrivilegedResponse {
                request_id: request.request_id,
                result: Some(json!({"principal": request.caller_identity.principal})),
                error: None,
            }
        }
    }

    #[tokio::test]
    async fn rejects_oversized_length_before_allocation() {
        let (mut client, mut server) = tokio::io::duplex(16);
        client
            .write_u32(u32::try_from(MAX_HELPER_FRAME_LENGTH + 1).expect("fits u32"))
            .await
            .expect("length");
        assert!(read_request(&mut server).await.is_err());
    }

    #[tokio::test]
    async fn wire_schema_rejects_spoofed_caller_identity() {
        let payload = br#"{"request_id":"r","operation_id":"o","caller_identity":{"principal":"0"},"operation":{"name":"safe_apply_list_pending"},"dry_run":true}"#;
        let (mut client, mut server) = tokio::io::duplex(512);
        client
            .write_u32(u32::try_from(payload.len()).expect("length"))
            .await
            .expect("length");
        client.write_all(payload).await.expect("payload");
        assert!(read_request(&mut server).await.is_err());
    }

    #[tokio::test]
    async fn authenticated_peer_identity_is_injected() {
        let request = PrivilegedWireRequest {
            request_id: "request-1".into(),
            operation_id: "operation-1".into(),
            operation: nettool_helper_protocol::PrivilegedOperation::SafeApplyListPending,
            dry_run: true,
        };
        let payload = serde_json::to_vec(&request).expect("request");
        let (mut client, mut server) = tokio::io::duplex(2048);
        client
            .write_u32(u32::try_from(payload.len()).expect("length"))
            .await
            .expect("length");
        client.write_all(&payload).await.expect("payload");
        let policy = AuthorizationPolicy::new(["501".to_owned()]);
        serve_one(
            &mut server,
            &PeerCredentials {
                principal: "501".into(),
                process_id: Some(42),
            },
            &policy,
            &mut EchoHandler,
        )
        .await
        .expect("served");
        let response_length = client.read_u32().await.expect("response length");
        let mut response = vec![0; usize::try_from(response_length).expect("usize")];
        client.read_exact(&mut response).await.expect("response");
        let response: PrivilegedResponse = serde_json::from_slice(&response).expect("JSON");
        assert_eq!(response.result, Some(json!({"principal":"501"})));
    }

    #[test]
    fn policy_denies_unknown_principal() {
        let policy = AuthorizationPolicy::new(["501".to_owned()]);
        assert!(
            policy
                .authorize(&PeerCredentials {
                    principal: "502".into(),
                    process_id: None
                })
                .is_err()
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn reads_credentials_from_kernel_socket_pair() {
        let (first, _second) = std::os::unix::net::UnixStream::pair().expect("socket pair");
        first.set_nonblocking(true).expect("nonblocking");
        let first = tokio::net::UnixStream::from_std(first).expect("tokio stream");
        let credential = super::unix_peer_credentials(&first).expect("kernel credentials");
        assert!(!credential.principal.is_empty());
    }
}

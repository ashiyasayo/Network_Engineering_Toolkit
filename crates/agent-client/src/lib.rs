//! CLI 與 GUI 共用的 Agent IPC client。

#![forbid(unsafe_code)]

use nettool_agent_protocol::{AgentEnvelope, MAX_FRAME_BYTES, decode_payload, encode_frame};
use nettool_error::{ErrorCode, NetToolError};
use std::path::{Path, PathBuf};

/// 回傳平台預設 Agent socket 路徑。
#[must_use]
pub fn default_socket_path() -> PathBuf {
    if let Some(path) = std::env::var_os("NETTOOL_AGENT_SOCKET") {
        return PathBuf::from(path);
    }
    #[cfg(unix)]
    {
        if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") {
            return PathBuf::from(runtime).join("nettool/agent.sock");
        }
        std::env::temp_dir()
            .join(format!("nettool-{}", current_user_scope()))
            .join("agent.sock")
    }
    #[cfg(windows)]
    {
        PathBuf::from(r"\\.\pipe\nettool-agent")
    }
}

#[cfg(unix)]
fn current_user_scope() -> String {
    std::env::var("USER")
        .unwrap_or_else(|_| "user".to_owned())
        .replace(|character: char| !character.is_ascii_alphanumeric(), "_")
}

/// 傳送單一 request 並等待單一 response。
///
/// # Errors
///
/// Agent 無法連線、frame I/O 失敗或 response protocol 無效時回傳錯誤。
#[cfg(unix)]
pub async fn request(
    socket_path: &Path,
    envelope: &AgentEnvelope,
) -> Result<AgentEnvelope, NetToolError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    let mut stream = UnixStream::connect(socket_path)
        .await
        .map_err(agent_error)?;
    let frame = encode_frame(envelope).map_err(protocol_error)?;
    stream.write_all(&frame).await.map_err(agent_error)?;
    let length = stream.read_u32().await.map_err(agent_error)? as usize;
    if length > MAX_FRAME_BYTES {
        return Err(protocol_error(
            "agent response exceeds maximum size".to_owned(),
        ));
    }
    let mut payload = vec![0_u8; length];
    stream.read_exact(&mut payload).await.map_err(agent_error)?;
    decode_payload(&payload).map_err(protocol_error)
}

/// Windows Named Pipe client 的公開介面。
///
/// # Errors
///
/// Named Pipe 無法連線、frame I/O 失敗或 response protocol 無效時回傳錯誤。
#[cfg(windows)]
pub async fn request(
    socket_path: &Path,
    envelope: &AgentEnvelope,
) -> Result<AgentEnvelope, NetToolError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::windows::named_pipe::ClientOptions;

    let mut stream = ClientOptions::new()
        .open(socket_path)
        .map_err(agent_error)?;
    let frame = encode_frame(envelope).map_err(protocol_error)?;
    stream.write_all(&frame).await.map_err(agent_error)?;
    stream.flush().await.map_err(agent_error)?;
    let length = stream.read_u32().await.map_err(agent_error)? as usize;
    if length > MAX_FRAME_BYTES {
        return Err(protocol_error(
            "agent response exceeds maximum size".to_owned(),
        ));
    }
    let mut payload = vec![0_u8; length];
    stream.read_exact(&mut payload).await.map_err(agent_error)?;
    decode_payload(&payload).map_err(protocol_error)
}

#[allow(clippy::needless_pass_by_value)]
fn agent_error(error: std::io::Error) -> NetToolError {
    NetToolError::new(
        ErrorCode::AgentUnavailable,
        format!("agent IPC failed: {error}"),
        true,
    )
}

fn protocol_error(message: String) -> NetToolError {
    NetToolError::new(ErrorCode::AgentUnavailable, message, false)
}

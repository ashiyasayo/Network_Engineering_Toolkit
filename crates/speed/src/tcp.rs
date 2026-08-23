//! 多 stream TCP throughput engine。

use crate::{authorization_tag_matches, validate_authorization_tag};
use nettool_error::{ErrorCode, NetToolError};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tokio::time::{Instant, timeout};

const TCP_AUTH_MAGIC: &[u8; 4] = b"NTA1";
const TCP_AUTH_HEADER_BYTES: usize = 26;
const TCP_AUTH_TIMEOUT: Duration = Duration::from_secs(5);

/// TCP measurement phase 的執行設定。
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TcpRunConfig {
    /// 平行 TCP streams 數量。
    pub streams: u16,
    /// 每個 stream 預先配置並重複使用的 payload bytes。
    pub payload_bytes: usize,
    /// Warm-up 時間；不納入主要 throughput。
    pub warmup_milliseconds: u64,
    /// Measurement 時間。
    pub measurement_milliseconds: u64,
}

impl TcpRunConfig {
    /// 驗證 compatibility engine 的資源界線。
    ///
    /// # Errors
    ///
    /// Stream、payload 或 measurement 超出產品安全界線時回傳錯誤。
    pub fn validate(self) -> Result<(), NetToolError> {
        if !(1..=128).contains(&self.streams) {
            return Err(invalid("TCP streams must be between 1 and 128"));
        }
        if !(1024..=16 * 1024 * 1024).contains(&self.payload_bytes) {
            return Err(invalid("TCP payload must be between 1 KiB and 16 MiB"));
        }
        if !(100..=86_400_000).contains(&self.measurement_milliseconds) {
            return Err(invalid(
                "TCP measurement must be between 100 ms and 24 hours",
            ));
        }
        Ok(())
    }
}

/// TCP measurement 結果；counter 使用 64-bit integer。
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TcpRunResult {
    /// 完成的 streams。
    pub streams: u16,
    /// Measurement phase 傳輸 bytes。
    pub transferred_bytes: u64,
    /// 實際 measurement elapsed nanoseconds。
    pub elapsed_nanoseconds: u64,
    /// 平均 bits per second。
    pub average_bits_per_second: u64,
}

/// TCP sender 的 session-scoped authorization 設定。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedTcpSenderConfig {
    /// Throughput measurement 設定。
    pub run: TcpRunConfig,
    /// Control plane 建立的 session ID。
    pub session_id: [u8; 16],
    /// Control plane 簽發的 session-scoped tag。
    pub authorization_tag: String,
}

/// TCP receiver 的 session-scoped authorization 設定。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedTcpReceiverConfig {
    /// 預期且必須唯一的 stream 數。
    pub expected_streams: u16,
    /// Control plane 建立的 session ID。
    pub session_id: [u8; 16],
    /// Control plane 簽發的 session-scoped tag。
    pub authorization_tag: String,
}

/// 以預先配置 payload 執行多 stream TCP upload。
///
/// # Errors
///
/// Config 無效、任何 stream 無法連線/傳送，或 counter overflow 時回傳錯誤。
pub async fn run_tcp_sender(
    address: SocketAddr,
    config: TcpRunConfig,
) -> Result<TcpRunResult, NetToolError> {
    run_tcp_sender_internal(address, config, None).await
}

/// 每條 TCP stream 在傳輸 payload 前先完成 session/stream/tag handshake。
///
/// # Errors
///
/// Config、authorization、連線、傳送或 counter 無效時回傳錯誤。
pub async fn run_authorized_tcp_sender(
    address: SocketAddr,
    config: AuthorizedTcpSenderConfig,
) -> Result<TcpRunResult, NetToolError> {
    validate_authorization_tag(&config.authorization_tag)?;
    let authorization = TcpAuthorization {
        session_id: config.session_id,
        tag: &config.authorization_tag,
    };
    run_tcp_sender_internal(address, config.run, Some(authorization)).await
}

async fn run_tcp_sender_internal(
    address: SocketAddr,
    config: TcpRunConfig,
    authorization: Option<TcpAuthorization<'_>>,
) -> Result<TcpRunResult, NetToolError> {
    config.validate()?;
    let mut streams = Vec::with_capacity(usize::from(config.streams));
    for stream_id in 0..config.streams {
        let mut stream = TcpStream::connect(address).await.map_err(io_error)?;
        if let Some(authorization) = authorization {
            write_tcp_authorization(&mut stream, authorization, u32::from(stream_id)).await?;
        }
        streams.push(stream);
    }
    let payload = vec![0xA5_u8; config.payload_bytes];
    let warmup_deadline = Instant::now() + Duration::from_millis(config.warmup_milliseconds);
    if config.warmup_milliseconds > 0 {
        while Instant::now() < warmup_deadline {
            for stream in &mut streams {
                stream.write_all(&payload).await.map_err(io_error)?;
            }
        }
    }
    let started = Instant::now();
    let deadline = started + Duration::from_millis(config.measurement_milliseconds);
    let mut transferred_bytes = 0_u64;
    while Instant::now() < deadline {
        for stream in &mut streams {
            stream.write_all(&payload).await.map_err(io_error)?;
            transferred_bytes = transferred_bytes
                .checked_add(payload.len() as u64)
                .ok_or_else(|| invalid("TCP byte counter overflow"))?;
        }
    }
    for stream in &mut streams {
        stream.shutdown().await.map_err(io_error)?;
    }
    let elapsed = started.elapsed();
    Ok(result(config.streams, transferred_bytes, elapsed))
}

/// 接受固定數量 streams 並讀取至所有 peer 關閉。
///
/// 此 receiver 回報 connection lifetime counters；正式協調測試由 Node barrier
/// 提供共同 measurement window。
///
/// # Errors
///
/// Stream 數無效、accept/read 失敗、worker panic 或 counter overflow 時回傳錯誤。
pub async fn run_tcp_receiver(
    listener: TcpListener,
    expected_streams: u16,
) -> Result<TcpRunResult, NetToolError> {
    run_tcp_receiver_internal(listener, expected_streams, None).await
}

/// 只接受每條 stream 都通過 session/tag 且 stream ID 唯一的 TCP 測試。
///
/// # Errors
///
/// Config、authorization、accept/read、worker 或 counter 無效時回傳錯誤。
pub async fn run_authorized_tcp_receiver(
    listener: TcpListener,
    config: AuthorizedTcpReceiverConfig,
) -> Result<TcpRunResult, NetToolError> {
    validate_authorization_tag(&config.authorization_tag)?;
    let authorization = TcpAuthorization {
        session_id: config.session_id,
        tag: &config.authorization_tag,
    };
    run_tcp_receiver_internal(listener, config.expected_streams, Some(authorization)).await
}

async fn run_tcp_receiver_internal(
    listener: TcpListener,
    expected_streams: u16,
    authorization: Option<TcpAuthorization<'_>>,
) -> Result<TcpRunResult, NetToolError> {
    if !(1..=128).contains(&expected_streams) {
        return Err(invalid("expected TCP streams must be between 1 and 128"));
    }
    let started = Instant::now();
    let mut workers = JoinSet::new();
    let mut stream_ids = HashSet::with_capacity(usize::from(expected_streams));
    for _ in 0..expected_streams {
        let (mut stream, _) = listener.accept().await.map_err(io_error)?;
        if let Some(authorization) = authorization {
            let stream_id = timeout(
                TCP_AUTH_TIMEOUT,
                read_tcp_authorization(&mut stream, authorization),
            )
            .await
            .map_err(|_| authorization_error("TCP authorization handshake timed out"))??;
            if stream_id >= u32::from(expected_streams) || !stream_ids.insert(stream_id) {
                return Err(authorization_error(
                    "TCP authorization stream ID is out of range or duplicated",
                ));
            }
        }
        workers.spawn(async move {
            let mut buffer = vec![0_u8; 64 * 1024];
            let mut bytes = 0_u64;
            loop {
                let count = stream.read(&mut buffer).await.map_err(io_error)?;
                if count == 0 {
                    break;
                }
                bytes = bytes
                    .checked_add(count as u64)
                    .ok_or_else(|| invalid("TCP byte counter overflow"))?;
            }
            Ok::<u64, NetToolError>(bytes)
        });
    }
    let mut transferred_bytes = 0_u64;
    while let Some(worker) = workers.join_next().await {
        let bytes = worker.map_err(|error| {
            NetToolError::new(
                ErrorCode::SpeedFailed,
                format!("TCP worker failed: {error}"),
                false,
            )
        })??;
        transferred_bytes = transferred_bytes
            .checked_add(bytes)
            .ok_or_else(|| invalid("TCP byte counter overflow"))?;
    }
    Ok(result(
        expected_streams,
        transferred_bytes,
        started.elapsed(),
    ))
}

#[derive(Clone, Copy)]
struct TcpAuthorization<'a> {
    session_id: [u8; 16],
    tag: &'a str,
}

async fn write_tcp_authorization<W: AsyncWrite + Unpin>(
    writer: &mut W,
    authorization: TcpAuthorization<'_>,
    stream_id: u32,
) -> Result<(), NetToolError> {
    let tag_length = u16::try_from(authorization.tag.len())
        .map_err(|_| authorization_error("TCP authorization tag is too long"))?;
    let mut header = [0_u8; TCP_AUTH_HEADER_BYTES];
    header[..4].copy_from_slice(TCP_AUTH_MAGIC);
    header[4..20].copy_from_slice(&authorization.session_id);
    header[20..24].copy_from_slice(&stream_id.to_be_bytes());
    header[24..26].copy_from_slice(&tag_length.to_be_bytes());
    writer.write_all(&header).await.map_err(io_error)?;
    writer
        .write_all(authorization.tag.as_bytes())
        .await
        .map_err(io_error)?;
    writer.flush().await.map_err(io_error)
}

async fn read_tcp_authorization<R: AsyncRead + Unpin>(
    reader: &mut R,
    expected: TcpAuthorization<'_>,
) -> Result<u32, NetToolError> {
    let mut header = [0_u8; TCP_AUTH_HEADER_BYTES];
    reader.read_exact(&mut header).await.map_err(io_error)?;
    if &header[..4] != TCP_AUTH_MAGIC || header[4..20] != expected.session_id {
        return Err(authorization_error(
            "TCP authorization session or protocol header mismatch",
        ));
    }
    let stream_id = u32::from_be_bytes(
        header[20..24]
            .try_into()
            .map_err(|_| authorization_error("TCP authorization stream ID is invalid"))?,
    );
    let tag_length =
        usize::from(u16::from_be_bytes(header[24..26].try_into().map_err(
            |_| authorization_error("TCP authorization tag length is invalid"),
        )?));
    if tag_length != expected.tag.len() {
        return Err(authorization_error("TCP authorization tag length mismatch"));
    }
    let mut tag = vec![0_u8; tag_length];
    reader.read_exact(&mut tag).await.map_err(io_error)?;
    if !authorization_tag_matches(expected.tag, &tag) {
        return Err(authorization_error("TCP authorization tag mismatch"));
    }
    Ok(stream_id)
}

fn authorization_error(message: &'static str) -> NetToolError {
    NetToolError::new(ErrorCode::DataPlaneUnauthorized, message, false)
}

fn result(streams: u16, transferred_bytes: u64, elapsed: Duration) -> TcpRunResult {
    let nanos = u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX).max(1);
    let average_bits_per_second = transferred_bytes
        .saturating_mul(8)
        .saturating_mul(1_000_000_000)
        .checked_div(nanos)
        .unwrap_or(0);
    TcpRunResult {
        streams,
        transferred_bytes,
        elapsed_nanoseconds: nanos,
        average_bits_per_second,
    }
}

fn invalid(message: &str) -> NetToolError {
    NetToolError::new(ErrorCode::InvalidArgument, message, false)
}

#[allow(clippy::needless_pass_by_value)]
fn io_error(error: std::io::Error) -> NetToolError {
    NetToolError::new(
        ErrorCode::SpeedFailed,
        format!("TCP speed I/O failed: {error}"),
        true,
    )
}

#[cfg(test)]
mod tests {
    use super::{
        AuthorizedTcpReceiverConfig, AuthorizedTcpSenderConfig, TcpAuthorization, TcpRunConfig,
        read_tcp_authorization, run_authorized_tcp_receiver, run_authorized_tcp_sender,
        run_tcp_receiver, run_tcp_sender, write_tcp_authorization,
    };
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn authorization_handshake_rejects_wrong_tag() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let sender = tokio::spawn(async move {
            write_tcp_authorization(
                &mut client,
                TcpAuthorization {
                    session_id: [7; 16],
                    tag: "0123456789abcdef",
                },
                3,
            )
            .await
        });
        let result = read_tcp_authorization(
            &mut server,
            TcpAuthorization {
                session_id: [7; 16],
                tag: "fedcba9876543210",
            },
        )
        .await;
        assert!(result.is_err());
        sender.await.expect("sender").expect("write");
    }

    #[tokio::test]
    #[ignore = "requires permission to bind a loopback socket"]
    async fn authorized_streams_transfer_real_data() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback bind succeeds");
        let address = listener.local_addr().expect("listener has address");
        let receiver_task = tokio::spawn(run_authorized_tcp_receiver(
            listener,
            AuthorizedTcpReceiverConfig {
                expected_streams: 2,
                session_id: [9; 16],
                authorization_tag: "0123456789abcdef".to_owned(),
            },
        ));
        let sender = run_authorized_tcp_sender(
            address,
            AuthorizedTcpSenderConfig {
                run: TcpRunConfig {
                    streams: 2,
                    payload_bytes: 16 * 1024,
                    warmup_milliseconds: 0,
                    measurement_milliseconds: 100,
                },
                session_id: [9; 16],
                authorization_tag: "0123456789abcdef".to_owned(),
            },
        )
        .await
        .expect("sender");
        let receiver = receiver_task.await.expect("task").expect("receiver");
        assert_eq!(sender.transferred_bytes, receiver.transferred_bytes);
    }

    #[tokio::test]
    #[ignore = "requires permission to bind a loopback socket"]
    async fn transfers_real_data_over_loopback() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback bind succeeds");
        let address = listener.local_addr().expect("listener has address");
        let receiver_task = tokio::spawn(run_tcp_receiver(listener, 2));
        let sender = run_tcp_sender(
            address,
            TcpRunConfig {
                streams: 2,
                payload_bytes: 16 * 1024,
                warmup_milliseconds: 0,
                measurement_milliseconds: 100,
            },
        )
        .await
        .expect("sender succeeds");
        let receiver_result = receiver_task
            .await
            .expect("receiver task completes")
            .expect("receiver succeeds");
        assert!(sender.transferred_bytes > 0);
        assert_eq!(receiver_result.transferred_bytes, sender.transferred_bytes);
        assert!(sender.average_bits_per_second > 0);
    }
}

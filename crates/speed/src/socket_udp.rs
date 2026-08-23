//! 實際 UDP socket TX/RX compatibility engine。

use crate::{
    BatchPacer, BoundedUdpSequenceTracker, UDP_SPEED_HEADER_BYTES, UdpJitterTracker,
    UdpSequenceStats, UdpSpeedHeader, authorization_tag_matches, validate_authorization_tag,
};
use nettool_error::{ErrorCode, NetToolError};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::task::yield_now;
use tokio::time::{Instant, sleep, timeout};

/// UDP datagram 的 graceful end flag。
pub const UDP_FLAG_END: u32 = 1;
/// UDP stream authorization bootstrap flag。
pub const UDP_FLAG_AUTH: u32 = 2;
const MAX_UDP_DATAGRAM_BYTES: usize = 65_507;

/// 單一 fixed/unlimited UDP measurement stage 的 sender 設定。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpSenderConfig {
    /// Session ID。
    pub session_id: [u8; 16],
    /// Stream ID。
    pub stream_id: u32,
    /// 完整 UDP datagram bytes，包含 speed header。
    pub datagram_bytes: usize,
    /// Measurement duration。
    pub measurement_milliseconds: u64,
    /// `None` 表示 unlimited；否則為 fixed datagram bits per second。
    pub target_bits_per_second: Option<u64>,
    /// 單次 burst 上限。
    pub maximum_packets_per_burst: u32,
    /// Control plane 簽發的 session-scoped authorization tag。
    pub authorization_tag: String,
}

impl UdpSenderConfig {
    /// 驗證 socket 與產品資源界線。
    ///
    /// # Errors
    ///
    /// Datagram、duration、rate 或 burst 超出界線時回傳錯誤。
    pub fn validate(&self) -> Result<(), NetToolError> {
        if !(UDP_SPEED_HEADER_BYTES..=MAX_UDP_DATAGRAM_BYTES).contains(&self.datagram_bytes) {
            return Err(invalid(
                "UDP datagram size is outside the valid socket range",
            ));
        }
        if !(100..=86_400_000).contains(&self.measurement_milliseconds) {
            return Err(invalid(
                "UDP measurement must be between 100 ms and 24 hours",
            ));
        }
        if self.target_bits_per_second == Some(0) {
            return Err(invalid("UDP target rate must be greater than zero"));
        }
        if !(1..=4096).contains(&self.maximum_packets_per_burst) {
            return Err(invalid("UDP burst size must be between 1 and 4096"));
        }
        validate_authorization_tag(&self.authorization_tag)?;
        Ok(())
    }
}

/// UDP receiver 的 session-scoped 設定。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpReceiverConfig {
    /// Session ID。
    pub session_id: [u8; 16],
    /// Stream ID。
    pub stream_id: u32,
    /// 授權的來源 IP 與 dynamic port；其他來源只計數、不進入結果。
    pub expected_source: SocketAddr,
    /// 可接受的最大 datagram bytes。
    pub maximum_datagram_bytes: usize,
    /// 等待第一個 packet 與相鄰 packets 的 timeout。
    pub idle_timeout_milliseconds: u64,
    /// Control plane 簽發的 session-scoped authorization tag。
    pub authorization_tag: String,
}

impl UdpReceiverConfig {
    /// 驗證 receive buffer 與 timeout 界線。
    ///
    /// # Errors
    ///
    /// Buffer 或 timeout 無效時回傳錯誤。
    pub fn validate(&self) -> Result<(), NetToolError> {
        if !(UDP_SPEED_HEADER_BYTES..=MAX_UDP_DATAGRAM_BYTES).contains(&self.maximum_datagram_bytes)
        {
            return Err(invalid(
                "UDP receive buffer is outside the valid socket range",
            ));
        }
        if !(100..=60_000).contains(&self.idle_timeout_milliseconds) {
            return Err(invalid(
                "UDP idle timeout must be between 100 ms and 60 seconds",
            ));
        }
        validate_authorization_tag(&self.authorization_tag)?;
        Ok(())
    }
}

/// UDP sender measurement counters。
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UdpSenderResult {
    /// 成功送出的 data packets。
    pub tx_packets: u64,
    /// 成功送出的完整 datagram bytes，不含 END packet。
    pub tx_datagram_bytes: u64,
    /// Local monotonic elapsed。
    pub elapsed_nanoseconds: u64,
    /// Datagram-layer average bits per second。
    pub tx_bits_per_second: u64,
}

/// UDP receiver measurement counters。
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UdpReceiverResult {
    /// 符合 session/stream 的 data packets，包含 duplicate。
    pub rx_packets: u64,
    /// 符合 session/stream 的完整 datagram bytes。
    pub rx_datagram_bytes: u64,
    /// Local monotonic elapsed。
    pub elapsed_nanoseconds: u64,
    /// Datagram-layer average bits per second。
    pub rx_bits_per_second: u64,
    /// Sequence accounting。
    pub sequence: UdpSequenceStats,
    /// 平滑 jitter。
    pub jitter_nanoseconds: u64,
    /// 格式錯誤或不支援 flags 的 datagrams。
    pub invalid_datagrams: u64,
    /// 來源、session 或 stream 不符的 datagrams。
    pub unauthorized_datagrams: u64,
    /// 是否收到 matching END；false 表示以 idle timeout 完成。
    pub graceful_end: bool,
}

/// 執行單一 fixed/unlimited UDP sender stage。
///
/// Payload 在進入 measurement 前預先配置；fixed rate 以 burst budget pacing，
/// 不在每個 packet 後 sleep。
///
/// # Errors
///
/// Config 無效、socket send 失敗或 counter overflow 時回傳錯誤。
pub async fn run_udp_sender(
    socket: &UdpSocket,
    destination: SocketAddr,
    config: UdpSenderConfig,
) -> Result<UdpSenderResult, NetToolError> {
    config.validate()?;
    send_auth(socket, destination, &config).await?;
    let payload_length = config.datagram_bytes - UDP_SPEED_HEADER_BYTES;
    let payload_length = u32::try_from(payload_length)
        .map_err(|_| invalid("UDP payload length cannot be represented"))?;
    let wire_bytes = u32::try_from(config.datagram_bytes)
        .map_err(|_| invalid("UDP datagram size cannot be represented"))?;
    let mut datagram = vec![0xA5_u8; config.datagram_bytes];
    let mut pacer = config
        .target_bits_per_second
        .map(|rate| BatchPacer::new(rate, wire_bytes))
        .transpose()?;
    let started = Instant::now();
    let deadline = started + Duration::from_millis(config.measurement_milliseconds);
    let mut sequence = 0_u64;
    let mut transmitted_bytes = 0_u64;
    while Instant::now() < deadline {
        let elapsed = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        let available = pacer
            .as_ref()
            .map_or(config.maximum_packets_per_burst, |value| {
                value.available_packets(elapsed, config.maximum_packets_per_burst)
            });
        if available == 0 {
            sleep(Duration::from_micros(50)).await;
            continue;
        }
        let mut sent_in_burst = 0_u32;
        for _ in 0..available {
            if Instant::now() >= deadline {
                break;
            }
            let send_timestamp = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
            let header = UdpSpeedHeader {
                session_id: config.session_id,
                stream_id: config.stream_id,
                sequence,
                flags: 0,
                send_timestamp_nanoseconds: send_timestamp,
                payload_length,
            };
            datagram[..UDP_SPEED_HEADER_BYTES].copy_from_slice(&header.encode());
            let sent = socket
                .send_to(&datagram, destination)
                .await
                .map_err(io_error)?;
            if sent != datagram.len() {
                return Err(engine_error(
                    "UDP socket reported a partial datagram send",
                    true,
                ));
            }
            sequence = sequence
                .checked_add(1)
                .ok_or_else(|| invalid("UDP sequence counter overflow"))?;
            transmitted_bytes = transmitted_bytes
                .checked_add(u64::from(wire_bytes))
                .ok_or_else(|| invalid("UDP byte counter overflow"))?;
            sent_in_burst += 1;
        }
        if let Some(value) = &mut pacer {
            value.record_sent(sent_in_burst)?;
        }
        yield_now().await;
    }
    let elapsed_nanoseconds = u64::try_from(started.elapsed().as_nanos())
        .unwrap_or(u64::MAX)
        .max(1);
    send_end(socket, destination, &config, sequence, elapsed_nanoseconds).await?;
    Ok(UdpSenderResult {
        tx_packets: sequence,
        tx_datagram_bytes: transmitted_bytes,
        elapsed_nanoseconds,
        tx_bits_per_second: rate(transmitted_bytes, elapsed_nanoseconds),
    })
}

/// 接收單一 UDP stream，直到 matching END 或 idle timeout。
///
/// # Errors
///
/// Config 無效、第一個有效 packet 前 timeout 或 socket I/O 失敗時回傳錯誤。
/// 已收到有效資料後的 timeout 會回傳 `graceful_end=false`，因為 UDP END 可能遺失。
pub async fn run_udp_receiver(
    socket: &UdpSocket,
    config: UdpReceiverConfig,
) -> Result<UdpReceiverResult, NetToolError> {
    config.validate()?;
    let mut buffer = vec![0_u8; config.maximum_datagram_bytes];
    let idle_timeout = Duration::from_millis(config.idle_timeout_milliseconds);
    let mut tracker = BoundedUdpSequenceTracker::default();
    let mut jitter = UdpJitterTracker::default();
    let mut started = None;
    let mut rx_packets = 0_u64;
    let mut rx_bytes = 0_u64;
    let mut invalid_datagrams = 0_u64;
    let mut unauthorized_datagrams = 0_u64;
    let mut authorized = false;
    let graceful_end;
    loop {
        let receive = timeout(idle_timeout, socket.recv_from(&mut buffer)).await;
        let (received, source) = match receive {
            Ok(result) => result.map_err(io_error)?,
            Err(_) if started.is_some() => {
                graceful_end = false;
                break;
            }
            Err(_) => return Err(engine_error("UDP receiver initial timeout", true)),
        };
        let now = Instant::now();
        let Ok(header) = UdpSpeedHeader::decode_datagram(&buffer[..received]) else {
            invalid_datagrams = invalid_datagrams.saturating_add(1);
            continue;
        };
        if source != config.expected_source
            || header.session_id != config.session_id
            || header.stream_id != config.stream_id
        {
            unauthorized_datagrams = unauthorized_datagrams.saturating_add(1);
            continue;
        }
        if header.flags == UDP_FLAG_AUTH {
            let presented = &buffer[UDP_SPEED_HEADER_BYTES..received];
            if authorized
                || header.sequence != 0
                || !authorization_tag_matches(&config.authorization_tag, presented)
            {
                unauthorized_datagrams = unauthorized_datagrams.saturating_add(1);
            } else {
                authorized = true;
            }
            continue;
        }
        if !authorized {
            unauthorized_datagrams = unauthorized_datagrams.saturating_add(1);
            continue;
        }
        if header.flags == UDP_FLAG_END {
            if header.payload_length != 0 {
                invalid_datagrams = invalid_datagrams.saturating_add(1);
                continue;
            }
            graceful_end = true;
            break;
        }
        if header.flags != 0 {
            invalid_datagrams = invalid_datagrams.saturating_add(1);
            continue;
        }
        let measurement_started = *started.get_or_insert(now);
        let receive_timestamp =
            u64::try_from(measurement_started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        tracker.observe(header.sequence);
        jitter.observe(header.send_timestamp_nanoseconds, receive_timestamp);
        rx_packets = rx_packets.saturating_add(1);
        rx_bytes = rx_bytes.saturating_add(u64::try_from(received).unwrap_or(u64::MAX));
    }
    let measurement_started = started
        .ok_or_else(|| engine_error("UDP receiver got END before any measurement packet", false))?;
    let elapsed_nanoseconds = u64::try_from(measurement_started.elapsed().as_nanos())
        .unwrap_or(u64::MAX)
        .max(1);
    Ok(UdpReceiverResult {
        rx_packets,
        rx_datagram_bytes: rx_bytes,
        elapsed_nanoseconds,
        rx_bits_per_second: rate(rx_bytes, elapsed_nanoseconds),
        sequence: tracker.stats(),
        jitter_nanoseconds: jitter.jitter_nanoseconds(),
        invalid_datagrams,
        unauthorized_datagrams,
        graceful_end,
    })
}

async fn send_end(
    socket: &UdpSocket,
    destination: SocketAddr,
    config: &UdpSenderConfig,
    sequence: u64,
    timestamp: u64,
) -> Result<(), NetToolError> {
    let header = UdpSpeedHeader {
        session_id: config.session_id,
        stream_id: config.stream_id,
        sequence,
        flags: UDP_FLAG_END,
        send_timestamp_nanoseconds: timestamp,
        payload_length: 0,
    }
    .encode();
    let sent = socket
        .send_to(&header, destination)
        .await
        .map_err(io_error)?;
    if sent != header.len() {
        return Err(engine_error("UDP socket reported a partial END send", true));
    }
    Ok(())
}

async fn send_auth(
    socket: &UdpSocket,
    destination: SocketAddr,
    config: &UdpSenderConfig,
) -> Result<(), NetToolError> {
    let payload_length = u32::try_from(config.authorization_tag.len())
        .map_err(|_| invalid("authorization tag length cannot be represented"))?;
    let header = UdpSpeedHeader {
        session_id: config.session_id,
        stream_id: config.stream_id,
        sequence: 0,
        flags: UDP_FLAG_AUTH,
        send_timestamp_nanoseconds: 0,
        payload_length,
    }
    .encode();
    let mut datagram = Vec::with_capacity(header.len() + config.authorization_tag.len());
    datagram.extend_from_slice(&header);
    datagram.extend_from_slice(config.authorization_tag.as_bytes());
    let sent = socket
        .send_to(&datagram, destination)
        .await
        .map_err(io_error)?;
    if sent != datagram.len() {
        return Err(engine_error(
            "UDP socket reported a partial AUTH datagram send",
            true,
        ));
    }
    Ok(())
}

fn rate(bytes: u64, elapsed_nanoseconds: u64) -> u64 {
    bytes
        .saturating_mul(8)
        .saturating_mul(1_000_000_000)
        .checked_div(elapsed_nanoseconds.max(1))
        .unwrap_or(0)
}

fn invalid(message: &str) -> NetToolError {
    NetToolError::new(ErrorCode::InvalidArgument, message, false)
}

fn engine_error(message: &str, retryable: bool) -> NetToolError {
    NetToolError::new(ErrorCode::SpeedFailed, message, retryable)
}

#[allow(clippy::needless_pass_by_value)]
fn io_error(error: std::io::Error) -> NetToolError {
    NetToolError::new(
        ErrorCode::SpeedFailed,
        format!("UDP speed I/O failed: {error}"),
        true,
    )
}

#[cfg(test)]
mod tests {
    use super::{UdpReceiverConfig, UdpSenderConfig, run_udp_receiver, run_udp_sender, send_auth};
    use std::net::SocketAddr;
    use tokio::net::UdpSocket;

    #[tokio::test]
    #[ignore = "requires permission to bind loopback UDP sockets"]
    async fn transfers_fixed_rate_datagrams_over_loopback() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.expect("receiver");
        let sender = UdpSocket::bind("127.0.0.1:0").await.expect("sender");
        let destination = receiver.local_addr().expect("address");
        let expected_source = sender.local_addr().expect("sender address");
        let receive_task = tokio::spawn(async move {
            run_udp_receiver(
                &receiver,
                UdpReceiverConfig {
                    session_id: [9; 16],
                    stream_id: 3,
                    expected_source,
                    maximum_datagram_bytes: 1500,
                    idle_timeout_milliseconds: 2_000,
                    authorization_tag: "0123456789abcdef".to_owned(),
                },
            )
            .await
        });
        send_auth(
            &sender,
            destination,
            &UdpSenderConfig {
                session_id: [9; 16],
                stream_id: 3,
                datagram_bytes: 256,
                measurement_milliseconds: 100,
                target_bits_per_second: Some(1_000_000),
                maximum_packets_per_burst: 32,
                authorization_tag: "fedcba9876543210".to_owned(),
            },
        )
        .await
        .expect("wrong auth datagram writes");
        let sent = run_udp_sender(
            &sender,
            SocketAddr::new(destination.ip(), destination.port()),
            UdpSenderConfig {
                session_id: [9; 16],
                stream_id: 3,
                datagram_bytes: 256,
                measurement_milliseconds: 100,
                target_bits_per_second: Some(1_000_000),
                maximum_packets_per_burst: 32,
                authorization_tag: "0123456789abcdef".to_owned(),
            },
        )
        .await
        .expect("sender");
        let receive_result = receive_task.await.expect("task").expect("receiver");
        assert!(sent.tx_packets > 0);
        assert_eq!(receive_result.rx_packets, sent.tx_packets);
        assert_eq!(receive_result.sequence.lost, 0);
        assert_eq!(receive_result.invalid_datagrams, 0);
        assert_eq!(receive_result.unauthorized_datagrams, 1);
        assert!(receive_result.graceful_end);
    }
}

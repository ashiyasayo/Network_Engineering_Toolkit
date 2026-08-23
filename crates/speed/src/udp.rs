//! 固定 16-byte UDP compact header 與 sequence accounting。

use nettool_error::{ErrorCode, NetToolError};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Compact header 的固定大小，讓 IPv4 UDP minimum benchmark payload 可預測。
pub const UDP_COMPACT_HEADER_BYTES: usize = 16;
const SIGNATURE_AND_VERSION: u8 = 0xA1;
/// 完整 UDP speed protocol v1 header bytes。
pub const UDP_SPEED_HEADER_BYTES: usize = 52;
const UDP_SPEED_HEADER_LENGTH: u16 = 52;
const UDP_SPEED_MAGIC: [u8; 4] = *b"NTUP";
/// Socket receiver 的固定 sequence window 大小。
pub const UDP_SEQUENCE_WINDOW_SIZE: usize = 65_536;
const UDP_SPEED_VERSION: u16 = 1;

/// 完整 UDP speed protocol header；所有整數皆使用 network byte order。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UdpSpeedHeader {
    /// 128-bit session ID。
    pub session_id: [u8; 16],
    /// Session 內 stream ID。
    pub stream_id: u32,
    /// Stream-local sequence number。
    pub sequence: u64,
    /// Protocol flags。
    pub flags: u32,
    /// Sender monotonic timestamp，單位 nanoseconds。
    pub send_timestamp_nanoseconds: u64,
    /// Header 後的 payload bytes。
    pub payload_length: u32,
}

impl UdpSpeedHeader {
    /// 編碼固定大小 v1 header。
    #[must_use]
    pub fn encode(self) -> [u8; UDP_SPEED_HEADER_BYTES] {
        let mut bytes = [0_u8; UDP_SPEED_HEADER_BYTES];
        bytes[0..4].copy_from_slice(&UDP_SPEED_MAGIC);
        bytes[4..6].copy_from_slice(&UDP_SPEED_VERSION.to_be_bytes());
        bytes[6..8].copy_from_slice(&UDP_SPEED_HEADER_LENGTH.to_be_bytes());
        bytes[8..24].copy_from_slice(&self.session_id);
        bytes[24..28].copy_from_slice(&self.stream_id.to_be_bytes());
        bytes[28..36].copy_from_slice(&self.sequence.to_be_bytes());
        bytes[36..40].copy_from_slice(&self.flags.to_be_bytes());
        bytes[40..48].copy_from_slice(&self.send_timestamp_nanoseconds.to_be_bytes());
        bytes[48..52].copy_from_slice(&self.payload_length.to_be_bytes());
        bytes
    }

    /// 解析 header 並驗證整個 datagram 的 payload length。
    ///
    /// # Errors
    ///
    /// Datagram 太短、magic/version/header length 或 payload length 不符時回傳錯誤。
    pub fn decode_datagram(datagram: &[u8]) -> Result<Self, NetToolError> {
        if datagram.len() < UDP_SPEED_HEADER_BYTES {
            return Err(protocol_error(
                "UDP speed datagram is shorter than its header",
            ));
        }
        if datagram[0..4] != UDP_SPEED_MAGIC {
            return Err(protocol_error("UDP speed magic is invalid"));
        }
        if read_u16(datagram, 4)? != UDP_SPEED_VERSION {
            return Err(protocol_error("UDP speed protocol version is unsupported"));
        }
        if usize::from(read_u16(datagram, 6)?) != UDP_SPEED_HEADER_BYTES {
            return Err(protocol_error("UDP speed header length is invalid"));
        }
        let payload_length = read_u32(datagram, 48)?;
        let actual_payload = datagram.len() - UDP_SPEED_HEADER_BYTES;
        if usize::try_from(payload_length).unwrap_or(usize::MAX) != actual_payload {
            return Err(protocol_error(
                "UDP speed payload length does not match datagram",
            ));
        }
        let mut session_id = [0_u8; 16];
        session_id.copy_from_slice(&datagram[8..24]);
        Ok(Self {
            session_id,
            stream_id: read_u32(datagram, 24)?,
            sequence: read_u64(datagram, 28)?,
            flags: read_u32(datagram, 36)?,
            send_timestamp_nanoseconds: read_u64(datagram, 40)?,
            payload_length,
        })
    }
}

/// UDP compact header v1。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UdpCompactHeader {
    /// Protocol flags。
    pub flags: u8,
    /// Session 內 stream ID。
    pub stream_id: u16,
    /// Session authentication/dispatch tag。
    pub session_tag: u32,
    /// 64-bit packet sequence。
    pub sequence: u64,
}

impl UdpCompactHeader {
    /// 編碼為固定 network-byte-order header。
    #[must_use]
    pub fn encode(self) -> [u8; UDP_COMPACT_HEADER_BYTES] {
        let mut bytes = [0_u8; UDP_COMPACT_HEADER_BYTES];
        bytes[0] = SIGNATURE_AND_VERSION;
        bytes[1] = self.flags;
        bytes[2..4].copy_from_slice(&self.stream_id.to_be_bytes());
        bytes[4..8].copy_from_slice(&self.session_tag.to_be_bytes());
        bytes[8..16].copy_from_slice(&self.sequence.to_be_bytes());
        bytes
    }

    /// 解碼並驗證 signature/version。
    ///
    /// # Errors
    ///
    /// 長度不是 16 bytes 或 signature/version 不支援時回傳錯誤。
    pub fn decode(bytes: &[u8]) -> Result<Self, NetToolError> {
        let bytes: &[u8; UDP_COMPACT_HEADER_BYTES] = bytes
            .try_into()
            .map_err(|_| protocol_error("UDP compact header must be exactly 16 bytes"))?;
        if bytes[0] != SIGNATURE_AND_VERSION {
            return Err(protocol_error(
                "UDP compact header signature or version is invalid",
            ));
        }
        Ok(Self {
            flags: bytes[1],
            stream_id: u16::from_be_bytes([bytes[2], bytes[3]]),
            session_tag: u32::from_be_bytes(
                bytes[4..8]
                    .try_into()
                    .map_err(|_| protocol_error("invalid session tag"))?,
            ),
            sequence: u64::from_be_bytes(
                bytes[8..16]
                    .try_into()
                    .map_err(|_| protocol_error("invalid sequence"))?,
            ),
        })
    }
}

/// UDP receiver 的 sequence counters。
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct UdpSequenceStats {
    /// 唯一 packets 數。
    pub received: u64,
    /// Highest sequence 範圍內尚未收到的 packets。
    pub lost: u64,
    /// 比已見 highest sequence 小、但首次出現的 packets。
    pub out_of_order: u64,
    /// 重複 sequence packets。
    pub duplicate: u64,
    /// 目前最高 sequence。
    pub highest_sequence: Option<u64>,
}

/// Compatibility engine 的精確 sequence tracker。
///
/// 這個實作使用 set 以提供完整測試正確性，不可直接放入 100G hot path；
/// accelerated backend 必須改用固定容量 window/flow-local counters。
#[derive(Default)]
pub struct UdpSequenceTracker {
    seen: HashSet<u64>,
    stats: UdpSequenceStats,
}

/// Accelerated UDP receiver 使用的固定容量 sequence window。
///
/// `UdpSequenceTracker` 保留完整 set 語義供相容性與離線分析使用；socket hot path
/// 不應在每個 packet 將 sequence 插入無界 `HashSet`，因此改用預先配置的 ring window。
pub struct BoundedUdpSequenceTracker {
    window: Vec<u64>,
    mask: u64,
    stats: UdpSequenceStats,
}

impl BoundedUdpSequenceTracker {
    /// 建立固定容量 window；容量必須是 power-of-two 且至少 2。
    ///
    /// # Errors
    ///
    /// window size 為零、非 power-of-two 或小於 2 時回傳錯誤。
    pub fn new(window_size: usize) -> Result<Self, NetToolError> {
        if window_size < 2 || !window_size.is_power_of_two() {
            return Err(NetToolError::new(
                ErrorCode::InvalidArgument,
                "UDP sequence window must be a power-of-two of at least two",
                false,
            ));
        }
        Ok(Self {
            window: vec![u64::MAX; window_size],
            mask: (window_size - 1) as u64,
            stats: UdpSequenceStats::default(),
        })
    }

    /// 納入 sequence；window 內的遺失封包若晚到會修正 lost counter。
    pub fn observe(&mut self, sequence: u64) -> UdpSequenceStats {
        let Some(highest) = self.stats.highest_sequence else {
            let slot = self.slot(sequence);
            self.window[slot] = sequence;
            self.stats.highest_sequence = Some(sequence);
            self.stats.received = 1;
            self.stats.lost = sequence;
            return self.stats;
        };

        if sequence > highest {
            let distance = sequence - highest;
            if distance >= self.window.len() as u64 {
                self.window.fill(u64::MAX);
            } else {
                for offset in 1..=distance {
                    let slot = self.slot(highest + offset);
                    self.window[slot] = u64::MAX;
                }
            }
            self.stats.lost = self.stats.lost.saturating_add(distance.saturating_sub(1));
            let slot = self.slot(sequence);
            self.window[slot] = sequence;
            self.stats.highest_sequence = Some(sequence);
            self.stats.received = self.stats.received.saturating_add(1);
            return self.stats;
        }

        let distance = highest - sequence;
        if distance >= self.window.len() as u64 {
            // Window 外無法安全判斷 duplicate；保守分類為 out-of-order，避免誤報 duplicate。
            self.stats.out_of_order = self.stats.out_of_order.saturating_add(1);
            self.stats.received = self.stats.received.saturating_add(1);
            return self.stats;
        }
        let slot = self.slot(sequence);
        if self.window[slot] == sequence {
            self.stats.duplicate = self.stats.duplicate.saturating_add(1);
            return self.stats;
        }
        self.window[slot] = sequence;
        self.stats.out_of_order = self.stats.out_of_order.saturating_add(1);
        self.stats.received = self.stats.received.saturating_add(1);
        self.stats.lost = self.stats.lost.saturating_sub(1);
        self.stats
    }

    /// 回傳目前統計。
    #[must_use]
    pub const fn stats(&self) -> UdpSequenceStats {
        self.stats
    }

    fn slot(&self, sequence: u64) -> usize {
        usize::try_from(sequence & self.mask).expect("sequence window mask fits usize")
    }
}

impl Default for BoundedUdpSequenceTracker {
    fn default() -> Self {
        Self::new(UDP_SEQUENCE_WINDOW_SIZE).expect("fixed UDP sequence window is valid")
    }
}

impl UdpSequenceTracker {
    /// 納入一個 sequence 並回傳最新統計。
    pub fn observe(&mut self, sequence: u64) -> UdpSequenceStats {
        if !self.seen.insert(sequence) {
            self.stats.duplicate = self.stats.duplicate.saturating_add(1);
            return self.stats;
        }
        if self
            .stats
            .highest_sequence
            .is_some_and(|highest| sequence < highest)
        {
            self.stats.out_of_order = self.stats.out_of_order.saturating_add(1);
        }
        self.stats.highest_sequence = Some(
            self.stats
                .highest_sequence
                .map_or(sequence, |highest| highest.max(sequence)),
        );
        self.stats.received = self.stats.received.saturating_add(1);
        self.stats.lost = self.stats.highest_sequence.map_or(0, |highest| {
            highest
                .saturating_add(1)
                .saturating_sub(self.stats.received)
        });
        self.stats
    }

    /// 回傳目前統計。
    #[must_use]
    pub const fn stats(&self) -> UdpSequenceStats {
        self.stats
    }
}

/// 以相鄰 packet transit time 差估算 jitter；固定 clock offset 會相消。
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UdpJitterTracker {
    previous_transit_nanoseconds: Option<i128>,
    jitter_nanoseconds: u64,
}

impl UdpJitterTracker {
    /// 納入 sender monotonic 與 receiver monotonic timestamp。
    pub fn observe(&mut self, send_timestamp_nanoseconds: u64, receive_timestamp_nanoseconds: u64) {
        let transit = i128::from(receive_timestamp_nanoseconds)
            .saturating_sub(i128::from(send_timestamp_nanoseconds));
        if let Some(previous) = self.previous_transit_nanoseconds {
            let delta = transit.saturating_sub(previous).unsigned_abs();
            let delta = u64::try_from(delta).unwrap_or(u64::MAX);
            // 以 1/16 平滑，避免單一 packet 的 scheduling noise 主導結果。
            self.jitter_nanoseconds = if delta >= self.jitter_nanoseconds {
                self.jitter_nanoseconds
                    .saturating_add((delta - self.jitter_nanoseconds) / 16)
            } else {
                self.jitter_nanoseconds
                    .saturating_sub((self.jitter_nanoseconds - delta) / 16)
            };
        }
        self.previous_transit_nanoseconds = Some(transit);
    }

    /// 目前平滑 jitter，單位 nanoseconds。
    #[must_use]
    pub const fn jitter_nanoseconds(self) -> u64 {
        self.jitter_nanoseconds
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, NetToolError> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| protocol_error("UDP speed u16 field is truncated"))?;
    Ok(u16::from_be_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, NetToolError> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| protocol_error("UDP speed u32 field is truncated"))?;
    Ok(u32::from_be_bytes(value.try_into().map_err(|_| {
        protocol_error("UDP speed u32 field is invalid")
    })?))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, NetToolError> {
    let value = bytes
        .get(offset..offset + 8)
        .ok_or_else(|| protocol_error("UDP speed u64 field is truncated"))?;
    Ok(u64::from_be_bytes(value.try_into().map_err(|_| {
        protocol_error("UDP speed u64 field is invalid")
    })?))
}

fn protocol_error(message: &str) -> NetToolError {
    NetToolError::new(ErrorCode::ProtocolInvalid, message, false)
}

#[cfg(test)]
mod tests {
    use super::{
        BoundedUdpSequenceTracker, UdpCompactHeader, UdpJitterTracker, UdpSequenceTracker,
        UdpSpeedHeader,
    };

    #[test]
    fn compact_header_round_trips_maximum_sequence() {
        let header = UdpCompactHeader {
            flags: 3,
            stream_id: u16::MAX,
            session_tag: 42,
            sequence: u64::MAX,
        };
        assert_eq!(
            UdpCompactHeader::decode(&header.encode()).expect("valid header"),
            header
        );
    }

    #[test]
    fn rejects_malformed_and_short_headers() {
        assert!(UdpCompactHeader::decode(&[]).is_err());
        assert!(UdpCompactHeader::decode(&[0_u8; 16]).is_err());
    }

    #[test]
    fn classifies_loss_reordering_and_duplicates() {
        let mut tracker = UdpSequenceTracker::default();
        tracker.observe(0);
        tracker.observe(2);
        assert_eq!(tracker.stats().lost, 1);
        tracker.observe(1);
        assert_eq!(tracker.stats().lost, 0);
        assert_eq!(tracker.stats().out_of_order, 1);
        tracker.observe(1);
        assert_eq!(tracker.stats().duplicate, 1);
    }

    #[test]
    fn bounded_tracker_corrects_in_window_loss_without_growing() {
        let mut tracker = BoundedUdpSequenceTracker::new(8).expect("window");
        tracker.observe(0);
        tracker.observe(2);
        assert_eq!(tracker.stats().lost, 1);
        tracker.observe(1);
        assert_eq!(tracker.stats().lost, 0);
        assert_eq!(tracker.stats().out_of_order, 1);
        tracker.observe(1);
        assert_eq!(tracker.stats().duplicate, 1);
    }

    #[test]
    fn bounded_tracker_rejects_unbounded_window_configuration() {
        assert!(BoundedUdpSequenceTracker::new(7).is_err());
        assert!(BoundedUdpSequenceTracker::new(1).is_err());
    }

    #[test]
    fn full_header_round_trips_and_binds_payload_length() {
        let header = UdpSpeedHeader {
            session_id: [7; 16],
            stream_id: 12,
            sequence: u64::MAX,
            flags: 3,
            send_timestamp_nanoseconds: 99,
            payload_length: 3,
        };
        let mut datagram = header.encode().to_vec();
        datagram.extend_from_slice(&[1, 2, 3]);
        assert_eq!(
            UdpSpeedHeader::decode_datagram(&datagram).expect("header"),
            header
        );
        datagram.pop();
        assert!(UdpSpeedHeader::decode_datagram(&datagram).is_err());
    }

    #[test]
    fn jitter_uses_transit_delta_not_absolute_clock_offset() {
        let mut tracker = UdpJitterTracker::default();
        tracker.observe(100, 1_000_100);
        tracker.observe(200, 1_000_300);
        assert_eq!(tracker.jitter_nanoseconds(), 6);
    }
}

//! UDP 單向與真正同步雙向的結果 contract。

use nettool_error::{ErrorCode, NetToolError};
use serde::{Deserialize, Serialize};

/// 單一方向的 UDP throughput 結果。
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UdpDirectionResult {
    /// Control plane 協調的共同開始時間。
    pub start_at_unix_nanoseconds: u64,
    /// Local monotonic measurement duration。
    pub elapsed_nanoseconds: u64,
    /// Transmit bits per second。
    pub tx_bits_per_second: u64,
    /// Receive bits per second。
    pub rx_bits_per_second: u64,
    /// Transmit packet count。
    pub tx_packets: u64,
    /// Receive packet count，包含 duplicate datagrams。
    pub rx_packets: u64,
    /// Sequence-based loss count。
    pub sequence_loss_packets: u64,
    /// Duplicate count。
    pub duplicate_packets: u64,
    /// Out-of-order count。
    pub out_of_order_packets: u64,
    /// 平滑 jitter，單位 nanoseconds。
    pub jitter_nanoseconds: u64,
    /// Total CPU usage，basis points；無可靠資料時為 `None`。
    pub cpu_usage_basis_points: Option<u32>,
}

impl UdpDirectionResult {
    /// 驗證結果內部一致性，不推測缺失 CPU 資料。
    ///
    /// # Errors
    ///
    /// Timestamp/duration 為零、loss 超過 TX 或 CPU 超過 100% 時回傳錯誤。
    pub fn validate(&self) -> Result<(), NetToolError> {
        if self.start_at_unix_nanoseconds == 0 || self.elapsed_nanoseconds == 0 {
            return Err(invalid("UDP result requires non-zero start and duration"));
        }
        if self.sequence_loss_packets > self.tx_packets {
            return Err(invalid(
                "UDP sequence loss cannot exceed transmitted packets",
            ));
        }
        if self.cpu_usage_basis_points.is_some_and(|cpu| cpu > 10_000) {
            return Err(invalid("UDP CPU usage cannot exceed 10000 basis points"));
        }
        Ok(())
    }
}

/// 同時雙向測試的 combined 結果。
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BidirectionalUdpResult {
    /// A → B 獨立結果。
    pub a_to_b: UdpDirectionResult,
    /// B → A 獨立結果。
    pub b_to_a: UdpDirectionResult,
    /// 兩方向 RX throughput 合計。
    pub combined_rx_bits_per_second: u64,
    /// 兩方向 TX throughput 合計。
    pub combined_tx_bits_per_second: u64,
    /// 兩方向 sequence loss 合計。
    pub combined_sequence_loss_packets: u64,
}

impl BidirectionalUdpResult {
    /// 合併具有相同 control-plane `start_at` 的兩個方向。
    ///
    /// # Errors
    ///
    /// 任一結果無效、開始時間不同或 aggregate counter overflow 時回傳錯誤；
    /// 因此兩次獨立的單向測試不能偽裝成 bidirectional result。
    pub fn combine(
        a_to_b: UdpDirectionResult,
        b_to_a: UdpDirectionResult,
    ) -> Result<Self, NetToolError> {
        a_to_b.validate()?;
        b_to_a.validate()?;
        if a_to_b.start_at_unix_nanoseconds != b_to_a.start_at_unix_nanoseconds {
            return Err(invalid(
                "bidirectional results must share the same scheduled start",
            ));
        }
        let aggregate_received_rate = a_to_b
            .rx_bits_per_second
            .checked_add(b_to_a.rx_bits_per_second)
            .ok_or_else(|| invalid("combined RX throughput overflow"))?;
        let aggregate_transmitted_rate = a_to_b
            .tx_bits_per_second
            .checked_add(b_to_a.tx_bits_per_second)
            .ok_or_else(|| invalid("combined TX throughput overflow"))?;
        let combined_sequence_loss_packets = a_to_b
            .sequence_loss_packets
            .checked_add(b_to_a.sequence_loss_packets)
            .ok_or_else(|| invalid("combined sequence loss overflow"))?;
        Ok(Self {
            a_to_b,
            b_to_a,
            combined_rx_bits_per_second: aggregate_received_rate,
            combined_tx_bits_per_second: aggregate_transmitted_rate,
            combined_sequence_loss_packets,
        })
    }
}

/// Idle 與 loaded RTT 必須分開保存。
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LatencyComparison {
    /// 無 throughput load 的 RTT nanoseconds。
    pub idle_rtt_nanoseconds: u64,
    /// Throughput test 執行中的 RTT nanoseconds。
    pub loaded_rtt_nanoseconds: u64,
}

impl LatencyComparison {
    /// 建立具有兩種獨立量測的 latency result。
    ///
    /// # Errors
    ///
    /// 任一量測為零時回傳錯誤。
    pub fn new(
        idle_rtt_nanoseconds: u64,
        loaded_rtt_nanoseconds: u64,
    ) -> Result<Self, NetToolError> {
        if idle_rtt_nanoseconds == 0 || loaded_rtt_nanoseconds == 0 {
            return Err(invalid(
                "idle and loaded RTT measurements are both required",
            ));
        }
        Ok(Self {
            idle_rtt_nanoseconds,
            loaded_rtt_nanoseconds,
        })
    }
}

fn invalid(message: &str) -> NetToolError {
    NetToolError::new(ErrorCode::InvalidArgument, message, false)
}

#[cfg(test)]
mod tests {
    use super::{BidirectionalUdpResult, LatencyComparison, UdpDirectionResult};

    #[test]
    fn combines_only_results_from_the_same_synchronized_start() {
        let forward = result(1_000, 80, 79);
        let reverse = result(1_000, 70, 69);
        let combined = BidirectionalUdpResult::combine(forward, reverse).expect("combined");
        assert_eq!(combined.combined_tx_bits_per_second, 150);
        assert_eq!(combined.combined_rx_bits_per_second, 148);
        assert_eq!(combined.combined_sequence_loss_packets, 2);
        assert!(BidirectionalUdpResult::combine(result(1_000, 1, 1), result(2_000, 1, 1)).is_err());
    }

    #[test]
    fn preserves_missing_cpu_instead_of_guessing() {
        let value = result(1_000, 1, 1);
        assert_eq!(value.cpu_usage_basis_points, None);
        value.validate().expect("valid result");
    }

    #[test]
    fn requires_separate_idle_and_loaded_latency_measurements() {
        assert_eq!(
            LatencyComparison::new(10, 20)
                .expect("latency")
                .loaded_rtt_nanoseconds,
            20
        );
        assert!(LatencyComparison::new(10, 0).is_err());
    }

    fn result(start: u64, tx_rate: u64, rx_rate: u64) -> UdpDirectionResult {
        UdpDirectionResult {
            start_at_unix_nanoseconds: start,
            elapsed_nanoseconds: 1_000,
            tx_bits_per_second: tx_rate,
            rx_bits_per_second: rx_rate,
            tx_packets: 100,
            rx_packets: 99,
            sequence_loss_packets: 1,
            duplicate_packets: 0,
            out_of_order_packets: 0,
            jitter_nanoseconds: 1,
            cpu_usage_basis_points: None,
        }
    }
}

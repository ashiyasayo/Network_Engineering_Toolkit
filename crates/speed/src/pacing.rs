//! UDP rate modes、batch pacing 與 ramp loss-threshold search。

use nettool_error::{ErrorCode, NetToolError};
use serde::{Deserialize, Serialize};

/// UDP transmitter rate mode。
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UdpRateMode {
    /// 不由 software pacer 限速。
    Unlimited,
    /// 固定 bits per second。
    Fixed {
        /// 目標 bits per second。
        bits_per_second: u64,
    },
    /// 依序執行多個固定速率階段。
    Ramp {
        /// 嚴格遞增的階段目標速率。
        steps_bits_per_second: Vec<u64>,
    },
}

impl UdpRateMode {
    /// 驗證非零且嚴格遞增的 rate 設定。
    ///
    /// # Errors
    ///
    /// Fixed rate 為零，或 ramp 為空、含零值、非遞增時回傳錯誤。
    pub fn validate(&self) -> Result<(), NetToolError> {
        match self {
            Self::Unlimited => Ok(()),
            Self::Fixed { bits_per_second } if *bits_per_second > 0 => Ok(()),
            Self::Fixed { .. } => Err(invalid("fixed UDP rate must be greater than zero")),
            Self::Ramp {
                steps_bits_per_second,
            } if steps_bits_per_second.is_empty() => Err(invalid("UDP ramp requires steps")),
            Self::Ramp {
                steps_bits_per_second,
            } => {
                if steps_bits_per_second[0] == 0
                    || steps_bits_per_second
                        .windows(2)
                        .any(|pair| pair[0] >= pair[1])
                {
                    return Err(invalid("UDP ramp steps must be non-zero and increasing"));
                }
                Ok(())
            }
        }
    }

    /// 規格列出的 10G 到 100G 預設 ramp；loss 門檻仍必須由 profile 提供。
    #[must_use]
    pub fn standard_100g_ramp() -> Self {
        Self::Ramp {
            steps_bits_per_second: vec![
                10_000_000_000,
                20_000_000_000,
                40_000_000_000,
                60_000_000_000,
                80_000_000_000,
                90_000_000_000,
                95_000_000_000,
                100_000_000_000,
            ],
        }
    }
}

/// Software/hardware pacing 策略。
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PacingStrategy {
    /// 低速 timer-based pacing。
    Timer,
    /// 高速 batch/burst pacing，不逐 packet sleep。
    Batch {
        /// 單一 burst 上限。
        maximum_packets_per_burst: u32,
    },
    /// NIC hardware pacing。
    Hardware,
}

/// Pacing capability 與 profile 門檻。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacingPolicy {
    /// Backend 是否提供 hardware pacing。
    pub hardware_pacing: bool,
    /// 達到此速率後不得使用逐 packet timer；由 profile/POC 決定。
    pub high_rate_threshold_bits_per_second: u64,
    /// Batch strategy 每次最多 packets。
    pub maximum_packets_per_burst: u32,
}

impl PacingPolicy {
    /// 依 target rate 選擇 pacing strategy。
    ///
    /// # Errors
    ///
    /// Policy 邊界或 target rate 無效時回傳錯誤。
    pub fn select(self, target_bits_per_second: u64) -> Result<PacingStrategy, NetToolError> {
        if target_bits_per_second == 0 || self.high_rate_threshold_bits_per_second == 0 {
            return Err(invalid("pacing rates must be greater than zero"));
        }
        if !(1..=4096).contains(&self.maximum_packets_per_burst) {
            return Err(invalid("pacing burst size must be between 1 and 4096"));
        }
        if target_bits_per_second >= self.high_rate_threshold_bits_per_second {
            if self.hardware_pacing {
                Ok(PacingStrategy::Hardware)
            } else {
                Ok(PacingStrategy::Batch {
                    maximum_packets_per_burst: self.maximum_packets_per_burst,
                })
            }
        } else {
            Ok(PacingStrategy::Timer)
        }
    }
}

/// Fixed-rate batch pacer 的累積 budget。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchPacer {
    bits_per_second: u64,
    wire_bytes_per_packet: u32,
    sent_packets: u64,
}

impl BatchPacer {
    /// 建立 pacer；wire size 必須包含 speed engine 用來計價的所有 framing bytes。
    ///
    /// # Errors
    ///
    /// Rate 或 wire size 為零時回傳錯誤。
    pub fn new(bits_per_second: u64, wire_bytes_per_packet: u32) -> Result<Self, NetToolError> {
        if bits_per_second == 0 || wire_bytes_per_packet == 0 {
            return Err(invalid("batch pacer rate and wire size must be non-zero"));
        }
        Ok(Self {
            bits_per_second,
            wire_bytes_per_packet,
            sent_packets: 0,
        })
    }

    /// 依 measurement 起點後的 monotonic elapsed 計算本 burst 可送 packets。
    ///
    /// 呼叫端若取得零值應等待下一個 batch deadline，不可逐 packet sleep。
    #[must_use]
    pub fn available_packets(&self, elapsed_nanoseconds: u64, maximum_burst: u32) -> u32 {
        let allowed_bits = u128::from(self.bits_per_second)
            .saturating_mul(u128::from(elapsed_nanoseconds))
            / 1_000_000_000_u128;
        let bits_per_packet = u128::from(self.wire_bytes_per_packet).saturating_mul(8);
        let allowed_packets = allowed_bits / bits_per_packet;
        let outstanding = allowed_packets.saturating_sub(u128::from(self.sent_packets));
        u32::try_from(outstanding.min(u128::from(maximum_burst))).unwrap_or(maximum_burst)
    }

    /// 提交實際成功送出的 packets。
    ///
    /// # Errors
    ///
    /// Counter overflow 時回傳錯誤。
    pub fn record_sent(&mut self, packets: u32) -> Result<(), NetToolError> {
        self.sent_packets = self
            .sent_packets
            .checked_add(u64::from(packets))
            .ok_or_else(|| invalid("UDP sent packet counter overflow"))?;
        Ok(())
    }
}

/// 單一 ramp stage 的量測。
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RampObservation {
    /// Target bits per second。
    pub target_bits_per_second: u64,
    /// 實際 TX packets。
    pub tx_packets: u64,
    /// Sequence loss packets。
    pub sequence_loss_packets: u64,
}

/// 依 profile 提供的 loss ppm 門檻找出最後通過的速率。
///
/// # Errors
///
/// 門檻大於一百萬、觀測順序錯誤、TX 為零或 loss 大於 TX 時回傳錯誤。
pub fn find_loss_threshold(
    observations: &[RampObservation],
    maximum_loss_parts_per_million: u32,
) -> Result<Option<u64>, NetToolError> {
    if maximum_loss_parts_per_million > 1_000_000 {
        return Err(invalid("loss threshold ppm cannot exceed one million"));
    }
    let mut last_rate = 0;
    let mut highest_passing = None;
    for observation in observations {
        if observation.target_bits_per_second == 0
            || observation.target_bits_per_second <= last_rate
            || observation.tx_packets == 0
            || observation.sequence_loss_packets > observation.tx_packets
        {
            return Err(invalid("ramp observation is invalid"));
        }
        last_rate = observation.target_bits_per_second;
        let loss_ppm = u128::from(observation.sequence_loss_packets).saturating_mul(1_000_000)
            / u128::from(observation.tx_packets);
        if loss_ppm > u128::from(maximum_loss_parts_per_million) {
            break;
        }
        highest_passing = Some(observation.target_bits_per_second);
    }
    Ok(highest_passing)
}

fn invalid(message: &str) -> NetToolError {
    NetToolError::new(ErrorCode::InvalidArgument, message, false)
}

#[cfg(test)]
mod tests {
    use super::{
        BatchPacer, PacingPolicy, PacingStrategy, RampObservation, UdpRateMode, find_loss_threshold,
    };

    #[test]
    fn high_rate_never_selects_per_packet_timer() {
        let policy = PacingPolicy {
            hardware_pacing: false,
            high_rate_threshold_bits_per_second: 10_000,
            maximum_packets_per_burst: 64,
        };
        assert_eq!(
            policy.select(10_000).expect("strategy"),
            PacingStrategy::Batch {
                maximum_packets_per_burst: 64
            }
        );
        assert_eq!(
            policy.select(9_999).expect("strategy"),
            PacingStrategy::Timer
        );
    }

    #[test]
    fn batch_budget_uses_cumulative_monotonic_elapsed() {
        let mut pacer = BatchPacer::new(8_000, 100).expect("pacer");
        assert_eq!(pacer.available_packets(500_000_000, 64), 5);
        pacer.record_sent(3).expect("counter");
        assert_eq!(pacer.available_packets(500_000_000, 64), 2);
        assert_eq!(pacer.available_packets(1_000_000_000, 4), 4);
    }

    #[test]
    fn ramp_stops_at_first_configured_loss_failure() {
        let observations = [
            RampObservation {
                target_bits_per_second: 10,
                tx_packets: 1_000_000,
                sequence_loss_packets: 10,
            },
            RampObservation {
                target_bits_per_second: 20,
                tx_packets: 1_000_000,
                sequence_loss_packets: 101,
            },
            RampObservation {
                target_bits_per_second: 30,
                tx_packets: 1_000_000,
                sequence_loss_packets: 0,
            },
        ];
        assert_eq!(
            find_loss_threshold(&observations, 100).expect("threshold"),
            Some(10)
        );
    }

    #[test]
    fn validates_standard_ramp_and_rejects_unsorted_steps() {
        UdpRateMode::standard_100g_ramp().validate().expect("ramp");
        assert!(
            UdpRateMode::Ramp {
                steps_bits_per_second: vec![20, 10]
            }
            .validate()
            .is_err()
        );
    }
}

use crate::{ConfidenceAssessment, FlowDirection};
use nettool_domain::AnalysisConfidence;

const FIN: u16 = 0x001;
const SYN: u16 = 0x002;
const RST: u16 = 0x004;
const ACK: u16 = 0x010;

/// 單一方向的 TCP observation。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpObservation {
    /// Canonical flow direction。
    pub direction: FlowDirection,
    /// Sequence number。
    pub sequence: u32,
    /// Acknowledgement number。
    pub acknowledgement: u32,
    /// Advertised receive window。
    pub window: u16,
    /// TCP flags。
    pub flags: u16,
    /// Payload length。
    pub payload_length: u32,
}

/// TCP packet classification。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpClassification {
    /// Sequence 延續目前已知範圍。
    InOrder,
    /// 已完整觀察過的 sequence range 再次出現。
    ObservedRetransmission,
    /// Range 與已觀察範圍重疊，但 capture 完整性不足。
    SuspectedRetransmission,
    /// Sequence 超前，可能有 reorder 或 capture gap。
    OutOfOrder,
    /// ACK 未前進且不攜帶 sequence space。
    DuplicateAck,
}

/// 每一方向至少保存規格要求的 TCP state。
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TcpFlowState {
    /// 下一個預期 sequence。
    pub next_seq: Option<u32>,
    /// 最近 ACK。
    pub last_ack: Option<u32>,
    /// 最近 advertised window。
    pub window: u16,
    /// 是否看過 SYN。
    pub syn_seen: bool,
    /// 是否看過 FIN。
    pub fin_seen: bool,
    /// 是否看過 RST。
    pub rst_seen: bool,
    /// Observed 與 suspected retransmission 總數。
    pub retransmission_count: u64,
    /// Out-of-order 總數。
    pub out_of_order_count: u64,
}

/// 單次分析結果與 confidence evidence。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcpAnalysis {
    /// Classification。
    pub classification: TcpClassification,
    /// Capture drop 會阻止 retransmission 維持 HIGH。
    pub confidence: ConfidenceAssessment,
}

/// 雙向 TCP flow analyzer；由 owning worker 保存，不需要共享鎖。
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TcpFlowAnalyzer {
    /// Canonical forward direction state。
    pub forward: TcpFlowState,
    /// Canonical reverse direction state。
    pub reverse: TcpFlowState,
}

impl TcpFlowAnalyzer {
    /// 更新指定方向並分類 packet。
    #[must_use]
    pub fn observe(&mut self, packet: TcpObservation, capture_drops: u64) -> TcpAnalysis {
        let state = match packet.direction {
            FlowDirection::Forward => &mut self.forward,
            FlowDirection::Reverse => &mut self.reverse,
        };
        let consumes = packet
            .payload_length
            .saturating_add(u32::from(packet.flags & SYN != 0))
            .saturating_add(u32::from(packet.flags & FIN != 0));
        let end = packet.sequence.wrapping_add(consumes);
        let duplicate_ack = packet.flags & ACK != 0
            && consumes == 0
            && state.last_ack == Some(packet.acknowledgement);

        let classification = if duplicate_ack {
            TcpClassification::DuplicateAck
        } else if let Some(expected) = state.next_seq {
            if seq_before(packet.sequence, expected) {
                state.retransmission_count = state.retransmission_count.saturating_add(1);
                if capture_drops == 0 {
                    TcpClassification::ObservedRetransmission
                } else {
                    TcpClassification::SuspectedRetransmission
                }
            } else if seq_after(packet.sequence, expected) {
                state.out_of_order_count = state.out_of_order_count.saturating_add(1);
                TcpClassification::OutOfOrder
            } else {
                state.next_seq = Some(end);
                TcpClassification::InOrder
            }
        } else {
            state.next_seq = Some(end);
            TcpClassification::InOrder
        };

        if matches!(
            classification,
            TcpClassification::ObservedRetransmission | TcpClassification::SuspectedRetransmission
        ) && state
            .next_seq
            .is_some_and(|expected| seq_after(end, expected))
        {
            state.next_seq = Some(end);
        }
        if packet.flags & ACK != 0 {
            state.last_ack = Some(packet.acknowledgement);
        }
        state.window = packet.window;
        state.syn_seen |= packet.flags & SYN != 0;
        state.fin_seen |= packet.flags & FIN != 0;
        state.rst_seen |= packet.flags & RST != 0;

        TcpAnalysis {
            classification,
            confidence: if capture_drops == 0 {
                ConfidenceAssessment {
                    level: AnalysisConfidence::High,
                    reason: "capture_complete",
                }
            } else {
                ConfidenceAssessment {
                    level: AnalysisConfidence::Low,
                    reason: "capture_drop_observed",
                }
            },
        }
    }
}

fn seq_before(left: u32, right: u32) -> bool {
    i32::from_ne_bytes(left.wrapping_sub(right).to_ne_bytes()) < 0
}

fn seq_after(left: u32, right: u32) -> bool {
    seq_before(right, left)
}

#[cfg(test)]
mod tests {
    use super::{ACK, SYN, TcpClassification, TcpFlowAnalyzer, TcpObservation};
    use crate::FlowDirection;
    use nettool_domain::AnalysisConfidence;

    fn packet(
        sequence: u32,
        acknowledgement: u32,
        flags: u16,
        payload_length: u32,
    ) -> TcpObservation {
        TcpObservation {
            direction: FlowDirection::Forward,
            sequence,
            acknowledgement,
            window: 65_535,
            flags,
            payload_length,
        }
    }

    #[test]
    fn tracks_required_state_and_retransmission() {
        let mut analyzer = TcpFlowAnalyzer::default();
        assert_eq!(
            analyzer.observe(packet(100, 0, SYN, 0), 0).classification,
            TcpClassification::InOrder
        );
        assert_eq!(
            analyzer.observe(packet(101, 1, ACK, 10), 0).classification,
            TcpClassification::InOrder
        );
        let retransmission = analyzer.observe(packet(101, 1, ACK, 10), 0);
        assert_eq!(
            retransmission.classification,
            TcpClassification::ObservedRetransmission
        );
        assert_eq!(retransmission.confidence.level, AnalysisConfidence::High);
        assert!(analyzer.forward.syn_seen);
        assert_eq!(analyzer.forward.next_seq, Some(111));
        assert_eq!(analyzer.forward.retransmission_count, 1);
    }

    #[test]
    fn capture_drop_makes_retransmission_suspected_and_low_confidence() {
        let mut analyzer = TcpFlowAnalyzer::default();
        let _ = analyzer.observe(packet(10, 0, 0, 10), 0);
        let result = analyzer.observe(packet(10, 0, 0, 10), 1);
        assert_eq!(
            result.classification,
            TcpClassification::SuspectedRetransmission
        );
        assert_eq!(result.confidence.level, AnalysisConfidence::Low);
    }

    #[test]
    fn distinguishes_gap_and_duplicate_ack() {
        let mut analyzer = TcpFlowAnalyzer::default();
        let _ = analyzer.observe(packet(10, 20, ACK, 10), 0);
        assert_eq!(
            analyzer.observe(packet(30, 21, ACK, 10), 0).classification,
            TcpClassification::OutOfOrder
        );
        assert_eq!(
            analyzer.observe(packet(20, 21, ACK, 0), 0).classification,
            TcpClassification::DuplicateAck
        );
        assert_eq!(analyzer.forward.out_of_order_count, 1);
    }

    #[test]
    fn sequence_comparison_handles_wraparound() {
        let mut analyzer = TcpFlowAnalyzer::default();
        let _ = analyzer.observe(packet(u32::MAX - 1, 0, 0, 4), 0);
        assert_eq!(analyzer.forward.next_seq, Some(2));
        assert_eq!(
            analyzer.observe(packet(2, 0, 0, 1), 0).classification,
            TcpClassification::InOrder
        );
    }
}

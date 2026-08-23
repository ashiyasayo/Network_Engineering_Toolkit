//! Data-plane packet view、local counters、drop accounting 與 confidence。

#![forbid(unsafe_code)]

use nettool_domain::AnalysisConfidence;
use nettool_error::{ErrorCode, NetToolError};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::ops::AddAssign;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

mod capture;
mod flow;
mod generator;
mod parser;
mod tcp;
mod worker;

pub use capture::{
    CaptureFormat, CaptureMode, CaptureQueue, CaptureReceiver, CaptureRecord, CaptureRotation,
    CaptureStorageEvidence, CaptureStorageGuard, RotatingCaptureWriter, certify_capture_storage,
};

pub use flow::{
    FlowDirection, FlowDisposition, FlowKey, FlowSharder, FlowTable, FlowTableStats, FlowTuple,
};
pub use generator::{
    GeneratorNetwork, GeneratorTransport, IpRange, PortRange, RawGeneratorProfile,
    theoretical_packets_per_second,
};
pub use parser::{
    ArpPacket, EthernetHeader, IcmpPacket, IpPacket, ParseError, ParsedPacket, TcpSegment,
    TransportPacket, UdpDatagram, VlanTag, parse_packet,
};
pub use tcp::{TcpAnalysis, TcpClassification, TcpFlowAnalyzer, TcpFlowState, TcpObservation};
pub use worker::{
    AnalysisCoverage, BurstSource, PacketWorker, PacketWorkerConfiguration, WorkerRunResult,
};

/// Backend-owned packet buffer 的零配置 borrowed view。
#[derive(Clone, Copy)]
pub struct PacketView<'a> {
    /// 完整可見 bytes；生命週期不得超過 backend buffer ownership。
    pub bytes: &'a [u8],
    /// Backend capture/receive monotonic timestamp nanoseconds。
    pub timestamp_nanoseconds: u64,
    /// 原始 wire length；可能大於 snaplen bytes。
    pub wire_length: u32,
    /// RX queue index。
    pub queue_id: u16,
}

/// Capture filter；未設定的欄位代表不限制該欄位。
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PacketFilter {
    /// IP protocol number（TCP=6、UDP=17、ICMP=1/58）。
    pub protocol: Option<u8>,
    /// Source IP。
    pub source_ip: Option<IpAddr>,
    /// Destination IP。
    pub destination_ip: Option<IpAddr>,
    /// Source TCP/UDP port。
    pub source_port: Option<u16>,
    /// Destination TCP/UDP port。
    pub destination_port: Option<u16>,
}

impl PacketFilter {
    /// 判定 borrowed packet 是否符合 filter；malformed packet 不符合 filter。
    #[must_use]
    pub fn matches(&self, packet: PacketView<'_>) -> bool {
        let Ok(parsed) = parse_packet(packet.bytes) else {
            return false;
        };
        let Some(ip) = parsed.ip else {
            return false;
        };
        if self
            .protocol
            .is_some_and(|protocol| protocol != ip.protocol)
            || self.source_ip.is_some_and(|source| source != ip.source)
            || self
                .destination_ip
                .is_some_and(|destination| destination != ip.destination)
        {
            return false;
        }
        let ports = match parsed.transport {
            Some(TransportPacket::Tcp(segment)) => {
                Some((segment.source_port, segment.destination_port))
            }
            Some(TransportPacket::Udp(datagram)) => {
                Some((datagram.source_port, datagram.destination_port))
            }
            _ => None,
        };
        if self.source_port.is_some() || self.destination_port.is_some() {
            let Some((source_port, destination_port)) = ports else {
                return false;
            };
            if self.source_port.is_some_and(|port| port != source_port)
                || self
                    .destination_port
                    .is_some_and(|port| port != destination_port)
            {
                return false;
            }
        }
        true
    }
}

/// 單一 worker 私有 counters；hot path 不需要 atomic 或 lock。
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct WorkerStats {
    /// Received packets。
    pub rx_packets: u64,
    /// Received wire bytes。
    pub rx_bytes: u64,
    /// Parsed TCP packets。
    pub tcp_packets: u64,
    /// Parsed UDP packets。
    pub udp_packets: u64,
    /// Parsed IPv4 packets。
    pub ipv4_packets: u64,
    /// Parsed IPv6 packets。
    pub ipv6_packets: u64,
    /// Parsed ICMP/ICMPv6 packets。
    pub icmp_packets: u64,
    /// Parsed IP packets with an unclassified transport protocol。
    pub other_packets: u64,
    /// Active/observed flows。
    pub flows: u64,
    /// Classified TCP retransmissions。
    pub retransmissions: u64,
    /// Parser 拒絕的 malformed 或 truncated packets。
    pub parse_errors: u64,
    /// Sampling policy 明確未分析的 packets。
    pub sampled_out_packets: u64,
    /// Drop counters。
    pub drops: DropAccounting,
}

impl WorkerStats {
    /// 記錄一個 packet；只做 local integer updates。
    #[inline]
    pub fn record_packet(&mut self, wire_length: u32) {
        self.rx_packets = self.rx_packets.saturating_add(1);
        self.rx_bytes = self.rx_bytes.saturating_add(u64::from(wire_length));
    }
}

impl AddAssign for WorkerStats {
    fn add_assign(&mut self, other: Self) {
        self.rx_packets = self.rx_packets.saturating_add(other.rx_packets);
        self.rx_bytes = self.rx_bytes.saturating_add(other.rx_bytes);
        self.tcp_packets = self.tcp_packets.saturating_add(other.tcp_packets);
        self.udp_packets = self.udp_packets.saturating_add(other.udp_packets);
        self.ipv4_packets = self.ipv4_packets.saturating_add(other.ipv4_packets);
        self.ipv6_packets = self.ipv6_packets.saturating_add(other.ipv6_packets);
        self.icmp_packets = self.icmp_packets.saturating_add(other.icmp_packets);
        self.other_packets = self.other_packets.saturating_add(other.other_packets);
        self.flows = self.flows.saturating_add(other.flows);
        self.retransmissions = self.retransmissions.saturating_add(other.retransmissions);
        self.parse_errors = self.parse_errors.saturating_add(other.parse_errors);
        self.sampled_out_packets = self
            .sampled_out_packets
            .saturating_add(other.sampled_out_packets);
        self.drops += other.drops;
    }
}

/// 不可互相混用的 drop 類別。
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct DropAccounting {
    /// NIC hardware/xstats drop。
    pub nic: u64,
    /// Driver/backend drop。
    pub driver: u64,
    /// Capture path 無法取得或保存的 packets。
    pub capture: u64,
    /// Internal bounded ring full。
    pub ring: u64,
    /// Analyzer 無法處理或 intentionally sampled packets。
    pub analyzer: u64,
    /// Application consumer drop。
    pub application: u64,
    /// 只有具 sequence 主動測試才可填入的 inferred network loss。
    pub network_inferred_loss: u64,
}

impl AddAssign for DropAccounting {
    fn add_assign(&mut self, other: Self) {
        self.nic = self.nic.saturating_add(other.nic);
        self.driver = self.driver.saturating_add(other.driver);
        self.capture = self.capture.saturating_add(other.capture);
        self.ring = self.ring.saturating_add(other.ring);
        self.analyzer = self.analyzer.saturating_add(other.analyzer);
        self.application = self.application.saturating_add(other.application);
        self.network_inferred_loss = self
            .network_inferred_loss
            .saturating_add(other.network_inferred_loss);
    }
}

/// NIC drop counter 的來源，避免無法比較的 counters 被混為一談。
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NicCounterEvidence {
    /// PMD xstat、hardware register 或 platform API 的 stable source name。
    pub source: String,
    /// Counter value。
    pub value: u64,
}

/// Aggregator 產生的低頻 statistics snapshot。
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct StatisticsSnapshot {
    /// 合併後 counters。
    pub counters: WorkerStats,
    /// Measurement elapsed nanoseconds。
    pub elapsed_nanoseconds: u64,
    /// Receive packets per second。
    pub rx_packets_per_second: f64,
    /// Receive bits per second。
    pub rx_bits_per_second: f64,
    /// Million packets per second。
    pub rx_mpps: f64,
    /// Gigabits per second。
    pub rx_gbps: f64,
}

/// 合併 worker-local counters 並計算低頻 rates。
#[must_use]
#[allow(clippy::cast_precision_loss)]
pub fn aggregate_statistics(workers: &[WorkerStats], elapsed: Duration) -> StatisticsSnapshot {
    let mut counters = WorkerStats::default();
    for worker in workers {
        counters += *worker;
    }
    let elapsed_nanoseconds = u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX);
    let seconds = elapsed.as_secs_f64();
    let (rx_packets_per_second, rx_bits_per_second) = if seconds > 0.0 {
        (
            counters.rx_packets as f64 / seconds,
            counters.rx_bytes as f64 * 8.0 / seconds,
        )
    } else {
        (0.0, 0.0)
    };
    StatisticsSnapshot {
        counters,
        elapsed_nanoseconds,
        rx_packets_per_second,
        rx_bits_per_second,
        rx_mpps: rx_packets_per_second / 1_000_000.0,
        rx_gbps: rx_bits_per_second / 1_000_000_000.0,
    }
}

/// POC 後由 benchmark specification 注入的 confidence thresholds。
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ConfidenceThresholds {
    /// 仍可標示 Medium 的最大 capture drop ratio。
    pub max_medium_capture_ratio: f64,
    /// 仍可標示 Medium 的最大 ring drop ratio。
    pub max_medium_ring_ratio: f64,
    /// 仍可標示 Medium 的最大 analyzer drop ratio。
    pub max_medium_analyzer_ratio: f64,
}

/// Confidence 判斷所需的 evidence。
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ConfidenceEvidence {
    /// Received packets，作為 drop ratio denominator 的一部分。
    pub received_packets: u64,
    /// Drop accounting。
    pub drops: DropAccounting,
    /// Required flow state 是否完整。
    pub required_flow_state_complete: bool,
    /// 任何會使結果無效的 runtime evidence。
    pub invalid_reason: Option<InvalidRuntimeReason>,
}

/// 會使 analysis result 直接成為 INVALID 的事件。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvalidRuntimeReason {
    /// Hardware/backend counter reset。
    CounterReset,
    /// NIC reset。
    NicReset,
    /// Capture backend failure。
    CaptureBackendFailure,
    /// Monotonic clock discontinuity。
    ClockDiscontinuity,
}

/// Confidence level 與可稽核理由。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfidenceAssessment {
    /// HIGH/MEDIUM/LOW/INVALID。
    pub level: AnalysisConfidence,
    /// Stable reason identifier。
    pub reason: &'static str,
}

/// 依 drop 與資料完整性計算 analysis confidence。
///
/// Threshold 尚未由 POC 固定時，不猜測數字；任何 drop 會保守降為 LOW。
///
/// # Errors
///
/// Threshold 不在 `0.0..=1.0` 時回傳錯誤。
pub fn assess_confidence(
    evidence: ConfidenceEvidence,
    thresholds: Option<ConfidenceThresholds>,
) -> Result<ConfidenceAssessment, NetToolError> {
    if evidence.invalid_reason.is_some() {
        return Ok(ConfidenceAssessment {
            level: AnalysisConfidence::Invalid,
            reason: "invalid_runtime_evidence",
        });
    }
    if !evidence.required_flow_state_complete {
        return Ok(ConfidenceAssessment {
            level: AnalysisConfidence::Low,
            reason: "flow_state_incomplete",
        });
    }
    if evidence.drops.capture == 0 && evidence.drops.ring == 0 && evidence.drops.analyzer == 0 {
        return Ok(ConfidenceAssessment {
            level: AnalysisConfidence::High,
            reason: "analysis_path_complete",
        });
    }
    let Some(thresholds) = thresholds else {
        return Ok(ConfidenceAssessment {
            level: AnalysisConfidence::Low,
            reason: "drop_threshold_not_frozen",
        });
    };
    validate_thresholds(thresholds)?;
    #[allow(clippy::cast_precision_loss)]
    let denominator = evidence
        .received_packets
        .saturating_add(evidence.drops.capture)
        .saturating_add(evidence.drops.ring)
        .saturating_add(evidence.drops.analyzer)
        .max(1) as f64;
    #[allow(clippy::cast_precision_loss)]
    let within_medium = evidence.drops.capture as f64 / denominator
        <= thresholds.max_medium_capture_ratio
        && evidence.drops.ring as f64 / denominator <= thresholds.max_medium_ring_ratio
        && evidence.drops.analyzer as f64 / denominator <= thresholds.max_medium_analyzer_ratio;
    Ok(if within_medium {
        ConfidenceAssessment {
            level: AnalysisConfidence::Medium,
            reason: "analysis_drop_within_threshold",
        }
    } else {
        ConfidenceAssessment {
            level: AnalysisConfidence::Low,
            reason: "analysis_drop_exceeds_threshold",
        }
    })
}

/// Fast-path cancellation token；worker 只在 burst boundary 讀取 relaxed atomic flag。
#[derive(Default)]
pub struct StopToken {
    stopped: AtomicBool,
}

impl StopToken {
    /// 建立未停止 token。
    #[must_use]
    pub const fn new() -> Self {
        Self {
            stopped: AtomicBool::new(false),
        }
    }
    /// 要求停止；重複呼叫為冪等操作。
    pub fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
    }
    /// Worker 在 burst boundary 檢查。
    #[inline]
    #[must_use]
    pub fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::Acquire)
    }
}

/// Data-plane error severity。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DataPlaneErrorSeverity {
    /// 記錄 counter 後可繼續。
    Recoverable,
    /// 可繼續但 confidence 必須降低。
    Degraded,
    /// 必須停止 session。
    Fatal,
}

fn validate_thresholds(thresholds: ConfidenceThresholds) -> Result<(), NetToolError> {
    if [
        thresholds.max_medium_capture_ratio,
        thresholds.max_medium_ring_ratio,
        thresholds.max_medium_analyzer_ratio,
    ]
    .into_iter()
    .all(|ratio| (0.0..=1.0).contains(&ratio))
    {
        Ok(())
    } else {
        Err(NetToolError::new(
            ErrorCode::InvalidArgument,
            "confidence thresholds must be between zero and one",
            false,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ConfidenceEvidence, ConfidenceThresholds, DropAccounting, InvalidRuntimeReason, StopToken,
        WorkerStats, aggregate_statistics, assess_confidence,
    };
    use nettool_domain::AnalysisConfidence;
    use std::time::Duration;

    #[test]
    fn merges_worker_counters_without_mixing_drop_categories() {
        let workers = [
            WorkerStats {
                rx_packets: 1_000_000,
                rx_bytes: 1_000_000_000,
                drops: DropAccounting {
                    nic: 1,
                    ring: 2,
                    analyzer: 3,
                    ..DropAccounting::default()
                },
                ..WorkerStats::default()
            },
            WorkerStats {
                rx_packets: 1_000_000,
                rx_bytes: 1_000_000_000,
                drops: DropAccounting {
                    capture: 4,
                    driver: 5,
                    ..DropAccounting::default()
                },
                ..WorkerStats::default()
            },
        ];
        let snapshot = aggregate_statistics(&workers, Duration::from_secs(1));
        assert_eq!(snapshot.counters.rx_packets, 2_000_000);
        assert!((snapshot.rx_mpps - 2.0).abs() < f64::EPSILON);
        assert!((snapshot.rx_gbps - 16.0).abs() < f64::EPSILON);
        assert_eq!(snapshot.counters.drops.nic, 1);
        assert_eq!(snapshot.counters.drops.capture, 4);
        assert_eq!(snapshot.counters.drops.ring, 2);
    }

    #[test]
    fn confidence_never_stays_high_when_analysis_drops_exist() {
        let evidence = ConfidenceEvidence {
            received_packets: 10_000,
            drops: DropAccounting {
                capture: 1,
                ..DropAccounting::default()
            },
            required_flow_state_complete: true,
            ..ConfidenceEvidence::default()
        };
        assert_eq!(
            assess_confidence(evidence, None)
                .expect("assessment succeeds")
                .level,
            AnalysisConfidence::Low
        );
        let thresholds = ConfidenceThresholds {
            max_medium_capture_ratio: 0.001,
            max_medium_ring_ratio: 0.0,
            max_medium_analyzer_ratio: 0.0,
        };
        assert_eq!(
            assess_confidence(evidence, Some(thresholds))
                .expect("assessment succeeds")
                .level,
            AnalysisConfidence::Medium
        );
    }

    #[test]
    fn runtime_discontinuity_is_invalid() {
        let evidence = ConfidenceEvidence {
            required_flow_state_complete: true,
            invalid_reason: Some(InvalidRuntimeReason::NicReset),
            ..ConfidenceEvidence::default()
        };
        assert_eq!(
            assess_confidence(evidence, None)
                .expect("assessment succeeds")
                .level,
            AnalysisConfidence::Invalid
        );
    }

    #[test]
    fn stop_token_is_idempotent() {
        let token = StopToken::new();
        assert!(!token.is_stopped());
        token.stop();
        token.stop();
        assert!(token.is_stopped());
    }
}

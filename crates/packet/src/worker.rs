use crate::{
    CaptureQueue, FlowKey, FlowTable, FlowTuple, PacketFilter, PacketView, StopToken,
    TcpClassification, TcpFlowAnalyzer, TcpObservation, TransportPacket, WorkerStats, parse_packet,
};
use nettool_error::{ErrorCode, NetToolError};
use std::net::IpAddr;

/// Analyzer coverage；sampled mode 必須由結果與 UI 明確揭露。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnalysisCoverage {
    /// 每個收到的 packet 都送入 analyzer。
    Full,
    /// 每 `one_in` packets 分析一個。
    Sampled {
        /// 每多少 packets 選取一個進入 analyzer。
        one_in: u32,
    },
}

impl AnalysisCoverage {
    /// 是否為 sampled analysis。
    #[must_use]
    pub const fn is_sampled(self) -> bool {
        matches!(self, Self::Sampled { .. })
    }
}

/// Packet worker configuration。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketWorkerConfiguration {
    /// Worker-local maximum active flows。
    pub maximum_flows: usize,
    /// Flow idle timeout nanoseconds。
    pub flow_idle_timeout_nanoseconds: u64,
    /// Analysis coverage policy。
    pub analysis_coverage: AnalysisCoverage,
}

impl PacketWorkerConfiguration {
    /// 驗證 worker bounds 與 sampling ratio。
    ///
    /// # Errors
    ///
    /// Flow bounds、timeout 或 sampling ratio 為零時回傳錯誤。
    pub fn validate(self) -> Result<(), NetToolError> {
        if self.maximum_flows == 0 || self.flow_idle_timeout_nanoseconds == 0 {
            return Err(NetToolError::new(
                ErrorCode::InvalidArgument,
                "packet worker flow bounds must be greater than zero",
                false,
            ));
        }
        if matches!(
            self.analysis_coverage,
            AnalysisCoverage::Sampled { one_in: 0 }
        ) {
            return Err(NetToolError::new(
                ErrorCode::InvalidArgument,
                "packet analysis sampling ratio must be greater than zero",
                false,
            ));
        }
        Ok(())
    }
}

/// Backend burst boundary；backend 保有 buffer ownership，callback 只在呼叫期間借用 view。
pub trait BurstSource {
    /// 取得一個 burst，對每個 packet 呼叫 consumer 並回傳數量。
    ///
    /// # Errors
    ///
    /// Backend receive failure 時回傳 data-plane error。
    fn receive_burst(
        &mut self,
        consumer: impl FnMut(PacketView<'_>),
    ) -> Result<usize, NetToolError>;

    /// Source 是否已永久耗盡；live backend 維持預設 `false`。
    #[must_use]
    fn is_exhausted(&self) -> bool {
        false
    }
}

/// Worker 執行摘要。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkerRunResult {
    /// 完成的 burst 數。
    pub bursts: u64,
    /// Worker-local counters。
    pub statistics: WorkerStats,
    /// Analysis coverage，讓 consumer 不會把 sampled 當成完整分析。
    pub analysis_coverage: AnalysisCoverage,
}

/// Run-to-completion packet worker；flow table 與 counters 只由此 worker 修改。
pub struct PacketWorker {
    configuration: PacketWorkerConfiguration,
    flows: FlowTable<TcpFlowAnalyzer>,
    capture: Option<CaptureQueue>,
    filter: Option<PacketFilter>,
    statistics: WorkerStats,
    observed_packets: u64,
}

impl PacketWorker {
    /// 建立 worker-local analyzer。
    ///
    /// # Errors
    ///
    /// Configuration 無效時回傳錯誤。
    pub fn new(
        configuration: PacketWorkerConfiguration,
        capture: Option<CaptureQueue>,
    ) -> Result<Self, NetToolError> {
        configuration.validate()?;
        Ok(Self {
            flows: FlowTable::new(
                configuration.maximum_flows,
                configuration.flow_idle_timeout_nanoseconds,
            )?,
            configuration,
            capture,
            filter: None,
            statistics: WorkerStats::default(),
            observed_packets: 0,
        })
    }

    /// 建立帶 capture filter 的 packet worker。
    ///
    /// Filter 只限制分析與保存分支；`rx_packets`/`rx_bytes` 仍代表 backend 收到的總量。
    ///
    /// # Errors
    ///
    /// Configuration 無效時回傳錯誤。
    pub fn new_with_filter(
        configuration: PacketWorkerConfiguration,
        capture: Option<CaptureQueue>,
        filter: Option<PacketFilter>,
    ) -> Result<Self, NetToolError> {
        let mut worker = Self::new(configuration, capture)?;
        worker.filter = filter;
        Ok(worker)
    }

    /// 處理固定數量 bursts，適合 session budget 與 deterministic tests。
    ///
    /// # Errors
    ///
    /// Backend receive failure 時立即停止並回傳錯誤，不隱藏部分結果。
    pub fn run_bursts<S: BurstSource>(
        &mut self,
        source: &mut S,
        maximum_bursts: u64,
        stop: &StopToken,
    ) -> Result<WorkerRunResult, NetToolError> {
        let mut bursts = 0_u64;
        while bursts < maximum_bursts && !stop.is_stopped() {
            let received = source.receive_burst(|packet| self.process_packet(packet))?;
            bursts = bursts.saturating_add(1);
            if received == 0 && source.is_exhausted() {
                break;
            }
        }
        Ok(WorkerRunResult {
            bursts,
            statistics: self.statistics,
            analysis_coverage: self.configuration.analysis_coverage,
        })
    }

    /// 目前 worker-local statistics snapshot。
    #[must_use]
    pub const fn statistics(&self) -> WorkerStats {
        self.statistics
    }

    fn process_packet(&mut self, packet: PacketView<'_>) {
        self.statistics.record_packet(packet.wire_length);
        if self
            .filter
            .as_ref()
            .is_some_and(|filter| !filter.matches(packet))
        {
            return;
        }
        if let Some(capture) = &self.capture {
            capture.try_capture(packet, &mut self.statistics);
        }
        self.observed_packets = self.observed_packets.saturating_add(1);
        if !self.should_analyze() {
            self.statistics.sampled_out_packets =
                self.statistics.sampled_out_packets.saturating_add(1);
            return;
        }
        let Ok(parsed) = parse_packet(packet.bytes) else {
            self.statistics.parse_errors = self.statistics.parse_errors.saturating_add(1);
            return;
        };
        if let Some(ip) = parsed.ip {
            match ip.source {
                IpAddr::V4(_) => {
                    self.statistics.ipv4_packets = self.statistics.ipv4_packets.saturating_add(1);
                }
                IpAddr::V6(_) => {
                    self.statistics.ipv6_packets = self.statistics.ipv6_packets.saturating_add(1);
                }
            }
        }
        match parsed.transport {
            Some(TransportPacket::Tcp(segment)) => {
                self.statistics.tcp_packets = self.statistics.tcp_packets.saturating_add(1);
                let Some(ip) = parsed.ip else {
                    self.statistics.parse_errors = self.statistics.parse_errors.saturating_add(1);
                    return;
                };
                let (key, direction) = FlowKey::canonical(FlowTuple {
                    source_ip: ip.source,
                    destination_ip: ip.destination,
                    source_port: segment.source_port,
                    destination_port: segment.destination_port,
                    protocol: ip.protocol,
                });
                let _ = self.flows.get_or_insert_with(
                    key,
                    packet.timestamp_nanoseconds,
                    TcpFlowAnalyzer::default,
                );
                let capture_drops = self.statistics.drops.capture;
                let Some(flow) = self.flows.value_mut(&key) else {
                    self.statistics.drops.analyzer =
                        self.statistics.drops.analyzer.saturating_add(1);
                    return;
                };
                let analysis = flow.observe(
                    TcpObservation {
                        direction,
                        sequence: segment.sequence,
                        acknowledgement: segment.acknowledgement,
                        window: segment.window,
                        flags: segment.flags,
                        payload_length: u32::try_from(segment.payload.len()).unwrap_or(u32::MAX),
                    },
                    capture_drops,
                );
                if matches!(
                    analysis.classification,
                    TcpClassification::ObservedRetransmission
                        | TcpClassification::SuspectedRetransmission
                ) {
                    self.statistics.retransmissions =
                        self.statistics.retransmissions.saturating_add(1);
                }
                self.statistics.flows = u64::try_from(self.flows.len()).unwrap_or(u64::MAX);
            }
            Some(TransportPacket::Udp(_)) => {
                self.statistics.udp_packets = self.statistics.udp_packets.saturating_add(1);
            }
            Some(TransportPacket::Icmp(_) | TransportPacket::Icmpv6(_)) => {
                self.statistics.icmp_packets = self.statistics.icmp_packets.saturating_add(1);
            }
            Some(TransportPacket::Other { .. } | TransportPacket::Fragment) => {
                self.statistics.other_packets = self.statistics.other_packets.saturating_add(1);
            }
            None => {}
        }
    }

    fn should_analyze(&self) -> bool {
        match self.configuration.analysis_coverage {
            AnalysisCoverage::Full => true,
            AnalysisCoverage::Sampled { one_in } => {
                (self.observed_packets - 1) % u64::from(one_in) == 0
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AnalysisCoverage, BurstSource, PacketWorker, PacketWorkerConfiguration};
    use crate::{CaptureMode, CaptureQueue, PacketFilter, PacketView, StopToken};
    use nettool_error::NetToolError;

    struct FakeSource {
        packets: Vec<Vec<u8>>,
        timestamp: u64,
    }

    impl BurstSource for FakeSource {
        fn receive_burst(
            &mut self,
            mut consumer: impl FnMut(PacketView<'_>),
        ) -> Result<usize, NetToolError> {
            for packet in &self.packets {
                consumer(PacketView {
                    bytes: packet,
                    timestamp_nanoseconds: self.timestamp,
                    wire_length: u32::try_from(packet.len()).unwrap_or(u32::MAX),
                    queue_id: 0,
                });
                self.timestamp = self.timestamp.saturating_add(1);
            }
            Ok(self.packets.len())
        }
    }

    fn tcp_packet(sequence: u32, payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![0_u8; 14 + 20 + 20 + payload.len()];
        frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        frame[14] = 0x45;
        let ip_length = u16::try_from(40 + payload.len()).expect("test packet length");
        frame[16..18].copy_from_slice(&ip_length.to_be_bytes());
        frame[23] = 6;
        frame[26..30].copy_from_slice(&[192, 0, 2, 1]);
        frame[30..34].copy_from_slice(&[198, 51, 100, 1]);
        frame[34..36].copy_from_slice(&1234_u16.to_be_bytes());
        frame[36..38].copy_from_slice(&443_u16.to_be_bytes());
        frame[38..42].copy_from_slice(&sequence.to_be_bytes());
        frame[46] = 0x50;
        frame[47] = 0x18;
        frame[54..].copy_from_slice(payload);
        frame
    }

    fn configuration(coverage: AnalysisCoverage) -> PacketWorkerConfiguration {
        PacketWorkerConfiguration {
            maximum_flows: 16,
            flow_idle_timeout_nanoseconds: 1_000,
            analysis_coverage: coverage,
        }
    }

    #[test]
    fn worker_connects_parser_flow_and_tcp_retransmission_state() {
        let packet = tcp_packet(100, b"payload");
        let mut source = FakeSource {
            packets: vec![packet.clone(), packet],
            timestamp: 1,
        };
        let mut worker =
            PacketWorker::new(configuration(AnalysisCoverage::Full), None).expect("worker");
        let result = worker
            .run_bursts(&mut source, 1, &StopToken::new())
            .expect("run");
        assert_eq!(result.statistics.rx_packets, 2);
        assert_eq!(result.statistics.tcp_packets, 2);
        assert_eq!(result.statistics.ipv4_packets, 2);
        assert_eq!(result.statistics.ipv6_packets, 0);
        assert_eq!(result.statistics.flows, 1);
        assert_eq!(result.statistics.retransmissions, 1);
    }

    #[test]
    fn sampled_mode_is_explicit_and_counts_omitted_packets() {
        let packet = tcp_packet(100, b"payload");
        let mut source = FakeSource {
            packets: vec![packet.clone(), packet.clone(), packet],
            timestamp: 1,
        };
        let mut worker =
            PacketWorker::new(configuration(AnalysisCoverage::Sampled { one_in: 2 }), None)
                .expect("worker");
        let result = worker
            .run_bursts(&mut source, 1, &StopToken::new())
            .expect("run");
        assert!(result.analysis_coverage.is_sampled());
        assert_eq!(result.statistics.sampled_out_packets, 1);
        assert_eq!(result.statistics.tcp_packets, 2);
    }

    #[test]
    fn stop_is_checked_at_burst_boundary() {
        let mut source = FakeSource {
            packets: vec![tcp_packet(1, b"x")],
            timestamp: 1,
        };
        let mut worker =
            PacketWorker::new(configuration(AnalysisCoverage::Full), None).expect("worker");
        let stop = StopToken::new();
        stop.stop();
        let result = worker.run_bursts(&mut source, 10, &stop).expect("run");
        assert_eq!(result.bursts, 0);
        assert_eq!(result.statistics.rx_packets, 0);
    }

    #[test]
    fn capture_branch_remains_independent_when_analysis_rejects_packet() {
        let (capture, receiver) = CaptureQueue::bounded(1, CaptureMode::FullPacket).expect("queue");
        let mut source = FakeSource {
            packets: vec![vec![1, 2, 3]],
            timestamp: 7,
        };
        let mut worker = PacketWorker::new(configuration(AnalysisCoverage::Full), Some(capture))
            .expect("worker");
        let result = worker
            .run_bursts(&mut source, 1, &StopToken::new())
            .expect("run");
        assert_eq!(result.statistics.parse_errors, 1);
        assert_eq!(receiver.try_receive().expect("captured").bytes, [1, 2, 3]);
    }

    #[test]
    fn filter_restricts_analysis_but_not_backend_receive_counters() {
        let packet = tcp_packet(100, b"payload");
        let mut source = FakeSource {
            packets: vec![packet],
            timestamp: 1,
        };
        let mut worker = PacketWorker::new_with_filter(
            configuration(AnalysisCoverage::Full),
            None,
            Some(PacketFilter {
                protocol: Some(17),
                ..PacketFilter::default()
            }),
        )
        .expect("worker");
        let result = worker
            .run_bursts(&mut source, 1, &StopToken::new())
            .expect("run");
        assert_eq!(result.statistics.rx_packets, 1);
        assert_eq!(result.statistics.tcp_packets, 0);
    }
}

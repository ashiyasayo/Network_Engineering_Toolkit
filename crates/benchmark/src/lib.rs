//! 100GbE benchmark evidence、A–J gates 與平台組合認證。

#![forbid(unsafe_code)]

use nettool_error::{ErrorCode, NetToolError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;

mod runner;

pub use runner::{
    BENCHMARK_PHASE_EVIDENCE_LIMIT_BYTES, BenchmarkCancellationToken, BenchmarkIssue,
    BenchmarkIssueSeverity, BenchmarkPhaseRecord, BenchmarkProfileRegistry, BenchmarkRunReport,
    BenchmarkRunState, BenchmarkRunner, PhaseExecution, PhaseStatus, RegisteredBenchmarkProfile,
};

/// 規格固定 benchmark phase。
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BenchmarkPhase {
    /// Environment Check。
    EnvironmentCheck,
    /// NIC Baseline。
    NicBaseline,
    /// RX Baseline。
    RxBaseline,
    /// TX Baseline。
    TxBaseline,
    /// Bidirectional。
    Bidirectional,
    /// Packet Size Matrix。
    PacketSizeMatrix,
    /// Flow Matrix。
    FlowMatrix,
    /// Duration Test。
    DurationTest,
    /// Analysis Test。
    AnalysisTest,
    /// Result。
    Result,
}

/// 可重複執行的 benchmark 計畫。
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BenchmarkPlan {
    /// Profile ID。
    pub profile_id: String,
    /// Ethernet frame size matrix。
    pub frame_sizes_bytes: Vec<u32>,
    /// Flow cardinality matrix。
    pub flow_counts: Vec<u64>,
    /// Warmup 秒數。
    pub warmup_seconds: u64,
    /// 每階段 measurement 秒數。
    pub measurement_seconds: u64,
    /// Sustained test 秒數。
    pub sustained_seconds: u64,
}

impl BenchmarkPlan {
    /// 固定 phase 順序。
    #[must_use]
    pub const fn phases() -> [BenchmarkPhase; 10] {
        [
            BenchmarkPhase::EnvironmentCheck,
            BenchmarkPhase::NicBaseline,
            BenchmarkPhase::RxBaseline,
            BenchmarkPhase::TxBaseline,
            BenchmarkPhase::Bidirectional,
            BenchmarkPhase::PacketSizeMatrix,
            BenchmarkPhase::FlowMatrix,
            BenchmarkPhase::DurationTest,
            BenchmarkPhase::AnalysisTest,
            BenchmarkPhase::Result,
        ]
    }

    /// 驗證 packet/flow matrix 與時間設定。
    ///
    /// # Errors
    ///
    /// 缺少規格必要 frame size、flow cardinality 或 duration 時回傳錯誤。
    pub fn validate(&self) -> Result<(), NetToolError> {
        if self.profile_id.trim().is_empty() {
            return Err(invalid("benchmark profile ID is required"));
        }
        for required in [64, 128, 256, 512, 1024, 1518, 9018] {
            if !self.frame_sizes_bytes.contains(&required) {
                return Err(invalid(&format!(
                    "benchmark frame matrix is missing {required}B"
                )));
            }
        }
        for required in [1, 16, 256, 4096] {
            if !self.flow_counts.contains(&required) {
                return Err(invalid(&format!(
                    "benchmark flow matrix is missing {required} flows"
                )));
            }
        }
        if !self.flow_counts.iter().any(|count| *count >= 1_000_000) {
            return Err(invalid(
                "benchmark flow matrix requires a high-cardinality test",
            ));
        }
        if self.warmup_seconds == 0 || self.measurement_seconds == 0 || self.sustained_seconds == 0
        {
            return Err(invalid("benchmark durations must be non-zero"));
        }
        Ok(())
    }
}

/// Benchmark 前保存的完整環境快照。
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BenchmarkEnvironmentSnapshot {
    /// OS 與版本。
    pub os: Option<String>,
    /// Kernel/build。
    pub kernel: Option<String>,
    /// CPU model。
    pub cpu: Option<String>,
    /// CPU frequency description。
    pub cpu_frequency: Option<String>,
    /// NUMA topology/locality。
    pub numa: Option<String>,
    /// Memory topology/capacity。
    pub memory: Option<String>,
    /// Huge Page configuration。
    pub huge_pages: Option<String>,
    /// NIC model。
    pub nic: Option<String>,
    /// `PCIe` topology/link。
    pub pcie: Option<String>,
    /// NIC firmware。
    pub firmware: Option<String>,
    /// Driver 與版本。
    pub driver: Option<String>,
    /// DPDK 版本；非 DPDK backend 可填 `not_applicable`。
    pub dpdk_version: Option<String>,
    /// Backend 與版本。
    pub backend: Option<String>,
    /// MTU bytes。
    pub mtu: Option<u32>,
    /// RX queue count。
    pub rx_queues: Option<u32>,
    /// TX queue count。
    pub tx_queues: Option<u32>,
    /// RSS configuration。
    pub rss: Option<String>,
    /// Offload configuration。
    pub offloads: Option<String>,
}

impl BenchmarkEnvironmentSnapshot {
    /// 回傳缺少的規格欄位名稱。
    #[must_use]
    pub fn missing_fields(&self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        macro_rules! required {
            ($field:ident) => {
                if self
                    .$field
                    .as_ref()
                    .is_none_or(|value| value.trim().is_empty())
                {
                    missing.push(stringify!($field));
                }
            };
        }
        required!(os);
        required!(kernel);
        required!(cpu);
        required!(cpu_frequency);
        required!(numa);
        required!(memory);
        required!(huge_pages);
        required!(nic);
        required!(pcie);
        required!(firmware);
        required!(driver);
        required!(dpdk_version);
        required!(backend);
        required!(rss);
        required!(offloads);
        if self.mtu.is_none() {
            missing.push("mtu");
        }
        if self.rx_queues.is_none() {
            missing.push("rx_queues");
        }
        if self.tx_queues.is_none() {
            missing.push("tx_queues");
        }
        missing
    }

    /// 產生綁定完整平台組合的 SHA-256 certification key。
    ///
    /// # Errors
    ///
    /// 快照缺欄位或 queue/MTU 為零時回傳錯誤。
    pub fn certification_key(&self) -> Result<String, NetToolError> {
        let missing = self.missing_fields();
        if !missing.is_empty() {
            return Err(invalid(&format!(
                "benchmark environment is incomplete: {}",
                missing.join(",")
            )));
        }
        if self.mtu == Some(0) || self.rx_queues == Some(0) || self.tx_queues == Some(0) {
            return Err(invalid("MTU and queue counts must be non-zero"));
        }
        let mut digest = Sha256::new();
        for value in [
            self.os.as_deref(),
            self.kernel.as_deref(),
            self.cpu.as_deref(),
            self.cpu_frequency.as_deref(),
            self.numa.as_deref(),
            self.memory.as_deref(),
            self.huge_pages.as_deref(),
            self.nic.as_deref(),
            self.pcie.as_deref(),
            self.firmware.as_deref(),
            self.driver.as_deref(),
            self.dpdk_version.as_deref(),
            self.backend.as_deref(),
            self.rss.as_deref(),
            self.offloads.as_deref(),
        ] {
            hash_field(&mut digest, value.unwrap_or_default().as_bytes());
        }
        hash_field(&mut digest, &self.mtu.unwrap_or_default().to_be_bytes());
        hash_field(
            &mut digest,
            &self.rx_queues.unwrap_or_default().to_be_bytes(),
        );
        hash_field(
            &mut digest,
            &self.tx_queues.unwrap_or_default().to_be_bytes(),
        );
        let mut key = String::with_capacity(64);
        for byte in digest.finalize() {
            let _ = write!(key, "{byte:02x}");
        }
        Ok(key)
    }
}

/// 分類後的 benchmark drop evidence。
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BenchmarkDrops {
    /// NIC drops。
    pub nic: u64,
    /// Capture drops。
    pub capture: u64,
    /// Ring drops。
    pub ring: u64,
    /// Analyzer drops。
    pub analyzer: u64,
}

/// RX baseline 必須保存的量測。
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RxBaselineEvidence {
    /// RX bits per second。
    pub bits_per_second: u64,
    /// RX packets per second。
    pub packets_per_second: u64,
    /// NIC drops。
    pub nic_drops: u64,
    /// Application drops。
    pub application_drops: u64,
    /// Total CPU basis points。
    pub cpu_basis_points: u32,
}

/// TX baseline 必須保存的量測。
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TxBaselineEvidence {
    /// TX bits per second。
    pub bits_per_second: u64,
    /// TX packets per second。
    pub packets_per_second: u64,
    /// Total CPU basis points。
    pub cpu_basis_points: u32,
    /// TX errors。
    pub tx_errors: u64,
    /// Queue utilization basis points。
    pub queue_utilization_basis_points: u32,
}

/// CPU efficiency evidence。
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CpuEvidence {
    /// 系統 total CPU basis points。
    pub total_cpu_basis_points: u32,
    /// Data-plane core count。
    pub data_plane_cores: u32,
    /// 每 core throughput。
    pub bits_per_second_per_core: u64,
    /// 每 core packet rate。
    pub packets_per_second_per_core: u64,
}

/// Short/sustained stability evidence。
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StabilityEvidence {
    /// Short test duration。
    pub short_duration_seconds: u64,
    /// Sustained test duration。
    pub sustained_duration_seconds: u64,
    /// 每次重複測試的 throughput。
    pub repeated_throughput_bits_per_second: Vec<u64>,
}

/// Thermal evidence 與需保存的 certification condition。
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ThermalEvidence {
    /// 測試開始 CPU frequency description。
    pub cpu_frequency_start: String,
    /// 測試期間最低 CPU frequency description。
    pub cpu_frequency_minimum: String,
    /// NIC state/temperature description。
    pub nic_state: String,
    /// 是否觀察到 thermal throttling。
    pub thermal_throttling: bool,
}

/// Analysis-enabled 主要 frame load evidence。
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AnalyzerLoadEvidence {
    /// Ethernet frame bytes。
    pub frame_bytes: u32,
    /// 實際 throughput。
    pub throughput_bits_per_second: u64,
    /// Analyzer drops。
    pub analyzer_drops: u64,
}

/// A–J gates 所需的全部觀測證據。
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CertificationEvidence {
    /// 功能是否能完成一次測試。
    pub functional: bool,
    /// 是否完成一般效能驗證。
    pub general_validation_completed: bool,
    /// Negotiated link speed Mbps。
    pub link_speed_mbps: Option<u64>,
    /// NIC/CPU/memory NUMA locality 是否有效。
    pub numa_locality_valid: Option<bool>,
    /// RSS 是否 active。
    pub rss_active: Option<bool>,
    /// RX queue distribution 是否有效。
    pub rx_queue_distribution_valid: Option<bool>,
    /// RX baseline。
    pub rx_baseline: Option<RxBaselineEvidence>,
    /// TX baseline。
    pub tx_baseline: Option<TxBaselineEvidence>,
    /// 同步 bidirectional aggregate throughput。
    pub bidirectional_bits_per_second: Option<u64>,
    /// Drop evidence。
    pub drops: Option<BenchmarkDrops>,
    /// CPU evidence。
    pub cpu: Option<CpuEvidence>,
    /// Stability/reproducibility evidence。
    pub stability: Option<StabilityEvidence>,
    /// Thermal evidence。
    pub thermal: Option<ThermalEvidence>,
    /// Analysis-enabled frame matrix。
    pub analyzer_loads: Vec<AnalyzerLoadEvidence>,
}

/// 只有硬體 POC/正式 profile 能提供的 certification thresholds。
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CertificationPolicy {
    /// Gate D 最低 throughput。
    pub minimum_throughput_bits_per_second: u64,
    /// Gate E 各 drop 類別上限。
    pub maximum_drops: BenchmarkDrops,
    /// Gate G short test 最短秒數。
    pub minimum_short_duration_seconds: u64,
    /// Gate G sustained test 最短秒數。
    pub minimum_sustained_duration_seconds: u64,
    /// Gate J 最少重複次數。
    pub minimum_repetitions: u32,
    /// Gate J throughput max-min 相對最低值的最大 ppm。
    pub maximum_reproducibility_spread_ppm: u32,
    /// Gate I analysis-enabled 最低 throughput。
    pub minimum_analyzer_throughput_bits_per_second: u64,
    /// Gate I 每個主要負載 analyzer drop 上限。
    pub maximum_analyzer_drops: u64,
    /// 是否允許在明確保存 condition 後通過 thermal throttling。
    pub allow_thermal_throttling_condition: bool,
}

impl CertificationPolicy {
    /// 驗證所有門檻均由 profile 明確提供且在合理 domain。
    ///
    /// # Errors
    ///
    /// 必要門檻為零、repetition 少於二或 ppm 超過一百萬時回傳錯誤。
    pub fn validate(self) -> Result<(), NetToolError> {
        if self.minimum_throughput_bits_per_second == 0
            || self.minimum_short_duration_seconds == 0
            || self.minimum_sustained_duration_seconds == 0
            || self.minimum_analyzer_throughput_bits_per_second == 0
        {
            return Err(invalid("certification thresholds must be non-zero"));
        }
        if self.minimum_repetitions < 2 {
            return Err(invalid("certification requires at least two repetitions"));
        }
        if self.maximum_reproducibility_spread_ppm > 1_000_000 {
            return Err(invalid("reproducibility spread ppm exceeds one million"));
        }
        Ok(())
    }
}

/// 固定 A–J gate ID。
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum CertificationGate {
    /// Link。
    A,
    /// NUMA。
    B,
    /// Queue/RSS。
    C,
    /// Throughput。
    D,
    /// Drops。
    E,
    /// CPU evidence。
    F,
    /// Stability duration。
    G,
    /// Thermal condition。
    H,
    /// Analyzer loads。
    I,
    /// Reproducibility。
    J,
}

/// 單一 gate 狀態。
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GateStatus {
    /// 證據通過門檻。
    Pass,
    /// 證據明確失敗。
    Fail,
    /// 缺證據或尚無 POC policy，不能判定。
    NotEvaluated,
    /// 通過與否由 policy 決定、且 condition 必須保存。
    Condition,
}

/// Gate 判定與可呈現理由。
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GateEvaluation {
    /// Gate ID。
    pub gate: CertificationGate,
    /// 判定狀態。
    pub status: GateStatus,
    /// 不含敏感資料的理由。
    pub reason: String,
}

/// 對外支援等級。
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SupportLevel {
    /// 功能可執行，不代表 100G。
    Functional,
    /// 完成一般效能驗證。
    Validated,
    /// 指定平台組合通過完整 A–J gates。
    Certified100G,
}

/// 完整 certification 判定結果。
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CertificationOutcome {
    /// 不可執行時為 `None`。
    pub support_level: Option<SupportLevel>,
    /// 平台組合 key；環境不完整時為 `None`。
    pub certification_key: Option<String>,
    /// 十個 gate，順序固定 A–J。
    pub gates: Vec<GateEvaluation>,
    /// 必須保存的 thermal conditions。
    pub conditions: Vec<String>,
}

/// 評估支援等級與全部 certification gates。
///
/// `policy=None` 代表 POC 尚未固定門檻；此時 throughput/stability/analyzer/reproducibility
/// 必須維持 `NotEvaluated`，最高只能是 `Validated`。
///
/// # Errors
///
/// Caller 提供的 policy 無效時明確回傳錯誤，不將它當成未設定。
pub fn evaluate_certification(
    environment: &BenchmarkEnvironmentSnapshot,
    evidence: &CertificationEvidence,
    policy: Option<CertificationPolicy>,
) -> Result<CertificationOutcome, NetToolError> {
    if let Some(value) = policy {
        value.validate()?;
    }
    let mut conditions = Vec::new();
    let gates = vec![
        gate_a(evidence),
        gate_b(evidence),
        gate_c(evidence),
        gate_d(evidence, policy),
        gate_e(evidence, policy),
        gate_f(evidence),
        gate_g(evidence, policy),
        gate_h(evidence, policy, &mut conditions),
        gate_i(evidence, policy),
        gate_j(evidence, policy),
    ];
    let certification_key = environment.certification_key().ok();
    let all_pass = gates.iter().all(|gate| gate.status == GateStatus::Pass)
        && certification_key.is_some()
        && policy.is_some();
    let support_level = if !evidence.functional {
        None
    } else if all_pass {
        Some(SupportLevel::Certified100G)
    } else if evidence.general_validation_completed {
        Some(SupportLevel::Validated)
    } else {
        Some(SupportLevel::Functional)
    };
    Ok(CertificationOutcome {
        support_level,
        certification_key,
        gates,
        conditions,
    })
}

fn gate_a(evidence: &CertificationEvidence) -> GateEvaluation {
    boolean_measurement(
        CertificationGate::A,
        evidence.link_speed_mbps.map(|speed| speed >= 100_000),
        "100GbE link is negotiated",
        "negotiated link is below 100GbE",
    )
}

fn gate_b(evidence: &CertificationEvidence) -> GateEvaluation {
    boolean_measurement(
        CertificationGate::B,
        evidence.numa_locality_valid,
        "NIC, CPU and memory locality are valid",
        "NUMA locality is invalid",
    )
}

fn gate_c(evidence: &CertificationEvidence) -> GateEvaluation {
    let value = evidence
        .rss_active
        .zip(evidence.rx_queue_distribution_valid)
        .map(|(rss, distribution)| rss && distribution);
    boolean_measurement(
        CertificationGate::C,
        value,
        "RSS and RX queue distribution are valid",
        "RSS or RX queue distribution is invalid",
    )
}

fn gate_d(evidence: &CertificationEvidence, policy: Option<CertificationPolicy>) -> GateEvaluation {
    let measurement = evidence
        .rx_baseline
        .zip(evidence.tx_baseline)
        .zip(evidence.bidirectional_bits_per_second)
        .and_then(|((rx, tx), bidirectional)| {
            if rx.bits_per_second == 0
                || rx.packets_per_second == 0
                || rx.cpu_basis_points > 10_000
                || tx.bits_per_second == 0
                || tx.packets_per_second == 0
                || tx.cpu_basis_points > 10_000
                || tx.queue_utilization_basis_points > 10_000
                || bidirectional == 0
            {
                None
            } else {
                Some(
                    rx.bits_per_second
                        .min(tx.bits_per_second)
                        .min(bidirectional),
                )
            }
        });
    threshold_gate(
        CertificationGate::D,
        measurement,
        policy.map(|value| value.minimum_throughput_bits_per_second),
        "throughput meets the POC-defined threshold",
        "throughput is below the POC-defined threshold",
    )
}

fn gate_e(evidence: &CertificationEvidence, policy: Option<CertificationPolicy>) -> GateEvaluation {
    let Some(policy) = policy else {
        return not_evaluated(CertificationGate::E, "drop thresholds are not configured");
    };
    let Some(drops) = evidence.drops else {
        return not_evaluated(CertificationGate::E, "drop evidence is missing");
    };
    let passed = drops.nic <= policy.maximum_drops.nic
        && drops.capture <= policy.maximum_drops.capture
        && drops.ring <= policy.maximum_drops.ring
        && drops.analyzer <= policy.maximum_drops.analyzer;
    evaluated(
        CertificationGate::E,
        passed,
        "all classified drops meet thresholds",
        "one or more classified drops exceed thresholds",
    )
}

fn gate_f(evidence: &CertificationEvidence) -> GateEvaluation {
    let value = evidence.cpu.map(|cpu| {
        cpu.total_cpu_basis_points <= 10_000
            && cpu.data_plane_cores > 0
            && cpu.bits_per_second_per_core > 0
            && cpu.packets_per_second_per_core > 0
    });
    boolean_measurement(
        CertificationGate::F,
        value,
        "CPU and per-core efficiency evidence is complete",
        "CPU evidence is invalid",
    )
}

fn gate_g(evidence: &CertificationEvidence, policy: Option<CertificationPolicy>) -> GateEvaluation {
    let Some(policy) = policy else {
        return not_evaluated(
            CertificationGate::G,
            "stability durations are not configured",
        );
    };
    let Some(stability) = &evidence.stability else {
        return not_evaluated(CertificationGate::G, "stability evidence is missing");
    };
    evaluated(
        CertificationGate::G,
        stability.short_duration_seconds >= policy.minimum_short_duration_seconds
            && stability.sustained_duration_seconds >= policy.minimum_sustained_duration_seconds,
        "short and sustained tests meet configured durations",
        "short or sustained test duration is insufficient",
    )
}

fn gate_h(
    evidence: &CertificationEvidence,
    policy: Option<CertificationPolicy>,
    conditions: &mut Vec<String>,
) -> GateEvaluation {
    let Some(thermal) = &evidence.thermal else {
        return not_evaluated(CertificationGate::H, "thermal evidence is missing");
    };
    if thermal.cpu_frequency_start.trim().is_empty()
        || thermal.cpu_frequency_minimum.trim().is_empty()
        || thermal.nic_state.trim().is_empty()
    {
        return evaluated(
            CertificationGate::H,
            false,
            "thermal evidence is complete",
            "thermal evidence is incomplete",
        );
    }
    if !thermal.thermal_throttling {
        return evaluated(
            CertificationGate::H,
            true,
            "no thermal throttling was observed",
            "",
        );
    }
    conditions.push("thermal_throttling_observed".to_owned());
    match policy {
        Some(value) if value.allow_thermal_throttling_condition => GateEvaluation {
            gate: CertificationGate::H,
            status: GateStatus::Pass,
            reason: "thermal throttling condition was explicitly allowed and preserved".to_owned(),
        },
        Some(_) => GateEvaluation {
            gate: CertificationGate::H,
            status: GateStatus::Fail,
            reason: "thermal throttling is not allowed by the certification policy".to_owned(),
        },
        None => GateEvaluation {
            gate: CertificationGate::H,
            status: GateStatus::Condition,
            reason: "thermal throttling condition requires an explicit policy".to_owned(),
        },
    }
}

fn gate_i(evidence: &CertificationEvidence, policy: Option<CertificationPolicy>) -> GateEvaluation {
    let Some(policy) = policy else {
        return not_evaluated(
            CertificationGate::I,
            "analyzer thresholds are not configured",
        );
    };
    let load_64 = evidence
        .analyzer_loads
        .iter()
        .find(|load| load.frame_bytes == 64);
    let load_1518 = evidence
        .analyzer_loads
        .iter()
        .find(|load| load.frame_bytes == 1518);
    let Some((small, standard)) = load_64.zip(load_1518) else {
        return not_evaluated(
            CertificationGate::I,
            "analysis-enabled 64B and 1518B loads are both required",
        );
    };
    let passed = [small, standard].iter().all(|load| {
        load.throughput_bits_per_second >= policy.minimum_analyzer_throughput_bits_per_second
            && load.analyzer_drops <= policy.maximum_analyzer_drops
    });
    evaluated(
        CertificationGate::I,
        passed,
        "64B and 1518B analyzer loads meet thresholds",
        "analyzer throughput or drops fail a primary load",
    )
}

fn gate_j(evidence: &CertificationEvidence, policy: Option<CertificationPolicy>) -> GateEvaluation {
    let Some(policy) = policy else {
        return not_evaluated(
            CertificationGate::J,
            "reproducibility thresholds are not configured",
        );
    };
    let Some(stability) = &evidence.stability else {
        return not_evaluated(CertificationGate::J, "repeated measurements are missing");
    };
    if stability.repeated_throughput_bits_per_second.len()
        < usize::try_from(policy.minimum_repetitions).unwrap_or(usize::MAX)
    {
        return evaluated(
            CertificationGate::J,
            false,
            "repetition count is sufficient",
            "repetition count is insufficient",
        );
    }
    let Some(minimum) = stability
        .repeated_throughput_bits_per_second
        .iter()
        .min()
        .copied()
    else {
        return not_evaluated(CertificationGate::J, "repeated measurements are missing");
    };
    let maximum = stability
        .repeated_throughput_bits_per_second
        .iter()
        .max()
        .copied()
        .unwrap_or(minimum);
    if minimum == 0 {
        return evaluated(
            CertificationGate::J,
            false,
            "throughput measurements are non-zero",
            "a repeated throughput measurement is zero",
        );
    }
    let spread_ppm = u128::from(maximum - minimum).saturating_mul(1_000_000) / u128::from(minimum);
    evaluated(
        CertificationGate::J,
        spread_ppm <= u128::from(policy.maximum_reproducibility_spread_ppm),
        "repeated results meet dispersion threshold",
        "repeated results are unstable",
    )
}

fn threshold_gate(
    gate: CertificationGate,
    measurement: Option<u64>,
    threshold: Option<u64>,
    passed: &str,
    failed: &str,
) -> GateEvaluation {
    match (measurement, threshold) {
        (Some(value), Some(minimum)) => evaluated(gate, value >= minimum, passed, failed),
        (_, None) => not_evaluated(gate, "POC-defined threshold is not configured"),
        (None, Some(_)) => not_evaluated(gate, "measurement evidence is missing"),
    }
}

fn boolean_measurement(
    gate: CertificationGate,
    value: Option<bool>,
    passed: &str,
    failed: &str,
) -> GateEvaluation {
    value.map_or_else(
        || not_evaluated(gate, "measurement evidence is missing"),
        |value| evaluated(gate, value, passed, failed),
    )
}

fn evaluated(
    gate: CertificationGate,
    passed: bool,
    pass_reason: &str,
    fail_reason: &str,
) -> GateEvaluation {
    GateEvaluation {
        gate,
        status: if passed {
            GateStatus::Pass
        } else {
            GateStatus::Fail
        },
        reason: if passed { pass_reason } else { fail_reason }.to_owned(),
    }
}

fn not_evaluated(gate: CertificationGate, reason: &str) -> GateEvaluation {
    GateEvaluation {
        gate,
        status: GateStatus::NotEvaluated,
        reason: reason.to_owned(),
    }
}

fn hash_field(digest: &mut Sha256, value: &[u8]) {
    digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(value);
}

fn invalid(message: &str) -> NetToolError {
    NetToolError::new(ErrorCode::InvalidArgument, message, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_poc_policy_never_claims_certified() {
        let outcome = evaluate_certification(&environment(), &evidence(), None).expect("outcome");
        assert_eq!(outcome.support_level, Some(SupportLevel::Validated));
        assert!(
            outcome
                .gates
                .iter()
                .any(|gate| gate.status == GateStatus::NotEvaluated)
        );
    }

    #[test]
    fn complete_evidence_and_explicit_policy_can_certify() {
        let outcome =
            evaluate_certification(&environment(), &evidence(), Some(policy())).expect("outcome");
        assert_eq!(outcome.support_level, Some(SupportLevel::Certified100G));
        assert_eq!(outcome.gates.len(), 10);
        assert!(
            outcome
                .gates
                .iter()
                .all(|gate| gate.status == GateStatus::Pass)
        );
        assert_eq!(outcome.certification_key.as_deref().map(str::len), Some(64));
    }

    #[test]
    fn one_drop_category_failure_blocks_certification() {
        let mut value = evidence();
        value.drops = Some(BenchmarkDrops {
            nic: 0,
            capture: 1,
            ring: 0,
            analyzer: 0,
        });
        let outcome =
            evaluate_certification(&environment(), &value, Some(policy())).expect("outcome");
        assert_eq!(outcome.support_level, Some(SupportLevel::Validated));
        assert_eq!(outcome.gates[4].status, GateStatus::Fail);
    }

    #[test]
    fn certification_key_changes_with_platform_component() {
        let first = environment().certification_key().expect("key");
        let mut changed = environment();
        changed.driver = Some("driver-2".to_owned());
        assert_ne!(first, changed.certification_key().expect("changed key"));
    }

    #[test]
    fn thermal_condition_is_preserved_and_policy_controlled() {
        let mut value = evidence();
        value.thermal.as_mut().expect("thermal").thermal_throttling = true;
        let outcome =
            evaluate_certification(&environment(), &value, Some(policy())).expect("outcome");
        assert_eq!(outcome.gates[7].status, GateStatus::Fail);
        assert_eq!(outcome.conditions, ["thermal_throttling_observed"]);
    }

    #[test]
    fn invalid_policy_is_not_silently_treated_as_missing() {
        let mut invalid_policy = policy();
        invalid_policy.minimum_repetitions = 1;
        assert!(evaluate_certification(&environment(), &evidence(), Some(invalid_policy)).is_err());
    }

    #[test]
    fn benchmark_plan_requires_small_standard_jumbo_and_high_cardinality() {
        let mut plan = BenchmarkPlan {
            profile_id: "100g-cert".to_owned(),
            frame_sizes_bytes: vec![64, 128, 256, 512, 1024, 1518, 9018],
            flow_counts: vec![1, 16, 256, 4096, 1_000_000],
            warmup_seconds: 10,
            measurement_seconds: 60,
            sustained_seconds: 3600,
        };
        plan.validate().expect("complete plan");
        assert_eq!(BenchmarkPlan::phases().len(), 10);
        plan.frame_sizes_bytes.retain(|size| *size != 64);
        assert!(plan.validate().is_err());
    }

    fn environment() -> BenchmarkEnvironmentSnapshot {
        BenchmarkEnvironmentSnapshot {
            os: Some("linux".to_owned()),
            kernel: Some("6.x".to_owned()),
            cpu: Some("cpu".to_owned()),
            cpu_frequency: Some("3GHz".to_owned()),
            numa: Some("node0".to_owned()),
            memory: Some("128GiB".to_owned()),
            huge_pages: Some("1GiB x 8".to_owned()),
            nic: Some("100GbE NIC".to_owned()),
            pcie: Some("Gen4 x16".to_owned()),
            firmware: Some("1.0".to_owned()),
            driver: Some("driver-1".to_owned()),
            dpdk_version: Some("24.11".to_owned()),
            backend: Some("dpdk".to_owned()),
            mtu: Some(1500),
            rx_queues: Some(4),
            tx_queues: Some(4),
            rss: Some("enabled".to_owned()),
            offloads: Some("none".to_owned()),
        }
    }

    fn evidence() -> CertificationEvidence {
        CertificationEvidence {
            functional: true,
            general_validation_completed: true,
            link_speed_mbps: Some(100_000),
            numa_locality_valid: Some(true),
            rss_active: Some(true),
            rx_queue_distribution_valid: Some(true),
            rx_baseline: Some(RxBaselineEvidence {
                bits_per_second: 95_000_000_000,
                packets_per_second: 10_000_000,
                nic_drops: 0,
                application_drops: 0,
                cpu_basis_points: 7000,
            }),
            tx_baseline: Some(TxBaselineEvidence {
                bits_per_second: 95_000_000_000,
                packets_per_second: 10_000_000,
                cpu_basis_points: 7000,
                tx_errors: 0,
                queue_utilization_basis_points: 8000,
            }),
            bidirectional_bits_per_second: Some(95_000_000_000),
            drops: Some(BenchmarkDrops {
                nic: 0,
                capture: 0,
                ring: 0,
                analyzer: 0,
            }),
            cpu: Some(CpuEvidence {
                total_cpu_basis_points: 8000,
                data_plane_cores: 4,
                bits_per_second_per_core: 25_000_000_000,
                packets_per_second_per_core: 10_000_000,
            }),
            stability: Some(StabilityEvidence {
                short_duration_seconds: 60,
                sustained_duration_seconds: 3600,
                repeated_throughput_bits_per_second: vec![
                    95_000_000_000,
                    95_100_000_000,
                    95_050_000_000,
                ],
            }),
            thermal: Some(ThermalEvidence {
                cpu_frequency_start: "3GHz".to_owned(),
                cpu_frequency_minimum: "3GHz".to_owned(),
                nic_state: "normal".to_owned(),
                thermal_throttling: false,
            }),
            analyzer_loads: vec![
                AnalyzerLoadEvidence {
                    frame_bytes: 64,
                    throughput_bits_per_second: 90_000_000_000,
                    analyzer_drops: 0,
                },
                AnalyzerLoadEvidence {
                    frame_bytes: 1518,
                    throughput_bits_per_second: 90_000_000_000,
                    analyzer_drops: 0,
                },
            ],
        }
    }

    fn policy() -> CertificationPolicy {
        CertificationPolicy {
            minimum_throughput_bits_per_second: 90_000_000_000,
            maximum_drops: BenchmarkDrops {
                nic: 0,
                capture: 0,
                ring: 0,
                analyzer: 0,
            },
            minimum_short_duration_seconds: 60,
            minimum_sustained_duration_seconds: 3600,
            minimum_repetitions: 3,
            maximum_reproducibility_spread_ppm: 2_000,
            minimum_analyzer_throughput_bits_per_second: 80_000_000_000,
            maximum_analyzer_drops: 0,
            allow_thermal_throttling_condition: false,
        }
    }
}

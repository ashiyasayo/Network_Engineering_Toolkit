//! Benchmark profile registry 與 deterministic phase orchestration。

use crate::{BenchmarkPhase, BenchmarkPlan, CertificationPolicy};
use nettool_error::{ErrorCode, NetToolError};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

/// 單一 phase evidence JSON 上限，避免 executor 塞入 packet payload 或無界資料。
pub const BENCHMARK_PHASE_EVIDENCE_LIMIT_BYTES: usize = 1024 * 1024;

/// Data-plane/benchmark issue 嚴重度。
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BenchmarkIssueSeverity {
    /// 暫時性問題，記錄 counter 後可繼續。
    Recoverable,
    /// 測試可繼續，但結果必須降級。
    Degraded,
    /// Backend/session 已不可用，停止後續 phases。
    Fatal,
}

/// Phase 執行時的結構化 issue。
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BenchmarkIssue {
    /// Stable machine-readable code。
    pub code: String,
    /// 嚴重度。
    pub severity: BenchmarkIssueSeverity,
    /// 不含敏感資料的說明。
    pub message: String,
}

/// Executor 回傳的 bounded phase evidence。
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct PhaseExecution {
    /// Phase-specific structured evidence。
    pub evidence: Value,
    /// Recoverable/degraded/fatal issues。
    pub issues: Vec<BenchmarkIssue>,
}

impl PhaseExecution {
    /// 建立無 issue 的 phase output。
    #[must_use]
    pub const fn successful(evidence: Value) -> Self {
        Self {
            evidence,
            issues: Vec::new(),
        }
    }

    fn validate(&self) -> Result<(), NetToolError> {
        let encoded = serde_json::to_vec(&self.evidence).map_err(|error| {
            NetToolError::new(
                ErrorCode::ProtocolInvalid,
                format!("benchmark phase evidence cannot be encoded: {error}"),
                false,
            )
        })?;
        if encoded.len() > BENCHMARK_PHASE_EVIDENCE_LIMIT_BYTES {
            return Err(NetToolError::new(
                ErrorCode::ControlFrameTooLarge,
                "benchmark phase evidence exceeds 1 MiB",
                false,
            ));
        }
        for issue in &self.issues {
            if issue.code.trim().is_empty() || issue.code.len() > 128 || issue.message.len() > 4096
            {
                return Err(NetToolError::new(
                    ErrorCode::ProtocolInvalid,
                    "benchmark issue code or message is invalid",
                    false,
                ));
            }
        }
        Ok(())
    }
}

/// 單一 phase 的 terminal 狀態。
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PhaseStatus {
    /// Phase 完成且沒有 fatal issue。
    Completed,
    /// Phase 執行失敗。
    Failed,
    /// 因 cancel/failure 未執行。
    Skipped,
}

/// Phase timing、evidence 與 issue record。
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct BenchmarkPhaseRecord {
    /// 固定 phase ID。
    pub phase: BenchmarkPhase,
    /// Terminal state。
    pub status: PhaseStatus,
    /// Local monotonic 起點；skipped 為 `None`。
    pub started_monotonic_nanoseconds: Option<u64>,
    /// Local monotonic 終點；skipped 為 `None`。
    pub ended_monotonic_nanoseconds: Option<u64>,
    /// Bounded evidence；未執行/失敗可為 `None`。
    pub evidence: Option<Value>,
    /// Phase issues。
    pub issues: Vec<BenchmarkIssue>,
    /// Executor error code。
    pub error_code: Option<String>,
    /// Executor error message。
    pub error_message: Option<String>,
}

/// Benchmark run terminal state。
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BenchmarkRunState {
    /// 所有 phases 完成且沒有 degraded issue。
    Completed,
    /// 所有必要 phases 完成，但至少有 degraded issue。
    CompletedDegraded,
    /// 使用者要求取消。
    Canceled,
    /// Executor error 或 fatal issue。
    Failed,
}

/// 完整 phase runner report。
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct BenchmarkRunReport {
    /// Profile ID。
    pub profile_id: String,
    /// Terminal state。
    pub state: BenchmarkRunState,
    /// 固定十個 phase records，包含 skipped phases。
    pub phases: Vec<BenchmarkPhaseRecord>,
}

/// Thread-safe cooperative cancellation token。
#[derive(Clone, Debug, Default)]
pub struct BenchmarkCancellationToken {
    canceled: Arc<AtomicBool>,
}

impl BenchmarkCancellationToken {
    /// 建立 token。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 要求在 phase boundary 取消。
    pub fn cancel(&self) {
        self.canceled.store(true, Ordering::Release);
    }

    /// 是否已取消。
    #[must_use]
    pub fn is_canceled(&self) -> bool {
        self.canceled.load(Ordering::Acquire)
    }
}

/// 單次使用的 benchmark runner。
pub struct BenchmarkRunner {
    plan: BenchmarkPlan,
    cancellation: BenchmarkCancellationToken,
    consumed: bool,
}

impl BenchmarkRunner {
    /// 建立並驗證 plan。
    ///
    /// # Errors
    ///
    /// Plan 缺少規格必要 matrix/duration 時回傳錯誤。
    pub fn new(
        plan: BenchmarkPlan,
        cancellation: BenchmarkCancellationToken,
    ) -> Result<Self, NetToolError> {
        plan.validate()?;
        Ok(Self {
            plan,
            cancellation,
            consumed: false,
        })
    }

    /// 依固定順序執行 phases；取消只在 phase boundary 生效。
    ///
    /// `monotonic_now` 必須由同一 local monotonic clock domain 提供。Runner 不自行等待，
    /// duration、hardware I/O 與 phase evidence 由 executor 負責。
    ///
    /// # Errors
    ///
    /// Runner 重複使用或 monotonic clock 倒退時回傳錯誤。Executor error 會被保存於
    /// report 並以 `BenchmarkRunState::Failed` 正常回傳。
    pub fn run(
        &mut self,
        mut execute: impl FnMut(BenchmarkPhase, &BenchmarkPlan) -> Result<PhaseExecution, NetToolError>,
        mut monotonic_now: impl FnMut() -> u64,
    ) -> Result<BenchmarkRunReport, NetToolError> {
        if self.consumed {
            return Err(NetToolError::new(
                ErrorCode::InvalidState,
                "benchmark runner can only execute once",
                false,
            ));
        }
        self.consumed = true;
        let phases = BenchmarkPlan::phases();
        let mut records = Vec::with_capacity(phases.len());
        let mut state = BenchmarkRunState::Completed;
        for (index, phase) in phases.into_iter().enumerate() {
            if self.cancellation.is_canceled() {
                state = BenchmarkRunState::Canceled;
                append_skipped(&mut records, &BenchmarkPlan::phases()[index..]);
                break;
            }
            let started = monotonic_now();
            let execution = execute(phase, &self.plan);
            let ended = monotonic_now();
            if ended < started {
                return Err(NetToolError::new(
                    ErrorCode::InvalidState,
                    "benchmark monotonic clock moved backwards",
                    false,
                ));
            }
            match execution {
                Ok(execution) => {
                    if let Err(error) = execution.validate() {
                        records.push(failed_record(phase, started, ended, &error));
                        append_skipped(&mut records, &BenchmarkPlan::phases()[index + 1..]);
                        state = BenchmarkRunState::Failed;
                        break;
                    }
                    let fatal = execution
                        .issues
                        .iter()
                        .any(|issue| issue.severity == BenchmarkIssueSeverity::Fatal);
                    let degraded = execution
                        .issues
                        .iter()
                        .any(|issue| issue.severity == BenchmarkIssueSeverity::Degraded);
                    records.push(BenchmarkPhaseRecord {
                        phase,
                        status: if fatal {
                            PhaseStatus::Failed
                        } else {
                            PhaseStatus::Completed
                        },
                        started_monotonic_nanoseconds: Some(started),
                        ended_monotonic_nanoseconds: Some(ended),
                        evidence: Some(execution.evidence),
                        issues: execution.issues,
                        error_code: None,
                        error_message: None,
                    });
                    if fatal {
                        append_skipped(&mut records, &BenchmarkPlan::phases()[index + 1..]);
                        state = BenchmarkRunState::Failed;
                        break;
                    }
                    if degraded {
                        state = BenchmarkRunState::CompletedDegraded;
                    }
                }
                Err(error) => {
                    records.push(failed_record(phase, started, ended, &error));
                    append_skipped(&mut records, &BenchmarkPlan::phases()[index + 1..]);
                    state = BenchmarkRunState::Failed;
                    break;
                }
            }
            if self.cancellation.is_canceled() {
                append_skipped(&mut records, &BenchmarkPlan::phases()[index + 1..]);
                state = BenchmarkRunState::Canceled;
                break;
            }
        }
        Ok(BenchmarkRunReport {
            profile_id: self.plan.profile_id.clone(),
            state,
            phases: records,
        })
    }
}

/// Registry 中的 plan 與可選 POC policy。
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisteredBenchmarkProfile {
    /// Benchmark plan。
    pub plan: BenchmarkPlan,
    /// 經 POC 固定後才能設定；內建 profile 目前為 `None`。
    pub certification_policy: Option<CertificationPolicy>,
}

/// Built-in benchmark profile registry。
pub struct BenchmarkProfileRegistry;

impl BenchmarkProfileRegistry {
    /// Stable built-in profile IDs。
    #[must_use]
    pub const fn ids() -> [&'static str; 2] {
        ["functional-default", "100g-cert"]
    }

    /// 取得 profile。`100g-cert` 目前只有完整 plan，policy 刻意為 `None`；
    /// 在硬體 POC 固定門檻前不能產生 Certified outcome。
    #[must_use]
    pub fn get(id: &str) -> Option<RegisteredBenchmarkProfile> {
        let (warmup_seconds, measurement_seconds, sustained_seconds) = match id {
            "functional-default" => (5, 10, 60),
            "100g-cert" => (10, 60, 3600),
            _ => return None,
        };
        Some(RegisteredBenchmarkProfile {
            plan: BenchmarkPlan {
                profile_id: id.to_owned(),
                frame_sizes_bytes: vec![64, 128, 256, 512, 1024, 1518, 9018],
                flow_counts: vec![1, 16, 256, 4096, 1_000_000],
                warmup_seconds,
                measurement_seconds,
                sustained_seconds,
            },
            certification_policy: None,
        })
    }
}

fn failed_record(
    phase: BenchmarkPhase,
    started: u64,
    ended: u64,
    error: &NetToolError,
) -> BenchmarkPhaseRecord {
    BenchmarkPhaseRecord {
        phase,
        status: PhaseStatus::Failed,
        started_monotonic_nanoseconds: Some(started),
        ended_monotonic_nanoseconds: Some(ended),
        evidence: None,
        issues: Vec::new(),
        error_code: Some(error.code.as_str().to_owned()),
        error_message: Some(error.message.clone()),
    }
}

fn append_skipped(records: &mut Vec<BenchmarkPhaseRecord>, phases: &[BenchmarkPhase]) {
    records.extend(phases.iter().map(|phase| BenchmarkPhaseRecord {
        phase: *phase,
        status: PhaseStatus::Skipped,
        started_monotonic_nanoseconds: None,
        ended_monotonic_nanoseconds: None,
        evidence: None,
        issues: Vec::new(),
        error_code: None,
        error_message: None,
    }));
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn runs_all_phases_in_fixed_order_and_is_single_use() {
        let profile = BenchmarkProfileRegistry::get("functional-default").expect("profile");
        let mut runner =
            BenchmarkRunner::new(profile.plan, BenchmarkCancellationToken::new()).expect("runner");
        let mut now = 0;
        let report = runner
            .run(
                |phase, _| Ok(PhaseExecution::successful(json!({"phase":phase}))),
                || {
                    now += 1;
                    now
                },
            )
            .expect("report");
        assert_eq!(report.state, BenchmarkRunState::Completed);
        assert_eq!(report.phases.len(), 10);
        assert_eq!(report.phases[0].phase, BenchmarkPhase::EnvironmentCheck);
        assert_eq!(report.phases[9].phase, BenchmarkPhase::Result);
        assert!(runner.run(|_, _| unreachable!(), || 0).is_err());
    }

    #[test]
    fn cancel_at_boundary_preserves_completed_and_skips_remaining() {
        let token = BenchmarkCancellationToken::new();
        let callback_token = token.clone();
        let profile = BenchmarkProfileRegistry::get("functional-default").expect("profile");
        let mut runner = BenchmarkRunner::new(profile.plan, token).expect("runner");
        let report = runner
            .run(
                |phase, _| {
                    if phase == BenchmarkPhase::RxBaseline {
                        callback_token.cancel();
                    }
                    Ok(PhaseExecution::successful(json!({})))
                },
                || 1,
            )
            .expect("report");
        assert_eq!(report.state, BenchmarkRunState::Canceled);
        assert_eq!(report.phases[2].status, PhaseStatus::Completed);
        assert!(
            report.phases[3..]
                .iter()
                .all(|phase| phase.status == PhaseStatus::Skipped)
        );
    }

    #[test]
    fn fatal_issue_stops_run_while_degraded_issue_only_marks_report() {
        let profile = BenchmarkProfileRegistry::get("functional-default").expect("profile");
        let mut fatal_runner =
            BenchmarkRunner::new(profile.plan.clone(), BenchmarkCancellationToken::new())
                .expect("runner");
        let fatal = fatal_runner
            .run(
                |phase, _| {
                    Ok(PhaseExecution {
                        evidence: json!({}),
                        issues: if phase == BenchmarkPhase::TxBaseline {
                            vec![issue(BenchmarkIssueSeverity::Fatal)]
                        } else {
                            Vec::new()
                        },
                    })
                },
                || 1,
            )
            .expect("fatal report");
        assert_eq!(fatal.state, BenchmarkRunState::Failed);
        assert_eq!(fatal.phases[3].status, PhaseStatus::Failed);

        let mut degraded_runner =
            BenchmarkRunner::new(profile.plan, BenchmarkCancellationToken::new()).expect("runner");
        let degraded = degraded_runner
            .run(
                |phase, _| {
                    Ok(PhaseExecution {
                        evidence: json!({}),
                        issues: if phase == BenchmarkPhase::AnalysisTest {
                            vec![issue(BenchmarkIssueSeverity::Degraded)]
                        } else {
                            Vec::new()
                        },
                    })
                },
                || 1,
            )
            .expect("degraded report");
        assert_eq!(degraded.state, BenchmarkRunState::CompletedDegraded);
    }

    #[test]
    fn builtin_cert_profile_has_no_invented_policy() {
        let profile = BenchmarkProfileRegistry::get("100g-cert").expect("profile");
        profile.plan.validate().expect("plan");
        assert_eq!(profile.certification_policy, None);
    }

    fn issue(severity: BenchmarkIssueSeverity) -> BenchmarkIssue {
        BenchmarkIssue {
            code: "TEST.ISSUE".to_owned(),
            severity,
            message: "test issue".to_owned(),
        }
    }
}

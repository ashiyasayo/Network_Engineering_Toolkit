//! Speed test lifecycle、雙端 barrier 與 monotonic measurement window。

use nettool_error::{ErrorCode, NetToolError};
use serde::{Deserialize, Serialize};

/// Speed test lifecycle phase。
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SpeedTestPhase {
    /// 正在協商 protocol 與 capability。
    Negotiate,
    /// 正在配置 socket、buffer 與資源。
    Prepare,
    /// 雙端已完成 prepare，等待排定時間。
    Ready,
    /// 暖機流量，不計入主要 throughput。
    Warmup,
    /// 正式 measurement window。
    Measure,
    /// 測量後的冷卻階段。
    Cooldown,
    /// 正在合併雙端結果。
    Finalize,
    /// 已產生最終結果。
    Result,
    /// 不可恢復失敗。
    Failed,
}

/// Barrier 的參與端。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BarrierPeer {
    /// 本機 test engine。
    Local,
    /// 遠端 test engine。
    Remote,
}

/// Measurement window，以 local monotonic clock 計算。
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MeasurementWindow {
    /// 本機 monotonic 起點，單位 nanoseconds。
    pub started_monotonic_nanoseconds: u64,
    /// 本機 monotonic 終點，單位 nanoseconds。
    pub ended_monotonic_nanoseconds: u64,
    /// 經過時間；不使用 wall clock 差值。
    pub elapsed_nanoseconds: u64,
}

/// 單一 speed test 的 lifecycle authority。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpeedTestLifecycle {
    phase: SpeedTestPhase,
    local_ready: bool,
    remote_ready: bool,
    start_at_unix_nanoseconds: Option<u64>,
    measurement_started_monotonic_nanoseconds: Option<u64>,
    measurement_window: Option<MeasurementWindow>,
}

impl Default for SpeedTestLifecycle {
    fn default() -> Self {
        Self::new()
    }
}

impl SpeedTestLifecycle {
    /// 建立位於 NEGOTIATE 的 lifecycle。
    #[must_use]
    pub const fn new() -> Self {
        Self {
            phase: SpeedTestPhase::Negotiate,
            local_ready: false,
            remote_ready: false,
            start_at_unix_nanoseconds: None,
            measurement_started_monotonic_nanoseconds: None,
            measurement_window: None,
        }
    }

    /// 目前 phase。
    #[must_use]
    pub const fn phase(&self) -> SpeedTestPhase {
        self.phase
    }

    /// 已協商完成並進入 PREPARE。
    ///
    /// # Errors
    ///
    /// 不在 NEGOTIATE 時回傳 `ACTION.INVALID_STATE`。
    pub fn negotiated(&mut self) -> Result<(), NetToolError> {
        self.transition(SpeedTestPhase::Negotiate, SpeedTestPhase::Prepare)
    }

    /// 標記一端已完成 prepare；只有雙端皆 ready 才進入 READY。
    ///
    /// 重複的相同 ready 訊息為冪等成功。
    ///
    /// # Errors
    ///
    /// 不在 PREPARE/READY 時回傳錯誤。
    pub fn mark_ready(&mut self, peer: BarrierPeer) -> Result<bool, NetToolError> {
        if !matches!(self.phase, SpeedTestPhase::Prepare | SpeedTestPhase::Ready) {
            return Err(invalid_state("readiness is only valid during prepare"));
        }
        match peer {
            BarrierPeer::Local => self.local_ready = true,
            BarrierPeer::Remote => self.remote_ready = true,
        }
        if self.local_ready && self.remote_ready {
            self.phase = SpeedTestPhase::Ready;
        }
        Ok(self.phase == SpeedTestPhase::Ready)
    }

    /// 由 control plane 設定共同 `start_at` wall-clock timestamp。
    ///
    /// Wall clock 只負責協調開始，不用來計算 throughput duration。
    ///
    /// # Errors
    ///
    /// Barrier 未完成或開始時間早於目前時間時回傳錯誤。
    pub fn schedule_start(
        &mut self,
        start_at_unix_nanoseconds: u64,
        now_unix_nanoseconds: u64,
    ) -> Result<(), NetToolError> {
        if self.phase != SpeedTestPhase::Ready {
            return Err(invalid_state(
                "both peers must be ready before scheduling start",
            ));
        }
        if start_at_unix_nanoseconds == 0 {
            return Err(invalid_argument("start_at must be non-zero"));
        }
        if start_at_unix_nanoseconds < now_unix_nanoseconds {
            return Err(invalid_argument("start_at cannot be in the past"));
        }
        if let Some(existing) = self.start_at_unix_nanoseconds {
            return if existing == start_at_unix_nanoseconds {
                Ok(())
            } else {
                Err(invalid_state("start_at is already scheduled"))
            };
        }
        self.start_at_unix_nanoseconds = Some(start_at_unix_nanoseconds);
        Ok(())
    }

    /// 到達排定時間後進入 WARMUP。
    ///
    /// # Errors
    ///
    /// 未排程、barrier 未完成或時間尚未到達時回傳錯誤。
    pub fn begin_warmup(&mut self, now_unix_nanoseconds: u64) -> Result<(), NetToolError> {
        if self.phase != SpeedTestPhase::Ready {
            return Err(invalid_state("session is not ready for warmup"));
        }
        let start_at = self
            .start_at_unix_nanoseconds
            .ok_or_else(|| invalid_state("start_at has not been scheduled"))?;
        if now_unix_nanoseconds < start_at {
            return Err(invalid_state("scheduled start time has not arrived"));
        }
        self.phase = SpeedTestPhase::Warmup;
        Ok(())
    }

    /// 以 local monotonic timestamp 開始正式測量。
    ///
    /// # Errors
    ///
    /// 不在 WARMUP 或重複開始時回傳錯誤。
    pub fn begin_measurement(
        &mut self,
        now_monotonic_nanoseconds: u64,
    ) -> Result<(), NetToolError> {
        if self.phase != SpeedTestPhase::Warmup {
            return Err(invalid_state("measurement can only begin after warmup"));
        }
        self.measurement_started_monotonic_nanoseconds = Some(now_monotonic_nanoseconds);
        self.phase = SpeedTestPhase::Measure;
        Ok(())
    }

    /// 結束正式測量並進入 COOLDOWN。
    ///
    /// # Errors
    ///
    /// 不在 MEASURE 或 monotonic clock 倒退時回傳錯誤。
    pub fn end_measurement(
        &mut self,
        now_monotonic_nanoseconds: u64,
    ) -> Result<MeasurementWindow, NetToolError> {
        if self.phase != SpeedTestPhase::Measure {
            return Err(invalid_state("measurement is not running"));
        }
        let started = self
            .measurement_started_monotonic_nanoseconds
            .ok_or_else(|| invalid_state("measurement start is missing"))?;
        let elapsed = now_monotonic_nanoseconds
            .checked_sub(started)
            .ok_or_else(|| invalid_state("monotonic clock moved backwards"))?;
        if elapsed == 0 {
            return Err(invalid_argument(
                "measurement duration must be greater than zero",
            ));
        }
        let window = MeasurementWindow {
            started_monotonic_nanoseconds: started,
            ended_monotonic_nanoseconds: now_monotonic_nanoseconds,
            elapsed_nanoseconds: elapsed,
        };
        self.measurement_window = Some(window);
        self.phase = SpeedTestPhase::Cooldown;
        Ok(window)
    }

    /// 完成 cooldown 並進入 FINALIZE。
    ///
    /// # Errors
    ///
    /// 不在 COOLDOWN 時回傳錯誤。
    pub fn finish_cooldown(&mut self) -> Result<(), NetToolError> {
        self.transition(SpeedTestPhase::Cooldown, SpeedTestPhase::Finalize)
    }

    /// 確認雙端資料已合併並產生 RESULT。
    ///
    /// # Errors
    ///
    /// 不在 FINALIZE 或 measurement window 遺失時回傳錯誤。
    pub fn finish(&mut self) -> Result<MeasurementWindow, NetToolError> {
        if self.phase != SpeedTestPhase::Finalize {
            return Err(invalid_state("session is not finalizing"));
        }
        let window = self
            .measurement_window
            .ok_or_else(|| invalid_state("measurement window is missing"))?;
        self.phase = SpeedTestPhase::Result;
        Ok(window)
    }

    /// 將任何尚未完成的 session 標記為失敗。
    ///
    /// # Errors
    ///
    /// RESULT 或 FAILED 已是 terminal state，不可再變更。
    pub fn fail(&mut self) -> Result<(), NetToolError> {
        if matches!(self.phase, SpeedTestPhase::Result | SpeedTestPhase::Failed) {
            return Err(invalid_state("terminal session state cannot change"));
        }
        self.phase = SpeedTestPhase::Failed;
        Ok(())
    }

    fn transition(
        &mut self,
        expected: SpeedTestPhase,
        next: SpeedTestPhase,
    ) -> Result<(), NetToolError> {
        if self.phase != expected {
            return Err(invalid_state("speed test phase transition is invalid"));
        }
        self.phase = next;
        Ok(())
    }
}

fn invalid_argument(message: &str) -> NetToolError {
    NetToolError::new(ErrorCode::InvalidArgument, message, false)
}

fn invalid_state(message: &str) -> NetToolError {
    NetToolError::new(ErrorCode::InvalidState, message, false)
}

#[cfg(test)]
mod tests {
    use super::{BarrierPeer, SpeedTestLifecycle, SpeedTestPhase};

    #[test]
    fn requires_both_peers_before_scheduling_start() {
        let mut lifecycle = SpeedTestLifecycle::new();
        lifecycle.negotiated().expect("negotiation");
        assert!(!lifecycle.mark_ready(BarrierPeer::Local).expect("local"));
        assert!(lifecycle.schedule_start(200, 100).is_err());
        assert!(lifecycle.mark_ready(BarrierPeer::Remote).expect("remote"));
        lifecycle.schedule_start(200, 100).expect("schedule");
        assert!(lifecycle.begin_warmup(199).is_err());
        lifecycle.begin_warmup(200).expect("warmup");
    }

    #[test]
    fn measurement_duration_uses_monotonic_timestamps() {
        let mut lifecycle = ready_lifecycle();
        lifecycle.schedule_start(1_000, 900).expect("schedule");
        lifecycle.begin_warmup(1_000).expect("warmup");
        lifecycle.begin_measurement(50_000).expect("measurement");
        let window = lifecycle.end_measurement(80_000).expect("end");
        assert_eq!(window.elapsed_nanoseconds, 30_000);
        lifecycle.finish_cooldown().expect("cooldown");
        assert_eq!(lifecycle.finish().expect("result"), window);
        assert_eq!(lifecycle.phase(), SpeedTestPhase::Result);
    }

    #[test]
    fn rejects_skipped_phases_and_monotonic_clock_regression() {
        let mut lifecycle = SpeedTestLifecycle::new();
        assert!(lifecycle.begin_measurement(1).is_err());
        lifecycle.negotiated().expect("negotiation");
        lifecycle.mark_ready(BarrierPeer::Local).expect("local");
        lifecycle.mark_ready(BarrierPeer::Remote).expect("remote");
        lifecycle.schedule_start(10, 10).expect("schedule");
        lifecycle.begin_warmup(10).expect("warmup");
        lifecycle.begin_measurement(100).expect("measurement");
        assert!(lifecycle.end_measurement(99).is_err());
        assert_eq!(lifecycle.phase(), SpeedTestPhase::Measure);
    }

    #[test]
    fn ready_and_schedule_messages_are_idempotent_but_not_mutable() {
        let mut lifecycle = ready_lifecycle();
        assert!(lifecycle.mark_ready(BarrierPeer::Remote).expect("repeat"));
        assert!(lifecycle.schedule_start(0, 0).is_err());
        lifecycle.schedule_start(500, 100).expect("schedule");
        lifecycle.schedule_start(500, 200).expect("repeat");
        assert!(lifecycle.schedule_start(600, 200).is_err());
    }

    fn ready_lifecycle() -> SpeedTestLifecycle {
        let mut lifecycle = SpeedTestLifecycle::new();
        lifecycle.negotiated().expect("negotiation");
        lifecycle.mark_ready(BarrierPeer::Remote).expect("remote");
        lifecycle.mark_ready(BarrierPeer::Local).expect("local");
        lifecycle
    }
}

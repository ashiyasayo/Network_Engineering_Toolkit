//! Node control connection 與 test session state machine。

use nettool_error::{ErrorCode, NetToolError};
use serde::{Deserialize, Serialize};

/// Node control/session states。
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NodeConnectionState {
    /// 尚未連線。
    Disconnected,
    /// TCP 正在連線。
    Connecting,
    /// 正在進行 TLS 1.3 handshake。
    TlsHandshake,
    /// 正在交換 Hello。
    Hello,
    /// 正在驗證 persistent identity。
    Authenticating,
    /// 正在交換 capability。
    CapabilityNegotiation,
    /// Control connection 可接受命令。
    Ready,
    /// 正在驗證並預約測試資源。
    Preparing,
    /// 兩端資料平面已就緒。
    TestReady,
    /// 測試執行中。
    Running,
    /// 正在彙整最終結果。
    Finalizing,
    /// 測試完成。
    Completed,
    /// 連線或測試失敗。
    Failed,
    /// 測試已取消。
    Canceled,
}

/// 強制執行合法轉移的 state machine。
pub struct NodeStateMachine {
    state: NodeConnectionState,
}

impl NodeStateMachine {
    /// 建立 disconnected machine。
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: NodeConnectionState::Disconnected,
        }
    }
    /// 回傳目前狀態。
    #[must_use]
    pub const fn state(&self) -> NodeConnectionState {
        self.state
    }
    /// 執行一個合法狀態轉移。
    ///
    /// # Errors
    ///
    /// 轉移不在固定 state graph 中時回傳 `INVALID_SESSION_STATE`。
    pub fn transition(&mut self, next: NodeConnectionState) -> Result<(), NetToolError> {
        if !allowed(self.state, next) {
            return Err(NetToolError::new(
                ErrorCode::InvalidState,
                format!(
                    "invalid node state transition: {:?} -> {next:?}",
                    self.state
                ),
                false,
            ));
        }
        self.state = next;
        Ok(())
    }
}

impl Default for NodeStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

fn allowed(current: NodeConnectionState, next: NodeConnectionState) -> bool {
    use NodeConnectionState::{
        Authenticating, Canceled, CapabilityNegotiation, Completed, Connecting, Disconnected,
        Failed, Finalizing, Hello, Preparing, Ready, Running, TestReady, TlsHandshake,
    };
    match current {
        Disconnected => next == Connecting,
        Connecting => matches!(next, TlsHandshake | Failed),
        TlsHandshake => matches!(next, Hello | Failed),
        Hello => matches!(next, Authenticating | Failed),
        Authenticating => matches!(next, CapabilityNegotiation | Failed),
        CapabilityNegotiation => matches!(next, Ready | Failed),
        Ready => matches!(next, Preparing | Failed),
        Preparing => matches!(next, TestReady | Failed | Canceled),
        TestReady => matches!(next, Running | Failed | Canceled),
        Running => matches!(next, Finalizing | Failed | Canceled),
        Finalizing => matches!(next, Completed | Failed | Canceled),
        Completed => next == Ready,
        Failed | Canceled => next == Disconnected,
    }
}

#[cfg(test)]
mod tests {
    use super::{NodeConnectionState, NodeStateMachine};

    #[test]
    fn accepts_complete_happy_path() {
        let mut machine = NodeStateMachine::new();
        for state in [
            NodeConnectionState::Connecting,
            NodeConnectionState::TlsHandshake,
            NodeConnectionState::Hello,
            NodeConnectionState::Authenticating,
            NodeConnectionState::CapabilityNegotiation,
            NodeConnectionState::Ready,
            NodeConnectionState::Preparing,
            NodeConnectionState::TestReady,
            NodeConnectionState::Running,
            NodeConnectionState::Finalizing,
            NodeConnectionState::Completed,
        ] {
            machine.transition(state).expect("transition is legal");
        }
    }
    #[test]
    fn rejects_ready_to_finalizing() {
        let mut machine = NodeStateMachine {
            state: NodeConnectionState::Ready,
        };
        assert!(machine.transition(NodeConnectionState::Finalizing).is_err());
        assert_eq!(machine.state(), NodeConnectionState::Ready);
    }
}

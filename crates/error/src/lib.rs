//! `NetTool` 穩定錯誤模型。

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{Display, Formatter};

/// 可供 CLI 與協定穩定判斷的錯誤代碼。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorCode {
    /// 使用者輸入無效。
    InvalidArgument,
    /// 探測外部系統資源失敗。
    ProbeFailed,
    /// 功能在目前平台不可用。
    Unsupported,
    /// `SQLite` metadata 操作失敗。
    StorageFailed,
    /// Agent IPC 或 protocol 操作失敗。
    AgentUnavailable,
    /// Action 不存在或尚未實作。
    ActionUnsupported,
    /// 獨占資源已由其他 operation 使用。
    ResourceConflict,
    /// Operation 不符合目前狀態。
    InvalidState,
    /// Safe Apply rollback 失敗。
    RollbackFailed,
    /// Helper-owned state 或 audit 無法持久化。
    PersistenceFailed,
    /// Socket speed engine 執行失敗。
    SpeedFailed,
    /// Binary 或 control protocol 資料無效。
    ProtocolInvalid,
    /// Control frame 大於協定安全上限。
    ControlFrameTooLarge,
    /// Frame flags 不受目前版本支援。
    ProtocolUnsupportedFlag,
    /// Node protocol 版本或能力不相容。
    ProtocolIncompatible,
    /// Node control stream I/O 失敗。
    NodeTransportFailed,
    /// Node TLS 1.3 設定或 handshake 失敗。
    NodeTlsFailed,
    /// 指定的 Node 尚未配對或已撤銷信任。
    NodeNotPaired,
    /// Session-scoped data-plane authorization 已逾期。
    AuthorizationExpired,
    /// Data-plane session、stream、endpoint 或 authorization tag 驗證失敗。
    DataPlaneUnauthorized,
    /// Operation ID 被不同 request 重複使用。
    OperationConflict,
    /// Cryptographically secure random source 失敗。
    RandomFailed,
    /// Data-plane preflight 含必要 failure。
    PreflightFailed,
    /// Build 未連結要求的 backend。
    BackendNotBuilt,
    /// Storage benchmark 無法認證 lossless full capture。
    LosslessCaptureNotCertified,
    /// Privileged Helper caller 未通過 peer authorization。
    HelperUnauthorized,
    /// Privileged Helper transport 尚未設定。
    HelperNotConfigured,
    /// Privileged Helper local transport 失敗。
    HelperTransportFailed,
    /// Privileged Helper 平台操作失敗。
    HelperExecutionFailed,
    /// Capture file format 或結構無效。
    CaptureFormatInvalid,
    /// Capture file I/O 失敗。
    CaptureReadFailed,
}

impl ErrorCode {
    /// 回傳穩定的機器可讀識別字。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgument => "CLI.INVALID_ARGUMENT",
            Self::ProbeFailed => "DATAPLANE.PROBE_FAILED",
            Self::Unsupported => "PLATFORM.UNSUPPORTED",
            Self::StorageFailed => "STORAGE.DATABASE_FAILED",
            Self::AgentUnavailable => "AGENT.UNAVAILABLE",
            Self::ActionUnsupported => "ACTION.UNSUPPORTED",
            Self::ResourceConflict => "RESOURCE.CONFLICT",
            Self::InvalidState => "ACTION.INVALID_STATE",
            Self::RollbackFailed => "SAFE_APPLY.ROLLBACK_FAILED",
            Self::PersistenceFailed => "HELPER.PERSISTENCE_FAILED",
            Self::SpeedFailed => "SPEED.ENGINE_FAILED",
            Self::ProtocolInvalid => "PROTOCOL.INVALID_MESSAGE",
            Self::ControlFrameTooLarge => "PROTOCOL.CONTROL_FRAME_TOO_LARGE",
            Self::ProtocolUnsupportedFlag => "PROTOCOL.UNSUPPORTED_FLAG",
            Self::ProtocolIncompatible => "PROTOCOL.MAJOR_INCOMPATIBLE",
            Self::NodeTransportFailed => "NODE.TRANSPORT_FAILED",
            Self::NodeTlsFailed => "NODE.TLS_FAILED",
            Self::NodeNotPaired => "NODE.NOT_PAIRED",
            Self::AuthorizationExpired => "NODE.AUTHORIZATION_EXPIRED",
            Self::DataPlaneUnauthorized => "NODE.DATA_PLANE_UNAUTHORIZED",
            Self::OperationConflict => "OPERATION.ID_CONFLICT",
            Self::RandomFailed => "SECURITY.RANDOM_FAILED",
            Self::PreflightFailed => "DATAPLANE.PREFLIGHT_FAILED",
            Self::BackendNotBuilt => "DATAPLANE.BACKEND_NOT_BUILT",
            Self::LosslessCaptureNotCertified => "LOSSLESS_CAPTURE_NOT_CERTIFIED",
            Self::HelperUnauthorized => "HELPER.UNAUTHORIZED",
            Self::HelperNotConfigured => "HELPER.NOT_CONFIGURED",
            Self::HelperTransportFailed => "HELPER.TRANSPORT_FAILED",
            Self::HelperExecutionFailed => "HELPER.EXECUTION_FAILED",
            Self::CaptureFormatInvalid => "CAPTURE.FORMAT_INVALID",
            Self::CaptureReadFailed => "CAPTURE.READ_FAILED",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ErrorCode;

    #[test]
    fn helper_not_configured_code_is_stable() {
        assert_eq!(
            ErrorCode::HelperNotConfigured.as_str(),
            "HELPER.NOT_CONFIGURED"
        );
    }
}

/// 核心共用錯誤，避免以顯示文字作為機器端判斷依據。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetToolError {
    /// 穩定錯誤代碼。
    pub code: ErrorCode,
    /// 給人閱讀的錯誤訊息。
    pub message: String,
    /// 呼叫端稍後重試是否可能成功。
    pub retryable: bool,
    /// 不含敏感資訊的結構化細節。
    pub details: BTreeMap<String, String>,
}

impl NetToolError {
    /// 建立不含額外細節的錯誤。
    #[must_use]
    pub fn new(code: ErrorCode, message: impl Into<String>, retryable: bool) -> Self {
        Self {
            code,
            message: message.into(),
            retryable,
            details: BTreeMap::new(),
        }
    }
}

impl Display for NetToolError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code.as_str(), self.message)
    }
}

impl Error for NetToolError {}

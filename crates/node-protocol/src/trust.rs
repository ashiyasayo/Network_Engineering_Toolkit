//! Node fingerprint 與 persistent trust decision。

use sha2::{Digest, Sha256};

/// 連線 identity 相對於既有 trust record 的判斷。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustDecision {
    /// 尚無紀錄，必須由使用者 pairing confirmation。
    PairingRequired,
    /// Fingerprint 與 trusted record 相同。
    Trusted,
    /// 相同 Node ID 的 public key 已改變，必須拒絕並重新 pairing。
    IdentityChanged,
}

/// 計算完整 SHA-256 colon-separated fingerprint。
#[must_use]
pub fn fingerprint_sha256(public_key_der: &[u8]) -> String {
    Sha256::digest(public_key_der)
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// 對照 persistent fingerprint，不允許 silent trust migration。
#[must_use]
pub fn verify_identity(
    stored_fingerprint: Option<&str>,
    presented_fingerprint: &str,
) -> TrustDecision {
    match stored_fingerprint {
        None => TrustDecision::PairingRequired,
        Some(stored) if stored.eq_ignore_ascii_case(presented_fingerprint) => {
            TrustDecision::Trusted
        }
        Some(_) => TrustDecision::IdentityChanged,
    }
}

#[cfg(test)]
mod tests {
    use super::{TrustDecision, fingerprint_sha256, verify_identity};
    #[test]
    fn identity_change_is_never_silently_accepted() {
        assert_eq!(
            verify_identity(Some("AA:BB"), "AA:CC"),
            TrustDecision::IdentityChanged
        );
    }
    #[test]
    fn fingerprint_is_full_sha256() {
        assert_eq!(fingerprint_sha256(b"public key").split(':').count(), 32);
    }
}

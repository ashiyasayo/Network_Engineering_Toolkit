use nettool_error::{ErrorCode, NetToolError};

/// Data-plane authorization tag 最大 UTF-8 bytes。
pub const MAX_AUTHORIZATION_TAG_BYTES: usize = 256;
/// Data-plane authorization tag 最小 bytes，避免低熵或空 token。
pub const MIN_AUTHORIZATION_TAG_BYTES: usize = 16;

/// 驗證 session-scoped bearer tag 的固定資源界線。
///
/// # Errors
///
/// Tag 太短、太長或含控制字元時回傳錯誤。
pub fn validate_authorization_tag(tag: &str) -> Result<(), NetToolError> {
    if !(MIN_AUTHORIZATION_TAG_BYTES..=MAX_AUTHORIZATION_TAG_BYTES).contains(&tag.len()) {
        return Err(invalid(
            "authorization tag length is outside the secure range",
        ));
    }
    if tag.chars().any(char::is_control) {
        return Err(invalid("authorization tag contains control characters"));
    }
    Ok(())
}

/// 以不依內容提前結束的方式比對兩個相同長度的 authorization tags。
#[must_use]
pub fn authorization_tag_matches(expected: &str, presented: &[u8]) -> bool {
    let expected = expected.as_bytes();
    if expected.len() != presented.len() {
        return false;
    }
    expected
        .iter()
        .zip(presented)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn invalid(message: &'static str) -> NetToolError {
    NetToolError::new(ErrorCode::InvalidArgument, message, false)
}

#[cfg(test)]
mod tests {
    use super::{authorization_tag_matches, validate_authorization_tag};

    #[test]
    fn validates_bounds_and_exact_bytes() {
        let tag = "0123456789abcdef";
        validate_authorization_tag(tag).expect("valid");
        assert!(authorization_tag_matches(tag, tag.as_bytes()));
        assert!(!authorization_tag_matches(tag, b"0123456789abcdeg"));
        assert!(!authorization_tag_matches(tag, b"short"));
        assert!(validate_authorization_tag("short").is_err());
    }
}

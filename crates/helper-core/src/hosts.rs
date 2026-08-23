//! Hosts managed section 的解析與無損取代。

use nettool_error::{ErrorCode, NetToolError};
use std::net::IpAddr;

/// 已驗證的 managed hosts entry。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedHostsEntry {
    /// IP address。
    pub address: IpAddr,
    /// Hostname。
    pub hostname: String,
    /// 不含換行的註解。
    pub comment: Option<String>,
    /// 是否輸出為有效 hosts mapping。
    pub enabled: bool,
}

/// 取代指定 profile 的 managed section，完整保留區塊外內容。
///
/// Section 不存在時附加於檔尾；重複 marker、缺少 end marker 或巢狀 marker
/// 會拒絕修改，避免在不明 ownership 狀態下破壞使用者內容。
///
/// # Errors
///
/// Profile ID、entry 或既有 marker 結構無效時回傳錯誤。
pub fn replace_managed_section(
    existing: &str,
    profile_id: &str,
    entries: &[ManagedHostsEntry],
) -> Result<String, NetToolError> {
    validate_profile_id(profile_id)?;
    for entry in entries {
        validate_entry(entry)?;
    }
    let begin = format!("# BEGIN NETTOOL PROFILE {profile_id}");
    let end = format!("# END NETTOOL PROFILE {profile_id}");
    let newline = if existing.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let lines = existing.lines().collect::<Vec<_>>();
    let begin_positions = lines
        .iter()
        .enumerate()
        .filter_map(|(index, line)| (line.trim() == begin).then_some(index))
        .collect::<Vec<_>>();
    let end_positions = lines
        .iter()
        .enumerate()
        .filter_map(|(index, line)| (line.trim() == end).then_some(index))
        .collect::<Vec<_>>();
    if begin_positions.len() > 1
        || end_positions.len() > 1
        || begin_positions.len() != end_positions.len()
    {
        return Err(hosts_error(
            "managed hosts markers are missing or duplicated",
        ));
    }
    let managed = render_section(&begin, &end, entries, newline);
    if begin_positions.is_empty() {
        let mut result = existing.to_owned();
        if !result.is_empty() && !result.ends_with(['\n', '\r']) {
            result.push_str(newline);
        }
        if !result.is_empty() && !result.ends_with(&format!("{newline}{newline}")) {
            result.push_str(newline);
        }
        result.push_str(&managed);
        return Ok(result);
    }
    let start = begin_positions[0];
    let finish = end_positions[0];
    if finish < start
        || lines[start + 1..finish]
            .iter()
            .any(|line| line.trim().starts_with("# BEGIN NETTOOL PROFILE "))
    {
        return Err(hosts_error(
            "managed hosts markers are nested or out of order",
        ));
    }
    let mut output = Vec::new();
    output.extend_from_slice(&lines[..start]);
    output.extend(managed.trim_end_matches(['\r', '\n']).split(newline));
    output.extend_from_slice(&lines[finish + 1..]);
    let mut result = output.join(newline);
    if existing.ends_with('\n') {
        result.push_str(newline);
    }
    Ok(result)
}

fn render_section(begin: &str, end: &str, entries: &[ManagedHostsEntry], newline: &str) -> String {
    let mut lines = Vec::with_capacity(entries.len() + 2);
    lines.push(begin.to_owned());
    for entry in entries {
        let comment = entry
            .comment
            .as_ref()
            .map_or_else(String::new, |comment| format!(" # {comment}"));
        if entry.enabled {
            lines.push(format!("{} {}{}", entry.address, entry.hostname, comment));
        } else {
            lines.push(format!(
                "# NETTOOL DISABLED {} {}{}",
                entry.address, entry.hostname, comment
            ));
        }
    }
    lines.push(end.to_owned());
    format!("{}{newline}", lines.join(newline))
}

fn validate_profile_id(profile_id: &str) -> Result<(), NetToolError> {
    if profile_id.is_empty()
        || !profile_id
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
    {
        Err(hosts_error(
            "hosts profile ID contains unsupported characters",
        ))
    } else {
        Ok(())
    }
}

fn validate_entry(entry: &ManagedHostsEntry) -> Result<(), NetToolError> {
    if entry.hostname.is_empty()
        || entry.hostname.len() > 253
        || !entry.hostname.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '.' | '_')
        })
    {
        return Err(hosts_error("hosts entry hostname is invalid"));
    }
    if entry
        .comment
        .as_ref()
        .is_some_and(|comment| comment.contains(['\r', '\n']))
    {
        return Err(hosts_error("hosts entry comment contains a newline"));
    }
    Ok(())
}

fn hosts_error(message: &str) -> NetToolError {
    NetToolError::new(ErrorCode::InvalidArgument, message, false)
}

#[cfg(test)]
mod tests {
    use super::{ManagedHostsEntry, replace_managed_section};
    use std::net::{IpAddr, Ipv4Addr};

    fn entry(hostname: &str) -> ManagedHostsEntry {
        ManagedHostsEntry {
            address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            hostname: hostname.to_owned(),
            comment: None,
            enabled: true,
        }
    }

    #[test]
    fn preserves_all_unmanaged_content() {
        let existing = "127.0.0.1 localhost\n# user entry\n203.0.113.2 custom.local\n";
        let updated =
            replace_managed_section(existing, "lab", &[entry("api.lab")]).expect("valid update");
        assert!(updated.starts_with(existing));
        assert!(
            updated.contains(
                "# BEGIN NETTOOL PROFILE lab\n192.0.2.1 api.lab\n# END NETTOOL PROFILE lab"
            )
        );
    }

    #[test]
    fn replaces_only_matching_managed_section() {
        let existing = "before\n# BEGIN NETTOOL PROFILE lab\n192.0.2.9 old.lab\n# END NETTOOL PROFILE lab\nafter\n";
        let updated =
            replace_managed_section(existing, "lab", &[entry("new.lab")]).expect("valid update");
        assert_eq!(
            updated,
            "before\n# BEGIN NETTOOL PROFILE lab\n192.0.2.1 new.lab\n# END NETTOOL PROFILE lab\nafter\n"
        );
    }

    #[test]
    fn renders_disabled_entry_without_enabling_resolution() {
        let existing = "# BEGIN NETTOOL PROFILE lab\n# END NETTOOL PROFILE lab\n";
        let mut disabled = entry("offline.lab");
        disabled.enabled = false;
        let updated = replace_managed_section(existing, "lab", &[disabled]).expect("valid update");
        assert!(updated.contains("# NETTOOL DISABLED 192.0.2.1 offline.lab"));
    }

    #[test]
    fn rejects_unbalanced_markers() {
        assert!(replace_managed_section("# BEGIN NETTOOL PROFILE lab\n", "lab", &[]).is_err());
    }
}

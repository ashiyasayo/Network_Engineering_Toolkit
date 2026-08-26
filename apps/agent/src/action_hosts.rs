#[allow(clippy::wildcard_imports)]
use super::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HostsReplacePayload {
    profile_id: String,
    entries: Vec<ManagedHostsEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HostsAddPayload {
    profile_id: String,
    address: String,
    hostname: String,
    #[serde(default)]
    comment: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HostsRemovePayload {
    profile_id: String,
    hostname: String,
}

type HostsTogglePayload = HostsRemovePayload;

#[allow(clippy::too_many_lines)]
pub(super) async fn execute(
    action: &str,
    payload: &[u8],
    operation_id: &str,
    dry_run: bool,
) -> Result<serde_json::Value, NetToolError> {
    if matches!(
        action,
        "hosts.add" | "hosts.remove" | "hosts.enable" | "hosts.disable"
    ) {
        return execute_mutation(action, payload, operation_id, dry_run).await;
    }
    let (operation, helper_operation_id) = match action {
        "hosts.replace" => {
            let request: HostsReplacePayload =
                serde_json::from_slice(payload).map_err(|error| {
                    NetToolError::new(
                        ErrorCode::InvalidArgument,
                        format!("invalid hosts replace payload: {error}"),
                        false,
                    )
                })?;
            let helper_operation_id = if operation_id.trim().is_empty() {
                let entries_json = serde_json::to_vec(&request.entries).map_err(|error| {
                    NetToolError::new(
                        ErrorCode::ProtocolInvalid,
                        format!("hosts entries cannot be fingerprinted: {error}"),
                        false,
                    )
                })?;
                let mut entries_digest = String::with_capacity(64);
                for byte in Sha256::digest(entries_json) {
                    let _ = write!(entries_digest, "{byte:02x}");
                }
                format!("hosts-replace-{}-{}", request.profile_id, entries_digest)
            } else {
                operation_id.to_owned()
            };
            (
                PrivilegedOperation::HostsAtomicReplace {
                    profile_id: request.profile_id,
                    entries: request.entries,
                },
                helper_operation_id,
            )
        }
        "hosts.read" => (
            PrivilegedOperation::HostsRead,
            operation_id_or_default(operation_id, "hosts-read"),
        ),
        "hosts.backup" => (
            PrivilegedOperation::HostsBackup,
            operation_id_or_default(operation_id, "hosts-backup"),
        ),
        "hosts.restore" => (
            PrivilegedOperation::HostsRestore,
            operation_id_or_default(operation_id, "hosts-restore"),
        ),
        _ => {
            return Err(NetToolError::new(
                ErrorCode::ActionUnsupported,
                "hosts action is not attached",
                false,
            ));
        }
    };
    super::action_helper::helper_call(&helper_operation_id, operation, dry_run).await
}

fn operation_id_or_default(operation_id: &str, default: &str) -> String {
    if operation_id.trim().is_empty() {
        default.to_owned()
    } else {
        operation_id.to_owned()
    }
}

async fn execute_mutation(
    action: &str,
    payload: &[u8],
    operation_id: &str,
    dry_run: bool,
) -> Result<serde_json::Value, NetToolError> {
    let (profile_id, hostname, replacement) = match action {
        "hosts.add" => {
            let request: HostsAddPayload = serde_json::from_slice(payload).map_err(|error| {
                NetToolError::new(
                    ErrorCode::InvalidArgument,
                    format!("invalid hosts add payload: {error}"),
                    false,
                )
            })?;
            let current = read_managed_hosts(&request.profile_id, operation_id).await?;
            if current
                .iter()
                .any(|entry| entry.hostname == request.hostname)
            {
                return Err(NetToolError::new(
                    ErrorCode::InvalidArgument,
                    "hosts hostname already exists in profile",
                    false,
                ));
            }
            let mut entries = current;
            entries.push(ManagedHostsEntry {
                address: request.address,
                hostname: request.hostname.clone(),
                comment: request.comment,
                enabled: true,
            });
            (request.profile_id, request.hostname, entries)
        }
        "hosts.remove" => {
            let request: HostsRemovePayload = serde_json::from_slice(payload).map_err(|error| {
                NetToolError::new(
                    ErrorCode::InvalidArgument,
                    format!("invalid hosts remove payload: {error}"),
                    false,
                )
            })?;
            let mut entries = read_managed_hosts(&request.profile_id, operation_id).await?;
            let before = entries.len();
            entries.retain(|entry| entry.hostname != request.hostname);
            if entries.len() == before {
                return Ok(
                    json!({"updated": false, "entry_count": before, "hostname": request.hostname}),
                );
            }
            (request.profile_id, request.hostname, entries)
        }
        "hosts.enable" | "hosts.disable" => {
            let request: HostsTogglePayload = serde_json::from_slice(payload).map_err(|error| {
                NetToolError::new(
                    ErrorCode::InvalidArgument,
                    format!("invalid hosts toggle payload: {error}"),
                    false,
                )
            })?;
            let mut entries = read_managed_hosts(&request.profile_id, operation_id).await?;
            let enabled = action == "hosts.enable";
            let mut found = false;
            for entry in &mut entries {
                if entry.hostname == request.hostname {
                    entry.enabled = enabled;
                    found = true;
                }
            }
            if !found {
                return Err(NetToolError::new(
                    ErrorCode::InvalidArgument,
                    "hosts hostname does not exist in profile",
                    false,
                ));
            }
            (request.profile_id, request.hostname, entries)
        }
        _ => unreachable!(),
    };
    let replace_operation_id = if operation_id.trim().is_empty() {
        format!("hosts-mutation-{profile_id}-{hostname}")
    } else {
        operation_id.to_owned()
    };
    super::action_helper::helper_call(
        &replace_operation_id,
        PrivilegedOperation::HostsAtomicReplace {
            profile_id,
            entries: replacement,
        },
        dry_run,
    )
    .await
}

async fn read_managed_hosts(
    profile_id: &str,
    operation_id: &str,
) -> Result<Vec<ManagedHostsEntry>, NetToolError> {
    let read_operation_id = if operation_id.trim().is_empty() {
        format!("hosts-read-{profile_id}")
    } else {
        format!("{operation_id}-read")
    };
    let value = super::action_helper::helper_call(
        &read_operation_id,
        PrivilegedOperation::HostsRead,
        false,
    )
    .await?;
    let content = value.as_str().ok_or_else(|| {
        NetToolError::new(
            ErrorCode::ProtocolInvalid,
            "helper hosts response is not text",
            false,
        )
    })?;
    parse_managed_hosts(content, profile_id)
}

pub(super) fn parse_managed_hosts(
    content: &str,
    profile_id: &str,
) -> Result<Vec<ManagedHostsEntry>, NetToolError> {
    let begin = format!("# BEGIN NETTOOL PROFILE {profile_id}");
    let end = format!("# END NETTOOL PROFILE {profile_id}");
    let lines = content.lines().collect::<Vec<_>>();
    let starts = lines.iter().filter(|line| line.trim() == begin).count();
    let ends = lines.iter().filter(|line| line.trim() == end).count();
    if starts == 0 && ends == 0 {
        return Ok(Vec::new());
    }
    if starts != 1 || ends != 1 {
        return Err(NetToolError::new(
            ErrorCode::InvalidArgument,
            "managed hosts markers are missing or duplicated",
            false,
        ));
    }
    let start = lines
        .iter()
        .position(|line| line.trim() == begin)
        .unwrap_or(0);
    let finish = lines
        .iter()
        .position(|line| line.trim() == end)
        .unwrap_or(0);
    if finish <= start {
        return Err(NetToolError::new(
            ErrorCode::InvalidArgument,
            "managed hosts markers are out of order",
            false,
        ));
    }
    let mut entries = Vec::new();
    for line in &lines[start + 1..finish] {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (line, enabled) = line
            .strip_prefix("# NETTOOL DISABLED ")
            .map_or((line, true), |value| (value.trim_start(), false));
        let (fields, comment) = line.split_once('#').map_or((line, None), |(value, note)| {
            (value.trim_end(), Some(note.trim().to_owned()))
        });
        let mut fields = fields.split_whitespace();
        let address = fields.next().ok_or_else(|| {
            NetToolError::new(
                ErrorCode::InvalidArgument,
                "managed hosts entry is invalid",
                false,
            )
        })?;
        let hostname = fields.next().ok_or_else(|| {
            NetToolError::new(
                ErrorCode::InvalidArgument,
                "managed hosts entry is invalid",
                false,
            )
        })?;
        if fields.next().is_some() {
            return Err(NetToolError::new(
                ErrorCode::InvalidArgument,
                "managed hosts entry is invalid",
                false,
            ));
        }
        address.parse::<std::net::IpAddr>().map_err(|_| {
            NetToolError::new(
                ErrorCode::InvalidArgument,
                "managed hosts address is invalid",
                false,
            )
        })?;
        entries.push(ManagedHostsEntry {
            address: address.to_owned(),
            hostname: hostname.to_owned(),
            comment,
            enabled,
        });
    }
    Ok(entries)
}

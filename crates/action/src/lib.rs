//! GUI、CLI 與自動化共用的 Action API。

#![forbid(unsafe_code)]

use nettool_error::NetToolError;
use serde::{Deserialize, Serialize};

/// Action 的穩定名稱。
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ActionName(String);

impl ActionName {
    /// 建立 Action 名稱；名稱是否存在由 [`ActionRegistry`] 驗證。
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// 取得穩定名稱。
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// 執行 Action 所需的權限層級。
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionRequirement {
    /// 無副作用的唯讀操作。
    ReadOnly,
    /// 一般使用者可執行的操作。
    User,
    /// 必須經 privileged helper whitelist 驗證。
    Privileged,
}

/// Action 的公開合約描述。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActionDescriptor {
    /// 穩定 Action 名稱。
    pub name: &'static str,
    /// 權限需求。
    pub permission: PermissionRequirement,
    /// 重送相同 operation ID 是否安全。
    pub idempotent: bool,
    /// 對應的 CLI 命令。
    pub cli: &'static str,
}

/// 集中管理 GUI、CLI 與 Agent 可執行的 Action。
pub struct ActionRegistry;

impl ActionRegistry {
    /// 回傳目前 protocol major 支援的完整 Action 清單。
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub const fn all() -> &'static [ActionDescriptor] {
        &[
            ActionDescriptor {
                name: "interface.list",
                permission: PermissionRequirement::ReadOnly,
                idempotent: true,
                cli: "nettool interface list",
            },
            ActionDescriptor {
                name: "interface.show",
                permission: PermissionRequirement::ReadOnly,
                idempotent: true,
                cli: "nettool interface show <name-or-id>",
            },
            ActionDescriptor {
                name: "interface.refresh",
                permission: PermissionRequirement::ReadOnly,
                idempotent: true,
                cli: "nettool interface refresh",
            },
            ActionDescriptor {
                name: "system.health",
                permission: PermissionRequirement::ReadOnly,
                idempotent: true,
                cli: "nettool health",
            },
            ActionDescriptor {
                name: "dataplane.probe",
                permission: PermissionRequirement::ReadOnly,
                idempotent: true,
                cli: "nettool dataplane probe",
            },
            ActionDescriptor {
                name: "profile.list",
                permission: PermissionRequirement::ReadOnly,
                idempotent: true,
                cli: "nettool profile list",
            },
            ActionDescriptor {
                name: "profile.show",
                permission: PermissionRequirement::ReadOnly,
                idempotent: true,
                cli: "nettool profile show <id-or-name>",
            },
            ActionDescriptor {
                name: "profile.create",
                permission: PermissionRequirement::User,
                idempotent: true,
                cli: "nettool profile create <id> <name>",
            },
            ActionDescriptor {
                name: "profile.delete",
                permission: PermissionRequirement::User,
                idempotent: true,
                cli: "nettool profile delete <id-or-name>",
            },
            ActionDescriptor {
                name: "profile.edit",
                permission: PermissionRequirement::User,
                idempotent: false,
                cli: "nettool profile edit <id-or-name> <json>",
            },
            ActionDescriptor {
                name: "profile.export",
                permission: PermissionRequirement::ReadOnly,
                idempotent: true,
                cli: "nettool profile export <id-or-name>",
            },
            ActionDescriptor {
                name: "profile.import",
                permission: PermissionRequirement::User,
                idempotent: false,
                cli: "nettool profile import <file>",
            },
            ActionDescriptor {
                name: "profile.apply",
                permission: PermissionRequirement::Privileged,
                idempotent: true,
                cli: "nettool profile apply",
            },
            ActionDescriptor {
                name: "profile.confirm",
                permission: PermissionRequirement::Privileged,
                idempotent: true,
                cli: "nettool profile confirm",
            },
            ActionDescriptor {
                name: "profile.rollback",
                permission: PermissionRequirement::Privileged,
                idempotent: true,
                cli: "nettool profile rollback",
            },
            ActionDescriptor {
                name: "ip.set",
                permission: PermissionRequirement::Privileged,
                idempotent: false,
                cli: "nettool ip set --interface <id> --address <ip> --prefix <n>",
            },
            ActionDescriptor {
                name: "ip.dhcp",
                permission: PermissionRequirement::Privileged,
                idempotent: false,
                cli: "nettool ip dhcp --interface <id>",
            },
            ActionDescriptor {
                name: "dns.set",
                permission: PermissionRequirement::Privileged,
                idempotent: false,
                cli: "nettool dns set --interface <id> --server <ip>",
            },
            ActionDescriptor {
                name: "hosts.replace",
                permission: PermissionRequirement::Privileged,
                idempotent: true,
                cli: "nettool hosts replace",
            },
            ActionDescriptor {
                name: "hosts.add",
                permission: PermissionRequirement::Privileged,
                idempotent: false,
                cli: "nettool hosts add <profile-id> <address> <hostname> [comment]",
            },
            ActionDescriptor {
                name: "hosts.remove",
                permission: PermissionRequirement::Privileged,
                idempotent: true,
                cli: "nettool hosts remove <profile-id> <hostname>",
            },
            ActionDescriptor {
                name: "hosts.enable",
                permission: PermissionRequirement::Privileged,
                idempotent: true,
                cli: "nettool hosts enable <profile-id> <hostname>",
            },
            ActionDescriptor {
                name: "hosts.disable",
                permission: PermissionRequirement::Privileged,
                idempotent: true,
                cli: "nettool hosts disable <profile-id> <hostname>",
            },
            ActionDescriptor {
                name: "hosts.backup",
                permission: PermissionRequirement::Privileged,
                idempotent: true,
                cli: "nettool hosts backup",
            },
            ActionDescriptor {
                name: "hosts.restore",
                permission: PermissionRequirement::Privileged,
                idempotent: true,
                cli: "nettool hosts restore",
            },
            ActionDescriptor {
                name: "hosts.read",
                permission: PermissionRequirement::ReadOnly,
                idempotent: true,
                cli: "nettool hosts list",
            },
            ActionDescriptor {
                name: "node.pair",
                permission: PermissionRequirement::User,
                idempotent: true,
                cli: "nettool node pair",
            },
            ActionDescriptor {
                name: "node.list",
                permission: PermissionRequirement::ReadOnly,
                idempotent: true,
                cli: "nettool node list",
            },
            ActionDescriptor {
                name: "node.status",
                permission: PermissionRequirement::ReadOnly,
                idempotent: true,
                cli: "nettool node status",
            },
            ActionDescriptor {
                name: "node.revoke",
                permission: PermissionRequirement::User,
                idempotent: false,
                cli: "nettool node revoke <id-or-name>",
            },
            ActionDescriptor {
                name: "speed.run",
                permission: PermissionRequirement::User,
                idempotent: false,
                cli: "nettool speed run <node> [options]",
            },
            ActionDescriptor {
                name: "speed.cancel",
                permission: PermissionRequirement::User,
                idempotent: true,
                cli: "nettool speed cancel",
            },
            ActionDescriptor {
                name: "speed.history",
                permission: PermissionRequirement::ReadOnly,
                idempotent: true,
                cli: "nettool speed history [--limit <n>]",
            },
            ActionDescriptor {
                name: "packet.capture.start",
                permission: PermissionRequirement::User,
                idempotent: false,
                cli: "nettool packet capture start",
            },
            ActionDescriptor {
                name: "packet.capture.stop",
                permission: PermissionRequirement::User,
                idempotent: true,
                cli: "nettool packet capture stop <session-id>",
            },
            ActionDescriptor {
                name: "packet.analyze",
                permission: PermissionRequirement::ReadOnly,
                idempotent: true,
                cli: "nettool packet analyze --input <capture>",
            },
            ActionDescriptor {
                name: "packet.stats",
                permission: PermissionRequirement::ReadOnly,
                idempotent: true,
                cli: "nettool packet stats [--interface <id>]",
            },
            ActionDescriptor {
                name: "packet.connections",
                permission: PermissionRequirement::ReadOnly,
                idempotent: true,
                cli: "nettool packet connections [--protocol tcp|udp]",
            },
            ActionDescriptor {
                name: "perf.topology",
                permission: PermissionRequirement::ReadOnly,
                idempotent: true,
                cli: "nettool perf topology",
            },
            ActionDescriptor {
                name: "perf.backend",
                permission: PermissionRequirement::ReadOnly,
                idempotent: true,
                cli: "nettool perf backend",
            },
            ActionDescriptor {
                name: "perf.profile.list",
                permission: PermissionRequirement::ReadOnly,
                idempotent: true,
                cli: "nettool perf profile list",
            },
            ActionDescriptor {
                name: "perf.benchmark",
                permission: PermissionRequirement::User,
                idempotent: false,
                cli: "nettool perf benchmark --profile <id>",
            },
        ]
    }

    /// 依名稱查詢 Action 合約。
    #[must_use]
    pub fn find(name: &str) -> Option<&'static ActionDescriptor> {
        Self::all()
            .iter()
            .find(|descriptor| descriptor.name == name)
    }
}

/// 傳送到 Agent 的統一 Action request。
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ActionRequest<T> {
    /// 每次 request 唯一的識別字。
    pub request_id: String,
    /// 變更操作的冪等識別字。
    pub operation_id: Option<String>,
    /// Action 穩定名稱。
    pub action: ActionName,
    /// Action-specific payload。
    pub payload: T,
    /// 僅產生計畫，不允許外部副作用。
    pub dry_run: bool,
}

/// 不阻止 Action 成功、但呼叫端必須呈現的警告。
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Warning {
    /// 穩定警告代碼。
    pub code: String,
    /// 給人閱讀的描述。
    pub message: String,
}

/// Agent 回傳的統一 Action result。
#[derive(Clone, Debug, PartialEq)]
pub struct ActionResult<T> {
    /// 對應 request ID。
    pub request_id: String,
    /// Action 是否成功。
    pub success: bool,
    /// 成功資料。
    pub data: Option<T>,
    /// 不影響成功狀態的警告。
    pub warnings: Vec<Warning>,
    /// 失敗資訊。
    pub error: Option<NetToolError>,
}

#[cfg(test)]
mod tests {
    use super::ActionRegistry;

    #[test]
    fn registry_names_are_unique() {
        let mut names = ActionRegistry::all()
            .iter()
            .map(|item| item.name)
            .collect::<Vec<_>>();
        let original_length = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), original_length);
    }
}

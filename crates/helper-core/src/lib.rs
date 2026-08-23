//! Privileged helper 的 Safe Apply 與 audit 核心；不包含任意命令執行介面。

#![forbid(unsafe_code)]

use nettool_error::{ErrorCode, NetToolError};
use nettool_helper_protocol::NetworkDesiredState;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

mod hosts;
mod linux_network_manager;
mod linux_resources;
mod platform_network;

pub use hosts::{ManagedHostsEntry, replace_managed_section};
pub use linux_network_manager::{
    CommandOutput, CommandRunner, LinuxNetworkManagerExecutor, SystemCommandRunner,
    build_network_manager_properties,
};
pub use linux_resources::{KernelAccess, LinuxResourceExecutor, SystemKernelAccess};
pub use platform_network::{
    MacosNetworkStateReader, PlatformBackend, PlatformCommand, PlatformNetworkExecutor,
    PlatformStateReader, WindowsNetshStateReader, build_macos_networksetup_commands,
    build_windows_netsh_commands, execute_platform_commands, run_validated_platform_command,
    validate_platform_command,
};

/// Safe Apply 的可恢復狀態。
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SafeApplyState {
    /// Snapshot 與 deadline 已持久化，尚未完成 apply。
    Prepared,
    /// Apply 已驗證，等待確認或逾期 rollback。
    PendingConfirmation,
    /// 使用者已確認，不再自動 rollback。
    Confirmed,
    /// Helper 正在執行 restore。
    RollingBack,
    /// Restore 已完成。
    RolledBack,
    /// Restore 失敗，需要人工處理或重試。
    Failed,
}

/// Helper 持久化的 pending operation。
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PendingSafeApply {
    /// 冪等 operation ID。
    pub operation_id: String,
    /// 目標介面 stable ID。
    pub target_interface: String,
    /// Helper snapshot ID。
    pub snapshot_id: String,
    /// Unix epoch deadline，單位為秒。
    pub deadline_unix_seconds: u64,
    /// 目前 transaction state。
    pub state: SafeApplyState,
    /// 套用前狀態的 SHA-256。
    pub old_state_hash: String,
    /// 目標狀態的 SHA-256。
    pub new_state_hash: String,
}

/// Helper 必須實作的平台 network transaction 原語。
pub trait NetworkExecutor {
    /// 讀取目前完整 canonical state，不建立 rollback snapshot。
    ///
    /// # Errors
    ///
    /// 無法完整讀取平台狀態時回傳錯誤。
    fn read_state(&mut self, interface_id: &str) -> Result<Value, NetToolError>;
    /// 建立可用於 restore 的完整 snapshot，並回傳 snapshot ID 與 canonical state。
    ///
    /// # Errors
    ///
    /// 無法完整讀取或持久化目前平台狀態時回傳錯誤。
    fn snapshot(&mut self, interface_id: &str) -> Result<(String, Value), NetToolError>;
    /// 套用 validated desired state。
    ///
    /// # Errors
    ///
    /// 平台拒絕或只完成部分設定時回傳錯誤。
    fn apply(
        &mut self,
        interface_id: &str,
        desired_state: &NetworkDesiredState,
    ) -> Result<(), NetToolError>;
    /// 驗證 OS 目前狀態符合 desired state。
    ///
    /// # Errors
    ///
    /// 讀回狀態失敗或狀態不符合時回傳錯誤。
    fn verify(
        &mut self,
        interface_id: &str,
        desired_state: &NetworkDesiredState,
    ) -> Result<(), NetToolError>;
    /// 由 helper-owned snapshot 恢復設定。
    ///
    /// # Errors
    ///
    /// Snapshot 不存在或平台無法完整恢復時回傳錯誤。
    fn restore(&mut self, snapshot_id: &str) -> Result<(), NetToolError>;
}

/// Helper-owned Safe Apply state store。
pub struct SafeApplyManager {
    state_path: PathBuf,
    audit_path: PathBuf,
    pending: Vec<PendingSafeApply>,
}

impl SafeApplyManager {
    /// 開啟持久化 state；檔案不存在時建立空 store。
    ///
    /// # Errors
    ///
    /// State 檔案無法讀取或不是有效 JSON 時回傳錯誤，不會靜默清空 deadline。
    pub fn open(
        state_path: impl Into<PathBuf>,
        audit_path: impl Into<PathBuf>,
    ) -> Result<Self, NetToolError> {
        let state_path = state_path.into();
        let pending = match fs::read(&state_path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(state_error)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(io_error(error)),
        };
        Ok(Self {
            state_path,
            audit_path: audit_path.into(),
            pending,
        })
    }

    /// 建立 snapshot、持久化 deadline、套用並驗證網路設定。
    ///
    /// # Errors
    ///
    /// Snapshot、持久化、apply 或 verify 失敗時回傳錯誤。Apply/verify 失敗後會嘗試 restore；restore 失敗不得被原始錯誤遮蔽。
    pub fn begin<E: NetworkExecutor>(
        &mut self,
        executor: &mut E,
        request: BeginSafeApply<'_>,
    ) -> Result<PendingSafeApply, NetToolError> {
        if request.operation_id.trim().is_empty() || request.interface_id.trim().is_empty() {
            return Err(NetToolError::new(
                ErrorCode::InvalidArgument,
                "operation and interface IDs are required",
                false,
            ));
        }
        if !(10..=600).contains(&request.confirm_timeout_seconds) {
            return Err(NetToolError::new(
                ErrorCode::InvalidArgument,
                "confirm timeout must be between 10 and 600 seconds",
                false,
            ));
        }
        request
            .desired_state
            .validate()
            .map_err(|message| NetToolError::new(ErrorCode::InvalidArgument, message, false))?;
        let desired_hash = hash_json(request.desired_state)?;
        if let Some(existing) = self
            .pending
            .iter()
            .find(|item| item.operation_id == request.operation_id)
        {
            if is_pending(existing.state)
                && existing.target_interface == request.interface_id
                && existing.new_state_hash == desired_hash
            {
                return Ok(existing.clone());
            }
            return Err(NetToolError::new(
                ErrorCode::OperationConflict,
                "operation ID was reused with a different Safe Apply request",
                false,
            ));
        }
        if self
            .pending
            .iter()
            .any(|item| is_pending(item.state) && item.target_interface == request.interface_id)
        {
            return Err(NetToolError::new(
                ErrorCode::ResourceConflict,
                "interface already has a pending Safe Apply",
                false,
            ));
        }

        let (snapshot_id, old_state) = executor.snapshot(request.interface_id)?;
        let deadline = request
            .now_unix_seconds
            .checked_add(request.confirm_timeout_seconds)
            .ok_or_else(|| {
                NetToolError::new(
                    ErrorCode::InvalidArgument,
                    "rollback deadline overflow",
                    false,
                )
            })?;
        let mut record = PendingSafeApply {
            operation_id: request.operation_id.to_owned(),
            target_interface: request.interface_id.to_owned(),
            snapshot_id,
            deadline_unix_seconds: deadline,
            state: SafeApplyState::Prepared,
            old_state_hash: hash_json(&old_state)?,
            new_state_hash: desired_hash,
        };
        self.pending.push(record.clone());
        self.persist()?;

        if let Err(apply_error) = executor
            .apply(request.interface_id, request.desired_state)
            .and_then(|()| executor.verify(request.interface_id, request.desired_state))
        {
            return match self.rollback_internal(executor, request.operation_id, "apply_failed") {
                Ok(()) => Err(apply_error),
                Err(rollback_error) => Err(NetToolError::new(
                    ErrorCode::RollbackFailed,
                    format!(
                        "apply failed ({apply_error}); rollback also failed ({rollback_error})"
                    ),
                    false,
                )),
            };
        }
        record.state = SafeApplyState::PendingConfirmation;
        self.replace_record(record.clone())?;
        self.audit(&record, "pending_confirmation")?;
        Ok(record)
    }

    /// 確認 operation 並取消自動 rollback。
    ///
    /// # Errors
    ///
    /// Operation 不存在、已終止或持久化失敗時回傳錯誤。
    pub fn confirm(&mut self, operation_id: &str) -> Result<PendingSafeApply, NetToolError> {
        self.confirm_at(operation_id, now_unix_seconds())
    }

    /// 在指定時間確認 operation；供 monotonic watchdog 邊界與測試注入 clock。
    ///
    /// # Errors
    ///
    /// Operation 不存在、deadline 已到或持久化失敗時回傳錯誤。
    pub fn confirm_at(
        &mut self,
        operation_id: &str,
        now_unix_seconds: u64,
    ) -> Result<PendingSafeApply, NetToolError> {
        let mut record = self.find_active(operation_id)?.clone();
        if now_unix_seconds >= record.deadline_unix_seconds {
            return Err(NetToolError::new(
                ErrorCode::InvalidState,
                "Safe Apply deadline has expired; rollback is required",
                false,
            ));
        }
        record.state = SafeApplyState::Confirmed;
        self.replace_record(record.clone())?;
        self.audit(&record, "confirmed")?;
        Ok(record)
    }

    /// 立即 rollback 指定 operation。
    ///
    /// # Errors
    ///
    /// Operation 不存在、restore 或持久化失敗時回傳錯誤。
    pub fn rollback<E: NetworkExecutor>(
        &mut self,
        executor: &mut E,
        operation_id: &str,
    ) -> Result<(), NetToolError> {
        self.rollback_internal(executor, operation_id, "explicit_rollback")
    }

    /// 恢復所有已逾期 operation；Agent 是否存活不影響此判斷。
    ///
    /// # Errors
    ///
    /// 任一 restore 或持久化失敗時立即回傳錯誤，未處理項目保留供下次重試。
    pub fn recover_expired<E: NetworkExecutor>(
        &mut self,
        executor: &mut E,
        now_unix_seconds: u64,
    ) -> Result<Vec<String>, NetToolError> {
        let expired = self
            .pending
            .iter()
            .filter(|item| is_pending(item.state) && item.deadline_unix_seconds <= now_unix_seconds)
            .map(|item| item.operation_id.clone())
            .collect::<Vec<_>>();
        for operation_id in &expired {
            self.rollback_internal(executor, operation_id, "deadline_expired")?;
        }
        Ok(expired)
    }

    /// 回傳仍由 helper 持有 deadline 的 operations。
    #[must_use]
    pub fn pending(&self) -> Vec<&PendingSafeApply> {
        self.pending
            .iter()
            .filter(|item| is_pending(item.state))
            .collect()
    }

    fn rollback_internal<E: NetworkExecutor>(
        &mut self,
        executor: &mut E,
        operation_id: &str,
        result: &str,
    ) -> Result<(), NetToolError> {
        let mut record = self.find_active(operation_id)?.clone();
        record.state = SafeApplyState::RollingBack;
        self.replace_record(record.clone())?;
        if let Err(error) = executor.restore(&record.snapshot_id) {
            record.state = SafeApplyState::Failed;
            self.replace_record(record.clone())?;
            self.audit(&record, "rollback_failed")?;
            return Err(error);
        }
        record.state = SafeApplyState::RolledBack;
        self.replace_record(record.clone())?;
        self.audit(&record, result)
    }

    fn find_active(&self, operation_id: &str) -> Result<&PendingSafeApply, NetToolError> {
        self.pending
            .iter()
            .find(|item| item.operation_id == operation_id && is_pending(item.state))
            .ok_or_else(|| {
                NetToolError::new(
                    ErrorCode::InvalidState,
                    "Safe Apply operation is not pending",
                    false,
                )
            })
    }

    fn replace_record(&mut self, record: PendingSafeApply) -> Result<(), NetToolError> {
        let slot = self
            .pending
            .iter_mut()
            .find(|item| item.operation_id == record.operation_id)
            .ok_or_else(|| {
                NetToolError::new(
                    ErrorCode::InvalidState,
                    "Safe Apply record disappeared",
                    false,
                )
            })?;
        *slot = record;
        self.persist()
    }

    fn persist(&self) -> Result<(), NetToolError> {
        if let Some(parent) = self.state_path.parent() {
            fs::create_dir_all(parent).map_err(io_error)?;
        }
        let temporary = self.state_path.with_extension("tmp");
        let bytes = serde_json::to_vec_pretty(&self.pending).map_err(state_error)?;
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temporary)
            .map_err(io_error)?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(io_error)?;
        fs::rename(&temporary, &self.state_path).map_err(io_error)?;
        sync_parent(&self.state_path)
    }

    fn audit(&self, record: &PendingSafeApply, result: &str) -> Result<(), NetToolError> {
        if let Some(parent) = self.audit_path.parent() {
            fs::create_dir_all(parent).map_err(io_error)?;
        }
        let event = serde_json::json!({"timestamp_unix_seconds":now_unix_seconds(),"operation":"network.apply","operation_id":record.operation_id,"target":record.target_interface,"old_state_hash":record.old_state_hash,"new_state_hash":record.new_state_hash,"result":result});
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.audit_path)
            .map_err(io_error)?;
        serde_json::to_writer(&mut file, &event).map_err(state_error)?;
        file.write_all(b"\n")
            .and_then(|()| file.sync_data())
            .map_err(io_error)
    }
}

/// 建立 Safe Apply 所需的 validated arguments。
#[derive(Clone, Copy)]
pub struct BeginSafeApply<'a> {
    /// 冪等 operation ID。
    pub operation_id: &'a str,
    /// 目標 interface ID。
    pub interface_id: &'a str,
    /// Canonical desired state。
    pub desired_state: &'a NetworkDesiredState,
    /// Confirm timeout 秒數。
    pub confirm_timeout_seconds: u64,
    /// Helper 目前 epoch 秒數，作為可測試 clock boundary。
    pub now_unix_seconds: u64,
}

fn is_pending(state: SafeApplyState) -> bool {
    matches!(
        state,
        SafeApplyState::Prepared
            | SafeApplyState::PendingConfirmation
            | SafeApplyState::RollingBack
    )
}

fn hash_json(value: &impl Serialize) -> Result<String, NetToolError> {
    let bytes = serde_json::to_vec(value).map_err(state_error)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[cfg(unix)]
fn sync_parent(path: &std::path::Path) -> Result<(), NetToolError> {
    if let Some(parent) = path.parent() {
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(io_error)?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn sync_parent(_path: &std::path::Path) -> Result<(), NetToolError> {
    Ok(())
}

#[allow(clippy::needless_pass_by_value)]
fn io_error(error: std::io::Error) -> NetToolError {
    NetToolError::new(
        ErrorCode::PersistenceFailed,
        format!("helper persistence failed: {error}"),
        true,
    )
}

#[allow(clippy::needless_pass_by_value)]
fn state_error(error: serde_json::Error) -> NetToolError {
    NetToolError::new(
        ErrorCode::PersistenceFailed,
        format!("helper state is invalid: {error}"),
        false,
    )
}

#[cfg(test)]
mod tests {
    use super::{BeginSafeApply, NetworkExecutor, SafeApplyManager, SafeApplyState};
    use nettool_domain::{DnsConfiguration, Ipv4Configuration, Ipv6Configuration};
    use nettool_error::NetToolError;
    use nettool_helper_protocol::NetworkDesiredState;
    use serde_json::{Value, json};
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_ID: AtomicU64 = AtomicU64::new(0);

    struct FakeExecutor {
        state: Value,
        snapshots: Vec<(String, Value)>,
        restore_count: usize,
    }

    impl FakeExecutor {
        fn new() -> Self {
            Self {
                state: json!({"mode":"dhcp"}),
                snapshots: Vec::new(),
                restore_count: 0,
            }
        }
    }

    impl NetworkExecutor for FakeExecutor {
        fn read_state(&mut self, _interface_id: &str) -> Result<Value, NetToolError> {
            Ok(self.state.clone())
        }

        fn snapshot(&mut self, _interface_id: &str) -> Result<(String, Value), NetToolError> {
            let id = format!("snapshot-{}", self.snapshots.len());
            self.snapshots.push((id.clone(), self.state.clone()));
            Ok((id, self.state.clone()))
        }
        fn apply(
            &mut self,
            _interface_id: &str,
            desired_state: &NetworkDesiredState,
        ) -> Result<(), NetToolError> {
            self.state = serde_json::to_value(desired_state).expect("serializable desired state");
            Ok(())
        }
        fn verify(
            &mut self,
            _interface_id: &str,
            desired_state: &NetworkDesiredState,
        ) -> Result<(), NetToolError> {
            assert_eq!(
                self.state,
                serde_json::to_value(desired_state).expect("serializable desired state")
            );
            Ok(())
        }
        fn restore(&mut self, snapshot_id: &str) -> Result<(), NetToolError> {
            self.restore_count += 1;
            self.state = self
                .snapshots
                .iter()
                .find(|(id, _)| id == snapshot_id)
                .expect("snapshot exists")
                .1
                .clone();
            Ok(())
        }
    }

    fn paths() -> (PathBuf, PathBuf) {
        let id = TEST_ID.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "nettool-safe-apply-test-{}-{id}",
            std::process::id()
        ));
        (root.join("state.json"), root.join("audit.jsonl"))
    }

    fn desired_state() -> NetworkDesiredState {
        NetworkDesiredState {
            ipv4: Ipv4Configuration::Dhcp,
            ipv6: Ipv6Configuration::Automatic,
            dns: DnsConfiguration {
                automatic: true,
                servers: Vec::new(),
                search_domains: Vec::new(),
            },
            routes: Vec::new(),
            mtu: None,
        }
    }

    #[test]
    fn expired_operation_survives_manager_restart_and_rolls_back() {
        let (state, audit) = paths();
        let desired = desired_state();
        let mut executor = FakeExecutor::new();
        let mut manager = SafeApplyManager::open(&state, &audit).expect("store opens");
        manager
            .begin(
                &mut executor,
                BeginSafeApply {
                    operation_id: "op-1",
                    interface_id: "eth0",
                    desired_state: &desired,
                    confirm_timeout_seconds: 10,
                    now_unix_seconds: 100,
                },
            )
            .expect("apply succeeds");
        drop(manager);
        let mut restarted = SafeApplyManager::open(&state, &audit).expect("state survives restart");
        assert_eq!(
            restarted
                .recover_expired(&mut executor, 110)
                .expect("rollback succeeds"),
            ["op-1"]
        );
        assert_eq!(executor.state, json!({"mode":"dhcp"}));
        assert_eq!(executor.restore_count, 1);
        let _ = fs::remove_dir_all(state.parent().expect("test path has parent"));
    }

    #[test]
    fn confirmed_operation_does_not_roll_back() {
        let (state, audit) = paths();
        let desired = desired_state();
        let mut executor = FakeExecutor::new();
        let mut manager = SafeApplyManager::open(&state, &audit).expect("store opens");
        manager
            .begin(
                &mut executor,
                BeginSafeApply {
                    operation_id: "op-2",
                    interface_id: "eth0",
                    desired_state: &desired,
                    confirm_timeout_seconds: 10,
                    now_unix_seconds: 100,
                },
            )
            .expect("apply succeeds");
        assert_eq!(
            manager
                .confirm_at("op-2", 109)
                .expect("confirm succeeds")
                .state,
            SafeApplyState::Confirmed
        );
        assert!(
            manager
                .recover_expired(&mut executor, 999)
                .expect("recovery succeeds")
                .is_empty()
        );
        assert_eq!(
            executor.state,
            serde_json::to_value(desired).expect("serializable desired state")
        );
        let _ = fs::remove_dir_all(state.parent().expect("test path has parent"));
    }

    #[test]
    fn repeated_identical_begin_is_idempotent_and_expired_confirm_is_rejected() {
        let (state, audit) = paths();
        let desired = desired_state();
        let mut executor = FakeExecutor::new();
        let mut manager = SafeApplyManager::open(&state, &audit).expect("store opens");
        let request = BeginSafeApply {
            operation_id: "op-idempotent",
            interface_id: "eth0",
            desired_state: &desired,
            confirm_timeout_seconds: 10,
            now_unix_seconds: 100,
        };
        let first = manager.begin(&mut executor, request).expect("first apply");
        let second = manager.begin(&mut executor, request).expect("same result");
        assert_eq!(first, second);
        assert_eq!(executor.snapshots.len(), 1);
        assert!(manager.confirm_at("op-idempotent", 110).is_err());
        assert_eq!(manager.pending().len(), 1);
        let _ = fs::remove_dir_all(state.parent().expect("test path has parent"));
    }
}

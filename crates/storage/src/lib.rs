//! `SQLite` metadata storage 與 forward-only migration。

#![forbid(unsafe_code)]

use nettool_benchmark::{
    BenchmarkEnvironmentSnapshot, CertificationEvidence, CertificationPolicy, SupportLevel,
    evaluate_certification,
};
use nettool_error::{ErrorCode, NetToolError};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::path::Path;

const INITIAL_MIGRATION: &str = include_str!("../../../migrations/0001_initial.sql");
const NODE_CONNECTION_MIGRATION: &str =
    include_str!("../../../migrations/0002_node_connection_trust.sql");
const PACKET_SESSION_STATE_MIGRATION: &str =
    include_str!("../../../migrations/0003_packet_session_state.sql");
type PacketSessionTerminal = (Option<String>, Option<String>, Option<String>, String);

/// Agent 擁有的 `SQLite` metadata store。
pub struct Storage {
    connection: Connection,
}

/// 儲存的 profile 摘要。
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProfileSummary {
    /// Profile ID。
    pub id: String,
    /// 顯示名稱。
    pub name: String,
    /// 使用中的 revision。
    pub active_revision: i64,
}

/// Profile 的完整持久化文件；configuration 不包含 secrets。
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProfileDocument {
    /// Profile 摘要。
    pub summary: ProfileSummary,
    /// 已保存的 versioned configuration JSON。
    pub configuration: Value,
}

/// 已建立 trust 的遠端 Node 摘要；不包含私鑰或其他敏感資料。
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TrustedNodeSummary {
    /// Stable Node ID。
    pub id: String,
    /// 使用者可辨識名稱。
    pub name: String,
    /// 最近一次通過驗證的 address。
    pub last_address: Option<String>,
    /// 配對憑證 fingerprint。
    pub fingerprint: String,
    /// Pairing 時保存的完整 identity certificate DER；不含 private key。
    pub certificate_der: Vec<u8>,
    /// 憑證 SAN 必須匹配的 TLS server name。
    pub server_name: String,
    /// 包含 dynamic/configured port 的完整 control socket address。
    pub control_address: String,
}

/// 經使用者確認後要原子保存的 Node connection trust material。
pub struct TrustedNodeConnection<'a> {
    /// Stable 128-bit Node ID，以 32 位十六進位表示。
    pub node_id: &'a str,
    /// 使用者可辨識名稱。
    pub name: &'a str,
    /// 最近驗證成功的完整 control socket address。
    pub control_address: &'a str,
    /// TLS certificate SAN server name。
    pub server_name: &'a str,
    /// 完整 X.509 identity certificate DER。
    pub certificate_der: &'a [u8],
    /// Pairing UI 顯示並由使用者確認的 public-key fingerprint。
    pub fingerprint: &'a str,
    /// 使用者已透過 out-of-band channel 核對 fingerprint。
    pub out_of_band_fingerprint_confirmed: bool,
    /// 只有使用者完成 re-pair confirmation 時才可接受既有 Node ID 的 key 變更。
    pub identity_change_confirmed: bool,
}

/// 原子保存 benchmark/certification 所需的資料。
pub struct BenchmarkPersistenceRequest<'a> {
    /// Hardware profile registry ID。
    pub hardware_profile_id: &'a str,
    /// Benchmark result ID。
    pub benchmark_result_id: &'a str,
    /// Certified 時使用的 certification ID。
    pub certification_id: Option<&'a str>,
    /// Software build/version/hash。
    pub software_build: &'a str,
    /// 完整 benchmark configuration。
    pub configuration: &'a Value,
    /// Environment snapshot。
    pub environment: &'a BenchmarkEnvironmentSnapshot,
    /// 原始 gate evidence。
    pub evidence: &'a CertificationEvidence,
    /// POC policy；沒有時絕不建立 certification row。
    pub policy: Option<CertificationPolicy>,
    /// UTC timestamp，由 Agent clock authority 提供。
    pub created_at: &'a str,
}

/// 已持久化 benchmark 的不可變識別資訊。
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PersistedBenchmark {
    /// Benchmark result ID。
    pub benchmark_result_id: String,
    /// 平台組合 SHA-256 key。
    pub hardware_profile_hash: String,
    /// Result/evidence checksum。
    pub checksum: String,
    /// 最終支援等級；功能不可執行時為 `unsupported`。
    pub certification_state: String,
    /// 是否建立 `hardware_certification` row。
    pub certification_created: bool,
}

/// 建立 Speed session persistence row 所需的不可變欄位。
pub struct SpeedSessionPersistenceRequest<'a> {
    /// 128-bit session ID，以 32 位十六進位表示。
    pub session_id: &'a str,
    /// 已配對 remote Node ID。
    pub remote_node_id: &'a str,
    /// Protocol registry name。
    pub protocol: &'a str,
    /// Backend registry name。
    pub backend: &'a str,
    /// Direction registry name。
    pub direction: &'a str,
    /// Agent clock authority 提供的 UTC timestamp。
    pub started_at: &'a str,
    /// 完整且已驗證的 versioned configuration。
    pub configuration: &'a Value,
}

/// Speed session history 的非敏感摘要。
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SpeedSessionSummary {
    /// Session ID。
    pub session_id: String,
    /// Remote Node ID；本機 session 可為空。
    pub remote_node: Option<String>,
    /// Protocol registry name。
    pub protocol: String,
    /// Backend registry name。
    pub backend: String,
    /// Direction registry name。
    pub direction: String,
    /// Start timestamp。
    pub started_at: String,
    /// Completion timestamp。
    pub completed_at: Option<String>,
    /// preparing/running/completed/failed/canceled。
    pub state: String,
}

/// 建立封包擷取 session persistence row 所需的不可變欄位。
pub struct PacketSessionPersistenceRequest<'a> {
    /// 128-bit session ID，以 32 位十六進位表示。
    pub session_id: &'a str,
    /// 介面名稱或 PCI identity。
    pub interface: &'a str,
    /// Capture backend。
    pub backend: &'a str,
    /// Capture payload policy。
    pub capture_mode: &'a str,
    /// Analyzer coverage policy。
    pub analysis_mode: &'a str,
    /// Agent clock authority 提供的 UTC timestamp。
    pub started_at: &'a str,
}

impl Storage {
    /// 開啟資料庫並套用所有 forward migrations。
    ///
    /// # Errors
    ///
    /// 無法建立、設定或遷移 `SQLite` 時回傳 `STORAGE.DATABASE_FAILED`。
    pub fn open(path: &Path) -> Result<Self, NetToolError> {
        let connection = Connection::open(path).map_err(database_error)?;
        connection
            .execute_batch("PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;")
            .map_err(database_error)?;
        let has_migration_table: bool = connection
            .query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_migration')", [], |row| row.get(0))
            .map_err(database_error)?;
        if !has_migration_table {
            connection
                .execute_batch(INITIAL_MIGRATION)
                .map_err(database_error)?;
        }
        let version: i64 = connection
            .query_row("SELECT MAX(version) FROM schema_migration", [], |row| {
                row.get(0)
            })
            .map_err(database_error)?;
        if version < 2 {
            connection
                .execute_batch(NODE_CONNECTION_MIGRATION)
                .map_err(database_error)?;
        }
        if version < 3 {
            connection
                .execute_batch(PACKET_SESSION_STATE_MIGRATION)
                .map_err(database_error)?;
        }
        Ok(Self { connection })
    }

    /// 建立只存在於記憶體的 store，供測試與短生命週期工具使用。
    ///
    /// # Errors
    ///
    /// `SQLite` 初始化失敗時回傳錯誤。
    pub fn in_memory() -> Result<Self, NetToolError> {
        Self::open(Path::new(":memory:"))
    }

    /// 回傳目前 schema migration 版本。
    ///
    /// # Errors
    ///
    /// 查詢 `SQLite` 失敗時回傳錯誤。
    pub fn schema_version(&self) -> Result<i64, NetToolError> {
        self.connection
            .query_row("SELECT MAX(version) FROM schema_migration", [], |row| {
                row.get(0)
            })
            .map_err(database_error)
    }

    /// 列出 profile，不回傳完整設定內容。
    ///
    /// # Errors
    ///
    /// 查詢或讀取資料列失敗時回傳錯誤。
    pub fn list_profiles(&self) -> Result<Vec<ProfileSummary>, NetToolError> {
        let mut statement = self
            .connection
            .prepare("SELECT id, name, active_revision FROM network_profile ORDER BY name, id")
            .map_err(database_error)?;
        let rows = statement
            .query_map([], |row| {
                Ok(ProfileSummary {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    active_revision: row.get(2)?,
                })
            })
            .map_err(database_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(database_error)
    }

    /// 建立 revision 1 的 profile；相同 ID 不會覆蓋既有設定。
    ///
    /// # Errors
    ///
    /// ID/name/configuration 無效、ID 已存在或 `SQLite` 寫入失敗時回傳錯誤。
    pub fn create_profile(
        &mut self,
        id: &str,
        name: &str,
        configuration: &Value,
        timestamp: &str,
    ) -> Result<ProfileSummary, NetToolError> {
        validate_profile_identity(id, name)?;
        if !configuration.is_object() {
            return Err(invalid("profile configuration must be a JSON object"));
        }
        let configuration_json = serde_json::to_string(configuration).map_err(|error| {
            NetToolError::new(
                ErrorCode::InvalidArgument,
                format!("profile configuration cannot be serialized: {error}"),
                false,
            )
        })?;
        let checksum = hex_digest(configuration_json.as_bytes());
        let transaction = self.connection.transaction().map_err(database_error)?;
        transaction
            .execute(
                "INSERT INTO network_profile(id, name, active_revision, created_at, updated_at) VALUES (?1, ?2, 1, ?3, ?3)",
                params![id, name, timestamp],
            )
            .map_err(|error| {
                if error.to_string().contains("UNIQUE") {
                    invalid("profile ID already exists")
                } else {
                    database_error(error)
                }
            })?;
        transaction
            .execute(
                "INSERT INTO network_profile_revision(profile_id, revision, configuration_json, checksum, created_at) VALUES (?1, 1, ?2, ?3, ?4)",
                params![id, configuration_json, checksum, timestamp],
            )
            .map_err(database_error)?;
        transaction.commit().map_err(database_error)?;
        Ok(ProfileSummary {
            id: id.to_owned(),
            name: name.to_owned(),
            active_revision: 1,
        })
    }

    /// 建立 profile 的下一個 revision，並將其設為 active revision。
    ///
    /// # Errors
    ///
    /// Profile 不存在、識別字或 configuration 無效、revision 溢位，或 `SQLite` 寫入失敗時回傳錯誤。
    pub fn update_profile(
        &mut self,
        id_or_name: &str,
        name: &str,
        configuration: &Value,
        timestamp: &str,
    ) -> Result<ProfileSummary, NetToolError> {
        validate_profile_identity(id_or_name, name)?;
        if !configuration.is_object() {
            return Err(invalid("profile configuration must be a JSON object"));
        }
        let current = self
            .get_profile(id_or_name)?
            .ok_or_else(|| invalid("profile does not exist"))?;
        let configuration_json = serde_json::to_string(configuration).map_err(|error| {
            NetToolError::new(
                ErrorCode::InvalidArgument,
                format!("profile configuration cannot be serialized: {error}"),
                false,
            )
        })?;
        let checksum = hex_digest(configuration_json.as_bytes());
        let revision = current
            .summary
            .active_revision
            .checked_add(1)
            .ok_or_else(|| invalid("profile revision overflow"))?;
        let transaction = self.connection.transaction().map_err(database_error)?;
        transaction
            .execute(
                "UPDATE network_profile SET name = ?1, active_revision = ?2, updated_at = ?3 WHERE id = ?4",
                params![name, revision, timestamp, current.summary.id],
            )
            .map_err(database_error)?;
        transaction
            .execute(
                "INSERT INTO network_profile_revision(profile_id, revision, configuration_json, checksum, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![current.summary.id, revision, configuration_json, checksum, timestamp],
            )
            .map_err(database_error)?;
        transaction.commit().map_err(database_error)?;
        Ok(ProfileSummary {
            id: current.summary.id,
            name: name.to_owned(),
            active_revision: revision,
        })
    }

    /// 依 ID 或精確名稱取得 profile 的 active revision。
    ///
    /// # Errors
    ///
    /// 名稱不唯一、JSON/checksum 損壞或 `SQLite` 查詢失敗時回傳錯誤。
    pub fn get_profile(&self, id_or_name: &str) -> Result<Option<ProfileDocument>, NetToolError> {
        if id_or_name.trim().is_empty() {
            return Err(invalid("profile ID or name must not be empty"));
        }
        let mut statement = self
            .connection
            .prepare(
                "SELECT p.id, p.name, p.active_revision, r.configuration_json, r.checksum
                 FROM network_profile p JOIN network_profile_revision r
                   ON r.profile_id = p.id AND r.revision = p.active_revision
                 WHERE p.id = ?1 OR p.name = ?1 ORDER BY p.id",
            )
            .map_err(database_error)?;
        let rows = statement
            .query_map([id_or_name], |row| {
                Ok((
                    ProfileSummary {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        active_revision: row.get(2)?,
                    },
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })
            .map_err(database_error)?;
        let mut matches = rows
            .collect::<Result<Vec<_>, _>>()
            .map_err(database_error)?;
        if matches.len() > 1 {
            return Err(invalid("profile name is ambiguous"));
        }
        let Some((summary, configuration_json, checksum)) = matches.pop() else {
            return Ok(None);
        };
        if hex_digest(configuration_json.as_bytes()) != checksum {
            return Err(NetToolError::new(
                ErrorCode::StorageFailed,
                "profile configuration checksum does not match",
                false,
            ));
        }
        let configuration = serde_json::from_str(&configuration_json).map_err(|error| {
            NetToolError::new(
                ErrorCode::StorageFailed,
                format!("profile configuration JSON is invalid: {error}"),
                false,
            )
        })?;
        Ok(Some(ProfileDocument {
            summary,
            configuration,
        }))
    }

    /// 刪除 profile 及其 revisions；不會觸碰已套用的作業狀態。
    ///
    /// # Errors
    ///
    /// Profile 不存在或 `SQLite` 寫入失敗時回傳錯誤。
    pub fn delete_profile(&mut self, id_or_name: &str) -> Result<ProfileSummary, NetToolError> {
        let document = self
            .get_profile(id_or_name)?
            .ok_or_else(|| invalid("profile does not exist"))?;
        let transaction = self.connection.transaction().map_err(database_error)?;
        transaction
            .execute(
                "DELETE FROM network_profile_revision WHERE profile_id = ?1",
                [&document.summary.id],
            )
            .map_err(database_error)?;
        transaction
            .execute(
                "DELETE FROM network_profile WHERE id = ?1",
                [&document.summary.id],
            )
            .map_err(database_error)?;
        transaction.commit().map_err(database_error)?;
        Ok(document.summary)
    }

    /// 依 stable ID 或精確名稱解析仍為 trusted 的 Node。
    ///
    /// # Errors
    ///
    /// 名稱為空、名稱不唯一或資料庫查詢失敗時回傳錯誤；找不到時回傳 `None`。
    pub fn resolve_trusted_node(
        &self,
        id_or_name: &str,
    ) -> Result<Option<TrustedNodeSummary>, NetToolError> {
        if id_or_name.trim().is_empty() {
            return Err(NetToolError::new(
                ErrorCode::InvalidArgument,
                "node ID or name must not be empty",
                false,
            ));
        }
        let mut statement = self
            .connection
            .prepare(
                "SELECT n.id, n.name, n.last_address, t.fingerprint, \
                        t.certificate_der, t.server_name, t.control_address \
                 FROM node n JOIN node_trust t ON t.node_id = n.id \
                 WHERE (n.id = ?1 OR n.name = ?1) AND t.trust_status = 'trusted' \
                   AND t.certificate_der IS NOT NULL AND t.server_name IS NOT NULL \
                   AND t.control_address IS NOT NULL \
                 ORDER BY CASE WHEN n.id = ?1 THEN 0 ELSE 1 END, n.id LIMIT 2",
            )
            .map_err(database_error)?;
        let matches = statement
            .query_map([id_or_name], trusted_node_from_row)
            .map_err(database_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(database_error)?;
        if matches.len() > 1 && matches.iter().all(|node| node.id != id_or_name) {
            return Err(NetToolError::new(
                ErrorCode::InvalidArgument,
                "node name is ambiguous; use the stable node ID",
                false,
            ));
        }
        Ok(matches.into_iter().next())
    }

    /// 列出具完整 TLS connection material 的 trusted Nodes。
    ///
    /// # Errors
    ///
    /// 資料庫查詢或欄位讀取失敗時回傳錯誤。
    pub fn list_trusted_nodes(&self) -> Result<Vec<TrustedNodeSummary>, NetToolError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT n.id, n.name, n.last_address, t.fingerprint, \
                        t.certificate_der, t.server_name, t.control_address \
                 FROM node n JOIN node_trust t ON t.node_id=n.id \
                 WHERE t.trust_status='trusted' AND t.certificate_der IS NOT NULL \
                   AND t.server_name IS NOT NULL AND t.control_address IS NOT NULL \
                 ORDER BY n.id",
            )
            .map_err(database_error)?;
        statement
            .query_map([], trusted_node_from_row)
            .map_err(database_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(database_error)
    }

    /// 撤銷指定 trusted Node；撤銷後不刪除歷史 identity metadata。
    ///
    /// # Errors
    ///
    /// 指定 Node 不存在、不再 trusted，名稱歧義或資料庫交易失敗時回傳錯誤。
    pub fn revoke_trusted_node(
        &mut self,
        id_or_name: &str,
    ) -> Result<TrustedNodeSummary, NetToolError> {
        let node = self.resolve_trusted_node(id_or_name)?.ok_or_else(|| {
            NetToolError::new(ErrorCode::NodeNotPaired, "Node is not trusted", false)
        })?;
        let transaction = self.connection.transaction().map_err(database_error)?;
        let changed = transaction
            .execute(
                "UPDATE node_trust SET trust_status='revoked', revoked_at=strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE node_id=?1 AND trust_status='trusted'",
                [&node.id],
            )
            .map_err(database_error)?;
        if changed != 1 {
            return Err(NetToolError::new(
                ErrorCode::NodeNotPaired,
                "Node is no longer trusted",
                false,
            ));
        }
        transaction.commit().map_err(database_error)?;
        Ok(node)
    }

    /// 依完整 SPKI fingerprint 唯一解析 trusted peer。
    ///
    /// # Errors
    ///
    /// Fingerprint 空白、資料庫失敗或同一 fingerprint 對應多個 Node ID 時回傳錯誤。
    pub fn resolve_trusted_node_by_fingerprint(
        &self,
        fingerprint: &str,
    ) -> Result<Option<TrustedNodeSummary>, NetToolError> {
        if fingerprint.trim().is_empty() {
            return Err(invalid("trusted Node fingerprint must not be empty"));
        }
        let matches = self
            .list_trusted_nodes()?
            .into_iter()
            .filter(|node| node.fingerprint.eq_ignore_ascii_case(fingerprint))
            .collect::<Vec<_>>();
        if matches.len() > 1 {
            return Err(NetToolError::new(
                ErrorCode::StorageFailed,
                "trusted fingerprint maps to multiple Node IDs",
                false,
            ));
        }
        Ok(matches.into_iter().next())
    }

    /// 原子保存已由使用者確認的 Node trust 與 TLS connection material。
    ///
    /// # Errors
    ///
    /// 欄位、Node ID、socket、X.509 certificate、fingerprint 或資料庫操作無效時回傳錯誤。
    pub fn trust_node_connection(
        &mut self,
        trusted: &TrustedNodeConnection<'_>,
    ) -> Result<(), NetToolError> {
        validate_trusted_connection(trusted)?;
        let transaction = self.connection.transaction().map_err(database_error)?;
        let existing_fingerprint = transaction
            .query_row(
                "SELECT fingerprint FROM node_trust WHERE node_id=?1",
                [trusted.node_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(database_error)?;
        if existing_fingerprint.is_some_and(|fingerprint| {
            !fingerprint.eq_ignore_ascii_case(trusted.fingerprint)
                && !trusted.identity_change_confirmed
        }) {
            return Err(NetToolError::new(
                ErrorCode::NodeTlsFailed,
                "Node identity changed; explicit re-pair confirmation is required",
                false,
            ));
        }
        transaction
            .execute(
                "INSERT INTO node(id, name, first_seen_at, last_seen_at, last_address) \
                 VALUES (?1, ?2, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), \
                         strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), ?3) \
                 ON CONFLICT(id) DO UPDATE SET name=excluded.name, \
                     last_seen_at=excluded.last_seen_at, last_address=excluded.last_address",
                params![trusted.node_id, trusted.name, trusted.control_address],
            )
            .map_err(database_error)?;
        transaction
            .execute(
                "INSERT INTO node_trust(node_id, fingerprint, trust_status, trusted_at, \
                                        certificate_der, server_name, control_address) \
                 VALUES (?1, ?2, 'trusted', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), ?3, ?4, ?5) \
                 ON CONFLICT(node_id) DO UPDATE SET fingerprint=excluded.fingerprint, \
                     trust_status='trusted', trusted_at=excluded.trusted_at, revoked_at=NULL, \
                     certificate_der=excluded.certificate_der, server_name=excluded.server_name, \
                     control_address=excluded.control_address",
                params![
                    trusted.node_id,
                    trusted.fingerprint,
                    trusted.certificate_der,
                    trusted.server_name,
                    trusted.control_address
                ],
            )
            .map_err(database_error)?;
        transaction.commit().map_err(database_error)
    }

    /// 原子建立 Speed session；相同 ID 與完全相同 request 可安全重送。
    ///
    /// # Errors
    ///
    /// 欄位／JSON 無效、相同 ID 對應不同 request，或資料庫操作失敗時回傳錯誤。
    pub fn begin_speed_session(
        &mut self,
        request: &SpeedSessionPersistenceRequest<'_>,
    ) -> Result<(), NetToolError> {
        validate_speed_persistence(request)?;
        let configuration = serde_json::to_string(request.configuration).map_err(json_error)?;
        let transaction = self.connection.transaction().map_err(database_error)?;
        let existing = transaction
            .query_row(
                "SELECT remote_node, protocol, backend, direction, started_at, configuration_json \
                 FROM speed_session WHERE session_id=?1",
                [request.session_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                    ))
                },
            )
            .optional()
            .map_err(database_error)?;
        if let Some(existing) = existing {
            let expected = (
                request.remote_node_id,
                request.protocol,
                request.backend,
                request.direction,
                request.started_at,
                configuration.as_str(),
            );
            let actual = (
                existing.0.as_str(),
                existing.1.as_str(),
                existing.2.as_str(),
                existing.3.as_str(),
                existing.4.as_str(),
                existing.5.as_str(),
            );
            if actual == expected {
                return transaction.commit().map_err(database_error);
            }
            return Err(NetToolError::new(
                ErrorCode::OperationConflict,
                "speed session ID is already associated with a different request",
                false,
            ));
        }
        transaction
            .execute(
                "INSERT INTO speed_session(session_id, remote_node, protocol, backend, direction, \
                                           started_at, result_state, configuration_json) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'preparing', ?7)",
                params![
                    request.session_id,
                    request.remote_node_id,
                    request.protocol,
                    request.backend,
                    request.direction,
                    request.started_at,
                    configuration
                ],
            )
            .map_err(database_error)?;
        transaction.commit().map_err(database_error)
    }

    /// 將已完成雙端 barrier 的 session 從 preparing 轉為 running。
    ///
    /// # Errors
    ///
    /// Session 不存在、狀態不允許或資料庫操作失敗時回傳錯誤。
    pub fn mark_speed_session_running(&mut self, session_id: &str) -> Result<(), NetToolError> {
        validate_session_id(session_id)?;
        let changed = self
            .connection
            .execute(
                "UPDATE speed_session SET result_state='running' \
                 WHERE session_id=?1 AND result_state='preparing'",
                [session_id],
            )
            .map_err(database_error)?;
        if changed == 1 {
            return Ok(());
        }
        if speed_state(&self.connection, session_id)?.as_deref() == Some("running") {
            return Ok(());
        }
        Err(invalid_speed_state("running"))
    }

    /// 原子保存成功結果，只有 running session 可完成。
    ///
    /// # Errors
    ///
    /// Session 狀態、timestamp、result JSON 或資料庫操作無效時回傳錯誤。
    pub fn complete_speed_session(
        &mut self,
        session_id: &str,
        completed_at: &str,
        result: &Value,
    ) -> Result<(), NetToolError> {
        validate_session_id(session_id)?;
        validate_timestamp(completed_at)?;
        let result = serde_json::to_string(result).map_err(json_error)?;
        let changed = self
            .connection
            .execute(
                "UPDATE speed_session SET completed_at=?2, result_state='completed', result_json=?3 \
                 WHERE session_id=?1 AND result_state='running'",
                params![session_id, completed_at, result],
            )
            .map_err(database_error)?;
        if changed == 1 {
            return Ok(());
        }
        if speed_terminal_matches(
            &self.connection,
            session_id,
            "completed",
            completed_at,
            &result,
        )? {
            return Ok(());
        }
        Err(invalid_speed_state("completed"))
    }

    /// 保存 preparing/running session 的 failed 或 canceled terminal state。
    ///
    /// # Errors
    ///
    /// Terminal state、session、timestamp、detail JSON 或資料庫操作無效時回傳錯誤。
    pub fn terminate_speed_session(
        &mut self,
        session_id: &str,
        completed_at: &str,
        terminal_state: &str,
        detail: &Value,
    ) -> Result<(), NetToolError> {
        validate_session_id(session_id)?;
        validate_timestamp(completed_at)?;
        if !matches!(terminal_state, "failed" | "canceled") {
            return Err(invalid("speed terminal state must be failed or canceled"));
        }
        let detail = serde_json::to_string(detail).map_err(json_error)?;
        let changed = self
            .connection
            .execute(
                "UPDATE speed_session SET completed_at=?2, result_state=?3, result_json=?4 \
                 WHERE session_id=?1 AND result_state IN ('preparing', 'running')",
                params![session_id, completed_at, terminal_state, detail],
            )
            .map_err(database_error)?;
        if changed == 1 {
            return Ok(());
        }
        if speed_terminal_matches(
            &self.connection,
            session_id,
            terminal_state,
            completed_at,
            &detail,
        )? {
            return Ok(());
        }
        Err(invalid_speed_state(terminal_state))
    }

    /// 原子建立封包擷取 session；相同 ID 與完全相同 request 可安全重送。
    ///
    /// # Errors
    ///
    /// 欄位驗證失敗、session ID 衝突或 `SQLite` 寫入失敗時回傳錯誤。
    pub fn begin_packet_session(
        &mut self,
        request: &PacketSessionPersistenceRequest<'_>,
    ) -> Result<(), NetToolError> {
        validate_session_id(request.session_id)?;
        validate_nonempty(request.interface, "packet interface")?;
        validate_nonempty(request.backend, "packet backend")?;
        validate_nonempty(request.capture_mode, "capture mode")?;
        validate_nonempty(request.analysis_mode, "analysis mode")?;
        validate_timestamp(request.started_at)?;
        let existing = self
            .connection
            .query_row(
                "SELECT interface, backend, capture_mode, analysis_mode, started_at FROM packet_session WHERE session_id=?1",
                [request.session_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                },
            )
            .optional()
            .map_err(database_error)?;
        if let Some(existing) = existing {
            if existing
                == (
                    request.interface.to_owned(),
                    request.backend.to_owned(),
                    request.capture_mode.to_owned(),
                    request.analysis_mode.to_owned(),
                    request.started_at.to_owned(),
                )
            {
                return Ok(());
            }
            return Err(NetToolError::new(
                ErrorCode::OperationConflict,
                "packet session ID is already associated with a different request",
                false,
            ));
        }
        self.connection
            .execute(
                "INSERT INTO packet_session(session_id, interface, backend, capture_mode, analysis_mode, started_at, confidence, result_state) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'unknown', 'running')",
                params![
                    request.session_id,
                    request.interface,
                    request.backend,
                    request.capture_mode,
                    request.analysis_mode,
                    request.started_at
                ],
            )
            .map_err(database_error)?;
        Ok(())
    }

    /// 保存封包擷取 session 的完成或失敗終態。
    ///
    /// # Errors
    ///
    /// session 不存在、狀態已終結、timestamp/JSON 無效或 `SQLite` 操作失敗時回傳錯誤。
    pub fn complete_packet_session(
        &mut self,
        session_id: &str,
        completed_at: &str,
        state: &str,
        drops: &Value,
        confidence: &str,
    ) -> Result<(), NetToolError> {
        validate_session_id(session_id)?;
        validate_timestamp(completed_at)?;
        if !matches!(state, "completed" | "failed" | "canceled") {
            return Err(invalid("packet terminal state is invalid"));
        }
        validate_nonempty(confidence, "packet confidence")?;
        let drops = serde_json::to_string(drops).map_err(json_error)?;
        let changed = self
            .connection
            .execute(
                "UPDATE packet_session SET completed_at=?2, final_drop_counters_json=?3, confidence=?4, result_state=?5 WHERE session_id=?1 AND completed_at IS NULL",
                params![session_id, completed_at, drops, confidence, state],
            )
            .map_err(database_error)?;
        if changed == 1 {
            return Ok(());
        }
        let existing: Option<PacketSessionTerminal> = self
            .connection
            .query_row(
                "SELECT completed_at, final_drop_counters_json, confidence, result_state FROM packet_session WHERE session_id=?1",
                [session_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(database_error)?;
        if existing.as_ref().is_some_and(|value| {
            value.0.as_deref() == Some(completed_at)
                && value.1.as_deref() == Some(drops.as_str())
                && value.2.as_deref() == Some(confidence)
                && value.3 == state
        }) {
            return Ok(());
        }
        Err(invalid("packet session is not active"))
    }

    /// 讀取封包擷取 session 的完成狀態。
    ///
    /// # Errors
    ///
    /// session ID 無效或 `SQLite` 查詢失敗時回傳錯誤。
    pub fn packet_session_state(&self, session_id: &str) -> Result<Option<String>, NetToolError> {
        validate_session_id(session_id)?;
        self.connection
            .query_row(
                "SELECT result_state FROM packet_session WHERE session_id=?1",
                [session_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(database_error)
    }

    /// 以 operation ID 查詢已完成結果，用於冪等操作去重。
    ///
    /// # Errors
    ///
    /// `SQLite` 查詢失敗時回傳錯誤。
    pub fn operation_state(&self, operation_id: &str) -> Result<Option<String>, NetToolError> {
        self.connection
            .query_row(
                "SELECT state FROM operation WHERE operation_id = ?1",
                [operation_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(database_error)
    }

    /// 讀取 Speed session 的持久化終態，供 Agent recovery 與診斷使用。
    ///
    /// # Errors
    ///
    /// `SQLite` 查詢失敗時回傳錯誤。
    pub fn speed_session_state(&self, session_id: &str) -> Result<Option<String>, NetToolError> {
        validate_session_id(session_id)?;
        speed_state(&self.connection, session_id)
    }

    /// 取得 Speed session 對應的 paired remote Node ID。
    ///
    /// # Errors
    ///
    /// Session ID 無效或 `SQLite` 查詢失敗時回傳錯誤。
    pub fn speed_session_remote_node(
        &self,
        session_id: &str,
    ) -> Result<Option<String>, NetToolError> {
        validate_session_id(session_id)?;
        self.connection
            .query_row(
                "SELECT remote_node FROM speed_session WHERE session_id=?1",
                [session_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(database_error)
    }

    /// 讀取最近的 Speed session history；只回傳非敏感摘要。
    ///
    /// # Errors
    ///
    /// limit 無效或 `SQLite` 查詢失敗時回傳錯誤。
    pub fn list_speed_sessions(
        &self,
        limit: u32,
    ) -> Result<Vec<SpeedSessionSummary>, NetToolError> {
        if limit == 0 || limit > 10_000 {
            return Err(invalid("speed history limit must be between 1 and 10000"));
        }
        let mut statement = self
            .connection
            .prepare(
                "SELECT session_id, remote_node, protocol, backend, direction, started_at, completed_at, result_state FROM speed_session ORDER BY started_at DESC, session_id DESC LIMIT ?1",
            )
            .map_err(database_error)?;
        let rows = statement
            .query_map([i64::from(limit)], |row| {
                Ok(SpeedSessionSummary {
                    session_id: row.get(0)?,
                    remote_node: row.get(1)?,
                    protocol: row.get(2)?,
                    backend: row.get(3)?,
                    direction: row.get(4)?,
                    started_at: row.get(5)?,
                    completed_at: row.get(6)?,
                    state: row.get(7)?,
                })
            })
            .map_err(database_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(database_error)
    }

    /// 記錄 Action operation 的初始狀態。
    ///
    /// # Errors
    ///
    /// operation ID 衝突或 `SQLite` 寫入失敗時回傳錯誤。
    pub fn begin_operation(&self, operation_id: &str, action: &str) -> Result<(), NetToolError> {
        self.connection.execute("INSERT INTO operation(operation_id, action, state, created_at) VALUES (?1, ?2, 'pending', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))", params![operation_id, action]).map_err(database_error)?;
        Ok(())
    }

    /// 重新評估並以單一 transaction 保存 environment、result 與可選 certification。
    ///
    /// Caller 不能直接提交 `Certified100G` 字串；只有 evaluator 在完整 policy/evidence
    /// 下回傳 Certified 才會建立 `hardware_certification` row。
    ///
    /// # Errors
    ///
    /// ID/timestamp 無效、environment/policy 不完整、序列化、constraint 或 transaction 失敗時回傳錯誤。
    pub fn persist_benchmark(
        &mut self,
        request: &BenchmarkPersistenceRequest<'_>,
    ) -> Result<PersistedBenchmark, NetToolError> {
        validate_benchmark_request(request)?;
        let hardware_profile_hash = request.environment.certification_key()?;
        let outcome =
            evaluate_certification(request.environment, request.evidence, request.policy)?;
        let environment_json = serde_json::to_string(request.environment).map_err(json_error)?;
        let configuration_json =
            serde_json::to_string(request.configuration).map_err(json_error)?;
        let result_json = serde_json::to_string(&outcome).map_err(json_error)?;
        let certification_state = support_state(outcome.support_level).to_owned();
        let checksum = benchmark_checksum(
            request,
            &hardware_profile_hash,
            &configuration_json,
            &result_json,
        );
        let certified = outcome.support_level == Some(SupportLevel::Certified100G);
        let transaction = self.connection.transaction().map_err(database_error)?;
        transaction
            .execute(
                "INSERT INTO hardware_profile(id, profile_json, profile_hash, created_at) VALUES (?1, ?2, ?3, ?4) ON CONFLICT(id) DO NOTHING",
                params![
                    request.hardware_profile_id,
                    environment_json,
                    hardware_profile_hash,
                    request.created_at
                ],
            )
            .map_err(database_error)?;
        let stored_hash: String = transaction
            .query_row(
                "SELECT profile_hash FROM hardware_profile WHERE id = ?1",
                [request.hardware_profile_id],
                |row| row.get(0),
            )
            .map_err(database_error)?;
        if stored_hash != hardware_profile_hash {
            return Err(NetToolError::new(
                ErrorCode::OperationConflict,
                "hardware profile ID is already bound to another platform combination",
                false,
            ));
        }
        transaction
            .execute(
                "INSERT INTO benchmark_result(id, hardware_profile_id, software_build, configuration_json, result_json, certification_state, checksum, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    request.benchmark_result_id,
                    request.hardware_profile_id,
                    request.software_build,
                    configuration_json,
                    result_json,
                    certification_state,
                    checksum,
                    request.created_at
                ],
            )
            .map_err(database_error)?;
        if certified {
            let certification_id = request.certification_id.ok_or_else(|| {
                NetToolError::new(
                    ErrorCode::InvalidArgument,
                    "certified benchmark requires a certification ID",
                    false,
                )
            })?;
            transaction
                .execute(
                    "INSERT INTO hardware_certification(id, hardware_profile_id, software_profile, result, benchmark_result_id, certified_at) VALUES (?1, ?2, ?3, '100g_certified', ?4, ?5)",
                    params![
                        certification_id,
                        request.hardware_profile_id,
                        request.software_build,
                        request.benchmark_result_id,
                        request.created_at
                    ],
                )
                .map_err(database_error)?;
        }
        transaction.commit().map_err(database_error)?;
        Ok(PersistedBenchmark {
            benchmark_result_id: request.benchmark_result_id.to_owned(),
            hardware_profile_hash,
            checksum,
            certification_state,
            certification_created: certified,
        })
    }

    /// 讀取 benchmark 的 certification state。
    ///
    /// # Errors
    ///
    /// `SQLite` 查詢失敗時回傳錯誤。
    pub fn benchmark_certification_state(
        &self,
        benchmark_result_id: &str,
    ) -> Result<Option<String>, NetToolError> {
        self.connection
            .query_row(
                "SELECT certification_state FROM benchmark_result WHERE id = ?1",
                [benchmark_result_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(database_error)
    }

    /// 回傳 hardware certification rows，供 invariant 測試與管理介面使用。
    ///
    /// # Errors
    ///
    /// `SQLite` 查詢失敗時回傳錯誤。
    pub fn hardware_certification_count(&self) -> Result<u64, NetToolError> {
        self.connection
            .query_row("SELECT COUNT(*) FROM hardware_certification", [], |row| {
                row.get(0)
            })
            .map_err(database_error)
    }
}

fn validate_benchmark_request(
    request: &BenchmarkPersistenceRequest<'_>,
) -> Result<(), NetToolError> {
    for (name, value) in [
        ("hardware profile ID", request.hardware_profile_id),
        ("benchmark result ID", request.benchmark_result_id),
        ("software build", request.software_build),
        ("created_at", request.created_at),
    ] {
        if value.trim().is_empty() || value.len() > 512 {
            return Err(NetToolError::new(
                ErrorCode::InvalidArgument,
                format!("{name} is empty or too long"),
                false,
            ));
        }
    }
    if request
        .certification_id
        .is_some_and(|value| value.trim().is_empty() || value.len() > 512)
    {
        return Err(NetToolError::new(
            ErrorCode::InvalidArgument,
            "certification ID is empty or too long",
            false,
        ));
    }
    Ok(())
}

fn support_state(level: Option<SupportLevel>) -> &'static str {
    match level {
        None => "unsupported",
        Some(SupportLevel::Functional) => "functional",
        Some(SupportLevel::Validated) => "validated",
        Some(SupportLevel::Certified100G) => "100g_certified",
    }
}

fn benchmark_checksum(
    request: &BenchmarkPersistenceRequest<'_>,
    hardware_profile_hash: &str,
    configuration_json: &str,
    result_json: &str,
) -> String {
    let mut digest = Sha256::new();
    for value in [
        request.benchmark_result_id,
        request.software_build,
        hardware_profile_hash,
        configuration_json,
        result_json,
    ] {
        digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
        digest.update(value.as_bytes());
    }
    let mut checksum = String::with_capacity(64);
    for byte in digest.finalize() {
        let _ = write!(checksum, "{byte:02x}");
    }
    checksum
}

#[allow(clippy::needless_pass_by_value)]
fn json_error(error: serde_json::Error) -> NetToolError {
    NetToolError::new(
        ErrorCode::StorageFailed,
        format!("benchmark JSON serialization failed: {error}"),
        false,
    )
}

#[allow(clippy::needless_pass_by_value)]
fn database_error(error: rusqlite::Error) -> NetToolError {
    NetToolError::new(
        ErrorCode::StorageFailed,
        format!("SQLite operation failed: {error}"),
        false,
    )
}

fn validate_trusted_connection(trusted: &TrustedNodeConnection<'_>) -> Result<(), NetToolError> {
    if !trusted.out_of_band_fingerprint_confirmed {
        return Err(NetToolError::new(
            ErrorCode::NodeTlsFailed,
            "out-of-band fingerprint verification is required before pairing",
            false,
        ));
    }
    if trusted.node_id.len() != 32 || !trusted.node_id.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(invalid("trusted Node ID must be 128-bit hexadecimal"));
    }
    if trusted.name.trim().is_empty() || trusted.name.len() > 255 {
        return Err(invalid("trusted Node name is empty or too long"));
    }
    if trusted.server_name.trim().is_empty() || trusted.server_name.len() > 253 {
        return Err(invalid("trusted Node TLS server name is invalid"));
    }
    trusted
        .control_address
        .parse::<SocketAddr>()
        .map_err(|_| invalid("trusted Node control address must include an IP and port"))?;
    let presented = public_key_fingerprint(trusted.certificate_der)?;
    if !presented.eq_ignore_ascii_case(trusted.fingerprint) {
        return Err(NetToolError::new(
            ErrorCode::NodeTlsFailed,
            "trusted Node certificate does not match the confirmed fingerprint",
            false,
        ));
    }
    Ok(())
}

fn trusted_node_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<TrustedNodeSummary> {
    Ok(TrustedNodeSummary {
        id: row.get(0)?,
        name: row.get(1)?,
        last_address: row.get(2)?,
        fingerprint: row.get(3)?,
        certificate_der: row.get(4)?,
        server_name: row.get(5)?,
        control_address: row.get(6)?,
    })
}

fn validate_speed_persistence(
    request: &SpeedSessionPersistenceRequest<'_>,
) -> Result<(), NetToolError> {
    validate_session_id(request.session_id)?;
    if request.remote_node_id.len() != 32
        || !request
            .remote_node_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(invalid("speed remote Node ID must be 128-bit hexadecimal"));
    }
    for (name, value) in [
        ("protocol", request.protocol),
        ("backend", request.backend),
        ("direction", request.direction),
    ] {
        if value.trim().is_empty() || value.len() > 64 {
            return Err(NetToolError::new(
                ErrorCode::InvalidArgument,
                format!("speed {name} is empty or too long"),
                false,
            ));
        }
    }
    validate_timestamp(request.started_at)
}

fn validate_session_id(session_id: &str) -> Result<(), NetToolError> {
    if session_id.len() != 32 || !session_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid("speed session ID must be 128-bit hexadecimal"));
    }
    if session_id.bytes().all(|byte| byte == b'0') {
        return Err(invalid("speed session ID must not be zero"));
    }
    Ok(())
}

fn validate_timestamp(timestamp: &str) -> Result<(), NetToolError> {
    if timestamp.trim().is_empty() || timestamp.len() > 64 {
        return Err(invalid("speed session timestamp is empty or too long"));
    }
    Ok(())
}

fn validate_nonempty(value: &str, field: &str) -> Result<(), NetToolError> {
    if value.trim().is_empty() || value.len() > 256 {
        return Err(NetToolError::new(
            ErrorCode::InvalidArgument,
            format!("{field} is empty or too long"),
            false,
        ));
    }
    Ok(())
}

fn speed_state(connection: &Connection, session_id: &str) -> Result<Option<String>, NetToolError> {
    connection
        .query_row(
            "SELECT result_state FROM speed_session WHERE session_id=?1",
            [session_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(database_error)
}

fn speed_terminal_matches(
    connection: &Connection,
    session_id: &str,
    state: &str,
    completed_at: &str,
    result_json: &str,
) -> Result<bool, NetToolError> {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM speed_session \
             WHERE session_id=?1 AND result_state=?2 AND completed_at=?3 AND result_json=?4)",
            params![session_id, state, completed_at, result_json],
            |row| row.get(0),
        )
        .map_err(database_error)
}

fn invalid_speed_state(target: &str) -> NetToolError {
    NetToolError::new(
        ErrorCode::InvalidState,
        format!("speed session cannot transition to {target} from its current state"),
        false,
    )
}

fn public_key_fingerprint(certificate_der: &[u8]) -> Result<String, NetToolError> {
    let (remaining, certificate) =
        x509_parser::parse_x509_certificate(certificate_der).map_err(|error| {
            NetToolError::new(
                ErrorCode::NodeTlsFailed,
                format!("trusted Node certificate is invalid: {error}"),
                false,
            )
        })?;
    if !remaining.is_empty() {
        return Err(NetToolError::new(
            ErrorCode::NodeTlsFailed,
            "trusted Node certificate contains trailing data",
            false,
        ));
    }
    Ok(Sha256::digest(certificate.public_key().raw)
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":"))
}

fn invalid(message: &'static str) -> NetToolError {
    NetToolError::new(ErrorCode::InvalidArgument, message, false)
}

fn validate_profile_identity(id: &str, name: &str) -> Result<(), NetToolError> {
    if id.trim().is_empty() || id.len() > 128 || id.chars().any(char::is_control) {
        return Err(invalid(
            "profile ID is empty, too long, or contains control characters",
        ));
    }
    if name.trim().is_empty() || name.len() > 256 || name.chars().any(char::is_control) {
        return Err(invalid(
            "profile name is empty, too long, or contains control characters",
        ));
    }
    Ok(())
}

fn hex_digest(bytes: &[u8]) -> String {
    let mut digest = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        let _ = write!(digest, "{byte:02x}");
    }
    digest
}

#[cfg(test)]
mod tests {
    use super::{BenchmarkPersistenceRequest, PacketSessionPersistenceRequest, Storage};
    use nettool_benchmark::{
        AnalyzerLoadEvidence, BenchmarkDrops, BenchmarkEnvironmentSnapshot, CertificationEvidence,
        CertificationPolicy, CpuEvidence, RxBaselineEvidence, StabilityEvidence, ThermalEvidence,
        TxBaselineEvidence,
    };
    use serde_json::json;

    #[test]
    fn initial_migration_creates_expected_schema() {
        let storage = Storage::in_memory().expect("in-memory migration should succeed");
        assert_eq!(
            storage
                .schema_version()
                .expect("schema version should be readable"),
            3
        );
        assert!(
            storage
                .list_profiles()
                .expect("profile query should succeed")
                .is_empty()
        );
    }

    #[test]
    fn operation_ids_are_unique() {
        let storage = Storage::in_memory().expect("in-memory migration should succeed");
        storage
            .begin_operation("operation-1", "profile.apply")
            .expect("first operation should succeed");
        assert!(
            storage
                .begin_operation("operation-1", "profile.apply")
                .is_err()
        );
    }

    #[test]
    fn packet_session_lifecycle_is_persistent_and_idempotent() {
        let mut storage = Storage::in_memory().expect("storage");
        let request = PacketSessionPersistenceRequest {
            session_id: "00112233445566778899aabbccddeeff",
            interface: "0000:01:00.0",
            backend: "dpdk",
            capture_mode: "full_packet",
            analysis_mode: "full",
            started_at: "2026-08-22T00:00:00Z",
        };
        storage.begin_packet_session(&request).expect("begin");
        storage.begin_packet_session(&request).expect("retry");
        assert_eq!(
            storage
                .packet_session_state(request.session_id)
                .expect("state")
                .as_deref(),
            Some("running")
        );
        storage
            .complete_packet_session(
                request.session_id,
                "2026-08-22T00:00:01Z",
                "completed",
                &json!({"capture":0}),
                "medium",
            )
            .expect("complete");
        assert_eq!(
            storage
                .packet_session_state(request.session_id)
                .expect("state")
                .as_deref(),
            Some("completed")
        );
    }

    #[test]
    fn packet_session_canceled_state_is_persistent() {
        let mut storage = Storage::in_memory().expect("storage");
        let request = PacketSessionPersistenceRequest {
            session_id: "11223344556677889900aabbccddeeff",
            interface: "eth0",
            backend: "socket",
            capture_mode: "metadata",
            analysis_mode: "basic",
            started_at: "2026-08-22T00:00:00Z",
        };
        storage.begin_packet_session(&request).expect("begin");
        storage
            .complete_packet_session(
                request.session_id,
                "2026-08-22T00:00:01Z",
                "canceled",
                &json!({"capture": 1}),
                "low",
            )
            .expect("cancel");
        assert_eq!(
            storage
                .packet_session_state(request.session_id)
                .expect("state")
                .as_deref(),
            Some("canceled")
        );
    }

    #[test]
    fn speed_history_returns_bounded_non_sensitive_summary() {
        let mut storage = Storage::in_memory().expect("storage");
        let configuration = json!({"secret":"must not be returned"});
        storage
            .begin_speed_session(&super::SpeedSessionPersistenceRequest {
                session_id: "00112233445566778899aabbccddeeff",
                remote_node_id: "ffeeddccbbaa99887766554433221100",
                protocol: "TCP_SOCKET",
                backend: "socket",
                direction: "A_TO_B",
                started_at: "2026-08-22T00:00:00Z",
                configuration: &configuration,
            })
            .expect("session");
        let history = storage.list_speed_sessions(10).expect("history");
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].protocol, "TCP_SOCKET");
        assert_eq!(history[0].state, "preparing");
    }

    #[test]
    fn profile_crud_preserves_revision_and_checksum() {
        let mut storage = Storage::in_memory().expect("storage");
        let configuration = json!({"version":1,"interface":"eth0","ipv4":{"mode":"dhcp"}});
        let summary = storage
            .create_profile("lab", "Lab", &configuration, "2026-08-21T00:00:00Z")
            .expect("create");
        assert_eq!(summary.active_revision, 1);
        assert_eq!(storage.list_profiles().expect("list").len(), 1);
        assert_eq!(
            storage
                .get_profile("Lab")
                .expect("get")
                .expect("document")
                .configuration,
            configuration
        );
        let updated = json!({"version":2,"interface":"eth1","ipv4":{"mode":"dhcp"}});
        let revised = storage
            .update_profile("lab", "Lab Updated", &updated, "2026-08-22T00:00:00Z")
            .expect("update");
        assert_eq!(revised.active_revision, 2);
        assert_eq!(
            storage
                .get_profile("Lab Updated")
                .expect("get revised")
                .expect("revised document")
                .configuration,
            updated
        );
        assert!(
            storage
                .create_profile("lab", "Other", &json!({}), "2026-08-21T00:00:00Z")
                .is_err()
        );
        storage.delete_profile("lab").expect("delete");
        assert!(storage.list_profiles().expect("list").is_empty());
    }

    #[test]
    fn resolves_only_trusted_nodes_and_rejects_ambiguous_names() {
        use rcgen::{CertifiedKey, generate_simple_self_signed};

        let mut storage = Storage::in_memory().expect("storage");
        let CertifiedKey { cert, .. } =
            generate_simple_self_signed(vec!["peer.local".to_owned()]).expect("certificate");
        let fingerprint = super::public_key_fingerprint(cert.der()).expect("fingerprint");
        for (index, id) in [
            "0000000000000000000000000000000a",
            "0000000000000000000000000000000b",
            "0000000000000000000000000000000c",
        ]
        .into_iter()
        .enumerate()
        {
            storage
                .trust_node_connection(&super::TrustedNodeConnection {
                    node_id: id,
                    name: "peer",
                    control_address: &format!("192.0.2.1:{}", 50_000 + index),
                    server_name: "peer.local",
                    certificate_der: cert.der(),
                    fingerprint: &fingerprint,
                    out_of_band_fingerprint_confirmed: true,
                    identity_change_confirmed: false,
                })
                .expect("trust");
        }
        storage
            .revoke_trusted_node("0000000000000000000000000000000c")
            .expect("revoke");
        assert_eq!(storage.list_trusted_nodes().expect("list").len(), 2);
        assert!(
            storage
                .resolve_trusted_node_by_fingerprint(&fingerprint)
                .is_err()
        );
        assert!(storage.resolve_trusted_node("peer").is_err());
        assert_eq!(
            storage
                .resolve_trusted_node("0000000000000000000000000000000a")
                .expect("lookup")
                .expect("trusted")
                .id,
            "0000000000000000000000000000000a"
        );
        assert!(
            storage
                .resolve_trusted_node("0000000000000000000000000000000c")
                .expect("lookup")
                .is_none()
        );
    }

    #[test]
    fn rejects_trust_record_when_certificate_fingerprint_differs() {
        use rcgen::{CertifiedKey, generate_simple_self_signed};

        let mut storage = Storage::in_memory().expect("storage");
        let CertifiedKey { cert, .. } =
            generate_simple_self_signed(vec!["peer.local".to_owned()]).expect("certificate");
        let result = storage.trust_node_connection(&super::TrustedNodeConnection {
            node_id: "0000000000000000000000000000000a",
            name: "peer",
            control_address: "192.0.2.1:50000",
            server_name: "peer.local",
            certificate_der: cert.der(),
            fingerprint: "00:11",
            out_of_band_fingerprint_confirmed: true,
            identity_change_confirmed: false,
        });
        assert!(result.is_err());
    }

    #[test]
    fn rejects_pairing_without_out_of_band_fingerprint_confirmation() {
        use rcgen::{CertifiedKey, generate_simple_self_signed};

        let mut storage = Storage::in_memory().expect("storage");
        let CertifiedKey { cert, .. } =
            generate_simple_self_signed(vec!["peer.local".to_owned()]).expect("certificate");
        let fingerprint = super::public_key_fingerprint(cert.der()).expect("fingerprint");
        let error = storage
            .trust_node_connection(&super::TrustedNodeConnection {
                node_id: "0000000000000000000000000000000a",
                name: "peer",
                control_address: "192.0.2.1:50000",
                server_name: "peer.local",
                certificate_der: cert.der(),
                fingerprint: &fingerprint,
                out_of_band_fingerprint_confirmed: false,
                identity_change_confirmed: false,
            })
            .expect_err("unconfirmed pairing must fail closed");
        assert_eq!(error.code, nettool_error::ErrorCode::NodeTlsFailed);
    }

    #[test]
    fn identity_change_requires_explicit_re_pair_confirmation() {
        use rcgen::{CertifiedKey, generate_simple_self_signed};

        let mut storage = Storage::in_memory().expect("storage");
        let CertifiedKey { cert: first, .. } =
            generate_simple_self_signed(vec!["peer.local".to_owned()]).expect("first");
        let CertifiedKey { cert: second, .. } =
            generate_simple_self_signed(vec!["peer.local".to_owned()]).expect("second");
        let first_fingerprint = super::public_key_fingerprint(first.der()).expect("fingerprint");
        let second_fingerprint = super::public_key_fingerprint(second.der()).expect("fingerprint");
        let base = super::TrustedNodeConnection {
            node_id: "0000000000000000000000000000000a",
            name: "peer",
            control_address: "192.0.2.1:50000",
            server_name: "peer.local",
            certificate_der: first.der(),
            fingerprint: &first_fingerprint,
            out_of_band_fingerprint_confirmed: true,
            identity_change_confirmed: false,
        };
        storage.trust_node_connection(&base).expect("first trust");
        let changed = super::TrustedNodeConnection {
            certificate_der: second.der(),
            fingerprint: &second_fingerprint,
            ..base
        };
        assert!(storage.trust_node_connection(&changed).is_err());
        storage
            .trust_node_connection(&super::TrustedNodeConnection {
                identity_change_confirmed: true,
                ..changed
            })
            .expect("explicit re-pair");
    }

    #[test]
    fn speed_session_persistence_is_idempotent_and_state_checked() {
        let mut storage = Storage::in_memory().expect("storage");
        let configuration = json!({"protocol":"tcp","streams":2});
        let request = super::SpeedSessionPersistenceRequest {
            session_id: "0000000000000000000000000000000a",
            remote_node_id: "0000000000000000000000000000000b",
            protocol: "TCP_SOCKET",
            backend: "socket",
            direction: "A_TO_B",
            started_at: "2026-08-19T12:00:00Z",
            configuration: &configuration,
        };
        storage.begin_speed_session(&request).expect("begin");
        storage.begin_speed_session(&request).expect("begin retry");
        assert_eq!(
            storage
                .speed_session_state(request.session_id)
                .expect("preparing state"),
            Some("preparing".to_owned())
        );
        assert_eq!(
            storage
                .speed_session_remote_node(request.session_id)
                .expect("remote node"),
            Some(request.remote_node_id.to_owned())
        );
        storage
            .mark_speed_session_running(request.session_id)
            .expect("running");
        storage
            .mark_speed_session_running(request.session_id)
            .expect("running retry");
        let result = json!({"transferred_bytes":1024,"elapsed_nanoseconds":1000});
        storage
            .complete_speed_session(request.session_id, "2026-08-19T12:00:10Z", &result)
            .expect("complete");
        storage
            .complete_speed_session(request.session_id, "2026-08-19T12:00:10Z", &result)
            .expect("complete retry");
        assert_eq!(
            storage
                .speed_session_state(request.session_id)
                .expect("completed state"),
            Some("completed".to_owned())
        );
        assert!(
            storage
                .terminate_speed_session(
                    request.session_id,
                    "2026-08-19T12:00:11Z",
                    "failed",
                    &json!({"code":"late"}),
                )
                .is_err()
        );
    }

    #[test]
    fn speed_session_id_reuse_with_different_request_is_rejected() {
        let mut storage = Storage::in_memory().expect("storage");
        let first_configuration = json!({"protocol":"tcp"});
        let second_configuration = json!({"protocol":"udp"});
        let first = super::SpeedSessionPersistenceRequest {
            session_id: "0000000000000000000000000000000a",
            remote_node_id: "0000000000000000000000000000000b",
            protocol: "TCP_SOCKET",
            backend: "socket",
            direction: "A_TO_B",
            started_at: "2026-08-19T12:00:00Z",
            configuration: &first_configuration,
        };
        storage.begin_speed_session(&first).expect("first");
        assert!(
            storage
                .begin_speed_session(&super::SpeedSessionPersistenceRequest {
                    protocol: "UDP_SOCKET",
                    configuration: &second_configuration,
                    ..first
                })
                .is_err()
        );
    }

    #[test]
    fn failed_speed_session_can_be_retried_but_not_completed() {
        let mut storage = Storage::in_memory().expect("storage");
        let configuration = json!({"protocol":"udp"});
        let request = super::SpeedSessionPersistenceRequest {
            session_id: "0000000000000000000000000000000a",
            remote_node_id: "0000000000000000000000000000000b",
            protocol: "UDP_SOCKET",
            backend: "socket",
            direction: "A_TO_B",
            started_at: "2026-08-19T12:00:00Z",
            configuration: &configuration,
        };
        storage.begin_speed_session(&request).expect("begin");
        let detail = json!({"code":"NODE.TRANSPORT_FAILED"});
        for _ in 0..2 {
            storage
                .terminate_speed_session(
                    request.session_id,
                    "2026-08-19T12:00:01Z",
                    "failed",
                    &detail,
                )
                .expect("failure retry");
        }
        assert!(
            storage
                .mark_speed_session_running(request.session_id)
                .is_err()
        );
    }

    #[test]
    fn benchmark_without_policy_is_persisted_but_never_certified() {
        let mut storage = Storage::in_memory().expect("store");
        let environment = environment();
        let evidence = evidence();
        let configuration = json!({"profile":"100g-cert"});
        let persisted = storage
            .persist_benchmark(&BenchmarkPersistenceRequest {
                hardware_profile_id: "hardware-1",
                benchmark_result_id: "benchmark-1",
                certification_id: None,
                software_build: "build-1",
                configuration: &configuration,
                environment: &environment,
                evidence: &evidence,
                policy: None,
                created_at: "2026-08-15T00:00:00Z",
            })
            .expect("persist");
        assert_eq!(persisted.certification_state, "validated");
        assert!(!persisted.certification_created);
        assert_eq!(persisted.checksum.len(), 64);
        assert_eq!(storage.hardware_certification_count().expect("count"), 0);
    }

    #[test]
    fn certified_insert_is_atomic_and_requires_certification_id() {
        let mut storage = Storage::in_memory().expect("store");
        let environment = environment();
        let evidence = evidence();
        let configuration = json!({"profile":"100g-cert"});
        let mut request = BenchmarkPersistenceRequest {
            hardware_profile_id: "hardware-1",
            benchmark_result_id: "benchmark-1",
            certification_id: None,
            software_build: "build-1",
            configuration: &configuration,
            environment: &environment,
            evidence: &evidence,
            policy: Some(policy()),
            created_at: "2026-08-15T00:00:00Z",
        };
        assert!(storage.persist_benchmark(&request).is_err());
        assert_eq!(
            storage
                .benchmark_certification_state("benchmark-1")
                .expect("state"),
            None
        );
        request.certification_id = Some("certification-1");
        let persisted = storage.persist_benchmark(&request).expect("certified");
        assert_eq!(persisted.certification_state, "100g_certified");
        assert!(persisted.certification_created);
        assert_eq!(storage.hardware_certification_count().expect("count"), 1);
    }

    fn environment() -> BenchmarkEnvironmentSnapshot {
        BenchmarkEnvironmentSnapshot {
            os: Some("linux".to_owned()),
            kernel: Some("6.x".to_owned()),
            cpu: Some("cpu".to_owned()),
            cpu_frequency: Some("3GHz".to_owned()),
            numa: Some("node0".to_owned()),
            memory: Some("128GiB".to_owned()),
            huge_pages: Some("1GiB x 8".to_owned()),
            nic: Some("100GbE NIC".to_owned()),
            pcie: Some("Gen4 x16".to_owned()),
            firmware: Some("1.0".to_owned()),
            driver: Some("driver-1".to_owned()),
            dpdk_version: Some("24.11".to_owned()),
            backend: Some("dpdk".to_owned()),
            mtu: Some(1500),
            rx_queues: Some(4),
            tx_queues: Some(4),
            rss: Some("enabled".to_owned()),
            offloads: Some("none".to_owned()),
        }
    }

    fn evidence() -> CertificationEvidence {
        CertificationEvidence {
            functional: true,
            general_validation_completed: true,
            link_speed_mbps: Some(100_000),
            numa_locality_valid: Some(true),
            rss_active: Some(true),
            rx_queue_distribution_valid: Some(true),
            rx_baseline: Some(RxBaselineEvidence {
                bits_per_second: 95_000_000_000,
                packets_per_second: 10_000_000,
                nic_drops: 0,
                application_drops: 0,
                cpu_basis_points: 7000,
            }),
            tx_baseline: Some(TxBaselineEvidence {
                bits_per_second: 95_000_000_000,
                packets_per_second: 10_000_000,
                cpu_basis_points: 7000,
                tx_errors: 0,
                queue_utilization_basis_points: 8000,
            }),
            bidirectional_bits_per_second: Some(95_000_000_000),
            drops: Some(BenchmarkDrops {
                nic: 0,
                capture: 0,
                ring: 0,
                analyzer: 0,
            }),
            cpu: Some(CpuEvidence {
                total_cpu_basis_points: 8000,
                data_plane_cores: 4,
                bits_per_second_per_core: 25_000_000_000,
                packets_per_second_per_core: 10_000_000,
            }),
            stability: Some(StabilityEvidence {
                short_duration_seconds: 60,
                sustained_duration_seconds: 3600,
                repeated_throughput_bits_per_second: vec![
                    95_000_000_000,
                    95_100_000_000,
                    95_050_000_000,
                ],
            }),
            thermal: Some(ThermalEvidence {
                cpu_frequency_start: "3GHz".to_owned(),
                cpu_frequency_minimum: "3GHz".to_owned(),
                nic_state: "normal".to_owned(),
                thermal_throttling: false,
            }),
            analyzer_loads: vec![
                AnalyzerLoadEvidence {
                    frame_bytes: 64,
                    throughput_bits_per_second: 90_000_000_000,
                    analyzer_drops: 0,
                },
                AnalyzerLoadEvidence {
                    frame_bytes: 1518,
                    throughput_bits_per_second: 90_000_000_000,
                    analyzer_drops: 0,
                },
            ],
        }
    }

    fn policy() -> CertificationPolicy {
        CertificationPolicy {
            minimum_throughput_bits_per_second: 90_000_000_000,
            maximum_drops: BenchmarkDrops {
                nic: 0,
                capture: 0,
                ring: 0,
                analyzer: 0,
            },
            minimum_short_duration_seconds: 60,
            minimum_sustained_duration_seconds: 3600,
            minimum_repetitions: 3,
            maximum_reproducibility_spread_ppm: 2_000,
            minimum_analyzer_throughput_bits_per_second: 80_000_000_000,
            maximum_analyzer_drops: 0,
            allow_thermal_throttling_condition: false,
        }
    }
}

//! Agent-owned hardware/runtime Resource Manager。

#![forbid(unsafe_code)]

use nettool_error::{ErrorCode, NetToolError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::{Display, Formatter};

/// 可被 session reservation 使用的資源識別字。
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(tag = "kind", content = "identity", rename_all = "snake_case")]
pub enum ResourceKey {
    /// DPDK physical port，永遠 exclusive。
    DpdkPort(String),
    /// DPDK RX queue，永遠 exclusive。
    DpdkRxQueue {
        /// NIC PCI address。
        pci_address: String,
        /// RX queue index。
        queue: u16,
    },
    /// DPDK TX queue，永遠 exclusive。
    DpdkTxQueue {
        /// NIC PCI address。
        pci_address: String,
        /// TX queue index。
        queue: u16,
    },
    /// Pinned data-plane CPU，永遠 exclusive。
    PinnedCpu(u32),
    /// NUMA-local memory budget，依 configured capacity 分享。
    NumaMemory(u32),
    /// 指定大小的 Huge Page pool，依 configured capacity 分享。
    HugePages {
        /// NUMA node。
        numa_node: u32,
        /// 單一 page 大小，單位為 KiB。
        page_size_kib: u64,
    },
    /// Lossless capture writer，永遠 exclusive。
    LosslessCaptureWriter(String),
    /// Capture storage bytes budget。
    CaptureStorage(String),
    /// Dynamic TCP/UDP port，永遠 exclusive。
    DataPort {
        /// `tcp` 或 `udp`。
        protocol: String,
        /// Bind address。
        address: String,
        /// Port number。
        port: u16,
    },
    /// Management interface，可 shared。
    ManagementInterface(String),
    /// Database runtime，可 shared。
    Database,
    /// 唯讀介面統計，可 shared。
    ReadOnlyInterfaceStatistics(String),
}

impl ResourceKey {
    /// 回傳此資源是否依規格強制 exclusive。
    #[must_use]
    pub const fn requires_exclusive(&self) -> bool {
        matches!(
            self,
            Self::DpdkPort(_)
                | Self::DpdkRxQueue { .. }
                | Self::DpdkTxQueue { .. }
                | Self::PinnedCpu(_)
                | Self::LosslessCaptureWriter(_)
                | Self::DataPort { .. }
        )
    }

    /// 回傳 shared claim 是否必須先設定有限 capacity。
    #[must_use]
    pub const fn requires_capacity(&self) -> bool {
        matches!(
            self,
            Self::NumaMemory(_) | Self::HugePages { .. } | Self::CaptureStorage(_)
        )
    }
}

impl Display for ResourceKey {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DpdkPort(pci) => write!(formatter, "dpdk-port:{pci}"),
            Self::DpdkRxQueue { pci_address, queue } => {
                write!(formatter, "dpdk-rx-queue:{pci_address}:{queue}")
            }
            Self::DpdkTxQueue { pci_address, queue } => {
                write!(formatter, "dpdk-tx-queue:{pci_address}:{queue}")
            }
            Self::PinnedCpu(cpu) => write!(formatter, "pinned-cpu:{cpu}"),
            Self::NumaMemory(node) => write!(formatter, "numa-memory:{node}"),
            Self::HugePages {
                numa_node,
                page_size_kib,
            } => write!(formatter, "huge-pages:{numa_node}:{page_size_kib}KiB"),
            Self::LosslessCaptureWriter(path) => {
                write!(formatter, "lossless-capture-writer:{path}")
            }
            Self::CaptureStorage(path) => write!(formatter, "capture-storage:{path}"),
            Self::DataPort {
                protocol,
                address,
                port,
            } => write!(formatter, "data-port:{protocol}:{address}:{port}"),
            Self::ManagementInterface(interface) => {
                write!(formatter, "management-interface:{interface}")
            }
            Self::Database => formatter.write_str("database"),
            Self::ReadOnlyInterfaceStatistics(interface) => {
                write!(formatter, "read-only-interface-statistics:{interface}")
            }
        }
    }
}

/// Reservation 對資源的使用模式。
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceMode {
    /// 不能與任何其他 owner 共用。
    Exclusive,
    /// 可與 shared claims 共存，並受 capacity 限制。
    Shared,
}

impl ResourceMode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Exclusive => "exclusive",
            Self::Shared => "shared",
        }
    }
}

/// 單一 reservation claim。
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResourceClaim {
    /// Resource key。
    pub resource: ResourceKey,
    /// Exclusive 或 shared。
    pub mode: ResourceMode,
    /// Capacity units；exclusive 必須為 `1`。
    pub units: u64,
}

/// 建立 reservation 的完整 request，用於冪等比較。
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReservationRequest {
    /// Reservation ID。
    pub reservation_id: String,
    /// Owner session ID。
    pub session_id: String,
    /// 必須原子取得的全部 claims。
    pub claims: Vec<ResourceClaim>,
}

/// Reservation lifecycle state。
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationState {
    /// Claims 已鎖定，平台 preparation 尚未完成。
    Pending,
    /// Session 可使用資源。
    Active,
    /// 正在停止 worker 並釋放平台資源。
    Releasing,
    /// Claims 已釋放。
    Released,
    /// Preparation 或 release 失敗，需要 recovery。
    Failed,
}

/// Resource Manager 保存的 reservation record。
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Reservation {
    /// 原始 request。
    pub request: ReservationRequest,
    /// Lifecycle state。
    pub state: ReservationState,
    /// Failure reason；只有 `Failed` 應有值。
    pub failure: Option<String>,
}

/// 單一 runtime authority 的 atomic Resource Manager。
#[derive(Default)]
pub struct ResourceManager {
    reservations: HashMap<String, Reservation>,
    capacities: HashMap<ResourceKey, u64>,
}

impl ResourceManager {
    /// 建立空 manager。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 設定 shared resource 的總 capacity units。
    ///
    /// # Errors
    ///
    /// Capacity 為零或 resource 強制 exclusive 時回傳錯誤。
    pub fn set_capacity(&mut self, resource: ResourceKey, units: u64) -> Result<(), NetToolError> {
        if units == 0 {
            return Err(invalid("resource capacity must be non-zero"));
        }
        if resource.requires_exclusive() {
            return Err(invalid("exclusive resource cannot define shared capacity"));
        }
        self.capacities.insert(resource, units);
        Ok(())
    }

    /// 原子鎖定全部 claims 並建立 `Pending` reservation。
    ///
    /// 相同 reservation ID 與完全相同 request 會回傳原 record；不同 request
    /// 重用 ID 會拒絕。任何 claim 衝突時不會保留部分資源。
    ///
    /// # Errors
    ///
    /// Request 無效、ID 重用、mode/capacity 不符或資源衝突時回傳結構化錯誤。
    pub fn reserve(&mut self, request: ReservationRequest) -> Result<Reservation, NetToolError> {
        if let Some(existing) = self.reservations.get(&request.reservation_id) {
            return if existing.request == request {
                Ok(existing.clone())
            } else {
                Err(operation_conflict())
            };
        }
        validate_request(&request)?;
        for claim in &request.claims {
            self.check_claim(claim)?;
        }
        let reservation_id = request.reservation_id.clone();
        let reservation = Reservation {
            request,
            state: ReservationState::Pending,
            failure: None,
        };
        self.reservations
            .insert(reservation_id, reservation.clone());
        Ok(reservation)
    }

    /// Platform preparation 成功後啟用 reservation。
    ///
    /// # Errors
    ///
    /// Reservation 不存在或不是 `Pending` 時回傳錯誤。重複 activate `Active` 為冪等成功。
    pub fn activate(&mut self, reservation_id: &str) -> Result<Reservation, NetToolError> {
        let reservation = self
            .reservations
            .get_mut(reservation_id)
            .ok_or_else(missing)?;
        match reservation.state {
            ReservationState::Pending => reservation.state = ReservationState::Active,
            ReservationState::Active => {}
            _ => {
                return Err(invalid_state(
                    "reservation cannot be activated from current state",
                ));
            }
        }
        Ok(reservation.clone())
    }

    /// 開始停止 worker 與釋放平台資源。
    ///
    /// # Errors
    ///
    /// Reservation 不存在或狀態不允許 release 時回傳錯誤；重複呼叫為冪等成功。
    pub fn begin_release(&mut self, reservation_id: &str) -> Result<Reservation, NetToolError> {
        let reservation = self
            .reservations
            .get_mut(reservation_id)
            .ok_or_else(missing)?;
        match reservation.state {
            ReservationState::Pending | ReservationState::Active | ReservationState::Failed => {
                reservation.state = ReservationState::Releasing;
            }
            ReservationState::Releasing | ReservationState::Released => {}
        }
        Ok(reservation.clone())
    }

    /// 平台資源釋放完成後解除所有 claims。
    ///
    /// # Errors
    ///
    /// Reservation 不存在或尚未進入 `Releasing` 時回傳錯誤；重複完成為冪等成功。
    pub fn finish_release(&mut self, reservation_id: &str) -> Result<Reservation, NetToolError> {
        let reservation = self
            .reservations
            .get_mut(reservation_id)
            .ok_or_else(missing)?;
        match reservation.state {
            ReservationState::Releasing => reservation.state = ReservationState::Released,
            ReservationState::Released => {}
            _ => {
                return Err(invalid_state(
                    "reservation must be releasing before release completes",
                ));
            }
        }
        Ok(reservation.clone())
    }

    /// 標記 preparation/release failure，claims 仍維持鎖定供 recovery 使用。
    ///
    /// # Errors
    ///
    /// Reservation 不存在或 failure reason 為空時回傳錯誤。
    pub fn fail(
        &mut self,
        reservation_id: &str,
        reason: &str,
    ) -> Result<Reservation, NetToolError> {
        if reason.trim().is_empty() {
            return Err(invalid("reservation failure reason is required"));
        }
        let reservation = self
            .reservations
            .get_mut(reservation_id)
            .ok_or_else(missing)?;
        if reservation.state != ReservationState::Released {
            reservation.state = ReservationState::Failed;
            reservation.failure = Some(reason.to_owned());
        }
        Ok(reservation.clone())
    }

    /// 依 ID 查詢 reservation。
    #[must_use]
    pub fn get(&self, reservation_id: &str) -> Option<&Reservation> {
        self.reservations.get(reservation_id)
    }

    fn check_claim(&self, requested: &ResourceClaim) -> Result<(), NetToolError> {
        let owners = self
            .reservations
            .values()
            .filter(|reservation| holds_resources(reservation.state))
            .flat_map(|reservation| {
                reservation
                    .request
                    .claims
                    .iter()
                    .map(move |claim| (reservation.request.session_id.as_str(), claim))
            })
            .filter(|(_, claim)| claim.resource == requested.resource)
            .collect::<Vec<_>>();
        if let Some((owner, _)) = owners.iter().find(|(_, claim)| {
            requested.mode == ResourceMode::Exclusive || claim.mode == ResourceMode::Exclusive
        }) {
            return Err(conflict(&requested.resource, owner, requested.mode));
        }
        if requested.mode == ResourceMode::Shared {
            let used = owners
                .iter()
                .try_fold(0_u64, |total, (_, claim)| total.checked_add(claim.units))
                .ok_or_else(|| {
                    conflict(&requested.resource, "capacity-overflow", requested.mode)
                })?;
            let capacity = match self.capacities.get(&requested.resource).copied() {
                Some(capacity) => capacity,
                None if requested.resource.requires_capacity() => {
                    return Err(invalid("shared resource capacity is not configured"));
                }
                None => u64::MAX,
            };
            if used
                .checked_add(requested.units)
                .is_none_or(|total| total > capacity)
            {
                let owner = owners.first().map_or("capacity", |(owner, _)| *owner);
                return Err(conflict(&requested.resource, owner, requested.mode));
            }
        }
        Ok(())
    }
}

fn validate_request(request: &ReservationRequest) -> Result<(), NetToolError> {
    if request.reservation_id.trim().is_empty() || request.session_id.trim().is_empty() {
        return Err(invalid("reservation and session IDs are required"));
    }
    if request.claims.is_empty() {
        return Err(invalid("reservation must contain at least one claim"));
    }
    for (index, claim) in request.claims.iter().enumerate() {
        if claim.units == 0 {
            return Err(invalid("resource claim units must be non-zero"));
        }
        if claim.mode == ResourceMode::Exclusive && claim.units != 1 {
            return Err(invalid("exclusive resource claim must request one unit"));
        }
        if claim.resource.requires_exclusive() && claim.mode != ResourceMode::Exclusive {
            return Err(invalid("resource requires exclusive mode"));
        }
        if request.claims[..index]
            .iter()
            .any(|earlier| earlier.resource == claim.resource)
        {
            return Err(invalid("reservation contains duplicate resource claims"));
        }
    }
    Ok(())
}

const fn holds_resources(state: ReservationState) -> bool {
    !matches!(state, ReservationState::Released)
}

fn conflict(resource: &ResourceKey, owner_session: &str, mode: ResourceMode) -> NetToolError {
    let mut error = NetToolError::new(
        ErrorCode::ResourceConflict,
        "requested resource conflicts with an existing reservation",
        false,
    );
    error
        .details
        .insert("resource".to_owned(), resource.to_string());
    error
        .details
        .insert("owner_session".to_owned(), owner_session.to_owned());
    error
        .details
        .insert("requested_mode".to_owned(), mode.as_str().to_owned());
    error
}

fn invalid(message: &str) -> NetToolError {
    NetToolError::new(ErrorCode::InvalidArgument, message, false)
}
fn invalid_state(message: &str) -> NetToolError {
    NetToolError::new(ErrorCode::InvalidState, message, false)
}
fn missing() -> NetToolError {
    NetToolError::new(
        ErrorCode::InvalidArgument,
        "reservation does not exist",
        false,
    )
}
fn operation_conflict() -> NetToolError {
    NetToolError::new(
        ErrorCode::OperationConflict,
        "reservation ID was reused with a different request",
        false,
    )
}

#[cfg(test)]
mod tests {
    use super::{
        ReservationRequest, ReservationState, ResourceClaim, ResourceKey, ResourceManager,
        ResourceMode,
    };

    fn request(id: &str, session: &str, claims: Vec<ResourceClaim>) -> ReservationRequest {
        ReservationRequest {
            reservation_id: id.to_owned(),
            session_id: session.to_owned(),
            claims,
        }
    }
    fn exclusive(resource: ResourceKey) -> ResourceClaim {
        ResourceClaim {
            resource,
            mode: ResourceMode::Exclusive,
            units: 1,
        }
    }

    #[test]
    fn exclusive_conflict_lists_resource_owner_and_mode() {
        let mut manager = ResourceManager::new();
        let key = ResourceKey::DpdkPort("0000:01:00.0".to_owned());
        manager
            .reserve(request("r1", "s1", vec![exclusive(key.clone())]))
            .expect("first reservation succeeds");
        let error = manager
            .reserve(request("r2", "s2", vec![exclusive(key)]))
            .expect_err("second reservation conflicts");
        assert_eq!(error.details["owner_session"], "s1");
        assert_eq!(error.details["requested_mode"], "exclusive");
        assert_eq!(error.details["resource"], "dpdk-port:0000:01:00.0");
    }

    #[test]
    fn multi_claim_reservation_is_atomic_on_conflict() {
        let mut manager = ResourceManager::new();
        manager
            .reserve(request(
                "r1",
                "s1",
                vec![exclusive(ResourceKey::PinnedCpu(1))],
            ))
            .expect("first reservation succeeds");
        assert!(
            manager
                .reserve(request(
                    "r2",
                    "s2",
                    vec![
                        exclusive(ResourceKey::PinnedCpu(2)),
                        exclusive(ResourceKey::PinnedCpu(1))
                    ]
                ))
                .is_err()
        );
        manager
            .reserve(request(
                "r3",
                "s3",
                vec![exclusive(ResourceKey::PinnedCpu(2))],
            ))
            .expect("CPU 2 was not partially retained");
    }

    #[test]
    fn shared_capacity_is_enforced_and_released() {
        let mut manager = ResourceManager::new();
        let key = ResourceKey::HugePages {
            numa_node: 0,
            page_size_kib: 2048,
        };
        manager
            .set_capacity(key.clone(), 10)
            .expect("capacity is valid");
        manager
            .reserve(request(
                "r1",
                "s1",
                vec![ResourceClaim {
                    resource: key.clone(),
                    mode: ResourceMode::Shared,
                    units: 6,
                }],
            ))
            .expect("first share succeeds");
        assert!(
            manager
                .reserve(request(
                    "r2",
                    "s2",
                    vec![ResourceClaim {
                        resource: key.clone(),
                        mode: ResourceMode::Shared,
                        units: 5
                    }]
                ))
                .is_err()
        );
        manager.begin_release("r1").expect("release begins");
        manager.finish_release("r1").expect("release finishes");
        manager
            .reserve(request(
                "r2",
                "s2",
                vec![ResourceClaim {
                    resource: key,
                    mode: ResourceMode::Shared,
                    units: 5,
                }],
            ))
            .expect("released capacity is reusable");
    }

    #[test]
    fn metered_shared_resource_requires_explicit_capacity() {
        let mut manager = ResourceManager::new();
        let claim = ResourceClaim {
            resource: ResourceKey::NumaMemory(0),
            mode: ResourceMode::Shared,
            units: 1024,
        };
        assert!(manager.reserve(request("r1", "s1", vec![claim])).is_err());
    }

    #[test]
    fn lifecycle_and_duplicate_requests_are_idempotent() {
        let mut manager = ResourceManager::new();
        let request = request("r1", "s1", vec![exclusive(ResourceKey::PinnedCpu(1))]);
        assert_eq!(
            manager.reserve(request.clone()).expect("reserve succeeds"),
            manager.reserve(request).expect("duplicate succeeds")
        );
        assert_eq!(
            manager.activate("r1").expect("activate succeeds").state,
            ReservationState::Active
        );
        assert_eq!(
            manager
                .activate("r1")
                .expect("duplicate activate succeeds")
                .state,
            ReservationState::Active
        );
        assert_eq!(
            manager.begin_release("r1").expect("release begins").state,
            ReservationState::Releasing
        );
        assert_eq!(
            manager
                .finish_release("r1")
                .expect("release completes")
                .state,
            ReservationState::Released
        );
        assert_eq!(
            manager
                .finish_release("r1")
                .expect("duplicate completion succeeds")
                .state,
            ReservationState::Released
        );
    }
}

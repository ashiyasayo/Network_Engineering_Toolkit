//! Protocol version 與 capability intersection。

use nettool_error::{ErrorCode, NetToolError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// 單一 major 下支援的 minor 範圍。
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProtocolRange {
    /// Protocol major。
    pub major: u32,
    /// 最低 minor。
    pub min_minor: u32,
    /// 最高 minor。
    pub max_minor: u32,
}

/// Capability registry ID 與版本範圍。
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CapabilityRange {
    /// 不可重用的 registry ID。
    pub id: u32,
    /// 最低 capability version。
    pub min_version: u32,
    /// 最高 capability version。
    pub max_version: u32,
    /// Hardware/runtime 是否實際可用。
    pub available: bool,
}

/// 雙方共同可用的 capability version。
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NegotiatedCapability {
    /// Registry ID。
    pub id: u32,
    /// 選定的最高共同版本。
    pub version: u32,
}

/// 選擇雙方最高共同 minor version。
///
/// # Errors
///
/// Major 不同、範圍無效或沒有共同 minor 時回傳不相容錯誤。
pub fn negotiate_version(
    local: ProtocolRange,
    remote: ProtocolRange,
) -> Result<(u32, u32), NetToolError> {
    if local.major != remote.major {
        return Err(incompatible("node protocol major is incompatible"));
    }
    if local.min_minor > local.max_minor || remote.min_minor > remote.max_minor {
        return Err(incompatible("node protocol minor range is invalid"));
    }
    let minimum = local.min_minor.max(remote.min_minor);
    let maximum = local.max_minor.min(remote.max_minor);
    if minimum > maximum {
        return Err(incompatible("nodes have no common protocol minor"));
    }
    Ok((local.major, maximum))
}

/// 依 capability ID 交集選擇最高共同版本。
#[must_use]
pub fn negotiate_capabilities(
    local: &[CapabilityRange],
    remote: &[CapabilityRange],
) -> Vec<NegotiatedCapability> {
    let remote = remote
        .iter()
        .filter(|item| item.available && item.min_version <= item.max_version)
        .map(|item| (item.id, item))
        .collect::<BTreeMap<_, _>>();
    let mut negotiated = local
        .iter()
        .filter(|item| item.available && item.min_version <= item.max_version)
        .filter_map(|local_item| {
            let remote_item = remote.get(&local_item.id)?;
            let minimum = local_item.min_version.max(remote_item.min_version);
            let maximum = local_item.max_version.min(remote_item.max_version);
            (minimum <= maximum).then_some(NegotiatedCapability {
                id: local_item.id,
                version: maximum,
            })
        })
        .collect::<Vec<_>>();
    negotiated.sort_by_key(|item| item.id);
    negotiated.dedup_by_key(|item| item.id);
    negotiated
}

fn incompatible(message: &str) -> NetToolError {
    NetToolError::new(ErrorCode::ProtocolIncompatible, message, false)
}

#[cfg(test)]
mod tests {
    use super::{
        CapabilityRange, NegotiatedCapability, ProtocolRange, negotiate_capabilities,
        negotiate_version,
    };

    #[test]
    fn chooses_highest_common_minor() {
        assert_eq!(
            negotiate_version(
                ProtocolRange {
                    major: 1,
                    min_minor: 0,
                    max_minor: 3
                },
                ProtocolRange {
                    major: 1,
                    min_minor: 0,
                    max_minor: 2
                }
            )
            .expect("compatible"),
            (1, 2)
        );
    }
    #[test]
    fn rejects_major_mismatch() {
        assert!(
            negotiate_version(
                ProtocolRange {
                    major: 1,
                    min_minor: 0,
                    max_minor: 1
                },
                ProtocolRange {
                    major: 2,
                    min_minor: 0,
                    max_minor: 1
                }
            )
            .is_err()
        );
    }
    #[test]
    fn intersects_available_capabilities_by_version() {
        let local = [
            CapabilityRange {
                id: 1,
                min_version: 1,
                max_version: 3,
                available: true,
            },
            CapabilityRange {
                id: 2,
                min_version: 1,
                max_version: 1,
                available: true,
            },
        ];
        let remote = [
            CapabilityRange {
                id: 1,
                min_version: 2,
                max_version: 4,
                available: true,
            },
            CapabilityRange {
                id: 2,
                min_version: 1,
                max_version: 1,
                available: false,
            },
        ];
        assert_eq!(
            negotiate_capabilities(&local, &remote),
            [NegotiatedCapability { id: 1, version: 3 }]
        );
    }
}

use std::collections::HashMap;
use std::net::IpAddr;

use nettool_error::{ErrorCode, NetToolError};

/// 單一 worker 可保留的最大 flow 數，避免 caller 以 usize 導致無界配置。
pub const MAX_FLOW_TABLE_ENTRIES: usize = 1_000_000;

/// 封包原始方向的 five tuple。
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FlowTuple {
    /// Source IP。
    pub source_ip: IpAddr,
    /// Destination IP。
    pub destination_ip: IpAddr,
    /// Source TCP/UDP port。
    pub source_port: u16,
    /// Destination TCP/UDP port。
    pub destination_port: u16,
    /// IP protocol number。
    pub protocol: u8,
}

/// 相對 canonical key 的 packet direction。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowDirection {
    /// 原始 source endpoint 是 canonical 第一端。
    Forward,
    /// 原始 source endpoint 是 canonical 第二端。
    Reverse,
}

/// 雙向共用的 canonical flow key。
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FlowKey {
    /// Lexicographically smaller endpoint IP。
    pub first_ip: IpAddr,
    /// First endpoint port。
    pub first_port: u16,
    /// Lexicographically larger endpoint IP。
    pub second_ip: IpAddr,
    /// Second endpoint port。
    pub second_port: u16,
    /// IP protocol number。
    pub protocol: u8,
}

impl FlowKey {
    /// Canonicalize five tuple，並保留原始方向。
    #[must_use]
    pub fn canonical(tuple: FlowTuple) -> (Self, FlowDirection) {
        let source = (tuple.source_ip, tuple.source_port);
        let destination = (tuple.destination_ip, tuple.destination_port);
        if source <= destination {
            (
                Self {
                    first_ip: tuple.source_ip,
                    first_port: tuple.source_port,
                    second_ip: tuple.destination_ip,
                    second_port: tuple.destination_port,
                    protocol: tuple.protocol,
                },
                FlowDirection::Forward,
            )
        } else {
            (
                Self {
                    first_ip: tuple.destination_ip,
                    first_port: tuple.destination_port,
                    second_ip: tuple.source_ip,
                    second_port: tuple.source_port,
                    protocol: tuple.protocol,
                },
                FlowDirection::Reverse,
            )
        }
    }
}

/// 將 canonical flow 穩定映射至 worker-owned shard。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlowSharder {
    shard_count: usize,
}

/// Flow lookup/creation 結果。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowDisposition {
    /// 命中既有 flow。
    Existing,
    /// 建立新 flow，未驅逐其他 entry。
    Created,
    /// 建立新 flow 前依 LRU-like policy 驅逐 entry。
    CreatedAfterEviction,
}

/// Worker-local flow table counters。
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FlowTableStats {
    /// 累計 lookup 次數。
    pub lookups: u64,
    /// 累計建立 flow 次數。
    pub creations: u64,
    /// Idle timeout 與 capacity eviction 總數。
    pub evictions: u64,
}

#[derive(Clone, Debug)]
struct FlowEntry<T> {
    value: T,
    last_seen_nanoseconds: u64,
}

/// 單一 worker 擁有的 bounded flow table；型別本身不提供共享鎖。
pub struct FlowTable<T> {
    entries: HashMap<FlowKey, FlowEntry<T>>,
    maximum_flows: usize,
    idle_timeout_nanoseconds: u64,
    stats: FlowTableStats,
}

impl<T> FlowTable<T> {
    /// 建立具有 maximum flow count 與 idle timeout 的 worker-local table。
    ///
    /// # Errors
    ///
    /// 最大 flow count 或 idle timeout 為零時回傳錯誤。
    pub fn new(maximum_flows: usize, idle_timeout_nanoseconds: u64) -> Result<Self, NetToolError> {
        if maximum_flows == 0
            || maximum_flows > MAX_FLOW_TABLE_ENTRIES
            || idle_timeout_nanoseconds == 0
        {
            return Err(NetToolError::new(
                ErrorCode::InvalidArgument,
                "flow table bounds must be between 1 and 1000000 and idle timeout must be greater than zero",
                false,
            ));
        }
        let mut entries = HashMap::new();
        entries.try_reserve(maximum_flows).map_err(|_| {
            NetToolError::new(
                ErrorCode::ResourceConflict,
                "flow table capacity cannot be reserved",
                false,
            )
        })?;
        Ok(Self {
            entries,
            maximum_flows,
            idle_timeout_nanoseconds,
            stats: FlowTableStats::default(),
        })
    }

    /// Lookup flow，命中時更新 last-seen timestamp。
    #[must_use]
    pub fn get_mut(&mut self, key: &FlowKey, now_nanoseconds: u64) -> Option<&mut T> {
        self.stats.lookups = self.stats.lookups.saturating_add(1);
        self.entries.get_mut(key).map(|entry| {
            entry.last_seen_nanoseconds = now_nanoseconds;
            &mut entry.value
        })
    }

    /// 在 `get_or_insert_with` 確保 entry 存在後取得 value，不重複計入 lookup。
    #[must_use]
    pub fn value_mut(&mut self, key: &FlowKey) -> Option<&mut T> {
        self.entries.get_mut(key).map(|entry| &mut entry.value)
    }

    /// Lookup 或建立 flow；達容量時先清除 idle entries，再驅逐最久未使用 entry。
    pub fn get_or_insert_with(
        &mut self,
        key: FlowKey,
        now_nanoseconds: u64,
        create: impl FnOnce() -> T,
    ) -> FlowDisposition {
        self.stats.lookups = self.stats.lookups.saturating_add(1);
        if let Some(entry) = self.entries.get_mut(&key) {
            entry.last_seen_nanoseconds = now_nanoseconds;
            return FlowDisposition::Existing;
        }

        let idle_evictions = self.expire_idle(now_nanoseconds);
        let capacity_eviction = if self.entries.len() >= self.maximum_flows {
            self.evict_least_recently_seen()
        } else {
            false
        };
        self.stats.creations = self.stats.creations.saturating_add(1);
        self.entries.insert(
            key,
            FlowEntry {
                value: create(),
                last_seen_nanoseconds: now_nanoseconds,
            },
        );
        if idle_evictions > 0 || capacity_eviction {
            FlowDisposition::CreatedAfterEviction
        } else {
            FlowDisposition::Created
        }
    }

    /// 清除達 idle timeout 的 entries，回傳清除數量。
    pub fn expire_idle(&mut self, now_nanoseconds: u64) -> usize {
        let before = self.entries.len();
        let timeout = self.idle_timeout_nanoseconds;
        self.entries.retain(|_, entry| {
            now_nanoseconds.saturating_sub(entry.last_seen_nanoseconds) < timeout
        });
        let removed = before.saturating_sub(self.entries.len());
        self.stats.evictions = self
            .stats
            .evictions
            .saturating_add(u64::try_from(removed).unwrap_or(u64::MAX));
        removed
    }

    /// 目前 active flow count。
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Table 是否為空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 累計 counters snapshot。
    #[must_use]
    pub const fn stats(&self) -> FlowTableStats {
        self.stats
    }

    fn evict_least_recently_seen(&mut self) -> bool {
        let victim = self
            .entries
            .iter()
            .min_by_key(|(_, entry)| entry.last_seen_nanoseconds)
            .map(|(key, _)| *key);
        if let Some(victim) = victim {
            self.entries.remove(&victim);
            self.stats.evictions = self.stats.evictions.saturating_add(1);
            true
        } else {
            false
        }
    }
}

impl FlowSharder {
    /// 建立 sharder；零個 shard 無法形成有效 ownership。
    #[must_use]
    pub const fn new(shard_count: usize) -> Option<Self> {
        if shard_count == 0 {
            None
        } else {
            Some(Self { shard_count })
        }
    }

    /// 回傳穩定 shard index；演算法刻意固定，避免 process-random hash 破壞 locality。
    #[must_use]
    pub fn shard_for(self, key: &FlowKey) -> usize {
        let mut hash = 0xcbf2_9ce4_8422_2325_u64;
        hash_ip(&mut hash, key.first_ip);
        hash_bytes(&mut hash, &key.first_port.to_be_bytes());
        hash_ip(&mut hash, key.second_ip);
        hash_bytes(&mut hash, &key.second_port.to_be_bytes());
        hash_bytes(&mut hash, &[key.protocol]);
        usize::try_from(hash % u64::try_from(self.shard_count).unwrap_or(u64::MAX)).unwrap_or(0)
    }
}

fn hash_ip(hash: &mut u64, address: IpAddr) {
    match address {
        IpAddr::V4(value) => {
            hash_bytes(hash, &[4]);
            hash_bytes(hash, &value.octets());
        }
        IpAddr::V6(value) => {
            hash_bytes(hash, &[6]);
            hash_bytes(hash, &value.octets());
        }
    }
}

fn hash_bytes(hash: &mut u64, bytes: &[u8]) {
    for byte in bytes {
        *hash ^= u64::from(*byte);
        *hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        FlowDirection, FlowDisposition, FlowKey, FlowSharder, FlowTable, FlowTuple,
        MAX_FLOW_TABLE_ENTRIES,
    };
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn reverse_tuple_has_same_key_and_shard() {
        let a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let b = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
        let (forward, direction) = FlowKey::canonical(FlowTuple {
            source_ip: a,
            destination_ip: b,
            source_port: 1234,
            destination_port: 443,
            protocol: 6,
        });
        let (reverse, reverse_direction) = FlowKey::canonical(FlowTuple {
            source_ip: b,
            destination_ip: a,
            source_port: 443,
            destination_port: 1234,
            protocol: 6,
        });
        assert_eq!(forward, reverse);
        assert_eq!(direction, FlowDirection::Forward);
        assert_eq!(reverse_direction, FlowDirection::Reverse);
        let sharder = FlowSharder::new(8).expect("non-zero");
        assert_eq!(sharder.shard_for(&forward), sharder.shard_for(&reverse));
    }

    #[test]
    fn rejects_zero_shards() {
        assert_eq!(FlowSharder::new(0), None);
    }

    #[test]
    fn rejects_unbounded_flow_table_configuration() {
        assert!(FlowTable::<u8>::new(MAX_FLOW_TABLE_ENTRIES + 1, 1).is_err());
    }

    fn key(last_octet: u8) -> FlowKey {
        FlowKey::canonical(FlowTuple {
            source_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, last_octet)),
            destination_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            source_port: u16::from(last_octet),
            destination_port: 443,
            protocol: 6,
        })
        .0
    }

    #[test]
    fn flow_table_never_exceeds_configured_bound() {
        let mut table = FlowTable::new(2, 1_000).expect("table");
        let _ = table.get_or_insert_with(key(1), 1, || 10);
        let _ = table.get_or_insert_with(key(2), 2, || 20);
        let disposition = table.get_or_insert_with(key(3), 3, || 30);
        assert_eq!(disposition, FlowDisposition::CreatedAfterEviction);
        assert_eq!(table.len(), 2);
        assert_eq!(table.stats().evictions, 1);
        assert!(table.get_mut(&key(1), 4).is_none());
    }

    #[test]
    fn idle_timeout_evicts_without_full_table_scan_per_lookup() {
        let mut table = FlowTable::new(4, 10).expect("table");
        let _ = table.get_or_insert_with(key(1), 1, || 10);
        let _ = table.get_or_insert_with(key(2), 5, || 20);
        assert_eq!(table.expire_idle(11), 1);
        assert_eq!(table.len(), 1);
        assert_eq!(table.get_mut(&key(2), 12), Some(&mut 20));
    }
}

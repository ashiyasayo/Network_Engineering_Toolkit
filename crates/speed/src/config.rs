use nettool_domain::{Direction, SpeedProtocol};
use nettool_error::{ErrorCode, NetToolError};
use serde::{Deserialize, Serialize};

/// 公開 `speed.run` action 的 versioned payload。
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SpeedRunRequest {
    /// Pairing registry 中的 remote node name 或 ID。
    pub node: String,
    /// TCP、UDP 或 raw Ethernet。
    pub protocol: SpeedProtocol,
    /// Backend registry ID。
    pub backend: String,
    /// Upload、download 或 bidirectional。
    pub direction: Direction,
    /// Measurement duration milliseconds。
    pub duration_ms: u64,
    /// Warmup milliseconds。
    pub warmup_ms: u64,
    /// Cooldown milliseconds。
    pub cooldown_ms: u64,
    /// `None` 代表 auto tune，否則為固定 stream count。
    pub streams: Option<u16>,
    /// Raw Ethernet on-wire frame size，含 FCS。
    pub frame_size: Option<u16>,
    /// UDP/raw target bits per second。
    pub target_rate_bps: Option<u64>,
    /// 是否允許執行受控 auto-tune matrix。
    pub auto_tune: bool,
    /// 是否同時執行 latency-under-load measurement。
    pub latency_under_load: bool,
    /// 明確指定的 logical CPUs；`None` 代表 auto。
    pub cpus: Option<Vec<u32>>,
    /// 明確指定的 NUMA node；`None` 代表 auto。
    pub numa_node: Option<u32>,
    /// Accelerated backend 的 canonical PCI BDF。
    pub accelerated_pci_address: Option<String>,
    /// 僅供 Agent 解析成 PCI BDF 的介面名稱，不得傳入 executor。
    pub accelerated_interface_name: Option<String>,
    /// Remote accelerated backend 的 canonical PCI BDF；僅由 Node control plane 消費。
    #[serde(default)]
    pub remote_accelerated_pci_address: Option<String>,
    /// DPDK raw Ethernet 對端 NIC 的 unicast MAC address。
    #[serde(default)]
    pub remote_mac_address: Option<String>,
}

impl SpeedRunRequest {
    /// 驗證 protocol/backend 組合與所有 session bounds。
    ///
    /// # Errors
    ///
    /// 未知 backend、缺少 protocol-required 欄位或資源設定互相衝突時回傳錯誤。
    #[allow(clippy::too_many_lines)]
    pub fn validate(&self) -> Result<(), NetToolError> {
        if self.node.trim().is_empty() {
            return Err(invalid("speed run requires a remote node"));
        }
        if !matches!(
            self.backend.as_str(),
            "socket" | "native" | "dpdk" | "af_xdp" | "rio"
        ) {
            return Err(invalid("speed backend is not registered"));
        }
        if self.duration_ms == 0 {
            return Err(invalid("measurement duration must be non-zero"));
        }
        if self.streams == Some(0) {
            return Err(invalid("stream count must be non-zero"));
        }
        if let Some(cpus) = &self.cpus {
            if cpus.is_empty() {
                return Err(invalid("CPU affinity list must not be empty"));
            }
            let mut unique = cpus.clone();
            unique.sort_unstable();
            unique.dedup();
            if unique.len() != cpus.len() {
                return Err(invalid("CPU affinity list contains duplicates"));
            }
            if self.backend != "dpdk" && self.backend != "af_xdp" {
                return Err(invalid("CPU affinity requires an accelerated backend"));
            }
        }
        if self.numa_node.is_some() && matches!(self.backend.as_str(), "socket" | "native") {
            return Err(invalid("NUMA selection requires an accelerated backend"));
        }
        let accelerated = matches!(self.backend.as_str(), "dpdk" | "af_xdp" | "rio");
        if accelerated {
            if self.accelerated_pci_address.is_some() == self.accelerated_interface_name.is_some() {
                return Err(invalid(
                    "accelerated backend requires exactly one PCI BDF or interface name",
                ));
            }
            if let Some(pci) = &self.accelerated_pci_address {
                if !valid_pci_bdf(pci) {
                    return Err(invalid("accelerated PCI BDF is invalid"));
                }
            }
            if self
                .accelerated_interface_name
                .as_deref()
                .is_some_and(|name| {
                    name.is_empty() || name.len() > 256 || name.chars().any(char::is_control)
                })
            {
                return Err(invalid("accelerated interface name is invalid"));
            }
            if self.backend == "dpdk"
                && !self
                    .remote_accelerated_pci_address
                    .as_deref()
                    .is_some_and(valid_pci_bdf)
            {
                return Err(invalid("DPDK backend requires a valid remote PCI BDF"));
            }
            if self.backend == "dpdk"
                && self.protocol == SpeedProtocol::Raw
                && !self
                    .remote_mac_address
                    .as_deref()
                    .is_some_and(valid_unicast_mac)
            {
                return Err(invalid(
                    "DPDK raw Ethernet requires a valid remote unicast MAC",
                ));
            }
            if self.backend != "dpdk" && self.remote_accelerated_pci_address.is_some() {
                return Err(invalid("only the DPDK backend accepts a remote PCI BDF"));
            }
        } else if self.accelerated_pci_address.is_some()
            || self.accelerated_interface_name.is_some()
            || self.remote_accelerated_pci_address.is_some()
            || self.remote_mac_address.is_some()
        {
            return Err(invalid(
                "socket and native backends do not accept accelerated NIC selectors",
            ));
        }
        match self.protocol {
            SpeedProtocol::Tcp => {
                if self.frame_size.is_some() || self.target_rate_bps.is_some() {
                    return Err(invalid("TCP does not accept raw frame size or target rate"));
                }
            }
            SpeedProtocol::Udp => {
                if self.frame_size.is_some() || self.target_rate_bps == Some(0) {
                    return Err(invalid(
                        "UDP requires a valid rate and does not accept frame size",
                    ));
                }
            }
            SpeedProtocol::Raw => {
                if self.backend != "dpdk" {
                    return Err(invalid("raw Ethernet currently requires the DPDK backend"));
                }
                if self.frame_size.is_none_or(|size| size < 64) || self.target_rate_bps == Some(0) {
                    return Err(invalid(
                        "raw Ethernet requires frame size >= 64 and a valid rate",
                    ));
                }
                if self.streams.is_some_and(|streams| streams != 1) {
                    return Err(invalid(
                        "raw Ethernet uses queue/flow sharding, not TCP streams",
                    ));
                }
            }
        }
        Ok(())
    }
}

fn valid_pci_bdf(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 12
        && bytes[4] == b':'
        && bytes[7] == b':'
        && bytes[10] == b'.'
        && bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| matches!(index, 4 | 7 | 10) || byte.is_ascii_hexdigit())
}

fn valid_unicast_mac(value: &str) -> bool {
    let bytes: Vec<_> = value.split(':').collect();
    bytes.len() == 6
        && bytes
            .iter()
            .all(|part| part.len() == 2 && part.bytes().all(|byte| byte.is_ascii_hexdigit()))
        && u8::from_str_radix(bytes[0], 16).is_ok_and(|first| first != 0 && first & 1 == 0)
}

fn invalid(message: &'static str) -> NetToolError {
    NetToolError::new(ErrorCode::InvalidArgument, message, false)
}

#[cfg(test)]
mod tests {
    use super::SpeedRunRequest;
    use nettool_domain::{Direction, SpeedProtocol};

    fn request(protocol: SpeedProtocol) -> SpeedRunRequest {
        SpeedRunRequest {
            node: "node-b".to_owned(),
            protocol,
            backend: "socket".to_owned(),
            direction: Direction::Upload,
            duration_ms: 10_000,
            warmup_ms: 1_000,
            cooldown_ms: 1_000,
            streams: Some(1),
            frame_size: None,
            target_rate_bps: None,
            auto_tune: false,
            latency_under_load: false,
            cpus: None,
            numa_node: None,
            accelerated_pci_address: None,
            accelerated_interface_name: None,
            remote_accelerated_pci_address: None,
            remote_mac_address: None,
        }
    }

    #[test]
    fn validates_tcp_and_udp_contracts() {
        request(SpeedProtocol::Tcp).validate().expect("TCP");
        let mut udp = request(SpeedProtocol::Udp);
        udp.target_rate_bps = Some(100_000_000_000);
        udp.validate().expect("UDP");
    }

    #[test]
    fn raw_requires_dpdk_frame_and_single_stream() {
        let mut raw = request(SpeedProtocol::Raw);
        assert!(raw.validate().is_err());
        raw.backend = "dpdk".to_owned();
        raw.accelerated_pci_address = Some("0000:01:00.0".to_owned());
        raw.remote_accelerated_pci_address = Some("0000:02:00.0".to_owned());
        raw.remote_mac_address = Some("02:00:00:00:00:02".to_owned());
        raw.frame_size = Some(64);
        raw.target_rate_bps = Some(100_000_000_000);
        raw.validate().expect("raw");
        raw.streams = Some(2);
        assert!(raw.validate().is_err());
    }

    #[test]
    fn rejects_duplicate_or_socket_cpu_affinity() {
        let mut value = request(SpeedProtocol::Tcp);
        value.cpus = Some(vec![4, 4]);
        assert!(value.validate().is_err());
        value.cpus = Some(vec![4, 5]);
        assert!(value.validate().is_err());
    }

    #[test]
    fn rejects_socket_numa_selection() {
        let mut value = request(SpeedProtocol::Tcp);
        value.numa_node = Some(1);
        assert!(value.validate().is_err());
    }
}

use nettool_error::{ErrorCode, NetToolError};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

const PREAMBLE_AND_SFD_BYTES: u64 = 8;
const INTER_FRAME_GAP_BYTES: u64 = 12;
const ETHERNET_FCS_BYTES: u16 = 4;

/// Raw generator 的 network layer。
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GeneratorNetwork {
    /// IPv4。
    Ipv4,
    /// IPv6。
    Ipv6,
}

/// Raw generator 的 transport layer。
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GeneratorTransport {
    /// TCP。
    Tcp,
    /// UDP。
    Udp,
}

/// Inclusive IP address range。
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IpRange {
    /// 第一個 address。
    pub start: IpAddr,
    /// 最後一個 address。
    pub end: IpAddr,
}

/// Inclusive transport port range。
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PortRange {
    /// 第一個 port；零不允許作為 generator endpoint。
    pub start: u16,
    /// 最後一個 port。
    pub end: u16,
}

/// 規格第 223 節的 raw packet generator profile。
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RawGeneratorProfile {
    /// 含 Ethernet FCS 的 on-wire frame size。
    pub ethernet_size: u16,
    /// IPv4 或 IPv6。
    pub network: GeneratorNetwork,
    /// TCP 或 UDP。
    pub transport: GeneratorTransport,
    /// Source IP range。
    pub source_ips: IpRange,
    /// Destination IP range。
    pub destination_ips: IpRange,
    /// Source port range。
    pub source_ports: PortRange,
    /// Destination port range。
    pub destination_ports: PortRange,
    /// 要產生的 distinct flows。
    pub flow_count: u64,
    /// Target packets per second。
    pub packet_rate: u64,
}

impl RawGeneratorProfile {
    /// 驗證 address family、ranges、flow cardinality、frame size 與 packet rate。
    ///
    /// # Errors
    ///
    /// Profile 無法形成要求的 flow matrix 或 frame 小於 Ethernet minimum 時回傳錯誤。
    pub fn validate(&self) -> Result<(), NetToolError> {
        if self.ethernet_size < 64 {
            return Err(invalid("Ethernet wire size must be at least 64 bytes"));
        }
        if self.flow_count == 0 || self.packet_rate == 0 {
            return Err(invalid("flow count and packet rate must be non-zero"));
        }
        validate_ip_range(self.source_ips, self.network)?;
        validate_ip_range(self.destination_ips, self.network)?;
        let source_ports = port_cardinality(self.source_ports)?;
        let destination_ports = port_cardinality(self.destination_ports)?;
        let capacity = ip_cardinality(self.source_ips)
            .saturating_mul(ip_cardinality(self.destination_ips))
            .saturating_mul(source_ports)
            .saturating_mul(destination_ports);
        if u128::from(self.flow_count) > capacity {
            return Err(invalid(
                "flow count exceeds the configured address/port matrix",
            ));
        }
        Ok(())
    }

    /// DPDK template bytes；NIC 通常附加四 byte FCS，因此不放入 mbuf。
    ///
    /// # Errors
    ///
    /// Profile 未通過驗證時回傳錯誤。
    pub fn transmit_length(&self) -> Result<u16, NetToolError> {
        self.validate()?;
        Ok(self.ethernet_size - ETHERNET_FCS_BYTES)
    }

    /// 建立可交給 raw Ethernet TX template 的固定封包。
    ///
    /// 此 template 使用 profile range 的第一個 IP/port；flow matrix 的變化由 TX worker
    /// 在後續 burst 迭代處理。封包不包含 NIC 通常附加的 Ethernet FCS。
    ///
    /// # Errors
    ///
    /// Profile 無效、frame 太小，或 address family 與 transport header 無法容納時回傳錯誤。
    #[allow(clippy::too_many_lines)]
    pub fn template_bytes(&self) -> Result<Vec<u8>, NetToolError> {
        let length = usize::from(self.transmit_length()?);
        let transport_header = match self.transport {
            GeneratorTransport::Udp => 8,
            GeneratorTransport::Tcp => 20,
        };
        let minimum = match self.network {
            GeneratorNetwork::Ipv4 => 14 + 20 + transport_header,
            GeneratorNetwork::Ipv6 => 14 + 40 + transport_header,
        };
        if length < minimum {
            return Err(invalid(
                "Ethernet frame is too small for the selected IP/transport template",
            ));
        }
        let mut bytes = vec![0_u8; length];
        bytes[0..6].copy_from_slice(&[0x02, 0, 0, 0, 0, 2]);
        bytes[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 1]);
        let source = self.source_ips.start;
        let destination = self.destination_ips.start;
        let source_port = self.source_ports.start.to_be_bytes();
        let destination_port = self.destination_ports.start.to_be_bytes();
        match (self.network, source, destination) {
            (GeneratorNetwork::Ipv4, IpAddr::V4(source), IpAddr::V4(destination)) => {
                bytes[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
                let ip = &mut bytes[14..34];
                ip[0] = 0x45;
                ip[2..4]
                    .copy_from_slice(&u16::try_from(length - 14).unwrap_or(u16::MAX).to_be_bytes());
                ip[8] = 64;
                ip[9] = match self.transport {
                    GeneratorTransport::Tcp => 6,
                    GeneratorTransport::Udp => 17,
                };
                ip[12..16].copy_from_slice(&source.octets());
                ip[16..20].copy_from_slice(&destination.octets());
                let header_checksum = checksum(ip);
                ip[10..12].copy_from_slice(&header_checksum.to_be_bytes());
                let transport = &mut bytes[34..];
                transport[0..2].copy_from_slice(&source_port);
                transport[2..4].copy_from_slice(&destination_port);
                let transport_protocol = match self.transport {
                    GeneratorTransport::Tcp => 6,
                    GeneratorTransport::Udp => 17,
                };
                match self.transport {
                    GeneratorTransport::Udp => transport[4..6].copy_from_slice(
                        &u16::try_from(length - 34).unwrap_or(u16::MAX).to_be_bytes(),
                    ),
                    GeneratorTransport::Tcp => transport[12] = 0x50,
                }
                let transport_checksum = transport_checksum(
                    IpAddr::V4(source),
                    IpAddr::V4(destination),
                    transport_protocol,
                    transport,
                );
                match self.transport {
                    GeneratorTransport::Udp => {
                        transport[6..8].copy_from_slice(&transport_checksum.to_be_bytes());
                    }
                    GeneratorTransport::Tcp => {
                        transport[16..18].copy_from_slice(&transport_checksum.to_be_bytes());
                    }
                }
            }
            (GeneratorNetwork::Ipv6, IpAddr::V6(source), IpAddr::V6(destination)) => {
                bytes[12..14].copy_from_slice(&0x86dd_u16.to_be_bytes());
                let ip = &mut bytes[14..54];
                ip[0] = 0x60;
                ip[4..6]
                    .copy_from_slice(&u16::try_from(length - 54).unwrap_or(u16::MAX).to_be_bytes());
                ip[6] = match self.transport {
                    GeneratorTransport::Tcp => 6,
                    GeneratorTransport::Udp => 17,
                };
                ip[7] = 64;
                ip[8..24].copy_from_slice(&source.octets());
                ip[24..40].copy_from_slice(&destination.octets());
                let transport = &mut bytes[54..];
                transport[0..2].copy_from_slice(&source_port);
                transport[2..4].copy_from_slice(&destination_port);
                let transport_protocol = match self.transport {
                    GeneratorTransport::Tcp => 6,
                    GeneratorTransport::Udp => 17,
                };
                match self.transport {
                    GeneratorTransport::Udp => transport[4..6].copy_from_slice(
                        &u16::try_from(length - 54).unwrap_or(u16::MAX).to_be_bytes(),
                    ),
                    GeneratorTransport::Tcp => transport[12] = 0x50,
                }
                let transport_checksum = transport_checksum(
                    IpAddr::V6(source),
                    IpAddr::V6(destination),
                    transport_protocol,
                    transport,
                );
                match self.transport {
                    GeneratorTransport::Udp => {
                        transport[6..8].copy_from_slice(&transport_checksum.to_be_bytes());
                    }
                    GeneratorTransport::Tcp => {
                        transport[16..18].copy_from_slice(&transport_checksum.to_be_bytes());
                    }
                }
            }
            _ => return Err(invalid("generator address family does not match network")),
        }
        Ok(bytes)
    }

    /// 建立指定遠端 NIC MAC 的 raw Ethernet template。
    ///
    /// MAC 必須是六組十六進位 byte 且為 unicast，避免未驗證輸入寫入 wire header。
    /// # Errors
    ///
    /// Destination MAC 不是合法 unicast address 或 profile 無效時回傳錯誤。
    pub fn template_bytes_with_destination_mac(
        &self,
        destination_mac: &str,
    ) -> Result<Vec<u8>, NetToolError> {
        let mut bytes = self.template_bytes()?;
        let parts: Vec<_> = destination_mac.split(':').collect();
        if parts.len() != 6
            || parts
                .iter()
                .any(|part| part.len() != 2 || !part.bytes().all(|byte| byte.is_ascii_hexdigit()))
        {
            return Err(invalid("destination MAC address is invalid"));
        }
        let mut mac = [0_u8; 6];
        for (slot, part) in mac.iter_mut().zip(parts) {
            *slot = u8::from_str_radix(part, 16)
                .map_err(|_| invalid("destination MAC address is invalid"))?;
        }
        if mac[0] & 1 != 0 || mac == [0; 6] {
            return Err(invalid("destination MAC address must be unicast"));
        }
        bytes[0..6].copy_from_slice(&mac);
        Ok(bytes)
    }
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0_u32;
    for chunk in bytes.chunks(2) {
        let value = u32::from(u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]));
        sum = sum.saturating_add(value);
        while sum > u32::from(u16::MAX) {
            sum = (sum & u32::from(u16::MAX)) + (sum >> 16);
        }
    }
    !u16::try_from(sum).unwrap_or(u16::MAX)
}

fn transport_checksum(source: IpAddr, destination: IpAddr, protocol: u8, segment: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(40 + segment.len());
    match (source, destination) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            pseudo.extend_from_slice(&source.octets());
            pseudo.extend_from_slice(&destination.octets());
            pseudo.extend_from_slice(&[0, protocol]);
            pseudo.extend_from_slice(
                &u16::try_from(segment.len())
                    .unwrap_or(u16::MAX)
                    .to_be_bytes(),
            );
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            pseudo.extend_from_slice(&source.octets());
            pseudo.extend_from_slice(&destination.octets());
            pseudo.extend_from_slice(
                &u32::try_from(segment.len())
                    .unwrap_or(u32::MAX)
                    .to_be_bytes(),
            );
            pseudo.extend_from_slice(&[0, 0, 0, protocol]);
        }
        _ => return 0,
    }
    pseudo.extend_from_slice(segment);
    let value = checksum(&pseudo);
    if value == 0 { u16::MAX } else { value }
}

/// 依 Ethernet frame + 8-byte preamble/SFD + 12-byte IFG 計算理論 packet rate。
///
/// # Errors
///
/// Line rate 或 frame size 為零時回傳錯誤。
#[allow(clippy::cast_precision_loss)]
pub fn theoretical_packets_per_second(
    line_rate_bits_per_second: u64,
    ethernet_size: u16,
) -> Result<f64, NetToolError> {
    if line_rate_bits_per_second == 0 || ethernet_size == 0 {
        return Err(invalid("line rate and Ethernet size must be non-zero"));
    }
    let wire_bits = (u64::from(ethernet_size) + PREAMBLE_AND_SFD_BYTES + INTER_FRAME_GAP_BYTES)
        .checked_mul(8)
        .ok_or_else(|| invalid("wire size overflow"))?;
    Ok(line_rate_bits_per_second as f64 / wire_bits as f64)
}

fn validate_ip_range(range: IpRange, network: GeneratorNetwork) -> Result<(), NetToolError> {
    let valid = match (range.start, range.end, network) {
        (IpAddr::V4(start), IpAddr::V4(end), GeneratorNetwork::Ipv4) => {
            u32::from(start) <= u32::from(end)
        }
        (IpAddr::V6(start), IpAddr::V6(end), GeneratorNetwork::Ipv6) => {
            u128::from(start) <= u128::from(end)
        }
        _ => false,
    };
    if !valid {
        return Err(invalid(
            "IP range family or order does not match the profile",
        ));
    }
    Ok(())
}

fn ip_cardinality(range: IpRange) -> u128 {
    match (range.start, range.end) {
        (IpAddr::V4(start), IpAddr::V4(end)) => u128::from(u32::from(end) - u32::from(start)) + 1,
        (IpAddr::V6(start), IpAddr::V6(end)) => u128::from(end)
            .saturating_sub(u128::from(start))
            .saturating_add(1),
        _ => 0,
    }
}

fn port_cardinality(range: PortRange) -> Result<u128, NetToolError> {
    if range.start == 0 || range.start > range.end {
        return Err(invalid("transport port range is invalid"));
    }
    Ok(u128::from(range.end - range.start) + 1)
}

fn invalid(message: &'static str) -> NetToolError {
    NetToolError::new(ErrorCode::InvalidArgument, message, false)
}

#[cfg(test)]
mod tests {
    use super::{
        GeneratorNetwork, GeneratorTransport, IpRange, PortRange, RawGeneratorProfile,
        theoretical_packets_per_second,
    };
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn profile() -> RawGeneratorProfile {
        RawGeneratorProfile {
            ethernet_size: 64,
            network: GeneratorNetwork::Ipv4,
            transport: GeneratorTransport::Udp,
            source_ips: IpRange {
                start: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                end: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
            },
            destination_ips: IpRange {
                start: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
                end: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
            },
            source_ports: PortRange {
                start: 1000,
                end: 1001,
            },
            destination_ports: PortRange {
                start: 2000,
                end: 2001,
            },
            flow_count: 16,
            packet_rate: 1_000_000,
        }
    }

    #[test]
    fn validates_complete_flow_matrix_and_fcs_length() {
        let profile = profile();
        profile.validate().expect("profile");
        assert_eq!(profile.transmit_length().expect("length"), 60);
    }

    #[test]
    fn builds_ipv4_udp_template_without_fcs() {
        let bytes = profile().template_bytes().expect("template");
        assert_eq!(bytes.len(), 60);
        assert_eq!(&bytes[12..14], &0x0800_u16.to_be_bytes());
        assert_eq!(bytes[23], 17);
        assert_eq!(&bytes[34..36], &1000_u16.to_be_bytes());
        assert_ne!(&bytes[40..42], &[0, 0]);
        assert_ne!(&bytes[24..26], &[0, 0]);
    }

    #[test]
    fn builds_ipv4_tcp_template_with_transport_header() {
        let mut profile = profile();
        profile.transport = GeneratorTransport::Tcp;
        let bytes = profile.template_bytes().expect("template");
        assert_eq!(bytes.len(), 60);
        assert_eq!(bytes[23], 6);
        assert_eq!(&bytes[34..36], &1000_u16.to_be_bytes());
        assert_eq!(bytes[46] & 0xf0, 0x50);
        assert_ne!(&bytes[50..52], &[0, 0]);
    }

    #[test]
    fn writes_and_validates_destination_mac() {
        let bytes = profile()
            .template_bytes_with_destination_mac("02:00:00:00:00:aa")
            .expect("mac");
        assert_eq!(&bytes[0..6], &[2, 0, 0, 0, 0, 0xaa]);
        assert!(
            profile()
                .template_bytes_with_destination_mac("01:00:00:00:00:aa")
                .is_err()
        );
    }

    #[test]
    fn rejects_family_range_and_cardinality_mismatches() {
        let mut invalid = profile();
        invalid.network = GeneratorNetwork::Ipv6;
        assert!(invalid.validate().is_err());
        invalid.network = GeneratorNetwork::Ipv4;
        invalid.flow_count = 17;
        assert!(invalid.validate().is_err());
        invalid.flow_count = 1;
        invalid.source_ips = IpRange {
            start: IpAddr::V6(Ipv6Addr::LOCALHOST),
            end: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        };
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn matches_specification_wire_rate_reference() {
        let rate = theoretical_packets_per_second(100_000_000_000, 64).expect("rate");
        assert!((rate - 148_809_523.81).abs() < 0.01);
        let jumbo = theoretical_packets_per_second(100_000_000_000, 9018).expect("rate");
        assert!((jumbo - 1_383_049.347_2).abs() < 0.01);
    }
}

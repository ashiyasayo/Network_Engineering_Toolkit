use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const ETHERNET_HEADER_LENGTH: usize = 14;
const VLAN_HEADER_LENGTH: usize = 4;
const ETHERTYPE_VLAN: u16 = 0x8100;
const ETHERTYPE_QINQ: u16 = 0x88a8;
const ETHERTYPE_ARP: u16 = 0x0806;
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86dd;

/// Fast-path parser error；不保留輸入資料，也不配置字串。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseError {
    /// Frame 或 header 在宣告長度前結束。
    Truncated,
    /// Header 欄位彼此矛盾或違反協定最小值。
    Malformed,
    /// VLAN 疊加超過 fast path 支援的 `QinQ` 兩層上限。
    TooManyVlanTags,
    /// IPv6 extension header 超過保守處理上限。
    TooManyIpv6Extensions,
}

/// 802.1Q/QinQ tag。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VlanTag {
    /// Priority Code Point。
    pub priority: u8,
    /// Drop Eligible Indicator。
    pub drop_eligible: bool,
    /// VLAN identifier。
    pub identifier: u16,
}

/// Ethernet II header 與最多兩層 VLAN tags。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EthernetHeader {
    /// Destination MAC。
    pub destination: [u8; 6],
    /// Source MAC。
    pub source: [u8; 6],
    /// VLAN tags，外層優先。
    pub vlan_tags: [Option<VlanTag>; 2],
    /// VLAN 解封裝後 `EtherType`。
    pub ether_type: u16,
}

/// ARP packet 的零配置 view。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArpPacket<'a> {
    /// Hardware address type。
    pub hardware_type: u16,
    /// Protocol address type。
    pub protocol_type: u16,
    /// ARP operation。
    pub operation: u16,
    /// 從 ARP header 開始的完整可見資料。
    pub bytes: &'a [u8],
}

/// IPv4/IPv6 packet metadata。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IpPacket<'a> {
    /// Source IP。
    pub source: IpAddr,
    /// Destination IP。
    pub destination: IpAddr,
    /// 最終 next-header/protocol number。
    pub protocol: u8,
    /// 非首片 fragment 無法安全解析 transport header。
    pub non_initial_fragment: bool,
    /// IP payload 或 extension headers 之後的 transport bytes。
    pub payload: &'a [u8],
}

/// TCP segment 的 fast-path 欄位。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpSegment<'a> {
    /// Source port。
    pub source_port: u16,
    /// Destination port。
    pub destination_port: u16,
    /// Sequence number。
    pub sequence: u32,
    /// Acknowledgement number。
    pub acknowledgement: u32,
    /// TCP flags（低 9 bits）。
    pub flags: u16,
    /// Advertised window。
    pub window: u16,
    /// Application payload。
    pub payload: &'a [u8],
}

/// UDP datagram 的 fast-path 欄位。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UdpDatagram<'a> {
    /// Source port。
    pub source_port: u16,
    /// Destination port。
    pub destination_port: u16,
    /// UDP payload。
    pub payload: &'a [u8],
}

/// ICMP/ICMPv6 message。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IcmpPacket<'a> {
    /// Message type。
    pub message_type: u8,
    /// Message code。
    pub code: u8,
    /// Checksum 後的 message body。
    pub payload: &'a [u8],
}

/// 已辨識的 transport protocol；未知協定仍保留 protocol number 與 bytes。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportPacket<'a> {
    /// TCP。
    Tcp(TcpSegment<'a>),
    /// UDP。
    Udp(UdpDatagram<'a>),
    /// ICMP。
    Icmp(IcmpPacket<'a>),
    /// `ICMPv6`。
    Icmpv6(IcmpPacket<'a>),
    /// 非首片 fragment，transport header 不在此 frame。
    Fragment,
    /// 其他 IP protocol。
    Other {
        /// IP protocol number。
        protocol: u8,
        /// Transport payload bytes。
        bytes: &'a [u8],
    },
}

/// Ethernet frame 的解析結果。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParsedPacket<'a> {
    /// Ethernet metadata。
    pub ethernet: EthernetHeader,
    /// ARP packet（若適用）。
    pub arp: Option<ArpPacket<'a>>,
    /// IP packet（若適用）。
    pub ip: Option<IpPacket<'a>>,
    /// Transport packet（若適用）。
    pub transport: Option<TransportPacket<'a>>,
}

/// 解析 Ethernet、VLAN/QinQ、ARP、IPv4/IPv6 與常見 transport headers。
///
/// 函式只借用輸入 slice，且所有動態長度都先驗證再切片。
///
/// # Errors
///
/// Frame 截斷、header malformed 或超過 fast-path extension 上限時回傳錯誤。
pub fn parse_packet(frame: &[u8]) -> Result<ParsedPacket<'_>, ParseError> {
    let ethernet = parse_ethernet(frame)?;
    let mut offset = ETHERNET_HEADER_LENGTH;
    for tag in ethernet.vlan_tags {
        if tag.is_some() {
            offset += VLAN_HEADER_LENGTH;
        }
    }
    let payload = frame.get(offset..).ok_or(ParseError::Truncated)?;
    match ethernet.ether_type {
        ETHERTYPE_ARP => {
            let arp = parse_arp(payload)?;
            Ok(ParsedPacket {
                ethernet,
                arp: Some(arp),
                ip: None,
                transport: None,
            })
        }
        ETHERTYPE_IPV4 => finish_ip(ethernet, parse_ipv4(payload)?),
        ETHERTYPE_IPV6 => finish_ip(ethernet, parse_ipv6(payload)?),
        _ => Ok(ParsedPacket {
            ethernet,
            arp: None,
            ip: None,
            transport: None,
        }),
    }
}

fn finish_ip(ethernet: EthernetHeader, ip: IpPacket<'_>) -> Result<ParsedPacket<'_>, ParseError> {
    let transport = if ip.non_initial_fragment {
        TransportPacket::Fragment
    } else {
        match ip.protocol {
            6 => TransportPacket::Tcp(parse_tcp(ip.payload)?),
            17 => TransportPacket::Udp(parse_udp(ip.payload)?),
            1 => TransportPacket::Icmp(parse_icmp(ip.payload)?),
            58 => TransportPacket::Icmpv6(parse_icmp(ip.payload)?),
            protocol => TransportPacket::Other {
                protocol,
                bytes: ip.payload,
            },
        }
    };
    Ok(ParsedPacket {
        ethernet,
        arp: None,
        ip: Some(ip),
        transport: Some(transport),
    })
}

fn parse_ethernet(frame: &[u8]) -> Result<EthernetHeader, ParseError> {
    let base = frame
        .get(..ETHERNET_HEADER_LENGTH)
        .ok_or(ParseError::Truncated)?;
    let mut destination = [0; 6];
    destination.copy_from_slice(&base[..6]);
    let mut source = [0; 6];
    source.copy_from_slice(&base[6..12]);
    let mut ether_type = read_u16(base, 12)?;
    let mut vlan_tags = [None; 2];
    let mut offset = ETHERNET_HEADER_LENGTH;
    let mut count = 0;
    while matches!(ether_type, ETHERTYPE_VLAN | ETHERTYPE_QINQ) {
        if count == vlan_tags.len() {
            return Err(ParseError::TooManyVlanTags);
        }
        let tag = frame
            .get(offset..offset + VLAN_HEADER_LENGTH)
            .ok_or(ParseError::Truncated)?;
        let control = read_u16(tag, 0)?;
        vlan_tags[count] = Some(VlanTag {
            priority: ((control >> 13) & 0x07) as u8,
            drop_eligible: control & 0x1000 != 0,
            identifier: control & 0x0fff,
        });
        ether_type = read_u16(tag, 2)?;
        offset += VLAN_HEADER_LENGTH;
        count += 1;
    }
    Ok(EthernetHeader {
        destination,
        source,
        vlan_tags,
        ether_type,
    })
}

fn parse_arp(bytes: &[u8]) -> Result<ArpPacket<'_>, ParseError> {
    let header = bytes.get(..8).ok_or(ParseError::Truncated)?;
    let hardware_length = usize::from(header[4]);
    let protocol_length = usize::from(header[5]);
    let required = 8usize
        .checked_add(2usize.saturating_mul(hardware_length.saturating_add(protocol_length)))
        .ok_or(ParseError::Malformed)?;
    let bytes = bytes.get(..required).ok_or(ParseError::Truncated)?;
    Ok(ArpPacket {
        hardware_type: read_u16(header, 0)?,
        protocol_type: read_u16(header, 2)?,
        operation: read_u16(header, 6)?,
        bytes,
    })
}

fn parse_ipv4(bytes: &[u8]) -> Result<IpPacket<'_>, ParseError> {
    let base = bytes.get(..20).ok_or(ParseError::Truncated)?;
    if base[0] >> 4 != 4 {
        return Err(ParseError::Malformed);
    }
    let header_length = usize::from(base[0] & 0x0f) * 4;
    if header_length < 20 {
        return Err(ParseError::Malformed);
    }
    let total_length = usize::from(read_u16(base, 2)?);
    if total_length < header_length {
        return Err(ParseError::Malformed);
    }
    let packet = bytes.get(..total_length).ok_or(ParseError::Truncated)?;
    let fragment = read_u16(base, 6)?;
    Ok(IpPacket {
        source: IpAddr::V4(Ipv4Addr::new(base[12], base[13], base[14], base[15])),
        destination: IpAddr::V4(Ipv4Addr::new(base[16], base[17], base[18], base[19])),
        protocol: base[9],
        non_initial_fragment: fragment & 0x1fff != 0,
        payload: &packet[header_length..],
    })
}

fn parse_ipv6(bytes: &[u8]) -> Result<IpPacket<'_>, ParseError> {
    let base = bytes.get(..40).ok_or(ParseError::Truncated)?;
    if base[0] >> 4 != 6 {
        return Err(ParseError::Malformed);
    }
    let payload_length = usize::from(read_u16(base, 4)?);
    let packet_length = 40usize
        .checked_add(payload_length)
        .ok_or(ParseError::Malformed)?;
    let packet = bytes.get(..packet_length).ok_or(ParseError::Truncated)?;
    let mut source = [0; 16];
    source.copy_from_slice(&base[8..24]);
    let mut destination = [0; 16];
    destination.copy_from_slice(&base[24..40]);
    let mut protocol = base[6];
    let mut offset = 40;
    let mut non_initial_fragment = false;
    for _ in 0..8 {
        let (next, length) = match protocol {
            0 | 43 | 60 => {
                let extension = packet
                    .get(offset..offset + 2)
                    .ok_or(ParseError::Truncated)?;
                (extension[0], (usize::from(extension[1]) + 1) * 8)
            }
            44 => {
                let extension = packet
                    .get(offset..offset + 8)
                    .ok_or(ParseError::Truncated)?;
                non_initial_fragment |= read_u16(extension, 2)? & 0xfff8 != 0;
                (extension[0], 8)
            }
            51 => {
                let extension = packet
                    .get(offset..offset + 2)
                    .ok_or(ParseError::Truncated)?;
                (extension[0], (usize::from(extension[1]) + 2) * 4)
            }
            _ => {
                return Ok(IpPacket {
                    source: IpAddr::V6(Ipv6Addr::from(source)),
                    destination: IpAddr::V6(Ipv6Addr::from(destination)),
                    protocol,
                    non_initial_fragment,
                    payload: packet.get(offset..).ok_or(ParseError::Truncated)?,
                });
            }
        };
        packet
            .get(offset..offset + length)
            .ok_or(ParseError::Truncated)?;
        offset = offset.checked_add(length).ok_or(ParseError::Malformed)?;
        protocol = next;
    }
    Err(ParseError::TooManyIpv6Extensions)
}

fn parse_tcp(bytes: &[u8]) -> Result<TcpSegment<'_>, ParseError> {
    let base = bytes.get(..20).ok_or(ParseError::Truncated)?;
    let header_length = usize::from(base[12] >> 4) * 4;
    if header_length < 20 {
        return Err(ParseError::Malformed);
    }
    let payload = bytes.get(header_length..).ok_or(ParseError::Truncated)?;
    Ok(TcpSegment {
        source_port: read_u16(base, 0)?,
        destination_port: read_u16(base, 2)?,
        sequence: read_u32(base, 4)?,
        acknowledgement: read_u32(base, 8)?,
        flags: (u16::from(base[12] & 1) << 8) | u16::from(base[13]),
        window: read_u16(base, 14)?,
        payload,
    })
}

fn parse_udp(bytes: &[u8]) -> Result<UdpDatagram<'_>, ParseError> {
    let base = bytes.get(..8).ok_or(ParseError::Truncated)?;
    let length = usize::from(read_u16(base, 4)?);
    if length < 8 {
        return Err(ParseError::Malformed);
    }
    let datagram = bytes.get(..length).ok_or(ParseError::Truncated)?;
    Ok(UdpDatagram {
        source_port: read_u16(base, 0)?,
        destination_port: read_u16(base, 2)?,
        payload: &datagram[8..],
    })
}

fn parse_icmp(bytes: &[u8]) -> Result<IcmpPacket<'_>, ParseError> {
    let message = bytes.get(..4).ok_or(ParseError::Truncated)?;
    Ok(IcmpPacket {
        message_type: message[0],
        code: message[1],
        payload: &bytes[4..],
    })
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, ParseError> {
    let value = bytes.get(offset..offset + 2).ok_or(ParseError::Truncated)?;
    Ok(u16::from_be_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, ParseError> {
    let value = bytes.get(offset..offset + 4).ok_or(ParseError::Truncated)?;
    Ok(u32::from_be_bytes([value[0], value[1], value[2], value[3]]))
}

#[cfg(test)]
mod tests {
    use super::{ParseError, TransportPacket, parse_packet};

    #[test]
    fn parses_qinq_ipv4_tcp_without_allocation() {
        let mut frame = vec![0_u8; 14 + 8 + 20 + 20 + 3];
        frame[12..14].copy_from_slice(&0x88a8_u16.to_be_bytes());
        frame[14..16].copy_from_slice(&100_u16.to_be_bytes());
        frame[16..18].copy_from_slice(&0x8100_u16.to_be_bytes());
        frame[18..20].copy_from_slice(&200_u16.to_be_bytes());
        frame[20..22].copy_from_slice(&0x0800_u16.to_be_bytes());
        let ip = 22;
        frame[ip] = 0x45;
        frame[ip + 2..ip + 4].copy_from_slice(&43_u16.to_be_bytes());
        frame[ip + 9] = 6;
        frame[ip + 12..ip + 16].copy_from_slice(&[192, 0, 2, 1]);
        frame[ip + 16..ip + 20].copy_from_slice(&[198, 51, 100, 2]);
        let tcp = ip + 20;
        frame[tcp..tcp + 2].copy_from_slice(&1234_u16.to_be_bytes());
        frame[tcp + 2..tcp + 4].copy_from_slice(&443_u16.to_be_bytes());
        frame[tcp + 12] = 0x50;
        frame[tcp + 13] = 0x18;
        frame[tcp + 20..].copy_from_slice(b"abc");

        let parsed = parse_packet(&frame).expect("valid packet");
        assert_eq!(parsed.ethernet.vlan_tags[0].expect("outer").identifier, 100);
        assert_eq!(parsed.ethernet.vlan_tags[1].expect("inner").identifier, 200);
        let Some(TransportPacket::Tcp(segment)) = parsed.transport else {
            panic!("expected TCP");
        };
        assert_eq!(segment.source_port, 1234);
        assert_eq!(segment.payload, b"abc");
    }

    #[test]
    fn rejects_every_truncated_prefix_without_panicking() {
        let mut frame = vec![0_u8; 14 + 20 + 20];
        frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        frame[14] = 0x45;
        frame[16..18].copy_from_slice(&40_u16.to_be_bytes());
        frame[23] = 6;
        frame[46] = 0x50;
        for length in 0..frame.len() {
            assert!(parse_packet(&frame[..length]).is_err(), "prefix {length}");
        }
        assert!(parse_packet(&frame).is_ok());
    }

    #[test]
    fn rejects_third_vlan_tag() {
        let mut frame = vec![0_u8; 26];
        frame[12..14].copy_from_slice(&0x8100_u16.to_be_bytes());
        frame[16..18].copy_from_slice(&0x8100_u16.to_be_bytes());
        frame[20..22].copy_from_slice(&0x8100_u16.to_be_bytes());
        assert_eq!(parse_packet(&frame), Err(ParseError::TooManyVlanTags));
    }
}

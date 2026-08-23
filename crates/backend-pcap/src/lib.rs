//! Bounds-checked streaming PCAP/PCAPNG offline backend。

#![forbid(unsafe_code)]

use nettool_error::{ErrorCode, NetToolError};
use nettool_packet::{BurstSource, PacketView};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

const MAX_CAPTURE_BLOCK_LENGTH: usize = 16 * 1024 * 1024;
const DEFAULT_BURST_SIZE: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Endian {
    Little,
    Big,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TimestampUnit {
    Microseconds,
    Nanoseconds,
}

#[derive(Clone, Debug)]
struct InterfaceDescription {
    link_type: u16,
    snaplen: u32,
    timestamp_resolution: TimestampResolution,
}

#[derive(Clone, Copy, Debug)]
enum TimestampResolution {
    Decimal(u8),
    Binary(u8),
}

enum CaptureFormat {
    Pcap {
        endian: Endian,
        timestamp_unit: TimestampUnit,
        link_type: u32,
        snaplen: u32,
    },
    PcapNg {
        endian: Endian,
        interfaces: Vec<InterfaceDescription>,
    },
}

#[derive(Clone, Copy)]
struct RecordMetadata {
    timestamp_nanoseconds: u64,
    wire_length: u32,
    queue_id: u16,
}

/// Streaming offline capture source；每次只保存目前 packet 與目前 block buffer。
pub struct CaptureFileSource {
    reader: BufReader<File>,
    format: CaptureFormat,
    packet_buffer: Vec<u8>,
    block_buffer: Vec<u8>,
    burst_size: usize,
    exhausted: bool,
}

impl CaptureFileSource {
    /// 開啟並驗證 PCAP 或 PCAPNG file header。
    ///
    /// # Errors
    ///
    /// File I/O、unknown magic、unsupported link type 或 malformed header 時回傳錯誤。
    pub fn open(path: impl AsRef<Path>) -> Result<Self, NetToolError> {
        let file = File::open(path).map_err(read_error)?;
        let mut reader = BufReader::new(file);
        let mut prefix = [0_u8; 4];
        reader.read_exact(&mut prefix).map_err(read_error)?;
        let format = match prefix {
            [0xd4, 0xc3, 0xb2, 0xa1] => {
                parse_pcap_header(&mut reader, Endian::Little, TimestampUnit::Microseconds)?
            }
            [0xa1, 0xb2, 0xc3, 0xd4] => {
                parse_pcap_header(&mut reader, Endian::Big, TimestampUnit::Microseconds)?
            }
            [0x4d, 0x3c, 0xb2, 0xa1] => {
                parse_pcap_header(&mut reader, Endian::Little, TimestampUnit::Nanoseconds)?
            }
            [0xa1, 0xb2, 0x3c, 0x4d] => {
                parse_pcap_header(&mut reader, Endian::Big, TimestampUnit::Nanoseconds)?
            }
            [0x0a, 0x0d, 0x0d, 0x0a] => parse_pcapng_section_header(&mut reader)?,
            _ => return Err(format_error("capture file magic is unsupported")),
        };
        Ok(Self {
            reader,
            format,
            packet_buffer: Vec::new(),
            block_buffer: Vec::new(),
            burst_size: DEFAULT_BURST_SIZE,
            exhausted: false,
        })
    }

    /// 設定每次 `receive_burst` 最多 records。
    ///
    /// # Errors
    ///
    /// Burst size 為零或大於 4096 時回傳錯誤。
    pub fn set_burst_size(&mut self, burst_size: usize) -> Result<(), NetToolError> {
        if !(1..=4096).contains(&burst_size) {
            return Err(NetToolError::new(
                ErrorCode::InvalidArgument,
                "offline capture burst size must be between 1 and 4096",
                false,
            ));
        }
        self.burst_size = burst_size;
        Ok(())
    }

    fn next_record(&mut self) -> Result<Option<RecordMetadata>, NetToolError> {
        match &mut self.format {
            CaptureFormat::Pcap {
                endian,
                timestamp_unit,
                link_type,
                snaplen,
            } => read_pcap_record(
                &mut self.reader,
                &mut self.packet_buffer,
                *endian,
                *timestamp_unit,
                *link_type,
                *snaplen,
            ),
            CaptureFormat::PcapNg { .. } => self.next_pcapng_record(),
        }
    }

    fn next_pcapng_record(&mut self) -> Result<Option<RecordMetadata>, NetToolError> {
        loop {
            let CaptureFormat::PcapNg { endian, interfaces } = &mut self.format else {
                return Err(format_error("internal capture format mismatch"));
            };
            let mut block_header = [0_u8; 8];
            if !read_exact_or_eof(&mut self.reader, &mut block_header)? {
                return Ok(None);
            }
            let block_type = read_u32(&block_header, 0, *endian)?;
            let total_length =
                usize::try_from(read_u32(&block_header, 4, *endian)?).unwrap_or(usize::MAX);
            if !(12..=MAX_CAPTURE_BLOCK_LENGTH).contains(&total_length) || total_length % 4 != 0 {
                return Err(format_error("PCAPNG block length is invalid"));
            }
            let remaining = total_length - 8;
            self.block_buffer.resize(remaining, 0);
            self.reader
                .read_exact(&mut self.block_buffer)
                .map_err(read_error)?;
            let trailing = read_u32(&self.block_buffer, remaining - 4, *endian)?;
            if usize::try_from(trailing).unwrap_or(usize::MAX) != total_length {
                return Err(format_error("PCAPNG trailing block length mismatch"));
            }
            let body = &self.block_buffer[..remaining - 4];
            match block_type {
                1 => parse_interface_description(body, *endian, interfaces)?,
                6 => {
                    let (metadata, packet_range) =
                        parse_enhanced_packet(body, *endian, interfaces)?;
                    self.packet_buffer.clear();
                    self.packet_buffer.extend_from_slice(&body[packet_range]);
                    return Ok(Some(metadata));
                }
                0x0a0d_0d0a => {
                    return Err(format_error(
                        "multiple PCAPNG sections are not supported by this backend",
                    ));
                }
                _ => {}
            }
        }
    }
}

impl BurstSource for CaptureFileSource {
    fn receive_burst(
        &mut self,
        mut consumer: impl FnMut(PacketView<'_>),
    ) -> Result<usize, NetToolError> {
        if self.exhausted {
            return Ok(0);
        }
        let mut received = 0;
        while received < self.burst_size {
            let Some(metadata) = self.next_record()? else {
                self.exhausted = true;
                break;
            };
            consumer(PacketView {
                bytes: &self.packet_buffer,
                timestamp_nanoseconds: metadata.timestamp_nanoseconds,
                wire_length: metadata.wire_length,
                queue_id: metadata.queue_id,
            });
            received += 1;
        }
        Ok(received)
    }

    fn is_exhausted(&self) -> bool {
        self.exhausted
    }
}

fn parse_pcap_header(
    reader: &mut impl Read,
    endian: Endian,
    timestamp_unit: TimestampUnit,
) -> Result<CaptureFormat, NetToolError> {
    let mut rest = [0_u8; 20];
    reader.read_exact(&mut rest).map_err(read_error)?;
    if read_u16(&rest, 0, endian)? != 2 || read_u16(&rest, 2, endian)? != 4 {
        return Err(format_error("PCAP version must be 2.4"));
    }
    let snaplen = read_u32(&rest, 12, endian)?;
    let link_type = read_u32(&rest, 16, endian)?;
    if snaplen == 0 || usize::try_from(snaplen).unwrap_or(usize::MAX) > MAX_CAPTURE_BLOCK_LENGTH {
        return Err(format_error("PCAP snaplen is invalid"));
    }
    if link_type != 1 {
        return Err(format_error("only Ethernet PCAP link type is supported"));
    }
    Ok(CaptureFormat::Pcap {
        endian,
        timestamp_unit,
        link_type,
        snaplen,
    })
}

fn parse_pcapng_section_header(reader: &mut impl Read) -> Result<CaptureFormat, NetToolError> {
    let mut prefix = [0_u8; 8];
    reader.read_exact(&mut prefix).map_err(read_error)?;
    let endian = match &prefix[4..8] {
        [0x4d, 0x3c, 0x2b, 0x1a] => Endian::Little,
        [0x1a, 0x2b, 0x3c, 0x4d] => Endian::Big,
        _ => return Err(format_error("PCAPNG byte-order magic is invalid")),
    };
    let total_length = usize::try_from(read_u32(&prefix, 0, endian)?).unwrap_or(usize::MAX);
    if !(28..=MAX_CAPTURE_BLOCK_LENGTH).contains(&total_length) || total_length % 4 != 0 {
        return Err(format_error("PCAPNG section header length is invalid"));
    }
    let mut remainder = vec![0_u8; total_length - 12];
    reader.read_exact(&mut remainder).map_err(read_error)?;
    if read_u16(&remainder, 0, endian)? != 1 {
        return Err(format_error("unsupported PCAPNG major version"));
    }
    let trailing = read_u32(&remainder, remainder.len() - 4, endian)?;
    if usize::try_from(trailing).unwrap_or(usize::MAX) != total_length {
        return Err(format_error("PCAPNG section trailing length mismatch"));
    }
    Ok(CaptureFormat::PcapNg {
        endian,
        interfaces: Vec::new(),
    })
}

fn read_pcap_record(
    reader: &mut impl Read,
    packet_buffer: &mut Vec<u8>,
    endian: Endian,
    timestamp_unit: TimestampUnit,
    link_type: u32,
    snaplen: u32,
) -> Result<Option<RecordMetadata>, NetToolError> {
    if link_type != 1 {
        return Err(format_error("PCAP link type changed unexpectedly"));
    }
    let mut header = [0_u8; 16];
    if !read_exact_or_eof(reader, &mut header)? {
        return Ok(None);
    }
    let seconds = u64::from(read_u32(&header, 0, endian)?);
    let fraction = u64::from(read_u32(&header, 4, endian)?);
    let captured = usize::try_from(read_u32(&header, 8, endian)?).unwrap_or(usize::MAX);
    let wire_length = read_u32(&header, 12, endian)?;
    if captured > MAX_CAPTURE_BLOCK_LENGTH
        || u64::try_from(captured).unwrap_or(u64::MAX) > u64::from(snaplen)
        || u64::try_from(captured).unwrap_or(u64::MAX) > u64::from(wire_length)
    {
        return Err(format_error("PCAP record length is invalid"));
    }
    let fraction_nanoseconds = match timestamp_unit {
        TimestampUnit::Microseconds if fraction < 1_000_000 => fraction.saturating_mul(1_000),
        TimestampUnit::Nanoseconds if fraction < 1_000_000_000 => fraction,
        _ => return Err(format_error("PCAP timestamp fraction is invalid")),
    };
    packet_buffer.resize(captured, 0);
    reader.read_exact(packet_buffer).map_err(read_error)?;
    Ok(Some(RecordMetadata {
        timestamp_nanoseconds: seconds
            .saturating_mul(1_000_000_000)
            .saturating_add(fraction_nanoseconds),
        wire_length,
        queue_id: 0,
    }))
}

fn parse_interface_description(
    body: &[u8],
    endian: Endian,
    interfaces: &mut Vec<InterfaceDescription>,
) -> Result<(), NetToolError> {
    if body.len() < 8 {
        return Err(format_error("PCAPNG interface block is truncated"));
    }
    let link_type = read_u16(body, 0, endian)?;
    if link_type != 1 {
        return Err(format_error(
            "only Ethernet PCAPNG interfaces are supported",
        ));
    }
    let snaplen = read_u32(body, 4, endian)?;
    let mut timestamp_resolution = TimestampResolution::Decimal(6);
    parse_options(&body[8..], endian, |code, value| {
        if code == 9 && value.len() == 1 {
            timestamp_resolution = if value[0] & 0x80 == 0 {
                TimestampResolution::Decimal(value[0])
            } else {
                TimestampResolution::Binary(value[0] & 0x7f)
            };
        }
        Ok(())
    })?;
    interfaces.push(InterfaceDescription {
        link_type,
        snaplen,
        timestamp_resolution,
    });
    Ok(())
}

fn parse_enhanced_packet(
    body: &[u8],
    endian: Endian,
    interfaces: &[InterfaceDescription],
) -> Result<(RecordMetadata, std::ops::Range<usize>), NetToolError> {
    if body.len() < 20 {
        return Err(format_error("PCAPNG enhanced packet is truncated"));
    }
    let interface_id = usize::try_from(read_u32(body, 0, endian)?).unwrap_or(usize::MAX);
    let interface = interfaces
        .get(interface_id)
        .ok_or_else(|| format_error("PCAPNG packet references unknown interface"))?;
    if interface.link_type != 1 {
        return Err(format_error("PCAPNG packet interface is not Ethernet"));
    }
    let timestamp =
        (u64::from(read_u32(body, 4, endian)?) << 32) | u64::from(read_u32(body, 8, endian)?);
    let captured = usize::try_from(read_u32(body, 12, endian)?).unwrap_or(usize::MAX);
    let wire_length = read_u32(body, 16, endian)?;
    if captured > MAX_CAPTURE_BLOCK_LENGTH
        || (interface.snaplen != 0
            && u64::try_from(captured).unwrap_or(u64::MAX) > u64::from(interface.snaplen))
        || u64::try_from(captured).unwrap_or(u64::MAX) > u64::from(wire_length)
    {
        return Err(format_error("PCAPNG packet length is invalid"));
    }
    let padded = captured
        .checked_add(3)
        .ok_or_else(|| format_error("PCAPNG packet length overflow"))?
        & !3;
    let packet_end = 20usize
        .checked_add(captured)
        .ok_or_else(|| format_error("PCAPNG packet length overflow"))?;
    let options_offset = 20usize
        .checked_add(padded)
        .ok_or_else(|| format_error("PCAPNG packet length overflow"))?;
    if options_offset > body.len() || packet_end > body.len() {
        return Err(format_error("PCAPNG packet data is truncated"));
    }
    let mut queue_id = u16::try_from(interface_id).unwrap_or(u16::MAX);
    parse_options(&body[options_offset..], endian, |code, value| {
        if code == 1 {
            if let Ok(comment) = std::str::from_utf8(value) {
                if let Some(raw) = comment.strip_prefix("queue_id=") {
                    queue_id = raw
                        .parse()
                        .map_err(|_| format_error("PCAPNG queue comment is invalid"))?;
                }
            }
        }
        Ok(())
    })?;
    Ok((
        RecordMetadata {
            timestamp_nanoseconds: timestamp_to_nanoseconds(
                timestamp,
                interface.timestamp_resolution,
            )?,
            wire_length,
            queue_id,
        },
        20..packet_end,
    ))
}

fn parse_options(
    mut bytes: &[u8],
    endian: Endian,
    mut visitor: impl FnMut(u16, &[u8]) -> Result<(), NetToolError>,
) -> Result<(), NetToolError> {
    while !bytes.is_empty() {
        if bytes.len() < 4 {
            return Err(format_error("PCAPNG option header is truncated"));
        }
        let code = read_u16(bytes, 0, endian)?;
        let length = usize::from(read_u16(bytes, 2, endian)?);
        bytes = &bytes[4..];
        if code == 0 {
            if length != 0 {
                return Err(format_error("PCAPNG end option has non-zero length"));
            }
            return Ok(());
        }
        let padded = length
            .checked_add(3)
            .ok_or_else(|| format_error("PCAPNG option length overflow"))?
            & !3;
        if padded > bytes.len() || length > bytes.len() {
            return Err(format_error("PCAPNG option is truncated"));
        }
        visitor(code, &bytes[..length])?;
        bytes = &bytes[padded..];
    }
    Ok(())
}

fn timestamp_to_nanoseconds(
    timestamp: u64,
    resolution: TimestampResolution,
) -> Result<u64, NetToolError> {
    match resolution {
        TimestampResolution::Decimal(power) if power <= 9 => {
            Ok(timestamp.saturating_mul(10_u64.saturating_pow(u32::from(9 - power))))
        }
        TimestampResolution::Decimal(power) if power <= 19 => {
            Ok(timestamp / 10_u64.saturating_pow(u32::from(power - 9)))
        }
        TimestampResolution::Binary(power) if power <= 63 => {
            let numerator = u128::from(timestamp).saturating_mul(1_000_000_000);
            Ok(u64::try_from(numerator >> power).unwrap_or(u64::MAX))
        }
        _ => Err(format_error("PCAPNG timestamp resolution is unsupported")),
    }
}

fn read_exact_or_eof(reader: &mut impl Read, bytes: &mut [u8]) -> Result<bool, NetToolError> {
    let mut offset = 0;
    while offset < bytes.len() {
        match reader.read(&mut bytes[offset..]) {
            Ok(0) if offset == 0 => return Ok(false),
            Ok(0) => return Err(format_error("capture record is truncated")),
            Ok(read) => offset += read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(read_error(error)),
        }
    }
    Ok(true)
}

fn read_u16(bytes: &[u8], offset: usize, endian: Endian) -> Result<u16, NetToolError> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| format_error("capture field is truncated"))?;
    Ok(match endian {
        Endian::Little => u16::from_le_bytes([value[0], value[1]]),
        Endian::Big => u16::from_be_bytes([value[0], value[1]]),
    })
}

fn read_u32(bytes: &[u8], offset: usize, endian: Endian) -> Result<u32, NetToolError> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| format_error("capture field is truncated"))?;
    Ok(match endian {
        Endian::Little => u32::from_le_bytes([value[0], value[1], value[2], value[3]]),
        Endian::Big => u32::from_be_bytes([value[0], value[1], value[2], value[3]]),
    })
}

fn format_error(message: &str) -> NetToolError {
    NetToolError::new(ErrorCode::CaptureFormatInvalid, message, false)
}

#[allow(clippy::needless_pass_by_value)]
fn read_error(error: std::io::Error) -> NetToolError {
    NetToolError::new(
        ErrorCode::CaptureReadFailed,
        format!("capture file read failed: {error}"),
        error.kind() == std::io::ErrorKind::Interrupted,
    )
}

#[cfg(test)]
mod tests {
    use super::CaptureFileSource;
    use nettool_packet::{
        BurstSource, CaptureFormat, CaptureMode, CaptureRecord, CaptureRotation, PacketView,
        RotatingCaptureWriter,
    };
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_ID: AtomicU64 = AtomicU64::new(0);

    fn path(extension: &str) -> std::path::PathBuf {
        let id = TEST_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "nettool-offline-{}-{id}.{extension}",
            std::process::id()
        ))
    }

    #[test]
    fn streams_little_endian_nanosecond_pcap() {
        let path = path("pcap");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0xa1b2_3c4d_u32.to_le_bytes());
        bytes.extend_from_slice(&2_u16.to_le_bytes());
        bytes.extend_from_slice(&4_u16.to_le_bytes());
        bytes.extend_from_slice(&0_i32.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&65_535_u32.to_le_bytes());
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&5_u32.to_le_bytes());
        bytes.extend_from_slice(&3_u32.to_le_bytes());
        bytes.extend_from_slice(&3_u32.to_le_bytes());
        bytes.extend_from_slice(&[1, 2, 3]);
        fs::write(&path, bytes).expect("fixture");
        let mut source = CaptureFileSource::open(&path).expect("source");
        let mut packets = Vec::new();
        assert_eq!(
            source
                .receive_burst(|packet: PacketView<'_>| packets
                    .push((packet.timestamp_nanoseconds, packet.bytes.to_vec())))
                .expect("burst"),
            1
        );
        assert_eq!(packets, [(1_000_000_005, vec![1, 2, 3])]);
        assert!(source.is_exhausted());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn rejects_record_larger_than_wire_length() {
        let path = path("pcap");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0xa1b2_3c4d_u32.to_le_bytes());
        bytes.extend_from_slice(&2_u16.to_le_bytes());
        bytes.extend_from_slice(&4_u16.to_le_bytes());
        bytes.extend_from_slice(&0_i32.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&65_535_u32.to_le_bytes());
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&4_u32.to_le_bytes());
        bytes.extend_from_slice(&3_u32.to_le_bytes());
        bytes.extend_from_slice(&[0; 4]);
        fs::write(&path, bytes).expect("fixture");
        let mut source = CaptureFileSource::open(&path).expect("header");
        assert!(source.receive_burst(|_| {}).is_err());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn rejects_record_larger_than_declared_snaplen() {
        let path = path("pcap");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0xa1b2_3c4d_u32.to_le_bytes());
        bytes.extend_from_slice(&2_u16.to_le_bytes());
        bytes.extend_from_slice(&4_u16.to_le_bytes());
        bytes.extend_from_slice(&0_i32.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&2_u32.to_le_bytes());
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&3_u32.to_le_bytes());
        bytes.extend_from_slice(&3_u32.to_le_bytes());
        bytes.extend_from_slice(&[1, 2, 3]);
        fs::write(&path, bytes).expect("fixture");
        let mut source = CaptureFileSource::open(&path).expect("header");
        assert!(source.receive_burst(|_| {}).is_err());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn reads_pcapng_emitted_by_capture_writer_with_queue_metadata() {
        let directory = path("dir");
        let mut writer = RotatingCaptureWriter::create(
            &directory,
            "capture",
            CaptureFormat::PcapNg,
            CaptureMode::FullPacket,
            "eth0",
            CaptureRotation {
                maximum_bytes: None,
                maximum_duration: None,
                file_count: 1,
            },
        )
        .expect("writer");
        writer
            .write_record(&CaptureRecord {
                timestamp_nanoseconds: 42,
                wire_length: 3,
                queue_id: 7,
                bytes: vec![1, 2, 3],
            })
            .expect("record");
        writer.flush().expect("flush");
        drop(writer);
        let capture = directory.join("capture-0000000000000000.pcapng");
        let mut source = CaptureFileSource::open(capture).expect("source");
        let mut result = None;
        assert_eq!(
            source
                .receive_burst(|packet| {
                    result = Some((
                        packet.timestamp_nanoseconds,
                        packet.queue_id,
                        packet.bytes.to_vec(),
                    ));
                })
                .expect("burst"),
            1
        );
        assert_eq!(result, Some((42, 7, vec![1, 2, 3])));
        let _ = fs::remove_dir_all(directory);
    }
}

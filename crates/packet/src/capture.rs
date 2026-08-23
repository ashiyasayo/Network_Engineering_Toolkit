use crate::{PacketView, WorkerStats};
use nettool_error::{ErrorCode, NetToolError};
use std::collections::VecDeque;
use std::fs::{File, create_dir_all, remove_file};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, TrySendError, sync_channel};
use std::time::{Duration, Instant};

const PCAP_GLOBAL_HEADER_LENGTH: u64 = 24;
const PCAP_RECORD_HEADER_LENGTH: u64 = 16;

/// Capture payload policy。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureMode {
    /// 只保存 timestamp、wire length 與 queue metadata。
    MetadataOnly,
    /// 保存固定 L2/L3/L4 header prefix。
    HeaderOnly,
    /// 保存使用者指定的最大 bytes。
    Snaplen(u32),
    /// 保存 backend 提供的完整可見 packet。
    FullPacket,
}

impl CaptureMode {
    fn retained_length(self, visible_length: usize) -> usize {
        match self {
            Self::MetadataOnly => 0,
            Self::HeaderOnly => visible_length.min(128),
            Self::Snaplen(length) => {
                visible_length.min(usize::try_from(length).unwrap_or(usize::MAX))
            }
            Self::FullPacket => visible_length,
        }
    }

    fn snaplen(self) -> u32 {
        match self {
            // PCAP snaplen 必須為正值；record captured length 仍維持零。
            Self::MetadataOnly => 1,
            Self::HeaderOnly => 128,
            Self::Snaplen(length) => length,
            Self::FullPacket => u32::MAX,
        }
    }
}

/// Capture file format。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureFormat {
    /// PCAPNG，保存 interface 與 nanosecond timestamp metadata。
    PcapNg,
    /// Legacy PCAP nanosecond format。
    Pcap,
}

/// 已從 backend ownership 複製出的 bounded capture record。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureRecord {
    /// Monotonic/backend timestamp nanoseconds。
    pub timestamp_nanoseconds: u64,
    /// Original wire length。
    pub wire_length: u32,
    /// RX queue identifier。
    pub queue_id: u16,
    /// 依 capture mode 截取的 bytes。
    pub bytes: Vec<u8>,
}

/// RX worker 端的 non-blocking bounded queue producer。
#[derive(Clone)]
pub struct CaptureQueue {
    sender: SyncSender<CaptureRecord>,
    mode: CaptureMode,
}

/// Capture writer 專用的 queue consumer。
pub struct CaptureReceiver {
    receiver: Receiver<CaptureRecord>,
}

impl CaptureQueue {
    /// 建立固定 record capacity 的 capture queue。
    ///
    /// # Errors
    ///
    /// Capacity 為零時回傳錯誤，避免 rendezvous channel 反向阻塞 RX worker。
    pub fn bounded(
        capacity: usize,
        mode: CaptureMode,
    ) -> Result<(Self, CaptureReceiver), NetToolError> {
        if capacity == 0 {
            return Err(NetToolError::new(
                ErrorCode::InvalidArgument,
                "capture queue capacity must be greater than zero",
                false,
            ));
        }
        let (sender, receiver) = sync_channel(capacity);
        Ok((Self { sender, mode }, CaptureReceiver { receiver }))
    }

    /// 複製 capture policy 允許的 bytes 並嘗試排入 writer queue，永不等待 consumer。
    ///
    /// Queue 滿時更新 worker-local capture drop；writer 已關閉時更新 application drop。
    pub fn try_capture(&self, packet: PacketView<'_>, stats: &mut WorkerStats) {
        let retained = self.mode.retained_length(packet.bytes.len());
        let record = CaptureRecord {
            timestamp_nanoseconds: packet.timestamp_nanoseconds,
            wire_length: packet.wire_length,
            queue_id: packet.queue_id,
            bytes: packet.bytes[..retained].to_vec(),
        };
        match self.sender.try_send(record) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                stats.drops.capture = stats.drops.capture.saturating_add(1);
            }
            Err(TrySendError::Disconnected(_)) => {
                stats.drops.application = stats.drops.application.saturating_add(1);
            }
        }
    }
}

impl CaptureReceiver {
    /// Non-blocking 接收下一筆 record。
    ///
    /// # Errors
    ///
    /// Queue 尚空或所有 producers 已關閉時保留標準 channel error。
    pub fn try_receive(&self) -> Result<CaptureRecord, TryRecvError> {
        self.receiver.try_recv()
    }

    /// Blocking writer thread 接收下一筆 record。
    #[must_use]
    pub fn receive(&self) -> Option<CaptureRecord> {
        self.receiver.recv().ok()
    }
}

/// File rotation policy；任一已設定限制到達即 rotation。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureRotation {
    /// 單檔最大 bytes；`None` 表示不依 size rotation。
    pub maximum_bytes: Option<u64>,
    /// 單檔最大 duration。
    pub maximum_duration: Option<Duration>,
    /// 最多保留檔案數；必須大於零。
    pub file_count: usize,
}

/// Full capture storage certification evidence。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureStorageEvidence {
    /// 預期持續寫入速率，bytes/s。
    pub expected_bytes_per_second: u64,
    /// 同一目標 storage 實測持續寫入速率，bytes/s。
    pub measured_bytes_per_second: u64,
    /// Rotation window 預期占用 bytes。
    pub required_capacity_bytes: u64,
    /// 目標 filesystem 可用 bytes。
    pub available_capacity_bytes: u64,
}

/// Storage guard 判定結果。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureStorageGuard {
    /// 實測 write rate 是否足夠。
    pub rate_sufficient: bool,
    /// 可用容量是否足夠。
    pub capacity_sufficient: bool,
}

/// 依實測 storage evidence 認證 lossless capture。
///
/// # Errors
///
/// Write rate 或 capacity 不足時回傳規格要求的 stable error code。
pub fn certify_capture_storage(
    evidence: CaptureStorageEvidence,
) -> Result<CaptureStorageGuard, NetToolError> {
    let guard = CaptureStorageGuard {
        rate_sufficient: evidence.measured_bytes_per_second >= evidence.expected_bytes_per_second,
        capacity_sufficient: evidence.available_capacity_bytes >= evidence.required_capacity_bytes,
    };
    if guard.rate_sufficient && guard.capacity_sufficient {
        Ok(guard)
    } else {
        let mut error = NetToolError::new(
            ErrorCode::LosslessCaptureNotCertified,
            "storage cannot sustain the requested lossless capture",
            false,
        );
        error.details.insert(
            "expected_bytes_per_second".into(),
            evidence.expected_bytes_per_second.to_string(),
        );
        error.details.insert(
            "measured_bytes_per_second".into(),
            evidence.measured_bytes_per_second.to_string(),
        );
        error.details.insert(
            "required_capacity_bytes".into(),
            evidence.required_capacity_bytes.to_string(),
        );
        error.details.insert(
            "available_capacity_bytes".into(),
            evidence.available_capacity_bytes.to_string(),
        );
        Err(error)
    }
}

/// 具 size、duration 與 retained file count rotation 的 capture writer。
pub struct RotatingCaptureWriter {
    directory: PathBuf,
    prefix: String,
    format: CaptureFormat,
    mode: CaptureMode,
    interface_name: String,
    rotation: CaptureRotation,
    generation: u64,
    current: File,
    current_bytes: u64,
    records_in_current: u64,
    opened_at: Instant,
    retained_files: VecDeque<PathBuf>,
}

impl RotatingCaptureWriter {
    /// 建立第一個 capture file 並寫入 format header。
    ///
    /// # Errors
    ///
    /// Rotation policy 無效、目錄或檔案無法建立、header 無法寫入時回傳錯誤。
    pub fn create(
        directory: impl AsRef<Path>,
        prefix: impl Into<String>,
        format: CaptureFormat,
        mode: CaptureMode,
        interface_name: impl Into<String>,
        rotation: CaptureRotation,
    ) -> io::Result<Self> {
        if rotation.file_count == 0 || rotation.maximum_bytes == Some(0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid capture rotation policy",
            ));
        }
        let directory = directory.as_ref().to_path_buf();
        create_dir_all(&directory)?;
        let prefix = prefix.into();
        let interface_name = interface_name.into();
        let path = capture_path(&directory, &prefix, format, 0);
        let mut current = File::create(&path)?;
        let current_bytes = write_file_header(&mut current, format, mode, &interface_name)?;
        let mut retained_files = VecDeque::new();
        retained_files.push_back(path);
        Ok(Self {
            directory,
            prefix,
            format,
            mode,
            interface_name,
            rotation,
            generation: 0,
            current,
            current_bytes,
            records_in_current: 0,
            opened_at: Instant::now(),
            retained_files,
        })
    }

    /// 寫入一筆 record，必要時先 rotation；不與 RX worker 共用此物件。
    ///
    /// # Errors
    ///
    /// Rotation、write、flush 或舊檔清理失敗時回傳 I/O error，不靜默忽略資料風險。
    pub fn write_record(&mut self, record: &CaptureRecord) -> io::Result<()> {
        let estimated = record_encoded_length(self.format, record.bytes.len());
        if self.should_rotate(estimated) {
            self.rotate()?;
        }
        let written = match self.format {
            CaptureFormat::Pcap => write_pcap_record(&mut self.current, record)?,
            CaptureFormat::PcapNg => write_pcapng_record(&mut self.current, record)?,
        };
        self.current_bytes = self.current_bytes.saturating_add(written);
        self.records_in_current = self.records_in_current.saturating_add(1);
        Ok(())
    }

    /// Flush 目前檔案。
    ///
    /// # Errors
    ///
    /// OS flush 失敗時回傳錯誤。
    pub fn flush(&mut self) -> io::Result<()> {
        self.current.flush()
    }

    fn should_rotate(&self, next_record_bytes: u64) -> bool {
        self.rotation.maximum_bytes.is_some_and(|limit| {
            self.records_in_current > 0
                && self.current_bytes.saturating_add(next_record_bytes) > limit
        }) || self
            .rotation
            .maximum_duration
            .is_some_and(|limit| self.opened_at.elapsed() >= limit)
    }

    fn rotate(&mut self) -> io::Result<()> {
        self.current.flush()?;
        self.generation = self.generation.wrapping_add(1);
        let path = capture_path(&self.directory, &self.prefix, self.format, self.generation);
        let mut next = File::create(&path)?;
        let bytes = write_file_header(&mut next, self.format, self.mode, &self.interface_name)?;
        self.current = next;
        self.current_bytes = bytes;
        self.records_in_current = 0;
        self.opened_at = Instant::now();
        self.retained_files.push_back(path);
        while self.retained_files.len() > self.rotation.file_count {
            if let Some(expired) = self.retained_files.pop_front() {
                remove_file(expired)?;
            }
        }
        Ok(())
    }
}

fn capture_path(directory: &Path, prefix: &str, format: CaptureFormat, generation: u64) -> PathBuf {
    let extension = match format {
        CaptureFormat::PcapNg => "pcapng",
        CaptureFormat::Pcap => "pcap",
    };
    directory.join(format!("{prefix}-{generation:016x}.{extension}"))
}

fn write_file_header(
    writer: &mut impl Write,
    format: CaptureFormat,
    mode: CaptureMode,
    interface_name: &str,
) -> io::Result<u64> {
    match format {
        CaptureFormat::Pcap => write_pcap_header(writer, mode.snaplen()),
        CaptureFormat::PcapNg => write_pcapng_header(writer, mode.snaplen(), interface_name),
    }
}

fn write_pcap_header(writer: &mut impl Write, snaplen: u32) -> io::Result<u64> {
    writer.write_all(&0xa1b2_3c4d_u32.to_le_bytes())?;
    writer.write_all(&2_u16.to_le_bytes())?;
    writer.write_all(&4_u16.to_le_bytes())?;
    writer.write_all(&0_i32.to_le_bytes())?;
    writer.write_all(&0_u32.to_le_bytes())?;
    writer.write_all(&snaplen.to_le_bytes())?;
    writer.write_all(&1_u32.to_le_bytes())?;
    Ok(PCAP_GLOBAL_HEADER_LENGTH)
}

fn write_pcap_record(writer: &mut impl Write, record: &CaptureRecord) -> io::Result<u64> {
    let seconds = record.timestamp_nanoseconds / 1_000_000_000;
    let nanoseconds = record.timestamp_nanoseconds % 1_000_000_000;
    writer.write_all(&u32::try_from(seconds).unwrap_or(u32::MAX).to_le_bytes())?;
    writer.write_all(&u32::try_from(nanoseconds).unwrap_or(u32::MAX).to_le_bytes())?;
    let captured = u32::try_from(record.bytes.len()).unwrap_or(u32::MAX);
    writer.write_all(&captured.to_le_bytes())?;
    writer.write_all(&record.wire_length.to_le_bytes())?;
    writer.write_all(&record.bytes)?;
    Ok(PCAP_RECORD_HEADER_LENGTH + u64::from(captured))
}

fn write_pcapng_header(
    writer: &mut impl Write,
    snaplen: u32,
    interface_name: &str,
) -> io::Result<u64> {
    write_block(
        writer,
        0x0a0d_0d0a,
        &[
            &0x1a2b_3c4d_u32.to_le_bytes(),
            &1_u16.to_le_bytes(),
            &0_u16.to_le_bytes(),
            &u64::MAX.to_le_bytes(),
        ],
    )?;
    let name = interface_name.as_bytes();
    let name_length = u16::try_from(name.len()).unwrap_or(u16::MAX);
    let name = &name[..usize::from(name_length)];
    let mut options = Vec::with_capacity(name.len() + 16);
    options.extend_from_slice(&2_u16.to_le_bytes());
    options.extend_from_slice(&name_length.to_le_bytes());
    options.extend_from_slice(name);
    pad_to_u32(&mut options);
    options.extend_from_slice(&9_u16.to_le_bytes());
    options.extend_from_slice(&1_u16.to_le_bytes());
    options.push(9);
    pad_to_u32(&mut options);
    options.extend_from_slice(&0_u32.to_le_bytes());
    let mut body = Vec::with_capacity(8 + options.len());
    body.extend_from_slice(&1_u16.to_le_bytes());
    body.extend_from_slice(&0_u16.to_le_bytes());
    body.extend_from_slice(&snaplen.to_le_bytes());
    body.extend_from_slice(&options);
    let interface_block = write_block(writer, 1, &[&body])?;
    Ok(28 + interface_block)
}

fn write_pcapng_record(writer: &mut impl Write, record: &CaptureRecord) -> io::Result<u64> {
    let captured = u32::try_from(record.bytes.len()).unwrap_or(u32::MAX);
    let timestamp_high = u32::try_from(record.timestamp_nanoseconds >> 32).unwrap_or(u32::MAX);
    let timestamp_low =
        u32::try_from(record.timestamp_nanoseconds & u64::from(u32::MAX)).unwrap_or(u32::MAX);
    let mut body = Vec::with_capacity(20 + record.bytes.len() + 4);
    // 目前每個檔案只宣告一個 IDB，因此 EPB interface ID 固定為零；queue ID 放在 comment option。
    body.extend_from_slice(&0_u32.to_le_bytes());
    body.extend_from_slice(&timestamp_high.to_le_bytes());
    body.extend_from_slice(&timestamp_low.to_le_bytes());
    body.extend_from_slice(&captured.to_le_bytes());
    body.extend_from_slice(&record.wire_length.to_le_bytes());
    body.extend_from_slice(&record.bytes);
    pad_to_u32(&mut body);
    let queue_comment = format!("queue_id={}", record.queue_id);
    body.extend_from_slice(&1_u16.to_le_bytes());
    body.extend_from_slice(
        &u16::try_from(queue_comment.len())
            .unwrap_or(u16::MAX)
            .to_le_bytes(),
    );
    body.extend_from_slice(queue_comment.as_bytes());
    pad_to_u32(&mut body);
    body.extend_from_slice(&0_u32.to_le_bytes());
    write_block(writer, 6, &[&body])
}

fn write_block(writer: &mut impl Write, block_type: u32, bodies: &[&[u8]]) -> io::Result<u64> {
    let body_length = bodies
        .iter()
        .try_fold(0_u64, |total, body| {
            total.checked_add(u64::try_from(body.len()).unwrap_or(u64::MAX))
        })
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "capture block too large"))?;
    let total = body_length
        .checked_add(12)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "capture block too large"))?;
    let total_u32 = u32::try_from(total)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "capture block too large"))?;
    writer.write_all(&block_type.to_le_bytes())?;
    writer.write_all(&total_u32.to_le_bytes())?;
    for body in bodies {
        writer.write_all(body)?;
    }
    writer.write_all(&total_u32.to_le_bytes())?;
    Ok(total)
}

fn pad_to_u32(bytes: &mut Vec<u8>) {
    while bytes.len() % 4 != 0 {
        bytes.push(0);
    }
}

fn record_encoded_length(format: CaptureFormat, captured_length: usize) -> u64 {
    let captured = u64::try_from(captured_length).unwrap_or(u64::MAX);
    match format {
        CaptureFormat::Pcap => PCAP_RECORD_HEADER_LENGTH.saturating_add(captured),
        // Queue comment option 的十進位內容至多 14 bytes，另含 option headers 與 padding。
        CaptureFormat::PcapNg => 56_u64.saturating_add(captured.saturating_add(3) & !3),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CaptureFormat, CaptureMode, CaptureQueue, CaptureRecord, CaptureRotation,
        CaptureStorageEvidence, RotatingCaptureWriter, certify_capture_storage, write_pcap_header,
        write_pcap_record, write_pcapng_header, write_pcapng_record,
    };
    use crate::{PacketView, WorkerStats};
    use nettool_error::ErrorCode;
    use std::fs;
    use std::time::Duration;

    #[test]
    fn bounded_queue_drops_without_blocking() {
        let (queue, receiver) = CaptureQueue::bounded(1, CaptureMode::HeaderOnly).expect("queue");
        let packet = PacketView {
            bytes: &[7; 256],
            timestamp_nanoseconds: 1,
            wire_length: 256,
            queue_id: 3,
        };
        let mut stats = WorkerStats::default();
        queue.try_capture(packet, &mut stats);
        queue.try_capture(packet, &mut stats);
        assert_eq!(stats.drops.capture, 1);
        assert_eq!(receiver.try_receive().expect("record").bytes.len(), 128);
    }

    #[test]
    fn emits_pcap_and_pcapng_headers_and_records() {
        let record = CaptureRecord {
            timestamp_nanoseconds: 1_500_000_009,
            wire_length: 64,
            queue_id: 2,
            bytes: vec![1, 2, 3],
        };
        let mut pcap = Vec::new();
        write_pcap_header(&mut pcap, 128).expect("header");
        write_pcap_record(&mut pcap, &record).expect("record");
        assert_eq!(&pcap[..4], &0xa1b2_3c4d_u32.to_le_bytes());
        assert_eq!(pcap.len(), 24 + 16 + 3);

        let mut pcapng = Vec::new();
        write_pcapng_header(&mut pcapng, 128, "eth0").expect("header");
        write_pcapng_record(&mut pcapng, &record).expect("record");
        assert_eq!(&pcapng[..4], &0x0a0d_0d0a_u32.to_le_bytes());
        assert!(pcapng.windows(4).any(|value| value == 6_u32.to_le_bytes()));
        assert!(pcapng.windows(10).any(|value| value == b"queue_id=2"));
        let mut offset = 0;
        while offset < pcapng.len() {
            let length = u32::from_le_bytes(
                pcapng[offset + 4..offset + 8]
                    .try_into()
                    .expect("block length"),
            );
            let length = usize::try_from(length).expect("usize block length");
            assert!(length >= 12);
            assert_eq!(
                &pcapng[offset + 4..offset + 8],
                &pcapng[offset + length - 4..offset + length]
            );
            offset += length;
        }
        assert_eq!(offset, pcapng.len());
    }

    #[test]
    fn storage_guard_never_certifies_insufficient_rate() {
        let error = certify_capture_storage(CaptureStorageEvidence {
            expected_bytes_per_second: 10_000,
            measured_bytes_per_second: 9_999,
            required_capacity_bytes: 1,
            available_capacity_bytes: 1,
        })
        .expect_err("rate is insufficient");
        assert_eq!(error.code, ErrorCode::LosslessCaptureNotCertified);
    }

    #[test]
    fn rotation_enforces_retained_file_count() {
        let directory =
            std::env::temp_dir().join(format!("nettool-capture-{}", std::process::id()));
        if directory.exists() {
            fs::remove_dir_all(&directory).expect("remove stale fixture");
        }
        let mut writer = RotatingCaptureWriter::create(
            &directory,
            "capture",
            CaptureFormat::Pcap,
            CaptureMode::FullPacket,
            "eth0",
            CaptureRotation {
                maximum_bytes: Some(50),
                maximum_duration: Some(Duration::from_secs(60)),
                file_count: 2,
            },
        )
        .expect("writer");
        let record = CaptureRecord {
            timestamp_nanoseconds: 1,
            wire_length: 20,
            queue_id: 0,
            bytes: vec![0; 20],
        };
        writer.write_record(&record).expect("first");
        writer.write_record(&record).expect("second");
        writer.write_record(&record).expect("third");
        writer.flush().expect("flush");
        assert_eq!(fs::read_dir(&directory).expect("directory").count(), 2);
        fs::remove_dir_all(directory).expect("cleanup fixture");
    }
}

//! Linux `AF_XDP` socket setup boundary。

#![allow(unsafe_code)]

/// 此 build 是否包含 Linux `AF_XDP` native socket/map/link implementation。
#[must_use]
pub const fn is_backend_built() -> bool {
    cfg!(target_os = "linux")
}

use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::fmt;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
#[cfg(target_os = "linux")]
use std::time::Duration;

/// `AF_XDP` 建立時的固定資源設定。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AfXdpConfig {
    /// 目標 RX/TX queue。
    pub queue_id: u32,
    /// RX descriptors。
    pub rx_ring_size: u32,
    /// TX descriptors。
    pub tx_ring_size: u32,
    /// FILL ring descriptors。
    pub fill_ring_size: u32,
    /// COMPLETION ring descriptors。
    pub completion_ring_size: u32,
    /// 是否強制 kernel zero-copy。
    pub require_zero_copy: bool,
}

impl Default for AfXdpConfig {
    fn default() -> Self {
        Self {
            queue_id: 0,
            rx_ring_size: 1024,
            tx_ring_size: 1024,
            fill_ring_size: 2048,
            completion_ring_size: 2048,
            require_zero_copy: true,
        }
    }
}

impl AfXdpConfig {
    /// 驗證 ring 數量為 kernel 可接受的非零 power-of-two。
    ///
    /// # Errors
    ///
    /// ring 為零、非 power-of-two 或超過上限時回傳錯誤。
    pub fn validate(self) -> Result<Self, AfXdpError> {
        for (name, value) in [
            ("rx_ring_size", self.rx_ring_size),
            ("tx_ring_size", self.tx_ring_size),
            ("fill_ring_size", self.fill_ring_size),
            ("completion_ring_size", self.completion_ring_size),
        ] {
            if value == 0 || !value.is_power_of_two() || value > 1 << 20 {
                return Err(AfXdpError::InvalidConfig(format!(
                    "{name} must be a power-of-two between 1 and 1048576"
                )));
            }
        }
        Ok(self)
    }
}

/// `AF_XDP` setup 錯誤；包含 stable code 供 Agent/CLI 顯示。
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AfXdpError {
    /// 設定不合法。
    InvalidConfig(String),
    /// interface name 不安全或不存在。
    InvalidInterface(String),
    /// 平台沒有 `AF_XDP` setup 能力。
    UnsupportedPlatform,
    /// kernel socket setup 失敗。
    Kernel {
        /// 失敗的 kernel operation。
        operation: &'static str,
        /// Linux errno。
        errno: i32,
    },
}

/// `AF_XDP` UMEM 的 page-aligned backing region。
pub struct UmemRegion {
    pointer: NonNull<u8>,
    layout: Layout,
    length: u64,
    chunk_size: u32,
    headroom: u32,
}

/// 指向 UMEM 單一 frame 的 descriptor；offset 永遠落在 owner region 內。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameDescriptor {
    /// UMEM relative offset。
    pub offset: u64,
    /// 可寫入的 payload bytes，不包含 headroom。
    pub length: u32,
}

/// Kernel `AF_XDP` ring offset metadata returned by `XDP_MMAP_OFFSETS`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct XdpRingOffset {
    /// Producer index offset from the mapped ring base.
    pub producer: u64,
    /// Consumer index offset from the mapped ring base.
    pub consumer: u64,
    /// Descriptor array offset from the mapped ring base.
    pub descriptor: u64,
    /// Optional kernel flags offset.
    pub flags: u64,
}

/// Kernel-provided offsets for RX/TX/FILL/COMPLETION mappings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct XdpMmapOffsets {
    /// RX ring offsets.
    pub rx: XdpRingOffset,
    /// TX ring offsets.
    pub tx: XdpRingOffset,
    /// FILL ring offsets.
    pub fill: XdpRingOffset,
    /// COMPLETION ring offsets.
    pub completion: XdpRingOffset,
}

/// Kernel `AF_XDP` descriptor layout。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct XdpDescriptor {
    /// UMEM frame address。
    pub address: u64,
    /// packet bytes。
    pub length: u32,
    /// kernel descriptor options。
    pub options: u32,
}

/// Linux XSKMAP 的 bounded socket registry。
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct XskMap {
    fd: i32,
    max_entries: u32,
}

/// 已載入並以 `BPF_XDP` link 綁定介面的 redirect program。
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct XdpRedirectLink {
    program_fd: i32,
    link_fd: i32,
}

/// 一個 kernel `AF_XDP` ring 的 mapped region。
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct XdpRingMapping {
    address: NonNull<u8>,
    length: usize,
    offsets: XdpRingOffset,
    entries: u32,
}

/// 四個 `AF_XDP` ring 的 RAII mapping；mapping 不會跨執行緒共享 owner。
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct XdpRingMappings {
    /// RX ring mapping。
    pub rx: XdpRingMapping,
    /// TX ring mapping。
    pub tx: XdpRingMapping,
    /// FILL ring mapping。
    pub fill: XdpRingMapping,
    /// COMPLETION ring mapping。
    pub completion: XdpRingMapping,
}

/// 已建立 ring mapping 後的單一 worker owner。
///
/// `rx`/`completion` 只由 worker consume，`tx`/`fill` 只由 worker produce；同一
/// mapping 不得交給另一條執行緒操作。
#[cfg(target_os = "linux")]
pub struct AfXdpWorker<'a> {
    rx: &'a XdpRingMapping,
    tx: &'a XdpRingMapping,
    fill: &'a XdpRingMapping,
    completion: &'a XdpRingMapping,
    umem: &'a UmemRegion,
}

#[cfg(target_os = "linux")]
impl<'a> AfXdpWorker<'a> {
    /// 建立 worker owner，驗證四個 ring 都是可用的 power-of-two capacity。
    ///
    /// # Errors
    ///
    /// 任一 mapping capacity 為零或不是 power-of-two 時回傳錯誤。
    pub fn new(mappings: &'a XdpRingMappings, umem: &'a UmemRegion) -> Result<Self, AfXdpError> {
        for capacity in [
            mappings.rx.entries,
            mappings.tx.entries,
            mappings.fill.entries,
            mappings.completion.entries,
        ] {
            if capacity == 0 || !capacity.is_power_of_two() {
                return Err(AfXdpError::InvalidConfig(
                    "AF_XDP worker ring capacity must be a non-zero power-of-two".to_owned(),
                ));
            }
        }
        Ok(Self {
            rx: &mappings.rx,
            tx: &mappings.tx,
            fill: &mappings.fill,
            completion: &mappings.completion,
            umem,
        })
    }

    /// 從 RX ring 取出最多 `output.len()` 個 descriptor，並發布 consumer index。
    ///
    /// # Errors
    ///
    /// ring metadata 讀取失敗、descriptor 超出 UMEM 邊界或發布 consumer index
    /// 失敗時回傳錯誤。
    pub fn receive_into(&self, output: &mut [XdpDescriptor]) -> Result<usize, AfXdpError> {
        let consumer = self.rx.consumer_index()?;
        let producer = self.rx.producer_index()?;
        let available = producer.wrapping_sub(consumer).min(self.rx.entries);
        let count = available.min(u32::try_from(output.len()).unwrap_or(u32::MAX));
        for (offset, item) in output.iter_mut().take(count as usize).enumerate() {
            let descriptor = self.rx.read_descriptor(
                consumer.wrapping_add(ring_index(offset)?) & (self.rx.entries - 1),
            )?;
            validate_umem_descriptor(self.umem, descriptor)?;
            *item = descriptor;
        }
        if count != 0 {
            self.rx.publish_consumer(consumer.wrapping_add(count))?;
        }
        Ok(count as usize)
    }

    /// 等待 RX readiness 後 drain 一批 descriptors；timeout 時回傳 `0`。
    ///
    /// # Errors
    ///
    /// 等待 kernel I/O 或讀取 RX ring metadata 失敗時回傳錯誤。
    pub fn receive_once(
        &self,
        socket: &AfXdpSocket,
        timeout: Duration,
        output: &mut [XdpDescriptor],
    ) -> Result<usize, AfXdpError> {
        if !socket.wait_for_io(timeout)? {
            return Ok(0);
        }
        self.receive_into(output)
    }

    /// 取出一個完整 multi-buffer packet；未收到 chain 結尾時保留 ring ownership。
    ///
    /// `output` 必須足以容納整個 packet 的 descriptors；方法不會只消費半個 jumbo
    /// packet，避免 caller 將不完整資料交給 parser。
    ///
    /// # Errors
    ///
    /// ring metadata 讀取失敗、descriptor 超出 UMEM 邊界、輸出緩衝區不足或發布
    /// consumer index 失敗時回傳錯誤。
    pub fn receive_packet_into(&self, output: &mut [XdpDescriptor]) -> Result<usize, AfXdpError> {
        let consumer = self.rx.consumer_index()?;
        let producer = self.rx.producer_index()?;
        let available = producer.wrapping_sub(consumer).min(self.rx.entries);
        let mut needed = 0_u32;
        let mut complete = false;
        while needed < available {
            let descriptor = self
                .rx
                .read_descriptor(consumer.wrapping_add(needed) & (self.rx.entries - 1))?;
            validate_umem_descriptor(self.umem, descriptor)?;
            needed += 1;
            if descriptor.options & XDP_PKT_CONTD == 0 {
                complete = true;
                break;
            }
        }
        if !complete {
            return Ok(0);
        }
        let needed_usize = needed as usize;
        if output.len() < needed_usize {
            return Err(AfXdpError::InvalidConfig(
                "RX output buffer is smaller than multi-buffer packet".to_owned(),
            ));
        }
        for (index, item) in output.iter_mut().take(needed_usize).enumerate() {
            *item = self.rx.read_descriptor(
                consumer.wrapping_add(ring_index(index)?) & (self.rx.entries - 1),
            )?;
        }
        self.rx.publish_consumer(consumer.wrapping_add(needed))?;
        Ok(needed_usize)
    }

    /// 將 TX descriptors 寫入 ring；容量不足時只提交可容納的前綴。
    ///
    /// # Errors
    ///
    /// ring metadata 讀取失敗、descriptor 超出 UMEM 邊界或發布 producer index
    /// 失敗時回傳錯誤。
    pub fn submit_tx(&self, descriptors: &[XdpDescriptor]) -> Result<usize, AfXdpError> {
        let producer = self.tx.producer_index()?;
        let consumer = self.tx.consumer_index()?;
        let free = self
            .tx
            .entries
            .saturating_sub(producer.wrapping_sub(consumer).min(self.tx.entries));
        let count = free.min(u32::try_from(descriptors.len()).unwrap_or(u32::MAX));
        for (offset, descriptor) in descriptors.iter().take(count as usize).enumerate() {
            validate_umem_descriptor(self.umem, *descriptor)?;
            self.tx.write_descriptor(
                producer.wrapping_add(ring_index(offset)?) & (self.tx.entries - 1),
                *descriptor,
            )?;
        }
        if count != 0 {
            self.tx.publish_producer(producer.wrapping_add(count))?;
        }
        Ok(count as usize)
    }

    /// 提交 TX descriptors 並立即通知 kernel；未提交 descriptor 時不發送 kick。
    ///
    /// # Errors
    ///
    /// ring 操作或 kernel TX kick 失敗時回傳錯誤。
    #[cfg(target_os = "linux")]
    pub fn submit_tx_and_kick(
        &self,
        socket: &AfXdpSocket,
        descriptors: &[XdpDescriptor],
    ) -> Result<usize, AfXdpError> {
        let count = self.submit_tx(descriptors)?;
        if count != 0 {
            socket.kick_tx()?;
        }
        Ok(count)
    }

    /// 從 COMPLETION ring 回收最多 `output.len()` 個 descriptor。
    ///
    /// # Errors
    ///
    /// ring metadata 讀取失敗或發布 consumer index 失敗時回傳錯誤。
    pub fn recycle_completions(&self, output: &mut [XdpDescriptor]) -> Result<usize, AfXdpError> {
        let consumer = self.completion.consumer_index()?;
        let producer = self.completion.producer_index()?;
        let available = producer.wrapping_sub(consumer).min(self.completion.entries);
        let count = available.min(u32::try_from(output.len()).unwrap_or(u32::MAX));
        for (offset, item) in output.iter_mut().take(count as usize).enumerate() {
            *item = self.completion.read_descriptor(
                consumer.wrapping_add(ring_index(offset)?) & (self.completion.entries - 1),
            )?;
        }
        if count != 0 {
            self.completion
                .publish_consumer(consumer.wrapping_add(count))?;
        }
        Ok(count as usize)
    }

    /// 將 UMEM frame base address 補回 FILL ring；容量不足時只提交可容納的前綴。
    ///
    /// # Errors
    ///
    /// ring metadata 讀取失敗、frame index 超出 UMEM 邊界或發布 producer index
    /// 失敗時回傳錯誤。
    pub fn refill_fill(&self, frame_indices: &[u64]) -> Result<usize, AfXdpError> {
        let producer = self.fill.producer_index()?;
        let consumer = self.fill.consumer_index()?;
        let free = self
            .fill
            .entries
            .saturating_sub(producer.wrapping_sub(consumer).min(self.fill.entries));
        let count = free.min(u32::try_from(frame_indices.len()).unwrap_or(u32::MAX));
        for (offset, frame_index) in frame_indices.iter().take(count as usize).enumerate() {
            self.fill.write_descriptor(
                producer.wrapping_add(ring_index(offset)?) & (self.fill.entries - 1),
                XdpDescriptor {
                    address: self.umem.frame_offset(*frame_index)?,
                    length: 0,
                    options: 0,
                },
            )?;
        }
        if count != 0 {
            self.fill.publish_producer(producer.wrapping_add(count))?;
        }
        Ok(count as usize)
    }
}

#[cfg(target_os = "linux")]
fn validate_umem_descriptor(
    umem: &UmemRegion,
    descriptor: XdpDescriptor,
) -> Result<(), AfXdpError> {
    let end = descriptor
        .address
        .checked_add(u64::from(descriptor.length))
        .ok_or_else(|| AfXdpError::InvalidConfig("descriptor address overflows".to_owned()))?;
    if end > umem.length() || descriptor.length > umem.chunk_size() {
        return Err(AfXdpError::InvalidConfig(
            "descriptor exceeds UMEM bounds".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn ring_index(value: usize) -> Result<u32, AfXdpError> {
    u32::try_from(value).map_err(|_| AfXdpError::InvalidConfig("ring index exceeds u32".to_owned()))
}

#[cfg(target_os = "linux")]
const XDP_PKT_CONTD: u32 = 1 << 1;

#[cfg(target_os = "linux")]
impl XdpRingMapping {
    /// 讀取 kernel producer index；只有 producer owner 可呼叫對應的寫入方法。
    ///
    /// # Errors
    ///
    /// index offset 超出 mapping 邊界時回傳錯誤。
    pub fn producer_index(&self) -> Result<u32, AfXdpError> {
        self.read_index(self.offsets.producer)
    }

    /// 讀取 kernel consumer index。
    ///
    /// # Errors
    ///
    /// index offset 超出 mapping 邊界時回傳錯誤。
    pub fn consumer_index(&self) -> Result<u32, AfXdpError> {
        self.read_index(self.offsets.consumer)
    }

    /// 由 producer owner 發布新 index。
    ///
    /// # Errors
    ///
    /// index offset 超出 mapping 邊界時回傳錯誤。
    pub fn publish_producer(&self, index: u32) -> Result<(), AfXdpError> {
        self.write_index(self.offsets.producer, index)
    }

    /// 由 consumer owner 發布新 index。
    ///
    /// # Errors
    ///
    /// index offset 超出 mapping 邊界時回傳錯誤。
    pub fn publish_consumer(&self, index: u32) -> Result<(), AfXdpError> {
        self.write_index(self.offsets.consumer, index)
    }

    /// 讀取 bounded descriptor slot。
    ///
    /// # Errors
    ///
    /// descriptor slot 或 mapping 邊界不合法時回傳錯誤。
    #[allow(clippy::cast_ptr_alignment)]
    pub fn read_descriptor(&self, slot: u32) -> Result<XdpDescriptor, AfXdpError> {
        let pointer = self.descriptor_pointer(slot)?;
        // SAFETY: descriptor_pointer validates mapping bounds and alignment.
        Ok(unsafe {
            XdpDescriptor {
                address: std::ptr::read_volatile(pointer.cast::<u64>()),
                length: std::ptr::read_volatile(pointer.add(8).cast::<u32>()),
                options: std::ptr::read_volatile(pointer.add(12).cast::<u32>()),
            }
        })
    }

    /// 寫入 bounded descriptor slot；呼叫者必須是該 ring 的 producer owner。
    ///
    /// # Errors
    ///
    /// descriptor slot 或 mapping 邊界不合法時回傳錯誤。
    #[allow(clippy::cast_ptr_alignment)]
    pub fn write_descriptor(&self, slot: u32, descriptor: XdpDescriptor) -> Result<(), AfXdpError> {
        let pointer = self.descriptor_pointer(slot)?;
        // SAFETY: descriptor_pointer validates mapping bounds and alignment.
        unsafe {
            std::ptr::write_volatile(pointer.cast::<u64>(), descriptor.address);
            std::ptr::write_volatile(pointer.add(8).cast::<u32>(), descriptor.length);
            std::ptr::write_volatile(pointer.add(12).cast::<u32>(), descriptor.options);
        }
        Ok(())
    }

    fn read_index(&self, offset: u64) -> Result<u32, AfXdpError> {
        let offset = usize::try_from(offset)
            .map_err(|_| AfXdpError::InvalidConfig("ring index offset overflows".to_owned()))?;
        if offset.checked_add(4).is_none_or(|end| end > self.length) {
            return Err(AfXdpError::InvalidConfig(
                "ring index offset exceeds mapping".to_owned(),
            ));
        }
        // SAFETY: bounds are checked above and mapping remains alive through &self.
        Ok(unsafe { std::ptr::read_volatile(self.address.as_ptr().add(offset).cast()) })
    }

    fn write_index(&self, offset: u64, index: u32) -> Result<(), AfXdpError> {
        let offset = usize::try_from(offset)
            .map_err(|_| AfXdpError::InvalidConfig("ring index offset overflows".to_owned()))?;
        if offset.checked_add(4).is_none_or(|end| end > self.length) {
            return Err(AfXdpError::InvalidConfig(
                "ring index offset exceeds mapping".to_owned(),
            ));
        }
        // SAFETY: bounds are checked above and mapping remains alive through &self.
        unsafe { std::ptr::write_volatile(self.address.as_ptr().add(offset).cast(), index) };
        Ok(())
    }

    fn descriptor_pointer(&self, slot: u32) -> Result<*mut u8, AfXdpError> {
        if slot >= self.entries {
            return Err(AfXdpError::InvalidConfig(
                "descriptor slot exceeds ring capacity".to_owned(),
            ));
        }
        let base = usize::try_from(self.offsets.descriptor)
            .map_err(|_| AfXdpError::InvalidConfig("descriptor offset overflows".to_owned()))?;
        let slot_offset = usize::try_from(slot)
            .ok()
            .and_then(|value| value.checked_mul(16))
            .and_then(|value| base.checked_add(value))
            .ok_or_else(|| AfXdpError::InvalidConfig("descriptor offset overflows".to_owned()))?;
        if slot_offset
            .checked_add(16)
            .is_none_or(|end| end > self.length)
        {
            return Err(AfXdpError::InvalidConfig(
                "descriptor exceeds mapping".to_owned(),
            ));
        }
        Ok(unsafe { self.address.as_ptr().add(slot_offset) })
    }
}

/// bounded single-producer/single-consumer descriptor ring。
///
/// Producer 與 consumer 必須各自只由一條 worker 操作；此 ownership invariant
/// 對應 `AF_XDP` ring 的 kernel producer/consumer 規則。
pub struct FrameRing {
    entries: Box<[AtomicFrame]>,
    capacity: u32,
    producer: AtomicU32,
    consumer: AtomicU32,
}

struct AtomicFrame {
    offset: AtomicU64,
    length: AtomicU32,
}

impl fmt::Debug for FrameRing {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FrameRing")
            .field("capacity", &self.capacity)
            .field("producer", &self.producer.load(Ordering::Relaxed))
            .field("consumer", &self.consumer.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl FrameRing {
    /// 建立固定容量 ring；capacity 必須是 power-of-two。
    ///
    /// # Errors
    ///
    /// capacity 為零、非 power-of-two 或過大時回傳錯誤。
    pub fn new(capacity: u32) -> Result<Self, AfXdpError> {
        if capacity == 0 || !capacity.is_power_of_two() || capacity > 1 << 20 {
            return Err(AfXdpError::InvalidConfig(
                "descriptor ring capacity must be a power-of-two between 1 and 1048576".to_owned(),
            ));
        }
        let entries = (0..capacity)
            .map(|_| AtomicFrame {
                offset: AtomicU64::new(0),
                length: AtomicU32::new(0),
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Ok(Self {
            entries,
            capacity,
            producer: AtomicU32::new(0),
            consumer: AtomicU32::new(0),
        })
    }

    /// Producer 嘗試加入 descriptor；ring 滿時不阻塞且回傳 false。
    pub fn try_push(&self, descriptor: FrameDescriptor) -> bool {
        let producer = self.producer.load(Ordering::Relaxed);
        let consumer = self.consumer.load(Ordering::Acquire);
        if producer.wrapping_sub(consumer) >= self.capacity {
            return false;
        }
        let index = producer & (self.capacity - 1);
        self.entries[index as usize]
            .offset
            .store(descriptor.offset, Ordering::Relaxed);
        self.entries[index as usize]
            .length
            .store(descriptor.length, Ordering::Relaxed);
        self.producer
            .store(producer.wrapping_add(1), Ordering::Release);
        true
    }

    /// Consumer 嘗試取出 descriptor；ring 空時回傳 None。
    pub fn try_pop(&self) -> Option<FrameDescriptor> {
        let consumer = self.consumer.load(Ordering::Relaxed);
        let producer = self.producer.load(Ordering::Acquire);
        if consumer == producer {
            return None;
        }
        let index = consumer & (self.capacity - 1);
        let offset = self.entries[index as usize].offset.load(Ordering::Relaxed);
        let length = self.entries[index as usize].length.load(Ordering::Relaxed);
        self.consumer
            .store(consumer.wrapping_add(1), Ordering::Release);
        Some(FrameDescriptor { offset, length })
    }

    /// 目前可供 consumer 讀取的 descriptor 數量。
    #[must_use]
    pub fn len(&self) -> u32 {
        self.producer
            .load(Ordering::Acquire)
            .wrapping_sub(self.consumer.load(Ordering::Acquire))
            .min(self.capacity)
    }

    /// ring 是否為空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl fmt::Debug for UmemRegion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UmemRegion")
            .field("length", &self.length)
            .field("chunk_size", &self.chunk_size)
            .field("headroom", &self.headroom)
            .finish_non_exhaustive()
    }
}

impl UmemRegion {
    /// 配置 page-aligned UMEM；region 由 Rust owner 持有至 socket 完成 teardown。
    ///
    /// # Errors
    ///
    /// 長度、chunk size、headroom 不符合 kernel/descriptor invariants 或 allocation
    /// 失敗時回傳錯誤。
    pub fn new(length: usize, chunk_size: u32, headroom: u32) -> Result<Self, AfXdpError> {
        if length == 0
            || length % 4096 != 0
            || !chunk_size.is_power_of_two()
            || !(2048..=65_536).contains(&chunk_size)
            || headroom >= chunk_size
            || length % usize::try_from(chunk_size).unwrap_or(usize::MAX) != 0
        {
            return Err(AfXdpError::InvalidConfig(
                "UMEM length must be page-aligned and divisible by a 2048..65536 power-of-two chunk; headroom must be smaller than chunk"
                    .to_owned(),
            ));
        }
        let layout = Layout::from_size_align(length, 4096)
            .map_err(|_| AfXdpError::InvalidConfig("UMEM layout is invalid".to_owned()))?;
        // SAFETY: layout has non-zero size and a valid power-of-two alignment.
        let pointer = NonNull::new(unsafe { alloc_zeroed(layout) })
            .ok_or_else(|| AfXdpError::InvalidConfig("UMEM allocation failed".to_owned()))?;
        Ok(Self {
            pointer,
            layout,
            length: u64::try_from(length).map_err(|_| {
                // SAFETY: pointer was allocated with layout above and is released exactly once.
                unsafe { dealloc(pointer.as_ptr(), layout) };
                AfXdpError::InvalidConfig("UMEM length exceeds u64".to_owned())
            })?,
            chunk_size,
            headroom,
        })
    }

    /// UMEM 起始位址，僅供同一 `AF_XDP` owner 計算 descriptor offset。
    #[must_use]
    pub fn address(&self) -> usize {
        self.pointer.as_ptr() as usize
    }

    /// UMEM bytes。
    #[must_use]
    pub const fn length(&self) -> u64 {
        self.length
    }

    /// Descriptor chunk bytes。
    #[must_use]
    pub const fn chunk_size(&self) -> u32 {
        self.chunk_size
    }

    /// Per-frame headroom bytes。
    #[must_use]
    pub const fn headroom(&self) -> u32 {
        self.headroom
    }

    /// 依 frame index 產生 bounded descriptor。
    ///
    /// # Errors
    ///
    /// index 超過 UMEM frame count 或 length 會跨越 region 時回傳錯誤。
    pub fn frame_descriptor(&self, index: u64, length: u32) -> Result<FrameDescriptor, AfXdpError> {
        let frame_count = self.length / u64::from(self.chunk_size);
        if index >= frame_count || length > self.chunk_size - self.headroom {
            return Err(AfXdpError::InvalidConfig(
                "UMEM frame descriptor exceeds region bounds".to_owned(),
            ));
        }
        let offset = index
            .checked_mul(u64::from(self.chunk_size))
            .and_then(|value| value.checked_add(u64::from(self.headroom)))
            .ok_or_else(|| AfXdpError::InvalidConfig("UMEM frame offset overflows".to_owned()))?;
        Ok(FrameDescriptor { offset, length })
    }

    /// 回傳 frame base address，供 kernel FILL ring 使用；不含 headroom。
    ///
    /// # Errors
    ///
    /// frame index 超過 UMEM frame count 或 offset 溢位時回傳錯誤。
    pub fn frame_offset(&self, index: u64) -> Result<u64, AfXdpError> {
        let frame_count = self.length / u64::from(self.chunk_size);
        if index >= frame_count {
            return Err(AfXdpError::InvalidConfig(
                "UMEM frame index exceeds region bounds".to_owned(),
            ));
        }
        index
            .checked_mul(u64::from(self.chunk_size))
            .ok_or_else(|| AfXdpError::InvalidConfig("UMEM frame offset overflows".to_owned()))
    }
}

impl Drop for UmemRegion {
    fn drop(&mut self) {
        // SAFETY: pointer/layout are the exact pair returned by alloc_zeroed and are dropped once.
        unsafe { dealloc(self.pointer.as_ptr(), self.layout) };
    }
}

impl fmt::Display for AfXdpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(message) => write!(formatter, "AF_XDP.INVALID_CONFIG: {message}"),
            Self::InvalidInterface(message) => {
                write!(formatter, "AF_XDP.INVALID_INTERFACE: {message}")
            }
            Self::UnsupportedPlatform => formatter.write_str("AF_XDP.UNSUPPORTED_PLATFORM"),
            Self::Kernel { operation, errno } => {
                write!(formatter, "AF_XDP.{operation}_FAILED: errno={errno}")
            }
        }
    }
}

impl std::error::Error for AfXdpError {}

/// 已完成 kernel bind 的 `AF_XDP` socket；drop 時關閉 fd。
#[derive(Debug)]
pub struct AfXdpSocket {
    #[cfg(target_os = "linux")]
    fd: i32,
}

impl AfXdpSocket {
    /// 建立並 bind `AF_XDP` socket，註冊 UMEM 並設定四個 ring 的 descriptor size。
    ///
    /// `umem` 必須由 caller 持有至 socket drop；socket 不會取得其 ownership，避免
    /// descriptor 在 kernel 使用期間失效。
    ///
    /// # Errors
    ///
    /// 設定、socket、ring 或 bind 失敗時回傳錯誤。要求 zero-copy 但 driver 不支援時
    /// 不會降級為 copy mode。
    pub fn bind(
        interface_name: &str,
        config: AfXdpConfig,
        umem: &UmemRegion,
    ) -> Result<Self, AfXdpError> {
        let config = config.validate()?;
        validate_interface_name(interface_name)?;
        #[cfg(target_os = "linux")]
        {
            linux::bind_socket(interface_name, config, umem)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (interface_name, config, umem);
            Err(AfXdpError::UnsupportedPlatform)
        }
    }

    /// 回傳 native file descriptor，供同一資料平面 owner 進行 UMEM/ring setup。
    #[cfg(target_os = "linux")]
    #[must_use]
    pub const fn raw_fd(&self) -> i32 {
        self.fd
    }

    /// 讀取 kernel ring mmap offsets；caller 必須依回傳 metadata 建立各自 owner mapping。
    ///
    /// # Errors
    ///
    /// kernel 不支援 `XDP_MMAP_OFFSETS` 或回傳大小不足時回傳錯誤。
    #[cfg(target_os = "linux")]
    pub fn ring_offsets(&self) -> Result<XdpMmapOffsets, AfXdpError> {
        linux::query_ring_offsets(self.fd)
    }

    /// 依 kernel offsets 建立四個 ring mapping。
    ///
    /// # Errors
    ///
    /// ring mapping 大小溢位、kernel mmap 失敗或設定不合法時回傳錯誤。
    #[cfg(target_os = "linux")]
    pub fn map_rings(
        &self,
        config: AfXdpConfig,
        offsets: XdpMmapOffsets,
    ) -> Result<XdpRingMappings, AfXdpError> {
        linux::map_rings(self.fd, config.validate()?, offsets)
    }

    /// 將 UMEM frame base address 一次填入 FILL ring，供 kernel 接收封包。
    ///
    /// # Errors
    ///
    /// FILL ring 非空、容量不足、frame index 計算溢位或 ring 操作失敗時回傳錯誤。
    #[cfg(target_os = "linux")]
    pub fn initialize_fill_ring(
        &self,
        mappings: &XdpRingMappings,
        umem: &UmemRegion,
    ) -> Result<u32, AfXdpError> {
        linux::initialize_fill_ring(&mappings.fill, umem)
    }

    /// 等待 RX/TX ring 有事件；timeout 到期回傳 `false`，不 busy-loop。
    ///
    /// # Errors
    ///
    /// kernel poll 回傳錯誤或 ring socket 發生錯誤事件時回傳錯誤。
    #[cfg(target_os = "linux")]
    pub fn wait_for_io(&self, timeout: Duration) -> Result<bool, AfXdpError> {
        linux::wait_for_io(self.fd, timeout)
    }

    /// 通知 kernel 消費已提交的 TX descriptors。
    ///
    /// `AF_XDP` 在 TX ring 發布 producer index 後，若 socket flag 要求 wakeup，仍須以
    /// zero-length `sendto` kick kernel；只更新 shared ring 不保證封包離開 NIC。
    ///
    /// # Errors
    ///
    /// kernel `sendto` kick 失敗時回傳錯誤。
    #[cfg(target_os = "linux")]
    pub fn kick_tx(&self) -> Result<(), AfXdpError> {
        linux::kick_tx(self.fd)
    }

    /// 建立可供 XDP redirect 使用的 XSKMAP。
    ///
    /// # Errors
    ///
    /// kernel 建立 XSKMAP 失敗或容量不符合 bounded power-of-two 限制時回傳錯誤。
    #[cfg(target_os = "linux")]
    pub fn create_xsk_map(max_entries: u32) -> Result<XskMap, AfXdpError> {
        linux::create_xsk_map(max_entries)
    }

    /// 非 Linux 沒有 `AF_XDP` ring metadata。
    ///
    /// # Errors
    ///
    /// 一律回傳 `UnsupportedPlatform`。
    #[cfg(not(target_os = "linux"))]
    pub fn ring_offsets(&self) -> Result<XdpMmapOffsets, AfXdpError> {
        Err(AfXdpError::UnsupportedPlatform)
    }
}

#[cfg(target_os = "linux")]
impl XskMap {
    /// 更新 queue 到 `AF_XDP` socket 的 mapping；同一 queue 只允許一個 socket owner。
    ///
    /// # Errors
    ///
    /// queue 超出 map 容量或 kernel 更新 XSKMAP 失敗時回傳錯誤。
    pub fn insert(&self, queue_id: u32, socket: &AfXdpSocket) -> Result<(), AfXdpError> {
        if queue_id >= self.max_entries {
            return Err(AfXdpError::InvalidConfig(
                "XSKMAP queue id exceeds map capacity".to_owned(),
            ));
        }
        linux::update_xsk_map(self.fd, queue_id, socket.fd)
    }

    /// native map fd，僅供同一 BPF owner 建立 redirect program。
    #[must_use]
    pub const fn raw_fd(&self) -> i32 {
        self.fd
    }

    /// 載入固定 XDP redirect program，將封包依 RX queue 導向此 XSKMAP。
    ///
    /// # Errors
    ///
    /// interface 不存在、kernel 載入 BPF program 或建立 link 失敗時回傳錯誤。
    pub fn attach_redirect(&self, interface_name: &str) -> Result<XdpRedirectLink, AfXdpError> {
        linux::attach_redirect(self.fd, interface_name)
    }
}

fn validate_interface_name(interface_name: &str) -> Result<(), AfXdpError> {
    if interface_name.is_empty()
        || interface_name.len() > 15
        || interface_name
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')))
    {
        return Err(AfXdpError::InvalidInterface(
            "interface name contains unsupported characters".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{AfXdpConfig, AfXdpError, AfXdpSocket, UmemRegion, XdpMmapOffsets, XdpRingOffset};
    use std::ffi::CString;
    use std::os::raw::{c_char, c_int, c_long, c_uint, c_void};
    use std::ptr::NonNull;
    use std::time::Duration;

    const AF_XDP: c_int = 44;
    const SOCK_RAW: c_int = 3;
    const SOL_XDP: c_int = 283;
    const XDP_RX_RING: c_int = 2;
    const XDP_TX_RING: c_int = 1;
    const XDP_UMEM_REG: c_int = 4;
    const XDP_UMEM_FILL_RING: c_int = 5;
    const XDP_UMEM_COMPLETION_RING: c_int = 6;
    const XDP_ZEROCOPY: u16 = 1 << 2;
    const XDP_MMAP_OFFSETS: c_int = 1;
    const XDP_PGOFF_RX_RING: i64 = 0;
    const XDP_PGOFF_TX_RING: i64 = 0x8000_0000;
    const XDP_UMEM_PGOFF_FILL_RING: i64 = 0x1_0000_0000;
    const XDP_UMEM_PGOFF_COMPLETION_RING: i64 = 0x1_8000_0000;
    const PROT_READ: c_int = 1;
    const PROT_WRITE: c_int = 2;
    const MAP_SHARED: c_int = 1;
    const MAP_FAILED: *mut c_void = -1isize as *mut c_void;
    const PAGE_SIZE: usize = 4096;
    const BPF_MAP_CREATE: c_int = 0;
    const BPF_MAP_UPDATE_ELEM: c_int = 2;
    const BPF_PROG_LOAD: c_int = 5;
    const BPF_LINK_CREATE: c_int = 28;
    const BPF_MAP_TYPE_XSKMAP: u32 = 17;
    const BPF_PROG_TYPE_XDP: u32 = 6;
    const BPF_XDP: u32 = 37;
    const BPF_FUNC_REDIRECT_MAP: i32 = 51;
    #[cfg(target_arch = "x86_64")]
    const SYS_BPF: c_long = 321;
    #[cfg(target_arch = "aarch64")]
    const SYS_BPF: c_long = 280;
    const POLLIN: i16 = 0x001;
    const POLLERR: i16 = 0x008;
    const POLLHUP: i16 = 0x010;

    #[repr(C)]
    struct PollFd {
        fd: c_int,
        events: i16,
        revents: i16,
    }

    #[repr(C)]
    struct BpfMapCreateAttr {
        map_type: u32,
        key_size: u32,
        value_size: u32,
        max_entries: u32,
        map_flags: u32,
        inner_map_fd: u32,
        numa_node: u32,
        map_name: [u8; 16],
        map_ifindex: u32,
        btf_fd: u32,
        btf_key_type_id: u32,
        btf_value_type_id: u32,
        btf_vmlinux_value_type_id: u32,
        map_extra: u64,
    }

    #[repr(C)]
    struct BpfMapElemAttr {
        map_fd: u32,
        key: u64,
        value: u64,
        flags: u64,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub(super) struct BpfInsn {
        pub(super) code: u8,
        pub(super) regs: u8,
        pub(super) off: i16,
        pub(super) imm: i32,
    }

    #[repr(C)]
    struct BpfProgLoadAttr {
        prog_type: u32,
        insn_count: u32,
        insns: u64,
        license: u64,
        log_level: u32,
        log_size: u32,
        log_buf: u64,
        kern_version: u32,
        prog_flags: u32,
        prog_name: [u8; 16],
        prog_ifindex: u32,
        expected_attach_type: u32,
        prog_btf_fd: u32,
        func_info_rec_size: u32,
        func_info: u64,
        func_info_cnt: u32,
        line_info_rec_size: u32,
        line_info: u64,
        line_info_cnt: u32,
        attach_btf_id: u32,
        attach_prog_fd: u32,
        core_relo_cnt: u32,
        fd_array: u64,
        core_relos: u64,
        core_relo_rec_size: u32,
        log_true_size: u64,
        prog_token_fd: u32,
        fd_array_cnt: u32,
    }

    #[repr(C)]
    struct BpfLinkCreateAttr {
        prog_fd: u32,
        target_fd: u32,
        attach_type: u32,
        flags: u32,
    }

    #[repr(C)]
    struct SockaddrXdp {
        family: u16,
        flags: u16,
        interface_index: u32,
        queue_id: u32,
        shared_umem_fd: u32,
    }

    #[repr(C)]
    struct XdpUmemReg {
        address: u64,
        length: u64,
        chunk_size: u32,
        headroom: u32,
        flags: u32,
        tx_metadata_len: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct XdpRingOffsetRaw {
        producer: u64,
        consumer: u64,
        desc: u64,
        flags: u64,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct XdpMmapOffsetsRaw {
        rx: XdpRingOffsetRaw,
        tx: XdpRingOffsetRaw,
        fr: XdpRingOffsetRaw,
        cr: XdpRingOffsetRaw,
    }

    unsafe extern "C" {
        fn socket(domain: c_int, socket_type: c_int, protocol: c_int) -> c_int;
        fn setsockopt(
            socket: c_int,
            level: c_int,
            option: c_int,
            value: *const c_void,
            option_length: u32,
        ) -> c_int;
        fn getsockopt(
            socket: c_int,
            level: c_int,
            option: c_int,
            value: *mut c_void,
            option_length: *mut u32,
        ) -> c_int;
        fn bind(socket: c_int, address: *const c_void, address_length: u32) -> c_int;
        fn close(fd: c_int) -> c_int;
        fn mmap(
            address: *mut c_void,
            length: usize,
            protection: c_int,
            flags: c_int,
            fd: c_int,
            offset: i64,
        ) -> *mut c_void;
        fn munmap(address: *mut c_void, length: usize) -> c_int;
        fn poll(fds: *mut PollFd, count: usize, timeout: c_int) -> c_int;
        fn sendto(
            socket: c_int,
            buffer: *const c_void,
            length: usize,
            flags: c_int,
            address: *const c_void,
            address_length: u32,
        ) -> isize;
        fn syscall(number: c_long, ...) -> c_long;
        fn if_nametoindex(interface: *const c_char) -> c_uint;
        fn __errno_location() -> *mut c_int;
    }

    pub(super) fn create_xsk_map(max_entries: u32) -> Result<super::XskMap, AfXdpError> {
        if max_entries == 0 || !max_entries.is_power_of_two() || max_entries > 1 << 20 {
            return Err(AfXdpError::InvalidConfig(
                "XSKMAP capacity must be a power-of-two between 1 and 1048576".to_owned(),
            ));
        }
        let attributes = BpfMapCreateAttr {
            map_type: BPF_MAP_TYPE_XSKMAP,
            key_size: 4,
            value_size: 4,
            max_entries,
            map_flags: 0,
            inner_map_fd: 0,
            numa_node: 0,
            map_name: [0; 16],
            map_ifindex: 0,
            btf_fd: 0,
            btf_key_type_id: 0,
            btf_value_type_id: 0,
            btf_vmlinux_value_type_id: 0,
            map_extra: 0,
        };
        // SAFETY: attributes is a stable, kernel-defined BPF_MAP_CREATE payload.
        // Linux bpf syscall 以 c_long 回傳由 c_int 表示的 fd；ABI 保證其範圍。
        let fd = unsafe {
            syscall(
                SYS_BPF,
                BPF_MAP_CREATE,
                (&raw const attributes).cast::<c_void>(),
                std::mem::size_of::<BpfMapCreateAttr>(),
            )
        };
        let fd = c_int::try_from(fd)
            .map_err(|_| AfXdpError::InvalidConfig("map fd exceeds c_int".to_owned()))?;
        if fd < 0 {
            return Err(kernel_error("bpf_map_create_xskmap"));
        }
        Ok(super::XskMap { fd, max_entries })
    }

    pub(super) fn update_xsk_map(
        map_fd: i32,
        queue_id: u32,
        socket_fd: i32,
    ) -> Result<(), AfXdpError> {
        let key = u64::from(queue_id);
        let value = u64::try_from(socket_fd)
            .map_err(|_| AfXdpError::InvalidConfig("socket fd is negative".to_owned()))?;
        let attributes = BpfMapElemAttr {
            map_fd: u32::try_from(map_fd)
                .map_err(|_| AfXdpError::InvalidConfig("map fd is negative".to_owned()))?,
            key: (&raw const key) as u64,
            value: (&raw const value) as u64,
            flags: 0,
        };
        // SAFETY: attributes contains valid key/value pointers for this syscall duration.
        let result = unsafe {
            syscall(
                SYS_BPF,
                BPF_MAP_UPDATE_ELEM,
                (&raw const attributes).cast::<c_void>(),
                std::mem::size_of::<BpfMapElemAttr>(),
            )
        };
        if result < 0 {
            return Err(kernel_error("bpf_map_update_xskmap"));
        }
        Ok(())
    }

    pub(super) fn attach_redirect(
        map_fd: i32,
        interface_name: &str,
    ) -> Result<super::XdpRedirectLink, AfXdpError> {
        let interface = CString::new(interface_name)
            .map_err(|_| AfXdpError::InvalidInterface("interface name contains NUL".to_owned()))?;
        // SAFETY: interface CString is NUL-terminated and valid for this call.
        let interface_index = unsafe { if_nametoindex(interface.as_ptr()) };
        if interface_index == 0 {
            return Err(kernel_error("if_nametoindex"));
        }
        let license = b"GPL\0";
        let instructions = redirect_instructions(map_fd);
        let mut log = vec![0_u8; 16 * 1024];
        let attributes = BpfProgLoadAttr {
            prog_type: BPF_PROG_TYPE_XDP,
            insn_count: u32::try_from(instructions.len()).expect("BPF instruction count fits u32"),
            insns: instructions.as_ptr() as u64,
            license: license.as_ptr() as u64,
            log_level: 1,
            log_size: u32::try_from(log.len()).expect("BPF log size fits u32"),
            log_buf: log.as_mut_ptr() as u64,
            kern_version: 0,
            prog_flags: 0,
            prog_name: [0; 16],
            prog_ifindex: interface_index,
            expected_attach_type: BPF_XDP,
            prog_btf_fd: 0,
            func_info_rec_size: 0,
            func_info: 0,
            func_info_cnt: 0,
            line_info_rec_size: 0,
            line_info: 0,
            line_info_cnt: 0,
            attach_btf_id: 0,
            attach_prog_fd: 0,
            core_relo_cnt: 0,
            fd_array: 0,
            core_relos: 0,
            core_relo_rec_size: 0,
            log_true_size: 0,
            prog_token_fd: 0,
            fd_array_cnt: 0,
        };
        // SAFETY: all pointers reference live fixed buffers for syscall duration.
        // Linux bpf syscall 以 c_long 回傳由 c_int 表示的 fd；ABI 保證其範圍。
        let program_fd = unsafe {
            syscall(
                SYS_BPF,
                BPF_PROG_LOAD,
                (&raw const attributes).cast::<c_void>(),
                std::mem::size_of::<BpfProgLoadAttr>(),
            )
        };
        let program_fd = c_int::try_from(program_fd)
            .map_err(|_| AfXdpError::InvalidConfig("program fd exceeds c_int".to_owned()))?;
        if program_fd < 0 {
            return Err(kernel_error("bpf_prog_load_xdp_redirect"));
        }
        let link_attributes = BpfLinkCreateAttr {
            prog_fd: u32::try_from(program_fd)
                .map_err(|_| AfXdpError::InvalidConfig("program fd is negative".to_owned()))?,
            target_fd: interface_index,
            attach_type: BPF_XDP,
            flags: 0,
        };
        // SAFETY: link attributes are a stable kernel payload and program fd is owned here.
        // Linux bpf syscall 以 c_long 回傳由 c_int 表示的 fd；ABI 保證其範圍。
        let link_fd = unsafe {
            syscall(
                SYS_BPF,
                BPF_LINK_CREATE,
                (&raw const link_attributes).cast::<c_void>(),
                std::mem::size_of::<BpfLinkCreateAttr>(),
            )
        };
        let link_fd = c_int::try_from(link_fd)
            .map_err(|_| AfXdpError::InvalidConfig("link fd exceeds c_int".to_owned()))?;
        if link_fd < 0 {
            // SAFETY: program_fd was returned by BPF_PROG_LOAD and is closed once.
            unsafe { close(program_fd) };
            return Err(kernel_error("bpf_link_create_xdp_redirect"));
        }
        Ok(super::XdpRedirectLink {
            program_fd,
            link_fd,
        })
    }

    pub(super) fn redirect_instructions(map_fd: i32) -> [BpfInsn; 5] {
        [
            // r2 = ctx->rx_queue_index (xdp_md offset 16).
            BpfInsn {
                code: 0x61,
                regs: 0x12,
                off: 16,
                imm: 0,
            },
            // r1 = map fd pseudo pointer.
            BpfInsn {
                code: 0x18,
                regs: 0x11,
                off: 0,
                imm: map_fd,
            },
            BpfInsn {
                code: 0,
                regs: 0,
                off: 0,
                imm: 0,
            },
            // r0 = bpf_redirect_map(r1, r2, 0).
            BpfInsn {
                code: 0x85,
                regs: 0,
                off: 0,
                imm: BPF_FUNC_REDIRECT_MAP,
            },
            // return r0.
            BpfInsn {
                code: 0x95,
                regs: 0,
                off: 0,
                imm: 0,
            },
        ]
    }

    impl Drop for super::XdpRedirectLink {
        fn drop(&mut self) {
            // SAFETY: both fds are owned by this link and closed exactly once.
            unsafe {
                close(self.link_fd);
                close(self.program_fd);
            }
        }
    }

    impl Drop for super::XskMap {
        fn drop(&mut self) {
            // SAFETY: map fd is owned by XskMap and closed once.
            unsafe { close(self.fd) };
        }
    }

    pub(super) fn query_ring_offsets(fd: i32) -> Result<XdpMmapOffsets, AfXdpError> {
        let mut raw = XdpMmapOffsetsRaw::default();
        let offsets_size = u32::try_from(std::mem::size_of::<XdpMmapOffsetsRaw>())
            .expect("XDP mmap offsets size fits u32");
        let mut length = offsets_size;
        // SAFETY: raw and length are valid writable buffers for the kernel ABI.
        let status = unsafe {
            getsockopt(
                fd,
                SOL_XDP,
                XDP_MMAP_OFFSETS,
                (&raw mut raw).cast(),
                &raw mut length,
            )
        };
        if status != 0 {
            return Err(kernel_error("getsockopt_mmap_offsets"));
        }
        if length < offsets_size {
            return Err(AfXdpError::Kernel {
                operation: "getsockopt_mmap_offsets_short",
                errno: 0,
            });
        }
        Ok(XdpMmapOffsets {
            rx: map_offset(raw.rx),
            tx: map_offset(raw.tx),
            fill: map_offset(raw.fr),
            completion: map_offset(raw.cr),
        })
    }

    pub(super) fn map_rings(
        fd: i32,
        config: AfXdpConfig,
        offsets: XdpMmapOffsets,
    ) -> Result<super::XdpRingMappings, AfXdpError> {
        let entries = [
            (
                "mmap_rx_ring",
                config.rx_ring_size,
                offsets.rx,
                XDP_PGOFF_RX_RING,
            ),
            (
                "mmap_tx_ring",
                config.tx_ring_size,
                offsets.tx,
                XDP_PGOFF_TX_RING,
            ),
            (
                "mmap_fill_ring",
                config.fill_ring_size,
                offsets.fill,
                XDP_UMEM_PGOFF_FILL_RING,
            ),
            (
                "mmap_completion_ring",
                config.completion_ring_size,
                offsets.completion,
                XDP_UMEM_PGOFF_COMPLETION_RING,
            ),
        ];
        let mut mapped: Vec<super::XdpRingMapping> = Vec::with_capacity(entries.len());
        for (operation, count, offset, page_offset) in entries {
            let length = ring_mapping_length(count, offset)?;
            // SAFETY: kernel-provided ring offsets and fixed read/write shared mapping flags.
            let address = unsafe {
                mmap(
                    std::ptr::null_mut(),
                    length,
                    PROT_READ | PROT_WRITE,
                    MAP_SHARED,
                    fd,
                    page_offset,
                )
            };
            if address == MAP_FAILED {
                let error = kernel_error(operation);
                for mapping in mapped {
                    // SAFETY: each address was returned by mmap with the matching length.
                    unsafe { munmap(mapping.address.as_ptr().cast(), mapping.length) };
                }
                return Err(error);
            }
            let address = NonNull::new(address.cast()).ok_or(AfXdpError::Kernel {
                operation,
                errno: 0,
            })?;
            mapped.push(super::XdpRingMapping {
                address,
                length,
                offsets: offset,
                entries: count,
            });
        }
        let mut mapped = mapped.into_iter();
        Ok(super::XdpRingMappings {
            rx: mapped.next().expect("four mappings"),
            tx: mapped.next().expect("four mappings"),
            fill: mapped.next().expect("four mappings"),
            completion: mapped.next().expect("four mappings"),
        })
    }

    pub(super) fn initialize_fill_ring(
        mapping: &super::XdpRingMapping,
        umem: &UmemRegion,
    ) -> Result<u32, AfXdpError> {
        if mapping.producer_index()? != 0 || mapping.consumer_index()? != 0 {
            return Err(AfXdpError::Kernel {
                operation: "fill_ring_not_empty",
                errno: 0,
            });
        }
        let frame_count = umem.length() / u64::from(umem.chunk_size());
        let frame_count = u32::try_from(frame_count).map_err(|_| {
            AfXdpError::InvalidConfig("UMEM frame count exceeds FILL ring index".to_owned())
        })?;
        if frame_count > mapping.entries {
            return Err(AfXdpError::InvalidConfig(
                "FILL ring capacity is smaller than UMEM frame count".to_owned(),
            ));
        }
        for index in 0..frame_count {
            mapping.write_descriptor(
                index,
                super::XdpDescriptor {
                    address: umem.frame_offset(u64::from(index))?,
                    length: 0,
                    options: 0,
                },
            )?;
        }
        mapping.publish_producer(frame_count)?;
        Ok(frame_count)
    }

    pub(super) fn wait_for_io(fd: i32, timeout: Duration) -> Result<bool, AfXdpError> {
        let millis = c_int::try_from(timeout.as_millis().min(i32::MAX as u128))
            .expect("poll timeout was clamped to c_int::MAX");
        let mut poll_fd = PollFd {
            fd,
            events: POLLIN,
            revents: 0,
        };
        // SAFETY: poll_fd is a valid one-element pollfd array for the owned socket fd.
        let result = unsafe { poll(&raw mut poll_fd, 1, millis) };
        if result < 0 {
            return Err(kernel_error("poll"));
        }
        if result == 0 {
            return Ok(false);
        }
        if poll_fd.revents & (POLLERR | POLLHUP) != 0 {
            return Err(kernel_error("poll_error"));
        }
        Ok(poll_fd.revents & POLLIN != 0)
    }

    pub(super) fn kick_tx(fd: i32) -> Result<(), AfXdpError> {
        const MSG_DONTWAIT: c_int = 0x40;
        // SAFETY: a zero-length kick uses no userspace buffer or destination address; the fd
        // remains owned by the live AfXdpSocket for the duration of this call.
        let result = unsafe { sendto(fd, std::ptr::null(), 0, MSG_DONTWAIT, std::ptr::null(), 0) };
        if result < 0 {
            return Err(kernel_error("sendto_tx_kick"));
        }
        Ok(())
    }

    fn ring_mapping_length(count: u32, offset: XdpRingOffset) -> Result<usize, AfXdpError> {
        let descriptor_bytes = usize::try_from(count)
            .ok()
            .and_then(|value| value.checked_mul(16))
            .ok_or_else(|| AfXdpError::InvalidConfig("ring mapping size overflows".to_owned()))?;
        let end = [
            offset.producer,
            offset.consumer,
            offset.descriptor,
            offset.flags,
        ]
        .into_iter()
        .max()
        .and_then(|value| usize::try_from(value).ok())
        .and_then(|value| value.checked_add(descriptor_bytes.max(4)))
        .ok_or_else(|| {
            AfXdpError::InvalidConfig("ring offset exceeds addressable size".to_owned())
        })?;
        end.checked_add(PAGE_SIZE - 1)
            .map(|value| value / PAGE_SIZE * PAGE_SIZE)
            .ok_or_else(|| AfXdpError::InvalidConfig("ring mapping alignment overflows".to_owned()))
    }

    impl Drop for super::XdpRingMapping {
        fn drop(&mut self) {
            // SAFETY: address/length are the exact pair returned by mmap and are dropped once.
            unsafe { munmap(self.address.as_ptr().cast(), self.length) };
        }
    }

    fn map_offset(raw: XdpRingOffsetRaw) -> XdpRingOffset {
        XdpRingOffset {
            producer: raw.producer,
            consumer: raw.consumer,
            descriptor: raw.desc,
            flags: raw.flags,
        }
    }

    pub(super) fn bind_socket(
        interface_name: &str,
        config: AfXdpConfig,
        umem: &UmemRegion,
    ) -> Result<AfXdpSocket, AfXdpError> {
        let interface = CString::new(interface_name)
            .map_err(|_| AfXdpError::InvalidInterface("interface name contains NUL".to_owned()))?;
        // SAFETY: arguments are fixed Linux constants; returned fd is owned by AfXdpSocket.
        let fd = unsafe { socket(AF_XDP, SOCK_RAW, 0) };
        if fd < 0 {
            return Err(kernel_error("socket"));
        }
        let result = (|| {
            // SAFETY: interface CString is NUL-terminated and valid for this call.
            let index = unsafe { if_nametoindex(interface.as_ptr()) };
            if index == 0 {
                return Err(kernel_error("if_nametoindex"));
            }
            let registration = XdpUmemReg {
                address: umem.address() as u64,
                length: umem.length(),
                chunk_size: umem.chunk_size(),
                headroom: umem.headroom(),
                flags: 0,
                tx_metadata_len: 0,
            };
            // SAFETY: registration points at a live, page-aligned UMEM owned by caller.
            let status = unsafe {
                setsockopt(
                    fd,
                    SOL_XDP,
                    XDP_UMEM_REG,
                    (&raw const registration).cast(),
                    u32::try_from(std::mem::size_of::<XdpUmemReg>())
                        .expect("XDP UMEM registration size fits u32"),
                )
            };
            if status != 0 {
                return Err(kernel_error("setsockopt_umem"));
            }
            for (option, value) in [
                (XDP_RX_RING, config.rx_ring_size),
                (XDP_TX_RING, config.tx_ring_size),
                (XDP_UMEM_FILL_RING, config.fill_ring_size),
                (XDP_UMEM_COMPLETION_RING, config.completion_ring_size),
            ] {
                // SAFETY: value pointer remains valid for the duration of setsockopt.
                let status = unsafe {
                    setsockopt(
                        fd,
                        SOL_XDP,
                        option,
                        (&raw const value).cast(),
                        u32::try_from(std::mem::size_of::<u32>()).expect("u32 size fits u32"),
                    )
                };
                if status != 0 {
                    return Err(kernel_error("setsockopt_ring"));
                }
            }
            let flags = if config.require_zero_copy {
                XDP_ZEROCOPY
            } else {
                0
            };
            let address = SockaddrXdp {
                family: u16::try_from(AF_XDP).expect("AF_XDP fits sockaddr family"),
                flags,
                interface_index: index,
                queue_id: config.queue_id,
                shared_umem_fd: 0,
            };
            // SAFETY: sockaddr has C representation and exact kernel-defined size.
            let status = unsafe {
                bind(
                    fd,
                    (&raw const address).cast(),
                    u32::try_from(std::mem::size_of::<SockaddrXdp>())
                        .expect("XDP sockaddr size fits u32"),
                )
            };
            if status != 0 {
                return Err(kernel_error(if config.require_zero_copy {
                    "bind_zero_copy"
                } else {
                    "bind"
                }));
            }
            Ok(AfXdpSocket { fd })
        })();
        if result.is_err() {
            // SAFETY: fd was returned by socket and is closed exactly once on setup failure.
            unsafe { close(fd) };
        }
        result
    }

    fn kernel_error(operation: &'static str) -> AfXdpError {
        // SAFETY: errno location is provided by the Linux C runtime.
        let errno = unsafe { *__errno_location() };
        AfXdpError::Kernel { operation, errno }
    }

    impl Drop for AfXdpSocket {
        fn drop(&mut self) {
            // SAFETY: fd is owned by this object and is closed at most once.
            unsafe { close(self.fd) };
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(not(target_os = "linux"))]
    use super::AfXdpError;
    use super::{AfXdpConfig, FrameRing, UmemRegion};

    #[test]
    fn validates_ring_sizes_and_interface_names() {
        assert!(
            AfXdpConfig {
                rx_ring_size: 1000,
                ..AfXdpConfig::default()
            }
            .validate()
            .is_err()
        );
        assert!(super::validate_interface_name("eth0;id").is_err());
        assert!(super::validate_interface_name("eth0").is_ok());
        let umem = UmemRegion::new(2 * 1024 * 1024, 2048, 256).expect("UMEM");
        assert_eq!(umem.length(), 2 * 1024 * 1024);
        assert!(UmemRegion::new(1024, 2048, 0).is_err());
        assert_eq!(
            umem.frame_descriptor(3, 1500).expect("frame").offset,
            3 * 2048 + 256
        );
        assert!(umem.frame_descriptor(1024, 64).is_err());
        let ring = FrameRing::new(2).expect("ring");
        let first = umem.frame_descriptor(0, 64).expect("frame");
        let second = umem.frame_descriptor(1, 64).expect("frame");
        assert!(ring.try_push(first));
        assert!(ring.try_push(second));
        assert!(!ring.try_push(first));
        assert_eq!(ring.len(), 2);
        assert_eq!(ring.try_pop(), Some(first));
        assert_eq!(ring.try_pop(), Some(second));
        assert!(ring.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn redirect_program_uses_queue_key_and_redirect_helper() {
        let instructions = super::linux::redirect_instructions(42);
        assert_eq!(instructions.len(), 5);
        assert_eq!(instructions[0].code, 0x61);
        assert_eq!(instructions[0].off, 16);
        assert_eq!(instructions[1].code, 0x18);
        assert_eq!(instructions[1].imm, 42);
        assert_eq!(instructions[3].code, 0x85);
        assert_eq!(instructions[3].imm, 51);
        assert_eq!(instructions[4].code, 0x95);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn non_linux_bind_is_explicitly_unsupported() {
        assert_eq!(
            super::AfXdpSocket::bind(
                "eth0",
                AfXdpConfig::default(),
                &UmemRegion::new(2 * 1024 * 1024, 2048, 256).expect("UMEM"),
            )
            .unwrap_err(),
            AfXdpError::UnsupportedPlatform
        );
    }
}

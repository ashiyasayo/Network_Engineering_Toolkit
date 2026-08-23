//! Windows RIO 資源生命週期與 bounded queue 邊界。
//!
//! 此 crate 不宣稱已連結 Winsock RIO；真正的 Windows API adapter 必須在此邊界
//! 取得已註冊 buffer 後，才能把 descriptor 交給 request/completion worker。

#![cfg_attr(not(windows), forbid(unsafe_code))]
#![cfg_attr(windows, allow(unsafe_code))]

use std::collections::VecDeque;

/// RIO backend 的固定資源設定。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RioConfig {
    /// 預先配置的 registered buffer bytes。
    pub buffer_length: usize,
    /// 單一 frame 最大 payload bytes。
    pub frame_size: u32,
    /// request queue 容量。
    pub request_queue_capacity: u32,
    /// completion queue 容量。
    pub completion_queue_capacity: u32,
}

impl Default for RioConfig {
    fn default() -> Self {
        Self {
            buffer_length: 2 * 1024 * 1024,
            frame_size: 2048,
            request_queue_capacity: 1024,
            completion_queue_capacity: 1024,
        }
    }
}

impl RioConfig {
    /// 驗證不可在 request path 動態擴張的資源設定。
    ///
    /// # Errors
    ///
    /// buffer 無法切成完整 frame，或 queue capacity 不是非零 power-of-two 時回傳錯誤。
    pub fn validate(self) -> Result<Self, RioError> {
        if self.buffer_length == 0
            || self.frame_size == 0
            || self.buffer_length % usize::try_from(self.frame_size).unwrap_or(usize::MAX) != 0
            || self.request_queue_capacity == 0
            || !self.request_queue_capacity.is_power_of_two()
            || self.completion_queue_capacity == 0
            || !self.completion_queue_capacity.is_power_of_two()
        {
            return Err(RioError::InvalidConfig(
                "buffer length must contain whole frames and queue capacities must be non-zero power-of-two values"
                    .to_owned(),
            ));
        }
        Ok(self)
    }
}

/// RIO setup 錯誤。
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RioError {
    /// 設定不合法。
    InvalidConfig(String),
    /// Windows RIO API 尚未在此 build 連結。
    UnsupportedPlatform,
    /// descriptor 超出 registered buffer。
    InvalidDescriptor(String),
    /// queue 已滿。
    QueueFull,
    /// Windows RIO extension discovery/API 呼叫失敗。
    WindowsApi {
        /// 失敗的 API operation。
        operation: &'static str,
        /// Winsock error code。
        code: u32,
    },
}

/// RIO completion result returned by `RIODequeueCompletion`。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RioCompletion {
    /// Winsock status code (zero 表示成功)。
    pub status: i32,
    /// 實際傳輸 bytes。
    pub bytes_transferred: u32,
    /// 呼叫端提交時的 request context token。
    pub request_context: usize,
}

impl std::fmt::Display for RioError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig(message) => write!(formatter, "RIO.INVALID_CONFIG: {message}"),
            Self::UnsupportedPlatform => formatter.write_str("RIO.UNSUPPORTED_PLATFORM"),
            Self::InvalidDescriptor(message) => {
                write!(formatter, "RIO.INVALID_DESCRIPTOR: {message}")
            }
            Self::QueueFull => formatter.write_str("RIO.QUEUE_FULL"),
            Self::WindowsApi { operation, code } => {
                write!(formatter, "RIO.{operation}_FAILED: code={code}")
            }
        }
    }
}

impl std::error::Error for RioError {}

#[cfg(windows)]
mod windows_api {
    use super::{RioBufferSlice, RioCompletion, RioConfig, RioError};
    use std::ffi::c_void;
    use std::marker::PhantomData;
    use std::ptr::NonNull;

    const SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER: u32 = 0xC800_0024;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Guid {
        data1: u32,
        data2: u16,
        data3: u16,
        data4: [u8; 8],
    }

    // WSAID_MULTIPLE_RIO from Mswsock.h; table field order follows the Windows SDK ABI.
    const WSAID_MULTIPLE_RIO: Guid = Guid {
        data1: 0x8509_e081,
        data2: 0x96dd,
        data3: 0x4005,
        data4: [0xb1, 0x65, 0x9e, 0x2e, 0xe8, 0xc7, 0x9e, 0x3f],
    };

    #[repr(C)]
    struct RioExtensionFunctionTable {
        cb_size: u32,
        rio_receive: usize,
        rio_receive_ex: usize,
        rio_send: usize,
        rio_send_ex: usize,
        rio_close_completion_queue: usize,
        rio_create_completion_queue: usize,
        rio_create_request_queue: usize,
        rio_dequeue_completion: usize,
        rio_deregister_buffer: usize,
        rio_notify: usize,
        rio_register_buffer: usize,
        rio_resize_completion_queue: usize,
        rio_resize_request_queue: usize,
    }

    #[repr(C)]
    struct RioBuf {
        buffer_id: usize,
        offset: u32,
        length: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct RioResult {
        status: i32,
        bytes_transferred: u32,
        socket_context: *mut c_void,
        request_context: *mut c_void,
    }

    unsafe extern "system" {
        fn WSAIoctl(
            socket: usize,
            control_code: u32,
            input: *mut c_void,
            input_length: u32,
            output: *mut c_void,
            output_length: u32,
            bytes_returned: *mut u32,
            overlapped: *mut c_void,
            completion: *mut c_void,
        ) -> i32;
        fn WSAGetLastError() -> i32;
    }

    /// Runtime-discovered Winsock RIO function table。
    pub struct RioApi {
        table: NonNull<RioExtensionFunctionTable>,
    }

    impl RioApi {
        /// 以已建立的 Winsock socket discovery RIO function table。
        ///
        /// # Errors
        ///
        /// `WSAIoctl` 失敗、輸出 table 為 null 或 table size 不足時回傳錯誤。
        pub fn discover(socket: usize) -> Result<Self, RioError> {
            let mut guid = WSAID_MULTIPLE_RIO;
            let mut table: *mut RioExtensionFunctionTable = std::ptr::null_mut();
            let mut returned = 0_u32;
            // SAFETY: input GUID/output pointer/lengths are valid for WSAIoctl duration.
            let result = unsafe {
                WSAIoctl(
                    socket,
                    SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER,
                    (&mut guid as *mut Guid).cast(),
                    std::mem::size_of::<Guid>() as u32,
                    (&mut table as *mut *mut RioExtensionFunctionTable).cast(),
                    std::mem::size_of::<*mut RioExtensionFunctionTable>() as u32,
                    &mut returned,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            if result != 0 {
                return Err(RioError::WindowsApi {
                    operation: "WSAIoctl_discover",
                    code: unsafe { WSAGetLastError() as u32 },
                });
            }
            let table = NonNull::new(table).ok_or(RioError::WindowsApi {
                operation: "WSAIoctl_null_table",
                code: returned,
            })?;
            // SAFETY: table pointer is returned by Winsock and must remain valid while provider lives.
            let cb_size = unsafe { table.as_ref().cb_size } as usize;
            if cb_size < std::mem::size_of::<RioExtensionFunctionTable>() {
                return Err(RioError::WindowsApi {
                    operation: "WSAIoctl_short_table",
                    code: cb_size as u32,
                });
            }
            Ok(Self { table })
        }

        /// Register a fixed buffer exactly once for its owner lifetime.
        ///
        /// # Errors
        ///
        /// RIO function pointer is missing or registration returns null時回傳錯誤。
        ///
        /// # Safety
        ///
        /// `address..address + length` 必須是 caller 持有、可寫且在 registration drop 前
        /// 持續有效的記憶體；呼叫端也必須確保不會在 registration 期間搬移或釋放該 buffer。
        pub unsafe fn register_buffer<'a>(
            &'a self,
            address: *mut u8,
            length: u32,
        ) -> Result<RioBufferRegistration<'a>, RioError> {
            // SAFETY: table pointer is validated at discovery; field is a Windows function pointer.
            let function = unsafe { self.table.as_ref().rio_register_buffer };
            if function == 0 {
                return Err(RioError::WindowsApi {
                    operation: "RIORegisterBuffer_missing",
                    code: 0,
                });
            }
            // SAFETY: caller upholds the function's pointer/lifetime contract.
            let id = unsafe {
                std::mem::transmute::<usize, unsafe extern "system" fn(*mut u8, u32) -> *mut c_void>(
                    function,
                )(address, length)
            };
            let id = NonNull::new(id).ok_or(RioError::WindowsApi {
                operation: "RIORegisterBuffer",
                code: unsafe { WSAGetLastError() as u32 },
            })?;
            Ok(RioBufferRegistration {
                api: self,
                id,
                _owner: PhantomData,
            })
        }

        /// 以 `RegisteredBuffer` owner 建立 lifetime-bound native registration。
        ///
        /// # Errors
        ///
        /// buffer 長度超出 Windows API 可接受的 u32 或 registration 失敗時回傳錯誤。
        pub fn register_registered_buffer<'a>(
            &'a self,
            buffer: &'a super::RegisteredBuffer,
        ) -> Result<RioBufferRegistration<'a>, RioError> {
            let length = u32::try_from(buffer.storage.len()).map_err(|_| {
                RioError::InvalidConfig("RIO registered buffer exceeds u32 length".to_owned())
            })?;
            // SAFETY: `buffer` is borrowed for the returned registration lifetime and its boxed
            // storage remains stable; the pointer/length pair is therefore valid for Winsock.
            unsafe { self.register_buffer(buffer.storage.as_ptr().cast_mut(), length) }
        }

        /// 建立固定容量的 RIO completion queue。
        ///
        /// 此 adapter 暫不啟用 notification；worker 以明確的 dequeue/等待策略
        /// 消費 completion，避免把未配置的 event 或 IOCP context 傳入 Winsock。
        ///
        /// # Errors
        ///
        /// capacity 為零、function pointer 缺失或 Windows API 建立失敗時回傳錯誤。
        pub fn create_completion_queue(
            &self,
            capacity: u32,
        ) -> Result<RioCompletionQueue<'_>, RioError> {
            if capacity == 0 {
                return Err(RioError::InvalidConfig(
                    "RIO completion queue capacity must be non-zero".to_owned(),
                ));
            }
            // SAFETY: table pointer is validated at discovery; field is a Windows function pointer.
            let function = unsafe { self.table.as_ref().rio_create_completion_queue };
            if function == 0 {
                return Err(RioError::WindowsApi {
                    operation: "RIOCreateCompletionQueue_missing",
                    code: 0,
                });
            }
            // SAFETY: null notification selects no notification object; capacity is validated.
            let handle = unsafe {
                std::mem::transmute::<
                    usize,
                    unsafe extern "system" fn(u32, *const c_void) -> *mut c_void,
                >(function)(capacity, std::ptr::null())
            };
            let handle = NonNull::new(handle).ok_or(RioError::WindowsApi {
                operation: "RIOCreateCompletionQueue",
                code: unsafe { WSAGetLastError() as u32 },
            })?;
            Ok(RioCompletionQueue { api: self, handle })
        }

        /// 以 completion queue 建立 socket 專屬 RIO request queue。
        ///
        /// RIO request queue 的生命週期由其 socket 管理；呼叫端必須先關閉
        /// request queue 所屬 socket，再釋放 completion queue。
        ///
        /// # Errors
        ///
        /// config 不合法、function pointer 缺失或 Windows API 建立失敗時回傳錯誤。
        pub fn create_request_queue(
            &self,
            socket: usize,
            config: RioConfig,
            completion: &RioCompletionQueue<'_>,
        ) -> Result<RioRequestQueue, RioError> {
            let config = config.validate()?;
            // SAFETY: table pointer is validated at discovery; field is a Windows function pointer.
            let function = unsafe { self.table.as_ref().rio_create_request_queue };
            if function == 0 {
                return Err(RioError::WindowsApi {
                    operation: "RIOCreateRequestQueue_missing",
                    code: 0,
                });
            }
            // SAFETY: handles and scalar limits are valid for this call; socket context is unused.
            let handle = unsafe {
                std::mem::transmute::<
                    usize,
                    unsafe extern "system" fn(
                        usize,
                        u32,
                        u32,
                        u32,
                        u32,
                        *mut c_void,
                        *mut c_void,
                        *mut c_void,
                    ) -> *mut c_void,
                >(function)(
                    socket,
                    config.request_queue_capacity,
                    1,
                    config.request_queue_capacity,
                    1,
                    completion.handle.as_ptr(),
                    completion.handle.as_ptr(),
                    std::ptr::null_mut(),
                )
            };
            let handle = NonNull::new(handle).ok_or(RioError::WindowsApi {
                operation: "RIOCreateRequestQueue",
                code: unsafe { WSAGetLastError() as u32 },
            })?;
            Ok(RioRequestQueue { handle })
        }

        /// 提交一個固定 registered-buffer slice 的接收 request。
        ///
        /// `request_context` 只作為 completion token 傳回，不由 RIO dereference。
        /// 同一 slice 在 completion dequeue 前不得重用。
        ///
        /// # Errors
        ///
        /// slice 無效、function pointer 缺失或 Windows API 拒絕 request 時回傳錯誤。
        pub fn receive(
            &self,
            queue: &RioRequestQueue,
            slice: RioBufferSlice,
            flags: u32,
            request_context: usize,
        ) -> Result<(), RioError> {
            self.submit_io(queue, slice, flags, request_context, false)
        }

        /// 提交一個固定 registered-buffer slice 的傳送 request。
        ///
        /// # Errors
        ///
        /// slice 無效、function pointer 缺失或 Windows API 拒絕 request 時回傳錯誤。
        pub fn send(
            &self,
            queue: &RioRequestQueue,
            slice: RioBufferSlice,
            flags: u32,
            request_context: usize,
        ) -> Result<(), RioError> {
            self.submit_io(queue, slice, flags, request_context, true)
        }

        fn submit_io(
            &self,
            queue: &RioRequestQueue,
            slice: RioBufferSlice,
            flags: u32,
            request_context: usize,
            send: bool,
        ) -> Result<(), RioError> {
            if slice.buffer_id == 0 {
                return Err(RioError::InvalidDescriptor(
                    "RIO buffer ID must be non-zero".to_owned(),
                ));
            }
            // SAFETY: table pointer is validated at discovery; selected field is a Windows function pointer.
            let function = unsafe {
                if send {
                    self.table.as_ref().rio_send
                } else {
                    self.table.as_ref().rio_receive
                }
            };
            if function == 0 {
                return Err(RioError::WindowsApi {
                    operation: if send {
                        "RIOSend_missing"
                    } else {
                        "RIOReceive_missing"
                    },
                    code: 0,
                });
            }
            let mut buffer = RioBuf {
                buffer_id: slice.buffer_id,
                offset: slice.offset,
                length: slice.length,
            };
            // SAFETY: buffer lives for the call; request context is an opaque token and is not dereferenced.
            let accepted = unsafe {
                std::mem::transmute::<
                    usize,
                    unsafe extern "system" fn(
                        *mut c_void,
                        *mut RioBuf,
                        u32,
                        u32,
                        *mut c_void,
                    ) -> i32,
                >(function)(
                    queue.handle.as_ptr(),
                    &mut buffer,
                    1,
                    flags,
                    request_context as *mut c_void,
                )
            };
            if accepted == 0 {
                return Err(RioError::WindowsApi {
                    operation: if send { "RIOSend" } else { "RIOReceive" },
                    code: unsafe { WSAGetLastError() as u32 },
                });
            }
            Ok(())
        }

        /// 從 completion queue 取出已完成的 RIO requests。
        ///
        /// # Errors
        ///
        /// function pointer 缺失或 Windows API 拒絕 dequeue 時回傳錯誤。
        pub fn dequeue_completions(
            &self,
            queue: &RioCompletionQueue<'_>,
            output: &mut [RioCompletion],
        ) -> Result<usize, RioError> {
            if output.is_empty() {
                return Ok(0);
            }
            // SAFETY: table pointer is validated at discovery; field is a Windows function pointer.
            let function = unsafe { self.table.as_ref().rio_dequeue_completion };
            if function == 0 {
                return Err(RioError::WindowsApi {
                    operation: "RIODequeueCompletion_missing",
                    code: 0,
                });
            }
            let mut results = vec![
                RioResult {
                    status: 0,
                    bytes_transferred: 0,
                    socket_context: std::ptr::null_mut(),
                    request_context: std::ptr::null_mut(),
                };
                output.len()
            ];
            // SAFETY: results points to writable storage for the bounded output length.
            let count = unsafe {
                std::mem::transmute::<
                    usize,
                    unsafe extern "system" fn(*mut c_void, *mut RioResult, u32) -> u32,
                >(function)(
                    queue.handle.as_ptr(),
                    results.as_mut_ptr(),
                    output.len() as u32,
                )
            };
            if count == u32::MAX {
                return Err(RioError::WindowsApi {
                    operation: "RIODequeueCompletion",
                    code: unsafe { WSAGetLastError() as u32 },
                });
            }
            let count = count as usize;
            for (destination, source) in output.iter_mut().zip(results.iter()).take(count) {
                *destination = RioCompletion {
                    status: source.status,
                    bytes_transferred: source.bytes_transferred,
                    request_context: source.request_context as usize,
                };
            }
            Ok(count)
        }
    }

    /// Registered buffer token；drop 時呼叫 `RIODeregisterBuffer`。
    pub struct RioBufferRegistration<'a> {
        api: &'a RioApi,
        id: NonNull<c_void>,
        _owner: PhantomData<&'a [u8]>,
    }

    impl RioBufferRegistration<'_> {
        /// native `RIO_BUFFERID` handle。
        #[must_use]
        pub fn raw_id(&self) -> usize {
            self.id.as_ptr() as usize
        }
    }

    impl Drop for RioBufferRegistration<'_> {
        fn drop(&mut self) {
            // SAFETY: table/function pointer and registration token are owned and valid here.
            let function = unsafe { self.api.table.as_ref().rio_deregister_buffer };
            if function != 0 {
                unsafe {
                    std::mem::transmute::<usize, unsafe extern "system" fn(*mut c_void)>(function)(
                        self.id.as_ptr(),
                    );
                }
            }
        }
    }

    /// RIO completion queue；drop 時呼叫 `RIOCloseCompletionQueue`。
    pub struct RioCompletionQueue<'a> {
        api: &'a RioApi,
        handle: NonNull<c_void>,
    }

    impl RioCompletionQueue<'_> {
        /// Native `RIO_CQ` handle。
        #[must_use]
        pub fn raw_handle(&self) -> usize {
            self.handle.as_ptr() as usize
        }
    }

    impl Drop for RioCompletionQueue<'_> {
        fn drop(&mut self) {
            // SAFETY: table/function pointer and completion queue token are valid here.
            let function = unsafe { self.api.table.as_ref().rio_close_completion_queue };
            if function != 0 {
                unsafe {
                    std::mem::transmute::<usize, unsafe extern "system" fn(*mut c_void)>(function)(
                        self.handle.as_ptr(),
                    );
                }
            }
        }
    }

    /// RIO request queue token；其資源由所屬 Winsock socket 管理。
    pub struct RioRequestQueue {
        handle: NonNull<c_void>,
    }

    impl RioRequestQueue {
        /// Native `RIO_RQ` handle。
        #[must_use]
        pub fn raw_handle(&self) -> usize {
            self.handle.as_ptr() as usize
        }
    }
}

#[cfg(windows)]
pub use windows_api::{RioApi, RioBufferRegistration, RioCompletionQueue, RioRequestQueue};

#[cfg(not(windows))]
/// Non-Windows RIO discovery always fails closed。
pub struct RioApi;

#[cfg(not(windows))]
impl RioApi {
    /// RIO 只提供 Windows API。
    ///
    /// # Errors
    ///
    /// 一律回傳 `UnsupportedPlatform`。
    pub fn discover(_socket: usize) -> Result<Self, RioError> {
        Err(RioError::UnsupportedPlatform)
    }
}

/// 此 build 是否已實際連結 Winsock RIO。
#[must_use]
pub const fn is_backend_built() -> bool {
    false
}

/// RIO preflight gate 嚴重程度。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RioPreflightSeverity {
    /// 條件已滿足。
    Pass,
    /// 不得啟動 RIO backend。
    Fail,
}

/// 單一 RIO preflight evidence。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RioPreflightCheck {
    /// Stable gate ID。
    pub id: &'static str,
    /// Gate 結果。
    pub severity: RioPreflightSeverity,
    /// 可呈現原因。
    pub message: &'static str,
}

/// RIO backend preflight 結果。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RioPreflightReport {
    /// 是否可建立 RIO resource/session。
    pub can_run: bool,
    /// 是否已連結 Winsock RIO implementation。
    pub implementation_available: bool,
    /// 不省略任何 gate evidence。
    pub checks: Vec<RioPreflightCheck>,
}

/// 評估 Windows 平台與 Winsock RIO implementation gates。
#[must_use]
pub fn evaluate_rio_preflight(
    platform_is_windows: bool,
    implementation_available: bool,
) -> RioPreflightReport {
    let checks = vec![
        RioPreflightCheck {
            id: "RIO_PLATFORM",
            severity: if platform_is_windows {
                RioPreflightSeverity::Pass
            } else {
                RioPreflightSeverity::Fail
            },
            message: if platform_is_windows {
                "Windows platform is available"
            } else {
                "RIO requires Windows"
            },
        },
        RioPreflightCheck {
            id: "RIO_IMPLEMENTATION",
            severity: if implementation_available {
                RioPreflightSeverity::Pass
            } else {
                RioPreflightSeverity::Fail
            },
            message: if implementation_available {
                "Winsock RIO implementation is linked"
            } else {
                "Winsock RIO implementation is not linked"
            },
        },
    ];
    RioPreflightReport {
        can_run: checks
            .iter()
            .all(|check| check.severity == RioPreflightSeverity::Pass),
        implementation_available,
        checks,
    }
}

/// 已配置且由單一 owner 持有的 registered buffer。
pub struct RegisteredBuffer {
    storage: Box<[u8]>,
    frame_size: u32,
}

impl RegisteredBuffer {
    /// 配置固定 buffer；真正的 `RIORegisterBuffer` 應由平台 adapter 在此 owner 上完成。
    ///
    /// # Errors
    ///
    /// `config` 不符合固定 buffer 與 queue invariants 時回傳錯誤。
    pub fn allocate(config: RioConfig) -> Result<Self, RioError> {
        let config = config.validate()?;
        Ok(Self {
            storage: vec![0; config.buffer_length].into_boxed_slice(),
            frame_size: config.frame_size,
        })
    }

    /// Buffer bytes。
    #[must_use]
    pub fn len(&self) -> usize {
        self.storage.len()
    }

    /// 是否沒有可用 frame。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.storage.is_empty()
    }

    /// 產生 bounded RIO buffer id；request 完成前不可重用同一 frame。
    ///
    /// # Errors
    ///
    /// descriptor 超出 registered buffer 或 payload 超過 frame 大小時回傳錯誤。
    pub fn descriptor(&self, frame_index: usize, length: u32) -> Result<RioDescriptor, RioError> {
        if length > self.frame_size {
            return Err(RioError::InvalidDescriptor(
                "payload exceeds registered frame size".to_owned(),
            ));
        }
        let offset = frame_index
            .checked_mul(self.frame_size as usize)
            .ok_or_else(|| RioError::InvalidDescriptor("frame offset overflows".to_owned()))?;
        let end = offset
            .checked_add(length as usize)
            .ok_or_else(|| RioError::InvalidDescriptor("descriptor end overflows".to_owned()))?;
        if end > self.storage.len() {
            return Err(RioError::InvalidDescriptor(
                "descriptor exceeds registered buffer".to_owned(),
            ));
        }
        Ok(RioDescriptor { offset, length })
    }
}

/// 指向 registered buffer 的 RIO request/completion descriptor。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RioDescriptor {
    /// Buffer 相對位移。
    pub offset: usize,
    /// 有效 payload bytes。
    pub length: u32,
}

/// RIO_BUF-compatible slice of one registered buffer。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RioBufferSlice {
    /// Native RIO buffer ID。
    pub buffer_id: usize,
    /// Slice offset within the registration。
    pub offset: u32,
    /// Slice length。
    pub length: u32,
}

impl RegisteredBuffer {
    /// 建立 RIO_BUF-compatible slice；slice 不得超出原始 registration。
    ///
    /// # Errors
    ///
    /// offset/length 超過 registered buffer 或無法以 u32 表示時回傳錯誤。
    pub fn slice(
        &self,
        buffer_id: usize,
        offset: usize,
        length: usize,
    ) -> Result<RioBufferSlice, RioError> {
        let end = offset
            .checked_add(length)
            .ok_or_else(|| RioError::InvalidDescriptor("RIO slice offset overflows".to_owned()))?;
        if end > self.storage.len() {
            return Err(RioError::InvalidDescriptor(
                "RIO slice exceeds registered buffer".to_owned(),
            ));
        }
        Ok(RioBufferSlice {
            buffer_id,
            offset: u32::try_from(offset).map_err(|_| {
                RioError::InvalidDescriptor("RIO slice offset exceeds u32".to_owned())
            })?,
            length: u32::try_from(length).map_err(|_| {
                RioError::InvalidDescriptor("RIO slice length exceeds u32".to_owned())
            })?,
        })
    }
}

/// bounded request/completion queue；滿時拒絕新 request，不配置額外記憶體。
pub struct RioQueue {
    entries: VecDeque<RioDescriptor>,
    capacity: usize,
}

/// 一組固定容量的 RIO request/completion queues。
pub struct RioQueuePair {
    request: RioQueue,
    completion: RioQueue,
}

impl RioQueuePair {
    /// 依設定建立 request 與 completion queue；兩者 ownership 分離。
    ///
    /// # Errors
    ///
    /// 任一 queue capacity 不合法時回傳錯誤。
    pub fn new(config: RioConfig) -> Result<Self, RioError> {
        let config = config.validate()?;
        Ok(Self {
            request: RioQueue::new(config.request_queue_capacity)?,
            completion: RioQueue::new(config.completion_queue_capacity)?,
        })
    }

    /// 將 descriptor 提交至 request queue。
    ///
    /// # Errors
    ///
    /// request queue 已滿時回傳 `QueueFull`。
    pub fn submit_request(&mut self, descriptor: RioDescriptor) -> Result<(), RioError> {
        self.request.submit(descriptor)
    }

    /// 將一個已完成 request 移至 completion queue；queue 滿時保留 request ownership。
    ///
    /// # Errors
    ///
    /// completion queue 已滿時回傳 `QueueFull`，request descriptor 不會被移除。
    pub fn complete_one(&mut self) -> Result<bool, RioError> {
        if self.completion.entries.len() >= self.completion.capacity {
            return Err(RioError::QueueFull);
        }
        let Some(descriptor) = self.request.complete() else {
            return Ok(false);
        };
        self.completion.entries.push_back(descriptor);
        Ok(true)
    }

    /// 取出下一個 completion descriptor。
    pub fn dequeue_completion(&mut self) -> Option<RioDescriptor> {
        self.completion.complete()
    }

    /// request queue 目前長度。
    #[must_use]
    pub fn request_len(&self) -> usize {
        self.request.len()
    }

    /// completion queue 目前長度。
    #[must_use]
    pub fn completion_len(&self) -> usize {
        self.completion.len()
    }
}

impl RioQueue {
    /// 建立固定容量 queue。
    ///
    /// # Errors
    ///
    /// capacity 為零或不是 power-of-two 時回傳錯誤。
    pub fn new(capacity: u32) -> Result<Self, RioError> {
        if capacity == 0 || !capacity.is_power_of_two() {
            return Err(RioError::InvalidConfig(
                "RIO queue capacity must be a non-zero power-of-two".to_owned(),
            ));
        }
        Ok(Self {
            entries: VecDeque::with_capacity(capacity as usize),
            capacity: capacity as usize,
        })
    }

    /// 嘗試提交 descriptor；queue 滿時回傳 `QueueFull`。
    ///
    /// # Errors
    ///
    /// queue 已達固定容量時回傳 `QueueFull`。
    pub fn submit(&mut self, descriptor: RioDescriptor) -> Result<(), RioError> {
        if self.entries.len() >= self.capacity {
            return Err(RioError::QueueFull);
        }
        self.entries.push_back(descriptor);
        Ok(())
    }

    /// 取出下一個 completion。
    pub fn complete(&mut self) -> Option<RioDescriptor> {
        self.entries.pop_front()
    }

    /// 目前 queue 長度。
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// queue 是否為空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        RegisteredBuffer, RioConfig, RioError, RioPreflightSeverity, RioQueue,
        evaluate_rio_preflight, is_backend_built,
    };

    #[test]
    fn registered_buffer_and_queue_are_bounded() {
        assert!(!is_backend_built());
        let config = RioConfig {
            buffer_length: 4096,
            frame_size: 1024,
            request_queue_capacity: 2,
            completion_queue_capacity: 2,
        };
        let buffer = RegisteredBuffer::allocate(config).expect("buffer");
        let first = buffer.descriptor(0, 512).expect("descriptor");
        let second = buffer.descriptor(3, 1024).expect("descriptor");
        assert_eq!(buffer.slice(7, 1024, 512).expect("slice").length, 512);
        assert!(buffer.slice(7, 4090, 16).is_err());
        assert!(buffer.descriptor(4, 1).is_err());
        let mut queue = RioQueue::new(2).expect("queue");
        queue.submit(first).expect("submit");
        queue.submit(second).expect("submit");
        assert_eq!(queue.submit(first), Err(RioError::QueueFull));
        assert_eq!(queue.complete(), Some(first));
        assert_eq!(queue.complete(), Some(second));
        assert_eq!(queue.complete(), None);
    }

    #[test]
    fn preflight_fails_closed_without_windows_implementation() {
        let report = evaluate_rio_preflight(false, false);
        assert!(!report.can_run);
        assert!(!report.implementation_available);
        assert_eq!(report.checks[0].severity, RioPreflightSeverity::Fail);
        assert_eq!(report.checks[1].severity, RioPreflightSeverity::Fail);
        let linked = evaluate_rio_preflight(true, true);
        assert!(linked.can_run);
    }

    #[test]
    fn request_and_completion_queues_have_separate_capacity() {
        let config = RioConfig {
            request_queue_capacity: 2,
            completion_queue_capacity: 2,
            ..RioConfig::default()
        };
        let buffer = RegisteredBuffer::allocate(config).expect("buffer");
        let descriptor = buffer.descriptor(0, 64).expect("descriptor");
        let mut queues = super::RioQueuePair::new(config).expect("queues");
        queues.submit_request(descriptor).expect("request");
        assert_eq!(queues.request_len(), 1);
        assert!(queues.complete_one().expect("complete"));
        assert_eq!(queues.request_len(), 0);
        assert_eq!(queues.completion_len(), 1);
        assert_eq!(queues.dequeue_completion(), Some(descriptor));
    }
}

//! 平台 peer identity adapter；unsafe 僅集中於此 FFI 邊界。

#![cfg_attr(not(windows), forbid(unsafe_code))]
#![cfg_attr(windows, allow(unsafe_code))]

/// OS transport peer identity。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerIdentity {
    /// Stable principal，Windows 使用 SID 字串。
    pub principal: String,
    /// OS process ID；無法取得時為 None。
    pub process_id: Option<u32>,
}

/// 取得目前 interactive 使用者的 SID。
///
/// 此函式以 process token 取得 SID；portable Helper 使用它將 Named Pipe
/// 限制在啟動桌面程式的同一位使用者，而不是信任 HTTP 或命令列提供的值。
///
/// # Errors
///
/// 無法讀取 token 或 SID 無法轉為文字時回傳錯誤。
#[cfg(windows)]
pub fn current_user_sid() -> Result<String, String> {
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Security::TOKEN_QUERY;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token = null_mut();
    // 安全性：目前程序的 pseudo-handle 有效，token 輸出指標可寫入。
    let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) } != 0;
    if !opened {
        return Err("cannot open current process token".to_owned());
    }
    let result = token_user_sid(token);
    // 安全性：OpenProcessToken 成功後 token 只在此處關閉一次。
    unsafe { CloseHandle(token) };
    result
}

/// 以 UAC `runas` 啟動固定的 Helper executable。
///
/// 呼叫端必須先決定 binary、Pipe、state 目錄與 SID；本函式不接受 shell
/// 指令，也不會以目前使用者權限偷偷降級執行。
///
/// # Errors
///
/// 使用者拒絕 UAC、檔案不存在或 Windows 拒絕啟動時回傳錯誤。
#[cfg(windows)]
pub fn launch_elevated(executable: &std::path::Path, arguments: &[String]) -> Result<(), String> {
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

    let executable = executable
        .canonicalize()
        .map_err(|error| format!("canonicalize helper executable: {error}"))?;
    if !executable.is_file() {
        return Err("helper executable is not a regular file".to_owned());
    }
    let verb = wide("runas");
    let executable = wide(executable.as_os_str());
    let parameters = wide(
        arguments
            .iter()
            .map(|argument| quote_windows_argument(argument))
            .collect::<Vec<_>>()
            .join(" "),
    );
    // 安全性：所有 UTF-16 buffer 都以 NUL 結尾且在呼叫期間保持存活；無視窗 handle
    // 與工作目錄不擴大權限範圍，runas 只會顯示 Windows 標準 UAC 同意提示。
    let result = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            executable.as_ptr(),
            parameters.as_ptr(),
            std::ptr::null(),
            SW_HIDE,
        )
    } as isize;
    if result <= 32 {
        return Err(format!(
            "Windows UAC helper launch was rejected (ShellExecute code {result})"
        ));
    }
    Ok(())
}

/// 取得 Windows 系統 Hosts 檔案的 canonical location。
///
/// 不採用可被目前 process 環境覆寫的 `SystemRoot`，避免 portable Helper
/// 在提權後把 Hosts 操作導向任意使用者指定路徑。
///
/// # Errors
///
/// Windows 無法回傳系統目錄時回傳錯誤。
#[cfg(windows)]
pub fn windows_hosts_path() -> Result<std::path::PathBuf, String> {
    use windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;

    let mut buffer = vec![0_u16; 32_768];
    // 安全性：buffer 可寫入且長度以 UTF-16 code units 傳遞，符合 Windows API 契約。
    let length = unsafe {
        GetSystemWindowsDirectoryW(
            buffer.as_mut_ptr(),
            u32::try_from(buffer.len()).map_err(|_| "Windows directory buffer overflow")?,
        )
    };
    let length = usize::try_from(length).map_err(|_| "Windows directory length overflow")?;
    if length == 0 || length >= buffer.len() {
        return Err("cannot determine Windows system directory".to_owned());
    }
    let directory = String::from_utf16(&buffer[..length])
        .map_err(|_| "Windows system directory is not UTF-16")?;
    Ok(std::path::PathBuf::from(directory)
        .join("drivers")
        .join("etc")
        .join("hosts"))
}

#[cfg(windows)]
static SERVICE_STOP_REQUESTED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(windows)]
static SERVICE_ENTRY: std::sync::OnceLock<fn() -> Result<(), String>> = std::sync::OnceLock::new();

#[cfg(windows)]
static SERVICE_NAME: std::sync::OnceLock<Vec<u16>> = std::sync::OnceLock::new();

/// 將固定 Helper workload 接到 Windows SCM service dispatcher。
///
/// FFI 與 service control callback 全數留在 platform adapter，讓 Helper
/// 本體維持 safe Rust。停止要求只會設旗標，workload 可先完成自身 rollback。
///
/// # Errors
///
/// Dispatcher 無法連接 SCM、重複啟動或 workload 結束失敗時回傳錯誤。
#[cfg(windows)]
pub fn run_windows_service(
    service_name: &str,
    workload: fn() -> Result<(), String>,
) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::System::Services::{SERVICE_TABLE_ENTRYW, StartServiceCtrlDispatcherW};

    SERVICE_STOP_REQUESTED.store(false, std::sync::atomic::Ordering::Release);
    SERVICE_ENTRY
        .set(workload)
        .map_err(|_| "Windows service workload was already configured".to_owned())?;
    SERVICE_NAME
        .set(
            std::ffi::OsStr::new(service_name)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect(),
        )
        .map_err(|_| "Windows service name was already configured".to_owned())?;
    let name = SERVICE_NAME
        .get()
        .ok_or("Windows service name is unavailable")?;
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: name.as_ptr().cast_mut(),
            lpServiceProc: Some(windows_service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: std::ptr::null_mut(),
            lpServiceProc: None,
        },
    ];
    // 安全性：service table 以 NUL 結尾，且會持續存活至 dispatcher 返回。
    let started = unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } != 0;
    if !started {
        // 安全性：GetLastError 會讀取 dispatcher 失敗後的 thread-local 錯誤碼。
        let code = unsafe { GetLastError() };
        return Err(format!(
            "Windows service dispatcher failed (Win32 error {code})"
        ));
    }
    Ok(())
}

/// 回傳 SCM stop control 是否已抵達；workload 應等待可恢復狀態完成後才離開。
#[cfg(windows)]
#[must_use]
pub fn windows_service_stop_requested() -> bool {
    SERVICE_STOP_REQUESTED.load(std::sync::atomic::Ordering::Acquire)
}

#[cfg(windows)]
unsafe extern "system" fn windows_service_main(_count: u32, _arguments: *mut *mut u16) {
    use windows_sys::Win32::System::Services::{
        RegisterServiceCtrlHandlerExW, SERVICE_ACCEPT_STOP, SERVICE_RUNNING, SERVICE_START_PENDING,
        SERVICE_STOPPED,
    };

    let Some(name) = SERVICE_NAME.get() else {
        return;
    };
    // 安全性：service name 以 NUL 結尾，callback 不使用外部 context。
    let handle = unsafe {
        RegisterServiceCtrlHandlerExW(
            name.as_ptr(),
            Some(windows_service_control_handler),
            std::ptr::null(),
        )
    };
    if handle.is_null() {
        return;
    }
    set_windows_service_status(handle, SERVICE_START_PENDING, 0, 0);
    set_windows_service_status(handle, SERVICE_RUNNING, SERVICE_ACCEPT_STOP, 0);
    let exit_code = SERVICE_ENTRY
        .get()
        .copied()
        .ok_or_else(|| "Windows service workload is unavailable".to_owned())
        .and_then(|workload| workload())
        .map_or(1, |()| 0);
    set_windows_service_status(handle, SERVICE_STOPPED, 0, exit_code);
}

#[cfg(windows)]
unsafe extern "system" fn windows_service_control_handler(
    control: u32,
    _event_type: u32,
    _event_data: *mut std::ffi::c_void,
    _context: *mut std::ffi::c_void,
) -> u32 {
    use windows_sys::Win32::System::Services::SERVICE_CONTROL_STOP;
    if control == SERVICE_CONTROL_STOP {
        SERVICE_STOP_REQUESTED.store(true, std::sync::atomic::Ordering::Release);
    }
    0
}

#[cfg(windows)]
fn set_windows_service_status(
    handle: windows_sys::Win32::System::Services::SERVICE_STATUS_HANDLE,
    state: windows_sys::Win32::System::Services::SERVICE_STATUS_CURRENT_STATE,
    controls: u32,
    exit_code: u32,
) {
    use windows_sys::Win32::System::Services::{
        SERVICE_STATUS, SERVICE_WIN32_OWN_PROCESS, SetServiceStatus,
    };

    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: controls,
        dwWin32ExitCode: exit_code,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 0,
        dwWaitHint: 0,
    };
    // 安全性：service handle 來自 SCM，status 在呼叫期間有效。
    let _ = unsafe { SetServiceStatus(handle, &raw const status) };
}

#[cfg(windows)]
fn token_user_sid(token: windows_sys::Win32::Foundation::HANDLE) -> Result<String, String> {
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_USER, TokenUser};

    let mut required = 0_u32;
    // SAFETY: 第一次呼叫只查詢 token user buffer 所需大小，null buffer 為 API 指定用法。
    let _ = unsafe { GetTokenInformation(token, TokenUser, null_mut(), 0, &raw mut required) };
    if required == 0 {
        return Err("cannot query token user size".to_owned());
    }
    let required_bytes = usize::try_from(required).map_err(|_| "token size overflow")?;
    let word_count = required_bytes
        .checked_add(std::mem::size_of::<usize>() - 1)
        .ok_or("token size overflow")?
        / std::mem::size_of::<usize>();
    let mut buffer = vec![0_usize; word_count];
    // SAFETY: buffer 可容納先前查得大小，輸出長度指標有效。
    let read = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            required,
            &raw mut required,
        )
    } != 0;
    if !read {
        return Err("cannot read token user".to_owned());
    }
    // SAFETY: TokenUser 成功時，buffer 開頭為有效 TOKEN_USER。
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    let mut sid_text = null_mut();
    // SAFETY: SID 由 token buffer 持有，輸出指標有效。
    let converted = unsafe { ConvertSidToStringSidW(user.User.Sid, &raw mut sid_text) } != 0;
    if !converted || sid_text.is_null() {
        return Err("cannot convert token SID".to_owned());
    }
    let mut length = 0_usize;
    // SAFETY: API 回傳 NUL-terminated UTF-16 LocalAlloc 字串。
    unsafe {
        while *sid_text.add(length) != 0 {
            length += 1;
        }
    }
    // SAFETY: 前述量測長度位於 API 保證的 UTF-16 buffer 範圍內。
    let sid = unsafe { std::slice::from_raw_parts(sid_text, length) };
    let result = String::from_utf16(sid).map_err(|_| "token SID is not UTF-16".to_owned());
    // SAFETY: ConvertSidToStringSidW 使用 LocalAlloc，LocalFree 必須釋放一次。
    unsafe { LocalFree(sid_text.cast()) };
    result
}

#[cfg(windows)]
fn wide(value: impl AsRef<std::ffi::OsStr>) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    value
        .as_ref()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

#[cfg(windows)]
fn quote_windows_argument(argument: &str) -> String {
    if !argument.contains([' ', '\t', '"']) && !argument.is_empty() {
        return argument.to_owned();
    }
    let mut quoted = String::from("\"");
    let mut backslashes = 0_usize;
    for character in argument.chars() {
        match character {
            '\\' => backslashes += 1,
            '"' => {
                quoted.push_str(&"\\".repeat(backslashes.saturating_mul(2).saturating_add(1)));
                quoted.push('"');
                backslashes = 0;
            }
            _ => {
                quoted.push_str(&"\\".repeat(backslashes));
                quoted.push(character);
                backslashes = 0;
            }
        }
    }
    quoted.push_str(&"\\".repeat(backslashes.saturating_mul(2)));
    quoted.push('"');
    quoted
}

/// 非 Windows 平台不能取得 Windows SID。
#[cfg(not(windows))]
pub fn current_user_sid() -> Result<String, String> {
    Err("Windows current user SID is unavailable on this platform".to_owned())
}

/// 非 Windows 平台不能透過 UAC 啟動 Helper。
#[cfg(not(windows))]
pub fn launch_elevated(_executable: &std::path::Path, _arguments: &[String]) -> Result<(), String> {
    Err("Windows UAC helper launch is unavailable on this platform".to_owned())
}

/// 非 Windows 平台沒有 Windows 系統 Hosts 路徑。
#[cfg(not(windows))]
pub fn windows_hosts_path() -> Result<std::path::PathBuf, String> {
    Err("Windows Hosts path is unavailable on this platform".to_owned())
}

/// 非 Windows 平台沒有 SCM service dispatcher。
#[cfg(not(windows))]
pub fn run_windows_service(
    _service_name: &str,
    _workload: fn() -> Result<(), String>,
) -> Result<(), String> {
    Err("Windows service dispatcher is unavailable on this platform".to_owned())
}

/// 非 Windows 平台不會收到 SCM stop control。
#[cfg(not(windows))]
#[must_use]
pub fn windows_service_stop_requested() -> bool {
    false
}

/// 以 Windows `MoveFileExW(REPLACE_EXISTING|WRITE_THROUGH)` 原子替換受控檔案。
///
/// 此 primitive 只供已驗證的 helper-owned path 使用；呼叫端仍必須先完成
/// protocol/path validation，不接受任意 shell command 或未驗證目的地。
///
/// # Errors
///
/// 檔案無法寫入、同步或 Windows 原子替換失敗時回傳錯誤。
#[cfg(windows)]
pub fn atomic_replace_file(path: &std::path::Path, bytes: &[u8]) -> Result<(), String> {
    use std::fs::OpenOptions;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };

    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)
        .map_err(|error| format!("create replacement file: {error}"))?;
    std::io::Write::write_all(&mut file, bytes)
        .and_then(|()| std::io::Write::flush(&mut file))
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("flush replacement file: {error}"))?;
    let source = temporary
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let destination = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    // SAFETY: both UTF-16 buffers are NUL-terminated and remain alive for the call;
    // flags request replacement and durable metadata update within the same volume.
    let moved = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if moved == 0 {
        let code = unsafe { GetLastError() };
        let _ = std::fs::remove_file(&temporary);
        return Err(format!(
            "replace helper-owned file failed (Win32 error {code})"
        ));
    }
    Ok(())
}

/// 非 Windows 平台不提供 Windows atomic replacement primitive。
///
/// # Errors
///
/// 永遠回傳 unsupported-platform 錯誤。
#[cfg(not(windows))]
pub fn atomic_replace_file(_path: &std::path::Path, _bytes: &[u8]) -> Result<(), String> {
    Err("Windows atomic replacement is unavailable on this platform".to_owned())
}

/// 從 Windows Named Pipe handle 取得 client SID 與 process ID。
///
/// # Errors
///
/// handle 無效、無法取得 client process/token、token 資訊格式錯誤或 SID
/// 無法轉為文字時回傳錯誤。
#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[cfg(windows)]
pub fn named_pipe_peer_identity(
    handle: windows_sys::Win32::Foundation::HANDLE,
) -> Result<PeerIdentity, String> {
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE, LocalFree};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser};
    use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err("named pipe handle is invalid".to_owned());
    }
    let mut process_id = 0_u32;
    // SAFETY: handle is owned by the Tokio NamedPipeServer for this call and output pointer is valid.
    let process_ok = unsafe { GetNamedPipeClientProcessId(handle, &raw mut process_id) } != 0;
    if !process_ok || process_id == 0 {
        return Err("cannot identify named pipe client process".to_owned());
    }
    // SAFETY: OpenProcess receives a validated PID and returns an owned kernel handle.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    if process.is_null() {
        return Err("cannot open named pipe client process".to_owned());
    }
    let mut token = null_mut();
    // SAFETY: process is a live handle; token output pointer is valid.
    let token_ok = unsafe { OpenProcessToken(process, TOKEN_QUERY, &raw mut token) } != 0;
    if !token_ok {
        // SAFETY: process was returned by OpenProcess and is closed exactly once.
        unsafe { CloseHandle(process) };
        return Err("cannot open named pipe client token".to_owned());
    }
    let mut required = 0_u32;
    // SAFETY: first call only queries required size; null buffer is documented for this use.
    let _ = unsafe { GetTokenInformation(token, TokenUser, null_mut(), 0, &raw mut required) };
    if required == 0 {
        // SAFETY: handles are valid and closed exactly once.
        unsafe {
            CloseHandle(token);
            CloseHandle(process);
        }
        return Err("cannot query named pipe client token size".to_owned());
    }
    let required_bytes = usize::try_from(required).map_err(|_| "token size overflow")?;
    let word_count = required_bytes
        .checked_add(std::mem::size_of::<usize>() - 1)
        .ok_or("token size overflow")?
        / std::mem::size_of::<usize>();
    let mut buffer = vec![0_usize; word_count];
    // SAFETY: buffer is writable for the requested size and output pointer is valid.
    let info_ok = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            required,
            &raw mut required,
        )
    } != 0;
    if !info_ok {
        // SAFETY: handles are valid and closed exactly once.
        unsafe {
            CloseHandle(token);
            CloseHandle(process);
        }
        return Err("cannot query named pipe client token".to_owned());
    }
    // SAFETY: TokenUser guarantees the buffer starts with a TOKEN_USER structure.
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    let mut sid_text = null_mut();
    // SAFETY: SID pointer is owned by the token buffer and output pointer is valid.
    let sid_ok = unsafe { ConvertSidToStringSidW(user.User.Sid, &raw mut sid_text) } != 0;
    // SAFETY: handles are valid and closed exactly once.
    unsafe {
        CloseHandle(token);
        CloseHandle(process);
    }
    if !sid_ok || sid_text.is_null() {
        return Err("cannot convert named pipe client SID".to_owned());
    }
    let mut length = 0_usize;
    // SAFETY: ConvertSidToStringSidW returns a NUL-terminated LocalAlloc string.
    unsafe {
        while *sid_text.add(length) != 0 {
            length += 1;
        }
    }
    // SAFETY: sid_text points to a valid UTF-16 string of the measured length.
    let principal = unsafe { std::slice::from_raw_parts(sid_text, length) };
    let principal = String::from_utf16(principal).map_err(|_| "client SID is not UTF-16")?;
    // SAFETY: ConvertSidToStringSidW allocates with LocalAlloc; LocalFree releases it.
    unsafe { LocalFree(sid_text.cast()) };
    Ok(PeerIdentity {
        principal,
        process_id: Some(process_id),
    })
}

/// Non-Windows builds cannot claim Windows token identity.
#[cfg(not(windows))]
///
/// # Errors
///
/// Always returns an unsupported-platform error.
pub fn named_pipe_peer_identity(_handle: usize) -> Result<PeerIdentity, String> {
    Err("Windows Named Pipe identity is unavailable on this platform".to_owned())
}

#[cfg(test)]
mod tests {
    #[cfg(not(windows))]
    #[test]
    fn non_windows_build_never_claims_named_pipe_identity() {
        assert!(super::named_pipe_peer_identity(0).is_err());
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_build_never_claims_windows_atomic_replace() {
        assert!(super::atomic_replace_file(std::path::Path::new("/tmp/nettool"), b"x").is_err());
    }
}

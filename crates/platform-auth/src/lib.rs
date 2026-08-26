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

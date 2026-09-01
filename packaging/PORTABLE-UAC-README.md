# NetTool Portable UAC Bundle

此 ZIP 不安裝任何 Windows Service。請保留所有檔案在同一目錄並執行 `nettool-desktop.exe`。當使用者在 Profiles 頁面按下 **Apply profile** 時，Windows 會顯示 UAC；接受後才會啟動一次性的 `nettool-helper.exe`。

這個 Helper 的 Named Pipe 只接受目前 Windows 使用者 SID。它在 profile confirm、explicit rollback 或 Safe Apply deadline rollback 完成後自行結束；若兩分鐘內沒有收到任何請求，也會自行結束。它不會註冊 Service、寫入開機啟動項目或留駐背景。

若拒絕 UAC，profile 不會套用。一般不含 `nettool-helper.exe` 的 portable ZIP 仍可建立、讀取、匯出 profile 與執行診斷，但會提示需安裝 Helper 才能套用。

# Windows package staging

桌面 MSI 與 `NetTool Helper` MSI 是兩個獨立套件。桌面 MSI 只含使用者層 desktop、Agent、GUI 與 dataplane；Helper MSI 才會以 LocalSystem 註冊 `NetToolHelper` service，並以安裝時指定的使用者 SID 限制 `\\.\pipe\NetTool.Helper.Service`。服務停止時會等待既有 Safe Apply confirm 或 deadline rollback，避免移除服務讓網路狀態無法復原。

Helper MSI 必須使用包裝器安裝，讓目前 interactive user 的 SID 作為 MSI property：

```powershell
.\packaging\windows\install-helper.ps1 -MsiPath .\target\release\bundle\msi\NetToolHelper_0.1.4_x64_en-US.msi
```

`build-release.ps1` 會 stage 六個 binary（含 `nettool-helper.exe`）；先使用 Tauri 建立 desktop MSI，再以 `build-helper-msi.ps1` 建立獨立 Helper MSI。兩者都應在發行前 Authenticode 簽章。

發行前請在可還原的專用 Windows VM 執行 [Release Acceptance](RELEASE-ACCEPTANCE.md)。它會實測 MSI 安裝／移除、Helper service、兩種 portable 的邊界與 optional Safe Apply rollback；不可在日常使用的機器執行。

GitHub Release 另提供兩種 portable ZIP：

- `nettool-windows-x64-portable.zip`：不含 Helper、不要求 UAC；可建立、讀取、匯出 profile 與執行診斷／測試。套用 profile 或變更 Hosts 會明確提示需安裝 Helper。
- `nettool-windows-x64-portable-uac.zip`：包含一次性 Helper；只有使用者在 GUI 按 Apply profile 時才顯示 UAC。接受後 Named Pipe 限制為目前 SID，Helper 在 confirm、rollback、deadline rollback 後或兩分鐘無請求時自行結束，絕不註冊 Service。

```powershell
.packaging\windows\install.ps1 -SourceDirectory .\target\release -DryRun
.packaging\windows\install.ps1 -SourceDirectory .\target\release
.\packaging\windows\build-helper-msi.ps1 -HelperBinary .\target\release\nettool-helper.exe -Version 0.1.4
```

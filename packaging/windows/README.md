# Windows package staging

`install.ps1` 僅安裝固定 allowlist binaries（包含 `nettool-desktop.exe`），先驗證完整 release 並拒絕 symlink/reparse point，再建立 staging directory，最後以同一 volume 的 rename 替換；既有目錄會保留 timestamp backup。腳本不自行繞過 UAC，也不註冊 privileged helper service；正式 MSI 應由 Tauri bundler 產生並簽章。

```powershell
.packaging\windows\install.ps1 -SourceDirectory .\target\release -DryRun
.packaging\windows\install.ps1 -SourceDirectory .\target\release
```

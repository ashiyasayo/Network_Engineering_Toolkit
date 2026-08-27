# Windows package staging

`build-release.ps1` 與 `install.ps1` 共用五個 binary manifest：`nettool.exe`、`nettool-desktop.exe`、`nettool-agent.exe`、`nettool-gui.exe`、`nettool-dataplane.exe`。Installer 先驗證完整 release 並拒絕 symlink/reparse point，再建立 staging directory，最後以同一 volume 的 rename 替換；既有目錄會保留 timestamp backup。腳本不自行繞過 UAC，也不註冊 privileged helper service；正式 MSI 應由 Tauri bundler 產生並簽章。

GitHub Release 會額外產生 `nettool-windows-x64-portable.zip`。解壓縮後可直接執行 `nettool-desktop.exe`，五個 binary、授權文件與 `README-portable.md` 都在 ZIP 根目錄；它不安裝 Helper、不要求 UAC，也不提供需要 privileged Helper 的網路或 Hosts 變更功能。stable release 的五個 binary 與 MSI 由 Authenticode 簽章，prerelease 則明確保持未簽章。

```powershell
.packaging\windows\install.ps1 -SourceDirectory .\target\release -DryRun
.packaging\windows\install.ps1 -SourceDirectory .\target\release
```

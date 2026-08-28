# NetTool 發行與安裝

原生桌面殼層是 `apps/desktop` 的 Tauri 2 application。它只負責原生視窗與程序生命週期；所有網路、設定與特權操作仍由 Agent/Helper 執行。

發行檔案依專案的 `MIT OR Apache-2.0` 雙重授權提供；請在再發布套件時一併保留根目錄的 `LICENSE.md`、`LICENSE-MIT` 與 `LICENSE-APACHE`。

## 開發

```sh
cargo run -p nettool-desktop
```

## 發行

- macOS：`./packaging/macos/build-desktop-app.sh` 建立 `NetTool.app`，再用 `install-desktop.sh` 安裝。正式發佈前必須 Developer ID codesign、notarize、staple。
- Windows：`./packaging/windows/build-release.ps1` staging 後，使用 Tauri/WiX 產生 MSI；GitHub Release 另外提供包含五個 binary 的免安裝 `nettool-windows-x64-portable.zip`，正式 MSI 與 portable binary 必須 Authenticode 簽章。
- Linux：`./packaging/linux/build-release.sh` staging 後，使用 Tauri bundler 產生 AppImage/deb；`install-desktop.sh` 適合內部部署。

使用 Tauri bundler 時，先執行 `cargo build --release -p nettool -p nettool-desktop -p nettool-agent -p nettool-gui -p nettool-dataplane`，再執行 `./packaging/prepare-tauri-resources.sh`，最後執行 `cargo tauri build`。Tauri bundle 會把四個 runtime sidecar 從 `apps/desktop/resources` 一起帶入。

## GitHub Release

推送版本 tag 即可觸發 `.github/workflows/release.yml`：

```sh
git tag v0.1.3
git push origin v0.1.3
```

GitHub Actions 會在 Ubuntu、macOS、Windows runner 平行產生 AppImage/deb、DMG、MSI 與 Windows portable ZIP，驗證套件內容後建立同名 GitHub **prerelease**，並附上三份授權文件。推送 tag 只會走 prerelease；從 GitHub Actions 以 `workflow_dispatch` 選擇 `stable` 時，workflow 會先要求並使用下列 secrets：Apple Developer ID (`APPLE_CERTIFICATE_BASE64`、`APPLE_CERTIFICATE_PASSWORD`、`APPLE_SIGNING_IDENTITY`、`APPLE_ID`、`APPLE_TEAM_ID`、`APPLE_APP_PASSWORD`)、Windows Authenticode (`WINDOWS_CERTIFICATE_BASE64`、`WINDOWS_CERTIFICATE_PASSWORD`) 與 Linux GPG release artifact signing (`LINUX_GPG_PRIVATE_KEY_BASE64`、`LINUX_GPG_KEY_ID`、`LINUX_GPG_PASSPHRASE`)。缺少任一 secret 或平台簽章工具時，stable release 會 fail closed，不會建立未簽章的正式 release；prerelease 產物僅適合測試或內部部署。完整的 secrets 設定與安全發行順序見 [Stable Release secrets 設定](RELEASE_SECRETS.md)。

所有 installer 都以固定 binary allowlist、staging directory 與 same-volume replacement 降低更新中斷風險。Helper 仍是獨立安裝步驟，不會因安裝 GUI 而取得 root 權限。

## Portable bundle

Windows portable ZIP 解壓縮後直接執行 `nettool-desktop.exe` 即可啟動桌面殼層；五個 binary 與 [portable 使用限制](PORTABLE-README.md) 必須留在同一個目錄。這個 bundle 不安裝 privileged Helper；需要變更網路或 Hosts 時，仍須依平台另行安裝並啟動 Helper。

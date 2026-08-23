# NetTool 發行與安裝

原生桌面殼層是 `apps/desktop` 的 Tauri 2 application。它只負責原生視窗與程序生命週期；所有網路、設定與特權操作仍由 Agent/Helper 執行。

## 開發

```sh
cargo run -p nettool-desktop
```

## 發行

- macOS：`./packaging/macos/build-desktop-app.sh` 建立 `NetTool.app`，再用 `install-desktop.sh` 安裝。正式發佈前必須 Developer ID codesign、notarize、staple。
- Windows：`./packaging/windows/build-release.ps1` staging 後，使用 Tauri/WiX 產生 MSI；正式 MSI 必須 Authenticode 簽章。
- Linux：`./packaging/linux/build-release.sh` staging 後，使用 Tauri bundler 產生 AppImage/deb；`install-desktop.sh` 適合內部部署。

使用 Tauri bundler 時，先執行 `cargo build --release -p nettool -p nettool-desktop -p nettool-agent -p nettool-gui -p nettool-dataplane`，再執行 `./packaging/prepare-tauri-resources.sh`，最後執行 `cargo tauri build`。Tauri bundle 會把四個 runtime sidecar 從 `apps/desktop/resources` 一起帶入。

## GitHub Release

推送版本 tag 即可觸發 `.github/workflows/release.yml`：

```sh
git tag v0.1.0
git push origin v0.1.0
```

GitHub Actions 會在 Ubuntu、macOS、Windows runner 平行產生 AppImage/deb、DMG、MSI，驗證套件內容後建立同名 GitHub Release。正式發行前應在 workflow 加入 Apple Developer ID、Windows Authenticode 與 Linux repository signing secrets；未設定簽章時產物僅適合測試或內部部署。

所有 installer 都以固定 binary allowlist、staging directory 與 same-volume replacement 降低更新中斷風險。Helper 仍是獨立安裝步驟，不會因安裝 GUI 而取得 root 權限。

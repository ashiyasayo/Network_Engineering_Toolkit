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

所有 installer 都以固定 binary allowlist、staging directory 與 same-volume replacement 降低更新中斷風險。Helper 仍是獨立安裝步驟，不會因安裝 GUI 而取得 root 權限。

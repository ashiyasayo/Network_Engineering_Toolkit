# macOS package staging

`install.sh` 只接受固定 allowlist 的 release binaries：`nettool`、`nettool-agent`、`nettool-gui` 與 `nettool-dataplane`，且拒絕 symlink。它先建立同一檔案系統的 staging directory，再以 directory rename 完成替換；既有安裝會保留 timestamp backup，失敗時嘗試恢復。

原生桌面 bundle 使用 `build-desktop-app.sh` 建立，`install-desktop.sh` 安裝至 `/Applications`。Bundle 預設為 unsigned；正式發布必須另外執行 Developer ID codesign、notarization 與 stapling。

```sh
sudo ./packaging/macos/install.sh ./target/release
```

目前沒有把尚未完成的 macOS privileged helper 偽裝成已安裝功能；正式 helper 與 launchd signing 仍需另外通過平台驗收。

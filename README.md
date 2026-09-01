# Network Engineering Toolkit

跨平台網路設定、測速與封包分析工具。專案提供 Agent/CLI 控制平面、loopback-only GUI、Tauri desktop shell、特權 Helper 與 dataplane 元件。

## 快速開始

需要 Rust 1.85 或更新版本。先執行唯讀環境探測：

```bash
cargo run -p nettool-dataplane -- probe
```

啟動 Agent 後，可使用 CLI 或 GUI：

```bash
cargo run -p nettool-agent
cargo run -p nettool -- health --output json
cargo run -p nettool-gui
```

正式桌面殼層使用 Tauri 2：

```bash
cargo run -p nettool-desktop
```

## 文件

- [架構說明](docs/ARCHITECTURE.md)：程序責任、IPC、信任邊界、資料平面與安全設計。
- [CLI Reference](docs/CLI_REFERENCE.md)：CLI、GUI、輸出格式、全域選項與常用操作。
- [規格追蹤矩陣](docs/REQUIREMENT_TRACEABILITY.md)：需求、實作模組、測試與驗收狀態。
- [Hardware Acceptance Runbook](docs/HARDWARE_ACCEPTANCE.md)：Linux/Windows backend 與 100GbE 實機驗收。
- [發行與安裝](packaging/README.md)：桌面套件、sidecar staging 與各平台安裝流程。
- [Windows Helper 與 Portable](packaging/windows/README.md)：獨立 Helper MSI、一般 portable 與按需 UAC portable 的安全邊界。

## 目前範圍

CLI 與 GUI 都經由 Agent Action API 執行；需要特權的網路設定與 Hosts 操作則交由 authenticated Helper。DPDK、AF_XDP 與 RIO 的 capability、implementation 和 runtime preflight 分開回報，預設 build 不會把未驗證的硬體能力標示為可用。未完成真實硬體 POC 前，任何結果都不標示為 `100G Certified`。

更多命令與限制請參閱 [CLI Reference](docs/CLI_REFERENCE.md)；程序邊界與設計原因請參閱 [Architecture](docs/ARCHITECTURE.md)。

## 授權

本專案採 `MIT OR Apache-2.0` 雙重授權，詳見 [授權說明](LICENSE.md)、[MIT License](LICENSE-MIT) 與 [Apache License 2.0](LICENSE-APACHE)。第三方依賴與平台元件仍受其各自授權條款約束。

# NetTool 專案綜合健檢與補充分析報告

> 本報告補充前兩次分析（架構設計/過度設計、USB 網卡快速設定），針對「測試策略」、「安全模型」、「部署打包」、「效能並發」及「程式碼品質/可觀測性」五大面向進行全面審查。
> 分析日期：2026-08-24
> 最近一次修正狀態複核：2026-08-26
> 專案版本：0.1.1 (Rust 1.85 Edition 2024)

---

## 總覽評分與核心發現

| 面向 | 評級 | 核心亮點 | 主要短板 / 潛在風險 |
|---|:---:|---|---|
| **1. 測試策略與覆蓋率** | 🟡 **良好 (7.5/10)** | 目前靜態計數約 237 個測試、封包熱路徑覆蓋紮實 | Windows/macOS loopback 已納入 CI 設定，真實 100G 硬體仍未接上 CI |
| **2. 安全模型與邊界** | 🟢 **卓越 (9.0/10)** | 權限最小化、Helper Whitelist、mTLS 1.3 + Out-of-band 指紋 | Windows reader 已改為固定 JSON query，仍需 Windows smoke test 與 Named Pipe ACL 實機驗證 |
| **3. 部署與打包交付** | 🟡 **中等 (7.0/10)** | Tauri 2 跨平台打包 sidecars、Release CI 自動化解包驗證 | 缺少 Apple/Windows 正式簽章、特權 Helper 需手動分開安裝 |
| **4. 效能與並發架構** | 🟢 **優良 (8.5/10)** | 封包 Hot Path 零記憶體配置、Bounded flow table | Mutex 仍存在，但目前未有長時間 worker 持鎖 await 的證據；需以 regression test 維護邊界 |
| **5. 程式碼品質與可觀測性** | 🟡 **兩極 (7.0/10)** | 長駐 binary 已有 stderr structured tracing 與 request correlation | 其他短命工具仍保留原始輸出；本輪不加入 file/syslog/EventLog |

---

## 一、測試策略與覆蓋率分析

### 1. 測試分佈現況
原報告的 **208 個測試已過期**；2026-08-26 Windows runner 的 workspace 驗證為 **220 個一般測試通過、10 個 ignored loopback 測試通過**，`cargo test --workspace -- --list` 列出 **230 個測試項目**。精確數量會依平台與 native feature 改變，測試集中在核心邏輯與協定層：

本次可核對的驗證命令如下；ignored suite 是分別執行，避免把平台差異或需要 dynamic socket bind 的測試誤算成一般 workspace 測試：

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- `cargo test -p nettool-agent --bin nettool-agent -- --ignored`
- `cargo test -p nettool-speed -- --ignored`
- `cargo test -p nettool-node -- --ignored`

上述命令在目前 Windows runner 均通過；這只代表目前 runner 的可重現結果，不代表 GitHub Ubuntu/macOS job 或真實 NIC 驗收已完成。

另以固定 PowerShell invocation 做無 NIC 副作用的語法與無 BOM UTF-8 中文介面名稱輸出 smoke check，結果通過；目前 sandbox 執行實際 `Get-NetAdapter` query 仍回傳拒絕存取，因此不把它計入真實介面讀取驗收。
- `crates/packet`: 30 個（封包解析、flow table、TCP 分析器、計數器）
- `crates/speed`: 27 個（TCP/UDP receiver/sender、pacing、header 驗證）
- `crates/node`: 26 個（mTLS、session coordinator、operation 冪等性）
- `apps/cli`: 19 個（參數解析、dry-run、錯誤代碼轉換）
- `crates/backend-dpdk`: Windows runner 13 個（Linux native feature 會有平台差異）
- `crates/helper-core`: 23 個（Safe Apply、NetworkManager、Hosts rollback、平台 state reader）
- `crates/storage`: 16 個（SQLite migration、trust 原子性、benchmark 評估）

### 2. 測試盲區與風險
- **平台與權限盲區**：多個涉及 socket bind 與 IPC 的 integration test 被標記為 `#[ignore]`；CI 已設定 Ubuntu、Windows、macOS 都執行該 suite，本次 Windows runner 的 Agent/Speed/Node suite 已通過，GitHub Ubuntu/macOS 實際結果仍未驗收。
- **無真實硬體測試**：AF_XDP zero-copy、DPDK native PMD、Windows RIO 目前在 CI 均僅是 `cargo check` 或語法/邊界 mock 測試，尚未連接到 Hardware Acceptance Runbook 提到的硬體驗證環境。
- **前端 E2E 測試缺席**：Tauri 2 桌面端與 loopback GUI 仍缺乏 Playwright / WebDriver 級別的 UI 操作自動化測試，列為後續工作。

---

## 二、安全模型與信任邊界分析

### 1. 優異設計
- **特權隔離 (Privilege Separation)**：GUI/CLI (無特權) → Agent (一般使用者) → Helper (Root/Admin)。Helper 協定為封閉 Enum Whitelist，沒有提供任意 shell、PowerShell 或動態腳本執行介面；Windows state reader 僅使用固定、唯讀的內嵌 PowerShell query。
- **嚴格身份驗證**：Unix Helper 向 kernel 讀取 socket peer UID/PID；Windows Helper 透過 Named Pipe client handle 提取 Token SID。
- **Node 控制面安全**：只允許 TLS 1.3，強制綁定 X.509 SPKI public key fingerprint。首次配對要求 out-of-band fingerprint 確認，換金鑰拒絕靜默覆寫。
- **私鑰防護**：私鑰只存在 OS Native Keyring (Keychain / Credential Manager / Secret Service)，SQLite 與設定檔中絕對不存私鑰。

### 2. 潛在安全與相容性風險
- **多語系 Windows state reader（已修正）**：讀取路徑改用固定 absolute PowerShell 與版本化 JSON schema；介面 alias 以獨立 argv 傳入，malformed/unknown schema、不可表示 routes 或 gateway、超量 DNS 與異常 MTU 均 fail closed。apply 仍保留固定 argv 的 `netsh.exe` builder。
- **Named Pipe 本機 ACL 驗證**：Windows Named Pipe 的 client impersonation 與 token 驗證已具備 FFI 程式碼，但尚缺少 Windows 環境下針對惡意本機處理程序偽造/劫持 Pipe 的防護驗證。

---

## 三、部署、打包與跨平台交付

### 1. 打包成熟度
- **Sidecar 集中管理**：透過 Tauri 2 bundle 將 `nettool` (CLI)、`nettool-agent`、`nettool-gui`、`nettool-dataplane` 一併打包進各平台安裝包（Linux AppImage/deb、macOS dmg/app、Windows msi）。
- **CI 自動解包驗證**：GitHub Actions 在 release 時會自動解開 deb、squashfs-root 與 MSI，驗證 4 個 sidecar 二進制檔與 License 完整無缺。

### 2. 交付痛點
- **程式碼簽章缺失**：macOS 尚未設定 Apple Developer ID + Notarization，Windows 尚未設定 Authenticode 憑證。一般使用者下載後可能觸發 Gatekeeper / SmartScreen 警告或政策限制。
- **特權 Helper 的安裝斷層**：桌面安裝包（MSI/DMG/Deb）只安裝了使用者層級的 App 與 sidecars，**沒有包含特權 Helper 的 Service 註冊**。網管如果需要修改 IP/DNS，仍必須另外以 root 執行 `install-helper.sh` 或手動設定 Service，UX 存在斷層。

---

## 四、效能、並發與熱路徑設計

### 1. 優異實作
- **熱路徑零配置 (Zero-Allocation)**：`PacketView` 使用 borrowed slices；計數器為 worker-local 整數；解析器（Ethernet/IP/TCP/UDP）只進行 bounds-checked 切片，不在 fast path 建立字串或 JSON。
- **記憶體邊界保護**：Flow table 限制 1,000,000 entries，使用 `try_reserve` 防止突發流量引發 OOM；AF_XDP UMEM 與 Ring buffer 具備明確的容量與 Frame bounds。

### 2. 並發檢查（D：不需架構重構）
- Agent runtime 仍採用 `Arc<Mutex<Storage>>` 與 `Arc<Mutex<SessionCoordinator>>`，但目前 source 顯示 socket/TLS/worker await 發生在 lock scope 外；本輪不導入 `RwLock` 或 Actor。以 deterministic lock-scope regression test/profiling 持續驗證，若日後出現實際 contention 再另立設計。

---

## 五、程式碼品質與可觀測性

### 1. 卓越的工程紀律
- **無任何殘留標記**：全專案 **0 個 `todo!`**、**0 個 `unimplemented!`**、**0 個 `FIXME/HACK`**。
- **零恐慌風險**：全專案 **0 個 `unwrap()`**；非測試程式碼中只有 2 處在 match enum 確定非空後的 `.expect()`。
- **Unsafe 邊界有明確範圍**：`dpdk-sys`、`dpdk-safe`、Linux AF_XDP、Windows RIO、Linux affinity 與 Windows `platform-auth` 等 native/FFI crate 以 crate-level lint 明確隔離 unsafe；其餘純 Rust workspace crate 維持 `#![forbid(unsafe_code)]`。

### 2. 結構化日誌（A：最小範圍已完成）
- Workspace 已加入 `tracing`/`tracing-subscriber`；Agent、Helper、GUI entrypoint 初始化 stderr formatter 與 `RUST_LOG`/`EnvFilter`。
- Agent action dispatch、Node control connection、Helper request handling 與 GUI action 帶有 request ID（可取得時）、operation/action、peer、success/error code、elapsed time；不記錄 payload、憑證、完整 fingerprint 或 desired state。
- CLI/API 正常 stdout contract 未改動；rolling file、syslog、Windows EventLog 與非長駐程序的全面改寫不在本輪。

---

## 綜合建議行動清單 (Action Items)

| 優先級 | 項目 | 具體建議 |
|:---:|---|---|
| **P0** | **引入 `tracing` 結構化日誌** | ✅ 已完成最小範圍：三個長駐 binary 使用 stderr formatter/EnvFilter 與關聯欄位；不加入外部 sink。 |
| **P1** | **解決 Windows 多語系 state reader** | 🟡 程式修正已完成、實機驗證部分完成：固定 PowerShell JSON query、typed schema、獨立 argv 與 fail-closed parser；netsh apply builder 保留。 |
| **P1** | **簽章與 Helper 安裝整合** | ⏸ 延後：缺少外部憑證與 Windows/macOS installer 安全決策；維持 prerelease gate，不假造正式安裝器。 |
| **P2** | **細粒度鎖優化** | ✅ 維持現況並完成 source-level lock scope review；不導入 `RwLock`/Actor，後續以 deterministic regression test 維護。 |
| **P2** | **補齊非 Linux 平台的整合測試** | 🟡 修正已完成：CI 已改為三平台執行現有 ignored Agent/Speed/Node loopback suite；本機 Windows runner 已通過，GitHub Ubuntu/macOS 尚待實際通過。 |

## 本次複核結論（2026-08-26）

| 項目 | 目前狀態 | 可核對證據 | 尚未完成或限制 |
|---|---|---|---|
| **A：結構化 tracing** | ✅ **已完成最小範圍** | `apps/agent/src/main.rs`、`apps/helper/src/main.rs`、`apps/gui/src/main.rs` 初始化 `EnvFilter`/stderr formatter；action、request、operation、peer、success/error code、elapsed 欄位已接入。 | 短命 CLI 的完整輸出結構化、file/syslog/EventLog sink 不在本輪。 |
| **B：Windows 多語系 state reader** | 🟡 **程式修正完成；實機驗證部分完成** | `crates/helper-core/src/platform_network_windows.rs` 使用固定 absolute PowerShell、無 BOM UTF-8 stdout、versioned JSON schema、獨立 alias argv；`platform_network.rs` 僅允許 exact fixed query，malformed/unknown schema、不可表示 route/gateway 等 fail closed；並有 query tampering、runner failure、interface mismatch 與非法 state fixture tests；`netsh.exe` apply builder 保留。 | 目前 Windows runner 的實際 PowerShell smoke test 受非系統管理員權限限制；Named Pipe ACL、真實 NIC rollback 與跨版本/多語系 Windows 仍待專用 runner。 |
| **C：簽章與 Helper 安裝整合** | ⏸ **延後** | 目前只有 unsigned/prerelease 與 allowlist staging 流程；沒有提交憑證或繞過平台安全政策。 | Apple Developer ID/Notarization、Windows Authenticode、macOS/Windows privileged service 註冊與正式 installer UX 仍需外部憑證及安全決策。 |
| **D：coordinator lock scope** | ✅ **已完成目前要求** | `crates/node/src/server.rs` 的 `with_coordinator` 在 guard 釋放後才進入 worker await，並有 `coordinator_lock_is_released_before_worker_await` deterministic regression test。 | 未導入 `RwLock`/Actor；尚未以長時間 production profiling 證明不存在其他 contention。 |
| **E：跨平台 loopback CI** | 🟡 **CI 修正完成；跨平台實際結果部分完成** | `.github/workflows/ci.yml` 的 Ubuntu/macOS/Windows matrix 都執行 Agent、Speed、Node ignored loopback suite；目前 Windows runner 的三組 suite 通過。 | GitHub Ubuntu/macOS job 實際結果、真實 100GbE、AF_XDP/DPDK/RIO hardware acceptance 仍待完成。 |

因此目前不能把整份稽核標示為「全部完成」：A、D 已完成；B、E 是「修正完成但外部驗收未全覆蓋」；C 是明確延期。文件中的分數與 production-ready 判定應維持此限制，不得以目前 Windows runner 的通過結果代替多平台或真實硬體證據。

# Network Engineering Toolkit 設計分析

> 分析範圍：24 crates + 6 apps，約 28,000+ 行 Rust 程式碼，版本 0.1.1。

---

## 整體評價

這個專案在安全邊界、fail-closed 原則與分層隔離上做得**非常扎實**。以下各節列出的問題屬於「值得關注但不影響核心正確性」的層次，不是否定專案整體設計。

---

## 🔴 重大結構問題

### 1. `agent/main.rs` — 4,020 行的上帝檔案

| 指標 | 數值 |
|---|---|
| 行數 | 4,020 |
| 佔整體比例 | ~14% |
| 責任 | IPC listener、Action dispatch、所有 40+ Action 的業務邏輯、Node control server、speed lifecycle、packet capture、dry-run、helpers、測試 |

這是整個專案最嚴重的結構性問題。Agent 是系統的 runtime authority，但它把**所有**業務邏輯集中在單一函式模組 `agent_runtime` 內，形成一個巨大的 God Module：

- 所有 Action 的 dispatch 與實作混在同一層
- 40+ 個 action 的 handler 函式全部平放在同一個 module
- `speed.run` 的完整 mTLS/session/scheduler lifecycle 直接寫在 agent 裡
- 測試也全部塞在底部

**不合邏輯之處**：專案花了大量心力把 `speed`、`node`、`packet`、`benchmark`、`storage` 拆成獨立 crate，每個都有清晰邊界。但 Agent——作為唯一把這些 crate 組合起來的消費者——卻完全沒有模組化。這與專案其他部分嚴謹的分層設計形成強烈矛盾。

> [!CAUTION]
> 在目前結構下，任何新增 Action 或修改現有 Action 都需要編輯這一個 4,000 行檔案，且所有 Action 的編譯時間耦合在一起。

### 2. `node/session.rs` — 2,185 行的過度集中

這個檔案承擔了：
- `SessionCoordinator` 的完整實作
- TCP/UDP/Bidirectional 的所有 Prepare/Start/Stop 變體
- Dynamic port binding 與 authorization tag 生成
- Resource Manager 互動
- Idempotent operation 追蹤
- Result persistence（含 SHA-256 checksum）
- 所有相關的 request/response 型別定義

> 2,185 行仍然可控，但作為專案中複雜度最高的「狀態機 + 資源管理 + 多協定分派」的組合，至少應將 TCP/UDP/Bidirectional 的 prepare 邏輯與 coordinator 核心分開。

---

## 🟡 過度設計嫌疑

### 3. 100G Certification / Benchmark 基礎建設的 ROI 問題

| 元件 | 行數 | 狀態 |
|---|---|---|
| `benchmark` crate | 1,443 | 骨架完整、evaluator/runner 已實作 |
| `benchmark_result` / `hardware_certification` SQLite tables | — | 已建立 |
| Gate A–J evaluator | ~400 | 已實作，含 thermal/reproducibility |
| Environment collector | 560 | Linux sysfs 已完整 |
| Storage certification persistence | ~200 | 已實作 |

**過度設計之處**：

- 專案版本為 **0.1.1**，尚未完成真實硬體 POC
- 但已建立了完整的 10-gate 認證流程（Gate A–J）、環境快照收集器（OS/kernel/CPU/NUMA/NIC/PCIe/firmware/driver/DPDK/MTU/queues/RSS/offloads）、平台組合 SHA-256 certification key、三級支援判定、SQLite 原子 persistence……
- 這些認證基礎建設在**沒有任何真實硬體 executor 可以產生測試資料**的情況下，只是空轉

文件中反覆強調「未完成真實硬體 POC 前，任何結果都不標示為 100G Certified」——這個防禦性聲明是正確的，但反過來說，既然還沒有硬體驗證，建立如此完整的認證框架屬於**提前投資過多**。

> [!NOTE]
> 如果這是刻意的 design-first 策略（先建規格再寫實作），則屬於合理的技術決策。但若 benchmark 規格日後改變，這些程式碼的改動成本不低。

### 4. RIO Backend — 完整的 FFI 骨架但 `is_backend_built()` 永遠 false

[`backend-rio`](file:///d:/temp/Network_Engineering_Toolkit/crates/backend-rio/src/lib.rs) 有 929 行，包含：
- `RioApi::discover` — `WSAIoctl` FFI
- `RegisteredBuffer` / `RioBufferSlice` — 完整 bounds-checked model
- Completion/Request queue pair — 含 ownership 與 backpressure 設計
- `RIORegisterBuffer`/`RIODeregisterBuffer` RAII

但 `is_backend_built()` 固定回傳 `false`，且 CHANGELOG 反覆說明「Windows runner 實機驗證仍待完成」。這 929 行在編譯檢查之外沒有真正的 runtime 價值。

### 5. 三平台 Helper Network Executor 的重複實作

| 平台 | 檔案 | 行數 | 狀態 |
|---|---|---|---|
| Linux | [`linux_network_manager.rs`](file:///d:/temp/Network_Engineering_Toolkit/crates/helper-core/src/linux_network_manager.rs) | 512 | 已接入 service |
| macOS/Windows | [`platform_network.rs`](file:///d:/temp/Network_Engineering_Toolkit/crates/helper-core/src/platform_network.rs) | 1,236 | macOS 已接入、Windows「仍待完成」 |

`platform_network.rs` 1,236 行中混合了：
- macOS `networksetup` command builder
- macOS state reader / parser
- Windows `netsh.exe` command builder
- Windows state reader / parser
- Generic `PlatformNetworkExecutor` trait + impl
- Snapshot / verify / restore 通用邏輯

**設計矛盾**：Linux 的 NetworkManager executor 已獨立成 `linux_network_manager.rs`（正確做法），但 macOS + Windows 卻擠在同一個檔案裡。且 Windows executor 在 CHANGELOG 中標註「仍待完成」，但已有完整的 command builder 和 parser。

---

## 🟡 設計矛盾與不一致

### 6. Domain Crate 的雙重角色

[`domain/src/lib.rs`](file:///d:/temp/Network_Engineering_Toolkit/crates/domain/src/lib.rs) 聲明自己是「與平台及傳輸層無關的核心領域模型」，但：
- [`model.rs`](file:///d:/temp/Network_Engineering_Toolkit/crates/domain/src/model.rs) 使用 `serde_json::Value` 作為 `Capability::parameters`、`SpeedSession::result`、`BenchmarkProfile::parameters` 的型別
- 一個自稱嚴格型別的 domain model 裡卻有三個 `Value` 欄位，這代表 domain 的型別安全邊界**在這些欄位上被放棄了**

> 對照同檔案中 `NetworkProfile` 的每個欄位都是強型別（含 `deny_unknown_fields`），`Value` 的使用顯得格格不入。

### 7. Storage Crate 直接依賴 Benchmark 的計算邏輯

[`storage/Cargo.toml`](file:///d:/temp/Network_Engineering_Toolkit/crates/storage/Cargo.toml) 依賴 `nettool-benchmark`，因為 Storage 在 transaction 內「重新執行 evaluator」：

```
storage → benchmark → error, serde, serde_json, sha2
```

**設計矛盾**：在 Clean Architecture 中，Storage（Infrastructure 層）不應依賴 Benchmark（Application/Domain 層的業務邏輯）。Storage 在寫入時重新執行 certification evaluation 是為了防止 caller 竄改結果，但更好的做法是讓 Application 層完成評估後，將**已簽名/已驗證**的結果交給 Storage 保存。

### 8. Action Crate 的 `ActionResult<T>` 泛型但 Wire Protocol 用 JSON bytes

- [`action/src/lib.rs`](file:///d:/temp/Network_Engineering_Toolkit/crates/action/src/lib.rs) 定義了 `ActionRequest<T>` 和 `ActionResult<T>` 泛型
- 但 Agent Protocol（Protobuf wire format）使用 `payload_json: Vec<u8>` 和 `data_json: Vec<u8>`
- Agent 內部的 dispatch 也是用 `serde_json::from_slice` / `serde_json::to_vec`

**不一致**：泛型的 `ActionRequest<T>` / `ActionResult<T>` 暗示型別安全的 Action pipeline，但實際 wire 和 runtime 全部走 JSON bytes。這兩層抽象同時存在但互不銜接。

### 9. `unsafe_code = "forbid"` vs DPDK/AF_XDP/RIO 的 FFI 需求

工作區設定 `unsafe_code = "forbid"`，但三個 backend crate 需要 FFI：

| Crate | Lint 覆寫 |
|---|---|
| `dpdk-sys` | `unsafe_code = "allow"` ✅ |
| `dpdk-safe` | `unsafe_code = "allow"` ✅ |
| `backend-af-xdp` | **未覆寫** — 但包含 syscall/mmap FFI |
| `backend-rio` | **未覆寫** — 但包含 Winsock RIO FFI |
| `platform-auth` | **未覆寫** — 但包含 Windows token FFI |

`backend-af-xdp` (1,559 行) 和 `backend-rio` (929 行) 有大量系統呼叫程式碼，如果它們真的需要 `unsafe`，lint 設定與實際需求矛盾。如果它們透過 safe wrapper 避免了 `unsafe`，那 DPDK 為什麼需要 `allow`？需要統一處理。

---

## 🟢 觀察到的良好設計（不需修改）

| 面向 | 做法 |
|---|---|
| **Fail-closed 原則** | 整個專案一致地在 capability/implementation/runtime 三層 gate 任何一層未通過時拒絕執行 |
| **Safe Apply 機制** | Helper-owned deadline + atomic snapshot + 重啟後自動 rollback |
| **Identity 設計** | 平台 native keyring、CSPRNG Node ID、bounded versioned envelope、certificate/key 一致性驗證 |
| **Wire Protocol** | 4-byte BE length + 1 MiB cap、Protobuf envelope、peer credential injection |
| **Packet Hot Path** | Zero-allocation `PacketView`、worker-local counters、bounded flow table |
| **Domain 模型** | `deny_unknown_fields`、typed schema、string_id macro 的 newtype pattern |
| **Error 模型** | Stable error codes、retryable flag、BTreeMap details |

---

## 總結與優先級建議

以下「目前狀態」依 2026-08-26 工作樹複核更新；原始問題與建議保留作為分析基線。

| 優先級 | 問題 | 建議 | 目前狀態（2026-08-26） |
|---|---|---|---|
| **P0** | Agent `main.rs` God Module | 拆分 Action handlers 為獨立模組；至少按 domain 分檔（speed、packet、profile、hosts、node、perf） | **已完成最低建議**：已拆出 9 個 `action_*` 模組；主檔仍保留 runtime wiring、control server 與測試，因此原始集中問題縮小但未完全消失。 |
| **P1** | Storage 依賴 Benchmark 業務邏輯 | 將 evaluation 責任移至 Application 層；Storage 只驗證 checksum | **已完成**：`nettool-benchmark` 僅保留於 Storage 的 dev-dependencies；production persistence 接受明確 certification state 並驗證 canonical checksum，不重新執行 evaluator。 |
| **P1** | `node/session.rs` 過長 | 至少將 TCP/UDP/Bidirectional prepare 各自獨立 | **已完成最低建議**：TCP、TCP bidirectional、UDP、UDP bidirectional prepare 已分別移至 `session_prepare_*` 模組；coordinator lifecycle 與 resource ownership 仍留在原檔。 |
| **P2** | Domain `Value` 欄位 | 替換為具體型別或 opaque validated wrapper | **已完成**：`Capability.parameters`、`SpeedSession.result` 與 `BenchmarkProfile.parameters` 改用只接受 JSON object 的 `ValidatedJson`。 |
| **P2** | macOS/Windows executor 混在一檔 | 參照 Linux 做法拆分 | **已完成**：macOS `networksetup` 與 Windows `netsh.exe` 的 reader/parser/builder 已移至各自平台模組，共用 snapshot、verify、restore executor 保留集中管理。 |
| **P3** | 100G Benchmark 提前投資 | 暫不需修改，但追蹤 ROI | **原本即不要求修改**：認證框架保留；尚無真實硬體 POC，仍不得把結果標示為 `100G Certified`。 |
| **P3** | RIO Backend 空轉 | 暫不需修改，但標記為 experimental | **原本即不要求修改**：`is_backend_built()` 維持 `false`，並以文件與 preflight 明確標示 experimental／Windows 實機驗收待完成。 |
| **Info** | `unsafe_code` lint 不一致 | 確認 AF_XDP/RIO/platform-auth 是否需要 `unsafe`，統一 lint 策略 | **已完成**：AF_XDP、RIO 與 platform-auth 已依 FFI 邊界明確允許 unsafe；其他 workspace crate 維持 `unsafe_code = "forbid"`。 |

### 驗證紀錄

- `gpt-5.6-sol` 已完成只讀獨立稽核，結果與目前 source 核對一致。
- `cargo test --workspace` 通過且無失敗；部分需要 loopback 權限的測試依環境限制被忽略。
- `cargo fmt --all -- --check` 與 `git diff --check` 通過。
- `README.md`、`docs/ARCHITECTURE.md`、`docs/CLI_REFERENCE.md` 與 `CHANGELOG.md` 已同步記錄模組拆分、Storage 邊界、`ValidatedJson` 與平台限制。

### 尚未驗證的外部條件

- 目前環境沒有 Windows runner，尚未驗證 RIO linker/API、Named Pipe SID 與 Windows `netsh` 實機行為。
- 目前沒有 Linux AF_XDP zero-copy NIC/driver 與 DPDK 硬體環境。
- 尚無真實 100GbE 硬體 benchmark evidence，因此上述修正不代表已完成 production-ready 或 `100G Certified` 驗收。

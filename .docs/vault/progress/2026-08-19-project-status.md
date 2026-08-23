# 專案開發進度（2026-08-19）

## 狀態摘要

專案仍在開發中，尚未完成全部規格，也不得宣稱達到 100GbE Certified。

最近一次完整且已確認的驗證基準仍為：一般測試 162 項通過、7 項 loopback 測試在預設受限環境忽略；該 7 項測試已另於允許 socket 的環境逐項執行並通過。該基準完成時，formatter、workspace Clippy、workspace tests，以及 dataplane/agent `ffi-api` Clippy 均通過。

2026-08-19 新增的 receiver scheduler 相關修改尚未重新編譯或測試，因此不納入上述已驗證基準。

## 已完成且已驗證的範圍

- Action Registry、Agent IPC、CLI adapter、SQLite metadata store 與穩定錯誤模型。
- Linux root Helper、peer credential authentication、Safe Apply、NetworkManager、PCI/vfio、Huge Pages 與 systemd 資產。
- NTCP bounded protocol、TLS 1.3 mutual authentication、Hello/capability/Prepare/Start/Stop/Ping/ResultQuery exchanges。
- Trusted Node certificate、SPKI fingerprint、Node ID 綁定及 SQLite v2 trust metadata migration。
- 平台安全 IdentityProvider；identity 存放於系統 credential store，沒有 plaintext fallback。
- TCP/UDP socket engines、session-scoped authorization、動態連接埠與同步開始屏障。
- Packet parser、flow/TCP analysis、capture、worker、PCAP/PCAPNG 與離線分析。
- 固定十階段 benchmark runner、A–J certification gates、結果 checksum 與 SQLite atomic persistence。
- DPDK preflight/planning、C shim、RAII safe layer，以及 feature-gated FFI 上層檢查。
- Agent opt-in TCP+mTLS control listener、共享 `SessionCoordinator`，以及 receiver-side control dispatcher。

完整已驗證能力與限制基準見 `2026-08-16-project-status.md`。

## 目前進行中的修改（尚未驗證）

### Node receiver ownership 與終態

- `crates/node/src/session.rs` 新增 `PreparedSocketReceiver`，統一表示已準備完成的 TCP 或 UDP receiver 與授權設定。
- 新增 `SessionCoordinator::begin_and_take_receiver`，預計將 scheduled state transition 與 receiver ownership 移交放在同一個 coordinator critical section，避免同一 session 重複啟動 worker。
- 新增 `SessionCoordinator::fail`，預計提供 Running/Finalizing/Failed 終態、versioned result JSON、SHA-256 checksum、冪等 result 保存與資源釋放。
- `crates/node/src/lib.rs` 已匯出 `PreparedSocketReceiver`。

### Agent receiver scheduler

- `apps/agent/src/main.rs` 已加入 Start response 後建立 wall-clock scheduler 的草稿。
- scheduler 預計在 `start_at` 到達後，從 coordinator 原子取得 TCP/UDP receiver，啟動 authorized receiver worker，並把成功或失敗結果寫回 coordinator。
- 已加入 wire session ID 解析與 receiver result JSON 建構輔助函式。

以上修改目前只確認已存在於工作目錄，尚未確認可編譯、Clippy 無警告、測試通過或 runtime 行為正確。

## 下一步

1. 檢查 Agent scheduler patch 是否完整，修正 dependency、ownership、錯誤處理與狀態轉移問題。
2. 為 begin-and-take、Completed/Failed 資源清理及重複 Start 補單元測試。
3. 增加 Agent TCP/UDP loopback 整合測試，驗證 mTLS control、scheduled Start、authorized worker 與 ResultQuery 的完整 receiver lifecycle。
4. 執行 formatter、workspace Clippy、workspace tests、`ffi-api` Clippy，以及需 socket 權限的 ignored tests。
5. 驗證通過後，再依外部行為影響更新 README、CLI_REFERENCE、ARCHITECTURE、SECURITY_MODEL 與 CHANGELOG。

## 仍未完成的主要規格

- Initiator 本機 data-plane bind、remote Prepare、雙方 barrier、worker、cancel/stop 與 SQLite result persistence 的單一 Agent runtime transaction。
- Remote sender、download 與 bidirectional scheduler。
- Raw DPDK TX orchestration、native DPDK/PMD/xstats 實機驗證與 100GbE POC policy。
- AF_XDP zero-copy/UMEM、Windows RIO、macOS/Windows privileged Helper 與 Windows Named Pipe transport。
- 安全的 trust runtime reload、正式 pairing UI、GUI、installer、跨平台 CI 與逐項規格驗收。

## 完成判定注意事項

- 新增程式碼存在不代表已驗證完成。
- Green unit tests 不代表完整規格完成。
- `ffi-api` 通過不代表 native DPDK 已連結或 PMD 已初始化。
- 理論 wire rate 不是實測 throughput。
- 只有真實環境證據、正式 POC policy 與全部 certification gates 通過時，才可標示 Certified100G。

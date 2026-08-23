# 專案開發進度（2026-08-16）

## 目前狀態

專案仍在開發中，尚未完成全部規格，也尚未達到 100GbE Certified。現有 Rust workspace 可通過 formatter、Clippy 與全 workspace 測試；最近一次完整驗證為 162 項通過、7 項因 loopback socket 權限而忽略、0 項失敗；全部 7 項 Agent mTLS、Node dispatcher/lifecycle 與 TCP/UDP 實際傳輸整合測試另在允許 socket 的環境明確執行並通過。

驗證命令：

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --quiet
cargo clippy -p nettool-dataplane --bin nettool-dataplane --features ffi-api -- -D warnings
cargo clippy -p nettool-agent --bin nettool-agent --features ffi-api -- -D warnings
```

## 已完成

### 核心控制面

- Action Registry、穩定錯誤模型、Protobuf Agent IPC 與 CLI adapter。
- macOS/Linux Unix domain socket Agent transport 與 SQLite metadata store。
- Operation ID、request correlation 與嚴格 action payload validation。
- `perf topology`、`perf backend`、`perf profile list`、`perf benchmark` 與 `speed run` CLI 契約。

### Helper 與系統操作

- Linux root Helper、kernel peer credential authentication 與 whitelist-only protocol。
- Safe Apply、Hosts、NetworkManager Ethernet、PCI/vfio 與 Huge Pages executors。
- systemd 安裝資產。

### Node protocol 與 Speed Engine

- NTCP bounded framing、Protobuf messages、version/capability negotiation 與 TLS 1.3 mutual authentication。
- Dynamic TCP/UDP data ports、session-scoped authorization、resource reservation 與 synchronized start barrier。
- 實際多-stream TCP 與 UDP socket TX/RX compatibility engine。
- UDP session/stream/sequence header、fixed-rate batch pacing、loss、duplicate、out-of-order 與 jitter accounting。
- `speed.run` 支援 protocol、backend、direction、duration、warmup、cooldown、streams、rate、frame size、auto-tune、latency-under-load、CPU affinity 與 NUMA 的 CLI normalization。
- 共用 `SpeedRunRequest` 採 `deny_unknown_fields`，並驗證 protocol/backend 與資源組合。
- Trusted Node 依 stable ID 或精確名稱解析；未知、撤銷或名稱歧義不啟動 session。
- Node control client 已實作：
  - TCP/TLS/Hello 各階段 bounded timeout。
  - X.509 `SubjectPublicKeyInfo` public-key fingerprint 與 Hello Node ID 雙重綁定。
  - CSPRNG 128-bit request ID 與 typed response correlation。
  - Capability、Prepare、Start、Stop 與 Ping exchanges。
- Speed session planner 已把 TCP、UDP、Raw、bidirectional、DPDK、AF_XDP、RIO、jumbo 與 latency-under-load 映射到固定 capability IDs，驗證 remote version/availability 後才產生 `PrepareTest`。
- UDP planner 強制先取得 dynamic source port，避免 remote authorization 接受零或任意來源 port。
- Client-side session orchestrator 已串接 capability query、planner、Prepare、Start 與 Stop，並嚴格驗證 dynamic data port、authorization tag、session correlation 與遠端狀態。
- Session ID 使用平台 CSPRNG 產生且拒絕全零值。
- 平台安全 `IdentityProvider` 已透過 macOS Keychain、Windows Credential Manager 或 Linux Secret Service 保存首次產生的 Node ID、PKCS#8 private key 與 certificate；無 plaintext fallback。
- Identity credential 採 bounded/versioned envelope，載入時驗證 X.509、PKCS#8 與 certificate/private-key 一致性；Agent 在開啟 IPC listener 前 fail closed 載入。
- SQLite v2 trust metadata 已保存 paired certificate DER、TLS server name 與完整 control socket；certificate/fingerprint 不符或未確認的 identity change 會拒絕。
- Agent-owned `speed.run` runtime 已完成真實 mTLS、Hello、capability exchange 與 planner preflight，並由 loopback integration test 驗證；data-plane executor 未就緒時不送 remote Prepare。
- Speed session persistence 已具備 immutable request、preparing/running/terminal 原子狀態轉移、完全相同內容的冪等 retry、ID reuse conflict 與 result JSON 保存。
- Prepare endpoint contract 已能分別表示 initiator/remote sender source 與 receiver ports，planner/orchestrator 依 direction 驗證 upload、download 與 bidirectional pre-bind。
- TCP 每條 stream 已在 payload 前驗證 session/唯一 stream/tag；UDP 已在 DATA 前執行 endpoint/session/stream/tag AUTH bootstrap，未授權資料不進入量測。
- Protocol minor 1 已新增 typed `TestResultRequest`；Node 正常完成會驗證 versioned JSON、進入 Finalizing、冪等釋放資源、保存 SHA-256 後轉 Completed，client 驗證 session/checksum 並可重試查詢。
- Trusted control server dispatcher 已具備 Hello-first/identity/version/request gates，映射 Capability、receiver Prepare、scheduled Start、Stop、Ping 與 ResultQuery，並跨 connections 共用 Agent-owned coordinator。
- Agent 已能透過 explicit opt-in `NETTOOL_CONTROL_LISTEN` 啟動 TCP+mTLS control listener，從 trusted certificates 建立 roots，拒絕 fingerprint ambiguity，並在 TLS 後以 SPKI fingerprint 綁定 peer record。

### Packet Engine

- Borrowed `PacketView`、worker-local counters 與分類式 drop accounting。
- Bounds-checked Ethernet、VLAN/QinQ、ARP、IPv4、IPv6 extension、ICMP、TCP 與 UDP parser。
- Canonical bidirectional flow key、stable sharding、bounded flow table 與 idle/LRU-like eviction。
- TCP retransmission、out-of-order、duplicate ACK 與 confidence classification。
- Run-to-completion `PacketWorker`、bounded non-blocking capture branch 與 sampled/full coverage。
- PCAP/PCAPNG streaming reader、writer、rotation、storage guard 與離線 analyze CLI。
- Raw generator profile 可驗證 Ethernet size、IP family/ranges、TCP/UDP ports、flow cardinality 與 packet rate。
- 依 frame + preamble/SFD + IFG 計算理論 wire rate；此數值不會冒充實測。

### DPDK

- Linux capability/environment probe 與 certification-aware preflight。
- 同 NUMA queue/core planner、一 RX queue 對一 worker ownership 與動態 mbuf pool sizing。
- `dpdk-sys` 集中 C ABI 與 inline API shim。
- `dpdk-safe` 提供 EAL、mempool、port、RX/TX queue RAII handles。
- RX 使用 callback-scoped borrowed mbuf view；burst guard 在正常、錯誤及 panic unwind 時回收 mbuf。
- RX/TX queue ownership registry 防止同一 queue 同時被多個 worker 取得。
- Bulk template TX 從預配置 mempool allocation，未送出的 mbuf 立即回收。
- `ffi-api` 可在沒有 DPDK SDK 時檢查 Rust FFI 上層；`native-dpdk` 必須由 `pkg-config libdpdk` 找到 SDK 才能建置。

### Benchmark 與認證

- 固定十階段 Benchmark runner、profile registry、phase-boundary cancellation 與 recoverable/degraded/fatal issue semantics。
- 完整環境快照、packet/flow matrix、RX/TX baseline、thermal condition 與 reproducibility evidence。
- A–J certification gates 與 Functional、Validated、Certified100G 分級。
- 沒有經 POC 驗證的 policy 時最高只能為 Validated，不使用推測門檻。
- SQLite transaction 內重新評估、canonical JSON/checksum 與 certification atomic persistence。

### 文件

- 已依影響更新 `README.md`、`docs/CLI_REFERENCE.md`、`docs/ARCHITECTURE.md`、`docs/SECURITY_MODEL.md`、協定文件、ADR 與 `CHANGELOG.md`。

## 尚未完成與限制

- Agent runtime 已持有平台 identity 並建立 per-session Node control connection，但尚未管理完成 Prepare 後的完整 data-plane worker/session lifecycle。
- 尚未把本機 data-plane bind、已完成的 remote control orchestration、雙方 barrier、實際 TCP/UDP/Raw worker、stop/cancel 與 result persistence 串成單一可執行 Agent session。
- Authenticated socket worker 已具備，但 Agent/Node 尚未把雙端 endpoint bind、Prepare、Start barrier、worker、Stop cleanup 與 persistence 串成單一 runtime transaction。
- Receiver-side dispatcher 已具備；remote sender、bidirectional scheduler 與 Agent listener/runtime attachment 尚未完成，未支援方向會在配置資源前明確拒絕。
- Agent listener/runtime attachment 已完成；remote sender、bidirectional scheduler 與 receiver worker scheduler 尚未完成，未支援方向會在配置資源前明確拒絕。
- Trust roots 是 Agent 啟動快照；pairing/revocation 更新目前需重啟，正式 pairing UI 尚未實作安全的 runtime reload。
- 本機沒有可由 `pkg-config` 找到的 `libdpdk` SDK，也沒有 vfio/hugepage/100GbE 測試設備，因此 native C shim、PMD 與 line-rate POC 尚未實機驗證。
- AF_XDP zero-copy/UMEM worker、Windows RIO 與 macOS optimized native backend 尚未完成。
- macOS/Windows privileged Helper、Windows Named Pipe Agent transport 尚未完成。
- GUI、正式 installer/packaging、跨平台 CI 與最終需求逐項驗收尚未完成。
- 100GbE certification policy 必須來自真實 POC；目前不得宣稱 Certified100G。

## 下一步優先順序

1. 在本機先動態 bind 完整 data-plane endpoint，再執行 remote prepare、resource reservation、同步 start、worker lifecycle、cancel 與 result persistence。
2. 完成 raw DPDK TX orchestration、DPDK hardware/xstats evidence 與 benchmark phase executor。
3. 補齊 AF_XDP、RIO、macOS/Windows Helper 與 transport。
4. 完成首次 pairing UI、GUI、installer、跨平台驗證與全規格 completion audit。

## 不可誤解的完成條件

- Green unit tests 只證明目前覆蓋的行為，不代表完整規格完成。
- `ffi-api` 成功不代表 native DPDK 已連結。
- 找到 DPDK runtime 不代表 PMD 初始化成功或通過 100GbE 認證。
- 理論 wire-rate 不是實測 throughput。
- 只有完整環境證據、正式 POC policy 與 A–J gates 全部通過時，才可標示 Certified100G。

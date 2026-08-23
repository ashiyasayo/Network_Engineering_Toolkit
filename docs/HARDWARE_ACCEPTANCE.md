# Hardware Acceptance Runbook

本文件是規格要求的實機驗收入口。Host unit tests、FFI syntax check 或 capability discovery 不足以把 backend 標示為可執行或 100GbE Certified；每一個 gate 都必須保存原始 command output、環境 snapshot、NIC/driver/firmware 資訊與結果 checksum。

## 共通前置

- 使用乾淨的 Linux x86_64 runner、Windows x64 runner，以及兩端相同版本的 release binary。
- 準備獨立於 management NIC 的測試 NIC；記錄 PCI address、driver、firmware、link speed、MTU、RSS、RX/TX queue 與 NUMA node。
- 保存 `cargo test --workspace -- --ignored`、`cargo clippy --workspace --all-targets -- -D warnings` 與 release binary checksum；dynamic socket test 必須允許 local bind。
- 任何 gate 失敗都保留 fail-closed 結果，不以 synthetic throughput 或 capability JSON 代替 evidence。

## Linux AF_XDP

1. 以 `nettool-dataplane probe --output json` 保存 kernel、BPF filesystem、NIC、queue、driver 與 zero-copy evidence。
2. 確認測試 NIC 不在 default route；`perf.backend` 的 AF_XDP `implementation_available`、interface/queue gate 與 `af_xdp_zero_copy_capable` 必須全部通過。
3. 使用實際 zero-copy driver 啟動 AF_XDP RX/TX，保存 XDP program/link、XSKMAP、UMEM frame、RX/TX/completion counters 與 kernel drop counters。
4. 執行 small packet、jumbo、多 queue、multi-buffer 與 sustained traffic；比較 NIC、ring、capture、analyzer、sequence loss 分類，不得只記錄 application counter。

Pass 條件：無未解釋的 NIC/ring drop、zero-copy evidence 完整、RX/TX queue ownership 與 CPU/NUMA mapping 一致，且所有結果可由保存的 session/result checksum 重現。

## Linux DPDK

1. 以 `native-dpdk` feature 建置，記錄 DPDK SDK、EAL、VFIO、hugepage、PCI binding、RSS 與 management NIC protection evidence。
2. 執行 bounded `rx`、`tx`、`capture` 命令，保存 `rte_eth_stats`、`rte_eth_xstats`、queue plan、CPU affinity、mempool sizing 與 PCAPNG metadata。
3. 依規格 frame/flow matrix 執行 small/standard/jumbo、high-cardinality、bidirectional 與 sustained phases；任何 PMD error、mempool exhaustion、capture drop 或 thermal excursion 都使 certification gate 失敗或降級。

Pass 條件：EAL/PMD 初始化成功、queue/worker/NUMA invariant 通過、hardware counters 與 capture evidence 一致，並完成 reproducibility/thermal record。

## Windows RIO 與 Helper

1. 在 Windows runner 以 release build 連結 Winsock RIO，驗證 `WSAIoctl` extension discovery、registered buffer lifetime、request/completion queue、`RIOReceive`/`RIOSend`/dequeue 與 linker/API 行為。
2. 以實際 Named Pipe server 驗證 token/SID exact allowlist、bounded framing、Safe Apply deadline、rollback 與 Hosts atomic replacement。
3. 保存 Windows build、OS version、NIC driver/firmware、ACL/SID、RIO completion counters 與 failure injection 結果。

Pass 條件：未授權 SID、越界 buffer、completion backpressure、deadline timeout 與 rollback 都 fail closed；任何未通過項目不得標示 RIO available 或 production-ready。

## 100GbE certification

- 依 `crates/benchmark` 固定 A–J phase order 執行 environment、NIC/RX/TX、bidirectional、frame/flow matrix、duration、analysis 與 result phases。
- 每一 phase 保存 bounded evidence（不含封包 payload/credential）、monotonic timing、drop classification、thermal condition、reproducibility dispersion 與 environment snapshot checksum。
- 只有所有 policy gates、small-packet worst case、sustained duration、capture storage/drop、NUMA/affinity、reproducibility 與 thermal checks 全部通過，才能把結果標示為 `100G Certified`；否則只能標示 `Functional` 或 `Validated`。

目前本機 macOS ARM 環境沒有 Linux/Windows runner、DPDK SDK 或 100GbE NIC，因此上述段落是待執行驗收，不是已完成 certification 的宣告。

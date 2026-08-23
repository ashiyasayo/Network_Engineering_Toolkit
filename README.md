# Network Engineering Toolkit

規格驅動的跨平台網路設定、測速與封包分析工具。目前包含 Repository Bootstrap、P0 唯讀環境探測，以及可執行的 Agent/CLI 控制平面基線。

Node control client 已具備 TCP+mTLS connect timeout、paired public-key fingerprint、Hello Node ID/version binding、CSPRNG request correlation，以及 capability/prepare/start/stop/heartbeat typed exchange。Client-side Speed session orchestration 會查詢 runtime capabilities、驗證計畫、執行 Prepare，並檢查 dynamic data port、authorization tag、Start/Stop session correlation 與穩定狀態。Agent 啟動時會從 macOS Keychain、Windows Credential Manager 或 Linux Secret Service 載入本機 identity；首次執行才產生並安全保存 Node ID、PKCS#8 private key 與 certificate，平台 store 不可用時不會退回明文檔案或 SQLite。

Trusted Node metadata 現在保存非秘密的 paired certificate DER、TLS server name 與完整 control socket。`speed.run` 的 socket upload、TCP/UDP download 與 TCP/UDP bidirectional 路徑已由 Agent-owned runtime 建立 mutual TLS、驗證 chain/name/fingerprint/Hello identity、交換 capability、雙端 endpoint Prepare、共同 scheduled Start、並行 authorized sender/receiver 與 ResultQuery；raw 與 accelerated executor 仍會明確拒絕，不會建立未執行的假結果。Socket worker 已支援 session-scoped authorization：TCP 每條 stream 在 payload 前驗證 session/stream/tag，UDP 在 DATA 前完成 endpoint/session/stream/tag AUTH bootstrap。

`nettool speed cancel <session-id>` 會從本機 SQLite session 找到 trusted remote，透過 mTLS 送出 idempotent StopTest，只有收到遠端 `CANCELED` 才保存本機 canceled state；Agent IPC client 使用 per-connection task，因此取消不會被長時間測試阻塞。

Trusted control server dispatcher 已實作 Hello-first、authenticated peer Node ID、negotiated minor與 nonzero request ID gates，並映射 Capability、socket receiver/sender/bidirectional Prepare、scheduled Start、Stop 與 ResultQuery。Coordinator 由 Agent runtime 共享，control reconnect 後仍能重取 session/result；scheduler 會在 `start_at` 到達時原子取得唯一 endpoint 或並行 sender/receiver worker，不會錯配成 receiver。

設定 `NETTOOL_CONTROL_LISTEN=<IP>:<port>` 才會啟動 Agent 的 Node TCP+mTLS listener；未設定時預設不開放網路 port。Listener 對每條新 TLS connection 從最新 trusted registry 建立 client certificate roots，拒絕同一 fingerprint 對應多個 Node IDs；每條 connection 再以 presented SPKI fingerprint 唯一解析 peer。更新 pairing/trust records 後，新連線立即使用最新 trust 狀態，既有連線不會被強制中斷。

Speed session planner 已把 CLI payload、固定 capability registry 與 `PrepareTest` wire contract 串接；在 remote 缺少 protocol/backend/bidirectional/jumbo/latency 能力時會於 resource prepare 前失敗，UDP 則強制先取得 dynamic source port。

```bash
cargo run -p nettool-dataplane -- probe
cargo run -p nettool-dataplane -- probe --output json
cargo run -p nettool-dataplane -- analyze --input capture.pcapng --output json
```

啟動 Agent 後，可由 CLI 經 length-prefixed Protobuf 本機 IPC 呼叫同一套 Action API：

```bash
cargo run -p nettool-agent
cargo run -p nettool -- health --output json
cargo run -p nettool -- profile list
cargo run -p nettool -- dataplane probe
cargo run -p nettool-gui
```

任何 CLI action 都可在命令列任意位置加入全域 `--dry-run`；Agent 會回傳包含 action、權限、冪等性與 payload SHA-256 的 bounded plan，不執行副作用。需要特權的 action 仍會交由 Helper 做同樣的驗證式 dry-run。

Linux 提供完整 P0 sysfs/procfs 探測；macOS 以固定絕對路徑 `ifconfig -l`、Windows 以固定 PowerShell `Get-NetAdapter` 唯讀列出介面，NUMA/Huge Page 等平台特有欄位仍明確保留為 unknown。DPDK capability 目前代表找到 runtime library，不代表硬體已通過初始化或 100G 認證；AF_XDP 基本 kernel/BPF surface 與 zero-copy driver evidence 也分開回報，未驗證 zero-copy 時不會誤標示可用。

DPDK 啟動規劃已具備同 NUMA queue/core mapping、one-queue/one-worker ownership 與依 descriptors、burst、pipeline、capture、safety margin 計算的動態 mbuf pool sizing。以 `native-dpdk` feature 建置且系統可由 `pkg-config` 找到 `libdpdk` 時，`nettool-dataplane rx` 會經集中式 C shim、RAII handles 與 borrowed mbuf view 啟動實際 EAL/PMD RX worker；`capture` 命令另以 bounded queue 與旋轉 PCAPNG writer 保存指定 burst，並回傳 `rte_eth_stats` 與 `rte_eth_xstats` hardware evidence。預設 build 不會宣稱 DPDK 可用。

macOS/Linux Agent 使用權限為 `0600` 的 Unix domain socket；Windows Agent IPC 使用 Named Pipe 與相同 bounded framing。`nettool-gui` 現提供 loopback-only localhost Dashboard，透過既有 Agent Action API 查詢資料；Linux 已提供 `nettool-helper` root service、Unix peer authentication、Safe Apply、Hosts、NetworkManager Ethernet、PCI driver 與 Huge Page executors，以及 systemd 安裝資產；macOS Unix helper 已接上 `networksetup` platform executor 與同一 Safe Apply/IPC 流程，Windows helper 已接上 Named Pipe token SID allowlist、`netsh` executor 與 Safe Apply。原生桌面殼層/正式 installer、Windows 實機 ACL 驗收仍在後續里程碑。

Packet core 已提供零配置、bounds-checked 的 L2/L3/L4 parser、雙向 canonical flow sharding、IPv4/IPv6/ICMP/Other protocol counters、可組合的 IP/port/protocol capture filter 與具 capture-drop confidence 的 TCP retransmission classification。這些是 dataplane 可掛接的核心能力；尚未宣稱已具備真實 DPDK line-rate capture 或 100GbE 認證。

Raw generator core 會驗證 Ethernet size、IPv4/IPv6、TCP/UDP、IP/port ranges、flow cardinality 與 packet rate，並依 preamble/SFD/IFG 計算理論 wire rate；native DPDK dataplane 另提供 bounded `tx` template burst worker，先完成 preflight 並回傳 PMD hardware counters，未連結 SDK 時明確失敗。`nettool speed run <node>` 現已具備完整 option normalization、共用 payload validation、trusted-node preflight，以及 socket upload、TCP/UDP download 與 bidirectional 的實際 control/data-plane lifecycle；accelerated speed orchestration 仍待掛接，未掛入時明確失敗而不建立假結果。

Capture core 另以 non-blocking bounded queue 隔離 RX 與檔案 I/O，支援 PCAPNG、PCAP、四種截取模式、protocol/IP/port filter 與檔案 rotation。Agent 的 `packet capture start/stop` 會持久化 session 並管理 dataplane worker；Full capture 只有在目標 storage 的實測吞吐與容量都足夠時才可標示 lossless certified。

Packet Worker 已把 backend burst ownership、獨立 capture、parser、bounded flows 與 TCP analyzer 串成 run-to-completion 路徑；native DPDK capture 已可將 bounded RX burst 寫入旋轉 PCAPNG，但仍待 AF_XDP backend 掛接與 line-rate POC。

Linux `packet connections` 讀取 `/proc/net/tcp*` 與 `/proc/net/udp*` 提供 endpoint/state inventory；無法由 procfs 證明的 process、PID 與 traffic 欄位明確回傳 `null`，不推測資料。

離線 backend 可串流讀取 Ethernet PCAP 與 PCAPNG，保留 nanosecond timestamp 與 PCAPNG queue metadata，並以 16 MiB block 上限及 snaplen/wire-length 檢查拒絕損壞輸入。`analyze` 可使用 `--sample-one-in <n>` 降低分析量；輸出會明確標示 sampled coverage，不能解讀為完整封包分析。

Socket Speed Engine 已具備實際多 stream TCP 與 UDP TX/RX compatibility 路徑。UDP sender 預先配置 payload，以 monotonic cumulative budget 進行 fixed-rate batch pacing；receiver 驗證來源 IP+port、session、stream、header 與 payload length，並回報 sequence loss、duplicate、out-of-order、jitter 與無效/未授權 datagram。這些 socket 結果屬功能性測速，不能標示為 100GbE wire-rate certified。

`nettool speed history` 可查詢 SQLite 中的非敏感測速 session 摘要與終態，完整設定與結果 payload 不會由 history endpoint 洩漏。`speed.run` 使用 AF_XDP/RIO 時會先做平台與 implementation preflight，未通過時不建立遠端 session。
可加上 `--format csv` 匯出 `session_id,remote_node,protocol,backend,direction,started_at,completed_at,state` 欄位；預設仍回傳 JSON/人類可讀輸出。

Node coordinator 已同時管理 TCP listener 與 UDP socket 的 dynamic ports、exclusive Resource Manager claims、256-bit authorization tag、雙端 barrier、`start_at` 及 idempotent prepare/start/stop；UDP prepared endpoint 可直接交給 Speed Engine 執行，不建立控制平面外的旁路。

Benchmark core 已實作完整環境快照、packet/flow matrix validation、RX/TX baseline evidence、A–J certification gates、thermal condition、reproducibility dispersion、平台組合 SHA-256 key 與 Functional/Validated/100G Certified 分級。尚未提供經真實 100GbE POC 固定的門檻，因此目前任何結果都不得宣稱 100G Certified。

可使用 `nettool perf topology` 與 `nettool perf backend` 經 Agent 查詢拓撲及 backend 狀態。Accelerated backend 的 platform/runtime capability 與 implementation availability 分開輸出；DPDK/RIO 只有在 native feature 已連結且 runtime 可探測時才標示 available，Linux AF_XDP implementation 也仍須通過 kernel/interface/zero-copy preflight，不會把 capability 誤報成可執行。
Linux native DPDK RX/TX worker 會在 calling thread 套用 bounded CPU affinity；若作業系統拒絕 affinity syscall，worker 會 fail-closed，不會把未 pin 的執行結果誤標為硬體驗證。

`nettool perf profile list` 可查看 benchmark plans；`nettool perf benchmark --profile <id>` 已具備穩定 Action/CLI contract。由於 accelerated hardware phase executor 尚未連結，目前命令會明確失敗，不生成模擬數字。Benchmark runner 本身已支援固定 phase order、monotonic timing、1 MiB evidence bound、recoverable/degraded/fatal issue 與 phase-boundary cancellation。

主要規格、實作模組、測試與實機驗收狀態請參考 [規格追蹤矩陣](docs/REQUIREMENT_TRACEABILITY.md)。

Linux/Windows backend 與 100GbE 實機驗收請依 [Hardware Acceptance Runbook](docs/HARDWARE_ACCEPTANCE.md) 執行；文件中的 hardware gate 證據未取得前，不標示 backend production-ready 或 `100G Certified`。

Network Profile metadata 可透過 `profile list/show/create/edit/delete/export/import` 經 Agent/SQLite 持久化，configuration 以 checksum 驗證；`profile apply/confirm/rollback` 已經由 authenticated Helper Safe Apply client 執行，平台 adapter 仍依作業系統逐步補齊。

快速 IP/DNS 操作 `ip set`、`ip dhcp` 與 `dns set` 也經由相同 Helper Safe Apply 路徑，不直接由 CLI 修改系統網路。

`node list` 與 `node status` 可查詢 Agent 目前信任的 Node inventory。

首次配對使用 `nettool node pair --id <id> --name <name> --address <ip:port> --server-name <name> --fingerprint <fp> --certificate <file> --confirm-fingerprint`，或在 localhost GUI 的 Node 頁面填寫相同欄位並勾選 out-of-band fingerprint verification；CLI/GUI 都只透過 typed `node.pair` action，Storage 會驗證 fingerprint、憑證與欄位格式。既有 Node ID 的憑證變更必須額外使用 identity replacement confirmation。

撤銷配對使用 `nettool node revoke <id-or-name>`；撤銷只停用 trust，不刪除歷史 metadata，且會立即影響後續新 control connections。

`packet analyze --input <capture>` 可透過 Agent 執行既有 bounded PCAP/PCAPNG analyzer，支援明確的 sampling coverage。

Linux 上的 `packet stats [--interface <id>]` 讀取 kernel sysfs counters；無法取得的欄位會回報錯誤，不填入推測值。

Hosts managed section 可透過 `hosts list/replace/add/remove/enable/disable` 操作，並可用 `hosts backup/restore` 管理 Helper-owned 備份；增刪與啟停會先由 Helper 讀取指定 section，再以原子 replace 寫回，停用項目以受控 marker 保留，區塊外的使用者內容保持不變。

介面查詢提供 `interface list/show/refresh`，統一回傳 probe 的 NIC stable metadata、driver、link speed、queue 與 NUMA 資訊。

Profile apply/confirm/rollback 與 Hosts list/replace 已透過 `NETTOOL_HELPER_SOCKET` 連接 authenticated privileged Helper，使用 bounded framing、Safe Apply deadline 與 kernel peer authorization；未設定 Helper socket 時會 fail closed。

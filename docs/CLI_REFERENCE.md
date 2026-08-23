# CLI Reference

## GUI

啟動 loopback-only Dashboard：

```bash
cargo run -p nettool-gui
```

預設網址為 `http://127.0.0.1:8765`，可用 `NETTOOL_GUI_LISTEN=127.0.0.1:<port>` 變更連接埠。GUI 不直接執行網路或特權操作，所有查詢與變更均經 Agent Action API；Agent 未啟動時會回傳明確的 unavailable 錯誤。Node 頁面提供首次 pairing 表單，可選取 DER certificate、勾選 out-of-band fingerprint confirmation，並明確確認 identity replacement；欄位仍由 Agent `node.pair` action 做最終驗證。

Dashboard 的 Action Console 只列出 `ActionRegistry` 已註冊項目；payload 必須是 JSON，未知 action（包含任意 shell/command）會在 Agent 連線前拒絕。

## `nettool health`

透過 Agent IPC 取得 runtime 與 database migration 健康狀態。

## `nettool profile list`

列出 SQLite 內的 network profiles；CLI 不直接開啟資料庫。

## `nettool dataplane probe`

透過 Agent 執行資料平面環境探測。上述命令皆可附加 `--output json`。

## `nettool speed run`

```bash
nettool speed run <node> [--protocol tcp|udp|raw] [--backend socket|native|dpdk|af_xdp|rio] [--direction upload|download|bidirectional] [--duration 10s] [--warmup 1s] [--cooldown 1s] [--streams auto|<n>] [--rate 100G] [--frame-size 64] [--auto-tune] [--latency-under-load] [--cpus auto|4-19] [--numa auto|1] [--output json]
```

時間單位接受 `ms`、`s`、`m`，rate 接受十進位 `K`、`M`、`G`、`T`。Raw Ethernet 必須使用 DPDK 且 frame size 至少 64 bytes；CPU affinity 只允許 accelerated backend。Agent 會先以 stable ID 或精確名稱解析仍為 trusted 且具有 paired certificate、TLS server name 與 control socket 的 Node，未配對回傳 `NODE.NOT_PAIRED`。socket upload、TCP/UDP download 與 TCP/UDP bidirectional 會實際完成 mutual TLS、Hello、capability、雙端 endpoint Prepare、共同 scheduled Start、並行 authorized sender/receiver 與 ResultQuery；raw 或未附著的 accelerated executor 會回報 `ACTION.UNSUPPORTED`，不產生虛假結果或遺留 remote reservation。

目前 socket executor 不支援 `--auto-tune`、`--latency-under-load` 或 socket backend 的 `--numa`；這些選項會明確回報 unsupported/invalid，不會被靜默忽略。

Node control server 預設不監聽網路。設定 Agent 環境變數 `NETTOOL_CONTROL_LISTEN=<IP>:<port>` 後才啟動 mutual TLS listener；值必須是明確的 IP socket address，例如 `192.0.2.10:49152` 或 `[2001:db8::10]:49152`。每條新連線都會從最新 trusted Node registry 建立 verifier；空 registry 的連線會被拒絕，但完成 pairing 後不需重啟 Agent。

## `nettool speed cancel`

```bash
nettool speed cancel <session-id>
```

Agent 會依 SQLite session record 找到 paired remote Node，透過 mutual TLS 送出 idempotent `StopTest`，確認遠端回覆 `CANCELED` 後將本機 session 保存為 canceled。取消未知、未配對或已完成的 session 會回傳明確錯誤。

## `nettool perf topology`

透過 Agent 顯示 CPU logical count、NUMA、Huge Pages，以及每張 NIC 的 PCI address、link speed、NUMA node、RX/TX queues 與 driver。無法驗證的欄位保留 `null` 並附 warning，不填入推測值。

## `nettool perf backend`

列出 `pcap`、`af_xdp`、`dpdk` 與 `rio` 的 availability。`available` 必須同時符合 implementation 與對應 platform/runtime gate；kernel/platform/runtime capability 以不同欄位呈現，不能把找到 DPDK runtime 或 AF_XDP kernel API 誤解為 zero-copy preflight 已通過。

兩個命令皆支援 `--output json`。

## `nettool perf profile list`

列出內建 benchmark plans 與 `certification_policy_configured`。`100g-cert` 目前包含完整 packet/flow/duration plan，但在真實硬體 POC 固定門檻前 policy 為 false。

## `nettool perf benchmark --profile <id>`

透過 Agent 驗證 profile 並啟動 benchmark orchestration。CLI 會把非冪等 request ID 同時作 operation ID。現階段 accelerated hardware phase executor 尚未連結，因此有效 profile 會明確回傳 `DATAPLANE.BACKEND_NOT_BUILT`，不產生模擬 throughput 或虛假成功結果。

所有 CLI action 可在命令列任意位置加入全域 `--dry-run`；Agent 只回傳 plan 與 payload fingerprint，不執行副作用。Privileged action 會把 dry-run 交給 Helper 驗證。

## `nettool-dataplane probe`

探測平台、CPU、NUMA、Huge Page、NIC、queue、驅動與資料平面能力，不修改系統。

使用 `--output json` 取得 schema `1.0` 的機器可讀輸出。標準輸出只包含成功結果；錯誤以 JSON envelope 寫到標準錯誤並回傳 exit code 2。

## `nettool-dataplane rx`

```bash
nettool-dataplane rx --backend dpdk --interface <pci-address> [--output json]
```

啟動 worker 前檢查 DPDK runtime、PCI device、queue、driver、NUMA、Huge Page 與 CPU affinity。預設 build 會明確回傳 `DATAPLANE.BACKEND_NOT_BUILT`；以 `--features native-dpdk` 建置且 `pkg-config libdpdk` 可用時，命令會初始化 EAL、mempool、port 與 RX queue，並以 borrowed mbuf view 執行 run-to-completion worker。`ffi-api` 僅供 ABI 編譯檢查，不得解讀為 RX backend 已連結。

## `nettool-dataplane analyze`

```text
nettool-dataplane analyze --input <capture.pcap|capture.pcapng> [--sample-one-in <n>] [--output json]
```

串流分析 Ethernet PCAP/PCAPNG，輸出封包、byte、TCP/UDP、flow、retransmission、parse error 與 sampled-out counters。`--sample-one-in` 必須大於零；啟用時 coverage 會標示為 `sampled`。損壞、截斷、超過 snaplen/wire length 或單一 block 超過 16 MiB 的輸入會以 `CAPTURE.FORMAT_INVALID` 失敗，檔案 I/O 錯誤則使用 `CAPTURE.READ_FAILED`。

Profile metadata 可使用 `nettool profile list`、`nettool profile show <id-or-name>`、`nettool profile create <id> <name> '<json>'`、`nettool profile edit <id-or-name> <name> '<json>'`、`nettool profile delete <id-or-name>`、`nettool profile export <id-or-name>` 與 `nettool profile import <file>`；export/import 使用 `nettool.profile.v1` JSON 文件，命令只管理已驗證的 SQLite revision，不會假裝完成平台套用。

快速網路設定可使用 `nettool ip set --interface <id> --address <ip> --prefix <n> [--gateway <ip>]`、`nettool ip dhcp --interface <id>` 與 `nettool dns set --interface <id> --server <ip> [--server <ip> ...]`；這些命令建立完整 desired state，經 Helper Safe Apply 與相同的 address-family、route、DNS、MTU validation。

Node inventory 可使用 `nettool node list` 或 `nettool node status`；輸出只包含已通過 pairing/trust 的 Node metadata，不包含私鑰或其他敏感材料。Speed Test history 可使用 `nettool speed history [--limit <n>]`，只回傳 session、Node、protocol/backend、direction、時間與終態摘要。

Node 配對可使用 `nettool node pair --id <id> --name <name> --address <ip:port> --server-name <name> --fingerprint <fp> --certificate <file> --confirm-fingerprint`。`--confirm-fingerprint` 表示使用者已透過 out-of-band channel 核對 fingerprint；憑證檔案必須是 DER，Storage 仍會驗證 certificate public-key fingerprint 與 control address。若既有 Node ID 的 identity key 改變，另必須明確加入 `--confirm-identity-change`，不接受 silent trust replacement。

撤銷配對可使用 `nettool node revoke <id-or-name>`；此操作保留歷史 certificate metadata，但將 trust status 設為 revoked，新的 Node control connection 會被拒絕。

封包統計可使用 `nettool packet stats [--interface <id>]` 讀取 Linux sysfs counters；目前連線可使用 `nettool packet connections [--protocol tcp|udp]` 讀取 Linux procfs endpoint tables（process/PID/traffic 無法由 endpoint table 證明時保持 `null`）；封包離線分析可使用 `nettool packet analyze --input <capture> [--sample-one-in <n>]`。Agent 使用 bounded PCAP/PCAPNG backend 與 blocking worker 執行，不會把 sampled 結果標示成 full coverage；非 Linux 平台的 packet stats/connections 會明確回報 unsupported。

Native DPDK build 可使用 `nettool-dataplane tx --backend dpdk --interface <pci-address> --frame-size <64..9018> --packets <n>` 執行 bounded raw TX template bursts。命令先跑最新 hardware preflight，並在可用時回傳 PMD `rte_eth_stats` hardware counters；未以 native DPDK SDK 建置時回傳 `DATAPLANE.BACKEND_NOT_BUILT`，不產生模擬傳輸數字。

Native DPDK build 亦可使用 `nettool-dataplane capture --backend dpdk --interface <pci-address> --output <directory> --bursts <n> [--protocol <tcp|udp|icmp|icmpv6|number>] [--source-ip <ip>] [--destination-ip <ip>] [--source-port <port>] [--destination-port <port>]` 執行 bounded RX capture。命令以 non-blocking bounded queue 將符合 filter 的 native RX mbuf 複製至旋轉 PCAPNG writer（單檔 1 GiB、60 秒、最多 4 檔），完成指定 burst 後輸出分析統計與 capture 目錄；未連結 SDK 時同樣回傳 `DATAPLANE.BACKEND_NOT_BUILT`，不宣稱 lossless 或 line-rate。

Agent 管理的 capture lifecycle 可使用 `nettool packet capture start --interface <id> --output <directory> --bursts <n> [--backend dpdk] [--protocol ...] [--source-ip ...] [--destination-ip ...] [--source-port ...] [--destination-port ...]`，回傳持久化 session ID；以 `nettool packet capture stop <session-id>` 停止仍由 Agent 擁有的 worker。Agent 會回收正常結束的 dataplane process 並保存 `packet_session` 終態；沒有可執行的 native dataplane binary 時明確回傳 `DATAPLANE.BACKEND_NOT_BUILT`。

介面查詢可使用 `nettool interface list`、`nettool interface show <name-or-id>` 與 `nettool interface refresh`；輸出包含 driver、link speed、RX/TX queues 與 NUMA node。Linux 讀取 sysfs；macOS 使用 `/sbin/ifconfig -l`，Windows 使用固定 PowerShell `Get-NetAdapter`，無法由平台 API 證明的欄位會保持 `null`。

網路設定操作使用 `nettool profile apply <id-or-name> --interface <id> [--confirm-timeout <seconds>]`（`--timeout` 為相容別名），完成後以 `nettool profile confirm <operation-id>` 或 `nettool profile rollback <operation-id>` 結束 Safe Apply；`nettool hosts list` 讀取目前 hosts，`nettool hosts replace <profile-id> '<entries-json>'`、`nettool hosts add <profile-id> <address> <hostname> [comment]`、`nettool hosts remove <profile-id> <hostname>`、`nettool hosts enable <profile-id> <hostname>`、`nettool hosts disable <profile-id> <hostname>`、`nettool hosts backup` 與 `nettool hosts restore` 透過同一 privileged Helper 寫入指定 managed section 或 Helper-owned backup。停用項目以受控 marker 保留，Agent 未設定 `NETTOOL_HELPER_SOCKET` 時會明確回報 unsupported，不會直接執行特權命令。
### `speed history`

`nettool speed history [--limit <n>] [--format csv]` 查詢非敏感測速歷史；CSV 輸出固定欄位並對逗號、引號與換行做 quoting。

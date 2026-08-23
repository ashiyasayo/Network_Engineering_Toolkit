# 專案開發進度（2026-08-21）

## 本次完成

- `apps/agent` 已將 `speed.run` 的 socket upload 路徑接上 remote capability/Prepare、scheduled Start、authorized TCP/UDP sender 與可重試 ResultQuery。
- sender 發生錯誤時會嘗試送出 Stop；raw 與未連結的 accelerated executor 仍明確回傳 unsupported，不產生 synthetic result。
- socket upload lifecycle 現在同步持久化至 SQLite `speed_session`，從 preparing 到 running，再保存 completed/failed terminal state；loopback test 已驗證 completed row。
- 新增 `speed.cancel <session-id>` CLI/Agent action：從 SQLite 解析 trusted remote，透過 mTLS `StopTest` 確認 CANCELED 後保存 canceled state；Unix IPC client 改為 per-connection task，長測試期間可接受取消 request。
- `SessionCoordinator::stop` 對已 CANCELED session 接受不同 operation ID 的重送，補足取消冪等性。
- `proto/node.proto` 已同步 minor 1 wire contract：`TestResultRequest`、Prepare source/receive ports 與 response source port。
- TCP download 已接通：initiator pre-bind receiver、remote `prepare_tcp_sender`、shared scheduled Start、authorized TCP sender/receiver、combined result 與 SQLite completed persistence；loopback mTLS test 已通過。
- UDP download 已接通：initiator pre-bind UDP receiver、remote `prepare_udp_sender`、AUTH/source-port binding、shared scheduled Start、authorized UDP sender/receiver、combined result 與 SQLite completed persistence。
- TCP/UDP bidirectional 已接通 coordinator/Agent worker：單一 session 同時保留 receiver endpoint 與 sender config，scheduler 在共同 `start_at` 以並行 workers 執行；UDP loopback 雙向測試已通過。
- Network Profile metadata 已支援 SQLite revision 1 的 create/show/list/delete、checksum 驗證與 CLI/Agent Action routing；profile apply/confirm/rollback 已接到 authenticated Helper Safe Apply client，平台 adapter 仍依作業系統逐步補齊。
- Profile workflow 已補上 `profile.edit/export/import`：edit 以新 revision 保存 checksum，export/import 使用 `nettool.profile.v1` JSON 文件。
- Hosts workflow 已補上 `hosts.add/remove`：Agent 先經 Helper 讀取指定 managed section，解析並驗證 entries 後再以 atomic replace 更新；區塊外內容不會被改寫。
- Hosts workflow 已補上 `hosts.enable/disable`：Helper schema 保留 `enabled` 狀態，停用項目以 `NETTOOL DISABLED` marker 留在 managed section，避免切換時遺失設定。
- Hosts workflow 已補上 `hosts.backup/restore`：Helper 將備份保存在受控 state directory，恢復時使用 atomic replace，不讓 Agent 直接碰特權 hosts path。
- SRS quick network commands 已補上 `ip.set`、`ip.dhcp` 與 `dns.set`；CLI payload 轉成完整 `NetworkDesiredState`，沿用 Helper Safe Apply 與既有 schema validation。
- Quick network commands 完成後再次執行完整 workspace format check、Clippy、tests 與 Agent/Dataplane `ffi-api` Clippy，全部通過。
- Node inventory 已補上 `node.list` 與 `node.status`，由 Storage 回傳 trusted Node 非敏感 metadata。
- Node inventory 完成後再次執行完整 workspace format check、Clippy、tests 與 Agent/Dataplane `ffi-api` Clippy，全部通過。
- 封包離線分析已補上 `packet.analyze` Action/CLI，重用 PCAP/PCAPNG bounded backend，並保留 full/sampled coverage 欄位。
- Packet analyze 完成後再次執行完整 workspace format check、Clippy、tests 與 Agent/Dataplane `ffi-api` Clippy，全部通過。
- Linux `packet.stats` 已補上 sysfs RX/TX/dropped counters；介面名稱有 path-safety validation，非 Linux 明確回傳 unsupported。
- Packet stats 完成後再次執行完整 workspace format check、Clippy、tests 與 Agent/Dataplane `ffi-api` Clippy，全部通過。
- Node pairing 完成後再次執行 `cargo fmt --all`、workspace Clippy、workspace tests，以及 Agent/Dataplane `ffi-api` Clippy，全部通過。
- Node control listener 已改為每條新連線從最新 trusted registry 建立 mTLS verifier；pairing/revoke 對新連線立即生效，既有連線不被強制中斷。
- Node revoke 已補上 Storage transaction、Agent action 與 CLI；撤銷保留歷史 metadata，後續新 control connection 會 fail closed。
- 修正 `node.revoke` 的 idempotency descriptor 與實際行為一致，避免重送空 operation ID。
- Windows `agent-client` 與 Agent server 已接上 Tokio Named Pipe bounded framing；Windows helper authentication、privileged executor 與實機編譯驗證仍列為未完成。
- Safe Apply CLI 已接受規格指定的 `--confirm-timeout`，舊有 `--timeout` 仍可用並映射同一確認視窗欄位。
- 本輪最後驗證：`cargo fmt --all`、workspace Clippy、workspace tests 與 CLI/Agent-client targeted tests 均通過。
- Agent Named Pipe listener 完成後再次執行 format、workspace Clippy 與 workspace tests，全部通過；Windows target 尚未在本機 runner 編譯。
- Remote sender role 稽核完成：Node server 已支援 TCP/UDP sender Prepare，Agent scheduler 已完成 sender handoff、authorized worker、ResultQuery 與 loopback lifecycle；不再列為未完成。
- Native DPDK dataplane 新增 bounded RX capture command；native RX mbuf 經 non-blocking queue 寫入旋轉 PCAPNG（單檔 1 GiB、60 秒、最多 4 檔），未連結 SDK 時 fail closed，未宣稱 lossless 或 line-rate。
- Packet capture lifecycle 已補上 Agent/CLI `packet capture start/stop`、`packet_session` persistence、dataplane child process ownership 與正常/取消終態回收。
- Packet Worker statistics 已補上 IPv4/IPv6/ICMP/Other protocol counters；新增 zero-allocation `PacketFilter` 可依 protocol、source/destination IP 與 TCP/UDP ports 限制分析與保存分支。
- PacketFilter 已接入 dataplane capture 與 Agent/CLI payload，capture start 可傳遞 protocol/IP/port filters 至 native worker。
- Interface probe 已補上 macOS `/sbin/ifconfig -l` 與 Windows 固定 PowerShell `Get-NetAdapter` 唯讀 fallback；未能證明的 driver/queue/NUMA 欄位維持 unknown，不誤標 DPDK capability。
- Linux `packet connections` 已補上 procfs TCP/UDP endpoint/state inventory；process/PID/traffic 缺乏可信來源時保留 `null`，非 Linux 明確 unsupported。
- `speed history` 已補上 read-only Action/CLI 與 SQLite session summary query，限制回傳非敏感欄位與 bounded limit。
- Native DPDK safe/FFI boundary 已補上 `rte_eth_stats` counter snapshot；RX/TX/capture JSON 在 native build 回傳 hardware counters，default/ffi-only build 仍 fail closed。
- Native DPDK safe/FFI boundary 已補上 bounded `rte_eth_xstats` snapshot；輸出 PMD/per-queue counters，`ffi-api` dataplane Clippy 通過，但仍不是 100GbE 實機 certification 證據。
- 新增 `nettool-gui` loopback-only localhost GUI 殼層與 Action API forwarding，包含 Dashboard 導覽與安全錯誤 handling；原生 desktop shell、installer 與完整 GUI 操作頁仍未完成。
- Remote sender 稽核後重跑 `cargo test -p nettool-node -- --ignored`（提升權限允許 loopback bind），6 個 TCP/UDP sender/bidirectional tests 全部通過。
- Native DPDK dataplane 已新增 bounded raw TX template worker/CLI；使用既有 preflight、NUMA mbuf sizing、exclusive TX queue 與 template burst，預設 build 與無 SDK 時明確回傳 backend-not-built。
- Raw template correctness 已補齊 IPv4/IPv6 的 TCP/UDP transport header 分支，並由 packet unit tests 驗證 EtherType、protocol、ports 與 TCP data offset。
- Raw template checksum 已補齊 IPv4/IPv6 pseudo-header transport checksum；TCP/UDP unit tests 會拒絕零 checksum。
- 非 Linux build 的 packet stats 條件式測試/匯入亦已修正，workspace Clippy 與 tests 再次通過；Linux `/sys` 實機測試會在 Linux runner 啟用。
- Node pairing 已補上 `node pair` CLI/Agent workflow；使用者提供 certificate DER、fingerprint、TLS server name 與 control address 後，由 Storage 原子驗證並保存 trust material，既有 identity key 變更需明確 confirmation。
- CI workflow 已調整為 Ubuntu 執行 loopback ignored integration tests，macOS/Windows 執行 non-ignored workspace lint/test，跨平台驗證邊界明確化。
- SRS 介面查詢已接上 `interface.list/show/refresh` Action 與 CLI，輸出統一使用 dataplane probe 的 stable NIC metadata。
- Agent 已新增 authenticated Helper client：`profile.apply/confirm/rollback` 與 `hosts.read/replace` 會經 bounded Unix framing、request correlation、2 秒 timeout 與 Helper kernel peer authorization；未配置 Helper socket 時 fail closed。
- Profile apply 同時接受直接 `NetworkDesiredState` JSON 與完整 `NetworkProfile` JSON，並將 IPv4/IPv6/DNS/routes/MTU 轉成 Helper whitelist schema。
- Safe Apply 與 hosts replace 的 fallback operation ID 現在包含 interface/profile 與 hosts payload fingerprint，避免同一 Agent 上的平行請求互相覆蓋。
- Node `SessionCoordinator` 已提供原子 `begin_and_take_receiver`，避免重複 scheduler 取得同一 TCP/UDP endpoint。
- Node 已提供 Completed/Failed terminal result 路徑：bounded versioned JSON、SHA-256 checksum、冪等保存、resource release 與 endpoint cleanup。
- Agent receiver scheduler 在 `start_at` 到達後啟動 authorized worker，成功或失敗均回寫 coordinator。
- loopback mTLS integration test 已實際通過 TCP upload：mutual TLS、Hello、capability、Prepare、scheduled Start、authorized sender、receiver worker 與 ResultQuery。
- 已補強 Node lifecycle test，確認 atomic receiver handoff 與重複 handoff 拒絕。

## 驗證結果

本次執行通過：

```text
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --quiet
cargo clippy -p nettool-dataplane --bin nettool-dataplane --features ffi-api -- -D warnings
cargo clippy -p nettool-agent --bin nettool-agent --features ffi-api -- -D warnings
cargo test -p nettool-agent --bin nettool-agent speed_runtime_performs_mutual_tls_hello_and_capability_preflight -- --ignored
```

workspace 測試仍有既有的 loopback ignored tests；本次 Agent TCP upload ignored test 已在允許 socket 的環境明確執行並通過。完整歷史基準見 `2026-08-16-project-status.md`。

最後一輪 workspace tests、workspace Clippy、dataplane `ffi-api` Clippy、agent `ffi-api` Clippy，以及 Agent loopback upload + SQLite persistence ignored test 均通過。

新增取消功能後，Agent 與 Node 的 socket loopback ignored tests 亦重新執行並通過。

TCP download integration test `speed_runtime_performs_mutual_tls_and_tcp_download` 已在允許 socket 的環境通過，並驗證 sender/receiver counters 與 SQLite `completed` state。

Node 全部 loopback ignored lifecycle tests（TCP/UDP receiver、sender handoff、TCP bidirectional prepare、UDP bidirectional execution）已在允許 socket 的環境通過；Agent TCP download integration 亦重新通過。

最新 workspace 驗證：format check、workspace Clippy、workspace tests、dataplane `ffi-api` Clippy 與 agent `ffi-api` Clippy 全數通過。

本輪修正後再次執行 `cargo fmt --all`、`cargo clippy --workspace --all-targets -- -D warnings` 與 `cargo test --workspace --quiet`，全部通過。

Profile edit/export/import 完成後再次執行上述三項完整 workspace 驗證，全部通過；workspace 仍保留既有需 loopback/特權環境的 ignored tests。

Hosts add/remove 完成後再次執行 format check、workspace Clippy、workspace tests，以及 Agent/Dataplane `ffi-api` Clippy，全部通過。

Hosts enable/disable 完成後，Helper core/protocol、Agent、CLI targeted tests 與 workspace Clippy 全部通過；disabled marker render/parser 亦有測試覆蓋。

Hosts backup/restore 完成後再次執行完整 workspace format check、Clippy、tests 與 Agent/Dataplane `ffi-api` Clippy，全部通過。

## 尚未完成

- 完整跨 Agent persistence transaction。
- raw DPDK TX orchestration 已具備 dataplane bounded worker，但尚未完成 Agent speed orchestration；native DPDK bounded RX capture 已可保存 PCAPNG；AF_XDP、Windows RIO、macOS/Windows privileged helper 與 Windows Named Pipe helper authentication 仍未完成。
- pairing UI、GUI、installer 與全規格逐項驗收；CLI pairing 與新連線 trust reload 已可用，跨平台 CI 基礎矩陣已建立，但平台 executor 仍未完成。
- native DPDK/PMD、真實硬體 xstats、100GbE POC policy 與 A–J Certified100G 證據。

## 2026-08-22 補充

- `packet_session` 已新增 v3 forward-only migration，明確持久化 `running/completed/failed/canceled`；capture stop/reaper 的取消與失敗終態可被查詢，並加入 canceled lifecycle 測試。
- CLI invalid-argument usage 已同步列出 `packet connections` 與 `speed history`。
- 最新驗證：`cargo fmt --all`、`cargo clippy --workspace --all-targets -- -D warnings`、`cargo test --workspace --quiet` 與 dataplane `ffi-api` Clippy 均通過。
- 新增 `nettool-platform-auth` Windows token/SID FFI 邊界與 helper-server Named Pipe authenticated exchange；Windows helper runtime executor 尚未接入，現有 Unix helper 行為不變。
- AF_XDP probe 已拆分基本 kernel/BPF surface 與 zero-copy capability；未有 driver evidence 時 zero-copy 明確為 false，backend/Agent/dataplane JSON 已同步欄位。
- 新增 macOS/Windows allowlist staging installer 與 backup/rollback 流程；尚未註冊平台 privileged helper 或完成 code signing/實機 installer 驗收。
- GUI 導覽已接上 `speed.history`、`packet.connections` 與 `dataplane.probe` 查詢頁，並對 Agent unavailable 顯示錯誤狀態。
- GUI Action Console 已接上 ActionRegistry，提供所有已註冊 action 的 JSON payload 執行入口並在 server 端拒絕未知命令。
- Helper core 新增 macOS `networksetup` fixed-argv builder 與安全測試；尚未接入 macOS helper runtime、snapshot restore 或實機驗證。
- Helper core 新增 Windows `netsh.exe` fixed-argv builder 與安全測試；尚未接入 Windows helper runtime、snapshot restore 或實機驗證。
- 平台 command runner 新增執行前 re-validation，限制固定絕對 executable、argv 長度並拒絕 shell metacharacters；helper-core 14 項測試、Clippy 與格式檢查通過。
- 平台 builder 也會在產生命令序列後再次驗證；macOS/Windows 對多位址與未支援的 DNS search domains 直接拒絕，避免部分套用。
- 新增 `execute_platform_commands` fail-closed runner，命令非零時停止後續 argv；helper-core 測試、Clippy 與 workspace 驗證持續通過。
- 新增 generic `PlatformNetworkExecutor`，以注入的 state reader 完成 typed snapshot、fixed-argv apply、verify 與 restore；目前仍缺 macOS/Windows 實際 state reader、privileged service wiring 與實機驗證。
- macOS `networksetup` state reader 已接上 typed parser（IPv4/IPv6、DNS、MTU），對未知格式與 gateway fail closed；Windows state reader 與 helper wiring 尚未完成。
- Windows `netsh.exe` state reader 已接上 typed parser（IPv4/IPv6、DHCP/static、DNS、MTU），對未知語系格式與 gateway fail closed；兩平台 helper wiring 尚未完成。
- macOS Unix helper service 已接上 platform executor，沿用 authenticated IPC、Safe Apply watchdog、snapshot restore 與 Hosts handling；Windows Named Pipe helper runtime wiring 尚未完成。
- Windows helper runtime 已新增 Named Pipe server、token SID allowlist、bounded exchange、Safe Apply watchdog、Windows netsh executor 與 snapshot restore；目前環境無法下載 `windows-sys`，故 target cross-compile 尚未完成。
- Windows helper 已補上 Hosts managed-section replace；Windows atomic file replacement 集中於 platform-auth FFI，使用 `MoveFileExW` replace/write-through flags。
- DPDK backend 新增 AF_XDP interface/queue/zero-copy preflight，zero-copy required 缺 evidence 時 fail closed；尚未建立實際 AF_XDP ring/UMEM data-plane worker。
- CLI/Agent 新增 `speed history --format csv`，固定欄位輸出並驗證 format；CLI/Agent targeted tests 與 workspace 驗證通過。
- 新增 `nettool-backend-af-xdp` Linux FFI setup boundary，完成 ring socket bind 與 zero-copy flag；UMEM/XDP program/XSKMAP/worker 尚未完成，故不誤標完整 backend。
- AF_XDP FFI setup 再補 page-aligned UMEM allocation 與 `XDP_UMEM_REG`；XDP program/XSKMAP、ring ownership 與 packet worker 仍未完成。
- AF_XDP UMEM 新增 bounded `FrameDescriptor` API，集中 frame offset/headroom/payload bounds；尚未接入 ring producer/consumer。
- AF_XDP 新增 bounded SPSC `FrameRing`，具 acquire/release ordering 與 full/empty non-blocking tests；kernel mmap ring/packet worker 尚未接入。
- 新增 `nettool-backend-rio`：固定 registered buffer、bounded request/completion queue 與 descriptor bounds；Winsock RIO FFI 尚未連結，`is_backend_built()` 明確維持 false。
- AF_XDP socket 新增 `XDP_MMAP_OFFSETS` query，取得 RX/TX/FILL/COMPLETION ring offsets；kernel mmap owner 與 packet worker 仍未完成。
- AF_XDP 新增四-ring RAII mmap mapping 與 page-aligned sizing；尚未接 descriptor accessors、FILL 初始化、XDP program/XSKMAP 或 packet worker。
- AF_XDP ring mapping 新增 bounds-checked producer/consumer index 與 `xdp_desc` volatile accessors；FILL 初始化、XDP program/XSKMAP 與 packet worker 仍未完成。
- AF_XDP 新增 FILL ring 初始化，檢查初始 indices、容量與 UMEM frame bounds 後發布 frame base descriptors；XDP program/XSKMAP 與 packet worker 仍未完成。
- AF_XDP 新增 `AfXdpWorker`，提供 RX drain、TX submit、COMPLETION recycle、FILL refill 與 UMEM bounds checks；XDP redirect/poll loop 仍未完成。
- AF_XDP socket 新增 bounded RX `poll` wait，區分 timeout 與 error/hangup，避免 worker busy-loop；XDP redirect 仍未完成。
- AF_XDP worker 新增 `receive_once`，整合 poll 與 RX batch drain；timeout 回傳零筆，XDP redirect/packet accounting 仍未完成。
- AF_XDP worker 新增 multi-buffer `receive_packet_into`，保留未完成 chain 的 consumer ownership，支援 jumbo descriptor aggregation；XDP redirect 仍未完成。
- AF_XDP 新增 Linux `BPF_MAP_TYPE_XSKMAP` RAII map 與 queue→socket FD 更新；XDP redirect program attach 仍未完成。
- Agent dataplane probe/perf backend 已分開回報 RIO platform capability 與 implementation availability；Winsock RIO FFI 仍未連結。
- AF_XDP 新增固定 eBPF `bpf_redirect_map` program 與 `BPF_LINK_CREATE` attach；失敗 fail-closed，program/link 由 RAII 釋放。
- AF_XDP BPF program load attr 補齊 interface index、expected attach type 與 verifier log 欄位，提升 kernel ABI 對齊；尚未有 Linux privileged hardware run。
- AF_XDP redirect instruction builder 增加 Linux unit coverage；目前環境為 macOS，Linux privileged attach 尚未實機驗證。
- Linux AF_XDP implementation availability 已由 Agent 依 crate build capability 回報；runtime/interface/zero-copy gates 仍獨立判定。
- Agent `speed.run` 已在遠端 session 建立前加入 AF_XDP zero-copy/RIO implementation preflight；未通過時 fail-closed。
- `nettool-backend-rio` 新增可測試 preflight contract，`perf.backend` 輸出 RIO gate evidence 與 `can_run`。
- RIO resource model 新增固定容量 request/completion queue pair，completion backpressure 不會遺失 request ownership。
- 新增 Windows-only RIO extension discovery/registered-buffer FFI 邊界；未在 Windows runner 實機驗證，implementation availability 維持 false。
- Windows-only RIO module 已以 host rustc 的 `--cfg windows` syntax check 通過；實際 Windows linker/API/WSAIoctl 驗證仍待 Windows runner。
- RIO registered buffer 新增 bounds-checked `RIO_BUF` slice model 與測試；Windows function table 實機仍待驗證。
- RIO Windows adapter 再補 `RIOCreateCompletionQueue`/`RIOCreateRequestQueue` wrappers：completion queue 以 RAII 關閉，request queue handle 明確繫結 socket，並以固定 config limits 建立 receive/send queue；host `--cfg windows` syntax check、workspace fmt、Clippy 與 tests 全數通過，Windows runner/linker/API 實機驗證仍待完成。
- RIO Windows adapter 再補 `RIOReceive`/`RIOSend` submission 與 bounded `RIODequeueCompletion`，以 `RioBufferSlice` 和 opaque request context token 連接 registered buffer；host Windows cfg syntax check、workspace fmt、Clippy 與 tests 全數通過，實機 API/throughput 驗證仍待 Windows runner。
- RIO registration 再補 `register_registered_buffer` owner-borrow API，raw pointer registration 改為明確 unsafe；host Windows cfg syntax check、workspace fmt、Clippy 與 tests 全數通過。
- GUI Node 頁面新增首次 pairing 表單（DER certificate file、fingerprint、server name、out-of-band confirmation、identity replacement confirmation），透過既有 typed `node.pair` action 保存；仍待實機 GUI 操作驗收。
- Node pairing 已加入 out-of-band fingerprint confirmation：CLI 必須使用 `--confirm-fingerprint`，GUI 必須勾選獨立通道核對；Agent payload 與 Storage 均 fail closed，workspace fmt/Clippy/tests 全數通過。
- 新增 pairing fail-closed regression test，確認未完成 out-of-band fingerprint 核對回傳 `NODE.TLS_FAILED` 且不建立 trust record。
- 新增規格追蹤矩陣，將主要需求連到實作、測試與實機待驗狀態；README 已加入入口。
- Linux packaging 新增固定路徑 `install-helper.sh` 與 dry-run 驗證；正式流程會建立 `nettool` group、設定 agent UID、安裝 root-owned helper/env/unit 並啟動 systemd，尚待隔離 Linux 主機實機驗收。
- macOS staging installer 現在拒絕 symlink release binary；Windows staging installer 也拒絕 reparse point，避免 allowlist 檔案透過連結逃逸；macOS rejection test 通過，PowerShell runner 仍不可用。
- 新增 `nettool-platform-affinity`：bounded、unique CPU set 與 Linux `sched_setaffinity` adapter；native DPDK RX/TX path 以 CPU 0 呼叫並對 syscall failure fail-closed，host workspace tests/fmt 已驗證通過。
- affinity crate 在本機 macOS host workspace fmt/Clippy/tests 全數通過；環境未安裝 rustup/Linux target，因此 Linux linker/runtime affinity 尚未交叉編譯或實機驗證。Architecture 已修正為 CPU pinning 部分完成、RSS/NUMA orchestration 仍未完成。
- README 已補充 native DPDK affinity 的 fail-closed 行為與驗證限制。
- DPDK environment collector 新增 `RssEvidence`/`parse_rss_evidence`，固定解析 enabled/disabled/queue count，並對 malformed 或 queue mismatch fail-closed；backend-dpdk targeted 與 workspace fmt/Clippy/tests 全數通過。
- DPDK `QueuePlan::validate` 新增 one-queue/one-worker invariant gate，拒絕 assignment count、CPU owner 重複與 non-contiguous queue ID；targeted/workspace fmt、Clippy、tests 全數通過。
- Native DPDK RX/TX/capture 目前會消費最新 `probe_environment` 的 NIC queue/NUMA evidence，經 `plan_queues` 驗證後再建立 PortConfiguration；`ffi-api` check 與 workspace fmt/Clippy/tests 全數通過，仍待 native hardware runner。
- DPDK preflight 新增 optional management PCI evidence；相同 target 由 `MANAGEMENT_NIC_PROTECTION` fail-closed，並補測試；workspace fmt/Clippy/tests 全數通過。
- Linux dataplane 現在從 `/proc/net/route` default route 解析 management interface，只有在最新 NIC probe 找到對應 PCI 時才提供 management evidence；解析器測試與 workspace fmt/Clippy/tests 全數通過。
- 本輪新增 `docs/REQUIREMENT_TRACEABILITY.md` 與 pairing fail-closed regression test；完整 workspace fmt/Clippy/tests 及 `cargo check -p nettool-dataplane --features ffi-api` 均通過。Windows target check 仍受環境無法解析 crates.io 限制，硬體驗收未宣稱完成。
- CLI pairing parser 已對 `--id`、`--name`、`--address`、`--server-name`、`--fingerprint`、`--certificate` 的重複參數 fail closed，並新增回歸測試；CLI targeted tests/Clippy 通過。
- 最新 workspace 驗證：CLI 測試數增至 18，workspace Clippy 與全部 workspace tests 均通過。
- AF_XDP worker 新增 `submit_tx_and_kick` 與 Linux `sendto` wakeup 邊界；backend-af-xdp tests/Clippy/fmt 通過，Linux NIC 實機仍待驗。
- 嘗試 `cargo check -p nettool-backend-af-xdp --target x86_64-unknown-linux-gnu --offline` 時確認本環境未安裝 Linux std target；因此 Linux compile/runtime evidence 仍待 Linux runner。
- UDP socket receiver 已改用 65,536-slot bounded sequence window，hot path 不再以無界 `HashSet` 累積 sequence；speed tests/Clippy/fmt 通過，並保留完整 tracker 供離線分析。
- Packet flow table 已限制最多 1,000,000 entries，建立時 `try_reserve` 固定 capacity，超出上限或配置失敗會回傳錯誤；packet tests/Clippy/fmt 通過。
- Agent `dry_run` wire flag 已接入 runtime；非 helper action 不執行 payload，helper action 保留既有 validation 並傳遞 dry-run；Agent targeted test/Clippy 通過。
- CLI 已接上全域 `--dry-run`，可在任意位置移除旗標後正常解析 command，再將 dry-run bit 送入 Agent；新增 duplicate flag parser test。
- `README.md` 與 `docs/PROTOCOL_SPECIFICATION.md` 已補上 `dry_run` 的使用方式、bounded plan、payload fingerprint 與 Helper 驗證契約；目前仍需以跨平台實機驗證不產生副作用。

> 進度筆記前段的「尚未完成」條目保留作歷史脈絡；以本檔案後段最新補充與 `docs/REQUIREMENT_TRACEABILITY.md` 為目前狀態來源，避免將已完成的 helper/AF_XDP 分層工作誤判為未實作。

不得因本次 socket upload loopback 通過而宣稱整個規格或 100GbE certification 已完成。

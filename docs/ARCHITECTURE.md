# Architecture

本文件說明程序責任、資料流、信任邊界與 backend 可用性判定。快速開始與文件索引請參閱 [README](../README.md)，命令與輸出格式請參閱 [CLI Reference](CLI_REFERENCE.md)。

## 程序責任

| 程序 | 主要責任 | 明確不負責 |
| --- | --- | --- |
| `nettool-agent` | 唯一 runtime authority、Action API、SQLite metadata、Node control 與 session coordination | 直接執行特權 OS 命令 |
| `nettool` / `nettool-gui` | CLI、loopback Dashboard 與使用者操作介面 | 直接修改網路設定或執行 dataplane |
| `nettool-desktop` | Tauri 2 WebView、程序生命週期與原生視窗 | 直接執行網路或特權操作 |
| `nettool-helper` | authenticated privileged action、Safe Apply、Hosts 與平台 adapter | 接受未驗證的 caller 身分或任意 command |
| `nettool-dataplane` | probe、socket/backend worker、封包分析與硬體 evidence | 取代 Agent 的 trust、session 或設定權限 |

依賴方向保持由應用層指向 action、domain、storage 與 backend；domain 不依賴 OS API 或資料平面實作。

## 控制平面

目前控制平面：

```text
nettool CLI → agent-client → Unix socket / Windows Named Pipe → nettool-agent
                                         ├─ Action Registry
                                         ├─ SQLite metadata
                                         └─ dataplane probe backend
```

IPC 使用四位元組 big-endian 長度加 Protobuf envelope，單一 frame 上限 1 MiB。Agent socket 設為 user-only；SQLite 啟用 foreign key 與 WAL，且 schema 不包含私鑰或封包 payload 欄位。

## Runtime module seams

`nettool-agent` 的 runtime authority 仍集中在同一個 process，但 implementation 已依責任拆成較深的內部 module：

- `action_dispatch` 只負責 action routing、response envelope 與 dry-run decision。
- `action_packet`、`action_speed`、`action_profile`、`action_hosts`、`action_node` 與 `action_perf` 分別隱藏各 action domain；`action_persistent` 只保留 system/interface read path，`action_helper` 只保留 network helper transport。
- `SessionCoordinator` 的 TCP、TCP bidirectional、UDP、UDP bidirectional prepare implementation 各自位於獨立 module；coordinator 本身保留 lifecycle、resource ownership 與 result state machine。
- Helper network executor 將 macOS `networksetup` reader/builder 與 Windows PowerShell JSON state reader、`netsh.exe` apply builder 放在獨立 platform module；Windows query 另固定無 BOM UTF-8 stdout，shared executor 只處理 typed snapshot、fixed-argv validation、verify 與 restore。

這些都是 process 內部 seam，不擴大 wire protocol surface；caller 仍只需要學習 Agent Action interface、Node session interface 或 Helper Safe Apply interface。

## Capability、implementation 與 runtime gate

三種狀態必須分開處理：platform/kernel capability 只表示系統表面存在，implementation availability 表示對應程式碼與 native SDK 已連結，runtime gate 則表示目前介面、driver、queue、權限與資源檢查均通過。任何一層未通過都不得產生可執行或認證成功的假結果。

- 預設 build 不宣稱 DPDK、RIO 或 accelerated speed executor 可用；`native-dpdk` 與 `pkg-config libdpdk` 是 DPDK native path 的必要條件。
- Linux AF_XDP 的 implementation 可編譯不代表 zero-copy driver、interface 或 queue preflight 已通過；RIO 同樣必須同時符合 Windows platform 與 implementation gate。
- `100G Certified` 需要完整 hardware evidence、核准 policy 與 A–J gates 全部通過；未完成真實硬體 POC 時最高只能呈現較低的驗證狀態。

Node identity 由獨立 Identity crate 管理。Production store 直接使用平台 native credential backend（macOS Keychain、Windows Credential Manager、Linux Secret Service），不存在一般檔案或 SQLite fallback。首次啟動以 CSPRNG 建立非零 128-bit Node ID，並產生 PKCS#8 asymmetric key 與含 SAN 的 certificate；credential blob 使用 bounded、versioned binary envelope。每次載入會驗證 header/length、X.509 DER、PKCS#8 DER，以及 certificate public key 與 private key 是否相符。Agent 在開啟 IPC listener 前載入此 material，store 鎖定、損壞或不可用會使啟動失敗。

Safe Apply deadline 與 snapshot ID 由 helper-owned state 保存。寫入流程使用暫存檔、`fsync` 與 atomic rename；即使 Agent 終止，helper 重新啟動後仍可查出 pending operation 並依 deadline rollback。Desired state 是拒絕未知欄位的 typed schema；相同 operation request 可冪等重送，不同 payload 重用 ID 或 deadline 後 confirm 會拒絕。

Linux Ethernet executor 使用明確設定的 absolute `nmcli` path，不依賴 privileged process 的 `PATH`，且只以 `Command + argv` 呼叫 NetworkManager，不經 shell。Snapshot 以 active connection UUID 讀取 IPv4/IPv6、DNS、routes 與 MTU properties，原子持久化後才允許 modify/activate；apply 後逐欄讀回驗證，rollback 由 snapshot 還原並重新 activate。Helper core 另提供 generic `PlatformNetworkExecutor`，集中 fixed-argv、typed snapshot、verify 與 restore；macOS `networksetup` reader/executor 與 Windows PowerShell JSON state reader、`netsh` fixed-argv apply executor 都已接上 fail-closed Safe Apply wiring，Windows query 固定無 BOM UTF-8 stdout，Windows Named Pipe 另以 token SID allowlist 建立 authenticated boundary。兩平台正式簽章、實機 ACL/rollback 驗收與完整發行 installer 仍待完成，因此目前不標示 production-ready。

`nettool-helper` Unix service 將 authenticated transport、Safe Apply、Hosts managed section 與平台 network executor 串接；Linux 使用 NetworkManager，macOS 使用 `networksetup` fixed-argv reader/executor。啟動時在接受 request 前先恢復所有逾期 operation，運行中每秒檢查 deadline；單一 client exchange 上限兩秒，避免 slow client 阻塞 watchdog。Socket path 若已存在會拒絕啟動，不會任意刪除 filesystem entry。Systemd unit 使用 root user、`nettool` group、`0660` socket、`0700` state directory、filesystem/sysfs write allowlist 與 address-family restriction。

NIC prepare 在任何 unbind 前保存 helper-owned original-driver snapshot，固定使用 sysfs `driver_override` 綁定 `vfio-pci`，read-back 成功才回報；restore 只能引用 prepare operation ID，不信任 caller 提供 driver。Huge Page prepare 保存 global 或 NUMA-node 原 count，再寫入並讀回驗證；release 由 snapshot 還原。所有 state/Hosts atomic rename 後在 Unix 同步 parent directory，補足 crash durability。

Helper local transport 將 wire request 與 authenticated request 分成不同型別。Unix server 從 kernel peer credentials 注入 UID/PID，經 exact allowlist 後才建立 authenticated request；caller 無法在 JSON 內自稱身份。Transport 與 Agent IPC 同樣先驗證 4-byte big-endian 長度，1 MiB 上限通過後才配置 payload。

Socket Speed Engine 位於獨立 `speed` crate。TCP sender 會預先建立所有 streams 並重複使用 payload buffer，將 warm-up 與 measurement 分離；完整 UDP v1 header 綁定 session、stream、sequence、flags、sender monotonic timestamp 與 payload length，另保留 16-byte compact header 供最小 frame benchmark。所有多位元組欄位使用 network byte order。Compatibility UDP tracker 使用精確 set，不得放入 100G hot path；accelerated backend 必須採固定容量 window 與 flow-local counters。

公開 `speed.run` payload 由 Speed crate 統一定義並採 deny-unknown-fields。CLI 將時間、十進位 rate、CPU ranges 與 auto selections 正規化成此 payload；Agent 再驗證 protocol/backend、duration、stream、raw frame 與 affinity invariants，並只解析 `node`/`node_trust` 中仍為 trusted、具完整 TLS connection material 且名稱不歧義的對端。socket upload 與 TCP download 會由 Agent 維持 control connection，完成雙端 endpoint Prepare、scheduled Start、authorized TCP/UDP sender/receiver 與可重試 ResultQuery；未配對、backend 未連結或尚未附著的方向 executor 都回傳不同 stable error，不以 synthetic result 取代執行。

Node control client 在 TCP connect、TLS handshake 與 NTCP Hello 各自套用 bounded timeout。TLS chain/server name 驗證後解析 X.509 SubjectPublicKeyInfo，並比對 pairing store 保存的完整 public-key fingerprint，再要求 Hello Node ID 等於 paired Node ID，避免受同一 CA 信任的另一身分冒用 logical Node，也允許同一金鑰的正常換證。每個 sequential request 使用 CSPRNG 128-bit request ID，response 必須匹配 major/minor、request ID 與預期 typed message；remote protocol error 保存其 stable code，heartbeat 另驗證 nonce。Client 已提供 capability、prepare、start、stop 與 ping methods。

SQLite v2 migration 為 trusted Node 增加 paired certificate DER、TLS server name 與完整 control socket。Certificate 是公開材料，不包含 private key；寫入前會解析 X.509 並重新計算 SPKI fingerprint。相同 Node ID 的 fingerprint 變更預設拒絕，只有明確標記使用者已完成 re-pair confirmation 才可原子更新。Agent 以 paired certificate 建立 peer-specific RootCertStore，再以平台 identity 建立 mTLS client；integration test 覆蓋真實 loopback TLS 1.3、Hello 與 capability exchange。

Speed session planner 使用固定且不可重用的 capability IDs，依 TCP/UDP/raw、bidirectional、DPDK/AF_XDP/RIO、jumbo 與 latency-under-load 組合產生排序去重的 requirements。Remote capability response 的 ID 不得重複，version range 必須有效且涵蓋本地要求版本；全部成立後才產生 wire `PrepareTest`。UDP 必須先動態 bind 本機 source port，再交給 remote 建立 session-scoped authorization；零 port 不會送上 control plane。

Client-side session orchestrator 串接 capability query、planner 與 Prepare exchange。Prepare 只有在 remote 明確回報 ready、authorization tag 非空，且 socket test 帶回合法 dynamic port 時才成立；Start/Stop 各自要求非空 operation ID，並驗證回覆的 session ID 與 RUNNING/CANCELED 狀態。Session ID 由平台 CSPRNG 產生且禁止全零。此邊界刻意不代替本機 data-plane bind 或 Agent identity provider，避免在控制面看似成功時繞過 endpoint authorization 與安全儲存要求。
Agent 在 accelerated `speed.run` 建立遠端 session 前先執行 backend preflight：AF_XDP 必須有 Linux implementation、AF_XDP surface 與 zero-copy evidence；RIO 必須是 Windows 且 implementation 已連結。任何 gate 失敗都在遠端 Prepare 前 fail-closed。

Speed session storage 以 transaction 建立 immutable request row，只有 preparing 可轉 running、只有 running 可轉 completed，preparing/running 可轉 failed 或 canceled；相同 session ID 只有完全相同 request/result 才可冪等重送，不同內容回傳 operation conflict。Prepare contract 已分開 initiator/remote 的 sender source 與 receiver ports，planner 依 upload/download/bidirectional 強制對應 endpoint 在 Prepare 前 bind。

Socket data plane 不只依賴可觀察的 endpoint。TCP 每條 stream 在 payload 前完成 bounded session/stream/tag handshake，receiver 同時拒絕重複或超出範圍的 stream ID；UDP 在量測前送出 AUTH datagram，receiver 未通過 endpoint/session/stream/tag 前不接受 DATA 或 END。Authorization tag 採 16–256 bytes bound、禁止控制字元並以不依內容提前結束的方式比對。Node coordinator 只交出包含 control-plane tag 的 authorized receiver config。

正常完成不使用 Stop/Cancel。Worker 產生含非空 schema version 的 bounded JSON 後，Node 將 Running 推進 Finalizing、冪等釋放 reservation，再保存 SHA-256 與 Completed result。Protocol minor 1 的 typed `TestResultRequest` 讓 client 以 session ID 重試取得 immutable result；client 同時驗證 request ID、session ID 與 checksum。Stop 只保留給 prepared/running/finalizing 的取消路徑，Completed session 不會被誤標 Canceled。

每條已通過 mTLS/pairing 的 server connection 都有獨立 Hello-first dispatcher state，Hello Node ID 必須等於 transport 已認證的 peer，之後每個 envelope 仍驗證 major、negotiated minor 與 nonzero 128-bit request ID。Dispatcher 將 capability、TCP/UDP receiver、sender 與 bidirectional Prepare、Start、Stop、Ping 與 ResultQuery 映射到 Agent-owned shared `SessionCoordinator`；Start response 後由 wall-clock scheduler 在指定時間原子取得唯一 endpoint 或並行 sender/receiver worker，再保存 terminal result，因此 connection 重建不會遺失 session/result。raw 與 accelerated role 在 bind 或 reservation 前回傳 stable unsupported error。

Agent 只有在明確設定 `NETTOOL_CONTROL_LISTEN` 時才建立 TCP listener。每條新 connection 都把最新具完整 connection material 的 trusted certificates 加入 mTLS client RootCertStore，先拒絕 fingerprint→Node ID 歧義；handshake 後再從 presented certificate 計算 SPKI fingerprint，選定唯一 peer record並建立 dispatcher。空 registry 的 connection 會 fail closed；pairing/revocation 對新連線立即生效，既有 TLS session 不被強制中斷。

Agent Unix IPC listener 對每個 accepted client connection 建立獨立 task，讓長時間 `speed.run` 不阻塞後續 `speed.cancel` request；取消仍須經 paired mTLS control connection 與遠端 `StopTest`，不能直接修改本機資料庫狀態冒充遠端取消。

UDP rate control model 支援 unlimited、fixed 與嚴格遞增 ramp。高低速分界與 loss ppm 都由 profile/POC 提供，不在程式內猜測認證門檻；高於分界時只允許 batch/burst 或 hardware pacing，不使用逐 packet sleep。Batch pacer 依 local monotonic elapsed 計算累積 wire-byte budget。雙向結果只有在兩方向共享同一 `start_at` 時才能合併，A→B 與 B→A 的 throughput、packet、loss、jitter、CPU 仍各自保存；idle RTT 與 loaded RTT 也維持不同欄位。

UDP socket compatibility engine 的 sender 在 measurement 前配置並重複使用 datagram buffer，以 burst boundary 檢查 deadline。Receiver 以完整 source IP+dynamic port、session ID 與 stream ID 作 data-plane dispatch boundary，不符合者只計入 unauthorized counter；格式、flags 或 payload length 不符則計入 invalid counter。Matching END 可正常結束，但 END 本身仍可能遺失，因此已收到有效資料後的 idle timeout 會保留結果並標示 `graceful_end=false`，不丟棄量測。

Speed lifecycle 固定為 NEGOTIATE → PREPARE → READY → WARMUP → MEASURE → COOLDOWN → FINALIZE → RESULT。READY 是 local/remote 雙端 barrier，重複訊息冪等；Node `StartTest` 只設定不可變的 `start_at`，本機 scheduler 到時才切換 Running。Wall clock 不參與 elapsed 計算，measurement window 只接受不倒退且非零的 local monotonic timestamps。

Node control plane 使用 TCP + mutual TLS 1.3 + 12-byte NTCP frame + Protobuf envelope。TLS configuration 明確只註冊 TLS 1.3；control payload 在配置前先檢查 1 MiB 上限。Protocol major 必須一致，minor 選擇最高交集，capability 依 ID 與各自版本範圍協商，不從 app version 推測。

Node session coordinator 在 prepare 階段以 port `0` 向 OS 取得 TCP 或 UDP dynamic ephemeral port，產生 256-bit random authorization tag，並綁定 session ID、source Node、source/destination endpoint、protocol 與 expiration。UDP sender port 必須先配置並經 TLS control plane 傳送；coordinator 交付的 socket 與 receiver config 可直接進入 Speed Engine。相同 operation ID 只有 request 完全一致時才回傳原始結果，不配置第二個 endpoint；不同 payload 重用 ID 會明確拒絕。

Resource Manager 原子取得 session 所需的全部 claims。DPDK port/queue、pinned CPU、lossless writer 與 data port 強制 exclusive；NUMA memory、Huge Pages 與 capture storage 必須設定有限 capacity。Pending、Active、Releasing、Failed 狀態都持續占用資源，只有完成 Released 後才能由其他 session 使用。

Benchmark/certification authority 位於獨立 `benchmark` crate。計畫固定執行 Environment、NIC、RX、TX、Bidirectional、Packet Matrix、Flow Matrix、Duration、Analysis 與 Result phases，並拒絕缺少 64/128/256/512/1024/1518/9018B 或 1/16/256/4096/high-cardinality flow 的 profile。Environment snapshot 必須包含 OS、kernel、CPU/frequency、NUMA、memory、Huge Pages、NIC/PCIe/firmware/driver、DPDK/backend、MTU、queues、RSS 與 offloads；完整平台組合以 length-delimited SHA-256 形成 certification key，不能只按 NIC 型號認證。

Linux environment collector 直接讀取 `/etc/os-release`、procfs 與 sysfs，並以 interface→PCI canonical identity 防止選錯裝置。Interface/PCI identifiers 先做 path-safe validation。Sysfs 無法可靠證明的 DPDK version、RSS 與 offloads 只接受 backend API 已驗證的輸入；缺少時保留 `None`/warning，使 certification key 無法產生。Collector 支援 injected sysroot，讓 PCIe、firmware、driver、NUMA、memory、Huge Pages、MTU 與 queue 探測可做無特權 fixture 測試。

100G evaluator 固定輸出 Gate A–J：Link、NUMA、Queue、Throughput、Drop、CPU、Stability、Thermal、Analyzer 與 Reproducibility。Throughput、drop、duration、analyzer 與 dispersion 門檻只能由已驗證的 POC policy 提供；policy 缺失時相關 gate 為 `not_evaluated`，最高只能顯示 Validated，無效 policy 則明確失敗。Thermal throttling 永遠保存 condition。只有完整環境、明確 policy 且十個 gate 全部 PASS 才能顯示 100G Certified。

Benchmark evaluator 位於 application/benchmark layer；Storage 不再依賴 evaluator，也不在 transaction 內重新執行 gates。Application layer 先產生 environment JSON、platform combination SHA-256、已驗證 result JSON、明確的 `BenchmarkCertificationState` 與 artifact checksum，再交給 Storage。Storage 只驗證 JSON/hash/checksum 形狀、checksum 是否符合 canonical artifact、certification ID invariant 與 SQLite transaction；只有 `100g_certified` 且有 certification ID 時，才同時寫入 `hardware_profile`、`benchmark_result` 與 `hardware_certification`。任何一步失敗會回滾全部 rows；同一 hardware profile ID 只能綁定同一平台組合 hash。實際硬體 benchmark executor 尚未掛接前，`perf.benchmark` 仍只驗證 plan 並回傳 backend 未建置，不會產生或保存 synthetic certification。

Domain 對 capability parameters、speed result 與 benchmark profile parameters 使用 `ValidatedJson` opaque wrapper。它保留 backend-specific keys 的延伸性，但在 domain deserialize seam 拒絕非 object JSON，避免 scalar/array 直接穿透到核心模型。`dpdk-sys`、`dpdk-safe`、Linux AF_XDP、Windows RIO、Linux affinity 與 Windows `platform-auth` 等 native/FFI crate 以 crate-level lint 明確隔離 unsafe code；其餘純 Rust workspace crate 維持 `unsafe_code = forbid`。

Benchmark runner 是單次使用的 deterministic orchestrator，依固定 phase order 呼叫 backend executor，並以 local monotonic timestamps 保存每一階段。Cancel 只在 phase boundary 生效，已完成 phase 保留、其餘明確標記 skipped。Recoverable issue 繼續、Degraded issue 完成但降低整體狀態、Fatal issue/錯誤立即停止；每個 phase evidence 上限 1 MiB。Runner 不自行 sleep 或產生 throughput，duration 與硬體 I/O 必須由真正 executor 實作。

NIC probe 會在 Linux 依 sysfs device path 回報 `bus_type`（`usb`、`pci` 或 `unknown`），只有符合合法 PCI BDF 的 target 才填入 `pci_address`；USB、virtual、缺少 device 或 malformed path 不會被猜測成 PCI。此分類是唯讀 metadata，不等於 hot-plug、auto-provision 或實體硬體驗收。DPDK preflight 每次使用最新 capability snapshot，檢查 runtime、PCI device、userspace driver、RX/TX queues、NUMA locality、Huge Pages 與 CPU affinity。Linux dataplane 會從 default route 唯讀解析 management interface，再映射到最新 NIC PCI evidence；若 control plane management NIC 與目標相同，由 `MANAGEMENT_NIC_PROTECTION` gate 直接拒絕。其他平台或無法解析時不猜測管理介面。Queue planner 會輸出同 NUMA 的 one-queue/one-worker contiguous ownership，且 `QueuePlan::validate` 在交給 native orchestration 前再次拒絕重複 CPU 或不連續 queue ID。一般模式可在部分條件下 degraded 執行，但任何 warning 都使結果不可認證；certification mode 將 NUMA、driver 與 Huge Page 缺失提升為 failure。

DPDK queue planner 不以 logical CPU 總數猜測可用資源；它只接受 Resource Manager 已排除 OS、control、GUI、storage 與其他 session 後的 CPU 集合。Auto queue 數量取 NIC RX capacity、同 NUMA 可用 core 與 configured maximum 的最小值，並建立一個 RX queue 對一個唯一 worker core 的穩定 mapping。Mbuf pool 大小由 RX/TX descriptors、queue 數、burst、pipeline depth、capture buffers 與 safety margin 以 checked arithmetic 計算，不使用固定的 8192 mbufs。

Native DPDK port wrapper 透過集中 C shim 讀取 `rte_eth_stats` 的 RX/TX、bytes、missed、error 與 RX mbuf failure counters，以及 `rte_eth_xstats` 的 driver-specific/per-queue counters；這些 hardware evidence 與 worker-local counters 分開輸出，不把其中一者冒充另一者。Linux native RX/TX worker 啟動時會將 calling thread pin 到規劃的 CPU 0，並將 affinity syscall failure 視為 preflight error；Linux environment collector 也只接受固定格式的 RSS evidence，並在宣告 queue count 與 sysfs RX queue 數不一致時保留缺證據 warning；xstats 名稱與順序可由控制面快取，fast path 不做字串查詢。

AF_XDP capability probe 只回報已觀察到的 Linux BPF filesystem/NIC surface；zero-copy capability 是獨立欄位，沒有 driver-level evidence 時維持 false，不能由基本 kernel surface 推論。
AF_XDP session 啟動前另須通過 interface、queue capacity 與 zero-copy preflight；要求 zero-copy 時 evidence 缺失會直接拒絕，compatibility mode 的未驗證 zero-copy 只標為 warning。
`nettool-backend-af-xdp` 已集中 Linux `socket`/`setsockopt`/`bind`、UMEM、XDP ring、XSKMAP 與 redirect-link FFI，配置 page-aligned UMEM、`XDP_UMEM_REG`、RX/TX/FILL/COMPLETION ring 與 zero-copy bind flag；Linux build 可標示 implementation available，但 interface/driver/zero-copy runtime preflight 未通過時仍不可執行。
UMEM 對外只產生經 headroom/frame-index/length 驗證的 `FrameDescriptor`，避免後續 worker 直接構造越界 offset。
`FrameRing` 採單一 producer/consumer ownership 與 bounded non-blocking push/pop；它與 kernel mmap ring 分開，供測試與上層 worker 使用。
AF_XDP socket setup 現可查詢 kernel `XDP_MMAP_OFFSETS`，取得四個 ring 的 producer/consumer/descriptor/flags offsets；mapping 的生命週期由 RAII 管理，各 ring owner 由 packet worker 明確持有。
`XdpRingMappings` 依上述 offsets 建立 RX/TX/FILL/COMPLETION 的 page-aligned shared mapping，並以 RAII 在 socket teardown 釋放；mapping 提供 bounds-checked producer/consumer index 與 `xdp_desc` volatile accessors。初始化流程會先確認 FILL ring producer/consumer 都為零，再以 UMEM frame base addresses 填入 descriptors 並發布 producer index。
`AfXdpWorker` 將四個 ring 的 producer/consumer ownership 收斂為單一 worker：RX/COMPLETION 只 consume，TX/FILL 只 produce，所有 descriptor 先做 UMEM bounds check，容量不足時只提交可容納前綴。TX 提供與 socket 綁定的 `submit_tx_and_kick`，以 zero-length `sendto` 喚醒 kernel；Socket 另提供只等待 RX readiness 的 bounded `poll`，timeout 與 error/hangup 分開回報；它仍不負責 XDP redirect 或 packet scheduling。
`receive_once` 將該 wait 與 RX drain 綁在同一操作，timeout 回傳零筆且不修改 ring；上層仍需負責 packet accounting、XDP redirect 與 session scheduling。
`receive_packet_into` 依 `XDP_PKT_CONTD` 聚合 multi-buffer RX chain，只有遇到 chain 結尾且 output 足夠時才發布 consumer；因此 jumbo packet 不會被半包交給 parser。
Linux backend 另以 raw `bpf` syscall 建立 `BPF_MAP_TYPE_XSKMAP`，限制 max entries 並以 bounded queue ID 更新 socket FD；map 與固定最小 redirect XDP program/link 均由 RAII 管理，失敗時不降級，仍須通過 NIC/zero-copy runtime preflight。
Agent 的 `dataplane.probe` 與 `perf.backend` 現在分開輸出 RIO platform capability 與 implementation availability；Winsock RIO 未連結時維持 unavailable，不會由 Windows 平台本身推論可執行。
`perf.backend` 另輸出 RIO preflight 的 stable gate IDs、severity 與 message；`can_run` 只有 Windows platform 與 RIO implementation 兩項都通過時為 true。
AF_XDP XSKMAP 現可載入固定最小 eBPF program（讀取 `rx_queue_index` 後呼叫 `bpf_redirect_map`）並以 `BPF_LINK_CREATE` 綁定 netdev；program/link 失敗不降級，且以 RAII 關閉 fd。這仍不替代 NIC driver zero-copy preflight 或完整 session scheduler。
Program load 使用完整 `bpf_attr` attach fields、target interface index 與 verifier log buffer；kernel verifier/permission 失敗會直接回傳 stable kernel error。
Windows RIO 另由 `nettool-backend-rio` 管理固定 registered buffer、frame descriptor 與 bounded request/completion queue；此層不會在每次 request register/deregister buffer。Windows-only adapter 已集中封裝 `RIORegisterBuffer`/`RIOReceive`/`RIOSend`/`RIODequeueCompletion`，但尚未在 Windows runner 實機驗證，因此 `is_backend_built()` 保持 false，不把 FFI 邊界誤報為可執行 backend。
RIO resource model 另以 `RioQueuePair` 分離 request/completion ownership；completion queue 滿時不會先移除 request descriptor，避免在 backpressure 下遺失 completion evidence。
Windows-only `RioApi::discover` 透過 `WSAIoctl(SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER)` 取得 `RIO_EXTENSION_FUNCTION_TABLE`，並以 lifetime-bound registration token 包裝 `RIORegisterBuffer`/`RIODeregisterBuffer`；目前尚未在 Windows runner 實機驗證，故 `is_backend_built()` 仍保持 false。
Registered buffer 另提供 bounds-checked `RioBufferSlice`，對應官方 `RIO_BUF` 的 buffer ID/offset/length，避免 request path 重新註冊或建立越界 slice。
Windows-only RIO adapter 另提供 completion queue 與 request queue 的 lifetime-bound handle wrapper；completion queue drop 時呼叫 `RIOCloseCompletionQueue`，request queue 生命週期則明確繫結所屬 socket，且建立時固定 receive/send outstanding limits。
`register_registered_buffer` 以 `RegisteredBuffer` borrow 綁定 native registration lifetime；raw pointer registration 保留為明確 `unsafe` 邊界，避免 buffer 在 RIO request 完成前被釋放或搬移。

Linux 另提供 root-only `install-helper.sh` 完成 helper、env、systemd unit 安裝與 service 啟動；macOS/Windows packaging 先以 allowlist staging installer 安裝 user-space binaries，staging 完成後才替換現有目錄，並保留 backup 供失敗恢復。macOS/Windows privilege helper 的註冊與平台簽章不由此腳本猜測或繞過。

Rust/DPDK 邊界分成 `dpdk-sys` 與 `dpdk-safe`。前者以 feature-gated C shim 包住包含 inline API 的 EAL、ethdev、mempool、RX burst 與 mbuf free，所有 `extern "C"` declarations 集中於此；後者以 process-global EAL ownership、RAII mempool/port、不可跨執行緒移動的 queue handle 與 callback-scoped borrowed packet view 約束生命週期。Burst guard 在正常、錯誤及 panic unwind 路徑都釋放未消耗 mbufs。`ffi-api` 只供無 SDK 的編譯檢查，不代表 backend 可執行；只有 `native-dpdk` 會透過 `pkg-config libdpdk` 編譯 shim 並使 implementation availability 成立。

RX 與 TX queue 都經 ownership registry 原子式 claim，同一 port/queue 在前一個 handle Drop 前不能重複取得。TX template burst 從既有 mempool bulk allocation，不進行系統 heap per-packet allocation；PMD 接受的 mbuf ownership 轉交 NIC，未送出或 template 配置失敗的 mbufs 在 C shim 當場釋放。

Raw generator profile 明確區分含 FCS 的 Ethernet wire size 與交給 NIC 的 template length，驗證 IPv4/IPv6 family、IP/port ranges、flow matrix cardinality 與 packet rate。理論 packet rate 固定使用 Ethernet frame 加 8-byte preamble/SFD 與 12-byte IFG，僅作 wire-rate 基準，不冒充實測。

Packet hot path 使用 borrowed `PacketView` 與 worker-local integer counters，不執行 JSON、SQL、filesystem、DNS、logging 或 heap allocation。低頻 aggregator 合併 counters 並計算 pps/bps/Mpps/Gbps。Drop 類別固定分為 NIC、driver、capture、ring、analyzer、application 與 sequence-based network inferred loss。

Fast-path parser 以 borrowed slices 完成 Ethernet、802.1Q/QinQ、ARP、IPv4、IPv6 extension headers、ICMP/ICMPv6、TCP 與 UDP 的 bounds-checked 解析；未知 protocol 保留原始 protocol number，不在 fast path 進行字串轉換或 deep parsing。Canonical five-tuple 將雙向流量映射至相同 stable shard，每個 worker 持有自己的 flow state，未引入全域 `HashMap + Mutex`。

每個 worker-local flow table 都要求非零 maximum flow count 與 idle timeout，且最多允許 1,000,000 entries；建立時以 `try_reserve` 預留 bounded capacity，避免高流量期間 rehash 或無界配置。一般 lookup 只觸碰目標 entry；新 flow 建立時先清除 idle entries，容量仍滿則以最久未使用時間進行 LRU-like eviction，因此 active entries 不會超過設定上限。Timing wheel 是否取代建立時掃描，保留給 high-cardinality POC benchmark 決定。

TCP analyzer 分方向保存 `next_seq`、`last_ack`、window、SYN/FIN/RST 與 retransmission/out-of-order counters，並區分 observed retransmission、suspected retransmission、out-of-order 與 duplicate ACK。只要 capture drop 非零，retransmission 結果就不會維持 HIGH confidence。UDP socket receiver 使用預先配置的 bounded sequence window，避免每個 packet 將 sequence 插入無界 set；完整 set tracker 僅保留給相容性/離線分析。Native DPDK RX/capture 命令已可用 bounded burst 掛接此 worker 並寫入 PCAPNG；CPU pinning 已接上 Linux native RX/TX calling thread，native RX/TX/capture 啟動前也會消費最新 probe snapshot 產生並驗證 queue plan，但 RSS/多 worker NUMA orchestration 與高流量 benchmark 仍未完成。

Capture path 由 bounded non-blocking queue 與獨立 writer ownership 組成；queue 滿時 RX worker 只增加 local `capture` drop，不等待檔案 I/O。Capture policy 支援 metadata-only、128-byte header、指定 snaplen 與 full packet。Writer 優先提供帶 interface、nanosecond timestamp 與 queue metadata 的 PCAPNG，也保留 nanosecond PCAP；rotation 可同時受 size、duration 與 retained file count 限制。Agent 的 `packet.capture.start/stop` 以 `packet_session` 保存 lifecycle，並只管理由自身啟動的 dataplane child process。Full capture 必須以目標 storage 的實測 write rate 與可用容量通過 guard，否則回傳 `LOSSLESS_CAPTURE_NOT_CERTIFIED`。

Run-to-completion `PacketWorker` 以 backend `BurstSource` 作 ownership boundary，在單一 worker 內串接 RX counters、可依 protocol/IP/port 限制的 filter、獨立 capture branch、bounds-checked parser、bounded flow table 與 TCP analyzer。Capture 在 filter 與 parsing 後分支，因此不符合 filter 的封包不會寫入檔案，malformed packet 在未設定 filter 時仍可被保存；backend buffer 只在 callback 期間借用。Stop token 只在 burst boundary 檢查。Sampling 使用明確的 `AnalysisCoverage::Sampled { one_in }`，結果同時帶 coverage 並累計 sampled-out packets，consumer 不得呈現為完整分析。

Offline capture backend 實作相同 `BurstSource` boundary，以 bounded reusable buffer 串流解析 PCAP 與 PCAPNG，不把整個 capture 載入記憶體。它處理兩種 endian、microsecond/nanosecond PCAP timestamp、PCAPNG interface timestamp resolution 與 queue comment metadata；只接受 Ethernet link type，並在配置記憶體前驗證 block、captured length、snaplen 與 wire length。EOF 由 backend 明確通知 worker，使離線分析可自然結束。

Confidence threshold 在硬體 POC 前保持未固定；有 analysis-path drop 且沒有已核准 threshold 時保守標記 LOW，不會維持 HIGH 或自行填入數值。Counter/NIC reset、backend failure 或 clock discontinuity 直接標記 INVALID。

Agent 本機 Action envelope 的 `dry_run` 旗標已由 runtime 實際處理：非 privileged action 回傳 payload hash、permission metadata 與「未執行副作用」plan；需要 privileged helper 的 action 則將旗標傳入 helper dry-run path。

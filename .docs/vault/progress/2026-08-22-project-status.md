# 專案開發進度（2026-08-22）

## 已完成且可由本機驗證

- Agent、CLI、GUI 共用 typed Action registry；Node pairing 的 DER、fingerprint、TLS server name、identity replacement 與 out-of-band fingerprint confirmation 均 fail closed。
- Profile、Hosts、IP/DHCP、DNS、Safe Apply、Helper bounded IPC、Node inventory/revoke、socket TCP/UDP upload/download/bidirectional lifecycle 均已接通，並有 SQLite persistence、idempotency 與 loopback 測試。
- Packet parser、bounded flow table、PCAP/PCAPNG offline analyzer、capture lifecycle、protocol/filter/drop/confidence 統計已完成；UDP runtime sequence tracking 使用固定 65,536-slot window。
- Linux/macOS/Windows 的唯讀 interface probe、平台命令 builder/state reader、macOS Unix helper、Windows Named Pipe helper authentication/runtime 邊界已建立；Linux helper installer 與 staging installer allowlist/rollback 亦已完成。
- AF_XDP 已完成 Linux FFI、UMEM、四 ring mmap、FILL/COMPLETION、multi-buffer RX、TX kick、XSKMAP 與 eBPF redirect RAII 邊界；RIO 已完成 registered buffer、queue pair、send/receive/dequeue 與 owner-borrow API 邊界。
- DPDK queue/NUMA/affinity/mempool preflight、native RX/TX/capture worker 與 hardware stats/xstats schema 已完成；未連結 SDK 時明確 fail closed。
- Agent/CLI `dry_run` 已完整串接：CLI 可在任意位置使用 `--dry-run`，Agent 回傳 bounded plan、permission/idempotency metadata 與 payload SHA-256；privileged action 將旗標傳給 Helper 驗證，不執行副作用。
- `speed.run` 已修正 accelerated backend fail-closed 邊界；DPDK、AF_XDP、RIO executor 未掛接時不會誤用 socket worker 或建立遠端 session。
- `speed history` parser 已支援 `--limit`/`--format csv` 任意順序，並拒絕缺值、未知格式與重複旗標。
- CI 已新增 Linux AF_XDP target compile gate 與 Windows RIO boundary test gate；跨平台實機功能仍需硬體 runner，CI 不會把 host syntax test 誤標為 certification。
- Agent dry-run 已加入無副作用 payload/schema validation；錯誤 JSON 或不存在的 benchmark profile 會在產生 plan 前 fail closed，並有回歸測試。
- dry-run plan 的 permission metadata 已固定為 snake_case wire values，並加入回歸斷言。
- `speed.run` 對 socket executor 的 auto-tune、latency-under-load 與 NUMA 選項已 fail closed；CLI reference 已說明目前限制。
- README、CLI reference、Architecture、Protocol specification 與 requirement traceability 已同步上述公開行為。

## 驗證

```text
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --quiet
```

以上三項最近一輪均通過；另已通過 Agent/CLI/packet/speed/AF_XDP targeted tests 與 dataplane/agent `ffi-api` Clippy。

## 尚待外部驗收

- Linux runner：AF_XDP kernel mmap、eBPF attach、zero-copy driver、CPU affinity 與實際 NIC traffic。
- Windows runner：RIO Winsock linker/API、Named Pipe ACL、privileged helper end-to-end 與 throughput。
- DPDK SDK、VFIO/hugepage、RSS/NUMA 多 worker 與真實 PMD counters。
- macOS/Windows code signing、正式 installer、ACL 與 rollback 實機流程。
- 100GbE sustained throughput、small-packet worst case、capture storage/drop、thermal/reproducibility 與 A–J certification evidence。

這些依賴外部作業系統、硬體與實驗室環境；在取得證據前，追蹤矩陣維持「部分完成／實機待驗」，不宣稱整體或 100GbE Certified 已完成。

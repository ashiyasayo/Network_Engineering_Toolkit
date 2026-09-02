# 規格追蹤矩陣

本文件把目前可由 repository 證明的主要規格項目，連到實作、測試與驗收狀態。`實機待驗` 不等同功能完成；在 Linux/Windows 硬體 runner、100GbE NIC 與實測證據可取得前，不標示為 Certified。

對應 `.doc/跨平台網路工具－100GbE 架構需求增補規格 v0.3.md` 的 MUST-01 至 MUST-32；下表將相鄰項目合併呈現，但每個範圍仍須依原規格個別驗收。

| 規格項目 | 適用設備 | 主要實作 | 自動化證據 | 狀態 |
| --- | --- | --- | --- | --- |
| Agent/GUI/CLI typed Action | 一般裝置 | `crates/action`、`apps/agent`、`apps/cli`、`apps/gui` | workspace tests、Action registry uniqueness | 已完成（實機 GUI 待驗） |
| Native desktop shell / installer | 一般裝置 | `apps/desktop`、`packaging/{macos,windows,linux}`、`.github/workflows/release.yml` | Tauri config、固定 allowlist staging scripts、portable bundle smoke test、stable signing gate | 殼層、staging、portable ZIP 與簽章 gate 完成；外部憑證實際執行、notarization、平台實機待驗 |
| Profile / Hosts / Safe Apply | 一般裝置（需 Helper） | `crates/storage`、`crates/helper-core`、`crates/helper-server` | storage/helper tests、rollback/idempotency tests | 已完成（平台實機待驗） |
| Node mTLS / trust reload | 一般裝置 | `crates/node`、`crates/storage`、`apps/agent` | Node protocol/Agent integration tests | 已完成 |
| Out-of-band fingerprint pairing | 一般裝置 | CLI `--confirm-fingerprint`、GUI checkbox、Storage gate | `rejects_pairing_without_out_of_band_fingerprint_confirmation` | 已完成 |
| Socket speed lifecycle | 一般裝置；長時間／多 Node 建議伺服器 | `crates/speed`、`crates/node`、`apps/agent` | workspace ignored runtime tests：Agent 1、Node 6、speed 3；mutual-TLS、authorized TCP/UDP、bidirectional 與 SQLite persistence | 已完成 |
| Offline packet analysis / capture persistence | 一般裝置 | `crates/packet`、`crates/backend-pcap`、Agent capture lifecycle | parser/PCAPNG/session tests | 已完成 |
| Linux AF_XDP zero-copy path | **伺服器專用** | `crates/backend-af-xdp` | ring/UMEM/BPF unit tests | 部分完成；Linux NIC/driver 實機待驗 |
| Native DPDK RX/TX/capture | **伺服器專用** | `crates/dpdk-safe`、`crates/backend-dpdk`、`apps/dataplane` | FFI compile check、queue/preflight tests | 部分完成；DPDK SDK/NIC 實機待驗 |
| Windows RIO path | **伺服器專用** | `crates/backend-rio` | Windows cfg syntax/resource tests | FFI 邊界完成；Windows linker/API/throughput 待驗 |
| macOS/Windows privileged helper | 一般裝置（需 Helper） | `crates/helper-core`、`apps/helper`、packaging scripts | parser/builder/security tests、release signing gate | wiring 部分完成；Helper ACL、實機 rollback 與正式 installer integration 待驗，release signing gate 已建立 |
| 100GbE certification matrix | **伺服器專用** | `crates/benchmark`、`crates/storage` | certification gate/property tests | policy/schema 完成；硬體 baseline、NUMA、drop、sustained benchmark 待驗 |

## MUST 項目狀態索引

| MUST | 狀態 |
| --- | --- |
| 01–09（GUI/CLI、Profiles、Safe Apply、Helper、Pairing） | 邏輯與 host 測試完成；平台實機待驗 |
| 10–16（控制/資料平面、TCP/UDP/Bidirectional、Packet） | socket 與 offline/capture lifecycle 已驗證 |
| 17（loss/drop/confidence 分類） | parser、capture drop 與 analyzer confidence 已驗證 |
| 18–24（100G 架構、queue、affinity、NUMA、ring、batch、allocation） | 核心資料結構與 preflight 已完成；多 worker/硬體待驗 |
| 25–27（benchmark、capability detection、backend selection） | policy、environment snapshot、stable gate 已完成；hardware phase executor 待驗 |
| 28–30（AF_XDP、DPDK、Windows backend） | FFI/resource boundaries 部分完成；Linux/Windows runtime 待驗 |
| 31（capture/analyzer confidence） | 已由 packet worker 與 capture metadata 驗證 |
| 32（100G certification matrix） | persistence/schema/gates 完成；實測 certification 證據待驗 |

## 驗證命令

```text
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --quiet
cargo test --workspace -- --ignored  # 需允許 dynamic socket bind 的受控 runner
```

這些命令證明 host 可編譯與邏輯測試通過，不取代規格要求的 Windows/Linux 實機與 100GbE hardware-lab evidence。

實機 command、環境快照與 certification gate 的交接流程請參考 [Hardware Acceptance Runbook](HARDWARE_ACCEPTANCE.md)。

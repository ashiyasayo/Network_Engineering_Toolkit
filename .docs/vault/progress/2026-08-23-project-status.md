# 專案開發進度（2026-08-23）

## 本次新增證據

- 以允許 dynamic socket bind 的受控 runner 執行 `cargo test -p nettool-node -- --ignored`，Node 的 6 個 TCP/UDP receiver、sender、bidirectional 與 idempotent lifecycle tests 全部通過。
- 同一受控 runner 執行 `cargo test -p nettool-agent --bin nettool-agent -- --ignored`，mutual-TLS TCP download、authorized data-plane 與 SQLite completed persistence integration test 通過。
- 同一受控 runner 執行 `cargo test -p nettool-speed -- --ignored`，TCP real-data、authorized streams 與 fixed-rate UDP loopback tests 全部通過（3 passed）。
- `cargo test --workspace -- --ignored` 在受控 runner 全部通過：Agent 1、Node 6、speed 3 個 runtime tests，其他 crate 無失敗 ignored tests。
- 最終 host/FFI gate 亦通過：workspace Clippy、dataplane `ffi-api` Clippy、Agent `ffi-api` Clippy、workspace format 與 workspace tests 全部成功。
- `cargo test --workspace --all-features` 已檢查；預期因本機沒有 `libdpdk.pc` 而由 `native-dpdk` build script fail closed，錯誤明確指向缺少 DPDK SDK，非 Rust/FFI 編譯回歸。
- `docs/REQUIREMENT_TRACEABILITY.md` 已回填 workspace ignored runtime test evidence，Socket speed lifecycle 的證據鏈可直接追溯至 Agent/Node/speed 三組測試。
- 未提升權限的本機 sandbox 執行同一命令會得到 `Operation not permitted`；該結果是環境 socket policy，不是測試 assertion failure，不能當作 runtime regression。

## 目前狀態

- Agent/CLI/GUI typed actions、socket speed lifecycle、pairing/trust、Helper Safe Apply、packet analysis/capture、dry-run contract 與 accelerated fail-closed 邊界已通過 host/workspace 測試。
- Linux AF_XDP、DPDK、Windows RIO、平台 ACL/installer 與 100GbE certification 仍需相應 OS、NIC、SDK、driver 與實驗室 runner；本機 macOS ARM 沒有 Linux target 或 Windows toolchain。
- 新增 `docs/HARDWARE_ACCEPTANCE.md`，固定 Linux AF_XDP/DPDK、Windows RIO/helper 與 100GbE A–J gate 的交接命令、pass/fail evidence 與禁止誤標 Certified 的規則。
- Ubuntu CI 的 loopback job 已加入 Agent ignored integration test，與 speed/Node tests 一起驗證 mTLS、SQLite persistence 與 dynamic TCP/UDP lifecycle。
- 新增 Tauri 2 `nettool-desktop` 原生殼層：啟動並管理 Agent/GUI backend，於原生 WebView 顯示既有 Action API Dashboard；不直接執行網路或特權操作。
- 新增 macOS `.app`、Windows release staging、Linux desktop staging 與 desktop entry 安裝資產；正式簽章、notarization、平台實機 ACL 與發行 runner 仍待驗。
- 本機無網路且 Cargo cache 沒有 `tauri` crate，`cargo check -p nettool-desktop --offline` 因缺少 crates.io `tauri` 明確失敗；格式、shell 語法、Tauri JSON 設定與 diff check 已通過。
- 依 desktop review 修正 runtime sidecar 定位、`NETTOOL_DATAPLANE_BIN` 傳遞、GUI `/health` ready check、8765 port collision 與啟動失敗 cleanup；Tauri resources 改由 `prepare-tauri-resources.sh` 在正式 bundling 前 staging。
- 同步修正 Windows/Linux/macOS release manifest、Linux 自訂 prefix 的 desktop entry、installer rollback，以及 CI 的 DMG/MSI/AppImage/deb package matrix 與 artifact upload。

## 最近驗證

```text
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --quiet
cargo test -p nettool-node -- --ignored   # 受控 socket runner：6 passed
cargo test -p nettool-agent --bin nettool-agent -- --ignored   # 受控 socket runner：1 passed
cargo test -p nettool-speed -- --ignored   # 受控 socket runner：3 passed
cargo test --workspace -- --ignored         # 受控 socket runner：Agent 1 + Node 6 + speed 3 passed
```

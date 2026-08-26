# USB 網卡快速設定可行性分析

> 使用情境：網管使用 USB 網卡快速設定並進行網路測試。
> 分析日期：2026-08-24
> 最近複核：2026-08-26（sol 唯讀分析與 Linux NIC bus classification 實作驗證）

---

## 使用情境描述

網管需要：**插上 USB 網卡 → 跑幾條命令 → 開始測試**。

---

## ✅ 專案目前已具備的能力

| 能力 | 對應功能 | 說明 |
|---|---|---|
| **列出網路介面與 bus type** | `nettool interface list` / `show` / `refresh`、`dataplane.probe` | Linux 透過 sysfs path 回報 `bus_type: usb|pci|unknown`，只有合法 PCI BDF 才填入 `pci_address`；macOS/Windows 目前只列舉介面名稱，bus type 為 `unknown`，尚無真實 USB 硬體或 hot-plug 驗收 |
| **設定 IP（靜態/DHCP）** | `nettool ip set` / `nettool ip dhcp` | 經 Helper Safe Apply，含 rollback 保護 |
| **設定 DNS** | `nettool dns set` | 同上 |
| **完整 Profile 套用** | `nettool profile create` → `profile apply` | 可事先建好設定檔，一條命令套用 |
| **測速** | `nettool speed run` | TCP/UDP socket executor 已接入，但需要 trusted paired Node 與 TLS material；尚無本機 loopback 模式 |
| **封包分析** | `nettool packet capture` / `packet analyze` | 離線 PCAP/PCAPNG 分析可用；即時 capture 仍需 native DPDK、硬體與 preflight，不能視為跨平台封包擷取已完成 |
| **Hosts 管理** | `nettool hosts add/remove` | 可搭配測試環境的 DNS mapping |
| **GUI 操作** | `nettool-gui` / `nettool-desktop` | Dashboard + 各功能頁面 |

---

## 🟡 可以做到但不夠「快速」的瓶頸

### 1. 啟動流程太重 — 需要 Agent + Helper 兩個 daemon

目前流程：

```
① 啟動 nettool-agent（常駐 daemon）
② 確認 nettool-helper 已安裝並執行中（root/admin 權限常駐 service）
③ 才能跑 nettool ip set / profile apply 等設定命令
```

沒有**單一命令直接設定網卡**的捷徑。所有操作都必須經 Agent IPC → Helper authenticated transport 的完整鏈路。

### 2. 沒有「USB 網卡友善」的抽象

- 介面識別用的是平台原生名稱（`eth1`、`enx00e04c680001` 等），USB 網卡的名稱在不同系統不可預測
- Linux 現在額外提供 `bus_type`（`usb`、`pci`、`unknown`）作為唯讀分類；這只根據 sysfs device path，不讀 vendor/product database，也不以 MAC/OUI 猜測
- 沒有 **hot-plug 偵測** — 插入 USB 網卡後需要手動 `interface refresh`
- 沒有 **auto-provision** — 不能「偵測到新 USB NIC → 自動套用預設 profile」

### 3. 測速需要雙端 Node pairing

`speed run` 需要兩台機器先完成 mutual TLS pairing（交換 certificate、確認 fingerprint），對「臨時拿 USB 網卡跑測試」的場景偏重。

### 4. 跨平台完成度不一

| 平台 | 網路設定 | 測速 | 封包 |
|---|---|---|---|
| **Linux** | ✅ 完成（NetworkManager） | ⚠️ socket 需 paired Node | ⚠️ sysfs stats/離線分析可用；即時 DPDK 仍需 native/hardware preflight |
| **macOS** | ⚠️ 已接入但未完整驗收 | ⚠️ socket 需 paired Node | ⚠️ 離線分析可用；原生 stats/即時 capture 未接入 |
| **Windows** | ⚠️ executor 已接入但 ACL/rollback/installer 尚未完整驗收 | ⚠️ socket 需 paired Node | ⚠️ 離線分析可用；原生 stats/即時 capture 未接入 |

---

## 📋 要讓網管「快速設定 USB 網卡」，建議增加的功能

| 優先級 | 功能 | 說明 |
|---|---|---|
| **P0** | **Standalone 模式** | 不需 Agent daemon，CLI 直接呼叫平台 API 設定網卡（或嵌入式 Agent） |
| **P0** | **USB NIC 友善識別** | Linux 的 sysfs bus classification 已完成第一階段，回報 `bus_type` 並避免 USB 被誤標成 PCI；vendor/product ID、人類可讀名稱與 macOS/Windows 分類仍待完成 |
| **P1** | **Quick-Setup 一鍵命令** | `nettool quick-setup --interface auto-usb --ip 192.168.1.100/24 --gateway 192.168.1.1 --dns 8.8.8.8` |
| **P1** | **本機 loopback 測速** | 不需 Node pairing 的單機 throughput/latency 基準測試（iPerf 模式） |
| **P2** | **Hot-plug 偵測** | 新 NIC 插入時通知或自動套用 profile |
| **P2** | **精簡 Helper** | 支援臨時提權（sudo prompt）而非必須常駐 root service |

---

## 2026-08-26 複核與第一階段開發結果

sol 的唯讀分析確認原文件高估了 USB 辨識、跨平台設定與即時封包 backend 的完成度；其中 Windows「executor 待完成」已過時，實際狀態是已有 Named Pipe、state reader、netsh 與 Safe Apply 接線，但仍缺完整 ACL、rollback、installer 與實機驗收。

本次依分析完成 Linux 唯讀 NIC bus classification：

- `NicProbe` 與各 NIC JSON 輸出新增 `bus_type`，穩定值為 `usb`、`pci` 或 `unknown`。
- Linux 只在 sysfs device path 的最後一段符合合法 PCI BDF 時填入 `pci_address`；USB path、virtual path、缺少 device 或格式不合法時不猜測 PCI address。
- `interface.list`、`interface.show`、`interface.refresh`、`dataplane.probe`、`perf.topology` 與 `nettool-dataplane probe` 都會傳遞該欄位。
- USB 分類使用純 path fixture 驗證 PCI、USB、virtual/no-device 與 malformed path；未加入 vendor/product database、MAC/OUI 推測、hot-plug、auto-provision 或 quick-setup。

已在 Windows 開發環境完成的自動化驗證：

| 檢查 | 結果 |
|---|---|
| `cargo fmt --all -- --check` | 通過 |
| `cargo test -p nettool-domain` | 2 passed |
| `cargo test -p nettool-backend-dpdk` | 16 passed，含 3 組 bus/path fixture |
| `cargo test -p nettool-agent` | 8 passed、1 ignored（需 loopback socket 權限） |
| `cargo test -p nettool-dataplane` | 8 passed |
| `cargo check -p nettool -p nettool-agent -p nettool-backend-dpdk` | 通過 |
| `git diff --check` | 通過 |

上述結果不能替代 Linux kernel/sysfs、真實 USB NIC 插拔、NetworkManager、Windows ACL/rollback 或 native DPDK 硬體驗收；目前只能確認分類規則與輸出合約已具備可測試的第一步。

## 結論

專案的核心技術棧（介面偵測、IP/DNS 設定、Safe Apply、測速、封包分析）已有多數基礎元件，但它是為「管理多台機器間的高速網路測試」設計的，不是為「網管插上 USB 網卡快速跑通」設計的。本次已完成 Linux 唯讀 bus classification，修正 USB sysfs path 可能被誤報為 PCI 的風險；這不等於 USB 網卡快速設定流程已完成。

主要落差仍在於 **UX 流程過重**（需要啟動 daemon、pairing）與跨平台/硬體驗收，而非只有介面列舉缺失。後續若要達到原始情境，仍需先完成 P0/P1 的 standalone、quick-setup、本機 loopback，以及 Linux 以外的 USB 識別與實機驗收。

# USB 網卡快速設定可行性分析

> 使用情境：網管使用 USB 網卡快速設定並進行網路測試。
> 分析日期：2026-08-24

---

## 使用情境描述

網管需要：**插上 USB 網卡 → 跑幾條命令 → 開始測試**。

---

## ✅ 專案已經具備的能力

| 能力 | 對應功能 | 說明 |
|---|---|---|
| **偵測 USB 網卡** | `nettool interface list` | 透過 sysfs (Linux)、`ifconfig` (macOS)、`Get-NetAdapter` (Windows) 列出所有 NIC，USB 網卡插入後會出現 |
| **設定 IP（靜態/DHCP）** | `nettool ip set` / `nettool ip dhcp` | 經 Helper Safe Apply，含 rollback 保護 |
| **設定 DNS** | `nettool dns set` | 同上 |
| **完整 Profile 套用** | `nettool profile create` → `profile apply` | 可事先建好設定檔，一條命令套用 |
| **測速** | `nettool speed run` | TCP/UDP socket 測速已可運作 |
| **封包分析** | `nettool packet capture` / `packet analyze` | PCAP/PCAPNG 擷取與分析 |
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
- 沒有 **hot-plug 偵測** — 插入 USB 網卡後需要手動 `interface refresh`
- 沒有 **auto-provision** — 不能「偵測到新 USB NIC → 自動套用預設 profile」

### 3. 測速需要雙端 Node pairing

`speed run` 需要兩台機器先完成 mutual TLS pairing（交換 certificate、確認 fingerprint），對「臨時拿 USB 網卡跑測試」的場景偏重。

### 4. 跨平台完成度不一

| 平台 | 網路設定 | 測速 | 封包 |
|---|---|---|---|
| **Linux** | ✅ 完成（NetworkManager） | ✅ socket | ✅ sysfs + DPDK |
| **macOS** | ⚠️ 已接入但未完整驗收 | ✅ socket | ❌ unsupported |
| **Windows** | ⚠️ executor 待完成 | ✅ socket | ❌ unsupported |

---

## 📋 要讓網管「快速設定 USB 網卡」，建議增加的功能

| 優先級 | 功能 | 說明 |
|---|---|---|
| **P0** | **Standalone 模式** | 不需 Agent daemon，CLI 直接呼叫平台 API 設定網卡（或嵌入式 Agent） |
| **P0** | **USB NIC 友善識別** | 用 vendor/product ID 或 MAC prefix 標記為 USB 裝置，給人類可讀名稱 |
| **P1** | **Quick-Setup 一鍵命令** | `nettool quick-setup --interface auto-usb --ip 192.168.1.100/24 --gateway 192.168.1.1 --dns 8.8.8.8` |
| **P1** | **本機 loopback 測速** | 不需 Node pairing 的單機 throughput/latency 基準測試（iPerf 模式） |
| **P2** | **Hot-plug 偵測** | 新 NIC 插入時通知或自動套用 profile |
| **P2** | **精簡 Helper** | 支援臨時提權（sudo prompt）而非必須常駐 root service |

---

## 結論

專案的核心技術棧（介面偵測、IP/DNS 設定、Safe Apply、測速、封包分析）已經齊備，但它是為「管理多台機器間的高速網路測試」設計的，不是為「網管插上 USB 網卡快速跑通」設計的。

主要落差在於 **UX 流程過重**（需要啟動 daemon、pairing）而非功能缺失。如果願意投資 P0/P1 的功能（standalone 模式 + quick-setup 命令），這個專案完全可以成為網管的日常工具。

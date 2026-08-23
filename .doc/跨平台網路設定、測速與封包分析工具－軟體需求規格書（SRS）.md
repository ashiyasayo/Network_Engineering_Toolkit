# 跨平台網路設定、測速與封包分析工具
## Software Requirements Specification（SRS）

版本：0.1 Draft  
狀態：需求草案

---

# 1. 專案概述

## 1.1 專案目的

建立一套跨平台網路管理工具，提供圖形介面（GUI）與命令列介面（CLI），讓使用者可以快速完成：

- 網路 IP 設定切換
- 多組網路設定檔保存與管理
- Hosts 檔案管理
- Node 間網路效能測試
- 網路封包狀態分析
- 網路介面與連線狀態診斷

系統主要訴求為：

1. **快速**
2. **跨平台**
3. **GUI / CLI 功能完全對應**
4. **設定可保存、快速切換及還原**
5. **低操作成本**
6. **適合工程師進行網路測試與故障排除**

---

# 2. 支援平台

系統至少必須支援以下平台。

| 平台 | 架構 | GUI | CLI |
|---|---|---:|---:|
| Windows | x86-64 | 必須 | 必須 |
| macOS | Apple Silicon ARM64 | 必須 | 必須 |
| macOS | Intel x86-64 | 必須 | 必須 |
| Linux KDE | x86-64 | 必須 | 必須 |

Linux 第一階段以 KDE 桌面環境為主要支援目標。

Linux 底層網路管理需透過抽象層處理，不得將 GUI 與特定 Linux 發行版直接耦合。

---

# 3. 設計原則

## 3.1 單一核心架構

GUI 與 CLI 不得各自實作網路控制邏輯。

架構必須採用：

```text
                 ┌─────────────┐
                 │     GUI     │
                 └──────┬──────┘
                        │
                        ▼
┌─────────────┐   ┌───────────────┐
│     CLI     │──▶│  Core Engine  │
└─────────────┘   └───────┬───────┘
                          │
          ┌───────────────┼────────────────┐
          │               │                │
          ▼               ▼                ▼
   Network Adapter    Hosts Manager   Network Tools
          │                                │
          ▼                                ▼
   Platform Layer                  Speed / Packet
          │                          Analysis
 ┌────────┼────────┐
 ▼        ▼        ▼
Windows  macOS    Linux
```

所有核心功能均由 Core Engine 提供。

GUI 僅負責：

- 顯示
- 輸入
- 操作流程
- 狀態呈現

CLI 亦呼叫相同 Core Engine。

---

# 4. 功能需求

# 4.1 網路介面偵測

程式啟動後必須能自動取得系統內所有可管理的網路介面。

至少顯示：

- 介面名稱
- Friendly Name
- MAC Address
- IPv4
- IPv6
- Subnet Mask / Prefix
- Default Gateway
- DNS Server
- DHCP 狀態
- Link Status
- Link Speed
- MTU
- Interface Index
- 是否為實體介面
- 是否為虛擬介面

例如：

```text
Ethernet
Intel I225-V

Status:
Connected

IPv4:
192.168.10.23/24

Gateway:
192.168.10.1

DNS:
192.168.10.10
1.1.1.1

MAC:
00:11:22:33:44:55

Speed:
2.5 Gbps
```

介面清單必須支援重新整理。

---

# 4.2 IP 快速切換

使用者可對指定網路介面設定：

- DHCP
- Static IPv4
- Static IPv6

IPv4 靜態設定至少包含：

```text
IP Address
Subnet Mask / Prefix
Default Gateway
Primary DNS
Secondary DNS
Additional DNS
MTU
```

IPv6 至少包含：

```text
IPv6 Address
Prefix Length
Default Gateway
DNS
```

使用者按下套用後，系統需：

1. 驗證設定格式。
2. 備份目前設定。
3. 套用新設定。
4. 檢查作業系統是否成功接受設定。
5. 更新 GUI 狀態。
6. 回傳操作結果。

---

# 4.3 Network Profile

系統必須支援建立多組 Network Profile。

例如：

```text
Office
Lab VLAN 100
Lab VLAN 200
Home
DHCP
Server Room
Production
Testing
```

每個 Profile 至少可以保存：

```yaml
name: Lab VLAN 100

interface:
  selector: Ethernet

ipv4:
  mode: static
  address: 192.168.100.50
  prefix: 24
  gateway: 192.168.100.1

dns:
  - 192.168.100.10
  - 8.8.8.8

mtu: 1500
```

Profile 必須支援：

- 建立
- 修改
- 刪除
- 複製
- 匯入
- 匯出
- 套用
- 設定預設 Profile

---

# 4.4 一鍵切換

GUI 主畫面必須可以直接看到常用 Profile。

例如：

```text
┌──────────────────────────────┐
│ Ethernet                     │
│ 192.168.100.50               │
│                              │
│ [ DHCP ]                     │
│ [ Office ]                   │
│ [ Lab VLAN 100 ]             │
│ [ Lab VLAN 200 ]             │
│ [ Production ]               │
└──────────────────────────────┘
```

使用者原則上應可透過：

```text
選擇 Profile → Apply
```

完成設定切換。

---

# 4.5 設定 Rollback

修改網路設定前必須保存原本設定。

至少支援：

```text
Restore Previous Configuration
```

避免錯誤 IP 設定導致使用者無法快速恢復網路。

建議 Core Engine 將設定操作視為一個交易式流程：

```text
Read Current
      ↓
Backup
      ↓
Validate
      ↓
Apply
      ↓
Verify
      ↓
Success
```

失敗則：

```text
Apply Failed
      ↓
Rollback
      ↓
Verify Original State
```

---

# 5. Hosts 管理

## 5.1 Hosts Editor

系統需要內建 Hosts Editor。

支援：

- 查看 Hosts
- 新增紀錄
- 修改紀錄
- 刪除紀錄
- 啟用 / 停用紀錄
- 搜尋
- 群組管理

例如：

```text
127.0.0.1 localhost

192.168.1.10 dev.example.com
192.168.1.20 api.example.com
```

GUI 建議以表格呈現：

| Enabled | IP | Hostname | Group | Comment |
|---|---|---|---|---|
| ✓ | 192.168.1.10 | dev.example.com | DEV | API Server |
| ✓ | 192.168.1.20 | db.example.com | DEV | DB |
| ✗ | 10.0.0.10 | test.example.com | TEST | Test |

---

# 5.2 Hosts Profile

Hosts 設定需要可以與 Network Profile 綁定。

例如：

```yaml
profile: Lab

network:
  ip: 192.168.10.100
  prefix: 24

hosts_profile: lab
```

切換：

```text
Lab
```

時可以同時套用：

```text
IP Configuration
+
DNS Configuration
+
Hosts Configuration
```

此功能必須可由使用者決定是否啟用。

---

# 5.3 Hosts 安全機制

修改前必須：

```text
Backup current hosts
```

修改後必須：

```text
Validate
↓
Write
↓
Verify
```

並保留最近的歷史版本。

歷史版本數量需設為可配置。

預設值屬實作階段決策，本規格不指定固定數字。

---

# 6. Node 模式

系統需提供 Node 功能，讓兩台執行本系統的電腦互相進行網路測試。

Node 至少支援：

```text
Server
Client
```

或：

```text
Controller
Agent
```

具體命名於 UI 設計階段決定。

---

# 6.1 Node Server

其中一台設備可以啟動：

```text
Listen Mode
```

例如：

```text
nettool node start
```

Node Server 必須顯示：

```text
Node Name
IP
Listening Port
Protocol
Status
Connected Client
```

---

# 6.2 Node Client

另一台設備可以連線：

```text
nettool node connect 192.168.1.100
```

完成連線後可執行網路效能測試。

---

# 7. Node 網路測速

兩個 Node 間至少需要測量：

- TCP Throughput
- UDP Throughput
- Latency
- Jitter
- Packet Loss
- Retransmission
- Upload Speed
- Download Speed

測試方向支援：

```text
Client → Server

Server → Client

Bidirectional
```

---

# 7.1 TCP 測試

測試結果至少包含：

```text
Duration
Transferred Data
Average Throughput
Peak Throughput
TCP Retransmissions
```

例如：

```text
Duration:       10 sec
Transferred:    11.2 GB
Average:        9.62 Gbps
Retransmission: 17
```

---

# 7.2 UDP 測試

UDP 測試至少提供：

```text
Target Bandwidth
Actual Bandwidth
Packet Count
Packet Loss
Jitter
Out-of-order Packets
```

---

# 7.3 Parallel Stream

必須可以設定 Parallel Stream。

例如：

```text
1
2
4
8
16
32
```

CLI：

```text
nettool speed \
  --target 192.168.1.100 \
  --parallel 8
```

具體最大數量不得硬編碼，需依實作能力及系統資源決定。

---

# 8. 封包狀態分析

系統必須提供基本 Packet Analysis。

第一階段主要目的為：

> 快速判斷網路品質及異常狀況，而非取代 Wireshark。

---

# 8.1 即時統計

至少顯示：

```text
Packets / sec
Bytes / sec
TCP packets
UDP packets
ICMP packets
IPv4 packets
IPv6 packets
Dropped packets
Error packets
```

---

# 8.2 TCP 狀態

應能分析：

```text
TCP SYN
TCP SYN/ACK
TCP FIN
TCP RST
TCP Retransmission
Duplicate ACK
Out-of-order
Zero Window
```

---

# 8.3 UDP 狀態

至少分析：

```text
UDP Packet Rate
Packet Loss
Out-of-order
Jitter
```

其中 Packet Loss 與 Jitter 如無法由單端封包資料直接可靠判斷時，必須標示資料來源及計算限制。

不得將推估值呈現為實際測量值。

---

# 8.4 Connection Statistics

提供目前連線統計：

```text
Local Address
Local Port
Remote Address
Remote Port
Protocol
Connection State
Process
PID
Traffic
```

作業系統未提供相關資訊時，可以顯示：

```text
N/A
```

不得自行推測。

---

# 8.5 Protocol Summary

提供 Protocol 分布。

例如：

```text
TCP     72%
UDP     19%
ICMP     2%
Other    7%
```

---

# 8.6 Top Talkers

提供：

```text
Top Source IP
Top Destination IP
Top Connections
Top Ports
```

用來快速發現異常流量。

---

# 8.7 Packet Capture

系統需支援：

```text
Start Capture
Stop Capture
```

可指定：

```text
Interface
Protocol
Source IP
Destination IP
Source Port
Destination Port
```

並允許將完整封包擷取結果匯出成業界通用格式。

優先格式：

```text
PCAP
PCAPNG
```

以便後續使用：

```text
Wireshark
tcpdump
tshark
```

進一步分析。

---

# 9. GUI

GUI 至少包含以下主要頁面：

```text
Dashboard

Network Interfaces

Profiles

Hosts

Speed Test

Packet Analysis

Node

Settings

Logs
```

---

# 9.1 Dashboard

Dashboard 顯示目前：

```text
Active Interface

IP
Gateway
DNS
Link Speed

Active Profile

Node Status

Traffic

Packet Errors
Packet Drops
```

---

# 9.2 Profile 快速操作

Dashboard 需提供：

```text
Quick Switch
```

使用者不需進入設定畫面即可切換常用 Profile。

---

# 10. CLI

CLI 必須覆蓋所有 GUI 功能。

核心原則：

```text
GUI Function == CLI Function
```

禁止存在只能由 GUI 執行的重要功能。

---

# 10.1 CLI 命令結構

建議 CLI 名稱：

```text
nettool
```

正式產品名稱尚未指定，因此 `nettool` 僅為規格書中的暫定名稱。

命令格式：

```text
nettool <module> <command> [options]
```

---

# 10.2 Interface Commands

```text
nettool interface list

nettool interface show <interface>

nettool interface refresh
```

---

# 10.3 Profile Commands

```text
nettool profile list

nettool profile show <name>

nettool profile apply <name>

nettool profile create <name>

nettool profile edit <name>

nettool profile delete <name>

nettool profile export <name>

nettool profile import <file>
```

---

# 10.4 IP Commands

例如：

```text
nettool ip set \
  --interface Ethernet \
  --address 192.168.1.100 \
  --prefix 24 \
  --gateway 192.168.1.1
```

DHCP：

```text
nettool ip dhcp \
  --interface Ethernet
```

DNS：

```text
nettool dns set \
  --interface Ethernet \
  --server 1.1.1.1 \
  --server 8.8.8.8
```

---

# 10.5 Hosts Commands

```text
nettool hosts list

nettool hosts add 192.168.1.10 server.local

nettool hosts remove server.local

nettool hosts enable server.local

nettool hosts disable server.local

nettool hosts backup

nettool hosts restore
```

---

# 10.6 Node Commands

啟動：

```text
nettool node start
```

停止：

```text
nettool node stop
```

狀態：

```text
nettool node status
```

---

# 10.7 Speed Commands

```text
nettool speed \
  --target 192.168.1.10
```

TCP：

```text
nettool speed \
  --target 192.168.1.10 \
  --protocol tcp \
  --duration 10
```

UDP：

```text
nettool speed \
  --target 192.168.1.10 \
  --protocol udp \
  --bandwidth 1G
```

雙向：

```text
nettool speed \
  --target 192.168.1.10 \
  --bidirectional
```

---

# 10.8 Packet Commands

介面統計：

```text
nettool packet stats
```

指定介面：

```text
nettool packet stats \
  --interface Ethernet
```

擷取：

```text
nettool packet capture \
  --interface Ethernet
```

Filter：

```text
nettool packet capture \
  --interface Ethernet \
  --filter "tcp port 443"
```

---

# 11. CLI 輸出格式

CLI 必須同時支援：

```text
Human Readable
JSON
```

例如：

```text
nettool interface list --output json
```

輸出：

```json
{
  "interfaces": [
    {
      "name": "Ethernet",
      "ipv4": "192.168.1.100",
      "prefix": 24,
      "gateway": "192.168.1.1",
      "status": "up"
    }
  ]
}
```

這項設計可讓 CLI 被：

- Shell Script
- PowerShell
- Python
- CI/CD
- 自動化工具

呼叫。

---

# 12. 權限管理

IP、Hosts 與 Packet Capture 均涉及系統管理權限。

系統不可要求 GUI 全程以 Administrator / root 身分執行。

建議架構：

```text
GUI
 │
Core
 │
Privileged Helper
 │
Operating System
```

只有必要操作才透過 Privileged Helper 提升權限。

---

# 12.1 Windows

涉及：

```text
Network Configuration
Hosts Modification
Packet Capture
```

時使用 Windows 管理員權限機制。

---

# 12.2 macOS

涉及：

```text
Network Configuration
/etc/hosts
Packet Capture
```

時透過受控的 Privileged Helper 或符合 macOS 平台安全模型的權限機制執行。

---

# 12.3 Linux

原則相同。

不得使整個 GUI 長時間以：

```text
root
```

權限執行。

---

# 13. 效能需求

系統設計原則：

> GUI 本身不得成為網路測速瓶頸。

---

# 13.1 IP Profile 切換

Core Engine 取得指令後應立即開始執行。

系統等待時間主要應來自：

```text
Operating System Network Reconfiguration
```

而不是：

```text
GUI
IPC
Configuration Parsing
```

---

# 13.2 Speed Test

資料傳輸核心必須使用高效能非同步 I/O。

需要避免：

```text
per-packet UI update
```

UI 應使用統計聚合結果，例如：

```text
100ms
250ms
500ms
```

等週期更新。

實際更新頻率由實作與效能測試決定。

---

# 13.3 Packet Capture

封包處理需將：

```text
Capture
Analysis
UI
```

分離。

建議：

```text
NIC
 ↓
Capture
 ↓
Ring Buffer
 ↓
Analyzer
 ↓
Statistics Aggregator
 ↓
GUI
```

避免 GUI render 阻塞封包擷取。

---

# 14. 平行處理模型

高負載工作不得執行於 UI Thread。

至少需要分離：

```text
UI Thread

Network Configuration Worker

Packet Capture Worker

Packet Analyzer Worker

Speed Test Worker

Node Worker
```

大量資料處理建議使用：

```text
async I/O
+
bounded queue
+
worker pool
```

避免不受控制的執行緒建立。

---

# 15. 平台抽象層

Core 不得直接包含：

```text
Windows Command

macOS Command

Linux Command
```

應建立：

```text
INetworkPlatform
```

概念例如：

```text
INetworkPlatform
    ├── WindowsNetworkPlatform
    ├── MacOSNetworkPlatform
    └── LinuxNetworkPlatform
```

介面能力至少包含：

```text
GetInterfaces()

GetConfiguration()

SetIPv4()

SetIPv6()

SetDHCP()

SetDNS()

SetMTU()

GetLinkState()

GetRouteTable()

FlushDNS()
```

Hosts 亦使用相同概念：

```text
IHostsPlatform
```

Packet Capture 則使用：

```text
IPacketCaptureProvider
```

---

# 16. 設定檔格式

建議所有設定使用結構化格式保存。

例如：

```yaml
version: 1

profiles:

  office:
    interface:
      match: Ethernet

    ipv4:
      mode: static
      address: 192.168.1.50
      prefix: 24
      gateway: 192.168.1.1

    dns:
      - 192.168.1.10
      - 1.1.1.1

  dhcp:
    interface:
      match: Ethernet

    ipv4:
      mode: dhcp
```

設定格式必須包含：

```text
schema version
```

以支援未來升級。

---

# 17. Log

所有系統變更必須留下 Log。

例如：

```text
2026-08-14 14:01:22
Profile Apply

Profile:
Lab-100

Interface:
Ethernet

Old IP:
192.168.1.100

New IP:
192.168.100.100

Result:
SUCCESS
```

---

# 17.1 Log 等級

至少：

```text
ERROR
WARN
INFO
DEBUG
TRACE
```

---

# 18. 安全需求

Network Profile 或 Log 不應保存不必要的敏感資訊。

Node 模式需考慮：

```text
Authentication
Authorization
Replay Protection
Connection Timeout
Rate Limit
```

不得預設讓 Node Service：

```text
0.0.0.0
```

無限制開放且沒有任何驗證機制。

---

# 19. Node 安全模型

Node 至少應具備 Node Identity。

例如：

```text
Node A
Node B
```

第一次連線可以建立信任關係。

概念流程：

```text
Node A
   │
   │ Pair Request
   ▼
Node B
   │
   │ Approve
   ▼
Trusted Node
```

之後才能進行：

```text
Speed Test
Diagnostics
```

未授權 Node 不得使用測速服務大量產生流量。

---

# 20. GUI / CLI 行為一致性

所有 GUI 操作均應可顯示其等效 CLI。

例如 GUI：

```text
Profile
Lab-100

[Apply]
```

可以提供：

```text
Show CLI Command
```

結果：

```text
nettool profile apply Lab-100
```

此功能可降低 GUI 與 CLI 的學習成本。

---

# 21. Dry Run

CLI 建議提供：

```text
--dry-run
```

例如：

```text
nettool profile apply Lab-100 --dry-run
```

顯示：

```text
Interface: Ethernet

Current:
192.168.1.100/24

Will Change To:
192.168.100.100/24

Gateway:
192.168.100.1

DNS:
192.168.100.10

No changes were made.
```

GUI 可提供：

```text
Preview Changes
```

---

# 22. Diagnostics

系統建議整合基本網路診斷。

至少規劃：

```text
Ping
Traceroute
DNS Lookup
TCP Connect Test
Route Table
ARP / Neighbor Table
Interface Statistics
```

GUI 可以形成：

```text
Network Diagnostics
```

頁面。

---

# 23. Speed Test 詳細資料

測速測試紀錄至少包含：

```text
Timestamp
Source Node
Destination Node
Protocol
Duration
Parallel Streams
Transferred Bytes
Average Throughput
Peak Throughput
Latency
Jitter
Packet Loss
Retransmission
```

支援匯出：

```text
JSON
CSV
```

---

# 24. 測試歷史

使用者可以查看過去測試結果。

例如：

```text
Node A → Node B

08/14 10:20
9.43 Gbps

08/14 11:10
9.61 Gbps

08/14 13:05
7.82 Gbps
```

方便判斷網路品質是否隨時間變化。

---

# 25. Packet Analysis Dashboard

封包分析畫面建議至少包含：

```text
Traffic
Packets/sec
Bandwidth

Protocol Distribution

TCP Retransmission

Packet Loss

Top Talkers

Top Ports

Connection States
```

需能快速辨識：

```text
正常
警告
異常
```

但任何「異常」判斷必須有明確規則及數值依據，不可僅依 UI 顏色主觀判斷。

---

# 26. 錯誤處理

所有操作必須回傳明確錯誤。

禁止只回傳：

```text
Operation failed.
```

需包含：

```text
Error Code
Operation
Interface
Reason
Platform Error
Suggested Action
```

例如：

```text
NET-1003

Unable to change IPv4 address.

Interface:
Ethernet

Reason:
Permission denied.

Suggested action:
Run the privileged operation with administrator permission.
```

---

# 27. Exit Code

CLI 必須提供一致的 Exit Code。

例如：

```text
0   Success
1   General Error
2   Invalid Argument
3   Permission Denied
4   Interface Not Found
5   Configuration Failed
6   Connection Failed
7   Timeout
8   Node Authentication Failed
```

正式 Exit Code 表需於開發階段固定並納入 CLI 相容性規格。

---

# 28. 自動化能力

CLI 必須適合腳本呼叫。

例如：

```bash
nettool profile apply Lab-100

if [ $? -ne 0 ]; then
    echo "Network configuration failed"
fi
```

或：

```bash
nettool speed \
  --target 192.168.100.10 \
  --output json
```

使工具能整合：

```text
Shell
PowerShell
CI/CD
Monitoring
Automation
```

---

# 29. 建議軟體模組

整體程式可拆成：

```text
NetworkTool

├── GUI
│
├── CLI
│
├── Core
│   ├── Profile
│   ├── Network
│   ├── Hosts
│   ├── Diagnostics
│   ├── SpeedTest
│   ├── PacketAnalysis
│   └── Node
│
├── Platform
│   ├── Windows
│   ├── macOS
│   └── Linux
│
├── PacketCapture
│
├── SpeedEngine
│
├── Config
│
└── PrivilegedHelper
```

---

# 30. 第一階段 MVP

第一階段建議完成以下核心功能：

- 網路介面偵測
- IPv4 Static / DHCP
- Gateway
- DNS
- Profile 管理
- Profile 一鍵切換
- 設定 Rollback
- Hosts 管理
- Hosts Profile
- GUI
- CLI
- Windows
- macOS Intel
- macOS ARM64
- Linux KDE

以及 Node：

- TCP Speed Test
- Latency
- Basic Packet Statistics

---

# 31. 第二階段

增加：

- UDP 測速
- Jitter
- Packet Loss
- Parallel Stream
- Bidirectional Test
- Packet Capture
- TCP Retransmission Analysis
- Top Talkers
- Connection Analysis
- PCAP / PCAPNG Export
- Speed Test History

---

# 32. 第三階段

可進一步發展：

- Remote Node Management
- Multi-node Testing
- Scheduled Testing
- Network Baseline
- Performance Comparison
- Network Quality Alert
- REST / Local API
- Plugin Architecture

是否實作上述項目需另立需求，不列為目前必要功能。

---

# 33. 非功能需求

## Performance

所有非必要操作不得阻塞 UI。

網路測速應盡量接近作業系統原生 socket 可達效能。

---

## Reliability

設定變更必須具備：

```text
Backup
Validation
Rollback
Logging
```

---

## Portability

平台相依程式碼必須限制於 Platform Layer。

---

## Maintainability

核心功能與 UI Framework 解耦。

---

## Automation

所有 GUI 核心功能均必須存在 CLI 對應操作。

---

## Observability

所有系統變更及測試應具備可追蹤 Log。

---

# 34. 驗收條件

## Network Profile

當使用者存在：

```text
Profile A
192.168.10.100/24

Profile B
192.168.20.100/24
```

使用者選擇：

```text
Profile B
```

系統必須：

1. 正確套用 IP。
2. 正確套用 Gateway。
3. 正確套用 DNS。
4. 顯示新設定。
5. 保存操作 Log。
6. CLI 查詢得到相同狀態。

---

## Hosts

執行：

```text
nettool hosts add 192.168.1.10 server.local
```

後：

```text
server.local
```

必須正確解析至：

```text
192.168.1.10
```

且 GUI 必須看到相同設定。

---

## Node Speed Test

Node A：

```text
nettool node start
```

Node B：

```text
nettool speed --target <Node-A>
```

必須成功取得至少：

```text
Throughput
Transferred Bytes
Duration
```

---

## GUI / CLI 一致性

任何 GUI 執行的核心操作，其結果必須能由 CLI 查詢。

任何 CLI 執行的核心操作，其結果亦必須即時反映於 GUI。

---

# 35. 仍待決定項目

原始需求沒有提供以下資訊，因此本規格暫不強制指定：

- 正式產品名稱
- GUI Framework
- 開發語言
- Node 預設 Port
- Node Authentication 技術
- 設定檔實際格式採 YAML、JSON 或其他格式
- Profile 儲存路徑
- Profile 是否進行加密
- Node 是否允許跨 Internet 使用
- Linux 除 KDE 外需支援哪些桌面環境
- Linux 需正式支援哪些發行版
- IPv6 功能深度
- Packet Analysis 是否需要 DPI
- 是否解析 HTTP / TLS / DNS 等 Application Layer Protocol
- 是否支援 VLAN 建立與修改
- 是否支援 Route Profile
- 是否支援 Proxy Profile
- 是否提供背景 Service
- 是否需要自動更新功能

上述項目必須於進入詳細設計階段前確認。

---

# 36. 核心設計目標

本系統最終應做到：

```text
Network Profile
     +
Hosts Profile
     +
Diagnostics
     +
Speed Test
     +
Packet Analysis
     +
Node
     │
     ▼
Single Core Engine
     │
 ┌───┴────┐
 ▼        ▼
GUI      CLI
```

核心要求可以濃縮為：

> 「一套跨 Windows、macOS 與 Linux 的工程師網路工具，讓使用者能在數秒內切換完整網路環境，並直接執行網路測速、診斷與封包狀態分析；所有 GUI 功能均具有完全等價的 CLI 操作方式。」
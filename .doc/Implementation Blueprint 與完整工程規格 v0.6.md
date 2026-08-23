# Implementation Blueprint 與完整工程規格

版本：0.6 Draft  
狀態：Implementation Ready Draft

承接：

```text
SRS v0.1
System Design v0.2
100GbE Architecture v0.3
Speed / Packet Engine v0.4
Node Protocol / CLI Contract v0.5
```

---

# 446. v0.6 核心目的

本版不再擴充大型產品功能。

本版目的為固定：

```text
Process Architecture

Rust Workspace

Crate Dependency

Domain Model

Action API

Local IPC

Privileged Helper API

Data Plane Process

SQLite Schema

Configuration Layout

Build Feature

Packaging

CI

Testing Strategy

Security Boundary

Observability

Crash Recovery

Upgrade / Migration

Requirement Traceability

Definition of Done
```

完成本版後，專案即可進入：

```text
Repository Initialization
↓
POC
↓
Implementation
```

---

# 447. 重要架構修正：導入 Agent

前版概念：

```text
GUI ─┐
     ├── Core
CLI ─┘
```

正式修改為：

```text
GUI ─────┐
         │
CLI ─────┼── Local IPC ──▶ nettool-agent
         │                     │
Automation┘                    │
                               ▼
                         Application Core
```

理由：

以下功能具有長生命週期：

```text
Safe Apply

Rollback Timer

Node Listener

Speed Session

Packet Capture

Benchmark

Hardware Reservation

History

Remote Node Connection
```

不適合由 GUI 或 CLI Process 擁有。

---

# 448. 最終 Process Architecture

正式定義五個主要執行元件：

```text
nettool-gui

nettool

nettool-agent

nettool-helper

nettool-dataplane
```

---

# 449. nettool-gui

用途：

```text
GUI
Dashboard
Profile Management
Node UI
Packet Dashboard
Benchmark UI
```

技術：

```text
Tauri 2
+
TypeScript
+
React 或 Svelte
```

前端不得直接：

```text
Modify IP

Modify Hosts

Open Raw Socket

Access DPDK

Modify Huge Page

Bind NIC Driver
```

Tauri frontend 僅與 Rust UI adapter 溝通，再透過 Local IPC 呼叫 Agent。Tauri 官方提供 frontend 呼叫 Rust command 及 Rust 向 frontend 傳送事件/資料的機制，適合本架構中低頻控制與 Snapshot 更新。

---

# 450. nettool

用途：

```text
CLI
```

CLI 不重新實作 Core。

流程：

```text
CLI Parser
    ↓
Action Request
    ↓
Local IPC
    ↓
nettool-agent
```

---

# 451. nettool-agent

Agent 為整個系統：

```text
Single Runtime Authority
```

負責：

```text
Action Dispatch

SQLite

Profile

Hosts Profile

Node

Remote Control Plane

Session Manager

Resource Manager

Benchmark Coordinator

Packet Session

Safe Apply Coordinator

History

Telemetry
```

Agent：

```text
MUST NOT
```

持有完整 Administrator / root 權限。

---

# 452. nettool-helper

唯一主要 Privileged Boundary。

負責：

```text
Network Configuration

Hosts Atomic Write

Route Change

DNS Change

MTU Change

NIC Preparation

DPDK Device Preparation

Huge Page Preparation

Platform-specific privileged operations
```

Helper 不負責：

```text
GUI

Node Control

Benchmark Logic

Packet Analysis

SQLite Business Logic
```

---

# 453. nettool-dataplane

專門負責高速 Session：

```text
DPDK

AF_XDP

RIO

Packet Generator

Packet Receiver

Packet Analyzer
```

其生命週期：

```text
Create Session
↓
Launch Worker
↓
Reserve Resources
↓
Run
↓
Return Statistics
↓
Shutdown
```

---

# 454. 為什麼 Data Plane 獨立 Process

正式要求：

```text
MUST
```

100G Data Plane 不與：

```text
GUI
Agent
Privileged Helper
```

位於相同 Process。

目的：

```text
Crash Isolation

Memory Isolation

CPU Affinity Isolation

DPDK EAL Isolation

Resource Accounting

Simpler Restart
```

---

# 455. Data Plane 權限

`nettool-dataplane`：

```text
MUST NOT
```

擁有任意 root command execution 能力。

需要 privileged preparation 時：

```text
Agent
  ↓
Helper
  ↓
Prepare Resource
  ↓
Dataplane
```

---

# 456. Process 關係

```text
                         ┌─────────────┐
                         │ nettool-gui │
                         └──────┬──────┘
                                │
                                │ Local IPC
                                │
┌───────────┐                   ▼
│  nettool  │────────────▶ nettool-agent
└───────────┘                   │
                                │
               ┌────────────────┼────────────────┐
               │                │                │
               ▼                ▼                ▼
         nettool-helper   nettool-dataplane   Remote Node
          privileged        high-speed        TLS 1.3
```

---

# 457. Rust Workspace

正式 Workspace：

```text
nettool/
│
├── Cargo.toml
├── Cargo.lock
│
├── crates/
│   │
│   ├── domain/
│   ├── error/
│   ├── action/
│   ├── config/
│   ├── storage/
│   │
│   ├── platform-api/
│   ├── platform-windows/
│   ├── platform-macos/
│   ├── platform-linux/
│   │
│   ├── helper-protocol/
│   ├── helper-client/
│   │
│   ├── agent-protocol/
│   ├── agent-client/
│   │
│   ├── node-protocol/
│   ├── node/
│   │
│   ├── speed/
│   ├── packet/
│   ├── analyzer/
│   │
│   ├── backend-pcap/
│   ├── backend-af-xdp/
│   ├── backend-dpdk/
│   ├── backend-rio/
│   │
│   ├── dpdk-sys/
│   ├── dpdk-safe/
│   │
│   ├── benchmark/
│   ├── telemetry/
│   └── test-support/
│
├── apps/
│   │
│   ├── gui/
│   ├── cli/
│   ├── agent/
│   ├── helper/
│   └── dataplane/
│
├── proto/
│
├── migrations/
│
├── schemas/
│
├── benchmark/
│
├── packaging/
│
├── tests/
│
└── docs/
```

Cargo Workspace 可共同管理多個相關套件，因此採單一 Workspace 管理上述 crates。

---

# 458. Dependency Rule

核心規則：

```text
domain
```

不得依賴：

```text
Tauri

Windows API

macOS API

Linux API

DPDK

AF_XDP
```

---

# 459. Dependency Direction

```text
                  apps
                   │
                   ▼
                action
                   │
          ┌────────┼────────┐
          ▼        ▼        ▼
       domain   storage   services
          ▲                 │
          │                 ▼
    platform-api       speed/packet
          ▲                 │
    ┌─────┼─────┐     ┌─────┼────────┐
    ▼     ▼     ▼     ▼     ▼        ▼
   win   mac   linux  pcap  xdp     dpdk
```

---

# 460. 禁止反向相依

例如：

```text
domain
   ↓
backend-dpdk
```

禁止。

```text
packet
   ↓
gui
```

禁止。

---

# 461. Cargo Feature

Cargo Features 用於條件式建構平台與 Backend；Cargo 官方將 Feature 定義為條件式編譯及 optional dependencies 的機制。

正式 Feature：

```text
platform-windows

platform-macos

platform-linux

backend-pcap

backend-af-xdp

backend-dpdk

backend-rio

capture-pcap

capture-pcapng

gui

cli

benchmark

dev-tools
```

---

# 462. Platform Build

Windows：

```text
platform-windows
backend-pcap
backend-rio
```

Optional：

```text
backend-dpdk
```

---

macOS：

```text
platform-macos
backend-pcap
```

---

Linux：

```text
platform-linux
backend-pcap
backend-af-xdp
backend-dpdk
```

---

# 463. Default Feature

核心函式庫：

```text
default = []
```

避免：

```text
import core
→
automatically link DPDK
```

---

# 464. Domain Model

核心物件：

```text
Interface

NetworkProfile

HostsProfile

Route

DnsConfiguration

Node

NodeTrust

Capability

Session

SpeedSession

PacketSession

BenchmarkProfile

HardwareProfile

ResourceReservation

Operation

AuditRecord
```

---

# 465. Interface ID

```rust
struct InterfaceId {
    platform: Platform,
    stable_id: String,
}
```

另外保存：

```text
MAC

Friendly Name

Current Name

PCI Address

Interface Index
```

如適用。

---

# 466. NetworkProfile

概念：

```rust
struct NetworkProfile {
    id: ProfileId,
    name: String,

    interface_selector: InterfaceSelector,

    ipv4: Ipv4Configuration,
    ipv6: Ipv6Configuration,

    dns: DnsConfiguration,
    routes: Vec<RouteConfiguration>,

    mtu: Option<u32>,

    hosts_profile: Option<HostsProfileId>,

    safety: SafetyPolicy,
}
```

---

# 467. SafetyPolicy

```rust
struct SafetyPolicy {
    safe_apply: bool,
    confirm_timeout: Duration,
    connectivity_check: ConnectivityPolicy,
}
```

預設：

```text
safe_apply = true
```

---

# 468. Action Model

所有 GUI / CLI 操作統一轉成：

```text
Action
```

例如：

```text
profile.apply

profile.confirm

profile.rollback

hosts.add

node.pair

speed.run

speed.cancel

packet.capture.start

perf.benchmark
```

---

# 469. Action Request

```rust
struct ActionRequest<T> {
    request_id: RequestId,
    operation_id: Option<OperationId>,
    action: ActionName,
    payload: T,
}
```

---

# 470. Action Result

```rust
struct ActionResult<T> {
    request_id: RequestId,
    success: bool,

    data: Option<T>,

    warnings: Vec<Warning>,
    error: Option<NetToolError>,
}
```

---

# 471. Action Registry

集中註冊：

```text
Action Name

Input Schema

Output Schema

Permission Requirement

Idempotency

CLI Mapping

GUI Mapping
```

例如：

```text
profile.apply

Permission:
PRIVILEGED

Idempotent:
YES

CLI:
nettool profile apply

GUI:
Profile / Apply
```

---

# 472. Agent Local IPC

GUI 與 CLI 都透過：

```text
Agent IPC
```

---

# 473. Windows Agent IPC

使用：

```text
Named Pipe
```

並限制：

```text
Current User / Authorized Local Principal
```

---

# 474. macOS / Linux Agent IPC

使用：

```text
Unix Domain Socket
```

Socket 檔案權限：

```text
User-only
```

---

# 475. Agent Protocol

與 Node Remote Protocol 分離。

使用：

```text
Length Prefix
+
Protobuf
```

但：

```text
NO TLS
```

因為是 local IPC。

安全依賴：

```text
OS IPC Access Control
+
Peer Validation
```

---

# 476. Agent Message

```protobuf
message AgentEnvelope {
    uint32 protocol_major = 1;
    uint32 protocol_minor = 2;

    bytes request_id = 3;

    oneof message {
        ActionRequest request = 10;
        ActionResponse response = 11;

        SubscribeRequest subscribe = 20;
        Event event = 21;
    }
}
```

---

# 477. Agent Event

只傳：

```text
State Change

Session State

Statistics Snapshot

Warning

Error
```

禁止：

```text
Per Packet Event
```

---

# 478. GUI Statistics

例如：

```text
Packet Worker:
continuous

Aggregator:
100 ms class

Agent Event:
250 ms class

GUI Render:
250–500 ms class
```

以上屬初始設計範圍，最終數值由效能測試固定。

---

# 479. Privileged Helper IPC

Helper Protocol 與 Agent Protocol 完全分離。

原因：

```text
Privilege Boundary
```

---

# 480. Helper API

第一版只允許：

```text
network.read_state

network.apply

network.restore

hosts.read

hosts.atomic_replace

nic.prepare_dpdk

nic.restore_driver

hugepage.prepare

hugepage.release
```

---

# 481. Helper 禁止 API

永遠不得提供：

```text
shell.execute

command.execute

powershell.execute

bash.execute

run_arbitrary
```

類型介面。

---

# 482. Helper Request

```rust
struct PrivilegedRequest {
    request_id: RequestId,
    operation_id: OperationId,

    caller_identity: CallerIdentity,

    operation: PrivilegedOperation,
}
```

---

# 483. Helper Validation

每次操作：

```text
Authenticate Caller
↓
Authorize Operation
↓
Validate Arguments
↓
Check Resource Lock
↓
Execute
↓
Verify
↓
Audit
```

---

# 484. Helper Audit

必須記錄：

```text
Operation

Target

Old State Hash

New State Hash

Caller

Result
```

不得記錄不必要敏感內容。

---

# 485. Safe Apply Ownership

流程：

```text
Agent
   │
   │ Apply Request
   ▼
Helper
   │
   ├── Snapshot
   ├── Apply
   ├── Verify
   └── Start Rollback Deadline
```

---

# 486. Rollback Deadline

Rollback Deadline：

```text
MUST survive
```

以下故障：

```text
GUI crash

CLI exit

Agent crash
```

因此 Deadline 最終由：

```text
Helper
```

持有。

---

# 487. Agent Restart

Agent 重啟後：

```text
query pending privileged operations
```

Helper 回傳：

```text
Pending Safe Apply

Deadline

Operation ID
```

Agent 恢復狀態。

---

# 488. Data Plane Session Process

每個高效能 Session：

```text
MUST
```

具有唯一：

```text
Session ID
```

與：

```text
Resource Reservation
```

---

# 489. Data Plane Launch

```text
Agent
 ↓
Capability Check
 ↓
Reserve
 ↓
Helper Prepare
 ↓
Launch dataplane
 ↓
Handshake
 ↓
READY
 ↓
Run
```

---

# 490. Data Plane IPC

Agent 與 Data Plane：

```text
Local IPC
```

只傳：

```text
Configuration

Start

Stop

Statistics Snapshot

Final Result

Fatal Error
```

---

# 491. Data Plane 禁止傳輸

不得透過 IPC 傳：

```text
Raw Packet Stream
```

---

# 492. Data Plane Worker Model

100G DPDK：

```text
Main Control Thread

Statistics Thread

RX Worker N

TX Worker N

Optional Writer Worker N
```

DPDK 本身採 Poll Mode Driver 與 Queue-based burst processing；Huge Page/NUMA 亦為 Linux DPDK 部署的重要環境條件。

---

# 493. Tokio Boundary

Tokio 使用於：

```text
Agent

Remote Node Control

Local IPC

Socket Speed Engine

Timers

Control Operations
```

---

# 494. Tokio 禁止區域

DPDK Poll Loop：

```text
MUST NOT
```

依賴 Tokio task scheduler。

使用：

```text
Dedicated Native Thread
+
CPU Affinity
```

---

# 495. Cancellation

Control Plane 使用：

```text
Cancellation Token
```

Fast Path：

```text
Atomic Stop Flag
```

Worker 在 burst boundary 檢查。

---

# 496. Database

Internal persistent database：

```text
SQLite
```

用途：

```text
Profiles

History

Node Trust Metadata

Benchmark

Audit Index

Configuration
```

---

# 497. Database 不保存

```text
Private Key

Full Packet Payload

Credential Secret
```

---

# 498. Database Tables

正式第一版：

```text
schema_migration

network_profile

network_profile_revision

hosts_profile

hosts_entry

node

node_trust

operation

safe_apply

speed_session

packet_session

benchmark_result

hardware_profile

hardware_certification

audit_log

application_setting
```

---

# 499. schema_migration

```sql
CREATE TABLE schema_migration (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL,
    checksum TEXT NOT NULL
);
```

---

# 500. network_profile

```sql
CREATE TABLE network_profile (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    active_revision INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
```

---

# 501. network_profile_revision

```sql
CREATE TABLE network_profile_revision (
    profile_id TEXT NOT NULL,
    revision INTEGER NOT NULL,

    configuration_json TEXT NOT NULL,
    checksum TEXT NOT NULL,

    created_at TEXT NOT NULL,

    PRIMARY KEY (profile_id, revision)
);
```

Profile 修改不覆寫歷史 Revision。

---

# 502. hosts_profile

```sql
CREATE TABLE hosts_profile (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
```

---

# 503. hosts_entry

```sql
CREATE TABLE hosts_entry (
    id TEXT PRIMARY KEY,
    profile_id TEXT NOT NULL,

    enabled INTEGER NOT NULL,

    address TEXT NOT NULL,
    hostname TEXT NOT NULL,

    comment TEXT,

    sort_order INTEGER NOT NULL
);
```

---

# 504. node

```sql
CREATE TABLE node (
    id TEXT PRIMARY KEY,

    name TEXT NOT NULL,

    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT,

    last_address TEXT
);
```

---

# 505. node_trust

```sql
CREATE TABLE node_trust (
    node_id TEXT PRIMARY KEY,

    fingerprint TEXT NOT NULL,

    trust_status TEXT NOT NULL,

    trusted_at TEXT,
    revoked_at TEXT
);
```

Private Key 不在此表。

---

# 506. operation

```sql
CREATE TABLE operation (
    operation_id TEXT PRIMARY KEY,

    action TEXT NOT NULL,

    state TEXT NOT NULL,

    created_at TEXT NOT NULL,
    completed_at TEXT,

    error_code TEXT
);
```

---

# 507. safe_apply

```sql
CREATE TABLE safe_apply (
    operation_id TEXT PRIMARY KEY,

    target_interface TEXT NOT NULL,

    snapshot_id TEXT NOT NULL,

    state TEXT NOT NULL,

    deadline TEXT NOT NULL
);
```

SQLite 只保存索引狀態。

Rollback 的最終權威狀態：

```text
Helper
```

---

# 508. speed_session

至少：

```text
session_id

remote_node

protocol

backend

direction

started_at

completed_at

result_state

configuration_json

result_json
```

---

# 509. packet_session

保存：

```text
Session ID

Interface

Backend

Capture Mode

Analysis Mode

Start

End

Final Drop Counters

Confidence
```

---

# 510. benchmark_result

保存：

```text
Benchmark ID

Hardware Profile

Software Build

Configuration

Result

Certification State

Checksum
```

---

# 511. Hardware Profile

包含：

```text
OS

Kernel / Build

Architecture

CPU Model

NUMA Topology

RAM

NIC

PCI Address

PCIe Link

NIC Firmware

Driver

MTU

Backend

DPDK Version
```

---

# 512. Hardware Certification

Certification 不只綁定：

```text
NIC Model
```

而是綁定：

```text
Hardware Profile Hash
+
Software Profile
```

---

# 513. Database Migration

每次 schema 變更：

```text
migration N
```

必須：

```text
Forward Migration
+
Migration Test
+
Backup Test
```

---

# 514. Database Downgrade

預設：

```text
NOT SUPPORTED
```

如果舊版程式遇到較新的 DB Schema：

```text
DATABASE_SCHEMA_TOO_NEW
```

不得自行嘗試讀寫。

---

# 515. Configuration Storage

設定分成：

```text
User Configuration

Machine Configuration

Runtime State

Persistent Database

Secrets
```

---

# 516. Windows Path

邏輯預設：

```text
User Config:
%LOCALAPPDATA%\NetTool\

Machine Config:
%PROGRAMDATA%\NetTool\

Database:
%LOCALAPPDATA%\NetTool\data\

Machine Log:
%PROGRAMDATA%\NetTool\logs\
```

正式產品名稱確定後替換 `NetTool`。

---

# 517. macOS Path

```text
User Data:
~/Library/Application Support/NetTool/

User Log:
~/Library/Logs/NetTool/

Machine Data:
/Library/Application Support/NetTool/
```

---

# 518. Linux Path

遵循 XDG 類型配置：

```text
Config:
$XDG_CONFIG_HOME/nettool/

Data:
$XDG_DATA_HOME/nettool/

State:
$XDG_STATE_HOME/nettool/

Runtime:
$XDG_RUNTIME_DIR/nettool/
```

若變數不存在：

```text
~/.config/nettool/

~/.local/share/nettool/

~/.local/state/nettool/
```

---

# 519. Linux Machine Config

```text
/etc/nettool/
```

---

# 520. Configuration Precedence

正式：

```text
CLI Argument
    ↓
Session Setting
    ↓
User Config
    ↓
Machine Config
    ↓
Built-in Default
```

---

# 521. Secret Storage

Node Private Key 等 Secret：

```text
MUST
```

使用平台 Secret Storage abstraction。

介面：

```rust
trait SecretStore {
    fn put(...);
    fn get(...);
    fn delete(...);
}
```

---

# 522. Packet Capture Path

Capture File：

```text
MUST NOT
```

預設寫入一般 application log directory。

使用：

```text
Explicit Capture Directory
```

並需預先檢查：

```text
Free Space

Write Permission

Storage Benchmark
```

---

# 523. Log Architecture

正式分成：

```text
Application Log

Audit Log

Performance Telemetry

Benchmark Result

Packet Capture
```

五種不同資料。

---

# 524. Application Log

提供：

```text
ERROR
WARN
INFO
DEBUG
TRACE
```

Production 預設：

```text
INFO
```

---

# 525. Audit Log

不可由一般 Debug 設定停用。

至少記錄：

```text
Profile Apply

Profile Rollback

Hosts Change

Node Pair

Node Unpair

DPDK NIC Preparation

Benchmark Start

Benchmark Stop
```

---

# 526. Performance Telemetry

只保存聚合資料：

```text
Gbps

Mpps

CPU

Queue

Drop

Flow Count

Ring Utilization
```

禁止 per-packet log。

---

# 527. Correlation ID

所有相關操作共用：

```text
Request ID

Operation ID

Session ID
```

例如：

```text
GUI
 ↓ request_id

Agent
 ↓ operation_id

Dataplane
 ↓ session_id
```

Log 可以完整串聯。

---

# 528. Metrics Snapshot

例如：

```json
{
  "session_id": "...",

  "rx_bps": "98500000000",
  "rx_pps": "8120000",

  "drops": {
    "nic": "0",
    "ring": "0",
    "analyzer": "0"
  },

  "workers": 16
}
```

---

# 529. Health Model

每個 Component：

```text
STARTING

HEALTHY

DEGRADED

FAILED

STOPPING
```

---

# 530. Agent Health

包含：

```text
Database

Helper Connection

Node Listener

Session Manager

Storage
```

---

# 531. Data Plane Health

包含：

```text
NIC

RX Queue

TX Queue

Memory Pool

Worker

Capture Writer

Statistics
```

---

# 532. Watchdog

Agent 必須偵測：

```text
Dataplane Process Exit

Helper Disconnect

Unexpected Session Stop
```

並執行：

```text
Cleanup

Resource Release

Audit

State Recovery
```

---

# 533. Crash Recovery

Agent 啟動：

```text
Load Database
↓
Check Pending Operation
↓
Query Helper
↓
Check Orphan Session
↓
Check Resource Reservation
↓
Restore Consistent State
```

---

# 534. Orphan DPDK Resource

若前次 Data Plane 異常結束：

```text
NIC still bound
```

不得自動直接重綁 Management NIC。

流程：

```text
Identify Port
↓
Check Ownership
↓
Check Management Dependency
↓
Recovery Policy
```

---

# 535. Resource Manager

Resource：

```text
NIC

RX Queue

TX Queue

CPU

NUMA Memory

Huge Page

Capture Storage

Port
```

---

# 536. Reservation

所有高速 Session 先取得：

```text
ResourceReservation
```

---

# 537. Reservation State

```text
PENDING

ACTIVE

RELEASING

RELEASED

FAILED
```

---

# 538. Exclusive Resource

以下預設 Exclusive：

```text
DPDK Physical Port

DPDK Queue

Pinned CPU Worker

Lossless Capture Writer
```

---

# 539. Shared Resource

可能 Shared：

```text
Management Interface

Agent

Database

Read-only Interface Statistics
```

---

# 540. Resource Conflict

回傳：

```text
RESOURCE_CONFLICT
```

並列出：

```text
resource

owner session

requested mode
```

---

# 541. Capability Discovery

Agent 啟動時建立：

```text
Capability Snapshot
```

包含：

```text
Platform

Backend

NIC

Privilege

Secret Storage

Capture

100G Capability
```

---

# 542. Capability 不可快取永久

以下事件後需重新整理：

```text
NIC Add / Remove

Driver Change

Link Change

Kernel Change

Backend Initialization Failure
```

---

# 543. AF_XDP Detection

需區分：

```text
XDP Supported

AF_XDP Supported

AF_XDP Copy

AF_XDP Zero Copy
```

Linux Kernel 文件明確區分 AF_XDP copy 與 zero-copy，並可要求 `XDP_ZEROCOPY`；若驅動不支援則 bind 失敗，因此本系統不得將 copy mode 誤標示成 zero-copy。

---

# 544. DPDK Preflight

檢查：

```text
DPDK Runtime

PMD

PCI Device

Huge Page

NUMA

Port Availability

CPU Affinity

Driver State
```

DPDK 官方 Linux 文件包含 Huge Page 的配置與 NUMA memory allocation，因此這些項目列為 DPDK Certified Mode 前置檢查。

---

# 545. Preflight Result

```text
PASS

WARN

FAIL
```

---

# 546. 100G Certification

任何：

```text
FAIL
```

的必要 Preflight：

```text
MUST prevent
```

100G Certification Run。

一般測試可依情況：

```text
continue degraded
```

但結果不得標示 Certified。

---

# 547. Build Profile

至少：

```text
dev

release

benchmark

release-certified
```

---

# 548. dev

目的：

```text
Debugging

Unit Test

Functional Development
```

不得用於正式 100G Certification。

---

# 549. benchmark

啟用：

```text
Optimization

Performance Counters

Benchmark Instrumentation
```

---

# 550. release-certified

需：

```text
Reproducible Build Metadata

Release Version

Git Commit

Dependency Lock

Compiler Version

Backend Version
```

全部記入 Benchmark Environment。

---

# 551. Build Metadata

每個 Binary 支援：

```bash
nettool version --verbose
```

輸出：

```text
Product Version

Protocol Version

CLI Schema Version

Git Commit

Build Target

Rust Version

Enabled Features

DPDK Version

Build Timestamp
```

Build Timestamp 不可作為唯一 Build Identity。

---

# 552. Packaging

正式 Distribution：

Windows：

```text
Installer
CLI
GUI
Agent
Helper
Optional Packet Driver Dependency
```

macOS：

```text
Application Bundle
CLI
Agent
Privileged Helper
```

Linux：

```text
GUI
CLI
Agent
Helper
udev / policy files
Optional DPDK support
```

---

# 553. Installer Transaction

Installer 必須處理：

```text
Install Binary

Install Agent

Install Helper

Register Services

Install Policy

Initialize Data
```

任一失敗：

```text
Rollback Installation
```

---

# 554. Uninstall

Uninstall 前：

```text
Stop Sessions

Restore Managed NIC State

Release DPDK Resource

Stop Agent

Remove Helper
```

---

# 555. Uninstall 不刪除

預設保留：

```text
Profiles

History

Capture Files
```

需使用者明確選擇：

```text
Remove User Data
```

才刪除。

---

# 556. Update 安全原則

GUI 自動更新不能自行偷偷更新：

```text
Privileged Helper
```

Helper 更新必須經：

```text
Signed Installer / Trusted Platform Upgrade Path
```

---

# 557. Protocol Upgrade

Node：

```text
Current Major
+
Previous Compatible Major
```

是否支援需由 Release Policy 明確定義。

第一版至少要求：

```text
Current Minor
↔
Previous Minor
```

相容測試。

---

# 558. Database Upgrade

流程：

```text
Backup
↓
Validate
↓
Migration
↓
Integrity Check
↓
Start Application
```

失敗：

```text
DATABASE_MIGRATION_FAILED
```

並保留原始 Backup。

---

# 559. Profile Schema Upgrade

Import File 必須包含：

```text
schema_version
```

---

# 560. Unknown Future Field

Profile JSON/YAML：

```text
MUST NOT
```

因未知 optional field 而無條件失敗。

但未知：

```text
required capability
```

必須拒絕套用。

---

# 561. CI Matrix

最低：

```text
Windows x86_64

macOS x86_64

macOS ARM64

Linux x86_64
```

---

# 562. Core CI

每次 Commit：

```text
format

lint

unit test

schema validation

protocol test

CLI contract test
```

---

# 563. Platform CI

執行：

```text
Interface Enumeration

Profile Validation

Hosts Parser

Helper IPC

Installer Smoke Test
```

實際 NIC 變更不可只靠一般 shared CI runner。

---

# 564. Hardware Lab CI

專用測試設備執行：

```text
Network Profile Apply

Safe Rollback

DPDK

AF_XDP

RIO

Packet Capture

100G Benchmark
```

---

# 565. 100G Hardware Test Lab

至少：

```text
Node A
+
Node B
+
100GbE Link
+
Management Network
```

---

# 566. 管理網路

100G Hardware Lab：

```text
Management Plane
```

與：

```text
Test Plane
```

必須分離。

---

# 567. Hardware CI 不與 Production 共用

100G 壓力測試：

```text
MUST NOT
```

直接使用正式生產服務 NIC。

---

# 568. Unit Test

至少：

```text
IP Parser

IPv6 Parser

Profile Validation

Hosts Parser

Action Validation

Error Mapping

Flow Hash

Packet Parser

Sequence Tracker

Drop Accounting

State Machine
```

---

# 569. Property Test

適用：

```text
IP

CIDR

Packet Header

Protocol Frame

CLI JSON

Profile Serialization
```

---

# 570. Fuzz Test

至少：

```text
Node Frame

Agent Frame

Helper Frame

Protobuf

UDP Header

Ethernet Parser

IPv4 Parser

IPv6 Parser

TCP Parser

PCAP Reader
```

---

# 571. Integration Test

```text
Agent ↔ Helper

Agent ↔ Dataplane

CLI ↔ Agent

GUI Adapter ↔ Agent

Node ↔ Node
```

---

# 572. Linux Namespace Test

Linux 建立：

```text
namespace A

namespace B

router namespace
```

測試：

```text
Static IP

Route

Ping

TCP

UDP

Loss

Latency
```

---

# 573. Failure Injection

必要：

```text
Kill GUI

Kill CLI

Kill Agent

Kill Dataplane

Restart Helper

Remove NIC

Link Down

Disk Full

DB Locked

Capture Writer Slow

Huge Page Exhaustion
```

---

# 574. Safe Apply Test

至少：

```text
Apply Success + Confirm

Apply Success + Timeout

Agent Crash During Countdown

GUI Crash During Countdown

Network Unreachable

Rollback Failure
```

---

# 575. Rollback Failure

屬於：

```text
CRITICAL
```

GUI / CLI 必須明確顯示：

```text
ROLLBACK_FAILED
```

不得顯示一般 Warning。

---

# 576. Security Test

至少：

```text
Unauthorized Agent IPC

Unauthorized Helper IPC

Malformed Helper Request

Replay Operation

Node Identity Change

Oversized Frame

Protocol Fuzz

Resource Exhaustion

Path Traversal

Capture File Path Injection
```

---

# 577. Helper Security Gate

正式 Release 前：

```text
MUST
```

完成獨立安全審查。

原因：

```text
Helper = Privilege Boundary
```

---

# 578. Dependency Security

Release Pipeline：

```text
Dependency Audit

Lockfile Check

License Inventory

Artifact Checksum
```

---

# 579. Performance Test

100G：

```text
64B

128B

256B

512B

1024B

1518B

9018B
```

---

# 580. Flow Test

```text
1

16

256

4096

100K

High-cardinality
```

具體最高 Flow 數由硬體 Benchmark 決定。

---

# 581. Performance Metrics

每次必須記：

```text
Gbps

Mpps

CPU

Cores

Gbps/Core

Mpps/Core

NIC Drop

Ring Drop

Analyzer Drop

Memory

NUMA

Queue Distribution
```

---

# 582. Benchmark Result Validity

結果缺少：

```text
Hardware Snapshot
```

則：

```text
NOT CERTIFIABLE
```

---

# 583. GUI Performance

GUI 不得影響 Benchmark。

必須測：

```text
GUI Open

GUI Closed

CLI Monitoring

No Client
```

四種狀態。

---

# 584. GUI Performance Regression

若開啟 GUI 後：

```text
Data Plane Result
```

出現超過正式門檻的退化：

```text
FAIL
```

門檻在 100G POC 後固定。

---

# 585. CLI Cold Start

設定：

```text
Engineering Target
```

而非 Product Guarantee。

需量測：

```text
nettool --version

nettool interface list
```

並持續進行 Regression Tracking。

---

# 586. 100G Performance Budget

正式不先虛構固定：

```text
CPU %
Drop %
Throughput %
```

門檻。

第一個 Hardware POC 取得 Baseline 後：

```text
Baseline
↓
Engineering Margin
↓
Certification Threshold
```

再寫入：

```text
Benchmark Specification v1.0
```

---

# 587. Acceptance Test — Profile

跨三 OS：

```text
DHCP
↓
Static
↓
Confirm
↓
DHCP
```

需驗證：

```text
IP

Gateway

DNS

Route

MTU

Audit
```

---

# 588. Acceptance Test — Safe Apply

Apply 後不 Confirm：

```text
MUST
```

自動恢復。

即使：

```text
GUI terminated
Agent terminated
```

仍必須恢復。

---

# 589. Acceptance Test — Hosts

Managed Section 不得修改：

```text
Non-managed User Entries
```

---

# 590. Acceptance Test — GUI / CLI

任何 GUI Action：

```text
MUST
```

具有相同：

```text
Action ID
```

與 CLI 對應。

---

# 591. Acceptance Test — Node

Trusted Node：

```text
Connect

Negotiate

Prepare

Run

Stop

Result
```

完整成功。

---

# 592. Acceptance Test — Identity Change

相同 Node ID 但 Fingerprint 改變：

```text
MUST DENY
```

直到重新 Pair。

---

# 593. Acceptance Test — 100G

至少驗證：

```text
RX

TX

Bidirectional

64B

1518B

Jumbo

TCP

UDP

Raw
```

---

# 594. Acceptance Test — Drop

至少人工產生：

```text
NIC Drop

Ring Drop

Analyzer Drop
```

確認 UI / CLI 不混淆三者。

---

# 595. Acceptance Test — Confidence

存在 Capture Drop：

```text
MUST NOT
```

維持不受影響的最高可信度。

---

# 596. Acceptance Test — NUMA

指定錯誤 NUMA：

```text
Certification Mode
→ FAIL
```

一般 Mode：

```text
Warning
```

---

# 597. Acceptance Test — AF_XDP

100G Zero-copy Profile：

若 Zero-copy 不存在：

```text
MUST FAIL
```

不得：

```text
silent fallback
```

AF_XDP 官方提供 copy / zero-copy 模式差異，因此此行為視為正式產品契約。

---

# 598. Acceptance Test — DPDK

缺少必要 Huge Page：

```text
100G Certified
→ FAIL
```

不得在 UI 上顯示：

```text
100G Ready
```

DPDK Linux 系統要求與 Huge Page 配置由官方文件明確提供，因此列為 Preflight 必測項。

---

# 599. Requirement Traceability

所有需求建立：

```text
Requirement ID
```

例如：

```text
MUST-07
Safe Apply
```

---

# 600. Traceability Record

格式：

```text
Requirement

Architecture Component

Implementation Module

Test Case

Status
```

---

# 601. 範例

```text
MUST-07
Safe Apply

Architecture:
Helper

Implementation:
helper/network_transaction

Tests:
SAFE-001
SAFE-002
SAFE-003
SAFE-004
```

---

# 602. 100G Traceability

例如：

```text
MUST-18
100GbE Architecture

Modules:
backend-dpdk
benchmark
dataplane

Tests:
PERF-100G-*
```

---

# 603. Test ID Namespace

```text
UNIT-

INT-

SAFE-

NODE-

PROTO-

CLI-

PACKET-

PERF-

SEC-

INSTALL-

UPGRADE-
```

---

# 604. ADR

目前所有重大決策：

```text
docs/adr/
```

例如：

```text
ADR-001-rust-core.md

ADR-006-control-data-plane.md

ADR-009-linux-dpdk.md

ADR-019-tls-control-plane.md

ADR-034-agent-runtime.md

ADR-035-dataplane-process-isolation.md
```

---

# 605. 新增 ADR

本版新增：

```text
ADR-034
Stateful operations hosted by nettool-agent

ADR-035
100G dataplane isolated into separate process

ADR-036
Privileged Helper has whitelist-only API

ADR-037
Agent / Helper / Node use separate protocols

ADR-038
SQLite is single persistent metadata store

ADR-039
Secrets stored outside SQLite

ADR-040
DPDK / AF_XDP / RIO compiled as optional backends

ADR-041
Data Plane does not use Tokio scheduler for poll loops

ADR-042
All performance resources require reservation

ADR-043
100G certification requires hardware profile
```

---

# 606. Development Branching

規格不強制指定 Git Branch 模型。

但：

```text
main
```

必須永遠保持：

```text
Buildable
```

---

# 607. Protocol Change Gate

修改：

```text
.proto

JSON Contract

CLI Flag

Error Code

Exit Code
```

必須通過：

```text
Compatibility Review
```

---

# 608. Database Change Gate

新增 Migration 時：

```text
Migration Test
+
Fresh Install Test
+
Upgrade Test
```

全部通過。

---

# 609. Data Plane Change Gate

修改 Hot Path：

```text
Packet Parser

Flow Lookup

Counter

Queue

Memory

DPDK Worker
```

必須執行：

```text
Performance Regression Test
```

---

# 610. Release Channel

建議：

```text
Development

Alpha

Beta

Stable
```

---

# 611. Alpha

必須具備：

```text
Linux DPDK POC

Basic CLI

Agent

Dataplane

100G Benchmark Harness
```

GUI 非 Alpha Blocking Requirement。

---

# 612. Beta

加入：

```text
Windows

macOS

Network Profile

Hosts

Safe Apply

GUI

Node

Packet Analysis
```

---

# 613. Stable

必須：

```text
Security Review

Installer

Upgrade

Rollback

Crash Recovery

CLI Contract Freeze

Protocol Compatibility

Hardware Certification
```

---

# 614. First Executable Milestone

第一個真正執行檔：

```text
nettool-dataplane
```

功能只做：

```text
Linux

DPDK

One NIC

RX

TX

Statistics
```

不做：

```text
GUI
SQLite
Profiles
```

---

# 615. Milestone P0

```text
DPDK environment detection
```

輸出：

```text
NIC

NUMA

Queue

Huge Page

CPU
```

---

# 616. Milestone P1

```text
DPDK RX
```

回報：

```text
Packets

Bytes

Mpps

Gbps

Drop
```

---

# 617. Milestone P2

```text
DPDK TX
```

Raw Packet Generator。

---

# 618. Milestone P3

```text
Bidirectional
```

---

# 619. Milestone P4

加入：

```text
Flow Sharding

Packet Parser

Drop Accounting
```

---

# 620. Milestone P5

加入：

```text
Agent

Resource Reservation

Dataplane IPC
```

---

# 621. Milestone P6

加入：

```text
Node Control Plane

Remote 100G Test
```

---

# 622. Milestone P7

加入：

```text
Network Core

Safe Apply

Privileged Helper
```

---

# 623. Milestone P8

加入：

```text
CLI Contract Complete
```

---

# 624. Milestone P9

加入：

```text
GUI
```

---

# 625. Repository Bootstrap

第一個 Commit 應只建立：

```text
Cargo Workspace

Core Crates

Protocol Directory

CI

Formatting

Lint

Test Skeleton

ADR
```

不要第一天就直接寫完整 DPDK Engine。

---

# 626. Coding Standard

所有 public API：

```text
MUST
```

有：

```text
Rustdoc
```

---

# 627. unsafe Policy

Workspace：

```text
unsafe
```

只允許於明確 crate，例如：

```text
dpdk-sys

platform-windows unsafe wrapper

platform-macos FFI

af-xdp low-level
```

---

# 628. unsafe Review

任何新增：

```rust
unsafe
```

必須說明：

```text
Safety Invariant

Ownership

Lifetime

Threading

Failure Behavior
```

---

# 629. Panic Policy

Library：

```text
recoverable external condition
```

不得：

```text
panic!
```

應回：

```text
Result
```

---

# 630. Fast Path Panic

Data Plane 未預期 Panic：

```text
Session FAILED
```

由 Agent 偵測 Process 結束並執行資源清理。

---

# 631. Error Type

核心：

```rust
struct NetToolError {
    code: ErrorCode,
    message: String,
    retryable: bool,
    details: ErrorDetails,
}
```

---

# 632. Error Message

```text
code
```

為穩定 API。

```text
message
```

為人類描述，可本地化。

---

# 633. Localization

v1：

```text
CLI machine output:
English identifiers

GUI:
Localizable
```

繁體中文 UI 可作正式 Locale。

---

# 634. Documentation

正式文件至少：

```text
Architecture

User Guide

CLI Reference

Protocol Specification

Benchmark Specification

Hardware Compatibility Matrix

Security Model

Troubleshooting

Developer Guide
```

---

# 635. Hardware Compatibility Matrix

每筆：

```text
OS

CPU

NIC

Firmware

Driver

Backend

Functional

Validated

100G Certified

Known Limitation
```

---

# 636. Benchmark Specification

從本文件分離：

```text
docs/benchmark/
```

正式固定：

```text
Topology

Frame Matrix

Flow Matrix

Duration

Warmup

Metrics

Certification Threshold
```

---

# 637. Threshold Freeze

第一個可靠 POC 完成前：

```text
Throughput PASS %

CPU Limit

Drop Limit
```

維持：

```text
TBD-BENCHMARK
```

不得自行填入沒有量測依據的數字。

---

# 638. Security Model 文件

必須明確畫出：

```text
User

GUI

CLI

Agent

Helper

Dataplane

Remote Node

NIC

Filesystem
```

Trust Boundary。

---

# 639. Threat Model

至少分析：

```text
Privilege Escalation

Malicious Local Client

Malicious Remote Node

Protocol Replay

Resource Exhaustion

Capture Data Exposure

Symlink Attack

Path Traversal

Unsafe NIC Rebind

Configuration Injection

Supply Chain
```

---

# 640. Packet Capture Privacy

Packet Capture 可能包含敏感網路內容。

因此：

```text
Capture
```

必須由使用者明確啟動。

---

# 641. Capture Default

預設：

```text
OFF
```

不允許背景自動保存完整 Payload。

---

# 642. Capture History

History 只保存：

```text
Metadata

Statistics

File Path

Checksum
```

不將 PCAP 內容複製進 SQLite。

---

# 643. Production Mode

正式增加：

```text
Production Safety Mode
```

開啟時：

```text
DPDK rebind

Huge Page modification

IRQ change

Network Apply
```

等操作增加明確確認。

---

# 644. Lab Mode

可提供：

```text
Lab Mode
```

降低重複確認操作。

但不能停用：

```text
Safe Apply

Privilege Validation

Resource Lock
```

---

# 645. Read-only Mode

支援：

```bash
nettool --read-only
```

只允許：

```text
Interface Query

Statistics

History

Topology
```

---

# 646. Dry Run 為一級能力

所有具變更能力 Action：

```text
SHOULD
```

支援：

```text
dry_run
```

例如：

```text
profile.apply

hosts.replace

nic.prepare_dpdk

perf.tune
```

---

# 647. Plan Output

Dry Run 回傳：

```text
Current State

Desired State

Required Privilege

Expected Side Effect

Rollback Plan
```

---

# 648. Final Architecture

```text
                           USER
                            │
               ┌────────────┴────────────┐
               ▼                         ▼
          nettool-gui                  nettool
               │                         │
               └──────────┬──────────────┘
                          │
                     Local IPC
                          │
                          ▼
                 ┌─────────────────┐
                 │ nettool-agent   │
                 │                 │
                 │ Action Service  │
                 │ Session Manager │
                 │ Node Control    │
                 │ SQLite          │
                 └───────┬─────────┘
                         │
          ┌──────────────┼─────────────────┐
          │              │                 │
          ▼              ▼                 ▼
 nettool-helper    nettool-dataplane    Remote Agent
   privileged          100G              TLS 1.3
          │              │
          ▼              ▼
 Operating System      NIC
                       │
                 ┌─────┼─────┐
                 ▼     ▼     ▼
               Socket XDP   DPDK
```

---

# 649. 核心安全界線

```text
GUI / CLI:
Unprivileged

Agent:
Unprivileged

Dataplane:
Minimal required access

Helper:
Privileged
```

---

# 650. 核心效能界線

```text
Control Plane:
Correctness
Security
Compatibility

Data Plane:
Throughput
Packet Rate
CPU Efficiency
Deterministic Resource Use
```

兩者不可混在一起最佳化。

---

# 651. Requirement Freeze

以下目前正式視為已固定：

```text
Cross-platform GUI

Cross-platform CLI

Single Action Core

Agent Architecture

Safe Apply

Privileged Helper

Hosts Profiles

Node Pairing

TLS 1.3 Control Plane

Control / Data Plane Separation

TCP / UDP Benchmark

100GbE Target

DPDK

AF_XDP

RIO

Multi-Queue

CPU Affinity

NUMA

Flow Sharding

Drop Classification

Packet Capture

Packet Analysis

CLI JSON API

Protocol Versioning

Hardware Certification
```

---

# 652. 尚未固定項目

以下保留至 POC：

```text
Exact Queue Count

Exact Burst Size

Exact Mempool Size

Exact CPU Layout

Certification Throughput Threshold

Certification Drop Threshold

Maximum Flow Count

Maximum Concurrent Sessions

Exact GUI Framework:
React vs Svelte

Exact Public Product Name

Final Control Port
```

---

# 653. POC 後才能固定的項目

100G POC 必須提供實測資料後才能決定：

```text
64B Mpps Gate

1518B Throughput Gate

Jumbo Throughput Gate

Gbps/Core

RX Queue Count

TX Queue Count

Burst Size

Mempool Size

Flow Table Capacity

Capture Performance
```

---

# 654. Implementation Definition of Done

任何 Feature 不以：

```text
Code Complete
```

視為完成。

必須：

```text
Requirement
+
Implementation
+
Unit Test
+
Integration Test
+
Error Handling
+
Audit
+
CLI
+
Documentation
```

全部完成。

如果是效能相關：

```text
+
Benchmark
```

---

# 655. 100G Feature Definition of Done

另外必須：

```text
Hardware Lab Test

NUMA Validation

Drop Validation

CPU Measurement

Sustained Test

Regression Baseline
```

---

# 656. Production Change Rule

以下變更：

```text
IP

Gateway

DNS

Route

MTU

NIC Driver

DPDK Binding

Huge Page

IRQ / CPU Affinity
```

在正式環境使用前：

```text
MUST
```

先於隔離測試環境使用相同或等價：

```text
OS

Kernel

NIC

Firmware

Driver

CPU / NUMA
```

完成驗證。

---

# 657. v0.6 最終 Architecture Decisions

新增並固定：

```text
ADR-034
使用 nettool-agent 作為唯一 Runtime Authority

ADR-035
100G Data Plane 使用獨立 Process

ADR-036
Helper API 必須 whitelist-only

ADR-037
Agent、Helper、Node Protocol 分離

ADR-038
SQLite 為 Metadata 唯一主要資料庫

ADR-039
Secret 不保存於 SQLite

ADR-040
Performance Backend 使用 Cargo Feature 隔離

ADR-041
DPDK Poll Worker 不依賴 async scheduler

ADR-042
100G Resource 必須先 Reservation

ADR-043
Certification 綁定 Hardware Profile

ADR-044
Crash Recovery 為 Agent 必要能力

ADR-045
Safe Apply Deadline 最終由 Helper 持有

ADR-046
Data Plane Raw Packet 不經 IPC / GUI

ADR-047
Hardware Benchmark Threshold 必須由實測固定
```

---

# 658. 下一步正式進入 Implementation

完成 v0.6 後，不再建議新增大型架構文件。

下一步：

```text
Phase 0
Repository Bootstrap

Phase 1
Linux DPDK POC

Phase 2
Benchmark Harness

Phase 3
Agent + Dataplane IPC

Phase 4
Node-to-Node 100G

Phase 5
Packet Analyzer

Phase 6
Network Core + Helper

Phase 7
CLI Contract

Phase 8
Windows / macOS

Phase 9
GUI

Phase 10
Certification / Stable Release
```

---

# 659. 第一個 Repository 驗收點

Repository 建立後第一個可驗收命令：

```bash
nettool-dataplane probe
```

應輸出：

```text
Platform

CPU

NUMA

Huge Pages

NIC

PCI Address

Driver

Link Speed

RX Queues

TX Queues

DPDK Capability

AF_XDP Capability
```

JSON：

```bash
nettool-dataplane probe --output json
```

---

# 660. 第一個 100G 驗收點

第二個可驗收命令：

```bash
nettool-dataplane rx \
  --backend dpdk \
  --interface <pci-address>
```

必須至少提供：

```text
RX Packets

RX Bytes

Gbps

Mpps

NIC Drop

Worker Count

Queue Count

CPU Mapping

NUMA
```

這將成為整個 100GbE Engine 的第一個可重複 Benchmark 基準。

---

# 661. 規格狀態

截至 v0.6：

```text
Product Requirement:
DEFINED

Core Architecture:
DEFINED

Privilege Architecture:
DEFINED

Node Protocol:
DEFINED

CLI Contract:
DEFINED

100G Data Plane Architecture:
DEFINED

Persistence:
DEFINED

Process Architecture:
DEFINED

CI / Test Strategy:
DEFINED

100G Numeric Certification Threshold:
WAITING FOR POC
```

因此：

> 本專案目前已具備足夠規格，可以停止大型架構設計並開始建立實際 Repository 與 Linux DPDK 100GbE POC。
# Node Protocol 與 CLI Contract 詳細技術規格

版本：0.5 Draft  
承接：

```text
SRS v0.1
System Design v0.2
100GbE Architecture v0.3
Speed / Packet Engine v0.4
```

---

# 303. 本版目的

本文件正式定義：

```text
Node Control Protocol

Node Pairing / Trust

Capability Negotiation

Speed Test Session

Data Plane Association

UDP Measurement Protocol

Protocol Versioning

CLI Command Tree

CLI JSON Contract

Error / Exit Code Contract
```

核心目標：

> Node A 與 Node B 即使執行不同版本，只要協定仍在相容範圍內，就能安全協商可共同使用的能力。

---

# 304. Node Protocol 分層

正式架構：

```text
┌────────────────────────────────────┐
│          Application Layer         │
│                                    │
│ Pair / Capability / Session / Stat │
└────────────────┬───────────────────┘
                 │
                 ▼
┌────────────────────────────────────┐
│          Control Protocol          │
│                                    │
│             Protobuf               │
└────────────────┬───────────────────┘
                 │
                 ▼
┌────────────────────────────────────┐
│             Framing                │
│                                    │
│       Length-prefixed binary       │
└────────────────┬───────────────────┘
                 │
                 ▼
┌────────────────────────────────────┐
│            TLS 1.3                 │
└────────────────┬───────────────────┘
                 │
                 ▼
               TCP
```

Data Plane：

```text
TCP
UDP
AF_XDP
DPDK
RIO
```

不經過 Protobuf。

---

# 305. 為什麼 Control Plane 使用 Protobuf

Control Plane 的要求是：

```text
Strong Schema

Binary

Backward Compatibility

Forward Evolution

Cross-language

Low Overhead
```

Protocol Buffers 的 binary wire format允許加入新欄位而讓舊版程式仍處理已知內容；Proto3 解析器也會保留未知欄位。

因此正式規定：

```text
Control Plane Serialization:
Protocol Buffers
```

---

# 306. Protobuf 相容規則

任何已發布的：

```text
field number
```

不得：

```text
reuse
renumber
repurpose
```

刪除欄位後：

```protobuf
reserved 7;
```

必須保留原 field number。

Protocol Buffers 官方亦明確要求 field number 不可重新利用。

---

# 307. 禁止 Required Field

Protocol Schema 不使用 Required Field。

新增功能：

```text
optional

repeated

new message
```

完成。

Protocol Buffers 官方同樣建議避免新增 required field，以降低 schema 演進問題。

---

# 308. Control Plane Transport

正式指定：

```text
TCP
+
TLS 1.3
```

TLS 1.3 依 RFC 8446 提供：

```text
Confidentiality
Integrity
Peer Authentication
```

等安全機制。

Rust 實作優先：

```text
rustls
```

rustls 支援 TLS 1.3。

---

# 309. TLS Policy

Node Control Plane：

```text
Minimum TLS:
1.3

Maximum:
1.3
```

第一版禁止：

```text
TLS 1.0
TLS 1.1
TLS 1.2 downgrade
```

未來 TLS 版本升級必須經：

```text
Protocol ADR
+
Security Review
```

---

# 310. Control Plane 與 Benchmark 分離

TLS 只保護：

```text
Pairing

Authentication

Capabilities

Commands

Configuration

Statistics

Results
```

100G Benchmark Payload：

```text
NOT transported inside TLS Control Plane
```

原因：

> 否則測到的是 TLS / crypto throughput，而不純粹是目標 Network Data Plane。

---

# 311. Control Connection

建立順序：

```text
TCP Connect
    ↓
TLS 1.3
    ↓
Framing Negotiation
    ↓
Hello
    ↓
Protocol Negotiation
    ↓
Authentication / Trust Check
    ↓
Capability Exchange
    ↓
READY
```

---

# 312. Control Frame

TLS stream 上使用固定：

```text
12-byte Frame Header
+
Protobuf Payload
```

---

# 313. Control Frame Header

Wire format：

```text
Offset  Size  Field
--------------------------------
0       4     Magic
4       1     Framing Version
5       1     Flags
6       2     Reserved
8       4     Payload Length
```

Total：

```text
12 bytes
```

---

# 314. Magic

固定：

```text
NTCP
```

Hex：

```text
4E 54 43 50
```

代表：

```text
Network Tool Control Protocol
```

即使未來產品名稱改變，Wire Identifier 不更動。

---

# 315. Integer Encoding

Frame Header：

```text
Network Byte Order
Big Endian
```

Protobuf Payload 則使用 Protobuf 自身 wire encoding。

---

# 316. Framing Version

第一版：

```text
1
```

注意：

```text
Framing Version
```

與：

```text
Application Protocol Version
```

是兩個不同概念。

---

# 317. Payload Length

型別：

```text
uint32
```

第一版安全限制：

```text
Maximum Control Payload:
1 MiB
```

若：

```text
payload_length > configured maximum
```

立即：

```text
CONTROL_FRAME_TOO_LARGE
```

並中止 Connection。

---

# 318. Compression

v1：

```text
Compression:
DISABLED
```

Control message 本身很小，不值得增加：

```text
CPU

complexity

attack surface
```

Flags 必須：

```text
0
```

未知 Flag：

```text
PROTOCOL_UNSUPPORTED_FLAG
```

---

# 319. Protocol Envelope

每個 Payload：

```protobuf
message Envelope {
    uint32 protocol_major = 1;
    uint32 protocol_minor = 2;

    bytes request_id = 3;

    oneof message {
        HelloRequest hello_request = 10;
        HelloResponse hello_response = 11;

        PairRequest pair_request = 20;
        PairResponse pair_response = 21;

        CapabilityRequest capability_request = 30;
        CapabilityResponse capability_response = 31;

        PrepareTest prepare_test = 40;
        PrepareTestResponse prepare_test_response = 41;

        StartTest start_test = 42;
        StopTest stop_test = 43;

        TestStatus test_status = 44;
        TestResult test_result = 45;

        Ping ping = 50;
        Pong pong = 51;

        Error error = 100;
    }
}
```

此為第一版 Schema 基準。

---

# 320. Protocol Version

第一版：

```text
Major:
1

Minor:
0
```

---

# 321. Major Version

Major 不相容時：

```text
PROTOCOL_MAJOR_INCOMPATIBLE
```

立即拒絕。

---

# 322. Minor Version

不同 Minor：

```text
Allowed
```

只要：

```text
Supported Feature Intersection
```

仍能正常運作。

---

# 323. Version Negotiation

Node A：

```text
1.0 - 1.3
```

Node B：

```text
1.0 - 1.2
```

結果：

```text
1.2
```

---

# 324. Capability Negotiation

不要以：

```text
app version
```

推斷功能。

例如：

```text
Node A v2.4
Node B v2.6
```

仍必須實際交換 Capability。

---

# 325. Capability

概念：

```protobuf
message Capability {
    uint32 id = 1;

    uint32 min_version = 2;
    uint32 max_version = 3;

    bool available = 4;
}
```

---

# 326. Capability ID Registry

例如：

```text
0x0001 TCP_SPEED

0x0002 UDP_SPEED

0x0003 BIDIRECTIONAL

0x0004 LATENCY

0x0005 DPDK

0x0006 AF_XDP

0x0007 RIO

0x0008 PACKET_CAPTURE

0x0009 PACKET_ANALYSIS

0x000A PCAPNG

0x000B JUMBO_FRAME

0x000C RAW_PACKET_GENERATOR

0x000D LATENCY_UNDER_LOAD
```

Capability ID：

```text
MUST NOT be reused
```

---

# 327. Hardware Capability

交換：

```text
Platform

Architecture

CPU

Logical CPU

NUMA Nodes

NIC

NIC Link Speed

RX Queue

TX Queue

MTU

RSS

DPDK

AF_XDP

AF_XDP Zero Copy

RIO
```

---

# 328. Node Identity

第一次執行：

```text
Generate

Node ID
+
Identity Key
```

Node ID：

```text
128-bit random identifier
```

表示設備邏輯 Identity。

---

# 329. Identity Key

Identity Key：

```text
Asymmetric Key Pair
```

Private Key 必須存於平台安全儲存區。

不得：

```text
plaintext SQLite
```

---

# 330. Trust Record

保存：

```text
Node ID

Node Name

Public Key Fingerprint

First Seen

Last Seen

Trust Status
```

---

# 331. Pairing

第一次：

```text
Node A
   │
   │ Pair
   ▼
Node B
```

顯示：

```text
Node:
Node-B

Fingerprint:
SHA-256
XX:XX:XX:...
```

使用者必須確認。

---

# 332. Fingerprint

完整 Fingerprint：

```text
SHA-256
```

為真正 Cryptographic Identifier。

GUI 可另外提供：

```text
Short Authentication String
```

提升易用性。

但短碼不得取代完整 Trust Identity。

---

# 333. Pairing Trust Model

第一次：

```text
Untrusted
     ↓
User Verification
     ↓
Trusted
```

後續：

```text
Mutual Authentication
```

如果 Public Key 改變：

```text
NODE_IDENTITY_CHANGED
```

不得自動接受。

---

# 334. Node Certificate Rotation

若 Identity Key 改變：

```text
Re-pair Required
```

不得：

```text
Silent Trust Migration
```

---

# 335. Node State Machine

正式狀態：

```text
DISCONNECTED

CONNECTING

TLS_HANDSHAKE

HELLO

AUTHENTICATING

CAPABILITY_NEGOTIATION

READY

PREPARING

TEST_READY

RUNNING

FINALIZING

COMPLETED

FAILED

CANCELED
```

---

# 336. 合法狀態轉移

例如：

```text
READY
 ↓
PREPARING
 ↓
TEST_READY
 ↓
RUNNING
 ↓
FINALIZING
 ↓
COMPLETED
```

---

# 337. 非法轉移

例如：

```text
READY
 ↓
FINALIZING
```

回傳：

```text
INVALID_SESSION_STATE
```

---

# 338. Session ID

每次 Benchmark：

```text
128-bit UUID
```

Session ID 在 Control Plane、Data Plane、Log、Result 中保持一致。

---

# 339. Request ID

每次 Control Request：

```text
128-bit UUID
```

用於：

```text
Tracing

Retry

Idempotency

Log correlation
```

---

# 340. Mutating Operation ID

任何會：

```text
Start

Stop

Apply

Change
```

的操作皆必須支援：

```text
Operation ID
```

避免因網路 Retry 重複執行。

---

# 341. Idempotency

例如：

```text
StartTest
operation_id = ABC
```

Node 已處理過：

```text
ABC
```

再次收到時：

```text
return original result
```

不得再建立第二個 Session。

---

# 342. Heartbeat

READY 狀態維持：

```text
Ping
Pong
```

Heartbeat 間隔：

```text
Configurable
```

預設建議值：

```text
2 seconds
```

Connection Timeout：

```text
Configurable
```

預設建議：

```text
10 seconds
```

以上屬初始設定值，可於實測後調整。

---

# 343. Prepare Test

Client：

```text
PrepareTest
```

內容：

```text
Session ID

Test Type

Backend

Direction

Duration

Warmup

Cooldown

Streams

Frame Size

Payload Size

Target Rate

MTU
```

---

# 344. Test Type

```text
TCP_SOCKET

UDP_SOCKET

RAW_PACKET

PACKET_RX

PACKET_TX

PACKET_ANALYSIS

CAPTURE
```

---

# 345. Direction

```text
A_TO_B

B_TO_A

BIDIRECTIONAL
```

---

# 346. Prepare Response

Server 驗證：

```text
Backend Available

NIC Available

NIC Ownership

MTU

Queue

CPU

NUMA

Memory

Privilege

Port
```

結果：

```text
READY
```

或明確 Error。

---

# 347. Test Synchronization

兩端：

```text
PREPARE
   ↓
READY
```

完成後才：

```text
START
```

禁止其中一端尚未完成 Buffer / Socket / Queue 初始化就開始 Measurement。

---

# 348. Test Phase

```text
WARMUP

MEASURE

COOLDOWN
```

只有：

```text
MEASURE
```

計入主要 Throughput Result。

---

# 349. Monotonic Clock

Duration 一律使用：

```text
Monotonic Clock
```

不得使用：

```text
System Wall Clock
```

計算 benchmark 時間。

---

# 350. Wall Clock

Wall Clock 只用於：

```text
Log Timestamp

Report Timestamp
```

---

# 351. Data Plane Port

TCP / UDP Data Plane Port：

```text
Dynamic Allocation
```

由 Receiver 在：

```text
PrepareTestResponse
```

告知 Sender。

---

# 352. 禁止固定大量 Data Ports

不要預留：

```text
50000
50001
50002
...
```

作每條 Stream 的固定 Port。

優先使用：

```text
dynamic ephemeral allocation
```

---

# 353. Control Port

Control Port：

```text
Configurable
```

正式產品 Default Port：

```text
TBD before public release
```

在正式產品名稱及 Service Registration 決定前，不將任意 Port 號永久寫死為協定標準。

---

# 354. Data Plane Authorization

每個 Session 建立：

```text
Data Plane Authorization Context
```

包含：

```text
Session ID

Source Node

Source Address

Destination Address

Protocol

Ports

Expiration
```

---

# 355. Data Plane 不直接使用 TLS

100G 測速：

```text
Plain TCP

Plain UDP

Raw Ethernet
```

可以是必要模式。

這是刻意設計：

> 測量 Network / NIC / TCP Stack，而不是 Encryption Engine。

---

# 356. Data Plane Security Boundary

未加密 Data Plane 僅允許：

```text
Trusted Benchmark Network
```

若跨：

```text
Internet

Untrusted Network
```

必須提供另一個：

```text
Secure Benchmark Mode
```

其效能結果必須標示：

```text
Encrypted Data Plane
```

且不能與 Raw 100G Certification 結果直接比較。

---

# 357. UDP Measurement Protocol

UDP Benchmark 禁止：

```text
JSON

Protobuf

CBOR
```

進入 per-packet Hot Path。

使用固定二進位 Header。

---

# 358. UDP Compact Header v1

固定：

```text
16 bytes
```

格式：

```text
Offset  Size  Field
---------------------------------
0       1     Signature / Version
1       1     Flags
2       2     Stream ID
4       4     Session Tag
8       8     Sequence Number
```

---

# 359. Signature / Version

v1：

```text
0xA1
```

其中：

```text
A = Protocol Signature
1 = Version
```

---

# 360. Flags

```text
0x01 Extended Timestamp

0x02 Echo Request

0x04 Echo Response

0x08 Final Packet
```

其餘保留。

---

# 361. Stream ID

```text
uint16
```

最大理論：

```text
65535 streams
```

實際 Stream 數受系統能力限制。

---

# 362. Session Tag

```text
uint32
```

由 Session ID 派生的本地快速識別值。

但真正 Session Identity 仍是：

```text
128-bit Session ID
```

Session Tag 只用於 Hot Path Lookup。

---

# 363. Sequence Number

必須：

```text
uint64
```

禁止使用：

```text
uint32
```

作為 100G 長時間 UDP Sequence。

因為 32-bit counter 在超高 PPS 下會很快回繞。

---

# 364. Extended UDP Header

如需 Tx Timestamp：

```text
Compact Header
16 bytes

+

TX Timestamp
8 bytes
```

總共：

```text
24 bytes
```

---

# 365. Timestamp

```text
uint64

Local Monotonic Nanoseconds
```

但不得拿：

```text
Node A timestamp
-
Node B timestamp
```

直接計算 One-Way Latency。

---

# 366. 64-byte Frame 特殊要求

100GbE：

```text
64-byte Ethernet Frame
```

是非常重要的 Mpps Worst Case。

因此不能讓 Measurement Header 任意膨脹。

---

# 367. IPv4 UDP 最小 Benchmark

IPv4：

```text
Ethernet Header  14
IPv4             20
UDP               8
Measurement      16
FCS                4
--------------------
                  62
```

Ethernet 最小 Frame：

```text
64 bytes
```

因此可由 Ethernet padding 補足。

所以：

```text
IPv4 + UDP + Compact Header
```

仍可進行 64-byte Ethernet Frame 測試。

---

# 368. IPv6 注意事項

IPv6 Header：

```text
40 bytes
```

因此：

```text
Ethernet
+
IPv6
+
UDP
+
16-byte Measurement Header
```

已超過 64-byte Frame。

所以不得將：

```text
IPv6 UDP measurement
```

與：

```text
64-byte raw Ethernet benchmark
```

視為相同測試。

---

# 369. 64B Raw Benchmark

真正：

```text
64-byte Line-rate Packet Test
```

使用：

```text
DPDK Raw Ethernet
```

模式。

例如：

```text
Custom EtherType
+
Measurement Header
```

---

# 370. Benchmark Profile 分開

至少：

```text
raw-l2-64

ipv4-udp-min

ipv6-udp-min

tcp-stream

jumbo
```

報表不能只寫：

```text
64B Test
```

而不說 Protocol Stack。

---

# 371. UDP Loss

Receiver 使用：

```text
64-bit Sequence
```

計算：

```text
Received

Missing

Duplicate

Out-of-order
```

---

# 372. Packet Loss 定義

UDP Active Test：

```text
Sequence Loss
```

才可作為主動 Network/Data Plane Loss 指標。

但仍需同時顯示：

```text
NIC Drop

Application Drop

Ring Drop
```

避免錯誤歸因。

---

# 373. Jitter

正式區分：

```text
Arrival Jitter

RTT Jitter

One-way Jitter
```

---

# 374. Arrival Jitter

可由：

```text
Receiver packet arrival intervals
```

計算。

不依賴兩台主機 Clock Sync。

---

# 375. RTT Probe

使用獨立：

```text
Echo Request

Echo Response
```

封包。

不應從 Bulk Throughput Packet 推估 RTT。

---

# 376. One-Way Latency

預設：

```text
DISABLED
```

只有確認：

```text
Clock Synchronization Quality
```

符合條件後啟用。

例如未來：

```text
PTP
```

整合。

---

# 377. Session Result

Result 至少包含：

```text
Session ID

Protocol Version

Node A

Node B

Backend

Direction

Protocol

Frame Size

Payload Size

Streams

Duration

TX Bytes

RX Bytes

TX Packets

RX Packets

Throughput

Mpps

Sequence Loss

NIC Drop

Ring Drop

Analyzer Drop

CPU

NUMA

Confidence
```

---

# 378. CLI 設計原則

CLI 正式名稱暫定：

```text
nettool
```

所有 GUI 核心操作：

```text
MUST
```

存在 CLI 對應命令。

---

# 379. CLI Parser

Rust CLI 建議：

```text
clap
```

其 derive API 可用 `Parser`、`Args`、`Subcommand` 等型別建立結構化命令樹。

---

# 380. CLI Command Tree

正式第一版：

```text
nettool

├── interface
│   ├── list
│   ├── show
│   └── watch
│
├── profile
│   ├── list
│   ├── show
│   ├── create
│   ├── edit
│   ├── delete
│   ├── apply
│   ├── confirm
│   ├── rollback
│   ├── import
│   └── export
│
├── hosts
│   ├── list
│   ├── add
│   ├── remove
│   ├── enable
│   ├── disable
│   ├── backup
│   └── restore
│
├── diagnose
│   ├── ping
│   ├── traceroute
│   ├── dns
│   └── tcp
│
├── node
│   ├── start
│   ├── stop
│   ├── status
│   ├── discover
│   ├── pair
│   ├── unpair
│   ├── list
│   └── show
│
├── speed
│   ├── run
│   ├── cancel
│   ├── status
│   └── result
│
├── packet
│   ├── stats
│   ├── capture
│   ├── analyze
│   └── flows
│
├── perf
│   ├── topology
│   ├── backend
│   ├── tune
│   └── benchmark
│
├── history
│   ├── list
│   ├── show
│   └── export
│
└── config
    ├── get
    ├── set
    └── show
```

---

# 381. Global CLI Options

所有命令統一支援適用的：

```text
--output text|json|jsonl

--timeout <duration>

--no-color

--quiet

--verbose

--config <path>

--request-id <uuid>
```

變更型操作另外：

```text
--dry-run

--yes

--operation-id <uuid>
```

---

# 382. Human Output

預設：

```text
--output text
```

針對人類閱讀。

允許：

```text
Color

Table

Progress

Units
```

---

# 383. JSON Output

```bash
nettool interface list --output json
```

必須只在：

```text
stdout
```

輸出 JSON。

---

# 384. stderr

以下一律：

```text
stderr
```

```text
Debug Log

Warning Log

Diagnostic Trace
```

如果：

```text
--output json
```

則 stderr 不得污染 stdout JSON。

---

# 385. JSON 不得包含 ANSI

`--output json`：

```text
ANSI color:
DISABLED
```

無論 terminal 是否支援色彩。

---

# 386. JSON Contract

所有 JSON 使用共同 Envelope：

```json
{
  "schema_version": "1.0",
  "command": "interface.list",
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "success": true,
  "data": {},
  "warnings": [],
  "error": null
}
```

---

# 387. JSON Schema Version

```text
Major.Minor
```

例如：

```text
1.0
```

---

# 388. JSON Major

Breaking Change：

```text
Major++
```

例如：

```text
1.x
→
2.0
```

---

# 389. JSON Minor

只允許：

```text
Additive Change
```

例如增加：

```text
optional field
```

可：

```text
1.0
→
1.1
```

---

# 390. JSON Consumer Rule

Consumer：

```text
MUST ignore unknown fields
```

除非使用：

```text
strict validation mode
```

---

# 391. 64-bit Counter JSON

為避免部分 JSON Runtime 對超過：

```text
2^53
```

整數失去精度：

以下值一律以：

```text
decimal string
```

輸出。

---

# 392. Decimal String Field

例如：

```json
{
  "rx_bytes": "128900123456789",
  "rx_packets": "148809523",
  "throughput_bps": "99730000000",
  "duration_ns": "10000000000"
}
```

---

# 393. Ratio

比例可使用：

```text
number
```

例如：

```json
{
  "packet_loss_percent": 0.0132,
  "cpu_percent": 62.4
}
```

---

# 394. Unit 必須寫入 Field Name

禁止：

```json
{
  "speed": 100
}
```

必須：

```json
{
  "throughput_bps": "100000000000"
}
```

或：

```json
{
  "latency_ns": "32500"
}
```

---

# 395. JSONL

即時指令：

```text
speed run

packet stats

packet flows

interface watch
```

支援：

```text
--output jsonl
```

---

# 396. JSONL Event

每行：

```json
{
  "schema_version": "1.0",
  "event": "speed.sample",
  "session_id": "...",
  "timestamp": "...",
  "rx_bps": "98620000000"
}
```

---

# 397. JSONL Event Type

至少：

```text
session.started

session.phase

speed.sample

packet.sample

warning

session.completed

session.failed
```

---

# 398. Final JSONL Event

成功：

```text
session.completed
```

失敗：

```text
session.failed
```

一定為最後事件。

---

# 399. CLI Speed Command

基本：

```bash
nettool speed run node-b
```

---

# 400. TCP

```bash
nettool speed run node-b \
  --protocol tcp \
  --duration 10s \
  --streams auto
```

---

# 401. UDP

```bash
nettool speed run node-b \
  --protocol udp \
  --rate 100G \
  --duration 10s
```

---

# 402. Bidirectional

```bash
nettool speed run node-b \
  --protocol tcp \
  --direction bidirectional
```

---

# 403. Backend

```bash
nettool speed run node-b \
  --backend dpdk
```

---

# 404. Frame Size

Raw：

```bash
nettool speed run node-b \
  --protocol raw \
  --frame-size 64
```

---

# 405. Auto Tune

```bash
nettool speed run node-b \
  --protocol tcp \
  --streams auto \
  --auto-tune
```

---

# 406. Latency Under Load

```bash
nettool speed run node-b \
  --protocol tcp \
  --latency-under-load
```

---

# 407. CPU Affinity

Advanced：

```bash
nettool speed run node-b \
  --backend dpdk \
  --cpus 4-19
```

一般使用者使用：

```text
auto
```

---

# 408. NUMA

```bash
nettool speed run node-b \
  --numa auto
```

可指定：

```bash
--numa 1
```

---

# 409. Safety

如果：

```text
NIC NUMA = 1
```

而使用者指定：

```text
--numa 0
```

CLI 必須警告：

```text
PERF_NUMA_MISMATCH
```

100G Certification Mode：

```text
FAIL
```

---

# 410. Profile Apply

```bash
nettool profile apply lab
```

預設必須：

```text
Safe Apply
```

---

# 411. Safe Apply CLI

```bash
nettool profile apply lab \
  --confirm-timeout 30s
```

完成後：

```bash
nettool profile confirm
```

---

# 412. No Confirmation

Timeout：

```text
Automatic Rollback
```

即使 CLI 已結束。

---

# 413. Explicit Rollback

```bash
nettool profile rollback
```

---

# 414. Dry Run

```bash
nettool profile apply lab \
  --dry-run
```

不得變更：

```text
NIC

IP

Route

DNS

Hosts
```

---

# 415. Error Envelope

例如：

```json
{
  "schema_version": "1.0",
  "command": "speed.run",
  "request_id": "...",
  "success": false,
  "data": null,
  "warnings": [],
  "error": {
    "code": "PERF_NUMA_MISMATCH",
    "message": "Selected CPU NUMA node does not match the NIC NUMA node.",
    "retryable": false,
    "details": {
      "nic_numa": 1,
      "cpu_numa": 0
    }
  }
}
```

---

# 416. Error Code

Error Code 必須：

```text
Stable

Machine-readable

Never localized
```

例如：

```text
PERF_NUMA_MISMATCH
```

GUI 可翻譯：

```text
選擇的 CPU NUMA Node 與 NIC 不一致。
```

但內部 Error Code 永遠相同。

---

# 417. Error Namespace

```text
CLI_

CONFIG_

PROFILE_

HOSTS_

NETWORK_

NODE_

AUTH_

PROTOCOL_

SPEED_

PACKET_

PERF_

STORAGE_

SYSTEM_
```

---

# 418. Exit Code Registry

正式第一版：

```text
0
SUCCESS

2
CLI_USAGE_ERROR

10
PERMISSION_DENIED

11
RESOURCE_NOT_FOUND

12
RESOURCE_CONFLICT

13
VALIDATION_FAILED

20
NETWORK_APPLY_FAILED

21
ROLLBACK_FAILED

30
CONNECTION_FAILED

31
AUTHENTICATION_FAILED

32
PROTOCOL_INCOMPATIBLE

33
TIMEOUT

40
BACKEND_UNAVAILABLE

41
PERFORMANCE_PRECONDITION_FAILED

42
BENCHMARK_FAILED

50
PACKET_CAPTURE_FAILED

51
PACKET_ANALYSIS_FAILED

60
COMPLETED_DEGRADED

70
INTERNAL_ERROR
```

---

# 419. Exit Code 與 Error Code 不相同

例如：

```text
Exit Code:
41
```

可能對應：

```text
PERF_NUMA_MISMATCH

PERF_HUGEPAGE_INSUFFICIENT

PERF_ZERO_COPY_UNAVAILABLE
```

Exit Code 是分類。

Error Code 是精確原因。

---

# 420. Warning 不等於 Failure

例如：

```text
AF_XDP available
Zero-copy unavailable
```

Compatibility Mode 可以：

```text
warning
```

但：

```text
100G Certification Mode
```

則是：

```text
failure
```

---

# 421. Degraded Result

如果 Test 完成但：

```text
Capture Drop > 0
```

可以：

```text
success = true
```

但同時：

```text
confidence = MEDIUM
```

與：

```text
warnings
```

存在。

CLI Exit Code 可使用：

```text
60
COMPLETED_DEGRADED
```

---

# 422. GUI / CLI Mapping Registry

系統維護：

```text
Action Registry
```

例如：

```text
GUI Action:
Apply Profile

Core Action:
profile.apply

CLI:
nettool profile apply
```

---

# 423. GUI 不自行建立另一套操作

GUI：

```text
button click
```

必須轉成：

```text
Core Command
```

相同 Core Command 亦由 CLI 呼叫。

---

# 424. Show CLI

GUI 每個主要操作建議提供：

```text
Show CLI
```

例如：

```text
Apply Lab Profile
```

顯示：

```bash
nettool profile apply lab
```

---

# 425. GUI 高階設定

例如 GUI：

```text
100G Benchmark

Backend:
DPDK

Queues:
Auto

CPU:
Auto

NUMA:
Auto
```

Show CLI：

```bash
nettool perf benchmark \
  --profile 100g-cert \
  --backend dpdk \
  --queues auto \
  --cpus auto \
  --numa auto
```

---

# 426. CLI Stability Policy

正式 Release 後：

```text
command name

flag name

JSON field

error code

exit code
```

皆屬 Public API。

不得任意變更。

---

# 427. Deprecated CLI

例如未來：

```text
--threads
```

改成：

```text
--streams
```

不可立即刪除。

先：

```text
Deprecated
```

並提供明確 Warning。

---

# 428. Protocol Compatibility Test

CI 必須保存：

```text
Protocol v1 golden data
```

每次 build：

```text
new version
```

必須能解析舊版 fixture。

---

# 429. CLI Contract Test

CI 必須保存：

```text
CLI JSON Golden Files

JSON Schema

Exit Code Tests

Error Code Tests
```

---

# 430. Node Compatibility Matrix

至少測：

```text
Current ↔ Current

Current ↔ Previous Minor

Previous Minor ↔ Current
```

Major Version Upgrade 時另外建立 Migration Test。

---

# 431. Fuzz Test

Control Protocol 必須 fuzz：

```text
Frame Header

Payload Length

Malformed Protobuf

Unknown Message

Oversized Message
```

---

# 432. UDP Parser Fuzz

必須測：

```text
0 byte

1 byte

15 byte

16 byte

Malformed version

Unknown flags

Maximum stream id

Sequence wrap
```

---

# 433. Sequence Wrap

因為採：

```text
uint64
```

即使 100G 最小 frame 長時間執行，也不應在一般 Benchmark 期間發生回繞。

---

# 434. Session Limits

Node 必須配置：

```text
Maximum Concurrent Sessions

Maximum Streams

Maximum Packet Rate

Maximum Duration

Maximum Capture Storage
```

避免未授權或設定錯誤造成：

```text
Resource Exhaustion
```

---

# 435. Trusted Node 不代表無限制

即使 Trusted：

```text
resource policy
```

仍須執行。

例如：

```text
Maximum:
1 active 100G test
```

可由管理者設定。

---

# 436. 100G Session Reservation

執行：

```text
DPDK
```

測試前必須 Reserve：

```text
NIC

Queues

CPUs

Huge Pages

Memory Pool
```

---

# 437. Reservation Conflict

另一 Session 已占用：

```text
RESOURCE_CONFLICT
```

不得偷偷分享同一個：

```text
DPDK Queue
```

---

# 438. Cancellation

```bash
nettool speed cancel <session-id>
```

Control Plane：

```text
CancelSession
```

---

# 439. Cancellation 必須 Idempotent

已取消：

```text
CancelSession
```

再次收到：

```text
CANCELED
```

不得回傳 Internal Error。

---

# 440. Crash Recovery

Node 啟動後需檢查：

```text
orphaned sessions
```

及：

```text
DPDK port ownership

temporary files

capture files

pending rollback
```

---

# 441. Benchmark Result Integrity

結果保存：

```text
Result

Environment Snapshot

Config

Hardware Profile

Software Version
```

並產生：

```text
SHA-256 checksum
```

以便比較後續測試。

---

# 442. Result Reproducibility

任何 100G Certification Result 必須可以回答：

```text
Which OS?

Which Kernel?

Which CPU?

Which NIC?

Which Firmware?

Which Driver?

Which DPDK?

Which Queue Count?

Which CPUs?

Which NUMA?

Which Frame Size?

Which Flow Count?
```

缺少其中核心資料：

```text
NOT CERTIFIABLE
```

---

# 443. v0.5 正式 ADR

新增：

```text
ADR-019
Node Control Plane 使用 TCP + TLS 1.3

ADR-020
Node Control Message 使用 Protobuf

ADR-021
Control Plane 使用固定 Length-prefixed Frame

ADR-022
Protocol Version 與 Capability Version 分離

ADR-023
Pairing 後使用 Persistent Node Trust

ADR-024
Data Plane 不使用 Protobuf

ADR-025
UDP Benchmark 使用固定 Binary Header

ADR-026
UDP Sequence 使用 uint64

ADR-027
64B Raw Benchmark 與 UDP Benchmark 分開

ADR-028
CLI JSON 為正式 Public API

ADR-029
64-bit Counter 以 JSON Decimal String 輸出

ADR-030
Error Code 與 Exit Code 分離

ADR-031
所有 GUI 核心操作必須映射至 CLI/Core Action

ADR-032
Mutating Operation 必須支援 Idempotency

ADR-033
100G Session 必須進行 Resource Reservation
```

---

# 444. 到 v0.5 為止的核心架構

```text
                     ┌───────────┐
                     │    GUI    │
                     └─────┬─────┘
                           │
                     Action Registry
                           │
             ┌─────────────┴─────────────┐
             │                           │
             ▼                           ▼
            CLI                     Application Core
                                         │
                      ┌──────────────────┼──────────────────┐
                      │                  │                  │
                      ▼                  ▼                  ▼
                 Network Core        Node Core         Packet Core
                      │                  │                  │
                      │           TLS + Protobuf            │
                      │                  │                  │
                      ▼                  ▼                  ▼
                 Privileged         Control Plane       Data Plane
                   Helper                                  │
                                                   ┌───────┼───────┐
                                                   ▼       ▼       ▼
                                                 Socket  AF_XDP   DPDK
```

---

# 445. 開始實作前仍需固定的最後一層

到 v0.5 後：

```text
Architecture
Protocol
CLI Contract
```

已具備足夠明確的邊界。

下一階段不應再持續增加大型功能。

應進入：

```text
v0.6
Implementation Blueprint
```

內容應固定：

```text
Rust Workspace

crate dependency graph

trait definitions

domain models

Protobuf .proto layout

SQLite schema

IPC protocol

Privileged Helper API

configuration paths

build features

feature flags

CI jobs

POC source tree

first executable milestones
```

完成 v0.6 後即可直接開始建立 Repository 與第一個 100G Linux/DPDK POC。
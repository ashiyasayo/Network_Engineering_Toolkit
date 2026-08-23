# 100GbE Speed Engine 與 Packet Engine 詳細技術規格

版本：0.4 Draft  
承接：

```text
SRS v0.1
System Design v0.2
100GbE Architecture Amendment v0.3
```

---

# 150. 本規格目的

本文件定義：

```text
Speed Engine
Packet Engine
100GbE Data Plane
```

內部架構。

目標包含：

```text
100GbE TCP / UDP 測速

100GbE Packet Generation

100GbE Packet Receive

100GbE Real-time Packet Analysis

Multi-Queue

RSS

NUMA Awareness

CPU Affinity

Flow Sharding

Drop Accounting

Benchmark / Certification
```

本文件不包含 GUI 視覺細節。

---

# 151. 設計原則

100G Data Plane 必須遵守：

```text
No blocking I/O

No per-packet dynamic allocation

No per-packet logging

No per-packet GUI event

No global packet lock

No unbounded queue

No per-packet JSON serialization

No per-packet database transaction
```

所有高速資料處理應採：

```text
Batch

Preallocation

Queue locality

CPU locality

NUMA locality

Sharding

Bounded buffering

Periodic aggregation
```

DPDK 目前的 PMD 架構本身即採直接處理 RX/TX descriptor、polling、burst API 與 per-queue/per-core 模型；官方也明確要求避免多個 logical core 共用同一 RX/TX Queue，以降低鎖競爭。

---

# 152. Data Plane 模式

系統定義三種 Performance Mode。

## 152.1 Compatibility Mode

目的：

```text
一般使用者
一般 NIC
開發
功能驗證
```

Backend：

```text
Windows:
Winsock / Npcap

Linux:
Socket / libpcap

macOS:
Native Socket / libpcap
```

不保證 100G。

---

## 152.2 High Performance Mode

Backend：

```text
Linux:
AF_XDP Zero Copy

Windows:
RIO

macOS:
Native optimized socket
```

其中 Linux AF_XDP 可與 Linux Network Stack 共存。

AF_XDP 的 RX/TX Ring、FILL/COMPLETION Ring 與 UMEM 均屬官方定義的高速資料路徑，亦可要求 `XDP_ZEROCOPY`，若驅動不支援則直接失敗，而不是悄悄退回 copy mode。

---

## 152.3 Maximum Performance Mode

Backend：

```text
DPDK
```

主要平台：

```text
Linux
```

Windows：

```text
Supported Hardware Only
```

使用情境：

```text
Dedicated 100G Port

Packet Generator

Packet Receiver

100G Benchmark

High-rate Analysis
```

DPDK 26.07 的 Ethernet PMD 文件已涵蓋從低速至數百 GbE 的 Ethernet speed 範圍，並採使用者空間 Poll Mode Driver 直接操作 RX/TX queue 的架構。

---

# 153. Packet Backend Interface

Core 定義統一介面：

```rust
pub trait PacketBackend {
    fn capabilities(&self) -> PacketCapabilities;

    fn configure(
        &mut self,
        config: PacketBackendConfig,
    ) -> Result<(), PacketError>;

    fn start(&mut self) -> Result<(), PacketError>;

    fn stop(&mut self) -> Result<(), PacketError>;

    fn statistics(&self) -> PacketStatistics;
}
```

Data Plane 不應透過這個高階介面逐封包呼叫。

高速資料路徑使用 Backend 內部 Worker。

---

# 154. Backend 分層

```text
PacketEngine
     │
     ├── PcapBackend
     │
     ├── AfXdpBackend
     │
     └── DpdkBackend
```

Speed Engine：

```text
SpeedEngine
    │
    ├── SocketBackend
    ├── RioBackend
    ├── AfXdpBackend
    └── DpdkBackend
```

---

# 155. Rust / DPDK FFI 邊界

Rust 與 DPDK 的 FFI 必須集中在：

```text
crates/dpdk-sys
```

與：

```text
crates/dpdk-safe
```

結構：

```text
DPDK C API
    │
    ▼
dpdk-sys
    │
 unsafe
    ▼
dpdk-safe
    │
 safe Rust API
    ▼
Packet Engine
Speed Engine
```

---

# 156. unsafe 使用原則

禁止：

```rust
unsafe {
    rte_xxx(...)
}
```

散落於：

```text
GUI
CLI
Analyzer
Speed Test
Node
```

所有：

```text
unsafe extern "C"
```

必須集中於 FFI crate。

Rust 官方文件指出，與 C API 互通通常經由 C ABI；跨語言傳遞 struct 時應以 `#[repr(C)]` 確保 C 相容 layout。

---

# 157. DPDK Handle 封裝

例如：

```rust
pub struct DpdkPort {
    port_id: u16,
}

pub struct RxQueue {
    port_id: u16,
    queue_id: u16,
}

pub struct TxQueue {
    port_id: u16,
    queue_id: u16,
}
```

不讓上層直接保存：

```text
raw C pointer
```

除非存在必要的生命週期理由。

---

# 158. Packet Memory Ownership

DPDK：

```text
NIC RX Descriptor
       │
       ▼
rte_mbuf
       │
       ▼
PacketView
```

Rust 上層：

```text
PacketView
```

原則上只借用 packet memory。

不要立即：

```text
copy packet → Vec<u8>
```

---

# 159. PacketView

概念：

```rust
pub struct PacketView<'a> {
    data: &'a [u8],
    metadata: PacketMetadata,
}
```

Metadata：

```text
timestamp

port

queue

rss_hash

packet_length

captured_length

offload flags
```

---

# 160. Packet Lifecycle

```text
RX Descriptor
      ↓
mbuf
      ↓
PacketView
      ↓
Parser
      ↓
Flow Update
      ↓
Optional Capture
      ↓
mbuf Free
```

預設：

```text
Zero extra packet copy
```

---

# 161. RX Queue 模型

基本規則：

```text
1 RX Queue
     │
     ▼
1 Data Plane Worker
```

例如：

```text
RXQ0 → Core 4

RXQ1 → Core 5

RXQ2 → Core 6

RXQ3 → Core 7
```

禁止：

```text
RXQ0
 ├── Core 4
 └── Core 5
```

同時 polling。

DPDK 官方 PMD 文件明確指出，同一 RX Queue 不應由多個 logical core 同時 polling，而不同 RX Queue 則可由不同 core 平行處理。

---

# 162. Queue 數量

系統啟動時取得：

```text
NIC Max RX Queues

NIC Max TX Queues

CPU Count

NUMA Topology
```

自動計算：

```text
Recommended Queue Count
```

但必須允許使用者指定：

```bash
nettool packet run \
  --rx-queues 16
```

---

# 163. Auto Queue Policy

建議：

```text
min(
    NIC available queues,
    available data-plane cores,
    configured maximum
)
```

但不得直接用：

```text
CPU thread count
```

作為 Queue 數量。

必須排除：

```text
OS reserved cores

Control Plane cores

GUI cores

Storage writer cores

Other NUMA nodes
```

---

# 164. CPU Role

CPU 建議分成：

```text
System Core

Control Core

RX Worker Core

TX Worker Core

Analyzer Core

Capture Writer Core

Statistics Core
```

例如 32-Core NUMA Node：

```text
Core 0
OS / interrupt

Core 1
Control Plane

Core 2
Statistics

Core 4-19
RX / Analyzer

Core 20-27
TX

Core 28-31
Capture Writer
```

實際配置必須 Benchmark。

---

# 165. CPU Pinning

High Performance Mode：

```text
SHOULD
```

100G Certified Mode：

```text
MUST
```

必須固定：

```text
Worker
→
Logical CPU
```

---

# 166. NUMA

每張高速 NIC 必須偵測：

```text
PCI Bus

NUMA Node
```

並將：

```text
RX Workers

TX Workers

Packet Memory Pool
```

優先放在同一 NUMA Node。

DPDK 官方 PMD 設計亦要求 packet buffer pool 儘量位於 NIC 所在 processor 的本地 NUMA memory，以降低 remote memory access。

---

# 167. Cross-NUMA Policy

預設：

```text
DENY
```

100G Certified 測試中，如果：

```text
NIC NUMA != Worker NUMA
```

顯示：

```text
CERTIFICATION INVALID
```

除非該 Hardware Profile 明確允許。

---

# 168. Memory Pool

DPDK Backend 使用：

```text
rte_mempool
+
rte_mbuf
```

每 NUMA Node 建立獨立 Pool。

例如：

```text
NUMA 0
 ├── RX Pool A
 └── TX Pool A

NUMA 1
 ├── RX Pool B
 └── TX Pool B
```

---

# 169. Memory Pool Sizing

不得硬編碼固定：

```text
8192 mbufs
```

需依：

```text
RX descriptors

TX descriptors

Queue count

Burst size

Pipeline depth

Capture buffer

Safety margin
```

計算。

---

# 170. Huge Pages

DPDK Mode 應使用符合目標平台的 Huge Page 配置。

啟動前需檢查：

```text
Huge Page Available

Huge Page Free

NUMA Distribution
```

若不足：

```text
DPDK_INIT_INSUFFICIENT_HUGEPAGE
```

不得進入 100G Certified Mode。

---

# 171. Burst RX

資料讀取：

```text
rte_eth_rx_burst()
```

概念：

```text
RX Queue

↓ burst

[packet packet packet ...]
```

DPDK PMD 設計本身以 burst 型 RX/TX API 降低每個封包的固定成本並改善 cache / descriptor 操作效率。

---

# 172. Burst Size

支援：

```text
16
32
64
128
256
auto
```

但：

```text
auto
```

為預設。

Benchmark Engine 自動測試：

```text
burst=16
burst=32
burst=64
...
```

找出目標硬體最佳值。

---

# 173. Run-to-Completion 模式

預設優先模式：

```text
RX
↓
Parse
↓
Flow
↓
Counters
↓
Free
```

全部由：

```text
同一 Worker
```

完成。

優點：

```text
Cache locality

No inter-core queue

Low latency

Less synchronization
```

DPDK 官方同時支援 run-to-completion 與 pipeline model；對同一 packet 在單一 core 完成處理可降低 core 間傳遞成本。

---

# 174. Pipeline Mode

只有當 Analyzer 太重時才啟用：

```text
RX Worker
   │
   ▼
Ring
   │
   ▼
Analyzer Worker
```

使用 bounded Ring。

---

# 175. Pipeline Decision

系統 Benchmark 判斷：

```text
Run-to-Completion
```

或：

```text
Pipeline
```

哪個效能較佳。

不得假定 Pipeline 一定比較快。

---

# 176. RSS

100G Mode 必須支援：

```text
Receive Side Scaling
```

Flow Hash 建議至少：

```text
IPv4 src/dst

IPv6 src/dst

TCP src/dst port

UDP src/dst port
```

---

# 177. RSS Consistency

同一：

```text
5-Tuple
```

應盡可能落至同一 RX Queue。

原因：

```text
TCP Sequence Tracking

Flow Accounting

Retransmission Analysis
```

都需要 Flow locality。

---

# 178. Flow Shard

Flow Key：

```text
src_ip
dst_ip
src_port
dst_port
protocol
```

Canonical 化後：

```text
FlowHash
```

映射至：

```text
FlowShard
```

---

# 179. Flow Table

禁止單一：

```text
HashMap<FiveTuple, Flow>
+
Mutex
```

採：

```text
Shard 0

Shard 1

Shard 2

...

Shard N
```

每個 Worker 優先只修改自己的 Shard。

---

# 180. Shared State

Data Plane Shared State 只允許：

```text
read-mostly configuration

atomic shutdown flag

periodic statistics snapshot
```

避免：

```text
shared mutable flow table
```

---

# 181. Local Counter

每 Worker：

```text
rx_packets

rx_bytes

tcp_packets

udp_packets

drops

flows

retransmissions
```

皆為 local counter。

例如：

```rust
struct WorkerStats {
    rx_packets: u64,
    rx_bytes: u64,
    tcp_packets: u64,
    udp_packets: u64,
}
```

---

# 182. Statistics Merge

獨立 Statistics Worker：

```text
Worker 0 ─┐
Worker 1 ─┤
Worker 2 ─┤
Worker N ─┘
          ↓
     Aggregator
          ↓
       Snapshot
```

例如：

```text
100 ms
```

合併一次。

---

# 183. Hardware Counters

DPDK Mode 同時讀取 NIC：

```text
rx_packets

rx_bytes

rx_errors

rx_missed

per-queue statistics
```

可使用 PMD 提供的 extended statistics。

DPDK xstats API 支援 driver-specific 與 per-queue 統計，且設計上可以快取 statistic ID，避免 Fast Path 做字串比較。

---

# 184. Drop Accounting

正式定義：

```text
NIC_DROP

DRIVER_DROP

CAPTURE_DROP

RING_DROP

ANALYZER_DROP

APPLICATION_DROP

NETWORK_INFERRED_LOSS
```

---

# 185. NIC_DROP

資料來源：

```text
NIC hardware counter
```

或：

```text
DPDK xstats
```

必須附：

```text
counter source
```

---

# 186. CAPTURE_DROP

定義：

```text
Packet arrived at capture path

but application failed to obtain/store it
```

依 Backend 提供。

---

# 187. RING_DROP

```text
RX Worker
     │
     ▼
Internal Ring FULL
```

時：

```text
ring_drop++
```

---

# 188. ANALYZER_DROP

Analyzer 無法處理或 intentionally sampled：

```text
analyzer_drop++
```

---

# 189. NETWORK_INFERRED_LOSS

只有：

```text
Node-to-Node UDP sequence test
```

這類具有：

```text
sequence number
```

的主動測試才能較可靠計算。

被動 Packet Capture 不得直接宣稱：

```text
Network packet loss = x%
```

除非具備足夠證據。

---

# 190. Analysis Confidence

定義：

```text
HIGH

MEDIUM

LOW

INVALID
```

---

# 191. HIGH

條件：

```text
Capture Drop = 0

Analyzer Drop = 0

Ring Drop = 0

Required Flow State Complete
```

---

# 192. MEDIUM

例如：

```text
Capture Drop > 0

但比例低於認證門檻
```

---

# 193. LOW

例如：

```text
Large Capture Drop

Flow State Incomplete
```

---

# 194. INVALID

例如：

```text
Counter Reset

NIC Reset

Capture Backend Failure

Clock Discontinuity
```

---

# 195. AF_XDP Backend

架構：

```text
NIC Queue
    │
    ▼
XDP Program
    │
    ▼
XSKMAP
    │
    ▼
AF_XDP Socket
    │
    ├── RX Ring
    ├── TX Ring
    ├── FILL Ring
    └── Completion Ring
```

Linux Kernel 文件定義 AF_XDP Socket 透過 XSKMAP 與 queue id 綁定，且同一 netdev/queue 的 ring 有明確 producer/consumer 模型。

---

# 196. AF_XDP Zero Copy

100G Mode：

```text
XDP_ZEROCOPY
```

為必要條件。

如果：

```text
Zero-copy unsupported
```

不得靜默降級。

回傳：

```text
AF_XDP_ZERO_COPY_UNAVAILABLE
```

Kernel 文件指出 `XDP_ZEROCOPY` 可強制要求 zero-copy，不支援時 bind 直接失敗。

---

# 197. AF_XDP Shared UMEM

可支援：

```text
multiple sockets
+
shared UMEM
```

但必須遵守：

```text
RX/TX ring ownership

FILL/COMPLETION ownership
```

AF_XDP 官方文件特別指出部分 ring 是 single-producer/single-consumer，不可讓多執行緒無同步地同時操作。

---

# 198. Jumbo Frame

AF_XDP Backend 必須支援：

```text
Multi-buffer
```

以處理：

```text
Jumbo Frame
```

目前 Linux AF_XDP 已定義 multi-buffer RX/TX，zero-copy 可依 NIC 能力處理多個 buffer 組成的 packet。

---

# 199. Windows RIO

Windows High Performance Socket Engine 使用：

```text
Registered I/O
```

架構：

```text
Registered Buffer

Request Queue

Completion Queue

RIOReceive / RIOSend
```

Microsoft 定義 RIO 為 Winsock 高效能 I/O extension，使用預先註冊 buffer、request queue 與 completion queue，並可降低大量訊息 I/O 的系統呼叫與 jitter。

---

# 200. RIO Buffer

啟動：

```text
Allocate Large Buffer

↓
RIORegisterBuffer()

↓
Slice Buffer

↓
Reuse
```

禁止：

```text
Register Buffer
Send
Deregister
```

per request。

---

# 201. RIO Protocol

RIO Socket 必須支援：

```text
TCP

UDP

IPv4

IPv6
```

RIO 官方文件包含 TCP、UDP、Multicast UDP、IPv4 與 IPv6。

---

# 202. Speed Engine

Speed Engine 定義：

```text
Control Plane

Test Coordinator

Stream Manager

TX Engine

RX Engine

Statistics Engine
```

---

# 203. Speed Test Session

每次測試建立：

```text
Session ID
```

例如：

```text
UUID
```

包含：

```text
source node

destination node

engine

protocol

stream count

duration

warmup

cooldown

payload size

direction

target rate
```

---

# 204. Test Lifecycle

```text
NEGOTIATE
    ↓
PREPARE
    ↓
READY
    ↓
WARMUP
    ↓
MEASURE
    ↓
COOLDOWN
    ↓
FINALIZE
    ↓
RESULT
```

---

# 205. Barrier Synchronization

雙方必須完成：

```text
READY
```

才開始測試。

禁止：

```text
Client starts immediately after connect
```

---

# 206. Timestamp

Control Plane 協調：

```text
start_at
```

但主要 Throughput Measurement 使用：

```text
local monotonic clock
```

不得使用 Wall Clock 計算 Duration。

---

# 207. TCP Speed Engine

TCP Engine 測量：

```text
Application throughput
```

不是 Ethernet wire-rate。

---

# 208. TCP Payload

使用固定預先配置 Buffer。

例如：

```text
256 KB

1 MB

4 MB
```

實際值 Auto Tune。

不得每次 send 重新產生資料。

---

# 209. TCP Payload Content

預設內容：

```text
pseudo-random pre-generated buffer
```

避免極端可壓縮內容對某些環境造成偏差。

---

# 210. TCP Stream

每 Stream：

```text
Socket

TX Counter

RX Counter

Worker Assignment
```

---

# 211. Parallel Stream Auto Tune

流程：

```text
1
↓
2
↓
4
↓
8
↓
16
↓
...
```

每一階段取得：

```text
Throughput

CPU

Efficiency
```

當：

```text
Throughput Improvement
<
Configured Threshold
```

連續數個階段後停止增加。

門檻為可配置。

---

# 212. TCP Result

至少：

```text
Application Throughput

Transferred Bytes

Duration

Streams

CPU Usage

CPU/Core

Socket Errors

Retransmission
```

Retransmission 能否直接取得依平台能力決定。

無可靠資料：

```text
N/A
```

不得推測。

---

# 213. UDP Speed Protocol

UDP Header：

```text
Magic

Protocol Version

Header Length

Session ID

Stream ID

Sequence Number

Flags

Send Timestamp

Payload Length
```

---

# 214. UDP Sequence

每 Stream：

```text
sequence++
```

Receiver：

```text
received

missing

duplicate

out_of_order
```

---

# 215. UDP Rate Control

支援：

```text
Unlimited

Fixed Rate

Ramp
```

例如：

```bash
nettool speed run node-b \
  --protocol udp \
  --rate 80G
```

---

# 216. Pacing

低速可：

```text
timer-based
```

高速不得逐 packet sleep。

100G Mode 使用：

```text
batch pacing

burst pacing

hardware pacing
```

若 NIC 支援。

---

# 217. UDP Ramp

支援：

```text
10G
20G
40G
60G
80G
90G
95G
100G
```

或：

```text
auto
```

用來找出：

```text
Loss Threshold
```

---

# 218. UDP Throughput Result

至少：

```text
TX Rate

RX Rate

TX Packets

RX Packets

Sequence Loss

Duplicate

Out-of-order

Jitter

CPU
```

---

# 219. RTT

Latency 預設：

```text
RTT
```

使用獨立 Control Probe 或 UDP Probe。

不要與大量吞吐量封包共用相同統計。

---

# 220. Latency Under Load

必須支援：

```text
Latency while throughput test running
```

因為：

```text
Idle RTT
```

與：

```text
Loaded RTT
```

代表不同網路品質。

---

# 221. Bidirectional

必須真正同時：

```text
A → B

B → A
```

測試。

兩個方向各自回報：

```text
Throughput

Packet Rate

Loss

CPU
```

再產生 Combined Result。

---

# 222. Packet Generator

除了 TCP / UDP Socket Test，加入：

```text
Raw Packet Generator
```

主要使用：

```text
DPDK
```

---

# 223. Packet Generator Profile

可配置：

```text
Ethernet Size

IPv4 / IPv6

TCP / UDP

Source IP Range

Destination IP Range

Source Port Range

Destination Port Range

Flow Count

Packet Rate
```

---

# 224. 100G Packet Rate 理論基準

Benchmark 計算採：

```text
Ethernet frame
+
8-byte Preamble/SFD
+
12-byte IFG
```

作為 wire-rate 模型。

因此 100GbE 約為：

```text
64-byte frame:
148.81 Mpps

128-byte:
84.46 Mpps

256-byte:
45.29 Mpps

512-byte:
23.50 Mpps

1024-byte:
11.97 Mpps

1518-byte:
8.13 Mpps

9018-byte:
1.38 Mpps
```

此表為規格中的理論計算基準，不代表實測結果。

---

# 225. Benchmark 不得只用 Jumbo Frame

必須至少測：

```text
64

128

256

512

1024

1518

9018
```

原因：

```text
100G @ 64B
```

主要測：

```text
Packet Processing Rate
```

而：

```text
100G @ Jumbo
```

主要測：

```text
Bandwidth
```

兩者壓力不同。

---

# 226. Packet Parser

Parser 必須：

```text
Bounds Checked

No Heap Allocation

No String Conversion
```

Fast Path 解析：

```text
Ethernet

802.1Q

QinQ

ARP

IPv4

IPv6

ICMP

ICMPv6

TCP

UDP
```

---

# 227. Deep Parsing

以下預設不在 100G Fast Path：

```text
HTTP

TLS

DNS

QUIC

Application Payload
```

若啟用：

```text
Deep Analysis Mode
```

需另外 Benchmark。

---

# 228. Sampling

若 Analyzer 無法 line-rate 完成 DPI，可：

```text
sample
```

但 GUI 必須顯示：

```text
Sampled Analysis
```

不得假裝為完整分析。

---

# 229. TCP Analyzer

每 Flow 至少維護：

```text
next_seq

last_ack

window

syn_seen

fin_seen

rst_seen

retransmission_count

out_of_order_count
```

---

# 230. Retransmission Classification

至少：

```text
Observed Retransmission

Suspected Retransmission

Out-of-order

Duplicate ACK
```

---

# 231. Retransmission Confidence

如果：

```text
Capture Drop > 0
```

則：

```text
TCP retransmission analysis
```

不得維持最高可信度。

---

# 232. Capture Writer

Capture Writer 與 Analyzer 必須獨立。

```text
RX
 ├── Analyze
 └── Capture
```

---

# 233. Capture Buffer Policy

```text
Bounded
```

滿：

```text
capture_writer_drop++
```

不允許 Capture Writer 反向阻塞 RX Worker。

---

# 234. Capture Mode

至少：

```text
Metadata Only

Header Only

Snaplen

Full Packet
```

---

# 235. PCAPNG

優先支援：

```text
PCAPNG
```

因為可以保留更多：

```text
interface metadata

timestamps

capture metadata
```

同時保留：

```text
PCAP
```

相容輸出。

---

# 236. File Rotation

支援：

```text
Size

Duration

File Count
```

例如：

```bash
nettool packet capture \
  --rotate-size 10G \
  --rotate-count 8
```

---

# 237. Storage Guard

Full Capture 前先計算：

```text
Expected Write Rate
```

與：

```text
Measured Storage Rate
```

若不足：

```text
LOSSLESS_CAPTURE_NOT_CERTIFIED
```

---

# 238. Control Plane

100G Node 建議使用獨立：

```text
Management NIC
```

Control Plane 不經過 Test NIC。

---

# 239. Control Protocol

可採：

```text
TLS over TCP
```

或後續選定安全 Protocol。

功能：

```text
Pairing

Authentication

Capabilities

Session Negotiation

Start

Stop

Result

Heartbeat
```

---

# 240. Capability Exchange

Node Connect 後先交換：

```json
{
  "protocol_version": 1,
  "engines": [
    "socket",
    "af_xdp",
    "dpdk"
  ],
  "link_speed_gbps": 100,
  "rx_queues": 64,
  "tx_queues": 64,
  "numa_nodes": 2
}
```

---

# 241. Backend Compatibility Check

例如：

```text
Node A:
DPDK

Node B:
No DPDK
```

則不能執行：

```text
DPDK Raw Benchmark
```

回傳：

```text
BACKEND_INCOMPATIBLE
```

---

# 242. Hardware Detection

Linux：

```text
PCI ID

NIC driver

Firmware

Link Speed

Queue Count

NUMA

RSS

XDP support

AF_XDP zero-copy support

DPDK PMD
```

---

# 243. DPDK Port Ownership

啟用 DPDK 前：

```text
Acquire Port
```

停止後：

```text
Release Port
```

DPDK 本身具有 Ethernet Port ownership 機制，以避免多個 entity 同時管理同一 port。

---

# 244. Management NIC 保護

若使用者嘗試將：

```text
Current Management Interface
```

交給 DPDK：

GUI 必須警告。

如果同一介面目前承載：

```text
Control Plane
```

則預設：

```text
DENY
```

---

# 245. Benchmark Mode

新增 CLI：

```bash
nettool benchmark run \
  --profile 100g-cert
```

---

# 246. Benchmark Environment Snapshot

測試前記錄：

```text
OS

Kernel

CPU

CPU Frequency

NUMA

Memory

Huge Pages

NIC

PCIe

Firmware

Driver

DPDK Version

MTU

Queue Count

RSS

Offload
```

---

# 247. Benchmark Phase

```text
Environment Check

↓
NIC Baseline

↓
RX Baseline

↓
TX Baseline

↓
Bidirectional

↓
Packet Size Matrix

↓
Flow Matrix

↓
Duration Test

↓
Analysis Test

↓
Result
```

---

# 248. RX Baseline

使用外部已知可產生 line-rate 流量的裝置或另一個 certified node。

記錄：

```text
Gbps

Mpps

NIC Drop

Application Drop

CPU
```

---

# 249. TX Baseline

同樣記錄：

```text
Gbps

Mpps

CPU

TX Errors

Queue Utilization
```

---

# 250. 100G Certification Gate

不以：

```text
99.x Gbps
```

單一數值判斷 PASS。

---

# 251. Gate A — Link

```text
100GbE negotiated
```

PASS。

---

# 252. Gate B — NUMA

```text
NIC / CPU / Memory locality valid
```

PASS。

---

# 253. Gate C — Queue

```text
RSS active

RX queue distribution valid
```

PASS。

---

# 254. Gate D — Throughput

測試取得：

```text
Target Throughput
```

正式百分比門檻在硬體 POC 後固定。

在沒有 POC 測量前，本規格不虛構：

```text
99%
99.9%
```

等數字。

---

# 255. Gate E — Drop

必須分別檢查：

```text
NIC Drop

Capture Drop

Ring Drop

Analyzer Drop
```

---

# 256. Gate F — CPU

必須記錄：

```text
Total CPU

Data-plane Core Count

Gbps/Core

Mpps/Core
```

---

# 257. Gate G — Stability

至少提供：

```text
Short Test

Sustained Test
```

正式 Certification 時間在 POC 後固定。

---

# 258. Gate H — Thermal

記錄：

```text
CPU frequency

NIC state

thermal throttling
```

若測試期間發生明顯 throttling：

```text
CERTIFICATION CONDITION
```

必須保存。

---

# 259. Gate I — Analyzer

在 Analysis Enabled 情況再次執行：

```text
64B

1518B
```

至少兩個主要負載。

---

# 260. Gate J — Reproducibility

同一環境重複測試。

若結果離散過高：

```text
UNSTABLE
```

不能標記 Certified。

---

# 261. Baseline Comparison

建議同硬體使用：

```text
DPDK testpmd

iperf3
```

作外部 baseline。

目的：

```text
確認硬體

確認 NIC

確認 OS

確認本系統差距
```

不是要求結果完全一致。

---

# 262. CLI Performance Commands

新增：

```bash
nettool perf topology
```

顯示：

```text
CPU

NUMA

NIC

PCIe

Queues
```

---

```bash
nettool perf backend
```

顯示：

```text
pcap

af_xdp

dpdk

rio
```

可用狀態。

---

```bash
nettool perf benchmark
```

執行完整測試。

---

# 263. Topology Output

例如：

```text
NIC:
0000:31:00.0

Link:
100 Gbps

NUMA:
1

RX Queues:
64

TX Queues:
64

Recommended CPUs:
32-47

AF_XDP:
Supported

Zero Copy:
Supported

DPDK:
Supported
```

---

# 264. Auto Tuning

提供：

```bash
nettool perf tune
```

分析：

```text
Queue count

CPU affinity

NUMA placement

Burst size

Ring size

Buffer count
```

---

# 265. Auto Tune 安全限制

`perf tune` 預設：

```text
recommend-only
```

不得直接修改：

```text
IRQ affinity

Huge Pages

NIC driver

Kernel setting
```

除非使用者明確：

```bash
--apply
```

---

# 266. Production Safety

若涉及：

```text
NIC driver rebind

DPDK binding

IRQ affinity

Huge Page reservation

NetworkManager change
```

GUI 必須提示：

> 此操作會變更主機網路或系統資源配置，請先於測試環境驗證。

---

# 267. DPDK Binding

若 Dedicated Test NIC 使用 DPDK：

```text
NIC
↓
Kernel Driver
↓
DPDK-compatible ownership
```

必須在 GUI 清楚呈現。

不能讓使用者誤以為：

```text
DPDK Mode
```

仍與一般 Kernel Network Interface 完全相同。

---

# 268. Performance Profile

新增 Profile：

```yaml
name: 100g-linux-dpdk

backend: dpdk

interface:
  pci: "0000:31:00.0"

numa:
  node: 1

rx:
  queues: auto
  burst: auto

tx:
  queues: auto
  burst: auto

cpu:
  affinity: auto

memory:
  hugepages: auto
```

---

# 269. Packet Analysis Profile

```yaml
name: 100g-analysis

capture:
  mode: header
  snaplen: 128

analysis:
  ethernet: true
  vlan: true
  ipv4: true
  ipv6: true
  tcp: true
  udp: true

  deep_inspection: false

flow:
  enabled: true
  timeout_seconds: 60
```

---

# 270. Telemetry

每 Worker 暴露：

```text
rx_pps

rx_bps

burst_average

ring_fill

flow_count

drops

cpu
```

---

# 271. Internal Telemetry Frequency

Data Plane：

```text
local counters
```

即時累積。

Aggregator：

```text
100ms
```

等級。

GUI：

```text
250ms
```

左右。

實際數值 Benchmark 後確認。

---

# 272. Packet Hot Path 目標

Hot Path 只允許：

```text
descriptor read

header parse

hash lookup

counter update

optional ring enqueue

buffer recycle
```

---

# 273. Hot Path 禁止項目

```text
SQL

JSON

filesystem

network logging

DNS lookup

string formatting

GUI event

heap allocation
```

---

# 274. Error Model

Data Plane Error 不應直接 panic。

定義：

```text
RECOVERABLE

DEGRADED

FATAL
```

---

# 275. RECOVERABLE

例如：

```text
Temporary TX ring full
```

記 Counter 後繼續。

---

# 276. DEGRADED

例如：

```text
Capture Writer Falling Behind
```

標記：

```text
Capture Confidence ↓
```

---

# 277. FATAL

例如：

```text
NIC reset

DPDK port lost

invalid UMEM

backend failure
```

停止 Session。

---

# 278. Session Result 必須包含

```json
{
  "session_id": "...",
  "engine": "dpdk",
  "status": "completed",

  "throughput": {},
  "packet_rate": {},

  "drops": {
    "nic": 0,
    "capture": 0,
    "ring": 0,
    "analyzer": 0
  },

  "cpu": {},

  "numa": {},

  "confidence": "HIGH"
}
```

---

# 279. Hardware Certification Database

新增：

```text
hardware_certification
```

資料。

至少：

```text
CPU

Mainboard

NUMA

NIC

PCIe

Firmware

Driver

OS

Kernel

DPDK

Backend

Result
```

---

# 280. Certification Key

認證不是：

```text
NIC Model
```

單獨決定。

而是：

```text
Platform Combination
```

例如：

```text
CPU
+
NIC
+
Firmware
+
Driver
+
OS
+
Kernel
+
Backend
```

---

# 281. 支援等級

GUI 顯示：

```text
Functional

Validated

100G Certified
```

---

# 282. Functional

代表：

```text
功能可以執行
```

不代表 100G。

---

# 283. Validated

代表：

```text
完成一般效能驗證
```

---

# 284. 100G Certified

代表：

```text
指定硬體組合
```

通過完整 100G Benchmark Gate。

---

# 285. 第一個 100G POC

最優先實作：

```text
Linux
+
DPDK
```

不要先做 GUI。

---

# 286. POC Hardware Topology

推薦：

```text
Node A

Management NIC
+
100G Test NIC

          │
          │ 100GbE
          │

Node B

100G Test NIC
+
Management NIC
```

---

# 287. POC 測試

Phase 1：

```text
DPDK RX Only
```

Phase 2：

```text
DPDK TX Only
```

Phase 3：

```text
DPDK Bidirectional
```

Phase 4：

```text
Analyzer Enabled
```

Phase 5：

```text
Capture Enabled
```

---

# 288. POC Packet Matrix

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

# 289. POC Flow Matrix

至少：

```text
1 Flow

16 Flows

256 Flows

4096 Flows

High-cardinality Flow Test
```

---

# 290. Flow Cardinality

這是重要測試項目。

因為：

```text
100G
+
1 Flow
```

與：

```text
100G
+
1,000,000 Flows
```

是完全不同的 Analyzer 負載。

---

# 291. Flow Benchmark

至少記錄：

```text
Flow creation/sec

Active flows

Flow lookup latency

Memory per flow

Evictions
```

---

# 292. Memory Bound

Flow Table 必須設定：

```text
maximum flow count
```

超過：

```text
Eviction
```

不能讓：

```text
RAM
```

持續增加。

---

# 293. Flow Eviction

支援：

```text
Idle Timeout

LRU-like policy

Time Wheel
```

具體演算法在實作 POC 後固定。

---

# 294. Time Wheel

若 Active Flow 非常多，建議評估：

```text
Timing Wheel
```

取代每次掃描全部 Flow。

此項屬實作建議，不先列為硬性要求。

---

# 295. 100G 最重要的效能指標

正式排序：

```text
1. Drop correctness

2. Mpps

3. Gbps

4. CPU efficiency

5. NUMA locality

6. Stability

7. Latency

8. Memory
```

不是只追求：

```text
Bandwidth
```

---

# 296. 100G Definition of Done

Speed Engine 完成需：

```text
TCP

UDP

Bidirectional

Parallel Stream

Auto Tune

Latency Under Load

Socket Mode

DPDK Mode
```

---

Packet Engine 完成需：

```text
Multi Queue

RSS

NUMA

CPU Pinning

Header Parser

Flow Table

TCP Analyzer

Drop Classification

PCAP/PCAPNG

DPDK

AF_XDP
```

---

# 297. 技術風險排序

## Risk 1

```text
64B @ 100GbE packet rate
```

最高。

---

## Risk 2

```text
High-cardinality Flow Analysis
```

---

## Risk 3

```text
NUMA / PCIe locality
```

---

## Risk 4

```text
Full Packet Capture Storage
```

---

## Risk 5

```text
Windows 100G performance consistency
```

---

## Risk 6

```text
Cross-platform privileged operations
```

---

# 298. 建議正式開發順序

```text
1
Linux DPDK RX/TX POC

2
100G benchmark harness

3
Multi-Queue + CPU affinity

4
NUMA-aware memory

5
UDP packet generator

6
UDP receiver/loss engine

7
Flow sharding

8
TCP/UDP analyzer

9
AF_XDP

10
Socket TCP test

11
Windows RIO

12
Cross-platform Core

13
Privilege Helper

14
Profile / Hosts

15
CLI stabilization

16
GUI
```

---

# 299. 最終架構

```text
                       GUI
                        │
                        ▼
                 Application Core
                        │
            ┌───────────┴────────────┐
            │                        │
            ▼                        ▼
      Control Plane              Data Plane
            │                        │
            │             ┌──────────┼──────────┐
            │             │          │          │
            │             ▼          ▼          ▼
            │          Socket     AF_XDP      DPDK
            │
            ▼
      Node Protocol


100G NIC
   │
   ▼
Hardware RSS
   │
   ├─────────┬─────────┬─────────┐
   ▼         ▼         ▼         ▼
 RXQ0       RXQ1      RXQ2      RXQN
   │         │         │         │
Core 4     Core 5    Core 6    Core N
   │         │         │         │
Parser    Parser     Parser    Parser
   │         │         │         │
Flow 0    Flow 1     Flow 2    Flow N
   │         │         │         │
   └─────────┴────┬────┴─────────┘
                  ▼
             Aggregator
                  │
          ┌───────┼────────┐
          ▼       ▼        ▼
         GUI     CLI     History
```

---

# 300. v0.4 架構決策

截至本版，以下決策視為正式 Architecture Decision：

```text
ADR-001
Rust 為 Core 主要語言

ADR-002
GUI 使用 Tauri 架構

ADR-003
GUI 與 CLI 共用 Core

ADR-004
Privileged Helper 與 GUI 分離

ADR-005
Safe Apply 為必要功能

ADR-006
Control Plane / Data Plane 分離

ADR-007
Network Loss / Capture Drop /
Analyzer Drop 必須分離

ADR-008
100GbE 為 Primary Performance Target

ADR-009
Linux DPDK 為 100G Maximum Performance Backend

ADR-010
Linux AF_XDP 為 High Performance Shared-stack Backend

ADR-011
Windows RIO 為 High Performance Socket Backend

ADR-012
100G Packet Engine 採 Multi-Queue + CPU Pinning

ADR-013
100G Packet Engine 必須 NUMA-aware

ADR-014
Hot Path 禁止動態配置記憶體

ADR-015
Packet Flow Table 採 Sharding

ADR-016
100G Certification 依完整 Hardware Profile

ADR-017
100G Full Capture 與 100G Analysis 分別認證

ADR-018
GUI 永遠不進入 Packet Hot Path
```

---

# 301. 下一階段實作前置條件

開始 Coding 前應先建立：

```text
Architecture Decision Records

Protocol Specification

Benchmark Specification

Error Code Registry

JSON Schema

Repository Structure

CI Matrix
```

尤其是：

```text
Protocol Specification
```

必須先固定：

```text
Node Handshake

Capability Negotiation

Speed Session

UDP Packet Header

Result Format

Protocol Versioning
```

避免 Node A / Node B 在後續版本失去相容性。

---

# 302. 生產環境要求

所有以下操作：

```text
NIC Driver Rebind

DPDK Port Binding

Huge Page Change

IRQ Affinity

CPU Isolation

RSS Change

Queue Change

MTU Change

Network Profile Apply
```

均屬可能影響主機網路服務的系統變更。

正式套用於生產設備前，必須先於：

```text
isolated test environment
```

使用與生產環境相同或等價的：

```text
NIC

Firmware

Driver

Kernel

CPU / NUMA topology
```

完成驗證。
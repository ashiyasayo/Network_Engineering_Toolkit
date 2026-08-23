# Protocol Specification

## Node control frame v1

每個 TLS 1.3 stream frame 由 12-byte header 與 Protobuf payload 組成：

| Offset | Size | Field |
| --- | ---: | --- |
| 0 | 4 | ASCII `NTCP` |
| 4 | 1 | Framing version `1` |
| 5 | 1 | Flags，v1 必須為 `0` |
| 6 | 2 | Reserved，必須為 `0` |
| 8 | 4 | Big-endian payload length |

Payload 上限為 1 MiB。未知 framing version、flags、非零 reserved、長度不符及 malformed Protobuf 必須終止該 connection。

Application protocol 起始版本為 `1.0`。Major 必須相同；minor 選擇雙方最高共同版本。Capability ID 不可重用，且以 capability 自身的 version range 與 runtime availability 取交集。

本機 Agent Action envelope 的 `dry_run` 欄位屬於 request execution policy，不改變 action payload 或 request correlation。設定為 true 時，Agent 對非特權 action 只回傳 bounded plan、permission/idempotency metadata 與 payload SHA-256；特權 action 必須把旗標傳給 authenticated Helper，由 Helper 完成相同 schema、權限與資源驗證後回傳 plan，任何路徑都不得套用設定或產生其他副作用。

`StartTest` 必須帶 non-zero `start_at_unix_nanoseconds`。Receiver 的 Prepare response 只代表本端 READY；coordinator 收到遠端 Start/READY 後才完成 barrier 並排程，指定時間到達前不得啟動 data plane。`start_at` 只用於雙端協調，throughput duration 必須由各端 local monotonic clock 計算。排程時間與實際啟動都不得超過 session-scoped authorization lifetime。

## Identity and TLS

Control connection 只允許 TLS 1.3，已信任連線使用 mutual certificate authentication。Persistent identity 使用完整 SHA-256 public-key fingerprint；相同 Node ID 的 fingerprint 變更必須重新 pairing。首次 `node.pair` 還必須由 CLI/GUI 明確攜帶 out-of-band fingerprint confirmation；Agent Storage 在 transaction 前拒絕未確認 request。

## Data-plane endpoint negotiation

`PrepareTest.source_data_port` 與 `receive_data_port` 分別表示 initiator 已 pre-bind 的 sender source port 與 receiver port；`PrepareTestResponse.data_port` 與 `source_data_port` 分別表示 remote receiver port 與 sender source port。如此 upload、download 與 bidirectional 都有明確的雙端 endpoint，不以零值或欄位名稱推測角色。UDP sender port及所有 socket receiver port 必須在 Prepare 前實際 bind；raw Ethernet 不使用這些 socket ports。

TCP 每條 data stream 在 payload 前送出 `NTA1` bounded authorization handshake，包含 session ID、stream ID 與 session-scoped tag；receiver 拒絕錯誤 tag、session、超出範圍或重複 stream ID。UDP 使用 `AUTH` flag datagram傳送相同 session-scoped tag，receiver 在來源 endpoint、session、stream 與 tag 全部通過前不接受 DATA/END。Tag 為 16–256 bytes且禁止控制字元；失敗回傳 `NODE.DATA_PLANE_UNAUTHORIZED`。

## Final result retrieval

Protocol minor 1 新增 tag 46 `TestResultRequest`，以 128-bit session ID 可重試地取得既有 tag 45 `TestResult`。Result JSON 必須是 object，且包含非空 `schema_version`；checksum 固定為完整 `result_json` bytes 的 SHA-256。Client 必須驗證 envelope request correlation、result session ID 與 checksum，任一不符都視為 protocol invalid。此 request/response 允許 control connection 中斷後重新取得 immutable final result，不依賴不可重送的 unsolicited event。

## Data plane

Benchmark payload 不進入 Protobuf/TLS control plane。TCP、UDP 或 accelerated backend 使用 PrepareTest 動態配置的 data port 與 session-scoped authorization context。

UDP sender 必須先配置 dynamic source port，並在 `PrepareTest.source_data_port` 提交。Receiver 將 source/destination IP+port、protocol、session ID、source Node ID、authorization tag 與 expiry 綁定為單一 authorization context；任何欄位不符都不可進入 speed engine。Authorization tag 使用固定時間內容比較，避免以一般字串早停比較處理 secret。

完整 UDP speed v1 header 固定 52 bytes，依序包含 `NTUP` magic、16-bit version、16-bit header length、128-bit session ID、32-bit stream ID、64-bit sequence、32-bit flags、64-bit sender monotonic timestamp 與 32-bit payload length；所有多位元組整數使用 network byte order，且接收端必須驗證 payload length 與完整 datagram 一致。16-byte compact header 保留給最小 frame/raw benchmark，但不取代完整 socket speed protocol。

Authorization context 至少綁定 session ID、source Node ID、source/destination address、protocol、dynamic port、256-bit random tag 與 expiration。Prepare、Start、Stop 都需要 operation ID；相同 operation ID 重送回傳原始結果，不建立第二個 listener 或 session，不同 request 重用同一 ID 則回傳 conflict。

## Privileged Helper request

Helper request 僅允許 `network.*`、`hosts.*`、`nic.*`、`hugepage.*` 與 `safe_apply.*` 封閉 operations。`network.apply` 的 desired state 不是自由格式 JSON，而是固定的 IPv4、IPv6、DNS、route 與 MTU schema；所有層級都拒絕未知欄位，並驗證 address family、prefix、gateway family、重複項目、數量及 MTU 範圍。

Unix Helper transport 使用 4-byte big-endian length + JSON payload，單一 frame 上限 1 MiB，並在配置 payload buffer 前拒絕超限長度。Wire request 不含且拒絕 `caller_identity`；server 只能由 kernel Unix socket peer credentials 建立 principal/process ID，再以 exact principal allowlist 授權。Windows Agent client 已使用同一 bounded framing over Named Pipe；Windows server/helper 仍必須提供等價的 token/SID 驗證，不能退回信任 payload。

具副作用 request 必須帶 operation ID。相同 operation ID 與相同 interface/state 的 Safe Apply 重送回傳既有 pending 結果；不同 request 重用 ID 回傳 `OPERATION.ID_CONFLICT`。確認時間到達 deadline 後不得再 confirm，必須進入 rollback。

`nic.prepare_dpdk` 固定綁定 `vfio-pci`，先由 Helper 保存原 driver；`nic.restore_driver` 只接受 prepare operation ID 與同一 PCI address，wire request 不再接受 caller 指定 driver 名稱。`hugepage.prepare` 同樣先保存指定 NUMA/global sysfs count，`hugepage.release` 只依 prepare operation ID 還原。兩者都必須 write 後 read-back verify，且相同 request 重送維持冪等。

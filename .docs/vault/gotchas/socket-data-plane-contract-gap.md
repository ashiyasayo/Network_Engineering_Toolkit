# Socket data-plane contract gap

## 問題

原有 `PrepareTest.source_data_port` 與 `PrepareTestResponse.data_port` 只足以自然描述
initiator 作為 sender、remote 作為 receiver 的單向測試。它無法無歧義表示 download 或
bidirectional 所需的：

- initiator receiver port；
- remote sender source port；
- 雙向同時存在的 source/destination endpoints；
- TCP 每條 stream 的 session-scoped authorization handshake。

現有 UDP socket engine 會比對 source endpoint、session ID 與 stream ID，但 wire payload
本身尚未攜帶 `authorization_tag`；TCP compatibility engine 也尚未在每條 stream 建立
session/tag handshake。因此，直接在 Agent 收到 `PrepareTestResponse` 後啟動現有 worker，
會造成方向錯誤或繞過 data-plane authorization。

## 已完成的契約修正

Wire contract 已向後相容新增：

- `PrepareTest.receive_data_port`：initiator receiver port；
- `PrepareTestResponse.source_data_port`：remote sender source port。

Planner 現在依 direction 強制 pre-bind：UDP upload/bidirectional 必須有 send port，所有 socket
download/bidirectional 必須有 receive port；raw test 則禁止夾帶 socket ports。Orchestrator 也會依
direction 驗證 remote receive/source ports。

## 已完成的 authorization 修正

- TCP 每條 stream 在 payload 前傳送 bounded handshake，receiver 驗證 session ID、唯一且範圍內的 stream ID，以及以固定工作量比對的 authorization tag。
- UDP sender 在量測前傳送 AUTH datagram；receiver 在 endpoint、session、stream 與 tag 全部符合前，不會讓任何 DATA/END 進入量測。
- Tag 長度限制為 16–256 UTF-8 bytes且禁止控制字元；錯誤授權使用穩定錯誤 `NODE.DATA_PLANE_UNAUTHORIZED`。
- Node coordinator 交給 TCP/UDP receiver 的 config 已包含同一份 control-plane authorization tag。

## 仍必要的 session wiring

在 Agent 送出具副作用的 remote Prepare 前，先完成並版本化下列契約：

1. 雙端都先 bind 所需 endpoints，Prepare 原子保留資源後才排定共同 `start_at`。
2. 任一端失敗時，以新的冪等 Stop operation 清理 remote reservation，並保存 failed/canceled result。

不得以「目前只支援 upload」作為正式完成方案，也不得在 executor 未接好時先送 Prepare，避免
remote reservation 洩漏。

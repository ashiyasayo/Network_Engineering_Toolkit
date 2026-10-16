# GUI 功能與操作說明

NetTool 提供瀏覽器 Dashboard 與 Tauri 原生桌面入口，兩者使用相同介面。所有查詢與變更經 Agent；修改系統網路或讀寫 Hosts 需要 Helper。

## 啟動

需要 Rust 1.85 以上。在專案根目錄開啟兩個終端機，分別執行：

```powershell
cargo run -p nettool-agent
```

```powershell
cargo run -p nettool-gui
```

瀏覽器開啟 `http://127.0.0.1:8765`。若連接埠已使用，可在 GUI 終端機設定：

```powershell
$env:NETTOOL_GUI_LISTEN = '127.0.0.1:8766'
cargo run -p nettool-gui
```

GUI 僅接受 loopback 監聽。Agent 未啟動時，頁面顯示原始錯誤碼與提示；啟動 Agent 後按「重新整理」。

原生桌面入口為 `cargo run -p nettool-desktop`，由殼層管理 Agent 與 GUI。開發及套件需要可用的 sidecar binaries，詳見 [桌面說明](../apps/desktop/README.md) 與 [發行安裝](../packaging/README.md)。

## 功能分析與頁面

| 頁面 | 提供功能 | 使用條件 |
| --- | --- | --- |
| 功能總覽 | Agent／資料庫狀態、常用功能入口 | Agent 已啟動 |
| 網路介面 | 名稱、IP、Mbps、驅動、匯流排、PCI、queue 表格 | 唯讀；平台未提供的欄位顯示「未提供」 |
| 網路設定 Profile | 列出、讀取、建立、套用及 Safe Apply 確認／回復 | 保存不需 Helper；套用需要 Helper |
| Hosts | 顯示目前 Hosts 文字 | 包含讀取在內都需要 Helper；變更使用 CLI／Action Console |
| 網路測速 | TCP／UDP socket 測速表單與最近歷史 | 雙端 Node 信任、對端控制監聽及可達網路 |
| 封包分析 | PCAP／PCAPNG 路徑、完整／取樣分析、連線查詢 | 離線分析跨平台；連線查詢限 Linux |
| Node 配對 | 信任清單、DER 憑證與指紋確認表單 | 先獨立核對對端 SPKI 指紋 |
| 環境與能力 | 平台、NIC 與 backend 探測完整報告 | 唯讀，不代表效能或硬體驗收通過 |
| 測速歷史 | 最近 20 筆 Session、Node、協定、backend、方向及終態 | 此處不是系統日誌 |
| 使用說明 | 操作順序、功能條件、限制與啟動命令 | 不需 Agent 即可閱讀 |

## Profile 與 Safe Apply

1. 在「網路介面」記下目標名稱，例如 `Ethernet`。
2. 到「網路設定 Profile」輸入穩定 ID、顯示名稱與完整設定 JSON。預設為 IPv4 DHCP、IPv6 自動與自動 DNS；按「建立 Profile」只保存設定。
3. 選取左側 Profile，核對設定，填寫目標介面與確認期限（10–600 秒）。
4. 按「套用 Profile」，確認目標。一般 portable 需要另行安裝 Helper；UAC portable 會要求提高權限。
5. 成功後，上方顯示 Helper 的 `operation_id` 與期限。檢查實際網路連線，再按「確認保留設定」；需撤銷時按「回復原設定」。

Helper 負責期限及回復，切換 GUI 頁面不會取消此操作。GUI 在送出套用前將操作識別碼存入目前分頁的 sessionStorage，重新整理後仍保留復原控制；若保存失敗，就不送出系統變更。確認只有在 Helper 明確回報套用成功且期限未過時才能使用。手動貼入既有 `operation_id` 僅供要求回復；它不同於追蹤請求用的 `request_id`。

逾期、連線失敗或回復失敗時，以 Helper 狀態與實際網路為準。失聯時保留操作識別碼，不自動重新建立交易；明確可重試的 Helper transport 錯誤最多重試 10 次，固定沿用同一 ID 與參數。期限過後可清除本頁提示，但這不代表 Helper 已完成回復。一般瀏覽器模式須讓 GUI 與 Agent 使用一致的 Helper 設定；GUI 可辨識既有外部 Helper 設定，`NETTOOL_HELPER_MODE=external` 也可明確指定此模式。

Profile 編輯、刪除、匯入／匯出與快速 IP／DNS 設定仍可使用 [CLI Reference](CLI_REFERENCE.md) 或 Action Console。

## Node 配對與基本測速

1. 取得對端 Node ID、控制位址、TLS server name、DER 憑證及 SPKI fingerprint。
2. 透過獨立管道核對指紋後，在「Node 配對」填寫並勾選核對確認。GUI 憑證檔案上限 8 KiB；憑證內容會經本機 GUI 轉交 Agent，請勿提供私鑰。
3. 只有確實要取代同 ID 的不同身分時，才勾選身分取代。雙端測速需建立雙向信任。
4. 對端 Agent 設定 `NETTOOL_CONTROL_LISTEN=<IP>:<port>` 才啟用 mTLS 控制監聽；預設不監聽。例：`192.0.2.10:9443`，請換成實際位址。
5. 在「網路測速」填寫 Node 名稱或 ID，選 TCP／UDP、上傳／下載／雙向、測量秒數及串流數。UDP 另填 Mbps 目標速率。

基本表單固定使用 `socket` backend，測量範圍 1–3600 秒，預熱與冷卻各 1 秒；串流數為 1–65535。參數仍由 Agent 與對端驗證。執行期間按鈕停用，切換頁面不會取消測速；完成後重新整理歷史。取消既有 Session 可用 CLI `nettool speed cancel <session-id>`。

TCP 不送 UDP 速率；表單不啟用 socket executor 不支援的 auto-tune、latency-under-load 或 NUMA。DPDK、AF_XDP、RIO、raw Ethernet 與高速 benchmark 是伺服器專用進階功能，需原生 SDK／backend 與硬體，請用 CLI／Action Console。未具備條件時會明確失敗，不產生模擬成功數字，也不提供 `100G Certified` 宣告。

## 封包離線分析

在「封包分析」輸入 Agent 主機可讀取的完整 PCAP／PCAPNG 路徑，例如 `D:\captures\capture.pcapng`。這是路徑參數，不是瀏覽器上傳；分析由 Agent 執行。

取樣間隔 `1` 為完整分析，`10` 為每十個封包取樣一次。結果會明確標示完整或取樣；取樣統計不能視為整份檔案的精確總量。損壞或無法讀取的檔案顯示 Agent 錯誤碼。下方「查詢 TCP／UDP 連線」目前限 Linux，Windows／macOS 會明確回報 unsupported。

## Action Console 與錯誤處理

進階 Console 預設收合，只列出 ActionRegistry 內項目，顯示權限、命令對照與伺服器專用標示。參數須為 JSON object；非唯讀操作先顯示確認視窗。網路設定 Action 成功後會帶入 Safe Apply 操作識別碼。請勿在未完成的設定交易上再送出新設定。

| 情況 | 處理方式 |
| --- | --- |
| Agent 無法連線 | 啟動 `nettool-agent`，核對本機 IPC 環境後重新整理 |
| `HELPER.NOT_CONFIGURED`／`HELPER.REQUIRED` | 安裝並設定 Helper，或使用 UAC portable |
| `HELPER.TRANSPORT_FAILED` | 檢查 Helper 已啟動且位址／權限一致；先確認是否已有操作生效 |
| `NODE.NOT_PAIRED` | 獨立核對憑證指紋並完成 Node 配對 |
| `DATAPLANE.BACKEND_NOT_BUILT` | 檢查建置選項、原生 SDK 與硬體條件 |
| GUI 斷線／非 JSON 回應 | 檢查 GUI 服務；變更中的操作先確認結果，避免重複送出 |

## 開發驗證

```powershell
node --test apps/gui/tests/ui.test.cjs apps/gui/tests/ui.test.mjs
cargo test -p nettool-gui
```

JavaScript 測試使用 Node 內建 test runner，不需 npm 安裝。瀏覽器流程測試位於 `apps/gui/tests/browser-smoke.js`，可由 Playwright MCP 的 `browser_run_code_unsafe` 載入執行；測試只攔截 API 使用固定回應，不會改變系統網路或 Node 信任資料。

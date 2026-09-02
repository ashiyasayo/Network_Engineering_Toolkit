# NetTool Portable Desktop Bundle

這是免安裝的桌面 bundle。Windows portable ZIP 解壓縮後，請在同一個目錄執行 `nettool-desktop.exe`；不要只搬移其中一個 binary，因為 desktop shell 會從同目錄尋找 Agent、GUI 與 dataplane sidecar。

Portable bundle 不會安裝、註冊或啟動 privileged Helper，也不會繞過 UAC。它仍可建立、讀取與匯出 profile，以及執行診斷與測試；GUI 在按下 Apply profile 時會明確提示「安裝 Helper MSI 或改用 portable UAC bundle」。因此下列操作在未設定 Helper 時會 fail closed：

一般 portable 適合筆電的狀態查詢、profile 管理、診斷與基本 `socket` 測試；DPDK、AF_XDP、RIO、NUMA／Huge Page 與 100GbE 驗收屬於**伺服器專用**，即使 binary 可啟動也不應以一般裝置的結果作效能宣告。

- `profile apply`、`profile confirm`、`profile rollback`
- `ip set`、`ip dhcp`、`dns set`
- `hosts list`、`hosts replace`、`hosts add`、`hosts remove`、`hosts enable`、`hosts disable`、`hosts backup`、`hosts restore`

錯誤行為是固定的：

- `HELPER.NOT_CONFIGURED`：沒有設定 `NETTOOL_HELPER_SOCKET`；訊息為 `privileged helper socket is not configured`，不會重試。
- `HELPER.TRANSPORT_FAILED`：已設定 Helper transport 但無法連線或逾時；此錯誤可重試。
- `DATAPLANE.BACKEND_NOT_BUILT`：目前 binary 沒有連結要求的 accelerated backend；不會回退成模擬結果。

需要變更系統網路或 Hosts 時，請依平台安裝並啟動獨立 Helper，再從同一個 Agent 使用該 transport。Portable bundle 只提供使用者層 desktop、Agent、GUI 與 dataplane 程序。

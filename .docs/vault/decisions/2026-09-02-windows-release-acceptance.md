# Windows Release Acceptance 決策

日期：2026-09-02

## 背景

Windows 發行已包含 Desktop MSI、獨立 Helper MSI、一般 portable 與 UAC portable。既有 GitHub workflow 可驗證編譯、解包內容與簽章狀態，但無法證明 MSI service、SID-bound Named Pipe、Helper 生命周期或 Safe Apply rollback 在安裝後的實際行為。

## 決策

新增 `packaging/windows/test-release-acceptance.ps1` 與手動 `Windows release acceptance` workflow。它只在具 `nettool-release-acceptance` label、可還原快照的 self-hosted Windows VM 執行，從已發佈的 prerelease 下載 release assets，輸出 JSON report 與 MSI logs。

預設 suite 不變更網路；Safe Apply rollback 只有在操作者明確傳入 `-EnableNetworkMutation`、專用測試 NIC 與 profile 時才會執行。腳本拒絕擁有 IPv4 或 IPv6 預設路由的介面，避免把 CI／管理連線當成測試目標。

## 取捨與限制

- 不將 self-hosted runner 直接納入 stable workflow gate，直到專用 VM 已部署並完成基線驗收；避免 release 因不存在或不健康的外部 runner 無限等待。
- UAC consent 不得自動接受。自動化只驗證 UAC portable Helper 的 binary 與 idle lifecycle；每個 stable release 仍保留一次互動式 UAC／confirm／rollback 人工驗收。
- Named Pipe 的未授權 SID 拒絕需要第二個使用者 token，屬於專用 VM 的人工／延伸測試；目前 harness 驗證安裝時 SID 被寫入 service command line，並驗證該 SID 的 Agent 可到達 Helper。

## 後續啟用 stable gate 的條件

1. 專用 VM runner 以乾淨快照、互動式 Administrator 與雙 NIC 拓撲穩定執行。
2. 至少完成一次 prerelease acceptance，含 optional Safe Apply deadline rollback。
3. 將 workflow 納入 stable release environment 的必要 deployment protection，而不是讓 tag prerelease 依賴該 runner。

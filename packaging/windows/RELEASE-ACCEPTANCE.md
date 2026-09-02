# Windows Release Acceptance

`test-release-acceptance.ps1` 驗證已發佈的 Windows MSI 與兩種 portable ZIP。它會實際安裝／移除 MSI、啟動 Helper service，故只能在可還原快照的獨立 Windows VM 執行；不可在開發機、管理工作站或承載 CI 以外工作負載的 runner 執行。

## VM 前置條件

- Windows x64、具本機 Administrator 權限的互動式 runner。
- 每次驗收從乾淨快照啟動；runner label 設為 `nettool-release-acceptance`。
- 若要測試 Safe Apply，VM 必須另有不承載預設路由／管理連線的測試 NIC。管理 NIC 與測試 NIC 不可共用。
- 已安裝 GitHub Actions self-hosted runner 與 `gh` CLI。workflow 會以 `GITHUB_TOKEN` 下載同 tag 的 prerelease assets。

## 預設驗收範圍

```powershell
.\packaging\windows\test-release-acceptance.ps1 `
  -ArtifactDirectory .\release-assets `
  -AcceptIsolatedVmRisk
```

它會驗證：

- 兩個 MSI、一般 portable、UAC portable 的必要檔案與一般 portable 不含 Helper。
- UAC portable 的 Helper 在無請求時於 bounded idle timeout 後自行結束。
- 一般 portable 可建立與匯出 profile，Apply 穩定回傳 `HELPER.NOT_CONFIGURED`。
- Desktop MSI 不會註冊 Helper；安裝後的 Agent 與 GUI sidecar 可通過 health check。
- Helper MSI 會啟動 `NetToolHelper`、留下 marker，且 service command line 綁定目前使用者 SID。
- 已授權 Agent 能通過 service pipe 送出不會變更網路的 request。

測試結束後會移除兩個 MSI，並在 artifact directory 產生 JSON report 與 MSI logs。失敗時仍應還原 VM snapshot，因為作業系統、憑證存放區與網路堆疊可能留下測試副作用。

## 可選 Safe Apply deadline rollback

只有明確指定測試 NIC 與 profile 才會變更網路。腳本會拒絕任何擁有 IPv4 或 IPv6 預設路由的介面。

```powershell
.\packaging\windows\test-release-acceptance.ps1 `
  -ArtifactDirectory .\release-assets `
  -AcceptIsolatedVmRisk `
  -EnableNetworkMutation `
  -TestInterfaceAlias 'NetTool Test NIC' `
  -SafeApplyProfilePath .\acceptance-profile.json
```

`acceptance-profile.json` 必須是針對該測試 NIC 的有效 `NetworkDesiredState` JSON。測試刻意不 confirm，並檢查 Helper audit 是否記錄 `deadline_expired` rollback；測試失敗後先依 runbook 檢查 NIC，再還原 VM snapshot。

## UAC 的人工驗收

Windows 不應自動繞過或接受 UAC。因此每個 stable release 仍須在互動式 VM 做一次人工確認：開啟 UAC portable、按 Apply、接受 UAC、確認或等待 rollback，並檢查沒有 `NetToolHelper` service 或開機啟動項目。自動化腳本只驗證 portable Helper 的 binary、SID 參數契約與 idle lifecycle，不能取代使用者 consent flow。

## GitHub Actions

`Windows release acceptance` workflow 是手動觸發的，應在 tag prerelease 已發佈後執行。穩定版 promotion 目前不強制等待此 workflow，直到專用 VM runner 已部署並完成至少一次基線驗收；屆時可將它設為 stable release environment 的必要 deployment protection，避免因不存在 runner 而阻塞一般 prerelease。

# Stable Release 簽章／公證決策

日期：2026-08-27

## 背景

Release workflow 已區分 `prerelease` 與 `stable`。Stable 需要 Apple Developer ID、Windows Authenticode 與 Linux GPG artifact signing 的 11 個 GitHub Actions secrets；目前 repository 尚未配置這些 secrets，也沒有實際 GitHub Release。

## 決策

在外部憑證與 signing secrets 尚未取得前，維持目前的 prerelease 流程，不建立未簽章的正式 Stable Release。Stable preflight 應在任一必要 secret 缺少時 fail closed。

## 不申請／不配置的影響

| 平台 | 影響 | 可保留的用途 |
|---|---|---|
| macOS | 無法取得 Developer ID certificate、完成 notarization 與 stapling；公開下載時可能出現 Gatekeeper 警告或阻擋。 | 本機開發、內部測試與未正式簽章的 prerelease。 |
| Windows | MSI 與 portable executable 沒有受信任的 Authenticode publisher；使用者可能看到 Unknown Publisher 或 SmartScreen 警告。 | CI 建置、內部測試；self-signed certificate 只作測試，不視為正式簽章。 |
| Linux | 沒有 GPG key 就不會產生 AppImage/deb 的 `.asc` detached signatures。 | AppImage/deb 仍可建置與測試，但無 release artifact 簽章。 |
| GitHub Release | tag push 仍可產生 prerelease；以 `stable` 執行時會在 preflight 停止，不會建立未簽章正式 Release。 | 保留 CI、跨平台打包、portable bundle 與 smoke test。 |

不配置這些憑證不會阻止程式編譯或 portable bundle 執行，但會使公開發布缺少平台信任鏈，且不符合本專案 Stable Release 的驗收條件。

## 重新啟用 Stable 的條件

1. Apple Developer Account 取得 Developer ID Application certificate，匯出含 private key 的密碼保護 `.p12`，並準備 notarization credentials。
2. Windows 向受信任 CA 取得可用於 Authenticode 的 code-signing `.pfx`。
3. Linux 建立專用 GPG release key，保存完整 fingerprint 與復原／撤銷資訊。
4. 只將必要值寫入 GitHub Actions repository secrets，確認 11 個名稱齊全後，才建立版本 tag 並執行 stable workflow。

在上述條件成立前，`packaging/RELEASE_SECRETS.md` 僅作為設定 runbook，不應填入或提交到 repository；本機暫存檔也應在上傳後刪除或移入加密儲存。

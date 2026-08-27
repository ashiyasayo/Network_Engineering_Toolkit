# Stable Release secrets 設定

Stable Release 需要 Apple、Windows 與 Linux 三組簽章材料。這些資料不可寫入 repository、workflow、shell script 或 release artifact；請只透過 GitHub Actions repository secrets 提供。

## 前置條件

在 repository 根目錄執行以下指令，確認 GitHub CLI 使用具有 Actions secrets 與 contents write 權限的帳號：

```sh
gh auth login
gh auth status
```

設定 repository 變數（只包含 repository 名稱，不包含 secret）：

```sh
REPO=ashiyasayo/Network_Engineering_Toolkit
```

PowerShell 使用：

```powershell
$repo = 'ashiyasayo/Network_Engineering_Toolkit'
```

以下所有 `gh secret set` 都是 repository-level secret，與 workflow 中的 `secrets.NAME` 對應。未提供 `--body` 時，GitHub CLI 會從互動式輸入或 stdin 讀取值；不要把密碼直接放進 shell history。

## Apple Developer ID

準備包含 Developer ID Application certificate 與 private key 的 `.p12` 檔案、其匯出密碼、完整 signing identity、Apple ID、Team ID，以及 App-Specific Password。App-Specific Password 不是 Apple 帳號的一般登入密碼。

在 macOS/Linux 將 `.p12` 轉成單行 base64 後直接送入 GitHub：

```sh
base64 /secure/path/DeveloperID.p12 | tr -d '\n' | gh secret set APPLE_CERTIFICATE_BASE64 --repo "$REPO"
```

Windows PowerShell：

```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes('C:\secure\DeveloperID.p12')) |
    gh secret set APPLE_CERTIFICATE_BASE64 --repo $repo
```

再逐一以互動式輸入設定其餘 Apple secrets：

```sh
gh secret set APPLE_CERTIFICATE_PASSWORD --repo "$REPO"
gh secret set APPLE_SIGNING_IDENTITY --repo "$REPO"
gh secret set APPLE_ID --repo "$REPO"
gh secret set APPLE_TEAM_ID --repo "$REPO"
gh secret set APPLE_APP_PASSWORD --repo "$REPO"
```

## Windows Authenticode

準備包含 code-signing certificate 與 private key 的 `.pfx` 檔案及其密碼。將 `.pfx` 以同樣方式轉成 base64：

```sh
base64 /secure/path/WindowsCodeSigning.pfx | tr -d '\n' | gh secret set WINDOWS_CERTIFICATE_BASE64 --repo "$REPO"
gh secret set WINDOWS_CERTIFICATE_PASSWORD --repo "$REPO"
```

Windows PowerShell：

```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes('C:\secure\WindowsCodeSigning.pfx')) |
    gh secret set WINDOWS_CERTIFICATE_BASE64 --repo $repo
gh secret set WINDOWS_CERTIFICATE_PASSWORD --repo $repo
```

## Linux GPG artifact signing

使用專門的 release signing key，`LINUX_GPG_KEY_ID` 應填完整 fingerprint，避免短 key ID 碰撞。先在受控環境確認 private key 與 passphrase，再直接匯出並傳送 base64：

```sh
LINUX_GPG_KEY_ID='REPLACE_WITH_FULL_FINGERPRINT'
gpg --batch --export-secret-keys --armor "$LINUX_GPG_KEY_ID" |
    base64 | tr -d '\n' |
    gh secret set LINUX_GPG_PRIVATE_KEY_BASE64 --repo "$REPO"
gh secret set LINUX_GPG_KEY_ID --repo "$REPO"
gh secret set LINUX_GPG_PASSPHRASE --repo "$REPO"
```

`REPLACE_WITH_FULL_FINGERPRINT` 只是本機 shell 變數的 placeholder；執行前請換成實際 fingerprint，不要將 private key 或 passphrase 寫入檔案或 commit。

## 驗證與發行順序

只列出 secret 名稱，不會列出值：

```sh
gh secret list --repo "$REPO" --json name --jq '.[].name'
```

Stable preflight 要求以下 11 個名稱全部存在：

```text
APPLE_CERTIFICATE_BASE64
APPLE_CERTIFICATE_PASSWORD
APPLE_SIGNING_IDENTITY
APPLE_ID
APPLE_TEAM_ID
APPLE_APP_PASSWORD
WINDOWS_CERTIFICATE_BASE64
WINDOWS_CERTIFICATE_PASSWORD
LINUX_GPG_PRIVATE_KEY_BASE64
LINUX_GPG_KEY_ID
LINUX_GPG_PASSPHRASE
```

確認名稱齊全、憑證仍有效且 signing identity/key fingerprint 正確後，才建立並推送版本 tag。tag push 會先產生 prerelease；請等待該 prerelease workflow 完成後，再對同一 tag 手動執行 stable workflow。stable workflow 會以已簽章產物更新並提升同名 prerelease，不會因 Release 已存在而失敗：

```sh
git tag -a v0.1.2 -m "release: v0.1.2"
git push origin v0.1.2
```

確認 tag push 觸發的 prerelease workflow 已完成且成功後，再執行 stable workflow：

```sh
gh workflow run release.yml --repo "$REPO" --ref v0.1.2 --field release_mode=stable
```

若 secrets 尚未齊全，請不要執行以上 tag／workflow 指令；stable preflight 會 fail closed，且不會建立正式未簽章 Release。現有遠端 tag 也可直接作為 `--ref`，不必重新建立 tag。

# Security Model

## 原始碼與發布機敏資料

`.env`、憑證、私鑰、簽章輸出與 credentials 目錄只允許存在於本機或受控的 CI secret store；`.gitignore` 已排除常見副檔名，但不能取代提交前檢查。GitHub Release 的 Apple、Windows 與 Linux 簽章材料只能透過 GitHub Actions secrets 提供，不能寫入 workflow、文件、測試 fixture 或 release artifact staging 目錄。

公開 repository 的 Git commit metadata 可能包含作者 email；後續提交應使用 GitHub 提供的 `noreply` email。既有公開歷史不在一般修正中改寫，若必須移除 metadata 需另行核准 history rewrite、force-push 與所有受影響 credential 的輪替。

## Trust boundaries

```text
User → GUI/CLI → user-only Agent IPC → unprivileged Agent
                                      ↓ authenticated helper IPC
                                privileged Helper → OS/NIC/filesystem
                                      ↓ scoped launch
                                  Dataplane → NIC queues
Remote Node → TLS 1.3 control plane → Agent
```

Helper protocol 使用封閉 enum whitelist，只包含 network、hosts、NIC、hugepage 與 Safe Apply 操作；不存在 shell、PowerShell、bash 或任意 command operation。Network desired state 使用逐層拒絕未知欄位的 typed schema，並在 snapshot 或副作用前驗證 IP family、prefix、route、DNS、MTU 與資源上限。Caller identity 必須由 OS peer credential 取得，不得信任 request payload 自稱的 principal。

Unix Helper server 的公開入口直接向 kernel 讀取 socket peer UID/PID，wire schema 會拒絕 caller identity 欄位，再以 exact UID allowlist 授權。可注入 credentials 的交換函式不對 crate 外公開，避免 production caller 繞過 kernel authentication。Frame 在 allocation 前限制為 1 MiB。

Safe Apply snapshot、deadline 與 audit 由 Helper 擁有。相同 operation ID 的相同 request 可安全重送；不同 payload 重用 ID 會拒絕，deadline 到達後不得以延遲 confirm 逃避 rollback。Audit 僅記錄 operation、target、狀態 hash 與結果，不記錄完整設定、credential 或 packet payload。Packet capture 預設關閉，且 SQLite 不保存完整封包或私鑰。

Linux NetworkManager executor 要求 absolute binary path，所有設定值都作為獨立 argv 傳遞而不經 shell。它在副作用前持久化完整 profile property snapshot，套用後讀回驗證，失敗則交由 Safe Apply rollback；snapshot ID 僅接受 64 位 hex，不能形成 path traversal。

macOS `networksetup` adapter 只產生固定 `/usr/sbin/networksetup` 與獨立 argv；interface ID 先做 allowlist validation，routes 等尚未具備完整 rollback/read-back 證據的操作會拒絕，不會退回 shell 或猜測性執行。

Windows adapter 只產生固定 `C:\Windows\System32\netsh.exe` 與獨立 argv；interface、DNS 與 address 欄位不會插入 PowerShell/script syntax，routes/search domains 等未完成 read-back 的操作會拒絕。

Runner 在交給平台執行器前會再次驗證 executable path、argv 長度與禁止字元，確保呼叫端無法繞過 fixed-argv builder。

Linux root helper binary 與 systemd hardening assets 已提供。Service 啟動後先處理 helper-owned expired deadlines，運行中以一秒 watchdog 持續檢查；client exchange 限制兩秒，不能無限期卡住 rollback。Socket mode 為 `0660`；systemd state directory 為 `0700`，並以 `ProtectSystem=strict` 及 `ReadWritePaths` 限制寫入位置。安裝程式仍必須填入 exact Agent UID、建立 group membership，且應在目標 distribution 驗證 sandbox 與 NetworkManager 相容性。

Linux NIC handler 不允許 wire request 指定任意 restore driver；原 driver 只從 Helper 在 unbind 前持久化的 snapshot 取得，PCI address 與 prepare operation 必須完全相符。Huge Page handler 同樣以 helper-owned previous count 還原，並限制單次請求總容量不超過 1 TiB。兩者寫入後都讀回驗證，snapshot rename 後同步 parent directory。這些 NIC binding 與 Huge Page 操作屬於**伺服器專用**工作負載，必須在隔離的測試 NIC 上執行，不能套用到一般筆電或 management NIC。

目前尚未完成的安全邊界包括 macOS/Windows 正式 installer 與 privileged service 整合；Linux 已提供 root-only helper installer。Node pairing 現在要求 CLI/GUI 明確提供 out-of-band fingerprint confirmation，Storage 會在 trust transaction 前拒絕未確認 request。macOS network executor 已接入 Unix helper，但仍需在 macOS 實機完成 privileged service/ACL 與 end-to-end 測試。Windows Named Pipe helper 已接入 token SID authentication、`netsh` executor 與 Safe Apply，但仍需在 Windows runner/VM 完成實機 ACL 與 end-to-end 測試後才能標示為 production-ready。

Hosts backup/restore 與 managed-section replace 使用 helper-owned temporary file；Windows replacement 由集中 FFI 邊界呼叫 `MoveFileExW` 的 replace/write-through flags。

Node transport 已限制為 mutual TLS 1.3，並以完整 SHA-256 public-key fingerprint 建立 persistent trust。相同 Node ID 出現不同 fingerprint 時回傳 identity-changed decision，不允許 silent migration。Identity private key 只保存於 macOS Keychain、Windows Credential Manager 或 Linux Secret Service；首次建立使用 CSPRNG Node ID 與 PKCS#8 asymmetric key，載入時驗證憑證／金鑰一致性，平台 store 失敗時不允許 plaintext fallback。每條新 control connection 會從最新 trust registry 建立 verifier，pairing/revoke 不需重啟即可影響新連線；既有 TLS 連線維持原 session。

Pairing metadata 保存 certificate DER、TLS server name、control socket 與 SPKI fingerprint；certificate 為公開資料，private key 永不進入 SQLite。Trust write 會驗證 certificate/fingerprint，既有 Node ID 換 key 時必須帶入明確 re-pair confirmation。Agent 連線同時要求 WebPKI chain/name、SPKI fingerprint 與 Hello Node ID 三者成立。

Socket data plane 使用 control plane 簽發的高熵 session-scoped tag。TCP 每條 stream 先驗證 session/tag 與唯一 stream ID，UDP receiver 先驗證 endpoint/session/stream/tag AUTH datagram；未授權 payload 不進入量測，並使用 `NODE.DATA_PLANE_UNAUTHORIZED` 與一般 transport failure 區分。Tag 只存在記憶體與控制／資料交換，不寫入 result 或 audit log。

Socket upload/download 的 Agent runtime 會在 remote Prepare 後以排定的 `start_at` 啟動 authorized sender/receiver，worker 失敗時嘗試送出 Stop 釋放 remote reservation；receiver endpoint 或 sender config 只在 coordinator 原子移交後執行，避免重複 Start 取得同一資源。完成或失敗 result 只保存 bounded versioned JSON 與 SHA-256，不包含 authorization tag。

Node server dispatcher 只能在外層完成 mTLS certificate/trust 驗證後建立，並再次要求 Hello Node ID 等於 authenticated peer record。Hello 前的 command、重複 Hello、零／錯誤長度 request ID、超出 negotiated minor及 response-only message 都會拒絕；request failure 只回傳 bounded stable `ProtocolError`，不執行猜測性 fallback。

Node network listener 採 explicit opt-in，未設定 `NETTOOL_CONTROL_LISTEN` 不會開 port。每條新連線由最新 trusted certificates 建立 client verifier，空 trust store 或 fingerprint ambiguity 會 fail closed；TLS 後仍重新計算 presented SPKI fingerprint。既有 TLS 連線維持原 session，pairing/revoke 對新連線立即生效。

Windows privileged helper 的 Named Pipe peer identity 不接受 request payload 內的 caller 欄位；`nettool-platform-auth` 由 kernel pipe handle 取得 client process token，轉成 SID principal 後交給 exact allowlist。Token/API 任何一步失敗都拒絕 request。

# Linux Helper Installation

`nettool-helper` 必須安裝為 root-owned `/usr/libexec/nettool-helper`，並由 systemd unit 啟動。GitHub Actions 的 stable release 會為 AppImage 與 deb 產生 ASCII-armored detached GPG signatures (`.asc`)；prerelease 不含這些簽章檔。安裝程式需完成：

桌面 shell 可由 `install-desktop.sh --source-directory <release-dir> --dry-run` 驗證，移除 `--dry-run` 後安裝至 `/opt/nettool` 並註冊 `/usr/share/applications/nettool.desktop`；自訂 prefix 時會同步產生正確的 `Exec` 路徑。此步驟不會以 root 執行 GUI；root 權限只用於安裝檔案，特權網路操作仍由獨立 helper 負責。

1. 透過 `nettool-helper.sysusers` 建立 `nettool` system group。
2. 將實際執行 `nettool-agent` 的帳號加入 `nettool` group。
3. 將 `nettool-helper.env.example` 複製為 `/etc/nettool/helper.env`，把 `NETTOOL_AGENT_UID` 設為該帳號的數字 UID；不得保留範例值。
4. 將 unit 安裝至 systemd unit directory，執行 daemon reload 後 enable/start。

可使用 `./packaging/linux/install-helper.sh --source-directory <release-dir> --agent-user <agent-user> --dry-run` 先驗證 binary、使用者與 UID；移除 `--dry-run` 後腳本才會要求 root、建立 `nettool` group、安裝 binary/env/unit 並執行 `systemctl enable --now`。腳本只接受固定參數與固定目標路徑，不接受 shell command 或任意 service 名稱。

Socket 由 root service 建立為 `/run/nettool/helper.sock`、mode `0660`。Group permission 只允許建立連線；Helper 仍會從 kernel 取得 peer UID，只有與 `NETTOOL_AGENT_UID` 完全相同的 caller 才能通過授權。

State 與 snapshots 位於 `/var/lib/nettool/helper`、mode `0700`。Unit 僅開放 `/etc/hosts`、state/runtime directory 與 PCI/Huge Page 所需的明確 sysfs paths 寫入；PCI binding 與 Huge Page 是**伺服器專用**功能，必須使用隔離測試 NIC，不能影響 management NIC。變更 UID 後必須重新啟動 Helper，並重新啟動 Agent 以取得新的 group membership。

目前 unit 只適用使用 NetworkManager 且 `/usr/bin/nmcli` 存在的 Linux Ethernet 主機。安裝前應在目標 distribution 的隔離測試機驗證 package path、systemd sandbox 與 NetworkManager 版本。

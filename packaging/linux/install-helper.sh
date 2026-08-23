#!/bin/sh
# 安裝 Linux privileged helper；只有明確的 root 執行才會修改系統狀態。
set -eu

source_dir=""
agent_user=""
dry_run=0

usage() {
    echo "usage: $0 --source-directory DIR --agent-user USER [--dry-run]" >&2
    exit 2
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --source-directory)
            [ "$#" -ge 2 ] || usage
            source_dir=$2
            shift 2
            ;;
        --agent-user)
            [ "$#" -ge 2 ] || usage
            agent_user=$2
            shift 2
            ;;
        --dry-run)
            dry_run=1
            shift
            ;;
        *)
            usage
            ;;
    esac
done

[ -n "$source_dir" ] && [ -n "$agent_user" ] || usage
case "$agent_user" in
    *[!A-Za-z0-9_.-]*|"") echo "agent user contains unsupported characters" >&2; exit 2 ;;
esac
[ -d "$source_dir" ] || { echo "source directory does not exist: $source_dir" >&2; exit 3; }
helper="$source_dir/nettool-helper"
[ -f "$helper" ] || { echo "missing release binary: $helper" >&2; exit 3; }
unit="$source_dir/../nettool-helper.service"
[ -f "$unit" ] || { echo "missing systemd unit: $unit" >&2; exit 3; }

if ! uid=$(id -u "$agent_user" 2>/dev/null); then
    echo "agent user does not exist: $agent_user" >&2
    exit 4
fi
case "$uid" in
    ''|*[!0-9]*) echo "agent UID is not numeric" >&2; exit 4 ;;
esac

if [ "$dry_run" -eq 1 ]; then
    echo "validated Linux helper release for user $agent_user (uid $uid); no files changed"
    exit 0
fi

[ "$(id -u)" -eq 0 ] || { echo "helper installation requires root" >&2; exit 5; }

if ! getent group nettool >/dev/null 2>&1; then
    groupadd --system nettool
fi
usermod --append --groups nettool "$agent_user"

install -d -m 0755 /usr/libexec
install -o root -g root -m 0755 "$helper" /usr/libexec/nettool-helper
install -d -m 0755 /etc/nettool
env_tmp=$(mktemp /etc/nettool/helper.env.tmp.XXXXXX)
cleanup() {
    rm -f "$env_tmp"
}
trap cleanup EXIT HUP INT TERM
printf 'NETTOOL_AGENT_UID=%s\n' "$uid" >"$env_tmp"
chown root:root "$env_tmp"
chmod 0600 "$env_tmp"
mv -f "$env_tmp" /etc/nettool/helper.env
env_tmp=""

install -d -m 0755 /usr/lib/systemd/system
install -o root -g root -m 0644 \
    "$unit" \
    /usr/lib/systemd/system/nettool-helper.service
systemctl daemon-reload
systemctl enable --now nettool-helper.service
echo "installed and started nettool-helper for agent UID $uid"

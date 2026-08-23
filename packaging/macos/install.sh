#!/bin/sh
# NetTool macOS staging installer；不自行取得 root，請由受控 package runner 呼叫。
set -eu

source_dir=${1:?"usage: install.sh <release-directory> [prefix]"}
prefix=${2:-"/Library/Application Support/NetTool"}
case "$prefix" in
  /* ) [ "$prefix" != "/" ] || { echo "prefix must not be filesystem root" >&2; exit 2; } ;;
  * ) echo "prefix must be an absolute path" >&2; exit 2 ;;
esac

allowed="nettool nettool-agent nettool-gui nettool-dataplane nettool-desktop"
stage="${prefix}.staging.$$"
backup="${prefix}.backup.$(date +%Y%m%d%H%M%S)"
old_moved=0
cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then
    rm -rf "$stage"
    if [ "$old_moved" -eq 1 ] && [ ! -e "$prefix" ] && [ -e "$backup" ]; then
      mv "$backup" "$prefix" || true
    fi
  fi
  exit "$status"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$stage"
for name in $allowed; do
  input="$source_dir/$name"
  [ -f "$input" ] || { echo "missing release binary: $input" >&2; exit 3; }
  [ ! -L "$input" ] || { echo "release binary must not be a symlink: $input" >&2; exit 3; }
  install -m 0755 "$input" "$stage/$name"
done

mkdir -p "$(dirname "$prefix")"
if [ -e "$prefix" ]; then
  mv "$prefix" "$backup"
  old_moved=1
fi
mv "$stage" "$prefix"
old_moved=0
echo "installed NetTool binaries to $prefix"

#!/bin/sh
set -eu
source_dir=""
prefix=/opt/nettool
dry_run=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --source-directory) [ "$#" -ge 2 ] || exit 2; source_dir=$2; shift 2 ;;
    --prefix) [ "$#" -ge 2 ] || exit 2; prefix=$2; shift 2 ;;
    --dry-run) dry_run=1; shift ;;
    *) echo "usage: $0 --source-directory DIR [--prefix ABS] [--dry-run]" >&2; exit 2 ;;
  esac
done
[ -n "$source_dir" ] || { echo "source directory is required" >&2; exit 2; }
case "$prefix" in /*) ;; *) echo "prefix must be absolute" >&2; exit 2 ;; esac
for name in nettool-desktop nettool-agent nettool-gui nettool-dataplane; do
  [ -f "$source_dir/$name" ] || { echo "missing release binary: $source_dir/$name" >&2; exit 3; }
done
if [ "$dry_run" -eq 1 ]; then echo "validated NetTool desktop release; no files changed"; exit 0; fi
[ "$(id -u)" -eq 0 ] || { echo "desktop installation requires root" >&2; exit 5; }
stage="$prefix.staging.$$"
backup="$prefix.backup.$(date +%Y%m%d%H%M%S)"
mkdir -p "$stage"
for name in nettool-desktop nettool-agent nettool-gui nettool-dataplane; do
  install -m 0755 "$source_dir/$name" "$stage/$name"
done
mkdir -p "$(dirname "$prefix")" /usr/share/applications
if [ -e "$prefix" ]; then mv "$prefix" "$backup"; fi
mv "$stage" "$prefix"
install -m 0644 "$(dirname "$0")/nettool.desktop" /usr/share/applications/nettool.desktop
echo "installed NetTool desktop to $prefix"

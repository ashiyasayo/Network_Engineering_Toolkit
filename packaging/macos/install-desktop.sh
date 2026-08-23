#!/bin/sh
# Install a previously built NetTool.app using same-volume replacement.
set -eu
source=${1:?'usage: install-desktop.sh <NetTool.app> [Applications-directory]'}
destination=${2:-/Applications}
[ -d "$source" ] && [ -f "$source/Contents/Info.plist" ] || { echo "invalid app bundle" >&2; exit 3; }
case "$destination" in /*) ;; *) echo "destination must be absolute" >&2; exit 2 ;; esac
stage="$destination/.NetTool.app.staging.$$"
backup="$destination/NetTool.app.backup.$(date +%Y%m%d%H%M%S)"
mkdir -p "$stage"
cp -R "$source/" "$stage/NetTool.app"
if [ -e "$destination/NetTool.app" ]; then mv "$destination/NetTool.app" "$backup"; fi
mv "$stage/NetTool.app" "$destination/NetTool.app"
rmdir "$stage"
echo "installed $destination/NetTool.app (unsigned; sign and notarize for release)"

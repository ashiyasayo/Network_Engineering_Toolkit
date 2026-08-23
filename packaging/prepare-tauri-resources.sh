#!/bin/sh
# Stage runtime sidecars consumed by `cargo tauri build`.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
resource_dir="$root/apps/desktop/resources"
mkdir -p "$resource_dir"
for name in nettool nettool-agent nettool-gui nettool-dataplane; do
  source="$root/target/release/$name"
  [ -f "$source" ] || { echo "missing release binary: $source" >&2; exit 3; }
  cp "$source" "$resource_dir/$name"
  chmod 0755 "$resource_dir/$name"
done
echo "staged Tauri runtime resources in $resource_dir"

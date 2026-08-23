#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
out=${1:-"$root/target/linux-release"}
cargo build --manifest-path "$root/Cargo.toml" --release -p nettool -p nettool-desktop -p nettool-agent -p nettool-gui -p nettool-dataplane
mkdir -p "$out"
for name in nettool nettool-desktop nettool-agent nettool-gui nettool-dataplane; do cp "$root/target/release/$name" "$out/$name"; done
echo "staged unsigned Linux release in $out; use Tauri AppImage/deb bundling for distribution"

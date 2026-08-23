#!/bin/sh
# Build a native macOS app bundle. Signing/notarization are explicit release steps.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
version=${NETTOOL_VERSION:-0.1.0}
out=${1:-"$root/target/macos"}
app="$out/NetTool.app"
cargo build --manifest-path "$root/Cargo.toml" --release -p nettool -p nettool-desktop -p nettool-agent -p nettool-gui -p nettool-dataplane
rm -rf "$app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
cp "$root/target/release/nettool-desktop" "$app/Contents/MacOS/NetTool"
cp "$root/target/release/nettool" "$app/Contents/Resources/nettool"
cp "$root/target/release/nettool-agent" "$app/Contents/Resources/nettool-agent"
cp "$root/target/release/nettool-gui" "$app/Contents/Resources/nettool-gui"
cp "$root/target/release/nettool-dataplane" "$app/Contents/Resources/nettool-dataplane"
chmod 0755 "$app/Contents/MacOS/NetTool" "$app/Contents/Resources"/*
cat > "$app/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleDisplayName</key><string>NetTool</string>
<key>CFBundleExecutable</key><string>NetTool</string>
<key>CFBundleIdentifier</key><string>com.nettool.desktop</string>
<key>CFBundleName</key><string>NetTool</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>$version</string>
<key>CFBundleVersion</key><string>$version</string>
<key>LSMinimumSystemVersion</key><string>11.0</string>
</dict></plist>
EOF
echo "built unsigned $app"

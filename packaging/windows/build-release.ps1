param([string]$OutputDirectory = "target\windows-release")
$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
cargo build --manifest-path (Join-Path $root "Cargo.toml") --release -p nettool -p nettool-desktop -p nettool-agent -p nettool-gui -p nettool-dataplane -p nettool-helper
New-Item -ItemType Directory -Force -Path (Join-Path $root $OutputDirectory) | Out-Null
foreach ($name in @("nettool.exe", "nettool-desktop.exe", "nettool-agent.exe", "nettool-gui.exe", "nettool-dataplane.exe")) {
  Copy-Item (Join-Path $root "target\release\$name") (Join-Path $root $OutputDirectory) -Force
}
Copy-Item (Join-Path $root "target\release\nettool-helper.exe") (Join-Path $root $OutputDirectory) -Force
Write-Output "staged unsigned Windows release in $OutputDirectory; build the desktop MSI with Tauri, then run packaging\windows\build-helper-msi.ps1 for the separate privileged Helper MSI"

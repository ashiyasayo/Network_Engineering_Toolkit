param(
    [Parameter(Mandatory = $true)][string]$HelperBinary,
    [Parameter(Mandatory = $true)][string]$Version,
    [string]$OutputDirectory = "target\release\bundle\msi",
    [switch]$SkipValidation
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$helper = (Resolve-Path -LiteralPath $HelperBinary).Path
if (-not (Test-Path -LiteralPath $helper -PathType Leaf)) {
    throw "HelperBinary must be a file: $HelperBinary"
}
if ($Version -notmatch '^\d+\.\d+\.\d+$') {
    throw "Version must use MSI-compatible major.minor.patch format"
}
$output = Join-Path $root $OutputDirectory
New-Item -ItemType Directory -Force -Path $output | Out-Null
$wixRoot = Join-Path $env:LOCALAPPDATA 'tauri\WixTools314'
$candle = Join-Path $wixRoot 'candle.exe'
$light = Join-Path $wixRoot 'light.exe'
if (-not (Test-Path -LiteralPath $candle -PathType Leaf) -and -not (Get-Command candle.exe -ErrorAction SilentlyContinue)) {
    throw "WiX candle.exe is unavailable. Run cargo tauri build once or install WiX Toolset 3.14."
}
if (-not (Test-Path -LiteralPath $light -PathType Leaf) -and -not (Get-Command light.exe -ErrorAction SilentlyContinue)) {
    throw "WiX light.exe is unavailable. Run cargo tauri build once or install WiX Toolset 3.14."
}
if (-not (Test-Path -LiteralPath $candle -PathType Leaf)) { $candle = (Get-Command candle.exe).Source }
if (-not (Test-Path -LiteralPath $light -PathType Leaf)) { $light = (Get-Command light.exe).Source }
$wxs = Join-Path $root 'packaging\windows\helper.wxs'
$marker = Join-Path $root 'packaging\windows\helper-installed.marker'
$object = Join-Path $output 'nettool-helper.wixobj'
$msi = Join-Path $output "NetToolHelper_$Version`_x64_en-US.msi"
& $candle -nologo -arch x64 "-dHelperBinary=$helper" "-dHelperVersion=$Version" "-dHelperMarker=$marker" -out $object $wxs
if ($LASTEXITCODE -ne 0) { throw "WiX candle failed" }
$lightArguments = @('-nologo', '-ext', 'WixUIExtension', '-out', $msi, $object)
if ($SkipValidation) { $lightArguments = @('-sval') + $lightArguments }
& $light @lightArguments
if ($LASTEXITCODE -ne 0) { throw "WiX light failed" }
if (-not (Test-Path -LiteralPath $msi -PathType Leaf)) { throw "Helper MSI was not created" }
Write-Output "created Helper MSI: $msi"

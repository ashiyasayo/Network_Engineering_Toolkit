param(
    [Parameter(Mandatory = $true)][string]$SourceDirectory,
    [string]$InstallDirectory = "$env:ProgramFiles\NetTool",
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
$allowed = @("nettool.exe", "nettool-agent.exe", "nettool-gui.exe", "nettool-dataplane.exe", "nettool-desktop.exe")
$source = (Resolve-Path -LiteralPath $SourceDirectory).Path
$parent = Split-Path -Parent $InstallDirectory
$stage = Join-Path $parent ("NetTool.staging." + [Guid]::NewGuid().ToString("N"))
$backup = "$InstallDirectory.backup.$(Get-Date -Format yyyyMMddHHmmss)"

if (-not [System.IO.Path]::IsPathFullyQualified($InstallDirectory)) {
    throw "InstallDirectory must be an absolute path"
}
foreach ($name in $allowed) {
    $input = Join-Path $source $name
    if (-not (Test-Path -LiteralPath $input -PathType Leaf)) {
        throw "missing release binary: $input"
    }
    $item = Get-Item -LiteralPath $input -Force
    if ($item.LinkType -or $item.Attributes.HasFlag([System.IO.FileAttributes]::ReparsePoint)) {
        throw "release binary must not be a symlink or reparse point: $input"
    }
}
if ($DryRun) {
    Write-Output "validated release binaries; no files changed"
    exit 0
}

$oldMoved = $false
try {
    New-Item -ItemType Directory -Path $stage -Force | Out-Null
    foreach ($name in $allowed) {
        Copy-Item -LiteralPath (Join-Path $source $name) -Destination (Join-Path $stage $name)
    }
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    if (Test-Path -LiteralPath $InstallDirectory) {
        Move-Item -LiteralPath $InstallDirectory -Destination $backup
        $oldMoved = $true
    }
    Move-Item -LiteralPath $stage -Destination $InstallDirectory
    $oldMoved = $false
    Write-Output "installed NetTool binaries to $InstallDirectory"
}
catch {
    if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
    if ($oldMoved -and -not (Test-Path -LiteralPath $InstallDirectory) -and (Test-Path -LiteralPath $backup)) {
        Move-Item -LiteralPath $backup -Destination $InstallDirectory
    }
    throw
}

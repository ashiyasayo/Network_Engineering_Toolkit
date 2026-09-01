param(
    [Parameter(Mandatory = $true)][string]$MsiPath,
    [switch]$Quiet
)

$ErrorActionPreference = "Stop"
$msi = (Resolve-Path -LiteralPath $MsiPath).Path
if ([IO.Path]::GetExtension($msi) -ne '.msi') { throw "MsiPath must point to an MSI" }
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if ([string]::IsNullOrWhiteSpace($sid)) { throw "Cannot determine the current user SID" }
$arguments = @('/i', ('"{0}"' -f $msi), ('NETTOOL_ALLOWED_SID={0}' -f $sid))
if ($Quiet) { $arguments += @('/qn', '/norestart') }
$process = Start-Process -FilePath 'msiexec.exe' -Verb RunAs -Wait -PassThru -ArgumentList $arguments
if ($process.ExitCode -ne 0) { throw "Helper MSI installation failed with exit code $($process.ExitCode)" }
Write-Output "NetTool Helper installed for SID $sid. Restart NetTool Desktop before applying profiles."

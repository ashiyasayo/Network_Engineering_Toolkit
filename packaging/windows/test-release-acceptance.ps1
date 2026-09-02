[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ArtifactDirectory,
    [Parameter(Mandatory = $true)][switch]$AcceptIsolatedVmRisk,
    [string]$ReportPath,
    [switch]$VerifySignatures,
    [switch]$EnableNetworkMutation,
    [string]$TestInterfaceAlias,
    [string]$SafeApplyProfilePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-Msi {
    param([Parameter(Mandatory = $true)][string[]]$Arguments, [Parameter(Mandatory = $true)][string]$LogPath)

    $process = Start-Process -FilePath 'msiexec.exe' -ArgumentList ($Arguments + @('/norestart', '/l*v', ('"{0}"' -f $LogPath))) -Wait -PassThru -NoNewWindow
    if ($process.ExitCode -ne 0) {
        throw "msiexec failed with exit code $($process.ExitCode); see $LogPath"
    }
}

function Start-NetToolProcess {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [string[]]$Arguments = @(),
        [hashtable]$Environment = @{}
    )

    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FilePath
    $startInfo.WorkingDirectory = $WorkingDirectory
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    foreach ($argument in $Arguments) {
        [void]$startInfo.ArgumentList.Add($argument)
    }
    foreach ($key in $Environment.Keys) {
        if ($null -eq $Environment[$key]) {
            [void]$startInfo.EnvironmentVariables.Remove($key)
        } else {
            $startInfo.EnvironmentVariables[$key] = [string]$Environment[$key]
        }
    }
    return [Diagnostics.Process]::Start($startInfo)
}

function Invoke-NetToolCli {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][hashtable]$Environment
    )

    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FilePath
    $startInfo.WorkingDirectory = $WorkingDirectory
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in $Arguments) {
        [void]$startInfo.ArgumentList.Add($argument)
    }
    foreach ($key in $Environment.Keys) {
        if ($null -eq $Environment[$key]) {
            [void]$startInfo.EnvironmentVariables.Remove($key)
        } else {
            $startInfo.EnvironmentVariables[$key] = [string]$Environment[$key]
        }
    }
    $process = [Diagnostics.Process]::Start($startInfo)
    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    return [pscustomobject]@{ ExitCode = $process.ExitCode; Stdout = $stdout; Stderr = $stderr }
}

function Wait-NetToolHealth {
    param(
        [Parameter(Mandatory = $true)][string]$Cli,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][hashtable]$Environment
    )

    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    do {
        $result = Invoke-NetToolCli -FilePath $Cli -WorkingDirectory $WorkingDirectory -Arguments @('health', '--output', 'json') -Environment $Environment
        if ($result.ExitCode -eq 0) {
            return
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'nettool-agent did not become ready within 10 seconds'
}

function Stop-NetToolProcess {
    param([AllowNull()][Diagnostics.Process]$Process)

    if ($null -ne $Process -and -not $Process.HasExited) {
        $Process.Kill()
        $Process.WaitForExit()
    }
}

function Get-OnlyFile {
    param([Parameter(Mandatory = $true)][string]$Directory, [Parameter(Mandatory = $true)][string]$Filter)

    $matches = @(Get-ChildItem -LiteralPath $Directory -Recurse -File -Filter $Filter)
    if ($matches.Count -ne 1) {
        throw "expected exactly one $Filter in $Directory, found $($matches.Count)"
    }
    return $matches[0].FullName
}

function Assert-RequiredFiles {
    param([Parameter(Mandatory = $true)][string]$Directory, [Parameter(Mandatory = $true)][string[]]$Names)

    foreach ($name in $Names) {
        if (-not (Test-Path -LiteralPath (Join-Path $Directory $name) -PathType Leaf)) {
            throw "missing required release file: $name"
        }
    }
}

function New-AgentEnvironment {
    param([Parameter(Mandatory = $true)][string]$Root, [AllowNull()][string]$HelperPipe)

    $socket = "\\.\pipe\NetTool.ReleaseAcceptance.$([Guid]::NewGuid().ToString('N'))"
    return @{
        NETTOOL_AGENT_SOCKET = $socket
        NETTOOL_DATABASE = (Join-Path $Root 'nettool.db')
        NETTOOL_HELPER_SOCKET = $HelperPipe
    }
}

function Assert-NotManagementInterface {
    param([Parameter(Mandatory = $true)][string]$Alias)

    $adapter = @(Get-NetAdapter -Name $Alias -ErrorAction Stop)
    if ($adapter.Count -ne 1) {
        throw "TestInterfaceAlias must resolve to exactly one adapter: $Alias"
    }
    $index = $adapter[0].ifIndex
    $defaultRoutes = @(Get-NetRoute -InterfaceIndex $index -ErrorAction SilentlyContinue | Where-Object { $_.DestinationPrefix -in @('0.0.0.0/0', '::/0') })
    if ($defaultRoutes.Count -ne 0) {
        throw "refusing network mutation: $Alias owns a default route and may be the management interface"
    }
    return $adapter[0]
}

if (-not $AcceptIsolatedVmRisk) {
    throw 'This acceptance test changes installed software and services. Run only on a disposable VM and pass -AcceptIsolatedVmRisk.'
}
if (-not (Test-IsAdministrator)) {
    throw 'This acceptance test requires an elevated administrator session.'
}
if ($EnableNetworkMutation -and ([string]::IsNullOrWhiteSpace($TestInterfaceAlias) -or [string]::IsNullOrWhiteSpace($SafeApplyProfilePath))) {
    throw '-EnableNetworkMutation requires both -TestInterfaceAlias and -SafeApplyProfilePath.'
}
if ((-not $EnableNetworkMutation) -and ($TestInterfaceAlias -or $SafeApplyProfilePath)) {
    throw 'TestInterfaceAlias and SafeApplyProfilePath require -EnableNetworkMutation.'
}

$artifactRoot = (Resolve-Path -LiteralPath $ArtifactDirectory).Path
$scratch = Join-Path ([IO.Path]::GetTempPath()) "nettool-release-acceptance-$([Guid]::NewGuid().ToString('N'))"
$diagnostics = Join-Path $scratch 'diagnostics'
New-Item -ItemType Directory -Path $diagnostics -Force | Out-Null
if ([string]::IsNullOrWhiteSpace($ReportPath)) {
    $ReportPath = Join-Path $artifactRoot 'nettool-release-acceptance-report.json'
}
$results = [Collections.Generic.List[object]]::new()
$desktopInstalled = $false
$helperInstalled = $false
$agents = [Collections.Generic.List[Diagnostics.Process]]::new()
$safeApplyOperation = $null
$safeApplyCli = $null
$safeApplyWorkingDirectory = $null
$safeApplyEnvironment = $null
$failure = $null

function Invoke-Check {
    param([Parameter(Mandatory = $true)][string]$Name, [Parameter(Mandatory = $true)][scriptblock]$Action)

    try {
        & $Action
        $results.Add([pscustomobject]@{ name = $Name; status = 'passed'; message = '' })
    } catch {
        $results.Add([pscustomobject]@{ name = $Name; status = 'failed'; message = $_.Exception.Message })
        throw
    }
}

try {
    New-Item -ItemType Directory -Path $scratch -Force | Out-Null
    $desktopMsi = Get-OnlyFile -Directory $artifactRoot -Filter 'NetTool_*.msi'
    $helperMsi = Get-OnlyFile -Directory $artifactRoot -Filter 'NetToolHelper_*.msi'
    $portableZip = Get-OnlyFile -Directory $artifactRoot -Filter 'nettool-windows-x64-portable.zip'
    $portableUacZip = Get-OnlyFile -Directory $artifactRoot -Filter 'nettool-windows-x64-portable-uac.zip'
    $portableRoot = Join-Path $scratch 'portable'
    $portableUacRoot = Join-Path $scratch 'portable-uac'

    Invoke-Check 'release artifacts are complete' {
        Expand-Archive -LiteralPath $portableZip -DestinationPath $portableRoot -Force
        Expand-Archive -LiteralPath $portableUacZip -DestinationPath $portableUacRoot -Force
        $runtimeFiles = @('nettool.exe', 'nettool-desktop.exe', 'nettool-agent.exe', 'nettool-gui.exe', 'nettool-dataplane.exe', 'LICENSE.md', 'LICENSE-MIT', 'LICENSE-APACHE')
        Assert-RequiredFiles -Directory $portableRoot -Names ($runtimeFiles + 'README-portable.md')
        Assert-RequiredFiles -Directory $portableUacRoot -Names ($runtimeFiles + @('nettool-helper.exe', 'README-portable-uac.md'))
        if (Test-Path -LiteralPath (Join-Path $portableRoot 'nettool-helper.exe') -PathType Leaf) {
            throw 'ordinary portable bundle must not contain nettool-helper.exe'
        }
    }

    Invoke-Check 'portable UAC helper exits after bounded idle time' {
        $stateDirectory = Join-Path $scratch 'portable-helper-state'
        $hostsPath = Join-Path $scratch 'hosts'
        Set-Content -LiteralPath $hostsPath -Value '' -NoNewline
        $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        $pipe = "\\.\pipe\NetTool.Acceptance.$([Guid]::NewGuid().ToString('N'))"
        $process = Start-NetToolProcess -FilePath (Join-Path $portableUacRoot 'nettool-helper.exe') -WorkingDirectory $portableUacRoot -Arguments @('--pipe', $pipe, '--allow-sid', $sid, '--state-dir', $stateDirectory, '--hosts-file', $hostsPath, '--idle-timeout-seconds', '10')
        if (-not $process.WaitForExit(15000)) {
            Stop-Process -Id $process.Id -Force
            throw 'portable UAC helper did not exit after its bounded idle timeout'
        }
        if ($process.ExitCode -ne 0) {
            throw "portable UAC helper exited with $($process.ExitCode)"
        }
    }

    Invoke-Check 'ordinary portable profile operations fail closed without Helper' {
        $environment = New-AgentEnvironment -Root (Join-Path $scratch 'portable-agent') -HelperPipe $null
        $agent = Start-NetToolProcess -FilePath (Join-Path $portableRoot 'nettool-agent.exe') -WorkingDirectory $portableRoot -Environment $environment
        $agents.Add($agent)
        Wait-NetToolHealth -Cli (Join-Path $portableRoot 'nettool.exe') -WorkingDirectory $portableRoot -Environment $environment
        $profile = '{"ipv4":{"mode":"dhcp"},"ipv6":{"mode":"automatic"},"dns":{"automatic":true,"servers":[],"search_domains":[]},"routes":[],"mtu":null}'
        $create = Invoke-NetToolCli -FilePath (Join-Path $portableRoot 'nettool.exe') -WorkingDirectory $portableRoot -Arguments @('profile', 'create', 'acceptance', 'Acceptance', $profile, '--output', 'json') -Environment $environment
        if ($create.ExitCode -ne 0) { throw "portable profile create failed: $($create.Stderr)" }
        $export = Invoke-NetToolCli -FilePath (Join-Path $portableRoot 'nettool.exe') -WorkingDirectory $portableRoot -Arguments @('profile', 'export', 'acceptance', '--output', 'json') -Environment $environment
        if ($export.ExitCode -ne 0 -or $export.Stdout -notmatch 'nettool.profile.v1') { throw "portable profile export failed: $($export.Stderr)" }
        $apply = Invoke-NetToolCli -FilePath (Join-Path $portableRoot 'nettool.exe') -WorkingDirectory $portableRoot -Arguments @('profile', 'apply', 'acceptance', '--interface', '__nettool_missing__', '--confirm-timeout', '10', '--output', 'json') -Environment $environment
        if ($apply.ExitCode -eq 0 -or ($apply.Stdout + $apply.Stderr) -notmatch 'HELPER.NOT_CONFIGURED') {
            throw "ordinary portable apply did not fail closed as HELPER.NOT_CONFIGURED: $($apply.Stdout)$($apply.Stderr)"
        }
    }

    Invoke-Check 'desktop MSI installs without privileged Helper' {
        if (Get-Service -Name 'NetToolHelper' -ErrorAction SilentlyContinue) {
            throw 'NetToolHelper is already installed; restore a clean VM snapshot before this test'
        }
        Invoke-Msi -Arguments @('/i', ('"{0}"' -f $desktopMsi), '/qn') -LogPath (Join-Path $diagnostics 'desktop-install.log')
        $desktopInstalled = $true
        $installedRoot = Join-Path ${env:ProgramFiles} 'NetTool'
        Assert-RequiredFiles -Directory $installedRoot -Names @('nettool.exe', 'nettool-desktop.exe', 'nettool-agent.exe', 'nettool-gui.exe', 'nettool-dataplane.exe')
        if (Get-Service -Name 'NetToolHelper' -ErrorAction SilentlyContinue) {
            throw 'desktop MSI unexpectedly registered NetToolHelper'
        }
    }

    Invoke-Check 'installed Agent and GUI sidecars become healthy' {
        $installedRoot = Join-Path ${env:ProgramFiles} 'NetTool'
        $environment = New-AgentEnvironment -Root (Join-Path $scratch 'installed-agent') -HelperPipe $null
        $agent = Start-NetToolProcess -FilePath (Join-Path $installedRoot 'nettool-agent.exe') -WorkingDirectory $installedRoot -Environment $environment
        $agents.Add($agent)
        Wait-NetToolHealth -Cli (Join-Path $installedRoot 'nettool.exe') -WorkingDirectory $installedRoot -Environment $environment
        $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
        $listener.Start()
        $port = ($listener.LocalEndpoint).Port
        $listener.Stop()
        $healthPath = "/health-$([Guid]::NewGuid().ToString('N'))"
        $guiEnvironment = $environment.Clone()
        $guiEnvironment.NETTOOL_GUI_LISTEN = "127.0.0.1:$port"
        $guiEnvironment.NETTOOL_GUI_HEALTH_PATH = $healthPath
        $gui = Start-NetToolProcess -FilePath (Join-Path $installedRoot 'nettool-gui.exe') -WorkingDirectory $installedRoot -Environment $guiEnvironment
        $agents.Add($gui)
        $deadline = [DateTime]::UtcNow.AddSeconds(10)
        do {
            try {
                $health = Invoke-RestMethod -Uri "http://127.0.0.1:$port$healthPath" -TimeoutSec 1
                if ($health.service -eq 'nettool-gui' -and $health.status -eq 'ok') { break }
            } catch { }
            Start-Sleep -Milliseconds 250
        } while ([DateTime]::UtcNow -lt $deadline)
        if ($health.service -ne 'nettool-gui' -or $health.status -ne 'ok') {
            throw 'installed GUI sidecar did not pass its health endpoint'
        }
    }

    Invoke-Check 'Helper MSI registers an SID-bound service' {
        $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        Invoke-Msi -Arguments @('/i', ('"{0}"' -f $helperMsi), ("NETTOOL_ALLOWED_SID=$sid"), '/qn') -LogPath (Join-Path $diagnostics 'helper-install.log')
        $helperInstalled = $true
        $service = Get-Service -Name 'NetToolHelper' -ErrorAction Stop
        if ($service.Status -ne 'Running') { throw "NetToolHelper is not running: $($service.Status)" }
        $marker = Join-Path ${env:ProgramData} 'NetTool\Helper\helper-installed.marker'
        if (-not (Test-Path -LiteralPath $marker -PathType Leaf)) { throw 'Helper installation marker is missing' }
        $configuration = (& sc.exe qc NetToolHelper | Out-String)
        if ($LASTEXITCODE -ne 0 -or $configuration -notmatch [Regex]::Escape($sid)) {
            throw 'NetToolHelper service command line does not contain the expected allowed SID'
        }
    }

    Invoke-Check 'authorized Agent reaches the Helper service without network mutation' {
        $installedRoot = Join-Path ${env:ProgramFiles} 'NetTool'
        $environment = New-AgentEnvironment -Root (Join-Path $scratch 'service-agent') -HelperPipe '\\.\pipe\NetTool.Helper.Service'
        $agent = Start-NetToolProcess -FilePath (Join-Path $installedRoot 'nettool-agent.exe') -WorkingDirectory $installedRoot -Environment $environment
        $agents.Add($agent)
        Wait-NetToolHealth -Cli (Join-Path $installedRoot 'nettool.exe') -WorkingDirectory $installedRoot -Environment $environment
        $profile = '{"ipv4":{"mode":"dhcp"},"ipv6":{"mode":"automatic"},"dns":{"automatic":true,"servers":[],"search_domains":[]},"routes":[],"mtu":null}'
        $create = Invoke-NetToolCli -FilePath (Join-Path $installedRoot 'nettool.exe') -WorkingDirectory $installedRoot -Arguments @('profile', 'create', 'acceptance', 'Acceptance', $profile, '--output', 'json') -Environment $environment
        if ($create.ExitCode -ne 0) { throw "service profile create failed: $($create.Stderr)" }
        $apply = Invoke-NetToolCli -FilePath (Join-Path $installedRoot 'nettool.exe') -WorkingDirectory $installedRoot -Arguments @('profile', 'apply', 'acceptance', '--interface', '__nettool_missing__', '--confirm-timeout', '10', '--output', 'json') -Environment $environment
        $response = $apply.Stdout + $apply.Stderr
        if ($apply.ExitCode -eq 0) {
            throw 'the deliberately nonexistent interface unexpectedly accepted a network change'
        }
        if ($response -match 'HELPER.NOT_CONFIGURED|HELPER.TRANSPORT_FAILED') {
            throw "authorized Agent could not reach the Helper service: $response"
        }
    }

    if ($EnableNetworkMutation) {
        Invoke-Check 'Safe Apply deadline rolls back a dedicated test interface' {
            $adapter = Assert-NotManagementInterface -Alias $TestInterfaceAlias
            $profile = Get-Content -LiteralPath $SafeApplyProfilePath -Raw
            $null = $profile | ConvertFrom-Json
            $installedRoot = Join-Path ${env:ProgramFiles} 'NetTool'
            $environment = New-AgentEnvironment -Root (Join-Path $scratch 'safe-apply-agent') -HelperPipe '\\.\pipe\NetTool.Helper.Service'
            $agent = Start-NetToolProcess -FilePath (Join-Path $installedRoot 'nettool-agent.exe') -WorkingDirectory $installedRoot -Environment $environment
            $agents.Add($agent)
            Wait-NetToolHealth -Cli (Join-Path $installedRoot 'nettool.exe') -WorkingDirectory $installedRoot -Environment $environment
            $create = Invoke-NetToolCli -FilePath (Join-Path $installedRoot 'nettool.exe') -WorkingDirectory $installedRoot -Arguments @('profile', 'create', 'safe-apply', 'Safe Apply', $profile, '--output', 'json') -Environment $environment
            if ($create.ExitCode -ne 0) { throw "Safe Apply profile create failed: $($create.Stderr)" }
            $apply = Invoke-NetToolCli -FilePath (Join-Path $installedRoot 'nettool.exe') -WorkingDirectory $installedRoot -Arguments @('profile', 'apply', 'safe-apply', '--interface', $adapter.Name, '--confirm-timeout', '10', '--output', 'json') -Environment $environment
            if ($apply.ExitCode -ne 0) { throw "Safe Apply did not start: $($apply.Stderr)" }
            $response = $apply.Stdout | ConvertFrom-Json
            $safeApplyOperation = $response.data.operation_id
            if ([string]::IsNullOrWhiteSpace($safeApplyOperation)) { throw 'Safe Apply response did not include operation_id' }
            $safeApplyCli = Join-Path $installedRoot 'nettool.exe'
            $safeApplyWorkingDirectory = $installedRoot
            $safeApplyEnvironment = $environment
            Start-Sleep -Seconds 13
            $auditPath = Join-Path ${env:ProgramData} 'NetTool\Helper\audit.jsonl'
            $audit = Get-Content -LiteralPath $auditPath -Raw
            if ($audit -notmatch [Regex]::Escape($safeApplyOperation) -or $audit -notmatch 'deadline_expired') {
                throw 'Safe Apply deadline rollback is not recorded in Helper audit log'
            }
            $safeApplyOperation = $null
            $safeApplyCli = $null
            $safeApplyWorkingDirectory = $null
            $safeApplyEnvironment = $null
        }
    }

    if ($VerifySignatures) {
        Invoke-Check 'release signatures are valid' {
            $signedFiles = @($desktopMsi, $helperMsi) + @(Get-ChildItem -LiteralPath $portableRoot, $portableUacRoot -Recurse -File -Filter '*.exe' | Select-Object -ExpandProperty FullName)
            foreach ($file in $signedFiles) {
                $signature = Get-AuthenticodeSignature -LiteralPath $file
                if ($signature.Status -ne 'Valid') { throw "invalid Authenticode signature: $file ($($signature.Status))" }
            }
        }
    }
} catch {
    $failure = $_
} finally {
    if ($safeApplyOperation) {
        try {
            $rollback = Invoke-NetToolCli -FilePath $safeApplyCli -WorkingDirectory $safeApplyWorkingDirectory -Arguments @('profile', 'rollback', $safeApplyOperation, '--output', 'json') -Environment $safeApplyEnvironment
            if ($rollback.ExitCode -ne 0) { throw $rollback.Stderr }
            $results.Add([pscustomobject]@{ name = 'Safe Apply emergency cleanup'; status = 'passed'; message = "rolled back $safeApplyOperation" })
        } catch {
            $results.Add([pscustomobject]@{ name = 'Safe Apply emergency cleanup'; status = 'failed'; message = "operation $safeApplyOperation may require manual rollback: $($_.Exception.Message)" })
        }
    }
    foreach ($agent in $agents) { Stop-NetToolProcess -Process $agent }
    if ($helperInstalled) {
        try { Invoke-Msi -Arguments @('/x', ('"{0}"' -f $helperMsi), '/qn') -LogPath (Join-Path $diagnostics 'helper-uninstall.log') } catch { $results.Add([pscustomobject]@{ name = 'Helper MSI uninstall'; status = 'failed'; message = $_.Exception.Message }) }
    }
    if ($desktopInstalled) {
        try { Invoke-Msi -Arguments @('/x', ('"{0}"' -f $desktopMsi), '/qn') -LogPath (Join-Path $diagnostics 'desktop-uninstall.log') } catch { $results.Add([pscustomobject]@{ name = 'Desktop MSI uninstall'; status = 'failed'; message = $_.Exception.Message }) }
    }
    Copy-Item -LiteralPath $diagnostics -Destination (Join-Path $artifactRoot 'nettool-release-acceptance-diagnostics') -Recurse -Force -ErrorAction SilentlyContinue
    $report = [pscustomobject]@{
        schema_version = '1.0'
        generated_at_utc = [DateTime]::UtcNow.ToString('o')
        artifact_directory = $artifactRoot
        network_mutation_enabled = [bool]$EnableNetworkMutation
        results = $results
    }
    $report | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ReportPath -Encoding utf8
    Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
}

if ($failure) { throw $failure }
Write-Output "Release acceptance passed. Report: $ReportPath"

Set-StrictMode -Version 2.0

function Invoke-DFIRExecutionCollection {
<#
.SYNOPSIS
    Collects Windows execution-history artifacts.
.DESCRIPTION
    Event logs roll over, and a re-imaged endpoint retains only weeks of history.
    Prefetch, Amcache, SRUM and the PowerShell console history survive longer and
    are frequently the only record of what ran before the retained log window.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    Write-DFIRLog -Context $Context -Message 'Starting execution-history collection'
    $success = $true

    $success = (Copy-DFIRPrefetch -Context $Context) -and $success
    $success = (Copy-DFIRAmcache -Context $Context) -and $success
    $success = (Copy-DFIRSrum -Context $Context) -and $success
    $success = (Copy-DFIRPowerShellHistory -Context $Context) -and $success
    $success = (Export-DFIRRecentFileCache -Context $Context) -and $success

    Add-DFIRResult -Context $Context -Name 'Execution' -Success $success
    return $success
}

function Copy-DFIRPrefetch {
<#
.SYNOPSIS
    Copies Windows Prefetch files.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    $prefetchRoot = Join-Path $env:SystemRoot 'Prefetch'
    if (-not (Test-Path -LiteralPath $prefetchRoot -PathType Container)) {
        Write-DFIRLog -Context $Context -Level WARN -Message 'Prefetch skipped: directory not found (may be disabled on SSD-backed images)'
        return $true
    }

    $dest = Join-Path $Context.Paths.Execution 'Prefetch'
    try { New-Item -ItemType Directory -Path $dest -Force -ErrorAction Stop | Out-Null }
    catch {
        Write-DFIRLog -Context $Context -Level ERROR -Message ("Prefetch destination create failed: {0}" -f $_.Exception.Message)
        return $false
    }

    $count = 0
    Get-ChildItem -LiteralPath $prefetchRoot -Filter '*.pf' -File -ErrorAction SilentlyContinue |
        ForEach-Object {
            if (Copy-DFIRLockedFile -Context $Context -Source $_.FullName -Destination (Join-Path $dest $_.Name)) { $count++ }
        }

    # An index keeps the run-count and last-run ordering readable without a
    # dedicated Prefetch parser.
    $index = Join-Path $Context.Paths.Execution 'Prefetch_Listing.csv'
    Export-DFIRCsv -Context $Context -Name 'Prefetch listing' -Path $index -ScriptBlock {
        Get-ChildItem -LiteralPath (Join-Path $env:SystemRoot 'Prefetch') -Filter '*.pf' -File -ErrorAction SilentlyContinue |
            Select-Object Name, Length, CreationTimeUtc, LastWriteTimeUtc
    } | Out-Null

    Write-DFIRLog -Context $Context -Message ("Prefetch files collected: {0}" -f $count)
    return $true
}

function Copy-DFIRAmcache {
<#
.SYNOPSIS
    Copies the Amcache hive and its transaction logs.
.DESCRIPTION
    Amcache.hve records executables present on the system with SHA-1 values and
    first-execution evidence, and it survives far longer than the event logs.
    The .LOG1/.LOG2 transaction logs are required for a clean replay.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    $amcacheDir = Join-Path $env:SystemRoot 'AppCompat\Programs'
    if (-not (Test-Path -LiteralPath $amcacheDir -PathType Container)) {
        Write-DFIRLog -Context $Context -Level WARN -Message 'Amcache skipped: AppCompat\Programs not found'
        return $true
    }

    $dest = Join-Path $Context.Paths.Execution 'Amcache'
    try { New-Item -ItemType Directory -Path $dest -Force -ErrorAction Stop | Out-Null }
    catch {
        Write-DFIRLog -Context $Context -Level ERROR -Message ("Amcache destination create failed: {0}" -f $_.Exception.Message)
        return $false
    }

    foreach ($name in @('Amcache.hve', 'Amcache.hve.LOG1', 'Amcache.hve.LOG2', 'RecentFileCache.bcf')) {
        $source = Join-Path $amcacheDir $name
        if (Test-Path -LiteralPath $source -PathType Leaf) {
            Copy-DFIRLockedFile -Context $Context -Source $source -Destination (Join-Path $dest $name) | Out-Null
        }
    }
    return $true
}

function Copy-DFIRSrum {
<#
.SYNOPSIS
    Copies the System Resource Usage Monitor database.
.DESCRIPTION
    SRUDB.dat records per-process network egress by application and user, which
    supports or refutes a data-exfiltration hypothesis when no packet capture or
    proxy log is available.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    $srumDir = Join-Path $env:SystemRoot 'System32\sru'
    if (-not (Test-Path -LiteralPath $srumDir -PathType Container)) {
        Write-DFIRLog -Context $Context -Level WARN -Message 'SRUM skipped: System32\sru not found'
        return $true
    }

    $dest = Join-Path $Context.Paths.Execution 'SRUM'
    try { New-Item -ItemType Directory -Path $dest -Force -ErrorAction Stop | Out-Null }
    catch {
        Write-DFIRLog -Context $Context -Level ERROR -Message ("SRUM destination create failed: {0}" -f $_.Exception.Message)
        return $false
    }

    Get-ChildItem -LiteralPath $srumDir -File -ErrorAction SilentlyContinue |
        ForEach-Object { Copy-DFIRLockedFile -Context $Context -Source $_.FullName -Destination (Join-Path $dest $_.Name) | Out-Null }
    return $true
}

function Copy-DFIRPowerShellHistory {
<#
.SYNOPSIS
    Copies the PSReadLine console history for each target profile.
.DESCRIPTION
    ConsoleHost_history.txt records commands typed interactively, including
    download-and-execute one-liners, and it is not cleared when event logs roll.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    $profiles = if ($Context.ContainsKey('TargetProfiles') -and $Context['TargetProfiles']) {
        @($Context['TargetProfiles'])
    } else {
        @(Resolve-DFIRTargetProfiles -Context $Context)
    }

    $dest = Join-Path $Context.Paths.Execution 'PowerShellHistory'
    try { New-Item -ItemType Directory -Path $dest -Force -ErrorAction Stop | Out-Null }
    catch {
        Write-DFIRLog -Context $Context -Level ERROR -Message ("PowerShell history destination create failed: {0}" -f $_.Exception.Message)
        return $false
    }

    foreach ($profile in $profiles) {
        $historyPath = Join-Path $profile.AppData 'Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
        if (-not (Test-Path -LiteralPath $historyPath -PathType Leaf)) { continue }
        $safeName = ('{0}_ConsoleHost_history.txt' -f (Get-DFIRSafeFileName -Value $profile.UserName))
        Copy-DFIRLockedFile -Context $Context -Source $historyPath -Destination (Join-Path $dest $safeName) | Out-Null
    }
    return $true
}

function Export-DFIRRecentFileCache {
<#
.SYNOPSIS
    Exports the ShimCache (AppCompatCache) registry value for offline parsing.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    $reg = Join-Path $Context.Paths.Execution 'AppCompatCache.reg'
    $txt = Join-Path $Context.Paths.Execution 'AppCompatCache.txt'
    return (Export-DFIRRegistryKey -Context $Context `
        -RegistryPath 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache' `
        -RegExePath $reg -TxtPath $txt)
}

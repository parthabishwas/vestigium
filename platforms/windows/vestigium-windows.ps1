#requires -version 5.1

<#
.SYNOPSIS
    Vestigium Windows Collector - live-response evidence collection for Windows 10/11.
.DESCRIPTION
    Runs modular endpoint evidence collection. The launcher verifies elevation,
    creates a timestamped output tree, starts transcript logging, optionally
    acquires physical memory first (order of volatility), invokes each
    collection step, hashes collected files, writes a manifest, and creates a
    ZIP archive with a sha256sum-compatible sidecar.

    Normally started from the kit root with vestigium.cmd or vestigium.ps1;
    this script can also be run directly.
.PARAMETER TargetUser
    Profiles to collect: user name, DOMAIN\name, SID, or full profile path.
    Comma-separated values are split ("alice,bob"). Default: every profile.
.PARAMETER CaseId
    Case identifier recorded in the manifest, triage summary and log. Default:
    AUTO-<COMPUTERNAME>-<timestamp>.
.PARAMETER OutputPath
    Evidence base folder. Default: <KitRoot>\output.
.PARAMETER Modules
    Subset of steps to run (case-insensitive, comma-separated accepted). See -ListModules.
.PARAMETER ListModules
    Print the step names and exit 0.
.PARAMETER CaptureMemory
    Acquire physical memory with Tools\winpmem_mini_x64*.exe before any other step.
.PARAMETER NoArchive
    Leave the evidence tree uncompressed.
.PARAMETER SkipYara
    Do not run YARA.
.PARAMETER YaraQuickScan
    Scan only Downloads, Desktop and Temp of each target profile.
.PARAMETER YaraThreads
    YARA scanning threads, 1-8 (default 8).
.PARAMETER YaraTimeoutSeconds
    Wall-clock limit per YARA target folder (default 1800). Each file also has a 120 s limit.
.PARAMETER BrowserCredentialStores
    Copy (default, v1.1 behaviour) or MetadataOnly (record size, timestamps and
    SHA256 of password/cookie/token stores instead of copying them).
.PARAMETER Version
    Print the kit version and exit 0.
.EXAMPLE
    .\vestigium.cmd -CaseId IR-2026-014 -TargetUser alice
.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\platforms\windows\vestigium-windows.ps1 -CaseId IR-2026-014 -TargetUser "alice,CORP\bob" -BrowserCredentialStores MetadataOnly
.EXAMPLE
    .\vestigium.ps1 -CaptureMemory -OutputPath E:\Evidence -YaraQuickScan
.EXAMPLE
    .\platforms\windows\vestigium-windows.ps1 -Modules System,Registry,Execution -SkipYara -NoArchive
.NOTES
    Exit codes: 0 success; 1 a step failed or the session is not elevated; 2 usage error.
#>

[CmdletBinding()]
param(
    [string[]]$TargetUser = @(),
    [switch]$SkipYara,
    [switch]$YaraQuickScan,
    [int]$YaraThreads = 8,
    [int]$YaraTimeoutSeconds = 1800,
    [string]$CaseId = '',
    [string]$OutputPath = '',
    [string[]]$Modules = @(),
    [switch]$ListModules,
    [switch]$NoArchive,
    [switch]$Version,
    [switch]$CaptureMemory,
    [string]$BrowserCredentialStores = 'Copy'
)

$script:VestigiumScriptRoot = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($script:VestigiumScriptRoot) -and -not [string]::IsNullOrWhiteSpace($PSCommandPath)) {
    $script:VestigiumScriptRoot = Split-Path -Parent $PSCommandPath
}
if ([string]::IsNullOrWhiteSpace($script:VestigiumScriptRoot)) {
    $script:VestigiumScriptRoot = (Get-Location).Path
}
$script:VestigiumBoundParameters = @{}
foreach ($key in $PSBoundParameters.Keys) { $script:VestigiumBoundParameters[$key] = $PSBoundParameters[$key] }

# Order matters: Memory runs first (order of volatility), Triage last.
$script:VestigiumStepNames = @('Memory','System','Processes','Registry','Startup','Autoruns','Services','Network','Browser','EventLogs','Defender','Execution','Devices','Forensics','YARA','Triage')

function Get-DFIRKitRoot {
<#
.SYNOPSIS
    Resolves the Vestigium kit root.
.DESCRIPTION
    $env:VESTIGIUM_HOME when set; else the grandparent of the script folder when
    it holds VERSION and platforms\windows; else the script folder (standalone).
.OUTPUTS
    System.String
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$ScriptRoot,
        [AllowEmptyString()][string]$EnvHome = $env:VESTIGIUM_HOME
    )

    if (-not [string]::IsNullOrWhiteSpace($EnvHome)) {
        if (Test-Path -LiteralPath $EnvHome -PathType Container) {
            return (Resolve-Path -LiteralPath $EnvHome).ProviderPath
        }
        Write-Warning ("VESTIGIUM_HOME does not exist and is ignored: {0}" -f $EnvHome)
    }
    $platforms = Split-Path -Parent $ScriptRoot
    if ($platforms) {
        $grand = Split-Path -Parent $platforms
        if ($grand -and (Test-Path -LiteralPath (Join-Path $grand 'VERSION') -PathType Leaf) -and
            (Test-Path -LiteralPath (Join-Path (Join-Path $grand 'platforms') 'windows') -PathType Container)) {
            return $grand
        }
    }
    return $ScriptRoot
}

function Get-DFIRKitVersion {
<#
.SYNOPSIS
    Reads the first line of <KitRoot>\VERSION (fallback 2.0.0).
.OUTPUTS
    System.String
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$KitRoot)

    $file = Join-Path $KitRoot 'VERSION'
    try {
        if (Test-Path -LiteralPath $file -PathType Leaf) {
            $first = @(Get-Content -LiteralPath $file -TotalCount 1 -ErrorAction Stop)
            if ($first.Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($first[0])) { return $first[0].Trim() }
        }
    }
    catch { }
    return '2.0.0'
}

function Split-DFIRListArgument {
<#
.SYNOPSIS
    Splits comma-separated entries (powershell.exe -File passes arrays as one string).
.OUTPUTS
    System.String[]
#>
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyCollection()][string[]]$Value)

    $out = New-Object System.Collections.ArrayList
    foreach ($item in @($Value)) {
        if ($null -eq $item) { continue }
        foreach ($part in ($item -split ',')) {
            $trimmed = $part.Trim().Trim('"').Trim("'").Trim()
            if (-not [string]::IsNullOrWhiteSpace($trimmed)) { [void]$out.Add($trimmed) }
        }
    }
    return ,([string[]]$out.ToArray())
}

function Select-DFIRSteps {
<#
.SYNOPSIS
    Maps requested step names (case-insensitive) onto canonical step names.
.OUTPUTS
    PSCustomObject with Selected (canonical names in run order) and Unknown.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string[]]$AllNames,
        [AllowEmptyCollection()][string[]]$Requested = @()
    )

    $wanted = @{}
    $unknown = New-Object System.Collections.ArrayList
    foreach ($name in (Split-DFIRListArgument -Value $Requested)) {
        $match = $null
        foreach ($candidate in $AllNames) {
            if ([string]::Equals($candidate, $name, [System.StringComparison]::OrdinalIgnoreCase)) { $match = $candidate }
        }
        if ($match) { $wanted[$match] = $true } else { [void]$unknown.Add($name) }
    }
    $selected = @($AllNames | Where-Object { $wanted.ContainsKey($_) })
    return [pscustomobject]@{ Selected = [string[]]$selected; Unknown = [string[]]$unknown.ToArray() }
}

function Get-DFIRInvocationRecord {
<#
.SYNOPSIS
    Converts bound parameters into a JSON-friendly ordered dictionary.
.OUTPUTS
    System.Collections.Specialized.OrderedDictionary
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Bound)

    $record = [ordered]@{}
    foreach ($key in ($Bound.Keys | Sort-Object)) {
        $value = $Bound[$key]
        if ($value -is [System.Management.Automation.SwitchParameter]) { $record[$key] = [bool]$value.IsPresent }
        elseif ($value -is [array]) { $record[$key] = @($value | ForEach-Object { [string]$_ }) }
        elseif ($null -eq $value) { $record[$key] = $null }
        else { $record[$key] = [string]$value }
    }
    return $record
}

function Get-DFIRModulePaths {
<#
.SYNOPSIS
    Gets all required collector module paths in dependency order.
.OUTPUTS
    System.String[]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$RootPath)

    $moduleNames = @(
        'Utilities.ps1',
        'System.ps1',
        'Memory.ps1',
        'Yara.ps1',
        'Registry.ps1',
        'Processes.ps1',
        'Services.ps1',
        'Startup.ps1',
        'Autoruns.ps1',
        'Network.ps1',
        'Browser.ps1',
        'EventLogs.ps1',
        'Defender.ps1',
        'Execution.ps1',
        'Devices.ps1',
        'Triage.ps1',
        'Forensics.ps1',
        'Findings.ps1'
    )

    foreach ($moduleName in $moduleNames) {
        $path = Join-Path (Join-Path $RootPath 'Modules') $moduleName
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw ("Required module missing: {0}" -f $path)
        }
        $path
    }
}

function Invoke-DFIRCollectionStep {
<#
.SYNOPSIS
    Invokes one collection step with progress, logging, and failure isolation.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][hashtable]$Context,
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][scriptblock]$ScriptBlock,
        [Parameter(Mandatory=$true)][int]$Index,
        [Parameter(Mandatory=$true)][int]$Total
    )

    $percent = [int](($Index / $Total) * 100)
    Write-Progress -Activity 'Vestigium Windows Collector' -Status $Name -PercentComplete $percent
    Write-DFIRLog -Context $Context -Message ("Step started: {0}" -f $Name)
    try {
        $result = & $ScriptBlock
        if ($result) {
            Write-DFIRLog -Context $Context -Level SUCCESS -Message ("Step completed: {0}" -f $Name)
            return $true
        }
        Write-DFIRLog -Context $Context -Level WARN -Message ("Step completed with warnings or partial failures: {0}" -f $Name)
        return $false
    }
    catch {
        Write-DFIRLog -Context $Context -Level ERROR -Message ("Unhandled step failure: {0}: {1}" -f $Name, $_.Exception.Message)
        Add-DFIRResult -Context $Context -Name $Name -Success $false -Message $_.Exception.Message
        return $false
    }
}

function Start-DFIRCollector {
<#
.SYNOPSIS
    Main Vestigium Windows collection routine (modules already loaded, arguments validated).
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$KitRoot,
        [Parameter(Mandatory=$true)][string]$KitVersion,
        [Parameter(Mandatory=$true)][string[]]$SelectedSteps,
        [AllowEmptyCollection()][string[]]$TargetUsers = @(),
        [Parameter(Mandatory=$true)][string]$CredentialPolicy,
        [bool]$MemoryRequested = $false
    )

    $scriptRoot = $script:VestigiumScriptRoot
    $context = $null
    $transcriptStarted = $false
    try {
        $context = Initialize-DFIRContext -ScriptRoot $scriptRoot -KitRoot $KitRoot -OutputBase $OutputPath -CollectorVersion $KitVersion -CaseId $CaseId
        $context['Invocation'] = Get-DFIRInvocationRecord -Bound $script:VestigiumBoundParameters
        $context['SelectedModules'] = @($SelectedSteps)
        $context['TargetUsers'] = @($TargetUsers)
        $context['TargetProfiles'] = @(Resolve-DFIRTargetProfiles -Context $context -TargetUsers @($TargetUsers))
        $context['SkipYara'] = [bool]$SkipYara
        $context['YaraQuickScan'] = [bool]$YaraQuickScan
        $context['YaraThreads'] = $YaraThreads
        $context['YaraTimeoutSeconds'] = $YaraTimeoutSeconds
        $context['CaptureMemory'] = $MemoryRequested
        $context['BrowserCredentialStores'] = $CredentialPolicy
        $transcriptPath = Join-Path $context.Paths.Logs 'Transcript.txt'
        try {
            Start-Transcript -Path $transcriptPath -Append -ErrorAction Stop | Out-Null
            $transcriptStarted = $true
            Add-DFIRCollectedFile -Context $context -Path $transcriptPath
        }
        catch {
            Write-DFIRLog -Context $context -Level WARN -Message ("Transcript could not be started: {0}" -f $_.Exception.Message)
        }

        Write-DFIRLog -Context $context -Message ("Vestigium Windows Collector {0} started. OutputRoot={1}" -f $KitVersion, $context.OutputRoot)
        Write-DFIRLog -Context $context -Message ("Case: {0} [{1}] Operator={2} KitRoot={3}" -f $context.CaseId, $context.CaseIdSource, $context.Operator, $KitRoot)
        Write-DFIRLog -Context $context -Message ("Invocation: {0}" -f (($context['Invocation'] | ConvertTo-Json -Compress -Depth 3)))
        Write-DFIRLog -Context $context -Message ("Steps: {0}; BrowserCredentialStores={1}" -f ($SelectedSteps -join ','), $CredentialPolicy)
        foreach ($profile in $context['TargetProfiles']) {
            Write-DFIRLog -Context $context -Message ("Target profile: UserName={0} SID={1} ProfilePath={2}" -f $profile.UserName, $profile.SID, $profile.ProfilePath)
        }
        Write-Host ("Vestigium Windows Collector {0} - case {1}" -f $KitVersion, $context.CaseId)

        $stepScripts = @{
            Memory    = { Invoke-DFIRMemoryCollection -Context $context }
            System    = { Invoke-DFIRSystemCollection -Context $context }
            Processes = { Invoke-DFIRProcessCollection -Context $context }
            Registry  = { Invoke-DFIRRegistryCollection -Context $context }
            Startup   = { Invoke-DFIRStartupCollection -Context $context }
            Autoruns  = { Invoke-DFIRAutorunsCollection -Context $context }
            Services  = { Invoke-DFIRServiceCollection -Context $context }
            Network   = { Invoke-DFIRNetworkCollection -Context $context }
            Browser   = { Invoke-DFIRBrowserCollection -Context $context }
            EventLogs = { Invoke-DFIREventLogCollection -Context $context }
            Defender  = { Invoke-DFIRDefenderCollection -Context $context }
            Execution = { Invoke-DFIRExecutionCollection -Context $context }
            Devices   = { Invoke-DFIRDeviceCollection -Context $context }
            Forensics = { Invoke-DFIRForensicsCollection -Context $context }
            YARA      = { Invoke-DFIRYaraCollection -Context $context }
            Triage    = { Invoke-DFIRTriageSummary -Context $context }
        }

        $overall = $true
        for ($i = 0; $i -lt $SelectedSteps.Count; $i++) {
            $name = $SelectedSteps[$i]
            $ok = Invoke-DFIRCollectionStep -Context $context -Name $name -ScriptBlock $stepScripts[$name] -Index ($i + 1) -Total $SelectedSteps.Count
            $overall = $ok -and $overall
        }

        Write-DFIRLog -Context $context -Message 'Finalizing collection metadata'
        if ($transcriptStarted) {
            try { Stop-Transcript | Out-Null } catch { }
            $transcriptStarted = $false
        }

        if ($overall) { $context['Status'] = 'Completed' } else { $context['Status'] = 'CompletedWithErrors' }

        # Cross-platform findings report, written to the evidence-tree root before
        # hashing so findings.json and findings.html are covered by SHA256.csv. A
        # findings problem is logged but does not fail the collection.
        Invoke-DFIRFindingsReport -Context $context | Out-Null

        $overall = (New-DFIRHashes -Context $context) -and $overall
        $overall = (New-DFIRManifest -Context $context) -and $overall

        $duration = (Get-Date) - $context.StartTime
        Write-DFIRLog -Context $context -Level SUCCESS -Message ("Collection finished. Status={0} Duration={1:n2}s Files={2}" -f $context['Status'], $duration.TotalSeconds, ((Get-ChildItem -LiteralPath $context.OutputRoot -File -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object).Count))

        if ($NoArchive) {
            Write-DFIRLog -Context $context -Message 'Archive skipped by -NoArchive'
        }
        else {
            $overall = (Compress-DFIROutput -Context $context) -and $overall
        }
        Write-Progress -Activity 'Vestigium Windows Collector' -Completed
        Write-Host ("Collection complete: {0}" -f $context.OutputRoot)
        $findingsHtml = Join-Path $context.OutputRoot 'findings.html'
        if (Test-Path -LiteralPath $findingsHtml -PathType Leaf) {
            Write-Host ("Findings report: {0}" -f $findingsHtml)
        }
        if ($context.ContainsKey('ZipPath')) {
            Write-Host ("Archive: {0}" -f $context['ZipPath'])
            Write-Host ("Archive SHA256: {0}.sha256" -f $context['ZipPath'])
        }
        if ($context.ContainsKey('MemoryImagePath') -and $context['MemoryImagePath']) {
            Write-Host ("Memory image (not in archive): {0}" -f $context['MemoryImagePath'])
        }
        if (-not $overall) {
            Write-Host ("One or more steps failed or were partial; see {0}" -f $context.LogFile)
        }
        return $overall
    }
    catch {
        if ($context) {
            Write-DFIRLog -Context $context -Level ERROR -Message ("Fatal launcher failure: {0}" -f $_.Exception.Message)
        }
        Write-Error $_.Exception.Message
        return $false
    }
    finally {
        if ($transcriptStarted) {
            try { Stop-Transcript | Out-Null } catch { }
        }
    }
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
$kitRoot = Get-DFIRKitRoot -ScriptRoot $script:VestigiumScriptRoot
$kitVersion = Get-DFIRKitVersion -KitRoot $kitRoot

if ($Version) {
    Write-Output ("Vestigium Windows Collector {0}" -f $kitVersion)
    exit 0
}
if ($ListModules) {
    foreach ($stepName in $script:VestigiumStepNames) { Write-Output $stepName }
    exit 0
}

$usageErrors = New-Object System.Collections.ArrayList
if ($YaraThreads -lt 1 -or $YaraThreads -gt 8) { [void]$usageErrors.Add(("-YaraThreads must be between 1 and 8 (got {0})" -f $YaraThreads)) }
if ($YaraTimeoutSeconds -lt 1) { [void]$usageErrors.Add(("-YaraTimeoutSeconds must be a positive number of seconds (got {0})" -f $YaraTimeoutSeconds)) }
$credentialPolicy = $null
foreach ($allowed in @('Copy','MetadataOnly')) {
    if ([string]::Equals($allowed, $BrowserCredentialStores.Trim(), [System.StringComparison]::OrdinalIgnoreCase)) { $credentialPolicy = $allowed }
}
if (-not $credentialPolicy) { [void]$usageErrors.Add(("-BrowserCredentialStores must be Copy or MetadataOnly (got '{0}')" -f $BrowserCredentialStores)) }
if (-not [string]::IsNullOrWhiteSpace($OutputPath) -and (Test-Path -LiteralPath $OutputPath -PathType Leaf)) {
    [void]$usageErrors.Add(("-OutputPath points to a file, not a folder: {0}" -f $OutputPath))
}

$memoryRequested = [bool]$CaptureMemory
$requestedModules = Split-DFIRListArgument -Value $Modules
if ($requestedModules.Count -gt 0) {
    $selection = Select-DFIRSteps -AllNames $script:VestigiumStepNames -Requested $requestedModules
    foreach ($unknownName in $selection.Unknown) {
        Write-Warning ("Unknown module ignored: {0} (valid: {1})" -f $unknownName, ($script:VestigiumStepNames -join ', '))
    }
    if ($selection.Selected.Count -eq 0) {
        [void]$usageErrors.Add('-Modules did not name any valid step; run with -ListModules')
    }
    $selectedSteps = @($selection.Selected)
    # Naming Memory in -Modules requests capture; -CaptureMemory adds it.
    if ($selectedSteps -contains 'Memory') { $memoryRequested = $true }
}
else {
    $selectedSteps = @($script:VestigiumStepNames | Where-Object { $_ -ne 'Memory' })
}
if ($memoryRequested -and -not ($selectedSteps -contains 'Memory')) { $selectedSteps = @('Memory') + $selectedSteps }

if ($usageErrors.Count -gt 0) {
    foreach ($usageError in $usageErrors) { [Console]::Error.WriteLine(("Usage error: {0}" -f $usageError)) }
    [Console]::Error.WriteLine('Run Get-Help .\vestigium-windows.ps1 -Detailed for usage.')
    exit 2
}

try {
    foreach ($modulePath in (Get-DFIRModulePaths -RootPath $script:VestigiumScriptRoot)) {
        . $modulePath
    }
}
catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}

if (-not (Test-DFIRAdministrator)) {
    Write-Host 'This tool requires Administrator privileges.'
    exit 1
}

$vestigiumSuccess = Start-DFIRCollector -KitRoot $kitRoot -KitVersion $kitVersion -SelectedSteps $selectedSteps -TargetUsers (Split-DFIRListArgument -Value $TargetUser) -CredentialPolicy $credentialPolicy -MemoryRequested $memoryRequested
if ($vestigiumSuccess) { exit 0 }
exit 1

#requires -version 5.1

<#
.SYNOPSIS
    Vestigium entry point for PowerShell. Detects the operating system and
    runs the matching live-response collector.
.DESCRIPTION
    Vestigium is a cross-platform live-response evidence collector.

      Windows (Windows PowerShell 5.1 or PowerShell 7)
          platforms\windows\vestigium-windows.ps1, in this session
      Linux (PowerShell 7)
          platforms/linux/vestigium-linux.sh through bash, via sudo when the
          session is not root

    Commands: collect (default), verify, setup, info, version, help.
    Common options have the same names on every platform and are translated
    for the selected collector. GNU-style options (--case-id) work as well.
    Other collector parameters are passed through by name.
.PARAMETER Command
    collect | verify | setup | info | version | help. Default: collect.
.PARAMETER Path
    verify: the evidence folder or archive to check (may also be given as the
    word after 'verify').
.PARAMETER Platform
    Auto (default), Windows or Linux.
.PARAMETER DryRun
    Print the resolved collector invocation without running it.
.PARAMETER Elevate
    Windows: when the session is not elevated, relaunch in an elevated window.
    The elevated window keeps its own exit code; relative -OutputPath values
    are made absolute first.
.EXAMPLE
    .\vestigium.cmd -CaseId IR-2026-014
.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\vestigium.ps1 -CaseId IR-2026-014 -TargetUser john.doe -OutputPath E:\Evidence
.EXAMPLE
    .\vestigium.ps1 verify .\output\WS01_20260911_101500.zip
.EXAMPLE
    .\vestigium.ps1 -ListModules
#>
[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter(Position = 0)][string]$Command = 'collect',
    [string]$Path,
    [string]$CaseId,
    [string[]]$TargetUser,
    [string]$OutputPath,
    [string[]]$Modules,
    [switch]$ListModules,
    [switch]$Quick,
    [switch]$SkipYara,
    [switch]$YaraQuickScan,
    [ValidateRange(1, 64)][int]$YaraThreads,
    [ValidateRange(1, 604800)][int]$YaraTimeoutSeconds,
    [switch]$CaptureMemory,
    [switch]$NoArchive,
    [ValidateSet('Copy', 'MetadataOnly')][string]$BrowserCredentialStores,
    [ValidateSet('Auto', 'Windows', 'Linux')][string]$Platform = 'Auto',
    [switch]$DryRun,
    [switch]$Elevate,
    [switch]$Version,
    # [object[]]: an in-process call such as `--target-user alice,bob` passes an array.
    [Parameter(ValueFromRemainingArguments = $true)][object[]]$PassThru
)

Set-StrictMode -Version 2.0

$KitRoot = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($KitRoot)) { $KitRoot = Split-Path -Parent $MyInvocation.MyCommand.Path }
$env:VESTIGIUM_HOME = $KitRoot

$CTVersion = 'unknown'
$versionFile = Join-Path $KitRoot 'VERSION'
if (Test-Path -LiteralPath $versionFile -PathType Leaf) {
    $CTVersion = ([string](Get-Content -LiteralPath $versionFile -TotalCount 1)).Trim()
}

$paths = @{
    WindowsCollector = Join-Path (Join-Path (Join-Path $KitRoot 'platforms') 'windows') 'vestigium-windows.ps1'
    WindowsSetup     = Join-Path (Join-Path (Join-Path (Join-Path $KitRoot 'platforms') 'windows') 'Tools') 'Update-YaraRules.ps1'
    LinuxCollector   = Join-Path (Join-Path (Join-Path $KitRoot 'platforms') 'linux') 'vestigium-linux.sh'
    LinuxSetup       = Join-Path (Join-Path (Join-Path (Join-Path $KitRoot 'platforms') 'linux') 'tools') 'setup-tools.sh'
    Verifier         = Join-Path (Join-Path $KitRoot 'shared') 'Verify-Evidence.ps1'
    Rules            = Join-Path (Join-Path $KitRoot 'shared') 'yara-rules'
}

# $IsWindows/$IsLinux only exist in PowerShell 6+; Windows PowerShell is Desktop edition.
$onWindows = ($PSVersionTable.PSEdition -eq 'Desktop') -or ((Test-Path variable:IsWindows) -and $IsWindows)
$onLinux = (Test-Path variable:IsLinux) -and $IsLinux
$onMac = (Test-Path variable:IsMacOS) -and $IsMacOS

function Exit-CTUsage {
    param([string]$Message)
    Write-Host ('vestigium: {0}' -f $Message) -ForegroundColor Red
    Write-Host 'Run .\vestigium.ps1 help for usage.'
    exit 2
}

function Format-CTArgument {
<#
.SYNOPSIS
    Quotes one argument for a Windows command line (CommandLineToArgvW rules).
#>
    param([AllowEmptyString()][string]$Value)

    if ($Value -eq '') { return '""' }
    if ($Value -notmatch '[\s"]') { return $Value }
    $escaped = [regex]::Replace($Value, '(\\*)"', [System.Text.RegularExpressions.MatchEvaluator]{
        param($m) ($m.Groups[1].Value * 2) + '\"' })
    $escaped = [regex]::Replace($escaped, '(\\+)$', [System.Text.RegularExpressions.MatchEvaluator]{
        param($m) $m.Groups[1].Value * 2 })
    return '"' + $escaped + '"'
}

function Format-CTPosixArgument {
    # Display quoting for a POSIX shell command line.
    param([AllowEmptyString()][string]$Value)
    if ($Value -match '^[A-Za-z0-9_./:=,@%+-]+$') { return $Value }
    return "'" + $Value.Replace("'", "'\''") + "'"
}

function Format-CTPowerShellArgument {
    # Display quoting for a PowerShell command line.
    param([AllowEmptyString()][string]$Value)
    if ($Value -match '^[A-Za-z0-9_./:\\,@%+-]+$') { return $Value }
    return "'" + $Value.Replace("'", "''") + "'"
}

function Show-CTUsage {
    @"
Vestigium $CTVersion - cross-platform live-response evidence collector

Usage: .\vestigium.ps1 [command] [options]      (or vestigium.cmd from cmd.exe)

Commands
  collect            Run a live-response collection (default)
  verify PACKAGE     Verify an evidence folder, a Windows .zip or a Linux .tar.zst/.tar.gz
  setup [options]    Prepare the toolkit (Windows: build the shared YARA rule bundle)
  info               Show the detected platform and toolkit readiness
  version            Print the version
  help               This help

Launcher options
  -Platform Auto|Windows|Linux     Override detection
  -DryRun                          Show the collector invocation without running it
  -Elevate                         Windows: relaunch elevated when needed

Common collection options (same names on every platform)
  -CaseId ID                       Case reference for the manifest
  -TargetUser USER[,USER]          Limit user-scoped artifacts
  -OutputPath DIR                  Evidence base directory (default .\output)
  -Modules A,B / -ListModules      Run or list a subset of modules
  -Quick                           Fast triage
  -SkipYara / -YaraQuickScan       Disable YARA / scan high-signal paths only
  -YaraThreads N / -YaraTimeoutSeconds SEC
  -CaptureMemory                   Acquire physical memory first
  -NoArchive                       Leave the evidence folder uncompressed
  -BrowserCredentialStores Copy|MetadataOnly    Browser credential stores (default Copy)
  -Verbose                         Verbose progress output

Other collector parameters are passed through by name. Collector help:
  Get-Help .\platforms\windows\vestigium-windows.ps1 -Detailed

Examples
  .\vestigium.cmd -CaseId IR-2026-014 -TargetUser john.doe -OutputPath E:\Evidence
  .\vestigium.ps1 verify .\output\WS01_20260911_101500.zip
"@ | Write-Host
}

# ---------------------------------------------------------------------------
# Normalise the command and fold GNU-style options into named options
# ---------------------------------------------------------------------------
$extra = New-Object System.Collections.Generic.List[string]
if ($Command -like '-*') {
    # Positional binding picked up an option such as --case-id.
    $extra.Add($Command)
    $Command = 'collect'
}
if ($PassThru) {
    foreach ($item in $PassThru) {
        if ($item -is [System.Array]) { $extra.Add((@($item) -join ',')) }
        else { $extra.Add([string]$item) }
    }
}
$Command = $Command.ToLowerInvariant()
if ($Version) { $Command = 'version' }
if (@('collect', 'verify', 'setup', 'info', 'version', 'help') -notcontains $Command) {
    Exit-CTUsage ("unknown command '{0}'" -f $Command)
}

$optionNames = @('CaseId', 'TargetUser', 'OutputPath', 'Modules', 'ListModules', 'Quick', 'SkipYara',
    'YaraQuickScan', 'YaraThreads', 'YaraTimeoutSeconds', 'CaptureMemory', 'NoArchive', 'BrowserCredentialStores')
$switchNames = @('ListModules', 'Quick', 'SkipYara', 'YaraQuickScan', 'CaptureMemory', 'NoArchive', 'Verbose')
$gnuNames = @{
    '--case-id' = 'CaseId'; '--target-user' = 'TargetUser'; '--output' = 'OutputPath'; '--modules' = 'Modules'
    '--list-modules' = 'ListModules'; '--quick' = 'Quick'; '--skip-yara' = 'SkipYara'; '--yara-quick' = 'YaraQuickScan'
    '--yara-threads' = 'YaraThreads'; '--yara-timeout' = 'YaraTimeoutSeconds'; '--memory' = 'CaptureMemory'
    '--no-archive' = 'NoArchive'; '--credential-stores' = 'BrowserCredentialStores'; '--verbose' = 'Verbose'; '-v' = 'Verbose'
}

$opts = [ordered]@{}
foreach ($name in $optionNames) {
    if ($PSBoundParameters.ContainsKey($name)) { $opts[$name] = $PSBoundParameters[$name] }
}
if ($PSBoundParameters.ContainsKey('Verbose')) { $opts['Verbose'] = [bool]$PSBoundParameters['Verbose'] }

$rest = New-Object System.Collections.Generic.List[string]
for ($i = 0; $i -lt $extra.Count; $i++) {
    $item = $extra[$i]
    $key = $item
    $inline = $null
    if ($item -match '^(--[a-z0-9-]+)=(.*)$') { $key = $Matches[1]; $inline = $Matches[2] }
    if (-not $gnuNames.ContainsKey($key)) { $rest.Add($item); continue }

    $name = $gnuNames[$key]
    if ($switchNames -contains $name) { $opts[$name] = $true; continue }
    $value = $inline
    if ($null -eq $value) {
        if ($i + 1 -ge $extra.Count) { Exit-CTUsage ("{0} needs a value" -f $key) }
        $i++
        $value = $extra[$i]
    }
    if ($null -eq $inline -and ($name -eq 'TargetUser' -or $name -eq 'Modules')) {
        # In-process calls unroll `--target-user alice,bob` into separate words.
        while ($i + 1 -lt $extra.Count -and $extra[$i + 1] -notlike '-*') {
            $i++
            $value = $value + ',' + $extra[$i]
        }
    }
    switch ($name) {
        'TargetUser' { $opts['TargetUser'] = @($(if ($opts.Contains('TargetUser')) { $opts['TargetUser'] }) + ($value -split ',')) }
        'Modules'    { $opts['Modules'] = @($(if ($opts.Contains('Modules')) { $opts['Modules'] }) + ($value -split ',')) }
        'BrowserCredentialStores' {
            if ($value -match '^(?i)copy$') { $opts[$name] = 'Copy' }
            elseif ($value -match '^(?i)metadata(only)?$') { $opts[$name] = 'MetadataOnly' }
            else { Exit-CTUsage "--credential-stores takes copy or metadata" }
        }
        default { $opts[$name] = $value }
    }
}

# ---------------------------------------------------------------------------
# Platform selection
# ---------------------------------------------------------------------------
$target = $Platform
if ($target -eq 'Auto') {
    if ($onWindows) { $target = 'Windows' }
    elseif ($onLinux) { $target = 'Linux' }
    elseif ($onMac) { $target = 'macOS' }
    else { $target = 'Unsupported' }
}

function Assert-CTTarget {
    if ($target -eq 'Windows' -and -not $onWindows -and -not $DryRun) {
        Write-Host 'vestigium: the Windows collector must run on Windows.' -ForegroundColor Red; exit 3
    }
    if ($target -eq 'Linux' -and -not $onLinux -and -not $DryRun) {
        Write-Host 'vestigium: the Linux collector must run on Linux.' -ForegroundColor Red; exit 3
    }
    if ($target -eq 'macOS' -or $target -eq 'Unsupported') {
        Write-Host ("vestigium: {0} is not supported yet. Supported: Windows 10/11 and Linux (Debian/Ubuntu family). 'verify' works everywhere." -f $target) -ForegroundColor Red
        exit 3
    }
}

function Test-CTAdministrator {
    try {
        $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch { return $false }
}

function Test-CTRoot {
    try { return ((& id -u) -eq '0') } catch { return $false }
}

function Add-CTNamedPassThru {
<#
.SYNOPSIS
    Binds -Name [value] pairs from the pass-through list against a script's own parameters.
#>
    param([hashtable]$Splat, [string]$ScriptPath, [System.Collections.Generic.List[string]]$Items)

    $parameters = (Get-Command -Name $ScriptPath -ErrorAction Stop).Parameters
    for ($i = 0; $i -lt $Items.Count; $i++) {
        $item = $Items[$i]
        if ($item -notmatch '^-([A-Za-z][A-Za-z0-9]*)(:(.*))?$') {
            Exit-CTUsage ("unexpected argument '{0}'" -f $item)
        }
        $name = $Matches[1]
        $inline = $Matches[3]
        $meta = $null
        foreach ($key in $parameters.Keys) { if ($key -eq $name) { $meta = $parameters[$key]; $name = $key } }
        if (-not $meta) { Exit-CTUsage ("unknown parameter -{0} for {1}" -f $name, (Split-Path -Leaf $ScriptPath)) }
        if ($meta.SwitchParameter) {
            $Splat[$name] = ($null -eq $inline -or $inline -notmatch '^(?i)\$?false$')
            continue
        }
        if ($null -eq $inline) {
            if ($i + 1 -ge $Items.Count) { Exit-CTUsage ("-{0} needs a value" -f $name) }
            $i++
            $inline = $Items[$i]
        }
        $Splat[$name] = $inline
    }
}

function Test-CTSwitchValue {
    param($Value)
    return ($Value -is [bool] -or $Value -is [System.Management.Automation.SwitchParameter])
}

function Show-CTPowerShellDryRun {
    param([string]$ScriptPath, [hashtable]$Splat)
    $parts = New-Object System.Collections.Generic.List[string]
    $parts.Add('&')
    $parts.Add((Format-CTPowerShellArgument $ScriptPath))
    foreach ($key in ($Splat.Keys | Sort-Object)) {
        $value = $Splat[$key]
        if (Test-CTSwitchValue $value) {
            if ($value) { $parts.Add('-' + $key) }
        }
        else {
            $parts.Add('-' + $key)
            $parts.Add((Format-CTPowerShellArgument (@($value) -join ',')))
        }
    }
    Write-Host ('vestigium: would run: {0}' -f ($parts -join ' '))
    exit 0
}

function Get-CTLinuxArguments {
    $argv = New-Object System.Collections.Generic.List[string]
    foreach ($name in $opts.Keys) {
        $value = $opts[$name]
        switch ($name) {
            'CaseId'             { $argv.Add('--case-id'); $argv.Add([string]$value) }
            'TargetUser'         { foreach ($u in (@($value) -split ',')) { if ($u) { $argv.Add('--target-user'); $argv.Add($u) } } }
            'OutputPath'         { $argv.Add('--output'); $argv.Add([string]$value) }
            'Modules'            { $argv.Add('--modules'); $argv.Add((@($value) -join ',')) }
            'ListModules'        { if ($value) { $argv.Add('--list-modules') } }
            'Quick'              { if ($value) { $argv.Add('--quick') } }
            'SkipYara'           { if ($value) { $argv.Add('--skip-yara') } }
            'YaraQuickScan'      { if ($value) { $argv.Add('--yara-quick') } }
            'YaraThreads'        { $argv.Add('--yara-threads'); $argv.Add([string]$value) }
            'YaraTimeoutSeconds' { $argv.Add('--yara-timeout'); $argv.Add([string]$value) }
            'CaptureMemory'      { if ($value) { $argv.Add('--memory') } }
            'NoArchive'          { if ($value) { $argv.Add('--no-archive') } }
            'Verbose'            { if ($value) { $argv.Add('--verbose') } }
            'BrowserCredentialStores' {
                $argv.Add('--credential-stores')
                if ($value -eq 'MetadataOnly') { $argv.Add('metadata') } else { $argv.Add('copy') }
            }
        }
    }
    foreach ($item in $rest) { $argv.Add($item) }
    return , $argv
}

function Invoke-CTLinux {
    param([string]$ScriptPath, [System.Collections.Generic.List[string]]$Arguments, [bool]$NeedsRoot)

    $runner = 'bash'
    $argv = @($ScriptPath) + @($Arguments)
    if ($NeedsRoot -and -not (Test-CTRoot)) {
        Write-Host 'vestigium: root privileges are required; running through sudo'
        $runner = 'sudo'
        $argv = @('--', 'bash') + $argv
    }
    if ($DryRun) {
        $shown = @($runner) + @($argv | ForEach-Object { Format-CTPosixArgument $_ })
        Write-Host ('vestigium: would run: {0}' -f ($shown -join ' '))
        exit 0
    }
    & $runner @argv
    exit $LASTEXITCODE
}

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
switch ($Command) {
    'help' { Show-CTUsage; exit 0 }

    'version' { Write-Host ('Vestigium {0}' -f $CTVersion); exit 0 }

    'info' {
        Write-Host ('Vestigium {0}' -f $CTVersion)
        Write-Host ''
        $rows = [ordered]@{
            'Kit root'          = $KitRoot
            'PowerShell'        = ('{0} ({1})' -f $PSVersionTable.PSVersion, $PSVersionTable.PSEdition)
            'Detected platform' = $target
        }
        if ($onWindows) { $rows['Elevated'] = [string](Test-CTAdministrator) } else { $rows['Running as root'] = [string](Test-CTRoot) }
        $bundle = Join-Path $paths.Rules 'active-rules.yar'
        if (Test-Path -LiteralPath $bundle -PathType Leaf) {
            $count = @(Select-String -LiteralPath $bundle -Pattern '^\s*((private|global)\s+)*rule\s+[A-Za-z_]').Count
            $rows['YARA rule bundle'] = ('present ({0} rules)' -f $count)
        }
        else { $rows['YARA rule bundle'] = 'MISSING - run vestigium setup' }
        $rows['signature-base IOC lists'] = [string](Test-Path -LiteralPath (Join-Path (Join-Path $paths.Rules 'signature-base') 'iocs'))
        if ($target -eq 'Windows') {
            $toolsDir = Split-Path -Parent $paths.WindowsSetup
            foreach ($tool in @('yara64.exe', 'Autorunsc64.exe')) {
                $rows[$tool] = [string](Test-Path -LiteralPath (Join-Path $toolsDir $tool))
            }
            $rows['winpmem (memory)'] = [string](@(Get-ChildItem -LiteralPath $toolsDir -Filter 'winpmem_mini_x64*.exe' -ErrorAction SilentlyContinue).Count -gt 0)
        }
        $rows['Default output'] = Join-Path $KitRoot 'output'
        foreach ($key in $rows.Keys) { Write-Host ('  {0,-26} {1}' -f $key, $rows[$key]) }
        exit 0
    }

    'verify' {
        $package = $Path
        if (-not $package -and $rest.Count -gt 0) { $package = $rest[0] }
        if (-not $package) { Exit-CTUsage 'verify needs an evidence folder or archive' }
        $global:LASTEXITCODE = 0
        & $paths.Verifier -Path $package
        exit $LASTEXITCODE
    }

    'setup' {
        Assert-CTTarget
        if ($target -eq 'Linux') {
            $argv = New-Object System.Collections.Generic.List[string]
            foreach ($item in $rest) { $argv.Add($item) }
            Invoke-CTLinux -ScriptPath $paths.LinuxSetup -Arguments $argv -NeedsRoot (-not ($rest -contains '--verify'))
        }
        $splat = @{}
        Add-CTNamedPassThru -Splat $splat -ScriptPath $paths.WindowsSetup -Items $rest
        if ($DryRun) { Show-CTPowerShellDryRun -ScriptPath $paths.WindowsSetup -Splat $splat }
        $global:LASTEXITCODE = 0
        & $paths.WindowsSetup @splat
        exit $LASTEXITCODE
    }

    'collect' {
        Assert-CTTarget
        if ($Path) { Exit-CTUsage '-Path is only used with verify' }
        if ($target -eq 'Linux') {
            $argv = Get-CTLinuxArguments
            $noRoot = ($argv -contains '--list-modules') -or ($argv -contains '--help') -or ($argv -contains '-h') -or
                ($argv -contains '--version') -or ($argv -contains '-V')
            Invoke-CTLinux -ScriptPath $paths.LinuxCollector -Arguments $argv -NeedsRoot (-not $noRoot)
        }

        $splat = @{}
        foreach ($name in $opts.Keys) {
            $value = $opts[$name]
            if ($name -eq 'Quick') { if ($value) { $splat['YaraQuickScan'] = $true }; continue }
            $splat[$name] = $value
        }
        Add-CTNamedPassThru -Splat $splat -ScriptPath $paths.WindowsCollector -Items $rest
        if ($DryRun) { Show-CTPowerShellDryRun -ScriptPath $paths.WindowsCollector -Splat $splat }

        $listing = $splat.ContainsKey('ListModules') -and $splat['ListModules']
        if (-not $listing -and -not (Test-CTAdministrator)) {
            if ($Elevate) {
                # An elevated PowerShell starts in System32, so relative paths
                # must be resolved here, in the operator's working directory.
                if ($splat.ContainsKey('OutputPath')) {
                    $splat['OutputPath'] = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath([string]$splat['OutputPath'])
                }
                $argList = New-Object System.Collections.Generic.List[string]
                foreach ($a in @('-NoLogo', '-NoProfile', '-NoExit', '-ExecutionPolicy', 'Bypass', '-File', (Format-CTArgument $PSCommandPath), 'collect')) {
                    $argList.Add($a)
                }
                foreach ($key in $splat.Keys) {
                    $value = $splat[$key]
                    if (Test-CTSwitchValue $value) {
                        if ($value) { $argList.Add('-' + $key) }
                    }
                    else {
                        $argList.Add('-' + $key)
                        $argList.Add((Format-CTArgument (@($value) -join ',')))
                    }
                }
                Start-Process -FilePath (Get-Process -Id $PID).Path -Verb RunAs -ArgumentList ($argList -join ' ') -WorkingDirectory (Get-Location).Path
                Write-Host 'vestigium: collection continues in the elevated window; its result and exit code are reported there.'
                exit 0
            }
            Write-Host 'vestigium: an elevated PowerShell is required (Run as administrator), or add -Elevate.' -ForegroundColor Red
            exit 1
        }

        $global:LASTEXITCODE = 0
        & $paths.WindowsCollector @splat
        exit $LASTEXITCODE
    }
}

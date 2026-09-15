#Requires -Version 5.1
<#
.SYNOPSIS
    Windows setup entry point: builds the shared YARA rule bundle and stages the
    non-redistributable helper binaries (yara64.exe, winpmem, Autorunsc64.exe).
.DESCRIPTION
    Run once on an internet-connected staging box before deploying the kit to an
    offline evidence host. It calls Update-YaraRules.ps1 (rule bundle) and
    Get-DFIRWindowsTools.ps1 (helper binaries, SHA256-pinned via
    tools.manifest.json). The binaries are git-ignored and never redistributed.
.PARAMETER RulesOnly
    Build the YARA rules only; do not download helper binaries.
.PARAMETER NoTools
    Same as -RulesOnly (skip helper binaries).
.PARAMETER Verify
    Report readiness (rule bundle and staged tools); change nothing.
.PARAMETER Force
    Re-download helper binaries even when already present.
.PARAMETER Locked
    Forwarded to Update-YaraRules.ps1: rebuild the exact commits in rules.lock.
.OUTPUTS
    Exit code 0 on success; non-zero if the rule build fails or a pinned tool
    fails its SHA256 check.
.EXAMPLE
    vestigium.cmd setup
.EXAMPLE
    powershell -File .\Setup-Windows.ps1 -Verify
#>
[CmdletBinding()]
param(
    [Alias('RepositoryUrl')][string[]]$RepositoryUrls = @(
        'https://github.com/Neo23x0/signature-base.git',
        'https://github.com/Yara-Rules/rules.git'
    ),
    [switch]$SkipGitUpdate,
    [string]$RulesRoot = '',
    [string]$YaracPath = '',
    [ValidateRange(1,100)][int]$MaxCompileAttempts = 10,
    [switch]$Locked,
    [switch]$RulesOnly,
    [switch]$NoTools,
    [switch]$Verify,
    [switch]$Force
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$here = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($here)) { $here = (Get-Location).Path }
$rulesScript = Join-Path $here 'Update-YaraRules.ps1'
$toolsScript = Join-Path $here 'Get-DFIRWindowsTools.ps1'
$skipTools = ($RulesOnly -or $NoTools)

Write-Host '=== Vestigium Windows setup ==='

$overall = 0

if ($Verify) {
    # Rule bundle readiness (Update-YaraRules.ps1 has no verify mode of its own).
    $bundle = $RulesRoot
    if ([string]::IsNullOrWhiteSpace($bundle)) {
        # $here is <kit>\platforms\windows\Tools; the shared bundle is three
        # levels up under shared\yara-rules.
        $kitRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $here))
        $shared = Join-Path (Join-Path (Join-Path $kitRoot 'shared') 'yara-rules') 'active-rules.yar'
        $legacy = Join-Path (Join-Path $here 'YaraRules') 'active-rules.yar'
        if (Test-Path -LiteralPath $shared) { $bundle = $shared } else { $bundle = $legacy }
    }
    if (Test-Path -LiteralPath $bundle -PathType Leaf) { Write-Host ('YARA rule bundle : present ({0})' -f $bundle) }
    else { Write-Host 'YARA rule bundle : MISSING - run setup' }
    if (Test-Path -LiteralPath $toolsScript -PathType Leaf) {
        & $toolsScript -Verify
        if ($LASTEXITCODE -ne 0) { $overall = $LASTEXITCODE }
    }
    exit $overall
}

# 1. Stage the helper binaries first (SHA256-pinned). Doing this before the rule
#    build means yarac64.exe is available to compile-validate the bundle on the
#    first run, not only on the next one.
if (-not $skipTools) {
    if (Test-Path -LiteralPath $toolsScript -PathType Leaf) {
        $global:LASTEXITCODE = 0
        & $toolsScript -Force:$Force
        if ($LASTEXITCODE -ne 0) { $overall = $LASTEXITCODE }
    }
    else {
        Write-Host ('Tool downloader not found: {0}' -f $toolsScript)
    }
}
else {
    Write-Host 'Skipping helper binaries (-RulesOnly / -NoTools).'
}

# 2. Build / refresh the YARA rule bundle.
if (Test-Path -LiteralPath $rulesScript -PathType Leaf) {
    $ruleSplat = @{}
    foreach ($k in @('RepositoryUrls', 'SkipGitUpdate', 'RulesRoot', 'YaracPath', 'MaxCompileAttempts', 'Locked')) {
        if ($PSBoundParameters.ContainsKey($k)) { $ruleSplat[$k] = $PSBoundParameters[$k] }
    }
    $global:LASTEXITCODE = 0
    & $rulesScript @ruleSplat
    if ($LASTEXITCODE -ne 0) {
        Write-Host ('YARA rule build reported exit code {0}.' -f $LASTEXITCODE)
        $overall = $LASTEXITCODE
    }
}
else {
    Write-Host ('Rule builder not found: {0}' -f $rulesScript)
    $overall = 1
}

exit $overall

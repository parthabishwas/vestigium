#Requires -Version 5.1
<#
.SYNOPSIS
    Stages the non-redistributable Windows helper binaries (yara64.exe,
    winpmem, Autorunsc64.exe) into platforms\windows\Tools\, with SHA256 pinning.
.DESCRIPTION
    These binaries are not shipped in Git (Sysinternals' licence forbids
    redistribution, and vendoring EXEs is poor hygiene). They are downloaded
    from their official vendor at SETUP time on an internet-connected staging
    box - never during a collection - verified, and git-ignored.

    The tool list lives in tools.manifest.json next to this script. Each entry
    may pin a lower-case sha256: the download is rejected on mismatch. An empty
    sha256 stages the tool unpinned and records the downloaded hash so an
    operator can pin it. Tools already present are left alone unless -Force.

    A fully air-gapped staging box (no internet at all) can skip this and place
    the binaries in platforms\windows\Tools\ by hand; the collector skips any
    missing tool gracefully.
.PARAMETER Verify
    Report what is present, its hash and pin status; download nothing.
.PARAMETER Force
    Re-download even when a tool is already present.
.PARAMETER ManifestPath
    Override the manifest location (default: tools.manifest.json beside this script).
.PARAMETER ToolsDir
    Override the output directory (default: this script's folder).
.OUTPUTS
    Exit code 0 on success (including graceful download failures), 1 when a
    pinned tool fails its SHA256 check (possible tampering or a stale pin).
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Get-DFIRWindowsTools.ps1
.EXAMPLE
    powershell -File .\Get-DFIRWindowsTools.ps1 -Verify
#>
[CmdletBinding()]
param(
    [switch]$Verify,
    [switch]$Force,
    [string]$ManifestPath = '',
    [string]$ToolsDir = ''
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Write-ToolLog {
    param([string]$Level, [string]$Message)
    $stamp = (Get-Date).ToString('HH:mm:ss')
    Write-Host ('[{0}] {1,-5} {2}' -f $stamp, $Level, $Message)
}

function Get-ToolSha256 {
    param([string]$Path)
    try { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower() }
    catch { return '' }
}

function Resolve-ToolUrl {
<#
    Returns the download URL for a manifest entry. An explicit 'url' always wins
    (a pinned or overridden download). Otherwise, when the entry gives a GitHub
    'repo' and an 'asset_pattern', recent releases are scanned newest-first and
    the first asset matching the pattern is used - so a release that publishes
    no matching Windows build (some projects do not attach one to every tag) is
    skipped rather than failing.
#>
    param($Tool)

    if ($Tool.PSObject.Properties.Name -contains 'url' -and $Tool.url) { return [string]$Tool.url }

    $repo = ''
    if ($Tool.PSObject.Properties.Name -contains 'repo' -and $Tool.repo) { $repo = [string]$Tool.repo }
    $pattern = ''
    if ($Tool.PSObject.Properties.Name -contains 'asset_pattern' -and $Tool.asset_pattern) { $pattern = [string]$Tool.asset_pattern }
    if (-not $repo -or -not $pattern) { return '' }

    $api = 'https://api.github.com/repos/' + $repo + '/releases?per_page=30'
    try {
        $headers = @{ 'User-Agent' = 'Vestigium-setup'; 'Accept' = 'application/vnd.github+json' }
        # Assign directly: wrapping Invoke-RestMethod's array result in @() collapses
        # it to a single element under PowerShell 7, breaking per-release iteration.
        $rels = Invoke-RestMethod -Uri $api -Headers $headers -TimeoutSec 60 -ErrorAction Stop
    }
    catch {
        Write-ToolLog -Level 'WARN' -Message ("{0}: GitHub release lookup failed ({1})" -f $Tool.name, $_.Exception.Message)
        return ''
    }

    foreach ($rel in $rels) {
        if ($rel.PSObject.Properties.Name -contains 'draft' -and $rel.draft) { continue }
        $tag = ''
        if ($rel.PSObject.Properties.Name -contains 'tag_name') { $tag = [string]$rel.tag_name }
        $assets = @()
        if ($rel.PSObject.Properties.Name -contains 'assets') { $assets = @($rel.assets) }
        foreach ($a in $assets) {
            if ([string]$a.name -match $pattern) {
                Write-ToolLog -Level 'INFO' -Message ("{0}: newest matching release {1}, asset {2}" -f $Tool.name, $tag, $a.name)
                return [string]$a.browser_download_url
            }
        }
    }
    Write-ToolLog -Level 'WARN' -Message ("{0}: no asset matched /{1}/ in the last {2} releases of {3}" -f $Tool.name, $pattern, @($rels).Count, $repo)
    return ''
}

if ([string]::IsNullOrWhiteSpace($ToolsDir)) { $ToolsDir = $PSScriptRoot }
if ([string]::IsNullOrWhiteSpace($ToolsDir)) { $ToolsDir = (Get-Location).Path }
if ([string]::IsNullOrWhiteSpace($ManifestPath)) { $ManifestPath = Join-Path $ToolsDir 'tools.manifest.json' }

if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
    Write-ToolLog -Level 'ERROR' -Message ("Manifest not found: {0}" -f $ManifestPath)
    exit 1
}

try {
    $manifest = Get-Content -LiteralPath $ManifestPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
}
catch {
    Write-ToolLog -Level 'ERROR' -Message ("Manifest is not valid JSON: {0}" -f $_.Exception.Message)
    exit 1
}

$tools = @()
if ($manifest -and ($manifest.PSObject.Properties.Name -contains 'tools')) { $tools = @($manifest.tools) }
if ($tools.Count -eq 0) {
    Write-ToolLog -Level 'WARN' -Message 'Manifest lists no tools; nothing to do.'
    exit 0
}

# Windows PowerShell 5.1 may default to an older TLS; force TLS 1.2 for GitHub.
try { [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 } catch { }

$tracked = Join-Path $ToolsDir 'STAGED-TOOLS.md'
$records = New-Object System.Collections.ArrayList
$pinFailure = $false

foreach ($t in $tools) {
    $name = [string]$t.name
    if ([string]::IsNullOrWhiteSpace($name)) { continue }
    $dest = Join-Path $ToolsDir $name
    $type = [string]$t.type
    if ([string]::IsNullOrWhiteSpace($type)) { $type = 'exe' }
    $pin = ''
    if ($t.PSObject.Properties.Name -contains 'sha256' -and $t.sha256) { $pin = ([string]$t.sha256).ToLower().Trim() }

    # Already present?
    if ((Test-Path -LiteralPath $dest -PathType Leaf) -and -not $Force) {
        $have = Get-ToolSha256 -Path $dest
        if ($pin -and $have -ne $pin) {
            Write-ToolLog -Level 'ERROR' -Message ("{0}: staged SHA256 {1} does not match the pin {2}; delete it and re-run to replace." -f $name, $have, $pin)
            $pinFailure = $true
        }
        else {
            $suffix = ''
            if ($pin) { $suffix = ', matches pin' } else { $suffix = ', UNPINNED' }
            Write-ToolLog -Level 'OK' -Message ("{0}: already present (sha256 {1}{2})" -f $name, $have, $suffix)
        }
        [void]$records.Add(('| {0} | present | {1} | {2} |' -f $name, $have, $(if ($pin) { 'pinned' } else { 'unpinned' })))
        continue
    }

    if ($Verify) {
        Write-ToolLog -Level 'WARN' -Message ("{0}: ABSENT (add it to Tools\ or run setup without -Verify)" -f $name)
        [void]$records.Add(('| {0} | absent | - | - |' -f $name))
        continue
    }

    $url = Resolve-ToolUrl -Tool $t
    if ([string]::IsNullOrWhiteSpace($url)) {
        Write-ToolLog -Level 'WARN' -Message ("{0}: no download URL could be resolved; skipping (place it in Tools\ by hand)." -f $name)
        continue
    }

    # Windows PowerShell 5.1's Expand-Archive only accepts a .zip extension, so
    # name the temp file accordingly when the payload is an archive.
    $tmpExt = '.download'
    if ($type -eq 'zip') { $tmpExt = '.download.zip' }
    $tmp = Join-Path $ToolsDir ('.{0}{1}' -f ([guid]::NewGuid().ToString('N')), $tmpExt)
    $extractDir = $null
    try {
        Write-ToolLog -Level 'INFO' -Message ("{0}: downloading {1}" -f $name, $url)
        Invoke-WebRequest -Uri $url -OutFile $tmp -UseBasicParsing -TimeoutSec 120 -ErrorAction Stop

        $payload = $tmp
        if ($type -eq 'zip') {
            $member = [string]$t.member
            if ([string]::IsNullOrWhiteSpace($member)) { $member = $name }
            $extractDir = Join-Path $ToolsDir ('.{0}.extract' -f ([guid]::NewGuid().ToString('N')))
            Expand-Archive -LiteralPath $tmp -DestinationPath $extractDir -Force -ErrorAction Stop
            $found = Get-ChildItem -LiteralPath $extractDir -Recurse -File -Filter $member -ErrorAction SilentlyContinue | Select-Object -First 1
            if (-not $found) {
                Write-ToolLog -Level 'WARN' -Message ("{0}: '{1}' not found inside the archive; skipping." -f $name, $member)
                continue
            }
            $payload = $found.FullName
        }

        $sha = Get-ToolSha256 -Path $payload
        if ($pin -and $sha -ne $pin) {
            Write-ToolLog -Level 'ERROR' -Message ("{0}: downloaded SHA256 {1} does not match the pin {2}; discarded." -f $name, $sha, $pin)
            $pinFailure = $true
            continue
        }

        Copy-Item -LiteralPath $payload -Destination $dest -Force -ErrorAction Stop
        if ($pin) {
            Write-ToolLog -Level 'OK' -Message ("{0}: staged (sha256 {1}, matches pin)" -f $name, $sha)
        }
        else {
            Write-ToolLog -Level 'WARN' -Message ("{0}: staged UNPINNED (sha256 {1}). Set this hash as 'sha256' in tools.manifest.json to pin it." -f $name, $sha)
        }
        [void]$records.Add(('| {0} | staged | {1} | {2} |' -f $name, $sha, $(if ($pin) { 'pinned' } else { 'unpinned' })))
    }
    catch {
        Write-ToolLog -Level 'WARN' -Message ("{0}: download failed ({1}). The related collection step will skip gracefully." -f $name, $_.Exception.Message)
    }
    finally {
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
        if ($extractDir -and (Test-Path -LiteralPath $extractDir)) { Remove-Item -LiteralPath $extractDir -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

# Record what was staged (git-ignored, travels with the kit for chain-of-custody).
try {
    $lines = New-Object System.Collections.ArrayList
    [void]$lines.Add('# Staged Windows tools')
    [void]$lines.Add('')
    [void]$lines.Add(('Generated: {0:o}' -f (Get-Date)))
    [void]$lines.Add('')
    [void]$lines.Add('| Tool | State | SHA256 | Pin |')
    [void]$lines.Add('|---|---|---|---|')
    foreach ($r in $records) { [void]$lines.Add($r) }
    $enc = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($tracked, (($lines -join "`r`n") + "`r`n"), $enc)
}
catch { Write-ToolLog -Level 'WARN' -Message ("Could not write {0}: {1}" -f $tracked, $_.Exception.Message) }

if ($pinFailure) {
    Write-ToolLog -Level 'ERROR' -Message 'One or more tools failed their SHA256 pin. Review the manifest and the downloaded files.'
    exit 1
}
Write-ToolLog -Level 'OK' -Message 'Windows tool staging complete.'
exit 0

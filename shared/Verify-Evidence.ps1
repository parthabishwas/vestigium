#requires -version 5.1

<#
.SYNOPSIS
    Verifies a Vestigium evidence package from either platform.
.DESCRIPTION
    Accepts a collection folder, a Windows .zip, or a Linux .tar.zst / .tar.gz
    (archives need tar with the matching decompressor).

      1. Archive: checks the <archive>.sha256 sidecar when present.
      2. Contents: recomputes SHA256 for every file in the recorded inventory
         (Linux 20_Hashes/SHA256SUMS.txt, Windows 15_Hashes/SHA256.csv) and
         reports mismatched, missing and unrecorded files. An empty or
         malformed inventory is a failure, never a pass.
      3. Prints the collection summary and module results.

    Runs on Windows PowerShell 5.1 and on PowerShell 7 (Windows, Linux, macOS).
    Exit codes: 0 verified, 1 integrity failure, 2 usage error or unreadable package.
.PARAMETER Path
    Collection folder or archive.
.PARAMETER KeepExtracted
    Keep the temporary extraction folder of an archive and print its location.
.EXAMPLE
    .\shared\Verify-Evidence.ps1 .\output\WS01_20260911_101500.zip
.EXAMPLE
    pwsh ./shared/Verify-Evidence.ps1 ./output/web01_20260911_101500
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)][string]$Path,
    [switch]$KeepExtracted
)

Set-StrictMode -Version 2.0

function Write-CTStatus {
    param([ValidateSet('OK', 'WARN', 'FAIL', 'INFO')][string]$Level, [string]$Message)
    $colors = @{ OK = 'Green'; WARN = 'Yellow'; FAIL = 'Red'; INFO = 'Gray' }
    Write-Host ('[{0,-4}] ' -f $Level) -ForegroundColor $colors[$Level] -NoNewline
    Write-Host $Message
}

function Write-CTHeading {
    param([string]$Text)
    Write-Host ''
    Write-Host ('=== {0} ===' -f $Text) -ForegroundColor Cyan
}

function Get-CTSha256 {
    param([string]$LiteralPath)
    return (Get-FileHash -LiteralPath $LiteralPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
}

function Expand-CTZip {
<#
.SYNOPSIS
    Extracts a ZIP, refusing entries that would land outside the destination.
#>
    param([string]$ZipPath, [string]$Destination)

    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
    $separator = [System.IO.Path]::DirectorySeparatorChar
    $root = [System.IO.Path]::GetFullPath($Destination).TrimEnd($separator) + $separator
    $zip = [System.IO.Compression.ZipFile]::OpenRead($ZipPath)
    try {
        foreach ($entry in $zip.Entries) {
            # Windows PowerShell 5.1 Compress-Archive stores backslash separators.
            $name = $entry.FullName -replace '\\', '/'
            $full = [System.IO.Path]::GetFullPath((Join-Path $Destination $name))
            if (-not $full.StartsWith($root, [System.StringComparison]::Ordinal)) {
                throw ("Unsafe path in archive: {0}" -f $entry.FullName)
            }
            if ($name.EndsWith('/')) {
                New-Item -ItemType Directory -Path $full -Force | Out-Null
                continue
            }
            $parent = Split-Path -Parent $full
            if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
            [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $full, $true)
        }
    }
    finally {
        $zip.Dispose()
    }
}

function Test-CTCollectionRoot {
    param([string]$Directory)
    foreach ($marker in @('20_Hashes', '19_CollectionLogs', '15_Hashes', '14_Logs')) {
        if (Test-Path -LiteralPath (Join-Path $Directory $marker) -PathType Container) { return $true }
    }
    return $false
}

function Resolve-CTCollectionRoot {
    param([string]$Directory)
    if (Test-CTCollectionRoot $Directory) { return $Directory }
    foreach ($child in @(Get-ChildItem -LiteralPath $Directory -Directory -ErrorAction SilentlyContinue)) {
        if (Test-CTCollectionRoot $child.FullName) { return $child.FullName }
    }
    return $Directory
}

function ConvertTo-CTRelative {
    param([string]$Root, [string]$FullName)
    return $FullName.Substring($Root.TrimEnd('\', '/').Length).TrimStart('\', '/') -replace '\\', '/'
}

function Read-CTLinuxInventory {
<#
.SYNOPSIS
    Parses sha256sum output, including its escaped form for unusual file names.
    Returns the entries plus the number of lines that could not be parsed.
#>
    param([string]$SumsPath)

    $items = New-Object System.Collections.Generic.List[object]
    $malformed = 0
    foreach ($line in [System.IO.File]::ReadLines($SumsPath)) {
        if ([string]::IsNullOrEmpty($line)) { continue }
        $escaped = $line.StartsWith('\')
        if ($escaped) { $line = $line.Substring(1) }
        if ($line -notmatch '^([0-9a-fA-F]{64}) [ *](.+)$') { $malformed++; continue }
        $hash = $Matches[1].ToLowerInvariant()
        $relative = $Matches[2]
        if ($escaped) {
            $relative = $relative.Replace('\\', [string][char]0).Replace('\n', "`n").Replace('\r', "`r").Replace([string][char]0, '\')
        }
        if ($relative.StartsWith('./')) { $relative = $relative.Substring(2) }
        $items.Add([pscustomobject]@{ Relative = $relative; Hash = $hash })
    }
    return [pscustomobject]@{ Items = $items; Malformed = $malformed }
}

function Read-CTWindowsInventory {
    param([string]$CsvPath)

    $items = New-Object System.Collections.Generic.List[object]
    $malformed = 0
    foreach ($row in @(Import-Csv -LiteralPath $CsvPath)) {
        $relative = [string]$row.RelativePath
        $hash = [string]$row.SHA256
        if (-not $relative -or $hash -notmatch '^[0-9a-fA-F]{64}$') { $malformed++; continue }
        $items.Add([pscustomobject]@{ Relative = ($relative -replace '\\', '/'); Hash = $hash.ToLowerInvariant() })
    }
    return [pscustomobject]@{ Items = $items; Malformed = $malformed }
}

# ---------------------------------------------------------------------------
$resolved = Resolve-Path -LiteralPath $Path -ErrorAction SilentlyContinue
if (-not $resolved) {
    Write-CTStatus FAIL ("Not found: {0}" -f $Path)
    exit 2
}
$target = $resolved.ProviderPath
$evidence = $target
$tempRoot = $null
$failures = 0

try {
    if (Test-Path -LiteralPath $target -PathType Leaf) {
        Write-CTHeading 'Archive integrity'
        $sidecar = $target + '.sha256'
        if (Test-Path -LiteralPath $sidecar -PathType Leaf) {
            $expected = (([string](Get-Content -LiteralPath $sidecar -TotalCount 1)).Trim() -split '\s+')[0].ToLowerInvariant()
            if ((Get-CTSha256 $target) -eq $expected) {
                Write-CTStatus OK ('Archive SHA256 matches {0}' -f (Split-Path -Leaf $sidecar))
            }
            else {
                Write-CTStatus FAIL ('Archive SHA256 does NOT match {0}' -f (Split-Path -Leaf $sidecar))
                exit 1
            }
        }
        else {
            Write-CTStatus WARN 'No .sha256 sidecar next to the archive'
        }

        $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('vestigium-verify-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $tempRoot | Out-Null
        if ($target -match '(?i)\.zip$') {
            Expand-CTZip -ZipPath $target -Destination $tempRoot
        }
        elseif ($target -match '(?i)(\.tar(\.(zst|gz|xz|bz2))?|\.tgz)$') {
            & tar -xf $target -C $tempRoot
            if ($LASTEXITCODE -ne 0) {
                Write-CTStatus FAIL 'Extraction failed (a tar with zstd support is needed for .tar.zst)'
                exit 2
            }
        }
        else {
            Write-CTStatus FAIL 'Unrecognised archive type (expected .zip, .tar.zst or .tar.gz)'
            exit 2
        }
        $evidence = Resolve-CTCollectionRoot $tempRoot
    }
    else {
        $evidence = Resolve-CTCollectionRoot $target
    }

    # -----------------------------------------------------------------------
    Write-CTHeading 'Evidence tree integrity'
    $linuxSums = Join-Path (Join-Path $evidence '20_Hashes') 'SHA256SUMS.txt'
    $windowsCsv = Join-Path (Join-Path $evidence '15_Hashes') 'SHA256.csv'
    $format = 'unknown'
    $parsed = [pscustomobject]@{ Items = (New-Object System.Collections.Generic.List[object]); Malformed = 0 }
    $postHash = @()
    if (Test-Path -LiteralPath $linuxSums -PathType Leaf) {
        $format = 'linux'
        $parsed = Read-CTLinuxInventory $linuxSums
        # Written after hashing, so never part of the inventory.
        $postHash = @('^19_CollectionLogs/collection\.log$', '^20_Hashes/', '^21_Manifest/')
    }
    elseif (Test-Path -LiteralPath $windowsCsv -PathType Leaf) {
        $format = 'windows'
        $parsed = Read-CTWindowsInventory $windowsCsv
        $postHash = @('^14_Logs/Collection\.log$', '^15_Hashes/', '^16_Manifest/')
    }
    else {
        Write-CTStatus FAIL 'No hash inventory found (20_Hashes/SHA256SUMS.txt or 15_Hashes/SHA256.csv)'
        $failures++
    }
    $inventory = $parsed.Items
    Write-CTStatus INFO ('Collection format: {0}; recorded files: {1}' -f $format, $inventory.Count)
    if ($format -ne 'unknown' -and $inventory.Count -eq 0) {
        Write-CTStatus FAIL 'The hash inventory is empty or unreadable'
        $failures++
    }
    if ($parsed.Malformed -gt 0) {
        Write-CTStatus FAIL ('{0} malformed line(s) in the hash inventory' -f $parsed.Malformed)
        $failures += $parsed.Malformed
    }

    # Linux file names are case-sensitive; Windows ones are not.
    $comparer = [System.StringComparer]::Ordinal
    if ($format -eq 'windows') { $comparer = [System.StringComparer]::OrdinalIgnoreCase }
    $separator = [System.IO.Path]::DirectorySeparatorChar
    $mismatched = New-Object System.Collections.Generic.List[string]
    $missing = New-Object System.Collections.Generic.List[string]
    $drift = New-Object System.Collections.Generic.List[string]
    $recorded = New-Object 'System.Collections.Generic.HashSet[string]' ($comparer)
    foreach ($item in $inventory) {
        [void]$recorded.Add($item.Relative)
        $full = Join-Path $evidence ($item.Relative -replace '/', $separator)
        if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { $missing.Add($item.Relative); continue }
        if ((Get-CTSha256 $full) -ne $item.Hash) {
            # Windows collections before 2.0 hashed Collection.log while it was still being written.
            if ($format -eq 'windows' -and $item.Relative -match '^14_Logs/Collection\.log$') { $drift.Add($item.Relative) }
            else { $mismatched.Add($item.Relative) }
        }
    }

    if ($inventory.Count -gt 0 -and $mismatched.Count -eq 0 -and $missing.Count -eq 0) {
        Write-CTStatus OK ('All {0} recorded files match their SHA256' -f $inventory.Count)
    }
    if ($mismatched.Count -gt 0) {
        $failures += $mismatched.Count
        Write-CTStatus FAIL ('{0} file(s) do not match their recorded hash' -f $mismatched.Count)
        $mismatched | Select-Object -First 20 | ForEach-Object { Write-Host ('         {0}' -f $_) }
    }
    if ($missing.Count -gt 0) {
        $failures += $missing.Count
        Write-CTStatus FAIL ('{0} recorded file(s) are missing' -f $missing.Count)
        $missing | Select-Object -First 20 | ForEach-Object { Write-Host ('         {0}' -f $_) }
    }
    foreach ($item in $drift) {
        Write-CTStatus WARN ('{0} changed after hashing (expected for collections made before Vestigium 2.0)' -f $item)
    }

    $unrecorded = New-Object System.Collections.Generic.List[string]
    foreach ($file in @(Get-ChildItem -LiteralPath $evidence -Recurse -File -Force -ErrorAction SilentlyContinue)) {
        # Copied symlinks are evidence but are not hashed; skip them here.
        if ($file.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { continue }
        $relative = ConvertTo-CTRelative -Root $evidence -FullName $file.FullName
        if ($recorded.Contains($relative)) { continue }
        $expectedLate = $false
        foreach ($pattern in $postHash) { if ($relative -match $pattern) { $expectedLate = $true; break } }
        if (-not $expectedLate) { $unrecorded.Add($relative) }
    }
    if ($unrecorded.Count -gt 0) {
        Write-CTStatus WARN ('{0} file(s) are present but not in the inventory' -f $unrecorded.Count)
        $unrecorded | Select-Object -First 10 | ForEach-Object { Write-Host ('         {0}' -f $_) }
    }

    # Memory images carry their own SHA256 sidecar and usually travel beside the archive.
    foreach ($sidecarFile in @(Get-ChildItem -LiteralPath $evidence -Recurse -File -Filter '*.sha256' -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match '[\\/](17|20)_Memory[\\/]' })) {
        $image = $sidecarFile.FullName.Substring(0, $sidecarFile.FullName.Length - '.sha256'.Length)
        $expected = (([string](Get-Content -LiteralPath $sidecarFile.FullName -TotalCount 1)).Trim() -split '\s+')[0].ToLowerInvariant()
        if (Test-Path -LiteralPath $image -PathType Leaf) {
            if ((Get-CTSha256 $image) -eq $expected) { Write-CTStatus OK ('Memory image matches: {0}' -f (Split-Path -Leaf $image)) }
            else { $failures++; Write-CTStatus FAIL ('Memory image does NOT match: {0}' -f (Split-Path -Leaf $image)) }
        }
        else {
            Write-CTStatus INFO ('Memory image {0} is stored outside the archive; expected SHA256 {1}' -f (Split-Path -Leaf $image), $expected)
        }
    }

    # -----------------------------------------------------------------------
    Write-CTHeading 'Collection summary'
    if ($format -eq 'linux') {
        $summary = Join-Path (Join-Path $evidence '21_Manifest') 'summary.txt'
        if (Test-Path -LiteralPath $summary) { Get-Content -LiteralPath $summary -TotalCount 30 | ForEach-Object { Write-Host $_ } }
        $incomplete = Join-Path (Join-Path $evidence '19_CollectionLogs') 'INCOMPLETE.txt'
        if (Test-Path -LiteralPath $incomplete) {
            Write-CTStatus WARN 'This collection was INTERRUPTED; see 19_CollectionLogs/INCOMPLETE.txt'
        }
        $results = Join-Path (Join-Path $evidence '19_CollectionLogs') 'module-results.csv'
        if (Test-Path -LiteralPath $results) {
            Write-CTHeading 'Module results'
            Import-Csv -LiteralPath $results | Format-Table Module, Status, Commands, Skipped, Failures, DurationSeconds -AutoSize | Out-String | Write-Host
        }
    }
    elseif ($format -eq 'windows') {
        $manifestPath = Join-Path (Join-Path $evidence '16_Manifest') 'Manifest.json'
        if (Test-Path -LiteralPath $manifestPath) {
            $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
            foreach ($key in @('Hostname', 'CaseId', 'Operator', 'CollectorVersion', 'CollectionTime', 'Status', 'NumberOfFiles', 'DurationSeconds')) {
                $property = $manifest.PSObject.Properties[$key]
                if ($property) { Write-Host ('{0,-18}: {1}' -f $key, $property.Value) }
            }
            $resultsProperty = $manifest.PSObject.Properties['Results']
            if ($resultsProperty -and $resultsProperty.Value) {
                Write-CTHeading 'Module results'
                @($resultsProperty.Value) | Format-Table Name, Success, Message -AutoSize | Out-String | Write-Host
            }
        }
        $findings = Join-Path (Join-Path $evidence '19_Triage') 'Findings.md'
        if (Test-Path -LiteralPath $findings) { Write-CTStatus INFO 'Triage summary: 19_Triage/Findings.md' }
    }

    # Triage findings (findings.json is at the evidence root on both platforms).
    $findingsJson = Join-Path $evidence 'findings.json'
    if (Test-Path -LiteralPath $findingsJson -PathType Leaf) {
        Write-CTHeading 'Triage findings'
        try {
            $fd = Get-Content -LiteralPath $findingsJson -Raw | ConvertFrom-Json
            $c = $null
            if ($fd.PSObject.Properties['counts']) { $c = $fd.counts }
            if ($c) {
                Write-Host ('  {0} critical  {1} high  {2} medium  {3} low  {4} info  ({5} total)' -f `
                    $c.critical, $c.high, $c.medium, $c.low, $c.info, $c.total)
            }
            foreach ($f in @($fd.findings)) {
                if ($f.severity -eq 'critical' -or $f.severity -eq 'high') {
                    Write-Host ('  [{0,-8}] {1}  ({2})' -f $f.severity, $f.title, $f.count)
                }
            }
            if (Test-Path -LiteralPath (Join-Path $evidence 'findings.html')) {
                Write-CTStatus INFO 'Findings report: findings.html'
            }
        }
        catch { Write-CTStatus WARN ('Could not read findings.json: {0}' -f $_.Exception.Message) }
    }

    Write-CTHeading 'Result'
    if ($failures -eq 0) {
        Write-CTStatus OK 'Evidence package verified'
        $exitCode = 0
    }
    else {
        Write-CTStatus FAIL ('Integrity problems found: {0}' -f $failures)
        $exitCode = 1
    }
}
catch {
    Write-CTStatus FAIL $_.Exception.Message
    $exitCode = 2
}
finally {
    if ($tempRoot -and (Test-Path -LiteralPath $tempRoot)) {
        if ($KeepExtracted) { Write-CTStatus INFO ('Extracted copy kept at {0}' -f $tempRoot) }
        else { Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue }
    }
}
exit $exitCode

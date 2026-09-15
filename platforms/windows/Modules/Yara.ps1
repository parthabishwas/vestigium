Set-StrictMode -Version 2.0

function Get-DFIRYaraExcludeRoots {
<#
.SYNOPSIS
    Returns the folders whose YARA matches are scanner self-matches.
.DESCRIPTION
    The kit root holds the rule corpus (malware strings and samples) and the
    output base holds evidence being written during the scan; -OutputPath may
    point outside the kit, so both are listed.
.OUTPUTS
    System.String[]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    $roots = New-Object System.Collections.ArrayList
    foreach ($key in @('KitRoot','ScriptRoot','OutputBase')) {
        if (-not $Context.ContainsKey($key)) { continue }
        $value = [string]$Context[$key]
        if ([string]::IsNullOrWhiteSpace($value)) { continue }
        $value = $value.TrimEnd('\')
        $already = $false
        foreach ($existing in $roots) {
            if ([string]::Equals($existing, $value, [System.StringComparison]::OrdinalIgnoreCase)) { $already = $true }
        }
        if (-not $already) { [void]$roots.Add($value) }
    }
    return @($roots)
}

function Remove-DFIRYaraSelfMatches {
<#
.SYNOPSIS
    Drops YARA output lines whose matched path is inside an excluded root.
.OUTPUTS
    PSCustomObject with Lines (string[]) and Suppressed (int).
#>
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()][string[]]$Lines = @(),
        [AllowEmptyCollection()][string[]]$ExcludeRoots = @()
    )

    $patterns = @(foreach ($root in @($ExcludeRoots)) {
        if ([string]::IsNullOrWhiteSpace($root)) { continue }
        '(?i)' + [regex]::Escape($root.TrimEnd('\').TrimEnd('/')) + '(\\|/|$)'
    })
    $kept = New-Object System.Collections.ArrayList
    $suppressed = 0
    foreach ($line in @($Lines)) {
        if ($null -eq $line) { continue }
        $hit = $false
        foreach ($pattern in $patterns) {
            if ($line -match $pattern) { $hit = $true; break }
        }
        if ($hit) { $suppressed++ } else { [void]$kept.Add($line) }
    }
    return [pscustomobject]@{ Lines = [string[]]$kept.ToArray(); Suppressed = $suppressed }
}

function Invoke-DFIRYaraCollection {
<#
.SYNOPSIS
    Runs optional YARA scans when yara64.exe and an active rule bundle are present.
.DESCRIPTION
    Rules are resolved from <KitRoot>\shared\yara-rules\active-rules.yar, then
    the legacy Tools\YaraRules\active-rules.yar. The rules path and SHA256 are
    written to the YaraResults.txt header and the manifest.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    if ($Context.ContainsKey('SkipYara') -and $Context['SkipYara']) {
        Write-DFIRLog -Context $Context -Level WARN -Message 'YARA skipped by -SkipYara'
        return $true
    }

    $yara = Join-Path $Context.ToolsPath 'yara64.exe'
    if (-not (Test-Path -LiteralPath $yara -PathType Leaf)) {
        Write-DFIRLog -Context $Context -Level WARN -Message 'YARA skipped: Tools\yara64.exe not found'
        return $true
    }

    $activeRules = Get-DFIRYaraRulesPath -Context $Context
    if (-not $activeRules) {
        $repoHints = @(
            (Join-Path $Context.KitRoot 'shared\yara-rules\signature-base'),
            (Join-Path $Context.ToolsPath 'YaraRules\signature-base')
        )
        $haveRepos = @($repoHints | Where-Object { Test-Path -LiteralPath $_ }).Count -gt 0
        if ($haveRepos) {
            Write-DFIRLog -Context $Context -Level WARN -Message 'YARA skipped: rule repositories exist but active-rules.yar is missing. Run "vestigium.ps1 setup" or Tools\Update-YaraRules.ps1 first.'
        }
        else {
            Write-DFIRLog -Context $Context -Level WARN -Message 'YARA skipped: active-rules.yar not found in shared\yara-rules or Tools\YaraRules'
        }
        return $true
    }
    $rulesSha = Get-DFIRFileSha256 -Path $activeRules
    $Context['YaraRulesPath'] = $activeRules
    $Context['YaraRulesSha256'] = $rulesSha

    $quick = ($Context.ContainsKey('YaraQuickScan') -and $Context['YaraQuickScan'])
    $targetProfiles = if ($Context.ContainsKey('TargetProfiles') -and $Context['TargetProfiles']) { @($Context['TargetProfiles']) } else { @(Resolve-DFIRTargetProfiles -Context $Context) }
    $quickTargets = foreach ($profile in $targetProfiles) {
        $profile.Downloads
        $profile.Desktop
        $profile.Temp
    }
    $fullTargets = @(
        foreach ($profile in $targetProfiles) {
            $profile.ProfilePath
        }
        $env:ProgramData
    )
    $targets = if ($quick) { $quickTargets } else { $fullTargets }
    # -ScanDrives adds the root of each requested non-system volume, in quick and
    # full mode alike (the operator opted in explicitly). Whole-drive scans can
    # be slow; the per-target YARA timeout still applies.
    $scanDrives = if ($Context.ContainsKey('ScanDrives')) { @($Context['ScanDrives']) } else { @() }
    foreach ($d in $scanDrives) { $targets = @($targets) + ($d + '\') }
    $targets = @($targets | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -Unique)

    # The toolkit ships a YARA rule corpus that embeds malware strings and test
    # samples, and the output base receives evidence copies while YARA runs. If
    # either sits inside a scanned folder, YARA reports matches on them. Warn
    # loudly and suppress matches inside those roots.
    $excludeRoots = @(Get-DFIRYaraExcludeRoots -Context $Context)
    foreach ($target in $targets) {
        foreach ($root in $excludeRoots) {
            if (-not (Test-DFIRPathUnder -Candidate $root -Parent $target)) { continue }
            if ($root -eq ([string]$Context.OutputBase).TrimEnd('\')) {
                Write-DFIRLog -Context $Context -Level WARN -Message ("Output base {0} is inside YARA target {1}; collected evidence will be scanned and self-matches suppressed. Prefer -OutputPath on removable media." -f $root, $target)
            }
            else {
                Write-DFIRLog -Context $Context -Level WARN -Message ("Collector root {0} is inside YARA target {1}; self-matches will be suppressed. Prefer running from removable media or a path outside C:\Users." -f $root, $target)
            }
        }
    }

    $threads = 1
    if ($Context.ContainsKey('YaraThreads') -and $Context['YaraThreads']) { $threads = [int]$Context['YaraThreads'] }
    $targetTimeout = 1800
    if ($Context.ContainsKey('YaraTimeoutSeconds') -and $Context['YaraTimeoutSeconds']) { $targetTimeout = [int]$Context['YaraTimeoutSeconds'] }
    $perFileTimeout = 120
    $mode = 'Full'
    if ($quick) { $mode = 'Quick' }

    $out = Join-Path $Context.Paths.System 'YaraResults.txt'
    try {
        Write-DFIRLog -Context $Context -Message ("YARA scan started. Mode={0} Threads={1} Rules={2} Output={3}" -f $mode, $threads, $activeRules, $out)
        @(
            "Rules: $activeRules",
            "Rules-SHA256: $rulesSha",
            "Mode: $mode",
            "Threads: $threads",
            "Per-File-Timeout-Seconds: $perFileTimeout",
            "Per-Target-Timeout-Seconds: $targetTimeout",
            ("Toolkit-Root: {0}" -f $Context.KitRoot),
            ("Output-Base: {0}" -f $Context.OutputBase),
            ("Suppressed-Roots: {0}" -f ($excludeRoots -join '; ')),
            'Note: matches whose path is inside a suppressed root are removed (scanner self-match).'
        ) | Add-Content -Path $out -Encoding UTF8

        $allOk = $true
        foreach ($target in $targets) {
            Write-DFIRLog -Context $Context -Message ("YARA scanning target: {0}" -f $target)
            "Target: $target" | Add-Content -Path $out -Encoding UTF8
            $targetOk = Invoke-DFIRYaraProcess -Context $Context -YaraPath $yara -RulesPath $activeRules -TargetPath $target -OutputPath $out -Threads $threads -ExcludeRoot $excludeRoots -TimeoutSeconds $targetTimeout -PerFileTimeoutSeconds $perFileTimeout
            if (-not $targetOk) { $allOk = $false }
        }
        Add-DFIRCollectedFile -Context $Context -Path $out
        if ($allOk) {
            Write-DFIRLog -Context $Context -Level SUCCESS -Message ("YARA scan finished. Results={0}" -f $out)
        }
        else {
            Write-DFIRLog -Context $Context -Level WARN -Message ("YARA scan finished with failed or timed-out targets. Results={0}" -f $out)
        }
        Add-DFIRResult -Context $Context -Name 'YARA' -Success $allOk
        return $allOk
    }
    catch {
        Write-DFIRLog -Context $Context -Level ERROR -Message ("YARA scan failed: {0}" -f $_.Exception.Message)
        Add-DFIRResult -Context $Context -Name 'YARA' -Success $false -Message $_.Exception.Message
        return $false
    }
}

function Invoke-DFIRYaraProcess {
<#
.SYNOPSIS
    Runs yara64.exe below normal priority for one target path.
.DESCRIPTION
    Arguments are quoted per CommandLineToArgvW rules so rule and target paths
    containing spaces survive Start-Process. YARA gets a per-file timeout (-a);
    the whole target gets a wall-clock limit after which yara64.exe is killed
    and a TIMED OUT line is written to YaraResults.txt.
.OUTPUTS
    System.Boolean ($false when the process failed to run or timed out)
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][hashtable]$Context,
        [Parameter(Mandatory=$true)][string]$YaraPath,
        [Parameter(Mandatory=$true)][string]$RulesPath,
        [Parameter(Mandatory=$true)][string]$TargetPath,
        [Parameter(Mandatory=$true)][string]$OutputPath,
        [Parameter(Mandatory=$true)][int]$Threads,
        [AllowEmptyCollection()][string[]]$ExcludeRoot = @(),
        [int]$TimeoutSeconds = 1800,
        [int]$PerFileTimeoutSeconds = 120
    )

    $stdout = Join-Path $env:TEMP ("Vestigium_Yara_{0}_stdout.tmp" -f ([guid]::NewGuid().ToString('N')))
    $stderr = Join-Path $env:TEMP ("Vestigium_Yara_{0}_stderr.tmp" -f ([guid]::NewGuid().ToString('N')))
    $argumentLine = Join-DFIRArguments -Arguments @('-r','-w','-f','-p',"$Threads",'-a',"$PerFileTimeoutSeconds",$RulesPath,$TargetPath)
    $commandText = '{0} {1}' -f (ConvertTo-DFIRArgument -Value $YaraPath), $argumentLine
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $startArgs = @{
            FilePath               = $YaraPath
            ArgumentList           = $argumentLine
            RedirectStandardOutput = $stdout
            RedirectStandardError  = $stderr
            PassThru               = $true
            ErrorAction            = 'Stop'
        }
        # -WindowStyle exists only on Windows (pwsh on Linux rejects it; used for tests).
        if ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT) { $startArgs['WindowStyle'] = 'Hidden' }
        $process = Start-Process @startArgs
        # Caching the handle is what makes ExitCode readable on Windows PowerShell 5.1.
        $null = $process.Handle
        try { $process.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::BelowNormal } catch { }

        $timedOut = $false
        $waitMs = [int][math]::Min(([double]$TimeoutSeconds * 1000), [double][int]::MaxValue)
        if (-not $process.WaitForExit($waitMs)) {
            $timedOut = $true
            try { $process.Kill() } catch { }
            try { [void]$process.WaitForExit(15000) } catch { }
        }
        $watch.Stop()

        $stdoutLines = @()
        $stderrLines = @()
        if (Test-Path -LiteralPath $stdout) { $stdoutLines = @(Get-Content -LiteralPath $stdout -ErrorAction SilentlyContinue) }
        if (Test-Path -LiteralPath $stderr) { $stderrLines = @(Get-Content -LiteralPath $stderr -ErrorAction SilentlyContinue) }

        $filtered = Remove-DFIRYaraSelfMatches -Lines $stdoutLines -ExcludeRoots $ExcludeRoot
        $stdoutLines = @($filtered.Lines)
        $suppressed = $filtered.Suppressed

        if ($stdoutLines.Count -gt 0) {
            $stdoutLines | Add-Content -Path $OutputPath -Encoding UTF8
        }
        elseif (-not $timedOut) {
            "No YARA matches for: $TargetPath" | Add-Content -Path $OutputPath -Encoding UTF8
        }
        if ($suppressed -gt 0) {
            "Suppressed-Self-Matches: $suppressed (paths inside $($ExcludeRoot -join '; '))" | Add-Content -Path $OutputPath -Encoding UTF8
            Write-DFIRLog -Context $Context -Message ("Suppressed {0} YARA self-match lines under {1}" -f $suppressed, ($ExcludeRoot -join '; '))
        }
        if ($stderrLines.Count -gt 0) { $stderrLines | Add-Content -Path $OutputPath -Encoding UTF8 }

        $exitText = ''
        if ($timedOut) {
            $exitText = 'TIMEOUT'
            ("TIMED OUT after {0}s: {1} (yara64.exe killed; matches above are partial)" -f $TimeoutSeconds, $TargetPath) | Add-Content -Path $OutputPath -Encoding UTF8
            Write-DFIRLog -Context $Context -Level WARN -Message ("YARA timed out after {0}s and was killed: {1}" -f $TimeoutSeconds, $TargetPath)
        }
        else {
            $exitText = [string]$process.ExitCode
            "ExitCode: $exitText" | Add-Content -Path $OutputPath -Encoding UTF8
            if ($process.ExitCode -gt 1) {
                Write-DFIRLog -Context $Context -Level WARN -Message ("YARA returned exit code {0} for {1}" -f $process.ExitCode, $TargetPath)
            }
        }
        Add-DFIRCommandRecord -Context $Context -Name ("YARA {0}" -f $TargetPath) -Command $commandText -ExitCode $exitText -DurationSeconds $watch.Elapsed.TotalSeconds -OutputFile $OutputPath
        return (-not $timedOut)
    }
    catch {
        $watch.Stop()
        Add-DFIRCommandRecord -Context $Context -Name ("YARA {0}" -f $TargetPath) -Command $commandText -ExitCode 'EXCEPTION' -DurationSeconds $watch.Elapsed.TotalSeconds -OutputFile $OutputPath
        Write-DFIRLog -Context $Context -Level ERROR -Message ("YARA process failed for {0}: {1}" -f $TargetPath, $_.Exception.Message)
        return $false
    }
    finally {
        Remove-Item -LiteralPath $stdout,$stderr -Force -ErrorAction SilentlyContinue
    }
}

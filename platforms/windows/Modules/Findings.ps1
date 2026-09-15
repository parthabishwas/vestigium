Set-StrictMode -Version 2.0

# ---------------------------------------------------------------------------
# Findings report (vestigium/findings/1)
#
# Builds the cross-platform findings.json and findings.html at the root of the
# evidence tree during finalisation, before hashing, so both are covered by
# 15_Hashes\SHA256.csv. The catalogue mirrors 19_Triage\Findings.md so the two
# views stay consistent; every finding points at the raw artifact it came from.
# ---------------------------------------------------------------------------

function New-DFIRFinding {
<#
.SYNOPSIS
    Builds one finding object matching the vestigium/findings/1 schema.
.OUTPUTS
    System.Collections.Specialized.OrderedDictionary
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Id,
        [Parameter(Mandatory=$true)][string]$Title,
        [Parameter(Mandatory=$true)][string]$Severity,
        [Parameter(Mandatory=$true)][string]$Category,
        [Parameter(Mandatory=$true)][int]$Count,
        [Parameter(Mandatory=$true)][string]$Summary,
        [string]$Detail = '',
        [AllowEmptyCollection()][string[]]$Evidence = @(),
        [AllowEmptyCollection()][string[]]$Items = @(),
        [string]$Note = ''
    )

    $sample = @($Items)
    if ($sample.Count -gt 50) { $sample = @($sample[0..49]) }

    return [ordered]@{
        id       = $Id
        title    = $Title
        severity = $Severity
        category = $Category
        count    = $Count
        summary  = $Summary
        detail   = $Detail
        evidence = @($Evidence)
        items    = @($sample)
        note     = $Note
    }
}

function Get-DFIRFindingFileLines {
<#
.SYNOPSIS
    Reads a text file as a string array, or returns an empty array if absent.
.OUTPUTS
    System.String[]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Path)

    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        return @(Get-Content -LiteralPath $Path -ErrorAction SilentlyContinue)
    }
    return @()
}

function Get-DFIRFindingCsvRows {
<#
.SYNOPSIS
    Imports a CSV as an object array, or returns an empty array if absent/unparseable.
.OUTPUTS
    System.Object[]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return @() }
    try {
        return @(Import-Csv -LiteralPath $Path -ErrorAction Stop)
    }
    catch {
        return @()
    }
}

function Test-DFIRYaraMatchLine {
<#
.SYNOPSIS
    Decides whether a YaraResults.txt line is a rule-match line (not header/status).
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param([AllowEmptyString()][AllowNull()][string]$Line)

    if ($null -eq $Line) { return $false }
    $t = $Line.Trim()
    if ($t.Length -eq 0) { return $false }
    # Header / status / annotation lines written by the YARA module.
    if ($t -match '^(Rules|Rules-SHA256|Mode|Threads|Per-File-Timeout-Seconds|Per-Target-Timeout-Seconds|Toolkit-Root|Output-Base|Suppressed-Roots|Suppressed-Self-Matches|Note|Target|ExitCode):') { return $false }
    if ($t -match '^No YARA matches') { return $false }
    if ($t -match '^TIMED OUT') { return $false }
    if ($t -eq '---') { return $false }
    # A yara64.exe match line is "<rule_identifier> <path>".
    if ($t -match '^[A-Za-z_][A-Za-z0-9_]*\s+\S') { return $true }
    return $false
}

function Get-DFIRTaskRunAsMap {
<#
.SYNOPSIS
    Maps full scheduled-task names to their Run As User from schtasks verbose output.
.DESCRIPTION
    Get-ScheduledTask.csv does not carry the run-as principal, so the SYSTEM
    check reads it from 06_ScheduledTasks\schtasks_LIST_verbose.txt when present.
.OUTPUTS
    System.Collections.Hashtable
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Path)

    $map = @{}
    $lines = @(Get-DFIRFindingFileLines -Path $Path)
    $current = $null
    foreach ($line in $lines) {
        if ($null -eq $line) { continue }
        if ($line -match '^\s*TaskName:\s+(.+?)\s*$') {
            $current = $matches[1].Trim()
            continue
        }
        if ($current -and $line -match '^\s*Run As User:\s+(.+?)\s*$') {
            $map[$current] = $matches[1].Trim()
            $current = $null
        }
    }
    return $map
}

function Get-DFIRFindingAvDetection {
<#
.SYNOPSIS
    windows.malware.av_detection (critical) from carved ESET strings and Defender detections.
.OUTPUTS
    System.Collections.Specialized.OrderedDictionary or $null
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    $hits = New-Object System.Collections.ArrayList
    $evidence = New-Object System.Collections.ArrayList

    $esetDir = Join-Path $Context.Paths.Defender 'ESET'
    if (Test-Path -LiteralPath $esetDir -PathType Container) {
        Get-ChildItem -LiteralPath $esetDir -Filter '*.strings.txt' -File -Recurse -ErrorAction SilentlyContinue |
            ForEach-Object {
                $sourceName = $_.Name
                Get-Content -LiteralPath $_.FullName -ErrorAction SilentlyContinue |
                    Where-Object { $_ -match '^@[A-Za-z]' -and $_.Length -gt 8 } |
                    Select-Object -Unique |
                    ForEach-Object { [void]$hits.Add(('ESET  {0}  (in {1})' -f $_, $sourceName)) }
            }
        [void]$evidence.Add('12_Defender/ESET')
    }

    $mpThreat = Join-Path $Context.Paths.Defender 'MpThreatDetection.csv'
    foreach ($row in (Get-DFIRFindingCsvRows -Path $mpThreat)) {
        $name = Get-DFIRObjectProperty -InputObject $row -Name 'ThreatID'
        $res = Get-DFIRObjectProperty -InputObject $row -Name 'Resources'
        [void]$hits.Add(('Defender  ThreatID={0}  {1}' -f $name, $res))
    }
    if (Test-Path -LiteralPath $mpThreat -PathType Leaf) { [void]$evidence.Add('12_Defender/MpThreatDetection.csv') }

    $unique = @($hits | Select-Object -Unique)
    if ($unique.Count -eq 0) { return $null }

    return New-DFIRFinding -Id 'windows.malware.av_detection' -Title 'Antivirus detection recorded on this host' `
        -Severity 'critical' -Category 'malware' -Count $unique.Count `
        -Summary 'A collected ESET or Microsoft Defender record names a detected threat.' `
        -Evidence @($evidence) -Items $unique `
        -Note 'Confirm each against the raw vendor log; absence elsewhere is only as good as the vendor log retention.'
}

function Get-DFIRFindingYara {
<#
.SYNOPSIS
    windows.malware.yara (high) from YaraResults.txt rule-match lines.
.OUTPUTS
    System.Collections.Specialized.OrderedDictionary or $null
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    $path = Join-Path $Context.Paths.System 'YaraResults.txt'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $null }

    $matchesList = New-Object System.Collections.ArrayList
    foreach ($line in (Get-DFIRFindingFileLines -Path $path)) {
        if (Test-DFIRYaraMatchLine -Line $line) { [void]$matchesList.Add($line.Trim()) }
    }
    $unique = @($matchesList | Select-Object -Unique)
    if ($unique.Count -eq 0) { return $null }

    return New-DFIRFinding -Id 'windows.malware.yara' -Title 'YARA rule matches' `
        -Severity 'high' -Category 'malware' -Count $unique.Count `
        -Summary 'One or more files matched a YARA rule during the scan.' `
        -Evidence @('01_System/YaraResults.txt') -Items $unique `
        -Note 'YARA hits are leads, not verdicts.'
}

function Get-DFIRFindingAutoruns {
<#
.SYNOPSIS
    windows.persistence.autoruns_suspicious (high) from Autoruns.csv.
.OUTPUTS
    System.Collections.Specialized.OrderedDictionary or $null
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    $csvPath = Join-Path $Context.Paths.Autoruns 'Autoruns.csv'
    $rows = @(Get-DFIRFindingCsvRows -Path $csvPath)
    if ($rows.Count -eq 0) { return $null }

    $flagged = New-Object System.Collections.ArrayList
    foreach ($row in $rows) {
        $signer = Get-DFIRObjectProperty -InputObject $row -Name 'Signer'
        $image = Get-DFIRObjectProperty -InputObject $row -Name 'Image Path'
        $entry = Get-DFIRObjectProperty -InputObject $row -Name 'Entry'
        $launch = Get-DFIRObjectProperty -InputObject $row -Name 'Launch String'
        if (-not $image) { $image = '' }
        if (-not $launch) { $launch = '' }

        $unsigned = ($signer -eq $null -or $signer -eq '' -or $signer -notmatch '\(Verified\)')
        $userPath = ($image -match '\\AppData\\|\\Temp\\|\\Downloads\\|\\Users\\Public\\|\\ProgramData\\')
        $lolbin = ($launch -match 'mshta|regsvr32|certutil|bitsadmin|wscript|cscript|-enc |FromBase64|DownloadString')

        if (($unsigned -and $userPath) -or $lolbin) {
            [void]$flagged.Add(('{0} | signer={1} | {2}' -f $entry, $signer, $launch))
        }
    }

    $unique = @($flagged | Select-Object -Unique)
    if ($unique.Count -eq 0) { return $null }

    return New-DFIRFinding -Id 'windows.persistence.autoruns_suspicious' -Title 'Autostart entries that are unsigned or use living-off-the-land binaries' `
        -Severity 'high' -Category 'persistence' -Count $unique.Count `
        -Summary 'Autostart entries are unsigned and run from a user-writable path, or invoke a known dual-use binary.' `
        -Evidence @('03_Autoruns/Autoruns.csv') -Items $unique
}

function Get-DFIRFindingSystemTasks {
<#
.SYNOPSIS
    windows.persistence.system_tasks (medium) from Get-ScheduledTask.csv.
.OUTPUTS
    System.Collections.Specialized.OrderedDictionary or $null
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    $csvPath = Join-Path $Context.Paths.ScheduledTasks 'Get-ScheduledTask.csv'
    $rows = @(Get-DFIRFindingCsvRows -Path $csvPath)
    if ($rows.Count -eq 0) { return $null }

    $runAsMap = Get-DFIRTaskRunAsMap -Path (Join-Path $Context.Paths.ScheduledTasks 'schtasks_LIST_verbose.txt')

    $flagged = New-Object System.Collections.ArrayList
    foreach ($row in $rows) {
        $taskPath = [string](Get-DFIRObjectProperty -InputObject $row -Name 'TaskPath')
        $taskName = [string](Get-DFIRObjectProperty -InputObject $row -Name 'TaskName')
        $author = [string](Get-DFIRObjectProperty -InputObject $row -Name 'Author')
        $state = [string](Get-DFIRObjectProperty -InputObject $row -Name 'State')
        if ($taskPath -like '\Microsoft\*') { continue }

        $full = $taskPath + $taskName
        $principal = ''
        if ($runAsMap.ContainsKey($full)) { $principal = [string]$runAsMap[$full] }

        $isSystem = ($principal -match 'SYSTEM|S-1-5-18')
        $suspiciousAuthor = ($author -and $author -notmatch 'Microsoft|Lenovo|Intel|Google|Mozilla|Adobe|Zoom|Realtek|NT AUTHORITY')
        if ($isSystem -or $suspiciousAuthor) {
            [void]$flagged.Add(('{0}{1} | author={2} | runas={3} | state={4}' -f $taskPath, $taskName, $author, $principal, $state))
        }
    }

    $unique = @($flagged | Select-Object -Unique)
    if ($unique.Count -eq 0) { return $null }

    return New-DFIRFinding -Id 'windows.persistence.system_tasks' -Title 'Non-Microsoft scheduled tasks running as SYSTEM or with an unrecognised author' `
        -Severity 'medium' -Category 'persistence' -Count $unique.Count `
        -Summary 'Scheduled tasks outside \Microsoft\ run as SYSTEM or carry an author not on the vendor allow-list.' `
        -Evidence @('06_ScheduledTasks/Get-ScheduledTask.csv') -Items $unique
}

function Get-DFIRFindingListeners {
<#
.SYNOPSIS
    windows.network.listeners (medium) from Get-NetTCPConnection.txt.
.OUTPUTS
    System.Collections.Specialized.OrderedDictionary or $null
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    $path = Join-Path $Context.Paths.Network 'Get-NetTCPConnection.txt'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $null }

    $portNotes = @{
        '3389'  = 'RDP'
        '5900'  = 'VNC'
        '5800'  = 'VNC over HTTP'
        '5985'  = 'WinRM'
        '5986'  = 'WinRM over TLS'
        '1433'  = 'MSSQL'
        '3306'  = 'MySQL/MariaDB'
        '445'   = 'SMB'
        '135'   = 'RPC endpoint mapper'
        '139'   = 'NetBIOS session'
        '5357'  = 'WSDAPI'
        '7070'  = 'AnyDesk'
        '16992' = 'Intel AMT'
        '16993' = 'Intel AMT over TLS'
        '623'   = 'IPMI/ASF-RMCP'
    }

    $seen = @{}
    $items = New-Object System.Collections.ArrayList
    foreach ($line in (Get-DFIRFindingFileLines -Path $path)) {
        if ($null -eq $line) { continue }
        if ($line -notmatch '^\s*(0\.0\.0\.0|::)\s+(\d+)\s+\S+\s+\d+\s+Listen') { continue }
        $address = $matches[1]
        $port = [int]$matches[2]
        if ($port -ge 49000) { continue }
        $key = ('{0}:{1}' -f $address, $port)
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        $note = ''
        if ($portNotes.ContainsKey([string]$port)) { $note = ('  ({0})' -f $portNotes[[string]$port]) }
        [void]$items.Add(('{0}:{1}{2}' -f $address, $port, $note))
    }

    if ($items.Count -eq 0) { return $null }

    return New-DFIRFinding -Id 'windows.network.listeners' -Title 'Services listening on all interfaces' `
        -Severity 'medium' -Category 'network' -Count $items.Count `
        -Summary 'Non-ephemeral TCP listeners are bound to all interfaces (0.0.0.0 or ::).' `
        -Evidence @('08_Network/Get-NetTCPConnection.txt') -Items @($items) `
        -Note 'Known ports are annotated; confirm the owning process against the raw netstat output.'
}

function Get-DFIRFindingRemoteAccess {
<#
.SYNOPSIS
    windows.execution.remote_access (medium) from the installed-software inventory.
.OUTPUTS
    System.Collections.Specialized.OrderedDictionary or $null
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    $pattern = 'AnyDesk|TeamViewer|VNC|Ammyy|Radmin|RustDesk|LogMeIn|Splashtop|ScreenConnect|GoToAssist|Atera|ngrok|Wireshark|Nmap|PuTTY|Everything|TeraBox|Tor Browser|activation|KMS'

    $sources = @(
        (Join-Path $Context.Paths.System 'InstalledApplications.csv'),
        (Join-Path $Context.Paths.Defender 'InstalledSecuritySoftware.csv')
    )
    $evidence = New-Object System.Collections.ArrayList
    $items = New-Object System.Collections.ArrayList
    foreach ($source in $sources) {
        $rows = @(Get-DFIRFindingCsvRows -Path $source)
        if ($rows.Count -eq 0) { continue }
        $matched = $false
        foreach ($row in $rows) {
            $name = [string](Get-DFIRObjectProperty -InputObject $row -Name 'DisplayName')
            if (-not $name) { continue }
            if ($name -notmatch $pattern) { continue }
            $matched = $true
            $ver = [string](Get-DFIRObjectProperty -InputObject $row -Name 'DisplayVersion')
            $pub = [string](Get-DFIRObjectProperty -InputObject $row -Name 'Publisher')
            [void]$items.Add(('{0} {1} ({2})' -f $name, $ver, $pub))
        }
        if ($matched) { [void]$evidence.Add((Get-DFIRRelativeEvidencePath -Context $Context -Path $source).Replace('\', '/')) }
    }

    $unique = @($items | Select-Object -Unique)
    if ($unique.Count -eq 0) { return $null }

    return New-DFIRFinding -Id 'windows.execution.remote_access' -Title 'Remote-access and dual-use software installed' `
        -Severity 'medium' -Category 'execution' -Count $unique.Count `
        -Summary 'Installed software matches the remote-access / dual-use watch-list.' `
        -Evidence @($evidence) -Items $unique `
        -Note 'Legitimate use is common; confirm the tool is expected on this host.'
}

function Get-DFIRFindingFirewallDisabled {
<#
.SYNOPSIS
    windows.defense.firewall_disabled (high) from FirewallProfiles.txt.
.OUTPUTS
    System.Collections.Specialized.OrderedDictionary or $null
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    $path = Join-Path $Context.Paths.Network 'FirewallProfiles.txt'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $null }

    $profileName = ''
    $items = New-Object System.Collections.ArrayList
    foreach ($line in (Get-DFIRFindingFileLines -Path $path)) {
        if ($null -eq $line) { continue }
        if ($line -match '^\s*([A-Za-z]+)\s+Profile\s+Settings:') { $profileName = $matches[1]; continue }
        if ($line -match '^\s*State\s+OFF\b') {
            [void]$items.Add(('{0} profile: firewall State OFF' -f ($(if ($profileName) { $profileName } else { 'Unknown' }))))
        }
    }

    if ($items.Count -eq 0) { return $null }

    return New-DFIRFinding -Id 'windows.defense.firewall_disabled' -Title 'Windows Firewall is disabled for one or more profiles' `
        -Severity 'high' -Category 'integrity' -Count $items.Count `
        -Summary 'A firewall profile reports State OFF, a common defence-evasion step.' `
        -Evidence @('08_Network/FirewallProfiles.txt') -Items @($items) `
        -Note 'Confirm whether the profile is disabled by policy; review FirewallRules.txt for malware-added inbound Allow rules.'
}

function Get-DFIRFindingBitsJobs {
<#
.SYNOPSIS
    windows.execution.bits_jobs (medium) from BitsTransfers.csv.
.OUTPUTS
    System.Collections.Specialized.OrderedDictionary or $null
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    $path = Join-Path $Context.Paths.Network 'BitsTransfers.csv'
    $rows = Get-DFIRFindingCsvRows -Path $path
    if ($rows.Count -eq 0) { return $null }

    $items = New-Object System.Collections.ArrayList
    foreach ($r in $rows) {
        $remote = [string](Get-DFIRObjectProperty -InputObject $r -Name 'RemoteName')
        $local  = [string](Get-DFIRObjectProperty -InputObject $r -Name 'LocalName')
        $state  = [string](Get-DFIRObjectProperty -InputObject $r -Name 'State')
        $suspicious = $false
        if ($remote -match '(?i)^https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}') { $suspicious = $true }
        if ($local -match '(?i)\\(Temp|AppData|Users\\Public)\\') { $suspicious = $true }
        if (-not $suspicious) { continue }
        [void]$items.Add(('{0}  {1} -> {2}' -f $state, $remote, $local))
    }

    if ($items.Count -eq 0) { return $null }

    return New-DFIRFinding -Id 'windows.execution.bits_jobs' -Title 'Suspicious BITS transfer jobs' `
        -Severity 'medium' -Category 'execution' -Count $items.Count `
        -Summary 'BITS jobs fetch from a raw-IP URL or write into a user-writable path, a common download / persistence channel.' `
        -Evidence @('08_Network/BitsTransfers.csv') -Items @($items) `
        -Note 'BITS jobs survive reboots and run as a service; confirm the remote host and the local payload.'
}

function Get-DFIRFindingCollectionSteps {
<#
.SYNOPSIS
    windows.collection.steps (info): module results, listing any non-Success step.
.OUTPUTS
    System.Collections.Specialized.OrderedDictionary
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    $failures = New-Object System.Collections.ArrayList
    if ($Context.ContainsKey('Results') -and $Context['Results']) {
        foreach ($result in @($Context['Results'])) {
            $success = Get-DFIRObjectProperty -InputObject $result -Name 'Success'
            if ($success -eq $true) { continue }
            $name = [string](Get-DFIRObjectProperty -InputObject $result -Name 'Name')
            $message = [string](Get-DFIRObjectProperty -InputObject $result -Name 'Message')
            [void]$failures.Add(('{0}: {1}' -f $name, $message))
        }
    }

    return New-DFIRFinding -Id 'windows.collection.steps' -Title 'Collection step results' `
        -Severity 'info' -Category 'collection' -Count $failures.Count `
        -Summary 'Modules that did not complete cleanly are listed; review before relying on any negative finding.' `
        -Items @($failures)
}

function Get-DFIRFindingCollectionSummary {
<#
.SYNOPSIS
    windows.collection.summary (info): cheap inventory counts.
.OUTPUTS
    System.Collections.Specialized.OrderedDictionary
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    $items = New-Object System.Collections.ArrayList

    $evtxCount = 0
    if (Test-Path -LiteralPath $Context.Paths.EventLogs -PathType Container) {
        $evtxCount = @(Get-ChildItem -LiteralPath $Context.Paths.EventLogs -Filter '*.evtx' -File -ErrorAction SilentlyContinue).Count
    }
    [void]$items.Add(('Event log channels exported: {0}' -f $evtxCount))

    $profileCount = 0
    if ($Context.ContainsKey('TargetProfiles') -and $Context['TargetProfiles']) {
        $profileCount = @($Context['TargetProfiles']).Count
    }
    [void]$items.Add(('User profiles examined: {0}' -f $profileCount))

    $moduleCount = 0
    if ($Context.ContainsKey('SelectedModules') -and $Context['SelectedModules']) {
        $moduleCount = @($Context['SelectedModules']).Count
    }
    [void]$items.Add(('Collection steps selected: {0}' -f $moduleCount))

    return New-DFIRFinding -Id 'windows.collection.summary' -Title 'Collection summary' `
        -Severity 'info' -Category 'collection' -Count 0 `
        -Summary 'Inventory counts for this collection.' `
        -Items @($items)
}

function Get-DFIRFindingsGaps {
<#
.SYNOPSIS
    Builds the top-level gaps array, mirroring the triage collection-gap logic.
.OUTPUTS
    System.String[]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    $gaps = New-Object System.Collections.ArrayList

    if ($Context.ContainsKey('LogFile') -and (Test-Path -LiteralPath $Context.LogFile -PathType Leaf)) {
        $log = Get-Content -LiteralPath $Context.LogFile -ErrorAction SilentlyContinue
        $warnCount = @($log | Where-Object { $_ -match '\[WARN\]' }).Count
        $errCount = @($log | Where-Object { $_ -match '\[ERROR\]' }).Count
        [void]$gaps.Add(('Collection.log recorded {0} warnings and {1} errors; review before relying on any negative finding.' -f $warnCount, $errCount))

        foreach ($line in $log) {
            if ($line -match 'is INSTALLED but no log path was found') { [void]$gaps.Add($line.Trim()) }
            if ($line -match 'Locked-file copy failed after all fallbacks') { [void]$gaps.Add($line.Trim()) }
            if ($line -match 'is inside YARA target') { [void]$gaps.Add($line.Trim()) }
            if ($line -match 'YARA timed out after') { [void]$gaps.Add($line.Trim()) }
        }
    }

    $memoryPresent = ($Context.ContainsKey('MemoryCaptured') -and $Context['MemoryCaptured'])
    if (-not $memoryPresent -and (Test-Path -LiteralPath $Context.Paths.Memory -PathType Container)) {
        $memoryPresent = @(Get-ChildItem -LiteralPath $Context.Paths.Memory -File -ErrorAction SilentlyContinue).Count -gt 0
    }
    if (-not $memoryPresent) {
        [void]$gaps.Add('No memory image was captured; memory-resident implants cannot be excluded.')
    }

    $ntfsOk = ($Context.ContainsKey('NtfsAcquired') -and $Context['NtfsAcquired'])
    if ($ntfsOk) {
        [void]$gaps.Add('$MFT / $UsnJrnl were acquired for offline parsing (21_FileSystem) but are not parsed inline; run MFTECmd for a deleted-file timeline.')
    }
    else {
        [void]$gaps.Add('$MFT / $UsnJrnl were NOT acquired (VSS unavailable or non-elevated); deleted-file history is not reconstructable from this collection.')
    }

    $policy = 'Copy'
    if ($Context.ContainsKey('BrowserCredentialStores') -and $Context['BrowserCredentialStores'] -eq 'MetadataOnly') { $policy = 'MetadataOnly' }
    if ($policy -eq 'MetadataOnly') {
        [void]$gaps.Add('Browser credential stores were recorded as metadata only (09_Browser/CredentialStoreMetadata.csv); their contents were not collected.')
    }
    else {
        [void]$gaps.Add('Browser credential stores were copied. Chromium values need the user DPAPI key to decrypt; Firefox logins.json + key4.db decrypt offline unless a Primary Password is set. Handle as sensitive.')
    }

    return @($gaps | Select-Object -Unique)
}

function Get-DFIRFindingsDocument {
<#
.SYNOPSIS
    Assembles the full vestigium/findings/1 document from the evidence tree.
.OUTPUTS
    System.Collections.Specialized.OrderedDictionary
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    $order = @{ critical = 0; high = 1; medium = 2; low = 3; info = 4 }

    $findings = New-Object System.Collections.ArrayList
    $builders = @(
        (Get-DFIRFindingAvDetection -Context $Context),
        (Get-DFIRFindingYara -Context $Context),
        (Get-DFIRFindingAutoruns -Context $Context),
        (Get-DFIRFindingSystemTasks -Context $Context),
        (Get-DFIRFindingListeners -Context $Context),
        (Get-DFIRFindingRemoteAccess -Context $Context),
        (Get-DFIRFindingFirewallDisabled -Context $Context),
        (Get-DFIRFindingBitsJobs -Context $Context),
        (Get-DFIRFindingCollectionSteps -Context $Context),
        (Get-DFIRFindingCollectionSummary -Context $Context)
    )
    foreach ($finding in $builders) {
        if ($null -ne $finding) { [void]$findings.Add($finding) }
    }

    $sorted = @($findings | Sort-Object `
        @{ Expression = { $order[[string]$_.severity] } }, `
        @{ Expression = { [int]$_.count }; Descending = $true })

    $counts = [ordered]@{ critical = 0; high = 0; medium = 0; low = 0; info = 0; total = 0 }
    foreach ($finding in $sorted) {
        $sev = [string]$finding.severity
        if ($counts.Contains($sev)) { $counts[$sev] = [int]$counts[$sev] + 1 }
        $counts['total'] = [int]$counts['total'] + 1
    }

    $os = $null
    try { $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue } catch { $os = $null }
    $osName = ''
    $osVersion = ''
    if ($os) {
        $osName = ((([string](Get-DFIRObjectProperty -InputObject $os -Name 'Caption')) + ' ' + ([string](Get-DFIRObjectProperty -InputObject $os -Name 'Version'))).Trim())
        $osVersion = [string](Get-DFIRObjectProperty -InputObject $os -Name 'Version')
    }
    if ([string]::IsNullOrWhiteSpace($osName)) { $osName = [string]$env:OS }

    $status = 'completed'
    if ($Context.ContainsKey('Status')) {
        $raw = [string]$Context['Status']
        if ($raw -notmatch '^Completed') { $status = 'interrupted' }
    }

    $startTime = Get-Date
    if ($Context.ContainsKey('StartTime') -and $Context['StartTime']) { $startTime = [datetime]$Context['StartTime'] }
    $endTime = Get-Date
    $startUtc = $startTime.ToUniversalTime()
    $endUtc = $endTime.ToUniversalTime()
    $duration = [int][math]::Round(($endUtc - $startUtc).TotalSeconds, 0)

    $caseId = ''
    if ($Context.ContainsKey('CaseId')) { $caseId = [string]$Context['CaseId'] }

    $collectorVersion = ''
    if ($Context.ContainsKey('CollectorVersion')) { $collectorVersion = [string]$Context['CollectorVersion'] }

    $evidenceRoot = ''
    if ($Context.ContainsKey('OutputRoot') -and $Context['OutputRoot']) { $evidenceRoot = Split-Path -Leaf $Context['OutputRoot'] }

    return [ordered]@{
        schema        = 'vestigium/findings/1'
        tool          = 'Vestigium'
        generated_utc = $endUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
        case_id       = $caseId
        host          = [ordered]@{
            hostname   = [string]$env:COMPUTERNAME
            platform   = 'windows'
            os         = $osName
            os_version = $osVersion
        }
        collection    = [ordered]@{
            status            = $status
            collector_version = $collectorVersion
            evidence_root     = $evidenceRoot
            started_utc       = $startUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
            ended_utc         = $endUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
            duration_seconds  = $duration
        }
        counts        = $counts
        findings      = @($sorted)
        gaps          = @(Get-DFIRFindingsGaps -Context $Context)
        notes         = @('Findings are automated leads, not verdicts; confirm each against the underlying artifact.')
    }
}

function Write-DFIRFindingsHtml {
<#
.SYNOPSIS
    Injects the escaped findings JSON into the shared report template.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][hashtable]$Context,
        [Parameter(Mandatory=$true)][string]$Json,
        [Parameter(Mandatory=$true)][string]$HtmlPath
    )

    $template = $null
    if ($Context.ContainsKey('KitRoot') -and $Context['KitRoot']) {
        $template = Join-Path $Context['KitRoot'] 'shared\report\findings-template.html'
    }
    if ((-not $template) -or (-not (Test-Path -LiteralPath $template -PathType Leaf))) {
        # Fall back to the grandparent of the script folder (kit root layout).
        $platforms = Split-Path -Parent $Context.ScriptRoot
        if ($platforms) {
            $grand = Split-Path -Parent $platforms
            if ($grand) { $template = Join-Path $grand 'shared\report\findings-template.html' }
        }
    }
    if ((-not $template) -or (-not (Test-Path -LiteralPath $template -PathType Leaf))) {
        Write-DFIRLog -Context $Context -Level WARN -Message ('Findings report template not found; findings.html not written. Looked for shared\report\findings-template.html under the kit root.')
        return $false
    }

    try {
        # HTML entities are NOT decoded inside a <script> element, so entity
        # escaping would render literally and corrupt the data. Use JSON unicode
        # escapes instead (valid JSON, safe to embed), matching the Linux
        # producer so both platforms embed identically.
        $escaped = $Json.Replace('<', '\u003c').Replace('>', '\u003e').Replace('&', '\u0026')
        $html = [System.IO.File]::ReadAllText($template)
        $html = $html.Replace('__VESTIGIUM_FINDINGS_JSON__', $escaped)
        $encoding = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($HtmlPath, $html, $encoding)
        return $true
    }
    catch {
        Write-DFIRLog -Context $Context -Level WARN -Message ('Findings HTML render failed: {0}' -f $_.Exception.Message)
        return $false
    }
}

function Invoke-DFIRFindingsReport {
<#
.SYNOPSIS
    Writes findings.json and findings.html at the evidence-tree root, before hashing.
.DESCRIPTION
    Builds the vestigium/findings/1 document from the collected artifacts,
    mirroring the triage summary, serialises it to JSON, injects the JSON into
    the shared HTML template, and registers both files for hashing. Returns
    $false only on a real error (never merely because there is nothing to flag).
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    Write-DFIRLog -Context $Context -Message 'Generating findings report (findings.json / findings.html)'
    try {
        $document = Get-DFIRFindingsDocument -Context $Context
        $json = $document | ConvertTo-Json -Depth 6

        $jsonPath = Join-Path $Context.OutputRoot 'findings.json'
        $encoding = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($jsonPath, $json, $encoding)
        Add-DFIRCollectedFile -Context $Context -Path $jsonPath

        $htmlPath = Join-Path $Context.OutputRoot 'findings.html'
        $htmlOk = Write-DFIRFindingsHtml -Context $Context -Json $json -HtmlPath $htmlPath
        if ($htmlOk) {
            Add-DFIRCollectedFile -Context $Context -Path $htmlPath
        }

        $total = 0
        if ($document.Contains('counts') -and $document['counts'].Contains('total')) { $total = [int]$document['counts']['total'] }
        Write-DFIRLog -Context $Context -Level SUCCESS -Message ('Findings report written: {0} findings' -f $total)
        Add-DFIRResult -Context $Context -Name 'Findings' -Success $true
        return $true
    }
    catch {
        Write-DFIRLog -Context $Context -Level ERROR -Message ('Findings report failed: {0}' -f $_.Exception.Message)
        Add-DFIRResult -Context $Context -Name 'Findings' -Success $false -Message $_.Exception.Message
        return $false
    }
}

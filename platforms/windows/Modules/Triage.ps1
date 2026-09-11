Set-StrictMode -Version 2.0

function Invoke-DFIRTriageSummary {
<#
.SYNOPSIS
    Generates 19_Triage\Findings.md, a first-pass triage summary of the collection.
.DESCRIPTION
    A collection produces roughly 200 files per host. This step surfaces the
    handful of items an analyst would normally look for first. Every entry is an
    observation requiring confirmation, not a verdict, and the file explicitly
    says so. It never suppresses evidence; the underlying artifacts remain
    authoritative.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    Write-DFIRLog -Context $Context -Message 'Generating triage summary'
    $lines = New-Object System.Collections.ArrayList

    [void]$lines.Add('# Vestigium Triage Summary')
    [void]$lines.Add('')
    [void]$lines.Add(('- Case ID: {0} ({1})' -f $Context.CaseId, $Context.CaseIdSource))
    [void]$lines.Add(('- Host: {0}' -f $env:COMPUTERNAME))
    [void]$lines.Add(('- Operator: {0}' -f $Context.Operator))
    [void]$lines.Add(('- Collected: {0}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')))
    [void]$lines.Add(('- Collector version: {0}' -f $Context.CollectorVersion))
    [void]$lines.Add(('- Collector root: {0}' -f $Context.ScriptRoot))
    [void]$lines.Add('')
    [void]$lines.Add('> These are automated observations to prioritise review, not conclusions.')
    [void]$lines.Add('> Every item must be confirmed against the underlying artifacts before it is reported.')
    [void]$lines.Add('')

    Add-DFIRTriageAvDetections -Context $Context -Lines $lines
    Add-DFIRTriageAutoruns -Context $Context -Lines $lines
    Add-DFIRTriageListeners -Context $Context -Lines $lines
    Add-DFIRTriageRemoteAccess -Context $Context -Lines $lines
    Add-DFIRTriageTasks -Context $Context -Lines $lines
    Add-DFIRTriageCollectionGaps -Context $Context -Lines $lines

    $path = Join-Path $Context.Paths.Triage 'Findings.md'
    try {
        $lines | Out-File -FilePath $path -Encoding UTF8 -Width 4096
        Add-DFIRCollectedFile -Context $Context -Path $path
        Add-DFIRResult -Context $Context -Name 'Triage' -Success $true
        return $true
    }
    catch {
        Write-DFIRLog -Context $Context -Level ERROR -Message ("Triage summary failed: {0}" -f $_.Exception.Message)
        Add-DFIRResult -Context $Context -Name 'Triage' -Success $false -Message $_.Exception.Message
        return $false
    }
}

function Add-DFIRTriageAvDetections {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][hashtable]$Context,
        [Parameter(Mandatory=$true)][AllowEmptyCollection()][System.Collections.ArrayList]$Lines
    )

    [void]$Lines.Add('## Antivirus detections')
    [void]$Lines.Add('')
    $hits = New-Object System.Collections.ArrayList

    # ESET stores detection history in binary .dat files; the carved companion
    # text is what makes detection names greppable.
    $esetDir = Join-Path $Context.Paths.Defender 'ESET'
    if (Test-Path -LiteralPath $esetDir) {
        Get-ChildItem -LiteralPath $esetDir -Filter '*.strings.txt' -File -Recurse -ErrorAction SilentlyContinue |
            ForEach-Object {
                $sourceName = $_.Name
                Get-Content -LiteralPath $_.FullName -ErrorAction SilentlyContinue |
                    Where-Object { $_ -match '^@[A-Za-z]' -and $_.Length -gt 8 } |
                    Select-Object -Unique |
                    ForEach-Object { [void]$hits.Add(('ESET  {0}  (in {1})' -f $_, $sourceName)) }
            }
    }

    $mpThreat = Join-Path $Context.Paths.Defender 'MpThreatDetection.csv'
    if (Test-Path -LiteralPath $mpThreat -PathType Leaf) {
        try {
            Import-Csv -LiteralPath $mpThreat -ErrorAction SilentlyContinue |
                ForEach-Object {
                    $name = Get-DFIRObjectProperty -InputObject $_ -Name 'ThreatID'
                    $res = Get-DFIRObjectProperty -InputObject $_ -Name 'Resources'
                    [void]$hits.Add(('Defender  ThreatID={0}  {1}' -f $name, $res))
                }
        }
        catch { }
    }

    if ($hits.Count -eq 0) {
        [void]$Lines.Add('No detections found in the collected ESET or Defender records.')
        [void]$Lines.Add('Note: absence here is only as good as the vendor log retention on this host.')
    }
    else {
        [void]$Lines.Add('Detection strings recovered from vendor logs. Confirm each against the raw log:')
        [void]$Lines.Add('')
        foreach ($hit in ($hits | Select-Object -Unique)) { [void]$Lines.Add(('- ' + $hit)) }
    }
    [void]$Lines.Add('')
}

function Add-DFIRTriageAutoruns {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][hashtable]$Context,
        [Parameter(Mandatory=$true)][AllowEmptyCollection()][System.Collections.ArrayList]$Lines
    )

    [void]$Lines.Add('## Autostart entries that are unsigned or run from user-writable paths')
    [void]$Lines.Add('')
    $csvPath = Join-Path $Context.Paths.Autoruns 'Autoruns.csv'
    if (-not (Test-Path -LiteralPath $csvPath -PathType Leaf)) {
        [void]$Lines.Add('Autoruns.csv not present.')
        [void]$Lines.Add('')
        return
    }

    try {
        $rows = Import-Csv -LiteralPath $csvPath -ErrorAction Stop
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

        if ($flagged.Count -eq 0) {
            [void]$Lines.Add('No autostart entry is both unsigned and located in a user-writable path.')
        }
        else {
            [void]$Lines.Add(('{0} entries flagged:' -f $flagged.Count))
            [void]$Lines.Add('')
            foreach ($f in ($flagged | Select-Object -Unique -First 40)) { [void]$Lines.Add(('- ' + $f)) }
        }
    }
    catch {
        [void]$Lines.Add(('Autoruns.csv could not be parsed: {0}' -f $_.Exception.Message))
    }
    [void]$Lines.Add('')
}

function Add-DFIRTriageListeners {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][hashtable]$Context,
        [Parameter(Mandatory=$true)][AllowEmptyCollection()][System.Collections.ArrayList]$Lines
    )

    [void]$Lines.Add('## Services listening on all interfaces')
    [void]$Lines.Add('')
    try {
        $listeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
            Where-Object { $_.LocalAddress -eq '0.0.0.0' -or $_.LocalAddress -eq '::' } |
            Where-Object { $_.LocalPort -lt 49000 } |
            Sort-Object LocalPort -Unique

        if (-not $listeners) {
            [void]$Lines.Add('No non-ephemeral listener bound to all interfaces.')
        }
        else {
            foreach ($l in $listeners) {
                $procName = ''
                try { $procName = (Get-Process -Id $l.OwningProcess -ErrorAction SilentlyContinue).Path } catch { }
                $note = ''
                switch ($l.LocalPort) {
                    3389  { $note = '  <-- Remote Desktop' }
                    5900  { $note = '  <-- VNC' }
                    5800  { $note = '  <-- VNC over HTTP' }
                    7070  { $note = '  <-- AnyDesk' }
                    3306  { $note = '  <-- MySQL/MariaDB' }
                    1433  { $note = '  <-- MSSQL' }
                    16992 { $note = '  <-- Intel AMT (out-of-band management)' }
                    16993 { $note = '  <-- Intel AMT over TLS' }
                    623   { $note = '  <-- IPMI/ASF-RMCP' }
                    5985  { $note = '  <-- WinRM' }
                    5986  { $note = '  <-- WinRM over TLS' }
                }
                [void]$Lines.Add(('- {0}:{1}  pid={2}  {3}{4}' -f $l.LocalAddress, $l.LocalPort, $l.OwningProcess, $procName, $note))
            }
        }
    }
    catch {
        [void]$Lines.Add(('Listener enumeration failed: {0}' -f $_.Exception.Message))
    }
    [void]$Lines.Add('')
}

function Add-DFIRTriageRemoteAccess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][hashtable]$Context,
        [Parameter(Mandatory=$true)][AllowEmptyCollection()][System.Collections.ArrayList]$Lines
    )

    [void]$Lines.Add('## Remote-access and dual-use software')
    [void]$Lines.Add('')
    try {
        $pattern = 'AnyDesk|TeamViewer|VNC|Ammyy|Radmin|RustDesk|LogMeIn|Splashtop|ScreenConnect|GoToAssist|Atera|ngrok|Wireshark|Nmap|PuTTY|Everything|TeraBox|Tor Browser|activation|KMS'
        $roots = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
        )
        $found = Get-ItemProperty -Path $roots -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -and $_.DisplayName -match $pattern } |
            Select-Object DisplayName, DisplayVersion, Publisher, InstallDate

        if (-not $found) {
            [void]$Lines.Add('No remote-access or dual-use software matched the watch-list.')
        }
        else {
            foreach ($f in $found) {
                [void]$Lines.Add(('- {0} {1} ({2}) installed {3}' -f $f.DisplayName, $f.DisplayVersion, $f.Publisher, $f.InstallDate))
            }
        }
    }
    catch {
        [void]$Lines.Add(('Software watch-list check failed: {0}' -f $_.Exception.Message))
    }
    [void]$Lines.Add('')
}

function Add-DFIRTriageTasks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][hashtable]$Context,
        [Parameter(Mandatory=$true)][AllowEmptyCollection()][System.Collections.ArrayList]$Lines
    )

    [void]$Lines.Add('## Non-Microsoft scheduled tasks running as SYSTEM')
    [void]$Lines.Add('')
    try {
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue |
            Where-Object { $_.TaskPath -notlike '\Microsoft\*' }

        $flagged = New-Object System.Collections.ArrayList
        foreach ($task in $tasks) {
            $principal = $null
            try { $principal = $task.Principal.UserId } catch { }
            $isSystem = ($principal -match 'SYSTEM|S-1-5-18')
            $author = $null
            try { $author = $task.Author } catch { }
            $suspiciousAuthor = ($author -and $author -notmatch 'Microsoft|Lenovo|Intel|Google|Mozilla|Adobe|Zoom|Realtek|NT AUTHORITY')
            if ($isSystem -or $suspiciousAuthor) {
                [void]$flagged.Add(('{0}{1} | author={2} | runas={3} | state={4}' -f $task.TaskPath, $task.TaskName, $author, $principal, $task.State))
            }
        }

        if ($flagged.Count -eq 0) {
            [void]$Lines.Add('No non-Microsoft task runs as SYSTEM or carries an unrecognised author.')
        }
        else {
            foreach ($f in ($flagged | Select-Object -Unique -First 40)) { [void]$Lines.Add(('- ' + $f)) }
        }
    }
    catch {
        [void]$Lines.Add(('Scheduled task check failed: {0}' -f $_.Exception.Message))
    }
    [void]$Lines.Add('')
}

function Add-DFIRTriageCollectionGaps {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][hashtable]$Context,
        [Parameter(Mandatory=$true)][AllowEmptyCollection()][System.Collections.ArrayList]$Lines
    )

    [void]$Lines.Add('## Collection gaps affecting the strength of negative findings')
    [void]$Lines.Add('')
    $gaps = New-Object System.Collections.ArrayList

    if (Test-Path -LiteralPath $Context.LogFile -PathType Leaf) {
        $log = Get-Content -LiteralPath $Context.LogFile -ErrorAction SilentlyContinue
        $warnCount = @($log | Where-Object { $_ -match '\[WARN\]' }).Count
        $errCount = @($log | Where-Object { $_ -match '\[ERROR\]' }).Count
        [void]$gaps.Add(('Collection.log recorded {0} warnings and {1} errors; review before relying on any negative finding.' -f $warnCount, $errCount))

        foreach ($line in $log) {
            if ($line -match 'is INSTALLED but no log path was found') { [void]$gaps.Add($line.Trim()) }
            if ($line -match 'Locked-file copy failed after all fallbacks') { [void]$gaps.Add($line.Trim()) }
            if ($line -match 'Collector root .* is inside YARA target') { [void]$gaps.Add($line.Trim()) }
            if ($line -match 'Output base .* is inside YARA target') { [void]$gaps.Add($line.Trim()) }
            if ($line -match 'YARA timed out after') { [void]$gaps.Add($line.Trim()) }
        }
    }

    $memoryCaptured = ($Context.ContainsKey('MemoryCaptured') -and $Context['MemoryCaptured'])
    if (-not $memoryCaptured) {
        [void]$gaps.Add('No memory image was captured; memory-resident implants cannot be excluded.')
    }
    $ntfsOk = ($Context.ContainsKey('NtfsAcquired') -and $Context['NtfsAcquired'])
    if ($ntfsOk) {
        [void]$gaps.Add('$MFT / $UsnJrnl were acquired for offline parsing (21_FileSystem) but are not parsed inline; run MFTECmd for a deleted-file timeline.')
    }
    else {
        [void]$gaps.Add('$MFT / $UsnJrnl were NOT acquired (VSS unavailable or non-elevated); deleted-file history is not reconstructable from this collection.')
    }
    if ((Get-DFIRCredentialStorePolicy -Context $Context) -eq 'MetadataOnly') {
        [void]$gaps.Add('Browser credential stores were recorded as metadata only (09_Browser\CredentialStoreMetadata.csv); their contents were not collected.')
    }
    else {
        [void]$gaps.Add('Browser credential stores were copied. Chromium values need the user''s DPAPI key to decrypt; Firefox logins.json + key4.db decrypt offline unless a Primary Password is set. Handle as sensitive.')
    }

    foreach ($gap in ($gaps | Select-Object -Unique)) { [void]$Lines.Add(('- ' + $gap)) }
    [void]$Lines.Add('')
}

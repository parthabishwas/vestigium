Set-StrictMode -Version 2.0

# ---------------------------------------------------------------------------
# Forensics.ps1 - NTFS and filesystem artifacts (21_FileSystem, plus hives,
# LNK/Jump Lists, Recycle Bin, Defender MPLog and clock offset).
#
# These are the artifacts a normal live collection cannot reach cleanly: $MFT
# and the USN journal (locked NTFS metadata) and the registry hives (locked by
# the running session) are acquired through a Volume Shadow Copy, so no
# reg-hive load is needed and deleted-file history becomes reconstructable
# offline. Everything degrades gracefully: a disabled VSS service, a
# non-elevated run or a missing artifact is logged, not fatal.
#
# UNTESTED ON WINDOWS in this repository's CI (no Windows host). See
# docs/WINDOWS-ARTIFACTS.md for the validation checklist.
# ---------------------------------------------------------------------------

function Invoke-DFIRForensicsCollection {
<#
.SYNOPSIS
    Acquires NTFS metadata, hives, user shell artifacts, Recycle Bin, MPLog and clock offset.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    Write-DFIRLog -Context $Context -Message 'Starting filesystem / NTFS artifact collection'
    $success = $true

    $success = (Invoke-DFIRVssAcquire -Context $Context) -and $success
    $success = (Invoke-DFIRScanDriveAcquire -Context $Context) -and $success
    $success = (Copy-DFIRUserShellArtifacts -Context $Context) -and $success
    $success = (Export-DFIRRecycleBin -Context $Context) -and $success
    $success = (Copy-DFIRDefenderMpLog -Context $Context) -and $success
    $success = (Export-DFIRClockOffset -Context $Context) -and $success
    $success = (Export-DFIRAlternateDataStreams -Context $Context) -and $success
    $success = (Export-DFIRStagingArchives -Context $Context) -and $success
    $success = (Copy-DFIRWerReports -Context $Context) -and $success

    Add-DFIRResult -Context $Context -Name 'Forensics' -Success $success
    return $success
}

function Get-DFIRForensicsTargetDirs {
<#
.SYNOPSIS
    High-signal, user-writable directories to sweep for ADS and staging archives.
.OUTPUTS
    System.String[]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    $dirs = New-Object System.Collections.ArrayList
    $profiles = @()
    if ($Context.ContainsKey('TargetProfiles') -and $Context['TargetProfiles']) { $profiles = @($Context['TargetProfiles']) }
    foreach ($profile in $profiles) {
        $pp = [string](Get-DFIRObjectProperty -InputObject $profile -Name 'ProfilePath')
        if (-not $pp) { continue }
        foreach ($sub in @('\Downloads', '\Desktop', '\Documents', '\AppData\Local\Temp')) {
            [void]$dirs.Add($pp + $sub)
        }
    }
    if ($env:ProgramData) { [void]$dirs.Add((Join-Path $env:ProgramData 'Temp')) }
    if ($env:SystemRoot)  { [void]$dirs.Add((Join-Path $env:SystemRoot 'Temp')) }
    if ($env:SystemDrive) { [void]$dirs.Add((Join-Path $env:SystemDrive 'Users\Public')) }
    return @($dirs | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Container) } | Select-Object -Unique)
}

function Export-DFIRAlternateDataStreams {
<#
.SYNOPSIS
    Records NTFS alternate data streams (Zone.Identifier download provenance and
    ADS-hidden payloads) under user-writable directories.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    $maxFiles = 40000
    $maxRows = 6000
    $seen = 0
    $rows = New-Object System.Collections.ArrayList
    foreach ($dir in (Get-DFIRForensicsTargetDirs -Context $Context)) {
        if ($rows.Count -ge $maxRows) { break }
        $files = @()
        try { $files = Get-ChildItem -LiteralPath $dir -Recurse -File -Force -ErrorAction SilentlyContinue }
        catch { $files = @() }
        foreach ($f in $files) {
            if ($seen -ge $maxFiles -or $rows.Count -ge $maxRows) { break }
            $seen++
            $streams = @()
            try { $streams = Get-Item -LiteralPath $f.FullName -Stream * -ErrorAction SilentlyContinue }
            catch { $streams = @() }
            foreach ($st in $streams) {
                $name = [string](Get-DFIRObjectProperty -InputObject $st -Name 'Stream')
                if (-not $name -or $name -eq ':$DATA') { continue }
                [void]$rows.Add([pscustomobject]@{
                    Path   = $f.FullName
                    Stream = $name
                    Length = (Get-DFIRObjectProperty -InputObject $st -Name 'Length')
                    Zone   = $(if ($name -eq 'Zone.Identifier') { 'download-mark' } else { '' })
                })
                if ($rows.Count -ge $maxRows) { break }
            }
        }
    }

    $out = Join-Path $Context.Paths.FileSystem 'AlternateDataStreams.csv'
    $data = @($rows)
    return Export-DFIRCsv -Context $Context -Name 'Alternate data streams' -Path $out -ScriptBlock ({ $data }.GetNewClosure())
}

function Export-DFIRStagingArchives {
<#
.SYNOPSIS
    Lists archive files in user-writable staging locations (collection/exfil prep).
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    $exts = '\.(zip|rar|7z|cab|tar|gz|tgz|bz2|iso|ace|arj)$'
    $maxRows = 5000
    $rows = New-Object System.Collections.ArrayList
    foreach ($dir in (Get-DFIRForensicsTargetDirs -Context $Context)) {
        if ($rows.Count -ge $maxRows) { break }
        $files = @()
        try { $files = Get-ChildItem -LiteralPath $dir -Recurse -File -Force -ErrorAction SilentlyContinue }
        catch { $files = @() }
        foreach ($f in $files) {
            if ($f.Name -notmatch $exts) { continue }
            [void]$rows.Add([pscustomobject]@{
                Path         = $f.FullName
                SizeBytes    = $f.Length
                LastWriteUtc = $f.LastWriteTimeUtc.ToString('o')
                CreatedUtc   = $f.CreationTimeUtc.ToString('o')
            })
            if ($rows.Count -ge $maxRows) { break }
        }
    }

    $out = Join-Path $Context.Paths.FileSystem 'StagingArchives.csv'
    $data = @($rows)
    return Export-DFIRCsv -Context $Context -Name 'Staging archives' -Path $out -ScriptBlock ({ $data }.GetNewClosure())
}

function Copy-DFIRWerReports {
<#
.SYNOPSIS
    Copies Windows Error Reporting metadata (Report.wer) - crash/injection
    evidence - without the large crash dumps.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    $destRoot = Join-Path $Context.Paths.FileSystem 'WER'
    $sources = New-Object System.Collections.ArrayList
    if ($env:ProgramData) { [void]$sources.Add((Join-Path $env:ProgramData 'Microsoft\Windows\WER')) }
    $profiles = @()
    if ($Context.ContainsKey('TargetProfiles') -and $Context['TargetProfiles']) { $profiles = @($Context['TargetProfiles']) }
    foreach ($profile in $profiles) {
        $la = [string](Get-DFIRObjectProperty -InputObject $profile -Name 'LocalAppData')
        if ($la) { [void]$sources.Add((Join-Path $la 'Microsoft\Windows\WER')) }
    }

    $count = 0
    foreach ($src in @($sources | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $src -PathType Container)) { continue }
        $wers = @()
        try { $wers = Get-ChildItem -LiteralPath $src -Recurse -File -Force -Filter '*.wer' -ErrorAction SilentlyContinue }
        catch { $wers = @() }
        foreach ($w in $wers) {
            $rel = $w.FullName
            if ($rel.Length -gt 3 -and $rel.Substring(1,1) -eq ':') { $rel = $rel.Substring(3) }
            $out = Join-Path $destRoot $rel
            if (Copy-DFIRFile -Context $Context -Source $w.FullName -Destination $out) { $count++ }
        }
    }
    Write-DFIRLog -Context $Context -Message ("WER report metadata copied: {0} .wer file(s)" -f $count)
    return $true
}

function New-DFIRShadowCopy {
<#
.SYNOPSIS
    Creates a ClientAccessible shadow copy of the system volume; returns its
    CIM instance (with .DeviceObject) or $null on failure.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    try {
        $volume = ($env:SystemDrive) + '\'
        $class = [wmiclass]'root\cimv2:Win32_ShadowCopy'
        $result = $class.Create($volume, 'ClientAccessible')
        if ($null -eq $result -or $result.ReturnValue -ne 0) {
            $rv = 'unknown'
            if ($result) { $rv = $result.ReturnValue }
            Write-DFIRLog -Context $Context -Level WARN -Message ("Shadow copy creation returned {0}; VSS artifacts unavailable" -f $rv)
            return $null
        }
        $shadow = Get-CimInstance -ClassName Win32_ShadowCopy -ErrorAction Stop |
            Where-Object { $_.ID -eq $result.ShadowID } | Select-Object -First 1
        if (-not $shadow) {
            Write-DFIRLog -Context $Context -Level WARN -Message 'Shadow copy created but could not be resolved'
            return $null
        }
        Write-DFIRLog -Context $Context -Message ("Shadow copy created: {0}" -f $shadow.DeviceObject)
        return $shadow
    }
    catch {
        Write-DFIRLog -Context $Context -Level WARN -Message ("Shadow copy creation failed ({0}); needs an elevated session and the VSS service" -f $_.Exception.Message)
        return $null
    }
}

function Remove-DFIRShadowCopy {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context, [Parameter(Mandatory=$true)]$Shadow)
    try {
        $Shadow | Remove-CimInstance -ErrorAction Stop
        Write-DFIRLog -Context $Context -Message 'Shadow copy deleted'
    }
    catch {
        try { & vssadmin.exe delete shadows ("/shadow=" + $Shadow.ID) /quiet 2>&1 | Out-Null }
        catch { Write-DFIRLog -Context $Context -Level WARN -Message ("Could not delete the shadow copy {0}; delete it manually with vssadmin" -f $Shadow.ID) }
    }
}

function Invoke-DFIRVssAcquire {
<#
.SYNOPSIS
    Via a shadow copy, acquires $MFT, $LogFile, the USN journal and the
    NTUSER.DAT / UsrClass.dat hives; deletes the shadow copy afterwards.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    $dest = $Context.Paths.FileSystem
    New-Item -ItemType Directory -Path $dest -Force -ErrorAction SilentlyContinue | Out-Null
    $lines = New-Object System.Collections.ArrayList
    [void]$lines.Add('NTFS metadata acquisition via Volume Shadow Copy')
    [void]$lines.Add('=================================================')
    [void]$lines.Add(('Generated: {0:o}' -f (Get-Date))); [void]$lines.Add('')

    $Context['NtfsAcquired'] = $false
    $shadow = New-DFIRShadowCopy -Context $Context
    if (-not $shadow) {
        [void]$lines.Add('Shadow copy: NOT AVAILABLE (VSS creation failed - see the collection log).')
        [void]$lines.Add('$MFT, $LogFile, the USN journal and locked hives were not acquired this way.')
        $note = Export-DFIRRawUsnFallback -Context $Context -Lines $lines   # try the live USN read anyway
        Write-DFIRAcquisitionNote -Context $Context -Dest $dest -Lines $lines
        return $true   # not fatal
    }

    $device = $shadow.DeviceObject   # \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN
    [void]$lines.Add(('Shadow device: {0}' -f $device)); [void]$lines.Add('')
    try {
        # NTFS metadata files. NTFS refuses to open these by name even on a
        # snapshot, so the built-in esentutl.exe (VSS-backed) is the primary
        # method; a raw backup-semantics handle on the snapshot is the fallback.
        $liveDrive = $env:SystemDrive                        # e.g. C:
        $metas = @(
            @{ Name = '$MFT';     Rel = '\$MFT';     Live = ($liveDrive + '\$MFT') },
            @{ Name = '$LogFile'; Rel = '\$LogFile'; Live = ($liveDrive + '\$LogFile') }
        )
        foreach ($m in $metas) {
            $out = Join-Path $dest ($m.Name.TrimStart('$'))   # 21_FileSystem\MFT, \LogFile
            if (Copy-DFIREsentutlVss -Context $Context -Source $m.Live -Destination $out) {
                [void]$lines.Add(('OK    {0} -> {1} (esentutl /vss)' -f $m.Name, (Split-Path -Leaf $out)))
            }
            elseif (Copy-DFIRRawFile -Context $Context -Source ($device + $m.Rel) -Destination $out) {
                [void]$lines.Add(('OK    {0} -> {1} (raw snapshot handle)' -f $m.Name, (Split-Path -Leaf $out)))
            }
            else {
                [void]$lines.Add(('FAIL  {0} (esentutl and raw snapshot handle both failed)' -f $m.Name))
            }
        }

        # USN journal: the $J data stream is sparse, so copy only its allocated
        # ranges; always also take an independent live fsutil read.
        $usnSrc = $device + '\$Extend\$UsnJrnl:$J'
        $usnLive = $env:SystemDrive + '\$Extend\$UsnJrnl:$J'
        $usnOut = Join-Path $dest 'UsnJrnl_J'
        if (Copy-DFIREsentutlVss -Context $Context -Source $usnLive -Destination $usnOut) {
            [void]$lines.Add('OK    $UsnJrnl:$J -> UsnJrnl_J (esentutl /vss)')
        }
        elseif (Copy-DFIRUsnJournal -Context $Context -Source $usnSrc -Destination $usnOut) {
            [void]$lines.Add('OK    $UsnJrnl:$J -> UsnJrnl_J (allocated ranges only)')
        }
        else {
            [void]$lines.Add('FAIL  $UsnJrnl:$J raw copy unavailable; using fsutil read only')
        }
        # Always also take an independent live fsutil read: proven, and useful
        # even when the raw $J copied cleanly.
        [void](Export-DFIRRawUsnFallback -Context $Context -Lines $lines)

        # Registry hives from the snapshot - no reg-hive load, no lock problem.
        # These drive ShellBags, UserAssist, RecentDocs and more, offline.
        $hiveRoot = Join-Path $Context.Paths.Registry 'Hives_VSS'
        $profiles = @()
        if ($Context.ContainsKey('TargetProfiles') -and $Context['TargetProfiles']) { $profiles = @($Context['TargetProfiles']) }
        $hiveCount = 0
        foreach ($profile in $profiles) {
            $rel = Get-DFIRShadowRelativePath -ProfilePath $profile.ProfilePath
            if (-not $rel) { continue }
            $userDest = Join-Path $hiveRoot (Get-DFIRSafeFileName -Value $profile.UserName)
            $hivePairs = @(
                @{ Src = ($device + $rel + '\NTUSER.DAT'); Name = 'NTUSER.DAT' },
                @{ Src = ($device + $rel + '\AppData\Local\Microsoft\Windows\UsrClass.dat'); Name = 'UsrClass.dat' }
            )
            foreach ($h in $hivePairs) {
                foreach ($suffix in @('', '.LOG1', '.LOG2')) {
                    $src = $h.Src + $suffix
                    $out = Join-Path $userDest ($h.Name + $suffix)
                    if (Copy-DFIRLockedFile -Context $Context -Source $src -Destination $out) {
                        if ($suffix -eq '') { $hiveCount++ }
                    }
                }
            }
        }
        [void]$lines.Add(('OK    registry hives from snapshot: {0} primary hive(s) -> {1}' -f $hiveCount, '05_Registry\Hives_VSS'))

        # Machine hives from the snapshot: SAM, SECURITY, SYSTEM, SOFTWARE (with
        # transaction logs). These enable offline local hash extraction, LSA
        # secrets, cached domain credentials and full SOFTWARE-hive persistence
        # parsing - none of which the live reg-export subtrees can provide.
        $machineDest = Join-Path $hiveRoot '_MACHINE'
        $configBase = $device + '\Windows\System32\config\'
        $machineCount = 0
        foreach ($hive in @('SAM', 'SECURITY', 'SYSTEM', 'SOFTWARE')) {
            foreach ($suffix in @('', '.LOG1', '.LOG2')) {
                $src = $configBase + $hive + $suffix
                $out = Join-Path $machineDest ($hive + $suffix)
                if (Copy-DFIRLockedFile -Context $Context -Source $src -Destination $out) {
                    if ($suffix -eq '') { $machineCount++ }
                }
            }
        }
        [void]$lines.Add(('OK    machine hives from snapshot: {0}/4 (SAM,SECURITY,SYSTEM,SOFTWARE) -> {1}' -f $machineCount, '05_Registry\Hives_VSS\_MACHINE'))
        $Context['NtfsAcquired'] = $true
    }
    catch {
        Write-DFIRLog -Context $Context -Level ERROR -Message ("VSS acquisition error: {0}" -f $_.Exception.Message)
        [void]$lines.Add(('ERROR during acquisition: {0}' -f $_.Exception.Message))
    }
    finally {
        Remove-DFIRShadowCopy -Context $Context -Shadow $shadow
    }

    [void]$lines.Add('')
    [void]$lines.Add('Parse offline, for example: MFTECmd.exe -f MFT --csv out; MFTECmd.exe -f UsnJrnl_J --csv out;')
    [void]$lines.Add('and load the hives with Registry Explorer / RECmd (ShellBags, UserAssist, RecentDocs).')
    [void]$lines.Add('Machine hives (SAM+SYSTEM, SECURITY+SYSTEM) parse offline with secretsdump.py / impacket or samdump2 for local hashes, cached domain creds and LSA secrets.')
    Write-DFIRAcquisitionNote -Context $Context -Dest $dest -Lines $lines
    return $true
}

function Get-DFIRShadowRelativePath {
<#
.SYNOPSIS
    Turns C:\Users\bob into the \Users\bob suffix used against a shadow device
    (only same-volume profiles on the system drive are handled).
.OUTPUTS
    System.String  (empty when the profile is not on the system volume)
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$ProfilePath)
    $sysDrive = $env:SystemDrive
    if ($ProfilePath.Length -lt 2 -or $ProfilePath.Substring(1,1) -ne ':') { return '' }
    if (-not $ProfilePath.ToUpper().StartsWith($sysDrive.ToUpper())) { return '' }
    return $ProfilePath.Substring(2).TrimEnd('\')
}

function Export-DFIRRawUsnFallback {
<#
.SYNOPSIS
    Live USN journal read via fsutil (used when the $J stream copy is unavailable).
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context,
          [Parameter(Mandatory=$true)][AllowEmptyCollection()][System.Collections.ArrayList]$Lines,
          [string]$Drive = '',
          [string]$DestDir = '')
    $ok = $true
    $drive = if ([string]::IsNullOrWhiteSpace($Drive)) { $env:SystemDrive } else { $Drive.TrimEnd('\') }
    $dir = if ([string]::IsNullOrWhiteSpace($DestDir)) { $Context.Paths.FileSystem } else { $DestDir }
    $query = Join-Path $dir 'UsnJrnl_query.txt'
    $ok = (Invoke-DFIRSafeCommand -Context $Context -Name ('fsutil usn queryjournal {0}' -f $drive) -OutputPath $query -FilePath 'fsutil.exe' -Arguments @('usn','queryjournal',$drive)) -and $ok
    $read = Join-Path $dir 'UsnJrnl_readjournal.csv'
    $ok = (Invoke-DFIRSafeCommand -Context $Context -Name ('fsutil usn readjournal {0}' -f $drive) -OutputPath $read -FilePath 'fsutil.exe' -Arguments @('usn','readjournal',$drive,'csv')) -and $ok
    [void]$Lines.Add('      (live fsutil usn queryjournal + readjournal written to UsnJrnl_query.txt / UsnJrnl_readjournal.csv)')
    return $ok
}

function Invoke-DFIRScanDriveAcquire {
<#
.SYNOPSIS
    Acquires NTFS metadata ($MFT, $LogFile, USN journal) from each -ScanDrives
    volume into 21_FileSystem\<letter>\.
.DESCRIPTION
    esentutl.exe /y /vss creates and releases its own shadow copy per source, so
    each requested volume is handled without managing a shadow here. A live
    fsutil USN read is always taken as an independent copy. Registry hives are
    not pulled from these drives (user profiles live on the system drive); the
    Recycle Bin of every fixed drive is already covered by Export-DFIRRecycleBin.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    $drives = if ($Context.ContainsKey('ScanDrives')) { @($Context['ScanDrives']) } else { @() }
    if (-not $drives -or $drives.Count -eq 0) { return $true }

    foreach ($id in $drives) {
        $letter = $id.TrimEnd(':')
        $dest = Join-Path $Context.Paths.FileSystem $letter
        New-Item -ItemType Directory -Path $dest -Force -ErrorAction SilentlyContinue | Out-Null
        $lines = New-Object System.Collections.ArrayList
        [void]$lines.Add(('NTFS metadata acquisition for volume {0} (-ScanDrives)' -f $id))
        [void]$lines.Add('======================================================')
        [void]$lines.Add(('Generated: {0:o}' -f (Get-Date))); [void]$lines.Add('')

        $metas = @(
            @{ Name = '$MFT';     Live = ($id + '\$MFT');     Out = (Join-Path $dest 'MFT') },
            @{ Name = '$LogFile'; Live = ($id + '\$LogFile'); Out = (Join-Path $dest 'LogFile') }
        )
        foreach ($m in $metas) {
            if (Copy-DFIREsentutlVss -Context $Context -Source $m.Live -Destination $m.Out) {
                [void]$lines.Add(('OK    {0} -> {1}\{2} (esentutl /vss)' -f $m.Name, $letter, (Split-Path -Leaf $m.Out)))
            }
            else {
                [void]$lines.Add(('FAIL  {0} (esentutl /vss copy failed)' -f $m.Name))
            }
        }

        $usnLive = $id + '\$Extend\$UsnJrnl:$J'
        $usnOut = Join-Path $dest 'UsnJrnl_J'
        if (Copy-DFIREsentutlVss -Context $Context -Source $usnLive -Destination $usnOut) {
            [void]$lines.Add(('OK    $UsnJrnl:$J -> {0}\UsnJrnl_J (esentutl /vss)' -f $letter))
        }
        else {
            [void]$lines.Add('FAIL  $UsnJrnl:$J raw copy unavailable; using fsutil read only')
        }
        [void](Export-DFIRRawUsnFallback -Context $Context -Lines $lines -Drive $id -DestDir $dest)

        [void]$lines.Add('')
        [void]$lines.Add('Parse offline, for example: MFTECmd.exe -f MFT --csv out; MFTECmd.exe -f UsnJrnl_J --csv out;')
        Write-DFIRAcquisitionNote -Context $Context -Dest $dest -Lines $lines
    }
    return $true
}

function Write-DFIRAcquisitionNote {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context, [Parameter(Mandatory=$true)][string]$Dest,
          [Parameter(Mandatory=$true)][AllowEmptyCollection()][System.Collections.ArrayList]$Lines)
    $path = Join-Path $Dest '_ACQUISITION.txt'
    try {
        $enc = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($path, (($Lines -join "`r`n") + "`r`n"), $enc)
        Add-DFIRCollectedFile -Context $Context -Path $path
    }
    catch { Write-DFIRLog -Context $Context -Level WARN -Message ("Could not write acquisition note: {0}" -f $_.Exception.Message) }
}

function Copy-DFIRUserShellArtifacts {
<#
.SYNOPSIS
    Copies LNK shortcuts and Jump Lists per profile into 17_Execution\UserArtifacts.
.DESCRIPTION
    Recent .lnk files and the AutomaticDestinations / CustomDestinations Jump
    Lists record files and folders the user opened, with embedded target paths,
    volume serials and timestamps - a rich picture of user activity.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    $profiles = @()
    if ($Context.ContainsKey('TargetProfiles') -and $Context['TargetProfiles']) { $profiles = @($Context['TargetProfiles']) }
    $index = New-Object System.Collections.ArrayList
    $root = Join-Path $Context.Paths.Execution 'UserArtifacts'

    foreach ($profile in $profiles) {
        $recent = Join-Path $profile.AppData 'Microsoft\Windows\Recent'
        $sources = @(
            @{ Kind = 'lnk';       Path = $recent;                                          Filter = '*.lnk' },
            @{ Kind = 'jumplist';  Path = (Join-Path $recent 'AutomaticDestinations');      Filter = '*.automaticDestinations-ms' },
            @{ Kind = 'jumplist';  Path = (Join-Path $recent 'CustomDestinations');         Filter = '*.customDestinations-ms' },
            @{ Kind = 'office';    Path = (Join-Path $profile.AppData 'Microsoft\Office\Recent'); Filter = '*.lnk' }
        )
        $userDest = Join-Path $root (Get-DFIRSafeFileName -Value $profile.UserName)
        foreach ($s in $sources) {
            if (-not (Test-Path -LiteralPath $s.Path -PathType Container)) { continue }
            $files = @(Get-ChildItem -LiteralPath $s.Path -Filter $s.Filter -File -Force -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 500)
            foreach ($f in $files) {
                $out = Join-Path (Join-Path $userDest $s.Kind) $f.Name
                if (Copy-DFIRLockedFile -Context $Context -Source $f.FullName -Destination $out) {
                    [void]$index.Add([pscustomobject]@{
                        User = $profile.UserName; Kind = $s.Kind; Name = $f.Name
                        SizeBytes = $f.Length
                        CreatedUtc = $f.CreationTimeUtc.ToString('o')
                        ModifiedUtc = $f.LastWriteTimeUtc.ToString('o')
                        Source = $f.FullName
                    })
                }
            }
        }
    }

    if ($index.Count -gt 0) {
        $csv = Join-Path $root 'index.csv'
        try {
            $index | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8 -Force
            Add-DFIRCollectedFile -Context $Context -Path $csv
        }
        catch { Write-DFIRLog -Context $Context -Level WARN -Message ("Shell-artifact index write failed: {0}" -f $_.Exception.Message) }
        Write-DFIRLog -Context $Context -Message ("Shell artifacts collected: {0} LNK / Jump List file(s)" -f $index.Count)
    }
    else {
        Write-DFIRLog -Context $Context -Message 'No LNK / Jump List artifacts found for the target profiles'
    }
    return $true
}

function Export-DFIRRecycleBin {
<#
.SYNOPSIS
    Copies Recycle Bin $I index files and lists $I/$R pairs (metadata only).
.DESCRIPTION
    Each $I file records a deleted item's original path, size and deletion time.
    The $R data blobs are deliberately not copied (potentially huge).
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    $dest = Join-Path $Context.Paths.FileSystem 'RecycleBin'
    $index = New-Object System.Collections.ArrayList
    $drives = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction SilentlyContinue |
        ForEach-Object { $_.DeviceID })
    if (-not $drives) { $drives = @($env:SystemDrive) }

    foreach ($drive in $drives) {
        $bin = Join-Path ($drive + '\') '$Recycle.Bin'
        if (-not (Test-Path -LiteralPath $bin -PathType Container)) { continue }
        foreach ($sidDir in @(Get-ChildItem -LiteralPath $bin -Directory -Force -ErrorAction SilentlyContinue)) {
            $sid = $sidDir.Name
            foreach ($iFile in @(Get-ChildItem -LiteralPath $sidDir.FullName -Filter '$I*' -File -Force -ErrorAction SilentlyContinue)) {
                $out = Join-Path (Join-Path $dest (Get-DFIRSafeFileName -Value $sid)) $iFile.Name
                $rName = '$R' + $iFile.Name.Substring(2)
                $rPath = Join-Path $sidDir.FullName $rName
                $rSize = $null
                if (Test-Path -LiteralPath $rPath -PathType Leaf) {
                    $rItem = Get-Item -LiteralPath $rPath -Force -ErrorAction SilentlyContinue
                    if ($rItem) { $rSize = $rItem.Length }
                }
                Copy-DFIRLockedFile -Context $Context -Source $iFile.FullName -Destination $out | Out-Null
                [void]$index.Add([pscustomobject]@{
                    SID = $sid; IndexFile = $iFile.Name; RDataFile = $rName
                    RDataSizeBytes = $rSize
                    DeletedRecordUtc = $iFile.LastWriteTimeUtc.ToString('o')
                    Drive = $drive
                })
            }
        }
    }

    if ($index.Count -gt 0) {
        $csv = Join-Path $dest 'index.csv'
        try {
            New-Item -ItemType Directory -Path $dest -Force -ErrorAction SilentlyContinue | Out-Null
            $index | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8 -Force
            Add-DFIRCollectedFile -Context $Context -Path $csv
        }
        catch { Write-DFIRLog -Context $Context -Level WARN -Message ("Recycle Bin index write failed: {0}" -f $_.Exception.Message) }
        Write-DFIRLog -Context $Context -Message ("Recycle Bin: {0} deleted-item record(s) indexed (parse the $I files with a tool for the original paths)" -f $index.Count)
    }
    else {
        Write-DFIRLog -Context $Context -Message 'Recycle Bin: no $I index files found'
    }
    return $true
}

function Copy-DFIRDefenderMpLog {
<#
.SYNOPSIS
    Copies the most recent Microsoft Defender MPLog / MPDetection files.
.DESCRIPTION
    MPLog records every file Defender's real-time engine scanned, with full
    paths and timestamps - often the only record that a since-deleted binary
    ran, even when Defender did not flag it.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    $support = Join-Path $env:ProgramData 'Microsoft\Windows Defender\Support'
    if (-not (Test-Path -LiteralPath $support -PathType Container)) {
        Write-DFIRLog -Context $Context -Message 'Defender MPLog: Support directory not present'
        return $true
    }
    $dest = Join-Path $Context.Paths.Defender 'MPLog'
    $files = @(Get-ChildItem -LiteralPath $support -File -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like 'MPLog-*' -or $_.Name -like 'MPDetection-*' } |
        Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 20)
    $count = 0
    foreach ($f in $files) {
        if (Copy-DFIRLockedFile -Context $Context -Source $f.FullName -Destination (Join-Path $dest $f.Name)) { $count++ }
    }
    Write-DFIRLog -Context $Context -Message ("Defender MPLog: {0} file(s) copied" -f $count)
    return $true
}

function Export-DFIRClockOffset {
<#
.SYNOPSIS
    Records the host clock, time source and any sync offset (w32tm).
.DESCRIPTION
    Every timestamp in the evidence is only as good as this clock. A skewed or
    Local-CMOS-only clock on a domain host must be known so timelines can be
    corrected and cross-host correlation stays honest.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    $out = Join-Path $Context.Paths.System 'ClockOffset.txt'
    return Save-DFIRText -Context $Context -Name 'ClockOffset' -Path $out -ScriptBlock {
        $local = Get-Date
        $utc = [DateTime]::UtcNow
        'Clock at collection time'
        '========================'
        ('Local time : {0:o}' -f $local)
        ('UTC time   : {0:o}' -f $utc)
        ('TimeZone   : {0}' -f ([System.TimeZoneInfo]::Local.Id))
        ''
        'w32tm /query /status'
        '--------------------'
        try { & w32tm.exe /query /status 2>&1 } catch { ('(w32tm status unavailable: {0})' -f $_.Exception.Message) }
        ''
        'w32tm /query /configuration'
        '---------------------------'
        try { & w32tm.exe /query /configuration 2>&1 } catch { ('(w32tm configuration unavailable: {0})' -f $_.Exception.Message) }
        ''
        'Interpretation: a large "Phase Offset", a stale "Last Successful Sync Time",'
        'or a "Source: Local CMOS Clock" on a domain-joined host means recorded'
        'timestamps may be skewed - note the offset when building the timeline.'
    }
}

Set-StrictMode -Version 2.0

function Test-DFIRAdministrator {
<#
.SYNOPSIS
    Determines whether the current PowerShell session is elevated.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param()

    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

function Get-DFIROperator {
<#
.SYNOPSIS
    Returns the DOMAIN\user identity running the collector.
.OUTPUTS
    System.String
#>
    [CmdletBinding()]
    param()

    try {
        $name = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        if (-not [string]::IsNullOrWhiteSpace($name)) { return $name }
    }
    catch { }
    return ('{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME)
}

function Write-DFIRLog {
<#
.SYNOPSIS
    Writes a timestamped entry to Collection.log and optionally to verbose output.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][hashtable]$Context,
        [Parameter(Mandatory=$true)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR','SUCCESS')][string]$Level = 'INFO'
    )

    try {
        $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'), $Level, $Message
        if ($Context.ContainsKey('LogFile') -and $Context.LogFile) {
            Add-Content -Path $Context.LogFile -Value $line -Encoding UTF8 -ErrorAction Stop
        }
        Write-Verbose $line
    }
    catch {
        Write-Verbose ("Logging failed: {0}" -f $_.Exception.Message)
    }
}

function New-DFIRDirectoryTree {
<#
.SYNOPSIS
    Creates the standard Vestigium Windows output directory structure.
.DESCRIPTION
    20_Memory is returned as a path but only created when memory acquisition
    runs, so collections without a memory image keep the v1.1 layout.
.OUTPUTS
    Hashtable mapping logical names to paths.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$RootPath
    )

    $dirs = [ordered]@{
        System         = '01_System'
        Processes      = '02_Processes'
        Autoruns       = '03_Autoruns'
        Startup        = '04_Startup'
        Registry       = '05_Registry'
        ScheduledTasks = '06_ScheduledTasks'
        Services       = '07_Services'
        Network        = '08_Network'
        Browser        = '09_Browser'
        EventLogs      = '10_EventLogs'
        Hosts          = '11_Hosts'
        Defender       = '12_Defender'
        SystemInfo     = '13_SystemInfo'
        Logs           = '14_Logs'
        Hashes         = '15_Hashes'
        Manifest       = '16_Manifest'
        Execution      = '17_Execution'
        Devices        = '18_Devices'
        Triage         = '19_Triage'
        FileSystem     = '21_FileSystem'
    }

    $paths = @{}
    New-Item -ItemType Directory -Path $RootPath -Force -ErrorAction Stop | Out-Null
    foreach ($key in $dirs.Keys) {
        $path = Join-Path $RootPath $dirs[$key]
        New-Item -ItemType Directory -Path $path -Force -ErrorAction Stop | Out-Null
        $paths[$key] = $path
    }
    $paths['Memory'] = Join-Path $RootPath '20_Memory'
    return $paths
}

function Initialize-DFIRContext {
<#
.SYNOPSIS
    Builds the collection context shared by all modules.
.PARAMETER ScriptRoot
    Folder holding vestigium-windows.ps1 (Modules and Tools live below it).
.PARAMETER KitRoot
    Vestigium kit root (holds VERSION, shared\ and output\). Defaults to ScriptRoot.
.PARAMETER OutputBase
    Evidence base folder. Defaults to <KitRoot>\output.
.PARAMETER CaseId
    Case identifier. When empty an AUTO-<COMPUTERNAME>-<timestamp> value is generated.
.OUTPUTS
    Hashtable
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$ScriptRoot,
        [string]$KitRoot = '',
        [string]$OutputBase = '',
        [string]$CollectorVersion = '2.0.0',
        [string]$CaseId = ''
    )

    if ([string]::IsNullOrWhiteSpace($KitRoot)) { $KitRoot = $ScriptRoot }
    if ([string]::IsNullOrWhiteSpace($OutputBase)) { $OutputBase = Join-Path $KitRoot 'output' }

    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $safeUser = $env:USERNAME
    if ([string]::IsNullOrWhiteSpace($safeUser)) { $safeUser = 'UnknownUser' }

    New-Item -ItemType Directory -Path $OutputBase -Force -ErrorAction Stop | Out-Null
    # Resolve to a full path so self-match suppression and relative-path
    # arithmetic work even when -OutputPath was given relative to the caller.
    $OutputBase = (Resolve-Path -LiteralPath $OutputBase -ErrorAction Stop).ProviderPath

    $rootName = '{0}_{1}_{2}' -f $env:COMPUTERNAME, $safeUser, $timestamp
    $outputRoot = Join-Path $OutputBase $rootName
    $paths = New-DFIRDirectoryTree -RootPath $outputRoot
    $logFile = Join-Path $paths.Logs 'Collection.log'
    New-Item -ItemType File -Path $logFile -Force -ErrorAction Stop | Out-Null

    $caseIdSource = 'supplied with -CaseId'
    if ([string]::IsNullOrWhiteSpace($CaseId)) {
        $CaseId = 'AUTO-{0}-{1}' -f $env:COMPUTERNAME, $timestamp
        $caseIdSource = 'auto-generated (no -CaseId supplied)'
    }

    return @{
        ScriptRoot       = $ScriptRoot
        KitRoot          = $KitRoot
        ToolsPath        = Join-Path $ScriptRoot 'Tools'
        OutputBase       = $OutputBase
        OutputRoot       = $outputRoot
        Timestamp        = $timestamp
        CollectorVersion = $CollectorVersion
        CaseId           = $CaseId.Trim()
        CaseIdSource     = $caseIdSource
        Operator         = Get-DFIROperator
        Paths            = $paths
        LogFile          = $logFile
        CommandLog       = Join-Path $paths.Logs 'CommandLog.csv'
        ProvenanceLog    = Join-Path $paths.Logs 'Provenance.csv'
        CommandLogCount  = 0
        ProvenanceCount  = 0
        StartTime        = Get-Date
        CollectedFiles   = New-Object System.Collections.ArrayList
        Results          = New-Object System.Collections.ArrayList
    }
}

function ConvertTo-DFIRSplitList {
<#
.SYNOPSIS
    Flattens comma-separated entries into a trimmed string array.
.DESCRIPTION
    powershell.exe -File passes an array parameter as ONE string such as
    "alice,bob". Splitting here keeps -TargetUser and -Modules working the same
    whether the launcher is called in-process or through -File.
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

function ConvertTo-DFIRArgument {
<#
.SYNOPSIS
    Quotes one argument for a Windows command line (CommandLineToArgvW rules).
.DESCRIPTION
    Start-Process -ArgumentList joins array elements with spaces and adds no
    quoting on Windows PowerShell 5.1, so a path such as C:\Users\John Doe
    becomes two arguments. Arguments containing whitespace or quotes are wrapped
    in double quotes; embedded quotes are escaped, and backslashes are doubled
    only where they precede a quote or the closing quote.
.OUTPUTS
    System.String
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][AllowEmptyString()][string]$Value)

    if ($Value.Length -eq 0) { return '""' }
    if ($Value -notmatch '[\s"]') { return $Value }

    $builder = New-Object System.Text.StringBuilder
    [void]$builder.Append('"')
    $backslashes = 0
    foreach ($ch in $Value.ToCharArray()) {
        if ($ch -eq '\') {
            $backslashes++
            continue
        }
        if ($ch -eq '"') {
            [void]$builder.Append(('\' * (($backslashes * 2) + 1)))
            [void]$builder.Append('"')
        }
        else {
            if ($backslashes -gt 0) { [void]$builder.Append(('\' * $backslashes)) }
            [void]$builder.Append($ch)
        }
        $backslashes = 0
    }
    if ($backslashes -gt 0) { [void]$builder.Append(('\' * ($backslashes * 2))) }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function Join-DFIRArguments {
<#
.SYNOPSIS
    Builds a single, correctly quoted argument string for Start-Process.
.OUTPUTS
    System.String
#>
    [CmdletBinding()]
    param([AllowEmptyCollection()][string[]]$Arguments = @())

    $quoted = foreach ($argument in @($Arguments)) {
        if ($null -eq $argument) { continue }
        ConvertTo-DFIRArgument -Value $argument
    }
    return (@($quoted) -join ' ')
}

function Get-DFIRFileSha256 {
<#
.SYNOPSIS
    Hashes a file through a shared-read stream so write-locked files can be hashed.
.OUTPUTS
    System.String (upper-case hex, same format as Get-FileHash), or $null on failure.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Path)

    $stream = $null
    $sha = $null
    try {
        $share = [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete
        $stream = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, $share)
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $bytes = $sha.ComputeHash($stream)
        return ([System.BitConverter]::ToString($bytes) -replace '-', '')
    }
    catch {
        return $null
    }
    finally {
        if ($stream) { $stream.Dispose() }
        if ($sha) { $sha.Dispose() }
    }
}

function Get-DFIRFileSnapshot {
<#
.SYNOPSIS
    Captures size, timestamps and attributes of a source file before it is touched.
.OUTPUTS
    PSCustomObject, or $null when the file cannot be read.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Path)

    try {
        $info = New-Object System.IO.FileInfo($Path)
        if (-not $info.Exists) { return $null }
        return [pscustomobject]@{
            SizeBytes         = $info.Length
            CreationTimeUtc   = $info.CreationTimeUtc
            LastWriteTimeUtc  = $info.LastWriteTimeUtc
            LastAccessTimeUtc = $info.LastAccessTimeUtc
            Attributes        = $info.Attributes.ToString()
        }
    }
    catch {
        return $null
    }
}

function Get-DFIRRelativeEvidencePath {
<#
.SYNOPSIS
    Returns a path relative to the collection root, or the full path when outside it.
.OUTPUTS
    System.String
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][hashtable]$Context,
        [Parameter(Mandatory=$true)][string]$Path
    )

    $root = $Context.OutputRoot.TrimEnd('\') + '\'
    if ($Path.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $Path.Substring($root.Length)
    }
    return $Path
}

function Add-DFIRCsvRecord {
<#
.SYNOPSIS
    Appends one record to a CSV log (header written on first use).
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][object]$Record
    )

    try {
        $Record | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8 -Append -Force -ErrorAction Stop
        return $true
    }
    catch {
        Write-Verbose ("CSV append failed for {0}: {1}" -f $Path, $_.Exception.Message)
        return $false
    }
}

function Add-DFIRCommandRecord {
<#
.SYNOPSIS
    Records one executed command in 14_Logs\CommandLog.csv.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][hashtable]$Context,
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][AllowEmptyString()][string]$Command,
        [AllowEmptyString()][string]$ExitCode = '',
        [double]$DurationSeconds = 0,
        [AllowEmptyString()][string]$OutputFile = ''
    )

    if (-not ($Context.ContainsKey('CommandLog') -and $Context.CommandLog)) { return }
    $relative = ''
    if (-not [string]::IsNullOrWhiteSpace($OutputFile)) { $relative = Get-DFIRRelativeEvidencePath -Context $Context -Path $OutputFile }
    $record = [pscustomobject][ordered]@{
        Timestamp       = (Get-Date).ToUniversalTime().ToString('o')
        Name            = $Name
        Command         = $Command
        ExitCode        = $ExitCode
        DurationSeconds = [math]::Round($DurationSeconds, 3)
        OutputFile      = $relative
    }
    if (Add-DFIRCsvRecord -Path $Context.CommandLog -Record $record) {
        $Context['CommandLogCount'] = [int]$Context['CommandLogCount'] + 1
    }
}

function Add-DFIRProvenance {
<#
.SYNOPSIS
    Records source metadata and the evidence-copy hash in 14_Logs\Provenance.csv.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][hashtable]$Context,
        [Parameter(Mandatory=$true)][string]$Source,
        [Parameter(Mandatory=$true)][string]$Destination,
        [AllowNull()][object]$Snapshot,
        [Parameter(Mandatory=$true)][ValidateSet('CopyItem','SharedRead','RobocopyBackup','RawBackup')][string]$CopyMethod
    )

    if (-not ($Context.ContainsKey('ProvenanceLog') -and $Context.ProvenanceLog)) { return }
    $record = [pscustomobject][ordered]@{
        Timestamp         = (Get-Date).ToUniversalTime().ToString('o')
        SourcePath        = $Source
        EvidencePath      = Get-DFIRRelativeEvidencePath -Context $Context -Path $Destination
        SizeBytes         = Get-DFIRObjectProperty -InputObject $Snapshot -Name 'SizeBytes'
        CreationTimeUtc   = ''
        LastWriteTimeUtc  = ''
        LastAccessTimeUtc = ''
        Attributes        = Get-DFIRObjectProperty -InputObject $Snapshot -Name 'Attributes'
        SHA256            = Get-DFIRFileSha256 -Path $Destination
        CopyMethod        = $CopyMethod
    }
    foreach ($field in @('CreationTimeUtc','LastWriteTimeUtc','LastAccessTimeUtc')) {
        $value = Get-DFIRObjectProperty -InputObject $Snapshot -Name $field
        if ($value) { $record.$field = ([datetime]$value).ToString('o') }
    }
    if (Add-DFIRCsvRecord -Path $Context.ProvenanceLog -Record $record) {
        $Context['ProvenanceCount'] = [int]$Context['ProvenanceCount'] + 1
    }
}

function Get-DFIRProfileObject {
<#
.SYNOPSIS
    Builds the profile object consumed by user-scoped collection modules.
.OUTPUTS
    PSCustomObject
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$ProfilePath,
        [string]$UserName = '',
        [string]$SID = ''
    )

    # String concatenation, not Join-Path: Join-Path throws "Cannot find drive"
    # for a ProfileList entry on a drive letter that is not currently mounted.
    $path = $ProfilePath.TrimEnd('\')
    if ([string]::IsNullOrWhiteSpace($UserName)) { $UserName = ($path -split '\\')[-1] }
    return [pscustomobject]@{
        UserName     = $UserName
        SID          = $SID
        ProfilePath  = $path
        LocalAppData = $path + '\AppData\Local'
        AppData      = $path + '\AppData\Roaming'
        Temp         = $path + '\AppData\Local\Temp'
        Desktop      = $path + '\Desktop'
        Downloads    = $path + '\Downloads'
        Startup      = $path + '\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'
        NTUserDat    = $path + '\NTUSER.DAT'
    }
}

function Get-DFIRProfileListEntries {
<#
.SYNOPSIS
    Reads HKLM ProfileList so relocated profiles (e.g. D:\Users\x) are found.
.OUTPUTS
    PSCustomObject with SID and ProfilePath.
#>
    [CmdletBinding()]
    param()

    $root = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    $entries = New-Object System.Collections.ArrayList
    try {
        foreach ($key in (Get-ChildItem -LiteralPath $root -ErrorAction Stop)) {
            try {
                $raw = (Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction Stop).PSObject.Properties['ProfileImagePath']
                if (-not $raw -or [string]::IsNullOrWhiteSpace([string]$raw.Value)) { continue }
                [void]$entries.Add([pscustomobject]@{
                    SID         = ($key.PSChildName -replace '\.bak$', '')
                    ProfilePath = [Environment]::ExpandEnvironmentVariables([string]$raw.Value).TrimEnd('\')
                })
            }
            catch { }
        }
    }
    catch { }
    return @($entries)
}

function Test-DFIRServiceSid {
<#
.SYNOPSIS
    True for the LocalSystem, LocalService and NetworkService SIDs.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$SID)

    return ($SID -in @('S-1-5-18','S-1-5-19','S-1-5-20'))
}

function Find-DFIRProfileListEntry {
<#
.SYNOPSIS
    Looks up a ProfileList entry by SID, profile path, or profile folder name.
.OUTPUTS
    PSCustomObject or $null
#>
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()][object[]]$Entries = @(),
        [string]$SID = '',
        [string]$Path = '',
        [string]$LeafName = ''
    )

    foreach ($entry in @($Entries)) {
        if ($null -eq $entry) { continue }
        if ($SID -and $entry.SID -eq $SID) { return $entry }
        if ($Path -and ($entry.ProfilePath.TrimEnd('\') -eq $Path.TrimEnd('\'))) { return $entry }
        if ($LeafName -and ((($entry.ProfilePath.TrimEnd('\')) -split '\\')[-1] -eq $LeafName)) { return $entry }
    }
    return $null
}

function Merge-DFIRProfileCandidates {
<#
.SYNOPSIS
    De-duplicates profile candidates by path and drops service accounts and shells.
.DESCRIPTION
    Candidates come from %SystemDrive%\Users and ProfileList. The same profile
    appears in both, so entries are merged on a case-insensitive path; a SID from
    either source is kept.
.OUTPUTS
    PSCustomObject[]
#>
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()][object[]]$Candidates = @(),
        [string[]]$ExcludedNames = @('All Users','Default','Default User','Public','desktop.ini')
    )

    $byPath = [ordered]@{}
    foreach ($candidate in @($Candidates)) {
        if ($null -eq $candidate) { continue }
        $path = [string](Get-DFIRObjectProperty -InputObject $candidate -Name 'ProfilePath')
        if ([string]::IsNullOrWhiteSpace($path)) { continue }
        $path = $path.TrimEnd('\')
        $sid = [string](Get-DFIRObjectProperty -InputObject $candidate -Name 'SID')
        if (Test-DFIRServiceSid -SID $sid) { continue }
        $leaf = ($path -split '\\')[-1]
        if ($leaf -in $ExcludedNames) { continue }
        $key = $path.ToLowerInvariant()
        if ($byPath.Contains($key)) {
            if ([string]::IsNullOrWhiteSpace($byPath[$key].SID) -and -not [string]::IsNullOrWhiteSpace($sid)) {
                $byPath[$key].SID = $sid
            }
            continue
        }
        $byPath[$key] = Get-DFIRProfileObject -ProfilePath $path -SID $sid
    }
    return @($byPath.Values)
}

function Resolve-DFIRTargetSpec {
<#
.SYNOPSIS
    Resolves one -TargetUser value to a profile candidate.
.DESCRIPTION
    Accepts a SID, a full profile path, a user name or DOMAIN\name (translated
    to a SID and looked up in ProfileList), or a profile folder name under
    %SystemDrive%\Users. Returns $null when nothing matches.
.OUTPUTS
    PSCustomObject or $null
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Target,
        [AllowEmptyCollection()][object[]]$ProfileList = @(),
        [string]$UsersRoot = ''
    )

    $candidate = $Target.Trim()
    if ($candidate -match '^S-1-\d+(-\d+)+$') {
        $entry = Find-DFIRProfileListEntry -Entries $ProfileList -SID $candidate
        if ($entry) { return [pscustomobject]@{ ProfilePath = $entry.ProfilePath; SID = $entry.SID } }
        return $null
    }

    if (($candidate -match '^[A-Za-z]:\\' -or $candidate.StartsWith('\\')) -and (Test-Path -LiteralPath $candidate -PathType Container)) {
        $entry = Find-DFIRProfileListEntry -Entries $ProfileList -Path $candidate
        $sid = ''
        if ($entry) { $sid = $entry.SID }
        return [pscustomobject]@{ ProfilePath = $candidate.TrimEnd('\'); SID = $sid }
    }

    $sidValue = ''
    try {
        $account = New-Object System.Security.Principal.NTAccount($candidate)
        $sidValue = $account.Translate([System.Security.Principal.SecurityIdentifier]).Value
    }
    catch { $sidValue = '' }
    if ($sidValue) {
        $entry = Find-DFIRProfileListEntry -Entries $ProfileList -SID $sidValue
        if ($entry -and (Test-Path -LiteralPath $entry.ProfilePath -PathType Container)) {
            return [pscustomobject]@{ ProfilePath = $entry.ProfilePath; SID = $entry.SID }
        }
    }

    $leaf = ($candidate -split '\\')[-1]
    if ($UsersRoot) {
        $guess = Join-Path $UsersRoot $leaf
        if (Test-Path -LiteralPath $guess -PathType Container) {
            $entry = Find-DFIRProfileListEntry -Entries $ProfileList -Path $guess
            $sid = $sidValue
            if ($entry) { $sid = $entry.SID }
            return [pscustomobject]@{ ProfilePath = $guess; SID = $sid }
        }
    }

    # Relocated profile whose account can no longer be translated (deleted or
    # offline domain account): match the ProfileList folder name.
    $entry = Find-DFIRProfileListEntry -Entries $ProfileList -LeafName $leaf
    if ($entry -and (Test-Path -LiteralPath $entry.ProfilePath -PathType Container)) {
        return [pscustomobject]@{ ProfilePath = $entry.ProfilePath; SID = $entry.SID }
    }
    return $null
}

function Resolve-DFIRTargetProfiles {
<#
.SYNOPSIS
    Resolves target user profiles for user-scoped artifact collection.
.DESCRIPTION
    With -TargetUser values, each is resolved by SID, full path, account name
    (DOMAIN\name -> SID -> ProfileList) or folder name. Without targets, every
    profile under %SystemDrive%\Users plus every ProfileList entry (relocated
    profiles) is returned, de-duplicated by path. LocalSystem, LocalService and
    NetworkService profiles are skipped. Each profile carries a SID when known.
.OUTPUTS
    PSCustomObject
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][hashtable]$Context,
        [string[]]$TargetUsers = @()
    )

    $usersRoot = Join-Path $env:SystemDrive 'Users'
    $profileList = @(Get-DFIRProfileListEntries)
    $candidates = New-Object System.Collections.ArrayList
    $profiles = @()

    try {
        $targets = ConvertTo-DFIRSplitList -Value $TargetUsers
        if ($targets.Count -gt 0) {
            foreach ($target in $targets) {
                $resolved = Resolve-DFIRTargetSpec -Target $target -ProfileList $profileList -UsersRoot $usersRoot
                if ($resolved) {
                    [void]$candidates.Add($resolved)
                }
                else {
                    Write-DFIRLog -Context $Context -Level WARN -Message ("Target user profile not found: {0}" -f $target)
                }
            }
            # An explicitly named target is honoured even if it is a shell name.
            $profiles = @(Merge-DFIRProfileCandidates -Candidates @($candidates) -ExcludedNames @())
        }
        else {
            if (Test-Path -LiteralPath $usersRoot -PathType Container) {
                foreach ($dir in (Get-ChildItem -LiteralPath $usersRoot -Directory -ErrorAction SilentlyContinue)) {
                    $entry = Find-DFIRProfileListEntry -Entries $profileList -Path $dir.FullName
                    $sid = ''
                    if ($entry) { $sid = $entry.SID }
                    [void]$candidates.Add([pscustomobject]@{ ProfilePath = $dir.FullName; SID = $sid })
                }
            }
            foreach ($entry in $profileList) {
                if (Test-DFIRServiceSid -SID $entry.SID) { continue }
                if (Test-Path -LiteralPath $entry.ProfilePath -PathType Container) {
                    [void]$candidates.Add($entry)
                }
            }
            $profiles = @(Merge-DFIRProfileCandidates -Candidates @($candidates))
        }

        if ($profiles.Count -eq 0) {
            $fallbackProfile = $env:USERPROFILE
            $fallbackSid = ''
            try { $fallbackSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value } catch { }
            $fallback = Get-DFIRProfileObject -ProfilePath $fallbackProfile -UserName $env:USERNAME -SID $fallbackSid
            $fallback.Startup = [Environment]::GetFolderPath('Startup')
            $profiles = @($fallback)
        }
    }
    catch {
        Write-DFIRLog -Context $Context -Level ERROR -Message ("Target profile resolution failed: {0}" -f $_.Exception.Message)
    }

    return @($profiles)
}

function Add-DFIRCollectedFile {
<#
.SYNOPSIS
    Tracks a collected file for logging, hashing, and manifest generation.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][hashtable]$Context,
        [Parameter(Mandatory=$true)][string]$Path
    )

    try {
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            [void]$Context.CollectedFiles.Add((Resolve-Path -LiteralPath $Path).Path)
            Write-DFIRLog -Context $Context -Message ("Collected file: {0}" -f $Path)
        }
    }
    catch {
        Write-DFIRLog -Context $Context -Level WARN -Message ("Unable to track collected file {0}: {1}" -f $Path, $_.Exception.Message)
    }
}

function Add-DFIRResult {
<#
.SYNOPSIS
    Records a module success/failure result.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][hashtable]$Context,
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][bool]$Success,
        [string]$Message = ''
    )

    try {
        $entry = [pscustomobject]@{
            Name      = $Name
            Success   = $Success
            Message   = $Message
            Timestamp = (Get-Date).ToString('o')
        }
        [void]$Context.Results.Add($entry)
    }
    catch {
        Write-DFIRLog -Context $Context -Level WARN -Message ("Unable to record result for {0}: {1}" -f $Name, $_.Exception.Message)
    }
}

function Get-DFIRScriptBlockText {
<#
.SYNOPSIS
    Collapses a script block to one line for the command log.
.OUTPUTS
    System.String
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][scriptblock]$ScriptBlock)

    $text = ($ScriptBlock.ToString() -replace '\s+', ' ').Trim()
    if ($text.Length -gt 1000) { $text = $text.Substring(0, 1000) + '...' }
    return $text
}

function Invoke-DFIRSafeCommand {
<#
.SYNOPSIS
    Runs a native executable or script block and writes stdout/stderr to disk.
.DESCRIPTION
    Exceptions are caught and logged. The function returns true when the command
    completed without a terminating exception, even if the executable produced
    stderr or a non-zero exit code; a non-zero native exit code is logged as a
    warning. Every invocation is recorded in 14_Logs\CommandLog.csv.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][hashtable]$Context,
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][string]$OutputPath,
        [Parameter(ParameterSetName='Native', Mandatory=$true)][string]$FilePath,
        [Parameter(ParameterSetName='Native')][string[]]$Arguments = @(),
        [Parameter(ParameterSetName='Script', Mandatory=$true)][scriptblock]$ScriptBlock
    )

    Write-DFIRLog -Context $Context -Message ("Starting command: {0}" -f $Name)
    $isNative = ($PSCmdlet.ParameterSetName -eq 'Native')
    if ($isNative) { $commandText = ('{0} {1}' -f (ConvertTo-DFIRArgument -Value $FilePath), (Join-DFIRArguments -Arguments $Arguments)).Trim() }
    else { $commandText = Get-DFIRScriptBlockText -ScriptBlock $ScriptBlock }
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $parent = Split-Path -Parent $OutputPath
        if ($parent -and -not (Test-Path -LiteralPath $parent)) {
            New-Item -ItemType Directory -Path $parent -Force -ErrorAction Stop | Out-Null
        }

        $exitCode = ''
        if ($isNative) {
            $global:LASTEXITCODE = 0
            $commandOutput = & $FilePath @Arguments 2>&1
            $exitCode = [string]$LASTEXITCODE
            $commandOutput | Out-File -FilePath $OutputPath -Encoding UTF8 -Width 4096
        }
        else {
            & $ScriptBlock | Out-File -FilePath $OutputPath -Encoding UTF8 -Width 4096
        }
        $watch.Stop()

        Add-DFIRCollectedFile -Context $Context -Path $OutputPath
        Add-DFIRCommandRecord -Context $Context -Name $Name -Command $commandText -ExitCode $exitCode -DurationSeconds $watch.Elapsed.TotalSeconds -OutputFile $OutputPath
        if ($isNative -and $exitCode -ne '0') {
            Write-DFIRLog -Context $Context -Level WARN -Message ("Command {0} exited with code {1}; output kept in {2}" -f $Name, $exitCode, $OutputPath)
        }
        Write-DFIRLog -Context $Context -Level SUCCESS -Message ("Finished command: {0}" -f $Name)
        return $true
    }
    catch {
        $watch.Stop()
        Add-DFIRCommandRecord -Context $Context -Name $Name -Command $commandText -ExitCode 'EXCEPTION' -DurationSeconds $watch.Elapsed.TotalSeconds -OutputFile $OutputPath
        Write-DFIRLog -Context $Context -Level ERROR -Message ("Command failed: {0}: {1}" -f $Name, $_.Exception.Message)
        return $false
    }
}

function Export-DFIRCsv {
<#
.SYNOPSIS
    Exports objects to CSV with consistent error handling.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][hashtable]$Context,
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][scriptblock]$ScriptBlock
    )

    Write-DFIRLog -Context $Context -Message ("Starting CSV export: {0}" -f $Name)
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $commandText = Get-DFIRScriptBlockText -ScriptBlock $ScriptBlock
    try {
        $data = & $ScriptBlock
        if ($null -eq $data) { $data = @() }
        $data | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8 -Force
        $watch.Stop()
        Add-DFIRCollectedFile -Context $Context -Path $Path
        Add-DFIRCommandRecord -Context $Context -Name $Name -Command $commandText -DurationSeconds $watch.Elapsed.TotalSeconds -OutputFile $Path
        Write-DFIRLog -Context $Context -Level SUCCESS -Message ("Finished CSV export: {0}" -f $Name)
        return $true
    }
    catch {
        $watch.Stop()
        Add-DFIRCommandRecord -Context $Context -Name $Name -Command $commandText -ExitCode 'EXCEPTION' -DurationSeconds $watch.Elapsed.TotalSeconds -OutputFile $Path
        Write-DFIRLog -Context $Context -Level ERROR -Message ("CSV export failed: {0}: {1}" -f $Name, $_.Exception.Message)
        return $false
    }
}

function Export-DFIRJson {
<#
.SYNOPSIS
    Exports objects to JSON with consistent error handling.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][hashtable]$Context,
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][scriptblock]$ScriptBlock,
        [int]$Depth = 5
    )

    Write-DFIRLog -Context $Context -Message ("Starting JSON export: {0}" -f $Name)
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $commandText = Get-DFIRScriptBlockText -ScriptBlock $ScriptBlock
    try {
        $data = & $ScriptBlock
        $data | ConvertTo-Json -Depth $Depth | Out-File -FilePath $Path -Encoding UTF8 -Width 4096
        $watch.Stop()
        Add-DFIRCollectedFile -Context $Context -Path $Path
        Add-DFIRCommandRecord -Context $Context -Name $Name -Command $commandText -DurationSeconds $watch.Elapsed.TotalSeconds -OutputFile $Path
        Write-DFIRLog -Context $Context -Level SUCCESS -Message ("Finished JSON export: {0}" -f $Name)
        return $true
    }
    catch {
        $watch.Stop()
        Add-DFIRCommandRecord -Context $Context -Name $Name -Command $commandText -ExitCode 'EXCEPTION' -DurationSeconds $watch.Elapsed.TotalSeconds -OutputFile $Path
        Write-DFIRLog -Context $Context -Level ERROR -Message ("JSON export failed: {0}: {1}" -f $Name, $_.Exception.Message)
        return $false
    }
}

function Save-DFIRText {
<#
.SYNOPSIS
    Writes text/object output to a UTF-8 text file.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][hashtable]$Context,
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][scriptblock]$ScriptBlock
    )

    return Invoke-DFIRSafeCommand -Context $Context -Name $Name -OutputPath $Path -ScriptBlock $ScriptBlock
}

function Copy-DFIRFile {
<#
.SYNOPSIS
    Copies a file if present, logs missing files gracefully, and records provenance.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][hashtable]$Context,
        [Parameter(Mandatory=$true)][string]$Source,
        [Parameter(Mandatory=$true)][string]$Destination
    )

    try {
        if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) {
            Write-DFIRLog -Context $Context -Level WARN -Message ("Source file not found: {0}" -f $Source)
            return $false
        }
        $parent = Split-Path -Parent $Destination
        if ($parent -and -not (Test-Path -LiteralPath $parent)) {
            New-Item -ItemType Directory -Path $parent -Force -ErrorAction Stop | Out-Null
        }
        $snapshot = Get-DFIRFileSnapshot -Path $Source
        Copy-Item -LiteralPath $Source -Destination $Destination -Force -ErrorAction Stop
        Add-DFIRCollectedFile -Context $Context -Path $Destination
        Add-DFIRProvenance -Context $Context -Source $Source -Destination $Destination -Snapshot $snapshot -CopyMethod 'CopyItem'
        return $true
    }
    catch {
        Write-DFIRLog -Context $Context -Level ERROR -Message ("File copy failed from {0}: {1}" -f $Source, $_.Exception.Message)
        return $false
    }
}

function Resolve-DFIRScanDrives {
<#
.SYNOPSIS
    Normalises and validates the -ScanDrives list into "X:" drive identifiers.
.DESCRIPTION
    Accepts entries such as D, d:, "E:\" and returns a de-duplicated list of
    validated, local fixed or removable volumes (e.g. @('D:','E:')). The system
    drive is dropped (already covered by the default collection), and anything
    that is not an accessible local volume is warned about and skipped.
.OUTPUTS
    System.String[]
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][hashtable]$Context,
        [Parameter(Mandatory=$true)][AllowEmptyCollection()][string[]]$Requested
    )

    $result = New-Object System.Collections.ArrayList
    if (-not $Requested -or $Requested.Count -eq 0) { return @() }

    $sysDrive = ($env:SystemDrive).TrimEnd('\').ToUpper()   # e.g. C:
    $known = @{}
    try {
        Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=2 OR DriveType=3' -ErrorAction Stop |
            ForEach-Object { $known[$_.DeviceID.ToUpper()] = [int]$_.DriveType }
    }
    catch { }

    # Expand any comma/semicolon/space-separated entries. A native call binds
    # `-ScanDrives D:,E:` to two elements, but the launcher forwards it as the
    # single string "D:,E:"; both must yield @('D:','E:').
    $tokens = New-Object System.Collections.ArrayList
    foreach ($entry in $Requested) {
        if ([string]::IsNullOrWhiteSpace($entry)) { continue }
        foreach ($part in ($entry -split '[,;\s]+')) {
            if (-not [string]::IsNullOrWhiteSpace($part)) { [void]$tokens.Add($part) }
        }
    }

    foreach ($raw in $tokens) {
        if ([string]::IsNullOrWhiteSpace($raw)) { continue }
        $letter = ($raw.Trim().TrimEnd('\').TrimEnd(':')).ToUpper()
        if ($letter.Length -ne 1 -or ($letter -notmatch '^[A-Z]$')) {
            Write-DFIRLog -Context $Context -Level WARN -Message ("Ignoring invalid -ScanDrives entry '{0}' (use a drive letter such as D or D:)" -f $raw)
            continue
        }
        $id = $letter + ':'
        if ($id -eq $sysDrive) {
            Write-DFIRLog -Context $Context -Message ("-ScanDrives {0} is the system drive; already covered by the default collection - skipping" -f $id)
            continue
        }
        if ($known.Count -gt 0 -and -not $known.ContainsKey($id)) {
            Write-DFIRLog -Context $Context -Level WARN -Message ("-ScanDrives {0} is not a local fixed or removable volume on this host - skipping" -f $id)
            continue
        }
        if (-not (Test-Path -LiteralPath ($id + '\'))) {
            Write-DFIRLog -Context $Context -Level WARN -Message ("-ScanDrives {0} is not accessible - skipping" -f $id)
            continue
        }
        $already = $false
        foreach ($e in $result) { if ($e -eq $id) { $already = $true; break } }
        if (-not $already) { [void]$result.Add($id) }
    }
    return @($result)
}

function Copy-DFIRLockedFile {
<#
.SYNOPSIS
    Copies a file that may be locked by a running process.
.DESCRIPTION
    Copy-Item fails with "Access to the path is denied" when a process such as a
    running browser holds an exclusive-write handle. This helper first tries a
    normal copy, then re-opens the source with FileShare.ReadWrite so that the
    read succeeds alongside the owning process's write handle, and restores the
    source creation and last-write times on that copy. Falls back to robocopy
    backup mode (/b), which uses SeBackupPrivilege when the collector is
    elevated; robocopy writes into a fresh temporary folder so a pre-existing
    same-named file in the destination can never be mistaken for the copy.
    Source metadata is captured before any copy attempt and written to
    14_Logs\Provenance.csv.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][hashtable]$Context,
        [Parameter(Mandatory=$true)][string]$Source,
        [Parameter(Mandatory=$true)][string]$Destination
    )

    # Test-Path itself throws UnauthorizedAccessException on NTFS metadata files
    # ($MFT, $LogFile, $UsnJrnl) even from a shadow copy. Access-denied means the
    # file exists but is locked, so fall through to the shared-read/backup copiers
    # rather than reporting it as missing.
    $sourceExists = $true
    try { $sourceExists = Test-Path -LiteralPath $Source -PathType Leaf -ErrorAction Stop }
    catch [System.UnauthorizedAccessException] { $sourceExists = $true }
    catch { $sourceExists = $false }
    if (-not $sourceExists) {
        Write-DFIRLog -Context $Context -Level WARN -Message ("Source file not found: {0}" -f $Source)
        return $false
    }

    $parent = Split-Path -Parent $Destination
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        try { New-Item -ItemType Directory -Path $parent -Force -ErrorAction Stop | Out-Null }
        catch {
            Write-DFIRLog -Context $Context -Level ERROR -Message ("Destination create failed {0}: {1}" -f $parent, $_.Exception.Message)
            return $false
        }
    }

    $snapshot = Get-DFIRFileSnapshot -Path $Source

    try {
        Copy-Item -LiteralPath $Source -Destination $Destination -Force -ErrorAction Stop
        Add-DFIRCollectedFile -Context $Context -Path $Destination
        Add-DFIRProvenance -Context $Context -Source $Source -Destination $Destination -Snapshot $snapshot -CopyMethod 'CopyItem'
        return $true
    }
    catch { }

    $inStream = $null
    $outStream = $null
    $streamCopied = $false
    try {
        $inStream = New-Object System.IO.FileStream($Source, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $outStream = New-Object System.IO.FileStream($Destination, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        $inStream.CopyTo($outStream)
        $outStream.Flush()
        $streamCopied = $true
    }
    catch { }
    finally {
        if ($outStream) { $outStream.Dispose() }
        if ($inStream) { $inStream.Dispose() }
    }
    if ($streamCopied) {
        if ($snapshot) {
            try {
                [System.IO.File]::SetCreationTimeUtc($Destination, $snapshot.CreationTimeUtc)
                [System.IO.File]::SetLastWriteTimeUtc($Destination, $snapshot.LastWriteTimeUtc)
            }
            catch {
                Write-DFIRLog -Context $Context -Level WARN -Message ("Could not restore timestamps on {0}: {1}" -f $Destination, $_.Exception.Message)
            }
        }
        Write-DFIRLog -Context $Context -Message ("Locked-file copy via shared read: {0}" -f $Source)
        Add-DFIRCollectedFile -Context $Context -Path $Destination
        Add-DFIRProvenance -Context $Context -Source $Source -Destination $Destination -Snapshot $snapshot -CopyMethod 'SharedRead'
        return $true
    }

    $staging = $null
    try {
        $srcDir = Split-Path -Parent $Source
        $srcName = Split-Path -Leaf $Source
        $dstDir = Split-Path -Parent $Destination
        $staging = Join-Path $dstDir ('.vestigium_robocopy_{0}' -f ([guid]::NewGuid().ToString('N')))
        New-Item -ItemType Directory -Path $staging -Force -ErrorAction Stop | Out-Null
        & robocopy.exe $srcDir $staging $srcName /b /r:0 /w:0 /nfl /ndl /njh /njs /nc /ns /np 2>&1 | Out-Null
        $landed = Join-Path $staging $srcName
        if (Test-Path -LiteralPath $landed -PathType Leaf) {
            Move-Item -LiteralPath $landed -Destination $Destination -Force -ErrorAction Stop
            Write-DFIRLog -Context $Context -Message ("Locked-file copy via robocopy backup mode: {0}" -f $Source)
            Add-DFIRCollectedFile -Context $Context -Path $Destination
            Add-DFIRProvenance -Context $Context -Source $Source -Destination $Destination -Snapshot $snapshot -CopyMethod 'RobocopyBackup'
            return $true
        }
    }
    catch { }
    finally {
        if ($staging -and (Test-Path -LiteralPath $staging)) {
            Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    Write-DFIRLog -Context $Context -Level WARN -Message ("Locked-file copy failed after all fallbacks: {0}" -f $Source)
    return $false
}

function Add-DFIRNativeFileType {
<#
.SYNOPSIS
    Registers the P/Invoke type used to open and query NTFS metadata files.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    if ('Vestigium.RawFile' -as [type]) { return $true }
    $signature = @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace Vestigium {
    public static class RawFile {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern SafeFileHandle CreateFileW(
            string lpFileName, uint dwDesiredAccess, uint dwShareMode,
            IntPtr lpSecurityAttributes, uint dwCreationDisposition,
            uint dwFlagsAndAttributes, IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DeviceIoControl(
            SafeFileHandle hDevice, uint dwIoControlCode,
            byte[] lpInBuffer, uint nInBufferSize,
            byte[] lpOutBuffer, uint nOutBufferSize,
            out uint lpBytesReturned, IntPtr lpOverlapped);
    }
}
'@
    try { Add-Type -TypeDefinition $signature -ErrorAction Stop; return $true }
    catch {
        Write-DFIRLog -Context $Context -Level ERROR -Message ("Native file type unavailable: {0}" -f $_.Exception.Message)
        return $false
    }
}

function Open-DFIRRawHandle {
<#
.SYNOPSIS
    Opens a file with backup semantics so NTFS metadata files can be read.
.OUTPUTS
    Microsoft.Win32.SafeHandles.SafeFileHandle (test .IsInvalid), or $null.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Source)

    $GENERIC_READ  = [uint32]2147483648            # 0x80000000
    $SHARE_ALL     = [uint32]7                      # READ | WRITE | DELETE
    $OPEN_EXISTING = [uint32]3
    $FLAGS         = [uint32](33554432 -bor 134217728)  # BACKUP_SEMANTICS | SEQUENTIAL_SCAN
    return [Vestigium.RawFile]::CreateFileW($Source, $GENERIC_READ, $SHARE_ALL, [IntPtr]::Zero, $OPEN_EXISTING, $FLAGS, [IntPtr]::Zero)
}

function Copy-DFIRRawFile {
<#
.SYNOPSIS
    Copies an NTFS metadata file that only opens with backup semantics
    ($MFT, $LogFile).
.DESCRIPTION
    Copy-Item, Test-Path and a plain FileStream all fail with "Access is denied"
    on NTFS metadata files, even from a Volume Shadow Copy and even when
    elevated, because those files are never opened through the normal Win32 path.
    This helper opens the source with CreateFileW using FILE_FLAG_BACKUP_SEMANTICS
    (which draws on SeBackupPrivilege, held by elevated administrators) and full
    share mode, then streams the bytes out with a hard size cap so a pathological
    or sparse source can never fill the evidence disk. Use Copy-DFIRUsnJournal
    for the sparse $UsnJrnl:$J stream.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][hashtable]$Context,
        [Parameter(Mandatory=$true)][string]$Source,
        [Parameter(Mandatory=$true)][string]$Destination,
        [long]$MaxBytes = 8589934592   # 8 GiB safety ceiling
    )

    if (-not (Add-DFIRNativeFileType -Context $Context)) { return $false }

    $parent = Split-Path -Parent $Destination
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        try { New-Item -ItemType Directory -Path $parent -Force -ErrorAction Stop | Out-Null }
        catch {
            Write-DFIRLog -Context $Context -Level ERROR -Message ("Destination create failed {0}: {1}" -f $parent, $_.Exception.Message)
            return $false
        }
    }

    $handle = $null
    $inStream = $null
    $outStream = $null
    $copied = $false
    $truncated = $false
    $total = [long]0
    try {
        $handle = Open-DFIRRawHandle -Source $Source
        if ($handle.IsInvalid) {
            $code = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-DFIRLog -Context $Context -Level WARN -Message ("Raw open failed ({0}): {1}" -f $code, $Source)
            return $false
        }
        $inStream = New-Object System.IO.FileStream($handle, [System.IO.FileAccess]::Read)
        $outStream = New-Object System.IO.FileStream($Destination, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        $buffer = New-Object byte[] 1048576
        while ($true) {
            $read = $inStream.Read($buffer, 0, $buffer.Length)
            if ($read -le 0) { break }
            if ($MaxBytes -gt 0 -and ($total + $read) -gt $MaxBytes) {
                $room = [int]($MaxBytes - $total)
                if ($room -gt 0) { $outStream.Write($buffer, 0, $room); $total += $room }
                $truncated = $true
                break
            }
            $outStream.Write($buffer, 0, $read)
            $total += $read
        }
        $outStream.Flush()
        $copied = $true
    }
    catch {
        Write-DFIRLog -Context $Context -Level WARN -Message ("Raw copy failed for {0}: {1}" -f $Source, $_.Exception.Message)
    }
    finally {
        if ($outStream) { $outStream.Dispose() }
        if ($inStream) { $inStream.Dispose() }
        elseif ($handle -and -not $handle.IsClosed) { $handle.Dispose() }
    }

    if (-not $copied) { return $false }
    if ($truncated) {
        Write-DFIRLog -Context $Context -Level WARN -Message ("Raw copy hit the {0}-byte cap for {1}; truncated" -f $MaxBytes, $Source)
    }
    Write-DFIRLog -Context $Context -Message ("Raw backup-semantics copy: {0} ({1} bytes)" -f $Source, $total)
    Add-DFIRCollectedFile -Context $Context -Path $Destination
    Add-DFIRProvenance -Context $Context -Source $Source -Destination $Destination -Snapshot $null -CopyMethod 'RawBackup'
    return $true
}

function Copy-DFIRUsnJournal {
<#
.SYNOPSIS
    Extracts the allocated data of the sparse $UsnJrnl:$J stream.
.DESCRIPTION
    $UsnJrnl:$J has a huge logical size but is almost entirely sparse: a naive
    stream copy from offset zero would write gigabytes of zeros and appear to
    hang. This queries the file's allocated byte ranges
    (FSCTL_QUERY_ALLOCATED_RANGES) and copies only those, preserving each
    record's true offset by marking the destination sparse
    (FSCTL_SET_SPARSE) and seeking. A byte cap bounds the real data copied.
    On any failure the caller falls back to a live fsutil read.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][hashtable]$Context,
        [Parameter(Mandatory=$true)][string]$Source,
        [Parameter(Mandatory=$true)][string]$Destination,
        [long]$MaxBytes = 2147483648   # 2 GiB of real data
    )

    if (-not (Add-DFIRNativeFileType -Context $Context)) { return $false }

    $FSCTL_QUERY_ALLOCATED_RANGES = [uint32]0x000940CF
    $FSCTL_SET_SPARSE             = [uint32]0x000900C4
    $ERROR_MORE_DATA              = 234

    $parent = Split-Path -Parent $Destination
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        try { New-Item -ItemType Directory -Path $parent -Force -ErrorAction Stop | Out-Null } catch { return $false }
    }

    $handle = $null
    $inStream = $null
    $outStream = $null
    $ok = $false
    $copied = [long]0
    try {
        $handle = Open-DFIRRawHandle -Source $Source
        if ($handle.IsInvalid) {
            $code = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-DFIRLog -Context $Context -Level WARN -Message ("USN raw open failed ({0}): {1}" -f $code, $Source)
            return $false
        }
        $inStream = New-Object System.IO.FileStream($handle, [System.IO.FileAccess]::Read)
        $logical = $inStream.Length
        $outStream = New-Object System.IO.FileStream($Destination, [System.IO.FileMode]::Create, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)

        # Mark the output sparse so unwritten gaps cost nothing on disk.
        $br = [uint32]0
        [void][Vestigium.RawFile]::DeviceIoControl($outStream.SafeFileHandle, $FSCTL_SET_SPARSE, $null, 0, $null, 0, [ref]$br, [IntPtr]::Zero)

        $outBuf = New-Object byte[] (16 * 1024)   # up to 1024 ranges per query
        $queryStart = [long]0
        $buffer = New-Object byte[] 1048576
        $capped = $false
        while ($true) {
            $inBuf = New-Object byte[] 16
            [System.BitConverter]::GetBytes([long]$queryStart).CopyTo($inBuf, 0)
            [System.BitConverter]::GetBytes([long]($logical - $queryStart)).CopyTo($inBuf, 8)
            $returned = [uint32]0
            $call = [Vestigium.RawFile]::DeviceIoControl($handle, $FSCTL_QUERY_ALLOCATED_RANGES, $inBuf, [uint32]16, $outBuf, [uint32]$outBuf.Length, [ref]$returned, [IntPtr]::Zero)
            $lastErr = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            $count = [int]($returned / 16)
            if ($count -eq 0) { break }
            $lastEnd = $queryStart
            for ($i = 0; $i -lt $count; $i++) {
                $off = [System.BitConverter]::ToInt64($outBuf, $i * 16)
                $len = [System.BitConverter]::ToInt64($outBuf, $i * 16 + 8)
                $lastEnd = $off + $len
                $inStream.Position = $off
                $outStream.Position = $off
                $remaining = $len
                while ($remaining -gt 0) {
                    if ($MaxBytes -gt 0 -and $copied -ge $MaxBytes) { $capped = $true; break }
                    $want = [int][math]::Min([long]$buffer.Length, $remaining)
                    if ($MaxBytes -gt 0) { $want = [int][math]::Min([long]$want, ($MaxBytes - $copied)) }
                    if ($want -le 0) { $capped = $true; break }
                    $got = $inStream.Read($buffer, 0, $want)
                    if ($got -le 0) { break }
                    $outStream.Write($buffer, 0, $got)
                    $copied += $got
                    $remaining -= $got
                }
                if ($capped) { break }
            }
            if ($capped) { break }
            if ($call) { break }                       # all ranges returned
            if ($lastErr -ne $ERROR_MORE_DATA) { break }
            if ($lastEnd -le $queryStart) { break }    # no progress; avoid a loop
            $queryStart = $lastEnd
        }
        $outStream.Flush()
        $ok = $true
        if ($capped) {
            Write-DFIRLog -Context $Context -Level WARN -Message ("USN copy hit the {0}-byte cap; truncated" -f $MaxBytes)
        }
    }
    catch {
        Write-DFIRLog -Context $Context -Level WARN -Message ("USN sparse copy failed for {0}: {1}" -f $Source, $_.Exception.Message)
    }
    finally {
        if ($outStream) { $outStream.Dispose() }
        if ($inStream) { $inStream.Dispose() }
        elseif ($handle -and -not $handle.IsClosed) { $handle.Dispose() }
    }

    if (-not $ok) { return $false }
    Write-DFIRLog -Context $Context -Message ("USN journal allocated-range copy: {0} ({1} real bytes)" -f $Source, $copied)
    Add-DFIRCollectedFile -Context $Context -Path $Destination
    Add-DFIRProvenance -Context $Context -Source $Source -Destination $Destination -Snapshot $null -CopyMethod 'RawBackup'
    return $true
}

function Copy-DFIREsentutlVss {
<#
.SYNOPSIS
    Copies a locked NTFS metadata file with the built-in esentutl.exe over a
    shadow copy ($MFT, $LogFile, $UsnJrnl:$J).
.DESCRIPTION
    NTFS refuses to open its metadata files by name even on a shadow copy, so a
    direct handle fails. esentutl.exe /y /vss uses the Volume Shadow Copy
    service to read the file through a snapshot it creates and releases itself.
    esentutl ships with every supported Windows, so this needs no bundled tool.
    The console output is kept beside the copy for provenance, and the copy is
    accepted only when the destination exists and is non-empty.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][hashtable]$Context,
        [Parameter(Mandatory=$true)][string]$Source,       # e.g. C:\$MFT
        [Parameter(Mandatory=$true)][string]$Destination
    )

    $esentutl = Join-Path $env:SystemRoot 'System32\esentutl.exe'
    if (-not (Test-Path -LiteralPath $esentutl -PathType Leaf)) {
        Write-DFIRLog -Context $Context -Level WARN -Message 'esentutl.exe not found; skipping VSS copy'
        return $false
    }

    $parent = Split-Path -Parent $Destination
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        try { New-Item -ItemType Directory -Path $parent -Force -ErrorAction Stop | Out-Null }
        catch {
            Write-DFIRLog -Context $Context -Level ERROR -Message ("Destination create failed {0}: {1}" -f $parent, $_.Exception.Message)
            return $false
        }
    }
    if (Test-Path -LiteralPath $Destination) {
        Remove-Item -LiteralPath $Destination -Force -ErrorAction SilentlyContinue
    }

    $log = $Destination + '.esentutl.log'
    $global:LASTEXITCODE = 0
    try {
        $out = & $esentutl '/y' '/vss' $Source '/d' $Destination 2>&1
        $code = [string]$LASTEXITCODE
        $out | Out-File -FilePath $log -Encoding UTF8 -Width 4096
        Add-DFIRCollectedFile -Context $Context -Path $log
    }
    catch {
        Write-DFIRLog -Context $Context -Level WARN -Message ("esentutl copy threw for {0}: {1}" -f $Source, $_.Exception.Message)
        return $false
    }

    $size = 0
    if (Test-Path -LiteralPath $Destination -PathType Leaf) {
        try { $size = (New-Object System.IO.FileInfo($Destination)).Length } catch { $size = 0 }
    }
    if ($size -le 0) {
        Write-DFIRLog -Context $Context -Level WARN -Message ("esentutl copy produced no data for {0} (exit {1}); see {2}" -f $Source, $code, $log)
        return $false
    }

    Write-DFIRLog -Context $Context -Message ("esentutl VSS copy: {0} ({1} bytes)" -f $Source, $size)
    Add-DFIRCollectedFile -Context $Context -Path $Destination
    Add-DFIRProvenance -Context $Context -Source $Source -Destination $Destination -Snapshot $null -CopyMethod 'RawBackup'
    return $true
}

function Export-DFIRBinaryStrings {
<#
.SYNOPSIS
    Carves printable ASCII and UTF-16LE strings from a binary file.
.DESCRIPTION
    Vendor security products such as ESET store detection history in proprietary
    binary .dat files. Carving both encodings makes detection names and file
    paths readable to the analyst without a vendor parser.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][hashtable]$Context,
        [Parameter(Mandatory=$true)][string]$Source,
        [Parameter(Mandatory=$true)][string]$Destination,
        [int]$MinimumLength = 5
    )

    try {
        if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) { return $false }
        $bytes = [System.IO.File]::ReadAllBytes($Source)
        if ($bytes.Length -eq 0) { return $false }

        $parent = Split-Path -Parent $Destination
        if ($parent -and -not (Test-Path -LiteralPath $parent)) {
            New-Item -ItemType Directory -Path $parent -Force -ErrorAction Stop | Out-Null
        }

        $pattern = '[\x20-\x7E]{' + $MinimumLength + ',}'
        $results = New-Object System.Collections.ArrayList

        # UTF-16LE strings are not guaranteed to begin on an even byte offset
        # inside a proprietary container. Decoding only at offset 0 silently
        # drops every string that starts at an odd offset, so decode at both
        # alignments. Verified against ESET virlog.dat, where the detection name
        # begins at offset 1579.
        $ascii = [System.Text.Encoding]::ASCII.GetString($bytes)
        foreach ($m in [regex]::Matches($ascii, $pattern)) { [void]$results.Add($m.Value) }

        foreach ($offset in 0, 1) {
            if ($bytes.Length -le $offset) { continue }
            $length = $bytes.Length - $offset
            if ($length % 2 -ne 0) { $length-- }
            if ($length -lt 2) { continue }
            $wide = [System.Text.Encoding]::Unicode.GetString($bytes, $offset, $length)
            foreach ($m in [regex]::Matches($wide, $pattern)) { [void]$results.Add($m.Value) }
        }

        $unique = $results | Select-Object -Unique
        if (-not $unique) { return $false }

        $header = @(
            ("Source: {0}" -f $Source),
            ("Carved: ASCII and UTF-16LE, minimum length {0}" -f $MinimumLength),
            '---'
        )
        ($header + $unique) | Out-File -FilePath $Destination -Encoding UTF8 -Width 4096
        Add-DFIRCollectedFile -Context $Context -Path $Destination
        return $true
    }
    catch {
        Write-DFIRLog -Context $Context -Level WARN -Message ("String carve failed for {0}: {1}" -f $Source, $_.Exception.Message)
        return $false
    }
}

function Test-DFIRPathUnder {
<#
.SYNOPSIS
    Tests whether a candidate path sits inside a parent path.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][AllowEmptyString()][string]$Candidate,
        [Parameter(Mandatory=$true)][AllowEmptyString()][string]$Parent
    )

    if ([string]::IsNullOrWhiteSpace($Candidate) -or [string]::IsNullOrWhiteSpace($Parent)) { return $false }
    $c = $Candidate.TrimEnd('\') + '\'
    $p = $Parent.TrimEnd('\') + '\'
    return $c.StartsWith($p, [System.StringComparison]::OrdinalIgnoreCase)
}

function Export-DFIRRegistryKey {
<#
.SYNOPSIS
    Exports a registry key to .reg and a readable .txt listing.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][hashtable]$Context,
        [Parameter(Mandatory=$true)][string]$RegistryPath,
        [Parameter(Mandatory=$true)][string]$RegExePath,
        [Parameter(Mandatory=$true)][string]$TxtPath
    )

    $ok = $true
    try {
        $regResult = & reg.exe export $RegistryPath $RegExePath /y 2>&1
        $regResult | Out-File -FilePath ($RegExePath + '.log.txt') -Encoding UTF8 -Width 4096
        if (Test-Path -LiteralPath $RegExePath) {
            Add-DFIRCollectedFile -Context $Context -Path $RegExePath
        }
        else {
            Write-DFIRLog -Context $Context -Level WARN -Message ("Registry export unavailable: {0}" -f $RegistryPath)
        }
    }
    catch {
        $ok = $false
        Write-DFIRLog -Context $Context -Level ERROR -Message ("reg.exe export failed for {0}: {1}" -f $RegistryPath, $_.Exception.Message)
    }

    try {
        $txtResult = & reg.exe query $RegistryPath /s 2>&1
        $txtResult | Out-File -FilePath $TxtPath -Encoding UTF8 -Width 4096
        Add-DFIRCollectedFile -Context $Context -Path $TxtPath
    }
    catch {
        $ok = $false
        Write-DFIRLog -Context $Context -Level ERROR -Message ("reg.exe query failed for {0}: {1}" -f $RegistryPath, $_.Exception.Message)
    }

    return $ok
}

function Get-DFIRSafeFileName {
<#
.SYNOPSIS
    Converts a string to a filename-safe value.
.OUTPUTS
    System.String
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Value)

    $invalid = [IO.Path]::GetInvalidFileNameChars()
    $builder = New-Object System.Text.StringBuilder
    foreach ($ch in $Value.ToCharArray()) {
        if ($invalid -contains $ch -or $ch -eq '\') {
            [void]$builder.Append('_')
        }
        else {
            [void]$builder.Append($ch)
        }
    }
    return $builder.ToString()
}

function Get-DFIRObjectProperty {
<#
.SYNOPSIS
    Safely reads a property from an object under StrictMode.
.OUTPUTS
    System.Object
#>
    [CmdletBinding()]
    param(
        [AllowNull()][object]$InputObject,
        [Parameter(Mandatory=$true)][string]$Name
    )

    if ($null -eq $InputObject) { return $null }
    try {
        $property = $InputObject.PSObject.Properties[$Name]
        if ($property) { return $property.Value }
    }
    catch { }
    return $null
}

function Get-DFIRYaraRulesPath {
<#
.SYNOPSIS
    Resolves the active YARA bundle: shared kit store first, then legacy Tools\YaraRules.
.OUTPUTS
    System.String, or $null when no bundle exists.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    $candidates = @()
    if ($Context.ContainsKey('KitRoot') -and $Context.KitRoot) {
        $candidates += (Join-Path $Context.KitRoot 'shared\yara-rules\active-rules.yar')
    }
    $candidates += (Join-Path $Context.ToolsPath 'YaraRules\active-rules.yar')
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
    }
    return $null
}

function Get-DFIRHashExclusions {
<#
.SYNOPSIS
    Returns full paths that must not appear in SHA256.csv.
.DESCRIPTION
    SHA256.csv cannot hash itself; Collection.log is still written after hashing
    (manifest, finish and archive lines); the memory image is excluded from the
    archive and carries its own .sha256 sidecar.
.OUTPUTS
    System.String[]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    $list = @(
        (Join-Path $Context.Paths.Hashes 'SHA256.csv'),
        $Context.LogFile
    )
    if ($Context.ContainsKey('MemoryImagePath') -and $Context['MemoryImagePath']) { $list += $Context['MemoryImagePath'] }
    return $list
}

function New-DFIRHashes {
<#
.SYNOPSIS
    Generates SHA256 hashes for every collected file.
.DESCRIPTION
    Excludes SHA256.csv itself, 14_Logs\Collection.log (still being written
    after hashing) and the memory image (outside the archive, own sidecar), and
    writes 15_Hashes\README.txt explaining the exclusions.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    $hashPath = Join-Path $Context.Paths.Hashes 'SHA256.csv'
    try {
        Write-DFIRLog -Context $Context -Message 'Generating SHA256 inventory'
        $readme = @(
            'SHA256.csv lists every file in this evidence tree EXCEPT:',
            '  - 15_Hashes\SHA256.csv itself;',
            '  - 14_Logs\Collection.log, which is still being written while hashes,',
            '    the manifest and the archive are produced;',
            '  - 16_Manifest\Manifest.json, which is written after hashing;',
            '  - 20_Memory\*.raw (when present), which stays outside the ZIP and has',
            '    its own .sha256 sidecar.',
            'The files listed as excluded are covered by the SHA256 of the finished',
            'archive (<archive>.zip.sha256). Verify with:',
            '    vestigium.ps1 verify <archive>.zip'
        )
        $readmePath = Join-Path $Context.Paths.Hashes 'README.txt'
        $readme | Out-File -FilePath $readmePath -Encoding UTF8 -Width 4096
        Add-DFIRCollectedFile -Context $Context -Path $readmePath

        $excluded = @(Get-DFIRHashExclusions -Context $Context)
        $files = Get-ChildItem -LiteralPath $Context.OutputRoot -File -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object { $excluded -notcontains $_.FullName }

        $hashes = foreach ($file in $files) {
            try {
                $hash = Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256 -ErrorAction Stop
                [pscustomobject]@{
                    RelativePath = $file.FullName.Substring($Context.OutputRoot.Length).TrimStart('\')
                    FullPath     = $file.FullName
                    SHA256       = $hash.Hash
                    Length       = $file.Length
                    LastWriteUtc = $file.LastWriteTimeUtc.ToString('o')
                }
            }
            catch {
                Write-DFIRLog -Context $Context -Level WARN -Message ("Hash failed for {0}: {1}" -f $file.FullName, $_.Exception.Message)
            }
        }

        $hashes | Export-Csv -Path $hashPath -NoTypeInformation -Encoding UTF8 -Force
        Add-DFIRCollectedFile -Context $Context -Path $hashPath
        return $true
    }
    catch {
        Write-DFIRLog -Context $Context -Level ERROR -Message ("SHA256 generation failed: {0}" -f $_.Exception.Message)
        return $false
    }
}

function New-DFIRManifest {
<#
.SYNOPSIS
    Creates Manifest.json for the completed collection.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    $manifestPath = Join-Path $Context.Paths.Manifest 'Manifest.json'
    try {
        $hashCsv = Join-Path $Context.Paths.Hashes 'SHA256.csv'
        $sha256 = @()
        if (Test-Path -LiteralPath $hashCsv) {
            $sha256 = Import-Csv -LiteralPath $hashCsv -ErrorAction Stop
        }
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue

        $rulesPath = $null
        $rulesSha = $null
        if ($Context.ContainsKey('YaraRulesPath') -and $Context['YaraRulesPath']) {
            $rulesPath = $Context['YaraRulesPath']
            if ($Context.ContainsKey('YaraRulesSha256')) { $rulesSha = $Context['YaraRulesSha256'] }
        }
        else {
            $rulesPath = Get-DFIRYaraRulesPath -Context $Context
            if ($rulesPath) { $rulesSha = Get-DFIRFileSha256 -Path $rulesPath }
        }

        $memory = [ordered]@{
            Requested        = [bool]($Context.ContainsKey('CaptureMemory') -and $Context['CaptureMemory'])
            Captured         = [bool]($Context.ContainsKey('MemoryCaptured') -and $Context['MemoryCaptured'])
            ImagePath        = $null
            Sha256           = $null
            IncludedInArchive = $false
        }
        if ($memory.Captured) {
            $memory.ImagePath = $Context['MemoryImagePath']
            $memory.Sha256 = $Context['MemoryImageSha256']
        }

        $manifest = [ordered]@{
            Tool              = 'Vestigium'
            Schema            = 'vestigium/windows-manifest/1'
            CaseId            = $Context.CaseId
            CaseIdSource      = $Context.CaseIdSource
            Status            = if ($Context.ContainsKey('Status')) { $Context['Status'] } else { 'Unknown' }
            Hostname          = $env:COMPUTERNAME
            Username          = $env:USERNAME
            Operator          = $Context.Operator
            Invocation        = if ($Context.ContainsKey('Invocation')) { $Context['Invocation'] } else { $null }
            TargetUsers       = if ($Context.ContainsKey('TargetUsers')) { @($Context['TargetUsers']) } else { @() }
            TargetProfiles    = if ($Context.ContainsKey('TargetProfiles')) { @($Context['TargetProfiles'] | Select-Object UserName, SID, ProfilePath) } else { @() }
            SelectedModules   = if ($Context.ContainsKey('SelectedModules')) { @($Context['SelectedModules']) } else { @() }
            BrowserCredentialStores = if ($Context.ContainsKey('BrowserCredentialStores')) { $Context['BrowserCredentialStores'] } else { 'Copy' }
            CollectionTime    = (Get-Date).ToString('o')
            CollectorVersion  = $Context.CollectorVersion
            WindowsVersion    = if ($os) { $os.Caption + ' ' + $os.Version } else { 'Unknown' }
            KitRoot           = $Context.KitRoot
            ScriptRoot        = $Context.ScriptRoot
            OutputBase        = $Context.OutputBase
            OutputRoot        = $Context.OutputRoot
            YaraRulesPath     = $rulesPath
            YaraRulesSha256   = $rulesSha
            Memory            = $memory
            CommandLog        = [ordered]@{ Path = '14_Logs\CommandLog.csv'; Records = [int]$Context['CommandLogCount'] }
            Provenance        = [ordered]@{ Path = '14_Logs\Provenance.csv'; Records = [int]$Context['ProvenanceCount'] }
            NumberOfFiles     = (Get-ChildItem -LiteralPath $Context.OutputRoot -File -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object).Count
            DurationSeconds   = [math]::Round(((Get-Date) - $Context.StartTime).TotalSeconds, 2)
            Results           = @($Context.Results)
            SHA256            = @($sha256)
        }
        $manifest | ConvertTo-Json -Depth 6 | Out-File -FilePath $manifestPath -Encoding UTF8 -Width 4096
        Add-DFIRCollectedFile -Context $Context -Path $manifestPath
        return $true
    }
    catch {
        Write-DFIRLog -Context $Context -Level ERROR -Message ("Manifest generation failed: {0}" -f $_.Exception.Message)
        return $false
    }
}

function Write-DFIRSha256Sidecar {
<#
.SYNOPSIS
    Writes <file>.sha256 in sha256sum -c format (lower-case hash, two spaces, file name, LF).
.OUTPUTS
    System.String (the hash), or $null on failure.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Path)

    $hash = Get-DFIRFileSha256 -Path $Path
    if (-not $hash) { return $null }
    $line = '{0}  {1}' -f $hash.ToLowerInvariant(), (Split-Path -Leaf $Path)
    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText(($Path + '.sha256'), ($line + "`n"), $encoding)
    return $hash
}

function New-DFIRZipArchive {
<#
.SYNOPSIS
    Builds the evidence ZIP with System.IO.Compression (Zip64, no 2 GB limit).
.DESCRIPTION
    Entries are stored as <collection folder>/<relative path>. Paths listed in
    -ExcludePath (the memory image) are not added.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$SourceRoot,
        [Parameter(Mandatory=$true)][string]$ZipPath,
        [string[]]$ExcludePath = @()
    )

    Add-Type -AssemblyName System.IO.Compression -ErrorAction Stop
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
    $rootName = Split-Path -Leaf $SourceRoot
    $prefixLength = $SourceRoot.TrimEnd('\').Length + 1
    $zip = [System.IO.Compression.ZipFile]::Open($ZipPath, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($file in (Get-ChildItem -LiteralPath $SourceRoot -File -Recurse -Force -ErrorAction Stop)) {
            if ($ExcludePath -contains $file.FullName) { continue }
            $entryName = $rootName + '/' + ($file.FullName.Substring($prefixLength) -replace '\\', '/')
            [void][System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $file.FullName, $entryName, [System.IO.Compression.CompressionLevel]::Optimal)
        }
    }
    finally {
        $zip.Dispose()
    }
}

function Compress-DFIROutput {
<#
.SYNOPSIS
    Compresses the completed collection folder to a ZIP archive with a .sha256 sidecar.
.DESCRIPTION
    Uses System.IO.Compression (fast, Zip64) and falls back to Compress-Archive.
    A captured memory image is left out of the archive and recorded in
    <zip base>.memory-image-location.txt beside the ZIP.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    $zipName = '{0}_{1}.zip' -f $env:COMPUTERNAME, $Context.Timestamp
    $zipPath = Join-Path $Context.OutputBase $zipName
    $memoryImage = $null
    if ($Context.ContainsKey('MemoryImagePath') -and $Context['MemoryImagePath'] -and (Test-Path -LiteralPath $Context['MemoryImagePath'] -PathType Leaf)) {
        $memoryImage = $Context['MemoryImagePath']
    }

    try {
        if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force -ErrorAction Stop }
        $method = 'System.IO.Compression'
        try {
            $exclude = @()
            if ($memoryImage) { $exclude = @($memoryImage) }
            New-DFIRZipArchive -SourceRoot $Context.OutputRoot -ZipPath $zipPath -ExcludePath $exclude
        }
        catch {
            Write-DFIRLog -Context $Context -Level WARN -Message ("System.IO.Compression archive failed, falling back to Compress-Archive: {0}" -f $_.Exception.Message)
            if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force -ErrorAction SilentlyContinue }
            $method = 'Compress-Archive'
            if ($memoryImage) {
                # Compress-Archive cannot exclude a single file; leave the whole
                # memory folder out (its README and sidecar stay beside the image).
                $items = @(Get-ChildItem -LiteralPath $Context.OutputRoot -Force | Where-Object { $_.FullName -ne $Context.Paths.Memory } | ForEach-Object { $_.FullName })
                Compress-Archive -LiteralPath $items -DestinationPath $zipPath -CompressionLevel Optimal -Force -ErrorAction Stop -Verbose:$false
            }
            else {
                Compress-Archive -LiteralPath $Context.OutputRoot -DestinationPath $zipPath -CompressionLevel Optimal -Force -ErrorAction Stop -Verbose:$false
            }
        }

        $zipHash = Write-DFIRSha256Sidecar -Path $zipPath
        if (-not $zipHash) {
            Write-DFIRLog -Context $Context -Level WARN -Message ("Could not write SHA256 sidecar for {0}" -f $zipPath)
        }
        if ($memoryImage) {
            $locationNote = Join-Path $Context.OutputBase ([IO.Path]::GetFileNameWithoutExtension($zipName) + '.memory-image-location.txt')
            @(
                'The memory image for this collection is stored outside the archive:',
                $memoryImage,
                ('SHA256 sidecar: {0}.sha256' -f $memoryImage),
                'Transfer it separately and verify it with: sha256sum -c <image>.raw.sha256'
            ) | Out-File -FilePath $locationNote -Encoding UTF8 -Width 4096
            Write-DFIRLog -Context $Context -Message ("Memory image excluded from the archive; location recorded in {0}" -f $locationNote)
            $Context['MemoryLocationNote'] = $locationNote
        }
        Write-DFIRLog -Context $Context -Level SUCCESS -Message ("Created archive via {0}: {1} SHA256={2}" -f $method, $zipPath, $zipHash)
        $Context['ZipPath'] = $zipPath
        return $true
    }
    catch {
        Write-DFIRLog -Context $Context -Level ERROR -Message ("Compression failed: {0}" -f $_.Exception.Message)
        return $false
    }
}

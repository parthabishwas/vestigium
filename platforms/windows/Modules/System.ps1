Set-StrictMode -Version 2.0

function Invoke-DFIRSystemCollection {
<#
.SYNOPSIS
    Collects asset, host, installed application, scheduled task, and system information artifacts.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    $success = $true
    Write-DFIRLog -Context $Context -Message 'Starting system collection'

    $success = (Export-DFIRAssetInfo -Context $Context) -and $success
    $success = (Export-DFIRInstalledApplications -Context $Context) -and $success
    $success = (Export-DFIRScheduledTasks -Context $Context) -and $success
    $success = (Export-DFIRSystemInformation -Context $Context) -and $success

    Add-DFIRResult -Context $Context -Name 'System' -Success $success
    return $success
}

function Export-DFIRAssetInfo {
<#
.SYNOPSIS
    Exports hardware, OS, disk, network, timezone, and user asset information.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    $path = Join-Path $Context.Paths.System 'AssetInfo.txt'
    return Save-DFIRText -Context $Context -Name 'AssetInfo' -Path $path -ScriptBlock {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
        $bios = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
        $cpu = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue
        $disks = Get-CimInstance Win32_DiskDrive -ErrorAction SilentlyContinue
        $logical = Get-CimInstance Win32_LogicalDisk -ErrorAction SilentlyContinue
        $nics = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction SilentlyContinue
        $tz = Get-TimeZone -ErrorAction SilentlyContinue
        $uefi = $false
        try { $uefi = Confirm-SecureBootUEFI -ErrorAction Stop } catch { $uefi = $false }

        [pscustomobject]@{
            ComputerName       = $env:COMPUTERNAME
            Hostname           = [System.Net.Dns]::GetHostName()
            Username           = $env:USERNAME
            Domain             = $env:USERDOMAIN
            Manufacturer       = if ($cs) { $cs.Manufacturer } else { $null }
            Model              = if ($cs) { $cs.Model } else { $null }
            SerialNumber       = if ($bios) { $bios.SerialNumber } else { $null }
            BIOSVersion        = if ($bios) { ($bios.SMBIOSBIOSVersion -join '; ') } else { $null }
            UEFI               = $uefi
            WindowsVersion     = if ($os) { $os.Caption } else { $null }
            BuildNumber        = if ($os) { $os.BuildNumber } else { $null }
            InstallDate        = if ($os) { $os.InstallDate } else { $null }
            CPU                = if ($cpu) { ($cpu | Select-Object -ExpandProperty Name) -join '; ' } else { $null }
            RAMGB              = if ($cs) { [math]::Round($cs.TotalPhysicalMemory / 1GB, 2) } else { $null }
            TimeZone           = if ($tz) { $tz.DisplayName } else { $null }
            LastBoot           = if ($os) { $os.LastBootUpTime } else { $null }
            CurrentLoggedUser  = if ($cs) { $cs.UserName } else { $null }
        } | Format-List

        ''
        'Disk Information'
        $disks | Select-Object Model, SerialNumber, InterfaceType, MediaType, Size | Format-Table -AutoSize
        ''
        'Logical Drives'
        $logical | Select-Object DeviceID, DriveType, FileSystem, Size, FreeSpace, VolumeName | Format-Table -AutoSize
        ''
        'Network Adapters'
        $nics | Select-Object Description, MACAddress, IPAddress, DefaultIPGateway, DNSServerSearchOrder | Format-List
    }
}

function Export-DFIRInstalledApplications {
<#
.SYNOPSIS
    Enumerates installed applications from uninstall registry keys without using wmic product.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    $path = Join-Path $Context.Paths.System 'InstalledApplications.csv'
    return Export-DFIRCsv -Context $Context -Name 'InstalledApplications' -Path $path -ScriptBlock {
        $roots = @(
            'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
        )
        foreach ($root in $roots) {
            Get-ItemProperty -Path $root -ErrorAction SilentlyContinue | Where-Object {
                Get-DFIRObjectProperty -InputObject $_ -Name 'DisplayName'
            } | ForEach-Object {
                [pscustomobject]@{
                    DisplayName     = Get-DFIRObjectProperty -InputObject $_ -Name 'DisplayName'
                    DisplayVersion  = Get-DFIRObjectProperty -InputObject $_ -Name 'DisplayVersion'
                    Publisher       = Get-DFIRObjectProperty -InputObject $_ -Name 'Publisher'
                    InstallDate     = Get-DFIRObjectProperty -InputObject $_ -Name 'InstallDate'
                    InstallLocation = Get-DFIRObjectProperty -InputObject $_ -Name 'InstallLocation'
                    UninstallString = Get-DFIRObjectProperty -InputObject $_ -Name 'UninstallString'
                    RegistryKey     = Get-DFIRObjectProperty -InputObject $_ -Name 'PSPath'
                }
            }
        }
    }
}

function Export-DFIRScheduledTasks {
<#
.SYNOPSIS
    Exports scheduled task data using schtasks and Get-ScheduledTask.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    $success = $true
    $success = (Invoke-DFIRSafeCommand -Context $Context -Name 'schtasks query verbose' -FilePath 'schtasks.exe' -Arguments @('/query','/fo','LIST','/v') -OutputPath (Join-Path $Context.Paths.ScheduledTasks 'schtasks_LIST_verbose.txt')) -and $success
    $success = (Export-DFIRCsv -Context $Context -Name 'Get-ScheduledTask CSV' -Path (Join-Path $Context.Paths.ScheduledTasks 'Get-ScheduledTask.csv') -ScriptBlock {
        Get-ScheduledTask -ErrorAction SilentlyContinue | Select-Object TaskName, TaskPath, State, Author, Date, Description, URI
    }) -and $success
    # Raw task XML carries the registration timestamp, author SID and exact
    # command line. schtasks /v omits the registration date, which is what pins
    # when an unauthorised task was created.
    $success = (Invoke-DFIRSafeCommand -Context $Context -Name 'schtasks query XML' -FilePath 'schtasks.exe' -Arguments @('/query','/xml','ONE') -OutputPath (Join-Path $Context.Paths.ScheduledTasks 'schtasks_ALL.xml')) -and $success
    $success = (Copy-DFIRScheduledTaskDefinitions -Context $Context) -and $success

    $success = (Save-DFIRText -Context $Context -Name 'Get-ScheduledTask TXT' -Path (Join-Path $Context.Paths.ScheduledTasks 'Get-ScheduledTask.txt') -ScriptBlock {
        Get-ScheduledTask -ErrorAction SilentlyContinue | Format-List *
    }) -and $success
    return $success
}

function Copy-DFIRScheduledTaskDefinitions {
<#
.SYNOPSIS
    Copies the on-disk scheduled task definition files from C:\Windows\System32\Tasks.
.DESCRIPTION
    Each file is the task's raw XML including RegistrationInfo\Date and the
    author SID. Non-Microsoft tasks are prioritised so the copy stays small.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    $tasksRoot = Join-Path $env:SystemRoot 'System32\Tasks'
    if (-not (Test-Path -LiteralPath $tasksRoot -PathType Container)) {
        Write-DFIRLog -Context $Context -Level WARN -Message 'Scheduled task definitions skipped: System32\Tasks not found'
        return $true
    }

    $dest = Join-Path $Context.Paths.ScheduledTasks 'TaskDefinitions'
    try { New-Item -ItemType Directory -Path $dest -Force -ErrorAction Stop | Out-Null }
    catch {
        Write-DFIRLog -Context $Context -Level ERROR -Message ("Task definition folder create failed: {0}" -f $_.Exception.Message)
        return $false
    }

    $success = $true
    try {
        Get-ChildItem -LiteralPath $tasksRoot -File -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -notmatch '\\Tasks\\Microsoft\\Windows\\' } |
            ForEach-Object {
                $relative = $_.FullName.Substring($tasksRoot.Length).TrimStart('\')
                $safeName = Get-DFIRSafeFileName -Value $relative
                Copy-DFIRLockedFile -Context $Context -Source $_.FullName -Destination (Join-Path $dest ($safeName + '.xml')) | Out-Null
            }
    }
    catch {
        $success = $false
        Write-DFIRLog -Context $Context -Level ERROR -Message ("Task definition copy failed: {0}" -f $_.Exception.Message)
    }
    return $success
}

function Export-DFIRSystemInformation {
<#
.SYNOPSIS
    Exports OS, driver, hotfix, and environment information.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    $success = $true
    $success = (Invoke-DFIRSafeCommand -Context $Context -Name 'systeminfo' -FilePath 'systeminfo.exe' -OutputPath (Join-Path $Context.Paths.SystemInfo 'systeminfo.txt')) -and $success
    $success = (Invoke-DFIRSafeCommand -Context $Context -Name 'driverquery' -FilePath 'driverquery.exe' -Arguments @('/v') -OutputPath (Join-Path $Context.Paths.SystemInfo 'driverquery_verbose.txt')) -and $success
    $success = (Export-DFIRCsv -Context $Context -Name 'Get-HotFix' -Path (Join-Path $Context.Paths.SystemInfo 'HotFixes.csv') -ScriptBlock { Get-HotFix -ErrorAction SilentlyContinue }) -and $success
    $success = (Export-DFIRCsv -Context $Context -Name 'Installed Drivers' -Path (Join-Path $Context.Paths.SystemInfo 'InstalledDrivers.csv') -ScriptBlock { Get-CimInstance Win32_PnPSignedDriver -ErrorAction SilentlyContinue }) -and $success
    $success = (Save-DFIRText -Context $Context -Name 'Environment Variables' -Path (Join-Path $Context.Paths.SystemInfo 'EnvironmentVariables.txt') -ScriptBlock { Get-ChildItem Env: | Sort-Object Name | Format-Table -AutoSize }) -and $success
    return $success
}

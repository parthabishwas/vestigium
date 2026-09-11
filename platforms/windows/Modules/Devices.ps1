Set-StrictMode -Version 2.0

function Invoke-DFIRDeviceCollection {
<#
.SYNOPSIS
    Collects removable-media, portable-device and volume evidence.
.DESCRIPTION
    Answers which external drives and phones have been attached to the endpoint
    and what non-system volumes exist. Without this the analyst has to infer
    removable media indirectly from driver-install events or third-party scan
    logs, which gives no volume label, serial or mount history.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    Write-DFIRLog -Context $Context -Message 'Starting device and volume collection'
    $success = $true

    $success = (Export-DFIRUsbRegistry -Context $Context) -and $success
    $success = (Export-DFIRVolumeInventory -Context $Context) -and $success
    $success = (Export-DFIRUserMountPoints -Context $Context) -and $success

    Add-DFIRResult -Context $Context -Name 'Devices' -Success $success
    return $success
}

function Export-DFIRUsbRegistry {
<#
.SYNOPSIS
    Exports USB, USBSTOR, portable-device and mounted-volume registry keys.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    $keys = [ordered]@{
        'USBSTOR'          = 'HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR'
        'USB'              = 'HKLM\SYSTEM\CurrentControlSet\Enum\USB'
        'SCSI'             = 'HKLM\SYSTEM\CurrentControlSet\Enum\SCSI'
        'MountedDevices'   = 'HKLM\SYSTEM\MountedDevices'
        'PortableDevices'  = 'HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices'
        'VolumeInfoCache'  = 'HKLM\SOFTWARE\Microsoft\Windows Search\VolumeInfoCache'
        'DiskDevices'      = 'HKLM\SYSTEM\CurrentControlSet\Services\disk\Enum'
    }

    $success = $true
    foreach ($name in $keys.Keys) {
        $reg = Join-Path $Context.Paths.Devices ($name + '.reg')
        $txt = Join-Path $Context.Paths.Devices ($name + '.txt')
        $success = (Export-DFIRRegistryKey -Context $Context -RegistryPath $keys[$name] -RegExePath $reg -TxtPath $txt) -and $success
    }
    return $success
}

function Export-DFIRVolumeInventory {
<#
.SYNOPSIS
    Enumerates every volume, including removable and network drives.
.DESCRIPTION
    Also records a shallow top-level listing of non-system fixed and removable
    volumes so that data stores such as personal backup drives are visible in
    the evidence rather than only inferable from other sources.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    $success = $true

    $success = (Export-DFIRCsv -Context $Context -Name 'Volumes' -Path (Join-Path $Context.Paths.Devices 'Volumes.csv') -ScriptBlock {
        Get-CimInstance Win32_Volume -ErrorAction SilentlyContinue |
            Select-Object DriveLetter, Label, FileSystem, DriveType, Capacity, FreeSpace, SerialNumber, DeviceID
    }) -and $success

    $success = (Export-DFIRCsv -Context $Context -Name 'Logical disks' -Path (Join-Path $Context.Paths.Devices 'LogicalDisks.csv') -ScriptBlock {
        Get-CimInstance Win32_LogicalDisk -ErrorAction SilentlyContinue |
            Select-Object DeviceID, DriveType, FileSystem, VolumeName, VolumeSerialNumber, Size, FreeSpace, ProviderName
    }) -and $success

    $success = (Export-DFIRCsv -Context $Context -Name 'Disk drives' -Path (Join-Path $Context.Paths.Devices 'DiskDrives.csv') -ScriptBlock {
        Get-CimInstance Win32_DiskDrive -ErrorAction SilentlyContinue |
            Select-Object Model, SerialNumber, InterfaceType, MediaType, Size, PNPDeviceID
    }) -and $success

    $success = (Export-DFIRCsv -Context $Context -Name 'PnP USB devices' -Path (Join-Path $Context.Paths.Devices 'PnPUsbDevices.csv') -ScriptBlock {
        Get-CimInstance Win32_PnPEntity -ErrorAction SilentlyContinue |
            Where-Object { $_.PNPDeviceID -and ($_.PNPDeviceID -like 'USB*' -or $_.PNPDeviceID -like 'USBSTOR*' -or $_.PNPDeviceID -like 'WPDBUSENUM*') } |
            Select-Object Name, Manufacturer, PNPDeviceID, Status, Service
    }) -and $success

    # Shallow listing only: depth 2 keeps the output small while still revealing
    # top-level data stores on attached drives.
    try {
        $systemDrive = ($env:SystemDrive).TrimEnd('\')
        $listingPath = Join-Path $Context.Paths.Devices 'NonSystemVolume_TopLevel.txt'
        $lines = New-Object System.Collections.ArrayList
        [void]$lines.Add('Top-level listing (depth 2) of non-system fixed and removable volumes')
        [void]$lines.Add('---')

        Get-CimInstance Win32_LogicalDisk -ErrorAction SilentlyContinue |
            Where-Object { ($_.DriveType -eq 2 -or $_.DriveType -eq 3) -and $_.DeviceID -and $_.DeviceID -ne $systemDrive } |
            ForEach-Object {
                $root = $_.DeviceID + '\'
                [void]$lines.Add('')
                [void]$lines.Add(("=== {0} (DriveType={1}, Label={2}) ===" -f $root, $_.DriveType, $_.VolumeName))
                try {
                    Get-ChildItem -LiteralPath $root -Force -ErrorAction SilentlyContinue |
                        Select-Object -First 200 |
                        ForEach-Object {
                            [void]$lines.Add(("  {0}  {1}  {2}" -f $_.Mode, $_.LastWriteTimeUtc, $_.Name))
                            if ($_.PSIsContainer) {
                                Get-ChildItem -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue |
                                    Select-Object -First 50 |
                                    ForEach-Object { [void]$lines.Add(("      {0}  {1}  {2}" -f $_.Mode, $_.LastWriteTimeUtc, $_.Name)) }
                            }
                        }
                }
                catch {
                    [void]$lines.Add(("  <listing failed: {0}>" -f $_.Exception.Message))
                }
            }

        $lines | Out-File -FilePath $listingPath -Encoding UTF8 -Width 4096
        Add-DFIRCollectedFile -Context $Context -Path $listingPath
    }
    catch {
        $success = $false
        Write-DFIRLog -Context $Context -Level ERROR -Message ("Non-system volume listing failed: {0}" -f $_.Exception.Message)
    }

    return $success
}

function Export-DFIRUserMountPoints {
<#
.SYNOPSIS
    Exports per-user MountPoints2, which records volumes mounted by that user.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    $reg = Join-Path $Context.Paths.Devices 'HKCU_MountPoints2.reg'
    $txt = Join-Path $Context.Paths.Devices 'HKCU_MountPoints2.txt'
    $success = Export-DFIRRegistryKey -Context $Context `
        -RegistryPath 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2' `
        -RegExePath $reg -TxtPath $txt

    # Per-target-user hives are loaded and unloaded by the Registry module; read
    # any that are already mounted under HKU rather than loading them again.
    $profiles = if ($Context.ContainsKey('TargetProfiles') -and $Context['TargetProfiles']) {
        @($Context['TargetProfiles'])
    } else {
        @()
    }

    foreach ($profile in $profiles) {
        try {
            # Profiles carry the SID from ProfileList; translating the folder
            # name fails for renamed, relocated or domain profiles.
            $sid = [string](Get-DFIRObjectProperty -InputObject $profile -Name 'SID')
            if ([string]::IsNullOrWhiteSpace($sid)) {
                try {
                    $account = New-Object System.Security.Principal.NTAccount($profile.UserName)
                    $sid = $account.Translate([System.Security.Principal.SecurityIdentifier]).Value
                }
                catch { continue }
            }
            if (-not $sid) { continue }

            $hkuPath = ('HKU\{0}\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2' -f $sid)
            & reg.exe query $hkuPath 2>&1 | Out-Null
            if ($LASTEXITCODE -ne 0) { continue }

            $safe = Get-DFIRSafeFileName -Value $profile.UserName
            $userReg = Join-Path $Context.Paths.Devices ('MountPoints2_' + $safe + '.reg')
            $userTxt = Join-Path $Context.Paths.Devices ('MountPoints2_' + $safe + '.txt')
            Export-DFIRRegistryKey -Context $Context -RegistryPath $hkuPath -RegExePath $userReg -TxtPath $userTxt | Out-Null
        }
        catch {
            Write-DFIRLog -Context $Context -Level WARN -Message ("MountPoints2 export failed for {0}: {1}" -f $profile.UserName, $_.Exception.Message)
        }
    }

    return $success
}

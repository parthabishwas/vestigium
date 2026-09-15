Set-StrictMode -Version 2.0

function Invoke-DFIRRegistryCollection {
<#
.SYNOPSIS
    Exports registry persistence locations to REG and TXT formats.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    Write-DFIRLog -Context $Context -Message 'Starting registry persistence collection'
    $success = $true
    $keys = [ordered]@{
        HKLM_Run              = 'HKLM\Software\Microsoft\Windows\CurrentVersion\Run'
        HKLM_RunOnce          = 'HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce'
        HKLM_RunServices      = 'HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices'
        HKLM_WowRun           = 'HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
        HKCU_Run              = 'HKCU\Software\Microsoft\Windows\CurrentVersion\Run'
        HKCU_RunOnce          = 'HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce'
        Policies_Explorer_Run = 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
        HKCU_Policies_Run     = 'HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
        Winlogon              = 'HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
        IFEO                  = 'HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
        AppInit_DLLs          = 'HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows'
        Explorer_Shell        = 'HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
        KnownDLLs             = 'HKLM\System\CurrentControlSet\Control\Session Manager\KnownDLLs'
        Services              = 'HKLM\System\CurrentControlSet\Services'
    }

    foreach ($name in $keys.Keys) {
        $safe = Get-DFIRSafeFileName -Value $name
        $regPath = Join-Path $Context.Paths.Registry ($safe + '.reg')
        $txtPath = Join-Path $Context.Paths.Registry ($safe + '.txt')
        $success = (Export-DFIRRegistryKey -Context $Context -RegistryPath $keys[$name] -RegExePath $regPath -TxtPath $txtPath) -and $success
    }

    $success = (Export-DFIRTargetUserRegistryPersistence -Context $Context) -and $success

    Add-DFIRResult -Context $Context -Name 'Registry' -Success $success
    return $success
}

function Test-DFIRLoadedUserHive {
<#
.SYNOPSIS
    True when HKU\<SID> is mounted (the user is logged on or the hive is held open).
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$SID)

    if ([string]::IsNullOrWhiteSpace($SID)) { return $false }
    try {
        & reg.exe query ('HKU\{0}' -f $SID) 2>&1 | Out-Null
        return ($LASTEXITCODE -eq 0)
    }
    catch {
        return $false
    }
}

function Export-DFIRTargetUserRegistryPersistence {
<#
.SYNOPSIS
    Exports target-user HKCU persistence keys from NTUSER.DAT hives.
.DESCRIPTION
    Each hive is loaded under HKU\Vestigium_<user>_<id>. When reg load fails
    because the user is logged on, the hive is already mounted at HKU\<SID>
    and the keys are exported from there instead. The profile fails only when
    neither source is available.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    $success = $true
    $targetProfiles = if ($Context.ContainsKey('TargetProfiles') -and $Context['TargetProfiles']) { @($Context['TargetProfiles']) } else { @() }
    foreach ($profile in $targetProfiles) {
        $sid = [string](Get-DFIRObjectProperty -InputObject $profile -Name 'SID')
        if (-not (Test-Path -LiteralPath $profile.NTUserDat -PathType Leaf)) {
            Write-DFIRLog -Context $Context -Level WARN -Message ("Target NTUSER.DAT not found for {0}: {1}" -f $profile.UserName, $profile.NTUserDat)
            continue
        }

        $safeUser = Get-DFIRSafeFileName -Value $profile.UserName
        $mountName = 'Vestigium_{0}_{1}' -f $safeUser, ([guid]::NewGuid().ToString('N').Substring(0,8))
        $mountRoot = 'HKU\{0}' -f $mountName
        $hiveRoot = $null
        $loaded = $false
        try {
            $loadOutput = & reg.exe load $mountRoot $profile.NTUserDat 2>&1
            $loadExit = $LASTEXITCODE
            $loadLog = Join-Path $Context.Paths.Registry ("TargetUser_{0}_HiveLoad.log.txt" -f $safeUser)
            $loadOutput | Out-File -FilePath $loadLog -Encoding UTF8 -Width 4096
            if ($loadExit -eq 0) {
                $loaded = $true
                $hiveRoot = $mountRoot
            }
            elseif (Test-DFIRLoadedUserHive -SID $sid) {
                $hiveRoot = 'HKU\{0}' -f $sid
                ("reg load failed (exit {0}); hive already mounted - exported from {1} instead" -f $loadExit, $hiveRoot) | Add-Content -Path $loadLog -Encoding UTF8
                Write-DFIRLog -Context $Context -Message ("NTUSER.DAT for {0} is in use (user logged on); exporting persistence keys from {1}" -f $profile.UserName, $hiveRoot)
            }
            Add-DFIRCollectedFile -Context $Context -Path $loadLog

            if (-not $hiveRoot) {
                Write-DFIRLog -Context $Context -Level WARN -Message ("Could not load NTUSER.DAT for {0} and no mounted hive found at HKU\{1}" -f $profile.UserName, $sid)
                $success = $false
                continue
            }

            $userKeys = [ordered]@{
                Run              = "$hiveRoot\Software\Microsoft\Windows\CurrentVersion\Run"
                RunOnce          = "$hiveRoot\Software\Microsoft\Windows\CurrentVersion\RunOnce"
                Policies_Run     = "$hiveRoot\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
                Winlogon         = "$hiveRoot\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
                Explorer_Startup = "$hiveRoot\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved"
                Office           = "$hiveRoot\Software\Microsoft\Office"
            }

            foreach ($name in $userKeys.Keys) {
                $safeName = Get-DFIRSafeFileName -Value ("TargetUser_{0}_{1}" -f $safeUser, $name)
                $regPath = Join-Path $Context.Paths.Registry ($safeName + '.reg')
                $txtPath = Join-Path $Context.Paths.Registry ($safeName + '.txt')
                Export-DFIRRegistryKey -Context $Context -RegistryPath $userKeys[$name] -RegExePath $regPath -TxtPath $txtPath | Out-Null
            }
        }
        catch {
            $success = $false
            Write-DFIRLog -Context $Context -Level ERROR -Message ("Target user registry export failed for {0}: {1}" -f $profile.UserName, $_.Exception.Message)
        }
        finally {
            if ($loaded) {
                try {
                    [gc]::Collect()
                    Start-Sleep -Milliseconds 200
                    & reg.exe unload $mountRoot 2>&1 | Out-File -FilePath (Join-Path $Context.Paths.Registry ("TargetUser_{0}_HiveUnload.log.txt" -f $safeUser)) -Encoding UTF8 -Width 4096
                }
                catch {
                    Write-DFIRLog -Context $Context -Level WARN -Message ("Could not unload target hive {0}: {1}" -f $mountRoot, $_.Exception.Message)
                }
            }
        }
    }

    return $success
}

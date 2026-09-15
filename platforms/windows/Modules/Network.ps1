Set-StrictMode -Version 2.0

function Invoke-DFIRNetworkCollection {
<#
.SYNOPSIS
    Collects network configuration, connection, DNS, ARP, route, and hosts-file evidence.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    Write-DFIRLog -Context $Context -Message 'Starting network collection'
    $success = $true
    $success = (Invoke-DFIRSafeCommand -Context $Context -Name 'ipconfig all' -FilePath 'ipconfig.exe' -Arguments @('/all') -OutputPath (Join-Path $Context.Paths.Network 'ipconfig_all.txt')) -and $success
    $success = (Invoke-DFIRSafeCommand -Context $Context -Name 'arp all' -FilePath 'arp.exe' -Arguments @('-a') -OutputPath (Join-Path $Context.Paths.Network 'arp_a.txt')) -and $success
    $success = (Invoke-DFIRSafeCommand -Context $Context -Name 'route print' -FilePath 'route.exe' -Arguments @('print') -OutputPath (Join-Path $Context.Paths.Network 'route_print.txt')) -and $success
    $success = (Invoke-DFIRSafeCommand -Context $Context -Name 'netstat abno' -FilePath 'netstat.exe' -Arguments @('-abno') -OutputPath (Join-Path $Context.Paths.Network 'netstat_abno.txt')) -and $success
    $success = (Invoke-DFIRSafeCommand -Context $Context -Name 'netstat ano' -FilePath 'netstat.exe' -Arguments @('-ano') -OutputPath (Join-Path $Context.Paths.Network 'netstat_ano.txt')) -and $success
    $success = (Invoke-DFIRSafeCommand -Context $Context -Name 'ipconfig displaydns' -FilePath 'ipconfig.exe' -Arguments @('/displaydns') -OutputPath (Join-Path $Context.Paths.Network 'ipconfig_displaydns.txt')) -and $success
    $success = (Save-DFIRText -Context $Context -Name 'Get-NetTCPConnection' -Path (Join-Path $Context.Paths.Network 'Get-NetTCPConnection.txt') -ScriptBlock { Get-NetTCPConnection -ErrorAction SilentlyContinue | Format-Table -AutoSize }) -and $success
    $success = (Save-DFIRText -Context $Context -Name 'Get-NetIPAddress' -Path (Join-Path $Context.Paths.Network 'Get-NetIPAddress.txt') -ScriptBlock { Get-NetIPAddress -ErrorAction SilentlyContinue | Format-Table -AutoSize }) -and $success
    $success = (Save-DFIRText -Context $Context -Name 'Get-NetAdapter' -Path (Join-Path $Context.Paths.Network 'Get-NetAdapter.txt') -ScriptBlock { Get-NetAdapter -ErrorAction SilentlyContinue | Format-Table -AutoSize }) -and $success
    $success = (Save-DFIRText -Context $Context -Name 'Get-NetRoute' -Path (Join-Path $Context.Paths.Network 'Get-NetRoute.txt') -ScriptBlock { Get-NetRoute -ErrorAction SilentlyContinue | Format-Table -AutoSize }) -and $success

    # Host firewall: per-profile state (a disabled profile is a defence-evasion
    # signal) and the full rule set (malware-added inbound Allow rules).
    $success = (Invoke-DFIRSafeCommand -Context $Context -Name 'firewall profiles' -FilePath 'netsh.exe' -Arguments @('advfirewall','show','allprofiles') -OutputPath (Join-Path $Context.Paths.Network 'FirewallProfiles.txt')) -and $success
    $success = (Invoke-DFIRSafeCommand -Context $Context -Name 'firewall rules' -FilePath 'netsh.exe' -Arguments @('advfirewall','firewall','show','rule','name=all') -OutputPath (Join-Path $Context.Paths.Network 'FirewallRules.txt')) -and $success

    # BITS transfer jobs (a common download / persistence / exfil channel). One
    # row per file so remote URLs and local destinations are both visible.
    $success = (Export-DFIRCsv -Context $Context -Name 'BITS transfers' -Path (Join-Path $Context.Paths.Network 'BitsTransfers.csv') -ScriptBlock {
        try { $jobs = @(Get-BitsTransfer -AllUsers -ErrorAction Stop) } catch { $jobs = @() }
        foreach ($j in $jobs) {
            $files = @()
            try { $files = @($j.FileList) } catch { $files = @() }
            if ($files.Count -eq 0) {
                [pscustomobject]@{ JobId = $j.JobId; DisplayName = $j.DisplayName; Owner = $j.OwnerAccount; State = $j.JobState; Type = $j.TransferType; Created = $j.CreationTime; RemoteName = ''; LocalName = '' }
            }
            else {
                foreach ($f in $files) {
                    [pscustomobject]@{ JobId = $j.JobId; DisplayName = $j.DisplayName; Owner = $j.OwnerAccount; State = $j.JobState; Type = $j.TransferType; Created = $j.CreationTime; RemoteName = $f.RemoteName; LocalName = $f.LocalName }
                }
            }
        }
    }) -and $success

    # WinRM / remote-management state (lateral-movement surface).
    $success = (Save-DFIRText -Context $Context -Name 'WinRM state' -Path (Join-Path $Context.Paths.Network 'WinRM.txt') -ScriptBlock {
        $svc = Get-Service -Name WinRM -ErrorAction SilentlyContinue
        'WinRM service status: ' + $(if ($svc) { [string]$svc.Status } else { 'not found' })
        ''
        '=== winrm get winrm/config ==='
        try { & winrm get winrm/config 2>&1 } catch { 'winrm config unavailable: ' + $_.Exception.Message }
        ''
        '=== winrm enumerate winrm/config/listener ==='
        try { & winrm enumerate winrm/config/listener 2>&1 } catch { 'winrm listeners unavailable: ' + $_.Exception.Message }
    }) -and $success

    $hostsSource = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    $hostsDest = Join-Path $Context.Paths.Hosts 'hosts'
    $success = (Copy-DFIRFile -Context $Context -Source $hostsSource -Destination $hostsDest) -and $success

    Add-DFIRResult -Context $Context -Name 'Network' -Success $success
    return $success
}

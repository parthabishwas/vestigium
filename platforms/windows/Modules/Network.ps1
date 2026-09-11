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

    $hostsSource = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    $hostsDest = Join-Path $Context.Paths.Hosts 'hosts'
    $success = (Copy-DFIRFile -Context $Context -Source $hostsSource -Destination $hostsDest) -and $success

    Add-DFIRResult -Context $Context -Name 'Network' -Success $success
    return $success
}

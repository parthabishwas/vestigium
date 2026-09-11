Set-StrictMode -Version 2.0

function Invoke-DFIRServiceCollection {
<#
.SYNOPSIS
    Collects Windows service evidence.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    Write-DFIRLog -Context $Context -Message 'Starting service collection'
    $success = $true
    $success = (Export-DFIRCsv -Context $Context -Name 'Get-Service CSV' -Path (Join-Path $Context.Paths.Services 'Get-Service.csv') -ScriptBlock { Get-Service -ErrorAction SilentlyContinue | Select-Object Name, DisplayName, Status, ServiceType, CanStop, CanPauseAndContinue }) -and $success
    $success = (Save-DFIRText -Context $Context -Name 'Get-Service TXT' -Path (Join-Path $Context.Paths.Services 'Get-Service.txt') -ScriptBlock { Get-Service -ErrorAction SilentlyContinue | Sort-Object Name | Format-Table -AutoSize }) -and $success
    $success = (Export-DFIRCsv -Context $Context -Name 'Win32_Service CSV' -Path (Join-Path $Context.Paths.Services 'Win32_Service.csv') -ScriptBlock { Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Select-Object Name, DisplayName, State, StartMode, PathName, StartName, ProcessId, ServiceType }) -and $success
    $success = (Invoke-DFIRSafeCommand -Context $Context -Name 'sc query' -FilePath 'sc.exe' -Arguments @('query','type=','service','state=','all') -OutputPath (Join-Path $Context.Paths.Services 'sc_query_all.txt')) -and $success

    Add-DFIRResult -Context $Context -Name 'Services' -Success $success
    return $success
}

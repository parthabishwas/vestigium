Set-StrictMode -Version 2.0

function Invoke-DFIRProcessCollection {
<#
.SYNOPSIS
    Collects process and running-service evidence.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    Write-DFIRLog -Context $Context -Message 'Starting process collection'
    $success = $true
    $success = (Invoke-DFIRSafeCommand -Context $Context -Name 'tasklist verbose' -FilePath 'tasklist.exe' -Arguments @('/v') -OutputPath (Join-Path $Context.Paths.Processes 'tasklist_v.txt')) -and $success
    $success = (Export-DFIRCsv -Context $Context -Name 'Get-Process CSV' -Path (Join-Path $Context.Paths.Processes 'Get-Process.csv') -ScriptBlock { Get-Process -ErrorAction SilentlyContinue | Select-Object * }) -and $success
    $success = (Save-DFIRText -Context $Context -Name 'Get-Process TXT' -Path (Join-Path $Context.Paths.Processes 'Get-Process.txt') -ScriptBlock { Get-Process -ErrorAction SilentlyContinue | Sort-Object ProcessName | Format-Table -AutoSize }) -and $success
    $success = (Export-DFIRCsv -Context $Context -Name 'Win32_Process CSV' -Path (Join-Path $Context.Paths.Processes 'Win32_Process.csv') -ScriptBlock { Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine, CreationDate, SessionId }) -and $success
    $success = (Export-DFIRCsv -Context $Context -Name 'Running Services CSV' -Path (Join-Path $Context.Paths.Processes 'RunningServices.csv') -ScriptBlock { Get-CimInstance Win32_Service -Filter "State='Running'" -ErrorAction SilentlyContinue | Select-Object Name, DisplayName, ProcessId, StartMode, PathName, StartName }) -and $success

    Add-DFIRResult -Context $Context -Name 'Processes' -Success $success
    return $success
}

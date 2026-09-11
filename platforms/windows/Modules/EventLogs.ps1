Set-StrictMode -Version 2.0

function Invoke-DFIREventLogCollection {
<#
.SYNOPSIS
    Exports selected Windows event logs as EVTX plus last 500 events as CSV.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    Write-DFIRLog -Context $Context -Message 'Starting event log collection'
    $success = $true
    $logs = [ordered]@{
        Security       = 'Security'
        System         = 'System'
        Application    = 'Application'
        Defender       = 'Microsoft-Windows-Windows Defender/Operational'
        PowerShell     = 'Windows PowerShell'
        PowerShellCore = 'Microsoft-Windows-PowerShell/Operational'
        TaskScheduler  = 'Microsoft-Windows-TaskScheduler/Operational'
        # RDP session history: answers "was this box actually accessed remotely"
        # rather than only "is 3389 listening".
        TSLocalSession = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
        TSRemoteConn   = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'
        RDPClient      = 'Microsoft-Windows-TerminalServices-RDPClient/Operational'
        # Removable-media history, WMI persistence execution, and BITS transfers.
        DriverFrameworks = 'Microsoft-Windows-DriverFrameworks-UserMode/Operational'
        WMIActivity    = 'Microsoft-Windows-WMI-Activity/Operational'
        BitsClient     = 'Microsoft-Windows-Bits-Client/Operational'
        WindowsDefenderWHC = 'Microsoft-Windows-Windows Defender/WHC'
        AppLockerEXE   = 'Microsoft-Windows-AppLocker/EXE and DLL'
        AppLockerMSI   = 'Microsoft-Windows-AppLocker/MSI and Script'
        Sysmon         = 'Microsoft-Windows-Sysmon/Operational'
        CodeIntegrity  = 'Microsoft-Windows-CodeIntegrity/Operational'
        SmbClientSec   = 'Microsoft-Windows-SmbClient/Security'
    }

    # Channels such as Sysmon and AppLocker are absent unless deployed. Their
    # absence is a fact about the estate, not a collection failure, so record it
    # and move on rather than marking the step failed.
    $availableChannels = @{}
    try {
        foreach ($channel in (& wevtutil.exe el 2>$null)) {
            if ($channel) { $availableChannels[$channel.Trim()] = $true }
        }
    }
    catch {
        Write-DFIRLog -Context $Context -Level WARN -Message ("Channel enumeration failed; all channels will be attempted: {0}" -f $_.Exception.Message)
    }

    $missingChannels = New-Object System.Collections.ArrayList

    foreach ($name in $logs.Keys) {
        $logName = $logs[$name]
        $safe = Get-DFIRSafeFileName -Value $name
        $evtx = Join-Path $Context.Paths.EventLogs ($safe + '.evtx')
        $csv = Join-Path $Context.Paths.EventLogs ($safe + '_Last500.csv')

        if ($availableChannels.Count -gt 0 -and -not $availableChannels.ContainsKey($logName)) {
            [void]$missingChannels.Add($logName)
            Write-DFIRLog -Context $Context -Message ("Channel not present on this host, skipped: {0}" -f $logName)
            continue
        }

        try {
            & wevtutil.exe epl $logName $evtx 2>&1 | Out-File -FilePath ($evtx + '.export.log.txt') -Encoding UTF8 -Width 4096
            if (Test-Path -LiteralPath $evtx) { Add-DFIRCollectedFile -Context $Context -Path $evtx }
        }
        catch {
            $success = $false
            Write-DFIRLog -Context $Context -Level ERROR -Message ("EVTX export failed for {0}: {1}" -f $logName, $_.Exception.Message)
        }

        try {
            $events = Get-WinEvent -LogName $logName -MaxEvents 500 -ErrorAction Stop
            $events |
                Select-Object TimeCreated, Id, ProviderName, LevelDisplayName, LogName, MachineName, Message |
                Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8 -Force
            Add-DFIRCollectedFile -Context $Context -Path $csv
        }
        catch {
            if ($_.Exception.Message -like '*No events were found*') {
                @() | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8 -Force
                Add-DFIRCollectedFile -Context $Context -Path $csv
                Write-DFIRLog -Context $Context -Level WARN -Message ("No events found for {0}; wrote empty CSV" -f $logName)
            }
            else {
                $success = $false
                Write-DFIRLog -Context $Context -Level WARN -Message ("Last 500 event export failed for {0}: {1}" -f $logName, $_.Exception.Message)
            }
        }
    }

    if ($missingChannels.Count -gt 0) {
        $notPresent = Join-Path $Context.Paths.EventLogs 'ChannelsNotPresent.txt'
        @('Channels absent on this host (not a collection failure):', '---') + $missingChannels |
            Out-File -FilePath $notPresent -Encoding UTF8 -Width 4096
        Add-DFIRCollectedFile -Context $Context -Path $notPresent
    }

    Add-DFIRResult -Context $Context -Name 'EventLogs' -Success $success
    return $success
}

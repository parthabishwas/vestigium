Set-StrictMode -Version 2.0

function Invoke-DFIRAutorunsCollection {
<#
.SYNOPSIS
    Runs optional Sysinternals Autorunsc64.exe when available.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    Write-DFIRLog -Context $Context -Message 'Starting autoruns collection'
    $tool = Join-Path $Context.ToolsPath 'Autorunsc64.exe'
    if (-not (Test-Path -LiteralPath $tool -PathType Leaf)) {
        Write-DFIRLog -Context $Context -Level WARN -Message 'Autoruns skipped: Tools\Autorunsc64.exe not found'
        Add-DFIRResult -Context $Context -Name 'Autoruns' -Success $true -Message 'Skipped: Autorunsc64.exe not found'
        return $true
    }

    # -s verifies Authenticode signatures, -h emits file hashes, -t normalises
    # timestamps to UTC. Without -s the Signer column is empty and autostart
    # entries can only be judged by publisher strings, which an attacker controls.
    $csv = Join-Path $Context.Paths.Autoruns 'Autoruns.csv'
    $success = Invoke-DFIRSafeCommand -Context $Context -Name 'Autorunsc64' -FilePath $tool -Arguments @('-accepteula','-nobanner','-a','*','-c','-s','-h','-t') -OutputPath $csv

    $success = (Export-DFIRWmiPersistence -Context $Context) -and $success
    Add-DFIRResult -Context $Context -Name 'Autoruns' -Success $success
    return $success
}

function Export-DFIRWmiPersistence {
<#
.SYNOPSIS
    Exports WMI event-subscription persistence from the root\subscription namespace.
.DESCRIPTION
    __EventFilter, __EventConsumer and __FilterToConsumerBinding form a fileless
    persistence mechanism that Autoruns does not enumerate. A binding that joins
    a filter to a CommandLineEventConsumer or ActiveScriptEventConsumer is the
    artifact of interest.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    $success = $true

    $success = (Export-DFIRJson -Context $Context -Name 'WMI __EventFilter' -Depth 4 `
        -Path (Join-Path $Context.Paths.Autoruns 'WMI_EventFilter.json') -ScriptBlock {
            Get-CimInstance -Namespace 'root\subscription' -ClassName '__EventFilter' -ErrorAction SilentlyContinue |
                Select-Object -Property * -ExcludeProperty CimClass, CimInstanceProperties, CimSystemProperties
        }) -and $success

    $success = (Export-DFIRJson -Context $Context -Name 'WMI __EventConsumer' -Depth 4 `
        -Path (Join-Path $Context.Paths.Autoruns 'WMI_EventConsumer.json') -ScriptBlock {
            Get-CimInstance -Namespace 'root\subscription' -ClassName '__EventConsumer' -ErrorAction SilentlyContinue |
                Select-Object -Property * -ExcludeProperty CimClass, CimInstanceProperties, CimSystemProperties
        }) -and $success

    $success = (Export-DFIRJson -Context $Context -Name 'WMI __FilterToConsumerBinding' -Depth 4 `
        -Path (Join-Path $Context.Paths.Autoruns 'WMI_FilterToConsumerBinding.json') -ScriptBlock {
            Get-CimInstance -Namespace 'root\subscription' -ClassName '__FilterToConsumerBinding' -ErrorAction SilentlyContinue |
                Select-Object -Property * -ExcludeProperty CimClass, CimInstanceProperties, CimSystemProperties
        }) -and $success

    return $success
}

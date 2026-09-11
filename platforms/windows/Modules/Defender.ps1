Set-StrictMode -Version 2.0

function Invoke-DFIRDefenderCollection {
<#
.SYNOPSIS
    Collects Windows Defender, Malwarebytes, and ESET security-product artifacts when available.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    Write-DFIRLog -Context $Context -Message 'Starting Defender/security product collection'
    $success = $true
    $success = (Export-DFIRCsv -Context $Context -Name 'Get-MpComputerStatus' -Path (Join-Path $Context.Paths.Defender 'MpComputerStatus.csv') -ScriptBlock { Get-MpComputerStatus -ErrorAction SilentlyContinue }) -and $success
    $success = (Export-DFIRCsv -Context $Context -Name 'Get-MpThreatDetection' -Path (Join-Path $Context.Paths.Defender 'MpThreatDetection.csv') -ScriptBlock { Get-MpThreatDetection -ErrorAction SilentlyContinue }) -and $success
    # Export-Csv renders array properties such as ExclusionPath as the literal
    # "System.String[]", and Get-MpPreference throws outright when WinDefend is
    # stopped because a third-party AV owns Security Center. JSON preserves the
    # arrays and the registry fallback covers the stopped-service case.
    $success = (Export-DFIRJson -Context $Context -Name 'Get-MpPreference' -Depth 4 -Path (Join-Path $Context.Paths.Defender 'MpPreference.json') -ScriptBlock {
        Get-MpPreference -ErrorAction SilentlyContinue
    }) -and $success
    $success = (Export-DFIRDefenderExclusionRegistry -Context $Context) -and $success

    $success = (Copy-DFIRSecurityProductLogs -Context $Context -ProductName 'Malwarebytes' -CandidatePaths @(
        (Join-Path $env:ProgramData 'Malwarebytes\MBAMService\ScanResults'),
        (Join-Path $env:ProgramData 'Malwarebytes\MBAMService\logs'),
        (Join-Path $env:ProgramData 'Malwarebytes\MBAMService\Logs'),
        (Join-Path $env:ProgramData 'Malwarebytes\Malwarebytes Anti-Malware\Logs'),
        (Join-Path $env:ProgramData 'Malwarebytes\Endpoint Agent\Logs'),
        (Join-Path $env:ProgramData 'Malwarebytes\Endpoint Agent\Plugins'),
        (Join-Path $env:ProgramData 'MBAMService\logs')
    ) -ProductNamePattern 'Malwarebytes') -and $success

    $success = (Copy-DFIRSecurityProductLogs -Context $Context -ProductName 'ESET' -CandidatePaths @(
        (Join-Path $env:ProgramData 'ESET\ESET Security\Logs'),
        (Join-Path $env:ProgramData 'ESET\ESET Endpoint Security\Logs'),
        (Join-Path $env:ProgramData 'ESET\ESET NOD32 Antivirus\Logs'),
        (Join-Path $env:ProgramData 'ESET\ESET Smart Security\Logs')
    ) -ProductNamePattern 'ESET' -CarveStrings) -and $success

    $success = (Export-DFIRInstalledSecurityProducts -Context $Context) -and $success

    Add-DFIRResult -Context $Context -Name 'Defender' -Success $success
    return $success
}

function Export-DFIRDefenderExclusionRegistry {
<#
.SYNOPSIS
    Reads Microsoft Defender exclusions and tamper-protection state from the registry.
.DESCRIPTION
    Provides coverage when the Defender service is stopped and Get-MpPreference
    is unavailable. Exclusion paths are a common persistence hiding place, so a
    silent gap here is a meaningful blind spot.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    $keys = @(
        'HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions',
        'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions',
        'HKLM\SOFTWARE\Microsoft\Windows Defender\Features',
        'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender'
    )

    $success = $true
    foreach ($key in $keys) {
        $safe = Get-DFIRSafeFileName -Value ($key -replace '^HKLM\\SOFTWARE\\', '')
        $txt = Join-Path $Context.Paths.Defender ('Registry_' + $safe + '.txt')
        $reg = Join-Path $Context.Paths.Defender ('Registry_' + $safe + '.reg')
        $success = (Export-DFIRRegistryKey -Context $Context -RegistryPath $key -RegExePath $reg -TxtPath $txt) -and $success
    }
    return $success
}

function Export-DFIRInstalledSecurityProducts {
<#
.SYNOPSIS
    Records registered antivirus products and installed security software.
.DESCRIPTION
    Lets the analyst distinguish "product not installed" from "installed but
    logs not found" when a vendor log path is missing.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    $success = $true
    $success = (Export-DFIRJson -Context $Context -Name 'SecurityCenter AntiVirusProduct' -Depth 3 `
        -Path (Join-Path $Context.Paths.Defender 'SecurityCenter_Products.json') -ScriptBlock {
            Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName 'AntiVirusProduct' -ErrorAction SilentlyContinue |
                Select-Object displayName, productState, pathToSignedProductExe, pathToSignedReportingExe, timestamp
        }) -and $success

    $success = (Export-DFIRCsv -Context $Context -Name 'Installed security software' `
        -Path (Join-Path $Context.Paths.Defender 'InstalledSecuritySoftware.csv') -ScriptBlock {
            $roots = @(
                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
            )
            Get-ItemProperty -Path $roots -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName -match 'Malwarebytes|ESET|Defender|Sophos|Symantec|McAfee|Kaspersky|Trend Micro|CrowdStrike|SentinelOne|Bitdefender|Avast|AVG|Norton|Webroot|Cylance|Carbon Black' } |
                Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation
        }) -and $success

    return $success
}

function Copy-DFIRSecurityProductLogs {
<#
.SYNOPSIS
    Copies recent security-product log files from known vendor paths.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][hashtable]$Context,
        [Parameter(Mandatory=$true)][string]$ProductName,
        [Parameter(Mandatory=$true)][string[]]$CandidatePaths,
        [string]$ProductNamePattern = '',
        [switch]$CarveStrings
    )

    $found = $false
    $success = $true
    foreach ($path in $CandidatePaths) {
        if (-not (Test-Path -LiteralPath $path)) { continue }
        $found = $true
        try {
            $dest = Join-Path $Context.Paths.Defender $ProductName
            New-Item -ItemType Directory -Path $dest -Force -ErrorAction Stop | Out-Null
            Get-ChildItem -LiteralPath $path -File -Recurse -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTimeUtc -Descending |
                Select-Object -First 50 |
                ForEach-Object {
                    $safeName = Get-DFIRSafeFileName -Value ($_.FullName.Substring($path.Length).TrimStart('\'))
                    $target = Join-Path $dest $safeName
                    $copied = Copy-DFIRLockedFile -Context $Context -Source $_.FullName -Destination $target
                    # Vendor detection history is stored in proprietary binary
                    # .dat files. Carving strings makes detection names and file
                    # paths readable without a vendor parser.
                    if ($copied -and $CarveStrings -and $_.Extension -eq '.dat') {
                        Export-DFIRBinaryStrings -Context $Context -Source $target -Destination ($target + '.strings.txt') | Out-Null
                    }
                }
        }
        catch {
            $success = $false
            Write-DFIRLog -Context $Context -Level ERROR -Message ("{0} log copy failed from {1}: {2}" -f $ProductName, $path, $_.Exception.Message)
        }
    }

    if (-not $found) {
        # Distinguish "product absent" from "product present but logs missing";
        # the second case is a collection gap, the first is simply a fact.
        $installed = $false
        if (-not [string]::IsNullOrWhiteSpace($ProductNamePattern)) {
            try {
                $roots = @(
                    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
                )
                $match = Get-ItemProperty -Path $roots -ErrorAction SilentlyContinue |
                    Where-Object { $_.DisplayName -and $_.DisplayName -match $ProductNamePattern }
                if ($match) { $installed = $true }
            }
            catch { }
        }

        if ($installed) {
            Write-DFIRLog -Context $Context -Level WARN -Message ("{0} is INSTALLED but no log path was found. Evidence gap: scan history unavailable." -f $ProductName)
        }
        else {
            Write-DFIRLog -Context $Context -Level INFO -Message ("{0} logs skipped: product does not appear to be installed on this host." -f $ProductName)
        }
    }
    return $success
}

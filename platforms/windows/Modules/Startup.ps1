Set-StrictMode -Version 2.0

function Invoke-DFIRStartupCollection {
<#
.SYNOPSIS
    Collects current-user and all-users Startup folder artifacts.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    Write-DFIRLog -Context $Context -Message 'Starting startup folder collection'
    $success = $true
    $locations = New-Object System.Collections.ArrayList
    $targetProfiles = if ($Context.ContainsKey('TargetProfiles') -and $Context['TargetProfiles']) { @($Context['TargetProfiles']) } else { @(Resolve-DFIRTargetProfiles -Context $Context) }
    foreach ($profile in $targetProfiles) {
        [void]$locations.Add(@{ Name = ('UserStartup_{0}' -f (Get-DFIRSafeFileName -Value $profile.UserName)); Path = $profile.Startup })
    }
    [void]$locations.Add(@{ Name = 'AllUsersStartup'; Path = [Environment]::GetFolderPath('CommonStartup') })

    foreach ($location in $locations) {
        try {
            $listing = Join-Path $Context.Paths.Startup ($location.Name + '_Listing.csv')
            if (Test-Path -LiteralPath $location.Path) {
                Get-ChildItem -LiteralPath $location.Path -Force -Recurse -ErrorAction SilentlyContinue |
                    Select-Object FullName, Length, CreationTimeUtc, LastWriteTimeUtc, Attributes |
                    Export-Csv -Path $listing -NoTypeInformation -Encoding UTF8 -Force
                Add-DFIRCollectedFile -Context $Context -Path $listing

                $dest = Join-Path $Context.Paths.Startup $location.Name
                New-Item -ItemType Directory -Path $dest -Force -ErrorAction Stop | Out-Null
                Copy-Item -Path (Join-Path $location.Path '*') -Destination $dest -Recurse -Force -ErrorAction SilentlyContinue
                Get-ChildItem -LiteralPath $dest -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                    Add-DFIRCollectedFile -Context $Context -Path $_.FullName
                }
            }
            else {
                Write-DFIRLog -Context $Context -Level WARN -Message ("Startup path not found: {0}" -f $location.Path)
            }
        }
        catch {
            $success = $false
            Write-DFIRLog -Context $Context -Level ERROR -Message ("Startup collection failed for {0}: {1}" -f $location.Name, $_.Exception.Message)
        }
    }

    Add-DFIRResult -Context $Context -Name 'Startup' -Success $success
    return $success
}

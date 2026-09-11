Set-StrictMode -Version 2.0

function Invoke-DFIRBrowserCollection {
<#
.SYNOPSIS
    Collects Chrome, Edge, Brave and Firefox extension metadata and profile artifacts.
.DESCRIPTION
    Credential stores (Login Data, Web Data, Cookies, logins.json, key4.db, ...)
    are copied by default (-BrowserCredentialStores Copy, the v1.1 behaviour).
    With -BrowserCredentialStores MetadataOnly they are NOT copied; size,
    timestamps and a SHA256 are recorded in 09_Browser\CredentialStoreMetadata.csv.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    Write-DFIRLog -Context $Context -Message 'Starting browser artifact collection'
    $success = $true
    foreach ($userRoot in (Get-DFIRBrowserUserRoots -Context $Context)) {
        $success = (Export-DFIRChromiumExtensions -Context $Context -BrowserName 'Chrome' -UserName $userRoot.UserName -UserDataRoot (Join-Path $userRoot.LocalAppData 'Google\Chrome\User Data')) -and $success
        $success = (Export-DFIRChromiumExtensions -Context $Context -BrowserName 'Edge' -UserName $userRoot.UserName -UserDataRoot (Join-Path $userRoot.LocalAppData 'Microsoft\Edge\User Data')) -and $success
        $success = (Export-DFIRFirefoxExtensions -Context $Context -UserName $userRoot.UserName -ProfilesRoot (Join-Path $userRoot.AppData 'Mozilla\Firefox\Profiles')) -and $success

        $success = (Export-DFIRChromiumProfileArtifacts -Context $Context -BrowserName 'Chrome' -UserName $userRoot.UserName -UserDataRoot (Join-Path $userRoot.LocalAppData 'Google\Chrome\User Data')) -and $success
        $success = (Export-DFIRChromiumProfileArtifacts -Context $Context -BrowserName 'Edge' -UserName $userRoot.UserName -UserDataRoot (Join-Path $userRoot.LocalAppData 'Microsoft\Edge\User Data')) -and $success
        $success = (Export-DFIRChromiumProfileArtifacts -Context $Context -BrowserName 'Brave' -UserName $userRoot.UserName -UserDataRoot (Join-Path $userRoot.LocalAppData 'BraveSoftware\Brave-Browser\User Data')) -and $success
        $success = (Export-DFIRFirefoxProfileArtifacts -Context $Context -UserName $userRoot.UserName -ProfilesRoot (Join-Path $userRoot.AppData 'Mozilla\Firefox\Profiles')) -and $success
    }
    Add-DFIRResult -Context $Context -Name 'Browser' -Success $success
    return $success
}

function Get-DFIRCredentialStorePolicy {
<#
.SYNOPSIS
    Returns 'Copy' or 'MetadataOnly' from the context (default Copy).
.OUTPUTS
    System.String
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    if ($Context.ContainsKey('BrowserCredentialStores') -and $Context['BrowserCredentialStores'] -eq 'MetadataOnly') { return 'MetadataOnly' }
    return 'Copy'
}

function Test-DFIRCredentialStoreArtifact {
<#
.SYNOPSIS
    True when a profile-relative artifact name is a credential, cookie or token store.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Artifact)

    $stores = @(
        'Login Data', 'Login Data For Account', 'Web Data',
        'Network\Cookies', 'Network\Trust Tokens',
        'logins.json', 'key4.db', 'cookies.sqlite', 'formhistory.sqlite'
    )
    return ($stores -contains $Artifact)
}

function Add-DFIRCredentialStoreMetadata {
<#
.SYNOPSIS
    Records a credential store's size, timestamps and SHA256 without copying it.
.DESCRIPTION
    The hash is computed through a shared-read stream, so a store held open by a
    running browser is hashed without copying its contents into the evidence.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][hashtable]$Context,
        [Parameter(Mandatory=$true)][string]$BrowserName,
        [Parameter(Mandatory=$true)][string]$UserName,
        [Parameter(Mandatory=$true)][string]$ProfileName,
        [Parameter(Mandatory=$true)][string]$Artifact,
        [Parameter(Mandatory=$true)][string]$Source
    )

    $csv = Join-Path $Context.Paths.Browser 'CredentialStoreMetadata.csv'
    $snapshot = Get-DFIRFileSnapshot -Path $Source
    $record = [pscustomobject][ordered]@{
        Timestamp         = (Get-Date).ToUniversalTime().ToString('o')
        Browser           = $BrowserName
        UserName          = $UserName
        Profile           = $ProfileName
        Artifact          = $Artifact
        SourcePath        = $Source
        SizeBytes         = Get-DFIRObjectProperty -InputObject $snapshot -Name 'SizeBytes'
        CreationTimeUtc   = ''
        LastWriteTimeUtc  = ''
        LastAccessTimeUtc = ''
        SHA256            = Get-DFIRFileSha256 -Path $Source
        Note              = 'Metadata only (-BrowserCredentialStores MetadataOnly); contents not collected'
    }
    foreach ($field in @('CreationTimeUtc','LastWriteTimeUtc','LastAccessTimeUtc')) {
        $value = Get-DFIRObjectProperty -InputObject $snapshot -Name $field
        if ($value) { $record.$field = ([datetime]$value).ToString('o') }
    }
    if (Add-DFIRCsvRecord -Path $csv -Record $record) {
        if (-not ($Context.ContainsKey('CredentialStoreMetadataTracked') -and $Context['CredentialStoreMetadataTracked'])) {
            Add-DFIRCollectedFile -Context $Context -Path $csv
            $Context['CredentialStoreMetadataTracked'] = $true
        }
        Write-DFIRLog -Context $Context -Message ("Credential store recorded as metadata only: {0}" -f $Source)
    }
    else {
        Write-DFIRLog -Context $Context -Level WARN -Message ("Could not record credential store metadata for {0}" -f $Source)
    }
}

function Read-DFIRSharedText {
<#
.SYNOPSIS
    Reads a text file that may be write-locked by a running process.
.OUTPUTS
    System.String
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Path)

    try { return (Get-Content -LiteralPath $Path -Raw -ErrorAction Stop) } catch { }

    $stream = $null
    $reader = $null
    try {
        $stream = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $reader = New-Object System.IO.StreamReader($stream)
        return $reader.ReadToEnd()
    }
    catch { return $null }
    finally {
        if ($reader) { $reader.Dispose() }
        if ($stream) { $stream.Dispose() }
    }
}

function Save-DFIRRedactedLocalState {
<#
.SYNOPSIS
    Writes a Chromium Local State copy with the credential-decryption keys removed.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][hashtable]$Context,
        [Parameter(Mandatory=$true)][string]$Source,
        [Parameter(Mandatory=$true)][string]$Destination
    )

    if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) { return $true }
    try {
        $text = Read-DFIRSharedText -Path $Source
        if ($null -eq $text) { throw 'unreadable' }
        $redacted = [regex]::Replace($text, '"(app_bound_encrypted_key|encrypted_key)"\s*:\s*"[^"]*"', '"$1":"<REDACTED BY COLLECTOR>"')
        $parent = Split-Path -Parent $Destination
        if ($parent -and -not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force -ErrorAction Stop | Out-Null }
        [System.IO.File]::WriteAllText($Destination, $redacted, (New-Object System.Text.UTF8Encoding($false)))
        Add-DFIRCollectedFile -Context $Context -Path $Destination
        return $true
    }
    catch {
        Write-DFIRLog -Context $Context -Level WARN -Message ("Local State redaction failed for {0}: {1}" -f $Source, $_.Exception.Message)
        return $false
    }
}

function Export-DFIRChromiumProfileArtifacts {
<#
.SYNOPSIS
    Copies Chromium profile artifacts relevant to credential-exposure investigations.
.DESCRIPTION
    Collects the authoritative extension registry (Preferences and Secure
    Preferences, which also record force-installed extensions and install
    source), plus the browsing, autofill, credential-store and cookie
    databases. Password and cookie values are encrypted with a key held in
    Local State that is itself protected by the user's DPAPI master key (and,
    in recent Chromium builds, app-bound encryption); anyone who also obtains
    that user's DPAPI material can decrypt them. Under MetadataOnly the
    credential stores are hashed and described, not copied.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][hashtable]$Context,
        [Parameter(Mandatory=$true)][string]$BrowserName,
        [Parameter(Mandatory=$true)][string]$UserName,
        [Parameter(Mandatory=$true)][string]$UserDataRoot
    )

    if (-not (Test-Path -LiteralPath $UserDataRoot -PathType Container)) { return $true }

    $artifacts = @(
        'Preferences',
        'Secure Preferences',
        'History',
        'Web Data',
        'Login Data',
        'Login Data For Account',
        'Shortcuts',
        'Top Sites',
        'Favicons',
        'Network\Cookies',
        'Network\Trust Tokens'
    )

    $success = $true
    $metadataOnly = ((Get-DFIRCredentialStorePolicy -Context $Context) -eq 'MetadataOnly')
    try {
        $rootDest = Join-Path $Context.Paths.Browser (Join-Path ($BrowserName + '_ProfileData') (Get-DFIRSafeFileName -Value $UserName))

        $localState = Join-Path $UserDataRoot 'Local State'
        if ($metadataOnly) {
            # Local State carries the DPAPI-wrapped (and app-bound) key that
            # decrypts the credential stores; keep the profile data, drop the keys.
            Save-DFIRRedactedLocalState -Context $Context -Source $localState -Destination (Join-Path $rootDest 'Local_State.redacted.json') | Out-Null
        }
        else {
            Copy-DFIRLockedFile -Context $Context -Source $localState -Destination (Join-Path $rootDest 'Local State') | Out-Null
        }

        $profiles = Get-ChildItem -LiteralPath $UserDataRoot -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' -or $_.Name -eq 'Guest Profile' }

        foreach ($profile in $profiles) {
            $destDir = Join-Path $rootDest (Get-DFIRSafeFileName -Value $profile.Name)
            New-Item -ItemType Directory -Path $destDir -Force -ErrorAction Stop | Out-Null
            foreach ($artifact in $artifacts) {
                $source = Join-Path $profile.FullName $artifact
                if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { continue }
                if ($metadataOnly -and (Test-DFIRCredentialStoreArtifact -Artifact $artifact)) {
                    Add-DFIRCredentialStoreMetadata -Context $Context -BrowserName $BrowserName -UserName $UserName -ProfileName $profile.Name -Artifact $artifact -Source $source
                    continue
                }
                $safeName = Get-DFIRSafeFileName -Value $artifact
                Copy-DFIRLockedFile -Context $Context -Source $source -Destination (Join-Path $destDir $safeName) | Out-Null
            }
        }
    }
    catch {
        $success = $false
        Write-DFIRLog -Context $Context -Level ERROR -Message ("{0} profile artifact collection failed for {1}: {2}" -f $BrowserName, $UserName, $_.Exception.Message)
    }
    return $success
}

function Export-DFIRFirefoxProfileArtifacts {
<#
.SYNOPSIS
    Copies Firefox profile artifacts relevant to credential-exposure investigations.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][hashtable]$Context,
        [Parameter(Mandatory=$true)][string]$UserName,
        [Parameter(Mandatory=$true)][string]$ProfilesRoot
    )

    if (-not (Test-Path -LiteralPath $ProfilesRoot -PathType Container)) { return $true }

    $artifacts = @(
        'logins.json',
        'key4.db',
        'places.sqlite',
        'cookies.sqlite',
        'formhistory.sqlite',
        'permissions.sqlite',
        'prefs.js',
        'addons.json',
        'extension-preferences.json',
        'extension-settings.json',
        'search.json.mozlz4'
    )

    $success = $true
    $metadataOnly = ((Get-DFIRCredentialStorePolicy -Context $Context) -eq 'MetadataOnly')
    try {
        $rootDest = Join-Path $Context.Paths.Browser (Join-Path 'Firefox_ProfileData' (Get-DFIRSafeFileName -Value $UserName))
        foreach ($profile in (Get-ChildItem -LiteralPath $ProfilesRoot -Directory -ErrorAction SilentlyContinue)) {
            $destDir = Join-Path $rootDest (Get-DFIRSafeFileName -Value $profile.Name)
            New-Item -ItemType Directory -Path $destDir -Force -ErrorAction Stop | Out-Null
            foreach ($artifact in $artifacts) {
                $source = Join-Path $profile.FullName $artifact
                if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { continue }
                # logins.json + key4.db are NOT DPAPI-protected: without a
                # Primary Password they decrypt offline, so MetadataOnly matters most here.
                if ($metadataOnly -and (Test-DFIRCredentialStoreArtifact -Artifact $artifact)) {
                    Add-DFIRCredentialStoreMetadata -Context $Context -BrowserName 'Firefox' -UserName $UserName -ProfileName $profile.Name -Artifact $artifact -Source $source
                    continue
                }
                Copy-DFIRLockedFile -Context $Context -Source $source -Destination (Join-Path $destDir $artifact) | Out-Null
            }
        }
    }
    catch {
        $success = $false
        Write-DFIRLog -Context $Context -Level ERROR -Message ("Firefox profile artifact collection failed for {0}: {1}" -f $UserName, $_.Exception.Message)
    }
    return $success
}

function Get-DFIRBrowserUserRoots {
<#
.SYNOPSIS
    Enumerates local user profile paths for browser artifact collection.
.OUTPUTS
    PSCustomObject
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    if ($Context.ContainsKey('TargetProfiles') -and $Context['TargetProfiles']) {
        return @($Context['TargetProfiles'])
    }

    return @(Resolve-DFIRTargetProfiles -Context $Context)
}

function Export-DFIRChromiumExtensions {
<#
.SYNOPSIS
    Exports Chromium-family extension manifest metadata and manifest.json copies.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][hashtable]$Context,
        [Parameter(Mandatory=$true)][string]$BrowserName,
        [Parameter(Mandatory=$true)][string]$UserName,
        [Parameter(Mandatory=$true)][string]$UserDataRoot
    )

    if (-not (Test-Path -LiteralPath $UserDataRoot)) {
        Write-DFIRLog -Context $Context -Level WARN -Message ("{0} user-data path not found: {1}" -f $BrowserName, $UserDataRoot)
        return $true
    }

    $success = $true
    $records = New-Object System.Collections.ArrayList
    try {
        $profiles = Get-ChildItem -LiteralPath $UserDataRoot -Directory -ErrorAction SilentlyContinue |
            Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'Extensions') }
        foreach ($profile in $profiles) {
            $extensionsRoot = Join-Path $profile.FullName 'Extensions'
            foreach ($extension in (Get-ChildItem -LiteralPath $extensionsRoot -Directory -ErrorAction SilentlyContinue)) {
                foreach ($version in (Get-ChildItem -LiteralPath $extension.FullName -Directory -ErrorAction SilentlyContinue)) {
                    $manifestPath = Join-Path $version.FullName 'manifest.json'
                    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { continue }
                    # A running browser holds an exclusive-write handle on
                    # manifest.json, so a plain read fails with "Access denied"
                    # and the extension is left uninspected. Read with
                    # FileShare.ReadWrite so the read succeeds regardless.
                    $manifest = $null
                    $manifestRaw = Read-DFIRSharedText -Path $manifestPath
                    if ($manifestRaw) {
                        try { $manifest = $manifestRaw | ConvertFrom-Json -ErrorAction Stop }
                        catch { Write-DFIRLog -Context $Context -Level WARN -Message ("Unable to parse manifest {0}: {1}" -f $manifestPath, $_.Exception.Message) }
                    }
                    else {
                        Write-DFIRLog -Context $Context -Level WARN -Message ("Unable to read manifest {0}" -f $manifestPath)
                    }

                    $destDir = Join-Path $Context.Paths.Browser (Join-Path $BrowserName (Join-Path $UserName (Join-Path $profile.Name (Join-Path $extension.Name $version.Name))))
                    New-Item -ItemType Directory -Path $destDir -Force -ErrorAction Stop | Out-Null
                    Copy-DFIRLockedFile -Context $Context -Source $manifestPath -Destination (Join-Path $destDir 'manifest.json') | Out-Null
                    $manifestName = Get-DFIRObjectProperty -InputObject $manifest -Name 'name'
                    $manifestDescription = Get-DFIRObjectProperty -InputObject $manifest -Name 'description'
                    $manifestPermissions = Get-DFIRObjectProperty -InputObject $manifest -Name 'permissions'
                    [void]$records.Add([pscustomobject]@{
                        Browser      = $BrowserName
                        UserName     = $UserName
                        Profile      = $profile.Name
                        ExtensionID  = $extension.Name
                        Version      = $version.Name
                        Name         = $manifestName
                        Description  = $manifestDescription
                        Permissions  = if ($manifestPermissions) { ($manifestPermissions -join ';') } else { $null }
                        ManifestPath = $manifestPath
                    })
                }
            }
        }
        $csv = Join-Path $Context.Paths.Browser ("{0}_{1}_Extensions.csv" -f $BrowserName, (Get-DFIRSafeFileName -Value $UserName))
        $records | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8 -Force
        Add-DFIRCollectedFile -Context $Context -Path $csv
    }
    catch {
        $success = $false
        Write-DFIRLog -Context $Context -Level ERROR -Message ("{0} extension collection failed: {1}" -f $BrowserName, $_.Exception.Message)
    }
    return $success
}

function Export-DFIRFirefoxExtensions {
<#
.SYNOPSIS
    Exports Firefox extension metadata from profile extension manifests and extensions.json.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][hashtable]$Context,
        [Parameter(Mandatory=$true)][string]$UserName,
        [Parameter(Mandatory=$true)][string]$ProfilesRoot
    )

    if (-not (Test-Path -LiteralPath $ProfilesRoot)) {
        Write-DFIRLog -Context $Context -Level WARN -Message ("Firefox profiles path not found: {0}" -f $ProfilesRoot)
        return $true
    }

    $success = $true
    $records = New-Object System.Collections.ArrayList
    try {
        foreach ($profile in (Get-ChildItem -LiteralPath $ProfilesRoot -Directory -ErrorAction SilentlyContinue)) {
            $extensionsJson = Join-Path $profile.FullName 'extensions.json'
            if (Test-Path -LiteralPath $extensionsJson -PathType Leaf) {
                $jsonDestDir = Join-Path $Context.Paths.Browser (Join-Path 'Firefox' (Join-Path $UserName $profile.Name))
                New-Item -ItemType Directory -Path $jsonDestDir -Force -ErrorAction Stop | Out-Null
                Copy-DFIRFile -Context $Context -Source $extensionsJson -Destination (Join-Path $jsonDestDir 'extensions.json') | Out-Null
                try {
                    $json = Get-Content -LiteralPath $extensionsJson -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                    $addons = Get-DFIRObjectProperty -InputObject $json -Name 'addons'
                    foreach ($addon in $addons) {
                        $locale = Get-DFIRObjectProperty -InputObject $addon -Name 'defaultLocale'
                        $userPermissions = Get-DFIRObjectProperty -InputObject $addon -Name 'userPermissions'
                        $permissions = Get-DFIRObjectProperty -InputObject $userPermissions -Name 'permissions'
                        [void]$records.Add([pscustomobject]@{
                            Browser     = 'Firefox'
                            UserName    = $UserName
                            Profile     = $profile.Name
                            ExtensionID = Get-DFIRObjectProperty -InputObject $addon -Name 'id'
                            Version     = Get-DFIRObjectProperty -InputObject $addon -Name 'version'
                            Name        = Get-DFIRObjectProperty -InputObject $locale -Name 'name'
                            Permissions = if ($permissions) { ($permissions -join ';') } else { $null }
                            Source      = $extensionsJson
                        })
                    }
                }
                catch {
                    Write-DFIRLog -Context $Context -Level WARN -Message ("Unable to parse Firefox extensions.json {0}: {1}" -f $extensionsJson, $_.Exception.Message)
                }
            }
            $extDir = Join-Path $profile.FullName 'extensions'
            if (Test-Path -LiteralPath $extDir) {
                foreach ($manifest in (Get-ChildItem -LiteralPath $extDir -Filter 'manifest.json' -Recurse -ErrorAction SilentlyContinue)) {
                    $dest = Join-Path $Context.Paths.Browser (Join-Path 'Firefox' (Join-Path $UserName (Join-Path $profile.Name $manifest.Directory.Name)))
                    New-Item -ItemType Directory -Path $dest -Force -ErrorAction Stop | Out-Null
                    Copy-DFIRFile -Context $Context -Source $manifest.FullName -Destination (Join-Path $dest 'manifest.json') | Out-Null
                }
            }
        }
        $csv = Join-Path $Context.Paths.Browser ("Firefox_{0}_Extensions.csv" -f (Get-DFIRSafeFileName -Value $UserName))
        $records | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8 -Force
        Add-DFIRCollectedFile -Context $Context -Path $csv
    }
    catch {
        $success = $false
        Write-DFIRLog -Context $Context -Level ERROR -Message ("Firefox extension collection failed: {0}" -f $_.Exception.Message)
    }
    return $success
}

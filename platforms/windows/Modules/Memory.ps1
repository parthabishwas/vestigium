Set-StrictMode -Version 2.0

function Get-DFIRMemoryTool {
<#
.SYNOPSIS
    Finds Tools\winpmem_mini_x64*.exe (newest name first).
.OUTPUTS
    System.IO.FileInfo or $null
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    if (-not (Test-Path -LiteralPath $Context.ToolsPath -PathType Container)) { return $null }
    return (Get-ChildItem -LiteralPath $Context.ToolsPath -Filter 'winpmem_mini_x64*.exe' -File -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending | Select-Object -First 1)
}

function Test-DFIRMemoryFreeSpace {
<#
.SYNOPSIS
    True when free space covers physical RAM plus 1 GB of headroom.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][double]$RamBytes,
        [Parameter(Mandatory=$true)][double]$FreeBytes
    )

    return ($FreeBytes -ge ($RamBytes + 1GB))
}

function Invoke-DFIRMemoryCollection {
<#
.SYNOPSIS
    Acquires physical memory with WinPmem into 20_Memory (only with -CaptureMemory).
.DESCRIPTION
    Runs first, in order of volatility. Checks that the evidence volume has
    RAM + 1 GB free, runs "<winpmem> <image.raw>", writes a sha256sum-format
    sidecar and a README. The image is excluded from the ZIP and SHA256.csv and
    stays beside the archive; a missing tool is logged and the step fails
    without stopping the collection.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Context)

    $dir = $Context.Paths.Memory
    try { New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop | Out-Null }
    catch {
        Write-DFIRLog -Context $Context -Level ERROR -Message ("Memory folder create failed: {0}" -f $_.Exception.Message)
        Add-DFIRResult -Context $Context -Name 'Memory' -Success $false -Message $_.Exception.Message
        return $false
    }
    $failedNote = Join-Path $dir 'memory-image-FAILED.txt'

    $tool = Get-DFIRMemoryTool -Context $Context
    if (-not $tool) {
        Write-DFIRLog -Context $Context -Level WARN -Message 'Memory capture requested but Tools\winpmem_mini_x64*.exe was not found; no memory image captured'
        'WinPmem (Tools\winpmem_mini_x64*.exe) not available; no memory image was captured.' | Out-File -FilePath $failedNote -Encoding UTF8
        Add-DFIRCollectedFile -Context $Context -Path $failedNote
        Add-DFIRResult -Context $Context -Name 'Memory' -Success $false -Message 'winpmem_mini_x64*.exe not found'
        return $false
    }

    $ramBytes = $null
    try { $ramBytes = [double](Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).TotalPhysicalMemory } catch { }
    $freeBytes = $null
    try {
        $drive = New-Object System.IO.DriveInfo([System.IO.Path]::GetPathRoot($dir))
        $freeBytes = [double]$drive.AvailableFreeSpace
    }
    catch { }
    if ($null -ne $ramBytes -and $null -ne $freeBytes) {
        if (-not (Test-DFIRMemoryFreeSpace -RamBytes $ramBytes -FreeBytes $freeBytes)) {
            $message = 'Insufficient free space for a memory image: need {0:n0} MB (RAM + 1 GB), have {1:n0} MB' -f (($ramBytes + 1GB) / 1MB), ($freeBytes / 1MB)
            Write-DFIRLog -Context $Context -Level ERROR -Message $message
            $message | Out-File -FilePath $failedNote -Encoding UTF8
            Add-DFIRCollectedFile -Context $Context -Path $failedNote
            Add-DFIRResult -Context $Context -Name 'Memory' -Success $false -Message $message
            return $false
        }
    }
    else {
        Write-DFIRLog -Context $Context -Level WARN -Message 'Could not determine RAM size or free space (UNC output path?); attempting memory capture anyway'
    }

    $image = Join-Path $dir ('memory_{0}_{1}.raw' -f $env:COMPUTERNAME, $Context.Timestamp)
    Write-DFIRLog -Context $Context -Message ("Acquiring physical memory with {0} (this takes several minutes)" -f $tool.Name)
    $ran = Invoke-DFIRSafeCommand -Context $Context -Name 'WinPmem memory acquisition' -FilePath $tool.FullName -Arguments @($image) -OutputPath (Join-Path $dir 'winpmem_output.txt')
    $exitCode = $LASTEXITCODE

    $imageInfo = $null
    if (Test-Path -LiteralPath $image -PathType Leaf) { $imageInfo = Get-Item -LiteralPath $image -ErrorAction SilentlyContinue }
    if (-not $ran -or -not $imageInfo -or $imageInfo.Length -eq 0) {
        Write-DFIRLog -Context $Context -Level ERROR -Message 'WinPmem acquisition failed - see 20_Memory\winpmem_output.txt'
        if ($imageInfo) { Remove-Item -LiteralPath $image -Force -ErrorAction SilentlyContinue }
        'WinPmem acquisition failed; see winpmem_output.txt.' | Out-File -FilePath $failedNote -Encoding UTF8
        Add-DFIRCollectedFile -Context $Context -Path $failedNote
        Add-DFIRResult -Context $Context -Name 'Memory' -Success $false -Message 'WinPmem acquisition failed'
        return $false
    }

    # Exclude the image from SHA256.csv and the archive from here on.
    $Context['MemoryImagePath'] = $imageInfo.FullName
    $hash = Write-DFIRSha256Sidecar -Path $imageInfo.FullName
    $Context['MemoryImageSha256'] = $hash
    $Context['MemoryCaptured'] = $true
    Add-DFIRCollectedFile -Context $Context -Path ($imageInfo.FullName + '.sha256')

    $readme = Join-Path $dir 'memory-image-README.txt'
    @(
        'Physical memory image',
        '=====================',
        '',
        ('Tool          : {0}' -f $tool.Name),
        'Format        : raw (padded physical memory)',
        ('Acquired (UTC): {0}' -f (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')),
        ('Image         : {0}' -f $imageInfo.Name),
        ('Size (bytes)  : {0}' -f $imageInfo.Length),
        ('SHA256        : {0}' -f $hash),
        ('Exit code     : {0}' -f $exitCode),
        '',
        'The image is NOT inside the evidence ZIP and NOT listed in 15_Hashes\SHA256.csv.',
        'It stays in the 20_Memory folder of the collection beside the archive; verify it with:',
        ('    sha256sum -c {0}.sha256' -f $imageInfo.Name),
        'Analyse with Volatility 3, e.g.: vol -f <image>.raw windows.pslist'
    ) | Out-File -FilePath $readme -Encoding UTF8 -Width 4096
    Add-DFIRCollectedFile -Context $Context -Path $readme

    $success = ([string]$exitCode -eq '0')
    if ($success) {
        Write-DFIRLog -Context $Context -Level SUCCESS -Message ("Memory image written: {0} ({1:n0} MB) SHA256={2}" -f $imageInfo.FullName, ($imageInfo.Length / 1MB), $hash)
        Add-DFIRResult -Context $Context -Name 'Memory' -Success $true
    }
    else {
        Write-DFIRLog -Context $Context -Level WARN -Message ("WinPmem exited with code {0}; the image may be incomplete: {1}" -f $exitCode, $imageInfo.FullName)
        Add-DFIRResult -Context $Context -Name 'Memory' -Success $false -Message ("WinPmem exit code {0}; image kept but may be incomplete" -f $exitCode)
    }
    return $success
}

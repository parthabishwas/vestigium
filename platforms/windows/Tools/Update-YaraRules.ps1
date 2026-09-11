#requires -version 5.1

<#
.SYNOPSIS
    Updates YARA rule repositories and builds the Vestigium active YARA bundle.
.DESCRIPTION
    Fetches the rule sources listed in <RulesRoot>\sources.conf and builds
    active-rules.yar plus RuleBuildReport.csv there, then records the build
    in rules.lock. The same files drive the Linux builder
    (platforms/linux/tools/build-yara-rules.py); see docs/YARA-RULES.md.

    Rules root: -RulesRoot, else <KitRoot>\shared\yara-rules (the store shared
    with the Linux collector), else Tools\YaraRules when run from a standalone
    Windows kit. Kit root is $env:VESTIGIUM_HOME or three levels above this
    script (platforms\windows\Tools) when that folder holds VERSION.

    Inputs under the rules root:
    - custom\          the organisation's own rules (*.yar, *.yara); always
                       included first, so they win identifier clashes.
    - sources.conf     "<name> <git-url> [<ref>]" per line, in precedence
                       order. Without it the -RepositoryUrls list is used.
    - exclusions.conf  "file:<glob>" drops rule files (path relative to the
                       rules root); "rule:<name|glob>" rewrites a rule to
                       "private rule" so it never reports on its own.
    - rules.lock       written after every successful build; with -Locked it
                       is the input (exact commits) and the result is checked
                       against it.

    The builder is intentionally conservative for production IR use:
    - Rules listed in a repository's yara\external-variable-rules.txt (Neo23x0
      signature-base) are excluded because vanilla yara64.exe does not
      populate LOKI/THOR external variables per scanned file.
    - Rule files with include statements are skipped because this builder
      creates one combined rule bundle.
    - Rule files with duplicate rule identifiers are skipped after the first
      occurrence so one incompatible source cannot break the whole bundle.
    - With a YARA compiler (-YaracPath, default Tools\yarac64.exe when present)
      the bundle is compiled; a file that fails is located from the error line
      and its /* BEGIN <file> */ marker, dropped and the bundle rebuilt, up to
      -MaxCompileAttempts times.
    - The bundle is built in a temporary file; active-rules.yar is replaced
      only when the build (and compile check) succeeds, so a failed build
      never leaves the shared bundle broken.
    - The bundle content is deterministic (no timestamps, paths relative to
      the rules root), so the same inputs give the same SHA256.
.PARAMETER RulesRoot
    Folder holding the rule repositories and the output bundle.
.PARAMETER YaracPath
    yarac executable for compile validation. Default Tools\yarac64.exe when present.
.PARAMETER SkipGitUpdate
    Use the repositories already on disk.
.PARAMETER Locked
    Rebuild exactly the sources and commits recorded in rules.lock: a source
    that is not at its locked commit is fetched (shallow, by commit) and
    checked out; the build fails when that is impossible. The resulting bundle
    SHA256 is compared with the lock (MATCH / MISMATCH); the lock itself is
    not rewritten.
.PARAMETER RepositoryUrls
    Legacy source list, used when sources.conf is missing or when given
    explicitly (then it overrides sources.conf).
.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\platforms\windows\Tools\Update-YaraRules.ps1
.EXAMPLE
    .\Update-YaraRules.ps1 -Locked
.EXAMPLE
    .\Update-YaraRules.ps1 -SkipGitUpdate -RulesRoot D:\Scratch\yara-rules -YaracPath C:\Tools\yarac64.exe
.NOTES
    Exit codes: 0 bundle built; 1 build failed (existing bundle left unchanged);
    2 usage or configuration error.
#>

[CmdletBinding()]
param(
    [Alias('RepositoryUrl')]
    [string[]]$RepositoryUrls = @(
        'https://github.com/Neo23x0/signature-base.git',
        'https://github.com/Yara-Rules/rules.git'
    ),
    [switch]$SkipGitUpdate,
    [string]$RulesRoot = '',
    [string]$YaracPath = '',
    [ValidateRange(1,100)][int]$MaxCompileAttempts = 10,
    [switch]$Locked
)

$script:RuleDeclPattern = '(?m)^([ \t]*)((?:(?:private|global)[ \t]+)*)rule([ \t]+)([A-Za-z_][A-Za-z0-9_]*)'
$script:SkipDirNames = @('.git', 'tests', 'test', 'deprecated')
$script:BuilderName = 'Update-YaraRules.ps1 (Windows)'

function Write-RuleBuilderLog {
<#
.SYNOPSIS
    Writes a timestamped rule-builder status message.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR','SUCCESS')][string]$Level = 'INFO'
    )

    Write-Host ('{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message)
}

function Get-RuleBuilderRoot {
<#
.SYNOPSIS
    Resolves the Tools directory that contains this script.
.OUTPUTS
    System.String
#>
    [CmdletBinding()]
    param()

    if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
        return $PSScriptRoot
    }
    return (Split-Path -Parent $PSCommandPath)
}

function Get-RuleBuilderKitRoot {
<#
.SYNOPSIS
    Returns the Vestigium kit root, or $null for a standalone Windows kit.
.OUTPUTS
    System.String
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$ToolsRoot,
        [AllowEmptyString()][string]$EnvHome = $env:VESTIGIUM_HOME
    )

    if (-not [string]::IsNullOrWhiteSpace($EnvHome) -and (Test-Path -LiteralPath $EnvHome -PathType Container)) {
        return $EnvHome
    }
    $windowsDir = Split-Path -Parent $ToolsRoot
    if (-not $windowsDir) { return $null }
    $platformsDir = Split-Path -Parent $windowsDir
    if (-not $platformsDir) { return $null }
    $kit = Split-Path -Parent $platformsDir
    if ($kit -and (Test-Path -LiteralPath (Join-Path $kit 'VERSION') -PathType Leaf) -and
        (Test-Path -LiteralPath (Join-Path (Join-Path $kit 'platforms') 'windows') -PathType Container)) {
        return $kit
    }
    return $null
}

function Get-YaraRepositoryName {
<#
.SYNOPSIS
    Creates a stable local folder name from a repository URL.
.DESCRIPTION
    Yara-Rules/rules is stored as "rules" (the shared Vestigium layout). A
    legacy "yara-rules" checkout in the rules root is reused when "rules" does
    not exist. Used only without sources.conf.
.OUTPUTS
    System.String
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$RepositoryUrl,
        [string]$RulesRoot = ''
    )

    $name = ($RepositoryUrl.TrimEnd('/') -split '/')[-1]
    $name = $name -replace '\.git$',''
    if ([string]::IsNullOrWhiteSpace($name)) { $name = 'rules' }
    if ($RepositoryUrl -match 'Neo23x0/signature-base') { return 'signature-base' }
    if ($RepositoryUrl -match 'Yara-Rules/rules') {
        if ($RulesRoot -and -not (Test-Path -LiteralPath (Join-Path $RulesRoot 'rules')) -and (Test-Path -LiteralPath (Join-Path $RulesRoot 'yara-rules'))) {
            return 'yara-rules'
        }
        return 'rules'
    }
    $name = ($name -replace '[^A-Za-z0-9_.-]','_').TrimStart('.', '-')
    if ([string]::IsNullOrWhiteSpace($name)) { $name = 'source' }
    return $name
}

# ---------------------------------------------------------------------------
# Configuration: sources.conf, exclusions.conf, rules.lock
# ---------------------------------------------------------------------------
function Test-YaraSourceEntry {
<#
.SYNOPSIS
    Validates one rule source; the same checks as the Linux builder.
.DESCRIPTION
    Nothing that fails these checks is ever passed to git.
.OUTPUTS
    System.String - an error message, or an empty string when valid.
#>
    [CmdletBinding()]
    param(
        [AllowEmptyString()][string]$Name,
        [AllowEmptyString()][string]$Url,
        [AllowEmptyString()][string]$Ref = ''
    )

    if ($Name -cnotmatch '^[A-Za-z0-9._-]+$' -or $Name.StartsWith('.') -or $Name.StartsWith('-') -or $Name -eq 'custom') {
        return ("invalid source name '{0}' (letters, digits, . _ -; must not start with . or -; 'custom' is reserved)" -f $Name)
    }
    if ($Url -cnotmatch '^(?:https://\S+|git@[^\s:]+:\S+)$') {
        return ("invalid URL '{0}' for source '{1}' (only https:// or git@host:path)" -f $Url, $Name)
    }
    if ($Ref -and ($Ref -cnotmatch '^[A-Za-z0-9._/-]+$' -or $Ref.StartsWith('-') -or $Ref.StartsWith('/') -or
                   $Ref.Contains('..') -or $Ref.EndsWith('/') -or $Ref.EndsWith('.lock'))) {
        return ("invalid ref '{0}' for source '{1}'" -f $Ref, $Name)
    }
    return ''
}

function Remove-YaraConfigComment {
<#
.SYNOPSIS
    Drops a trailing "# comment" (a # at line start or after whitespace) and trims.
.OUTPUTS
    System.String
#>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Line)

    return ([regex]::Replace($Line, '(^|\s)#.*$', '')).Trim()
}

function Read-YaraSourcesConf {
<#
.SYNOPSIS
    Parses sources.conf ("<name> <git-url> [<ref>]"); throws on invalid entries.
.OUTPUTS
    PSCustomObject[] with Name, Url, Ref, Commit.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Path)

    $sources = New-Object System.Collections.ArrayList
    $seen = @{}
    $number = 0
    foreach ($raw in [System.IO.File]::ReadAllLines($Path)) {
        $number++
        $line = Remove-YaraConfigComment -Line $raw
        if (-not $line) { continue }
        $fields = @($line -split '\s+')
        if ($fields.Count -lt 2 -or $fields.Count -gt 3) {
            throw ("{0}:{1}: expected '<name> <git-url> [<ref>]'" -f $Path, $number)
        }
        $ref = ''
        if ($fields.Count -eq 3) { $ref = $fields[2] }
        $problem = Test-YaraSourceEntry -Name $fields[0] -Url $fields[1] -Ref $ref
        if ($problem) { throw ("{0}:{1}: {2}" -f $Path, $number, $problem) }
        if ($seen.ContainsKey($fields[0])) { throw ("{0}:{1}: duplicate source name '{2}'" -f $Path, $number, $fields[0]) }
        $seen[$fields[0]] = $true
        [void]$sources.Add([pscustomobject]@{ Name = $fields[0]; Url = $fields[1]; Ref = $ref; Commit = '' })
    }
    return @($sources)
}

function Read-YaraExclusions {
<#
.SYNOPSIS
    Parses exclusions.conf ("file:<glob>" / "rule:<name|glob>"); throws on invalid lines.
.OUTPUTS
    PSCustomObject[] with Kind, Pattern, Line, Label.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Path)

    $entries = New-Object System.Collections.ArrayList
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return @() }
    $number = 0
    foreach ($raw in [System.IO.File]::ReadAllLines($Path)) {
        $number++
        $line = Remove-YaraConfigComment -Line $raw
        if (-not $line) { continue }
        $index = $line.IndexOf(':')
        $kind = ''
        $pattern = ''
        if ($index -gt 0) {
            $kind = $line.Substring(0, $index).Trim().ToLowerInvariant()
            $pattern = $line.Substring($index + 1).Trim()
        }
        if (@('file', 'rule') -notcontains $kind -or -not $pattern -or $pattern.Contains(' ')) {
            throw ("{0}:{1}: expected 'file:<glob>' or 'rule:<name|glob>', got '{2}'" -f $Path, $number, $line)
        }
        if ($kind -eq 'file') {
            $pattern = $pattern.Replace('\', '/').TrimStart('/')
        }
        elseif ($pattern -cnotmatch '^[A-Za-z0-9_*?\[\]]+$') {
            throw ("{0}:{1}: invalid rule name or glob '{2}'" -f $Path, $number, $pattern)
        }
        [void]$entries.Add([pscustomobject]@{
            Kind    = $kind
            Pattern = $pattern
            Line    = $number
            Label   = ('exclusions.conf line {0}: {1}:{2}' -f $number, $kind, $pattern)
        })
    }
    return @($entries)
}

function Read-YaraRuleLock {
<#
.SYNOPSIS
    Parses rules.lock: [section] headers and "key = value" lines, order preserved.
.OUTPUTS
    PSCustomObject[] with Name (section) and Values (hashtable).
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Path)

    $sections = New-Object System.Collections.ArrayList
    $current = $null
    foreach ($raw in [System.IO.File]::ReadAllLines($Path)) {
        $line = $raw.Trim()
        if (-not $line -or $line.StartsWith('#') -or $line.StartsWith(';')) { continue }
        if ($line.StartsWith('[') -and $line.EndsWith(']')) {
            $current = [pscustomobject]@{ Name = $line.Substring(1, $line.Length - 2).Trim(); Values = @{} }
            [void]$sections.Add($current)
        }
        elseif ($line.Contains('=') -and $null -ne $current) {
            $index = $line.IndexOf('=')
            $current.Values[$line.Substring(0, $index).Trim().ToLowerInvariant()] = $line.Substring($index + 1).Trim()
        }
    }
    return @($sections)
}

function Get-YaraLockValue {
<#
.SYNOPSIS
    Returns one value from parsed rules.lock sections (empty string when absent).
.OUTPUTS
    System.String
#>
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()][object[]]$Sections = @(),
        [Parameter(Mandatory=$true)][string]$Section,
        [Parameter(Mandatory=$true)][string]$Key
    )

    foreach ($entry in $Sections) {
        if ($entry.Name -eq $Section -and $entry.Values.ContainsKey($Key)) { return [string]$entry.Values[$Key] }
    }
    return ''
}

function Get-YaraLockSources {
<#
.SYNOPSIS
    Returns the [source <name>] entries of rules.lock (validated, with full commit SHAs).
.OUTPUTS
    PSCustomObject[] with Name, Url, Ref, Commit.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Path)

    $sources = New-Object System.Collections.ArrayList
    foreach ($section in (Read-YaraRuleLock -Path $Path)) {
        if (-not $section.Name.StartsWith('source ')) { continue }
        $name = $section.Name.Substring(7).Trim()
        $url = ''; $ref = ''; $commit = ''
        if ($section.Values.ContainsKey('url')) { $url = [string]$section.Values['url'] }
        if ($section.Values.ContainsKey('ref')) { $ref = [string]$section.Values['ref'] }
        if ($section.Values.ContainsKey('commit')) { $commit = [string]$section.Values['commit'] }
        $problem = Test-YaraSourceEntry -Name $name -Url $url -Ref $ref
        if ($problem) { throw ("{0}: {1}" -f $Path, $problem) }
        if ($commit -cnotmatch '^[0-9a-f]{40}$') { throw ("{0}: source '{1}' has no full commit SHA (got '{2}')" -f $Path, $name, $commit) }
        [void]$sources.Add([pscustomobject]@{ Name = $name; Url = $url; Ref = $ref; Commit = $commit })
    }
    if ($sources.Count -eq 0) { throw ("{0}: no [source <name>] sections" -f $Path) }
    return @($sources)
}

# ---------------------------------------------------------------------------
# git
# ---------------------------------------------------------------------------
function Invoke-YaraGit {
<#
.SYNOPSIS
    Runs git inside one checkout; returns the exit code. Output goes to the host.
.DESCRIPTION
    safe.directory lets an elevated shell work on a kit copied from another
    user or from removable media.
.OUTPUTS
    System.Int32
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Git,
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string[]]$Arguments
    )

    $ErrorActionPreference = 'Continue'
    $global:LASTEXITCODE = 0
    & $Git -c ('safe.directory=' + $Path) -c advice.detachedHead=false -C $Path @Arguments 2>&1 |
        ForEach-Object { Write-Host ('    git: {0}' -f [string]$_) }
    return [int]$LASTEXITCODE
}

function Get-YaraCheckoutCommit {
<#
.SYNOPSIS
    Returns the HEAD commit of a checkout, 'none' without one, 'unknown' when unreadable.
.OUTPUTS
    System.String
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Path)

    $gitDir = Join-Path $Path '.git'
    if (-not (Test-Path -LiteralPath $gitDir)) { return 'none' }
    $head = ''
    $git = Get-Command git -ErrorAction SilentlyContinue
    if ($git) {
        $ErrorActionPreference = 'Continue'
        $head = [string](& $git.Source -c ('safe.directory=' + $Path) -C $Path rev-parse HEAD 2>$null | Select-Object -First 1)
    }
    if (-not $head) {
        $headFile = Join-Path $gitDir 'HEAD'
        if (Test-Path -LiteralPath $headFile -PathType Leaf) {
            $head = ([System.IO.File]::ReadAllText($headFile)).Trim()
        }
    }
    $head = $head.Trim()
    if ($head -cmatch '^[0-9a-f]{40}$') { return $head }
    return 'unknown'
}

function Get-YaraCommitDate {
<#
.SYNOPSIS
    Returns the ISO commit date of a checkout's HEAD, or 'unknown'.
.OUTPUTS
    System.String
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Path)

    $git = Get-Command git -ErrorAction SilentlyContinue
    if (-not $git -or -not (Test-Path -LiteralPath (Join-Path $Path '.git'))) { return 'unknown' }
    $ErrorActionPreference = 'Continue'
    $date = [string](& $git.Source -c ('safe.directory=' + $Path) -C $Path log -1 --format=%cI 2>$null | Select-Object -First 1)
    if ($date) { return $date.Trim() }
    return 'unknown'
}

function Update-YaraRepository {
<#
.SYNOPSIS
    Fetches one rule source (shallow) and checks out the requested ref.
.DESCRIPTION
    Ref is a branch, tag or full commit SHA; empty means the default branch.
    A new source is fetched into a temporary folder first, so a failed clone
    leaves nothing behind. Local changes in a checkout make the update fail.
.OUTPUTS
    System.Boolean - $true when the ref was fetched and checked out.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$RepositoryUrl,
        [Parameter(Mandatory=$true)][string]$RepositoryPath,
        [AllowEmptyString()][string]$Ref = '',
        [switch]$SkipGitUpdate
    )

    $work = $null
    try {
        if ($SkipGitUpdate) {
            Write-RuleBuilderLog -Level WARN -Message ("Git update skipped for {0}" -f $RepositoryUrl)
            return $false
        }

        $git = Get-Command git -ErrorAction SilentlyContinue
        if (-not $git) {
            Write-RuleBuilderLog -Level WARN -Message ("git not found; using existing files if present: {0}" -f $RepositoryPath)
            return $false
        }

        if (Test-Path -LiteralPath (Join-Path $RepositoryPath '.git')) {
            $work = $RepositoryPath
            $ErrorActionPreference = 'Continue'
            $origin = [string](& $git.Source -c ('safe.directory=' + $work) -C $work remote get-url origin 2>$null | Select-Object -First 1)
            if ($origin.Trim() -ne $RepositoryUrl) {
                Write-RuleBuilderLog -Message ("Setting origin of {0} to {1}" -f $RepositoryPath, $RepositoryUrl)
                if ((Invoke-YaraGit -Git $git.Source -Path $work -Arguments @('remote', 'set-url', 'origin', $RepositoryUrl)) -ne 0) {
                    if ((Invoke-YaraGit -Git $git.Source -Path $work -Arguments @('remote', 'add', 'origin', $RepositoryUrl)) -ne 0) { return $false }
                }
            }
        }
        elseif (Test-Path -LiteralPath $RepositoryPath) {
            Write-RuleBuilderLog -Level WARN -Message ("Repository path exists but is not a git checkout: {0}" -f $RepositoryPath)
            return $false
        }
        else {
            $parent = Split-Path -Parent $RepositoryPath
            $work = Join-Path $parent ('.fetch-{0}.{1}' -f (Split-Path -Leaf $RepositoryPath), ([guid]::NewGuid().ToString('N')))
            New-Item -ItemType Directory -Path $work -Force -ErrorAction Stop | Out-Null
            Write-RuleBuilderLog -Message ("Cloning repository: {0}" -f $RepositoryUrl)
            if ((Invoke-YaraGit -Git $git.Source -Path $work -Arguments @('init', '-q')) -ne 0) { return $false }
            if ((Invoke-YaraGit -Git $git.Source -Path $work -Arguments @('remote', 'add', 'origin', $RepositoryUrl)) -ne 0) { return $false }
        }

        $target = $Ref
        if (-not $target) { $target = 'HEAD' }
        Write-RuleBuilderLog -Message ("Fetching {0} ({1})" -f $RepositoryUrl, $target)
        if ((Invoke-YaraGit -Git $git.Source -Path $work -Arguments @('fetch', '-q', '--depth', '1', 'origin', $target)) -ne 0) { return $false }
        if ((Invoke-YaraGit -Git $git.Source -Path $work -Arguments @('checkout', '-q', '--detach', 'FETCH_HEAD')) -ne 0) { return $false }
        if ($work -ne $RepositoryPath) {
            Move-Item -LiteralPath $work -Destination $RepositoryPath -ErrorAction Stop
        }
        $work = $null
        return $true
    }
    catch {
        Write-RuleBuilderLog -Level ERROR -Message ("Repository update failed for {0}: {1}" -f $RepositoryUrl, $_.Exception.Message)
        return $false
    }
    finally {
        if ($work -and $work -ne $RepositoryPath -and (Test-Path -LiteralPath $work)) {
            Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

# ---------------------------------------------------------------------------
# Rule files
# ---------------------------------------------------------------------------
function Get-YaraRuleSearchRoots {
<#
.SYNOPSIS
    Returns rule search roots for one repository.
.OUTPUTS
    System.String[]
#>
    [CmdletBinding()]
    param(
        [AllowEmptyString()][string]$RepositoryUrl = '',
        [Parameter(Mandatory=$true)][string]$RepositoryPath
    )

    $leaf = Split-Path -Leaf $RepositoryPath
    if ($leaf -eq 'signature-base' -or $RepositoryUrl -match 'Neo23x0/signature-base') {
        $yaraDir = Join-Path $RepositoryPath 'yara'
        if (Test-Path -LiteralPath $yaraDir -PathType Container) { return @($yaraDir) }
        return @($RepositoryPath)
    }

    $commonRoots = @('yara','malware','maldocs','webshells','exploit_kits','packers','email','mobile_malware','crypto','cve_rules','antidebug_antivm','capabilities','rules')
    $existing = foreach ($root in $commonRoots) {
        $path = Join-Path $RepositoryPath $root
        if (Test-Path -LiteralPath $path -PathType Container) { $path }
    }

    if ($existing) { return @($existing) }
    return @($RepositoryPath)
}

function Get-ExternalVariableExclusions {
<#
.SYNOPSIS
    Reads repository-specific rule files that should be excluded (yara\external-variable-rules.txt).
.OUTPUTS
    Hashtable keyed by lower-case file name.
#>
    [CmdletBinding()]
    param(
        [AllowEmptyString()][string]$RepositoryUrl = '',
        [Parameter(Mandatory=$true)][string]$RepositoryPath
    )

    $excluded = @{}
    $externalVariableList = Join-Path (Join-Path $RepositoryPath 'yara') 'external-variable-rules.txt'
    if (Test-Path -LiteralPath $externalVariableList -PathType Leaf) {
        foreach ($line in [System.IO.File]::ReadAllLines($externalVariableList)) {
            $entry = $line.Trim()
            if (-not $entry -or $entry.StartsWith('#')) { continue }
            $excluded[(($entry -split '[\\/]')[-1]).ToLowerInvariant()] = $true
        }
    }
    return $excluded
}

function Get-YaraRelativePath {
<#
.SYNOPSIS
    Path relative to a base folder, with "/" separators.
.OUTPUTS
    System.String
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string]$BasePath
    )

    $base = [System.IO.Path]::GetFullPath($BasePath).TrimEnd('\', '/')
    $full = [System.IO.Path]::GetFullPath($Path)
    if ($full.Length -gt $base.Length -and $full.StartsWith($base, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $full.Substring($base.Length + 1).Replace('\', '/')
    }
    return $full.Replace('\', '/')
}

function Get-YaraCandidateFiles {
<#
.SYNOPSIS
    Rule files under the search roots, sorted (ordinal) by path relative to the rules root.
.DESCRIPTION
    Skip decisions use only the part of the path inside the repository, so a
    kit stored under e.g. D:\tests\ is not mistaken for a test folder.
.OUTPUTS
    PSCustomObject[] with Path and Rel.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string[]]$Roots,
        [Parameter(Mandatory=$true)][string]$RepositoryPath,
        [Parameter(Mandatory=$true)][string]$RulesRoot
    )

    $found = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([System.StringComparer]::Ordinal)
    foreach ($root in $Roots) {
        foreach ($file in @(Get-ChildItem -LiteralPath $root -Recurse -File -Force -ErrorAction SilentlyContinue)) {
            if (@('.yar', '.yara') -notcontains $file.Extension.ToLowerInvariant()) { continue }
            if ($file.Name.StartsWith('.') -or $file.Name.StartsWith('~') -or $file.Name.StartsWith('_')) { continue }
            $inner = @((Get-YaraRelativePath -Path $file.FullName -BasePath $RepositoryPath) -split '/')
            $skip = $false
            for ($i = 0; $i -lt ($inner.Count - 1); $i++) {
                if ($script:SkipDirNames -contains $inner[$i]) { $skip = $true; break }
            }
            if ($skip) { continue }
            $rel = Get-YaraRelativePath -Path $file.FullName -BasePath $RulesRoot
            if (-not $found.ContainsKey($rel)) { $found[$rel] = $file.FullName }
        }
    }
    $keys = New-Object 'System.Collections.Generic.List[string]'
    foreach ($key in $found.Keys) { $keys.Add($key) }
    $keys.Sort([System.StringComparer]::Ordinal)
    foreach ($key in $keys) { [pscustomobject]@{ Path = $found[$key]; Rel = $key } }
}

function Read-YaraRuleText {
<#
.SYNOPSIS
    Reads a rule file as UTF-8 (invalid bytes replaced) with LF line endings.
.OUTPUTS
    System.String
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Path)

    $encoding = New-Object System.Text.UTF8Encoding($false, $false)
    $text = [System.IO.File]::ReadAllText($Path, $encoding)
    if ($text.Length -gt 0 -and $text[0] -eq [char]0xFEFF) { $text = $text.Substring(1) }
    return (($text -replace "`r`n", "`n") -replace "`r", "`n")
}

function Get-YaraRuleNames {
<#
.SYNOPSIS
    Extracts YARA rule identifiers from rule text or a rule file.
.OUTPUTS
    System.String[]
#>
    [CmdletBinding()]
    param(
        [string]$Path = '',
        [AllowEmptyString()][string]$Text = ''
    )

    $content = $Text
    if ($Path) { $content = Read-YaraRuleText -Path $Path }
    $found = [regex]::Matches($content, '(?m)^[ \t]*(?:private[ \t]+|global[ \t]+)*rule[ \t]+([A-Za-z_][A-Za-z0-9_]*)')
    foreach ($match in $found) { $match.Groups[1].Value }
}

function Test-YaraRuleFileHasInclude {
<#
.SYNOPSIS
    Detects YARA include wrapper files.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Path)

    try { return [bool](Select-String -LiteralPath $Path -Pattern '^[ \t]*include[ \t]+"' -Quiet -ErrorAction Stop) }
    catch { return $false }
}

function Convert-YaraSuppressedRules {
<#
.SYNOPSIS
    Rewrites rule declarations that match rule: exclusions to "private rule".
.DESCRIPTION
    "global" is kept; already-private rules are left alone. A private rule
    still evaluates for rules that reference it but never reports a match.
.OUTPUTS
    PSCustomObject with Text and Applied (Rule, Exclusion pairs).
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][AllowEmptyString()][string]$Text,
        [AllowEmptyCollection()][object[]]$Patterns = @()
    )

    $applied = New-Object System.Collections.ArrayList
    if ($Patterns.Count -eq 0) { return [pscustomobject]@{ Text = $Text; Applied = @() } }
    $builder = New-Object System.Text.StringBuilder
    $last = 0
    foreach ($match in [regex]::Matches($Text, $script:RuleDeclPattern)) {
        $modifiers = $match.Groups[2].Value
        $name = $match.Groups[4].Value
        if (@($modifiers -split '\s+') -ccontains 'private') { continue }
        $hit = $null
        foreach ($entry in $Patterns) {
            if ($name -clike $entry.Pattern) { $hit = $entry; break }
        }
        if (-not $hit) { continue }
        [void]$builder.Append($Text, $last, $match.Index - $last)
        [void]$builder.Append($match.Groups[1].Value + $modifiers + 'private rule' + $match.Groups[3].Value + $name)
        $last = $match.Index + $match.Length
        [void]$applied.Add([pscustomobject]@{ Rule = $name; Exclusion = $hit })
    }
    [void]$builder.Append($Text, $last, $Text.Length - $last)
    return [pscustomobject]@{ Text = $builder.ToString(); Applied = @($applied) }
}

function Write-YaraBundle {
<#
.SYNOPSIS
    Writes the combined bundle (UTF-8 without BOM, LF) with BEGIN/END markers per file.
.DESCRIPTION
    The content is deterministic and byte-identical to the Linux builder's
    for the same accepted files: no timestamps, relative paths.
.OUTPUTS
    PSCustomObject[] - the suppressed rules (Entry, Rule, Exclusion).
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][AllowEmptyCollection()][object[]]$AcceptedFiles,
        [Parameter(Mandatory=$true)][string]$OutputPath,
        [AllowEmptyCollection()][object[]]$Sources = @(),
        [AllowEmptyCollection()][object[]]$Suppress = @()
    )

    $suppressed = New-Object System.Collections.ArrayList
    $encoding = New-Object System.Text.UTF8Encoding($false)
    $writer = New-Object System.IO.StreamWriter($OutputPath, $false, $encoding)
    $writer.NewLine = "`n"
    try {
        $writer.WriteLine('/*')
        $writer.WriteLine('    Vestigium - active YARA rule bundle')
        $writer.WriteLine('    Sources (earlier entries win rule identifier clashes):')
        foreach ($source in $Sources) { $writer.WriteLine(('      - {0} @ {1}' -f $source.Name, $source.Commit)) }
        $writer.WriteLine('    Excluded: include wrappers, duplicate rule identifiers, external-variable')
        $writer.WriteLine('              rules, exclusions.conf entries and files that do not compile.')
        $writer.WriteLine('    Record: rules.lock (commits, bundle SHA256) and the build report.')
        $writer.WriteLine('*/')
        foreach ($ruleFile in $AcceptedFiles) {
            $converted = Convert-YaraSuppressedRules -Text (Read-YaraRuleText -Path $ruleFile.Path) -Patterns $Suppress
            foreach ($item in $converted.Applied) {
                [void]$suppressed.Add([pscustomobject]@{ Entry = $ruleFile; Rule = $item.Rule; Exclusion = $item.Exclusion })
            }
            $text = $converted.Text
            $writer.WriteLine('')
            $writer.WriteLine(('/* BEGIN {0} */' -f $ruleFile.Rel))
            $writer.Write($text)
            if (-not $text.EndsWith("`n")) { $writer.WriteLine('') }
            $writer.WriteLine(('/* END {0} */' -f $ruleFile.Rel))
        }
    }
    finally {
        $writer.Dispose()
    }
    return @($suppressed)
}

function Get-YaraCompileErrors {
<#
.SYNOPSIS
    Extracts bundle line numbers from yarac error output.
.DESCRIPTION
    yarac reports two shapes:
      <file>(<line>): error: <message>                     (syntax errors)
      error: rule "<name>" in <file>(<line>): <message>    (rule-level errors)
    The bundle file name is matched first so parentheses elsewhere in a path
    (e.g. "D:\IR Kit (1)\") cannot be mistaken for the line number.
.OUTPUTS
    PSCustomObject[] with Line (int) and Text (string), one per distinct line.
#>
    [CmdletBinding()]
    param(
        [AllowEmptyString()][string]$ErrorText,
        [string]$BundleName = ''
    )

    $found = New-Object System.Collections.ArrayList
    $seen = @{}
    foreach ($raw in ([string]$ErrorText -split "`n")) {
        if ($raw -notmatch 'error') { continue }
        $match = $null
        if ($BundleName) { $match = [regex]::Match($raw, [regex]::Escape($BundleName) + '\((\d+)\)') }
        if (-not $match -or -not $match.Success) { $match = [regex]::Match($raw, '\((\d+)\):\s*error') }
        if (-not $match.Success) { $match = [regex]::Match($raw, '\((\d+)\):') }
        if (-not $match.Success) { continue }
        $number = [int]$match.Groups[1].Value
        if ($seen.ContainsKey($number)) { continue }
        $seen[$number] = $true
        [void]$found.Add([pscustomobject]@{ Line = $number; Text = $raw.Trim() })
    }
    return @($found)
}

function Get-YaraBundleSourceForLine {
<#
.SYNOPSIS
    Maps a bundle line number (1-based) to the nearest preceding /* BEGIN <file> */ marker.
.OUTPUTS
    System.String or $null
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][AllowEmptyCollection()][AllowEmptyString()][string[]]$BundleLines,
        [Parameter(Mandatory=$true)][int]$LineNumber
    )

    $current = $null
    $limit = [math]::Min($LineNumber, $BundleLines.Count)
    for ($i = 0; $i -lt $limit; $i++) {
        $line = $BundleLines[$i]
        if ($line.StartsWith('/* BEGIN ')) {
            $current = ($line.Substring(9) -replace '\s*\*/\s*$', '').Trim()
        }
    }
    return $current
}

function Invoke-YaraCompiler {
<#
.SYNOPSIS
    Compiles a bundle with yarac (-w) into a throw-away file.
.OUTPUTS
    PSCustomObject with Ok and Output.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$YaracPath,
        [Parameter(Mandatory=$true)][string]$BundlePath
    )

    $compiled = Join-Path ([System.IO.Path]::GetTempPath()) ('Vestigium_yarac_{0}.bin' -f ([guid]::NewGuid().ToString('N')))
    try {
        $ErrorActionPreference = 'Continue'
        $global:LASTEXITCODE = 0
        $output = @(& $YaracPath -w $BundlePath $compiled 2>&1 | ForEach-Object { [string]$_ })
        $code = $LASTEXITCODE
        return [pscustomobject]@{ Ok = ($code -eq 0); Output = (($output -join "`n").Trim()) }
    }
    catch {
        return [pscustomobject]@{ Ok = $false; Output = ('yarac invocation failed: {0}' -f $_.Exception.Message) }
    }
    finally {
        Remove-Item -LiteralPath $compiled -Force -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------------------
# Hashing and rules.lock
# ---------------------------------------------------------------------------
function Get-YaraSha256Hex {
<#
.SYNOPSIS
    Lower-case SHA256 of a byte array.
.OUTPUTS
    System.String
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][AllowEmptyCollection()][byte[]]$Bytes)

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return (-join ($sha.ComputeHash($Bytes) | ForEach-Object { $_.ToString('x2') })) }
    finally { $sha.Dispose() }
}

function Get-YaraNormalizedBytes {
<#
.SYNOPSIS
    File bytes with a UTF-8 BOM removed and CRLF/CR folded to LF (matches the Linux builder).
.OUTPUTS
    System.Byte[]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Path)

    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $latin1 = [System.Text.Encoding]::GetEncoding(28591)
    $text = $latin1.GetString($bytes)
    if ($text.StartsWith(([string][char]0xEF + [char]0xBB + [char]0xBF))) { $text = $text.Substring(3) }
    $text = ($text -replace "`r`n", "`n") -replace "`r", "`n"
    return ,$latin1.GetBytes($text)
}

function Get-YaraTreeDigest {
<#
.SYNOPSIS
    SHA256 over "<sha256>  <relative path>" lines of line-ending-normalised files.
.OUTPUTS
    System.String
#>
    [CmdletBinding()]
    param([AllowEmptyCollection()][object[]]$Files = @())

    $rels = New-Object 'System.Collections.Generic.List[string]'
    $byRel = @{}
    foreach ($file in $Files) { $rels.Add($file.Rel); $byRel[$file.Rel] = $file.Path }
    $rels.Sort([System.StringComparer]::Ordinal)
    $builder = New-Object System.Text.StringBuilder
    foreach ($rel in $rels) {
        $content = Get-YaraSha256Hex -Bytes (Get-YaraNormalizedBytes -Path $byRel[$rel])
        [void]$builder.Append(('{0}  {1}' -f $content, $rel) + "`n")
    }
    return (Get-YaraSha256Hex -Bytes ([System.Text.Encoding]::UTF8.GetBytes($builder.ToString())))
}

function Get-YaraToolVersion {
<#
.SYNOPSIS
    First line of "<tool> --version", or 'unknown'.
.OUTPUTS
    System.String
#>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Path)

    if (-not $Path) { return 'unknown' }
    try {
        $ErrorActionPreference = 'Continue'
        $global:LASTEXITCODE = 0
        $line = [string](& $Path --version 2>$null | Select-Object -First 1)
        if ($LASTEXITCODE -eq 0 -and $line.Trim()) { return $line.Trim() }
    }
    catch { }
    return 'unknown'
}

function Get-YaraLockText {
<#
.SYNOPSIS
    Renders rules.lock (same layout as the Linux builder).
.OUTPUTS
    System.String
#>
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][hashtable]$Data)

    $lines = New-Object 'System.Collections.Generic.List[string]'
    foreach ($header in @(
        '# Vestigium YARA rule lock (format 1) - generated, but versioned in git.',
        '# Written by the rule builder after every successful build (unless only the',
        "# 'generated' line would change). Reproduce this exact build with:",
        '#   Linux:   sudo ./vestigium.sh setup --rules-locked',
        '#   Windows: .\vestigium.ps1 setup -Locked',
        '# Format: "key = value" lines under [lock], [source <name>] (in precedence',
        '# order), [custom], [exclusions] and [bundle]. See docs/YARA-RULES.md.',
        '')) { $lines.Add($header) }
    $lines.Add('[lock]')
    foreach ($key in @('format', 'generated', 'builder', 'yara')) { $lines.Add(('{0} = {1}' -f $key, $Data[$key])) }
    foreach ($source in $Data['sources']) {
        $lines.Add('')
        $lines.Add(('[source {0}]' -f $source.Name))
        foreach ($pair in @(@('url', $source.Url), @('ref', $source.Ref), @('commit', $source.Commit), @('commit_date', $source.CommitDate))) {
            if ([string]$pair[1]) { $lines.Add(('{0} = {1}' -f $pair[0], $pair[1])) } else { $lines.Add(('{0} =' -f $pair[0])) }
        }
    }
    foreach ($section in @(
        @('custom', @('files', 'sha256')),
        @('exclusions', @('sha256', 'files_excluded', 'rules_suppressed')),
        @('bundle', @('file', 'sha256', 'rules', 'rules_reporting', 'files_accepted', 'files_skipped')))) {
        $lines.Add('')
        $lines.Add(('[{0}]' -f $section[0]))
        $values = $Data[$section[0]]
        foreach ($key in $section[1]) { $lines.Add(('{0} = {1}' -f $key, $values[$key])) }
    }
    return (($lines -join "`n") + "`n")
}

function Write-YaraRuleLock {
<#
.SYNOPSIS
    Writes rules.lock unless only its 'generated' line would change.
.OUTPUTS
    System.Boolean - $true when the file was (re)written.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string]$Text
    )

    $significant = {
        param([string]$Content)
        @(($Content -replace "`r", '') -split "`n" | Where-Object { -not $_.StartsWith('generated =') -and -not $_.StartsWith('#') }) -join "`n"
    }
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        $old = [System.IO.File]::ReadAllText($Path)
        if ((& $significant $old) -ceq (& $significant $Text)) { return $false }
    }
    $temp = '{0}.{1}.tmp' -f $Path, ([guid]::NewGuid().ToString('N'))
    try {
        [System.IO.File]::WriteAllText($temp, $Text, (New-Object System.Text.UTF8Encoding($false)))
        Move-Item -LiteralPath $temp -Destination $Path -Force -ErrorAction Stop
    }
    finally {
        if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue }
    }
    return $true
}

function Test-YaraBundleAgainstLock {
<#
.SYNOPSIS
    Compares a finished build with rules.lock and logs MATCH or MISMATCH with the differing inputs.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$LockPath,
        [Parameter(Mandatory=$true)][hashtable]$Data
    )

    $sections = Read-YaraRuleLock -Path $LockPath
    $want = Get-YaraLockValue -Sections $sections -Section 'bundle' -Key 'sha256'
    $have = [string]$Data['bundle']['sha256']
    if ($want -eq $have) {
        Write-RuleBuilderLog -Level SUCCESS -Message ("Lock check: MATCH - bundle SHA256 {0} equals rules.lock" -f $have)
        return $true
    }
    if (-not $want) { $want = '(none)' }
    Write-RuleBuilderLog -Level WARN -Message ("Lock check: MISMATCH - bundle SHA256 {0}, rules.lock records {1}" -f $have, $want)
    $lockedYara = Get-YaraLockValue -Sections $sections -Section 'lock' -Key 'yara'
    if ($lockedYara -ne [string]$Data['yara']) {
        Write-RuleBuilderLog -Level WARN -Message ("Lock check:   yara {0} here, {1} in lock (built by {2})" -f $Data['yara'], $lockedYara, (Get-YaraLockValue -Sections $sections -Section 'lock' -Key 'builder'))
    }
    foreach ($pair in @(@('custom', 'sha256'), @('exclusions', 'sha256'), @('bundle', 'rules'), @('bundle', 'files_accepted'))) {
        $locked = Get-YaraLockValue -Sections $sections -Section $pair[0] -Key $pair[1]
        $current = [string]$Data[$pair[0]][$pair[1]]
        if ($locked -ne $current) {
            Write-RuleBuilderLog -Level WARN -Message ("Lock check:   {0}.{1}: {2} here, {3} in lock" -f $pair[0], $pair[1], $current, $locked)
        }
    }
    Write-RuleBuilderLog -Level WARN -Message 'Lock check:   the Linux builder also compile-checks each file on its own, so bundles from the two builders can differ legitimately; compare the build reports.'
    return $false
}

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
function New-ActiveYaraRuleSet {
<#
.SYNOPSIS
    Builds active-rules.yar from custom rules and all configured repository rule files.
.OUTPUTS
    PSCustomObject with the build statistics, or $null when the build failed.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][object[]]$Repositories,
        [Parameter(Mandatory=$true)][string]$RulesRoot,
        [Parameter(Mandatory=$true)][string]$OutputPath,
        [Parameter(Mandatory=$true)][string]$ReportPath,
        [AllowEmptyCollection()][object[]]$Exclusions = @(),
        [string]$YaracPath = '',
        [int]$MaxCompileAttempts = 10
    )

    $tempBundle = $null
    try {
        $parent = Split-Path -Parent $OutputPath
        if (-not (Test-Path -LiteralPath $parent)) {
            New-Item -ItemType Directory -Path $parent -Force -ErrorAction Stop | Out-Null
        }

        $fileRules = @($Exclusions | Where-Object { $_.Kind -eq 'file' })
        $ruleRules = @($Exclusions | Where-Object { $_.Kind -eq 'rule' })
        $usedPatterns = @{}
        $report = New-Object System.Collections.ArrayList
        $seenRuleNames = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([System.StringComparer]::Ordinal)
        $acceptedFiles = New-Object System.Collections.ArrayList
        $customFiles = New-Object System.Collections.ArrayList

        foreach ($repo in $Repositories) {
            $isCustom = ($repo.Name -eq 'custom')
            $externalVariableFiles = @{}
            if (-not $isCustom) { $externalVariableFiles = Get-ExternalVariableExclusions -RepositoryUrl $repo.Url -RepositoryPath $repo.Path }
            $roots = @(Get-YaraRuleSearchRoots -RepositoryUrl $repo.Url -RepositoryPath $repo.Path | Where-Object { $_ -and (Test-Path -LiteralPath $_) })
            if ($isCustom) { $roots = @($repo.Path) }

            if ($roots.Count -eq 0) {
                [void]$report.Add([pscustomobject]@{ Repository = $repo.Name; File = ''; Status = 'Skipped'; Reason = 'No rule search roots found'; Rules = '' })
                continue
            }
            $ruleFiles = @(Get-YaraCandidateFiles -Roots $roots -RepositoryPath $repo.Path -RulesRoot $RulesRoot)
            Write-RuleBuilderLog -Message ("{0}: {1} candidate rule file(s)" -f $repo.Name, $ruleFiles.Count)

            foreach ($ruleFile in $ruleFiles) {
                if ($isCustom) { [void]$customFiles.Add($ruleFile) }
                $status = 'Accepted'
                $reason = ''
                $ruleNames = @()
                try {
                    $matched = $null
                    foreach ($entry in $fileRules) {
                        if ($ruleFile.Rel -like $entry.Pattern) { $matched = $entry; break }
                    }
                    if ($matched) {
                        $status = 'Excluded'
                        $reason = $matched.Label
                        $usedPatterns[$matched.Label] = $true
                    }
                    elseif ($externalVariableFiles.ContainsKey((Split-Path -Leaf $ruleFile.Path).ToLowerInvariant())) {
                        $status = 'Skipped'
                        $reason = 'External-variable rule file'
                    }
                    elseif (Test-YaraRuleFileHasInclude -Path $ruleFile.Path) {
                        $status = 'Skipped'
                        $reason = 'Contains include statement'
                    }
                    else {
                        $ruleNames = @(Get-YaraRuleNames -Path $ruleFile.Path)
                        $unique = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
                        foreach ($ruleName in $ruleNames) { [void]$unique.Add($ruleName) }
                        if ($ruleNames.Count -eq 0) {
                            $status = 'Skipped'
                            $reason = 'No rule identifiers found'
                        }
                        elseif ($unique.Count -ne $ruleNames.Count) {
                            $status = 'Skipped'
                            $reason = 'Duplicate rule identifiers inside file'
                        }
                        else {
                            $duplicates = @($ruleNames | Where-Object { $seenRuleNames.ContainsKey($_) })
                            if ($duplicates.Count -gt 0) {
                                $status = 'Skipped'
                                $reason = 'Duplicate rule identifiers already accepted: ' + (($duplicates | Select-Object -First 5) -join ',')
                            }
                        }
                    }

                    if ($status -eq 'Accepted') {
                        foreach ($ruleName in $ruleNames) { $seenRuleNames[$ruleName] = $ruleFile.Rel }
                        [void]$acceptedFiles.Add([pscustomobject]@{ Repository = $repo.Name; Path = $ruleFile.Path; Rel = $ruleFile.Rel; Rules = $ruleNames })
                    }
                    elseif ($isCustom -and $status -eq 'Skipped') {
                        Write-RuleBuilderLog -Level WARN -Message ("Custom rule file {0} not included: {1}" -f $ruleFile.Rel, $reason)
                    }
                }
                catch {
                    $status = 'Skipped'
                    $reason = 'Parse/read failure: ' + $_.Exception.Message
                }

                [void]$report.Add([pscustomobject]@{
                    Repository = $repo.Name
                    File       = $ruleFile.Rel
                    Status     = $status
                    Reason     = $reason
                    Rules      = ($ruleNames -join ';')
                })
            }
        }

        if ($acceptedFiles.Count -eq 0) {
            Write-RuleBuilderLog -Level ERROR -Message 'No eligible YARA rule files found; active-rules.yar left unchanged'
            $report | Export-Csv -Path $ReportPath -NoTypeInformation -Encoding UTF8 -Force
            return $null
        }

        $sources = @($Repositories | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Commit = $_.Commit } })
        $tempBundle = Join-Path $parent ('.active-rules.building.{0}.yar' -f ([guid]::NewGuid().ToString('N')))
        $suppressed = @(Write-YaraBundle -AcceptedFiles @($acceptedFiles) -OutputPath $tempBundle -Sources $sources -Suppress $ruleRules)

        if (-not [string]::IsNullOrWhiteSpace($YaracPath)) {
            $compiled = $false
            $attempts = 0
            $dropped = 0
            $bundleName = Split-Path -Leaf $tempBundle
            while ($true) {
                $result = Invoke-YaraCompiler -YaracPath $YaracPath -BundlePath $tempBundle
                if ($result.Ok) { $compiled = $true; break }
                if ($attempts -ge $MaxCompileAttempts) {
                    Write-RuleBuilderLog -Level ERROR -Message ("Bundle still does not compile after {0} rebuild attempts: {1}" -f $attempts, $result.Output)
                    break
                }
                # Map every reported error line to its source file and drop all
                # of them in this pass (one compile can report several files).
                $bundleLines = ([System.IO.File]::ReadAllText($tempBundle)).Split([char]10)
                $culprits = [ordered]@{}
                foreach ($compileError in (Get-YaraCompileErrors -ErrorText $result.Output -BundleName $bundleName)) {
                    $source = Get-YaraBundleSourceForLine -BundleLines $bundleLines -LineNumber $compileError.Line
                    if ($source -and -not $culprits.Contains($source)) { $culprits[$source] = $compileError.Text }
                }
                if ($culprits.Count -eq 0) {
                    Write-RuleBuilderLog -Level ERROR -Message ("Bundle compile failed and the source file could not be identified: {0}" -f $result.Output)
                    break
                }
                $attempts++
                foreach ($culprit in @($culprits.Keys)) {
                    $errorText = [string]$culprits[$culprit]
                    if ($errorText.Length -gt 200) { $errorText = $errorText.Substring(0, 200) }
                    Write-RuleBuilderLog -Level WARN -Message ("Compile attempt {0}: dropping {1} ({2})" -f $attempts, $culprit, $errorText)
                    foreach ($row in $report) {
                        if ($row.File -eq $culprit) {
                            $row.Status = 'Skipped'
                            $row.Reason = 'Bundle compile failure: ' + $errorText
                        }
                    }
                    $dropped++
                }
                $remaining = New-Object System.Collections.ArrayList
                foreach ($entry in $acceptedFiles) { if (-not $culprits.Contains($entry.Rel)) { [void]$remaining.Add($entry) } }
                $acceptedFiles = $remaining
                if ($acceptedFiles.Count -eq 0) {
                    Write-RuleBuilderLog -Level ERROR -Message 'Every rule file was dropped during compile validation'
                    break
                }
                $suppressed = @(Write-YaraBundle -AcceptedFiles @($acceptedFiles) -OutputPath $tempBundle -Sources $sources -Suppress $ruleRules)
            }
            if (-not $compiled) {
                $report | Export-Csv -Path $ReportPath -NoTypeInformation -Encoding UTF8 -Force
                Write-RuleBuilderLog -Level ERROR -Message ("Build failed; existing {0} left unchanged. Report={1}" -f $OutputPath, $ReportPath)
                return $null
            }
            Write-RuleBuilderLog -Level SUCCESS -Message ("Bundle compiles with {0} ({1} files dropped in {2} rebuilds)" -f $YaracPath, $dropped, $attempts)
        }
        else {
            Write-RuleBuilderLog -Level WARN -Message 'Compile validation skipped: no yarac available (use -YaracPath or place Tools\yarac64.exe)'
        }

        Move-Item -LiteralPath $tempBundle -Destination $OutputPath -Force -ErrorAction Stop
        $tempBundle = $null

        foreach ($item in $suppressed) {
            $usedPatterns[$item.Exclusion.Label] = $true
            [void]$report.Add([pscustomobject]@{
                Repository = $item.Entry.Repository
                File       = $item.Entry.Rel
                Status     = 'Suppressed'
                Reason     = ('{0} (rewritten to private rule)' -f $item.Exclusion.Label)
                Rules      = $item.Rule
            })
        }
        foreach ($entry in $Exclusions) {
            if ($usedPatterns.ContainsKey($entry.Label)) { continue }
            Write-RuleBuilderLog -Level WARN -Message ("{0} matched nothing" -f $entry.Label)
            [void]$report.Add([pscustomobject]@{ Repository = 'exclusions.conf'; File = ''; Status = 'Unmatched'; Reason = ('{0} matched nothing' -f $entry.Label); Rules = '' })
        }
        $report | Export-Csv -Path $ReportPath -NoTypeInformation -Encoding UTF8 -Force

        $acceptedCount = @($report | Where-Object { $_.Status -eq 'Accepted' }).Count
        $skippedCount = @($report | Where-Object { $_.Status -eq 'Skipped' }).Count
        $excludedCount = @($report | Where-Object { $_.Status -eq 'Excluded' }).Count
        $suppressedCount = @($report | Where-Object { $_.Status -eq 'Suppressed' }).Count
        $ruleTotal = 0
        $rulePrivate = 0
        foreach ($match in [regex]::Matches((Read-YaraRuleText -Path $OutputPath), $script:RuleDeclPattern)) {
            $ruleTotal++
            if (@($match.Groups[2].Value -split '\s+') -ccontains 'private') { $rulePrivate++ }
        }
        Write-RuleBuilderLog -Level SUCCESS -Message ("Built {0} from {1} files and {2} rule identifiers; skipped {3}, excluded {4} files, suppressed {5} rules. Report={6}" -f $OutputPath, $acceptedCount, $seenRuleNames.Count, $skippedCount, $excludedCount, $suppressedCount, $ReportPath)
        return [pscustomobject]@{
            Accepted     = $acceptedCount
            Skipped      = $skippedCount
            Excluded     = $excludedCount
            Suppressed   = $suppressedCount
            Rules        = $ruleTotal
            RulesPrivate = $rulePrivate
            CustomFiles  = @($customFiles)
        }
    }
    catch {
        Write-RuleBuilderLog -Level ERROR -Message ("Active rule build failed (line {0}): {1}" -f $_.InvocationInfo.ScriptLineNumber, $_.Exception.Message)
        return $null
    }
    finally {
        if ($tempBundle -and (Test-Path -LiteralPath $tempBundle)) {
            Remove-Item -LiteralPath $tempBundle -Force -ErrorAction SilentlyContinue
        }
    }
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
$toolsRoot = Get-RuleBuilderRoot
if ([string]::IsNullOrWhiteSpace($RulesRoot)) {
    $kitRoot = Get-RuleBuilderKitRoot -ToolsRoot $toolsRoot
    if ($kitRoot) { $RulesRoot = Join-Path (Join-Path $kitRoot 'shared') 'yara-rules' }
    else { $RulesRoot = Join-Path $toolsRoot 'YaraRules' }
}
$RulesRoot = [System.IO.Path]::GetFullPath($RulesRoot)
$activeRulesPath = Join-Path $RulesRoot 'active-rules.yar'
$reportPath = Join-Path $RulesRoot 'RuleBuildReport.csv'
$lockPath = Join-Path $RulesRoot 'rules.lock'
$sourcesPath = Join-Path $RulesRoot 'sources.conf'
$exclusionsPath = Join-Path $RulesRoot 'exclusions.conf'
$customPath = Join-Path $RulesRoot 'custom'

if ([string]::IsNullOrWhiteSpace($YaracPath)) {
    $defaultYarac = Join-Path $toolsRoot 'yarac64.exe'
    if (Test-Path -LiteralPath $defaultYarac -PathType Leaf) { $YaracPath = $defaultYarac }
}
elseif (-not (Test-Path -LiteralPath $YaracPath -PathType Leaf)) {
    Write-RuleBuilderLog -Level ERROR -Message ("-YaracPath not found: {0}" -f $YaracPath)
    exit 2
}

Write-RuleBuilderLog -Message ("Rules root: {0}" -f $RulesRoot)
if (-not (Test-Path -LiteralPath $RulesRoot)) {
    New-Item -ItemType Directory -Path $RulesRoot -Force | Out-Null
}

# Configuration errors are fatal: nothing unvalidated reaches git.
try {
    $exclusionEntries = @(Read-YaraExclusions -Path $exclusionsPath)
    if ($Locked) {
        if (-not (Test-Path -LiteralPath $lockPath -PathType Leaf)) {
            Write-RuleBuilderLog -Level ERROR -Message ("-Locked: {0} not found (build once without -Locked, or restore it from git)" -f $lockPath)
            exit 2
        }
        $sourceList = @(Get-YaraLockSources -Path $lockPath)
        $origin = 'rules.lock'
    }
    elseif ($PSBoundParameters.ContainsKey('RepositoryUrls') -or -not (Test-Path -LiteralPath $sourcesPath -PathType Leaf)) {
        $sourceList = New-Object System.Collections.ArrayList
        foreach ($url in $RepositoryUrls) {
            $name = Get-YaraRepositoryName -RepositoryUrl $url -RulesRoot $RulesRoot
            $problem = Test-YaraSourceEntry -Name $name -Url $url
            if ($problem) { throw $problem }
            [void]$sourceList.Add([pscustomobject]@{ Name = $name; Url = $url; Ref = ''; Commit = '' })
        }
        $sourceList = @($sourceList)
        if ($PSBoundParameters.ContainsKey('RepositoryUrls')) { $origin = '-RepositoryUrls' } else { $origin = 'built-in list (sources.conf not found)' }
    }
    else {
        $sourceList = @(Read-YaraSourcesConf -Path $sourcesPath)
        $origin = 'sources.conf'
    }
}
catch {
    Write-RuleBuilderLog -Level ERROR -Message ("Configuration error: {0}" -f $_.Exception.Message)
    exit 2
}
Write-RuleBuilderLog -Message ("Sources ({0}): {1}" -f $origin, (($sourceList | ForEach-Object { $_.Name }) -join ', '))
if ($exclusionEntries.Count -gt 0) {
    Write-RuleBuilderLog -Message ("exclusions.conf: {0} file pattern(s), {1} rule pattern(s)" -f @($exclusionEntries | Where-Object { $_.Kind -eq 'file' }).Count, @($exclusionEntries | Where-Object { $_.Kind -eq 'rule' }).Count)
}

$repositories = New-Object System.Collections.ArrayList
if (Test-Path -LiteralPath $customPath -PathType Container) {
    [void]$repositories.Add([pscustomobject]@{ Name = 'custom'; Url = ''; Ref = ''; Path = $customPath; Commit = 'kit'; CommitDate = '' })
}
$lockEntries = New-Object System.Collections.ArrayList
$failedLocked = $false
foreach ($source in $sourceList) {
    $path = Join-Path $RulesRoot $source.Name
    if ($Locked) {
        if ((Get-YaraCheckoutCommit -Path $path) -ne $source.Commit) {
            if ($SkipGitUpdate) {
                Write-RuleBuilderLog -Level ERROR -Message ("{0} is not at locked commit {1} and -SkipGitUpdate forbids fetching it" -f $source.Name, $source.Commit)
                $failedLocked = $true
                continue
            }
            [void](Update-YaraRepository -RepositoryUrl $source.Url -RepositoryPath $path -Ref $source.Commit)
            if ((Get-YaraCheckoutCommit -Path $path) -ne $source.Commit) {
                Write-RuleBuilderLog -Level ERROR -Message ("Cannot check out {0} at locked commit {1} from {2} (commit unavailable upstream, network failure, or local changes in the checkout)" -f $source.Name, $source.Commit, $source.Url)
                $failedLocked = $true
                continue
            }
        }
        Write-RuleBuilderLog -Level SUCCESS -Message ("{0} at locked commit {1}" -f $source.Name, $source.Commit)
    }
    elseif (-not (Update-YaraRepository -RepositoryUrl $source.Url -RepositoryPath $path -Ref $source.Ref -SkipGitUpdate:$SkipGitUpdate)) {
        if (Test-Path -LiteralPath $path) {
            if (-not $SkipGitUpdate) { Write-RuleBuilderLog -Level WARN -Message ("Could not update {0}; using the existing copy" -f $source.Name) }
        }
        else {
            Write-RuleBuilderLog -Level ERROR -Message ("Source {0} is not available: {1}" -f $source.Name, $path)
        }
    }
    if (-not (Test-Path -LiteralPath $path -PathType Container)) { continue }
    $commit = Get-YaraCheckoutCommit -Path $path
    [void]$repositories.Add([pscustomobject]@{ Name = $source.Name; Url = $source.Url; Ref = $source.Ref; Path = $path; Commit = $commit; CommitDate = (Get-YaraCommitDate -Path $path) })
    [void]$lockEntries.Add([pscustomobject]@{ Name = $source.Name; Url = $source.Url; Ref = $source.Ref; Commit = $commit; CommitDate = (Get-YaraCommitDate -Path $path) })
}

if ($failedLocked) {
    Write-RuleBuilderLog -Level ERROR -Message 'Locked rebuild aborted; the existing bundle is unchanged'
    exit 1
}
if ($lockEntries.Count -eq 0) {
    Write-RuleBuilderLog -Level ERROR -Message 'No YARA repositories are available'
    exit 1
}

$build = New-ActiveYaraRuleSet -Repositories @($repositories) -RulesRoot $RulesRoot -OutputPath $activeRulesPath -ReportPath $reportPath -Exclusions $exclusionEntries -YaracPath $YaracPath -MaxCompileAttempts $MaxCompileAttempts
if ($null -eq $build) {
    exit 1
}

$exclusionsSha = 'none'
if (Test-Path -LiteralPath $exclusionsPath -PathType Leaf) { $exclusionsSha = Get-YaraSha256Hex -Bytes (Get-YaraNormalizedBytes -Path $exclusionsPath) }
$bundleSha = Get-YaraSha256Hex -Bytes ([System.IO.File]::ReadAllBytes($activeRulesPath))
$lockData = @{
    format     = '1'
    generated  = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    builder    = $script:BuilderName
    yara       = (Get-YaraToolVersion -Path $YaracPath)
    sources    = @($lockEntries)
    custom     = @{ files = @($build.CustomFiles).Count; sha256 = (Get-YaraTreeDigest -Files @($build.CustomFiles)) }
    exclusions = @{ sha256 = $exclusionsSha; files_excluded = $build.Excluded; rules_suppressed = $build.Suppressed }
    bundle     = @{
        file            = 'active-rules.yar'
        sha256          = $bundleSha
        rules           = $build.Rules
        rules_reporting = ($build.Rules - $build.RulesPrivate)
        files_accepted  = $build.Accepted
        files_skipped   = $build.Skipped
    }
}
Write-RuleBuilderLog -Message ("Bundle SHA256 {0}; {1} rules ({2} reporting)" -f $bundleSha, $build.Rules, ($build.Rules - $build.RulesPrivate))

if ($Locked) {
    [void](Test-YaraBundleAgainstLock -LockPath $lockPath -Data $lockData)
}
elseif (Write-YaraRuleLock -Path $lockPath -Text (Get-YaraLockText -Data $lockData)) {
    Write-RuleBuilderLog -Level SUCCESS -Message ("Lock written: {0} (commit it to pin this rule set)" -f $lockPath)
}
else {
    Write-RuleBuilderLog -Message ("Lock unchanged: {0}" -f $lockPath)
}
exit 0

<#
.SYNOPSIS
    Finds calls to boolean-returning functions whose result leaks into the
    caller's output stream.
.DESCRIPTION
    Collection steps report success through their return value. A call such as
    `Invoke-Something -Context $c` on its own line (not assigned, returned,
    cast to [void] or piped to Out-Null) adds its $true/$false to the caller's
    output, so `$result = & $step` becomes an array and a failure can read as
    success. Prints one line per leak; no output means clean.

    Step script blocks inside hashtable literals (the launcher's step table)
    are intentional and ignored.
.EXAMPLE
    pwsh -File tests/ast-leaks.ps1 -Root platforms/windows
#>
param([Parameter(Mandatory = $true)][string]$Root)

$Ast = [System.Management.Automation.Language.Ast]
$files = Get-ChildItem -LiteralPath $Root -Recurse -Filter *.ps1
$boolFunctions = @{}
$parsed = @{}

foreach ($file in $files) {
    $tokens = $null; $errors = $null
    $tree = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
    $parsed[$file.FullName] = $tree
    $definitions = $tree.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
    foreach ($fn in $definitions) {
        $returns = $fn.Body.FindAll({
            param($n)
            $n -is [System.Management.Automation.Language.ReturnStatementAst] -and $n.Pipeline -and
            $n.Pipeline.Extent.Text -match '^\$(true|false|success|ok)\b|^\('
        }, $true)
        if ($returns.Count -gt 0) { $boolFunctions[$fn.Name] = $true }
    }
}

foreach ($entry in $parsed.GetEnumerator()) {
    $calls = $entry.Value.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)
    foreach ($call in $calls) {
        $name = $call.GetCommandName()
        if (-not $name -or -not $boolFunctions.ContainsKey($name)) { continue }
        $pipeline = $call.Parent
        if ($pipeline -isnot [System.Management.Automation.Language.PipelineAst]) { continue }
        if ($pipeline.PipelineElements.Count -gt 1) { continue }
        $parent = $pipeline.Parent
        if ($parent -isnot [System.Management.Automation.Language.NamedBlockAst] -and
            $parent -isnot [System.Management.Automation.Language.StatementBlockAst]) { continue }

        $inHashtable = $false
        for ($node = $parent; $node; $node = $node.Parent) {
            if ($node -is [System.Management.Automation.Language.HashtableAst]) { $inHashtable = $true; break }
        }
        if ($inHashtable) { continue }
        '{0}:{1}: {2}' -f (Split-Path -Leaf $entry.Key), $call.Extent.StartLineNumber, $call.Extent.Text.Split("`n")[0]
    }
}

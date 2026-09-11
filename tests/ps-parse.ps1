<#
.SYNOPSIS
    Parses PowerShell files with the language parser and reports syntax errors.
.DESCRIPTION
    Prints "OK <file>" or "ERROR <file>: L<line>: <message>" per file and exits
    1 when any file fails to parse.
.EXAMPLE
    pwsh -File tests/ps-parse.ps1 vestigium.ps1 shared/Verify-Evidence.ps1
#>
# Flatten arguments so both `ps-parse.ps1 a b c` and a single array argument
# (`ps-parse.ps1 @($paths)`) work: the latter would otherwise arrive as one
# System.Object[] element and be stringified into an invalid path.
$targets = @()
$args | ForEach-Object { $targets += $_ }

$failed = $false
foreach ($file in $targets) {
    $tokens = $null
    $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile([string]$file, [ref]$tokens, [ref]$errors)
    if ($errors) {
        $failed = $true
        foreach ($e in $errors) { 'ERROR {0}: L{1}: {2}' -f $file, $e.Extent.StartLineNumber, $e.Message }
    }
    else {
        'OK {0}' -f $file
    }
}
if ($failed) { exit 1 }
exit 0   # explicit: callers using `& ps-parse.ps1` read $LASTEXITCODE

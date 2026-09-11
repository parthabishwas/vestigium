<#
.SYNOPSIS
    Parses PowerShell files with the language parser and reports syntax errors.
.DESCRIPTION
    Prints "OK <file>" or "ERROR <file>: L<line>: <message>" per file and exits
    1 when any file fails to parse.
.EXAMPLE
    pwsh -File tests/ps-parse.ps1 vestigium.ps1 shared/Verify-Evidence.ps1
#>
$failed = $false
foreach ($file in $args) {
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

<#
.SYNOPSIS
    Checks that every PowerShell script next to this one parses.

.DESCRIPTION
    The scripts in this folder are started by hand, on machines that CI
    never sees. CI runs this check in the PowerShell that every Windows
    has and in the newer one, so that a script at least cannot stop at a
    slip of the pen. It runs nothing of what it reads.
#>
$failed = 0
foreach ($file in @(Get-ChildItem -LiteralPath $PSScriptRoot -Filter '*.ps1' | Sort-Object Name)) {
    $tokens = $null
    $problems = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$problems)
    if ($problems) {
        foreach ($problem in $problems) {
            Write-Host "$($file.Name), line $($problem.Extent.StartLineNumber): $($problem.Message)"
            $failed++
        }
    } else {
        Write-Host "$($file.Name) parses."
    }
}
if ($failed -gt 0) {
    exit 1
}
exit 0

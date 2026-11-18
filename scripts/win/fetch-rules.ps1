<#
.SYNOPSIS
    Downloads the YARA Forge rule package that rules\yara-forge.pin names.

.DESCRIPTION
    Saves the package to rules\vendor\ and checks it against the SHA-256
    recorded in the pin file. Nothing is kept if the checksum does not match.
    Writes the path of the package to the output when it succeeds.

    Microsoft Defender blocks this package, because a rule file is full of
    the byte patterns of the malware it describes. This script never changes
    an antivirus setting. It says which single folder would have to be
    excluded, and leaves that to you.

    Run it from a terminal with:
        powershell -NoProfile -ExecutionPolicy Bypass -File scripts\win\fetch-rules.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
# The progress bar of Invoke-WebRequest slows a download down considerably.
$ProgressPreference = 'SilentlyContinue'

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$pinFile = Join-Path $repo 'rules\yara-forge.pin'
$pin = @{}
foreach ($line in Get-Content -LiteralPath $pinFile) {
    if ($line -match '^\s*([a-z0-9_]+)\s*=\s*(.+?)\s*$') {
        $pin[$Matches[1]] = $Matches[2]
    }
}
foreach ($key in 'tag', 'package', 'sha256') {
    if (-not $pin[$key]) {
        Write-Host "$pinFile does not name a $key." -ForegroundColor Red
        exit 2
    }
}

$vendor = Join-Path $repo 'rules\vendor'
$target = Join-Path $vendor $pin['package']
New-Item -ItemType Directory -Force -Path $vendor | Out-Null

function Get-Digest([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

# True if Windows refused a file operation because an antivirus flagged the
# file: error 225, "the file contains a virus", or 226, "... and was deleted".
function Test-AntivirusBlock($Exception) {
    while ($Exception) {
        $code = $Exception.HResult -band 0xFFFF
        if ($code -eq 225 -or $code -eq 226) {
            return $true
        }
        $Exception = $Exception.InnerException
    }
    return $false
}

function Write-AntivirusAdvice {
    Write-Host ''
    Write-Host 'Your antivirus has most likely blocked the rule package. A rule file is full of the' -ForegroundColor Yellow
    Write-Host 'byte patterns of the malware it describes, and Microsoft Defender takes this package' -ForegroundColor Yellow
    Write-Host 'for the real thing. To work with these rules, exclude this single folder from it. The' -ForegroundColor Yellow
    Write-Host 'folder holds the downloaded package and the rule bundle built from it, nothing else.' -ForegroundColor Yellow
    Write-Host 'For Microsoft Defender, from a PowerShell window opened as administrator:' -ForegroundColor Yellow
    Write-Host ''
    Write-Host "  Add-MpPreference -ExclusionPath '$vendor'"
    Write-Host ''
    Write-Host 'Then try again. To undo the exclusion later:' -ForegroundColor Yellow
    Write-Host ''
    Write-Host "  Remove-MpPreference -ExclusionPath '$vendor'"
    Write-Host ''
    Write-Host 'With another antivirus, add the same folder to its exclusions instead.' -ForegroundColor Yellow
    Write-Host 'More in docs\RULES.md.' -ForegroundColor Yellow
}

$present = $false
try {
    $present = (Test-Path -LiteralPath $target) -and ((Get-Digest $target) -eq $pin['sha256'])
} catch {
    Write-Host "The package is there, but it cannot be read: $($_.Exception.Message)" -ForegroundColor Red
    Write-AntivirusAdvice
    exit 1
}
if ($present) {
    Write-Host "Already present: $target (YARA Forge $($pin['tag']))"
    Write-Output $target
    exit 0
}

$url = "https://github.com/YARAHQ/yara-forge/releases/download/$($pin['tag'])/$($pin['package'])"
$part = "$target.part"
Write-Host "Downloading $url"
try {
    # Older systems do not offer TLS 1.2 to Windows PowerShell by default.
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $url -OutFile $part -UseBasicParsing
} catch {
    $blocked = Test-AntivirusBlock $_.Exception
    Remove-Item -LiteralPath $part -Force -ErrorAction SilentlyContinue
    Write-Host "The download failed: $($_.Exception.Message)" -ForegroundColor Red
    if ($blocked) {
        Write-AntivirusAdvice
    }
    exit 1
}

# An antivirus that takes the package for malware removes or locks it the
# moment it is written. On a Windows 11 desktop, Microsoft Defender did.
if (-not (Test-Path -LiteralPath $part)) {
    Write-Host 'The download finished, but the file is gone.' -ForegroundColor Red
    Write-AntivirusAdvice
    exit 1
}
try {
    $actual = Get-Digest $part
} catch {
    Write-Host "The downloaded file cannot be read: $($_.Exception.Message)" -ForegroundColor Red
    Remove-Item -LiteralPath $part -Force -ErrorAction SilentlyContinue
    Write-AntivirusAdvice
    exit 1
}
if ($actual -ne $pin['sha256']) {
    Remove-Item -LiteralPath $part -Force -ErrorAction SilentlyContinue
    Write-Host 'The download does not match the pinned checksum.' -ForegroundColor Red
    Write-Host "  expected $($pin['sha256'])"
    Write-Host "  found    $actual"
    Write-Host 'The package for this tag has changed, or the download was damaged. Nothing was kept.'
    exit 1
}
Move-Item -LiteralPath $part -Destination $target -Force
Write-Host "Saved $target (YARA Forge $($pin['tag']), checksum verified)"
Write-Output $target
exit 0

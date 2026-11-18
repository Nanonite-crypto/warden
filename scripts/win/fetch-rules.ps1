<#
.SYNOPSIS
    Downloads the YARA Forge rule package that rules\yara-forge.pin names.

.DESCRIPTION
    Saves the package to rules\vendor\ and checks it against the SHA-256
    recorded in the pin file. Nothing is kept if the checksum does not match.
    Writes the path of the package to the output when it succeeds.

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

if ((Test-Path -LiteralPath $target) -and ((Get-Digest $target) -eq $pin['sha256'])) {
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
    Remove-Item -LiteralPath $part -Force -ErrorAction SilentlyContinue
    Write-Host "The download failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

$actual = Get-Digest $part
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

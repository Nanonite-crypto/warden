<#
.SYNOPSIS
    Phase 1 acceptance check for Warden on Windows.

.DESCRIPTION
    Builds the release binary, checks that the EICAR antivirus test file is
    detected, runs the test suite and measures scan throughput.

    What it touches:
    - It writes inside this repository only: target\ and testdata\.
    - Cargo and rustup do what they do on any first build: they download the
      Rust toolchain pinned in rust-toolchain.toml and the dependencies into
      your user profile.
    - The benchmark reads the folder it is pointed at and changes nothing.
    - It never changes a Windows or antivirus setting.

    Results are written to target\phase1\ so they can be read back later:
    summary.json, system.json, bench.json, eicar-scan.json and one log per
    step.

.PARAMETER BenchPath
    Folder to benchmark. Defaults to the Windows System32 folder.

.PARAMETER BenchRuns
    Number of timed benchmark runs. Defaults to 3.

.PARAMETER SkipTests
    Skip the test suite.

.PARAMETER SkipBench
    Skip the benchmark.

.PARAMETER RequireEicar
    Count "the antivirus got to the EICAR test file first" as a failure
    instead of an incomplete check. CI uses this.
#>
[CmdletBinding()]
param(
    [string]$BenchPath = (Join-Path $env:SystemRoot 'System32'),
    [int]$BenchRuns = 3,
    [switch]$SkipTests,
    [switch]$SkipBench,
    [switch]$RequireEicar
)

$ErrorActionPreference = 'Stop'

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $repo
$out = Join-Path $repo 'target\phase1'
$zone = Join-Path $repo 'testdata\eicar-zone'
New-Item -ItemType Directory -Force -Path $out, $zone | Out-Null
$warden = Join-Path $repo 'target\release\warden.exe'
$steps = [ordered]@{}

function Write-Heading([string]$Text) {
    Write-Host ''
    Write-Host "== $Text ==" -ForegroundColor Cyan
}

function Write-Utf8([string]$Path, [string]$Text) {
    [System.IO.File]::WriteAllText($Path, $Text, (New-Object System.Text.UTF8Encoding($false)))
}

# Runs a command line through cmd.exe, which merges the error stream of every
# command in it into the output stream before PowerShell sees any of it.
# (Windows PowerShell turns error-stream text from programs into errors of
# its own, and cargo writes its normal progress there.) Shows the output
# live, saves it as UTF-8 under target\phase1 and returns the exit code.
function Invoke-Logged([string]$Name, [string]$CommandLine) {
    $lines = New-Object 'System.Collections.Generic.List[string]'
    cmd /c "($CommandLine) 2>&1" | ForEach-Object {
        $line = [string]$_
        $lines.Add($line)
        Write-Host $line
    }
    $code = $LASTEXITCODE
    Write-Utf8 (Join-Path $out "$Name.log") ($lines -join "`n")
    return $code
}

# True when the file exists and can be read. A resident antivirus removes the
# EICAR test file, or refuses to let it be opened, within moments.
function Test-Readable([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        return $false
    }
    try {
        [void][System.IO.File]::ReadAllBytes($Path)
        return $true
    } catch {
        return $false
    }
}

function Get-SystemInfo {
    $info = [ordered]@{}
    try {
        $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
        $info.cpu = $cpu.Name.Trim()
        $info.cores = $cpu.NumberOfCores
        $info.logical_processors = $cpu.NumberOfLogicalProcessors
    } catch { }
    try {
        $os = Get-CimInstance Win32_OperatingSystem
        $info.os = $os.Caption.Trim()
        $info.os_version = $os.Version
        $info.memory_gb = [math]::Round($os.TotalVisibleMemorySize / 1MB, 1)
    } catch { }
    try {
        $letter = (Split-Path -Qualifier $BenchPath).TrimEnd(':')
        $disk = Get-Partition -DriveLetter $letter | Get-Disk
        $physical = Get-PhysicalDisk | Where-Object { $_.DeviceId -eq $disk.Number }
        $info.benchmark_disk = "$($disk.FriendlyName) ($($physical.MediaType), $($disk.BusType))"
    } catch { }
    try {
        $info.defender_realtime_protection = [bool](Get-MpComputerStatus).RealTimeProtectionEnabled
    } catch { }
    return $info
}

function Complete-Check {
    $values = @($steps.Values)
    if ($values -contains 'failed') {
        $overall = 'failed'
    } elseif ($values -contains 'blocked') {
        $overall = 'incomplete'
    } else {
        $overall = 'passed'
    }
    $commit = (cmd /c 'git rev-parse HEAD 2>nul')
    $summary = [ordered]@{
        schema      = 1
        finished_at = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        commit      = [string]$commit
        steps       = $steps
        overall     = $overall
    }
    Write-Utf8 (Join-Path $out 'summary.json') ($summary | ConvertTo-Json -Depth 5)

    Write-Heading 'Summary'
    foreach ($name in $steps.Keys) {
        $color = 'Green'
        if ($steps[$name] -eq 'failed') { $color = 'Red' }
        if ($steps[$name] -eq 'blocked' -or $steps[$name] -eq 'skipped') { $color = 'Yellow' }
        Write-Host ('  {0,-12} {1}' -f $name, $steps[$name]) -ForegroundColor $color
    }
    Write-Host ''
    Write-Host "PHASE 1 CHECK: $($overall.ToUpper())    (details in target\phase1)"
    if ($overall -eq 'failed') { exit 1 }
    exit 0
}

# --- 1. Toolchain ---------------------------------------------------------------
Write-Heading 'Toolchain'
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    Write-Host 'cargo was not found. Install Rust from https://rustup.rs and run this again.' -ForegroundColor Red
    $steps.toolchain = 'failed'
    Complete-Check
}
$toolchainCommand = 'rustc --version && cargo --version'
if (Get-Command rustup -ErrorAction SilentlyContinue) {
    # rust-toolchain.toml pins the compiler, and cargo would fetch it on its
    # own. Doing it here first keeps that download out of the build log. It
    # is a no-op when the toolchain is already installed.
    $manifest = Get-Content (Join-Path $repo 'rust-toolchain.toml') -Raw
    $channel = [regex]::Match($manifest, 'channel\s*=\s*"([^"]+)"').Groups[1].Value
    $toolchainCommand = "rustup toolchain install $channel --profile minimal --component clippy,rustfmt && $toolchainCommand"
}
if ((Invoke-Logged 'toolchain' $toolchainCommand) -ne 0) {
    $steps.toolchain = 'failed'
    Complete-Check
}
$steps.toolchain = 'passed'
Write-Utf8 (Join-Path $out 'system.json') ((Get-SystemInfo) | ConvertTo-Json -Depth 5)

# --- 2. Release build -------------------------------------------------------------
Write-Heading 'Release build (the first one downloads dependencies and takes a few minutes)'
if ((Invoke-Logged 'build' 'cargo build --release --locked') -ne 0) {
    $steps.build = 'failed'
    $log = Get-Content (Join-Path $out 'build.log') -Raw
    if ($log -match 'link\.exe|linker `link') {
        Write-Host ''
        Write-Host 'The Microsoft C++ linker is missing. Install the Visual Studio Build Tools with the' -ForegroundColor Yellow
        Write-Host '"Desktop development with C++" workload, for example:' -ForegroundColor Yellow
        Write-Host '  winget install Microsoft.VisualStudio.2022.BuildTools --override "--passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"' -ForegroundColor Yellow
    }
    Complete-Check
}
$steps.build = 'passed'

# --- 3. EICAR detection -------------------------------------------------------------
Write-Heading 'EICAR detection'
$eicar = Join-Path $zone 'eicar.com'
$eicarReport = Join-Path $out 'eicar-scan.json'
Remove-Item -LiteralPath $eicarReport -Force -ErrorAction SilentlyContinue
$detected = $false
$code = $null
$name = $null

& $warden eicar write $zone | Out-Null
# Give a resident antivirus a moment to react before deciding what happened.
Start-Sleep -Seconds 3
$eicarUsable = Test-Readable $eicar
if ($eicarUsable) {
    & $warden scan $zone --no-progress --report $eicarReport
    $code = $LASTEXITCODE
    try {
        $report = Get-Content -LiteralPath $eicarReport -Raw -Encoding UTF8 | ConvertFrom-Json
        $name = $report.detections[0].findings[0].name
    } catch { }
    $detected = ($code -eq 1 -and $name -eq 'EICAR-Test-File')
    if (-not $detected) {
        # The antivirus may have stepped in between the check and the scan.
        $eicarUsable = Test-Readable $eicar
    }
    Remove-Item -LiteralPath $eicar -Force -ErrorAction SilentlyContinue
}

if ($detected) {
    $steps.eicar = 'passed'
} elseif ($eicarUsable) {
    $steps.eicar = 'failed'
    Write-Host "Expected exit code 1 and EICAR-Test-File, got exit code $code and '$name'." -ForegroundColor Red
} else {
    if ($RequireEicar) {
        $steps.eicar = 'failed'
    } else {
        $steps.eicar = 'blocked'
    }
    Write-Host 'Your antivirus removed or locked the EICAR test file before Warden could scan it.' -ForegroundColor Yellow
    Write-Host 'That is the antivirus doing its job. To let this one check run, exclude this single' -ForegroundColor Yellow
    Write-Host 'folder from it. For Microsoft Defender, from a PowerShell window opened as' -ForegroundColor Yellow
    Write-Host 'administrator:' -ForegroundColor Yellow
    Write-Host ''
    Write-Host "  Add-MpPreference -ExclusionPath '$zone'"
    Write-Host ''
    Write-Host 'Then run this script again. To undo the exclusion later:' -ForegroundColor Yellow
    Write-Host ''
    Write-Host "  Remove-MpPreference -ExclusionPath '$zone'"
    Write-Host ''
    Write-Host 'With another antivirus, add the same folder to its exclusions instead.' -ForegroundColor Yellow
}

# --- 4. Test suite --------------------------------------------------------------------
if ($SkipTests) {
    $steps.tests = 'skipped'
} else {
    Write-Heading 'Test suite'
    if ($detected) {
        # The folder is usable, so the on-disk EICAR tests must run for real.
        $env:WARDEN_EICAR_DIR = $zone
        $env:WARDEN_REQUIRE_EICAR = '1'
    } else {
        # Without a usable folder the on-disk EICAR tests do not run on
        # Windows, so the test suite does not set off the antivirus.
        Remove-Item Env:WARDEN_EICAR_DIR -ErrorAction SilentlyContinue
        Remove-Item Env:WARDEN_REQUIRE_EICAR -ErrorAction SilentlyContinue
    }
    if ((Invoke-Logged 'test' 'cargo test --workspace --locked') -eq 0) {
        $steps.tests = 'passed'
    } else {
        $steps.tests = 'failed'
    }
}

# --- 5. Benchmark ------------------------------------------------------------------------
if ($SkipBench) {
    $steps.benchmark = 'skipped'
} else {
    Write-Heading "Benchmark: $BenchRuns runs over $BenchPath (read-only)"
    & $warden bench $BenchPath --runs $BenchRuns --label 'local machine' --output (Join-Path $out 'bench.json')
    if ($LASTEXITCODE -eq 0) {
        $steps.benchmark = 'passed'
    } else {
        $steps.benchmark = 'failed'
    }
}

Complete-Check

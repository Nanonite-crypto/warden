<#
.SYNOPSIS
    Acceptance check for Warden on Windows.

.DESCRIPTION
    Builds the release binary, checks that the EICAR antivirus test file is
    detected in each of its forms and that Warden can tell who signed two
    files of Windows, runs the test suite and measures scan throughput.
    With -Rules it also builds a rule bundle from YARA Forge,
    without the rules that rules\exclusions.toml names, and counts false
    positives over the benchmark folder.

    What it touches:
    - It writes its results and the test files inside this repository only:
      target\check\, testdata\ and, with -Rules, rules\vendor\ (the
      downloaded rule package and the rule bundle built from it).
    - Cargo and rustup do what they do on any first build: they download the
      Rust toolchain pinned in rust-toolchain.toml and the dependencies, and
      put the build output in cargo's target folder (target\ here, unless
      you have configured another one).
    - With -Rules, one download: the rule package named in
      rules\yara-forge.pin, checked against the SHA-256 recorded there.
    - The benchmark and the false-positive check read the folder they are
      pointed at and change nothing.
    - The check of signatures lets Windows ask over the network whether a
      certificate was revoked, as Windows does whenever it checks one.
    - It never changes a Windows or antivirus setting, and it never updates
      rustup.

    Results are written to target\check\ so they can be read back later:
    summary.json, system.json, bench.json, eicar-scan.json, trust.json,
    fp.json and one log per step.

.PARAMETER BenchPath
    Folder to benchmark and, with -Rules, to check for false positives.
    Defaults to the Windows System32 folder.

.PARAMETER BenchRuns
    Number of timed benchmark runs. Defaults to 3.

.PARAMETER SkipTests
    Skip the test suite.

.PARAMETER SkipBench
    Skip the benchmark.

.PARAMETER Rules
    Also fetch the pinned YARA Forge rule package, build a rule bundle from
    it, and scan BenchPath with it. Everything it flags there is counted as
    a false positive, because the folder is expected to be clean. The rules
    named in rules\exclusions.toml are left out of the bundle.

.PARAMETER AllRules
    With -Rules: build the bundle from every rule of the package and ignore
    rules\exclusions.toml. This is the "before" of a before-and-after
    comparison, and how a rule is shown to deserve its place on that list.

.PARAMETER RequireEicar
    Count "the antivirus got to the EICAR test files first" as a failure
    instead of an incomplete check. CI uses this.
#>
[CmdletBinding()]
param(
    [string]$BenchPath = (Join-Path $env:SystemRoot 'System32'),
    [int]$BenchRuns = 3,
    [switch]$SkipTests,
    [switch]$SkipBench,
    [switch]$Rules,
    [switch]$AllRules,
    [switch]$RequireEicar
)

$ErrorActionPreference = 'Stop'

# The programs started below write UTF-8. Read their output as such, so that
# paths with non-ASCII characters survive. The previous setting is restored
# when the script ends.
$previousOutputEncoding = $null
try {
    $previousOutputEncoding = [Console]::OutputEncoding
    [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
} catch { }

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $repo
$out = Join-Path $repo 'target\check'
$zone = Join-Path $repo 'testdata\eicar-zone'
New-Item -ItemType Directory -Force -Path $out, $zone | Out-Null
$steps = [ordered]@{}
$notes = [ordered]@{}

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
# live, saves it as UTF-8 under target\check and returns the exit code.
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
        # With administrator rights more of a system folder can be read, so
        # two benchmark runs only compare if this is the same for both.
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        $info.administrator_rights = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { }
    try {
        $info.defender_realtime_protection = [bool](Get-MpComputerStatus).RealTimeProtectionEnabled
    } catch { }
    try {
        # Other antivirus products that Windows knows about, by name.
        $products = Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct
        $info.antivirus_products = @($products | ForEach-Object { $_.displayName })
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
        schema      = 2
        finished_at = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        commit      = [string]$commit
        steps       = $steps
        notes       = $notes
        overall     = $overall
    }
    Write-Utf8 (Join-Path $out 'summary.json') ($summary | ConvertTo-Json -Depth 5)

    Write-Heading 'Summary'
    foreach ($name in $steps.Keys) {
        $color = 'Green'
        if ($steps[$name] -eq 'failed') { $color = 'Red' }
        if ($steps[$name] -eq 'blocked' -or $steps[$name] -eq 'skipped') { $color = 'Yellow' }
        $line = '  {0,-12} {1}' -f $name, $steps[$name]
        if ($notes.Contains($name)) {
            $line = "$line  ($($notes[$name]))"
        }
        Write-Host $line -ForegroundColor $color
    }
    Write-Host ''
    Write-Host "WARDEN CHECK: $($overall.ToUpper())    (details in target\check)"
    if ($previousOutputEncoding) {
        try { [Console]::OutputEncoding = $previousOutputEncoding } catch { }
    }
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
if (Get-Command rustup -ErrorAction SilentlyContinue) {
    # rust-toolchain.toml pins the compiler. Install it if it is missing, and
    # nothing else: without --no-self-update, rustup would also try to update
    # itself, which is not this script's business.
    $manifest = Get-Content (Join-Path $repo 'rust-toolchain.toml') -Raw
    $channel = [regex]::Match($manifest, 'channel\s*=\s*"([^"]+)"').Groups[1].Value
    $installed = @(cmd /c 'rustup toolchain list 2>nul') -match ('^' + [regex]::Escape($channel) + '-')
    if (-not $installed) {
        Invoke-Logged 'toolchain-install' "rustup toolchain install $channel --no-self-update --profile minimal" | Out-Null
    }
}
# Whatever happened above, the step passes if the pinned compiler runs.
if ((Invoke-Logged 'toolchain' 'rustc --version && cargo --version') -ne 0) {
    $steps.toolchain = 'failed'
    Complete-Check
}
$steps.toolchain = 'passed'
Write-Utf8 (Join-Path $out 'system.json') ((Get-SystemInfo) | ConvertTo-Json -Depth 5)

# The build output is not always in <repo>\target: CARGO_TARGET_DIR or a cargo
# configuration file can move it. Ask cargo where it is.
$targetDir = Join-Path $repo 'target'
try {
    $metadata = (cmd /c 'cargo metadata --format-version 1 --no-deps 2>nul') -join "`n" | ConvertFrom-Json
    if ($metadata.target_directory) {
        $targetDir = $metadata.target_directory
    }
} catch { }
$warden = Join-Path $targetDir 'release\warden.exe'

# --- 2. Release build -------------------------------------------------------------
Write-Heading 'Release build (the first one downloads dependencies and takes several minutes)'
if ((Invoke-Logged 'build' 'cargo build --release --locked') -ne 0) {
    $steps.build = 'failed'
    $log = Get-Content (Join-Path $out 'build.log') -Raw
    if ($log -match 'link\.exe|linker `link') {
        Write-Host ''
        Write-Host 'The Microsoft C++ linker is missing. Rust on Windows needs the Visual Studio Build' -ForegroundColor Yellow
        Write-Host 'Tools with the "Desktop development with C++" workload.' -ForegroundColor Yellow
        Write-Host ''
        Write-Host 'If the Build Tools are not installed yet, close the Visual Studio Installer window if' -ForegroundColor Yellow
        Write-Host 'one is open (with it open, the command below reports success and installs nothing), then:' -ForegroundColor Yellow
        Write-Host '  winget install --id Microsoft.VisualStudio.2022.BuildTools --source winget --override "--passive --wait --norestart --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"' -ForegroundColor Yellow
        Write-Host 'Without --norestart the installer restarts Windows by itself if it needs to.' -ForegroundColor Yellow
        Write-Host 'If they are installed without that workload: open "Visual Studio Installer" from the' -ForegroundColor Yellow
        Write-Host 'Start menu, choose Modify on the Build Tools, and tick "Desktop development with C++".' -ForegroundColor Yellow
        Write-Host ''
        Write-Host 'Then open a new terminal and run this script again.' -ForegroundColor Yellow
    }
    Complete-Check
}
if (-not (Test-Path -LiteralPath $warden)) {
    Write-Host "The build succeeded, but warden.exe is not at $warden." -ForegroundColor Red
    $steps.build = 'failed'
    Complete-Check
}
$steps.build = 'passed'

# --- 3. EICAR detection -------------------------------------------------------------
# Three forms of the same harmless test file, one for each thing that must
# work: the plain file is known by hash, the padded file has a different hash
# and is only caught by the YARA rule, and the zip holds the plain file as a
# member.
Write-Heading 'EICAR detection'
$forms = 'eicar.com', 'eicar-padded.com', 'eicar.zip'
$eicarReport = Join-Path $out 'eicar-scan.json'
Remove-Item -LiteralPath $eicarReport -Force -ErrorAction SilentlyContinue
$detected = $false
$problem = ''

function Test-FormsReadable {
    foreach ($form in $forms) {
        if (-not (Test-Readable (Join-Path $zone $form))) {
            return $false
        }
    }
    return $true
}

& $warden eicar write $zone --kind all | Out-Null
# Give a resident antivirus a moment to react before deciding what happened.
Start-Sleep -Seconds 3
$eicarUsable = Test-FormsReadable
if ($eicarUsable) {
    & $warden scan $zone --no-progress --report $eicarReport
    $code = $LASTEXITCODE
    try {
        $report = Get-Content -LiteralPath $eicarReport -Raw -Encoding UTF8 | ConvertFrom-Json
        $byFile = @{}
        foreach ($detection in @($report.detections)) {
            $byFile[[System.IO.Path]::GetFileName($detection.path)] = $detection
        }
        $plain = $byFile['eicar.com']
        $padded = $byFile['eicar-padded.com']
        $zipped = $byFile['eicar.zip']
        if ($code -ne 1) {
            $problem = "the scan ended with exit code $code instead of 1"
        } elseif (-not $plain -or -not $padded -or -not $zipped) {
            $problem = "only $(@($report.detections).Count) of the 3 forms were detected"
        } elseif (@($plain.findings | Where-Object { $_.detector -eq 'hash' }).Count -eq 0) {
            $problem = 'the plain file was not detected by its hash'
        } elseif (@($padded.findings | Where-Object { $_.detector -eq 'yara' }).Count -eq 0) {
            $problem = 'the padded file was not detected by the YARA rule'
        } elseif (-not $zipped.findings[0].member -or $zipped.findings[0].member.path[0] -ne 'eicar.com') {
            $problem = 'the finding for the zip does not name the member inside it'
        } else {
            $detected = $true
        }
    } catch {
        $problem = "the scan report could not be read ($($_.Exception.Message))"
    }
    if (-not $detected) {
        # The antivirus may have stepped in between the check and the scan.
        $eicarUsable = Test-FormsReadable
    }
}
foreach ($form in $forms) {
    Remove-Item -LiteralPath (Join-Path $zone $form) -Force -ErrorAction SilentlyContinue
}

if ($detected) {
    $steps.eicar = 'passed'
    $notes.eicar = 'by hash, by YARA rule and inside a zip'
} elseif ($eicarUsable) {
    $steps.eicar = 'failed'
    Write-Host "EICAR detection failed: $problem." -ForegroundColor Red
} else {
    if ($RequireEicar) {
        $steps.eicar = 'failed'
    } else {
        $steps.eicar = 'blocked'
    }
    Write-Host 'Your antivirus removed or locked the EICAR test files before Warden could scan them.' -ForegroundColor Yellow
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

# --- 4. Signatures ------------------------------------------------------------------
# Two files that every Windows has and that Windows signs in two different
# ways: one in the file, one in a catalogue. If Warden trusts both, it can
# read signatures on this machine, and Windows could find out that their
# certificates were not revoked.
Write-Heading 'Signatures'
$system32 = Join-Path $env:SystemRoot 'System32'
$signedFiles = @((Join-Path $system32 'ntdll.dll'), (Join-Path $system32 'whoami.exe'))
& $warden trust check @signedFiles
$trustJson = (& $warden trust check --json @signedFiles) -join "`n"
Write-Utf8 (Join-Path $out 'trust.json') $trustJson
try {
    $checked = @($trustJson | ConvertFrom-Json)
    $trusted = @($checked | Where-Object { $_.trust.answer -eq 'trusted' -and $_.trust.publisher -eq 'Microsoft Windows' })
    $offline = @($checked | Where-Object { $_.trust.reason -eq 'revocation_unknown' })
    if ($trusted.Count -eq $signedFiles.Count) {
        $steps.signatures = 'passed'
        $routes = @($trusted | ForEach-Object { $_.trust.route } | Sort-Object -Unique)
        $notes.signatures = "two files of Windows, found by: $($routes -join ', ')"
    } elseif ($offline.Count -gt 0) {
        # Not a fault of Warden's: the signatures are there, and what is
        # missing is the answer to whether a certificate was revoked.
        $steps.signatures = 'blocked'
        $notes.signatures = 'Windows could not find out whether a certificate was revoked; is this machine online?'
    } else {
        $steps.signatures = 'failed'
        Write-Host 'Warden does not trust two files that Windows itself signed. The lines above say why.' -ForegroundColor Red
    }
} catch {
    $steps.signatures = 'failed'
    Write-Host "The result of the signature check could not be read ($($_.Exception.Message))." -ForegroundColor Red
}

# --- 5. Test suite --------------------------------------------------------------------
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

# --- 6. Benchmark ------------------------------------------------------------------------
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

# --- 7. Rule bundle and false positives ------------------------------------------------------
if ($Rules) {
    Write-Heading 'Rule bundle from YARA Forge'
    # The bundle is kept next to the package it is built from. Microsoft
    # Defender blocks that package, so whoever works with rules excludes
    # that one folder, and the bundle is then covered as well.
    $bundle = Join-Path $repo 'rules\vendor\rules.wrb'
    $package = $null
    try {
        # The fetch script writes the path of the package as its last output.
        $package = @(& (Join-Path $PSScriptRoot 'fetch-rules.ps1'))[-1]
    } catch {
        Write-Host "Fetching the rule package failed: $($_.Exception.Message)" -ForegroundColor Red
    }
    if (-not $package -or -not (Test-Path -LiteralPath $package)) {
        $steps.rules = 'failed'
        Complete-Check
    }
    if ($AllRules) {
        $notes.rules = 'every rule of the package, exclusion list ignored'
        & $warden rules build $package --out $bundle
    } else {
        $notes.rules = 'without the rules named in rules\exclusions.toml'
        & $warden rules build $package --exclusions (Join-Path $repo 'rules\exclusions.toml') --out $bundle
    }
    if ($LASTEXITCODE -ne 0) {
        $steps.rules = 'failed'
        Complete-Check
    }
    $steps.rules = 'passed'

    Write-Heading "False positives: $BenchPath with the rule bundle and the heuristics (read-only)"
    $fpReport = Join-Path $out 'fp.json'
    Remove-Item -LiteralPath $fpReport -Force -ErrorAction SilentlyContinue
    & $warden false-positives $BenchPath --rules $bundle --label 'local machine' --no-progress --output $fpReport
    # Exit code 0 means nothing was flagged and 1 means something was. Both
    # are a completed measurement; only 2 is a failure of the check itself.
    if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq 1) {
        $steps.false_positives = 'passed'
        try {
            $fp = Get-Content -LiteralPath $fpReport -Raw -Encoding UTF8 | ConvertFrom-Json
            $flagged = $fp.flagged_malicious + $fp.flagged_suspicious
            $notes.false_positives = "$flagged of $($fp.files_scanned) files flagged"
            # Findings that did not count: the file kept its clean verdict.
            if ($fp.recorded_files -gt 0) {
                $notes.false_positives += ", $($fp.recorded_files) more with findings on record that did not count"
            }
        } catch { }
    } else {
        $steps.false_positives = 'failed'
    }
}

Complete-Check

<#
.SYNOPSIS
    Scans a freshly installed Windows with Warden and counts what it flags.

.DESCRIPTION
    Made for a virtual machine that has just been installed and has nothing
    else on it. Such a machine holds only what Microsoft shipped, so every
    file Warden flags there is a false positive.

    The script expects warden.exe and a rule bundle, rules.wrb, in the
    folder it is in. That folder can be read-only, a CD image for instance,
    which is the simplest way to bring files into a machine that has no
    network and no guest tools.

    What it does:
    - It writes down what the machine is: Windows edition and build, the
      updates and programs that are installed, whether the network is up,
      what the antivirus is doing.
    - It scans the whole system drive with all of Warden's layers.
    - It writes both results to C:\warden-out: machine.json and fp.json.
    - If the machine has a serial port, it sends both files out through it
      as text. A virtual machine can connect that port to a file on the
      host, and the results arrive there without a shared folder.

    It installs nothing, and it changes no Windows or antivirus setting.
    Run it as administrator, or the scan cannot read part of the drive.

.PARAMETER ScanPath
    What to scan. Defaults to the system drive.

.PARAMETER OutDir
    Where the results go. Defaults to warden-out on the system drive.

.PARAMETER SerialPort
    Serial port to send the results through. Defaults to COM1. An empty
    string turns this off.

.PARAMETER Label
    Free text stored with the scan result.
#>
[CmdletBinding()]
param(
    [string]$ScanPath = "$env:SystemDrive\",
    [string]$OutDir = (Join-Path "$env:SystemDrive\" 'warden-out'),
    [string]$SerialPort = 'COM1',
    [string]$Label = 'fresh Windows installation'
)

$ErrorActionPreference = 'Stop'

$kit = $PSScriptRoot
$warden = Join-Path $kit 'warden.exe'
$rules = Join-Path $kit 'rules.wrb'
$utf8 = New-Object System.Text.UTF8Encoding($false)

function Write-Utf8([string]$Path, [string]$Text) {
    [System.IO.File]::WriteAllText($Path, $Text, $utf8)
}

function Get-UtcNow {
    return [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
}

# --- The serial port ---------------------------------------------------------
# Everything sent is plain ASCII: marker lines that start with WARDEN-KIT, and
# files as base64 between a BEGIN and an END line that carry the file's name.
$script:port = $null

function Open-Serial {
    if (-not $SerialPort) {
        return
    }
    try {
        $p = New-Object System.IO.Ports.SerialPort $SerialPort, 115200, 'None', 8, 'One'
        $p.Handshake = 'None'
        $p.WriteTimeout = 30000
        $p.Open()
        $script:port = $p
    } catch {
        Write-Host "No serial port ${SerialPort}: the results stay in $OutDir only." -ForegroundColor Yellow
    }
}

function Send-Line([string]$Text) {
    if ($null -eq $script:port) {
        return
    }
    try {
        $script:port.Write($Text + "`r`n")
    } catch {
        Write-Host "Writing to $SerialPort failed: $($_.Exception.Message)" -ForegroundColor Yellow
        $script:port = $null
    }
}

function Send-File([string]$Path) {
    if ($null -eq $script:port) {
        return
    }
    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }
    $name = Split-Path -Leaf $Path
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $hash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    $text = [Convert]::ToBase64String($bytes)
    Send-Line "-----BEGIN WARDEN FILE $name sha256=$hash bytes=$($bytes.Length)-----"
    for ($i = 0; $i -lt $text.Length; $i += 76) {
        Send-Line $text.Substring($i, [Math]::Min(76, $text.Length - $i))
    }
    Send-Line "-----END WARDEN FILE $name-----"
}

function Close-Serial {
    if ($null -ne $script:port) {
        try { $script:port.Close() } catch { }
        $script:port = $null
    }
}

# --- What this machine is -----------------------------------------------------
function Get-MachineFacts {
    $info = [ordered]@{}
    $info.recorded_at = Get-UtcNow
    try {
        $os = Get-CimInstance Win32_OperatingSystem
        $info.os = $os.Caption.Trim()
        $info.os_version = $os.Version
        $info.installed_at = $os.InstallDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        $info.memory_gb = [math]::Round($os.TotalVisibleMemorySize / 1MB, 1)
    } catch { }
    try {
        $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        $info.os_display_version = $cv.DisplayVersion
        $info.os_edition = $cv.EditionID
        $info.os_build = "$($cv.CurrentBuild).$($cv.UBR)"
    } catch { }
    try {
        $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
        $info.cpu = $cpu.Name.Trim()
        $info.logical_processors = [int](Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors
    } catch { }
    try {
        $system = Get-CimInstance Win32_ComputerSystem
        $info.computer_model = "$($system.Manufacturer) $($system.Model)".Trim()
    } catch { }
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        $info.administrator_rights = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { }
    try {
        $status = Get-MpComputerStatus
        $info.defender_realtime_protection = [bool]$status.RealTimeProtectionEnabled
        $info.defender_signature_version = "$($status.AntivirusSignatureVersion)"
        $info.defender_product_version = "$($status.AMProductVersion)"
    } catch { }
    try {
        $up = @(Get-NetAdapter -Physical -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' })
        $info.network_adapters_up = $up.Count
    } catch { }
    try {
        $info.updates = @(Get-HotFix | Sort-Object HotFixID | ForEach-Object { $_.HotFixID })
    } catch { }
    try {
        $keys = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
        )
        $names = @(Get-ItemProperty $keys -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName } |
            ForEach-Object { "$($_.DisplayName) $($_.DisplayVersion)".Trim() } |
            Sort-Object -Unique)
        $info.installed_programs = $names
    } catch { }
    # Warden's own build may need this runtime library; a fresh Windows does
    # not have to have it.
    $info.has_vcruntime140 = Test-Path (Join-Path $env:SystemRoot 'System32\vcruntime140.dll')
    try {
        $info.warden_sha256 = (Get-FileHash -LiteralPath $warden -Algorithm SHA256).Hash.ToLowerInvariant()
        $info.rules_sha256 = (Get-FileHash -LiteralPath $rules -Algorithm SHA256).Hash.ToLowerInvariant()
    } catch { }
    return $info
}

# --- Run ------------------------------------------------------------------------
Write-Host ''
Write-Host '== Warden: scan of a fresh Windows installation ==' -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
Open-Serial
Send-Line "WARDEN-KIT START $(Get-UtcNow)"

$facts = Get-MachineFacts
$machineReport = Join-Path $OutDir 'machine.json'
Write-Utf8 $machineReport ($facts | ConvertTo-Json -Depth 5)
Send-File $machineReport
Write-Host "Machine: $($facts.os) $($facts.os_display_version), build $($facts.os_build)"
if (-not $facts.administrator_rights) {
    Write-Host 'Not running as administrator: part of the drive cannot be read.' -ForegroundColor Yellow
}

$failure = $null
if (-not (Test-Path -LiteralPath $warden)) {
    $failure = "warden.exe is not in $kit"
} elseif (-not (Test-Path -LiteralPath $rules)) {
    $failure = "rules.wrb is not in $kit"
}

if (-not $failure) {
    # Does the program start at all? On a machine without the Visual C++
    # runtime a build that needs it ends here, with nothing on the screen.
    $version = cmd /c "(`"$warden`" --version) 2>&1"
    if ($LASTEXITCODE -ne 0) {
        $failure = "warden.exe does not start here (exit code $LASTEXITCODE): $version"
    } else {
        Write-Host "Scanner: $version"
        Send-Line "WARDEN-KIT VERSION $version"
    }
}

$fpReport = Join-Path $OutDir 'fp.json'
if (-not $failure) {
    Remove-Item -LiteralPath $fpReport -Force -ErrorAction SilentlyContinue
    Write-Host ''
    Write-Host "Scanning $ScanPath with every layer. Nothing is changed." -ForegroundColor Cyan
    Send-Line "WARDEN-KIT SCAN-START $(Get-UtcNow)"
    & $warden false-positives $ScanPath --rules $rules --label $Label --output $fpReport
    $code = $LASTEXITCODE
    Send-Line "WARDEN-KIT SCAN-END $(Get-UtcNow) exit=$code"
    # 0: nothing flagged. 1: something flagged. Both are a finished scan.
    if (($code -ne 0 -and $code -ne 1) -or -not (Test-Path -LiteralPath $fpReport)) {
        # Run it once more over a single file, to catch what it says. (cmd.exe
        # merges the error stream into the output before PowerShell sees it.)
        $said = cmd /c "(`"$warden`" false-positives `"$warden`" --rules `"$rules`" --no-progress) 2>&1"
        $errorLog = Join-Path $OutDir 'scan-error.log'
        Write-Utf8 $errorLog (($said | ForEach-Object { [string]$_ }) -join "`n")
        Send-File $errorLog
        $failure = "the scan did not finish (exit code $code); see $errorLog"
    }
}

Write-Host ''
if ($failure) {
    Send-Line "WARDEN-KIT FAILED $failure"
    Write-Host "FAILED: $failure" -ForegroundColor Red
    Close-Serial
    exit 2
}

Send-File $fpReport
$fp = Get-Content -LiteralPath $fpReport -Raw -Encoding UTF8 | ConvertFrom-Json
$flagged = $fp.flagged_malicious + $fp.flagged_suspicious
Send-Line "WARDEN-KIT DONE $(Get-UtcNow) flagged=$flagged files=$($fp.files_scanned)"
Close-Serial
Write-Host "DONE: $flagged of $($fp.files_scanned) files flagged." -ForegroundColor Green
Write-Host "Results: $OutDir"
exit 0

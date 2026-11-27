<#
.SYNOPSIS
    Shows on a real Windows that Warden removes what starts a quarantined
    file, and puts it back when the file is restored.

.DESCRIPTION
    Made for a virtual machine that was installed for the purpose. The
    script takes three runs with a restart of Windows between them, and
    remembers in C:\warden-test where it is.

    It works with warden-dummy.exe, a harmless program that adds one line
    to a file next to itself when it is started and then ends. The script
    expects it and warden.exe in the folder it is in. That folder can be
    read-only, a CD image for instance.

    Run 1:
    - It times a look at everything that Windows starts on the machine,
      before it adds anything, and writes down the times and how many
      entries of each kind there are.
    - It copies the dummy to C:\warden-test\dummy and registers it in the
      places Windows starts programs from, with Windows' own tools: three
      Run values, a task at logon, a task at boot, a service, and a
      shortcut in the Startup folder. Each entry passes the dummy a word
      of its own.
    - It writes down what Windows' tools show of each entry.
    - It makes a signature database that names the dummy, and lets Warden
      scan the folder. The scan has to report the dummy.
    - It asks Warden what starts the dummy, and lets Warden quarantine it.
    - It checks that Windows' tools no longer show any of the entries.
    Then Windows is restarted by hand.

    Run 2:
    - It checks that the dummy was not started and that nothing brought
      an entry back.
    - It lets Warden restore the dummy, and checks that Windows' tools
      show every entry as they showed it before.
    Then Windows is restarted by hand.

    Run 3:
    - It reads the file the dummy writes: there has to be a line for each
      entry, with that entry's word.
    - If autostart-tests.exe is in its folder, the automated tests of the
      Windows side built as a program, it runs them here, and then removes
      with Windows' tools whatever they may have left.
    - It removes the entries with Windows' tools, and the folder.
    - It writes the result to C:\warden-out\autostart-remedy.json, and
      sends it out through the serial port if the machine has one.

    With -Reset the script removes everything it may have left behind,
    in whatever run it stopped, and whatever the automated tests may have
    left, and does nothing else.

    With -Only the script does one part of run 1 and nothing else. That
    is for restart-study.ps1, which asks what it is about run 1 that a
    restart of Windows may stumble over.

    It registers a service and two tasks, and writes to the Run keys.
    Never run it on a machine that is in use. It changes no antivirus
    setting. Run it as administrator.

.PARAMETER OutDir
    Where the results go. Defaults to warden-out on the system drive.

.PARAMETER SerialPort
    Serial port to send the results through. Defaults to COM1. An empty
    string or the word none turns this off.

.PARAMETER Reset
    Remove what an earlier run left behind, and stop.

.PARAMETER Only
    Look: time the look at what the machine starts, as run 1 does, and add
    nothing to the machine. Entries: make the seven entries with Windows'
    own tools, write down what Windows shows of them, and remove them
    again with Windows' own tools, without starting Warden once. Either
    way the script keeps no place and writes no result of the three runs.

.PARAMETER BootDriverTest
    Let the automated tests include the one that registers a driver with
    the start "boot". Without this switch that test is left out: for a
    second or two it leaves the machine with a driver that is none, to be
    loaded at the next start, and a machine that is kept should not be one
    power cut away from not starting. CI gives the switch on its runner,
    which is deleted after the job.
#>
[CmdletBinding()]
param(
    [string]$OutDir = (Join-Path "$env:SystemDrive\" 'warden-out'),
    [string]$SerialPort = 'COM1',
    [switch]$Reset,
    [ValidateSet('', 'Look', 'Entries')]
    [string]$Only = '',
    [switch]$BootDriverTest
)

$ErrorActionPreference = 'Stop'

$kit = $PSScriptRoot
$warden = Join-Path $kit 'warden.exe'
$dummySource = Join-Path $kit 'warden-dummy.exe'
$tests = Join-Path $kit 'autostart-tests.exe'
$utf8 = New-Object System.Text.UTF8Encoding($false)

# Everything the script makes is below this folder. No blank is in any of
# these paths and names, so that none of them needs quotes inside quotes.
$work = Join-Path "$env:SystemDrive\" 'warden-test'
$dummyDir = Join-Path $work 'dummy'
$dummy = Join-Path $dummyDir 'warden-dummy.exe'
$dummyLog = Join-Path $dummyDir 'warden-dummy-starts.log'
$store = Join-Path $work 'quarantine'
$sigdb = Join-Path $work 'dummy.wdb'
$stageFile = Join-Path $work 'stage.txt'
$entryFile = Join-Path $work 'entry.txt'
$beforeFile = Join-Path $work 'views-before.json'

$runKey = 'Software\Microsoft\Windows\CurrentVersion\Run'
$userValue = 'WardenTestDummy'
$machineValue = 'WardenTestDummyForAll'
$oldViewValue = 'WardenTestDummy32'
$taskFolder = 'WardenTest'
$logonTask = '\WardenTest\DummyAtLogon'
$bootTask = '\WardenTest\DummyAtBoot'
$service = 'WardenTestDummy'
$shortcutName = 'WardenTestDummy.lnk'

# What the automated tests make on a real Windows, by the names they give
# it in crates/warden-autostart/tests: scene/mod.rs and on_windows.rs. The
# tests remove all of it themselves. This script removes it once more with
# Windows' own tools after the tests ran, in case the test program died
# half way. A test of that crate checks that every name is known here.
$testRunValue = 'WardenTestThreat'
$testMachineValue = 'WardenTestThreatForAll'
$testOldViewValue = 'WardenTestThreat32'
$testTaskFolder = 'Warden Test'
$testLogonTask = '\Warden Test\Threat at logon'
$testBootTask = '\Warden Test\Threat at boot'
$testService = 'WardenTestThreat'
$testShortcut = 'WardenTestThreat.lnk'
$testBootDriver = 'WardenTestBootDriver'
$testOtherDriver = 'WardenTestDriverElsewhere'
$testDriverFile = Join-Path $env:SystemRoot 'System32\drivers\wardentest.sys'
# The test that registers the driver with the start "boot".
$bootDriverTestName = 'a_driver_that_windows_loads_while_it_starts_is_known_and_goes_and_comes_back'

# The word each entry passes to the dummy, by a name for the entry.
$words = [ordered]@{
    'the Run value of the user'               = '--from-run'
    'the Run value of the machine'            = '--from-run-for-all'
    'the Run value in the 32-bit view'        = '--from-run-32'
    'the task at logon'                       = '--from-logon-task'
    'the task at boot'                        = '--from-boot-task'
    'the service'                             = '--service'
    'the shortcut in the Startup folder'      = '--from-shortcut'
}

function Write-Utf8([string]$Path, [string]$Text) {
    [System.IO.File]::WriteAllText($Path, $Text, $utf8)
}

function Get-UtcNow {
    return [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
}

# --- The serial port ---------------------------------------------------------
# As in fresh-install-scan.ps1: marker lines that start with WARDEN-KIT, and
# files as base64 between a BEGIN and an END line.
$script:port = $null

function Open-Serial {
    if ((-not $SerialPort) -or ($SerialPort -eq 'none')) {
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

# --- Windows' own tools ---------------------------------------------------------
# A tool is run through cmd.exe, which merges what it prints as an error into
# its output before PowerShell sees it. Returns the text, and leaves the exit
# code in $LASTEXITCODE.
function Invoke-Tool([string]$CommandLine) {
    $said = cmd /c "($CommandLine) 2>&1"
    return ((@($said) | ForEach-Object { [string]$_ }) -join "`n").Trim()
}

# Runs a tool that has to succeed.
function Invoke-Must([string]$CommandLine) {
    $said = Invoke-Tool $CommandLine
    if ($LASTEXITCODE -ne 0) {
        throw "$CommandLine failed (exit code $LASTEXITCODE): $said"
    }
    return $said
}

# What a tool shows, or nothing if the tool says the thing is not there.
function Get-Shown([string]$CommandLine) {
    $said = Invoke-Tool $CommandLine
    if ($LASTEXITCODE -ne 0) {
        return $null
    }
    return $said
}

function Get-StartupFolder {
    return [Environment]::GetFolderPath('Startup')
}

function Get-ShortcutPath {
    return (Join-Path (Get-StartupFolder) $shortcutName)
}

# Who may do what with a task. No tool that comes with Windows prints it, so
# the Task Scheduler is asked through its interface for scripts.
function Get-TaskRights([string]$TaskPath) {
    try {
        $scheduler = New-Object -ComObject Schedule.Service
        $scheduler.Connect()
        return [string]$scheduler.GetFolder('\').GetTask($TaskPath).GetSecurityDescriptor(7)
    } catch {
        return $null
    }
}

# What Windows' tools show of each entry, by a name for the view. An entry
# that is not there shows as nothing.
function Get-Views {
    $views = [ordered]@{}
    $views['the Run value of the user'] = Get-Shown "reg query HKCU\$runKey /v $userValue"
    $views['the Run value of the machine'] = Get-Shown "reg query HKLM\$runKey /v $machineValue"
    $views['the Run value in the 32-bit view'] = Get-Shown "reg query HKLM\$runKey /v $oldViewValue /reg:32"
    $views['the definition of the task at logon'] = Get-Shown "schtasks /query /tn $logonTask /xml"
    $views['who may do what with the task at logon'] = Get-TaskRights $logonTask
    $views['the definition of the task at boot'] = Get-Shown "schtasks /query /tn $bootTask /xml"
    $views['who may do what with the task at boot'] = Get-TaskRights $bootTask
    $views['the settings of the service'] = Get-Shown "sc.exe qc $service"
    $views['the description of the service'] = Get-Shown "sc.exe qdescription $service"
    $views['what happens when the service fails'] = Get-Shown "sc.exe qfailure $service"
    $views['the identity of the service'] = Get-Shown "sc.exe qsidtype $service"
    $views['who may do what with the service'] = Get-Shown "sc.exe sdshow $service"
    # A key lists its values in the order they were made in, which means
    # nothing to Windows. The lines are put in order, so that only what the
    # key holds is compared.
    $key = Get-Shown "reg query HKLM\SYSTEM\CurrentControlSet\Services\$service /s"
    if ($null -ne $key) {
        $lines = @($key -split "`n" | ForEach-Object { $_.TrimEnd() } | Where-Object { $_ -ne '' } | Sort-Object)
        $key = $lines -join "`n"
    }
    $views['the key of the service in the registry, its lines in order'] = $key
    $shortcut = Get-ShortcutPath
    if (Test-Path -LiteralPath $shortcut) {
        $views['the shortcut, by its SHA-256'] = (Get-FileHash -LiteralPath $shortcut -Algorithm SHA256).Hash.ToLowerInvariant()
    } else {
        $views['the shortcut, by its SHA-256'] = $null
    }
    return $views
}

# The names of the views that show something.
function Get-Present($Views) {
    $present = @()
    foreach ($name in $Views.Keys) {
        if ($null -ne $Views[$name]) {
            $present += $name
        }
    }
    return ,$present
}

# Removes every entry the script makes, with Windows' tools, there or not.
function Remove-Entries {
    $null = Invoke-Tool "reg delete HKCU\$runKey /v $userValue /f"
    $null = Invoke-Tool "reg delete HKLM\$runKey /v $machineValue /f"
    $null = Invoke-Tool "reg delete HKLM\$runKey /v $oldViewValue /f /reg:32"
    $null = Invoke-Tool "schtasks /delete /tn $logonTask /f"
    $null = Invoke-Tool "schtasks /delete /tn $bootTask /f"
    $null = Invoke-Tool "sc.exe delete $service"
    try {
        $scheduler = New-Object -ComObject Schedule.Service
        $scheduler.Connect()
        $scheduler.GetFolder('\').DeleteFolder($taskFolder, 0)
    } catch { }
    $shortcut = Get-ShortcutPath
    if (Test-Path -LiteralPath $shortcut) {
        Remove-Item -LiteralPath $shortcut -Force
    }
}

function Remove-Everything {
    Remove-Entries
    if (Test-Path -LiteralPath $work) {
        Remove-Item -LiteralPath $work -Recurse -Force
    }
}

# Removes what the automated tests make, with Windows' tools, there or not.
function Remove-TestLeftovers {
    $null = Invoke-Tool "reg delete HKCU\$runKey /v $testRunValue /f"
    $null = Invoke-Tool "reg delete HKLM\$runKey /v $testMachineValue /f"
    $null = Invoke-Tool "reg delete HKLM\$runKey /v $testOldViewValue /f /reg:32"
    $null = Invoke-Tool "schtasks /delete /tn `"$testLogonTask`" /f"
    $null = Invoke-Tool "schtasks /delete /tn `"$testBootTask`" /f"
    $null = Invoke-Tool "sc.exe delete $testService"
    $null = Invoke-Tool "sc.exe delete $testBootDriver"
    $null = Invoke-Tool "sc.exe delete $testOtherDriver"
    try {
        $scheduler = New-Object -ComObject Schedule.Service
        $scheduler.Connect()
        $scheduler.GetFolder('\').DeleteFolder($testTaskFolder, 0)
    } catch { }
    foreach ($file in @((Join-Path (Get-StartupFolder) $testShortcut), $testDriverFile)) {
        if (Test-Path -LiteralPath $file) {
            Remove-Item -LiteralPath $file -Force
        }
    }
}

# What is left of the automated tests, by a name for each thing. Nothing,
# if all is as it should be.
function Get-TestLeftovers {
    $left = @()
    if ($null -ne (Get-Shown "reg query HKCU\$runKey /v $testRunValue")) { $left += 'the Run value of the user' }
    if ($null -ne (Get-Shown "reg query HKLM\$runKey /v $testMachineValue")) { $left += 'the Run value of the machine' }
    if ($null -ne (Get-Shown "reg query HKLM\$runKey /v $testOldViewValue /reg:32")) { $left += 'the Run value in the 32-bit view' }
    if ($null -ne (Get-Shown "schtasks /query /tn `"$testLogonTask`"")) { $left += 'the task at logon' }
    if ($null -ne (Get-Shown "schtasks /query /tn `"$testBootTask`"")) { $left += 'the task at boot' }
    if ($null -ne (Get-Shown "sc.exe qc $testService")) { $left += 'the service' }
    if ($null -ne (Get-Shown "sc.exe qc $testBootDriver")) { $left += 'the driver with the start boot' }
    if ($null -ne (Get-Shown "sc.exe qc $testOtherDriver")) { $left += 'the other driver' }
    if (Test-Path -LiteralPath (Join-Path (Get-StartupFolder) $testShortcut)) { $left += 'the shortcut' }
    if (Test-Path -LiteralPath $testDriverFile) { $left += 'the file in the drivers folder' }
    return ,$left
}

# --- The result -----------------------------------------------------------------
$resultFile = Join-Path $OutDir 'autostart-remedy.json'

function Read-Result {
    if (Test-Path -LiteralPath $resultFile) {
        return (Get-Content -LiteralPath $resultFile -Raw -Encoding UTF8 | ConvertFrom-Json)
    }
    return $null
}

# The checks of all runs so far, each a name, whether it held, and a word
# about it. Kept in a file between the runs.
$script:checks = @()

function Add-Check([string]$Name, [bool]$Held, [string]$Detail) {
    $script:checks += [ordered]@{ check = $Name; held = $Held; detail = $Detail }
    if ($Held) {
        Write-Host "  ok      $Name" -ForegroundColor Green
    } else {
        Write-Host "  WRONG   $Name" -ForegroundColor Red
        if ($Detail) {
            Write-Host "          $Detail" -ForegroundColor Red
        }
    }
    $state = if ($Held) { 'ok' } else { 'wrong' }
    Send-Line "WARDEN-KIT CHECK $state $Name"
}

function Save-Result([int]$Run, [bool]$Finished) {
    $failed = @($script:checks | Where-Object { -not $_.held }).Count
    $result = [ordered]@{
        recorded_at = Get-UtcNow
        run = $Run
        finished = $Finished
        checks = $script:checks
        failed = $failed
        machine = $script:machine
    }
    Write-Utf8 $resultFile ($result | ConvertTo-Json -Depth 6)
}

function Get-MachineFacts {
    $info = [ordered]@{}
    try {
        $os = Get-CimInstance Win32_OperatingSystem
        $info.os = $os.Caption.Trim()
        $info.os_version = $os.Version
    } catch { }
    try {
        $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        $info.os_display_version = $cv.DisplayVersion
        $info.os_build = "$($cv.CurrentBuild).$($cv.UBR)"
    } catch { }
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        $info.administrator_rights = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { }
    try {
        $status = Get-MpComputerStatus
        $info.defender_realtime_protection = [bool]$status.RealTimeProtectionEnabled
    } catch { }
    try {
        $info.warden_sha256 = (Get-FileHash -LiteralPath $warden -Algorithm SHA256).Hash.ToLowerInvariant()
        $info.dummy_sha256 = (Get-FileHash -LiteralPath $dummySource -Algorithm SHA256).Hash.ToLowerInvariant()
    } catch { }
    return $info
}

# Runs warden.exe with a command line, through cmd.exe as above. Returns what
# it said and leaves its exit code in $LASTEXITCODE.
function Invoke-Warden([string]$Arguments) {
    return (Invoke-Tool "`"$warden`" $Arguments")
}

# The number that `warden autostart list` prints after one of its headings.
function Get-ListedCount([string]$Listing, [string]$Heading) {
    $found = [regex]::Match($Listing, '(?m)^' + [regex]::Escape($Heading) + ': ([0-9,]+)')
    if (-not $found.Success) {
        throw "warden autostart list has no line for: $Heading"
    }
    return [int]($found.Groups[1].Value -replace ',', '')
}

# How long a look at everything that Windows starts on this machine takes,
# and how many such entries there are, before the test adds its own. Five
# looks are timed with their output thrown away; one more is counted. Only
# numbers are written down, as on every machine. Returns a line about it.
function Save-Look {
    $looks = @()
    foreach ($look in 1..5) {
        $watch = [System.Diagnostics.Stopwatch]::StartNew()
        $null = Invoke-Warden 'autostart list --json >nul'
        $watch.Stop()
        if ($LASTEXITCODE -ne 0) {
            throw "warden autostart list --json ended with exit code $LASTEXITCODE"
        }
        $looks += [int]$watch.ElapsedMilliseconds
    }
    $listing = Invoke-Warden 'autostart list'
    if ($LASTEXITCODE -ne 0) {
        throw "warden autostart list ended with exit code $LASTEXITCODE"
    }
    $runValues = Get-ListedCount $listing 'Run and RunOnce values'
    $tasks = Get-ListedCount $listing 'Scheduled tasks'
    $services = Get-ListedCount $listing 'Services and drivers'
    $shortcuts = Get-ListedCount $listing 'Shortcuts in the Startup folders'
    # What could not be looked at is listed last, a line for each.
    $problems = 0
    $tail = $listing.IndexOf('Not everything could be looked at:')
    if ($tail -ge 0) {
        $problems = [regex]::Matches($listing.Substring($tail), '(?m)^  - ').Count
    }
    $result = [ordered]@{
        label                = 'the machine of the kit, release build: the whole program each time, started through cmd.exe, its output thrown away'
        milliseconds         = $looks
        run_values           = $runValues
        tasks                = $tasks
        services_and_drivers = $services
        shortcuts            = $shortcuts
        problems             = $problems
    }
    Write-Utf8 (Join-Path $OutDir 'autostart-look.json') ($result | ConvertTo-Json -Depth 5)
    $entries = $runValues + $tasks + $services + $shortcuts
    return "$entries entries, five looks: $($looks -join ', ') ms"
}

# Puts the dummy into its folder and registers it in seven places, with
# Windows' own tools.
function New-Entries {
    New-Item -ItemType Directory -Force -Path $dummyDir | Out-Null
    Copy-Item -LiteralPath $dummySource -Destination $dummy -Force

    $null = Invoke-Must "reg add HKCU\$runKey /v $userValue /t REG_SZ /d `"$dummy --from-run`" /f"
    $null = Invoke-Must "reg add HKLM\$runKey /v $machineValue /t REG_SZ /d `"$dummy --from-run-for-all`" /f"
    $null = Invoke-Must "reg add HKLM\$runKey /v $oldViewValue /t REG_SZ /d `"$dummy --from-run-32`" /f /reg:32"
    $null = Invoke-Must "schtasks /create /tn $logonTask /tr `"$dummy --from-logon-task`" /sc onlogon /f"
    $null = Invoke-Must "schtasks /create /tn $bootTask /tr `"$dummy --from-boot-task`" /sc onstart /ru SYSTEM /f"
    $null = Invoke-Must "sc.exe create $service binPath= `"$dummy --service`" start= auto DisplayName= WardenTestDummy"
    $null = Invoke-Must "sc.exe description $service WardenTestDummy"
    $null = Invoke-Must "sc.exe sidtype $service unrestricted"
    New-Item -ItemType Directory -Force -Path (Get-StartupFolder) | Out-Null
    $link = (New-Object -ComObject WScript.Shell).CreateShortcut((Get-ShortcutPath))
    $link.TargetPath = $dummy
    $link.Arguments = '--from-shortcut'
    $link.Save()
}

# --- A part of run 1 by itself, for the restart study ----------------------------
# The look, timed as run 1 times it. Nothing is added to the machine.
function Invoke-OnlyLook {
    Write-Host 'Only the look: what the machine starts is read, and nothing is added.' -ForegroundColor Cyan
    $looked = Save-Look
    Write-Host "  $looked"
    Send-Line "WARDEN-KIT ONLY look: $looked"
}

# The seven entries, made and removed with Windows' own tools. Warden is
# not started. Fails if an entry does not show after it was made, or still
# shows after it was removed.
function Invoke-OnlyEntries {
    Write-Host 'Only the entries: made and removed with the tools of Windows, without Warden.' -ForegroundColor Cyan
    Remove-Everything
    New-Entries
    $made = Get-Views
    $present = Get-Present $made
    Remove-Everything
    $left = Get-Present (Get-Views)
    $said = "$($present.Count) of $($made.Count) views showed something, $($left.Count) show something now"
    Write-Host "  $said"
    Send-Line "WARDEN-KIT ONLY entries: $said"
    if (($present.Count -ne $made.Count) -or ($left.Count -ne 0)) {
        throw "the entries were not made and removed as they should be: $said"
    }
}

# --- Run 1: plant, scan, quarantine -------------------------------------------
function Invoke-FirstRun {
    Write-Host 'Run 1 of 3: the dummy is registered, found by a scan and quarantined.' -ForegroundColor Cyan
    Remove-Everything

    # The machine as it is, before anything is added to it.
    $looked = ''
    try {
        $looked = Save-Look
        Add-Check 'Warden could look at everything that this machine starts' $true $looked
        Write-Host "          $looked"
    } catch {
        Add-Check 'Warden could look at everything that this machine starts' $false "$($_.Exception.Message)"
    }

    New-Entries

    $before = Get-Views
    Write-Utf8 $beforeFile ($before | ConvertTo-Json -Depth 3)
    $present = Get-Present $before
    Add-Check 'Windows shows every entry after it was made' ($present.Count -eq $before.Count) "$($present.Count) of $($before.Count) views show something"

    # A signature database that names the dummy, and a scan that reports it.
    $hash = (Get-FileHash -LiteralPath $dummy -Algorithm SHA256).Hash.ToLowerInvariant()
    $hashes = Join-Path $work 'dummy-hash.txt'
    Write-Utf8 $hashes "$hash`n"
    $null = Invoke-Warden "sigdb build --hashes `"$hashes`" --name Test.WardenDummy --out `"$sigdb`""
    Add-Check 'a signature database that names the dummy was built' ($LASTEXITCODE -eq 0) "exit code $LASTEXITCODE"
    $report = Join-Path $OutDir 'autostart-scan.json'
    $said = Invoke-Warden "scan `"$dummyDir`" --sigdb `"$sigdb`" --no-progress --report `"$report`""
    $scanCode = $LASTEXITCODE
    Write-Utf8 (Join-Path $OutDir 'autostart-scan.txt') $said
    Add-Check 'the scan reports the dummy' (($scanCode -eq 1) -and ($said -match 'Test\.WardenDummy')) "exit code $scanCode"

    # What starts it, as Warden sees it. Looking changes nothing.
    $found = Invoke-Warden "autostart find `"$dummy`""
    Write-Utf8 (Join-Path $OutDir 'autostart-find.txt') $found
    Add-Check 'Warden finds seven entries that start the dummy' ($found -match 'is started by 7 entries') ''

    # Into the quarantine, with what starts it.
    $added = Invoke-Warden "quarantine add `"$dummy`" --dir `"$store`""
    $addCode = $LASTEXITCODE
    Write-Utf8 (Join-Path $OutDir 'autostart-quarantine.txt') $added
    $removed = @($added -split "`n" | Where-Object { $_ -match '^\s+removed\s' }).Count
    $left = @($added -split "`n" | Where-Object { $_ -match '^\s+left\s' }).Count
    Add-Check 'the dummy went into the quarantine' (($addCode -eq 0) -and -not (Test-Path -LiteralPath $dummy)) "exit code $addCode"
    Add-Check 'Warden removed seven entries and left none' (($removed -eq 7) -and ($left -eq 0)) "$removed removed, $left left"
    $id = ''
    foreach ($line in ($added -split "`n")) {
        if ($line -match '^\s*entry\s+(\S+)') {
            $id = $Matches[1]
        }
    }
    Write-Utf8 $entryFile $id
    Add-Check 'the quarantine named the entry' ($id -ne '') ''

    $gone = Get-Present (Get-Views)
    Add-Check 'Windows shows none of the entries any more' ($gone.Count -eq 0) ($gone -join '; ')

    Write-Utf8 $stageFile '2'
    Save-Result 1 $false
    Write-Host ''
    Write-Host 'Now restart Windows, log on, wait a minute, and run this script again.' -ForegroundColor Cyan
}

# --- Run 2: nothing started; restore ---------------------------------------------
function Invoke-SecondRun {
    Write-Host 'Run 2 of 3: after a restart nothing may have started; then the dummy is restored.' -ForegroundColor Cyan
    Add-Check 'the dummy was not started while it was quarantined' (-not (Test-Path -LiteralPath $dummyLog)) ''
    $back = Get-Present (Get-Views)
    Add-Check 'no entry came back by itself over the restart' ($back.Count -eq 0) ($back -join '; ')

    $id = (Get-Content -LiteralPath $entryFile -Raw -Encoding UTF8).Trim()
    $restored = Invoke-Warden "quarantine restore $id --dir `"$store`""
    $code = $LASTEXITCODE
    Write-Utf8 (Join-Path $OutDir 'autostart-restore.txt') $restored
    Add-Check 'the dummy is back at its place' (($code -eq 0) -and (Test-Path -LiteralPath $dummy)) "exit code $code"
    Add-Check 'Warden put every entry back without a reservation' (-not ($restored -match 'Not put back|not in every detail|could not be|from the next start')) ''

    # Every view as it was before, to the letter.
    $before = Get-Content -LiteralPath $beforeFile -Raw -Encoding UTF8 | ConvertFrom-Json
    $now = Get-Views
    Write-Utf8 (Join-Path $work 'views-after.json') ($now | ConvertTo-Json -Depth 3)
    $different = @()
    foreach ($name in $now.Keys) {
        $then = $before.$name
        if ([string]$then -cne [string]$now[$name]) {
            $different += $name
        }
    }
    Add-Check 'Windows shows every entry as it showed it before' ($different.Count -eq 0) ($different -join '; ')

    Write-Utf8 $stageFile '3'
    Save-Result 2 $false
    Write-Host ''
    Write-Host 'Now restart Windows, log on, wait two minutes, and run this script again.' -ForegroundColor Cyan
}

# --- Run 3: everything started; clean up -------------------------------------------
function Invoke-ThirdRun {
    Write-Host 'Run 3 of 3: after a restart every entry must have started the dummy.' -ForegroundColor Cyan
    $lines = @()
    if (Test-Path -LiteralPath $dummyLog) {
        $lines = @(Get-Content -LiteralPath $dummyLog -Encoding UTF8)
        Copy-Item -LiteralPath $dummyLog -Destination (Join-Path $OutDir 'autostart-dummy-starts.log') -Force
    }
    foreach ($entry in $words.Keys) {
        $word = [regex]::Escape($words[$entry])
        $started = @($lines | Where-Object { $_ -match "args=$word`$" }).Count
        Add-Check "Windows started the dummy through $entry" ($started -ge 1) "$started lines"
    }

    # The automated tests, if the kit brought them: the same round trips as
    # in CI, on this Windows. One after the other, because they share the
    # names of what they make.
    if (Test-Path -LiteralPath $tests) {
        $arguments = '--test-threads=1'
        $which = 'all of them'
        if (-not $BootDriverTest) {
            $arguments = "$arguments --skip $bootDriverTestName"
            $which = 'without the one that registers a driver with the start boot'
        }
        $env:WARDEN_AUTOSTART_TESTS = 'this-machine-may-be-changed'
        $said = Invoke-Tool "`"$tests`" $arguments"
        $code = $LASTEXITCODE
        Remove-Item Env:\WARDEN_AUTOSTART_TESTS
        Write-Utf8 (Join-Path $OutDir 'autostart-tests.txt') $said
        $counted = [regex]::Match($said, 'test result: \S+ (\d+) passed; (\d+) failed')
        $numbers = 'no count in what the tests printed'
        if ($counted.Success) {
            $numbers = "$($counted.Groups[1].Value) passed, $($counted.Groups[2].Value) failed"
        }
        Add-Check 'the automated tests of the Windows side pass here' ($code -eq 0) "exit code $code, $numbers, $which"
        # Whatever the tests may have left, before anything restarts this
        # machine: above all the driver.
        Remove-TestLeftovers
        $leftovers = Get-TestLeftovers
        Add-Check 'nothing of the automated tests is left on the machine' ($leftovers.Count -eq 0) ($leftovers -join '; ')
    }

    Remove-Everything
    $leftBehind = Get-Present (Get-Views)
    Add-Check 'nothing of the test is left on the machine' (($leftBehind.Count -eq 0) -and -not (Test-Path -LiteralPath $work)) ($leftBehind -join '; ')
    Save-Result 3 $true
}

# --- Run ------------------------------------------------------------------------
Write-Host ''
Write-Host '== Warden: autostart entries, removed and put back ==' -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
Open-Serial
Send-Line "WARDEN-KIT START $(Get-UtcNow)"

$script:machine = Get-MachineFacts
if (-not $script:machine.administrator_rights) {
    Send-Line 'WARDEN-KIT FAILED not run as administrator'
    Close-Serial
    Write-Host 'FAILED: run this as administrator. It registers a service and tasks.' -ForegroundColor Red
    exit 2
}

if ($Reset) {
    Remove-Everything
    Remove-TestLeftovers
    Send-Line 'WARDEN-KIT DONE reset'
    Close-Serial
    Write-Host 'Everything the script makes is removed.' -ForegroundColor Green
    exit 0
}

foreach ($needed in @($warden, $dummySource)) {
    if (-not (Test-Path -LiteralPath $needed)) {
        Send-Line "WARDEN-KIT FAILED $needed is missing"
        Close-Serial
        Write-Host "FAILED: $needed is missing." -ForegroundColor Red
        exit 2
    }
}

if ($Only) {
    try {
        if ($Only -eq 'Look') {
            Invoke-OnlyLook
        } else {
            Invoke-OnlyEntries
        }
    } catch {
        Send-Line "WARDEN-KIT FAILED $($_.Exception.Message)"
        Close-Serial
        Write-Host "FAILED: $($_.Exception.Message)" -ForegroundColor Red
        exit 2
    }
    Send-Line "WARDEN-KIT DONE $(Get-UtcNow) only=$Only"
    Close-Serial
    exit 0
}

$stage = 1
if (Test-Path -LiteralPath $stageFile) {
    $stage = [int]((Get-Content -LiteralPath $stageFile -Raw -Encoding UTF8).Trim())
}
# The checks of the runs before this one.
$earlier = Read-Result
if (($stage -gt 1) -and ($null -ne $earlier)) {
    foreach ($check in @($earlier.checks)) {
        $script:checks += [ordered]@{ check = $check.check; held = [bool]$check.held; detail = [string]$check.detail }
    }
}

$failure = $null
try {
    if ($stage -eq 1) {
        Invoke-FirstRun
    } elseif ($stage -eq 2) {
        Invoke-SecondRun
    } else {
        Invoke-ThirdRun
    }
} catch {
    $failure = "$($_.Exception.Message)"
}

if ($failure) {
    Save-Result $stage $false
    Send-File $resultFile
    Send-Line "WARDEN-KIT FAILED $failure"
    Close-Serial
    Write-Host ''
    Write-Host "FAILED: $failure" -ForegroundColor Red
    Write-Host 'To remove what this run left behind, run the script with -Reset.' -ForegroundColor Yellow
    exit 2
}

$failed = @($script:checks | Where-Object { -not $_.held }).Count
foreach ($file in @(Get-ChildItem -LiteralPath $OutDir -Filter 'autostart-*' | Sort-Object Name)) {
    Send-File $file.FullName
}
Send-Line "WARDEN-KIT DONE $(Get-UtcNow) run=$stage checks=$($script:checks.Count) failed=$failed"
Close-Serial
Write-Host ''
if ($failed -eq 0) {
    Write-Host "Run $stage of 3 is done: $($script:checks.Count) checks so far, all held." -ForegroundColor Green
} else {
    Write-Host "Run $stage of 3 is done: $failed of $($script:checks.Count) checks so far did not hold." -ForegroundColor Red
}
Write-Host "Results: $OutDir"
if ($failed -eq 0) {
    exit 0
}
exit 1

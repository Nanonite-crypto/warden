<#
.SYNOPSIS
    Restarts a virtual machine again and again, with something else done
    before each restart, to find out whether a restart of Windows stumbles
    over something that Warden does.

.DESCRIPTION
    Twice a restart of the test machine did not go as usual, and both
    times it was the restart after the first run of autostart-remedy.ps1,
    in which Warden removes seven autostart entries. Seven other restarts
    went as usual. Nine restarts are too few to tell a cause from a
    coincidence. This script makes more of them, of four kinds, in a mixed
    order:

    nothing   Nothing is done.
    look      Warden reads what the machine starts, six times, as the
              first run of autostart-remedy.ps1 does. Nothing is added to
              the machine.
    entries   The seven entries are made with Windows' own tools and
              removed with Windows' own tools. Warden is not started.
    warden    The first run of autostart-remedy.ps1 as it is: the look,
              the entries, a scan, and Warden quarantines the dummy and
              removes the entries.

    A round goes like this. Windows has started and the user is logged on.
    The script waits, does what the round's kind says, waits again, and
    restarts Windows. A task that the script registers for itself starts
    it again when the user is logged on after the restart, with the rights
    of an administrator.

    What counts is how long a restart takes. The script writes a line to
    the serial port right before it asks Windows to restart, and one when
    it runs again. In between, the machine's firmware writes to the same
    port when the machine starts. Whoever watches the capture from outside
    can time all three by a clock that does not restart. The script also
    passes on what Windows itself wrote down about each shutdown and each
    start.

    A restart that does not come back has to be noticed from outside, and
    the machine reset by hand. The script then goes on as after any other
    restart.

    The script expects warden.exe, warden-dummy.exe and
    autostart-remedy.ps1 in the folder it is in, which can be a CD image.
    It needs a user who is logged on automatically. It registers a task,
    and through autostart-remedy.ps1 a service and more tasks, and it
    restarts the machine about forty times without asking. Only for a
    virtual machine made for the purpose. It changes no antivirus setting.
    Run it as administrator.

.PARAMETER Rounds
    How many rounds of each kind. Defaults to 10.

.PARAMETER SettleSeconds
    How long the script waits after the user is logged on before it does
    anything. Defaults to 60.

.PARAMETER PauseSeconds
    How long it waits between what a round does and the restart. Defaults
    to 45, about what it was when the restarts were made by hand.

.PARAMETER Seed
    The number the order of the rounds is made from. The same number gives
    the same order.

.PARAMETER OutDir
    Where the results go. Defaults to warden-out on the system drive.

.PARAMETER SerialPort
    Serial port to write to. Defaults to COM1. An empty string or the word
    none turns this off.

.PARAMETER Continue
    Go on after a restart. The task that the script registers gives this.

.PARAMETER Stop
    End a study that is under way: remove the task and whatever a round
    left on the machine, and do nothing else.

.PARAMETER Rehearse
    One round of each kind without the waiting and without a restart, to
    see that every step works on this Windows. For CI.
#>
[CmdletBinding()]
param(
    [int]$Rounds = 10,
    [int]$SettleSeconds = 60,
    [int]$PauseSeconds = 45,
    [int]$Seed = 20261127,
    [string]$OutDir = (Join-Path "$env:SystemDrive\" 'warden-out'),
    [string]$SerialPort = 'COM1',
    [switch]$Continue,
    [switch]$Stop,
    [switch]$Rehearse
)

$ErrorActionPreference = 'Stop'

$kinds = @('nothing', 'look', 'entries', 'warden')

$kit = $PSScriptRoot
$warden = Join-Path $kit 'warden.exe'
$dummySource = Join-Path $kit 'warden-dummy.exe'
$remedy = Join-Path $kit 'autostart-remedy.ps1'
$utf8 = New-Object System.Text.UTF8Encoding($false)

# What the script keeps between the restarts. The folder goes when the
# study is done.
$study = Join-Path "$env:SystemDrive\" 'warden-study'
$stateFile = Join-Path $study 'state.json'
$remedyOut = Join-Path $study 'remedy-out'
# Where autostart-remedy.ps1 keeps its place. If the folder is there, a
# round of the kind "warden" has left its quarantine behind.
$remedyWork = Join-Path "$env:SystemDrive\" 'warden-test'

$taskFolder = 'WardenStudy'
$taskName = '\WardenStudy\Continue'

# The events of Windows that are passed on, by the log they are in. Those
# of the first log come with their fields: how long a start or a shutdown
# took, in milliseconds, and what held it up.
$eventLogs = [ordered]@{
    performance = @{
        Log    = 'Microsoft-Windows-Diagnostics-Performance/Operational'
        # 100: Windows has started. 200: Windows has shut down. 203: a
        # service held the shutdown up.
        Ids    = @(100, 200, 203)
        Fields = $true
    }
    system      = @{
        Log    = 'System'
        # 12 and 13: the system started, shut down. 41: it was not shut
        # down before it started again. 1074: something asked for a
        # restart. 6005 and 6006: the event log started, stopped. 6008:
        # the shutdown before this start was unexpected.
        Ids    = @(12, 13, 41, 1074, 6005, 6006, 6008)
        Fields = $false
    }
}

function Write-Utf8([string]$Path, [string]$Text) {
    [System.IO.File]::WriteAllText($Path, $Text, $utf8)
}

function Get-UtcNow {
    return [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
}

# How long this Windows has been running, in milliseconds. A clock that
# does not jump, as long as Windows is not restarted.
function Get-Uptime {
    return [int64][Environment]::TickCount
}

# --- The serial port ---------------------------------------------------------
# As in autostart-remedy.ps1, with lines that start with WARDEN-STUDY. Every
# line also goes into a file next to the results.
$script:port = $null
$script:lineLog = $null

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
        Write-Host "No serial port ${SerialPort}: the lines stay in $OutDir only." -ForegroundColor Yellow
    }
}

function Send-Line([string]$Text) {
    if ($script:lineLog) {
        try { [System.IO.File]::AppendAllText($script:lineLog, $Text + "`r`n", $utf8) } catch { }
    }
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
    $script:port.Write("-----BEGIN WARDEN FILE $name sha256=$hash bytes=$($bytes.Length)-----`r`n")
    for ($i = 0; $i -lt $text.Length; $i += 76) {
        $script:port.Write($text.Substring($i, [Math]::Min(76, $text.Length - $i)) + "`r`n")
    }
    $script:port.Write("-----END WARDEN FILE $name-----`r`n")
}

function Close-Serial {
    if ($null -ne $script:port) {
        try { $script:port.Close() } catch { }
        $script:port = $null
    }
}

# --- Staying awake --------------------------------------------------------------
# As in fresh-install-scan.ps1: neither the machine nor its screen goes to
# sleep while this script's thread lives.
function Request-Awake {
    try {
        $signature = '[DllImport("kernel32.dll")] public static extern uint SetThreadExecutionState(uint esFlags);'
        $power = Add-Type -Namespace WardenKit -Name StudyPower -MemberDefinition $signature -PassThru
        return ($power::SetThreadExecutionState([uint32]2147483651) -ne 0)
    } catch {
        return $false
    }
}

# --- Tools -------------------------------------------------------------------------
# A command line run through cmd.exe, which merges what it prints as an
# error into its output. Returns the text and the exit code.
function Invoke-Line([string]$CommandLine) {
    $said = cmd /c "($CommandLine) 2>&1"
    $code = $LASTEXITCODE
    $text = ((@($said) | ForEach-Object { [string]$_ }) -join "`n").Trim()
    return @{ code = $code; said = $text }
}

# Runs autostart-remedy.ps1 with what is given. That script writes to the
# serial port itself, so this one lets go of the port for as long.
function Invoke-Remedy([string]$Arguments) {
    $serial = $SerialPort
    if (-not $serial) {
        $serial = 'none'
    }
    Close-Serial
    $ran = Invoke-Line "powershell -NoProfile -ExecutionPolicy Bypass -File `"$remedy`" -OutDir `"$remedyOut`" -SerialPort $serial $Arguments"
    Open-Serial
    return $ran
}

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
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
    foreach ($file in @($warden, $dummySource, $remedy, $PSCommandPath)) {
        try {
            $name = (Split-Path -Leaf $file) -replace '[^A-Za-z0-9]', '_'
            $info["sha256_$name"] = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()
        } catch { }
    }
    return $info
}

function Wait-Seconds([int]$Seconds, [string]$Why) {
    if ($Rehearse -or ($Seconds -le 0)) {
        return
    }
    Write-Host "  $Why ($Seconds seconds)"
    Start-Sleep -Seconds $Seconds
}

# --- What the script keeps between the restarts -------------------------------------
function Read-State {
    return (Get-Content -LiteralPath $stateFile -Raw -Encoding UTF8 | ConvertFrom-Json)
}

function Save-State($State) {
    New-Item -ItemType Directory -Force -Path $study | Out-Null
    Write-Utf8 $stateFile ($State | ConvertTo-Json -Depth 6)
}

# The order of the rounds: each kind once, in an order of its own, and that
# as many times as there are rounds of each kind.
function New-Schedule([int]$Count, [int]$SeedValue) {
    $random = New-Object System.Random($SeedValue)
    $all = @()
    foreach ($block in 1..$Count) {
        $order = $kinds.Clone()
        for ($i = $order.Count - 1; $i -gt 0; $i--) {
            $j = $random.Next($i + 1)
            $held = $order[$i]
            $order[$i] = $order[$j]
            $order[$j] = $held
        }
        $all += $order
    }
    return ,$all
}

# --- The events of Windows -------------------------------------------------------------
# The number of the newest event in a log. Zero for a log without events,
# and -1 for one that cannot be read.
function Get-NewestRecord([string]$Log) {
    try {
        $newest = Get-WinEvent -LogName $Log -MaxEvents 1 -ErrorAction Stop
        return [int64]$newest.RecordId
    } catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {
            return [int64]0
        }
        return [int64]-1
    }
}

# Passes on the events that were written since the last time, and returns
# the number of the newest of each log. Each kind of event is asked about
# by itself: Windows turns down a query that names many numbers.
function Send-NewEvents($Seen) {
    $now = @{}
    foreach ($name in $eventLogs.Keys) {
        $source = $eventLogs[$name]
        $after = [int64]$Seen.$name
        $now[$name] = $after
        if ($after -lt 0) {
            continue
        }
        $records = @()
        foreach ($id in $source.Ids) {
            try {
                $records += @(Get-WinEvent -FilterHashtable @{ LogName = $source.Log; Id = $id } -MaxEvents 40 -ErrorAction Stop |
                        Where-Object { $_.RecordId -gt $after })
            } catch {
                if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') {
                    Send-Line "WARDEN-STUDY NOTE the events $id of the log $name could not be read: $($_.Exception.Message)"
                }
            }
        }
        foreach ($record in @($records | Sort-Object RecordId)) {
            $at = $record.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
            $line = "WARDEN-STUDY EVENT log=$name id=$($record.Id) record=$($record.RecordId) at=$at provider=$($record.ProviderName)"
            if ($source.Fields) {
                $parts = @()
                try {
                    $xml = [xml]$record.ToXml()
                    foreach ($data in @($xml.Event.EventData.Data)) {
                        if ($null -ne $data) {
                            $parts += "$([string]$data.Name)=$([string]$data.'#text')"
                        }
                    }
                } catch { }
                $line = "$line fields: $($parts -join '; ')"
            }
            Send-Line $line
            if ([int64]$record.RecordId -gt $now[$name]) {
                $now[$name] = [int64]$record.RecordId
            }
        }
    }
    return $now
}

# --- The task that starts the script again ------------------------------------------------
function Register-Task {
    if ($PSCommandPath -match '\s') {
        throw "the path of this script has a blank in it, which the task's command line cannot hold: $PSCommandPath"
    }
    $command = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath -Continue"
    $made = Invoke-Line "schtasks /create /tn $taskName /tr `"$command`" /sc onlogon /rl highest /f"
    if ($made.code -ne 0) {
        throw "the task could not be registered (exit code $($made.code)): $($made.said)"
    }
}

function Remove-Task {
    $null = Invoke-Line "schtasks /delete /tn $taskName /f"
    try {
        $scheduler = New-Object -ComObject Schedule.Service
        $scheduler.Connect()
        $scheduler.GetFolder('\').DeleteFolder($taskFolder, 0)
    } catch { }
}

# --- A round ---------------------------------------------------------------------------------
# Does what a kind of round says, and returns how it went: the exit code of
# autostart-remedy.ps1, how long it took, and what it printed.
function Invoke-Kind([string]$Kind) {
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $ran = @{ code = 0; said = '' }
    if ($Kind -eq 'look') {
        $ran = Invoke-Remedy '-Only Look'
    } elseif ($Kind -eq 'entries') {
        $ran = Invoke-Remedy '-Only Entries'
    } elseif ($Kind -eq 'warden') {
        $ran = Invoke-Remedy ''
    } elseif ($Kind -ne 'nothing') {
        throw "no such kind of round: $Kind"
    }
    $watch.Stop()
    return @{ code = $ran.code; said = $ran.said; seconds = [Math]::Round($watch.Elapsed.TotalSeconds, 1) }
}

# Removes what a round of the kind "warden" left: the quarantine with the
# dummy in it. With Windows' tools, by autostart-remedy.ps1 -Reset.
function Clear-LastRound([string]$About) {
    if (-not (Test-Path -LiteralPath $remedyWork)) {
        return
    }
    $cleaned = Invoke-Remedy '-Reset'
    $gone = -not (Test-Path -LiteralPath $remedyWork)
    Send-Line "WARDEN-STUDY CLEANED $About exit=$($cleaned.code) gone=$gone"
}

# One round up to the moment before the restart: says so, does what the
# kind says, and writes down how it went.
function Start-Round($State, [int]$Number) {
    $kind = [string]@($State.schedule)[$Number - 1]
    Write-Host ''
    Write-Host "Round $Number of $(@($State.schedule).Count): $kind" -ForegroundColor Cyan
    Send-Line "WARDEN-STUDY ROUND round=$Number kind=$kind guest=$(Get-UtcNow) up=$(Get-Uptime)"
    $acted = Invoke-Kind $kind
    Send-Line "WARDEN-STUDY ACTED round=$Number kind=$kind exit=$($acted.code) seconds=$($acted.seconds)"
    if ($acted.said) {
        Write-Utf8 (Join-Path $study ('round-{0:d2}-{1}.txt' -f $Number, $kind)) $acted.said
    }
    if ($acted.code -ne 0) {
        $last = @($acted.said -split "`n" | Where-Object { $_.Trim() -ne '' } | Select-Object -Last 1)
        Send-Line "WARDEN-STUDY NOTE round=$Number went wrong: $($last -join '')"
        Write-Host "  went wrong (exit code $($acted.code))" -ForegroundColor Red
    } else {
        Write-Host "  done in $($acted.seconds) seconds" -ForegroundColor Green
    }
    $State.rounds = @($State.rounds) + [pscustomobject]@{
        round       = $Number
        kind        = $kind
        exit        = $acted.code
        seconds     = $acted.seconds
        asked_guest = ''
        asked_up    = 0
        back_guest  = ''
        back_up     = 0
    }
}

# The results, as a file of their own.
function Save-Results($State, [bool]$Finished) {
    $result = [ordered]@{
        started_at  = $State.started_at
        recorded_at = Get-UtcNow
        finished    = $Finished
        settings    = [ordered]@{
            rounds_of_each_kind = $State.each
            kinds               = $kinds
            seed                = $State.seed
            settle_seconds      = $State.settle
            pause_seconds       = $State.pause
        }
        machine     = $State.machine
        schedule    = @($State.schedule)
        rounds      = @($State.rounds)
    }
    $path = Join-Path $OutDir 'restart-study.json'
    Write-Utf8 $path ($result | ConvertTo-Json -Depth 6)
    return $path
}

function Restart-Windows {
    Close-Serial
    & shutdown.exe /r /t 0
}

# --- The ways to run ---------------------------------------------------------------------------
# A new study: nothing of the kit on the machine, the order of the rounds,
# the task, and a first restart that counts for nothing.
function Start-Study {
    if (Test-Path -LiteralPath $stateFile) {
        throw 'a study is under way on this machine. Run restart-study-stop.cmd first.'
    }
    New-Item -ItemType Directory -Force -Path $study | Out-Null
    $facts = Get-MachineFacts
    $schedule = New-Schedule $Rounds $Seed
    Send-Line "WARDEN-STUDY START guest=$(Get-UtcNow) rounds=$Rounds kinds=$($kinds -join ',') seed=$Seed settle=$SettleSeconds pause=$PauseSeconds"
    Send-Line "WARDEN-STUDY MACHINE $(($facts.Keys | ForEach-Object { "$_=$($facts[$_])" }) -join '; ')"
    Send-Line "WARDEN-STUDY SCHEDULE $($schedule -join ',')"

    # Whatever an earlier run of the kit left behind.
    $cleaned = Invoke-Remedy '-Reset'
    Send-Line "WARDEN-STUDY CLEANED before the first round exit=$($cleaned.code)"

    $seen = @{}
    foreach ($name in $eventLogs.Keys) {
        $seen[$name] = Get-NewestRecord $eventLogs[$name].Log
    }
    $state = [pscustomobject]@{
        started_at = Get-UtcNow
        each       = $Rounds
        seed       = $Seed
        settle     = $SettleSeconds
        pause      = $PauseSeconds
        out        = $OutDir
        serial     = $SerialPort
        machine    = $facts
        schedule   = $schedule
        pending    = 0
        seen       = $seen
        rounds     = @()
    }
    Save-State $state
    Register-Task
    Write-Host ''
    Write-Host "$(@($schedule).Count) rounds, and a restart after each. The first restart comes by itself." -ForegroundColor Cyan
    Write-Host 'To stop: close this window now, then run restart-study-stop.cmd.' -ForegroundColor Yellow
    Wait-Seconds $PauseSeconds 'Waiting before the first restart'
    Send-Line "WARDEN-STUDY RESTART round=0 kind=setup guest=$(Get-UtcNow) up=$(Get-Uptime)"
    Restart-Windows
}

# After a restart: says that the machine is back, clears what the round
# before left, waits, passes on what Windows wrote down, and either starts
# the next round or ends the study.
function Resume-Study {
    $state = Read-State
    $script:OutDir = [string]$state.out
    $script:SerialPort = [string]$state.serial
    $script:lineLog = Join-Path $OutDir 'restart-study-lines.txt'
    Open-Serial
    $total = @($state.schedule).Count
    $back = [int]$state.pending
    $kindBefore = 'setup'
    if ($back -ge 1) {
        $kindBefore = [string]@($state.schedule)[$back - 1]
    }
    $guest = Get-UtcNow
    $up = Get-Uptime
    Send-Line "WARDEN-STUDY BACK round=$back kind=$kindBefore guest=$guest up=$up"
    Write-Host ''
    Write-Host "Back from the restart of round $back of $total ($kindBefore)." -ForegroundColor Cyan
    if ($back -ge 1) {
        $entry = @($state.rounds)[$back - 1]
        $entry.back_guest = $guest
        $entry.back_up = $up
    }
    Clear-LastRound "round=$back"
    Save-State $state

    Wait-Seconds ([int]$state.settle) 'Letting Windows settle'
    $state.seen = Send-NewEvents $state.seen
    Save-State $state

    if ($back -ge $total) {
        Complete-Study $state
        return
    }

    $number = $back + 1
    Start-Round $state $number
    Wait-Seconds ([int]$state.pause) 'Waiting before the restart'
    $entry = @($state.rounds)[$number - 1]
    $entry.asked_guest = Get-UtcNow
    $entry.asked_up = Get-Uptime
    $state.pending = $number
    Save-State $state
    $null = Save-Results $state $false
    Send-Line "WARDEN-STUDY RESTART round=$number kind=$($entry.kind) guest=$($entry.asked_guest) up=$($entry.asked_up)"
    Restart-Windows
}

# The end: what Windows still writes down about the last start, the
# results, and nothing of the study left but its results.
function Complete-Study($State) {
    Write-Host ''
    Write-Host 'All rounds are done.' -ForegroundColor Green
    Wait-Seconds 120 'Waiting for what Windows still writes down about the last start'
    $State.seen = Send-NewEvents $State.seen
    Remove-Task
    $path = Save-Results $State $true
    Send-File $path
    $wrong = @(@($State.rounds) | Where-Object { $_.exit -ne 0 }).Count
    Send-Line "WARDEN-STUDY DONE guest=$(Get-UtcNow) rounds=$(@($State.rounds).Count) went_wrong=$wrong"
    if (Test-Path -LiteralPath $study) {
        Remove-Item -LiteralPath $study -Recurse -Force
    }
    Write-Host "Results: $path"
}

# One round of each kind, one after the other, without the waiting, the
# task and the restarts. What a round leaves is cleared as it would be
# after the restart.
function Invoke-Rehearsal {
    if (Test-Path -LiteralPath $study) {
        Remove-Item -LiteralPath $study -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $study | Out-Null
    $facts = Get-MachineFacts
    $schedule = New-Schedule 1 $Seed
    Send-Line "WARDEN-STUDY START guest=$(Get-UtcNow) rounds=1 kinds=$($kinds -join ',') seed=$Seed rehearsal"
    Send-Line "WARDEN-STUDY MACHINE $(($facts.Keys | ForEach-Object { "$_=$($facts[$_])" }) -join '; ')"
    Send-Line "WARDEN-STUDY SCHEDULE $($schedule -join ',')"
    $cleaned = Invoke-Remedy '-Reset'
    Send-Line "WARDEN-STUDY CLEANED before the first round exit=$($cleaned.code)"
    $seen = @{}
    foreach ($name in $eventLogs.Keys) {
        # From the first event on and with their fields, so that the
        # rehearsal has something to pass on from each log that can be read.
        $eventLogs[$name].Fields = $true
        $newest = Get-NewestRecord $eventLogs[$name].Log
        if ($newest -gt 0) {
            $newest = 0
        }
        $seen[$name] = $newest
    }
    $state = [pscustomobject]@{
        started_at = Get-UtcNow
        each       = 1
        seed       = $Seed
        settle     = 0
        pause      = 0
        out        = $OutDir
        serial     = $SerialPort
        machine    = $facts
        schedule   = $schedule
        pending    = 0
        seen       = $seen
        rounds     = @()
    }
    Save-State $state
    # The task is registered and removed again, to see that Windows takes it.
    Register-Task
    $shown = Invoke-Line "schtasks /query /tn $taskName"
    Send-Line "WARDEN-STUDY NOTE the task was registered: exit=$($shown.code)"
    Remove-Task
    if ($shown.code -ne 0) {
        throw "the task was registered, and Windows does not show it: $($shown.said)"
    }
    # What the script keeps is read back, as it is after a restart.
    $state = Read-State
    foreach ($number in 1..@($state.schedule).Count) {
        Start-Round $state $number
        $entry = @($state.rounds)[$number - 1]
        $entry.asked_guest = Get-UtcNow
        $entry.asked_up = Get-Uptime
        $state.pending = $number
        Save-State $state
        Send-Line "WARDEN-STUDY RESTART round=$number kind=$($entry.kind) guest=$($entry.asked_guest) up=$($entry.asked_up) rehearsal"
        $state = Read-State
        $entry = @($state.rounds)[$number - 1]
        $entry.back_guest = Get-UtcNow
        $entry.back_up = Get-Uptime
        Send-Line "WARDEN-STUDY BACK round=$number kind=$($entry.kind) guest=$($entry.back_guest) up=$($entry.back_up) rehearsal"
        Clear-LastRound "round=$number"
        Save-State $state
    }
    $state.seen = Send-NewEvents $state.seen
    Complete-Study $state
    $wrong = @(@($state.rounds) | Where-Object { $_.exit -ne 0 }).Count
    if ($wrong -gt 0) {
        throw "$wrong of the rounds went wrong"
    }
    if (Test-Path -LiteralPath $remedyWork) {
        throw "something of the kit is left on the machine: $remedyWork"
    }
}

# --- Run -------------------------------------------------------------------------------------------
Write-Host ''
Write-Host '== Warden: restarts, with and without Warden ==' -ForegroundColor Cyan

if (-not (Test-Administrator)) {
    Write-Host 'FAILED: run this as administrator. It registers a task and restarts the machine.' -ForegroundColor Red
    exit 2
}
foreach ($needed in @($warden, $dummySource, $remedy)) {
    if (-not (Test-Path -LiteralPath $needed)) {
        Write-Host "FAILED: $needed is missing." -ForegroundColor Red
        exit 2
    }
}
$null = Request-Awake

if ($Stop) {
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
    $script:lineLog = Join-Path $OutDir 'restart-study-lines.txt'
    Open-Serial
    Remove-Task
    $cleaned = Invoke-Remedy '-Reset'
    if (Test-Path -LiteralPath $study) {
        Remove-Item -LiteralPath $study -Recurse -Force
    }
    Send-Line "WARDEN-STUDY STOPPED guest=$(Get-UtcNow) exit=$($cleaned.code)"
    Close-Serial
    Write-Host 'The study is ended: its task is removed, and what a round left.' -ForegroundColor Green
    exit 0
}

$failure = $null
try {
    if ($Continue) {
        Resume-Study
    } else {
        New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
        $script:lineLog = Join-Path $OutDir 'restart-study-lines.txt'
        if (Test-Path -LiteralPath $script:lineLog) {
            Remove-Item -LiteralPath $script:lineLog -Force
        }
        Open-Serial
        if ($Rehearse) {
            Invoke-Rehearsal
        } else {
            Start-Study
        }
    }
} catch {
    $failure = "$($_.Exception.Message)"
}

if ($failure) {
    Send-Line "WARDEN-STUDY FAILED $failure"
    Close-Serial
    Write-Host ''
    Write-Host "FAILED: $failure" -ForegroundColor Red
    if ($Continue) {
        # The task started this window, and it would close with the script.
        Write-Host 'The study stands still. To end it, run restart-study-stop.cmd.' -ForegroundColor Yellow
        $null = Read-Host 'Press Enter to close this window'
    }
    exit 2
}

Close-Serial
if ($Continue) {
    # Either Windows is restarting, or the study is done. If it is done,
    # the window stays, and with it the request to stay awake.
    if (-not (Test-Path -LiteralPath $stateFile)) {
        $null = Read-Host 'The study is done. Press Enter to close this window'
    }
}
exit 0

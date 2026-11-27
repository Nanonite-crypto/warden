<#
.SYNOPSIS
    Lists what this machine's own logs say it was doing: Microsoft
    Defender's scans and updates, Windows Update, and when Windows was
    started, put to sleep and woken.

.DESCRIPTION
    How long a scan by Warden takes depends on what else the machine does
    at the time. Microsoft Defender looks at every file that is opened,
    Windows Update and a start of the machine keep the disk busy. This
    script reads Windows' logs and lists such events with their times, so
    that a scan that took unusually long can be laid next to them.

    It reads, and changes nothing. For each event it prints the time, the
    source, the event's number and what that number means. For Defender's
    scans and updates it also prints the kind of scan, how long it took,
    the kind of update and the version numbers. It prints no message text
    and no other field: those can hold paths, and the names of users,
    programs and devices.

    One kind of event gets more: where Defender found the EICAR test file.
    Warden's own tests write that file, and whether Defender got to it is
    what such a line is for. It names what Defender called the file, what
    found it and what was done, and the file's place if that is inside
    this repository. Of anything else that Defender found on this machine
    the list says when, and nothing more.

    The list is printed and written to target\check\machine-events.txt.

.PARAMETER Days
    How many days back to list. Defaults to 14.

.PARAMETER Out
    The file to write the list to.
#>
[CmdletBinding()]
param(
    [int]$Days = 14,
    [string]$Out = ''
)

$ErrorActionPreference = 'Stop'

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
if (-not $Out) {
    $Out = Join-Path $repo 'target\check\machine-events.txt'
}
$since = (Get-Date).AddDays(-$Days)

# What is listed: a log, the provider in it if the log has several, and the
# events by their numbers. The numbers of Defender's events are those of
# Microsoft's documentation, "Review event logs and error codes to
# troubleshoot issues with Microsoft Defender Antivirus".
$sources = @(
    @{
        Name     = 'defender'
        Log      = 'Microsoft-Windows-Windows Defender/Operational'
        Provider = ''
        Events   = @{
            '1000' = 'a scan of its own started'
            '1001' = 'a scan of its own finished'
            '1002' = 'a scan of its own was stopped before it finished'
            '1005' = 'a scan of its own failed'
            '2000' = 'definitions updated'
            '2001' = 'an update of the definitions failed'
            '2002' = 'engine updated'
            '2003' = 'an update of the engine failed'
            '2004' = 'definitions could not be loaded, the last good ones are tried'
            '2006' = 'an update of the platform failed'
            '2010' = 'more definitions fetched from the cloud'
            '2011' = 'definitions from the cloud deleted as out of date'
            '2013' = 'all definitions from the cloud deleted'
            '1006' = 'it found something'
            '1007' = 'it acted on what it found'
            '1008' = 'an action on what it found failed'
            '1116' = 'it found something'
            '1117' = 'it acted on what it found'
            '1118' = 'an action on what it found failed'
            '1119' = 'an action on what it found failed badly'
            '3002' = 'real-time protection failed'
            '3007' = 'real-time protection recovered from a failure'
            '5000' = 'real-time protection switched on'
            '5001' = 'real-time protection switched off'
            '5008' = 'the engine failed'
        }
    },
    @{
        Name     = 'update'
        Log      = 'System'
        Provider = 'Microsoft-Windows-WindowsUpdateClient'
        Events   = @{
            '19' = 'an update was installed'
            '20' = 'an update failed to install'
            '43' = 'the installation of an update started'
            '44' = 'the download of an update started'
        }
    },
    @{
        Name     = 'start'
        Log      = 'System'
        Provider = 'Microsoft-Windows-Kernel-General'
        Events   = @{
            '12' = 'Windows started'
            '13' = 'Windows shut down'
        }
    },
    @{
        Name     = 'sleep'
        Log      = 'System'
        Provider = 'Microsoft-Windows-Kernel-Power'
        Events   = @{
            '42'  = 'the machine went to sleep'
            '107' = 'the machine came back from sleep'
        }
    }
)

# The fields of an event that are shown, by their names: the kind of scan,
# how long a scan took, the kind of update, and version numbers.
$shown = '^(Scan Type|Scan Parameters|Scan Time Hours|Scan Time Minutes|Scan Time Seconds|Update Type)( Index)?$|Version$'

# The events that say Defender found something, and the fields of such an
# event that are shown if what it found is the EICAR test file.
$findings = @('1006', '1007', '1008', '1116', '1117', '1118', '1119')
$shownOfTheTestFile = @('Threat Name', 'Source Name', 'Action Name', 'Error Code', 'Error Description')

function Format-Utc($Time) {
    return ([datetime]$Time).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
}

# The events of one source since the day the list starts. No event at all
# is an answer and not an error.
#
# Each number is asked about by itself. Windows turns down a query that
# names more than 22 event numbers, and Get-WinEvent then says that there
# are no such events, which reads like an answer. That is how this list
# once showed nothing of Defender on a machine whose Defender had been busy.
function Read-Events([string]$Log, [string]$Provider, [int[]]$Ids) {
    $found = @()
    foreach ($id in $Ids) {
        $filter = @{ LogName = $Log; Id = $id; StartTime = $since }
        if ($Provider) {
            $filter.ProviderName = $Provider
        }
        try {
            $found += @(Get-WinEvent -FilterHashtable $filter -ErrorAction Stop)
        } catch {
            if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') {
                throw
            }
        }
    }
    return $found
}

# How far back a log reaches: the time of its oldest event.
function Get-Reach([string]$Log) {
    try {
        $first = Get-WinEvent -LogName $Log -Oldest -MaxEvents 1 -ErrorAction Stop
        return (Format-Utc $first.TimeCreated)
    } catch {
        return 'unknown'
    }
}

# The fields of an event that may be shown, as "name=value; name=value".
function Get-Fields($Record) {
    $parts = @()
    try {
        $xml = [xml]$Record.ToXml()
        foreach ($data in @($xml.Event.EventData.Data)) {
            if ($null -eq $data) {
                continue
            }
            $name = [string]$data.Name
            if ($name -match $shown) {
                $parts += "$name=$([string]$data.'#text')"
            }
        }
    } catch { }
    return ($parts -join '; ')
}

# What may be shown of an event that says Defender found something. If it
# is the EICAR test file: what Defender called it, what found it, what was
# done, and where the file was if that is inside this repository. Of
# anything else, nothing: what an antivirus found on a machine is the
# business of whoever owns it.
function Get-Finding($Record) {
    $values = @{}
    try {
        $xml = [xml]$Record.ToXml()
        foreach ($data in @($xml.Event.EventData.Data)) {
            if ($null -eq $data) {
                continue
            }
            $values[[string]$data.Name] = [string]$data.'#text'
        }
    } catch { }
    # The test file is known by its name in what Defender calls it, looked
    # for in every field: the fields have had other names in other versions.
    $all = (@($values.Values) | ForEach-Object { [string]$_ }) -join ' '
    if (-not ($all -match 'EICAR')) {
        return 'not the test file'
    }
    $parts = @()
    foreach ($name in $shownOfTheTestFile) {
        if ($values.ContainsKey($name) -and $values[$name]) {
            $parts += "$name=$($values[$name])"
        }
    }
    # The place, or the places: several are separated by semicolons.
    $places = @()
    foreach ($place in @(([string]$values['Path']) -split ';')) {
        $place = $place.Trim()
        if (-not $place) {
            continue
        }
        $at = $place.ToLowerInvariant().IndexOf($repo.ToLowerInvariant())
        if ($at -ge 0) {
            $places += '<repository>' + $place.Substring($at + $repo.Length)
        } else {
            $places += '(a place outside this repository)'
        }
    }
    if ($places.Count -gt 0) {
        $parts += "Path=$($places -join ', ')"
    }
    return ($parts -join '; ')
}

$lines = New-Object 'System.Collections.Generic.List[string]'
$lines.Add("# What this machine's logs say it was doing, since $(Format-Utc $since). Times are UTC.")
$lines.Add("# Listed at $(Format-Utc (Get-Date)). Nothing was changed.")

$rows = @()
foreach ($source in $sources) {
    $ids = @($source.Events.Keys | ForEach-Object { [int]$_ })
    try {
        $records = @(Read-Events $source.Log $source.Provider $ids)
    } catch {
        $lines.Add("# $($source.Name): the log $($source.Log) could not be read: $($_.Exception.Message)")
        continue
    }
    $lines.Add("# $($source.Name): $($records.Count) events, from the log $($source.Log), which reaches back to $(Get-Reach $source.Log)")
    foreach ($record in $records) {
        $what = $source.Events[[string]$record.Id]
        $line = '{0}  {1,-8}  {2,5}  {3}' -f (Format-Utc $record.TimeCreated), $source.Name, $record.Id, $what
        if ($source.Name -eq 'defender') {
            if ($findings -contains [string]$record.Id) {
                $fields = Get-Finding $record
            } else {
                $fields = Get-Fields $record
            }
            if ($fields) {
                $line = "$line  [$fields]"
            }
        }
        $rows += New-Object PSObject -Property @{ Time = $record.TimeCreated; Line = $line }
    }
}
foreach ($row in @($rows | Sort-Object Time)) {
    $lines.Add($row.Line)
}

New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Out) | Out-Null
[System.IO.File]::WriteAllText($Out, (($lines -join "`r`n") + "`r`n"), (New-Object System.Text.UTF8Encoding($false)))
foreach ($line in $lines) {
    Write-Host $line
}
Write-Host ''
Write-Host "Written to $Out"
exit 0

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

function Format-Utc($Time) {
    return ([datetime]$Time).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
}

# The events of one source since the day the list starts. No event at all
# is an answer and not an error.
function Read-Events([string]$Log, [string]$Provider, [int[]]$Ids) {
    $filter = @{ LogName = $Log; Id = $Ids; StartTime = $since }
    if ($Provider) {
        $filter.ProviderName = $Provider
    }
    try {
        return @(Get-WinEvent -FilterHashtable $filter -ErrorAction Stop)
    } catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {
            return @()
        }
        throw
    }
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
            $fields = Get-Fields $record
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

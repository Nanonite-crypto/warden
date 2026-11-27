# What starts a file

A program that wants to stay makes Windows start it again: with a value
under a Run key, a scheduled task, a service, or a shortcut in the Startup
folder. When Warden quarantines a file, it removes the entries that start
it. When it restores the file, it puts them back, each as it was.

Both halves follow from what the [quarantine](QUARANTINE.md) is. An entry
that starts a quarantined file is a loose end: Windows reports an error at
every start, or something else is put at that path and gets started. And a
restore that brings back the file without what started it has not undone
the quarantine.

The code is the crate `warden-autostart`. This document says where it
looks, what it removes and what it leaves, how it puts things back, and
what a real Windows had to say about the first attempt.

## What it looks like

On a hosted Windows runner of the CI, with seven entries that Windows' own
tools had made for a harmless file. The output is the test's, of
2026-11-26; the commands are shortened, the test gives the file's full
path and a quarantine folder of its own. Nothing is changed by looking:

```text
> warden autostart find threat.exe
C:\Users\RUNNER~1\AppData\Local\Temp\Warden test scene SAfFxL\threat.exe is started by 7 entries:
  the value "WardenTestThreatForAll" under HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
      rundll32.exe "C:\Users\RUNNER~1\AppData\Local\Temp\Warden test scene SAfFxL\threat.exe",Start
  the value "WardenTestThreat32" under HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run (as 32-bit programs see it)
      C:\Users\RUNNER~1\AppData\Local\Temp\WARDEN~1\threat.exe
  the value "WardenTestThreat" under HKEY_USERS\S-1-5-21-3414932011-3134797172-3625386099-500\Software\Microsoft\Windows\CurrentVersion\Run
      "C:\Users\RUNNER~1\AppData\Local\Temp\Warden test scene SAfFxL\threat.exe" --from-run
  the scheduled task \Warden Test\Threat at boot
      "C:\Users\RUNNER~1\AppData\Local\Temp\Warden test scene SAfFxL\threat.exe" --from-boot-task
  the scheduled task \Warden Test\Threat at logon
      "C:\Users\RUNNER~1\AppData\Local\Temp\Warden test scene SAfFxL\threat.exe" --from-task
  the service WardenTestThreat
      "C:\Users\RUNNER~1\AppData\Local\Temp\Warden test scene SAfFxL\threat.exe" --service
  the shortcut C:\Users\runneradmin\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\WardenTestThreat.lnk
      C:\Users\runneradmin\AppData\Local\Temp\Warden test scene SAfFxL\threat.exe --from-shortcut

Nothing was changed. `warden quarantine add` removes these together with the file, and `warden quarantine restore` puts them back.
```

Three of the seven do not spell the path the way it was asked for. The
second writes it in the short form that Windows keeps for old programs,
the first had a variable in it, which is shown filled in, and the shortcut
holds the long form. All three are the same file.

```text
> warden quarantine add threat.exe
Quarantined  C:\Users\RUNNER~1\AppData\Local\Temp\Warden test scene SAfFxL\threat.exe
  entry      14a621c1d0cd9050
  sha256     98e9c4eb3b8ee8a486a75137c2bf33e9f37fddf0ca673758326fccf79a54e76c (1,495,552 bytes)
  removed    the value "WardenTestThreatForAll" under HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
  removed    the value "WardenTestThreat32" under HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run (as 32-bit programs see it)
  removed    the value "WardenTestThreat" under HKEY_USERS\S-1-5-21-3414932011-3134797172-3625386099-500\Software\Microsoft\Windows\CurrentVersion\Run
  removed    the scheduled task \Warden Test\Threat at boot
  removed    the scheduled task \Warden Test\Threat at logon
  removed    the service WardenTestThreat
  removed    the shortcut C:\Users\runneradmin\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\WardenTestThreat.lnk
             what was removed started the file, and a restore puts it back

> warden quarantine restore 14a6
Restored  C:\Users\RUNNER~1\AppData\Local\Temp\Warden test scene SAfFxL\threat.exe
  sha256  98e9c4eb3b8ee8a486a75137c2bf33e9f37fddf0ca673758326fccf79a54e76c (1,495,552 bytes), as recorded
  Its timestamps and permissions are what they were.
  What started it is back as well:
  - the value "WardenTestThreatForAll" under HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
  - the value "WardenTestThreat32" under HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run (as 32-bit programs see it)
  - the value "WardenTestThreat" under HKEY_USERS\S-1-5-21-3414932011-3134797172-3625386099-500\Software\Microsoft\Windows\CurrentVersion\Run
  - the scheduled task \Warden Test\Threat at boot
  - the scheduled task \Warden Test\Threat at logon
  - the service WardenTestThreat
  - the shortcut C:\Users\runneradmin\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\WardenTestThreat.lnk
```

In between, `warden quarantine info` and `list` say what the quarantine
holds for the file. Afterwards Windows' own tools show every entry as they
showed it before, to the letter. That comparison is the test; see
[How it is tested](#how-it-is-tested).

## The four places

| Place | What is read | Read and removed through | Put back through |
|---|---|---|---|
| Run and RunOnce values | The machine's, in the view of 64-bit programs and in the view of 32-bit programs, and those of every user whose settings are loaded | The registry | The registry: the value with its type and its bytes |
| Scheduled tasks | Every task in every folder, hidden ones included | The Task Scheduler | The Task Scheduler, from the definition it gave out |
| Services and drivers | Every key below `Services` that has a type and a program. The program, and the library that a shared service host loads for the service | The registry for reading, the service manager for removing | The service manager, then the service's key |
| Shortcuts in the Startup folders | The folder of the user Warden runs as, and the one for all users | The shell for reading; the quarantine takes the shortcut, which is a file | The quarantine |

Windows is asked wherever Windows owns the format. Warden does not edit a
task's file or write a service into the registry by hand: it could produce
something that Windows reads differently than Warden meant it.

### What is not looked at

Windows has many more places that start programs.
[Autoruns](https://learn.microsoft.com/sysinternals/downloads/autoruns),
Microsoft's own tool for showing them, has a tab for each kind. Warden
covers the four that the roadmap set out. Among those it does not cover:

- the values that name the shell and the logon program, and the Run keys
  that policies use;
- programs that Windows loads into other programs: libraries named for
  every process, debuggers registered for a program's name, handlers and
  extensions of the shell, add-ins of browsers and of Office;
- event subscriptions in the management database (WMI), and logon and
  startup scripts;
- what Windows runs before any user logs on, apart from services, drivers
  and tasks;
- the Startup folders of other users, and the settings of users who are
  not logged on, which Windows has not loaded.

Inside the four places there are entries Warden does not follow:

- **A bare name.** `updater.exe` without a folder is found by Windows on
  its search path. Warden follows full paths only: which file a bare name
  means depends on who asks and from where.
- **A script that starts the file.** If a task runs `start.cmd` and that
  file starts the program, the task starts `start.cmd`. Warden does not
  read scripts.
- **A driver whose key names no file.** Windows then loads the file of the
  driver's name from its drivers folder. Warden reads no command line for
  it.
- **A task that does something else than run a program**, such as one that
  hands work to a component of Windows.

## What "starts the file" means

An entry starts a file if the file's full path stands in the entry's
command line, once the variables in it are filled in.

It may stand there as the program or as something passed to a program.
`rundll32.exe C:\x\a.dll,Start` starts `a.dll`. A service that lives in a
shared host starts the library its key names. The comparison ignores case,
as Windows does.

The path has to stand between characters that end a path, so that a
longer name is not taken for a shorter one:

| Command line | Starts `C:\x\tool.exe` |
|---|---|
| `"C:\x\tool.exe" --quiet` | Yes |
| `C:\x\tool.exe` | Yes |
| `rundll32.exe "C:\x\tool.exe",Start` | Yes |
| `C:\x\tool.exe.bak` | No |
| `C:\x\tool.exe2` | No |
| `D:\C\x\tool.exe` | No |
| `tool.exe` | No: a bare name |

**The path is looked for in every way Windows writes it**: as it was
given, in the long form, and in the short form of eight letters and three
that Windows keeps for old programs. Windows is asked for the other forms.
An entry written as `C:\PROGRA~1\x\tool.exe` starts
`C:\Program Files\x\tool.exe`.

**Variables are filled in with the values of the user the entry belongs
to.** `%APPDATA%\x.exe` means a different file for each user.

| The entry belongs to | Its variables come from |
|---|---|
| The user Warden runs as | Warden's own environment, which is that user's |
| Another person's account | The places Windows fills them from: the list of profiles, the user's folders for programs' data, and what the user has set |
| The machine, the system or a service account | What is the same for everybody: the Windows folder, the program folders, the system drive |

A variable that Warden has no value for stays as it is, and the entry does
not match. That is the safe side: a wrong guess could make an entry look
as if it started a file that it has nothing to do with.

## The record

Everything an entry is goes into a record before the entry is touched. The
record is kept in the quarantine, with the file's entry.

| Kind | What the record holds |
|---|---|
| Run value | The hive, the view, the key, the name, the type and the bytes |
| Task | Its path, the definition as the Task Scheduler gives it out, and its access rights |
| Service or driver | Its settings, its whole key in the registry with every key below it, and its access rights |
| Shortcut | Where it was, what it points at and what it passes. The shortcut itself is in the quarantine, as an entry of its own |

Two keys below a service's key are left out. `Security` holds the access
rights in a form of the service manager's own; they are recorded as the
service manager gives them out. `Enum` is written by Windows when it finds
the device a driver belongs to.

The record also says, for each entry, whether it was removed, and it is
written again after every single removal.

## Removing

- **The file first.** Entries are removed once the file is safe in the
  quarantine, not before. If the file cannot be quarantined, nothing is
  touched.
- **Looked at once more.** Right before an entry goes, it is read again.
  Only what still is what the record holds is removed. An entry that
  changed in the meantime stays as it is now.
- **One at a time.** After each removal the record is written. Whenever a
  run is cut off, every entry is in its place, in the record, or in both.
  `warden autostart remove <entry>` goes on where it stopped.
- **What could not be put back is not removed.** A task that runs with a
  stored password, and a service that runs as an account with one: nobody
  could give the password back. The copy of a service that Windows makes
  for each user who is logged on: nobody else can make one. Such an entry
  stays and is named with the reason.
- **Rights.** The machine's entries need an administrator's rights.
  Without them, what belongs to the user goes, and the rest is named.
  `warden autostart remove <entry>` removes it later, from a prompt with
  those rights.
- **Never for a file of Windows.** A file that was taken past the
  [guard](QUARANTINE.md#the-guard) keeps its entries. A program of Windows
  can have services of Windows that start it.
- **Nothing is stopped.** Warden removes what would start a program the
  next time. A program that runs is not ended, and the file of a program
  that runs cannot be quarantined at all yet; see [Limits](#limits).

## Putting back

A restore looks before it writes.

| What is at the entry's place | What happens |
|---|---|
| Nothing | The entry is created, read back and compared with the record |
| The same entry | It is left alone |
| Something else | It is not replaced. The entry stays owed |
| Windows refuses | The entry stays owed, with the reason |

An entry that is owed stays in the record. `warden quarantine list` names
it, a second `warden quarantine restore` tries again, and
`warden quarantine delete` gives it up.

The entries are put back when the file returns to the place it was taken
from. A file that is restored to another place gets none: they would start
a path where nothing is.

Warden starts nothing. A service that was put back runs when Windows next
starts it.

### What a real Windows said to the first attempt

The part that talks to Windows cannot be built or run on the system this
project is developed on. It was written against the documentation and then
run in CI, against entries made with Windows' own tools. It found all
seven and read them right, and the Run values and the shortcut came back
unchanged. Two things did not.

**A task was handed back with its access rights.** The Task Scheduler
takes a definition and, next to it, access rights. Given both, it wrote
the rights into the definition, which then was no longer the recorded one,
and it listed the rights in another order. A task is now registered from
its definition alone. It takes its rights from its folder, with a right to
read for the account it runs as, exactly as it did when it was first made.
Only if its rights then differ from the recorded ones are they set.

**A service's settings were only in the registry.** The service manager
creates a service from a handful of settings. Everything else a service
has is in its key, and was written back there. The key was whole
afterwards. But asked right after, the service manager knew of no delayed
start and gave the service no identity of its own:

```text
before   START_TYPE         : 2   AUTO_START  (DELAYED)
after    START_TYPE         : 2   AUTO_START

before   SERVICE_SID_TYPE:  UNRESTRICTED
after    SERVICE_SID_TYPE:  NONE
```

It keeps such settings in its own memory and reads the registry when
Windows starts. Until the next restart the service would have been another
one than before. Six settings are now told to the service manager through
its own calls, read from the recorded key: a delayed start, the service's
own identity for access checks, the privileges it asks for, whether a
failure without a crash counts as one, the time it gets before a shutdown,
and the events that start it by itself. The key is written back afterwards
as before. That covers what the service manager has no call for, such as a
service's own parameters, and whatever could not be handed over. If that
happens, the restore says that the setting holds from the next start of
Windows.

Neither would have shown in a test against a stand-in. Both showed in the
first run because the test does not ask Warden whether it did well. It
asks `schtasks` and `sc`.

## The commands

| Command | What it does |
|---|---|
| `warden autostart find <file>` | Shows what starts a file. Changes nothing |
| `warden autostart list` | Shows every entry Warden looks at, by place. Changes nothing |
| `warden autostart remove <entry>` | Goes on removing what starts a quarantined file: what was left for want of rights, or by a run that was cut off |
| `warden quarantine add <file>` | Quarantines the file and removes what starts it |
| `warden quarantine restore <entry>` | Restores the file and puts back what started it |
| `warden quarantine info <entry>`, `list` | Show what was removed with a file, and what is still owed |
| `warden quarantine delete <entry>` | Deletes the file for good, and its record with it |

`find` and `list` take `--json`. On a system that is not Windows they say
that these entries exist on Windows only.

The list of a machine's autostart entries says what is installed on it.
Warden prints it and records it nowhere.

## Limits

- **A file that is in use.** Windows does not let the file of a running
  program be removed. `warden quarantine add` then fails, takes nothing
  and touches no entry. Stopping the program first takes the rights of a
  service. Whether that comes with the service of phase 6 is one of the
  open decisions in the [roadmap](ROADMAP.md#open-decisions).
- **A file that Windows needs to start.** The guard keeps files that
  Windows itself signed out of the quarantine. A driver of another maker
  that Windows loads at boot is not such a file, and without it a machine
  may not start. Warden does not look at this yet; see the open decisions
  in the [roadmap](ROADMAP.md#open-decisions).
- **The places above that are not looked at.**
- **A setting that could not be told to the service manager** holds from
  the next start of Windows. The restore says so.
- **Rights on a task that differ from what its folder gives** are set
  after the task is registered. For a moment the task has its folder's
  rights.

## How it is tested

| | Where it runs | What must hold |
|---|---|---|
| The rules, against a stand-in for Windows | Everywhere | With a real quarantine and real files: what starts a file is found and nothing else; all of it goes and comes back; a run cut off after every single step of a removal and of a put-back leaves each entry in its place or in the record, and can be finished; without rights the user's entries go and the rest is named; an entry that changed since it was written down stays; a task with a stored password and a user's copy of a service are not removed; a place that is taken is not written over |
| Reading | Everywhere | Command lines of all four kinds, variables filled in the way Windows does it, paths between the characters that end a path, task definitions that are no task definitions, any text at all |
| The Windows side, on Windows | CI, and the virtual machine | Seven entries made with `reg`, `schtasks`, `sc` and the shell are all found, and read right. Each goes through Warden and Windows' tools no longer show it; each comes back and they show it as before. The same with a real quarantine around it |
| The whole program, on Windows | CI | `warden autostart find`, `quarantine add`, `info`, `list`, `restore` and `delete` on the same seven entries |
| The run by hand | The virtual machine | See below |

What Windows' tools show is compared as text, before and after: the
registry's lines for each Run value; each task's definition, and its
access rights as the Task Scheduler's interface for scripts gives them;
for the service its settings, description, failure actions, identity,
privileges, triggers and access rights, each from `sc`, and its whole key
from `reg`; the shortcut byte for byte.

The seven entries are picked to be awkward. One value holds a variable and
names the file as something passed to `rundll32`. One is in the registry
view of 32-bit programs and spells the path in its short form. One task
runs as the user and one as the system. The service has a delayed start,
an identity, two privileges, failure actions, three triggers, two of them
with data, and keys of its own below its key. The folder has blanks in its
name.

These tests register a service and tasks. They run only where a variable
says in as many words that the machine may be changed:
`WARDEN_AUTOSTART_TESTS=this-machine-may-be-changed`. CI sets it on the
hosted runner, which is deleted after the job. A developer's `cargo test`
skips them and says why.

**The run by hand** shows what no test can: that Windows itself stops
starting the program, and starts it again after a restore. A harmless
program, `warden-dummy`, adds a line to a file whenever it is started and
does nothing else. The script `autostart-remedy` registers it in seven
places, lets a scan report it and lets Warden quarantine it. After a
restart it checks that no line was written, and restores it. After a
second restart there has to be a line from each of the seven entries.
[TESTING.md](TESTING.md#autostart-entries) has the steps. CI rehearses the
script on the hosted runner first, all three runs without the restarts.

**Not tested:** a user without administrator rights on a real Windows,
where the stand-in has to do; entries of a second user who is logged on at
the same time; a task whose rights were changed after it was registered;
a service of a kind other than its own process, such as a driver or a
service in a shared host, on a real Windows.

Measured numbers are in
[BENCHMARKS.md](BENCHMARKS.md#the-look-at-autostart-entries).

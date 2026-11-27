# The quarantine

A quarantined file is out of harm's way and not lost. It is gone from its
place, it lies in the quarantine in a form that cannot be run, and it can
be put back exactly as it was: the same bytes, the same timestamps, the
same owner and access rights.

The second half matters as much as the first. A scanner is wrong now and
then, and this one says so in its own
[false-positive runs](BENCHMARKS.md#false-positives). Whoever quarantines a
file by mistake has to be able to undo it without a trace, or they will not
dare to quarantine anything.

The code is the crate `warden-quarantine`. This document says what it
does, what it does when it is interrupted, and what it does not do yet.

## What it looks like

```text
> warden quarantine add files/report.txt --reason "trying it out"
Quarantined  /tmp/qtrial/files/report.txt
  entry      40425e45425cdc2b
  sha256     e75abf67266a5bb7fdc0724872be882a0058795a27bba69fe4734f86f3787d49 (20 bytes)
`warden quarantine restore <entry>` puts a file back. The first few characters of the entry are enough.

> warden quarantine list
Quarantine  /tmp/qtrial/q
1 entry

  40425e45425cdc2b  2026-11-18T23:21:50Z  20 bytes
    /tmp/qtrial/files/report.txt
    reason: trying it out

> warden quarantine info 4042
Entry        40425e45425cdc2b
Quarantined  2026-11-18T23:21:50Z
Was at       /tmp/qtrial/files/report.txt
Size         20 bytes
SHA-256      e75abf67266a5bb7fdc0724872be882a0058795a27bba69fe4734f86f3787d49
Modified     2021-03-04T05:06:07Z and 500,000,000 ns
Last read    2021-03-04T05:06:07Z and 500,000,000 ns
Created      2026-11-18T23:20:14Z and 795,113,737 ns
Permissions  0640, user 0, group 0
Reason       trying it out
Made by      Warden 0.1.0
Kept in      /tmp/qtrial/q/items/40425e45425cdc2b.wq

> warden quarantine restore 4042
Restored  /tmp/qtrial/files/report.txt
  sha256  e75abf67266a5bb7fdc0724872be882a0058795a27bba69fe4734f86f3787d49 (20 bytes), as recorded
  Its timestamps and permissions are what they were.
  The time it was made is the exception: this system gives a file that time itself, so it is the time of the restore.
```

That is Linux, where the commands were run for this page. On Windows the
last line does not appear, because Windows lets a program set the time a
file was made.

| Command | What it does |
|---|---|
| `warden quarantine add <file>...` | Moves files into the quarantine. `--reason` keeps a note with the entry. On Windows, what starts a file goes with it |
| `warden quarantine list` | Lists the entries, oldest first, and entry files that cannot be read. `--json` prints the records |
| `warden quarantine info <id>` | Shows everything that is recorded about one entry |
| `warden quarantine restore <id>` | Puts the file back and removes the entry. `--to <path>` puts it somewhere else; `--overwrite` replaces a file that is in the way. On Windows, what started the file comes back with it |
| `warden quarantine delete <id>...` | Removes entries for good |

An entry is named by its identifier, sixteen hexadecimal digits, or by
enough of its start to tell it apart, the way git names commits.

The quarantine is a folder. By default it is
`%LOCALAPPDATA%\Warden\Quarantine` on Windows and
`$XDG_DATA_HOME/warden/quarantine` elsewhere (`~/.local/share/...` if that
variable is not set). `--dir` or the environment variable
`WARDEN_QUARANTINE` names another one.

## What an entry is

One file per quarantined file, `items/<identifier>.wq`:

| Offset | Size | What |
|---|---|---|
| 0 | 8 | Signature: `WRDNQRT` followed by a zero byte |
| 8 | 4 | Format version, little-endian: 1 |
| 12 | size of the file | The file's content, under the cipher |
| then | n | The record, as JSON |
| then | 32 | SHA-256 of the record |
| then | 8 | n, little-endian |
| then | 8 | Signature of the end: `WRDNQEND` |

The record comes last so that a file is read once on its way in. Its size
and its SHA-256 are known only when the last byte has been read, and
reading it a second time would leave room for it to change in between. A
file that does not end in the closing signature was cut short. That is how
an entry that was being written when the program died is told from a
finished one.

The record of the entry above:

```json
{
  "id": "40425e45425cdc2b",
  "quarantined_unix_ms": 1795044110598,
  "original_path": "/tmp/qtrial/files/report.txt",
  "size": 20,
  "sha256": "e75abf67266a5bb7fdc0724872be882a0058795a27bba69fe4734f86f3787d49",
  "cipher": {
    "algorithm": "chacha20",
    "key": "c7cbd7f45ae4ab943aca8c6414850f814125d03916cb05de2ca6321c67da96e1",
    "nonce": "e390dd2619e7305d4c2182f8"
  },
  "times": {
    "modified": { "secs": 1614834367, "nanos": 500000000 },
    "accessed": { "secs": 1614834367, "nanos": 500000000 },
    "created": { "secs": 1795044014, "nanos": 795113737 }
  },
  "unix": { "mode": "0640", "uid": 0, "gid": 0 },
  "reason": { "note": "trying it out" },
  "warden_version": "0.1.0"
}
```

(Printed by `warden quarantine info 4042 --json`, with the timestamps drawn
together to one line each.)

An entry made on Windows has `windows` in place of `unix`: the attribute
bits, the security descriptor and, if the file had one, the content of its
`Zone.Identifier` stream. A path that is not valid Unicode is kept twice:
readable, with the odd parts replaced, and exact, so that the file can go
back under the name it had.

### What the cipher is for

The key is in the record, right behind the content it opens. The cipher
keeps nothing secret. It makes sure that the bytes on disk are not the
file:

- they cannot be started, by a person or by anything else;
- a resident antivirus does not find the threat a second time and remove
  the quarantine's copy, which would turn "can be put back" into a claim;
- a search indexer or a backup tool that reads the folder does not pick up
  the content.

Each entry has a key of its own, 32 random bytes from the operating system,
so two entries with the same content do not look alike either. The cipher
is ChaCha20, from the RustCrypto project. The test suite checks the claim
with the EICAR test file: a scan of the folder where it lay finds nothing
once it is quarantined, a scan of the quarantine folder finds nothing, and
after the restore the file is detected again and has its old hash.

## Interruptions

Moving a file takes three steps that cannot happen at once: write the
copy, give the copy its final name, remove the original. Putting it back
is the same three in the other direction. The program can die between any
two of them, and the machine can go down.

So before the first step a note of the intention goes into a journal, one
small file per operation. When the quarantine is next opened, by any
command, every note that is still there is settled from what is on disk:

| The program died | What the next command finds | What it does |
|---|---|---|
| while quarantining, before the copy had its final name | The file at its place, and a half-made copy | Removes the half-made copy. **Undone**: the file is where it was |
| while quarantining, after the copy had its name | A whole entry, and the file still at its place, unchanged | Removes the file. **Finished**: what was asked for was a file out of harm's way |
| the same, and something else has the file's place by now | A whole entry, and another file | Touches neither, and says so |
| while restoring, before the file had its name | The entry, and a half-written file under a temporary name | Removes the half-written file. **Undone**: the entry is still there |
| while restoring, after the file had its name | The file at its place, whole, and the entry | Gives the file what it gets last (see below), removes the entry. **Finished** |

"Unchanged" and "whole" are checked, not assumed: by size and SHA-256
against the record. The command says what it settled before it does its own
work:

```text
> warden quarantine list
note: Quarantining /tmp/qtrial2/files/suspect.bin had been cut off after the copy was safe. It was finished: the file is in quarantine as 0487fe826bab29e2.
Quarantine  /tmp/qtrial2/q
1 entry

  0487fe826bab29e2  2026-11-18T23:21:50Z  43 bytes
    /tmp/qtrial2/files/suspect.bin
```

At no point is the only copy of a file one that is incomplete. A copy gets
its final name only when all of it is written and on disk, and the original
is removed only after that, and only if it is still the file that was
copied: the same file, of the same size, not written to since. If it is
not, the copy is thrown away and the file stays, with a message.

Only one program has a quarantine open at a time; a second one waits. That
is what lets a note be read as left behind by a run that died, and never as
the work of one that is still going.

### How that is tested, and what is not

The library has a switch for tests that stops an operation after any of
its steps and leaves everything the way a program that died there would.
The tests stop each operation after each step, open the quarantine again
and look at what was made of it. A property test does the same with random
content and random stopping points, for a file's way in and its way back,
and checks one thing: afterwards the file is whole and in exactly one
place, never lost and never there twice.

That is a program that dies between two steps. A note that was itself cut
short is covered too. What a power cut does to data that the system had
not written to the disk yet is **not** tested. The code asks for every
file to be on disk before it goes on, and on Unix for the folder entry as
well; whether a given disk keeps that promise is outside its reach.

## What comes back

| | |
|---|---|
| Content | Checked against the recorded SHA-256 while it is written. A file that does not pass never appears under its real name |
| Timestamps | Last change and last read, as exactly as the system keeps them: to the nanosecond on Linux, in steps of 100 ns on Windows. The time the file was made on Windows only |
| Unix | Owner, group and permission bits, including set-user-id and its relatives |
| Windows: attribute bits | Read-only, hidden, system, "archive" and "not indexed" |
| Windows: access rights | The security descriptor: owner, group and access-control list, and whether the list takes entries from the folder |
| Windows: the mark of the internet | The `Zone.Identifier` stream of a downloaded file |

The last one is there because of what a quarantine is for. Windows marks a
file that came from the internet and asks before it runs one. A restore
that lost the mark would hand back a file that Windows trusts more than
before it was quarantined.

What could not be put back is said, one sentence each, and does not stop a
restore: the content is what matters most. Setting the owner back to
somebody else, for one, takes a privilege that an ordinary user does not
have.

**Not kept**: extended attributes, other named streams, the compressed and
encrypted states of NTFS, and hard links. A file that had other names keeps
them; only the name that was given is removed. The "archive" bit, which
Windows sets on every file that is written, is set on a restored file
whether the original had it or not.

### The order of things on Windows

A restored file is written under a temporary name next to its destination
and gets its own name in one step, so it appears whole or not at all. What
it has besides its content goes on in two parts around that step.

Before it: the mark of the internet and the timestamps. They have to be
there the moment the file appears.

After it: the read-only bit and the access rights. Either can take away
what the step itself needs. A read-only file cannot be given another name.
And access rights can deny the user who restores the file everything but
reading it, if that is what the file had. So the file is created with a
handle that carries the rights to change its access rights and its owner,
and those are put back through that handle at the very end. A handle
keeps the rights it was opened with, whatever the file's access rights say
afterwards.

A test does exactly that: a file that its user may only read goes into the
quarantine and comes back, with a security descriptor that is the same
byte for byte, and can still only be read.

Reading and writing a security descriptor takes two functions of the
Windows API, `GetKernelObjectSecurity` and `SetKernelObjectSecurity`. They
work on the open file and not on its name: a name can be given to another
file between two looks at it. The three calls are the only `unsafe` code of
the crate. A descriptor is a block of bytes with offsets in it, and Windows
follows them, so a descriptor that comes out of a record is checked first,
offset by offset, in ordinary code that runs and is tested on every system.

## What starts the file

A file that Windows starts by itself has entries that say so: a value
under a Run key, a scheduled task, a service, a shortcut in the Startup
folder. `warden quarantine add` removes the entries that start the file
it takes, and `restore` puts them back. [REMEDIATION.md](REMEDIATION.md)
describes that part.

To the quarantine such entries are a record that it keeps with an entry.
Any part of Warden can attach a record to an entry, under a kind of its
own. A record is a file next to the entry's, written the way the entry is:
whole or not at all. It lives as long as the entry does. `delete` removes
it with the entry, and `restore` leaves it to whoever attached it, because
only they know what has to happen before it may go. The quarantine does
not read it.

A Startup shortcut is a file, so it goes into the quarantine as an entry
of its own, with a note that names the entry of the file it started.

## What it refuses

- **Anything but a regular file.** A folder is not quarantined, and a link
  is not followed: what would be moved is what has the name, not what it
  points to.
- **Replacing a file.** If something has taken the place of the
  quarantined file, restore stops and names `--to` and `--overwrite`. A
  folder or a link at that place is never replaced, with or without
  `--overwrite`.
- **A damaged entry.** One flipped bit in the content, and the file is not
  restored; nothing appears at the destination, not even for a moment. An
  entry whose record is damaged is listed as damaged, with what is wrong
  with it, and can be deleted by its whole identifier.
- **A record it does not understand in every part.** A field the format
  does not know is an error, not something to skip.

## The guard

A quarantined file can be put back, unless Windows needed it in order to
start: then there may be nothing left to put it back with. So two kinds of
file stay where they are: a file that Windows itself signed, and a driver
that Windows loads while it starts, whoever made it.

### Files of Windows

```text
> warden quarantine add C:\Windows\System32\ntdll.dll
error: C:\Windows\System32\ntdll.dll was left where it is: it is part of the operating system (signed for Microsoft Windows, found in the file itself)
Without a file of its own the system may not start, and then nothing is left to restore the file with. To quarantine such a file all the same, add --even-if-signed-by-windows.
```

- **What makes a file one of Windows** is its signature, by any of the
  three routes that [TRUST.md](TRUST.md#three-routes-to-a-signature)
  describes: in the file, in a catalogue of Windows, or in the signature of
  its package. Its place and its name say nothing. A copy of `ntdll.dll` in
  a download folder stays, and a file that somebody put into System32 does
  not.
- **Which signature** is for the trust list to say, not for the program:
  the entry for "Microsoft Windows" carries `operating_system = true`
  ([TRUST.md](TRUST.md#what-an-entry-holds)). Microsoft's applications,
  which are signed as "Microsoft Corporation", are not Windows and go into
  the quarantine like any other file.
- **Whether a certificate was revoked makes no difference here.** A scan
  lets a finding go only for a signature whose certificates were looked up.
  The guard is after the opposite mistake, so it does not ask for that: a
  file of Windows whose certificates cannot be looked up right now is still
  a file of Windows. It asks nothing over the network.
- **Not knowing is not a no.** If Windows could not be asked, or the file
  could not be read in a way that keeps it from changing meanwhile, the
  file stays too, and the message says that it could not be checked.
  Otherwise every file of Windows would pass whenever the check is out of
  order.
- **A changed file is nobody's.** With one byte more, no catalogue lists
  the content and no signature holds. Such a file is quarantined like any
  other.
- **The way past the guard** is a flag that has to be typed out,
  `--even-if-signed-by-windows`. The file is then taken, and the output has
  one line more, which says what was taken all the same:

  ```text
    although   it is part of the operating system (signed for Microsoft Windows, found in the file itself)
  ```

- **The content the guard looked at is the content that goes.** The guard
  says which SHA-256 it saw. If the file has another by the time it is
  copied, it stays, as any file does that changes on the way.

### Drivers that Windows loads while it starts

Windows can need a driver of another maker in order to start: one for the
disk it is on, say. Microsoft signs such drivers under a name of their
own, which is not the name of Windows, so the first guard lets them pass.
A second one does not. It is not about who made the file. It is about what
Windows does with it.

A test on the hosted Windows runner registers a harmless file as such a
driver, with `sc`, and asks for the file. The path is shortened here:

```text
> warden quarantine add wardentest.sys
error: C:\...\wardentest.sys was left where it is: Windows loads it as the driver WardenTestBootDriver while it starts
Without a driver that it loads while it starts, Windows may not start, and then nothing is left to restore the file with. To quarantine such a file all the same, add --even-if-loaded-at-boot.
```

- **Which drivers.** Those whose entry in the registry says that the
  loader reads them in together with the kernel, before anything else
  runs: a driver with the start "boot". Windows has four more starts for a
  driver, and none of them counts here: when the system comes up, by the
  service manager, on demand, never.
- **Which file.** The one that the driver's entry names by its full path,
  in any of the ways Windows writes that path. It is the same look at what
  starts programs that finds the entries of a file, see
  [What starts the file](#what-starts-the-file).
- **Whoever made it.** A driver of Windows is covered twice. A driver
  that came with a program is covered by this alone, and so would be a
  driver that malware has registered. That is what the flag is for.
- **The way past it** is a flag of its own, `--even-if-loaded-at-boot`.
  The flag for files of Windows does not open this guard, and a file that
  both would leave needs both. The file is then taken, and its entry with
  it, as for any file: Windows then no longer looks for the driver when it
  starts, and a restore puts the entry back.

  ```text
    although   Windows loads it as the driver WardenTestBootDriver while it starts
    removed    the driver WardenTestBootDriver
  ```

### Where the guards sit

Both sit in the quarantine itself, at the one place that every file
passes on its way in. The quarantine does not know what a signature or a
driver is. It asks a `Guard` that whoever opens it has given it, the way
the scan engine asks a trust check. `warden` gives it one that is made of
two: the first asks `warden-trust`, the second the look at what starts
programs. Whatever quarantines files later, the service or a scan, gets
the guard without having to think of it. Going past it is a call of its
own, `add_with` with `overrule_guard`; the command-line program instead
leaves out the guard that a flag was given for, and still asks it, so
that it can say what was taken all the same.

What the two guards do not cover:

- **Files of Windows that are no executables.** A catalogue is asked about
  executables only, so a data file of Windows is not recognised, unless it
  is part of a package that Windows signed.
- **A driver whose entry names no file.** Windows then loads the file of
  the driver's name from its drivers folder, and the look at what starts
  programs does not see such an entry. Drivers that come with Windows can
  be like that, and those the first guard knows by their signature.
- **Drivers with another start, and services.** Windows can also be set
  to stop when one of those fails to start. The second guard does not
  look at that setting.
- **Systems that are not Windows.** Nothing can be checked there, and there
  is nothing to guard.

## What is not there yet

| | Comes with |
|---|---|
| A quarantine for the whole machine, in a folder that ordinary users cannot read. Today it is a folder of the user who runs Warden, used with that user's rights | The Windows service (phase 6) |
| Refusing to restore, on behalf of a user, to a place that user could not write to. A program with more rights than its user that restores through a link into a system folder is how antivirus products have been turned into a way of planting files. With the user's own rights there is nothing to gain | The Windows service (phase 6) |
| Quarantining a file that is in use. Windows does not let the file of a running program be removed, so today `add` fails for it: the copy is taken out of the quarantine again, and the error says that the file could not be removed. Stopping the program first takes the rights of a service | The Windows service (phase 6) |
| Quarantine as the consequence of a scan. Today a person names the file | Later phases. The [guards](#the-guard) that had to come first are there |

## Tests

[TESTING.md](TESTING.md#the-quarantine) lists them: what runs everywhere,
what runs on Windows only, and how the Windows code is checked when it
cannot be built anywhere else.

# YARA rules

The second detection layer runs YARA rules over file content. This document
covers what the layer does, where its rules come from, which rules are left
out and why, how a rule match becomes a verdict, and the rule bundle file
format.

The engine underneath is [YARA-X](https://virustotal.github.io/yara-x/),
VirusTotal's implementation of YARA in Rust. The layer lives in the
`warden-yara` crate.

## Why a second layer

A hash signature matches one exact file. Add a line break and the hash is a
different one. A YARA rule describes byte patterns and file structure
instead, so it keeps matching when a file has been changed, repacked or
rebuilt. The price is speed: every rule has to be checked against every
byte, where a hash lookup is a few dozen nanoseconds.
[BENCHMARKS.md](BENCHMARKS.md) has the measurements.

Warden shows the difference with the EICAR test file. The plain 68-byte
file is known by hash. The same file with a line break added has another
hash and is caught only by the built-in rule:

```
warden eicar write demo --kind all
warden scan demo
```

## Where rules come from

**Built in.** One rule ships inside the program:
[`crates/warden-yara/rules/builtin.yar`](../crates/warden-yara/rules/builtin.yar).
It detects the EICAR test file by its definition: the 68 characters at the
start of the file, followed by nothing but whitespace, 128 bytes at most.
Built-in rules cover test files only.

**Rule bundles.** Everything else comes from rule files you choose.
`warden rules build` compiles them into a bundle, and `warden scan --rules`
uses it:

```
warden rules build my-rules.yar a-folder-of-rules\ a-package.zip --out rules.wrb
warden rules info rules.wrb
warden scan C:\Users\me\Downloads --rules rules.wrb
```

A rule that does not compile is left out and counted; it does not stop the
build. `--show-skipped` lists the rules that were left out with the reason.
The built-in rules are part of every bundle unless `--no-builtin` is given,
so a scan with a bundle catches everything a scan without one does.

### Other people's rules are not in this repository

Public rule sets belong to their authors and carry their own licences, some
of which restrict redistribution or commercial use. Warden therefore ships
none of them. The repository holds a pointer instead,
[`rules/yara-forge.pin`](../rules/yara-forge.pin): one release of
[YARA Forge](https://yarahq.github.io/), named by tag and SHA-256. YARA
Forge collects public rule repositories, filters them by quality, and
publishes the result as packages. Warden uses the "core" package, which
YARA Forge describes as leaving out rules that are prone to false positives
or slow.

```
scripts\win\check.cmd -Rules                                  (Windows: fetch, build and test)
bash scripts/fetch-rules.sh                                   (Linux)
warden rules build rules/vendor/yara-forge-rules-core.zip --exclusions rules/exclusions.toml --out rules/vendor/rules.wrb
```

The fetch scripts refuse a download that does not match the pinned
checksum. `warden rules info` lists the licences that the rules in a bundle
name, so you can see what you are running. For the pinned release, built
with the exclusion list described below:

| | |
|---|---|
| Release | 20261018 |
| Rules in the package | 5,137, all of which compile |
| Left out by the exclusion list | 10 |
| Rules in the bundle | 5,128: 5,127 from the package, plus the built-in rule |
| Repositories the package draws on | 35 |
| Rules that name a licence | 3,078 |
| Rules that name none | 2,050 |
| Reported as malicious (score 80 and above) | 205 |
| Reported as suspicious (score 60 to 79) | 4,923 |

### Rule files and your antivirus

A rule file is full of the byte patterns of the malware it describes; that
is what it is for. Microsoft Defender takes the YARA Forge package for the
real thing. On a Windows 11 desktop with real-time protection on, the
download was blocked the moment it was written, with the message "the file
contains a virus or potentially unwanted software". The hosted CI machines
run without real-time protection, so the package arrives there.

The remedy is the one used for the EICAR test folder: exclude one dedicated
folder, knowingly, and nothing more. That folder is `rules\vendor`. The
scripts keep the downloaded package and the bundle built from it there, so
one exclusion covers both, and the folder holds nothing else. From a
PowerShell window opened as administrator, in the repository:

```powershell
Add-MpPreference -ExclusionPath "$PWD\rules\vendor"
```

To undo it:

```powershell
Remove-MpPreference -ExclusionPath "$PWD\rules\vendor"
```

The scripts never do this for you. When the package is blocked, the Windows
fetch script says so and prints these two commands with the full path. With
the folder excluded, the download, the build of the bundle and a scan of
System32 with it ran through on the same machine.

Whether Defender also objects to a compiled bundle outside that folder has
not been tried.

## Rules that are left out

Public rules flag clean files now and then. With all 5,137 rules of the
pinned package, Warden reported 22 of 137,155 clean files in Windows system
folders and a CI runner's software as suspicious, and two rules accounted
for all 22. In the installed programs of a desktop, eight more rules
flagged 13 of 310,849 files ([BENCHMARKS.md](BENCHMARKS.md) has the runs).
A scanner that calls a system library suspicious teaches its user to ignore
it, so those ten rules are left out. Which rules, and on what evidence, is
written down in one file:
[`rules/exclusions.toml`](../rules/exclusions.toml).

They are of three kinds.

**Generated from malware samples, and matching library code.** These four
come from a tool that picks code sequences out of the samples of one
malware family. Each asks for seven of its ten sequences. If the samples
carry a common library, some sequences are that library's, and other
programs built with the same library can have them too.

| Rule | What it flagged |
|---|---|
| `MALPEDIA_Win_Triback_Loader_Auto` | `vulkan-1.dll` in System32 of a GitHub-hosted Windows runner, and `liblouis.dll`, a braille library, in System32 of a Windows 11 desktop |
| `MALPEDIA_Win_Bqtlock_Auto` | `libstdc++-6.dll`, the GNU C++ runtime library, in Git for Windows (two copies) |
| `MALPEDIA_Win_Mystic_Stealer_Auto` | `zip.dll` and `unpack200.exe` of the Java runtime. At least three of the rule's sequences are zlib's compression code |
| `MALPEDIA_Win_Yokai_Auto` | `ucrtbased.dll`, the debug build of Microsoft's C runtime, in two places of the Windows SDK |

**Recognising a tool, not malware.** These four describe how a program was
packaged or protected. That is true of the files they flag, and it says
nothing against them.

| Rule | What it recognises | What it flagged |
|---|---|---|
| `COD3NYM_DOTNET_Singlefilehost_Bundled_App` | A way of packaging .NET programs. Its author gave it no score, the package fills in 75, and that makes every match suspicious | All 20 copies of `singlefilehost.exe` in the .NET SDK of a GitHub-hosted Windows runner |
| `DITEKSHEN_INDICATOR_TOOL_UAC_NSISUAC` | A plug-in of the NSIS installer builder | The uninstallers of two versions of FL Studio |
| `COD3NYM_SUSP_OBF_NET_Reactor_Indicators_Jan24` | .NET Reactor, a commercial obfuscator | Two files of a commercial .NET application; not named, see below |
| `CAPE_Obfuscar` | Obfuscar, an open-source obfuscator for .NET programs | A library of a small .NET utility; not named, see below |

**Asking for too little.** These two ask for a few common strings and
little else.

| Rule | What it asks for | What it flagged |
|---|---|---|
| `SECUINFRA_SUSP_Powershell_Download_Temp_Rundll_1` | `$Env:temp`, `downloadfile(` and `rundll32.exe` anywhere in a file of any kind and size | `node_modules.asar` of Visual Studio Code, a 55 MB archive of JavaScript |
| `COD3NYM_SUSP_NET_Shellcode_Loader_Indicators_Jan24` | Three of six names of Windows memory and thread functions in a .NET program | `Clipchamp.Widgets.exe`, part of the video editor that Microsoft ships with Windows 11 |

### What an entry holds

```toml
[[rule]]
name = "MALPEDIA_Win_Triback_Loader_Auto"
reason = "Generated automatically from samples of one malware family. ..."
source = "malpedia/signator-rules (yara-signator v0.6.0), through the YARA Forge core package 20261018"

[[rule.evidence]]
file = 'C:\Windows\System32\vulkan-1.dll'
sha256 = "591d4c316a0a39f96792979ce5ebb1bb380f0015c30707ba7ac611b35ae01cfc"
seen = 2026-11-18
machine = "GitHub-hosted Windows runner (Windows Server 2025)"
```

The rule's name, the reason, and at least one piece of evidence: a clean
file the rule flagged, that file's SHA-256, the day, and the machine. An
entry without evidence is refused, and so is a field the format does not
know, so that a misspelt field is not skipped unnoticed. With the hash,
anyone who has the same file can repeat the observation.

There is one exception. The name and the hash of a file can give away
something private, such as which programs are installed on the machine of
the person who ran the scan. Evidence may then describe the file by its
kind and say why the rest is withheld:

```toml
[[rule.evidence]]
file = "the main program of a commercial .NET application protected with .NET Reactor"
withheld = "The name and the hash would show which programs are installed on a private machine."
seen = 2026-11-18
machine = "Windows 11 desktop"
```

One of `sha256` and `withheld` has to be there, and never both. Evidence
like this is weaker: nobody else can check it. Two entries rest on it
alone, the two obfuscator rules in the table above. What carries those
entries is the rule text, which anyone can read: each recognises a
protection tool that ordinary software uses, and says so in its
description.

### How a rule gets on the list

1. A false-positive run flags a file in a folder of clean software. The
   runs are described in [TESTING.md](TESTING.md).
2. Someone reads the rule and looks at the file: what the file is, where it
   came from, and what in it the rule matches.
3. If the file is clean and the rule cannot tell it from its target, the
   rule gets an entry with the evidence.
4. The bundle is built again and the run repeated, and both results go into
   [BENCHMARKS.md](BENCHMARKS.md).

"Clean" rests on where the files were found. Those on the GitHub runner sat
in the Windows system folder and the .NET SDK folder of a machine image
that is built fresh from installers. `liblouis.dll` sat in the system
folder of a desktop in daily use with Microsoft Defender on. The files
from that desktop's installed programs belong to Git for Windows, Oracle's
Java runtime, Microsoft's Windows SDK, Visual Studio Code and Clipchamp,
and Image-Line's FL Studio, each in the folder its installer puts it in.
Nobody has checked their signatures: Warden cannot verify an Authenticode
signature yet. When it can, the signer belongs in the evidence.

### What the build does with it

`warden rules build --exclusions rules/exclusions.toml` takes each listed
rule out of the rule text before it reaches the compiler. `warden-yara`
finds the rule with the parser that YARA-X itself uses and puts a stub of
the same name in its place, which the compiler discards. Everything else in
the file stays as it was, byte for byte.

- A rule is found by name, in every rule file that declares it.
- **Rules that use a listed rule are left out as well.** They cannot work
  without it. The build lists them among the rules that were left out, with
  the rule they depend on as the reason. No rule of the pinned package uses
  any of the ten listed ones.
- **Some rules cannot be listed**, and the build stops if one is: the
  built-in rules, and `global` rules. A global rule narrows every other rule
  in its file, so without it all of those would match more than their
  authors meant.
- **A name that matches no rule is reported.** That brings a misspelt name
  to light, and an entry that a newer release of the rule set has made
  unnecessary.
- **The bundle records what happened**: the SHA-256 of the list it was
  built with, and the names of the rules that were taken out.
  `warden rules info` shows both, and a scan report counts the excluded
  rules next to the rules it used. The SHA-256 is that of the file, so
  `sha256sum rules/exclusions.toml` or `Get-FileHash` checks it.

### What it costs

A rule that is left out no longer finds what it was written for either.
Three of the four generated rules were the only ones in this rule set to
name their malware family; for the fourth, Mystic Stealer, two hand-written
rules remain. Nothing else in the rule set recognises Obfuscar, and for
.NET Reactor one rule remains, which looks for another trace of it. That
is the price of an entry, and the reason the list asks for evidence instead
of a feeling that a rule is noisy.

How much detection the ten entries cost is not measured. In every run so
far the ten rules flagged clean files and nothing else, but no run held a
file they were written for.

The list also only knows what somebody has scanned. Of the 5,137 rules in
the package, 1,622 are generated the way the first four were, and every
machine with other software on it is likely to find another one.

The gentler tool is to let such a rule count only together with a second
sign: its match alone would be recorded and would not change the verdict,
and it would make a file suspicious when another layer has something to
say about the file as well. Warden does not have that yet. It is scheduled
as the first piece of phase 4, see [ROADMAP.md](ROADMAP.md); the four
generated rules can then be tried without their entries.

## From a match to a verdict

Detectors report, a policy decides: that rule of the engine holds here too.

1. A rule states how much a match means with a `score` from 0 to 100 in its
   metadata. This is a convention of public rule sets, described in the
   [YARA Style Guide](https://github.com/Neo23x0/YARA-Style-Guide): 80 to
   100 for direct matches on malware and hack tools, 60 to 79 for
   heuristics and generic detections, lower for things that are only
   noteworthy.
2. The YARA layer turns the score into a confidence: 80 and above is high,
   60 to 79 is medium, anything lower is low. A rule without a score is
   treated as 75.
3. The engine's verdict policy turns the strongest confidence into a
   verdict: high is malicious, medium is suspicious, low changes nothing.

So a single match of a generic rule makes a file suspicious, which is shown
to the user and never acted on automatically. Only rules whose authors rate
them as direct matches make a file malicious. The thresholds are options
(`YaraOptions`), not constants.

Metadata that Warden reads from a rule:

| Field | Use |
|---|---|
| `score` | Confidence, as above |
| `threat_name` | The name the detection is reported under. Default: the rule's name |
| `category` | `malware` (default), `test_file` or `potentially_unwanted` |
| `description`, `author`, `reference` | Shown as the reasons for a detection |
| `license`, `license_url` | Listed by `warden rules info` |

A detection always says why. These are the lines the built-in rule
produces for the test file:

```
yara [test file]: YARA rule Warden_EICAR_Test_File matched: the EICAR antivirus test file, a harmless file that every scanner detects on purpose
yara [test file]: Patterns found: $first at offset 0x0, $second at offset 0x21
yara [test file]: Rule score 100 of 100, written by Vevang Technologies, see https://www.eicar.org/download-anti-malware-testfile/
```

When many rules match one file, the ten with the highest scores are listed
and the rest are counted.

## Limits

- **Time.** One file may take the rules 30 seconds. After that the scan of
  that file is given up and the file is listed as partially scanned, with
  the reason `timeout`.
- **Size.** Files larger than the content limit (128 MiB by default) are
  checked by hash only and listed as partially scanned, with the reason
  `too_large`.
- **Modules.** The build includes the YARA modules `pe`, `dotnet`, `elf`,
  `macho`, `lnk`, `hash`, `math`, `string`, `time` and `console`. Rules
  that need another module (`magic`, `cuckoo` and a few more) are left out
  of the bundle and counted.
- **Includes.** An `include` statement in a rule file is a compile error.
  The included file would be missing from the bundle's record of where its
  rules came from, and the exclusion list would not see the rules in it.
  Give the builder every rule file directly, or a folder of them.
- **One thread, one scanner.** A YARA-X scanner holds the state of the rule
  engine and cannot be shared. Each worker thread has its own; the compiled
  rules are shared.
- **Packed and encrypted content.** Rules see the bytes of a file as it is
  on disk. Warden unpacks zip archives and runs the rules over the members;
  it does not unpack executables that are packed or encrypted. That is what
  the next layer, PE heuristics, is for.

## The rule bundle format

A bundle (`.wrb`) is one file: a fixed header, a manifest that records
where the rules came from, and the compiled rules. All integers are
little-endian. This is version 1.

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | Signature: `WRDNRUL` followed by a zero byte |
| 8 | 4 | Format version: 1 |
| 12 | 4 | Header length: 96 |
| 16 | 4 | Flags: 0 |
| 20 | 4 | Number of rules |
| 24 | 8 | Creation time, seconds since the Unix epoch |
| 32 | 8 | Length of the manifest in bytes |
| 40 | 8 | Length of the compiled rules in bytes |
| 48 | 16 | Reserved: zero |
| 64 | 32 | SHA-256 of bytes 0 to 63 followed by the manifest and the rules |

The manifest follows the header and is UTF-8 JSON:

```json
{
  "engine": "yara-x 1.23.0",
  "sources": [
    {
      "name": "warden/builtin.yar",
      "sha256": "e157092d259c6412922c8fae43f4b90d47d426045d2b7ea1ce76e8002ec51cee",
      "bytes": 1844,
      "rules": 1,
      "skipped": 0
    },
    {
      "name": "yara-forge-rules-core.zip/packages/core/yara-rules-core.yar",
      "sha256": "7770d912c4b1f7ce67d3614abda9a96d9d9dd2b5207b30ae0b4e7ba96bbdb0f8",
      "bytes": 7879714,
      "rules": 5127,
      "skipped": 0,
      "excluded": 10
    }
  ],
  "exclusions": {
    "sha256": "the SHA-256 of the exclusion list",
    "rules": [
      "MALPEDIA_Win_Triback_Loader_Auto",
      "COD3NYM_DOTNET_Singlefilehost_Bundled_App",
      "...eight more"
    ]
  }
}
```

`sha256` and `bytes` of a rule file describe the file as it was given to the
builder, before listed rules were taken out. `excluded` is written only when
it is not zero, and `exclusions` only when the bundle was built with an
exclusion list. Both were added after version 1 was first written down. A
reader that does not know them ignores them, and a bundle without them
loads as before, so the version number did not change.

The compiled rules follow the manifest, in the form YARA-X serialises them.

When a bundle is opened, Warden checks in this order: the signature and
version, that the three lengths add up to the size of the file, the digest,
the manifest, that the bundle was built with the same YARA-X release as the
program, and that the number of rules matches the header. A file that fails
any check is refused as a whole.

Compiled rules load only in the YARA-X release that compiled them. A bundle
from another release is refused with the advice to build it again; the rule
files themselves stay valid.

### What the digest does and does not protect

The digest catches damage: a truncated download, a flipped bit. It does not
authenticate the bundle. Someone who can replace the file can write a
matching digest, and YARA-X's own documentation warns against loading
compiled rules from a source that is not trusted.

A bundle is therefore trusted in the same way as the program itself: it
must come from a place that only trusted users can write to. For the
command-line tool that is your own folder. For the service planned in phase
6 it is a folder that only the service and administrators can write to, and
phase 10 adds a signed manifest that covers the program, the signature
database and the rule bundle together.

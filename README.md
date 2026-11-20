# Warden

A Windows anti-malware scanner written in Rust.

Warden is a portfolio project by Vevang Technologies. It is built in phases,
each ending with something that can be run and tested. The aim is depth in
the scan engine, a clean architecture and measured results.

> **Status: phase 4 of 10.** The scan engine has three detection layers:
> hash matching, YARA rules, and heuristics that judge a Windows executable
> by its structure. It looks inside zip archives. A file can be moved into
> a quarantine and put back exactly as it was. Everything is driven from
> the command line: there is no GUI, no background service and no
> real-time protection yet. Warden is not a replacement for your
> antivirus; it runs next to Microsoft Defender.

## What works today

`warden scan` on a folder that holds the EICAR test file in three forms: as
it is, with a line ending appended, and inside a zip archive.

```
Warden 0.1.0

Scanned     3 files, 324 B in 1.6 ms
Speed       1,888 files/s, 0.2 MB/s on 2 threads
Signatures  1 built-in
Rules       1 built-in YARA rule
Archives    1 unpacked, 1 file inside (68 B)

3 detections

  MALICIOUS   EICAR-Test-File
    D:\a\warden\warden\testdata\eicar-zone\eicar-padded.com
    sha256 8b3f191819931d1f2cef7289239b5f77c00b079847b9c2636e56854d1e5eff71 (70 bytes)
    yara [test file]: YARA rule Warden_EICAR_Test_File matched: the EICAR antivirus test file, a harmless file that every scanner detects on purpose
    yara [test file]: Patterns found: $first at offset 0x0, $second at offset 0x21
    yara [test file]: Rule score 100 of 100, written by Vevang Technologies, see https://www.eicar.org/download-anti-malware-testfile/

  MALICIOUS   EICAR-Test-File
    D:\a\warden\warden\testdata\eicar-zone\eicar.com
    sha256 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f (68 bytes)
    hash [test file]: SHA-256 matches the EICAR antivirus test file, a harmless file that every scanner detects on purpose
    yara [test file]: YARA rule Warden_EICAR_Test_File matched: the EICAR antivirus test file, a harmless file that every scanner detects on purpose
    yara [test file]: Patterns found: $first at offset 0x0, $second at offset 0x21
    yara [test file]: Rule score 100 of 100, written by Vevang Technologies, see https://www.eicar.org/download-anti-malware-testfile/

  MALICIOUS   EICAR-Test-File
    D:\a\warden\warden\testdata\eicar-zone\eicar.zip
    sha256 483e573bb46d8ff69634d5c6672f1be44bef82a60c7231f8485c744b14ec7c55 (186 bytes)
    inside: eicar.com (68 bytes, sha256 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f)
      hash [test file]: SHA-256 matches the EICAR antivirus test file, a harmless file that every scanner detects on purpose
      yara [test file]: YARA rule Warden_EICAR_Test_File matched: the EICAR antivirus test file, a harmless file that every scanner detects on purpose
      yara [test file]: Patterns found: $first at offset 0x0, $second at offset 0x21
      yara [test file]: Rule score 100 of 100, written by Vevang Technologies, see https://www.eicar.org/download-anti-malware-testfile/
```

The first file is found by its hash and by a rule. The second has a
different hash, so only the rule finds it. The third is found after
unpacking, and the finding says where inside the archive it is.

That is output from Windows: the CI run for phase 2, in which the check
script wrote the three files and scanned them. (Since phase 3 the header
has one more line, for the heuristics.) Screenshots arrive with the desktop
app.

The third layer judges files that no signature and no rule knows.
`warden inspect` shows what it sees in one file, here an inert test file
that is built like a packed loader:

```
Indicators that add to the score
   +10  A section is both writable and executable: sections "UPX0", "UPX1"
    +9  An executable section looks compressed or encrypted: section "UPX1" has an entropy of 7.99 bits per byte
    +5  A quarter of the file or more sits after the last section: 16384 of 33280 bytes come after the last section
    +8  The program imports nothing: the import table is empty or missing
    +5  The header holds no checksum: the checksum field is zero
    +4  The program has no resources: the header points to no resource table

Score       41
Verdict     suspicious: a file counts as suspicious from a score of 32
```

(Shortened: every line comes with an explanation.) The weights are not
guesses. They are fitted to the 2.3 million labelled files of the training
weeks of the public EMBER2024 dataset, and a test fails if the code and the
data disagree. [docs/HEURISTICS.md](docs/HEURISTICS.md) has the method, the
numbers, and what the layer cannot do.

A file that should be out of the way goes into the quarantine, and comes
back from it exactly as it was:

```
> warden quarantine add files/report.txt --reason "trying it out"
Quarantined  /tmp/qtrial/files/report.txt
  entry      40425e45425cdc2b
  sha256     e75abf67266a5bb7fdc0724872be882a0058795a27bba69fe4734f86f3787d49 (20 bytes)

> warden quarantine restore 4042
Restored  /tmp/qtrial/files/report.txt
  sha256  e75abf67266a5bb7fdc0724872be882a0058795a27bba69fe4734f86f3787d49 (20 bytes), as recorded
  Its timestamps and permissions are what they were.
```

(From Linux, and shortened by a line of advice each.) In between, the file
lies in the quarantine under a cipher, so that it cannot be started and no
other scanner trips over it. On Windows it comes back with its access
rights, its attribute bits and the mark that says it was downloaded. An
operation that is cut off is finished or undone the next time the
quarantine is opened; the tests stop every operation after every step,
the way a program that dies would. [docs/QUARANTINE.md](docs/QUARANTINE.md)
has the format, the reasoning and the limits.

| Command | What it does |
|---|---|
| `warden scan <path>...` | Scans files and folders in parallel, including the files inside zip archives. Exit code 0 means clean, 1 means something was detected, 2 means an error. `--rules <bundle>` adds a rule bundle, `--json` prints the full report. |
| `warden quarantine add` / `list` / `info` / `restore` / `delete` | Moves files into the quarantine, shows what is in it, puts a file back with its content, timestamps and permissions, or removes an entry for good. |
| `warden inspect <file>` | Shows what the heuristics see in one Windows executable: its sections, imports and header, every indicator that applies with its weight, the score and the threshold. |
| `warden rules build <path>... --out <file>` | Compiles YARA rule files, folders or a YARA Forge package into a rule bundle. `--exclusions <list>` leaves out rules that are known to flag clean files. |
| `warden rules info <file>` | Shows what a bundle holds: how many rules lead to which verdict, the rule files it was built from, the rules that were left out on purpose, the licences the rules name. |
| `warden false-positives <path>...` | Scans files that are expected to be clean and lists every one that was flagged. |
| `warden sigdb build` | Builds a signature database from lists of SHA-256 hashes. |
| `warden sigdb info` / `lookup` | Inspects a database, or looks up one hash. |
| `warden bench <folder>` | Measures scan throughput: files/sec and MB/sec over several runs. |
| `warden hash <file>...` | Prints SHA-256 digests. |
| `warden eicar write <dir>` | Writes the harmless EICAR test file in three forms, for demos. |

Every command has `--help`.

## Building

You need [Rust](https://rustup.rs) and, on Windows, the Visual Studio Build
Tools with the "Desktop development with C++" workload. The compiler version
is pinned in `rust-toolchain.toml`; `rustup` fetches it on first use.

```
cargo build --release
cargo run --release -- scan C:\some\folder
```

The program itself is `warden.exe` in cargo's target folder, which is
`target\release\` unless you have configured another one.

On Windows, `scripts\win\check.cmd` builds Warden, checks EICAR detection,
runs the test suite and measures scan speed in one go.

### Trying the EICAR detection

EICAR is a harmless 68-byte file that every antivirus product detects on
purpose. Microsoft Defender will remove it before Warden can scan it, unless
the folder is excluded. [docs/TESTING.md](docs/TESTING.md) explains how to
exclude one dedicated folder, and how to undo it.

```
warden eicar write testdata\eicar-zone
warden scan testdata\eicar-zone
```

### Scanning with a real rule set

Warden ships one YARA rule, the one for the EICAR test file. Real rule sets
are not stored in this repository, because their rules belong to their
authors. The scripts below download one pinned release of the
[YARA Forge](https://yarahq.github.io/) core package, about 5,100 rules
collected from 35 public repositories, and check its SHA-256.

```
powershell -ExecutionPolicy Bypass -File scripts\win\fetch-rules.ps1
warden rules build rules\vendor\yara-forge-rules-core.zip --exclusions rules\exclusions.toml --out rules\vendor\rules.wrb
warden scan C:\some\folder --rules rules\vendor\rules.wrb
```

On Linux the first line is `scripts/fetch-rules.sh`. On Windows,
`scripts\win\check.cmd -Rules` does all of this and then counts false
positives in the System32 folder. [docs/RULES.md](docs/RULES.md) explains
how a rule's score becomes a verdict.

Public rules flag clean files now and then, and Warden has two answers.
About 1,600 of the package's rules were generated by a tool from malware
samples, and such a rule also matches library code that those samples
share with clean software. Its match counts only together with a sign
from another layer; alone it is kept on record and changes nothing. For a
rule that is wrong in a way of its own,
[`rules/exclusions.toml`](rules/exclusions.toml) names the rules that
Warden leaves out, each with the evidence: the clean file it flagged, that
file's SHA-256, the day and the machine.

Microsoft Defender blocks that package: a rule file is full of the byte
patterns it describes, and Defender takes it for the real thing. The fetch
script then names the one folder to exclude, `rules\vendor`, and
[docs/RULES.md](docs/RULES.md#rule-files-and-your-antivirus) has the
details.

## How detection works

Warden is a layered engine. Each layer exists to catch what the one before
it cannot.

| Layer | Phase | Catches | Weakness |
|---|---|---|---|
| Hash match | 1, done | Exact copies of known files | One changed byte evades it |
| YARA rules | 2, done | Patterns shared by a malware family | Packing hides the patterns |
| PE heuristics | 3, built | Executables nobody has seen that are built the way malware often is | Clean software is packed too; says little about libraries and .NET |
| ML classifier | optional | Statistical resemblance to known malware | Only as good as its training data |

Today's layers work like this:

1. A walker thread enumerates the folders. It does not follow links, and it
   does not download cloud-only files.
2. Worker threads read every file exactly once and compute its SHA-256.
3. The hash is looked up in the signature database: a sorted table of
   digests with a 16-bit prefix index, memory-mapped and verified in full
   when opened. A lookup among a million entries takes tens of nanoseconds.
4. The YARA rules run over the same bytes. The rule engine is
   [YARA-X](https://virustotal.github.io/yara-x/); every worker thread has a
   scanner of its own, and the compiled rules are shared.
5. If the file is a Windows executable, the heuristic layer reads its
   structure with a reader written for hostile input, asks 43 yes-or-no
   questions about it, and adds up the weights of the 13 that are scored.
   A score of 32 or more makes the file suspicious, never malicious.
6. A zip archive is unpacked in memory and its members go through steps 3
   to 5, archives inside archives included. Limits on depth, member count,
   size and compression ratio keep a zip bomb from getting anywhere.
7. Every match becomes a finding with reasons attached: which hash or rule,
   where in the file, who wrote the rule, which indicators with which
   weights. A separate verdict policy turns the findings into clean,
   suspicious or malicious, so every detection can answer "why was this
   flagged?". Some findings count only together with a second sign from
   another layer; one that stays alone is kept on record, so "why was this
   not flagged?" has an answer too.
8. Files that could not be read, and files that could only be checked in
   part (too large, a password-protected member, a limit reached), are
   listed with the reason, never silently dropped.

More in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md),
[docs/RULES.md](docs/RULES.md), [docs/HEURISTICS.md](docs/HEURISTICS.md),
[docs/QUARANTINE.md](docs/QUARANTINE.md) and
[docs/SIGDB_FORMAT.md](docs/SIGDB_FORMAT.md).

## What Warden is not

- **Not a match for a commercial product's detection quality.** That quality
  comes from a research team and telemetry, not from engine design. Warden's
  signatures come from public feeds.
- **Not able to block a file before it runs.** That needs a kernel driver,
  which cannot be distributed without Microsoft's signature. Real-time
  protection, when it arrives, will detect and respond.
- **Not protected against an administrator.** User-mode self-protection
  stops unprivileged tampering, nothing more.

## Testing without malware

Warden is developed without writing, generating, modifying or handling live
malware. Tests use the EICAR file, harmless generated fixtures, published
detection rules and a public dataset that holds features and labels of
files, not the files.

One consequence is stated plainly wherever numbers appear: detection rates
on live samples are **not measured**, by design. What is measured is scan
speed, false positives on clean files, and how the heuristic score does on
the labelled feature records of the EMBER2024 dataset. See
[docs/TESTING.md](docs/TESTING.md).

## Benchmarks

[docs/BENCHMARKS.md](docs/BENCHMARKS.md) has the numbers and how they were
produced. In short, as of phase 4:

- **Speed.** A 16-thread desktop with Microsoft Defender running scans its
  System32 folder (27,646 files, 10 GB) from the file cache in 8 seconds
  with the default layers, heuristics included, and in 22 seconds with
  5,132 YARA rules as well. On two cores of a cloud container, a 7 GB Linux
  tree of small files runs at 800 MB/s with hash matching alone and at
  52 MB/s with the 5,138 rules of the full rule package; those two figures
  are from phase 2.
- **False positives of the heuristic layer:** none in 447,994 files that
  were expected to be clean, on a GitHub-hosted Windows runner and on a
  Windows 11 desktop in daily use, the 310,849 files of the desktop's
  installed programs included. (It judges the executables among them.)
- **False positives of the public YARA rules:** in the first runs, ten
  rules flagged 35 clean files among about 448,000 on the two machines,
  all as suspicious and none as malicious. Six of the ten are on
  the [exclusion list](rules/exclusions.toml), each with its evidence.
  The other four were generated by a tool, and for rules of that kind the
  verdict policy changed in phase 4: a match counts only together with a
  second sign. With them back in the bundle, no file is flagged in 535,859
  on the runner, the desktop and a Linux tree. The twelve clean files that
  such rules match are on record with a clean verdict; four of them are
  files that no list knew. What the second sign costs in detection is not
  measured.
- **On a Windows 11 that was installed for the test**, with nothing else
  on it, the built-in rule and the heuristic layer flag none of 153,317
  files. The public rules have not run there yet. That machine's Defender
  blocks the rule bundle, as the desktop's does, and no script of this
  project changes an antivirus setting.
- **The heuristic score on EMBER2024**, on the twelve weeks it was not
  fitted to: it flags 24.6 % of the malicious Windows executables and
  0.0056 % of the benign ones (15 of 269,813). Among programs it is 29.6 %;
  among libraries and .NET assemblies it is 1 % and less. Of 4,868
  malicious files that no antivirus product detected when they first
  appeared, it flags none.
- **Detection rate on live malware:** not measured, by design.

## Roadmap

[docs/ROADMAP.md](docs/ROADMAP.md) lists every phase with its exit
criterion. Next, in phase 5: removing the autostart entries that point at
a quarantined file, and putting them back on restore, tried in a virtual
machine.

## Licence

No licence has been chosen yet. Until one is, all rights are reserved.

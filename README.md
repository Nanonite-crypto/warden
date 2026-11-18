# Warden

A Windows anti-malware scanner written in Rust.

Warden is a portfolio project by Vevang Technologies. It is built in phases,
each ending with something that can be run and tested. The aim is depth in
the scan engine, a clean architecture and measured results.

> **Status: phase 2 of 10.** The scan engine has two detection layers, hash
> matching and YARA rules, and looks inside zip archives. It is driven from
> the command line. There is no GUI, no quarantine and no real-time
> protection yet. Warden is not a replacement for your antivirus; it runs
> next to Microsoft Defender.

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
script wrote the three files and scanned them. Screenshots arrive with the
desktop app.

| Command | What it does |
|---|---|
| `warden scan <path>...` | Scans files and folders in parallel, including the files inside zip archives. Exit code 0 means clean, 1 means something was detected, 2 means an error. `--rules <bundle>` adds a rule bundle, `--json` prints the full report. |
| `warden rules build <path>... --out <file>` | Compiles YARA rule files, folders or a YARA Forge package into a rule bundle. |
| `warden rules info <file>` | Shows what a bundle holds: how many rules lead to which verdict, the rule files it was built from, the licences the rules name. |
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
warden rules build rules\vendor\yara-forge-rules-core.zip --out rules\vendor\rules.wrb
warden scan C:\some\folder --rules rules\vendor\rules.wrb
```

On Linux the first line is `scripts/fetch-rules.sh`. On Windows,
`scripts\win\check.cmd -Rules` does all of this and then counts false
positives in the System32 folder. [docs/RULES.md](docs/RULES.md) explains
how a rule's score becomes a verdict.

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
| PE heuristics | 3 | Signs of packing, injection and evasion | Legitimate software can look suspicious |
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
5. A zip archive is unpacked in memory and its members go through steps 3
   and 4, archives inside archives included. Limits on depth, member count,
   size and compression ratio keep a zip bomb from getting anywhere.
6. Every match becomes a finding with reasons attached: which hash or rule,
   where in the file, who wrote the rule. A separate verdict policy turns
   the findings into clean, suspicious or malicious, so every detection can
   answer "why was this flagged?".
7. Files that could not be read, and files that could only be checked in
   part (too large, a password-protected member, a limit reached), are
   listed with the reason, never silently dropped.

More in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md),
[docs/RULES.md](docs/RULES.md) and
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
detection rules and, later, public feature datasets.

One consequence is stated plainly wherever numbers appear: detection rates
on live samples are **not measured**, by design. What is measured is scan
speed, false positives on clean files and, from phase 3, detection rates in
feature space on the EMBER2024 dataset. See [docs/TESTING.md](docs/TESTING.md).

## Benchmarks

[docs/BENCHMARKS.md](docs/BENCHMARKS.md) has the numbers and how they were
produced. In short, as of phase 2:

- **Speed.** On two cores of a cloud container, a 7 GB Linux system tree is
  scanned from the file cache at 800 MB/s with hash matching alone, at
  640 MB/s with archives unpacked as well, and at 52 MB/s with 5,138 YARA
  rules on top.
- **False positives** with those 5,138 rules: none among 140,383
  files of the Linux tree. On a Windows CI machine, 1 of 21,804 files in
  System32 and 20 of 87,707 files of installed software were reported as
  suspicious, and none as malicious. The document names the two rules
  responsible.
- **Detection rate on live malware:** not measured, by design.

## Roadmap

[docs/ROADMAP.md](docs/ROADMAP.md) lists every phase with its exit
criterion. Next: heuristics for Windows executables.

## Licence

No licence has been chosen yet. Until one is, all rights are reserved.

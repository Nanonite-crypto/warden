# Benchmarks

Every number on this page comes from a run that is recorded in
`docs/benchmarks/` and can be reproduced with the commands shown.

## What is and is not measured

| Measured | Since |
|---|---|
| Scan throughput: files/sec and MB/sec | Phase 1 |
| Signature lookup and hashing speed | Phase 1 |
| What each detection layer costs in throughput | Phase 2 |
| False positives on clean files | Phase 2 |
| Detection and false-positive rates in feature space (EMBER2024) | From phase 3 |
| Real-time time-to-detect | From phase 9 |

**Not measured, by design:** detection rates on live malware samples. Warden
is built without handling live malware, so no such test set exists here.
See [TESTING.md](TESTING.md).

## Method

- **Throughput** is measured by `warden bench <folder> --runs N`, which runs
  complete scans of a real folder and reports each run. MB means 10^6 bytes.
- **First run versus repeat runs.** The first run of a benchmark reads
  whatever the operating system had not cached yet; repeat runs are served
  from the file cache and measure the engine itself. `warden bench` marks
  the first run and takes its median over the repeat runs only. Both are
  shown here. A rigorous cold-cache figure, taken after a reboot, is planned
  for the portfolio checkpoint.
- Benchmark result files marked `"schema": 1` were written before that
  split, so their median fields include the first run. The tables below are
  built from the individual runs.
- **False positives** are counted by `warden false-positives <folder>`,
  which scans files that are expected to be clean and lists every one that
  gets a verdict other than clean. Each result names the rule release it
  was produced with, because the count belongs to the rules as much as to
  the engine.
- **Micro-benchmarks** use Criterion (`cargo bench`) and report the
  estimate with its confidence interval.
- **Hardware is always stated.** Numbers from a shared CI runner or a cloud
  container say so, and are only indicative.
- On Windows, Microsoft Defender scans the same files as they are opened.
  That overhead is part of the measured time, because it is what a user
  would experience.

## Results: phase 1

Phase 1 has one detection layer (hash matching), so these figures are the
ceiling that later layers are measured against.

### Development container (Linux, 2 vCPU)

Intel Xeon @ 2.10 GHz, 2 virtual CPUs, 7 GB RAM, Linux 6.18. This is the
cloud container the engine was developed in, not a Windows machine.

**Scan throughput** over `/usr`: 140,383 files, 7.15 GB, nothing skipped.
`warden bench /usr --runs 3 --threads 1,2`

| Threads | Run | Time | Files/s | MB/s | Cache |
|---|---|---|---|---|---|
| 1 | 1 | 50.82 s | 2,762 | 140.7 | First read |
| 1 | 2 | 15.25 s | 9,208 | 469.1 | Warm |
| 1 | 3 | 15.18 s | 9,246 | 471.0 | Warm |
| 2 | 1 | 9.09 s | 15,444 | 786.7 | Warm |
| 2 | 2 | 8.57 s | 16,381 | 834.4 | Warm |
| 2 | 3 | 9.41 s | 14,913 | 759.6 | Warm |

Warm runs: about 9,200 files/s and 470 MB/s on one thread; a median of
15,444 files/s and 787 MB/s on two. Raw results:
[2026-11-18-dev-container-usr.json](benchmarks/2026-11-18-dev-container-usr.json).

**The same scan with a million signatures loaded.** The runs above used only
the built-in signature. To see what a realistic database costs, the scan was
repeated with a database of 1,000,000 random hashes.
`warden bench /usr --runs 3 --threads 2 --sigdb million.wdb`

| Threads | Run | Time | Files/s | MB/s |
|---|---|---|---|---|
| 2 | 1 | 9.34 s | 15,031 | 765.7 |
| 2 | 2 | 9.16 s | 15,324 | 780.5 |
| 2 | 3 | 9.23 s | 15,201 | 774.3 |

Median 15,201 files/s, against 15,444 without the database. The difference
is smaller than the spread between runs. Building that database from a text
list took 0.65 s, and opening it with full verification took 35 ms. Raw
results:
[2026-11-18-dev-container-usr-1m-signatures.json](benchmarks/2026-11-18-dev-container-usr-1m-signatures.json).

**Micro-benchmarks.** `cargo bench -p warden-sigdb -p warden-engine`

| Operation | Estimate | 95% interval |
|---|---|---|
| SHA-256, one thread | 1.59 GiB/s | 1.54 to 1.63 GiB/s |
| Signature lookup, hit, 1,000,000 entries | 64.4 ns | 63.8 to 65.1 ns |
| Signature lookup, miss, 1,000,000 entries | 27.7 ns | 26.5 to 29.1 ns |
| Open and fully verify a 1,000,000-entry database (36 MB) | 35.6 ms | 33.3 to 38.2 ms |

Raw output:
[2026-11-18-dev-container-micro.txt](benchmarks/2026-11-18-dev-container-micro.txt).

Reading the tables together: hashing alone runs at about 1.7 GB/s per
thread, while a warm scan reaches about 0.47 GB/s per thread. The difference
is per-file cost (opening, reading through the kernel, closing), which
dominates on a tree whose average file is 51 kB. Lookups are not a factor:
at 28 ns per miss, 140,383 of them add up to about 4 ms, which matches the
scan with a million signatures being no slower.

### GitHub-hosted Windows runner (indicative)

AMD EPYC 9V74, 2 logical processors, 8 GB RAM, Windows Server 2025
(10.0.26100), Microsoft Defender real-time protection off. This is the
shared virtual machine that ran CI for the phase 1 pull request, so these
figures are indicative only.

**Scan throughput** over `C:\Windows\System32`: 21,783 files, 4.71 GB, with
44 files skipped because they could not be read.
`warden bench C:\Windows\System32 --runs 2`, run by the Windows check
script

| Threads | Run | Time | Files/s | MB/s | Cache |
|---|---|---|---|---|---|
| 2 | 1 | 6 min 26 s | 56 | 12.2 | First read |
| 2 | 2 | 4.53 s | 4,814 | 1,057.1 | Warm |

The first run read at 12 MB/s. The same scan from the file cache took
4.5 seconds, so the first run was waiting for the runner's virtual disk,
not for the engine. Raw results:
[2026-11-18-github-windows-runner-system32.json](benchmarks/2026-11-18-github-windows-runner-system32.json),
machine:
[2026-11-18-github-windows-runner-machine.json](benchmarks/2026-11-18-github-windows-runner-machine.json).

Since that run, CI points the benchmark at a smaller folder, so that a
slow first read does not add minutes to every pull request. The results
are attached to each workflow run.

### Windows desktop

AMD Ryzen 7 5800X (8 cores, 16 threads), 32 GB RAM, Kingston SNVS1000G NVMe
SSD, Windows 11 Home (10.0.26300), Microsoft Defender real-time protection
on.

**Scan throughput** over `C:\Windows\System32` on 16 threads. The Windows
check script was run twice, three minutes apart.
`warden bench C:\Windows\System32 --runs 3`

| Started from | Files | Data | Could not be read | Pass | Time | Files/s | MB/s |
|---|---|---|---|---|---|---|---|
| File Explorer | 25,521 | 9.35 GB | 315 | 1, first read | 50.28 s | 508 | 186.1 |
| | | | | 2 | 9.06 s | 2,818 | 1,033.0 |
| | | | | 3 | 11.71 s | 2,180 | 799.1 |
| A terminal | 27,641 | 10.12 GB | 37 | 1 | 15.47 s | 1,787 | 653.9 |
| | | | | 2 | 8.37 s | 3,302 | 1,208.5 |
| | | | | 3 | 8.28 s | 3,337 | 1,221.4 |

- The second run read 2,120 more files and failed on 37 instead of 315.
  That is the difference administrator rights make in System32, so the
  terminal was almost certainly an elevated one. The check script did not
  record this at the time; it does now.
- The first pass of the second run was not a first read: most of the
  folder was still in the file cache from the run before.
- From the cache, this machine scans System32 at 0.8 to 1.2 GB/s.

Sixteen threads on this desktop are barely faster in warm passes than the
two threads of the CI runner above (1,057 MB/s). Defender inspects every
file that Warden opens here and did not on the runner, and the scanner may
not scale to 16 threads the way it does to two. The two effects have not
been separated yet: that takes a run with `--threads 1,2,4,8,16` on this
machine.

Raw results:
[first run](benchmarks/2026-11-18-windows-desktop-system32.json),
[second run](benchmarks/2026-11-18-windows-desktop-system32-administrator.json),
[machine](benchmarks/2026-11-18-windows-desktop-machine.json).

Both runs used the phase 1 build. In the first, Defender removed the EICAR
test file before Warden read it, which is what it should do, and the check
ended as incomplete. For the second, the test folder had been excluded
from Defender as [TESTING.md](TESTING.md#eicar-and-your-antivirus)
describes, and the check passed in full.

## Results: phase 2

Phase 2 added two things that take time: looking inside zip archives, and
YARA rules. The rule set used throughout is the YARA Forge core package,
release 20261018, compiled together with Warden's built-in rule: 5,138
rules. [RULES.md](RULES.md) describes it.

### Development container (Linux, 2 vCPU)

The same machine and folder as in phase 1: `/usr`, 140,383 files, 7.15 GB.
Two threads, median of the repeat runs.
`warden bench /usr --runs 3 --threads 2`, plus the switches in the table

| Configuration | Switches | Files/s | MB/s | Time taken, hash only = 1 |
|---|---|---|---|---|
| Hash only | `--no-yara --no-archives` | 15,707 | 800.1 | 1 |
| Hash and archives | `--no-yara` | 12,573 | 640.4 | 1.25 |
| Default: hash, the built-in rule, archives | none | 12,558 | 639.7 | 1.25 |
| Hash, archives, 5,138 rules | `--rules core.wrb` | 1,015 | 51.7 | 15.5 |

- **Archives** add a quarter to the scan time on this tree. 380 of its files
  are zip archives (document templates, Java archives, plain zips), and
  unpacking them adds 88,855 members and 361.9 MB to what is checked.
- **One rule** costs nothing that can be measured: the second and third
  rows differ by less than the spread between runs.
- **The full rule set** makes the same scan take 12 times as long as the
  row above it. This tree is mostly small files (51 kB on average), and
  every one pays for evaluating 5,138 rules: about 1.1 ms of processor time
  for each of the 229,238 files and archive members.

On larger files the picture is different. `/usr/bin` holds 901 files with an
average size of 783 kB:
`warden bench /usr/bin --runs 2 --threads 1,2 --rules core.wrb`

| Threads | Files/s | MB/s |
|---|---|---|
| 1 | 105 | 82.6 |
| 2 | 210 | 164.5 |

Two threads are 1.99 times as fast as one.

Raw results:
[hash only](benchmarks/2026-11-18-dev-container-usr-phase2-hash-only.json),
[hash and archives](benchmarks/2026-11-18-dev-container-usr-phase2-hash-archives.json),
[default](benchmarks/2026-11-18-dev-container-usr-phase2-defaults.json),
[5,138 rules](benchmarks/2026-11-18-dev-container-usr-phase2-yara-forge.json),
[5,138 rules on /usr/bin](benchmarks/2026-11-18-dev-container-usr-bin-phase2-yara-forge.json).

**Rule bundle.** Timed in the same container.

| Operation | Time |
|---|---|
| Compile 5,138 rules into a bundle (8.7 MB) | 2.2 s |
| Start, open that bundle, scan three small files | 0.73 s (median of 30) |
| The same with only the built-in rule | 7 ms |
| The same without YARA | 3 ms |

Opening the bundle is the 0.7 seconds: the rule engine rebuilds its search
structures from the stored rules. A command-line scan pays that every time.
The service planned for phase 6 pays it once. Raw figures:
[2026-11-18-dev-container-rule-bundle.txt](benchmarks/2026-11-18-dev-container-rule-bundle.txt).

### GitHub-hosted Windows runner (indicative)

Intel Xeon 6973P-C, 2 logical processors, 8 GB RAM, Windows Server 2025
(10.0.26100), Microsoft Defender real-time protection off. Hosted runners
are not all the same hardware: this is a different machine from the one in
phase 1, so the two sets of figures are not comparable with each other.

**Scan throughput** over `C:\Windows\System32\drivers`: 613 files, 157.1 MB,
with the default layers (hash, the built-in rule, archives).
`warden bench C:\Windows\System32\drivers --runs 3`, run by
`scripts\win\check.cmd`

| Threads | Run | Time | Files/s | MB/s | Cache |
|---|---|---|---|---|---|
| 2 | 1 | 2.38 s | 258 | 66.1 | First read |
| 2 | 2 | 114 ms | 5,396 | 1,382.6 | Warm |
| 2 | 3 | 91 ms | 6,706 | 1,718.1 | Warm |

**The same folder with 5,138 rules**, one pass with the files in the cache:
613 files in 2.78 s, which is 221 files/s and 56.6 MB/s on two threads.
Compiling the bundle took 1.6 s on this machine.

Raw results:
[benchmark](benchmarks/2026-11-18-github-windows-runner-phase2-drivers.json),
[the run with rules](benchmarks/2026-11-18-github-windows-runner-phase2-drivers-false-positives.json),
[machine](benchmarks/2026-11-18-github-windows-runner-phase2-machine.json).

## False positives

The rule set is the YARA Forge core package, release 20261018, with
Warden's built-in rule: 5,138 rules. A match of 205 of them leads to the
verdict malicious, a match of any of the other 4,933 to suspicious. The
tables count files with either verdict.

| Files expected to be clean | Files | Data | Files inside archives | Malicious | Suspicious |
|---|---|---|---|---|---|
| `C:\Windows\System32` on a GitHub-hosted Windows runner | 21,804 | 4.80 GB | 193 | 0 | 1 |
| Software installed on that runner: 7-Zip, Git, Chrome, Firefox, PowerShell, .NET, Node.js | 87,707 | 14.42 GB | 89,049 | 0 | 20 |
| `/usr` in the Linux development container | 140,383 | 7.15 GB | 88,855 | 0 | 0 |

No clean file was reported as malicious. 21 of the 109,511 Windows files
(0.019%) were reported as suspicious, and they come from two rules:

- **`MALPEDIA_Win_Triback_Loader_Auto`** flagged `System32\vulkan-1.dll`,
  the loader of the Vulkan graphics interface. The rule was generated by a
  tool from code sequences found in one malware family; 1,622 of the rules
  in the package were made that way. This is a plain false positive.
- **`COD3NYM_DOTNET_Singlefilehost_Bundled_App`** flagged all 20 copies of
  `singlefilehost.exe` in the .NET SDK. The rule's own description is
  "Detects single file host .NET bundled apps": it recognises a way of
  packaging a program, and Microsoft's host is that packaging itself. The
  package gives the rule a score of 75, like most of its rules, so Warden
  reports a match as suspicious.

What follows from this:

- The verdict that later phases will act on by themselves is malicious,
  and it stayed at zero. A suspicious file is shown to the user and nothing
  else happens to it.
- Both cases have the same root: Warden takes a rule's score at face
  value. What a match of a medium-score rule should mean is an open
  decision in the [roadmap](ROADMAP.md#open-decisions), to be settled
  with the heuristics of phase 3.
- Zero flagged files in a folder says that the rules are quiet there. It
  says nothing about what they catch, which is not measured here.
- A hosted runner is a server image with developer tools on it. A desktop
  with graphics drivers, games and office software holds many kinds of
  files that were not part of this run.

Not everything could be checked in full. In System32, 39 files could not be
read and 2 were checked in part; in the software folders, 7 were checked in
part; in `/usr`, 8: four larger than the 128 MiB content limit, two with
more than 10,000 archive members, two zip files that are damaged on
purpose (test data of the Go toolchain).

The Windows runs read every file for the first time from the runner's
disk, at 14 to 21 MB/s, so their duration (5 min 39 s and 11 min 37 s) says
little about the engine. Machine: AMD EPYC 9V74, 2 logical processors, 8 GB
RAM, Windows Server 2025, Microsoft Defender real-time protection off.
Produced by the `False positives` workflow.

Raw results:
[System32](benchmarks/2026-11-18-github-windows-runner-system32-false-positives.json),
[software](benchmarks/2026-11-18-github-windows-runner-software-false-positives.json),
[machine](benchmarks/2026-11-18-github-windows-runner-false-positives-machine.json),
[`/usr`](benchmarks/2026-11-18-dev-container-usr-false-positives.json).

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
| How the heuristic score does on the labelled records of EMBER2024, and on the files of a clean Windows installation | Phase 3 |
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

### Windows desktop

The machine described under phase 1: AMD Ryzen 7 5800X, 16 threads, 32 GB
RAM, Windows 11 Home, Microsoft Defender real-time protection on. Run with
administrator rights.

**Scan throughput** over `C:\Windows\System32`: 27,644 files, 10.28 GB, with
34 files that could not be read.
`scripts\win\check.cmd -Rules`, which runs `warden bench` and then
`warden false-positives` on the same folder

| Layers | Pass | Time | Files/s | MB/s |
|---|---|---|---|---|
| Default: hash, the built-in rule, archives | 1 | 16.69 s | 1,656 | 615.7 |
| | 2 | 7.61 s | 3,634 | 1,350.9 |
| | 3 | 8.07 s | 3,426 | 1,273.8 |
| Hash, archives, 5,138 rules | One, after those | 19.35 s | 1,429 | 531.3 |

- The default layers cost nothing that can be measured against the phase 1
  build on this folder: 8.3 s then, 7.6 to 8.1 s now.
- With all 5,138 rules the scan takes about two and a half times as long,
  not fifteen times as on the Linux tree. The files here are larger, 372 kB
  on average, so the fixed cost per file weighs less.
- Compiling the bundle took 1.8 s on this machine.

A first attempt on this machine stopped before the rules: Defender blocked
the download of the rule package.
[RULES.md](RULES.md#rule-files-and-your-antivirus) describes that and the
one folder exclusion it took.

Raw results:
[benchmark](benchmarks/2026-11-18-windows-desktop-phase2-system32.json),
[the run with rules](benchmarks/2026-11-18-windows-desktop-system32-false-positives.json),
[machine](benchmarks/2026-11-18-windows-desktop-phase2-machine.json).

## Results: phase 3

Phase 3 added the heuristic layer for Windows executables.
[HEURISTICS.md](HEURISTICS.md) explains it; this section has its numbers.

### The heuristic score on EMBER2024

EMBER2024 holds feature records and labels of files, not the files. The
score was fitted to its first 52 weeks and is measured here on its last 12,
which the fit did not see. A file is flagged when its score is 32 or more.

| Files of the test weeks | Malicious files flagged | Benign files flagged |
|---|---|---|
| Programs | 29.6 % (66,262 of 224,062) | 0.0079 % (5 of 63,669) |
| Libraries | 0.98 % (138 of 14,144) | 0.0057 % (10 of 175,573) |
| .NET assemblies | 0.079 % (25 of 31,790) | 0 of 30,571 |
| All Windows executables | 24.6 % (66,425 of 269,996) | 0.0056 % (15 of 269,813) |
| The challenge set: malicious files that no antivirus product detected at first | 0 of 4,868 | |

Area under the ROC curve on the test weeks: 0.915 for all kinds of file
together, 0.883 for programs. For comparison, the dataset's authors report
more than 0.99 for a gradient-boosted classifier on all features of the
dataset. The score here is thirteen yes-or-no questions with whole-number
weights, chosen so that a verdict can be explained line by line.

These are rates over a dataset's records, with the dataset's labels. They
say how the score behaves on those files. They are not a detection rate of
Warden on malware in the wild, which stays unmeasured.

Reproduce: `cargo run --release -p warden-calibrate -- report
calibration/ember2024-counts.zip calibration/installed-counts.json`. The
output is [`calibration/report.txt`](../calibration/report.txt), and a test
keeps that file and the scanner's weights in step with the counts.

### On the files of a clean Windows installation

The threshold was set on a dataset's benign files. Whether it holds on the
files of a real machine was counted separately, by the same tool that
counted the dataset, on a GitHub-hosted runner (Windows Server 2025, image
`win25-vs2026` 20261103.298.1):

| Folder | Windows executables | Reach the threshold of 32 | Highest score |
|---|---|---|---|
| `C:\Windows\System32` | 9,015 | 0 | 20 |
| Installed software: 7-Zip, Git, Chrome, Firefox, PowerShell, .NET, Node.js | 45,261 | 0 | below 16 |

The counts are [`calibration/installed-counts.json`](../calibration/README.md).
The full scan of the same folders, with all layers and with the files
inside archives, is under [False positives](#with-the-heuristic-layer).

### What the heuristic layer costs

One folder that is almost all executables, `C:\Program Files\PowerShell`
on the runner (1,104 files, 297 MB, 959 of them Windows executables),
scanned five times in each of four configurations. The median is over the
four repeat runs, which are served from the file cache.

| Layers | Median time | MB/s | Files/s |
|---|---|---|---|
| Hash matching | 0.25 s | 1,177 | 4,373 |
| Hash matching and heuristics | 0.45 s | 666 | 2,474 |
| Hash matching and 5,136 YARA rules | 10.34 s | 28.7 | 107 |
| All three | 10.43 s | 28.5 | 106 |

Next to hash matching alone, the layer adds three quarters to the time of
a folder of executables: it measures the entropy of the whole file and of
every section, which is two more passes over the bytes. Next to the rules
it adds under one percent. A file that is not an executable is dismissed
after its first two bytes.

Machine: AMD EPYC 7763, 2 logical processors, 8 GB RAM, Windows Server
2025, Microsoft Defender real-time protection off. A shared CI runner: the
four rows can be compared with each other and with nothing else.

Raw results:
[hash](benchmarks/2026-11-18-github-windows-runner-heuristics-cost-hash.json),
[hash and heuristics](benchmarks/2026-11-18-github-windows-runner-heuristics-cost-hash-heuristics.json),
[rules](benchmarks/2026-11-18-github-windows-runner-heuristics-cost-rules.json),
[all three](benchmarks/2026-11-18-github-windows-runner-heuristics-cost-rules-heuristics.json).

### Windows desktop

The machine described under phases 1 and 2: AMD Ryzen 7 5800X, 16 threads,
32 GB RAM, Windows 11 Home, Microsoft Defender real-time protection on. Run
with administrator rights, on commit `f276730`, some hours after the
phase 2 runs.

**Scan throughput** over `C:\Windows\System32`, with
`scripts\win\check.cmd -Rules -SkipTests`. The three benchmark passes read
27,642 files, 10.12 GB, and could not read 37; the pass with rules read
27,645 files, 10.28 GB, and could not read 34.

| Layers | Pass | Time | Files/s | MB/s |
|---|---|---|---|---|
| Default: hash, the built-in rule, heuristics, archives | 1 | 36.59 s | 756 | 276.6 |
| | 2 | 7.61 s | 3,635 | 1,330.7 |
| | 3 | 7.71 s | 3,583 | 1,311.8 |
| Hash, archives, 5,136 rules, heuristics | One, after those | 22.78 s | 1,214 | 451.4 |

- With the default layers the heuristic layer cannot be seen in the times
  on this machine: the passes from the file cache took 7.6 and 7.7 s with
  it, and 7.6 and 8.1 s without it in phase 2.
- The pass with all rules took 22.78 s. The same pass took 19.35 s in
  phase 2, without the heuristic layer. That is one run each, hours apart,
  on a machine in use, so how much of the 3.4 s belongs to the layer is not
  known. The comparison on the runner above is the only controlled one so
  far, and it is a different kind of machine: two threads, and a rule scan
  that is many times slower. A controlled comparison on this desktop is
  still to do.
- No file was flagged, see
  [False positives](#with-the-heuristic-layer).

Raw results:
[benchmark](benchmarks/2026-11-18-windows-desktop-phase3-system32.json),
[the run with rules](benchmarks/2026-11-18-windows-desktop-phase3-system32-false-positives.json),
[machine](benchmarks/2026-11-18-windows-desktop-phase3-machine.json).

## False positives

Three rounds of runs. The first used every rule of the rule package and
found two rules that flag clean files. Those two went onto the
[exclusion list](RULES.md#rules-that-are-left-out), and the second round
measured what is left. The third round has the heuristic layer switched on
as well.

### With every rule of the package

The rule set is the YARA Forge core package, release 20261018, with
Warden's built-in rule: 5,138 rules. A match of 205 of them leads to the
verdict malicious, a match of any of the other 4,933 to suspicious. The
table counts files with either verdict.

| Files expected to be clean | Files | Data | Files inside archives | Malicious | Suspicious |
|---|---|---|---|---|---|
| `C:\Windows\System32` on a Windows 11 desktop | 27,644 | 10.28 GB | 194 | 0 | 1 |
| `C:\Windows\System32` on a GitHub-hosted Windows runner | 21,804 | 4.80 GB | 193 | 0 | 1 |
| Software installed on that runner: 7-Zip, Git, Chrome, Firefox, PowerShell, .NET, Node.js | 87,707 | 14.42 GB | 89,049 | 0 | 20 |
| `/usr` in the Linux development container | 140,383 | 7.15 GB | 88,855 | 0 | 0 |

No clean file was reported as malicious. 22 of the 137,155 Windows files
(0.016%) were reported as suspicious, and they come from two rules:

- **`MALPEDIA_Win_Triback_Loader_Auto`** flagged one file in each System32
  folder: `vulkan-1.dll`, the loader of the Vulkan graphics interface, on
  the runner, and `liblouis.dll`, a braille translation library, on the
  desktop. The rule was generated by a tool from code sequences found in
  one malware family; 1,622 of the rules in the package were made that
  way. Two machines, two unrelated files, one rule: these are plain false
  positives.
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
  value. The answer chosen for now is to leave out a rule that is shown to
  flag clean files, with the evidence written down. The next section has
  the result.
- Zero flagged files in a folder says that the rules are quiet there. It
  says nothing about what they catch, which is not measured here.
- A hosted runner is a server image with developer tools on it, and of
  the desktop only the System32 folder was scanned. Installed programs,
  games and drivers elsewhere on a desktop were not part of these runs.

Not everything could be checked in full. In System32 on the desktop, 34
files could not be read and 6 were checked in part; on the runner, 39 and
2. In the software folders, 7 were checked in part; in `/usr`, 8: four
larger than the 128 MiB content limit, two with more than 10,000 archive
members, two zip files that are damaged on purpose (test data of the Go
toolchain).

The runs on the runner read every file for the first time from its disk,
at 14 to 21 MB/s, so their duration (5 min 39 s and 11 min 37 s) says
little about the engine. That machine: AMD EPYC 9V74, 2 logical
processors, 8 GB RAM, Windows Server 2025, Microsoft Defender real-time
protection off; the runs were produced by the `False positives` workflow.
The desktop is described above; its run took 19 s from the file cache.

Raw results:
[System32 on the desktop](benchmarks/2026-11-18-windows-desktop-system32-false-positives.json),
[System32 on the runner](benchmarks/2026-11-18-github-windows-runner-system32-false-positives.json),
[software](benchmarks/2026-11-18-github-windows-runner-software-false-positives.json),
[machine](benchmarks/2026-11-18-github-windows-runner-false-positives-machine.json),
[`/usr`](benchmarks/2026-11-18-dev-container-usr-false-positives.json).

### With the exclusion list

[`rules/exclusions.toml`](../rules/exclusions.toml) names the two rules,
each with the files above as evidence. A bundle built with it has 5,136
rules: 205 lead to the verdict malicious, 4,931 to suspicious. The runs on
the GitHub-hosted runner were repeated with that bundle on the same day.

| Files expected to be clean | Files | Data | Files inside archives | Flagged with every rule | Flagged with the exclusion list |
|---|---|---|---|---|---|
| `C:\Windows\System32` on a GitHub-hosted Windows runner | 21,792 | 4.78 GB | 193 | 1 of 21,804 | 0 |
| Software installed on that runner: 7-Zip, Git, Chrome, Firefox, PowerShell, .NET, Node.js | 87,707 | 14.42 GB | 89,049 | 20 | 0 |

How far the two rounds can be compared:

- **The software folders held the same files both times**: the same number
  of files, of bytes (14,416,680,921) and of files inside archives. The 20
  copies of `singlefilehost.exe` were scanned again and are no longer
  flagged.
- **The System32 runs are less alike.** Every run gets a fresh virtual
  machine. The first had an AMD processor and the second an Intel one, and
  the second run scanned 12 files fewer, 18 MB less. It did not record
  whether `vulkan-1.dll` was among the files it scanned.
- **The desktop was scanned again in the third round**, with the exclusion
  list and the heuristic layer together: none of 27,645 files was flagged,
  where `liblouis.dll` had been in the first round. The run does not record
  which files it read. That `liblouis.dll` was among them is an assumption,
  if a safe one: the file is part of Windows, and the folder held one file
  more than in the first round, not one fewer.
- **`/usr` was not scanned again.** It had no flagged file with every rule,
  and a bundle with fewer rules cannot flag more.

Nothing else surfaced: in 109,499 files, the 5,136 remaining rules flagged
none. As before, that says the rules are quiet in these folders and nothing
about what they catch.

In System32, 38 files could not be read and 2 were checked in part; in the
software folders 7 were checked in part, as before. The second runner: Intel Xeon Platinum 8370C, 2 logical processors, 8 GB RAM, Windows
Server 2025, Microsoft Defender real-time protection off. The runs took
4 min 37 s and 13 min 16 s, again reading every file for the first time
from the disk.

Raw results:
[System32](benchmarks/2026-11-18-github-windows-runner-system32-false-positives-with-exclusions.json),
[software](benchmarks/2026-11-18-github-windows-runner-software-false-positives-with-exclusions.json),
[machine](benchmarks/2026-11-18-github-windows-runner-false-positives-with-exclusions-machine.json).

### With the heuristic layer

The runs on the GitHub-hosted runner were repeated once more with all three
layers: the built-in signature, the 5,136 rules that the exclusion list
leaves, and the heuristics with 13 scored indicators and a threshold of 32.
The system folder of the desktop was scanned again the same way.

| Files expected to be clean | Files | Data | Files inside archives | Flagged by any layer |
|---|---|---|---|---|
| `C:\Windows\System32` on a GitHub-hosted Windows runner | 21,793 | 4.78 GB | 193 | 0 |
| Software installed on that runner: 7-Zip, Git, Chrome, Firefox, PowerShell, .NET, Node.js | 87,707 | 14.42 GB | 89,049 | 0 |
| `C:\Windows\System32` on a Windows 11 desktop | 27,645 | 10.28 GB | 194 | 0 |

None of 137,145 files was flagged. Of the runner's 109,500 files, about
54,000 are Windows executables, which is what the heuristic layer judges;
it also judges the executables among the files inside archives. How many
of the desktop's files are executables was not counted.

What these runs do not cover is the rest of a machine that people use. The
runner is a tidy server image with developer tools, where two thirds of the
files belong to .NET, and on the desktop only the system folder was
scanned. Games, installers in a downloads folder and the small utilities
that are packed to save space were in none of the runs, and that is where a
layer like this one is most likely to be wrong.

In System32 on the runner, 38 files could not be read and 2 were checked in
part; in its software folders 7 were checked in part, as in the rounds
before. The runner: AMD EPYC 7763, 2 logical processors, 8 GB RAM, Windows
Server 2025, Microsoft Defender real-time protection off. Its runs took
5 min 28 s and 12 min 31 s, reading every file for the first time from the
disk. On the desktop, 34 files could not be read and 6 were checked in
part, also as before; the machine is described
[above](#windows-desktop-2), and its run took 23 s from the file cache.

Raw results:
[System32](benchmarks/2026-11-18-github-windows-runner-system32-false-positives-with-heuristics.json),
[software](benchmarks/2026-11-18-github-windows-runner-software-false-positives-with-heuristics.json),
[machine](benchmarks/2026-11-18-github-windows-runner-false-positives-with-heuristics-machine.json),
[System32 on the desktop](benchmarks/2026-11-18-windows-desktop-phase3-system32-false-positives.json).

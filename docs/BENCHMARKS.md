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
| How many clean files a generated rule matches, with and without counting such a match alone | Phase 4 |
| False positives on a Windows that was installed for the test: so far without the public rules | Phase 4 |
| Real-time time-to-detect | From phase 9 |

**Not measured, by design:** detection rates on live malware samples. Warden
is built without handling live malware, so no such test set exists here.
That includes what the second sign of phase 4 costs in detection.
See [TESTING.md](TESTING.md).

**Not measured yet:** how long quarantining and restoring a file take.

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
  the engine. Since phase 4 a result also lists the files with a finding
  that did not count, apart from the flagged ones: their verdict is clean.
- **What could not be read.** A folder that cannot be opened hides what is
  in it: its files are neither scanned nor counted. A result written
  since the end of phase 4 (`"schema": 3`) counts such folders apart from
  the files that could not be read, and names both. The results before
  have one number for the two and name nothing. Where a table or a
  sentence below says that so many files could not be read, that number
  is of entries, and a lower bound of what the run did not see. This was
  noticed in phase 4, see
  [the fifth round](#with-a-second-sign-for-generated-rules).
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
  it, and 7.6 and 8.1 s without it in phase 2. When the check was run again
  two and a half hours later, they took 7.8 s twice.
- The pass with all rules took 22.78 s, and 21.21 s in that later run, by
  then with eight rules fewer. The same pass took 19.35 s in phase 2,
  without the heuristic layer. These are single runs, hours apart, on a
  machine in use, and the two with the layer differ by 1.6 s between
  themselves. So how much of the 1.9 to 3.4 s belongs to the layer is not
  known. The comparison on the runner above is the only controlled one so
  far, and it is a different kind of machine: two threads, and a rule scan
  that is many times slower. A controlled comparison on this desktop is
  still to do.
- No file was flagged, see
  [False positives](#with-the-heuristic-layer).

Raw results:
[benchmark](benchmarks/2026-11-18-windows-desktop-phase3-system32.json),
[the run with rules](benchmarks/2026-11-18-windows-desktop-phase3-system32-false-positives.json),
[machine](benchmarks/2026-11-18-windows-desktop-phase3-machine.json);
the later run:
[benchmark](benchmarks/2026-11-18-windows-desktop-phase3-repeat-system32.json),
[the run with rules](benchmarks/2026-11-18-windows-desktop-phase3-repeat-system32-false-positives.json).

## Results: phase 4

Phase 4 changed how findings add up to a verdict, and added the
quarantine. Its numbers are about false positives and are under
[the fifth round](#with-a-second-sign-for-generated-rules). This section
has two checks: how long a scan takes now, and what the cipher on the rule
bundle costs at a start.

### Windows desktop

The machine of the phases before, with administrator rights, on commit
`f9aef95`, on 2026-11-19 at 00:12 UTC. This build has the C runtime linked
in; the builds before loaded it as a library.

**Scan throughput** over `C:\Windows\System32`, with
`scripts\win\check.cmd -Rules -SkipTests`. The three benchmark passes read
27,646 files, 10.29 GB, and could not read 34 entries; the pass with rules
read 27,643 files, 10.12 GB, and could not read 37.

| Layers | Pass | Time | Files/s | MB/s |
|---|---|---|---|---|
| Default: hash, the built-in rule, heuristics, archives | 1 | 21.76 s | 1,271 | 472.8 |
| | 2 | 8.10 s | 3,412 | 1,269.4 |
| | 3 | 8.07 s | 3,427 | 1,275.0 |
| Hash, archives, 5,132 rules, heuristics | One, after those | 21.91 s | 1,261 | 462.0 |

- From the file cache a pass took 8.1 s and read 1,269 to 1,275 MB/s. The
  passes of phase 3 took 7.6 to 7.8 s for 0.17 GB less, and read 1,291 to
  1,331 MB/s; that is a spread of 3 % between two runs of one build. So
  the passes of phase 4 are 1 to 5 % slower per byte, on a machine in use.
  The reason may be the change to the verdict, the C runtime linked in, or
  the machine. This run cannot tell them apart.
- The pass with rules took 21.9 s, between the 21.2 s and 22.8 s of the
  two runs of phase 3. It ran four rules more than the later of those.
- What linking the C runtime in changes was not measured by itself.
- No file was flagged, and one is on record, see
  [False positives](#with-a-second-sign-for-generated-rules).

Raw results:
[benchmark](benchmarks/2026-11-19-windows-desktop-phase4-system32.json),
[the run with rules](benchmarks/2026-11-19-windows-desktop-phase4-system32-false-positives.json),
[machine](benchmarks/2026-11-19-windows-desktop-phase4-machine.json).

### What the cipher on the rule bundle costs

Since 2026-11-20 a rule bundle keeps its contents under a cipher;
[RULES.md](RULES.md#rule-files-and-your-antivirus) has the reason. A start
with a bundle now takes the cipher off and checks the key against what it
opened. Measured in the development container, 2 virtual CPUs, with the
bundle of 5,132 rules from the pinned package, built with the cipher and
without (8.7 MB each):

| Start, open the bundle, scan three small files | With the cipher | Without |
|---|---|---|
| Wall-clock time, median of 30 runs | 0.528 s | 0.523 s |
| Fastest and slowest of the 30 | 0.504 s and 0.678 s | 0.495 s and 0.601 s |
| Processor time, mean of 60 runs | 0.561 s | 0.547 s |

- The two differ by less than the runs of either one do. So the steps
  that the cipher adds were also timed on their own, inside the reader:
  0.6 ms to copy the contents, 4.1 ms for ChaCha20, and 4.8 ms for the
  SHA-256 that checks the key. Together that is 9 ms, under 2 % of a
  start with this bundle.
- The rest of the half second is what it was in
  [phase 2](#development-container-linux-2-vcpu-1): the rule engine
  rebuilds its search structures from the stored rules.
- These figures do not compare with the 0.73 s of 2026-11-18. The
  container is not always on the same hardware, and the bundle had six
  rules more then.
- The same rules give the same file. Each of the two bundles was built
  twice and came out the same byte for byte. Built without the cipher,
  with the exclusion list and the creation time of the bundle on the
  Windows desktop, the container wrote that very file: the one that the
  Windows build of commit `f9aef95` had written there the day before.

Raw figures, with what can and cannot be read in the two files:
[2026-11-20-dev-container-sealed-bundle.txt](benchmarks/2026-11-20-dev-container-sealed-bundle.txt).

## False positives

Five rounds of runs. The first used every rule of the rule package and
found two rules that flag clean files. Those two went onto the
[exclusion list](RULES.md#rules-that-are-left-out), and the second round
measured what is left. The third round has the heuristic layer switched on
as well, and took in the installed programs of a desktop, where eight more
rules flagged clean files. The fourth measured what is left with those on
the list too. For the fifth, four of the ten rules came off the list
again: they were generated by a tool, and the match of such a rule now
counts only together with a sign from another layer. After the rounds
comes one run of another kind, on
[a Windows that was installed for it](#on-a-freshly-installed-windows-11).

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
The system folder of the desktop was scanned again the same way, and after
it the two folders that hold the desktop's installed programs.

| Files expected to be clean | Files | Data | Files inside archives | Flagged by the heuristics | Flagged by rules |
|---|---|---|---|---|---|
| `C:\Windows\System32` on a GitHub-hosted Windows runner | 21,793 | 4.78 GB | 193 | 0 | 0 |
| Software installed on that runner: 7-Zip, Git, Chrome, Firefox, PowerShell, .NET, Node.js | 87,707 | 14.42 GB | 89,049 | 0 | 0 |
| `C:\Windows\System32` on a Windows 11 desktop | 27,645 | 10.28 GB | 194 | 0 | 0 |
| `C:\Program Files` and `C:\Program Files (x86)` on that desktop | 310,849 | 74.50 GB | 345,010 | 0 | 13 |

**The heuristic layer flagged none of 447,994 files.** The last row is the
test it was most likely to fail: the installed programs of a machine in
daily use, which is where packed and protected software is. Of the runner's
109,500 files, about 54,000 are Windows executables, which is what the
layer judges; it also judges the executables among the files inside
archives. How many of the desktop's files are executables was not counted.

**The rules flagged 13 files among the installed programs**, all as
suspicious and none as malicious. Eight rules account for them:

| Rule | Files | What it flagged |
|---|---|---|
| `MALPEDIA_Win_Bqtlock_Auto` | 2 | `libstdc++-6.dll`, the GNU C++ runtime library, twice in Git for Windows |
| `MALPEDIA_Win_Mystic_Stealer_Auto` | 2 | `zip.dll` and `unpack200.exe` of the Java runtime |
| `MALPEDIA_Win_Yokai_Auto` | 2 | `ucrtbased.dll`, the debug build of Microsoft's C runtime, in two places of the Windows SDK |
| `DITEKSHEN_INDICATOR_TOOL_UAC_NSISUAC` | 2 | The uninstallers of two versions of FL Studio |
| `COD3NYM_SUSP_OBF_NET_Reactor_Indicators_Jan24` | 2 | Two files of a commercial .NET application protected with .NET Reactor |
| `CAPE_Obfuscar` | 1 | A library of a small .NET utility protected with Obfuscar |
| `COD3NYM_SUSP_NET_Shellcode_Loader_Indicators_Jan24` | 1 | `Clipchamp.Widgets.exe`, part of the video editor that Microsoft ships with Windows 11 |
| `SECUINFRA_SUSP_Powershell_Download_Temp_Rundll_1` | 1 | `node_modules.asar` of Visual Studio Code, a 55 MB archive of JavaScript |

The first three are generated automatically from samples of one malware
family, like the rule that flagged `liblouis.dll` in the first round. The
next three recognise an installer plug-in and two obfuscators, and the last
two ask for a few common strings.
[RULES.md](RULES.md#rules-that-are-left-out) goes through each.

Of the 5,137 rules in the package, 1,622 are generated automatically in
the way of the first three. Four of those have now flagged clean files, in
about 448,000 Windows files on two machines. Every further machine is
likely to find more: that is what public rules are like. The answer at
the time was the exclusion list. For generated rules it has since become
another one, see
[the fifth round](#with-a-second-sign-for-generated-rules).

**All eight went onto the exclusion list the same day**, each with its
evidence. A bundle built with that list had 5,128 rules: 205 led to the
verdict malicious and 4,923 to suspicious. Both scans of the desktop were
repeated with that bundle: that is
[the fourth round](#with-ten-rules-on-the-list).

Three of the 13 files are not named, here or in the raw result: their names
would show which programs are installed on a private machine. They are
described by their kind.

What the runs still do not cover: the folders of a user, such as downloads
and application data, programs on other drives, and other people's
machines. The runner is a tidy server image with developer tools, where two
thirds of the files belong to .NET, and the desktop is one desktop.

In System32 on the runner, 38 files could not be read and 2 were checked in
part; in its software folders 7 were checked in part, as in the rounds
before. The runner: AMD EPYC 7763, 2 logical processors, 8 GB RAM, Windows
Server 2025, Microsoft Defender real-time protection off. Its runs took
5 min 28 s and 12 min 31 s, reading every file for the first time from the
disk. The desktop is described [above](#windows-desktop-2). In its
System32, 34 files could not be read and 6 were checked in part, also as
before, and the run took 23 s from the file cache. Among its installed
programs, 2 files could not be read and 1,069 were checked in part. That
run took 7 min 59 s, at 155 MB/s: these folders were read from the disk,
not from the file cache.

Raw results:
[System32](benchmarks/2026-11-18-github-windows-runner-system32-false-positives-with-heuristics.json),
[software](benchmarks/2026-11-18-github-windows-runner-software-false-positives-with-heuristics.json),
[machine](benchmarks/2026-11-18-github-windows-runner-false-positives-with-heuristics-machine.json),
[System32 on the desktop](benchmarks/2026-11-18-windows-desktop-phase3-system32-false-positives.json),
[installed programs on the desktop](benchmarks/2026-11-18-windows-desktop-phase3-programs-false-positives.json).

### With ten rules on the list

The check on the desktop was run again with the bundle that the longer list
gives: 5,128 rules, of which 205 lead to the verdict malicious and 4,923 to
suspicious. After it, the two folders with the installed programs were
scanned again with the same bundle.

| Files expected to be clean | Files | Data | Files inside archives | Flagged by the heuristics | Flagged by rules |
|---|---|---|---|---|---|
| `C:\Windows\System32` on the Windows 11 desktop | 27,642 | 10.12 GB | 194 | 0 | 0 |
| `C:\Program Files` and `C:\Program Files (x86)` on that desktop | 310,853 | 74.63 GB | 345,010 | 0 | 0 |

**No file among the installed programs is flagged any more**: 0 of 310,853,
where the bundle with two exclusions had flagged 13 of 310,849. That row is
the one that shows what the eight new entries do. The first row cannot,
because none of those rules had flagged anything in System32. What the
first row shows is that a bundle with ten exclusions builds and runs on
this machine, and that nothing new surfaced in its system folder.

What that zero is worth, and what it is not:

- **It was measured on the files the list was written from.** The eight
  entries exist because of 13 files in these folders. That the same folders
  come out clean afterwards says the list does what it was written to do.
  It says nothing about the next machine, which is likely to find rules of
  its own.
- **The folders had changed a little.** They belong to a machine in use,
  and an hour and forty minutes lay between the two scans: the second found
  four files and 0.13 GB more.
- **A result lists what is flagged, not what passes.** That the 13 files
  were scanned again follows from the folders being the same ones, not from
  the result.

In System32, 37 files could not be read and 5 were checked in part, and the
run took 21 s from the file cache. Among the installed programs, 2 files
could not be read and 1,069 were checked in part, as in the first scan.
That run took 6 min 6 s, at 204 MB/s, where the first had taken 7 min 59 s.
The folders had been read once by then; how much of them the file cache
still held was not measured.

Raw results:
[System32](benchmarks/2026-11-18-windows-desktop-phase3-repeat-system32-false-positives.json),
[installed programs](benchmarks/2026-11-18-windows-desktop-phase3-repeat-programs-false-positives.json).

### With a second sign for generated rules

In phase 4 the four generated rules came off the exclusion list, and the
verdict policy changed instead: the match of a rule that a tool generated
counts only together with a sign from another layer
([RULES.md](RULES.md#generated-rules)). A bundle built with the remaining
list of six has 5,132 rules. A match of 205 leads to the verdict malicious
and a match of 3,305 to suspicious; the other 1,622 are generated. The
heuristic layer backs up such a match from a score of 14.

Every run of the rounds before was repeated with that bundle.

| Files expected to be clean | Files | Data | Files inside archives | Flagged | On record, verdict clean |
|---|---|---|---|---|---|
| `C:\Windows\System32` on a GitHub-hosted Windows runner | 21,806 | 4.80 GB | 193 | 0 | 1 |
| Software installed on that runner: 7-Zip, Git, Chrome, Firefox, PowerShell, .NET, Node.js | 87,707 | 14.42 GB | 89,049 | 0 | 0 |
| `C:\Windows\System32` on the Windows 11 desktop | 27,643 | 10.12 GB | 194 | 0 | 1 |
| `C:\Program Files` and `C:\Program Files (x86)` on that desktop | 258,274 | 64.32 GB | 328,862 | 0 | 10 |
| `/usr` in the Linux development container | 140,429 | 7.15 GB | 88,855 | 0 | 0 |
| All | 535,859 | 100.81 GB | 507,153 | **0** | 12 |

**No file is flagged, and twelve are on record.** A file on record was
matched by a generated rule and by nothing else: the heuristic layer has
nothing to say about it, so the match is kept and the verdict is clean.

| On record | Rule | |
|---|---|---|
| `vulkan-1.dll` in System32 of the runner | `MALPEDIA_Win_Triback_Loader_Auto` | Flagged in the first round |
| `liblouis.dll` in System32 of the desktop | the same | Flagged in the first round |
| `libstdc++-6.dll` in Git for Windows, two copies | `MALPEDIA_Win_Bqtlock_Auto` | Flagged in the third round |
| `zip.dll` and `unpack200.exe` of the Java runtime | `MALPEDIA_Win_Mystic_Stealer_Auto` | Flagged in the third round |
| `ucrtbased.dll` in the Windows SDK, two copies | `MALPEDIA_Win_Yokai_Auto` | Flagged in the third round |
| `SDL3_image.dll`, `libavif-16.dll` and `libpng16-16.dll` in Steam | `MALPEDIA_Win_Triback_Loader_Auto` | **New** |
| `driver_VirtualDesktop.dll` of Virtual Desktop Streamer | the same | **New** |

The first eight are the files that the four rules flagged before, each with
the SHA-256 it had then. That is the exit criterion of the change: the
clean files these rules flagged are no longer reported.

**The last four were not known.** When the desktop's programs were first
scanned, in the third round, the Triback rule was already on the exclusion
list, so it never ran over them. Back in the bundle, it matches four more
clean libraries on the same machine. Counted alone, each of these matches
would make its file suspicious. With the second sign there was nothing to
do: no list knew these files, and they are not reported.

What the round shows, and what it does not:

- **How often generated rules match clean files:** twelve files in
  535,859. Four of the 1,622 rules account for all of them, and one rule
  for six. None of the twelve has a structure that scores 14 or more.
- **It is the same kind of evidence as the fourth round.** The mechanism
  was built knowing eight of these files. The four new ones are a small
  test it did not know, and passed.
- **The scan of the desktop's programs saw less than the ones before.** It
  found 258,274 files where the fourth round, on 2026-11-18, had found
  310,853, and 8 entries could not be read where 2 could not before. The
  likely reason: this run was started from the Run box of Windows, and
  nothing asked for administrator rights. The runs before had them, and
  they read `C:\Program Files\WindowsApps`, where the apps from the
  Microsoft Store are: a file flagged in the third round is in it. By
  default Windows lets an ordinary program list that folder only with
  administrator rights, and a folder that cannot be opened counts as one
  entry, whatever it holds. The result does not name the entries, and the
  run did not record its rights, so this is a likely reason and not a
  measured one. The six files that generated rules flagged among the
  programs are in other folders, and the table shows that all six were
  scanned again.
- **It says nothing about detection.** A generated rule that matches
  malware with an ordinary structure is now kept on record in the same
  way. What that costs is not measured, see
  [RULES.md](RULES.md#what-the-second-sign-costs).

On the runner, in System32, 38 entries could not be read and 2 files were
checked in part; in its software folders 7 files were checked in part. On
the desktop, 37 entries in System32 could not be read and 5 files were
checked in part; in the program folders 8 and 1,060. In `/usr`, 8 files
were checked in part. This runner: AMD EPYC 9V45, 2 logical processors,
8 GB RAM, Windows Server 2025, Microsoft Defender real-time protection
off; its runs took 5 min 22 s and 9 min 26 s, reading every file for the
first time from the disk. The desktop's took 22 s and 4 min 44 s, the
second at 226 MB/s. The scan of `/usr` took 2 min 49 s on two cores.

The desktop ran a build of commit `f9aef95`, which has the C runtime
linked in. System32 was scanned on 2026-11-19 and the program folders a
day later.

Raw results:
runner [System32](benchmarks/2026-11-18-github-windows-runner-system32-false-positives-with-second-sign.json),
[software](benchmarks/2026-11-18-github-windows-runner-software-false-positives-with-second-sign.json),
[machine](benchmarks/2026-11-18-github-windows-runner-false-positives-with-second-sign-machine.json);
desktop [System32](benchmarks/2026-11-19-windows-desktop-phase4-system32-false-positives.json),
[programs](benchmarks/2026-11-20-windows-desktop-phase4-programs-false-positives.json),
[machine](benchmarks/2026-11-19-windows-desktop-phase4-machine.json);
[`/usr`](benchmarks/2026-11-18-dev-container-usr-false-positives-with-second-sign.json).

### On a freshly installed Windows 11

The machines of the rounds above have shaped Warden: the exclusion list
was written from their files, the bar for a second sign was tried on them,
and the heuristic threshold was checked against them. A fairer test is a
machine that none of that has seen. One was set up for it:

| | |
|---|---|
| Machine | A VirtualBox 7.1 virtual machine on the desktop of the rounds above: 4 processors, 8 GB RAM, an 80 GB disk image, EFI with Secure Boot, TPM 2.0. A network adapter with the cable unplugged |
| Windows | Windows 11 Enterprise Evaluation 26H2, build 26300.9457, from Microsoft's evaluation image `26300.9457.260913-1737.26h2_ge_release_svc_refresh_CLIENTENTERPRISEEVAL_OEMRET_x64FRE_en-us.iso` (SHA-256 `bc3f24086ebadc94489066b5ad78089e2cf5c3491e90e790bb81a2b199c10e38`) |
| State | Installed on 2026-11-20 without a network, and never connected to one. Nothing installed: the programs are the four the image brings (Edge, Edge Update, WebView2 Runtime, OneDrive), the updates the four in the image |
| Antivirus | Microsoft Defender with real-time protection on, signatures 1.437.1.0 |
| Scan | The whole of `C:\`, as administrator, by the [scan kit](TESTING.md#a-machine-the-list-was-not-written-from), with the build of commit `f9aef95` |

| Files expected to be clean | Files | Data | Files inside archives | Flagged | On record, verdict clean |
|---|---|---|---|---|---|
| `C:\` of that Windows 11, **without the public rules** | 153,317 | 26.36 GB | 5,018 | 0 | 0 |

**No file is flagged.** What ran is the built-in signature and rule and
the heuristic layer, which judges the Windows executables among these
files; how many of the 153,317 are executables was not counted. For that
layer this is the first run that is held out in full: its weights and its
threshold come from a dataset, and the machines it was checked on before
were a Windows Server 2025 image and a desktop in daily use. This one is a
client Windows with nothing on it but what Microsoft ships.

**The run it was set up for is still open.** The public rules did not
run, so this result says nothing about the exclusion list or about the
second sign, and nothing can be on record: no rule that needs a second
sign was there. The reason is the machine's own antivirus. Defender took
the rule bundle on the kit's CD for `Trojan:JS/Webshell.DSK1!MTB` and
let no program read it, three times, once for each attempt described
below. The same happens on the desktop
([RULES.md](RULES.md#rule-files-and-your-antivirus)). Letting Defender
leave that one file alone is a change to an antivirus setting. No script
of this project makes such a change, on any machine; the owner of the
machine does. Until then the kit says what it could not read and scans
with the rest.

Since this run a rule bundle keeps its contents under a cipher, so that
the patterns of its rules are not in the file as they are
([RULES.md](RULES.md#rule-files-and-your-antivirus)). A kit with such a
bundle has not run on this machine yet.

How the run went, because it took three attempts on the same
installation:

1. The first kit stopped when the bundle could not be read. The kit now
   goes on without it and marks its result.
2. The second attempt never finished. Some time into the scan the
   virtual machine's screen was black, and it answered neither keyboard
   nor mouse nor its power button. The likely reason, which was not
   confirmed: Windows put the machine to sleep, as it does after a while
   without input, and the virtual machine did not wake up again. The kit
   now asks Windows to stay awake while it runs.
3. The third attempt is the result above.

Between the attempts nothing was installed and no setting was changed.
The machine was switched off and on once, after the second attempt. What
the attempts left on it is the folder `C:\warden-out` with the kit's
results, and three entries in Defender's history.

Also from this machine:

- **It has no `vcruntime140.dll`**, the C runtime that a build of Warden
  asked for until phase 4. That build would not have started here. The
  build with the runtime linked in did.
- **Its clock is nine hours ahead in the results.** Setup gave it the
  Pacific time zone and the host's local time, which is Central European.
  The times in the result files are the machine's; by the host's clock
  the scan ran on 2026-11-20 from 04:24 to 04:31 UTC.
- **Its speed is not a measurement of Warden.** 6 min 31 s for 26 GB, at
  67 MB/s, on four virtual processors with Defender reading every file
  along.

162 entries could not be read, and 66 files were checked in part.

Raw results, as the kit sent them through the machine's serial port:
[the scan](benchmarks/2026-11-20-windows11-fresh-vm-false-positives-without-rules.json),
[the machine](benchmarks/2026-11-20-windows11-fresh-vm-machine.json),
[what Defender reported](benchmarks/2026-11-20-windows11-fresh-vm-antivirus.json),
and [the capture](benchmarks/2026-11-20-windows11-fresh-vm-serial-capture.txt)
they were read from, which holds a checksum for each:
`python3 scripts/read-scan-kit-output.py <capture> --out <folder>`.

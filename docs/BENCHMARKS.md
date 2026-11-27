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
| False positives on a Windows that was installed for the test, without the public rules and with them | Phase 4 |
| What Microsoft Defender does with a rule bundle, with its contents under a cipher and without | Phase 4 |
| What the signature check says about signatures that were made to be turned down | Phase 5 |
| Who signed the files of a Windows installation, by which of three routes that is found out, and what one check costs | Phase 5 |
| What the signature check changes about the false positives | Phase 5 |
| What a look at everything that a machine starts costs, and what putting one such entry back costs | Phase 5 |
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
  [the fifth round](#with-a-second-sign-for-generated-rules). On Windows,
  which folders a scan may open depends on how it was started, and not
  only on the account:
  [TESTING.md](TESTING.md#tests-that-close-a-file-or-a-folder).
- **Micro-benchmarks** use Criterion (`cargo bench`) and report the
  estimate with its confidence interval.
- **Hardware is always stated.** Numbers from a shared CI runner or a cloud
  container say so, and are only indicative.
- On Windows, Microsoft Defender scans the same files as they are opened.
  That overhead is part of the measured time, because it is what a user
  would experience.
- **What else the machine was doing.** `scripts\win\machine-events.cmd`
  lists from Windows' own logs when Microsoft Defender updated itself or
  ran a scan of its own, when Windows Update worked, and when the machine
  was started, put to sleep or woken. It prints times and the numbers of
  the events, and nothing that names a file or a program. It was written
  after one scan of the desktop took four times as long as the scans
  before it, with nothing on record that could say why. The list showed
  that Defender was running a full scan of its own at the time: see
  [that scan](#the-desktops-programs-with-the-rule-back-in-the-bundle).
  A number from a machine with a resident antivirus is worth laying next
  to this list before it is believed.

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

## Results: phase 5

The first piece of phase 5 is the check of who signed a file
([TRUST.md](TRUST.md)). Its numbers answer three questions. Does the check
say the right thing about signatures that were made to be turned down? How
many files of a Windows installation does each of its three routes reach,
and who signed them? What does one check cost? What the check changes
about a scan is a question of false positives, and is under
[With the signature check](#with-the-signature-check).

The second piece removes what starts a quarantined file, and puts it back
with the file. Its numbers are at the end of this section, under
[The look at autostart entries](#the-look-at-autostart-entries).

Most of this section was measured on GitHub-hosted Windows runners on
2026-11-21: Windows Server 2025 (10.0.26100, runner image
`windows-2025-vs2026` 20261116.315), 2 logical processors, 8 GB RAM. The
last part, [On the desktop](#on-the-desktop), is from the Windows 11
desktop of the earlier phases, on 2026-11-25. The trust list had its two
publishers both times, and the machines had a network, over which Windows
asks whether a certificate was revoked. Every result carries the SHA-256
of the list it was made with, which begins `6f21a3f5`. The list has the
same two publishers now, and another digest: one piece of its evidence
gained a note after the run on the desktop, and the entry for Microsoft
Windows the mark that the quarantine's guard goes by.

### Who signed what

#### Signatures made to be turned down

A step of the Windows CI job makes test files with signatures of its own
([TESTING.md](TESTING.md#signatures)). The middle column is the `Status`
that PowerShell's `Get-AuthenticodeSignature` printed for each file on the
runner; the right one is what `warden trust check` said.

| File | Windows says | Warden says |
|---|---|---|
| `plain.exe`, a small program, not signed | NotSigned | No signature, by any of the three routes |
| `signed.exe`, the same, signed for "Warden Test Publisher" | Valid | The signature holds. Not trusted: "that publisher is not on the trust list" |
| `tampered.exe`, that file with one byte changed | HashMismatch | Not trusted: "the file was changed after it was signed" |
| `padded.exe`, that file with 40 bytes added inside the table that holds the signature | **Valid** | Not trusted: "bytes follow the signature inside its entry, so what the file carries as a signature does not count" |
| `lookalike.exe`, signed for "Microsoft Corporation" under a root that was made on the spot | **Valid** | The signature holds. Not trusted: "the trust list has a publisher with these names, but only with a chain that ends in one of Microsoft's own root certificates, which this signature does not have" |
| A text file and a program in the folder of a signed app package | Valid, for the package | Both covered by the package's signature. Not trusted: its publisher is not on the list |
| The same folder with the text file changed | | Not trusted: "the file is not the one that the block map of its package describes" |
| The same folder with a file added | | Not trusted: "the block map of the file's package does not list the file" |

- **Windows calls two of these valid that Warden turns down for a reason
  of its own.** `padded.exe` is the gap of
  [CVE-2013-3900](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2013-3900):
  the bytes were added where no signature reaches, and Windows accepts
  that unless an administrator has switched a stricter check on. The
  runner's Windows had not. `lookalike.exe` is validly signed, by a
  certificate that says Microsoft Corporation twice. The machine trusts
  the root above it, because the test put that root there, as any program
  with administrator rights could. What the certificate cannot have is a
  root with Microsoft's key.
- **A valid signature alone changes nothing.** `signed.exe` and the files
  of the package are signed and the signature holds, and they are not
  trusted: nobody put "Warden Test Publisher" on the list.
- For `lookalike.exe` Windows could not find out whether the certificate
  was revoked: it names no place to ask. That alone would have kept it
  from being trusted, had its names and its root been right.

The same step asked about files that came with the machine:

| File | Route | Signed for | Trusted |
|---|---|---|---|
| `C:\Windows\System32\ntdll.dll` | In the file | Microsoft Windows | Yes |
| `C:\Windows\explorer.exe` | In the file | Microsoft Windows | Yes |
| `C:\Windows\System32\whoami.exe` | Catalogue `Microsoft-Windows-Utilities-Package~...~10.0.26100.4202.cat`; the file carries nothing | Microsoft Windows | Yes |
| `C:\Windows\System32\notepad.exe` | Catalogue `Microsoft-Windows-Notepad-FoD-Package~...~10.0.26100.33828.cat`; the file carries nothing | Microsoft Windows | Yes |
| `C:\Program Files\PowerShell\7\pwsh.exe` | In the file | Microsoft Corporation | Yes |
| `C:\Program Files\dotnet\dotnet.exe` | In the file | .NET, an identity of Microsoft's that is not on the list | No |

Every one of these chains ends in a root of Microsoft's, and revocation
was checked for each. `dotnet.exe` shows that this is not what decides:
the list names signing identities, and ".NET" is not one of the two.

Raw output, with the chains:
[2026-11-21-github-windows-runner-phase5-signature-test-files.txt](benchmarks/2026-11-21-github-windows-runner-phase5-signature-test-files.txt).

#### By which route

`warden trust survey` checks every file of a folder and counts. A scan
asks about very few files; a survey asks about all of them, to show what
the check would say. Three folders of one runner:

| | `C:\Windows\System32` | Software installed on the runner | `C:\Program Files\WindowsApps` |
|---|---|---|---|
| Files | 21,567 | 91,144 | 2,178 |
| Windows executables among them | 8,760 | 48,235 | 1,054 |
| **Trusted executables** | **8,544 (97.5 %)** | **13,636 (28.3 %)** | **1,054 (100 %)** |
| by the signature in the file | 1,673 (19.1 %) | 13,636 | 640 |
| through a catalogue of Windows | 6,871 (78.4 %) | 0 | 0 |
| through the signature of their app package | 0 | 0 | 414 |
| Signed, by a publisher that is not on the list | 127 | 33,954 (70.4 %) | 0 |
| No signature by any route | 85 | 643 | 0 |
| A signature that does not hold | 4 | 2 | 0 |
| Other files that are trusted | 0 of 12,807 | 0 of 42,909 | 1,091 of 1,124 |

The software is what the false-positive runs scan: 7-Zip, Git, Chrome,
Firefox, PowerShell, .NET and Node.js.

- **Each route is needed.** In System32, 78 % of the executables carry no
  signature of their own and are vouched for in a catalogue. A check that
  only looks inside the file would trust 19 % of that folder's executables
  and call most of the rest unsigned. In the folder of the app packages,
  414 executables are trusted through the signature of their package.
  399 of them also carry a signature of their own, from a signer that is
  not on the list, most often .NET.
- **Other files are trusted only as part of a package**, and there nearly
  all of them are. The 33 that are not are 20 signature files, which
  nothing can cover, and 13 files that sit in a package's folder without
  being in its block map. The one that the survey names as an example is
  in `microsoft.system.package.metadata`, a folder that Windows adds to
  an installed package.
- **In the software, the list is what decides.** 47,590 of its 48,235
  executables carry a valid signature. Two in seven are trusted, because
  Microsoft Corporation signed them. The rest are signed by somebody the
  list does not name, and a rule match in one of them is reported as it
  always was.
- **Signatures that do not hold are rare and real.** Four files in
  System32 are signed under a root that the machine does not trust. In
  Git for Windows, the header of `git-bash.exe` points to a signature
  beyond the end of the file, and for `wintoast.exe` Windows says that a
  certificate of the chain was not valid at the time that counts.
- In System32, 236 files could not be checked. The check has to keep
  others from writing to a file while it looks, and 232 files were in use
  by Windows, registry files and logs among them. The other 4 are aliases
  of Store apps, which cannot be opened like a file. A scan asks for less
  and could not read 36 files of the folder.

#### Who is not on the list

The surveys on the runner name every signer, because the machine is the
same for everybody. These are the signers of executables that the list
does not name, with the number of files each signed:

| Signer | System32 | Software | WindowsApps |
|---|---|---|---|
| .NET | | 33,430 | 375 |
| Microsoft 3rd Party Application Component | 4 | 248 | 4 |
| Microsoft Windows Software Compatibility Publisher | 46 | 16 | |
| Microsoft Windows Hardware Compatibility Publisher | 30 | | |
| .NET DAC | | 30 | 3 |
| Microsoft Windows Hardware Abstraction Layer Publisher | 18 | | |
| Microsoft Windows Publisher | 15 | | 4 |
| Windows Phone | | | 11 |
| Five more names of Microsoft's | 11 | | |
| **Under a root of Microsoft's, together** | **124** | **33,724** | **397** |
| Publishers under other roots: the .NET Foundation's projects, Mozilla, Google, the maintainer of Git for Windows, the Python Software Foundation, GitHub, the OpenJS Foundation, Intel and others | 3 | 230 | 2 |

- **"Microsoft signed it" is not one thing.** All the names in the upper
  part are in certificates that chain to a root of Microsoft's, with
  Microsoft Corporation as the organisation. Some stand for Microsoft's
  own code, such as .NET. Others exist to say the opposite: the hardware
  compatibility publisher signs other companies' drivers, and the
  third-party component names sign other people's code that Microsoft
  ships. A list that trusted the root would trust all of it.
- **A root with Microsoft's name is not a root of Microsoft's.** The files
  signed for the maintainer of Git for Windows, the Python Software
  Foundation, the OpenJS Foundation and GitHub have chains that end in
  "Microsoft Identity Verification Root Certificate Authority 2020".
  Windows' own check does not count that root among Microsoft's own, and
  the anchor of the two entries on the list rests on that check.
- **The largest gap is .NET.** One identity signs 69 % of the executables
  in the software folders. Whether it goes on the list is a decision, and
  the list's own rule says what it takes: a clean file of that publisher
  that a rule flagged. Today no rule flags a file on this runner.
- In the folder of the app packages every one of these files is trusted
  anyway, through the package it belongs to.

#### What a check costs

For every file, a survey measures the time from opening it to the answer.
The file is read twice in that time: once for its SHA-256, and once by
whatever checks the signature.

| Survey | Answer | Files | Half under | 95 % under | Longest |
|---|---|---|---|---|---|
| System32 | Trusted, signature in the file | 1,673 | 6.0 ms | 36 ms | 3.5 s |
| | Trusted, through a catalogue | 6,871 | 5.5 ms | 28 ms | 0.3 s |
| | Not trusted | 13,023 | 0.5 ms | 3.2 ms | 0.9 s |
| Software | Trusted, signature in the file | 13,636 | 4.0 ms | 7.2 ms | 0.6 s |
| | Not trusted | 77,508 | 1.1 ms | 8.8 ms | 2.1 s |
| WindowsApps | Trusted, signature in the file | 640 | 8.1 ms | 71 ms | 0.6 s |
| | Trusted, through the package | 1,505 | 4.4 ms | 20 ms | 1.2 s |
| The drivers folder, on another runner, as the first thing that asked there | Trusted, signature in the file | 291 | 6.1 ms | 19 ms | 0.3 s |
| | Trusted, through a catalogue | 296 | 154 ms | 505 ms | 0.8 s |

The whole surveys took 55 s for System32, 3 min 12 s for the software and
13 s for the app packages, on two threads.

- **A check costs milliseconds.** A file without a signature costs about
  one, which is reading it. A file with a signature costs 4 to 8 ms at the
  median, by whichever route.
- **Except the first time a machine is asked about its catalogues.** The
  same route took 5.5 ms in one survey and 154 ms in the other. The likely
  reason is what had been read before. Windows keeps its catalogues in
  System32, and before the survey of that folder two scans had read all
  of it. On the other runner nothing had read them, and a runner reads
  a file for the first time slowly: the first scan of System32 ran at
  14.7 MB/s. This was not measured apart, so it stays a likely reason.
- **A scan pays for very few checks.** The check is asked only about a
  file with a rule match that would otherwise be reported. In the scans
  of these folders that was no file of 112,675, see
  [With the signature check](#with-the-signature-check).

Hardware: the three large surveys ran on an AMD EPYC 9V74 with 2 logical
processors, the drivers folder on an Intel Xeon Platinum 8370C with 2.
Shared machines, so the times are for comparing the routes with each
other.

Raw results:
[System32](benchmarks/2026-11-21-github-windows-runner-phase5-trust-system32.json),
[software](benchmarks/2026-11-21-github-windows-runner-phase5-trust-software.json),
[app packages](benchmarks/2026-11-21-github-windows-runner-phase5-trust-windowsapps.json),
[machine](benchmarks/2026-11-21-github-windows-runner-phase5-machine.json);
[drivers](benchmarks/2026-11-21-github-windows-runner-phase5-trust-drivers.json),
[its machine](benchmarks/2026-11-21-github-windows-runner-phase5-trust-drivers-machine.json).

#### On the desktop

A runner is a tidy machine: Windows, and software that Microsoft or a
handful of projects made. On 2026-11-25 the same survey ran over two
folders of the desktop, with administrator rights. A survey of a private
machine writes down numbers only: no file, and no signer that is not on
the list, because both would show which programs are installed.

| | `C:\Windows\System32` | `C:\Program Files\WindowsApps` |
|---|---|---|
| Files | 27,676 | 52,641 |
| Windows executables among them | 12,132 | 20,205 |
| **Trusted executables** | **11,491 (94.7 %)** | **20,115 (99.6 %)** |
| by the signature in the file | 2,026 (16.7 %) | 15,412 (76.3 %) |
| through a catalogue of Windows | 9,465 (78.0 %) | 22 |
| through the signature of their app package | 0 | 4,681 (23.2 %) |
| Signed, by a publisher that is not on the list | 550 | 90 |
| No signature by any route | 89 | 0 |
| A signature that does not hold | 2 | 0 |
| Other files that are trusted | 0 of 15,544 | 18,645 of 32,436 (57.5 %) |
| Signers that are not on the list | 51, on 550 files | 29, on 15,527 files |
| of those, with a chain that ends in a root of Microsoft's | 11, on 180 files | 12, on 15,288 files |
| One check at the median: in the file, catalogue, package | 18 ms, 22 ms, none | 16 ms, 26 ms, 12 ms |
| The whole survey, on 16 threads | 57 s | 1 min 29 s |

- **The routes share System32 as they do on the runner.** A catalogue
  vouches for 78.0 % of the executables here and for 78.4 % there. What a
  desktop adds is other people's software: 550 executables of 51 signers
  that the list does not name, where the runner had 127.
- **A root of Microsoft's is not the question.** In the folder of the app
  packages, 13,440 files that are no executables sit in packages whose
  signer the list does not name: the apps of other publishers. The
  Microsoft Store signs the packages it hands out with a certificate that
  names the publisher and chains to Microsoft; the answer about
  `Clipchamp.Widgets.exe` under
  [With the signature check](#with-the-signature-check) shows such a
  chain. The numbers agree: all but 239 of the files with a signature of
  an unlisted signer have a chain that ends in a root of Microsoft's. A
  list that trusted the root would trust every app from the Store. This
  one does not: those 13,440 files and 90 executables are not trusted,
  and a rule match in one of them is reported.
- **Nearly every executable in that folder is trusted**: 99.6 %, three
  quarters of them by their own signature and the rest through their
  package. The other files that are not trusted are the 13,440 above,
  245 signature files, 71 files that no block map lists, and 35 without
  any signature.
- **A check took longer here**: 16 to 26 ms at the median, where the
  runner took 4 to 8. The desktop checked on 16 threads at once, with
  Microsoft Defender's real-time protection on; the runner has 2 threads
  and that protection off. Which of the two makes the difference was not
  measured.
- In System32, 242 files could not be checked: 236 were in use, and 6
  are aliases of Store apps. A scan of the folder could not read 34.

Raw results:
[System32](benchmarks/2026-11-25-windows-desktop-phase5-trust-system32.json),
[app packages](benchmarks/2026-11-25-windows-desktop-phase5-trust-windowsapps.json),
[machine](benchmarks/2026-11-25-windows-desktop-phase5-machine.json).

### The look at autostart entries

The second piece of phase 5 removes what starts a quarantined file, and
puts it back when the file is restored ([REMEDIATION.md](REMEDIATION.md)).
Whether it does that right is a question for tests, which compare what
Windows' own tools show before and after. Two things can be measured: what
one look at everything that a machine starts costs, and what putting one
entry back costs.

Most of it is from GitHub-hosted Windows runners, on 2026-11-26 and
2026-11-27. The look was also timed on the desktop. Nothing here is from
the virtual machine yet; the kit for it times the look as well, so that
number comes with its run.

#### One look at the four places

`warden autostart list` reads every Run value, scheduled task, service,
driver and Startup shortcut of the machine. `scripts\win\check.cmd` runs
it five times, as a release build, and times the whole program each time:
started through `cmd.exe`, with its output thrown away. On a person's
machine that output says what is installed there. The script keeps the
times and the number of entries of each kind, and nothing else.

In the acceptance job of the CI, on 2026-11-27:

| Look | 1 | 2 | 3 | 4 | 5 |
|---|---|---|---|---|---|
| Time | 197 ms | 144 ms | 145 ms | 141 ms | 212 ms |

The runner's Windows had 900 entries: 2 Run values, 210 scheduled tasks,
687 services and drivers, and 1 shortcut. Warden could read every one.

- **A look costs about a sixth of a second on this machine**, for nine
  hundred entries. Whose entries they are was not counted.
- **A command pays for one look, however many files it is given.**
  `warden quarantine add` looks once, and then asks for each file which of
  the entries start it. A scan does not look at all.
- **The times scatter by half**, from 141 to 212 ms, on a machine that is
  shared. What they show is the size of the cost, not a third digit.

Hardware: an AMD EPYC 9V74 with 2 logical processors, 8 GB RAM, Windows
Server 2025 (10.0.26100), Microsoft Defender's real-time protection off.

On the desktop, the same day, with the same script and administrator
rights, twice, five hours apart:

| Look | 1 | 2 | 3 | 4 | 5 |
|---|---|---|---|---|---|
| 02:56 UTC, commit 71248e5 | 451 ms | 376 ms | 349 ms | 366 ms | 419 ms |
| 08:00 UTC, commit 4e126ae | 384 ms | 237 ms | 246 ms | 238 ms | 249 ms |

That Windows had 1,099 entries both times: 30 Run values, 263 scheduled
tasks, 794 services and drivers, and 12 shortcuts. Warden could read every
one. As for every result from a private machine, the numbers are all that
is kept.

- **A look takes between a quarter and four tenths of a second there**,
  for a fifth more entries than the runner has: 1.7 times the runner's
  time in the later run, 2.6 times in the earlier one, by the middle of
  the five. The desktop runs Microsoft Defender's real-time protection,
  which the runner has switched off, and it has more entries of every
  kind. Which of the two makes the difference was not measured.
- **The two runs differ by a third, and the look did not change between
  them.** The commits between them changed what the quarantine does with
  what the look finds, not the look. What else the machine was doing was
  not recorded either time, so the difference stands unexplained.
- **It is still a cost per command**, and one that a person does not
  wait for: `warden quarantine add` looks once.

Hardware: an AMD Ryzen 7 5800X with 16 logical processors, 32 GB RAM,
Windows 11 Home (10.0.26300), Microsoft Defender's real-time protection
on.

#### In the tests

The tests of the Windows side print what three calls took. These are debug
builds, as `cargo test` makes them, from three runs of the `Windows check`
workflow on 2026-11-26, each on a runner of its own:

| | First run | Second | Third |
|---|---|---|---|
| One look at the four places | 278 ms | 300 ms | 297 ms |
| A look, and what starts one file found in it | 276 ms | 340 ms | 346 ms |
| A Run value put back, three of them | 91 to 174 µs | 106 to 178 µs | 120 to 178 µs |
| A scheduled task put back, two of them | 8.9 and 11.0 ms | 8.6 and 13.6 ms | 11.1 and 12.5 ms |
| The service put back | 2.4 ms | 2.4 ms | 3.1 ms |

- **A debug build is slower.** Its look alone, without starting a program
  or printing anything, takes 278 to 300 ms.
- **Finding what starts a file is the look, and little more.** The second
  row is a look of its own, made at another moment than the first row's.
  Then Windows is asked for the other ways the file's path is written, and
  the seven entries that start the file are read once more, whole.
- **A scheduled task is the slowest to put back**, at about a hundredth of
  a second: the Task Scheduler registers it from its definition. The
  service takes a quarter of that. It is created by the service manager,
  which is then told four things about it: its delayed start, its own
  identity, its two privileges and its three triggers. Then its key is
  written back. A Run value is one write to the registry.
- **These are the calls alone.** A restore also reads each entry back and
  compares it with the record, and it restores the file. How long
  `warden quarantine add` and `restore` take as a whole was not measured,
  nor was the removal of an entry.
- **What a look spends its time on was not measured**: the four places are
  not timed apart.

The logs of these three runs name the runner image, and not the processor.

#### The run by hand, rehearsed

That Windows stops starting a program, and starts it again after a
restore, can only be seen on a machine that is restarted in between. That
run is done by hand in the virtual machine, with a script
([TESTING.md](TESTING.md#the-run-in-a-virtual-machine)), and
[its result is below](#the-run-by-hand-in-the-virtual-machine).
CI rehearses the script on the runner first: its three runs one after the
other, with the release builds, without the two restarts. On 2026-11-27,
on the machine of the five looks above:

| Run of the script | Checks | Held in the rehearsal |
|---|---|---|
| 1: a look at what the machine starts is timed. Seven entries are made for a harmless program, a scan reports it, and Warden quarantines it with what starts it | 9 | 9 |
| 2: nothing was started and nothing came back; the program is restored, and what started it with it | 5 | 5 |
| 3: Windows started the program through each of the seven entries | 7 | 0 |
| 3: nothing of the test is left on the machine | 1 | 1 |

- **The seven that failed have to fail here**: nothing restarts a runner,
  so Windows never got to start the program. The step of the CI expects
  exactly these seven to fail, and everything else to hold.
- **Two of the checks that held say little without a restart**: that the
  program was not started while it was in the quarantine, and that no
  entry came back by itself.
- **What the rehearsal does show** is the rest. Windows' tools showed
  something in all 14 views of the seven entries. Warden found seven
  entries, removed seven and left none, and Windows' tools showed none
  afterwards. The restore put all seven back without a reservation, and
  Windows' tools showed each as they had shown it before.
- **The script's own five looks** took 361, 158, 162, 156 and 170 ms, a
  few minutes after the five above and with a copy of the program that
  had just been made. Only the first start of that copy was slow.

#### The run by hand, in the virtual machine

On 2026-11-27 the script ran in the virtual machine of the
[runs on a freshly installed Windows 11](#on-a-freshly-installed-windows-11),
from a kit with the release builds of commit 4e126ae. It went through
twice, one pass after the other:

| Run of the script | Checks | Held, first pass | Held, second pass |
|---|---|---|---|
| 1: a look at what the machine starts is timed. Seven entries are made for a harmless program, a scan reports it, and Warden quarantines it with what starts it | 9 | 9 | 9 |
| 2: after a restart nothing was started and nothing came back; the program is restored, and what started it with it | 5 | 5 | 5 |
| 3: after another restart Windows had started the program through each of the seven entries | 7 | 7 | 7 |
| 3: nothing of the test is left on the machine | 1 | 1 | 1 |

- **Windows did what the entries say, and stopped when Warden had removed
  them.** After the restore and a restart the program had left seven
  lines, one for each entry with that entry's word, all within seven
  seconds: two as the machine's own account, for the service and the task
  at start, and five as the user who logged on. After the quarantine and a
  restart it had left none, and no entry had come back.
- **The first pass is not a clean one.** Its first restart never
  finished: Windows shut down, and the machine did not start again. Eleven
  and a half hours later it was reset by hand in VirtualBox, and the pass
  went on from there. So in that pass the second run's checks came after a
  reset, not after a restart that Windows completed. The second pass was
  done for that reason, and all its restarts were Windows' own.
- **Why that restart hung is not known.** By Windows' own record its
  shutdown took 7.8 seconds; the four others that were looked up took 8.2
  to 10.7. In the second pass the restart at the same place did finish,
  and took about a hundred seconds longer than the others, again after
  Windows had shut down. Seven more restarts, five of them with nothing of
  the test on the machine, went as usual. Two of nine can fall on the same
  step by chance, and this machine has left a black screen twice before:
  at a restart during Windows Setup, before anything of Warden's was on
  it, and once in the middle of a scan
  ([the runs there](#on-a-freshly-installed-windows-11),
  [TESTING.md](TESTING.md#a-machine-the-list-was-not-written-from)). What
  was seen and measured of each restart is
  [on record](benchmarks/2026-11-27-windows11-fresh-vm-phase5-autostart-restarts.txt),
  with what was not tried.
- **A look takes about a fifth of a second there.** The machine has 930
  entries: 5 Run values, 248 scheduled tasks, 677 services and drivers,
  and no shortcut, and Warden could read every one. The five looks took
  2,218, 204, 206, 207 and 204 ms in the first pass and 2,142, 197, 193,
  200 and 197 ms in the second. The first look of a pass is the first time
  the program is started from the CD image since Windows started; what
  takes the two seconds was not measured.

The machine: Windows 11 Enterprise Evaluation 26H2 (10.0.26300), 4
processors and 8 GB of memory under VirtualBox, administrator rights,
Microsoft Defender's real-time protection on.

What the machine sent has all six runs of the two passes. A run sends
every result file that is in the kit's folder, and that folder was not
emptied between the passes: the first two runs of the second pass carry
the first pass's copy of the program's list of starts again. No check
reads that copy. The checks read the list that the program itself keeps,
and that one is gone with the test's folder when a pass has cleaned up.

Raw results:
[the five looks](benchmarks/2026-11-27-github-windows-runner-phase5-autostart.json),
[their machine](benchmarks/2026-11-27-github-windows-runner-phase5-autostart-machine.json),
[the rehearsal](benchmarks/2026-11-27-github-windows-runner-phase5-autostart-kit-rehearsal.json),
[the times from the tests](benchmarks/2026-11-26-github-windows-runner-phase5-autostart-test-times.txt);
[the five looks on the desktop](benchmarks/2026-11-27-windows-desktop-phase5-autostart.json),
[its machine](benchmarks/2026-11-27-windows-desktop-phase5-autostart-machine.json),
[the five looks of the later run](benchmarks/2026-11-27-windows-desktop-phase5-autostart-second-run.json),
[its machine](benchmarks/2026-11-27-windows-desktop-phase5-autostart-second-run-machine.json);
[the run in the virtual machine](benchmarks/2026-11-27-windows11-fresh-vm-phase5-autostart-kit.json),
[its first pass](benchmarks/2026-11-27-windows11-fresh-vm-phase5-autostart-kit-first-pass.json),
[what the machine sent](benchmarks/2026-11-27-windows11-fresh-vm-phase5-autostart-serial-capture.txt),
[its restarts](benchmarks/2026-11-27-windows11-fresh-vm-phase5-autostart-restarts.txt).

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
comes [a repeat of one run](#the-desktops-programs-again-with-administrator-rights),
which put a seventh rule on the list and was run once more with it, and
then two runs of another kind, on
[a Windows that was installed for them](#on-a-freshly-installed-windows-11).
In phase 5 that seventh rule came off the list again, and the runs are
repeated [with the signature check](#with-the-signature-check).

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

### The desktop's programs again, with administrator rights

The scan of the desktop's programs in the round above had seen 52,579
files fewer than the one before it, and the likely reason was that it ran
without administrator rights. On 2026-11-20 it was repeated with them:
a build of commit `2a625c1`, the same 5,132 rules, this time in a bundle
under the cipher. A script asked Windows for the rights and wrote down
what it could list before and after.

| | |
|---|---|
| `C:\Program Files\WindowsApps` without administrator rights | Cannot be listed |
| The same folder with them | 52,631 files, 9.45 GB, and no folder in it that could not be opened |
| Scanned in `C:\Program Files` and `C:\Program Files (x86)` | 310,910 files, 74.31 GB, 344,996 files inside archives |
| Could not be read | 2 files and no folder |
| Checked in part | 1,069 files |
| Time | 4 min 54 s, at 253 MB/s |
| Flagged | **1**, as suspicious |
| On record, verdict clean | 14 |

**The likely reason was the reason.** Without administrator rights, the
folder that holds the apps from the Microsoft Store cannot be listed, and
it holds about as many files as the run before had missed. This result is
of the format that counts folders apart from files, and it has no folder
that could not be opened.

**One file is flagged, and it is clean.** `xpdAgent.exe` belongs to the
Microsoft Defender app from the Microsoft Store. The rule,
`RUSSIANPANDA_Purecrypter`, was written by hand for PureCrypter, a malware
loader that is itself a .NET program. It asks for four of five short
sequences of .NET instructions, three of them ordinary, in a program under
6 MB with exactly one embedded resource of more than 300 KB. The rule was
in the bundle when these folders were first scanned, on 2026-11-18, and
flagged nothing then. It went on the exclusion list that day as the
seventh rule ([RULES.md](RULES.md#rules-that-are-left-out)), and a bundle
built with that list has 5,131 rules. Phase 5 took it off again, for
[a reason that has to do with who signed the file](RULES.md#a-rule-that-came-off-the-list-again).

**Four more files are on record**, all of them in the folder that the run
without those rights could not list, and all through the Triback rule:
`NativeHostNE.dll` of Phone Link, and `pyshellext.exe`, `launcher-64.exe`
and `launcherw-64.exe` of the Python install manager. The other ten are
the ten of the round above. On the runner and the desktop together that
makes sixteen clean files that a generated rule matches, and none of them
is reported.

**With that list, no file is flagged.** The scan was repeated on
2026-11-21 with a bundle built with the list of seven, with administrator
rights and the same build of Warden:

| | |
|---|---|
| Rules | 5,131, with 7 left out |
| `C:\Program Files\WindowsApps` | 52,633 files, 9.47 GB, and no folder in it that could not be opened |
| Scanned in `C:\Program Files` and `C:\Program Files (x86)` | 311,415 files, 76.17 GB, 345,262 files inside archives |
| Could not be read | 2 files and no folder: the two of the day before |
| Checked in part | 1,073 files |
| Time | 4 min 53 s, at 260 MB/s |
| Flagged | **0** |
| On record, verdict clean | 14: the files of the day before, each with the SHA-256 it had then |

The folders held 505 files and 1.85 GB more than the day before; the
machine is in use. A result names no file without a finding, so this one
cannot show that `xpdAgent.exe` was among the files it scanned. What it
shows is that a bundle built with the list does not hold the rule, and
that nothing else flags a file in these folders. The bundle was built in
the development container, from the pinned package and the list as the
repository has it, and copied to the desktop.

On 2026-11-20 the desktop's check was repeated with that build as well.
System32 with the 5,132 rules: none of 27,649 files flagged,
`liblouis.dll` on record as before, 34 files and 3 folders that could not
be read. The passes without rules took 19.3 s, 8.7 s and 9.5 s, and the
pass with them 16.3 s; on 2026-11-19 they had taken 21.8 s, 8.1 s, 8.1 s
and 21.9 s. The machine was in use both times.

A result now names what it could not read. Four of those files are not
named in the two results of 2026-11-20, the two among the programs and two
of the 34 in System32: their paths would show which programs are installed
on a private machine. The repeat could not read the same two among the
programs, and its result does not name them either. Each raw result says
so at its top.

Raw results:
[programs](benchmarks/2026-11-20-windows-desktop-phase4-programs-administrator-false-positives.json),
[what the script wrote down](benchmarks/2026-11-20-windows-desktop-phase4-programs-administrator-rights.txt);
programs with the list of seven
[a day later](benchmarks/2026-11-21-windows-desktop-phase4-programs-administrator-repeat-false-positives.json),
[what the script wrote down then](benchmarks/2026-11-21-windows-desktop-phase4-programs-administrator-repeat-rights.txt);
System32 [benchmark](benchmarks/2026-11-20-windows-desktop-phase4-repeat-system32.json),
[with rules](benchmarks/2026-11-20-windows-desktop-phase4-repeat-system32-false-positives.json),
[machine](benchmarks/2026-11-20-windows-desktop-phase4-repeat-machine.json).

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
| Antivirus | Microsoft Defender with real-time protection on, signatures 1.437.1.0, in both runs |
| Scan | The whole of `C:\`, as administrator, by the [scan kit](TESTING.md#a-machine-the-list-was-not-written-from): on 2026-11-20 with the build of commit `f9aef95`, on 2026-11-21 with that of `2a625c1` |

| Files expected to be clean | Files | Data | Files inside archives | Flagged | On record, verdict clean |
|---|---|---|---|---|---|
| `C:\` of that Windows 11, **without the public rules**, 2026-11-20 | 153,317 | 26.36 GB | 5,018 | 0 | 0 |
| The same **with the 5,132 rules**, 2026-11-21 | 153,370 | 26.39 GB | 5,018 | **0** | 5 |

**No file is flagged, with the public rules or without.** Without them,
what ran is the built-in signature and rule and the heuristic layer, which
judges the Windows executables among these files; how many of them are
executables was not counted. For that layer the first run was the first
that is held out in full: its weights and its threshold come from a
dataset, and the machines it was checked on before were a Windows Server
2025 image and a desktop in daily use. This one is a client Windows with
nothing on it but what Microsoft ships.

The second run is the one the machine was set up for. It holds out the
exclusion list and the second sign as well: no rule was taken out
because of a file on this machine, and the bar for a second sign was
never tried here.

**Five files are on record**, all through `MALPEDIA_Win_Triback_Loader_Auto`,
the generated rule that matches the most clean files elsewhere:

| On record | |
|---|---|
| `vulkan-1.dll` in System32 | The same file as on the CI runner, by its SHA-256 |
| `liblouis.dll` in System32, and its copy in the component store | Another build than the one on the desktop |
| `NativeDprt.dll` of Defender's own sensor, and its copy in the component store | Not seen before |

None of them has a structure that scores 14 or more, so the matches are
kept and the verdicts are clean. On a machine that it had never seen, the
second sign did what it does on the others, and nothing had to be written
down for it. With these five, generated rules match 21 clean files on the
three machines, fifteen of them through this one rule.

**The first run had to do without the rules** because of the machine's
own antivirus. Defender took the rule bundle on the kit's CD for
`Trojan:JS/Webshell.DSK1!MTB` and let no program read it, three times,
once for each attempt described below. That bundle stored its rules as
they are. The same happens on the desktop
([RULES.md](RULES.md#rule-files-and-your-antivirus)). Letting Defender
leave the file alone would have been a change to an antivirus setting,
and no script of this project makes such a change, on any machine.

**Defender tells a bundle under the cipher from one without.** A rule
bundle keeps its contents under a cipher since then, so that the patterns
of its rules are not in the file as they are. The kit of the second run
carried two bundles: the one it scanned with, under the cipher, and as a
control the very bundle of the first run. The two hold the same compiled
rules, byte for byte.

| On the kit of 2026-11-21 | What the machine did with it |
|---|---|
| `rules-plain.wrb`, the bundle of the first run, rules as they are | Blocked: "the file contains a virus or potentially unwanted software". Defender's history names it `Trojan:JS/Webshell.DSK1!MTB`, as before |
| `rules.wrb`, the same rules under the cipher | Read. The scan above ran with it. Defender's history has no entry for it from this run |

The machine was the same in both runs: no network, so the same Defender
with the same signatures, real-time protection on, nothing excluded. What
differed is the cipher. This is one antivirus with one set of signatures;
it says nothing about what another product does, or this one after an
update.

How the runs went, because the first took three attempts on the same
installation:

1. The first kit stopped when the bundle could not be read. The kit now
   goes on without it and marks its result.
2. The second attempt never finished. Some time into the scan the
   virtual machine's screen was black, and it answered neither keyboard
   nor mouse nor its power button. The likely reason, which was not
   confirmed: Windows put the machine to sleep, as it does after a while
   without input, and the virtual machine did not wake up again. The kit
   now asks Windows to stay awake while it runs.
3. The third attempt is the first result above.
4. The run with the rules, a day later, went through at the first
   attempt.

Between the attempts nothing was installed and no setting was changed.
The machine was switched off and on after the second and the third
attempt. What the attempts left on it is the folder `C:\warden-out` with
the kit's results, and four entries in Defender's history: three for the
bundle of the first kits and one for the control.

Also from this machine:

- **It has no `vcruntime140.dll`**, the C runtime that a build of Warden
  asked for until phase 4. That build would not have started here. The
  build with the runtime linked in did.
- **Its clock is nine hours ahead in the results.** Setup gave it the
  Pacific time zone and the host's local time, which is Central European.
  The times in the result files are the machine's; by the host's clock
  the first scan ran on 2026-11-20 from 04:24 to 04:31 UTC and the second
  on 2026-11-21 from 01:10 to 01:24 UTC.
- **Its speed is not a measurement of Warden.** 6 min 31 s for 26 GB
  without the rules, at 67 MB/s, and 13 min 15 s with them, at 33 MB/s, on
  four virtual processors with Defender reading every file along. With
  the rules the scan took twice as long here; on the desktop, with sixteen
  logical processors, it takes about as long with them as without.

In the first run 162 entries could not be read. The second result is of
the format that counts folders apart: 136 files and 21 folders, most of
the folders Defender's own. In both, 66 files were checked in part.

Raw results, as the kit sent them through the machine's serial port. Of
the first run:
[the scan](benchmarks/2026-11-20-windows11-fresh-vm-false-positives-without-rules.json),
[the machine](benchmarks/2026-11-20-windows11-fresh-vm-machine.json),
[what Defender reported](benchmarks/2026-11-20-windows11-fresh-vm-antivirus.json),
[the capture](benchmarks/2026-11-20-windows11-fresh-vm-serial-capture.txt).
Of the second:
[the scan](benchmarks/2026-11-21-windows11-fresh-vm-false-positives.json),
[the machine](benchmarks/2026-11-21-windows11-fresh-vm-machine.json),
[what Defender reported](benchmarks/2026-11-21-windows11-fresh-vm-antivirus.json),
[the capture](benchmarks/2026-11-21-windows11-fresh-vm-serial-capture.txt).
Each capture holds a checksum for every result that was read from it:
`python3 scripts/read-scan-kit-output.py <capture> --out <folder>`.

### With the signature check

Since phase 5 the match of a rule from a bundle yields to the signature of
a trusted publisher ([TRUST.md](TRUST.md)), and
`RUSSIANPANDA_Purecrypter` is back in the bundle
([RULES.md](RULES.md#a-rule-that-came-off-the-list-again)). That makes
5,132 rules with six left out, as in the fifth round. On 2026-11-21 the
runner's folders were scanned with that bundle twice, with the check and
with `--no-trust`:

| Files expected to be clean | Files | Data | Files inside archives | Flagged | On record, verdict clean | Files the check was asked about |
|---|---|---|---|---|---|---|
| `C:\Windows\System32` on a GitHub-hosted Windows runner | 21,531 | 4.69 GB | 193 | 0 | 1 | 0 |
| The same without the check | 21,531 | 4.69 GB | 193 | 0 | 1 | |
| Software installed on that runner | 91,144 | 15.32 GB | 91,927 | 0 | 2 | 0 |
| The same without the check | 91,144 | 15.32 GB | 91,927 | 0 | 2 | |

- **On the runner the check changes nothing, and that is what was to be
  expected.** No file is flagged there without it, so it has nothing to
  take away. It was asked about no file: it is asked only when a rule
  match would otherwise be reported, and none got that far.
- **So it cost nothing either.** The scans with the check ran first and
  read the files from the disk, in 5 min 20 s and 11 min 33 s. The scans
  without it came second and took 1 min 37 s and 8 min 53 s. With nobody
  asked, that difference is the file cache and nothing else.
- **Three files are on record**, all through the generated rule
  `MALPEDIA_Win_Triback_Loader_Auto` without a second sign: `vulkan-1.dll`
  as in every run, and two new ones, `node_js2c.exe` and `nop.exe` in a
  tool pack of .NET. The runner's image has grown since the fifth round,
  from 87,707 files in the software folders to 91,144. With these two,
  generated rules match 23 clean files on the three machines, 17 of them
  through this one rule, and none is reported.
- **Where the check does change a result is tested, not measured here.**
  In CI a test rule that matches every Windows program runs over copies
  of files that Microsoft signed and over the test files of
  [Who signed what](#signatures-made-to-be-turned-down): the first are on
  record, the rest are reported, each with its reason
  ([TESTING.md](TESTING.md#signatures)).

In System32, 36 files and 2 folders could not be read and 2 files were
checked in part; in the software folders 7 files were checked in part.
This runner: AMD EPYC 9V74, 2 logical processors, 8 GB RAM, Windows
Server 2025, Microsoft Defender real-time protection off.

Raw results:
System32 [with the check](benchmarks/2026-11-21-github-windows-runner-phase5-system32-false-positives.json)
and [without](benchmarks/2026-11-21-github-windows-runner-phase5-system32-false-positives-without-trust.json),
software [with](benchmarks/2026-11-21-github-windows-runner-phase5-software-false-positives.json)
and [without](benchmarks/2026-11-21-github-windows-runner-phase5-software-false-positives-without-trust.json),
[machine](benchmarks/2026-11-21-github-windows-runner-phase5-machine.json).

#### The desktop's programs, with the rule back in the bundle

The file that `RUSSIANPANDA_Purecrypter` flagged is on no runner. It is on
the desktop, in a folder that opens only with administrator rights, so
the proof of this change had to come from there. On 2026-11-25 the scan
of [2026-11-20](#the-desktops-programs-again-with-administrator-rights)
was repeated with a build of commit `7d068c8`, made on the desktop, and a
bundle built there from the pinned package and the list of six.

| | |
|---|---|
| Rules | 5,132, with 6 left out. `RUSSIANPANDA_Purecrypter` is one of the 5,132 |
| Scanned in `C:\Program Files` and `C:\Program Files (x86)` | 312,347 files, 77.54 GB, 345,740 files inside archives |
| Could not be read | 2 files and no folder: as before, a configuration file of one program and a lock file of another |
| Checked in part | 1,075 files |
| Flagged | **0** |
| On record, verdict clean | 15 |
| Files the check was asked about | 1, and a trusted publisher had signed it |
| Time | 21 min 17 s, at 61 MB/s |

- **The rule matches the same file, and the file is not reported.**
  `xpdAgent.exe` is at the same path with the same SHA-256 as on
  2026-11-20. The match is on record with its reason, "signed for
  Microsoft Corporation, found in the file itself", and the verdict is
  clean.
- **What Warden reads in that file.** The signature in the file holds;
  its chain is Microsoft Corporation, Microsoft Windows Code Signing PCA
  2024, Microsoft Root Certificate Authority 2010, and nothing in it is
  revoked. The signature of the package the file belongs to holds as
  well, for Microsoft Corporation again, through the certificates of the
  Microsoft Store. Either route alone would have been enough.
- **The check was asked once in 312,347 files.** The other 14 files on
  record are the ones of the earlier runs, matched by generated rules
  that wait for a second sign. Nobody was asked about them, because their
  matches would not have been reported anyway. Thirteen have the SHA-256
  they had then; Phone Link was updated in between, and the new version
  of its `NativeHostNE.dll` matches as the old one did.
- **The scan took four times as long as the two before it**, which ran in
  4 min 54 s and 4 min 53 s. The check is not the reason: one file was
  asked about. **Microsoft Defender was running a full scan of the machine
  at the time.** Defender's own log has that scan from 23:37:18 to 01:31:49
  UTC, for 1 h 54 min. Warden's scan ran from 00:51:46 to 01:13:05, all of
  it inside. During the two scans before, on 2026-11-20 and 2026-11-21,
  Defender ran no scan of its own. That is the one difference between the
  three scans that the machine's logs show, and it fits: two scanners
  read the same disk, and Defender also looks at every file that Warden
  opens. It is what one night shows, and no experiment: the scan was not
  repeated during another full scan of Defender.
- **System32 was not slower in the same hour.** Twenty minutes before
  that scan, and during the same full scan of Defender, the same build
  scanned System32 with the same rules in 23.5 s, as on other days. The
  likely reason is memory: the passes just before had read those 10 GB,
  and the machine has 32 GB. The programs are 77.5 GB, and most of them
  had to come from the disk that Defender was reading. That was not
  measured apart.
- **What the logs were asked.** The list is from
  `scripts\win\machine-events.cmd`, run on the desktop on 2026-11-27. It
  has the times of Defender's own scans and updates, of the work of
  Windows Update and of the starts of Windows, with event numbers and
  version numbers, and no path and no name. Windows had been running
  since 2026-11-14, so none of the three scans came after a fresh start.
  Defender updated its definitions at 01:19:17, six minutes after
  Warden's scan had ended.

The acceptance script ran on the desktop before that scan, with the same
build. Its new step asked who signed two files of Windows, and both came
back trusted as Microsoft Windows: `ntdll.dll` by its own signature and
`whoami.exe` through a catalogue. System32 with the 5,132 rules: none of
27,643 files flagged, `liblouis.dll` on record as before, the check asked
about no file, 34 files and 3 folders that could not be read. The passes
without the public rules took 28.2 s, 9.7 s and 8.3 s, and the pass with
them 23.5 s.

**Who signed the files that the exclusion list names.** Four of the seven
files that [the list](RULES.md#rules-that-are-left-out) names by path are
on the desktop, and the same run asked about them:

| File | What Warden found | Trusted |
|---|---|---|
| `uninstall.exe` of FL Studio 2025 and of FL Studio 21 | A signature in the file that holds, for Image Line, under a root of DigiCert's | No: not on the list |
| `node_modules.asar` of Visual Studio Code | Nothing to look for: no executable, and in no package | No |
| `Clipchamp.Widgets.exe` | No signature of its own. Its package is signed for `33F0F141-36F3-4EC2-A77D-51B53D0BA0E4`, a publisher's identity in the Microsoft Store, with a chain that ends in Microsoft Root Certificate Authority 2011 | No: not on the list |

None of the six entries could give way to the trust list as it is. The
last row is why the list asks for names and not for a root: the chain is
Microsoft's, and the signer is whoever published the app.

As in the earlier results of the desktop, the paths of four files that
could not be read are replaced in the raw results, two among the programs
and two in System32, and each result says so at its top.

The part of the machine's list that bears on the three scans:
[2026-11-27-windows-desktop-phase5-machine-events.txt](benchmarks/2026-11-27-windows-desktop-phase5-machine-events.txt).

Raw results:
[programs](benchmarks/2026-11-25-windows-desktop-phase5-programs-administrator-false-positives.json),
[what the script wrote down](benchmarks/2026-11-25-windows-desktop-phase5-programs-administrator-rights.txt),
[the answer about `xpdAgent.exe`](benchmarks/2026-11-25-windows-desktop-phase5-trust-check-xpdagent.txt),
[the answers about the files of the exclusion list](benchmarks/2026-11-25-windows-desktop-phase5-trust-check-exclusion-evidence.txt);
System32 [benchmark](benchmarks/2026-11-25-windows-desktop-phase5-system32.json),
[with rules](benchmarks/2026-11-25-windows-desktop-phase5-system32-false-positives.json),
[machine](benchmarks/2026-11-25-windows-desktop-phase5-machine.json).

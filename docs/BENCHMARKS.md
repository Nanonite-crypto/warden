# Benchmarks

Every number on this page comes from a run that is recorded in
`docs/benchmarks/` and can be reproduced with the commands shown.

## What is and is not measured

| Measured | Since |
|---|---|
| Scan throughput: files/sec and MB/sec | Phase 1 |
| Signature lookup and hashing speed | Phase 1 |
| False positives on clean files | From phase 2 |
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
- Result files marked `"schema": 1` were written before that split, so
  their median fields include the first run. The tables below are built
  from the individual runs.
- **Micro-benchmarks** use Criterion (`cargo bench`) and report the
  estimate with its confidence interval.
- **Hardware is always stated.** Numbers from a shared CI runner or a cloud
  container say so, and are only indicative.
- On Windows, Microsoft Defender scans the same files as they are opened.
  That overhead is part of the measured time, because it is what a user
  would experience.

## Results: phase 1

Phase 1 has one detection layer (hash matching), so these figures are the
ceiling that later layers will be measured against.

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
`warden bench C:\Windows\System32 --runs 2`, run by
`scripts\win\phase1-check.cmd`

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

Not yet measured. `scripts\win\phase1-check.cmd` produces these numbers by
scanning the System32 folder with the machine's antivirus running, and
writes them to `target\phase1\bench.json`, next to a description of the
machine in `system.json`. They will be added here from that run.

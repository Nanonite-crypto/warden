# Warden

A Windows anti-malware scanner written in Rust.

Warden is a portfolio project by Vevang Technologies. It is built in phases,
each ending with something that can be run and tested. The aim is depth in
the scan engine, a clean architecture and measured results.

> **Status: phase 1 of 10.** The engine core, the signature database, the
> hash-matching layer and the command-line scanner exist. There is no GUI, no
> quarantine and no real-time protection yet. Warden is not a replacement
> for your antivirus; it runs next to Microsoft Defender.

## What works today

`warden scan` on a folder that holds the EICAR test file:

```
Warden 0.1.0

Scanned     1 file, 68 B in 0.5 ms
Speed       1,900 files/s, 0.1 MB/s on 2 threads
Signatures  1 built-in

1 detection

  MALICIOUS   EICAR-Test-File
    D:\a\warden\warden\testdata\eicar-zone\eicar.com
    sha256 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f (68 bytes)
    hash [test file]: SHA-256 matches the EICAR antivirus test file, a harmless file that every scanner detects on purpose
```

That is unedited output from Windows: the CI run for phase 1, in which the
acceptance script wrote the test file and scanned it. Screenshots arrive
with the desktop app.

| Command | What it does |
|---|---|
| `warden scan <path>...` | Scans files and folders in parallel. Exit code 0 means clean, 1 means something was detected, 2 means an error. `--json` prints the full report. |
| `warden sigdb build` | Builds a signature database from lists of SHA-256 hashes. |
| `warden sigdb info` / `lookup` | Inspects a database, or looks up one hash. |
| `warden bench <folder>` | Measures scan throughput: files/sec and MB/sec over several runs. |
| `warden hash <file>...` | Prints SHA-256 digests. |
| `warden eicar write <dir>` | Writes the harmless EICAR test file, for demos. |

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

On Windows, `scripts\win\phase1-check.cmd` builds Warden, checks EICAR
detection, runs the test suite and measures scan speed in one go.

### Trying the EICAR detection

EICAR is a harmless 68-byte file that every antivirus product detects on
purpose. Microsoft Defender will remove it before Warden can scan it, unless
the folder is excluded. [docs/TESTING.md](docs/TESTING.md) explains how to
exclude one dedicated folder, and how to undo it.

```
warden eicar write testdata\eicar-zone
warden scan testdata\eicar-zone
```

## How detection works

Warden is a layered engine. Each layer exists to catch what the one before
it cannot.

| Layer | Phase | Catches | Weakness |
|---|---|---|---|
| Hash match | 1, done | Exact copies of known files | One changed byte evades it |
| YARA rules | 2 | Patterns shared by a malware family | Packing hides the patterns |
| PE heuristics | 3 | Signs of packing, injection and evasion | Legitimate software can look suspicious |
| ML classifier | optional | Statistical resemblance to known malware | Only as good as its training data |

Today's layer works like this:

1. A walker thread enumerates the folders. It does not follow links, and it
   does not download cloud-only files.
2. Worker threads read every file exactly once and compute its SHA-256.
3. The hash is looked up in the signature database: a sorted table of
   digests with a 16-bit prefix index, memory-mapped and verified in full
   when opened. A lookup among a million entries takes tens of nanoseconds.
4. A match becomes a finding with a reason attached. A separate verdict
   policy turns findings into clean, suspicious or malicious, so every
   detection can answer "why was this flagged?".
5. Files that could not be read are listed with the reason, never silently
   dropped.

More in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and
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
malware. Tests use the EICAR file, harmless generated fixtures and, later,
public feature datasets.

One consequence is stated plainly wherever numbers appear: detection rates
on live samples are **not measured**, by design. What is measured is scan
speed, false positives on clean files and, from phase 3, detection rates in
feature space on the EMBER2024 dataset. See [docs/TESTING.md](docs/TESTING.md).

## Benchmarks

[docs/BENCHMARKS.md](docs/BENCHMARKS.md) has the numbers and how they were
produced.

## Roadmap

[docs/ROADMAP.md](docs/ROADMAP.md) lists every phase with its exit
criterion. Next: YARA rules and zip scanning.

## Licence

No licence has been chosen yet. Until one is, all rights are reserved.

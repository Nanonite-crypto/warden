# Calibration data

The weights of the heuristic indicators and the score from which a file
counts as suspicious are computed from the files in this folder.
[`docs/HEURISTICS.md`](../docs/HEURISTICS.md) explains the method and what
came out.

| File | What it holds |
|---|---|
| `sets.txt` | The parts of the EMBER2024 dataset that are read. |
| `ember2024-counts.zip` | Counts over EMBER2024: for every combination of indicators that occurs, how many files show exactly that combination, by part of the dataset, kind of file and label. 2,883,898 Windows executables, 188,512 combinations. |
| `installed-counts.json` | The same counts for the executables of a Windows installation: 9,015 in `C:\Windows\System32` and 45,261 in seven installed programs. |
| `report.txt` | What `warden-calibrate report` prints for the two files above. |

Both sets of counts were made on 2026-11-18 by the
[Calibration workflow](../.github/workflows/calibration.yml) on
GitHub-hosted runners. The installed files are those of the Windows runner:
Windows Server 2025, version 10.0.26100, image `win25-vs2026` 20261103.298.1.

The dataset's training and test files list every record twice, and a few
more often. A file is counted once per part of the dataset, told apart by
its SHA-256; `report.txt` says how many repeats each part had.

The counts hold nothing about a single file: no names, no hashes, no
content. EMBER2024 itself holds features and labels of files, not the
files, so no malware is downloaded or handled at any point.

## Why the counts are in the repository

A weight in `crates/warden-pe/src/indicators.rs` is a number somebody could
change by hand. The test
`the_scanner_has_what_the_counts_in_the_repository_give` in
`crates/warden-calibrate` fits the weights to these counts again on every
test run and fails if the scanner has other weights, another threshold, or
if `report.txt` is not what the tool prints. Reading the dataset takes
about 25 minutes on a hosted runner; fitting to the counts takes a few
seconds.

## Doing it again

The report, from the counts:

```text
cargo run --release -p warden-calibrate -- report calibration/ember2024-counts.zip calibration/installed-counts.json > calibration/report.txt
```

The counts, from the dataset and from a Windows machine: start the
Calibration workflow by hand and choose what to measure. It prints the
counts into its log and keeps them as an artifact. Without GitHub:

```text
warden-calibrate collect Win32_train.zip Win32_test.zip ... --out ember2024-counts.json
warden-calibrate collect-files --as system C:\Windows\System32 --out system.json
warden-calibrate collect-files --as software "C:\Program Files\7-Zip" ... --out software.json
warden-calibrate merge system.json software.json --out installed-counts.json
```

The counts over the dataset are kept as a zip archive with one file in
it, to keep the repository small; the tool reads both forms.

New counts are needed when an indicator is added or the question it asks
is changed. Counts and scanner then have to move together: the test names
every weight that no longer matches.

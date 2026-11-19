# The heuristic layer

The first two layers know files. The hash layer knows them by their digest,
the YARA layer by patterns somebody wrote after seeing them. The third layer
looks at a Windows executable that nobody has seen and asks a different
question: what kind of file is built like this?

It answers with a score, and with every reason behind the score. A file
whose score reaches the threshold is reported as **suspicious**: shown to
the user, never acted on. Structure alone never makes a file malicious,
because clean programs are packed and protected too. A lower score reports
nothing, and from a second, lower bar on it can still back up a finding of
another layer that does not count alone.

The questions this layer asks were written by hand. What an answer is
worth was not: every weight and the threshold are computed from a public
dataset, the counts they rest on are in this repository, and a test fails
if the code and the counts disagree. The few choices that remain, such as
how many false alarms are acceptable, are named where they are made. This
document says how it works, shows what came out, and is plain about what
the layer cannot do.

## What it looks like

`warden inspect <file>` prints what the layer sees. This is the end of its
output for an inert test file that is built to look like a packed loader
(no real program is in it, see [TESTING.md](TESTING.md)):

```text
Indicators that add to the score
   +10  A section is both writable and executable: sections "UPX0", "UPX1"
        Code that rewrites itself needs memory that can be written and run.
        Linkers keep code read-only, so this is the mark of a packer's
        unpacking stub or of code that patches itself. Some older compilers
        and a few game protections produce it too.
    +9  An executable section looks compressed or encrypted: section "UPX1" has an entropy of 7.99 bits per byte
    +5  A quarter of the file or more sits after the last section: 16384 of 33280 bytes come after the last section
    +8  The program imports nothing: the import table is empty or missing
    +5  The header holds no checksum: the checksum field is zero
    +4  The program has no resources: the header points to no resource table

Also seen, and not scored: measured next to the others these add nothing, or they are left out on purpose
     ·  A section has a name that a packer or protector writes: sections "UPX0", "UPX1"
     ·  The entry point is in a writable section: the entry point is in section "UPX1", which is writable
     ...

Score       41
Verdict     suspicious: a file counts as suspicious from a score of 32
```

(Shortened: each scored indicator comes with its explanation, and the list
of unscored ones is longer.) In a scan, the same file is one finding,
`Heuristic.SuspiciousExecutable`, with those six lines as its reasons.

The same file with its three imports left in and nothing behind its last
section scores 28 and is not reported. Packed is common in clean software,
and the weights know it. For that file the output ends like this:

```text
Score       28
Verdict     not suspicious: a file counts as suspicious from a score of 32
Second sign yes: it backs up a finding of another layer that does not count alone, which takes a score of 14
```

The last line is about [the bar for a second sign](#the-bar-for-a-second-sign).

## How it works

Three steps, in `crates/warden-pe`:

1. **Read.** A reader turns the bytes of the file into facts: the sections
   with their sizes, flags and entropy; the imported libraries and
   functions; which tables the header points to; what follows the last
   section; the header fields a linker fills in. The reader is written for
   hostile input, and what is wrong with a file is itself a fact.
2. **Ask.** 43 indicators each ask one yes-or-no question about the facts.
   "Is a section both writable and executable?" "Is the entry point outside
   every section?" "Does the program import nothing?"
3. **Add up.** Each indicator has a weight. The score is the sum of the
   weights of the indicators that apply, and a score of 32 or more is
   suspicious.

The unit of a weight is the **deciban**: ten times the base-ten logarithm of
a factor on the odds. An indicator with weight 10 makes it ten times as
likely, in odds, that a file is malicious; weight 3 doubles the odds; and
because logarithms add where factors multiply, a score of 30 stands for a
factor of a thousand. That is the reason for the unit: adding weights is
then the right way to combine evidence, as far as the indicators are
independent of each other, which the fit below takes care of.

## Where the weights come from

### The dataset

[EMBER2024](https://github.com/FutureComputing4AI/EMBER2024) is a public
dataset for malware research (Joyce and others, 2025,
[arXiv:2506.05074](https://arxiv.org/abs/2506.05074)). For each of
3.2 million files that were submitted to VirusTotal over 64 weeks it gives
a label, malicious or benign, and a record of features: section table,
import table, header fields, entropy, and more. It does **not** contain the files.
Nothing in this project downloads or handles malware.

The dataset's authors split it by time: the first 52 weeks for training,
the last 12 for testing. Warden keeps to that. Weights and threshold are
computed from the training weeks only, and the results further down are
from the test weeks, which the fit never saw. That matters, because malware
changes: a score that only describes the past is of little use.

The dataset also has a **challenge set**: malicious files that no antivirus
product detected when they were first seen.

Warden uses the Windows executables in it:

| | Malicious | Benign |
|---|---|---|
| Training weeks | 1,169,644 | 1,169,577 |
| Test weeks | 269,996 | 269,813 |
| Challenge set | 4,868 | |

The published training and test files list every record twice, and a few
more often. A file is counted once here, told apart by its SHA-256. (The
first count for this project did not do that, and every number came out
doubled. What gave it away: among 187,567 counts of combinations, not one
was odd.)

### Counting

Warden's reader collects only facts that a record of the dataset holds as
well. So the indicator code that runs on a file on disk also runs on a
record, unchanged, and for every file of the dataset it is known which
indicators apply.

`warden-calibrate` (a development tool, not part of the scanner) reads the
dataset once and writes down, for every combination of indicators that
occurs, how many files show exactly that combination, by label, by part of
the dataset and by kind of file. That table is small: it is
[`calibration/ember2024-counts.zip`](../calibration/). Everything below is
computed from it, in seconds, and can be computed again by anyone.

### Why not weigh each indicator on its own

The obvious way to get a weight is to count how often an indicator applies
to malicious and to benign files, and take the ratio. That was done first.
It goes wrong in two ways, and both show in the counts.

**The kind of file gets mistaken for evidence.** In the training weeks
73 % of the programs are malicious and 9 % of the libraries. Most malware
is a program; most of what is benign in the dataset is a library. So
anything that programs show more often than libraries looks like a sign of
malware when all files are counted together, and anything typical of
libraries looks like a sign of innocence.

| Indicator | All files | Programs only | Libraries only |
|---|---|---|---|
| The whole file looks compressed | 5.4 dB | 1.3 dB | 11.1 dB |
| The program has no relocation table | 6.7 dB | 2.4 dB | |
| A section has a packer's name | 11.5 dB | 8.1 dB | 14.8 dB |
| The imports are only what loads other functions | 11.3 dB | 7.9 dB | 16.0 dB |

(dB: ten times the logarithm of how many times more often the indicator
applies to malicious than to benign training files.)

**The same thing is counted several times.** A packed file has a writable
code section, high entropy in it, an entry point in a writable section, an
import table of three functions and a section called `UPX0`. Each of those
is measured at 8 to 12 dB among programs. Added up, a plainly packed file
would score more than 40, as if five independent witnesses had spoken,
when all five say the same thing: "packed".

### The fit

So the weights are fitted together, with a logistic regression: the
standard model for "which yes-or-no facts shift the odds, and by how much".
It says that the odds that a file is malicious are the odds for its kind of
file, multiplied by one factor for every indicator that applies. The
factors that explain the labels of the training files best are the weights.

Four choices make it a heuristic score and not a black box:

- **The kind of file gets a term of its own** (program, library, .NET
  assembly), so that "is a program" is explained there and not spread over
  the indicators. The three terms are fitted and then thrown away. They
  describe the dataset, where every second file is malicious, not a real
  disk.
- **No weight may be negative.** The score counts what speaks against a
  file. Nothing may talk it down, because whatever lowers a score is the
  first thing malware would imitate.
- **Nothing below 3 decibans.** An indicator that does not at least double
  the odds is taken out, the weakest first, and the rest is fitted again.
  What remains is a short table in which every line means something.
- **Whole numbers, and none above 20.** The fitted values are rounded. A
  single indicator should not be able to settle the matter alone.

Two indicators are never offered to the fit: one that applies to too few
malicious files to say anything, and the missing signature, see
[below](#the-signature).

The problem is convex: it has one solution, and
[`fit.rs`](../crates/warden-calibrate/src/fit.rs) finds it with Newton's
method in about two hundred lines of plain Rust, without a machine-learning
library.

### The weights

Thirteen indicators remain.

| Weight | Indicator | Malicious | Benign | Fitted |
|---|---|---|---|---|
| 18 | The PE header starts inside the DOS header | 0.57 % | 0.0003 % | 18.15 dB |
| 10 | A section is both writable and executable | 45.94 % | 1.90 % | 9.66 dB |
| 10 | The entry point is in none of the sections | 0.77 % | 0.04 % | 9.93 dB |
| 9 | An executable section looks compressed or encrypted | 41.75 % | 1.83 % | 8.86 dB |
| 8 | A data section looks compressed or encrypted | 9.07 % | 1.57 % | 7.70 dB |
| 8 | The program imports nothing | 9.21 % | 1.53 % | 7.84 dB |
| 7 | The entry point is in a section that is not marked executable | 1.51 % | 0.04 % | 6.77 dB |
| 6 | The imports allow writing into the memory of another process | 1.58 % | 0.80 % | 5.51 dB |
| 5 | A quarter of the file or more sits after the last section | 38.25 % | 9.17 % | 5.13 dB |
| 5 | The program can download a file with a single call | 1.19 % | 0.37 % | 5.20 dB |
| 5 | The header holds no checksum | 61.04 % | 24.28 % | 5.15 dB |
| 4 | An executable section is several times larger in memory than in the file | 14.75 % | 0.13 % | 3.59 dB |
| 4 | The program has no resources | 20.68 % | 1.41 % | 4.21 dB |

Malicious, Benign: the share of the training files of each label that the
indicator applies to. Fitted: what the fit gives it next to the other
twelve, before rounding.

The table is easier to believe once the two columns are seen to disagree
with intuition in places. "Several times larger in memory than in the file"
applies to malicious files a hundred times as often as to benign ones, and
weighs 4: of the files that have it, 99.4 % also have a writable code
section or code with high entropy, which have already said so. The missing checksum is in a
quarter of all benign files, and still weighs 5, because it is one of the
few indicators that say something the others do not.

### What gets no weight

Thirty indicators are still asked and shown by `warden inspect`. They add
nothing to a score, for one of three reasons.

**They say what a scored indicator has already said.** The fit holds them
at zero. A section named `UPX0` is the best known sign of packing and adds
nothing next to a writable code section with high entropy; the same goes
for an entry point in a writable section, for an import table that only
loads other functions, and for a file without relocations.

**They are no sign of malware in this dataset.** This was the surprise of
the phase. The import combinations that every introduction to malware
analysis lists are about as common in the dataset's benign files as in its
malicious ones, or more common:

| Indicator | Malicious | Benign |
|---|---|---|
| The imports allow running code inside another process | 0.87 % | 0.74 % |
| The imports allow replacing the code of another process (hollowing) | 0.011 % | 0.035 % |
| The imports allow watching the keyboard in other programs | 4.28 % | 5.38 % |
| The program checks whether another process is being debugged | 0.14 % | 0.27 % |
| The program can switch on privileges for itself | 5.81 % | 9.98 % |
| The program can list the running processes | 3.77 % | 5.38 % |
| The file uses thread-local storage | 22.40 % | 34.09 % |
| The link time in the header is in the future | 6.45 % | 11.77 % |

That does not mean that malware has stopped injecting code. The likely
reason is that malware which does so rarely says so in its import table:
it is packed, or it looks its functions up while it runs. What is left to
carry those names in plain sight is debuggers, installers, remote-control
tools and games.

**They are too weak.** Eleven indicators came out of the fit between 0.2
and 2.4 decibans and were taken out one by one, among them the missing
ASLR flag, `WinExec`, and a file whose sections have no ordinary name.

[`calibration/report.txt`](../calibration/report.txt) lists every
indicator with its counts and with what the fit made of it.

### The signature

90.6 % of the malicious training files have no embedded signature, and
40.4 % of the benign ones. Offered to the fit, "no signature" gets
10.5 decibans, the third largest weight of all. It is left out anyway.

Warden only sees whether a signature is *there*. Whether it is valid is
not checked, and a signature block can be appended to any file. Ten points
for something an attacker removes with one copy command would be the
weakest spot of the score. The open-source tool that nobody paid a
certificate for would start almost a third of the way to suspicious. And so
would most of Windows: 77 % of the executables in `C:\Windows\System32`
have no embedded signature, because Windows signs its system files in
separate catalogues.

The measurement agrees with leaving it out.
`warden-calibrate report --offer-all` fits the variant with the signature.
With the threshold set by the same rule, it flags 18.1 % of the malicious
files of the test weeks; the variant in use flags 24.6 %. Both keep the
false alarms among the benign files of the test weeks below 0.006 %.

Checking a signature for validity is a different matter, and later work. A
valid signature from a known publisher may then lower a score.

## The threshold

The score from which a file is suspicious follows from a rule, too: **the
lowest score that at most one in 5,000 benign training files of any kind
reaches**. "Of any kind" means that the limit has to hold for programs, for
libraries and for .NET assemblies separately; programs are the hard case.
The rule gives 32.

What other thresholds would do, on all kinds of file together:

| Suspicious from | Malicious flagged, training | Benign flagged, training | Malicious flagged, test | Benign flagged, test |
|---|---|---|---|---|
| 24 | 32.4 % | 0.72 % | 35.9 % | 0.42 % |
| 25 | 27.3 % | 0.15 % | 31.8 % | 0.074 % |
| 28 | 25.6 % | 0.064 % | 29.3 % | 0.035 % |
| 30 | 18.5 % | 0.014 % | 24.9 % | 0.0082 % |
| **32** | **18.2 %** | **0.0064 %** | **24.6 %** | **0.0056 %** |
| 33 | 10.1 % | 0.0033 % | 15.1 % | 0.0033 % |

The table shows what the choice costs. In the test weeks, a threshold of
25 would flag three in ten more malicious files and thirteen times as many
benign ones. For a scanner that people are meant to trust, a false alarm is
the expensive mistake: this layer would rather stay silent.

## The bar for a second sign

A score below 32 reports nothing. It can still do one thing: back up a
finding of another layer that does not count alone. Today that is the
match of a YARA rule that a tool generated, which makes a file suspicious
only if the file's structure is unusual as well
([RULES.md](RULES.md#generated-rules) has the reasons).

"Unusual" needs a number, and it comes from a rule of the same kind as the
threshold: **the lowest score that at most one in twenty benign training
files of every kind reaches**. The rule gives 14. At 13, more than one in
twenty of the dataset's benign programs would reach it.

One in twenty is the choice here, and it is 250 times looser than the
threshold's one in 5,000. It can be, because reaching the bar reports
nothing. For a clean file to be reported, a generated rule has to match
it by mistake and its structure has to reach the bar, and the first of the
two is rare already: in the runs so far, generated rules matched 8 of about
448,000 clean files.

What other bars would do, on programs, which are the hard case:

| Second sign from | Malicious programs that reach it, test | Benign programs that reach it, training | Benign programs that reach it, test |
|---|---|---|---|
| 10 | 71.4 % | 15.1 % | 10.8 % |
| 13 | 60.5 % | 5.7 % | 4.5 % |
| **14** | **56.1 %** | **4.1 %** | **3.0 %** |
| 20 | 46.3 % | 2.0 % | 1.4 % |
| 25 | 37.9 % | 0.32 % | 0.22 % |

With the bar at 14, on the test weeks:

| Kind of file | Malicious files that reach it | Benign files that reach it |
|---|---|---|
| Programs | 56.1 % (125,742 of 224,062) | 3.0 % (1,922 of 63,669) |
| Libraries | 32.9 % (4,647 of 14,144) | 0.67 % (1,185 of 175,573) |
| .NET assemblies | 38.4 % (12,201 of 31,790) | 1.7 % (513 of 30,571) |
| All | 52.8 % (142,590 of 269,996) | 1.3 % (3,620 of 269,813) |

The left column is what the second sign costs. A generated rule that
matches a malicious file is backed up for about half of the dataset's
malicious files, and for the other half it is not, and then its match
changes nothing. On the challenge set it is worse: 95 of 4,868 reach the
bar, one in fifty. Whether the files that generated rules match are like
the dataset's files in this respect is not known; measuring it takes the
samples themselves.

A file that reaches the bar and not the threshold is given a finding of
its own, `Heuristic.UnusualExecutable`, which exists only to be counted
with. When nothing else waits for it, it is dropped, and the file's report
is what it would be without this layer. `warden inspect` says for every
file whether its score would be enough.

## What the score does

### On the weeks it was not fitted to

With a threshold of 32, on the test weeks:

| Kind of file | Malicious files flagged | Benign files flagged |
|---|---|---|
| Programs | 29.6 % (66,262 of 224,062) | 0.0079 % (5 of 63,669) |
| Libraries | 0.98 % (138 of 14,144) | 0.0057 % (10 of 175,573) |
| .NET assemblies | 0.079 % (25 of 31,790) | 0 of 30,571 |
| All | 24.6 % (66,425 of 269,996) | 0.0056 % (15 of 269,813) |

Read that as: of the malicious programs in the dataset's last twelve
weeks, the structure alone gives away three in ten, at the price of one
false alarm in 18,000 benign files. The numbers are a little better than on
the training weeks (18.2 % and 0.0064 %), so the score has not learned the
training weeks by heart.

It is a rate over the dataset's files, with the dataset's labels. It is
not a detection rate of Warden on malware in the wild, which this project
does not measure, see [TESTING.md](TESTING.md).

### On malware that nothing detected at first

Of the 4,868 Windows executables in the challenge set, the score flags
**none**. These are the files that got past every antivirus product on
the day they appeared. They are built to look ordinary, and to a layer
that only looks at structure they do. Even the bar for a second sign is
out of reach for most of them: 95 reach it.

### On a clean Windows installation

The benign files of the dataset are files that somebody uploaded to a
scanning service, often because something about them seemed odd. False
alarms that matter happen elsewhere: on the files of a Windows
installation. So the same tool counted the same indicators on a clean
machine, a GitHub-hosted runner with Windows Server 2025:

| Folder | Executables | Reach 32 | Reach 14, the bar for a second sign | Highest score |
|---|---|---|---|---|
| `C:\Windows\System32` | 9,015 | 0 | 5 | 20 |
| Installed software: 7-Zip, Git, Chrome, Firefox, PowerShell, .NET, Node.js | 45,261 | 0 | 0 | below 14 |

Three system files score 16 or more. The files of a Windows installation
are far more regular than the dataset's benign files. In System32, one
executable in 270 has no checksum, one in 130 has a section that is both
writable and executable, and one in 1,000 has code with high entropy; among
the dataset's benign files it is one in 4, one in 53 and one in 55.

A full scan of the same folders with all three layers, the files inside
archives included, flagged none of 109,500 files. Neither did a scan of
`C:\Windows\System32` on a Windows 11 desktop in daily use: none of 27,645
([BENCHMARKS.md](BENCHMARKS.md#with-the-heuristic-layer)).

All of that is system folders and a tidy server image. The harder test is
the installed programs of a desktop that people use, because that is where
packed and protected software is. It was run on the same desktop:
310,849 files in `C:\Program Files` and `C:\Program Files (x86)`, 74.5 GB,
and 345,010 more files inside archives. None reached the threshold. (The
YARA rules flagged 13 of those files. That is a matter for the rule layer:
see the [exclusion list](RULES.md#rules-that-are-left-out) and
[generated rules](RULES.md#generated-rules).)

In all, the layer has flagged none of 447,994 files that were expected to
be clean. Only the Windows executables among them can be flagged at all:
on the runner that is about half of the files, on the desktop they were not
counted. And it is two machines, not a promise about a third.

### What it costs

On a folder of executables the layer adds three quarters to the time of a
scan that only matches hashes, and under one percent to a scan with the
YARA rules. That was measured on a CI runner with two threads
([BENCHMARKS.md](BENCHMARKS.md#what-the-heuristic-layer-costs)). On a
desktop with sixteen threads the layer could not be seen in the time of
three passes over System32 without the rules; with the rules there is one
run on each side, which does not settle it.

## What this layer cannot do

- **It says little about libraries and nothing about .NET assemblies.**
  One in a hundred malicious libraries is flagged, and fewer than one in a
  thousand .NET assemblies. A .NET assembly keeps its code in metadata that
  this layer does not read; from the outside, they all look alike.
- **It catches what is built carelessly.** Three in ten malicious programs
  means seven in ten are not flagged. Malware built with an ordinary
  compiler, importing what it uses, looks like any other program. The
  challenge set shows it: none of 4,868.
- **It can be evaded by anyone who reads this page.** The weights are
  public. That is the price of a score that can be explained, and the
  reason this layer comes third, after the two that know files.
- **Its weights describe one dataset.** The labels come from the verdicts
  of antivirus products, so the fit learns, in part, what those products
  find suspicious. The files are those that reached VirusTotal in 64 weeks
  of 2023 and 2024. Malware changes, and so the measurement has to be
  repeated on newer data from time to time.
- **It is a simple model on purpose.** The dataset's authors report an
  area under the ROC curve above 0.99 for a gradient-boosted classifier on
  all of the dataset's features; this score reaches 0.91 with thirteen
  yes-or-no questions. That gap is what the optional machine-learning
  layer on the [roadmap](ROADMAP.md) would close, at the cost of a verdict
  that explains itself far less well.

## Doing it again

The counts, the report and the commands are in
[`calibration/`](../calibration/README.md). In short:

```text
cargo run --release -p warden-calibrate -- report calibration/ember2024-counts.zip calibration/installed-counts.json
```

prints the numbers on this page in a few seconds (with `--offer-all`,
those of the variant with the signature).
`cargo test -p warden-calibrate` fits the weights again and fails if the
scanner has others. The `Calibration` workflow reads the dataset and the
files of a Windows runner again from scratch.

To change the layer, add or change an indicator in
[`indicators.rs`](../crates/warden-pe/src/indicators.rs) with weight zero,
collect the counts again, and let the fit decide what it is worth. The test
then names the weights the scanner has to take over.

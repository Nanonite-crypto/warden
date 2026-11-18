# YARA rules

The second detection layer runs YARA rules over file content. This document
covers what the layer does, where its rules come from, how a rule match
becomes a verdict, and the rule bundle file format.

The engine underneath is [YARA-X](https://virustotal.github.io/yara-x/),
VirusTotal's implementation of YARA in Rust. The layer lives in the
`warden-yara` crate.

## Why a second layer

A hash signature matches one exact file. Add a line break and the hash is a
different one. A YARA rule describes byte patterns and file structure
instead, so it keeps matching when a file has been changed, repacked or
rebuilt. The price is speed: every rule has to be checked against every
byte, where a hash lookup is a few dozen nanoseconds.
[BENCHMARKS.md](BENCHMARKS.md) has the measurements.

Warden shows the difference with the EICAR test file. The plain 68-byte
file is known by hash. The same file with a line break added has another
hash and is caught only by the built-in rule:

```
warden eicar write demo --kind all
warden scan demo
```

## Where rules come from

**Built in.** One rule ships inside the program:
[`crates/warden-yara/rules/builtin.yar`](../crates/warden-yara/rules/builtin.yar).
It detects the EICAR test file by its definition: the 68 characters at the
start of the file, followed by nothing but whitespace, 128 bytes at most.
Built-in rules cover test files only.

**Rule bundles.** Everything else comes from rule files you choose.
`warden rules build` compiles them into a bundle, and `warden scan --rules`
uses it:

```
warden rules build my-rules.yar a-folder-of-rules\ a-package.zip --out rules.wrb
warden rules info rules.wrb
warden scan C:\Users\me\Downloads --rules rules.wrb
```

A rule that does not compile is left out and counted; it does not stop the
build. `--show-skipped` lists the rules that were left out with the reason.
The built-in rules are part of every bundle unless `--no-builtin` is given,
so a scan with a bundle catches everything a scan without one does.

### Other people's rules are not in this repository

Public rule sets belong to their authors and carry their own licences, some
of which restrict redistribution or commercial use. Warden therefore ships
none of them. The repository holds a pointer instead,
[`rules/yara-forge.pin`](../rules/yara-forge.pin): one release of
[YARA Forge](https://yarahq.github.io/), named by tag and SHA-256. YARA
Forge collects public rule repositories, filters them by quality, and
publishes the result as packages. Warden uses the "core" package, which
YARA Forge describes as leaving out rules that are prone to false positives
or slow.

```
scripts\win\check.cmd -Rules                                  (Windows: fetch, build and test)
bash scripts/fetch-rules.sh                                   (Linux)
warden rules build rules/vendor/yara-forge-rules-core.zip --out rules.wrb
```

The fetch scripts refuse a download that does not match the pinned
checksum. `warden rules info` lists the licences that the rules in a bundle
name, so you can see what you are running. For the pinned release:

| | |
|---|---|
| Release | 20261018 |
| Rules in the bundle | 5,138: all 5,137 of the package compiled, plus the built-in rule |
| Repositories the package draws on | 35 |
| Rules that name a licence | 3,083 |
| Rules that name none | 2,055 |
| Reported as malicious (score 80 and above) | 205 |
| Reported as suspicious (score 60 to 79) | 4,933 |

## From a match to a verdict

Detectors report, a policy decides: that rule of the engine holds here too.

1. A rule states how much a match means with a `score` from 0 to 100 in its
   metadata. This is a convention of public rule sets, described in the
   [YARA Style Guide](https://github.com/Neo23x0/YARA-Style-Guide): 80 to
   100 for direct matches on malware and hack tools, 60 to 79 for
   heuristics and generic detections, lower for things that are only
   noteworthy.
2. The YARA layer turns the score into a confidence: 80 and above is high,
   60 to 79 is medium, anything lower is low. A rule without a score is
   treated as 75.
3. The engine's verdict policy turns the strongest confidence into a
   verdict: high is malicious, medium is suspicious, low changes nothing.

So a single match of a generic rule makes a file suspicious, which is shown
to the user and never acted on automatically. Only rules whose authors rate
them as direct matches make a file malicious. The thresholds are options
(`YaraOptions`), not constants.

Metadata that Warden reads from a rule:

| Field | Use |
|---|---|
| `score` | Confidence, as above |
| `threat_name` | The name the detection is reported under. Default: the rule's name |
| `category` | `malware` (default), `test_file` or `potentially_unwanted` |
| `description`, `author`, `reference` | Shown as the reasons for a detection |
| `license`, `license_url` | Listed by `warden rules info` |

A detection always says why. These are the lines the built-in rule
produces for the test file:

```
yara [test file]: YARA rule Warden_EICAR_Test_File matched: the EICAR antivirus test file, a harmless file that every scanner detects on purpose
yara [test file]: Patterns found: $first at offset 0x0, $second at offset 0x21
yara [test file]: Rule score 100 of 100, written by Vevang Technologies, see https://www.eicar.org/download-anti-malware-testfile/
```

When many rules match one file, the ten with the highest scores are listed
and the rest are counted.

## Limits

- **Time.** One file may take the rules 30 seconds. After that the scan of
  that file is given up and the file is listed as partially scanned, with
  the reason `timeout`.
- **Size.** Files larger than the content limit (128 MiB by default) are
  checked by hash only and listed as partially scanned, with the reason
  `too_large`.
- **Modules.** The build includes the YARA modules `pe`, `dotnet`, `elf`,
  `macho`, `lnk`, `hash`, `math`, `string`, `time` and `console`. Rules
  that need another module (`magic`, `cuckoo` and a few more) are left out
  of the bundle and counted.
- **One thread, one scanner.** A YARA-X scanner holds the state of the rule
  engine and cannot be shared. Each worker thread has its own; the compiled
  rules are shared.
- **Packed and encrypted content.** Rules see the bytes of a file as it is
  on disk. Warden unpacks zip archives and runs the rules over the members;
  it does not unpack executables that are packed or encrypted. That is what
  the next layer, PE heuristics, is for.

## The rule bundle format

A bundle (`.wrb`) is one file: a fixed header, a manifest that records
where the rules came from, and the compiled rules. All integers are
little-endian. This is version 1.

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | Signature: `WRDNRUL` followed by a zero byte |
| 8 | 4 | Format version: 1 |
| 12 | 4 | Header length: 96 |
| 16 | 4 | Flags: 0 |
| 20 | 4 | Number of rules |
| 24 | 8 | Creation time, seconds since the Unix epoch |
| 32 | 8 | Length of the manifest in bytes |
| 40 | 8 | Length of the compiled rules in bytes |
| 48 | 16 | Reserved: zero |
| 64 | 32 | SHA-256 of bytes 0 to 63 followed by the manifest and the rules |

The manifest follows the header and is UTF-8 JSON:

```json
{
  "engine": "yara-x 1.23.0",
  "sources": [
    {
      "name": "warden/builtin.yar",
      "sha256": "e157092d259c6412922c8fae43f4b90d47d426045d2b7ea1ce76e8002ec51cee",
      "bytes": 1844,
      "rules": 1,
      "skipped": 0
    }
  ]
}
```

The compiled rules follow the manifest, in the form YARA-X serialises them.

When a bundle is opened, Warden checks in this order: the signature and
version, that the three lengths add up to the size of the file, the digest,
the manifest, that the bundle was built with the same YARA-X release as the
program, and that the number of rules matches the header. A file that fails
any check is refused as a whole.

Compiled rules load only in the YARA-X release that compiled them. A bundle
from another release is refused with the advice to build it again; the rule
files themselves stay valid.

### What the digest does and does not protect

The digest catches damage: a truncated download, a flipped bit. It does not
authenticate the bundle. Someone who can replace the file can write a
matching digest, and YARA-X's own documentation warns against loading
compiled rules from a source that is not trusted.

A bundle is therefore trusted in the same way as the program itself: it
must come from a place that only trusted users can write to. For the
command-line tool that is your own folder. For the service planned in phase
6 it is a folder that only the service and administrators can write to, and
phase 10 adds a signed manifest that covers the program, the signature
database and the rule bundle together.

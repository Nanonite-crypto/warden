# Who signed a file

A rule that was written to find malware describes byte patterns, and clean
software has byte patterns too. Sooner or later a published rule matches a
file of Windows or of a well-known program. For such a file there is better
evidence than the rule: a signature that says who the file comes from.

This document covers how Warden finds that signature, which publishers it
trusts and how one gets on that list, what a trusted signature changes
about a scan, and what it does not protect against. The code is the crate
[`warden-trust`](../crates/warden-trust); the measured numbers are in
[BENCHMARKS.md](BENCHMARKS.md#who-signed-what).

Signatures can only be checked on Windows. On Linux a scan says so in its
summary, asks nobody, and reports every match.

## Why

On 2026-11-20 a scan of a desktop's installed programs flagged one file of
310,910: `xpdAgent.exe` of the Microsoft Defender app, matched by
`RUSSIANPANDA_Purecrypter`, a rule that asks for little
([RULES.md](RULES.md#rules-that-are-left-out)). The file carries a valid
signature of Microsoft Corporation. Warden could not read it, so the only
remedy was to leave the rule out of the bundle, for every file on every
machine.

Leaving a rule out costs detection: the rule no longer finds what it was
written for either. A signature costs less. The rule stays, and its match
is set aside only in a file whose publisher is known and trusted.

## A valid signature is not trust

A signature says two things: who signed the file, and that the file has not
been changed since. It does not say that the file is harmless. Malware is
signed too, with certificates that were bought under a made-up company name
or stolen from a real one, and such a signature is as valid as any other
until the certificate is revoked.

So Warden never asks "is this file signed?". It asks "did one of a few
named publishers sign this file?", and a valid signature of anybody else
changes nothing.

## Three routes to a signature

A file on Windows can be signed in three ways. A check that knows only the
first misses most of Windows: on a Windows runner in CI, 19 % of the
executables in System32 carry a signature that Warden trusts, and another
78 % are vouched for in a catalogue
([BENCHMARKS.md](BENCHMARKS.md#by-which-route)).

| Route | Where the signature is | What it is typical of |
|---|---|---|
| Embedded | Inside the executable, in a table at its end | Applications, and the parts of Windows that are needed before the catalogues can be read |
| Windows catalogue | In a catalogue: a signed list of file hashes that Windows keeps in `System32\CatRoot` | Most files of Windows itself, which carry nothing |
| Package | In `AppxSignature.p7x` in the folder of an app package | The files of apps from the Microsoft Store, under `C:\Program Files\WindowsApps` |

Warden tries them in that order and stops at the first that finds a
signature of a publisher on the list. `warden trust check` tries all three
and shows what each found.

### Embedded

Windows checks the signature, through `WinVerifyTrust`. Warden does one
thing first that Windows does not do by default.

The table that holds the signature cannot be covered by the signature: the
signature is in it. Bytes added inside that table leave the signature
valid. Windows has had a stricter check since 2013, and it is still
something an administrator has to switch on
([CVE-2013-3900](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2013-3900)):
switched on, it makes existing software that keeps data there count as
unsigned. A malware campaign that was described in January 2022 used the
gap: it added a script to a library that Microsoft had signed, the
signature stayed valid, and a tool of Windows ran the script
([Check Point Research](https://research.checkpoint.com/2022/can-you-trust-a-files-digital-signature-new-zloader-campaign-exploits-microsofts-signature-verification-putting-users-at-risk/)).

Warden reads the table itself, without Windows, before it asks about the
signature. The table has to hold exactly one signature, the signature has
to fill its entry up to the padding that the format calls for, and the
table has to be the last thing in the file. Anything else and the file's
signature does not count. This is done in
[`sigarea.rs`](../crates/warden-trust/src/sigarea.rs), with no `unsafe`
code and with its own fuzz target.

CI makes such a file to test with: a signed program with forty bytes added
inside the table. On the hosted runner, a Windows Server 2025, PowerShell's
`Get-AuthenticodeSignature` calls it "Valid". Warden says that bytes follow
the signature inside its entry, and does not trust it.

### Windows catalogue

Windows works out the hash by which its catalogues list a file, finds the
catalogues that list that hash, and checks the signature of the catalogue.
Warden asks for all of that through the catalogue functions of Windows and
`WinVerifyTrust`, with SHA-256 first and SHA-1 for older catalogues.

The hash a catalogue lists is the same kind of hash an embedded signature
covers, so it leaves the signature table out as well. A file that is listed
in a catalogue stays listed when somebody adds a signature table to it with
anything in it. So Warden looks a file up in the catalogues only if it has
no signature table at all.

### Package

Windows unpacks an app from the Microsoft Store into a folder of its own,
and the files in it are not signed one by one. Two files in the folder
carry the signature of the whole package:

- `AppxBlockMap.xml` lists every file of the package with its length and
  the SHA-256 of each 64 KiB block of it.
- `AppxSignature.p7x` is the signature. What it signs is a short list of
  digests, and one of them is the SHA-256 of the block map.

A file is covered if its blocks hash to what the block map says, the block
map hashes to what the signature says, and the signature holds. Warden does
the first two steps itself, which is arithmetic, and asks Windows about the
third with the very bytes it read. Every byte of the file is covered this
way, so this is the one route that also works for a file that is no
executable.

Three files of a package are not in its block map, because they are what
describes it: the block map itself, `[Content_Types].xml`, and
`AppxMetadata\CodeIntegrity.cat` where a package has one. The signature
names each of them by a digest of its own, the SHA-256 of the whole file,
and Warden compares. That leaves one file of a package that nothing covers:
`AppxSignature.p7x`. A signature cannot cover itself.

Both files lie in a folder that anyone with the rights may have written to,
so they are read with a limit on every size, the block map is parsed only
after Windows has accepted the signature, and a block map with a document
type declaration is refused.

### Files that are no executables

A signature inside a file is only looked for in Windows executables, and
only those are looked up in the catalogues. Scripts and installer packages
can be signed as well, each format in its own way, and for those Warden
could not say which part of the file the signature leaves uncovered. A file
that is no executable can be trusted as part of a package and no other way.

## The same bytes

A scan reads a file, and the check opens it again a moment later. Between
the two, the file could be swapped for one with a good signature and
swapped back. Two things rule that out:

- The check opens the file so that nobody can write to it, rename it or
  delete it until the check is done, and hands Windows that open file, not
  the path.
- The check computes the SHA-256 of what it opened and compares it with the
  SHA-256 the scan computed. If they differ, the file is not trusted.

This is the one place where Warden keeps other programs from writing to a
file, for as long as one check takes. A scan asks about very few files, see
[below](#what-a-trusted-signature-changes).

## What Windows is asked

Whether a signature holds is a question for Windows, which owns the
certificates and the rules. Warden does not rebuild any of that. For each
route it calls `WinVerifyTrust`, with no user interface, after the
catalogue functions of Windows have found the catalogue where one is
needed. From the answer it reads:

- **who signed**: the name and the organisation in the signer's
  certificate, and the chain of certificates up to the root, each with its
  SHA-256;
- **whether the chain ends in one of Microsoft's own roots**, by Windows'
  own check of the root's key
  (`CERT_CHAIN_POLICY_MICROSOFT_ROOT`). A root that somebody installed
  under Microsoft's name does not pass it, because it has another key;
- **whether revocation was checked** for every certificate below the root.

All of this is in one module,
[`windows.rs`](../crates/warden-trust/src/windows.rs), the only one in the
crate with `unsafe` code.

## The trust list

[`trust/publishers.toml`](../trust/publishers.toml) names the publishers
Warden trusts. It is compiled into the program: whoever can write next to
`warden.exe` cannot add a publisher. `warden trust list` prints it, and
every scan report carries its SHA-256.

### What an entry holds

```toml
[[publisher]]
name = "Microsoft Corporation"
common_name = "Microsoft Corporation"
organization = "Microsoft Corporation"
anchor = "microsoft-root"
signs = "Microsoft's own applications, ..."
reason = "A rule written by hand flagged a file of the Microsoft Defender app ..."
added = 2026-11-21

[[publisher.evidence]]
file = 'C:\Program Files\WindowsApps\Microsoft.6365217CE6EB4_...\MicrosoftSecurityApp\xpdAgent.exe'
sha256 = "86f95974cb32af876d64a85b647b042e5aa3d215d8daff481d1f876b1373a8ec"
route = "embedded"
seen = 2026-11-21
machine = "Windows 11 desktop"
```

An entry is a signing identity, not a company:

- `common_name` and `organization` are the two fields of the signer's
  certificate that say who it is for. Both have to match exactly.
- `anchor` is what ties those names to somebody who was checked. A name
  alone is worth nothing: anyone who runs a certificate authority of their
  own can issue a certificate that says "Microsoft Corporation". The anchor
  is either `"microsoft-root"`, which means the chain ends in one of
  Microsoft's own roots by Windows' check of the root's key, or
  `"sha256:..."`, a certificate that has to be in the chain: the
  publisher's own, the one of the authority that issued it, or the root.
- `signs` says in words what this identity is used for, and what it is not.
- `reason` says why the entry is there: which false positive it answers.
- `evidence` is at least one real file that was seen with such a signature:
  its path, its SHA-256, the route, the day and the machine, and a note on
  how it was read where that helps.

An entry without evidence is refused, and so are a field the format does
not know and a second entry for the same names and anchor. A test loads the
list in this repository, so a mistake in it fails in CI.

A signature that carries the two names of a listed publisher without the
chain is somebody else's, and the file is not trusted. `warden trust check`
then says which chain the list asks for, so that the answer does not read
"Microsoft Corporation is not on the list".

### Who is on it

Two signing identities, both Microsoft's, both added on 2026-11-21:

| Publisher | Names in the certificate | What it signs | Evidence |
|---|---|---|---|
| Microsoft Corporation | name and organisation "Microsoft Corporation" | Microsoft's applications, and the packages of the apps Microsoft itself publishes in the Microsoft Store | `xpdAgent.exe` of the Microsoft Defender app on a desktop; `pwsh.exe` of PowerShell 7 on the CI runner |
| Microsoft Windows | name "Microsoft Windows", organisation "Microsoft Corporation" | Windows itself: its system files, through the catalogues and in the file | `ntdll.dll`, which carries its signature, and `whoami.exe`, which a catalogue lists, on the CI runner |

For both, the chain has to end in one of Microsoft's own roots.

Microsoft signs under many more names than these two, and they are not on
the list: ".NET" for the .NET runtime, "Microsoft Windows Hardware
Compatibility Publisher" for other companies' drivers, "Microsoft 3rd Party
Application Component" for other people's code that Microsoft ships. A
chain that ends in a root of Microsoft's says that Microsoft signed, not
that Microsoft wrote the code. How many files each of those names signs on
a Windows machine is in
[BENCHMARKS.md](BENCHMARKS.md#who-is-not-on-the-list).

### How a publisher gets on the list

The list is narrow on purpose. Every entry is a publisher whose key, if it
is stolen, signs malware that a published rule will no longer report.

1. **There has to be a false positive.** A rule from the bundle flagged a
   clean file of this publisher in a run over clean software
   ([TESTING.md](TESTING.md#false-positives)). Nobody gets on the list
   because their software is popular.
2. **The signature is read with Warden**: `warden trust check FILE` shows
   the route, the two names, the chain and whether revocation was checked.
3. **The anchor is chosen as narrow as it can be**: for anybody but
   Microsoft, the SHA-256 of the publisher's own certificate or of the
   issuing authority's, not a root that signs for thousands of companies.
   A certificate that is pinned by its SHA-256 has to be pinned again when
   the publisher renews it; that is the price, and it is paid on purpose.
4. **The entry is written with the evidence**, in a commit of its own that
   says which run flagged which file.
5. **The run is repeated**, and both results go into
   [BENCHMARKS.md](BENCHMARKS.md).

A publisher comes off the list the same way it came on: with a commit that
says why. A stolen key is reason enough.

Where the choice is between the trust list and the
[exclusion list](RULES.md#rules-that-are-left-out), the trust list comes
first. An exclusion takes a rule away from every file; a trusted publisher
takes its match away from that publisher's files only. The exclusion list
is for rules that flag clean files nobody on the trust list signed.

## Revocation and the network

A certificate authority revokes a certificate when its key is stolen or
was obtained by fraud. A check that does not ask about revocation trusts
such a key for as long as the certificate runs.

Windows is asked to check every certificate of the chain below the root. It
looks in what it has stored from earlier checks, and where it has nothing
it asks the certificate authority over the network. If it cannot find out,
because the machine is offline, or the answer does not come, or a
certificate names no place to ask, the signature does not count, even if it
is of a publisher on the list. The finding is then reported, and it says
that revocation could not be checked.

This is the strict choice. Windows itself is more lenient and accepts a
signature whose revocation it could not check. Warden errs on the side of
reporting: what is at stake is whether a rule match is shown, and showing
one too many is the smaller mistake.

`--offline` keeps Windows from using the network. Only what it has stored
is used then, and a certificate it knows nothing about counts as not
checked.

## What a trusted signature changes

One thing: the match of a rule that came with a rule bundle is recorded and
not reported.

| Finding | With a trusted signature |
|---|---|
| A hash match against the signature database | Reported, as always. A hash names one exact file, and no signature makes that file something else |
| The match of a rule that is part of the program | Reported |
| The match of a rule from a bundle | Recorded with low confidence, with the publisher and the route as the reason. It does not change the verdict, and it is no second sign for a finding of another layer |
| A finding about the structure of an executable | Reported |

Warden cannot tell a published rule in a bundle from one its user wrote, so
all rules of a bundle are treated alike.

The check is asked only when it matters: when a file has a match of a
bundle's rule that would otherwise be reported. Most files have no finding
at all and are never asked about, and the report says how many were. In
the scans of 112,675 files on a Windows runner that was none; where it is
asked, a check takes a few milliseconds, or a tenth of a second and more
through a catalogue on a machine that has not been asked before
([BENCHMARKS.md](BENCHMARKS.md#what-a-check-costs)).

Two kinds of content are never asked about:

- **A file inside an archive.** Its bytes are not a file on disk, and the
  signature of the archive around it does not cover it for certain, see
  [Limits](#limits).
- **Bytes that were handed to the engine in memory.** There is no file to
  ask about.

### In a report

A scan report (schema 5) and a false-positive result (schema 4) carry:

- `trust_check`: whether signatures could be checked, the SHA-256 of the
  trust list, and how many publishers are on it;
- `trust_checks` and `files_trusted`: how many files were asked about, and
  how many of them a trusted publisher had signed;
- `trust` on each file that was asked about: the publisher and the route,
  or the reason the file is not trusted;
- `yields_to_trust` on each finding that would have yielded.

A file whose match yielded keeps a clean verdict and is listed among the
files with findings on record, so "why was this not flagged?" has an
answer.

## The commands

```text
warden trust check FILE...     who signed these files, route by route
warden trust list              the publishers that are part of the program
warden trust survey FOLDER...  check every file and count
```

`check` exits with 1 if a file is not trusted. `survey` counts files and
executables by publisher and route, by reason where a file is not trusted,
and how long a check takes. It names no signer that is not on the list
unless `--signers` is given, and no file unless `--examples` is: a survey
of a private machine shows which programs are installed on it.

`warden scan`, `false-positives` and `bench` check signatures unless
`--no-trust` is given.

## Limits

- **A stolen or abused key of a listed publisher.** A file signed with it
  is trusted until the certificate is revoked and Windows learns of it.
  That is what the list being short is for.
- **Data inside the signature itself.** Warden makes sure the table holds
  one signature and nothing beside it. A signature is itself a structure
  with parts that it does not cover, such as timestamps and further
  signatures, and data can be put there without breaking it. A rule match
  on such data in a trusted file is set aside like any other. The program
  in that file is still the publisher's and does nothing with the data;
  something else has to read it, and that something is a file of its own.
- **Archives.** For the reason above, a signed file can hold an archive
  that its signature does not cover. So nothing inside an archive is ever
  trusted because of the file around it, and a match there is reported.
- **A trusted program that is used for something bad.** A signature says
  who made a program, not what it is being used for. Tools of Windows are
  used in attacks all the time. Warden's rules do not report the tool; this
  check would not either.
- **Files with a signature table that a catalogue lists.** They are not
  looked up in the catalogues, so they are trusted only if their own
  signature is of a publisher on the list.
- **Files that are no executables**, outside a package: signed scripts and
  installer packages are not recognised as signed.
- **Machines that are offline.** Without stored answers about revocation,
  no signature counts.
- **The machine's own Windows is believed.** Whoever controls Windows as an
  administrator controls what it answers. Such a program does not need to
  hide from a rule match.
- **Windows only.**

## How it is tested

Without Windows, with a stand-in that answers for it; with damaged input
for the three readers; and on Windows in CI against signatures that are
made there for the purpose, including the ones that have to be turned down.
See [TESTING.md](TESTING.md#signatures).

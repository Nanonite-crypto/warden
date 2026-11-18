# Signature database format (`.wdb`), version 1

A Warden signature database maps SHA-256 digests of known-bad files to
detection names. It is implemented by the `warden-sigdb` crate.

## Goals

- **No load cost.** The file is memory-mapped and queried in place. Nothing is
  parsed into heap structures, so a database with millions of entries opens
  without allocating.
- **Fast negative lookups.** Almost every file a scanner sees is not in the
  database, so the common case is a miss. A 16-bit prefix index narrows a
  lookup to a handful of candidates before any hash is compared.
- **Safe on hostile input.** The file is verified in full when it is opened.
  After that, no lookup can read out of bounds or return an answer from a
  damaged table, whatever the file contained.
- **Reproducible.** The same set of signatures and the same creation time
  always produce the same bytes.

## Layout

All integers are little-endian. Sections follow the header in a fixed order
with no gaps or padding, so version 1 has exactly one valid layout for a
given entry count, name count and name-blob length.

| Section | Size in bytes | Content |
|---|---|---|
| Header | 128 | See below |
| Prefix index | 65,536 × 4 | `u32` per 16-bit prefix: number of hashes whose first two bytes, read big-endian, are less than or equal to that prefix |
| Hash table | entries × 32 | SHA-256 digests, sorted ascending, unique |
| Name ids | entries × 4 | `u32` per hash: index of its detection name |
| Name offsets | (names + 1) × 4 | `u32` offsets into the name blob; name *i* is the bytes from offset *i* to offset *i + 1* |
| Name categories | names × 1 | `u8` per name: 1 malware, 2 test file, 3 potentially unwanted |
| Name blob | variable | Detection names, UTF-8, concatenated without separators |

### Header

| Offset | Size | Field | Value |
|---|---|---|---|
| 0 | 8 | Magic | `WRDNSIG\0` |
| 8 | 4 | Format version | 1 |
| 12 | 4 | Header length | 128 |
| 16 | 4 | Hash algorithm | 1 (SHA-256) |
| 20 | 4 | Flags | 0 |
| 24 | 8 | Entry count | Number of hashes |
| 32 | 4 | Name count | Number of distinct detection names |
| 36 | 4 | Reserved | 0 |
| 40 | 8 | Created | Seconds since the Unix epoch |
| 48 | 8 × 6 | Section offsets | Start of each section after the header, in the order of the table above |
| 96 | 32 | Digest | SHA-256 over header bytes 0 to 95 followed by every byte after the header |

The section offsets are redundant: they can be computed from the counts. They
are stored so that the file describes itself to other tools, and the reader
requires them to match the computed layout.

## Lookup

1. Read the first two bytes of the hash as a big-endian number `p`.
2. The candidates are entries `index[p - 1]` (or 0 when `p` is 0) up to, but
   not including, `index[p]`.
3. Binary-search those candidates.

With one million entries a bucket holds about fifteen hashes, so a lookup
touches one index page and one or two hash-table pages.

## Verification on open

Every one of these is checked before a database is handed to the caller:

1. The file holds a complete header with the right magic, version, header
   length and algorithm, and with flags and reserved fields at zero.
2. The entry count fits the format, the section sizes do not overflow, and
   the file is long enough for them.
3. The stored section offsets equal the canonical layout.
4. The stored digest matches the file.
5. The prefix index never decreases, never exceeds the entry count, ends at
   the entry count, and every hash sits in the bucket its prefix says.
6. The hash table is strictly ascending.
7. Every name id refers to an existing name.
8. Name offsets start at zero, never decrease, and end exactly at the end of
   the blob. Every name is valid UTF-8, between 1 and 200 bytes, without
   control characters or surrounding whitespace, and has a known category.

Steps 5 to 8 run even when the digest matches. The digest only detects
accidental damage: anyone can compute it, so it says nothing about who wrote
the file. Authenticity (a signed manifest over the database and the binaries)
is part of the self-protection work in phase 10.

## Updating a database in use

On Windows a database is opened without write or delete sharing, so no other
process can change, replace or remove it while a scanner has it mapped. To
update, write the new database under a new name, switch the scanner over, and
remove the old file once it is closed. The builder itself writes atomically:
temporary file, flush to disk, rename into place.

## Limits

| Limit | Value |
|---|---|
| Entries | 4,294,967,295 |
| Distinct names | 4,294,967,295 |
| Name length | 200 bytes |
| Total size of all names | 4 GiB |

## Building one

```
warden sigdb build --out signatures.wdb --hashes hashes.txt --name Malware.Generic
warden sigdb build --out signatures.wdb --csv named.csv
warden sigdb info signatures.wdb
warden sigdb lookup signatures.wdb <sha256>
```

- `--hashes` takes a text file with one hexadecimal SHA-256 per line, the
  shape of MalwareBazaar's plain-text hash export. Blank lines and lines
  starting with `#` are ignored.
- `--csv` takes rows of `sha256,name` or `sha256,name,category`.
- Malformed lines are counted and reported, not fatal.
- When a hash appears more than once, the first signature wins.
- `--created`, or the `SOURCE_DATE_EPOCH` environment variable, fixes the
  creation time so that a build is reproducible byte for byte.

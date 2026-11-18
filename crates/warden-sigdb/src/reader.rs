use std::fmt;
use std::fs::{File, OpenOptions};
use std::path::Path;

use crate::Sha256;
use crate::error::SigDbError;
use crate::format::{self, Category, HASH_LEN, HEADER_LEN, Header, Layout};

/// One signature: what a file with a matching hash is reported as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature<'db> {
    /// Detection name, for example `Trojan.Example`.
    pub name: &'db str,
    /// What kind of thing the signature identifies.
    pub category: Category,
}

enum Backing {
    Mapped {
        map: memmap2::Mmap,
        /// Kept open for as long as the mapping lives, so that the sharing
        /// mode it was opened with keeps protecting the file.
        _file: File,
    },
    Owned(Vec<u8>),
}

impl Backing {
    fn bytes(&self) -> &[u8] {
        match self {
            Self::Mapped { map, .. } => map,
            Self::Owned(bytes) => bytes,
        }
    }
}

/// An opened signature database.
///
/// A `SigDb` only exists for a file that passed full verification, so its
/// methods cannot fail and never read out of bounds. It is cheap to share:
/// wrap it in an `Arc` and query it from any number of threads.
pub struct SigDb {
    backing: Backing,
    layout: Layout,
    entry_count: usize,
    name_count: usize,
    created_unix_secs: u64,
    digest: Sha256,
}

impl fmt::Debug for SigDb {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SigDb")
            .field("entries", &self.entry_count)
            .field("names", &self.name_count)
            .field("created_unix_secs", &self.created_unix_secs)
            .field("digest", &crate::hex::encode(&self.digest))
            .field("memory_mapped", &self.is_memory_mapped())
            .finish()
    }
}

impl SigDb {
    /// Memory-maps and verifies the database at `path`.
    ///
    /// On Windows the file is opened without write or delete sharing, so no
    /// other process can modify, replace or remove it while it is in use.
    ///
    /// # Errors
    ///
    /// Fails if the file cannot be opened or mapped, or if it is not a valid
    /// database: wrong magic or version, truncated, digest mismatch, or any
    /// structural invariant violated.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SigDbError> {
        let path = path.as_ref();
        let context = || format!("cannot open signature database {}", path.display());
        let file = open_read_only(path).map_err(|source| SigDbError::io(context(), source))?;
        let len = file
            .metadata()
            .map_err(|source| SigDbError::io(context(), source))?
            .len();
        if len < HEADER_LEN as u64 {
            // Also covers empty files, which cannot be mapped on every platform.
            return Err(SigDbError::Truncated {
                expected: HEADER_LEN as u64,
                actual: len,
            });
        }
        let map = map_file(&file).map_err(|source| SigDbError::io(context(), source))?;
        Self::from_backing(Backing::Mapped { map, _file: file })
    }

    /// Verifies a database held in memory.
    ///
    /// # Errors
    ///
    /// Fails on the same validity conditions as [`open`](Self::open).
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Result<Self, SigDbError> {
        Self::from_backing(Backing::Owned(bytes.into()))
    }

    fn from_backing(backing: Backing) -> Result<Self, SigDbError> {
        let verified = verify(backing.bytes())?;
        Ok(Self {
            backing,
            layout: verified.layout,
            entry_count: verified.entry_count,
            name_count: verified.name_count,
            created_unix_secs: verified.created_unix_secs,
            digest: verified.digest,
        })
    }

    /// Number of hashes in the database.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entry_count
    }

    /// Whether the database holds no hashes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entry_count == 0
    }

    /// Number of distinct detection names.
    #[must_use]
    pub fn name_count(&self) -> usize {
        self.name_count
    }

    /// When the database was built, in seconds since the Unix epoch.
    #[must_use]
    pub fn created_unix_secs(&self) -> u64 {
        self.created_unix_secs
    }

    /// The digest stored in the header, which identifies this exact database.
    #[must_use]
    pub fn digest(&self) -> Sha256 {
        self.digest
    }

    /// Size of the database in bytes.
    #[must_use]
    pub fn size_bytes(&self) -> u64 {
        self.backing.bytes().len() as u64
    }

    /// Whether the database is memory-mapped rather than held on the heap.
    #[must_use]
    pub fn is_memory_mapped(&self) -> bool {
        matches!(self.backing, Backing::Mapped { .. })
    }

    /// Looks up a hash.
    ///
    /// The first two bytes of the hash select a bucket through the prefix
    /// index; a binary search inside that bucket finishes the job. With a
    /// million entries a bucket holds about fifteen hashes.
    #[must_use]
    pub fn lookup(&self, hash: &Sha256) -> Option<Signature<'_>> {
        let prefix = usize::from(u16::from_be_bytes([hash[0], hash[1]]));
        let end = self.fanout(prefix);
        let start = if prefix == 0 {
            0
        } else {
            self.fanout(prefix - 1)
        };
        let bucket = &self.hashes()[start..end];
        let position = bucket.binary_search(hash).ok()?;
        Some(self.signature_at(start + position))
    }

    /// Whether the database contains a hash.
    #[must_use]
    pub fn contains(&self, hash: &Sha256) -> bool {
        self.lookup(hash).is_some()
    }

    /// Iterates over every hash and its signature, in ascending hash order.
    #[must_use]
    pub fn iter(&self) -> Iter<'_> {
        Iter { db: self, next: 0 }
    }

    fn section(&self, range: &std::ops::Range<usize>) -> &[u8] {
        &self.backing.bytes()[range.clone()]
    }

    fn hashes(&self) -> &[Sha256] {
        self.section(&self.layout.hashes).as_chunks::<HASH_LEN>().0
    }

    /// Number of hashes whose 16-bit prefix is less than or equal to `prefix`.
    fn fanout(&self, prefix: usize) -> usize {
        format::read_u32(self.section(&self.layout.fanout), prefix * 4) as usize
    }

    fn signature_at(&self, index: usize) -> Signature<'_> {
        let name_id = format::read_u32(self.section(&self.layout.name_ids), index * 4) as usize;
        let offsets = self.section(&self.layout.name_offsets);
        let start = format::read_u32(offsets, name_id * 4) as usize;
        let end = format::read_u32(offsets, (name_id + 1) * 4) as usize;
        // Verification proved every name is valid UTF-8 and every category
        // byte is known; the fallbacks keep this function free of panics even
        // if that proof were ever wrong.
        let name = std::str::from_utf8(&self.section(&self.layout.name_blob)[start..end])
            .unwrap_or("<invalid name>");
        let category = Category::from_u8(self.section(&self.layout.name_categories)[name_id])
            .unwrap_or(Category::Malware);
        Signature { name, category }
    }
}

impl<'db> IntoIterator for &'db SigDb {
    type Item = (Sha256, Signature<'db>);
    type IntoIter = Iter<'db>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Iterator over the entries of a [`SigDb`], in ascending hash order.
#[derive(Debug)]
pub struct Iter<'db> {
    db: &'db SigDb,
    next: usize,
}

impl<'db> Iterator for Iter<'db> {
    type Item = (Sha256, Signature<'db>);

    fn next(&mut self) -> Option<Self::Item> {
        let hash = *self.db.hashes().get(self.next)?;
        let signature = self.db.signature_at(self.next);
        self.next += 1;
        Some((hash, signature))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.db.len() - self.next;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for Iter<'_> {}

fn open_read_only(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_SHARE_READ: u32 = 0x0000_0001;
        options.share_mode(FILE_SHARE_READ);
    }
    options.open(path)
}

#[allow(unsafe_code)]
fn map_file(file: &File) -> std::io::Result<memmap2::Mmap> {
    // SAFETY: a mapping is only sound while nothing changes the file under
    // it. On Windows `open_read_only` denies write and delete sharing, so the
    // operating system enforces that for the lifetime of the mapping. On
    // other platforms the database is an immutable artifact that Warden
    // itself only ever replaces by renaming a new file into place, which
    // leaves existing mappings pointing at the old, unchanged file.
    unsafe { memmap2::Mmap::map(file) }
}

struct Verified {
    layout: Layout,
    entry_count: usize,
    name_count: usize,
    created_unix_secs: u64,
    digest: Sha256,
}

/// Checks everything a lookup relies on.
///
/// The digest catches accidental damage. It is not a signature: anyone can
/// compute it. The structural checks therefore run for every file, including
/// ones whose digest matches, so that a deliberately crafted database still
/// cannot cause an out-of-bounds read or a wrong answer.
fn verify(bytes: &[u8]) -> Result<Verified, SigDbError> {
    let actual = bytes.len() as u64;
    if bytes.len() < HEADER_LEN {
        return Err(SigDbError::Truncated {
            expected: HEADER_LEN as u64,
            actual,
        });
    }
    let header = Header::decode(bytes)?;
    if header.entry_count > u64::from(u32::MAX) {
        return Err(SigDbError::Corrupt("entry count exceeds the format limit"));
    }
    let fixed = Layout::fixed_len(header.entry_count, header.name_count)
        .ok_or(SigDbError::Corrupt("section sizes overflow"))?;
    if actual < fixed {
        return Err(SigDbError::Truncated {
            expected: fixed,
            actual,
        });
    }
    let layout = Layout::new(header.entry_count, header.name_count, actual - fixed).ok_or(
        SigDbError::Corrupt("database does not fit in the address space"),
    )?;
    if header.offsets != layout.offsets() {
        return Err(SigDbError::Corrupt(
            "section offsets do not match the canonical layout",
        ));
    }
    if format::compute_digest(&bytes[..HEADER_LEN], &bytes[HEADER_LEN..]) != header.digest {
        return Err(SigDbError::DigestMismatch);
    }

    let entry_count = usize::try_from(header.entry_count)
        .map_err(|_| SigDbError::Corrupt("database does not fit in the address space"))?;
    let name_count = header.name_count as usize;

    verify_hash_table(
        &bytes[layout.fanout.clone()],
        &bytes[layout.hashes.clone()],
        entry_count,
    )?;
    verify_names(
        &bytes[layout.name_offsets.clone()],
        &bytes[layout.name_categories.clone()],
        &bytes[layout.name_blob.clone()],
        name_count,
    )?;
    let (name_ids, _) = bytes[layout.name_ids.clone()].as_chunks::<4>();
    if name_ids
        .iter()
        .any(|raw| u32::from_le_bytes(*raw) as usize >= name_count)
    {
        return Err(SigDbError::Corrupt(
            "an entry refers to a missing detection name",
        ));
    }

    Ok(Verified {
        layout,
        entry_count,
        name_count,
        created_unix_secs: header.created_unix_secs,
        digest: header.digest,
    })
}

fn verify_hash_table(
    fanout_bytes: &[u8],
    hash_bytes: &[u8],
    entry_count: usize,
) -> Result<(), SigDbError> {
    let (fanout, _) = fanout_bytes.as_chunks::<4>();
    let (hashes, _) = hash_bytes.as_chunks::<HASH_LEN>();

    let mut start = 0usize;
    for (prefix, raw) in fanout.iter().enumerate() {
        let end = u32::from_le_bytes(*raw) as usize;
        if end < start || end > entry_count {
            return Err(SigDbError::Corrupt("prefix index is not monotonic"));
        }
        let misfiled = hashes[start..end]
            .iter()
            .any(|hash| usize::from(u16::from_be_bytes([hash[0], hash[1]])) != prefix);
        if misfiled {
            return Err(SigDbError::Corrupt(
                "a hash is filed under the wrong prefix",
            ));
        }
        start = end;
    }
    if start != entry_count {
        return Err(SigDbError::Corrupt(
            "prefix index does not cover every entry",
        ));
    }
    if hashes.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(SigDbError::Corrupt("hash table is not sorted and unique"));
    }
    Ok(())
}

fn verify_names(
    offset_bytes: &[u8],
    categories: &[u8],
    blob: &[u8],
    name_count: usize,
) -> Result<(), SigDbError> {
    let (offsets, _) = offset_bytes.as_chunks::<4>();
    let offset = |index: usize| u32::from_le_bytes(offsets[index]) as usize;

    if offset(0) != 0 {
        return Err(SigDbError::Corrupt(
            "name table does not start at offset zero",
        ));
    }
    debug_assert_eq!(categories.len(), name_count);
    for (index, &category) in categories.iter().enumerate() {
        let (start, end) = (offset(index), offset(index + 1));
        if end < start || end > blob.len() {
            return Err(SigDbError::Corrupt("name table offsets are out of order"));
        }
        let name = std::str::from_utf8(&blob[start..end])
            .map_err(|_| SigDbError::Corrupt("a detection name is not valid UTF-8"))?;
        if format::check_name(name).is_err() {
            return Err(SigDbError::Corrupt("a detection name is not acceptable"));
        }
        if Category::from_u8(category).is_none() {
            return Err(SigDbError::Corrupt(
                "a detection name has an unknown category",
            ));
        }
    }
    if offset(name_count) != blob.len() {
        return Err(SigDbError::Corrupt(
            "name blob has unreferenced trailing bytes",
        ));
    }
    Ok(())
}

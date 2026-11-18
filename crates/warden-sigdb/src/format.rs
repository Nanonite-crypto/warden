//! On-disk layout of the signature database. See `docs/SIGDB_FORMAT.md`.

use std::fmt;
use std::ops::Range;
use std::str::FromStr;

use sha2::{Digest, Sha256 as Sha256Hasher};

use crate::Sha256;
use crate::error::SigDbError;

/// File magic: the first eight bytes of every signature database.
pub const MAGIC: [u8; 8] = *b"WRDNSIG\0";
/// Format version written and read by this crate.
pub const FORMAT_VERSION: u32 = 1;
/// Size of the fixed header in bytes.
pub const HEADER_LEN: usize = 128;
/// Size of one hash record in bytes (SHA-256).
pub const HASH_LEN: usize = 32;
/// Longest accepted detection name, in bytes.
pub const MAX_NAME_LEN: usize = 200;

/// Number of entries in the prefix index: one per 16-bit hash prefix.
pub(crate) const FANOUT_ENTRIES: usize = 1 << 16;
pub(crate) const FANOUT_BYTES: u64 = (FANOUT_ENTRIES as u64) * 4;
pub(crate) const HASH_ALGORITHM_SHA256: u32 = 1;
/// Offset of the digest field inside the header. The digest covers the header
/// bytes before this offset and every byte after the header.
pub(crate) const DIGEST_OFFSET: usize = 96;

/// What kind of thing a signature identifies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Category {
    /// Malicious software.
    Malware,
    /// A harmless antivirus test file, such as the EICAR test file.
    TestFile,
    /// A potentially unwanted program: not malware, but rarely wanted.
    PotentiallyUnwanted,
}

impl Category {
    /// The byte this category is stored as.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Malware => 1,
            Self::TestFile => 2,
            Self::PotentiallyUnwanted => 3,
        }
    }

    /// Decodes a stored category byte.
    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Malware),
            2 => Some(Self::TestFile),
            3 => Some(Self::PotentiallyUnwanted),
            _ => None,
        }
    }

    /// Stable lowercase identifier, used in reports and CSV files.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Malware => "malware",
            Self::TestFile => "test_file",
            Self::PotentiallyUnwanted => "potentially_unwanted",
        }
    }
}

impl fmt::Display for Category {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Error returned when a category name is not recognised.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown category {0:?} (expected malware, test_file or potentially_unwanted)")]
pub struct ParseCategoryError(String);

impl FromStr for Category {
    type Err = ParseCategoryError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text.trim().to_ascii_lowercase().as_str() {
            "malware" => Ok(Self::Malware),
            "test_file" | "test-file" | "test" => Ok(Self::TestFile),
            "potentially_unwanted" | "potentially-unwanted" | "pup" => {
                Ok(Self::PotentiallyUnwanted)
            }
            _ => Err(ParseCategoryError(text.to_owned())),
        }
    }
}

/// Checks that a detection name is acceptable for storage.
pub(crate) fn check_name(name: &str) -> Result<(), &'static str> {
    if name.is_empty() {
        return Err("name is empty");
    }
    if name.len() > MAX_NAME_LEN {
        return Err("name is longer than 200 bytes");
    }
    if name.chars().any(char::is_control) {
        return Err("name contains control characters");
    }
    if name.trim() != name {
        return Err("name has leading or trailing whitespace");
    }
    Ok(())
}

/// Byte ranges of every section, for one combination of counts.
///
/// Format version 1 has exactly one valid layout for a given entry count,
/// name count and name-blob length: the sections follow the header in a fixed
/// order with no gaps. The offsets stored in the header are therefore
/// redundant, and the reader requires them to match this computation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Layout {
    pub fanout: Range<usize>,
    pub hashes: Range<usize>,
    pub name_ids: Range<usize>,
    pub name_offsets: Range<usize>,
    pub name_categories: Range<usize>,
    pub name_blob: Range<usize>,
}

impl Layout {
    /// Size in bytes of the header and every section except the name blob.
    pub fn fixed_len(entry_count: u64, name_count: u32) -> Option<u64> {
        let hashes = entry_count.checked_mul(HASH_LEN as u64)?;
        let name_ids = entry_count.checked_mul(4)?;
        let name_offsets = (u64::from(name_count) + 1) * 4;
        (HEADER_LEN as u64)
            .checked_add(FANOUT_BYTES)?
            .checked_add(hashes)?
            .checked_add(name_ids)?
            .checked_add(name_offsets)?
            .checked_add(u64::from(name_count))
    }

    /// Computes the layout, or `None` if it does not fit in memory.
    pub fn new(entry_count: u64, name_count: u32, blob_len: u64) -> Option<Self> {
        let mut cursor = HEADER_LEN as u64;
        let mut take = |len: u64| -> Option<Range<usize>> {
            let start = usize::try_from(cursor).ok()?;
            cursor = cursor.checked_add(len)?;
            let end = usize::try_from(cursor).ok()?;
            Some(start..end)
        };
        let fanout = take(FANOUT_BYTES)?;
        let hashes = take(entry_count.checked_mul(HASH_LEN as u64)?)?;
        let name_ids = take(entry_count.checked_mul(4)?)?;
        let name_offsets = take((u64::from(name_count) + 1) * 4)?;
        let name_categories = take(u64::from(name_count))?;
        let name_blob = take(blob_len)?;
        Some(Self {
            fanout,
            hashes,
            name_ids,
            name_offsets,
            name_categories,
            name_blob,
        })
    }

    /// Total file length implied by this layout.
    pub fn total_len(&self) -> usize {
        self.name_blob.end
    }

    /// Section start offsets in header order.
    pub fn offsets(&self) -> [u64; 6] {
        [
            self.fanout.start as u64,
            self.hashes.start as u64,
            self.name_ids.start as u64,
            self.name_offsets.start as u64,
            self.name_categories.start as u64,
            self.name_blob.start as u64,
        ]
    }
}

/// The decoded fixed header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Header {
    pub entry_count: u64,
    pub name_count: u32,
    pub created_unix_secs: u64,
    /// Section offsets as stored, in the order of [`Layout::offsets`].
    pub offsets: [u64; 6],
    pub digest: Sha256,
}

impl Header {
    /// Serialises the header. The digest field is written as given.
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0..8].copy_from_slice(&MAGIC);
        out[8..12].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        out[12..16].copy_from_slice(&(HEADER_LEN as u32).to_le_bytes());
        out[16..20].copy_from_slice(&HASH_ALGORITHM_SHA256.to_le_bytes());
        // Bytes 20..24 are flags and 36..40 are reserved; both stay zero.
        out[24..32].copy_from_slice(&self.entry_count.to_le_bytes());
        out[32..36].copy_from_slice(&self.name_count.to_le_bytes());
        out[40..48].copy_from_slice(&self.created_unix_secs.to_le_bytes());
        for (index, offset) in self.offsets.iter().enumerate() {
            let at = 48 + index * 8;
            out[at..at + 8].copy_from_slice(&offset.to_le_bytes());
        }
        out[DIGEST_OFFSET..HEADER_LEN].copy_from_slice(&self.digest);
        out
    }

    /// Parses and sanity-checks the fixed header.
    ///
    /// `bytes` must hold at least [`HEADER_LEN`] bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, SigDbError> {
        debug_assert!(bytes.len() >= HEADER_LEN);
        if bytes[0..8] != MAGIC {
            return Err(SigDbError::BadMagic);
        }
        let version = read_u32(bytes, 8);
        if version != FORMAT_VERSION {
            return Err(SigDbError::UnsupportedVersion(version));
        }
        if read_u32(bytes, 12) as usize != HEADER_LEN {
            return Err(SigDbError::Corrupt("unexpected header length"));
        }
        if read_u32(bytes, 16) != HASH_ALGORITHM_SHA256 {
            return Err(SigDbError::Corrupt("unknown hash algorithm"));
        }
        if read_u32(bytes, 20) != 0 {
            return Err(SigDbError::Corrupt("unknown header flags are set"));
        }
        if read_u32(bytes, 36) != 0 {
            return Err(SigDbError::Corrupt("reserved header field is not zero"));
        }
        let mut offsets = [0u64; 6];
        for (index, offset) in offsets.iter_mut().enumerate() {
            *offset = read_u64(bytes, 48 + index * 8);
        }
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&bytes[DIGEST_OFFSET..HEADER_LEN]);
        Ok(Self {
            entry_count: read_u64(bytes, 24),
            name_count: read_u32(bytes, 32),
            created_unix_secs: read_u64(bytes, 40),
            offsets,
            digest,
        })
    }
}

/// Digest stored in the header: SHA-256 over the header bytes that precede the
/// digest field, followed by every byte after the header.
pub(crate) fn compute_digest(header: &[u8], body: &[u8]) -> Sha256 {
    let mut hasher = Sha256Hasher::new();
    hasher.update(&header[..DIGEST_OFFSET]);
    hasher.update(body);
    hasher.finalize().into()
}

pub(crate) fn read_u32(bytes: &[u8], at: usize) -> u32 {
    let mut raw = [0u8; 4];
    raw.copy_from_slice(&bytes[at..at + 4]);
    u32::from_le_bytes(raw)
}

pub(crate) fn read_u64(bytes: &[u8], at: usize) -> u64 {
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&bytes[at..at + 8]);
    u64::from_le_bytes(raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn category_round_trips_through_byte_and_text() {
        for category in [
            Category::Malware,
            Category::TestFile,
            Category::PotentiallyUnwanted,
        ] {
            assert_eq!(Category::from_u8(category.as_u8()), Some(category));
            assert_eq!(category.as_str().parse::<Category>(), Ok(category));
        }
        assert_eq!(Category::from_u8(0), None);
        assert_eq!(Category::from_u8(4), None);
        assert_eq!("PUP".parse::<Category>(), Ok(Category::PotentiallyUnwanted));
        assert!("virus".parse::<Category>().is_err());
    }

    #[test]
    fn header_round_trips() {
        let layout = Layout::new(3, 2, 17).unwrap();
        let header = Header {
            entry_count: 3,
            name_count: 2,
            created_unix_secs: 1_800_000_000,
            offsets: layout.offsets(),
            digest: [7u8; 32],
        };
        let encoded = header.encode();
        assert_eq!(Header::decode(&encoded).unwrap(), header);
    }

    #[test]
    fn header_rejects_foreign_and_future_files() {
        let layout = Layout::new(0, 0, 0).unwrap();
        let header = Header {
            entry_count: 0,
            name_count: 0,
            created_unix_secs: 0,
            offsets: layout.offsets(),
            digest: [0u8; 32],
        };
        let good = header.encode();

        let mut bad_magic = good;
        bad_magic[0] ^= 0xff;
        assert!(matches!(
            Header::decode(&bad_magic),
            Err(SigDbError::BadMagic)
        ));

        let mut future = good;
        future[8..12].copy_from_slice(&2u32.to_le_bytes());
        assert!(matches!(
            Header::decode(&future),
            Err(SigDbError::UnsupportedVersion(2))
        ));

        let mut flags = good;
        flags[20] = 1;
        assert!(matches!(
            Header::decode(&flags),
            Err(SigDbError::Corrupt(_))
        ));
    }

    #[test]
    fn layout_is_contiguous_and_matches_fixed_len() {
        let layout = Layout::new(10, 4, 99).unwrap();
        assert_eq!(layout.fanout.start, HEADER_LEN);
        assert_eq!(layout.fanout.end, layout.hashes.start);
        assert_eq!(layout.hashes.len(), 10 * HASH_LEN);
        assert_eq!(layout.hashes.end, layout.name_ids.start);
        assert_eq!(layout.name_ids.len(), 10 * 4);
        assert_eq!(layout.name_ids.end, layout.name_offsets.start);
        assert_eq!(layout.name_offsets.len(), 5 * 4);
        assert_eq!(layout.name_offsets.end, layout.name_categories.start);
        assert_eq!(layout.name_categories.len(), 4);
        assert_eq!(layout.name_categories.end, layout.name_blob.start);
        assert_eq!(layout.name_blob.len(), 99);
        assert_eq!(
            Layout::fixed_len(10, 4).unwrap() + 99,
            layout.total_len() as u64
        );
    }

    #[test]
    fn layout_refuses_sizes_that_overflow() {
        assert!(Layout::fixed_len(u64::MAX, 0).is_none());
        assert!(Layout::new(u64::MAX / 2, 0, 0).is_none());
    }

    #[test]
    fn names_are_validated() {
        assert!(check_name("Trojan.Example").is_ok());
        assert!(check_name("").is_err());
        assert!(check_name(" padded").is_err());
        assert!(check_name("line\nbreak").is_err());
        assert!(check_name(&"x".repeat(MAX_NAME_LEN)).is_ok());
        assert!(check_name(&"x".repeat(MAX_NAME_LEN + 1)).is_err());
    }
}

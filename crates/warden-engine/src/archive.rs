//! Zip archives: recognising them, and the bookkeeping for unpacking them
//! under limits. The unpacking loop itself is in [`crate::session`], next to
//! the detectors it feeds.

use memchr::memmem;
use zip::result::ZipError;

use crate::options::ArchiveOptions;
use crate::report::PartialReason;

/// Signature of a local file header, which an ordinary zip starts with.
const LOCAL_HEADER: &[u8] = b"PK\x03\x04";
/// Signature of the end-of-central-directory record, which every zip ends with.
const END_RECORD: &[u8] = b"PK\x05\x06";
/// Size of that record without its comment.
const END_RECORD_BYTES: usize = 22;
/// Longest comment that can follow it.
const MAX_COMMENT_BYTES: usize = 65_535;

/// Members smaller than this after unpacking are never stopped by the
/// compression-ratio limit. Small, highly repetitive files are common and
/// harmless; the limit exists for members that turn kilobytes into gigabytes.
pub(crate) const RATIO_SLACK_BYTES: u64 = 1024 * 1024;

/// Longest member name, in characters, that is carried into a report.
const MAX_NAME_CHARS: usize = 200;

/// How sure the bytes are to be a zip archive before it is opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ZipHint {
    /// Starts like a zip. If it cannot be read, that is worth reporting.
    Declared,
    /// Something else in front, with what may be a zip directory at the
    /// end: a self-extracting archive, or a zip glued onto another file. If
    /// it turns out not to be one, nothing is reported.
    Possible,
}

/// Cheap test for whether `bytes` are worth opening as a zip archive.
pub(crate) fn zip_hint(bytes: &[u8]) -> Option<ZipHint> {
    if bytes.len() < END_RECORD_BYTES {
        return None;
    }
    if bytes.starts_with(LOCAL_HEADER) {
        return Some(ZipHint::Declared);
    }
    let tail_start = bytes
        .len()
        .saturating_sub(END_RECORD_BYTES + MAX_COMMENT_BYTES);
    memmem::rfind(&bytes[tail_start..], END_RECORD).map(|_| ZipHint::Possible)
}

/// What one scanned file may still unpack, across all nesting levels.
#[derive(Debug)]
pub(crate) struct Budget {
    /// Bytes that may still be unpacked.
    pub bytes: u64,
    /// Archive entries that may still be visited.
    pub members: u64,
    /// Set once the budget has run out and that has been reported. Every
    /// nesting level stops when it sees this, so the report says it once.
    pub spent: bool,
}

impl Budget {
    pub(crate) fn new(options: &ArchiveOptions) -> Self {
        Self {
            bytes: options.max_total_bytes,
            members: options.max_members,
            spent: false,
        }
    }
}

/// Which limit caps how far one member may unpack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Cap {
    /// The limit on a single member.
    Member,
    /// What is left of the limit for the whole scanned file.
    Total,
    /// The compression-ratio limit.
    Ratio,
}

/// How many bytes a member with the given packed size may unpack to, and
/// which limit that number comes from.
pub(crate) fn allowance(options: &ArchiveOptions, budget: &Budget, packed: u64) -> (u64, Cap) {
    let by_ratio = packed
        .saturating_mul(options.max_ratio)
        .max(RATIO_SLACK_BYTES);
    let mut allowed = (options.max_member_bytes, Cap::Member);
    if by_ratio < allowed.0 {
        allowed = (by_ratio, Cap::Ratio);
    }
    if budget.bytes < allowed.0 {
        allowed = (budget.bytes, Cap::Total);
    }
    allowed
}

/// Why opening or reading part of a zip failed, as a reason for the report.
pub(crate) fn failure_reason(error: &ZipError) -> PartialReason {
    match error {
        ZipError::CompressionMethodNotSupported(_) => PartialReason::UnsupportedCompression,
        ZipError::InvalidPassword => PartialReason::EncryptedArchive,
        _ => PartialReason::DamagedArchive,
    }
}

/// Makes a name taken from an archive safe to show. Member names are chosen
/// by whoever built the archive.
pub(crate) fn display_name(name: &str) -> String {
    crate::text::printable(name, MAX_NAME_CHARS)
}

/// Shows where a member is: its enclosing archives and its own name.
pub(crate) fn display_chain(chain: &[String]) -> String {
    chain.join(" > ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_zips_are_recognised_by_their_first_bytes() {
        let mut bytes = b"PK\x03\x04".to_vec();
        bytes.resize(64, 0);
        assert_eq!(zip_hint(&bytes), Some(ZipHint::Declared));
    }

    #[test]
    fn a_zip_directory_at_the_end_of_another_file_is_a_possible_zip() {
        let mut bytes = b"MZ this pretends to be a program".to_vec();
        bytes.extend_from_slice(b"PK\x05\x06");
        bytes.resize(bytes.len() + 18, 0);
        assert_eq!(zip_hint(&bytes), Some(ZipHint::Possible));
    }

    #[test]
    fn other_files_are_not_opened_as_zips() {
        assert_eq!(zip_hint(b""), None);
        assert_eq!(zip_hint(b"PK\x03\x04"), None);
        assert_eq!(zip_hint(&[0u8; 4096]), None);
        // The end record only counts where a zip could have one: within the
        // last 22 + 65,535 bytes.
        let mut bytes = b"PK\x05\x06".to_vec();
        bytes.resize(END_RECORD_BYTES + MAX_COMMENT_BYTES + 100, b'x');
        assert_eq!(zip_hint(&bytes), None);
    }

    #[test]
    fn the_smallest_limit_decides_the_allowance() {
        let options = ArchiveOptions {
            max_member_bytes: 10_000_000,
            max_total_bytes: 50_000_000,
            max_ratio: 100,
            ..ArchiveOptions::default()
        };
        let mut budget = Budget::new(&options);

        // 200 kB packed may become 20 MB by ratio, but one member may not
        // exceed 10 MB.
        assert_eq!(
            allowance(&options, &budget, 200_000),
            (10_000_000, Cap::Member)
        );
        // 50 kB packed may become 5 MB by ratio.
        assert_eq!(
            allowance(&options, &budget, 50_000),
            (5_000_000, Cap::Ratio)
        );
        // Tiny members get the slack instead of being cut at a few bytes.
        assert_eq!(
            allowance(&options, &budget, 10),
            (RATIO_SLACK_BYTES, Cap::Ratio)
        );
        // When little is left for the whole file, that wins.
        budget.bytes = 1_000;
        assert_eq!(allowance(&options, &budget, 200_000), (1_000, Cap::Total));
    }

    #[test]
    fn names_from_archives_are_made_safe_to_show() {
        assert_eq!(display_name("docs/readme.txt"), "docs/readme.txt");
        assert_eq!(display_name("line\nbreak"), "line\u{fffd}break");
        assert_eq!(
            display_name(&"a".repeat(500)).chars().count(),
            MAX_NAME_CHARS + 3
        );
    }

    #[test]
    fn chains_read_from_the_outside_in() {
        let chain = vec!["inner.zip".to_owned(), "tool.exe".to_owned()];
        assert_eq!(display_chain(&chain), "inner.zip > tool.exe");
    }
}

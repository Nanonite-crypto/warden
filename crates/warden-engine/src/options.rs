use std::path::PathBuf;

use serde::Serialize;

/// Hard upper bound on worker threads when the count is chosen automatically.
const MAX_AUTO_THREADS: usize = 16;

/// Tunable behaviour of a scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScanOptions {
    /// Number of worker threads. Zero means one per logical CPU, up to 16.
    pub threads: usize,

    /// Largest file, in bytes, whose content is handed to content detectors.
    ///
    /// Larger files are still hashed, in a streaming fashion with constant
    /// memory, and still checked by hash-based detectors. The report counts
    /// how many files had their content scan skipped for this reason.
    pub max_content_bytes: u64,

    /// Paths to leave out. A directory excludes everything below it.
    pub exclude: Vec<PathBuf>,

    /// How many skipped files, and how many partially scanned files, are
    /// listed individually in the report. The per-reason counts are always
    /// complete; this only bounds memory when a scan meets very many
    /// unreadable files.
    pub max_recorded_skips: usize,

    /// Whether and how far archives are unpacked.
    pub archives: ArchiveOptions,
}

/// How archives are unpacked.
///
/// Members are unpacked in memory, never to disk, and every limit here
/// exists because an archive is hostile input: a few kilobytes can claim to
/// unpack to petabytes. When a limit is reached the file is reported as
/// partially scanned, with the limit that stopped it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ArchiveOptions {
    /// Whether zip archives are unpacked and their members checked.
    pub enabled: bool,

    /// How many archives deep to go. With 1, a zip is unpacked but a zip
    /// inside it is only checked as a file.
    pub max_depth: u32,

    /// Most members unpacked from one archive.
    pub max_members: u64,

    /// Largest member, in bytes after unpacking.
    pub max_member_bytes: u64,

    /// Most bytes unpacked from one scanned file, summed over all members
    /// at all nesting levels.
    pub max_total_bytes: u64,

    /// Highest ratio of unpacked to packed size for one member. Members
    /// that unpack to less than a mebibyte are never stopped by this.
    pub max_ratio: u64,
}

impl Default for ArchiveOptions {
    fn default() -> Self {
        Self {
            enabled: true,
            max_depth: 3,
            max_members: 10_000,
            max_member_bytes: 64 * 1024 * 1024,
            max_total_bytes: 512 * 1024 * 1024,
            max_ratio: 250,
        }
    }
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            threads: 0,
            max_content_bytes: 128 * 1024 * 1024,
            exclude: Vec::new(),
            max_recorded_skips: 10_000,
            archives: ArchiveOptions::default(),
        }
    }
}

impl ScanOptions {
    /// The number of worker threads a scan with these options will use.
    #[must_use]
    pub fn effective_threads(&self) -> usize {
        if self.threads > 0 {
            return self.threads;
        }
        std::thread::available_parallelism()
            .map_or(1, std::num::NonZeroUsize::get)
            .min(MAX_AUTO_THREADS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_thread_count_is_respected() {
        let options = ScanOptions {
            threads: 3,
            ..ScanOptions::default()
        };
        assert_eq!(options.effective_threads(), 3);
    }

    #[test]
    fn automatic_thread_count_is_bounded() {
        let threads = ScanOptions::default().effective_threads();
        assert!((1..=MAX_AUTO_THREADS).contains(&threads));
    }
}

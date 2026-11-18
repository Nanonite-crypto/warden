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

    /// How many skipped files are listed individually in the report. The
    /// per-reason counts are always complete; this only bounds memory when a
    /// scan meets very many unreadable files.
    pub max_recorded_skips: usize,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            threads: 0,
            max_content_bytes: 128 * 1024 * 1024,
            exclude: Vec::new(),
            max_recorded_skips: 10_000,
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

use std::time::Duration;

use crate::report::{Detection, Recorded, Skipped};

/// A snapshot of a running scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Progress {
    /// Files read and checked so far.
    pub files_scanned: u64,
    /// Bytes read so far.
    pub bytes_scanned: u64,
    /// Files that could not be read so far.
    pub files_skipped: u64,
    /// Files with a verdict other than clean so far.
    pub detections: u64,
    /// Time since the scan started.
    pub elapsed: Duration,
}

/// Receives events while a scan runs.
///
/// All methods are called on the thread that called
/// [`Scanner::scan`](crate::Scanner::scan), so an observer needs no locking.
/// Every method has an empty default, so an observer implements only what it
/// cares about.
pub trait ScanObserver {
    /// A file received a verdict other than clean.
    fn on_detection(&mut self, _detection: &Detection) {}

    /// A file kept its clean verdict and has findings on record.
    fn on_recorded(&mut self, _recorded: &Recorded) {}

    /// A file could not be read, or a folder could not be opened.
    fn on_skipped(&mut self, _skipped: &Skipped) {}

    /// Called a few times per second, and once more when the scan ends.
    fn on_progress(&mut self, _progress: &Progress) {}
}

/// An observer that ignores every event.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoObserver;

impl ScanObserver for NoObserver {}

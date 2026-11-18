use std::collections::BTreeMap;
use std::path::Path;

use serde::Serialize;

use crate::Sha256;
use crate::finding::Finding;

/// What a detector gets to look at for one file.
///
/// The pipeline reads each file once. The SHA-256 is always available; the
/// content is only loaded when at least one detector asks for it through
/// [`Detector::needs_content`], and only for files small enough to hold in
/// memory (see [`ScanOptions::max_content_bytes`](crate::ScanOptions)).
#[derive(Debug, Clone, Copy)]
pub struct FileView<'a> {
    path: &'a Path,
    size: u64,
    sha256: &'a Sha256,
    content: Option<&'a [u8]>,
}

impl<'a> FileView<'a> {
    pub(crate) fn new(
        path: &'a Path,
        size: u64,
        sha256: &'a Sha256,
        content: Option<&'a [u8]>,
    ) -> Self {
        Self {
            path,
            size,
            sha256,
            content,
        }
    }

    /// Where the file is. Empty for in-memory scans.
    #[must_use]
    pub fn path(&self) -> &'a Path {
        self.path
    }

    /// Number of bytes that were read.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.size
    }

    /// SHA-256 of the bytes that were read.
    #[must_use]
    pub fn sha256(&self) -> &'a Sha256 {
        self.sha256
    }

    /// The file's bytes, if content was loaded for this file.
    #[must_use]
    pub fn content(&self) -> Option<&'a [u8]> {
        self.content
    }
}

/// A detector failed on one file. The scan carries on with the next detector
/// and the failure is recorded in the report.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct DetectorError(pub String);

/// A value in [`DetectorInfo::details`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum InfoValue {
    /// A count, such as a number of signatures.
    Count(u64),
    /// Free text, such as a database digest.
    Text(String),
}

/// A detector's description of itself, recorded in every report so that a
/// result can be traced back to the exact signatures that produced it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DetectorInfo {
    /// The detector's identifier.
    pub id: &'static str,
    /// Detector-specific facts, for example signature counts.
    pub details: BTreeMap<&'static str, InfoValue>,
}

/// One detection layer.
///
/// Detectors are shared between worker threads, so they must be `Send` and
/// `Sync` and must not keep per-file state.
pub trait Detector: Send + Sync {
    /// Short, stable identifier, used in findings and reports.
    fn id(&self) -> &'static str;

    /// Whether this detector reads file content. A detector that only needs
    /// the hash returns `false` and never causes a file to be buffered.
    fn needs_content(&self) -> bool {
        false
    }

    /// Describes the detector for the report.
    fn describe(&self) -> DetectorInfo {
        DetectorInfo {
            id: self.id(),
            details: BTreeMap::new(),
        }
    }

    /// Inspects one file.
    ///
    /// # Errors
    ///
    /// Returns an error if the detector could not do its job on this file.
    /// That is recorded against the file and does not stop the scan.
    fn inspect(&self, file: &FileView<'_>) -> Result<Vec<Finding>, DetectorError>;
}

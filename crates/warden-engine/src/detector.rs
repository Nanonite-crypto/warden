use std::collections::BTreeMap;
use std::path::Path;

use serde::Serialize;

use crate::Sha256;
use crate::finding::Finding;

/// What a detector gets to look at: one file, or one member of an archive.
///
/// The pipeline reads each file once. The SHA-256 is always available; the
/// content is only loaded when at least one detector asks for it through
/// [`Detector::needs_content`], and only for files small enough to hold in
/// memory (see [`ScanOptions::max_content_bytes`](crate::ScanOptions)).
#[derive(Debug, Clone, Copy)]
pub struct FileView<'a> {
    path: &'a Path,
    member: &'a [String],
    size: u64,
    sha256: &'a Sha256,
    content: Option<&'a [u8]>,
}

impl<'a> FileView<'a> {
    pub(crate) fn new(
        path: &'a Path,
        member: &'a [String],
        size: u64,
        sha256: &'a Sha256,
        content: Option<&'a [u8]>,
    ) -> Self {
        Self {
            path,
            member,
            size,
            sha256,
            content,
        }
    }

    /// A view of bytes that are already in memory, with no path.
    ///
    /// `sha256` must be the digest of `content`. This exists so that a
    /// detector can be exercised directly in tests and benchmarks.
    #[must_use]
    pub fn in_memory(content: &'a [u8], sha256: &'a Sha256) -> Self {
        Self::new(
            Path::new(""),
            &[],
            content.len() as u64,
            sha256,
            Some(content),
        )
    }

    /// Where the scanned file is. Empty for in-memory scans.
    #[must_use]
    pub fn path(&self) -> &'a Path {
        self.path
    }

    /// The names leading from the scanned file to the archive member this
    /// view is of, outermost first. Empty when the view is of the scanned
    /// file itself.
    #[must_use]
    pub fn member(&self) -> &'a [String] {
        self.member
    }

    /// Number of bytes that were read or unpacked.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.size
    }

    /// SHA-256 of those bytes.
    #[must_use]
    pub fn sha256(&self) -> &'a Sha256 {
        self.sha256
    }

    /// The bytes themselves, if content was loaded for this file.
    #[must_use]
    pub fn content(&self) -> Option<&'a [u8]> {
        self.content
    }
}

/// A detector could not finish its work on one file. The scan carries on with
/// the next detector, and the report lists the file as partially scanned.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DetectorError {
    /// The detector failed on this file.
    #[error("{0}")]
    Failed(String),
    /// The detector ran out of time on this file.
    #[error("{0}")]
    TimedOut(String),
}

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
/// A detector holds what is shared and read-only: signatures, compiled
/// rules, settings. It is shared between worker threads, so it must be
/// `Send` and `Sync`. Anything a thread needs to itself while inspecting
/// files lives in the [`Session`] the detector hands out.
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

    /// Creates the state one thread uses to inspect files.
    ///
    /// The pipeline calls this once per worker thread, and again after a
    /// panic, so that a session never carries broken state forward.
    fn session(&self) -> Box<dyn Session + '_>;
}

/// A detector's working state for one thread.
///
/// A detector with nothing to keep between files can implement this for a
/// reference to itself. A detector with scratch memory, or an engine that
/// may only be used from one thread at a time, keeps it here.
pub trait Session {
    /// Inspects one file or one archive member.
    ///
    /// # Errors
    ///
    /// Returns an error if the detector could not do its job on this file.
    /// That is recorded against the file and does not stop the scan.
    fn inspect(&mut self, file: &FileView<'_>) -> Result<Vec<Finding>, DetectorError>;
}

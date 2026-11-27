use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Serialize, Serializer};
use time::OffsetDateTime;

use crate::detector::DetectorInfo;
use crate::finding::{Finding, Verdict};
use crate::trust::{TrustAnswer, TrustCheckInfo};

/// Why a file was not scanned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SkipReason {
    /// The operating system refused access.
    AccessDenied,
    /// Another program holds the file open exclusively.
    InUse,
    /// The file disappeared between being listed and being opened.
    NotFound,
    /// Not a regular file: a device, pipe, socket or similar.
    SpecialFile,
    /// A cloud placeholder whose content is not on this disk.
    CloudPlaceholder,
    /// The file could be opened but reading it failed.
    ReadError,
    /// A directory could not be listed.
    WalkError,
    /// A bug in Warden: a detector panicked on this file.
    InternalError,
}

impl SkipReason {
    /// Stable lowercase identifier, as used in JSON reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AccessDenied => "access_denied",
            Self::InUse => "in_use",
            Self::NotFound => "not_found",
            Self::SpecialFile => "special_file",
            Self::CloudPlaceholder => "cloud_placeholder",
            Self::ReadError => "read_error",
            Self::WalkError => "walk_error",
            Self::InternalError => "internal_error",
        }
    }
}

/// Why part of a file was not examined.
///
/// A file in this state was read and checked as far as possible; what the
/// reason names is the part that was not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PartialReason {
    /// Larger than the content limit: checked by hash, but detectors that
    /// read content did not run and archives were not unpacked.
    TooLarge,
    /// A detector failed on the file or on one of its members.
    DetectorError,
    /// A detector ran out of time on the file or on one of its members.
    Timeout,
    /// An archive holds password-protected members, which cannot be read.
    EncryptedArchive,
    /// An unpacking limit was reached: nesting depth, member count,
    /// unpacked size or compression ratio.
    ArchiveLimit,
    /// The file is an archive that could not be read in full.
    DamagedArchive,
    /// An archive member is packed with a method Warden cannot unpack.
    UnsupportedCompression,
}

impl PartialReason {
    /// Stable lowercase identifier, as used in JSON reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TooLarge => "too_large",
            Self::DetectorError => "detector_error",
            Self::Timeout => "timeout",
            Self::EncryptedArchive => "encrypted_archive",
            Self::ArchiveLimit => "archive_limit",
            Self::DamagedArchive => "damaged_archive",
            Self::UnsupportedCompression => "unsupported_compression",
        }
    }
}

/// One reason a file was scanned only in part.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Partial {
    /// What kept the scan from being complete.
    pub reason: PartialReason,
    /// The specifics, written for a person.
    pub detail: String,
}

/// A file that was scanned only in part, as listed in a report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PartialScan {
    /// The file.
    #[serde(serialize_with = "lossy_path")]
    pub path: PathBuf,
    /// What kept the scan from being complete.
    pub reason: PartialReason,
    /// The specifics, written for a person.
    pub detail: String,
}

/// A file or folder that could not be scanned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Skipped {
    /// The path that was skipped.
    #[serde(serialize_with = "lossy_path")]
    pub path: PathBuf,
    /// Whether this is a folder. A folder that could not be opened hides
    /// what is in it: none of that was scanned, and none of it is counted
    /// anywhere, so one such entry can stand for any number of files.
    pub folder: bool,
    /// Why it was skipped.
    pub reason: SkipReason,
    /// The underlying error message, when there is one.
    pub detail: String,
}

/// A file whose verdict is not clean.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Detection {
    /// Where the file is.
    #[serde(serialize_with = "lossy_path")]
    pub path: PathBuf,
    /// Number of bytes read.
    pub size: u64,
    /// SHA-256 of the file, in lowercase hexadecimal.
    pub sha256: String,
    /// The decision about the file.
    pub verdict: Verdict,
    /// What the check of the file's signature said, if it was asked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust: Option<TrustAnswer>,
    /// What the detectors found, with reasons. A finding about a file
    /// inside an archive says which member it is about. At most 100 are
    /// listed; when there are more, the strongest stay.
    pub findings: Vec<Finding>,
    /// Findings left out because there were more than 100.
    #[serde(skip_serializing_if = "is_zero")]
    pub findings_omitted: u64,
}

/// A file whose verdict is clean and that has findings on record.
///
/// Nothing is wrong with such a file as far as Warden can tell. What is
/// kept is what a detector noticed and the verdict policy did not count: a
/// rule match that waits for a second sign and got none, for example, or
/// one in a file that a trusted publisher signed. It is kept so that "why
/// was this file not flagged?" has an answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Recorded {
    /// Where the file is.
    #[serde(serialize_with = "lossy_path")]
    pub path: PathBuf,
    /// Number of bytes read.
    pub size: u64,
    /// SHA-256 of the file, in lowercase hexadecimal.
    pub sha256: String,
    /// What the check of the file's signature said, if it was asked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust: Option<TrustAnswer>,
    /// What the detectors noticed, with reasons. At most 100 are listed.
    pub findings: Vec<Finding>,
    /// Findings left out because there were more than 100.
    #[serde(skip_serializing_if = "is_zero")]
    pub findings_omitted: u64,
}

/// Counters for a whole scan.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct ScanStats {
    /// Files read and checked.
    pub files_scanned: u64,
    /// Bytes read.
    pub bytes_scanned: u64,
    /// Files whose verdict is not clean.
    pub detections: u64,
    /// Files whose verdict is clean and that have findings on record.
    pub files_recorded: u64,
    /// Files whose signature was checked: the ones with a finding that
    /// yields to a trusted signature and would otherwise have been
    /// reported.
    pub trust_checks: u64,
    /// How many of those have a valid signature of a publisher on the
    /// trust list. Their yielding findings are on record and did not
    /// count; a file among them can still be a detection for another
    /// reason.
    pub files_trusted: u64,
    /// Files that could not be scanned.
    pub files_skipped: u64,
    /// Folders that could not be opened. What is in them was neither
    /// scanned nor counted, so this is not a number of files: one folder
    /// can hide any number of them.
    pub folders_skipped: u64,
    /// Both together, broken down by reason.
    pub skipped_by_reason: BTreeMap<SkipReason, u64>,
    /// Symbolic links and junctions that were not followed. Their targets
    /// are scanned if they lie inside the scan roots themselves.
    pub links_not_followed: u64,
    /// Files and directories left out by an exclusion.
    pub excluded: u64,
    /// Files that were scanned only in part.
    pub files_partially_scanned: u64,
    /// How often each reason for a partial scan occurred. A file with two
    /// reasons counts under both.
    pub partial_by_reason: BTreeMap<PartialReason, u64>,
    /// Files that were unpacked as archives.
    pub archives_unpacked: u64,
    /// Archive members that were unpacked and checked, at every nesting
    /// level.
    pub archive_members_scanned: u64,
    /// Total size of those members after unpacking, in bytes.
    pub archive_member_bytes: u64,
    /// Throughput in files per second over the whole scan.
    pub files_per_second: f64,
    /// Throughput in megabytes (10^6 bytes) per second over the whole scan.
    pub megabytes_per_second: f64,
}

/// The result of a scan.
#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    /// Version of this layout, see [`REPORT_SCHEMA`](crate::REPORT_SCHEMA).
    pub schema: u32,
    /// Version of the engine that produced the report.
    pub engine_version: &'static str,
    /// When the scan started.
    #[serde(with = "time::serde::rfc3339")]
    pub started_at: OffsetDateTime,
    /// When the scan finished.
    #[serde(with = "time::serde::rfc3339")]
    pub finished_at: OffsetDateTime,
    /// How long the scan took.
    #[serde(rename = "duration_ms", serialize_with = "duration_as_millis")]
    pub duration: Duration,
    /// Whether the scan was stopped before it covered everything.
    pub cancelled: bool,
    /// The paths that were scanned, made absolute.
    #[serde(serialize_with = "lossy_paths")]
    pub roots: Vec<PathBuf>,
    /// Number of worker threads used.
    pub threads: usize,
    /// The detectors that ran, with their signature counts.
    pub detectors: Vec<DetectorInfo>,
    /// What was asked who signed a file, if the scan had such a check.
    pub trust_check: Option<TrustCheckInfo>,
    /// Counters.
    pub stats: ScanStats,
    /// Every file whose verdict is not clean, sorted by path.
    pub detections: Vec<Detection>,
    /// Files whose verdict is clean and that have findings on record,
    /// sorted by path.
    pub recorded: Vec<Recorded>,
    /// Whether `recorded` was cut short. The counters are always complete.
    pub recorded_truncated: bool,
    /// Files and folders that could not be scanned, sorted by path.
    pub skipped: Vec<Skipped>,
    /// Whether `skipped` was cut short. The counters are always complete.
    pub skipped_truncated: bool,
    /// Files that were scanned only in part, sorted by path. A file appears
    /// once per reason.
    pub partially_scanned: Vec<PartialScan>,
    /// Whether `partially_scanned` was cut short. The counters are always
    /// complete.
    pub partially_scanned_truncated: bool,
}

impl ScanReport {
    /// Whether no file received a verdict other than clean.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.detections.is_empty()
    }
}

// Serde hands the field over by reference.
fn is_zero(count: &u64) -> bool {
    *count == 0
}

fn lossy_path<S: Serializer>(path: &Path, serializer: S) -> Result<S::Ok, S::Error> {
    // File names are not guaranteed to be valid Unicode on any platform. A
    // report must still be writable, so unrepresentable parts are replaced.
    serializer.serialize_str(&path.to_string_lossy())
}

fn lossy_paths<S: Serializer>(paths: &[PathBuf], serializer: S) -> Result<S::Ok, S::Error> {
    serializer.collect_seq(paths.iter().map(|path| path.to_string_lossy()))
}

fn duration_as_millis<S: Serializer>(
    duration: &Duration,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_u64(u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
}

//! Warden scan engine.
//!
//! The engine is a plain library: no user interface, no service code and no
//! operating-system specifics beyond a few file-opening hints. Everything
//! else in Warden (the command-line tool, and later the Windows service and
//! the desktop app) is a client of this crate.
//!
//! # How a scan works
//!
//! 1. A walker thread enumerates the scan roots and queues every regular
//!    file. Symbolic links and junctions are not followed, and files that
//!    only exist in the cloud are not downloaded.
//! 2. Worker threads read each file exactly once, computing its SHA-256 on
//!    the way, and hand a [`FileView`] to every [`Detector`].
//! 3. Detectors report [`Finding`]s: what they saw and why it matters.
//! 4. A [`VerdictPolicy`] turns the findings for a file into a [`Verdict`].
//!    Detection and decision are separate on purpose, so that a new detector
//!    never has to know what the product does about a finding.
//! 5. The calling thread collects the results into a [`ScanReport`]. Files
//!    that could not be read are listed with a reason, never silently
//!    dropped.
//!
//! # Example
//!
//! ```
//! use warden_engine::{CancelToken, HashDetector, NoObserver, Scanner, Verdict, eicar};
//!
//! let scanner = Scanner::builder().detector(HashDetector::new()).build();
//!
//! // The EICAR test file is a harmless 68-byte string that every antivirus
//! // product agrees to detect. Warden ships a built-in signature for it.
//! let result = scanner.scan_bytes(&eicar::test_file());
//! assert_eq!(result.verdict, Verdict::Malicious);
//! assert_eq!(result.findings[0].name, eicar::DETECTION_NAME);
//!
//! // Scanning a directory tree works the same way.
//! let dir = tempfile::tempdir()?;
//! std::fs::write(dir.path().join("notes.txt"), "nothing to see here")?;
//! let report = scanner.scan(&[dir.path().to_path_buf()], &mut NoObserver, &CancelToken::new())?;
//! assert_eq!(report.stats.files_scanned, 1);
//! assert!(report.is_clean());
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![forbid(unsafe_code)]

mod archive;
mod cancel;
mod detector;
pub mod eicar;
mod error;
mod file;
mod finding;
mod hash_detector;
mod observer;
mod options;
mod paths;
mod report;
mod scanner;
mod session;
pub mod text;
mod verdict;

pub use cancel::CancelToken;
pub use detector::{Detector, DetectorError, DetectorInfo, FileView, InfoValue, Session};
pub use error::ScanError;
pub use finding::{Confidence, Finding, Member, ThreatCategory, Verdict};
pub use hash_detector::HashDetector;
pub use observer::{NoObserver, Progress, ScanObserver};
pub use options::{ArchiveOptions, ScanOptions};
pub use report::{
    Detection, Partial, PartialReason, PartialScan, ScanReport, ScanStats, SkipReason, Skipped,
};
pub use scanner::{Scanner, ScannerBuilder};
pub use session::{FileResult, ScanSession};
pub use verdict::VerdictPolicy;

/// A SHA-256 digest.
pub type Sha256 = [u8; 32];

/// Version of the engine crate, as recorded in every report.
pub const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Version of the JSON report layout. Bumped on incompatible changes.
///
/// Version 2 added archive members to findings and replaced the separate
/// lists of oversized files and detector failures with one list of partially
/// scanned files.
pub const REPORT_SCHEMA: u32 = 2;

/// Computes the SHA-256 of a byte slice.
#[must_use]
pub fn sha256(bytes: &[u8]) -> Sha256 {
    use sha2::Digest;
    sha2::Sha256::digest(bytes).into()
}

/// Computes the SHA-256 of everything a reader yields, in constant memory.
///
/// This is the same routine the scan pipeline uses for files it does not
/// buffer, so a hash printed by a tool built on it always agrees with a scan.
///
/// # Errors
///
/// Returns the first error the reader reports.
pub fn sha256_reader(reader: &mut impl std::io::Read) -> std::io::Result<Sha256> {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    let mut chunk = vec![0u8; session::STREAM_CHUNK_BYTES];
    session::hash_stream(reader, &mut hasher, &mut chunk)?;
    Ok(hasher.finalize().into())
}

//! The seam for the check of who a file comes from.
//!
//! A rule describes byte patterns, and clean software has byte patterns
//! too, so a rule that was written to find malware will sooner or later
//! match a file of Windows or of a well-known program. For such a file
//! there is better evidence than the rule: a signature that says who it
//! comes from. Whether a signature holds is a question for the operating
//! system, and this crate asks the operating system nothing. So the engine
//! only says what it needs to know, as [`TrustCheck`], and a client hands
//! it something that can answer.
//!
//! What the engine does with the answer is narrow on purpose, see
//! [`VerdictPolicy::settle_with_trust`](crate::VerdictPolicy::settle_with_trust):
//! only a finding that says of itself that it
//! [yields](crate::Finding::yields_to_trust) is set aside, and the check
//! is only asked when such a finding would otherwise be reported.

use std::path::Path;

use serde::Serialize;

use crate::Sha256;

/// What a [`TrustCheck`] says about one file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "answer", rename_all = "snake_case")]
pub enum TrustAnswer {
    /// The file has a valid signature of a publisher the check trusts.
    Trusted {
        /// The publisher, by the name the check knows it under.
        publisher: String,
        /// Where the signature was found, as a stable identifier.
        route: &'static str,
        /// The same for a person to read, to follow a colon.
        detail: String,
    },
    /// No signature of a trusted publisher speaks for the file.
    NotTrusted {
        /// Why not, as a stable identifier.
        reason: &'static str,
        /// Why not, for a person to read, to follow a colon.
        detail: String,
    },
}

impl TrustAnswer {
    /// Whether the file comes from a trusted publisher.
    #[must_use]
    pub fn is_trusted(&self) -> bool {
        matches!(self, Self::Trusted { .. })
    }
}

/// A trust check's description of itself, recorded in every report so that
/// a result can be traced back to the list of publishers behind it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TrustCheckInfo {
    /// Whether signatures can be checked on this system. Where they
    /// cannot, the check is never asked and nothing yields.
    pub available: bool,
    /// SHA-256 of the list of trusted publishers, in lowercase
    /// hexadecimal.
    pub trust_list: String,
    /// How many publishers are on it.
    pub publishers: u64,
}

/// Says whether a file comes from a publisher that is trusted.
///
/// The engine asks this about a scanned file, never about a file inside an
/// archive and never about bytes that were handed to it in memory. An
/// implementation is shared between worker threads.
pub trait TrustCheck: Send + Sync {
    /// Describes the check for the report.
    fn describe(&self) -> TrustCheckInfo;

    /// Checks the file at `path`.
    ///
    /// `sha256` is the digest of the content that was scanned. The answer
    /// has to be about that content: an implementation that finds other
    /// content at the path now answers that the file is not trusted.
    fn check(&self, path: &Path, sha256: &Sha256) -> TrustAnswer;
}

use std::io;

use crate::format::FORMAT_VERSION;

/// Errors produced while building, opening or importing a signature database.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SigDbError {
    /// An I/O operation failed. `context` says what was being attempted.
    #[error("{context}")]
    Io {
        /// What the database code was doing, including the path when known.
        context: String,
        /// The underlying operating-system error.
        #[source]
        source: io::Error,
    },

    /// The file ends before the sections its header describes.
    #[error("signature database is truncated: need at least {expected} bytes, found {actual}")]
    Truncated {
        /// Minimum size the header implies.
        expected: u64,
        /// Size actually found.
        actual: u64,
    },

    /// The file does not start with the Warden signature database magic.
    #[error("not a Warden signature database (bad magic)")]
    BadMagic,

    /// The file was written by a format version this build cannot read.
    #[error(
        "unsupported signature database format version {0} (this build reads version {FORMAT_VERSION})"
    )]
    UnsupportedVersion(u32),

    /// The digest stored in the header does not match the file contents.
    #[error(
        "signature database digest mismatch: the file was modified or damaged after it was built"
    )]
    DigestMismatch,

    /// A structural invariant does not hold.
    #[error("signature database is corrupt: {0}")]
    Corrupt(&'static str),

    /// A detection name is not acceptable.
    #[error("invalid detection name {name:?}: {reason}")]
    InvalidName {
        /// The rejected name.
        name: String,
        /// Why it was rejected.
        reason: &'static str,
    },

    /// The database would exceed a limit of the format.
    #[error("signature database limit exceeded: {0}")]
    LimitExceeded(&'static str),
}

impl SigDbError {
    pub(crate) fn io(context: impl Into<String>, source: io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }
}

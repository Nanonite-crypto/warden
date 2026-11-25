//! A last look at a file before it is taken away.
//!
//! Quarantining the wrong file is usually cheap, because the file can be
//! put back. It is not cheap when the system needs the file in order to
//! start: then there may be nothing left to put it back with. So a
//! quarantine can be given a [`Guard`], which looks at every file that is
//! about to go and can say that it should stay.
//!
//! This crate does not know what makes a file one to leave alone. Whoever
//! opens the quarantine says, by the guard they give it: Warden's
//! command-line program asks who signed the file, and leaves a file that
//! Windows itself signed. What this crate does is ask every time, at the
//! one place that every file passes on its way in, and take a file that
//! the guard would leave only when the caller says so in as many words
//! ([`AddOptions::overrule_guard`]).

use std::fmt;
use std::path::Path;

/// What a guard says about a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Nothing speaks against quarantining the file.
    Take {
        /// SHA-256 of the content the guard looked at, if it read the
        /// file. The file is then quarantined only if this is the content
        /// that gets copied. If it is another by then, the file stays, and
        /// the operation fails as it does for any file that changes on the
        /// way.
        sha256: Option<[u8; 32]>,
    },
    /// The file should stay where it is.
    Leave {
        /// Why. It finishes a sentence that names the file and goes on
        /// "was left where it is:".
        why: String,
    },
}

/// Looks at a file before it is quarantined.
pub trait Guard: fmt::Debug + Send + Sync {
    /// Says whether the file at `path` may be taken. The path is absolute
    /// and names a regular file.
    fn look_at(&self, path: &Path) -> Verdict;
}

/// How a file is to be quarantined.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AddOptions {
    /// Take the file even if the guard would leave it. The guard is not
    /// asked.
    pub overrule_guard: bool,
}

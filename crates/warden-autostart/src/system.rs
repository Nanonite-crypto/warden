//! What Warden asks of the system about autostart entries.
//!
//! Finding, removing and putting back are written against the [`System`]
//! trait, which Windows answers in one module and a stand-in answers in
//! tests. The logic that decides what to remove and in which order, and
//! what to do when it is cut off, is therefore tried on every system the
//! tests run on, and only the calls into Windows are left to Windows.

use std::fmt;
use std::path::Path;

use crate::entry::Entry;

/// An entry as the system has it, with the command lines it stands for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seen {
    /// The entry.
    pub entry: Entry,
    /// Its command lines, as written and with variables filled in.
    pub lines: Vec<String>,
}

/// Everything the system has that Warden looks at, as far as the process
/// was allowed to see it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Survey {
    /// The entries.
    pub seen: Vec<Seen>,
    /// What could not be looked at, one sentence each. An entry that
    /// starts a file can be among what is missing here.
    pub problems: Vec<String>,
}

/// Why the system did not do what it was asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    /// What went wrong, as a clause that can follow "because".
    pub reason: String,
    /// Whether it would work with more rights: the entry belongs to the
    /// machine or to somebody else, and the process is not an
    /// administrator's.
    pub needs_rights: bool,
}

impl Failure {
    /// A failure that more rights would not help with.
    #[must_use]
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            needs_rights: false,
        }
    }

    /// A failure for want of rights.
    #[must_use]
    pub fn denied(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            needs_rights: true,
        }
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.reason)
    }
}

/// The system's side of autostart entries.
///
/// Shortcuts are the exception among the four kinds: a shortcut is a
/// file, so it is taken away and put back by the quarantine, and
/// [`remove`](Self::remove) and [`create`](Self::create) are never asked
/// to do it.
pub trait System: fmt::Debug {
    /// Looks at every place and reports what is there.
    fn survey(&self) -> Survey;

    /// The other ways the system writes the path of a file that exists,
    /// such as with short names. Asked while the file is still there.
    fn spellings(&self, file: &Path) -> Vec<String>;

    /// The entry that is at the place of `entry` now, if there is one.
    ///
    /// # Errors
    ///
    /// Fails if the place cannot be looked at.
    fn current(&self, entry: &Entry) -> Result<Option<Entry>, Failure>;

    /// Removes the entry at the place of `entry`. That there is none is
    /// not a failure.
    ///
    /// # Errors
    ///
    /// Fails if the entry is there and cannot be removed.
    fn remove(&self, entry: &Entry) -> Result<(), Failure>;

    /// Creates `entry` as it is written down, at a place where there is
    /// none. Returns what could not be made the way it was, one sentence
    /// each.
    ///
    /// # Errors
    ///
    /// Fails if the entry cannot be created. Nothing is replaced: an
    /// entry at that place is a failure.
    fn create(&self, entry: &Entry) -> Result<Vec<String>, Failure>;
}

/// A system without the autostart entries Warden looks at: every system
/// that is not Windows. There is nothing to find on it, and nothing can
/// be put on it.
#[derive(Debug, Clone, Copy, Default)]
pub struct Nowhere;

impl System for Nowhere {
    fn survey(&self) -> Survey {
        Survey::default()
    }

    fn spellings(&self, _: &Path) -> Vec<String> {
        Vec::new()
    }

    fn current(&self, _: &Entry) -> Result<Option<Entry>, Failure> {
        Ok(None)
    }

    fn remove(&self, _: &Entry) -> Result<(), Failure> {
        Ok(())
    }

    fn create(&self, _: &Entry) -> Result<Vec<String>, Failure> {
        Err(Failure::new(
            "entries like it exist on Windows only, and this is another system",
        ))
    }
}

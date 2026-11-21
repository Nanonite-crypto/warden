//! Warden's quarantine.
//!
//! A quarantined file is out of harm's way and not lost. It is gone from
//! its place, it lies in the quarantine in a form that cannot be run and
//! that no other scanner trips over, and it can be put back exactly as it
//! was: the same bytes, the same timestamps, the same owner and access
//! rights. Whoever quarantines a file by mistake has to be able to undo it
//! without a trace, or they will not dare to quarantine anything.
//!
//! # How it works
//!
//! A [`Quarantine`] is a folder. Each quarantined file is one entry file in
//! it: the content under a stream cipher, followed by a record of what the
//! file was ([`EntryInfo`]). The layout is described in [`mod@format`].
//!
//! Moving a file in takes three steps that cannot happen at once: write the
//! copy, give the copy its final name, remove the original. Putting it
//! back is the same three in the other direction. Before the first step a
//! note of the intention goes into a journal, and when the quarantine is
//! next opened, every note that is still there is settled:
//!
//! - If the copy had not reached its destination, the operation is undone.
//!   The file is where it came from.
//! - If it had, the operation is finished. A file that somebody asked to
//!   have quarantined does not stay in place because the power went out.
//!
//! At no point is the only copy of a file one that is incomplete.
//!
//! # What the cipher is for
//!
//! Not secrecy: the key is stored next to the content. It makes sure that
//! the bytes on disk are not the file. They cannot be started, a resident
//! antivirus does not find the threat a second time and remove the
//! quarantine's copy, and a search indexer does not read them.
//!
//! # What this crate does not do yet
//!
//! It runs with the rights of whoever calls it and keeps its folder in that
//! user's own data folder. A quarantine for a whole machine has to belong
//! to a program with rights of its own, and that program must not restore
//! a file on behalf of a user to a place that user could not write to
//! themselves: that is how antivirus products have been turned into a way
//! of planting files in system folders. It comes with the Windows service.
//!
//! # Example
//!
//! ```
//! use warden_quarantine::{Quarantine, Reason, RestoreOptions};
//!
//! let dir = tempfile::tempdir()?;
//! let file = dir.path().join("report.txt");
//! std::fs::write(&file, "nothing wrong with this file")?;
//!
//! let (quarantine, _) = Quarantine::open(dir.path().join("quarantine"))?;
//! let entry = quarantine.add(&file, Reason::note("a false alarm, as it will turn out"))?;
//! assert!(!file.exists());
//! assert_eq!(quarantine.list()?.entries.len(), 1);
//!
//! // The first few characters of an identifier are enough.
//! let restored = quarantine.restore(&entry.info.id[..6], &RestoreOptions::default())?;
//! assert_eq!(restored.path, file);
//! assert_eq!(std::fs::read_to_string(&file)?, "nothing wrong with this file");
//! assert!(quarantine.list()?.entries.is_empty());
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

pub mod format;
mod hex;
mod info;
mod journal;
mod meta;
pub mod sd;
mod store;
#[cfg(windows)]
mod windows;

pub use format::Problem;
pub use info::{CIPHER, Cipher, EntryInfo, ExactPath, Reason, Stamp, Times, UnixMeta, WindowsMeta};
pub use store::{
    Damaged, Entry, Listing, Operation, Outcome, Quarantine, QuarantineError, Recovered,
    RestoreOptions, Restored, Step, default_dir,
};

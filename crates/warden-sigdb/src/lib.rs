//! Warden signature database (`.wdb`).
//!
//! A signature database is an immutable file that maps SHA-256 digests of
//! known-bad files to detection names. It is designed to be:
//!
//! - **cheap to open**: the file is memory-mapped, never parsed into heap
//!   structures, so a database with millions of entries costs no allocation;
//! - **fast to query**: a 16-bit prefix index narrows every lookup to a few
//!   dozen candidates before a binary search;
//! - **hard to misuse**: the file is checked in full when it is opened
//!   (header, digest and every structural invariant), so a lookup can never
//!   read out of bounds or return an answer from a damaged table.
//!
//! The on-disk layout is specified in `docs/SIGDB_FORMAT.md`.
//!
//! # Example
//!
//! ```
//! use warden_sigdb::{Category, SigDb, SigDbBuilder};
//!
//! let known_bad = [0xAB_u8; 32];
//!
//! let mut builder = SigDbBuilder::new();
//! builder.add(known_bad, "Example.Threat", Category::Malware)?;
//! let (bytes, stats) = builder.build()?;
//! assert_eq!(stats.entries, 1);
//!
//! let db = SigDb::from_bytes(bytes)?;
//! let hit = db.lookup(&known_bad).expect("the hash was added above");
//! assert_eq!(hit.name, "Example.Threat");
//! assert!(db.lookup(&[0u8; 32]).is_none());
//! # Ok::<(), warden_sigdb::SigDbError>(())
//! ```

mod builder;
mod error;
mod format;
pub mod hex;
pub mod import;
mod reader;

pub use builder::{BuildStats, SigDbBuilder};
pub use error::SigDbError;
pub use format::{
    Category, FORMAT_VERSION, HASH_LEN, HEADER_LEN, MAGIC, MAX_NAME_LEN, ParseCategoryError,
};
pub use reader::{Iter, SigDb, Signature};

/// A SHA-256 digest: the key type of the database.
pub type Sha256 = [u8; HASH_LEN];

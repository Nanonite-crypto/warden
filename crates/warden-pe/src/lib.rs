//! Warden's heuristic layer for Windows executables.
//!
//! The layers before this one know files: the hash layer by their digest,
//! the YARA layer by patterns someone wrote after seeing them. This layer
//! looks at a file nobody has seen and asks what kind of file is built like
//! this.
//!
//! It works in three steps, each of which can be used alone:
//!
//! 1. [`read`] takes a file's bytes and returns [`PeFacts`]: its sections
//!    with their sizes, flags and entropy, what it imports, which tables
//!    its header points to, what follows its last section. The reader is
//!    written for hostile input: bounded, checked, and unable to step
//!    outside the file.
//! 2. [`indicators::evaluate`] asks a fixed list of yes-or-no questions
//!    about those facts. Each question is an [`Indicator`] with a weight.
//! 3. [`assess`] adds up the weights of the indicators that apply and
//!    compares the sum with [`SUSPICIOUS_FROM`].
//!
//! The result is an [`Assessment`] that lists every indicator behind the
//! score, which is what `warden inspect` prints. [`PeDetector`] wraps the
//! three steps as a detector for the scan pipeline.
//!
//! # Where the weights come from
//!
//! A weight is not an opinion. `PeFacts` holds only facts that the
//! EMBER2024 dataset also records for the 2.9 million Windows executables
//! it describes, so the same indicator code runs over a file on disk and
//! over the dataset. The weights are fitted to how the indicators are
//! spread over the malicious and the benign files there, all of them
//! together, and the threshold is set on the benign ones.
//! `docs/HEURISTICS.md` has the method and the numbers.
//!
//! # What this layer cannot do
//!
//! Structure is a hint. Clean programs are packed and malware is built
//! with ordinary compilers, so this layer reports at most "suspicious",
//! which Warden shows to the user and never acts on.
//!
//! ```
//! use warden_pe::{Context, assess, fixture::Fixture, read};
//!
//! let file = Fixture::packed_looking().build();
//! let facts = read(&file)?;
//! assert_eq!(facts.sections[0].name, "UPX0");
//!
//! let assessment = assess(&facts, &Context::now());
//! assert!(assessment
//!     .hits
//!     .iter()
//!     .any(|hit| hit.indicator.id == "sections.packer_name"));
//! # Ok::<(), warden_pe::NotPe>(())
//! ```

mod assess;
mod bytes;
mod detector;
pub mod entropy;
mod facts;
pub mod fixture;
pub mod indicators;
mod reader;

pub use assess::{Assessment, SUSPICIOUS_FROM, assess, assess_with, score_of};
pub use detector::{FINDING_NAME, PeDetector, finding_for};
pub use facts::{
    Anomaly, Directory, Format, ImportedLibrary, Overlay, PeFacts, Section, image_flags,
    section_flags,
};
pub use indicators::{Context, Group, Hit, Indicator};
pub use reader::{
    MAX_EXPORTS, MAX_FUNCTION_NAME, MAX_FUNCTIONS, MAX_FUNCTIONS_PER_LIBRARY, MAX_LIBRARIES,
    MAX_LIBRARY_NAME, MAX_SECTIONS, NotPe, looks_like_pe, read,
};

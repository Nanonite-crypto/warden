//! Warden's YARA layer.
//!
//! Hash matching only finds exact copies of known files. YARA rules describe
//! byte patterns and file structure, so they keep matching when a file has
//! been changed. This crate adds that layer to the scan engine:
//!
//! - [`BundleBuilder`] compiles rule files into a [`RuleBundle`]: one file
//!   with the compiled rules and a record of where they came from. A rule
//!   that does not compile is left out and reported; it does not stop the
//!   build.
//! - [`YaraDetector`] runs a bundle as a [`warden_engine::Detector`]. It
//!   turns the `score` a rule states about itself into a confidence, and
//!   the engine's verdict policy decides what that means.
//!
//! A handful of rules ship inside the program, see `rules/builtin.yar`. They
//! cover test files only. Everything else comes from rule sets the user
//! chooses, which keeps other people's rules, and their licences, out of
//! this repository.
//!
//! The rule engine is [YARA-X](https://virustotal.github.io/yara-x/),
//! VirusTotal's implementation of YARA in Rust.
//!
//! # Example
//!
//! ```
//! use warden_engine::{Scanner, Verdict, eicar};
//! use warden_yara::YaraDetector;
//!
//! let scanner = Scanner::builder().detector(YaraDetector::builtin()?).build();
//!
//! // The test file with a line break added has a different hash, so a hash
//! // signature no longer matches it. The built-in rule still does.
//! let mut variant = eicar::test_file();
//! variant.extend_from_slice(b"\r\n");
//! let result = scanner.scan_bytes(&variant);
//! assert_eq!(result.verdict, Verdict::Malicious);
//! assert_eq!(result.findings[0].name, eicar::DETECTION_NAME);
//! assert_eq!(result.findings[0].detector, "yara");
//! # Ok::<(), warden_yara::BundleError>(())
//! ```

#![forbid(unsafe_code)]

mod builder;
mod bundle;
mod detector;
mod exclusions;

pub use builder::{
    BUILTIN_SOURCE, BuildReport, Built, BundleBuilder, ExcludedRuleMatch, SkippedRule, SourceReport,
};
pub use bundle::{
    BundleError, ENGINE, ExclusionInfo, FORMAT_VERSION, HEADER_LEN, MAGIC, Manifest, RuleBundle,
    SourceInfo, write_bundle,
};
pub use detector::{RuleStats, YaraDetector, YaraOptions};
pub use exclusions::{Evidence, ExcludedRule, ExclusionError, ExclusionList};

//! Who signed a file, and whether Warden trusts that publisher.
//!
//! A scan engine that reads published rules will sooner or later flag a
//! file of Windows or of a well-known program: a rule describes byte
//! patterns, and clean software has byte patterns too. For such a file
//! there is better evidence than any rule, which is its signature. This
//! crate finds it, has Windows check it, and compares the signer with a
//! short list of publishers.
//!
//! # Three routes
//!
//! A file can be signed in three ways, and a check that knows only one
//! misses most of Windows:
//!
//! 1. **Embedded.** The signature is inside the file, at its end.
//! 2. **The Windows catalogue.** Windows keeps catalogues, signed lists of
//!    file hashes, and most of its own files are signed only there.
//! 3. **The package.** The files of an app from the Microsoft Store are
//!    covered by the signature of the app's package, see [`package`].
//!
//! [`Verifier`] tries them in that order, see its module for why the
//! order matters. What a route finds is a [`Signer`]; whether that signer
//! counts is up to the [`TrustList`].
//!
//! # What is asked of Windows, and what is not
//!
//! Whether a signature holds, whether its certificates were revoked and
//! whether its chain ends in a root of Microsoft's are questions for
//! Windows, which owns the certificates and the rules. This crate does not
//! rebuild any of that. What it does itself is what Windows does not do:
//! it holds the file open so that the answer is about one content, it
//! compares that content with what was scanned, it looks through the part
//! of an executable that a signature cannot cover ([`sigarea`]), and it
//! follows a package's signature down to the bytes of the file.
//!
//! On a system that is not Windows nothing can be asked, and every file is
//! [not trusted](Trust::NotTrusted).
//!
//! # In a scan
//!
//! A [`Verifier`] is what the scan engine asks who signed a file: it
//! implements the engine's [`TrustCheck`](warden_engine::TrustCheck). The
//! engine asks only about a file with a finding that yields to a trusted
//! signature, and what it does with the answer is described there.
//!
//! # Example
//!
//! ```
//! use warden_trust::{Options, TrustList, Verifier};
//!
//! let verifier = Verifier::new(TrustList::builtin()?, Options::default());
//! let trust = verifier.trust(std::path::Path::new("no-such-file.exe"), None);
//! assert!(!trust.is_trusted());
//! # Ok::<(), warden_trust::ListError>(())
//! ```

mod der;
mod engine;
pub mod list;
pub mod package;
pub mod sigarea;
mod signature;
mod verify;
#[cfg(windows)]
mod windows;

pub use list::{Anchor, Evidence, ListError, Publisher, TrustList};
pub use signature::{
    Certificate, Examination, Found, Reason, Revocation, Route, RouteReport, Signer, Trust,
};
pub use verify::{Options, Verifier, stand_in};

/// What answers for Windows on this system.
#[cfg(windows)]
fn system(options: Options) -> Box<dyn verify::Os> {
    Box::new(windows::Windows::new(options))
}

/// What answers for Windows on a system that is not Windows: nothing.
#[cfg(not(windows))]
fn system(_: Options) -> Box<dyn verify::Os> {
    struct Elsewhere;

    impl verify::Os for Elsewhere {
        fn available(&self) -> bool {
            false
        }

        fn embedded(&self, _: &std::path::Path, _: &std::fs::File) -> Found {
            not_here()
        }

        fn catalog(&self, _: &std::path::Path, _: &std::fs::File) -> Found {
            not_here()
        }

        fn package_signature(&self, _: &[u8]) -> Found {
            not_here()
        }
    }

    fn not_here() -> Found {
        Found::Failed {
            why: "signatures can only be checked on Windows".to_owned(),
        }
    }

    Box::new(Elsewhere)
}

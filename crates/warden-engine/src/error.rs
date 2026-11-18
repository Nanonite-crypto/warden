use std::io;
use std::path::PathBuf;

/// A scan could not start.
///
/// Problems with individual files never produce a `ScanError`: they are
/// recorded in the report as skipped files. This type is only for requests
/// that make no sense as a whole.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ScanError {
    /// No path was given.
    #[error("nothing to scan: no path was given")]
    NoRoots,

    /// A path to scan, or to exclude, could not be resolved or does not exist.
    #[error("cannot scan {}", path.display())]
    Root {
        /// The offending path, as given.
        path: PathBuf,
        /// Why it could not be used.
        #[source]
        source: io::Error,
    },
}

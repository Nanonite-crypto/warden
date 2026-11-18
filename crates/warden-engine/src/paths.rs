use std::io;
use std::path::{Component, Path, PathBuf};

/// Makes a path absolute without touching the file system or resolving links.
///
/// Reports therefore show paths the way the user wrote them, not the
/// `\\?\`-prefixed or link-resolved form that canonicalisation would produce.
pub(crate) fn absolute(path: &Path) -> io::Result<PathBuf> {
    std::path::absolute(path)
}

/// A set of paths to leave out of a scan.
#[derive(Debug, Default)]
pub(crate) struct ExcludeSet {
    prefixes: Vec<PathBuf>,
}

impl ExcludeSet {
    /// Builds the set. On failure returns the path that could not be resolved.
    pub fn new(paths: &[PathBuf]) -> Result<Self, (PathBuf, io::Error)> {
        let mut prefixes = Vec::with_capacity(paths.len());
        for path in paths {
            prefixes.push(absolute(path).map_err(|error| (path.clone(), error))?);
        }
        Ok(Self { prefixes })
    }

    /// Whether `path` is one of the excluded paths or lies below one.
    pub fn excludes(&self, path: &Path) -> bool {
        self.prefixes.iter().any(|prefix| starts_with(path, prefix))
    }
}

/// Component-wise prefix test, so that `/data/ab` is not under `/data/a`.
fn starts_with(path: &Path, prefix: &Path) -> bool {
    let mut components = path.components();
    prefix.components().all(|expected| {
        components
            .next()
            .is_some_and(|actual| same_component(&actual, &expected))
    })
}

/// Windows file names are case-insensitive, so exclusions must be too.
#[cfg(windows)]
fn same_component(left: &Component<'_>, right: &Component<'_>) -> bool {
    let fold = |component: &Component<'_>| component.as_os_str().to_string_lossy().to_lowercase();
    fold(left) == fold(right)
}

#[cfg(not(windows))]
fn same_component(left: &Component<'_>, right: &Component<'_>) -> bool {
    left == right
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(paths: &[&str]) -> ExcludeSet {
        let paths: Vec<PathBuf> = paths.iter().map(PathBuf::from).collect();
        ExcludeSet::new(&paths).unwrap()
    }

    fn root(relative: &str) -> PathBuf {
        absolute(Path::new(relative)).unwrap()
    }

    #[test]
    fn excludes_the_path_itself_and_everything_below() {
        let excludes = set(&["data/skip"]);
        assert!(excludes.excludes(&root("data/skip")));
        assert!(excludes.excludes(&root("data/skip/deep/file.bin")));
        assert!(!excludes.excludes(&root("data")));
        assert!(!excludes.excludes(&root("data/keep/file.bin")));
    }

    #[test]
    fn does_not_confuse_a_sibling_with_a_shared_name_prefix() {
        let excludes = set(&["data/a"]);
        assert!(!excludes.excludes(&root("data/ab")));
        assert!(!excludes.excludes(&root("data/a.txt")));
    }

    #[test]
    fn an_empty_set_excludes_nothing() {
        assert!(!ExcludeSet::default().excludes(&root("anything")));
    }

    #[cfg(windows)]
    #[test]
    fn matching_ignores_case_on_windows() {
        let excludes = set(&[r"C:\Data\Skip"]);
        assert!(excludes.excludes(Path::new(r"c:\data\SKIP\file.bin")));
    }

    #[cfg(not(windows))]
    #[test]
    fn matching_is_case_sensitive_elsewhere() {
        let excludes = set(&["/data/skip"]);
        assert!(!excludes.excludes(Path::new("/data/SKIP/file.bin")));
    }
}

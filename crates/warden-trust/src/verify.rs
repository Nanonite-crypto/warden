//! The check: the three routes in order, and the list.
//!
//! The routes differ in what part of a file their hash covers, and the
//! order and the conditions below follow from that.
//!
//! - **The package route** hashes every byte of the file, so it needs no
//!   precaution: either the file is what the package's block map says or
//!   it is not.
//! - **The embedded route** cannot cover the table that holds the
//!   signature. It is tried for executables only, where
//!   [`sigarea`] can look through that table, and it counts only when the
//!   table holds one signature and nothing else.
//! - **The catalogue route** uses the same hash as the embedded route, so
//!   it leaves the same table uncovered. It is tried only for an
//!   executable that has no such table.
//!
//! A file that is no executable can therefore be trusted only as part of a
//! package. That leaves out signed scripts and installers; for those,
//! Warden could not say what a signature leaves uncovered.

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use sha2::{Digest, Sha256};

use crate::list::TrustList;
use crate::package::{self, BlockMap, PackageFiles};
use crate::sigarea::{self, SignatureArea};
use crate::signature::{
    Examination, Found, Reason, Revocation, Route, RouteReport, Signer, Trust, hex,
};

/// How many packages are remembered. A survey goes through a package file
/// by file, and reading its block map once is enough.
const PACKAGES_REMEMBERED: usize = 16;

/// What Windows is asked. Everything else in the check is arithmetic and
/// the same on every system, which is what lets it be tested anywhere.
pub(crate) trait Os: Send + Sync {
    /// Whether signatures can be checked at all on this system.
    fn available(&self) -> bool {
        true
    }

    /// Asks about the signature inside an executable. `file` is open and
    /// cannot change.
    fn embedded(&self, path: &Path, file: &File) -> Found;

    /// Looks the file up in the catalogues of Windows and asks about the
    /// signature of a catalogue that lists it.
    fn catalog(&self, path: &Path, file: &File) -> Found;

    /// Asks about the signature of a package, given the bytes of the
    /// package's signature file.
    fn package_signature(&self, signature_file: &[u8]) -> Found;
}

/// How a check is to go about its work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    /// Whether Windows may ask a certificate authority over the network
    /// if a certificate was revoked. Without it, only what Windows has
    /// stored from earlier checks is used, and a certificate that is not
    /// in that store counts as unknown.
    pub network: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self { network: true }
    }
}

/// What is remembered about one package's folder.
enum Package {
    /// Its signature holds, and this is its block map.
    Signed { signer: Signer, block_map: BlockMap },
    /// It vouches for nothing, and this is what to say about it.
    Unusable(Found),
}

/// Checks who signed a file and whether that publisher is on a trust
/// list.
pub struct Verifier {
    list: TrustList,
    os: Box<dyn Os>,
    packages: Mutex<HashMap<PathBuf, Arc<Package>>>,
}

impl std::fmt::Debug for Verifier {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Verifier")
            .field("publishers", &self.list.len())
            .field("available", &self.os.available())
            .finish()
    }
}

impl Verifier {
    /// Creates a verifier for this system that trusts the publishers on
    /// `list`.
    #[must_use]
    pub fn new(list: TrustList, options: Options) -> Self {
        Self::with_os(list, crate::system(options))
    }

    pub(crate) fn with_os(list: TrustList, os: Box<dyn Os>) -> Self {
        Self {
            list,
            os,
            packages: Mutex::new(HashMap::new()),
        }
    }

    /// The trust list in use.
    #[must_use]
    pub fn list(&self) -> &TrustList {
        &self.list
    }

    /// Whether signatures can be checked on this system. Where they
    /// cannot, every file is [not trusted](Trust::NotTrusted).
    #[must_use]
    pub fn available(&self) -> bool {
        self.os.available()
    }

    /// Checks one file and stops at the first route that makes it trusted.
    ///
    /// `scanned` is the SHA-256 the file had when it was scanned. If the
    /// file has another one now, it is not trusted: the answer would be
    /// about other bytes than the finding it is asked for.
    #[must_use]
    pub fn trust(&self, path: &Path, scanned: Option<&[u8; 32]>) -> Trust {
        self.examine(path, scanned, false).trust
    }

    /// Checks one file and reports what each route found. With
    /// `every_route`, a route is tried even when an earlier one has
    /// already made the file trusted.
    #[must_use]
    pub fn examine(
        &self,
        path: &Path,
        scanned: Option<&[u8; 32]>,
        every_route: bool,
    ) -> Examination {
        if !self.os.available() {
            return refused(
                None,
                Reason::Unavailable,
                "signatures can only be checked on Windows".to_owned(),
            );
        }
        let mut file = match open_for_check(path) {
            Ok(file) => file,
            Err(error) => {
                return refused(
                    None,
                    Reason::NotChecked,
                    format!(
                        "the file cannot be opened in a way that keeps it from changing during the check: {error}"
                    ),
                );
            }
        };
        let unreadable = |error: io::Error| {
            refused(
                None,
                Reason::NotChecked,
                format!("the file cannot be read: {error}"),
            )
        };
        let sha256 = match sha256_of(&mut file) {
            Ok(sha256) => sha256,
            Err(error) => return unreadable(error),
        };
        let sha256_text = hex(&sha256);
        if scanned.is_some_and(|scanned| *scanned != sha256) {
            return refused(
                Some(sha256_text),
                Reason::Changed,
                "the file has changed since it was scanned".to_owned(),
            );
        }
        let area = match sigarea::inspect(&mut file) {
            Ok(area) => area,
            Err(error) => return unreadable(error),
        };

        let mut routes: Vec<RouteReport> = Vec::with_capacity(3);
        let mut trusted: Option<Trust> = None;
        for route in Route::ALL {
            if trusted.is_some() && !every_route {
                break;
            }
            let found = match route {
                Route::Embedded => match &area {
                    SignatureArea::NotExecutable => Found::NotApplicable {
                        why: "the file is no Windows executable, and a signature inside a file is only looked for in those".to_owned(),
                    },
                    SignatureArea::NoTable => Found::Nothing,
                    SignatureArea::Untidy(why) => Found::Invalid {
                        why: format!("{why}, so what the file carries as a signature does not count"),
                    },
                    SignatureArea::Tidy => self.os.embedded(path, &file),
                },
                Route::WindowsCatalog => match &area {
                    SignatureArea::NoTable => self.os.catalog(path, &file),
                    SignatureArea::NotExecutable => Found::NotApplicable {
                        why: "the file is no Windows executable, and only those are looked up in the catalogues".to_owned(),
                    },
                    SignatureArea::Tidy | SignatureArea::Untidy(_) => Found::NotApplicable {
                        why: "the file has a signature table, which the hash in a catalogue does not cover".to_owned(),
                    },
                },
                Route::Package => match package::locate(path) {
                    Some((folder, name)) => self.in_package(&folder, &name, &mut file),
                    None => Found::Nothing,
                },
            };
            if trusted.is_none()
                && let Found::Valid { signer, .. } = &found
                && signer.revocation == Revocation::Checked
                && let Some(publisher) = self.list.publisher_of(signer)
            {
                trusted = Some(Trust::Trusted {
                    publisher: publisher.name.clone(),
                    route,
                });
            }
            routes.push(RouteReport { route, found });
        }

        let trust = trusted.unwrap_or_else(|| self.why_not(&area, &routes));
        Examination {
            sha256: Some(sha256_text),
            executable: Some(area != SignatureArea::NotExecutable),
            routes,
            trust,
        }
    }

    /// Says why no route made the file trusted, by the route that came
    /// closest.
    fn why_not(&self, area: &SignatureArea, routes: &[RouteReport]) -> Trust {
        let signed = routes.iter().filter_map(|report| match &report.found {
            Found::Valid { signer, .. } => Some((report.route, signer)),
            _ => None,
        });
        let mut not_listed = None;
        for (route, signer) in signed {
            if self.list.publisher_of(signer).is_some() {
                // On the list, so what kept it from counting is revocation.
                return Trust::NotTrusted {
                    reason: Reason::RevocationUnknown,
                    detail: format!(
                        "signed for {}, which is on the trust list, but it could not be found out whether a certificate of the chain was revoked",
                        signer.common_name
                    ),
                };
            }
            not_listed.get_or_insert((route, signer));
        }
        if let Some((route, signer)) = not_listed {
            return Trust::NotTrusted {
                reason: Reason::NotListed,
                detail: format!(
                    "signed for {}, found in {}; that publisher is not on the trust list",
                    name_of(signer),
                    route.in_words()
                ),
            };
        }
        let first = |wanted: fn(&Found) -> Option<&String>| {
            routes.iter().find_map(|report| wanted(&report.found))
        };
        if let Some(why) = first(|found| match found {
            Found::Invalid { why } => Some(why),
            _ => None,
        }) {
            return Trust::NotTrusted {
                reason: Reason::Invalid,
                detail: why.clone(),
            };
        }
        if let Some(why) = first(|found| match found {
            Found::Failed { why } => Some(why),
            _ => None,
        }) {
            return Trust::NotTrusted {
                reason: Reason::NotChecked,
                detail: why.clone(),
            };
        }
        let detail = if *area == SignatureArea::NotExecutable {
            "the file is no Windows executable and no package vouches for it; signatures of other files are not looked for"
        } else {
            "no signature was found: not in the file, not in a catalogue of Windows, and not in a package"
        };
        Trust::NotTrusted {
            reason: Reason::NoSignature,
            detail: detail.to_owned(),
        }
    }

    /// The package route for a file in a package's folder.
    fn in_package(&self, folder: &Path, name: &str, file: &mut File) -> Found {
        let package = self.package(folder);
        let (signer, block_map) = match &*package {
            Package::Unusable(found) => return found.clone(),
            Package::Signed { signer, block_map } => (signer, block_map),
        };
        let Some(entry) = block_map.file(name) else {
            return Found::Invalid {
                why: "the block map of the file's package does not list the file".to_owned(),
            };
        };
        let matches = file
            .seek(SeekFrom::Start(0))
            .and_then(|_| entry.matches(file));
        match matches {
            Ok(true) => Found::Valid {
                signer: signer.clone(),
                place: Some(folder.display().to_string()),
            },
            Ok(false) => Found::Invalid {
                why: "the file is not the one that the block map of its package describes"
                    .to_owned(),
            },
            Err(error) => Found::Invalid {
                why: format!(
                    "the file could not be compared with the block map of its package: {error}"
                ),
            },
        }
    }

    /// What a package's folder is worth, looked up once and remembered.
    fn package(&self, folder: &Path) -> Arc<Package> {
        let remembered = |packages: &Mutex<HashMap<PathBuf, Arc<Package>>>| {
            packages
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get(folder)
                .cloned()
        };
        if let Some(package) = remembered(&self.packages) {
            return package;
        }
        // Worked out without holding the lock: two threads may do it at
        // the same time, and both get the same answer.
        let package = Arc::new(self.read_package(folder));
        let mut packages = self.packages.lock().unwrap_or_else(PoisonError::into_inner);
        if packages.len() >= PACKAGES_REMEMBERED {
            packages.clear();
        }
        packages.insert(folder.to_path_buf(), Arc::clone(&package));
        package
    }

    fn read_package(&self, folder: &Path) -> Package {
        let files = match PackageFiles::read(folder) {
            Ok(files) => files,
            Err(error) => {
                return Package::Unusable(Found::Invalid {
                    why: error.to_string(),
                });
            }
        };
        // Windows gets the bytes that were read here, so its answer is
        // about the signature whose digest the block map was compared
        // with.
        let signer = match self.os.package_signature(files.signature()) {
            Found::Valid { signer, .. } => signer,
            Found::Nothing => {
                return Package::Unusable(Found::Invalid {
                    why: "Windows finds no signature in the signature file of the file's package"
                        .to_owned(),
                });
            }
            other => return Package::Unusable(other),
        };
        match files.block_map() {
            Ok(block_map) => Package::Signed { signer, block_map },
            Err(error) => Package::Unusable(Found::Invalid {
                why: error.to_string(),
            }),
        }
    }
}

/// A signer's name for a sentence: the name, and the organisation where
/// it says more.
fn name_of(signer: &Signer) -> String {
    if signer.organization.is_empty() || signer.organization == signer.common_name {
        signer.common_name.clone()
    } else {
        format!("{} ({})", signer.common_name, signer.organization)
    }
}

fn refused(sha256: Option<String>, reason: Reason, detail: String) -> Examination {
    Examination {
        sha256,
        executable: None,
        routes: Vec::new(),
        trust: Trust::NotTrusted { reason, detail },
    }
}

/// Opens a file for the check. On Windows nobody can write to the file,
/// rename it or delete it while it is open this way, so what the routes
/// look at is one and the same content. Other readers are not kept out.
#[cfg(windows)]
fn open_for_check(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    /// Others may open the file for reading, and for nothing else.
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    File::options()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(path)
}

/// Opens a file for the check. Only Windows can answer about signatures,
/// and only there does opening a file keep others from changing it.
#[cfg(not(windows))]
fn open_for_check(path: &Path) -> io::Result<File> {
    File::open(path)
}

fn sha256_of(file: &mut File) -> io::Result<[u8; 32]> {
    file.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 256 * 1024];
    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => hasher.update(&buffer[..read]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(hasher.finalize().into())
}

/// A stand-in for Windows that answers with what it was told to, for tests
/// here and of the code that uses a [`Verifier`].
#[doc(hidden)]
pub mod stand_in {
    use std::fs::File;
    use std::path::Path;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::{Os, Verifier};
    use crate::list::TrustList;
    use crate::signature::{Certificate, Found, Revocation, Signer};

    /// The answers to give, and how often each question was asked.
    #[derive(Debug)]
    pub struct Answers {
        /// What the embedded route finds.
        pub embedded: Found,
        /// What the catalogue route finds.
        pub catalog: Found,
        /// What the signature of any package is worth.
        pub package: Found,
        /// How often the embedded route was asked.
        pub embedded_asked: AtomicUsize,
        /// How often the catalogue route was asked.
        pub catalog_asked: AtomicUsize,
        /// How often a package's signature was asked about.
        pub package_asked: AtomicUsize,
    }

    impl Default for Answers {
        fn default() -> Self {
            Self {
                embedded: Found::Nothing,
                catalog: Found::Nothing,
                package: Found::Nothing,
                embedded_asked: AtomicUsize::new(0),
                catalog_asked: AtomicUsize::new(0),
                package_asked: AtomicUsize::new(0),
            }
        }
    }

    impl Os for &'static Answers {
        fn embedded(&self, _: &Path, _: &File) -> Found {
            self.embedded_asked.fetch_add(1, Ordering::Relaxed);
            self.embedded.clone()
        }

        fn catalog(&self, _: &Path, _: &File) -> Found {
            self.catalog_asked.fetch_add(1, Ordering::Relaxed);
            self.catalog.clone()
        }

        fn package_signature(&self, _: &[u8]) -> Found {
            self.package_asked.fetch_add(1, Ordering::Relaxed);
            self.package.clone()
        }
    }

    /// A verifier that asks `answers` instead of Windows. The answers are
    /// leaked, which is fine for a test.
    #[must_use]
    pub fn verifier(list: TrustList, answers: Answers) -> (Verifier, &'static Answers) {
        let answers: &'static Answers = Box::leak(Box::new(answers));
        (Verifier::with_os(list, Box::new(answers)), answers)
    }

    /// A signature that holds, made by the given signer.
    #[must_use]
    pub fn valid(signer: Signer) -> Found {
        Found::Valid {
            signer,
            place: None,
        }
    }

    /// A signer with a chain of two certificates whose revocation was
    /// checked.
    #[must_use]
    pub fn signer(common_name: &str, organization: &str, microsoft_root: bool) -> Signer {
        Signer {
            common_name: common_name.to_owned(),
            organization: organization.to_owned(),
            chain: vec![
                Certificate {
                    subject: common_name.to_owned(),
                    sha256: "11".repeat(32),
                },
                Certificate {
                    subject: "A root".to_owned(),
                    sha256: "22".repeat(32),
                },
            ],
            microsoft_root,
            revocation: Revocation::Checked,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use base64::Engine as _;

    use super::stand_in::{Answers, signer, valid, verifier};
    use super::*;
    use crate::package::{BLOCK_BYTES, BLOCK_MAP_FILE, SIGNATURE_FILE, unsigned_signature_file};
    use crate::sigarea::{executable_with_table, table_with_signature};

    const LIST: &str = r#"
[[publisher]]
name = "Example"
common_name = "Example Ltd"
organization = "Example Ltd"
anchor = "microsoft-root"
signs = "Its own programs."
reason = "For the tests."
added = 2026-11-21

[[publisher.evidence]]
file = 'C:\example.exe'
sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
route = "embedded"
seen = 2026-11-21
machine = "a test"
"#;

    fn list() -> TrustList {
        TrustList::parse(LIST).expect("the test list")
    }

    fn listed() -> Signer {
        signer("Example Ltd", "Example Ltd", true)
    }

    fn stranger() -> Signer {
        signer("Somebody Else", "Somebody Else Inc", false)
    }

    /// A stand-in for a signature: one DER value of 100 bytes.
    fn signature() -> Vec<u8> {
        let mut value = vec![0x30, 0x62];
        value.resize(100, 0x5A);
        value
    }

    fn signed_executable() -> Vec<u8> {
        executable_with_table(&table_with_signature(&signature()))
    }

    fn unsigned_executable() -> Vec<u8> {
        executable_with_table(&[])
    }

    fn write(dir: &tempfile::TempDir, name: &str, content: &[u8]) -> PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, content).expect("a file in a temporary folder");
        path
    }

    fn reason(trust: &Trust) -> Option<Reason> {
        match trust {
            Trust::NotTrusted { reason, .. } => Some(*reason),
            Trust::Trusted { .. } => None,
        }
    }

    #[test]
    fn an_embedded_signature_of_a_listed_publisher_is_trusted() {
        let dir = tempfile::tempdir().expect("temporary folder");
        let path = write(&dir, "tool.exe", &signed_executable());
        let (verifier, answers) = verifier(
            list(),
            Answers {
                embedded: valid(listed()),
                ..Answers::default()
            },
        );
        let examination = verifier.examine(&path, None, false);
        assert_eq!(
            examination.trust,
            Trust::Trusted {
                publisher: "Example".to_owned(),
                route: Route::Embedded
            }
        );
        // The first route settled it, and the others were not tried.
        assert_eq!(examination.routes.len(), 1);
        assert_eq!(answers.catalog_asked.load(Ordering::Relaxed), 0);
        assert_eq!(examination.sha256.as_deref().map(str::len), Some(64));
    }

    #[test]
    fn a_valid_signature_of_somebody_else_is_not_trust() {
        let dir = tempfile::tempdir().expect("temporary folder");
        let path = write(&dir, "tool.exe", &signed_executable());
        let (verifier, answers) = verifier(
            list(),
            Answers {
                embedded: valid(stranger()),
                // Even a catalogue of a listed publisher does not help a
                // file that carries a signature table.
                catalog: valid(listed()),
                ..Answers::default()
            },
        );
        let examination = verifier.examine(&path, None, false);
        assert_eq!(reason(&examination.trust), Some(Reason::NotListed));
        assert_eq!(answers.catalog_asked.load(Ordering::Relaxed), 0);
        assert!(matches!(
            examination.routes[1].found,
            Found::NotApplicable { .. }
        ));
        let Trust::NotTrusted { detail, .. } = &examination.trust else {
            unreachable!("checked above");
        };
        assert!(detail.contains("Somebody Else"), "{detail}");
    }

    #[test]
    fn the_right_names_under_another_root_are_not_trust() {
        let dir = tempfile::tempdir().expect("temporary folder");
        let path = write(&dir, "tool.exe", &signed_executable());
        let impostor = signer("Example Ltd", "Example Ltd", false);
        let (verifier, _) = verifier(
            list(),
            Answers {
                embedded: valid(impostor),
                ..Answers::default()
            },
        );
        assert_eq!(
            reason(&verifier.trust(&path, None)),
            Some(Reason::NotListed)
        );
    }

    #[test]
    fn revocation_that_could_not_be_checked_is_not_trust() {
        let dir = tempfile::tempdir().expect("temporary folder");
        let path = write(&dir, "tool.exe", &signed_executable());
        let mut unchecked = listed();
        unchecked.revocation = Revocation::Unknown;
        let (verifier, _) = verifier(
            list(),
            Answers {
                embedded: valid(unchecked),
                ..Answers::default()
            },
        );
        assert_eq!(
            reason(&verifier.trust(&path, None)),
            Some(Reason::RevocationUnknown)
        );
    }

    #[test]
    fn bytes_added_to_the_signature_table_cost_the_trust() {
        let dir = tempfile::tempdir().expect("temporary folder");
        let mut table = table_with_signature(&signature());
        table.extend_from_slice(b"hidden in the table, sixteen bytes and more");
        table.resize(table.len().next_multiple_of(8), 0);
        let entry_len = table.len() as u32;
        table[..4].copy_from_slice(&entry_len.to_le_bytes());
        let path = write(&dir, "tool.exe", &executable_with_table(&table));

        // Windows would still call the signature valid.
        let (verifier, answers) = verifier(
            list(),
            Answers {
                embedded: valid(listed()),
                catalog: valid(listed()),
                ..Answers::default()
            },
        );
        let examination = verifier.examine(&path, None, false);
        assert_eq!(reason(&examination.trust), Some(Reason::Invalid));
        // Windows was not even asked.
        assert_eq!(answers.embedded_asked.load(Ordering::Relaxed), 0);
        assert_eq!(answers.catalog_asked.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn an_executable_without_a_signature_is_looked_up_in_the_catalogues() {
        let dir = tempfile::tempdir().expect("temporary folder");
        let path = write(&dir, "system.dll", &unsigned_executable());
        let (verifier, answers) = verifier(
            list(),
            Answers {
                catalog: valid(listed()),
                ..Answers::default()
            },
        );
        let examination = verifier.examine(&path, None, false);
        assert_eq!(
            examination.trust,
            Trust::Trusted {
                publisher: "Example".to_owned(),
                route: Route::WindowsCatalog
            }
        );
        assert_eq!(answers.embedded_asked.load(Ordering::Relaxed), 0);
        assert_eq!(examination.routes[0].found, Found::Nothing);
    }

    #[test]
    fn a_file_without_any_signature_is_not_trusted() {
        let dir = tempfile::tempdir().expect("temporary folder");
        let path = write(&dir, "plain.exe", &unsigned_executable());
        let (verifier, _) = verifier(list(), Answers::default());
        let examination = verifier.examine(&path, None, false);
        assert_eq!(reason(&examination.trust), Some(Reason::NoSignature));
        assert_eq!(examination.routes.len(), 3);
    }

    #[test]
    fn a_file_that_is_no_executable_is_not_asked_about() {
        let dir = tempfile::tempdir().expect("temporary folder");
        let path = write(&dir, "notes.txt", b"nothing to see here");
        let (verifier, answers) = verifier(
            list(),
            Answers {
                embedded: valid(listed()),
                catalog: valid(listed()),
                ..Answers::default()
            },
        );
        let examination = verifier.examine(&path, None, false);
        assert_eq!(reason(&examination.trust), Some(Reason::NoSignature));
        assert_eq!(answers.embedded_asked.load(Ordering::Relaxed), 0);
        assert_eq!(answers.catalog_asked.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn a_file_that_changed_since_the_scan_is_not_trusted() {
        let dir = tempfile::tempdir().expect("temporary folder");
        let content = signed_executable();
        let path = write(&dir, "tool.exe", &content);
        let (verifier, answers) = verifier(
            list(),
            Answers {
                embedded: valid(listed()),
                ..Answers::default()
            },
        );
        let scanned: [u8; 32] = Sha256::digest(&content).into();
        assert!(verifier.trust(&path, Some(&scanned)).is_trusted());

        let other = [0u8; 32];
        assert_eq!(
            reason(&verifier.trust(&path, Some(&other))),
            Some(Reason::Changed)
        );
        // Asked once, for the file that had not changed.
        assert_eq!(answers.embedded_asked.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn a_file_that_is_not_there_is_not_trusted() {
        let dir = tempfile::tempdir().expect("temporary folder");
        let (verifier, _) = verifier(list(), Answers::default());
        let trust = verifier.trust(&dir.path().join("gone.exe"), None);
        assert_eq!(reason(&trust), Some(Reason::NotChecked));
    }

    /// Builds a package's folder with a block map for the given files and
    /// a signature file that names it.
    fn package_folder(dir: &tempfile::TempDir, files: &[(&str, &[u8])]) -> PathBuf {
        let root = dir.path().join("Example.App_1.0.0.0_x64__0123456789abc");
        std::fs::create_dir_all(&root).expect("folder");
        let mut xml = String::from(
            "<BlockMap xmlns=\"http://schemas.microsoft.com/appx/2010/blockmap\" \
             HashMethod=\"http://www.w3.org/2001/04/xmlenc#sha256\">",
        );
        for (name, content) in files {
            let path = root.join(name.replace('\\', "/"));
            std::fs::create_dir_all(path.parent().expect("inside the folder")).expect("folder");
            std::fs::write(&path, content).expect("file");
            xml.push_str(&format!(
                "<File Name=\"{name}\" Size=\"{}\">",
                content.len()
            ));
            for block in content.chunks(BLOCK_BYTES) {
                let hash = base64::engine::general_purpose::STANDARD.encode(Sha256::digest(block));
                xml.push_str(&format!("<Block Hash=\"{hash}\"/>"));
            }
            xml.push_str("</File>");
        }
        xml.push_str("</BlockMap>");
        std::fs::write(root.join(BLOCK_MAP_FILE), &xml).expect("file");
        let mut digests = b"APPX".to_vec();
        digests.extend_from_slice(b"AXBM");
        digests.extend_from_slice(&Sha256::digest(xml.as_bytes()));
        std::fs::write(root.join(SIGNATURE_FILE), unsigned_signature_file(&digests)).expect("file");
        root
    }

    #[test]
    fn a_file_of_a_package_is_vouched_for_by_the_package() {
        let dir = tempfile::tempdir().expect("temporary folder");
        let script = b"console.log('part of an app');".as_slice();
        let library = unsigned_executable();
        let root = package_folder(
            &dir,
            &[("app\\main.js", script), ("bin\\helper.dll", &library)],
        );
        let (verifier, answers) = verifier(
            list(),
            Answers {
                package: valid(listed()),
                ..Answers::default()
            },
        );

        // A file that is no executable: only the package can vouch for it.
        let examination = verifier.examine(&root.join("app").join("main.js"), None, false);
        assert_eq!(
            examination.trust,
            Trust::Trusted {
                publisher: "Example".to_owned(),
                route: Route::Package
            }
        );
        // An executable without a signature of its own, not in any
        // catalogue: the package again.
        let trust = verifier.trust(&root.join("bin").join("helper.dll"), None);
        assert!(trust.is_trusted(), "{trust:?}");
        // The package's signature was asked about once for both files.
        assert_eq!(answers.package_asked.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn a_changed_or_added_file_in_a_package_is_not_vouched_for() {
        let dir = tempfile::tempdir().expect("temporary folder");
        let root = package_folder(&dir, &[("app\\main.js", b"console.log('original');")]);
        let (verifier, _) = verifier(
            list(),
            Answers {
                package: valid(listed()),
                ..Answers::default()
            },
        );

        std::fs::write(
            root.join("app").join("main.js"),
            b"console.log('changed!');",
        )
        .expect("file");
        let trust = verifier.trust(&root.join("app").join("main.js"), None);
        assert_eq!(reason(&trust), Some(Reason::Invalid));

        std::fs::write(
            root.join("app").join("added.js"),
            b"// not in the block map",
        )
        .expect("file");
        let trust = verifier.trust(&root.join("app").join("added.js"), None);
        assert_eq!(reason(&trust), Some(Reason::Invalid));
    }

    #[test]
    fn a_package_whose_signature_does_not_hold_vouches_for_nothing() {
        let dir = tempfile::tempdir().expect("temporary folder");
        let root = package_folder(&dir, &[("app\\main.js", b"console.log('x');")]);
        let file = root.join("app").join("main.js");

        let (unsigned, _) = verifier(list(), Answers::default());
        assert_eq!(reason(&unsigned.trust(&file, None)), Some(Reason::Invalid));

        let (rejected, _) = verifier(
            list(),
            Answers {
                package: Found::Invalid {
                    why: "the chain ends in a root that this machine does not trust".to_owned(),
                },
                ..Answers::default()
            },
        );
        assert_eq!(reason(&rejected.trust(&file, None)), Some(Reason::Invalid));

        let (foreign, _) = verifier(
            list(),
            Answers {
                package: valid(stranger()),
                ..Answers::default()
            },
        );
        assert_eq!(reason(&foreign.trust(&file, None)), Some(Reason::NotListed));
    }

    #[test]
    fn a_block_map_that_the_signature_does_not_name_vouches_for_nothing() {
        let dir = tempfile::tempdir().expect("temporary folder");
        let root = package_folder(&dir, &[("app\\main.js", b"console.log('x');")]);
        // Somebody rewrites the block map to fit a file of their own.
        let mut xml = std::fs::read(root.join(BLOCK_MAP_FILE)).expect("file");
        xml.push(b'\n');
        std::fs::write(root.join(BLOCK_MAP_FILE), xml).expect("file");

        let (verifier, answers) = verifier(
            list(),
            Answers {
                package: valid(listed()),
                ..Answers::default()
            },
        );
        let trust = verifier.trust(&root.join("app").join("main.js"), None);
        assert_eq!(reason(&trust), Some(Reason::Invalid));
        // Windows was not asked about a signature that does not fit.
        assert_eq!(answers.package_asked.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn every_route_can_be_reported() {
        let dir = tempfile::tempdir().expect("temporary folder");
        let root = package_folder(&dir, &[("tool.exe", &signed_executable())]);
        let (verifier, _) = verifier(
            list(),
            Answers {
                embedded: valid(listed()),
                package: valid(listed()),
                ..Answers::default()
            },
        );
        let examination = verifier.examine(&root.join("tool.exe"), None, true);
        assert_eq!(examination.routes.len(), 3);
        // The first route that made it trusted is the one that is named.
        assert_eq!(
            examination.trust,
            Trust::Trusted {
                publisher: "Example".to_owned(),
                route: Route::Embedded
            }
        );
        assert!(matches!(examination.routes[2].found, Found::Valid { .. }));
    }

    #[test]
    fn a_system_that_cannot_check_signatures_trusts_nothing() {
        struct Nowhere;
        impl Os for Nowhere {
            fn available(&self) -> bool {
                false
            }
            fn embedded(&self, _: &Path, _: &File) -> Found {
                unreachable!("not asked")
            }
            fn catalog(&self, _: &Path, _: &File) -> Found {
                unreachable!("not asked")
            }
            fn package_signature(&self, _: &[u8]) -> Found {
                unreachable!("not asked")
            }
        }
        let dir = tempfile::tempdir().expect("temporary folder");
        let path = write(&dir, "tool.exe", &signed_executable());
        let verifier = Verifier::with_os(list(), Box::new(Nowhere));
        assert!(!verifier.available());
        assert_eq!(
            reason(&verifier.trust(&path, None)),
            Some(Reason::Unavailable)
        );
    }
}

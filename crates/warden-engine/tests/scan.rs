//! End-to-end tests of the scan pipeline against real directory trees.
//!
//! Nothing here is malware. "Threats" are harmless files whose hashes the
//! test itself registers in a throwaway signature database, plus the EICAR
//! antivirus test file.

#![allow(clippy::unwrap_used)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use warden_engine::{
    CancelToken, Confidence, Detection, Detector, DetectorError, FileView, Finding, HashDetector,
    NoObserver, PartialReason, Progress, ScanError, ScanObserver, ScanOptions, ScanReport, Scanner,
    Session, SkipReason, ThreatCategory, Verdict, eicar,
};
use warden_sigdb::{Category, SigDb, SigDbBuilder};

/// Deterministic, harmless file content.
fn fixture(seed: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| seed.wrapping_add((index % 251) as u8))
        .collect()
}

fn write(path: &Path, bytes: &[u8]) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

fn database(threats: &[(&[u8], &str, Category)]) -> Arc<SigDb> {
    let mut builder = SigDbBuilder::new();
    for (bytes, name, category) in threats {
        builder
            .add(warden_engine::sha256(bytes), name, *category)
            .unwrap();
    }
    Arc::new(SigDb::from_bytes(builder.build().unwrap().0).unwrap())
}

fn hash_scanner(threats: &[(&[u8], &str, Category)], options: ScanOptions) -> Scanner {
    Scanner::builder()
        .detector(HashDetector::with_database(database(threats)))
        .options(options)
        .build()
}

fn scan(scanner: &Scanner, root: &Path) -> ScanReport {
    scanner
        .scan(&[root.to_path_buf()], &mut NoObserver, &CancelToken::new())
        .unwrap()
}

fn relative_paths(report: &ScanReport, root: &Path) -> Vec<String> {
    let root = std::path::absolute(root).unwrap();
    report
        .detections
        .iter()
        .map(|detection| {
            detection
                .path
                .strip_prefix(&root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect()
}

#[test]
fn planted_fixtures_are_found_and_reported_in_path_order() {
    let dir = tempfile::tempdir().unwrap();
    let trojan = fixture(1, 5000);
    let adware = fixture(2, 300);
    write(&dir.path().join("zeta/trojan.bin"), &trojan);
    write(&dir.path().join("alpha/deep/er/adware.bin"), &adware);
    write(&dir.path().join("alpha/copy-of-trojan.bin"), &trojan);
    for index in 0..40u8 {
        write(
            &dir.path().join(format!("clean/{index}.dat")),
            &fixture(100 + index, 64 + usize::from(index)),
        );
    }

    let scanner = hash_scanner(
        &[
            (&trojan, "Test.Trojan", Category::Malware),
            (&adware, "Test.Adware", Category::PotentiallyUnwanted),
        ],
        ScanOptions::default(),
    );
    let report = scan(&scanner, dir.path());

    assert_eq!(report.stats.files_scanned, 43);
    assert_eq!(report.stats.detections, 3);
    assert_eq!(report.stats.files_skipped, 0);
    assert!(!report.cancelled);
    assert!(!report.is_clean());
    assert_eq!(
        relative_paths(&report, dir.path()),
        [
            "alpha/copy-of-trojan.bin",
            "alpha/deep/er/adware.bin",
            "zeta/trojan.bin"
        ]
    );

    let adware_hit = &report.detections[1];
    assert_eq!(adware_hit.verdict, Verdict::Malicious);
    assert_eq!(adware_hit.size, 300);
    assert_eq!(
        adware_hit.sha256,
        warden_sigdb::hex::encode(&warden_engine::sha256(&adware))
    );
    assert_eq!(adware_hit.findings.len(), 1);
    let finding = &adware_hit.findings[0];
    assert_eq!(finding.detector, "hash");
    assert_eq!(finding.name, "Test.Adware");
    assert_eq!(finding.category, ThreatCategory::PotentiallyUnwanted);
    assert_eq!(finding.confidence, Confidence::Definitive);
    assert!(!finding.reasons.is_empty());

    let expected_bytes: u64 = 5000 + 300 + 5000 + (0..40u64).map(|index| 64 + index).sum::<u64>();
    assert_eq!(report.stats.bytes_scanned, expected_bytes);
    assert!(report.stats.files_per_second > 0.0);
    assert!(report.stats.megabytes_per_second > 0.0);
}

#[test]
fn a_clean_tree_is_clean() {
    let dir = tempfile::tempdir().unwrap();
    write(&dir.path().join("a.txt"), b"hello");
    write(&dir.path().join("sub/b.txt"), b"world");
    fs::create_dir_all(dir.path().join("empty-directory")).unwrap();
    write(&dir.path().join("empty-file"), b"");

    let report = scan(&hash_scanner(&[], ScanOptions::default()), dir.path());
    assert!(report.is_clean());
    assert_eq!(report.stats.files_scanned, 3);
    assert_eq!(report.stats.bytes_scanned, 10);
    assert_eq!(report.stats.detections, 0);
}

#[test]
fn hashes_match_published_test_vectors() {
    // FIPS 180-2 test vectors, so the pipeline's hashing is checked against
    // something other than itself.
    let dir = tempfile::tempdir().unwrap();
    let abc = b"abc";
    let empty = b"";
    write(&dir.path().join("abc"), abc);
    write(&dir.path().join("empty"), empty);
    let scanner = hash_scanner(
        &[
            (abc, "Vector.Abc", Category::TestFile),
            (empty, "Vector.Empty", Category::TestFile),
        ],
        ScanOptions::default(),
    );
    let report = scan(&scanner, dir.path());
    assert_eq!(
        report.detections[0].sha256,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        report.detections[1].sha256,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn eicar_is_detected_in_memory() {
    let scanner = Scanner::builder().detector(HashDetector::new()).build();
    let result = scanner.scan_bytes(&eicar::test_file());
    assert_eq!(result.verdict, Verdict::Malicious);
    assert_eq!(result.size, 68);
    assert_eq!(warden_sigdb::hex::encode(&result.sha256), eicar::SHA256_HEX);
    assert_eq!(result.findings[0].name, eicar::DETECTION_NAME);
    assert_eq!(result.findings[0].category, ThreatCategory::TestFile);

    assert_eq!(scanner.scan_bytes(b"just text").verdict, Verdict::Clean);
}

/// Writes the EICAR test file to disk and scans it.
///
/// A resident antivirus removes that file, or blocks access to it, within
/// moments, and raises an alert while doing so. The test is therefore careful
/// about where and when it runs:
///
/// - `WARDEN_EICAR_DIR` names a folder that is excluded from the resident
///   antivirus. The test then works inside it.
/// - Without that variable the test uses the system temporary folder, except
///   on Windows, where it does not run at all: every Windows machine has a
///   resident antivirus, and a test suite should not set off its alarms.
/// - `WARDEN_REQUIRE_EICAR=1` turns "did not run" or "was blocked" into a
///   failure. CI sets it, together with a folder of its own.
#[test]
fn eicar_is_detected_on_disk() {
    let strict = std::env::var_os("WARDEN_REQUIRE_EICAR").is_some_and(|value| value == "1");
    let not_exercised = |why: &str| {
        let note = format!("EICAR on-disk test not exercised: {why}. See docs/TESTING.md.");
        assert!(!strict, "{note}");
        eprintln!("note: {note}");
    };

    let configured = std::env::var_os("WARDEN_EICAR_DIR")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from);
    if cfg!(windows) && configured.is_none() {
        not_exercised("WARDEN_EICAR_DIR is not set to an antivirus-excluded folder");
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let dir = match &configured {
        Some(base) => base.join(format!("engine-{}", std::process::id())),
        None => temp.path().to_path_buf(),
    };
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join(eicar::FILE_NAME);

    if let Err(error) = fs::write(&path, eicar::test_file()) {
        not_exercised(&format!("the test file could not be written ({error})"));
        return;
    }
    let scanner = Scanner::builder().detector(HashDetector::new()).build();
    let report = scan(&scanner, &dir);
    let _ = fs::remove_file(&path);
    if configured.is_some() {
        let _ = fs::remove_dir(&dir);
    }

    if report.stats.files_scanned == 0 {
        not_exercised("the test file was removed or locked before it could be scanned");
        return;
    }
    assert_eq!(report.stats.detections, 1);
    let detection = &report.detections[0];
    assert_eq!(detection.sha256, eicar::SHA256_HEX);
    assert_eq!(detection.findings[0].name, eicar::DETECTION_NAME);
    assert_eq!(detection.verdict, Verdict::Malicious);
}

#[test]
fn unusual_names_and_deep_paths_are_scanned() {
    let dir = tempfile::tempdir().unwrap();
    let threat = fixture(7, 100);
    let unicode = dir.path().join("ünïcödé ディレクトリ/файл с пробелами.bin");
    write(&unicode, &threat);

    // Deeper than the 260-character limit that old Windows APIs impose.
    let mut deep = dir.path().to_path_buf();
    for level in 0..30 {
        deep.push(format!("level-{level:02}-padding"));
    }
    deep.push("deep.bin");
    let deep_supported = fs::create_dir_all(deep.parent().unwrap())
        .and_then(|()| fs::write(&deep, &threat))
        .is_ok();

    let scanner = hash_scanner(
        &[(&threat, "Test.Named", Category::Malware)],
        ScanOptions::default(),
    );
    let report = scan(&scanner, dir.path());
    let expected = if deep_supported { 2 } else { 1 };
    assert_eq!(report.stats.detections, expected);
    assert_eq!(report.stats.files_skipped, 0);
    assert!(
        report
            .detections
            .iter()
            .any(|detection| detection.path.ends_with("файл с пробелами.bin"))
    );
}

#[test]
fn exclusions_prune_whole_subtrees() {
    let dir = tempfile::tempdir().unwrap();
    let threat = fixture(9, 64);
    write(&dir.path().join("scan-me/threat.bin"), &threat);
    write(&dir.path().join("skip-me/threat.bin"), &threat);
    write(&dir.path().join("skip-me/nested/threat.bin"), &threat);
    write(&dir.path().join("skip-me-not/threat.bin"), &threat);
    write(&dir.path().join("single-file.bin"), &threat);

    let options = ScanOptions {
        exclude: vec![
            dir.path().join("skip-me"),
            dir.path().join("single-file.bin"),
        ],
        ..ScanOptions::default()
    };
    let scanner = hash_scanner(&[(&threat, "Test.Excluded", Category::Malware)], options);
    let report = scan(&scanner, dir.path());

    assert_eq!(
        relative_paths(&report, dir.path()),
        ["scan-me/threat.bin", "skip-me-not/threat.bin"]
    );
    // One pruned directory and one excluded file.
    assert_eq!(report.stats.excluded, 2);
    assert_eq!(report.stats.files_scanned, 2);
}

#[test]
fn a_single_file_can_be_a_root() {
    let dir = tempfile::tempdir().unwrap();
    let threat = fixture(11, 10);
    let path = dir.path().join("only.bin");
    write(&path, &threat);
    write(&dir.path().join("neighbour.bin"), &threat);

    let scanner = hash_scanner(
        &[(&threat, "Test.Single", Category::Malware)],
        ScanOptions::default(),
    );
    let report = scan(&scanner, &path);
    assert_eq!(report.stats.files_scanned, 1);
    assert_eq!(report.stats.detections, 1);
}

#[test]
fn several_roots_are_scanned_together() {
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    let threat = fixture(13, 10);
    write(&first.path().join("a.bin"), &threat);
    write(&second.path().join("b.bin"), &threat);

    let scanner = hash_scanner(
        &[(&threat, "Test.Roots", Category::Malware)],
        ScanOptions::default(),
    );
    let report = scanner
        .scan(
            &[first.path().to_path_buf(), second.path().to_path_buf()],
            &mut NoObserver,
            &CancelToken::new(),
        )
        .unwrap();
    assert_eq!(report.stats.detections, 2);
    assert_eq!(report.roots.len(), 2);
}

#[test]
fn impossible_requests_are_errors_not_empty_reports() {
    let scanner = hash_scanner(&[], ScanOptions::default());
    let none = scanner.scan(&[], &mut NoObserver, &CancelToken::new());
    assert!(matches!(none, Err(ScanError::NoRoots)));

    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("does-not-exist");
    let result = scanner.scan(
        std::slice::from_ref(&missing),
        &mut NoObserver,
        &CancelToken::new(),
    );
    match result {
        Err(ScanError::Root { path, .. }) => assert_eq!(path, missing),
        other => panic!("expected a root error, got {other:?}"),
    }
}

#[cfg(unix)]
#[test]
fn links_are_counted_but_not_followed() {
    let dir = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let threat = fixture(15, 50);
    write(&outside.path().join("threat.bin"), &threat);
    write(&dir.path().join("real/threat.bin"), &threat);
    std::os::unix::fs::symlink(outside.path(), dir.path().join("link-to-directory")).unwrap();
    std::os::unix::fs::symlink(
        outside.path().join("threat.bin"),
        dir.path().join("link-to-file"),
    )
    .unwrap();
    // A link that points back up the tree must not cause an endless walk.
    std::os::unix::fs::symlink(dir.path(), dir.path().join("real/loop")).unwrap();

    let scanner = hash_scanner(
        &[(&threat, "Test.Linked", Category::Malware)],
        ScanOptions::default(),
    );
    let report = scan(&scanner, dir.path());
    assert_eq!(relative_paths(&report, dir.path()), ["real/threat.bin"]);
    assert_eq!(report.stats.links_not_followed, 3);
    assert_eq!(report.stats.files_skipped, 0);
}

#[cfg(unix)]
#[test]
fn unreadable_files_are_reported_with_a_reason() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let locked = dir.path().join("locked.bin");
    write(&locked, b"secret");
    write(&dir.path().join("open.bin"), b"public");
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
    if fs::read(&locked).is_ok() {
        // Running as root: permissions do not apply, nothing to test.
        return;
    }

    let report = scan(&hash_scanner(&[], ScanOptions::default()), dir.path());
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o600)).unwrap();

    assert_eq!(report.stats.files_scanned, 1);
    assert_eq!(report.stats.files_skipped, 1);
    assert_eq!(report.stats.folders_skipped, 0);
    assert_eq!(report.stats.skipped_by_reason[&SkipReason::AccessDenied], 1);
    assert_eq!(report.skipped[0].reason, SkipReason::AccessDenied);
    assert!(!report.skipped[0].folder);
    assert!(report.skipped[0].path.ends_with("locked.bin"));
    assert!(!report.skipped[0].detail.is_empty());
}

/// What a scan says about a folder it may not open: one entry, marked as a
/// folder and counted apart from the files, because nobody knows how many
/// files it stands for. Here it stands for three.
fn assert_the_closed_folder_is_told_apart(report: &ScanReport) {
    assert_eq!(report.stats.files_scanned, 1, "only the file next to it");
    assert_eq!(report.stats.folders_skipped, 1);
    assert_eq!(report.stats.files_skipped, 0);
    assert_eq!(report.stats.skipped_by_reason[&SkipReason::AccessDenied], 1);
    assert_eq!(report.skipped.len(), 1);
    assert!(report.skipped[0].folder);
    assert_eq!(report.skipped[0].reason, SkipReason::AccessDenied);
    assert!(report.skipped[0].path.ends_with("closed"));
    assert!(!report.skipped[0].detail.is_empty());
    assert!(
        report.detections.is_empty(),
        "what is in it was not scanned"
    );
}

/// A folder with three files in it, one of them a registered threat, next
/// to one ordinary file.
fn tree_with_a_folder_to_close(threat: &[u8]) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let closed = dir.path().join("closed");
    write(&closed.join("one.bin"), b"first");
    write(&closed.join("two.bin"), b"second");
    write(&closed.join("deeper/threat.bin"), threat);
    write(&dir.path().join("open.bin"), b"public");
    (dir, closed)
}

#[cfg(unix)]
#[test]
fn a_folder_that_cannot_be_opened_is_counted_apart_from_files() {
    use std::os::unix::fs::PermissionsExt;

    let threat = fixture(91, 64);
    let (dir, closed) = tree_with_a_folder_to_close(&threat);
    fs::set_permissions(&closed, fs::Permissions::from_mode(0o000)).unwrap();
    if fs::read_dir(&closed).is_ok() {
        // Running as root: permissions do not apply, nothing to test.
        fs::set_permissions(&closed, fs::Permissions::from_mode(0o700)).unwrap();
        return;
    }

    let scanner = hash_scanner(
        &[(&threat, "Test.Hidden", Category::Malware)],
        ScanOptions::default(),
    );
    let report = scan(&scanner, dir.path());
    fs::set_permissions(&closed, fs::Permissions::from_mode(0o700)).unwrap();

    assert_the_closed_folder_is_told_apart(&report);
}

/// The Windows case that this was written for: a folder like
/// `C:\Program Files\WindowsApps`, which a program without administrator
/// rights may see and not list.
#[cfg(windows)]
#[test]
fn a_folder_that_cannot_be_opened_is_counted_apart_from_files() {
    fn icacls(folder: &Path, arguments: &[&str]) {
        let status = std::process::Command::new("icacls")
            .arg(folder)
            .args(arguments)
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "icacls {arguments:?}");
    }

    let threat = fixture(91, 64);
    let (dir, closed) = tree_with_a_folder_to_close(&threat);
    // Everyone (S-1-1-0) is denied the right to list the folder. A denial
    // comes before every permission, an administrator's included.
    icacls(&closed, &["/deny", "*S-1-1-0:(RD)"]);
    assert!(
        fs::read_dir(&closed).is_err(),
        "the folder should be closed"
    );

    let scanner = hash_scanner(
        &[(&threat, "Test.Hidden", Category::Malware)],
        ScanOptions::default(),
    );
    let report = scan(&scanner, dir.path());
    icacls(&closed, &["/remove:d", "*S-1-1-0"]);

    assert_the_closed_folder_is_told_apart(&report);
}

/// A detector that reads content: flags files that contain a marker.
struct MarkerDetector;

const MARKER: &[u8] = b"WARDEN-TEST-MARKER";

impl Detector for MarkerDetector {
    fn id(&self) -> &'static str {
        "marker"
    }

    fn needs_content(&self) -> bool {
        true
    }

    fn session(&self) -> Box<dyn Session + '_> {
        Box::new(self)
    }
}

impl Session for &MarkerDetector {
    fn inspect(&mut self, file: &FileView<'_>) -> Result<Vec<Finding>, DetectorError> {
        let content = file
            .content()
            .ok_or_else(|| DetectorError::Failed("content was not provided".to_owned()))?;
        assert_eq!(content.len() as u64, file.size());
        if file
            .path()
            .file_name()
            .is_some_and(|name| name == "fail.bin")
        {
            return Err(DetectorError::Failed(
                "refusing this file on purpose".to_owned(),
            ));
        }
        if file
            .path()
            .file_name()
            .is_some_and(|name| name == "boom.bin")
        {
            panic!("panicking on purpose");
        }
        if content.windows(MARKER.len()).any(|window| window == MARKER) {
            return Ok(vec![Finding::new(
                "marker",
                "Test.Marker",
                ThreatCategory::Malware,
                Confidence::Medium,
                vec!["contains the test marker".to_owned()],
            )]);
        }
        Ok(Vec::new())
    }
}

fn with_marker(len: usize) -> Vec<u8> {
    let mut bytes = fixture(21, len);
    bytes[10..10 + MARKER.len()].copy_from_slice(MARKER);
    bytes
}

#[test]
fn content_detectors_see_small_files_and_large_files_are_still_hashed() {
    let dir = tempfile::tempdir().unwrap();
    let small = with_marker(200);
    let large = with_marker(5000);
    let exact = with_marker(1024);
    write(&dir.path().join("small.bin"), &small);
    write(&dir.path().join("large.bin"), &large);
    write(&dir.path().join("exactly-at-limit.bin"), &exact);
    write(&dir.path().join("clean.bin"), &fixture(22, 300));

    let scanner = Scanner::builder()
        .detector(HashDetector::with_database(database(&[(
            &large,
            "Test.LargeByHash",
            Category::Malware,
        )])))
        .detector(MarkerDetector)
        .options(ScanOptions {
            max_content_bytes: 1024,
            ..ScanOptions::default()
        })
        .build();
    let report = scan(&scanner, dir.path());

    assert_eq!(report.stats.files_scanned, 4);
    assert_eq!(report.stats.files_partially_scanned, 1);
    assert_eq!(report.stats.partial_by_reason[&PartialReason::TooLarge], 1);
    assert_eq!(report.partially_scanned.len(), 1);
    assert!(report.partially_scanned[0].path.ends_with("large.bin"));
    assert!(report.partially_scanned[0].detail.contains("1024 bytes"));
    assert_eq!(
        relative_paths(&report, dir.path()),
        ["exactly-at-limit.bin", "large.bin", "small.bin"]
    );
    // Medium confidence alone is suspicious, not malicious.
    assert_eq!(report.detections[0].verdict, Verdict::Suspicious);
    assert_eq!(report.detections[2].verdict, Verdict::Suspicious);
    // The large file never reached the marker detector, but its streamed
    // hash is correct, so the hash layer still caught it.
    let large_hit = &report.detections[1];
    assert_eq!(large_hit.verdict, Verdict::Malicious);
    assert_eq!(large_hit.size, 5000);
    assert_eq!(large_hit.findings.len(), 1);
    assert_eq!(large_hit.findings[0].name, "Test.LargeByHash");
    assert_eq!(
        large_hit.sha256,
        warden_sigdb::hex::encode(&warden_engine::sha256(&large))
    );
    assert_eq!(report.stats.bytes_scanned, 200 + 5000 + 1024 + 300);
}

#[test]
fn a_failing_detector_is_recorded_and_the_other_detectors_still_run() {
    let dir = tempfile::tempdir().unwrap();
    let threat = fixture(31, 80);
    write(&dir.path().join("fail.bin"), &threat);
    write(&dir.path().join("fine.bin"), &with_marker(80));

    let scanner = Scanner::builder()
        .detector(MarkerDetector)
        .detector(HashDetector::with_database(database(&[(
            &threat,
            "Test.StillCaught",
            Category::Malware,
        )])))
        .build();
    let report = scan(&scanner, dir.path());

    assert_eq!(report.stats.files_scanned, 2);
    assert_eq!(report.stats.files_partially_scanned, 1);
    assert_eq!(
        report.stats.partial_by_reason[&PartialReason::DetectorError],
        1
    );
    assert_eq!(report.partially_scanned.len(), 1);
    assert!(report.partially_scanned[0].path.ends_with("fail.bin"));
    assert_eq!(
        report.partially_scanned[0].reason,
        PartialReason::DetectorError
    );
    assert!(
        report.partially_scanned[0]
            .detail
            .starts_with("marker: refusing")
    );
    assert_eq!(report.stats.detections, 2);
    assert!(
        report
            .detections
            .iter()
            .any(|detection| detection.findings[0].name == "Test.StillCaught")
    );
}

#[test]
fn a_panicking_detector_costs_one_file_not_the_scan() {
    let dir = tempfile::tempdir().unwrap();
    for name in ["a/boom.bin", "b/boom.bin", "c/boom.bin"] {
        write(
            &dir.path().join(name),
            b"this file makes the test detector panic",
        );
    }
    for index in 0..20 {
        write(
            &dir.path().join(format!("ok/{index}.bin")),
            &with_marker(64),
        );
    }

    let scanner = Scanner::builder()
        .detector(MarkerDetector)
        .options(ScanOptions {
            max_recorded_skips: 2,
            ..ScanOptions::default()
        })
        .build();
    let report = scan(&scanner, dir.path());

    assert_eq!(report.stats.files_scanned, 20);
    assert_eq!(report.stats.detections, 20);
    assert_eq!(report.stats.files_skipped, 3);
    assert_eq!(
        report.stats.skipped_by_reason[&SkipReason::InternalError],
        3
    );
    // The list is capped, the counters are not.
    assert_eq!(report.skipped.len(), 2);
    assert!(report.skipped_truncated);
    assert!(report.skipped[0].detail.contains("panicking on purpose"));
}

#[test]
fn results_do_not_depend_on_the_number_of_threads() {
    let dir = tempfile::tempdir().unwrap();
    let threat = fixture(41, 777);
    for index in 0..200u32 {
        let bytes = if index % 17 == 0 {
            threat.clone()
        } else {
            fixture((index % 200) as u8, 100 + index as usize)
        };
        write(
            &dir.path().join(format!("d{}/f{index}.bin", index % 7)),
            &bytes,
        );
    }
    let run = |threads: usize| {
        let options = ScanOptions {
            threads,
            ..ScanOptions::default()
        };
        let scanner = hash_scanner(&[(&threat, "Test.Threads", Category::Malware)], options);
        scan(&scanner, dir.path())
    };
    let single = run(1);
    let many = run(8);
    assert_eq!(single.threads, 1);
    assert_eq!(many.threads, 8);
    assert_eq!(single.detections, many.detections);
    assert_eq!(single.stats.files_scanned, many.stats.files_scanned);
    assert_eq!(single.stats.bytes_scanned, many.stats.bytes_scanned);
    assert_eq!(single.stats.detections, 12);
}

/// Sleeps on every file, so that a scan lasts long enough to be cancelled.
struct SlowDetector;

impl Detector for SlowDetector {
    fn id(&self) -> &'static str {
        "slow"
    }

    fn session(&self) -> Box<dyn Session + '_> {
        Box::new(self)
    }
}

impl Session for &SlowDetector {
    fn inspect(&mut self, _file: &FileView<'_>) -> Result<Vec<Finding>, DetectorError> {
        std::thread::sleep(Duration::from_millis(3));
        Ok(Vec::new())
    }
}

#[derive(Default)]
struct CancelOnFirstProgress {
    token: CancelToken,
    progress_calls: u32,
    last: Option<Progress>,
}

impl ScanObserver for CancelOnFirstProgress {
    fn on_progress(&mut self, progress: &Progress) {
        self.progress_calls += 1;
        self.last = Some(*progress);
        self.token.cancel();
    }
}

#[test]
fn a_scan_can_be_cancelled_while_it_runs() {
    let dir = tempfile::tempdir().unwrap();
    for index in 0..600 {
        write(&dir.path().join(format!("{index}.bin")), b"x");
    }
    let scanner = Scanner::builder()
        .detector(SlowDetector)
        .options(ScanOptions {
            threads: 2,
            ..ScanOptions::default()
        })
        .build();

    let mut observer = CancelOnFirstProgress::default();
    let token = observer.token.clone();
    let report = scanner
        .scan(&[dir.path().to_path_buf()], &mut observer, &token)
        .unwrap();

    assert!(report.cancelled);
    assert!(
        report.stats.files_scanned < 600,
        "the scan ran to completion ({} files) despite being cancelled",
        report.stats.files_scanned
    );
    assert!(
        observer.progress_calls >= 2,
        "a final progress call is made"
    );
    assert_eq!(
        observer.last.unwrap().files_scanned,
        report.stats.files_scanned
    );
}

#[test]
fn a_token_cancelled_up_front_scans_nothing() {
    let dir = tempfile::tempdir().unwrap();
    write(&dir.path().join("a.bin"), b"x");
    let token = CancelToken::new();
    token.cancel();
    let report = hash_scanner(&[], ScanOptions::default())
        .scan(&[dir.path().to_path_buf()], &mut NoObserver, &token)
        .unwrap();
    assert!(report.cancelled);
    assert_eq!(report.stats.files_scanned, 0);
}

#[derive(Default)]
struct Recorder {
    detections: Vec<Detection>,
    skipped: u32,
}

impl ScanObserver for Recorder {
    fn on_detection(&mut self, detection: &Detection) {
        self.detections.push(detection.clone());
    }

    fn on_skipped(&mut self, _skipped: &warden_engine::Skipped) {
        self.skipped += 1;
    }
}

#[test]
fn the_observer_hears_about_every_detection() {
    let dir = tempfile::tempdir().unwrap();
    let threat = fixture(51, 32);
    for index in 0..5 {
        write(&dir.path().join(format!("{index}.bin")), &threat);
    }
    let scanner = hash_scanner(
        &[(&threat, "Test.Observed", Category::Malware)],
        ScanOptions::default(),
    );
    let mut recorder = Recorder::default();
    let report = scanner
        .scan(
            &[dir.path().to_path_buf()],
            &mut recorder,
            &CancelToken::new(),
        )
        .unwrap();
    assert_eq!(recorder.detections.len(), 5);
    assert_eq!(recorder.skipped, 0);
    recorder
        .detections
        .sort_by(|left, right| left.path.cmp(&right.path));
    assert_eq!(recorder.detections, report.detections);
}

#[test]
fn the_report_serialises_to_the_documented_json_shape() {
    let dir = tempfile::tempdir().unwrap();
    let threat = fixture(61, 16);
    write(&dir.path().join("threat.bin"), &threat);
    let scanner = hash_scanner(
        &[(&threat, "Test.Json", Category::Malware)],
        ScanOptions {
            threads: 2,
            ..ScanOptions::default()
        },
    );
    let report = scan(&scanner, dir.path());
    let json = serde_json::to_value(&report).unwrap();

    assert_eq!(json["schema"], 4);
    assert_eq!(json["engine_version"], env!("CARGO_PKG_VERSION"));
    assert!(json["started_at"].as_str().unwrap().contains('T'));
    assert!(json["finished_at"].is_string());
    assert!(json["duration_ms"].is_u64());
    assert_eq!(json["cancelled"], false);
    assert_eq!(json["threads"], 2);
    assert!(json["roots"][0].is_string());

    let detector = &json["detectors"][0];
    assert_eq!(detector["id"], "hash");
    assert_eq!(detector["details"]["builtin_signatures"], 1);
    assert_eq!(detector["details"]["database_signatures"], 1);
    assert_eq!(
        detector["details"]["database_digest"]
            .as_str()
            .unwrap()
            .len(),
        64
    );

    assert_eq!(json["stats"]["files_scanned"], 1);
    assert_eq!(json["stats"]["bytes_scanned"], 16);
    assert_eq!(json["stats"]["files_skipped"], 0);
    assert_eq!(json["stats"]["folders_skipped"], 0);
    assert!(json["stats"]["skipped_by_reason"].is_object());
    assert!(json["stats"]["files_per_second"].is_f64());

    let detection = &json["detections"][0];
    assert!(detection["path"].as_str().unwrap().ends_with("threat.bin"));
    assert_eq!(detection["size"], 16);
    assert_eq!(detection["verdict"], "malicious");
    assert_eq!(detection["findings"][0]["detector"], "hash");
    assert_eq!(detection["findings"][0]["name"], "Test.Json");
    assert_eq!(detection["findings"][0]["category"], "malware");
    assert_eq!(detection["findings"][0]["confidence"], "definitive");
    assert!(detection["findings"][0]["reasons"][0].is_string());

    assert_eq!(json["stats"]["files_recorded"], 0);
    assert_eq!(json["recorded"], serde_json::json!([]));
    assert_eq!(json["recorded_truncated"], false);
    assert_eq!(json["skipped"], serde_json::json!([]));
    assert_eq!(json["skipped_truncated"], false);
    assert_eq!(json["partially_scanned"], serde_json::json!([]));
    assert_eq!(json["partially_scanned_truncated"], false);
    // A finding about the scanned file itself names no archive member, and
    // one that counts by itself does not say so.
    assert!(detection["findings"][0].get("member").is_none());
    assert!(detection["findings"][0].get("counts").is_none());
    assert!(detection.get("findings_omitted").is_none());
}

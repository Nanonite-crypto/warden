//! A rule match and a signature, end to end: the rule layer, the scan
//! engine and the signature check together.
//!
//! Nothing here is malware and nothing is really signed. The rules match
//! marker strings, the files are the smallest thing that passes for a
//! Windows executable, and what Windows would say about a signature is
//! said by a stand-in. What Windows really says is tested on Windows, see
//! `docs/TESTING.md`.
//!
//! One test needs a file that a built-in rule matches, and the only
//! built-in rule is the one for the EICAR antivirus test file. That test
//! writes the test file to disk, and only where it may be written: in the
//! folder that `WARDEN_EICAR_DIR` names, or, on systems other than
//! Windows, in a temporary folder.

#![allow(clippy::unwrap_used)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use warden_engine::{
    CancelToken, Confidence, HashDetector, NoObserver, ScanReport, Scanner, TrustAnswer, Verdict,
    eicar,
};
use warden_sigdb::{Category, SigDb, SigDbBuilder};
use warden_trust::stand_in::{Answers, signer, valid, verifier};
use warden_trust::{Revocation, TrustList};
use warden_yara::{BundleBuilder, YaraDetector};

const RULES: &str = r#"
rule Test_Published_Rule
{
    meta:
        description = "contains the marker"
        score = 90
    strings:
        $marker = "WARDEN-TRUST-MARKER"
    condition:
        $marker
}
"#;

const MARKER: &[u8] = b"WARDEN-TRUST-MARKER";

/// The smallest file that passes for a Windows executable without a
/// signature of its own, with the marker in its first header.
fn executable_with_marker() -> Vec<u8> {
    let mut file = warden_trust::sigarea::executable_with_table(&[]);
    file[2..2 + MARKER.len()].copy_from_slice(MARKER);
    file
}

fn detector() -> YaraDetector {
    let mut builder = BundleBuilder::new().created_unix_secs(1_800_000_000);
    builder.add_source("published.yar", RULES);
    YaraDetector::new(builder.build().unwrap().bundle)
}

/// A scanner with the rule layer and a signature check that asks
/// `answers` instead of Windows.
fn scanner(answers: Answers) -> (Scanner, &'static Answers) {
    let (verifier, answers) = verifier(TrustList::builtin().unwrap(), answers);
    let scanner = Scanner::builder()
        .detector(detector())
        .trust(verifier)
        .build();
    (scanner, answers)
}

fn scan(scanner: &Scanner, root: &Path) -> ScanReport {
    scanner
        .scan(&[root.to_path_buf()], &mut NoObserver, &CancelToken::new())
        .unwrap()
}

/// What a catalogue of Windows would say about a file of Microsoft's.
fn in_a_catalogue_of_microsofts() -> Answers {
    Answers {
        catalog: valid(signer(
            "Microsoft Corporation",
            "Microsoft Corporation",
            true,
        )),
        ..Answers::default()
    }
}

#[test]
fn a_rule_match_in_a_file_that_microsoft_signed_is_recorded_and_not_reported() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("tool.exe"), executable_with_marker()).unwrap();

    let (scanner, answers) = scanner(in_a_catalogue_of_microsofts());
    let report = scan(&scanner, dir.path());
    assert!(report.is_clean(), "{:?}", report.detections);
    assert_eq!(report.stats.trust_checks, 1);
    assert_eq!(report.stats.files_trusted, 1);
    assert_eq!(answers.catalog_asked.load(Ordering::Relaxed), 1);

    let recorded = &report.recorded[0];
    assert_eq!(
        recorded.trust,
        Some(TrustAnswer::Trusted {
            publisher: "Microsoft Corporation".to_owned(),
            route: "windows_catalog",
            detail: "signed for Microsoft Corporation, found in a catalogue of Windows".to_owned(),
        })
    );
    let finding = &recorded.findings[0];
    assert_eq!(finding.name, "Test_Published_Rule");
    assert_eq!(finding.confidence, Confidence::Low);
    assert_eq!(
        finding.reasons.last().map(String::as_str),
        Some(
            "The file has a valid signature of a publisher on the trust list, so this is \
             recorded and does not change the verdict: signed for Microsoft Corporation, found \
             in a catalogue of Windows"
        )
    );
}

#[test]
fn any_valid_signature_is_not_enough() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("tool.exe"), executable_with_marker()).unwrap();

    // Signed, validly, by somebody who is not on the list. And the same
    // names as Microsoft's under a root that is not Microsoft's.
    for (signed_by, said) in [
        (
            signer("Somebody Else", "Somebody Else", false),
            "that publisher is not on the trust list",
        ),
        (
            signer("Microsoft Corporation", "Microsoft Corporation", false),
            "only with a chain that ends in one of Microsoft's own root certificates, \
             which this signature does not have",
        ),
    ] {
        let (scanner, _) = scanner(Answers {
            catalog: valid(signed_by),
            ..Answers::default()
        });
        let report = scan(&scanner, dir.path());
        assert_eq!(report.stats.detections, 1);
        assert_eq!(report.stats.trust_checks, 1);
        assert_eq!(report.stats.files_trusted, 0);
        let detection = &report.detections[0];
        assert_eq!(detection.verdict, Verdict::Malicious);
        let last = detection.findings[0].reasons.last().unwrap();
        assert!(
            last.starts_with("No signature of a publisher on the trust list speaks for the file")
                && last.ends_with(said),
            "{last}"
        );
        assert!(matches!(
            detection.trust,
            Some(TrustAnswer::NotTrusted {
                reason: "not_listed",
                ..
            })
        ));
    }
}

#[test]
fn a_signature_whose_revocation_could_not_be_checked_is_not_enough() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("tool.exe"), executable_with_marker()).unwrap();

    let mut unchecked = signer("Microsoft Corporation", "Microsoft Corporation", true);
    unchecked.revocation = Revocation::Unknown;
    let (scanner, _) = scanner(Answers {
        catalog: valid(unchecked),
        ..Answers::default()
    });
    let report = scan(&scanner, dir.path());
    assert_eq!(report.stats.detections, 1);
    assert!(matches!(
        report.detections[0].trust,
        Some(TrustAnswer::NotTrusted {
            reason: "revocation_unknown",
            ..
        })
    ));
}

#[test]
fn a_hash_match_is_reported_whoever_signed_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let content = executable_with_marker();
    fs::write(dir.path().join("tool.exe"), &content).unwrap();

    let mut database = SigDbBuilder::new().with_created_unix_secs(1_800_000_000);
    database
        .add(
            warden_engine::sha256(&content),
            "Test.Known",
            Category::Malware,
        )
        .unwrap();
    let database = SigDb::from_bytes(database.build().unwrap().0).unwrap();

    let (verifier, _) = verifier(
        TrustList::builtin().unwrap(),
        in_a_catalogue_of_microsofts(),
    );
    let scanner = Scanner::builder()
        .detector(HashDetector::with_database(Arc::new(database)))
        .detector(detector())
        .trust(verifier)
        .build();
    let report = scan(&scanner, dir.path());

    assert_eq!(report.stats.detections, 1);
    assert_eq!(report.stats.files_trusted, 1);
    let detection = &report.detections[0];
    assert_eq!(detection.verdict, Verdict::Malicious);
    assert_eq!(detection.findings[0].name, "Test.Known");
    assert_eq!(detection.findings[0].confidence, Confidence::Definitive);
    assert!(!detection.findings[0].yields_to_trust);
    assert_eq!(detection.findings[1].name, "Test_Published_Rule");
    assert_eq!(detection.findings[1].confidence, Confidence::Low);
}

/// The match of a built-in rule does not yield to a signature, so nobody
/// is asked about one.
///
/// Only a file on disk can be asked about, and only the EICAR test file
/// matches a built-in rule. A resident antivirus removes that file or
/// blocks it, and raises an alert, so the test is as careful as the
/// engine's `eicar_is_detected_on_disk` about where it writes it:
///
/// - `WARDEN_EICAR_DIR` names a folder that is excluded from the resident
///   antivirus. The test then works inside it.
/// - Without that variable the test uses the system temporary folder, except
///   on Windows, where it does not run at all.
/// - `WARDEN_REQUIRE_EICAR=1` turns "did not run" or "was blocked" into a
///   failure. CI sets it, together with a folder of its own.
#[test]
fn the_match_of_a_built_in_rule_is_reported_and_nobody_is_asked() {
    let strict = std::env::var_os("WARDEN_REQUIRE_EICAR").is_some_and(|value| value == "1");
    let not_exercised = |why: &str| {
        let note =
            format!("a built-in rule's match on disk not exercised: {why}. See docs/TESTING.md.");
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
        Some(base) => base.join(format!("rule-and-signature-{}", std::process::id())),
        None => temp.path().to_path_buf(),
    };
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join(eicar::FILE_NAME);

    // The test file with something after it, so that it is the rule and
    // not the hash that finds it.
    let mut variant = eicar::test_file();
    variant.extend_from_slice(b"\r\n");
    if let Err(error) = fs::write(&path, variant) {
        not_exercised(&format!("the test file could not be written ({error})"));
        return;
    }
    let (scanner, answers) = scanner(in_a_catalogue_of_microsofts());
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
    assert_eq!(report.stats.trust_checks, 0);
    assert!(!report.detections[0].findings[0].yields_to_trust);
    assert_eq!(answers.catalog_asked.load(Ordering::Relaxed), 0);
    assert_eq!(answers.embedded_asked.load(Ordering::Relaxed), 0);
}

#[test]
fn a_file_that_is_no_executable_is_vouched_for_by_no_catalogue() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("notes.txt"), MARKER).unwrap();

    // The stand-in would say yes to anything it is asked. It is not asked:
    // a signature is looked for in executables only.
    let (scanner, answers) = scanner(Answers {
        embedded: valid(signer(
            "Microsoft Corporation",
            "Microsoft Corporation",
            true,
        )),
        ..in_a_catalogue_of_microsofts()
    });
    let report = scan(&scanner, dir.path());
    assert_eq!(report.stats.detections, 1);
    assert_eq!(report.stats.trust_checks, 1);
    assert_eq!(report.stats.files_trusted, 0);
    assert_eq!(answers.catalog_asked.load(Ordering::Relaxed), 0);
    assert_eq!(answers.embedded_asked.load(Ordering::Relaxed), 0);
    assert!(matches!(
        report.detections[0].trust,
        Some(TrustAnswer::NotTrusted {
            reason: "no_signature",
            ..
        })
    ));
}

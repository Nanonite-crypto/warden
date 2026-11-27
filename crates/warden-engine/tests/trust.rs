//! Findings that yield to a trusted signature, and the check the engine
//! asks about one.
//!
//! The detectors and the check here are stand-ins. The detectors react to
//! marker strings, and the check goes by the file's name, so nothing in
//! this file is, or looks like, malware, and nothing is really signed.

#![allow(clippy::unwrap_used)]

use std::fs;
use std::io::{Cursor, Write};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use warden_engine::{
    CancelToken, Confidence, Detector, DetectorError, FileView, Finding, NoObserver, ScanReport,
    Scanner, Session, Sha256, ThreatCategory, TrustAnswer, TrustCheck, TrustCheckInfo, Verdict,
};
use zip::write::SimpleFileOptions;

const PUBLISHED: &[u8] = b"WARDEN-TEST-MATCHES-A-PUBLISHED-RULE";
const WEAK: &[u8] = b"WARDEN-TEST-MATCHES-A-WEAK-PUBLISHED-RULE";
const EXACT: &[u8] = b"WARDEN-TEST-IS-A-KNOWN-FILE";

fn contains(file: &FileView<'_>, marker: &[u8]) -> bool {
    file.content()
        .is_some_and(|content| content.windows(marker.len()).any(|window| window == marker))
}

/// Stands in for the rules of a bundle: its findings yield.
struct Published;

impl Detector for Published {
    fn id(&self) -> &'static str {
        "published"
    }

    fn needs_content(&self) -> bool {
        true
    }

    fn session(&self) -> Box<dyn Session + '_> {
        Box::new(self)
    }
}

impl Session for &Published {
    fn inspect(&mut self, file: &FileView<'_>) -> Result<Vec<Finding>, DetectorError> {
        let mut findings = Vec::new();
        for (marker, name, confidence) in [
            (PUBLISHED, "Test.Published", Confidence::High),
            (WEAK, "Test.Weak", Confidence::Low),
        ] {
            if contains(file, marker) {
                findings.push(
                    Finding::new(
                        "published",
                        name,
                        ThreatCategory::Malware,
                        confidence,
                        vec!["contains a marker".to_owned()],
                    )
                    .yielding_to_trust(),
                );
            }
        }
        Ok(findings)
    }
}

/// Stands in for a hash match: its finding does not yield.
struct Exact;

impl Detector for Exact {
    fn id(&self) -> &'static str {
        "exact"
    }

    fn needs_content(&self) -> bool {
        true
    }

    fn session(&self) -> Box<dyn Session + '_> {
        Box::new(self)
    }
}

impl Session for &Exact {
    fn inspect(&mut self, file: &FileView<'_>) -> Result<Vec<Finding>, DetectorError> {
        if !contains(file, EXACT) {
            return Ok(Vec::new());
        }
        Ok(vec![Finding::new(
            "exact",
            "Test.Exact",
            ThreatCategory::Malware,
            Confidence::Definitive,
            vec!["is the known file".to_owned()],
        )])
    }
}

/// A check that trusts every file whose name starts with `signed-`, and
/// counts how often it was asked.
struct ByName {
    available: bool,
    asked: Arc<AtomicUsize>,
}

impl TrustCheck for ByName {
    fn describe(&self) -> TrustCheckInfo {
        TrustCheckInfo {
            available: self.available,
            trust_list: "00".repeat(32),
            publishers: 1,
        }
    }

    fn check(&self, path: &Path, sha256: &Sha256) -> TrustAnswer {
        self.asked.fetch_add(1, Ordering::SeqCst);
        // The engine has to hand over the digest of what it scanned.
        let on_disk = warden_engine::sha256(&fs::read(path).unwrap());
        assert_eq!(*sha256, on_disk, "{}", path.display());
        let name = path.file_name().unwrap().to_string_lossy();
        if name.starts_with("signed-") {
            TrustAnswer::Trusted {
                publisher: "Example".to_owned(),
                route: "embedded",
                detail: "signed for Example, found in the file itself".to_owned(),
            }
        } else {
            TrustAnswer::NotTrusted {
                reason: "no_signature",
                detail: "no signature was found".to_owned(),
            }
        }
    }
}

struct Setup {
    scanner: Scanner,
    asked: Arc<AtomicUsize>,
}

impl Setup {
    fn asked(&self) -> usize {
        self.asked.load(Ordering::SeqCst)
    }

    fn scan(&self, root: &Path) -> ScanReport {
        self.scanner
            .scan(&[root.to_path_buf()], &mut NoObserver, &CancelToken::new())
            .unwrap()
    }
}

fn setup(available: bool) -> Setup {
    let asked = Arc::new(AtomicUsize::new(0));
    let scanner = Scanner::builder()
        .detector(Published)
        .detector(Exact)
        .trust(ByName {
            available,
            asked: Arc::clone(&asked),
        })
        .build();
    Setup { scanner, asked }
}

fn zip_of(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (name, bytes) in members {
        writer
            .start_file(*name, SimpleFileOptions::default())
            .unwrap();
        writer.write_all(bytes).unwrap();
    }
    writer.finish().unwrap().into_inner()
}

#[test]
fn a_file_without_findings_is_never_asked_about() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("signed-notes.txt"), "nothing to see here").unwrap();
    fs::write(dir.path().join("signed-weak.bin"), WEAK).unwrap();
    fs::write(dir.path().join("known.bin"), EXACT).unwrap();

    let setup = setup(true);
    let report = setup.scan(dir.path());
    assert_eq!(report.stats.files_scanned, 3);
    assert_eq!(
        setup.asked(),
        0,
        "no finding, a finding that is only on record, and one that does not yield"
    );
    assert_eq!(report.stats.trust_checks, 0);
    assert_eq!(report.stats.detections, 1);
    assert!(report.detections[0].trust.is_none());
}

#[test]
fn a_published_rule_match_in_a_file_of_a_trusted_publisher_is_recorded_not_reported() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("signed-tool.bin"), PUBLISHED).unwrap();

    let setup = setup(true);
    let report = setup.scan(dir.path());
    assert_eq!(setup.asked(), 1);
    assert!(report.is_clean(), "{:?}", report.detections);
    assert_eq!(report.stats.files_recorded, 1);
    assert_eq!(report.stats.trust_checks, 1);
    assert_eq!(report.stats.files_trusted, 1);

    let recorded = &report.recorded[0];
    assert!(recorded.trust.as_ref().is_some_and(TrustAnswer::is_trusted));
    let finding = &recorded.findings[0];
    assert_eq!(finding.name, "Test.Published");
    assert_eq!(finding.confidence, Confidence::Low);
    assert!(finding.yields_to_trust);
    let last = finding.reasons.last().unwrap();
    assert!(
        last.ends_with("does not change the verdict: signed for Example, found in the file itself"),
        "{last}"
    );
}

#[test]
fn the_same_match_in_a_file_nobody_vouches_for_is_reported_and_says_so() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("tool.bin"), PUBLISHED).unwrap();

    let setup = setup(true);
    let report = setup.scan(dir.path());
    assert_eq!(setup.asked(), 1);
    assert_eq!(report.stats.detections, 1);
    assert_eq!(report.stats.trust_checks, 1);
    assert_eq!(report.stats.files_trusted, 0);

    let detection = &report.detections[0];
    assert_eq!(detection.verdict, Verdict::Malicious);
    assert_eq!(
        detection.trust,
        Some(TrustAnswer::NotTrusted {
            reason: "no_signature",
            detail: "no signature was found".to_owned(),
        })
    );
    assert_eq!(
        detection.findings[0].reasons.last().map(String::as_str),
        Some(
            "No signature of a publisher on the trust list speaks for the file: no signature \
             was found"
        )
    );
}

#[test]
fn a_finding_that_does_not_yield_is_reported_whoever_signed_the_file() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("signed-both.bin"),
        [PUBLISHED, b" and ", EXACT].concat(),
    )
    .unwrap();

    let setup = setup(true);
    let report = setup.scan(dir.path());
    assert_eq!(setup.asked(), 1);
    assert_eq!(report.stats.detections, 1);
    assert_eq!(report.stats.files_trusted, 1);

    let detection = &report.detections[0];
    assert_eq!(detection.verdict, Verdict::Malicious);
    assert!(
        detection
            .trust
            .as_ref()
            .is_some_and(TrustAnswer::is_trusted)
    );
    assert_eq!(detection.findings[0].name, "Test.Published");
    assert_eq!(detection.findings[0].confidence, Confidence::Low);
    assert_eq!(detection.findings[1].name, "Test.Exact");
    assert_eq!(detection.findings[1].confidence, Confidence::Definitive);
    assert_eq!(detection.findings[1].reasons.len(), 1);
}

#[test]
fn a_file_inside_an_archive_is_never_asked_about_and_its_finding_counts() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("signed-archive.zip"),
        zip_of(&[("tool.bin", PUBLISHED)]),
    )
    .unwrap();

    let setup = setup(true);
    let report = setup.scan(dir.path());
    assert_eq!(report.stats.archive_members_scanned, 1);
    assert_eq!(setup.asked(), 0);
    assert_eq!(report.stats.detections, 1);
    let detection = &report.detections[0];
    assert!(detection.trust.is_none());
    let finding = &detection.findings[0];
    assert_eq!(finding.member.as_ref().unwrap().path, ["tool.bin"]);
    assert_eq!(finding.confidence, Confidence::High);
    assert_eq!(finding.reasons.len(), 1);
}

#[test]
fn the_archive_itself_can_be_asked_about_and_that_says_nothing_about_what_is_in_it() {
    // The marker is stored, not packed, so the rule matches the archive's
    // own bytes as well as the member.
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let stored = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    writer.start_file("tool.bin", stored).unwrap();
    writer.write_all(PUBLISHED).unwrap();
    let archive = writer.finish().unwrap().into_inner();

    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("signed-archive.zip"), archive).unwrap();

    let setup = setup(true);
    let report = setup.scan(dir.path());
    assert_eq!(setup.asked(), 1);
    assert_eq!(report.stats.detections, 1);
    let detection = &report.detections[0];
    assert!(
        detection
            .trust
            .as_ref()
            .is_some_and(TrustAnswer::is_trusted)
    );
    assert_eq!(detection.findings.len(), 2);
    assert!(detection.findings[0].member.is_none());
    assert_eq!(detection.findings[0].confidence, Confidence::Low);
    assert!(detection.findings[1].member.is_some());
    assert_eq!(detection.findings[1].confidence, Confidence::High);
}

#[test]
fn bytes_in_memory_have_no_file_to_ask_about() {
    let setup = setup(true);
    let result = setup.scanner.scan_bytes(PUBLISHED);
    assert_eq!(setup.asked(), 0);
    assert_eq!(result.verdict, Verdict::Malicious);
    assert!(result.trust.is_none());
    assert_eq!(result.findings[0].reasons.len(), 1);
}

#[test]
fn a_check_that_cannot_work_here_is_described_and_never_asked() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("signed-tool.bin"), PUBLISHED).unwrap();

    let setup = setup(false);
    let report = setup.scan(dir.path());
    assert_eq!(setup.asked(), 0);
    assert_eq!(report.stats.detections, 1);
    assert_eq!(report.stats.trust_checks, 0);
    assert_eq!(report.detections[0].findings[0].reasons.len(), 1);
    let info = report.trust_check.as_ref().unwrap();
    assert!(!info.available);
}

#[test]
fn without_a_check_nothing_yields() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("signed-tool.bin"), PUBLISHED).unwrap();

    let scanner = Scanner::builder().detector(Published).build();
    let report = scanner
        .scan(
            &[dir.path().to_path_buf()],
            &mut NoObserver,
            &CancelToken::new(),
        )
        .unwrap();
    assert_eq!(report.stats.detections, 1);
    assert!(report.trust_check.is_none());
}

#[test]
fn the_report_says_what_was_asked_and_what_was_found() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("signed-tool.bin"), PUBLISHED).unwrap();
    fs::write(dir.path().join("tool.bin"), PUBLISHED).unwrap();
    fs::write(dir.path().join("known.bin"), EXACT).unwrap();

    let report = setup(true).scan(dir.path());
    let json: serde_json::Value =
        serde_json::from_str(&serde_json::to_string(&report).unwrap()).unwrap();

    assert_eq!(json["schema"], 5);
    assert_eq!(json["trust_check"]["available"], true);
    assert_eq!(json["trust_check"]["publishers"], 1);
    assert_eq!(json["trust_check"]["trust_list"], "00".repeat(32));
    assert_eq!(json["stats"]["trust_checks"], 2);
    assert_eq!(json["stats"]["files_trusted"], 1);

    let recorded = &json["recorded"][0];
    assert_eq!(recorded["trust"]["answer"], "trusted");
    assert_eq!(recorded["trust"]["publisher"], "Example");
    assert_eq!(recorded["trust"]["route"], "embedded");
    assert_eq!(recorded["findings"][0]["yields_to_trust"], true);
    assert_eq!(recorded["findings"][0]["confidence"], "low");

    let detections = json["detections"].as_array().unwrap();
    assert_eq!(detections.len(), 2);
    // Sorted by path: known.bin, then tool.bin.
    assert!(
        detections[0].get("trust").is_none(),
        "nobody was asked about a file whose finding does not yield"
    );
    assert!(
        detections[0]["findings"][0]
            .get("yields_to_trust")
            .is_none()
    );
    assert_eq!(detections[1]["trust"]["answer"], "not_trusted");
    assert_eq!(detections[1]["trust"]["reason"], "no_signature");
}

//! Findings that count only together: a finding of one layer that waits for
//! a second sign, and the sign another layer offers.
//!
//! The two detectors here are stand-ins for the real pair, a generated YARA
//! rule and the structure of an executable. They react to marker strings, so
//! nothing in this file is, or looks like, malware.

#![allow(clippy::unwrap_used)]

use std::fs;
use std::io::{Cursor, Write};
use std::path::Path;

use warden_engine::{
    CancelToken, Confidence, Counts, Detector, DetectorError, FileView, Finding, NoObserver,
    Recorded, ScanObserver, ScanOptions, ScanReport, Scanner, Session, ThreatCategory, Verdict,
};
use zip::write::SimpleFileOptions;

const WAITS: &[u8] = b"WARDEN-TEST-WAITS-FOR-A-SECOND-SIGN";
const OFFERS: &[u8] = b"WARDEN-TEST-OFFERS-A-SECOND-SIGN";

fn contains(file: &FileView<'_>, marker: &[u8]) -> bool {
    file.content()
        .is_some_and(|content| content.windows(marker.len()).any(|window| window == marker))
}

/// Reports a finding that counts only with a second sign.
struct Waiting;

impl Detector for Waiting {
    fn id(&self) -> &'static str {
        "waiting"
    }

    fn needs_content(&self) -> bool {
        true
    }

    fn session(&self) -> Box<dyn Session + '_> {
        Box::new(self)
    }
}

impl Session for &Waiting {
    fn inspect(&mut self, file: &FileView<'_>) -> Result<Vec<Finding>, DetectorError> {
        if !contains(file, WAITS) {
            return Ok(Vec::new());
        }
        Ok(vec![
            Finding::new(
                "waiting",
                "Test.Waiting",
                ThreatCategory::Malware,
                Confidence::Medium,
                vec!["contains the first marker".to_owned()],
            )
            .with_second_sign(),
        ])
    }
}

/// Offers a second sign.
struct Offering;

impl Detector for Offering {
    fn id(&self) -> &'static str {
        "offering"
    }

    fn needs_content(&self) -> bool {
        true
    }

    fn session(&self) -> Box<dyn Session + '_> {
        Box::new(self)
    }
}

impl Session for &Offering {
    fn inspect(&mut self, file: &FileView<'_>) -> Result<Vec<Finding>, DetectorError> {
        if !contains(file, OFFERS) {
            return Ok(Vec::new());
        }
        Ok(vec![
            Finding::new(
                "offering",
                "Test.Offering",
                ThreatCategory::Malware,
                Confidence::Low,
                vec!["contains the second marker".to_owned()],
            )
            .as_second_sign(),
        ])
    }
}

fn scanner() -> Scanner {
    scanner_with(ScanOptions::default())
}

fn scanner_with(options: ScanOptions) -> Scanner {
    Scanner::builder()
        .detector(Waiting)
        .detector(Offering)
        .options(options)
        .build()
}

fn scan(scanner: &Scanner, root: &Path) -> ScanReport {
    scanner
        .scan(&[root.to_path_buf()], &mut NoObserver, &CancelToken::new())
        .unwrap()
}

fn both() -> Vec<u8> {
    [b"one ", WAITS, b" two ", OFFERS].concat()
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
fn a_waiting_finding_alone_leaves_the_verdict_clean_and_stays_on_record() {
    let result = scanner().scan_bytes(WAITS);
    assert_eq!(result.verdict, Verdict::Clean);
    assert_eq!(result.findings.len(), 1);
    let finding = &result.findings[0];
    assert_eq!(finding.name, "Test.Waiting");
    assert_eq!(finding.counts, Counts::WithSecondSign);
    assert_eq!(finding.confidence, Confidence::Low);
}

#[test]
fn a_second_sign_about_the_same_file_makes_it_suspicious() {
    let result = scanner().scan_bytes(&both());
    assert_eq!(result.verdict, Verdict::Suspicious);
    let names: Vec<&str> = result
        .findings
        .iter()
        .map(|finding| finding.name.as_str())
        .collect();
    assert_eq!(names, ["Test.Waiting", "Test.Offering"]);
    assert_eq!(result.findings[0].confidence, Confidence::Medium);
    assert_eq!(result.findings[1].counts, Counts::AsSecondSign);
}

#[test]
fn a_second_sign_alone_leaves_no_trace() {
    let result = scanner().scan_bytes(OFFERS);
    assert_eq!(result.verdict, Verdict::Clean);
    assert!(result.findings.is_empty());
}

#[test]
fn a_sign_in_one_archive_member_says_nothing_about_another() {
    let archive = zip_of(&[("first.bin", WAITS), ("second.bin", OFFERS)]);
    let result = scanner().scan_bytes(&archive);
    assert_eq!(result.members_scanned, 2);
    assert_eq!(result.verdict, Verdict::Clean);
    assert_eq!(result.findings.len(), 1, "{:?}", result.findings);
    let finding = &result.findings[0];
    assert_eq!(finding.name, "Test.Waiting");
    assert_eq!(finding.confidence, Confidence::Low);
    assert_eq!(finding.member.as_ref().unwrap().path, ["first.bin"]);
}

#[test]
fn two_signs_about_the_same_archive_member_count() {
    let content = both();
    let archive = zip_of(&[("plain.txt", b"nothing here"), ("both.bin", &content)]);
    let result = scanner().scan_bytes(&archive);
    assert_eq!(result.verdict, Verdict::Suspicious);
    assert_eq!(result.findings.len(), 2);
    for finding in &result.findings {
        assert_eq!(finding.member.as_ref().unwrap().path, ["both.bin"]);
    }
}

#[test]
fn an_archive_is_not_its_members() {
    // The archive as a file holds both markers, because it stores them
    // without compression. That makes the archive itself suspicious, which
    // is right: both signs are about the same bytes. Each member, taken
    // alone, has one sign and stays as it was.
    let stored = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    writer.start_file("first.bin", stored).unwrap();
    writer.write_all(WAITS).unwrap();
    writer.start_file("second.bin", stored).unwrap();
    writer.write_all(OFFERS).unwrap();
    let archive = writer.finish().unwrap().into_inner();

    let result = scanner().scan_bytes(&archive);
    assert_eq!(result.verdict, Verdict::Suspicious);
    let about_the_archive: Vec<&Finding> = result
        .findings
        .iter()
        .filter(|finding| finding.member.is_none())
        .collect();
    assert_eq!(about_the_archive.len(), 2);
    let about_members: Vec<&Finding> = result
        .findings
        .iter()
        .filter(|finding| finding.member.is_some())
        .collect();
    assert_eq!(about_members.len(), 1, "{about_members:?}");
    assert_eq!(about_members[0].confidence, Confidence::Low);
}

#[derive(Default)]
struct Seen {
    detections: Vec<String>,
    recorded: Vec<String>,
}

impl ScanObserver for Seen {
    fn on_detection(&mut self, detection: &warden_engine::Detection) {
        self.detections.push(name_of(&detection.path));
    }

    fn on_recorded(&mut self, recorded: &Recorded) {
        self.recorded.push(name_of(&recorded.path));
    }
}

fn name_of(path: &Path) -> String {
    path.file_name().unwrap().to_string_lossy().into_owned()
}

#[test]
fn a_report_lists_what_was_recorded_apart_from_what_was_flagged() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("b-waits.bin"), WAITS).unwrap();
    fs::write(dir.path().join("a-waits.bin"), [b"x ", WAITS].concat()).unwrap();
    fs::write(dir.path().join("offers.bin"), OFFERS).unwrap();
    fs::write(dir.path().join("both.bin"), both()).unwrap();
    fs::write(dir.path().join("plain.txt"), "nothing here").unwrap();

    let scanner = scanner();
    let mut seen = Seen::default();
    let report = scanner
        .scan(&[dir.path().to_path_buf()], &mut seen, &CancelToken::new())
        .unwrap();

    assert_eq!(report.stats.files_scanned, 5);
    assert_eq!(report.stats.detections, 1);
    assert_eq!(report.stats.files_recorded, 2);
    assert!(!report.is_clean());

    let flagged: Vec<String> = report.detections.iter().map(|d| name_of(&d.path)).collect();
    assert_eq!(flagged, ["both.bin"]);
    let recorded: Vec<String> = report.recorded.iter().map(|r| name_of(&r.path)).collect();
    assert_eq!(recorded, ["a-waits.bin", "b-waits.bin"], "sorted by path");
    assert!(!report.recorded_truncated);
    for entry in &report.recorded {
        assert_eq!(entry.findings.len(), 1);
        assert_eq!(entry.findings[0].confidence, Confidence::Low);
        assert_eq!(entry.sha256.len(), 64);
    }

    assert_eq!(seen.detections, ["both.bin"]);
    seen.recorded.sort();
    assert_eq!(seen.recorded, ["a-waits.bin", "b-waits.bin"]);
}

#[test]
fn the_list_of_recorded_files_is_bounded_and_the_count_is_not() {
    let dir = tempfile::tempdir().unwrap();
    for index in 0..5 {
        let content = [format!("file {index} ").as_bytes(), WAITS].concat();
        fs::write(dir.path().join(format!("waits-{index}.bin")), content).unwrap();
    }
    let scanner = scanner_with(ScanOptions {
        max_recorded_skips: 2,
        ..ScanOptions::default()
    });
    let report = scan(&scanner, dir.path());
    assert_eq!(report.stats.files_recorded, 5);
    assert_eq!(report.recorded.len(), 2);
    assert!(report.recorded_truncated);
    assert!(report.is_clean());
}

#[test]
fn a_report_shows_when_a_finding_counts_and_leaves_the_usual_case_out() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("both.bin"), both()).unwrap();
    fs::write(dir.path().join("waits.bin"), WAITS).unwrap();
    let report = scan(&scanner(), dir.path());

    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["schema"], 5);
    assert_eq!(json["stats"]["files_recorded"], 1);
    let flagged = &json["detections"][0]["findings"];
    assert_eq!(flagged[0]["counts"], "with_second_sign");
    assert_eq!(flagged[0]["confidence"], "medium");
    assert_eq!(flagged[1]["counts"], "as_second_sign");
    assert_eq!(flagged[1]["confidence"], "low");
    let recorded = &json["recorded"][0];
    assert!(recorded["path"].as_str().unwrap().ends_with("waits.bin"));
    assert_eq!(recorded["findings"][0]["counts"], "with_second_sign");
    assert_eq!(recorded["findings"][0]["confidence"], "low");
    assert!(recorded.get("verdict").is_none());
}

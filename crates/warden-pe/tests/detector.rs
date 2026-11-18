//! The heuristic layer as the scan pipeline sees it: a detector that is
//! handed a file and answers with a finding, or with nothing.

#![allow(clippy::unwrap_used)]

use warden_engine::{Confidence, Detector, FileView, Finding, ThreatCategory, sha256};
use warden_pe::fixture::Fixture;
use warden_pe::{FINDING_NAME, PeDetector, SUSPICIOUS_FROM};

fn findings(detector: &PeDetector, content: &[u8]) -> Vec<Finding> {
    let digest = sha256(content);
    let view = FileView::in_memory(content, &digest);
    detector.session().inspect(&view).unwrap()
}

#[test]
fn a_suspicious_structure_is_one_finding_that_lists_its_reasons() {
    let file = Fixture::suspicious_looking().build();
    let found = findings(&PeDetector::new(), &file);
    assert_eq!(found.len(), 1);
    let finding = &found[0];
    assert_eq!(finding.detector, "heuristic");
    assert_eq!(finding.name, FINDING_NAME);
    assert_eq!(finding.category, ThreatCategory::Malware);
    // Shown to the user as suspicious, and never more than that.
    assert_eq!(finding.confidence, Confidence::Medium);
    assert_eq!(finding.member, None);

    assert!(
        finding.reasons[0].starts_with("The structure of the file scores ")
            && finding.reasons[0].ends_with(&format!(
                "a file counts as suspicious from {SUSPICIOUS_FROM}"
            )),
        "{:?}",
        finding.reasons
    );
    // One reason per scored indicator, each with its weight; the weights
    // add up to the score in the first line.
    let weights: Vec<u32> = finding.reasons[1..]
        .iter()
        .map(|reason| {
            let weight = reason.strip_prefix('+').unwrap().split(' ').next().unwrap();
            weight.parse().unwrap()
        })
        .collect();
    assert!(weights.len() >= 4, "{:?}", finding.reasons);
    let score: u32 = weights.iter().sum();
    assert!(finding.reasons[0].contains(&format!("scores {score};")));
    assert!(
        finding.reasons.iter().any(|reason| reason
            .contains("A section is both writable and executable: sections \"UPX0\", \"UPX1\"")),
        "{:?}",
        finding.reasons
    );
}

#[test]
fn files_below_the_threshold_and_files_that_are_not_executables_are_left_alone() {
    let detector = PeDetector::new();
    assert!(findings(&detector, &Fixture::plain().build()).is_empty());
    // Packed, and nothing else: common in clean software.
    assert!(findings(&detector, &Fixture::packed_looking().build()).is_empty());
    assert!(findings(&detector, b"MZ, and then a text file that goes on").is_empty());
    assert!(findings(&detector, b"").is_empty());
    // A file whose header is cut off in the middle.
    let whole = Fixture::suspicious_looking().build();
    assert!(findings(&detector, &whole[..0x90]).is_empty());
}

#[test]
fn the_threshold_can_be_set() {
    let packed = Fixture::packed_looking().build();
    let plain = Fixture::plain().build();
    let strict = PeDetector::with_threshold(1);
    assert_eq!(findings(&strict, &packed).len(), 1);
    assert_eq!(findings(&strict, &plain).len(), 1);
    let never = PeDetector::with_threshold(u32::MAX);
    assert!(findings(&never, &Fixture::suspicious_looking().build()).is_empty());
}

#[test]
fn the_detector_says_what_it_runs_with() {
    let detector = PeDetector::new();
    assert_eq!(detector.id(), "heuristic");
    assert!(detector.needs_content());
    let info = serde_json::to_value(detector.describe()).unwrap();
    assert_eq!(info["id"], "heuristic");
    assert_eq!(info["details"]["suspicious_from"], SUSPICIOUS_FROM);
    let scored = info["details"]["indicators_scored"].as_u64().unwrap();
    let all = info["details"]["indicators"].as_u64().unwrap();
    assert!(scored > 0 && scored < all, "{info}");
}

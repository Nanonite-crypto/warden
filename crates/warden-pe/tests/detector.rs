//! The heuristic layer as the scan pipeline sees it: a detector that is
//! handed a file and answers with a finding, with a second sign for another
//! layer's finding, or with nothing.

#![allow(clippy::unwrap_used)]

use warden_engine::{
    Confidence, Counts, Detector, FileView, Finding, Scanner, ThreatCategory, Verdict, sha256,
};
use warden_pe::fixture::Fixture;
use warden_pe::{
    FINDING_NAME, PeDetector, SECOND_SIGN_FROM, SECOND_SIGN_NAME, SUSPICIOUS_FROM, Thresholds,
};

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
    assert_eq!(finding.counts, Counts::Alone);
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
fn plain_files_and_files_that_are_not_executables_are_left_alone() {
    let detector = PeDetector::new();
    assert!(findings(&detector, &Fixture::plain().build()).is_empty());
    assert!(findings(&detector, b"MZ, and then a text file that goes on").is_empty());
    assert!(findings(&detector, b"").is_empty());
    // A file whose header is cut off in the middle.
    let whole = Fixture::suspicious_looking().build();
    assert!(findings(&detector, &whole[..0x90]).is_empty());
}

#[test]
fn a_score_between_the_bar_and_the_threshold_is_offered_as_a_second_sign() {
    // Packed, and nothing else: common in clean software, so not a finding.
    let file = Fixture::packed_looking().build();
    let found = findings(&PeDetector::new(), &file);
    assert_eq!(found.len(), 1);
    let sign = &found[0];
    assert_eq!(sign.detector, "heuristic");
    assert_eq!(sign.name, SECOND_SIGN_NAME);
    assert_eq!(sign.counts, Counts::AsSecondSign);
    assert_eq!(sign.confidence, Confidence::Low);
    assert!(
        sign.reasons[0].contains(&format!("less than the {SUSPICIOUS_FROM} that make"))
            && sign.reasons[0].contains(&format!("at least the {SECOND_SIGN_FROM} from which")),
        "{:?}",
        sign.reasons
    );
    // It brings the same evidence a finding would: one line per indicator.
    assert!(sign.reasons.len() >= 4, "{:?}", sign.reasons);
    assert!(sign.reasons[1..].iter().all(|line| line.starts_with('+')));

    // In a scan with no other layer it is nobody's second sign: the file is
    // clean, and nothing about it is kept.
    let scanner = Scanner::builder().detector(PeDetector::new()).build();
    let result = scanner.scan_bytes(&file);
    assert_eq!(result.verdict, Verdict::Clean);
    assert!(result.findings.is_empty());
}

#[test]
fn both_scores_can_be_set() {
    let packed = Fixture::packed_looking().build();
    let plain = Fixture::plain().build();
    let suspicious = Fixture::suspicious_looking().build();

    let strict = PeDetector::with_thresholds(Thresholds {
        suspicious_from: 1,
        ..Thresholds::default()
    });
    for file in [&packed, &plain] {
        let found = findings(&strict, file);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, FINDING_NAME);
    }

    let never = PeDetector::with_thresholds(Thresholds {
        second_sign_from: u32::MAX,
        suspicious_from: u32::MAX,
    });
    assert!(findings(&never, &suspicious).is_empty());

    // With the bar at the bottom every executable is a second sign, and a
    // file that is not an executable still is not.
    let eager = PeDetector::with_thresholds(Thresholds {
        second_sign_from: 0,
        ..Thresholds::default()
    });
    assert_eq!(findings(&eager, &plain)[0].name, SECOND_SIGN_NAME);
    assert_eq!(findings(&eager, &suspicious)[0].name, FINDING_NAME);
    assert!(findings(&eager, b"not an executable").is_empty());
}

#[test]
fn the_detector_says_what_it_runs_with() {
    let detector = PeDetector::new();
    assert_eq!(detector.id(), "heuristic");
    assert!(detector.needs_content());
    let info = serde_json::to_value(detector.describe()).unwrap();
    assert_eq!(info["id"], "heuristic");
    assert_eq!(info["details"]["suspicious_from"], SUSPICIOUS_FROM);
    assert_eq!(info["details"]["second_sign_from"], SECOND_SIGN_FROM);
    let scored = info["details"]["indicators_scored"].as_u64().unwrap();
    let all = info["details"]["indicators"].as_u64().unwrap();
    assert!(scored > 0 && scored < all, "{info}");
}

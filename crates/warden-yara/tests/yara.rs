//! The YARA layer end to end: built-in rules, bundles, and how matches turn
//! into findings.
//!
//! Nothing here is malware. The rules match harmless marker strings that the
//! tests make up, and the EICAR antivirus test file, which only ever exists
//! in memory in this file.

#![allow(clippy::unwrap_used)]

use std::io::{Cursor, Write};
use std::path::Path;

use warden_engine::{
    Confidence, Counts, Detector, DetectorError, FileResult, FileView, Finding, HashDetector,
    Scanner, Session, ThreatCategory, Verdict, eicar,
};
use warden_yara::{
    BUILTIN_SOURCE, BundleBuilder, BundleError, ENGINE, RuleBundle, YaraDetector, YaraOptions,
    generator, write_bundle,
};

const MARKER_RULES: &str = r#"
rule Test_Marker_High
{
    meta:
        description = "contains the high marker"
        author = "the test suite"
        reference = "https://example.test/high"
        score = 90
    strings:
        $marker = "WARDEN-YARA-HIGH"
        $other = "never present"
    condition:
        any of them
}

rule Test_Marker_Medium
{
    meta:
        score = 65
    strings:
        $marker = "WARDEN-YARA-MEDIUM"
    condition:
        $marker
}

rule Test_Marker_Low
{
    meta:
        score = 30
    strings:
        $marker = "WARDEN-YARA-LOW"
    condition:
        $marker
}

rule Test_Marker_Unscored
{
    strings:
        $marker = "WARDEN-YARA-UNSCORED"
    condition:
        $marker
}

rule Test_Marker_Named
{
    meta:
        threat_name = "PUA.Test.Named"
        category = "potentially_unwanted"
        score = 85
    strings:
        $marker = "WARDEN-YARA-NAMED"
    condition:
        $marker
}
"#;

fn marker_bundle() -> warden_yara::Built {
    let mut builder = BundleBuilder::new().created_unix_secs(1_800_000_000);
    builder.add_source("markers.yar", MARKER_RULES);
    builder.build().unwrap()
}

fn marker_scanner() -> Scanner {
    Scanner::builder()
        .detector(YaraDetector::new(marker_bundle().bundle))
        .build()
}

fn builtin_scanner() -> Scanner {
    Scanner::builder()
        .detector(YaraDetector::builtin().unwrap())
        .build()
}

fn padded(padding: &[u8]) -> Vec<u8> {
    let mut bytes = eicar::test_file();
    bytes.extend_from_slice(padding);
    bytes
}

fn names(result: &FileResult) -> Vec<&str> {
    result
        .findings
        .iter()
        .map(|finding| finding.name.as_str())
        .collect()
}

#[test]
fn the_builtin_rules_compile_and_do_not_hold_the_whole_test_string() {
    let detector = YaraDetector::builtin().unwrap();
    assert_eq!(detector.bundle().rule_count(), 1);
    assert_eq!(detector.bundle().manifest().sources[0].name, BUILTIN_SOURCE);
    assert_eq!(detector.bundle().manifest().engine, ENGINE);

    // If the rule file held the complete test string, other antivirus
    // products would report the file, and every program it is built into.
    let source = include_str!("../rules/builtin.yar");
    let test_string = String::from_utf8(eicar::test_file()).unwrap();
    assert!(!source.contains(&test_string));
    assert!(!source.replace("\\\\", "\\").contains(&test_string));
}

#[test]
fn the_test_file_and_its_padded_forms_are_detected() {
    let scanner = builtin_scanner();
    let sixty_spaces = [b' '; 60];
    let paddings: [&[u8]; 6] = [b"", b"\n", b"\r\n", b" \t \x1a", b"\r\n\r\n", &sixty_spaces];
    for padding in paddings {
        let result = scanner.scan_bytes(&padded(padding));
        assert_eq!(result.verdict, Verdict::Malicious, "padding {padding:?}");
        assert_eq!(names(&result), [eicar::DETECTION_NAME]);
        let finding = &result.findings[0];
        assert_eq!(finding.detector, "yara");
        assert_eq!(finding.category, ThreatCategory::TestFile);
        assert_eq!(finding.confidence, Confidence::High);
    }
}

#[test]
fn files_that_only_resemble_the_test_file_are_not_detected() {
    let scanner = builtin_scanner();
    let exact = eicar::test_file();
    let mut shifted = vec![b' '];
    shifted.extend_from_slice(&exact);
    let sixty_one_spaces = [b' '; 61];

    let near_misses: [(&str, Vec<u8>); 6] = [
        ("followed by text", padded(b"x")),
        ("followed by a line break and text", padded(b"\nmore")),
        ("longer than 128 bytes", padded(&sixty_one_spaces)),
        ("one byte short", exact[..67].to_vec()),
        ("not at the start", shifted),
        ("empty", Vec::new()),
    ];
    for (what, bytes) in near_misses {
        let result = scanner.scan_bytes(&bytes);
        assert_eq!(result.verdict, Verdict::Clean, "{what}");
        assert!(result.findings.is_empty(), "{what}");
    }
}

#[test]
fn a_variant_the_hash_layer_misses_is_caught_by_the_rule() {
    let scanner = Scanner::builder()
        .detector(HashDetector::new())
        .detector(YaraDetector::builtin().unwrap())
        .build();

    // The exact test file is known to both layers.
    let exact = scanner.scan_bytes(&eicar::test_file());
    let detectors: Vec<&str> = exact
        .findings
        .iter()
        .map(|finding| finding.detector)
        .collect();
    assert_eq!(detectors, ["hash", "yara"]);

    // One added line break changes the hash. Only the rule still matches.
    let variant = scanner.scan_bytes(&padded(b"\n"));
    assert_eq!(variant.verdict, Verdict::Malicious);
    assert_eq!(variant.findings.len(), 1);
    assert_eq!(variant.findings[0].detector, "yara");
    assert_eq!(variant.findings[0].name, eicar::DETECTION_NAME);
    assert_ne!(
        warden_sigdb::hex::encode(&variant.sha256),
        eicar::SHA256_HEX
    );
}

#[test]
fn a_variant_inside_a_zip_is_found_by_the_rule() {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options = zip::write::SimpleFileOptions::default();
    writer.start_file("notes.txt", options).unwrap();
    writer.write_all(b"nothing of interest").unwrap();
    writer.start_file("samples/variant.com", options).unwrap();
    writer.write_all(&padded(b"\r\n")).unwrap();
    let archive = writer.finish().unwrap().into_inner();

    let scanner = Scanner::builder()
        .detector(HashDetector::new())
        .detector(YaraDetector::builtin().unwrap())
        .build();
    let result = scanner.scan_bytes(&archive);

    assert_eq!(result.verdict, Verdict::Malicious);
    assert_eq!(result.findings.len(), 1);
    let finding = &result.findings[0];
    assert_eq!(finding.detector, "yara");
    let member = finding.member.as_ref().unwrap();
    assert_eq!(member.path, ["samples/variant.com"]);
    assert_eq!(member.size, 70);
}

#[test]
fn a_rule_score_decides_the_confidence_and_so_the_verdict() {
    let scanner = marker_scanner();
    let cases = [
        ("WARDEN-YARA-HIGH", Confidence::High, Verdict::Malicious),
        (
            "WARDEN-YARA-MEDIUM",
            Confidence::Medium,
            Verdict::Suspicious,
        ),
        ("WARDEN-YARA-LOW", Confidence::Low, Verdict::Clean),
        // A rule without a score is assumed to be worth 75: suspicious.
        (
            "WARDEN-YARA-UNSCORED",
            Confidence::Medium,
            Verdict::Suspicious,
        ),
    ];
    for (marker, confidence, verdict) in cases {
        let content = format!("some text, then {marker}, then more text");
        let result = scanner.scan_bytes(content.as_bytes());
        assert_eq!(result.findings.len(), 1, "{marker}");
        assert_eq!(result.findings[0].confidence, confidence, "{marker}");
        assert_eq!(result.verdict, verdict, "{marker}");
    }
    assert!(scanner.scan_bytes(b"no marker here").findings.is_empty());

    // The thresholds are options, not constants.
    let strict = Scanner::builder()
        .detector(
            YaraDetector::new(marker_bundle().bundle).with_options(YaraOptions {
                high_at: 60,
                ..YaraOptions::default()
            }),
        )
        .build();
    assert_eq!(
        strict.scan_bytes(b"WARDEN-YARA-MEDIUM").verdict,
        Verdict::Malicious
    );
}

#[test]
fn a_finding_says_which_rule_matched_where_and_who_wrote_it() {
    let result = marker_scanner().scan_bytes(b"0123456789WARDEN-YARA-HIGH");
    let finding = &result.findings[0];
    assert_eq!(finding.name, "Test_Marker_High");
    assert_eq!(finding.category, ThreatCategory::Malware);
    assert_eq!(
        finding.reasons,
        [
            "YARA rule Test_Marker_High matched: contains the high marker",
            "Patterns found: $marker at offset 0xa",
            "Rule score 90 of 100, written by the test suite, see https://example.test/high",
        ]
    );
}

#[test]
fn a_rule_can_name_the_threat_and_its_category() {
    let result = marker_scanner().scan_bytes(b"WARDEN-YARA-NAMED");
    let finding = &result.findings[0];
    assert_eq!(finding.name, "PUA.Test.Named");
    assert_eq!(finding.category, ThreatCategory::PotentiallyUnwanted);
    assert_eq!(finding.reasons[0], "YARA rule Test_Marker_Named matched");
}

#[test]
fn when_many_rules_match_the_strongest_are_listed() {
    let mut rules = String::new();
    for index in 0..15 {
        rules.push_str(&format!(
            "rule Crowd_{index:02} {{ meta: score = {} strings: $m = \"WARDEN-YARA-CROWD\" condition: $m }}\n",
            50 + index
        ));
    }
    let mut builder = BundleBuilder::new();
    builder.add_source("crowd.yar", rules);
    let scanner = Scanner::builder()
        .detector(YaraDetector::new(builder.build().unwrap().bundle))
        .build();

    let result = scanner.scan_bytes(b"WARDEN-YARA-CROWD");
    let listed = names(&result);
    assert_eq!(listed.len(), 10);
    // Scores run from 50 to 64; the ten highest are 55 to 64, strongest first.
    assert_eq!(listed[0], "Crowd_14");
    assert_eq!(listed[9], "Crowd_05");
    assert!(
        result.findings[0]
            .reasons
            .contains(&"5 more rules matched this file and are not listed".to_owned())
    );
}

#[test]
fn a_bundle_survives_being_written_and_read_back() {
    let built = marker_bundle();
    assert_eq!(built.report.rules, 6);
    assert_eq!(built.report.skipped_total, 0);
    assert_eq!(built.report.error_total, 0);
    let names: Vec<&str> = built
        .report
        .sources
        .iter()
        .map(|source| source.name.as_str())
        .collect();
    assert_eq!(names, [BUILTIN_SOURCE, "markers.yar"]);
    assert_eq!(built.report.sources[1].rules, 5);

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rules.wrb");
    write_bundle(&path, &built.bytes).unwrap();
    // Writing again replaces the file in one step.
    write_bundle(&path, &built.bytes).unwrap();
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);

    let loaded = RuleBundle::open(&path).unwrap();
    assert_eq!(loaded.rule_count(), 6);
    assert_eq!(loaded.created_unix_secs(), 1_800_000_000);
    assert_eq!(loaded.digest(), built.bundle.digest());
    assert_eq!(loaded.size_bytes(), built.bytes.len() as u64);
    assert_eq!(loaded.manifest(), built.bundle.manifest());
    let source = &loaded.manifest().sources[1];
    assert_eq!(source.bytes, MARKER_RULES.len() as u64);
    assert_eq!(
        source.sha256,
        warden_sigdb::hex::encode(&warden_engine::sha256(MARKER_RULES.as_bytes()))
    );

    // A loaded bundle detects what the freshly built one does, including
    // through the built-in rules that every bundle carries.
    let scanner = Scanner::builder()
        .detector(YaraDetector::new(loaded))
        .build();
    assert_eq!(
        scanner.scan_bytes(b"WARDEN-YARA-HIGH").verdict,
        Verdict::Malicious
    );
    assert_eq!(
        scanner.scan_bytes(&padded(b"\n")).findings[0].name,
        eicar::DETECTION_NAME
    );
}

#[test]
fn a_rule_that_does_not_compile_is_left_out_and_the_rest_is_kept() {
    let rules = r#"
import "magic"

rule Good_One { strings: $a = "WARDEN-YARA-GOOD" condition: $a }

rule Broken_One { condition: this_identifier_does_not_exist > 3 }

rule Needs_Missing_Module { condition: magic.type() contains "text" }

rule Good_Two { strings: $a = "WARDEN-YARA-ALSO-GOOD" condition: $a }
"#;
    let mut builder = BundleBuilder::new().builtin_rules(false);
    builder.add_source("mixed.yar", rules);
    let built = builder.build().unwrap();

    assert_eq!(built.report.rules, 2);
    assert_eq!(built.report.skipped_total, 2);
    assert_eq!(built.report.sources[0].rules, 2);
    assert_eq!(built.report.sources[0].skipped, 2);
    let skipped: Vec<(&str, &str)> = built
        .report
        .skipped
        .iter()
        .map(|rule| (rule.rule.as_str(), rule.reason.as_str()))
        .collect();
    assert_eq!(skipped[0].0, "Broken_One");
    assert!(
        skipped[0].1.contains("this_identifier_does_not_exist"),
        "{}",
        skipped[0].1
    );
    assert_eq!(skipped[1].0, "Needs_Missing_Module");
    assert!(skipped[1].1.contains("\"magic\""), "{}", skipped[1].1);

    let scanner = Scanner::builder()
        .detector(YaraDetector::new(built.bundle))
        .build();
    assert_eq!(
        names(&scanner.scan_bytes(b"WARDEN-YARA-GOOD")),
        ["Good_One"]
    );
    assert_eq!(
        names(&scanner.scan_bytes(b"WARDEN-YARA-ALSO-GOOD")),
        ["Good_Two"]
    );
}

#[test]
fn an_include_is_refused_and_the_rest_of_the_file_is_kept() {
    // A bundle records every rule file it was built from. A file that is
    // pulled in by an include would be missing from that record.
    let dir = tempfile::tempdir().unwrap();
    let hidden = dir.path().join("hidden.yar");
    std::fs::write(&hidden, "rule Hidden { condition: true }").unwrap();
    let rules = format!(
        "include \"{}\"\nrule Visible {{ strings: $a = \"WARDEN-YARA-VISIBLE\" condition: $a }}\n",
        hidden.display().to_string().replace('\\', "/")
    );
    let mut builder = BundleBuilder::new().builtin_rules(false);
    builder.add_source("with-include.yar", rules);
    let built = builder.build().unwrap();

    assert_eq!(built.report.rules, 1);
    assert_eq!(built.report.error_total, 1);
    assert!(
        built.report.errors[0].contains("include statements not allowed"),
        "{}",
        built.report.errors[0]
    );
    let names: Vec<String> = built
        .bundle
        .rules()
        .iter()
        .map(|rule| rule.identifier().to_owned())
        .collect();
    assert_eq!(names, ["Visible"]);
}

#[test]
fn rule_files_are_read_from_folders_and_packages() {
    let rule = |name: &str| format!("rule {name} {{ strings: $a = \"{name}\" condition: $a }}\n");
    let dir = tempfile::tempdir().unwrap();
    let folder = dir.path().join("rules");
    std::fs::create_dir_all(folder.join("nested")).unwrap();
    std::fs::write(folder.join("b.yar"), rule("From_B")).unwrap();
    std::fs::write(folder.join("a.YAR"), rule("From_A")).unwrap();
    std::fs::write(folder.join("nested").join("c.yara"), rule("From_C")).unwrap();
    std::fs::write(folder.join("readme.txt"), "not a rule file").unwrap();

    let package = dir.path().join("package.zip");
    let mut writer = zip::ZipWriter::new(std::fs::File::create(&package).unwrap());
    let options = zip::write::SimpleFileOptions::default();
    writer.start_file("packages/core/set.yar", options).unwrap();
    writer.write_all(rule("From_Package").as_bytes()).unwrap();
    writer.start_file("packages/core/LICENSE", options).unwrap();
    writer.write_all(b"not a rule file").unwrap();
    writer.finish().unwrap();

    let single = dir.path().join("single.yar");
    std::fs::write(&single, rule("From_Single")).unwrap();

    let mut builder = BundleBuilder::new().builtin_rules(false);
    assert_eq!(builder.add_path(&folder).unwrap(), 3);
    assert_eq!(builder.add_path(&package).unwrap(), 1);
    assert_eq!(builder.add_path(&single).unwrap(), 1);
    assert_eq!(builder.source_count(), 5);
    let built = builder.build().unwrap();

    let sources: Vec<&str> = built
        .report
        .sources
        .iter()
        .map(|source| source.name.as_str())
        .collect();
    assert_eq!(
        sources,
        [
            "a.YAR",
            "b.yar",
            "nested/c.yara",
            "package.zip/packages/core/set.yar",
            "single.yar"
        ]
    );
    assert_eq!(built.report.rules, 5);

    // A folder without rule files, and a path that does not exist, are errors.
    let empty = dir.path().join("empty");
    std::fs::create_dir(&empty).unwrap();
    let mut builder = BundleBuilder::new();
    assert!(matches!(
        builder.add_path(&empty),
        Err(BundleError::Source(_))
    ));
    assert!(matches!(
        builder.add_path(Path::new("does/not/exist.yar")),
        Err(BundleError::Io { .. })
    ));
}

#[test]
fn two_files_with_the_same_name_and_the_same_rule_names_do_not_collide() {
    let rule = "rule Same_Name { strings: $a = \"WARDEN-YARA-SAME\" condition: $a }";
    let mut builder = BundleBuilder::new().builtin_rules(false);
    builder.add_source("set.yar", rule);
    builder.add_source("set.yar", rule);
    let built = builder.build().unwrap();
    assert_eq!(built.report.rules, 2);
    assert_eq!(built.report.sources[1].name, "set.yar (2)");
}

#[test]
fn a_bundle_needs_at_least_one_rule() {
    let builder = BundleBuilder::new().builtin_rules(false);
    assert!(matches!(builder.build(), Err(BundleError::Empty)));

    let mut builder = BundleBuilder::new().builtin_rules(false);
    builder.add_source(
        "broken.yar",
        "rule Broken { condition: nonsense_identifier }",
    );
    assert!(matches!(builder.build(), Err(BundleError::Empty)));
}

#[test]
fn damaged_bundles_are_refused() {
    let bytes = marker_bundle().bytes;

    // Cut short anywhere.
    for length in (0..bytes.len()).step_by(bytes.len() / 64 + 1) {
        assert!(
            RuleBundle::from_bytes(&bytes[..length]).is_err(),
            "length {length}"
        );
    }
    // Longer than it should be.
    let mut longer = bytes.clone();
    longer.push(0);
    assert!(matches!(
        RuleBundle::from_bytes(&longer),
        Err(BundleError::WrongLength { .. })
    ));
    // One changed byte anywhere: in the header, the manifest or the rules.
    for position in (0..bytes.len()).step_by(bytes.len() / 48 + 1) {
        let mut damaged = bytes.clone();
        damaged[position] ^= 0x01;
        assert!(
            RuleBundle::from_bytes(&damaged).is_err(),
            "position {position}"
        );
    }
    let mut body_damage = bytes.clone();
    let last = body_damage.len() - 1;
    body_damage[last] ^= 0x80;
    assert!(matches!(
        RuleBundle::from_bytes(&body_damage),
        Err(BundleError::DigestMismatch)
    ));
    // Something else entirely.
    assert!(matches!(
        RuleBundle::from_bytes(&[0u8; 4096]),
        Err(BundleError::BadMagic)
    ));
    assert!(matches!(
        RuleBundle::from_bytes(b"short"),
        Err(BundleError::WrongLength { .. })
    ));
}

/// Rules that say a tool made them, in the words of the real ones, and one
/// that names a tool Warden does not know as a rule generator.
const GENERATED_RULES: &str = r#"
rule Test_Generated
{
    meta:
        description = "autogenerated rule brought to you by yara-signator"
        score = 75
        tool = "yara-signator v0.6.0"
    strings:
        $sequence_0 = "WARDEN-YARA-GENERATED-QUIET"
    condition:
        $sequence_0
}

rule Test_Generated_Loud
{
    meta:
        score = 95
        tool = "YARA-Signator v9"
    strings:
        $sequence_0 = "WARDEN-YARA-GENERATED-LOUD"
    condition:
        $sequence_0
}

rule Test_Made_With_Something_Else
{
    meta:
        score = 75
        tool = "a text editor"
    strings:
        $marker = "WARDEN-YARA-BY-HAND"
    condition:
        $marker
}
"#;

fn generated_detector() -> YaraDetector {
    let mut builder = BundleBuilder::new().builtin_rules(false);
    builder.add_source("generated.yar", GENERATED_RULES);
    YaraDetector::new(builder.build().unwrap().bundle)
}

/// What the detector reports about some bytes, before the verdict policy
/// has settled anything.
fn reported(detector: &YaraDetector, content: &[u8]) -> Vec<Finding> {
    let sha256 = warden_engine::sha256(content);
    detector
        .session()
        .inspect(&FileView::in_memory(content, &sha256))
        .unwrap()
}

#[test]
fn a_rule_says_in_its_metadata_whether_a_tool_made_it() {
    assert_eq!(
        generator("yara-signator v0.6.0"),
        Some("yara-signator v0.6.0")
    );
    assert_eq!(generator("  YARA-Signator v9 "), Some("YARA-Signator v9"));
    assert_eq!(generator("a text editor"), None);
    assert_eq!(generator("yara"), None);
    assert_eq!(generator(""), None);
}

#[test]
fn a_match_of_a_generated_rule_waits_for_a_second_sign() {
    let detector = generated_detector();

    let findings = reported(&detector, b"... WARDEN-YARA-GENERATED-QUIET ...");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].name, "Test_Generated");
    assert_eq!(findings[0].counts, Counts::WithSecondSign);
    assert_eq!(findings[0].confidence, Confidence::Medium);
    let said = findings[0].reasons.join("\n");
    assert!(
        said.contains("generated by a tool, yara-signator v0.6.0"),
        "{said}"
    );

    // Its tool gave this one a score that would make a file malicious.
    // Backed up or not, a generated rule stops at suspicious.
    let findings = reported(&detector, b"WARDEN-YARA-GENERATED-LOUD");
    assert_eq!(findings[0].counts, Counts::WithSecondSign);
    assert_eq!(findings[0].confidence, Confidence::Medium);
    assert!(findings[0].reasons.join("\n").contains("Rule score 95"));

    // A rule that names some other tool is a rule like any other.
    let findings = reported(&detector, b"WARDEN-YARA-BY-HAND");
    assert_eq!(findings[0].counts, Counts::Alone);
    assert_eq!(findings[0].confidence, Confidence::Medium);
    assert!(!findings[0].reasons.join("\n").contains("generated"));
}

#[test]
fn alone_a_generated_rule_leaves_a_file_clean_and_on_record() {
    let scanner = Scanner::builder().detector(generated_detector()).build();

    let result = scanner.scan_bytes(b"WARDEN-YARA-GENERATED-QUIET");
    assert_eq!(result.verdict, Verdict::Clean);
    assert_eq!(names(&result), ["Test_Generated"]);
    assert_eq!(result.findings[0].confidence, Confidence::Low);
    let last = result.findings[0].reasons.last().unwrap();
    assert!(last.contains("does not change the verdict"), "{last}");

    // Two generated rules about the same file are still one layer.
    let result = scanner.scan_bytes(b"WARDEN-YARA-GENERATED-QUIET and WARDEN-YARA-GENERATED-LOUD");
    assert_eq!(result.verdict, Verdict::Clean);
    assert_eq!(result.findings.len(), 2);

    // A rule a person wrote counts as before.
    assert_eq!(
        scanner.scan_bytes(b"WARDEN-YARA-BY-HAND").verdict,
        Verdict::Suspicious
    );
}

/// A stand-in for another layer: offers a second sign for any content that
/// holds its marker.
struct OddLooking;

impl Detector for OddLooking {
    fn id(&self) -> &'static str {
        "odd"
    }

    fn needs_content(&self) -> bool {
        true
    }

    fn session(&self) -> Box<dyn Session + '_> {
        Box::new(self)
    }
}

impl Session for &OddLooking {
    fn inspect(&mut self, file: &FileView<'_>) -> Result<Vec<Finding>, DetectorError> {
        const MARKER: &[u8] = b"LOOKS-ODD";
        let odd = file
            .content()
            .is_some_and(|content| content.windows(MARKER.len()).any(|window| window == MARKER));
        Ok(odd
            .then(|| {
                Finding::new(
                    "odd",
                    "Test.OddLooking",
                    ThreatCategory::Malware,
                    Confidence::Low,
                    vec!["holds the odd marker".to_owned()],
                )
                .as_second_sign()
            })
            .into_iter()
            .collect())
    }
}

#[test]
fn with_a_sign_from_another_layer_a_generated_rule_makes_a_file_suspicious() {
    let scanner = Scanner::builder()
        .detector(generated_detector())
        .detector(OddLooking)
        .build();

    let result = scanner.scan_bytes(b"WARDEN-YARA-GENERATED-QUIET, and it LOOKS-ODD");
    assert_eq!(result.verdict, Verdict::Suspicious);
    assert_eq!(names(&result), ["Test_Generated", "Test.OddLooking"]);
    let last = result.findings[0].reasons.last().unwrap();
    assert!(last.ends_with("same file: odd"), "{last}");

    // The loud one too, and no further than suspicious.
    let result = scanner.scan_bytes(b"WARDEN-YARA-GENERATED-LOUD, and it LOOKS-ODD");
    assert_eq!(result.verdict, Verdict::Suspicious);

    // Odd-looking alone is nothing.
    let result = scanner.scan_bytes(b"it only LOOKS-ODD");
    assert_eq!(result.verdict, Verdict::Clean);
    assert!(result.findings.is_empty());
}

#[test]
fn the_detector_describes_its_rules_for_the_report() {
    use warden_engine::InfoValue;

    let built = marker_bundle();
    let digest = warden_sigdb::hex::encode(&built.bundle.digest());
    let info = YaraDetector::new(built.bundle).describe();
    assert_eq!(info.id, "yara");
    assert_eq!(info.details["rules"], InfoValue::Count(6));
    assert_eq!(info.details["rules_generated"], InfoValue::Count(0));
    assert_eq!(
        generated_detector().describe().details["rules_generated"],
        InfoValue::Count(2)
    );
    assert_eq!(info.details["rule_files"], InfoValue::Count(2));
    assert_eq!(info.details["engine"], InfoValue::Text(ENGINE.to_owned()));
    assert_eq!(
        info.details["origin"],
        InfoValue::Text("rule bundle".to_owned())
    );
    assert_eq!(
        YaraDetector::builtin().unwrap().describe().details["origin"],
        InfoValue::Text("built-in rules".to_owned())
    );
    assert_eq!(info.details["bundle_digest"], InfoValue::Text(digest));
    assert_eq!(
        info.details["bundle_created_unix_secs"],
        InfoValue::Count(1_800_000_000)
    );
}

#[test]
fn rules_are_counted_by_confidence_and_by_licence() {
    let rules = r#"
rule Licensed_One { meta: score = 85 license_url = "https://example.test/LICENSE" condition: false }
rule Licensed_Two { meta: score = 70 license = "Example Licence 1.0" license_url = "N/A" condition: false }
rule Unlicensed { meta: score = 10 condition: false }
rule Unscored { condition: false }
"#;
    let mut builder = BundleBuilder::new().builtin_rules(false);
    builder.add_source("licences.yar", rules);
    let stats = YaraDetector::new(builder.build().unwrap().bundle).rule_stats();

    assert_eq!((stats.high, stats.medium, stats.low), (1, 2, 1));
    assert_eq!(stats.unscored, 1);
    assert_eq!(stats.generated, 0);
    assert_eq!(stats.licences["https://example.test/LICENSE"], 1);
    assert_eq!(stats.licences["Example Licence 1.0"], 1);
    assert_eq!(stats.licences[""], 2);

    // Generated rules are counted as that, whatever their score says: one
    // of the two states 95. The third rule names a tool that is not a rule
    // generator and is counted like any other.
    let generated = generated_detector().rule_stats();
    assert_eq!((generated.high, generated.medium, generated.low), (0, 1, 0));
    assert_eq!(generated.generated, 2);
}

#[test]
fn the_recorded_engine_is_the_one_this_crate_is_built_with() {
    let lock = include_str!("../../../Cargo.lock");
    let entry = lock
        .split("[[package]]")
        .find(|package| package.contains("name = \"yara-x\"\n"))
        .unwrap();
    let version = entry
        .lines()
        .find_map(|line| line.strip_prefix("version = \""))
        .unwrap()
        .trim_end_matches('"');
    assert_eq!(ENGINE, format!("yara-x {version}"));
}

//! The rule exclusion list end to end: a listed rule is left out of the
//! bundle, the bundle says so, and everything else keeps working.
//!
//! Nothing here is malware. The rules match harmless marker strings that the
//! tests make up.

#![allow(clippy::unwrap_used)]

use std::path::Path;

use warden_engine::{Scanner, Verdict};
use warden_yara::{
    BundleBuilder, BundleError, ExclusionError, ExclusionList, RuleBundle, YaraDetector,
};

const RULES: &str = r#"
rule Loud_Rule
{
    meta:
        score = 90
    strings:
        $marker = "WARDEN-EXCLUSION-LOUD"
    condition:
        $marker
}

rule Quiet_Rule
{
    meta:
        score = 90
    strings:
        $marker = "WARDEN-EXCLUSION-QUIET"
    condition:
        $marker
}
"#;

/// An exclusion list that names the given rules, each with made-up evidence.
fn list_of(names: &[&str]) -> ExclusionList {
    let mut text = String::new();
    for name in names {
        text.push_str(&format!(
            "[[rule]]\n\
             name = \"{name}\"\n\
             reason = \"Made up for a test.\"\n\
             [[rule.evidence]]\n\
             file = '/usr/lib/example.so'\n\
             sha256 = \"{}\"\n\
             seen = 2026-11-18\n\
             machine = \"test suite\"\n",
            "ab".repeat(32)
        ));
    }
    ExclusionList::parse(&text).unwrap()
}

fn verdict_of(scanner: &Scanner, content: &[u8]) -> Verdict {
    scanner.scan_bytes(content).verdict
}

#[test]
fn a_listed_rule_is_left_out_and_the_bundle_says_so() {
    let plain = {
        let mut builder = BundleBuilder::new().builtin_rules(false);
        builder.add_source("set.yar", RULES);
        builder.build().unwrap()
    };
    assert_eq!(plain.report.rules, 2);
    assert!(plain.report.excluded.is_empty());
    assert_eq!(plain.bundle.manifest().exclusions, None);

    let list = list_of(&["Loud_Rule"]);
    let digest = list.digest().to_owned();
    let mut builder = BundleBuilder::new().builtin_rules(false).exclusions(list);
    builder.add_source("set.yar", RULES);
    let built = builder.build().unwrap();

    let report = &built.report;
    assert_eq!(report.rules, 1);
    assert_eq!(report.excluded.len(), 1);
    assert_eq!(report.excluded[0].rule, "Loud_Rule");
    assert_eq!(report.excluded[0].source, "set.yar");
    assert!(report.unused_exclusions.is_empty());
    assert_eq!(report.sources[0].rules, 1);
    assert_eq!(report.sources[0].excluded, 1);
    // Leaving a rule out on purpose is not a fault in the rule file.
    assert_eq!(report.sources[0].skipped, 0);
    assert_eq!(report.skipped_total, 0);
    assert!(report.skipped.is_empty());
    assert_eq!(report.error_total, 0);
    assert_eq!(report.warnings, plain.report.warnings);

    // The record survives being written and read back.
    let loaded = RuleBundle::from_bytes(&built.bytes).unwrap();
    assert_eq!(loaded.rule_count(), 1);
    let recorded = loaded.manifest().exclusions.as_ref().unwrap();
    assert_eq!(recorded.sha256, digest);
    assert_eq!(recorded.rules, ["Loud_Rule"]);
    assert_eq!(loaded.manifest().sources[0].excluded, 1);
    // The record of the rule file is of the file as it was given.
    assert_eq!(
        loaded.manifest().sources[0].sha256,
        plain.bundle.manifest().sources[0].sha256
    );
    assert_eq!(loaded.manifest().sources[0].bytes, RULES.len() as u64);

    let with_list = Scanner::builder()
        .detector(YaraDetector::new(loaded))
        .build();
    let without_list = Scanner::builder()
        .detector(YaraDetector::new(plain.bundle))
        .build();
    let loud = b"a clean file that holds WARDEN-EXCLUSION-LOUD";
    let quiet = b"a file that holds WARDEN-EXCLUSION-QUIET";
    assert_eq!(verdict_of(&without_list, loud), Verdict::Malicious);
    assert_eq!(verdict_of(&with_list, loud), Verdict::Clean);
    assert_eq!(verdict_of(&with_list, quiet), Verdict::Malicious);
}

#[test]
fn rules_that_use_a_listed_rule_are_left_out_too_and_reported() {
    let rules = r#"
rule Base { strings: $a = "WARDEN-EXCLUSION-BASE" condition: $a }
rule Uses_Base { condition: Base and filesize < 1MB }
rule Uses_The_User { condition: Uses_Base or filesize == 3 }
rule Independent { strings: $a = "WARDEN-EXCLUSION-OTHER" condition: $a }
"#;
    let mut builder = BundleBuilder::new()
        .builtin_rules(false)
        .exclusions(list_of(&["Base"]));
    builder.add_source("chain.yar", rules);
    let built = builder.build().unwrap();

    let report = &built.report;
    assert_eq!(report.rules, 1);
    assert_eq!(report.excluded.len(), 1);
    assert_eq!(report.sources[0].excluded, 1);
    assert_eq!(report.sources[0].skipped, 2);
    assert_eq!(report.skipped_total, 2);
    let skipped: Vec<(&str, &str)> = report
        .skipped
        .iter()
        .map(|rule| (rule.rule.as_str(), rule.reason.as_str()))
        .collect();
    assert_eq!(
        skipped,
        [
            ("Uses_Base", "depends on the rule Base, which was left out"),
            (
                "Uses_The_User",
                "depends on the rule Uses_Base, which was left out"
            ),
        ]
    );
    // None of this is a compile error or a warning about the rule file.
    assert_eq!(report.error_total, 0);
    assert_eq!(report.warnings, 0);

    let scanner = Scanner::builder()
        .detector(YaraDetector::new(built.bundle))
        .build();
    assert_eq!(
        verdict_of(&scanner, b"WARDEN-EXCLUSION-BASE"),
        Verdict::Clean
    );
    assert_ne!(
        verdict_of(&scanner, b"WARDEN-EXCLUSION-OTHER"),
        Verdict::Clean
    );
}

#[test]
fn a_listed_rule_is_found_in_every_file_that_declares_it() {
    let rule = |marker: &str| {
        format!(
            "rule Loud_Rule {{ strings: $a = \"{marker}\" condition: $a }}\nrule Other_{marker} {{ condition: false }}\n"
        )
    };
    let mut builder = BundleBuilder::new()
        .builtin_rules(false)
        .exclusions(list_of(&["Loud_Rule", "Never_Declared", "Also_Missing"]));
    builder.add_source("one.yar", rule("FIRST"));
    builder.add_source("two.yar", rule("SECOND"));
    builder.add_source("three.yar", "rule Unrelated { condition: false }");
    let built = builder.build().unwrap();

    let report = &built.report;
    assert_eq!(report.rules, 3);
    let found: Vec<(&str, &str)> = report
        .excluded
        .iter()
        .map(|entry| (entry.rule.as_str(), entry.source.as_str()))
        .collect();
    assert_eq!(found, [("Loud_Rule", "one.yar"), ("Loud_Rule", "two.yar")]);
    let per_file: Vec<u64> = report
        .sources
        .iter()
        .map(|source| source.excluded)
        .collect();
    assert_eq!(per_file, [1, 1, 0]);
    // Names that match nothing are reported, so that a misspelt or outdated
    // entry does not go unnoticed.
    assert_eq!(report.unused_exclusions, ["Also_Missing", "Never_Declared"]);

    // The bundle names each rule once, however many files declared it.
    let recorded = built.bundle.manifest().exclusions.as_ref().unwrap();
    assert_eq!(recorded.rules, ["Loud_Rule"]);
}

#[test]
fn a_list_that_matches_nothing_is_still_recorded() {
    let list = list_of(&["Not_In_Any_File"]);
    let digest = list.digest().to_owned();
    let mut builder = BundleBuilder::new().exclusions(list);
    builder.add_source("set.yar", RULES);
    let built = builder.build().unwrap();
    assert_eq!(built.report.rules, 3);
    assert!(built.report.excluded.is_empty());
    assert_eq!(built.report.unused_exclusions, ["Not_In_Any_File"]);
    let recorded = built.bundle.manifest().exclusions.as_ref().unwrap();
    assert_eq!(recorded.sha256, digest);
    assert!(recorded.rules.is_empty());
}

#[test]
fn rules_that_must_stay_cannot_be_listed() {
    // The built-in rules are what makes a scan with a bundle catch
    // everything a scan without one does.
    let mut builder = BundleBuilder::new().exclusions(list_of(&["Warden_EICAR_Test_File"]));
    builder.add_source("set.yar", RULES);
    let error = builder.build().unwrap_err();
    assert!(matches!(error, BundleError::Exclusion(_)), "{error}");
    let message = error.to_string();
    assert!(message.contains("Warden_EICAR_Test_File"), "{message}");
    assert!(message.contains("built into Warden"), "{message}");

    // A global rule narrows every other rule in its file. Without it, all
    // of them would match more than their authors meant.
    let rules = r#"
global rule Only_Small_Files { condition: filesize < 1KB }
rule Marker { strings: $a = "WARDEN-EXCLUSION-GLOBAL" condition: $a }
"#;
    let mut builder = BundleBuilder::new()
        .builtin_rules(false)
        .exclusions(list_of(&["Only_Small_Files"]));
    builder.add_source("gated.yar", rules);
    let error = builder.build().unwrap_err();
    assert!(matches!(error, BundleError::Exclusion(_)), "{error}");
    let message = error.to_string();
    assert!(message.contains("Only_Small_Files"), "{message}");
    assert!(message.contains("gated.yar"), "{message}");
    assert!(message.contains("global"), "{message}");
}

#[test]
fn a_rule_file_cannot_pose_as_the_exclusion_list() {
    // The stubs use a module name of their own. A rule file that uses the
    // same name gains nothing by it: its rule is one that needs a module
    // which does not exist, and it is not counted as excluded.
    let rules = r#"
import "warden_excluded"
rule Poses { condition: warden_excluded.listed }
rule Fine { strings: $a = "WARDEN-EXCLUSION-FINE" condition: $a }
"#;
    for list in [None, Some(list_of(&["Listed_But_Elsewhere"]))] {
        let with_list = list.is_some();
        let mut builder = BundleBuilder::new().builtin_rules(false);
        if let Some(list) = list {
            builder = builder.exclusions(list);
        }
        builder.add_source("poser.yar", rules);
        let built = builder.build().unwrap();

        assert_eq!(built.report.rules, 1, "with a list: {with_list}");
        assert!(built.report.excluded.is_empty());
        assert_eq!(built.report.sources[0].excluded, 0);
        assert_eq!(built.report.skipped_total, 1);
        assert_eq!(built.report.skipped[0].rule, "Poses");
        let names: Vec<String> = built
            .bundle
            .rules()
            .iter()
            .map(|rule| rule.identifier().to_owned())
            .collect();
        assert_eq!(names, ["Fine"]);
    }
}

#[test]
fn a_list_is_read_from_a_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("exclusions.toml");
    assert!(matches!(
        ExclusionList::load(&path),
        Err(ExclusionError::Io { .. })
    ));

    std::fs::write(&path, b"[[rule]]\nname = \"A\"\n\xff\xfe").unwrap();
    assert!(matches!(
        ExclusionList::load(&path),
        Err(ExclusionError::Syntax(_))
    ));

    let text = "[[rule]]\nname = \"A\"\nreason = \"r\"\n[[rule.evidence]]\nfile = \"f\"\nsha256 = \"0000000000000000000000000000000000000000000000000000000000000000\"\nseen = 2026-01-02\nmachine = \"m\"\n";
    std::fs::write(&path, text).unwrap();
    let list = ExclusionList::load(&path).unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list.digest(), ExclusionList::parse(text).unwrap().digest());
}

/// The list in this repository is what the check scripts and CI build with.
/// A mistake in it must fail here, not on someone's machine.
#[test]
fn the_list_in_the_repository_is_valid_and_documented() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let list = ExclusionList::load(&root.join("rules/exclusions.toml")).unwrap();
    assert!(!list.is_empty());

    let documentation = std::fs::read_to_string(root.join("docs/RULES.md")).unwrap();
    for rule in list.rules() {
        assert!(
            documentation.contains(&rule.name),
            "docs/RULES.md does not mention {}, which rules/exclusions.toml leaves out",
            rule.name
        );
    }
}

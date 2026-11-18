//! Tests of the `warden` binary as a user would run it.

#![allow(clippy::unwrap_used)]

use std::fs;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use predicates::prelude::*;

fn warden() -> Command {
    let mut command = assert_cmd::cargo_bin_cmd!("warden");
    // Keep the developer's own configuration out of the tests.
    command
        .env_remove("WARDEN_SIGDB")
        .env_remove("WARDEN_RULES")
        .env_remove("SOURCE_DATE_EPOCH");
    command
}

fn stdout_of(command: &mut Command) -> String {
    String::from_utf8(command.assert().get_output().stdout.clone()).unwrap()
}

/// SHA-256 of bytes, in lowercase hexadecimal.
fn sha256_hex(bytes: &[u8]) -> String {
    warden_sigdb::hex::encode(&warden_engine::sha256(bytes))
}

/// SHA-256 of a file, as printed by `warden hash`.
fn hash_of(path: &Path) -> String {
    let output = stdout_of(warden().arg("hash").arg(path));
    output.split_whitespace().next().unwrap().to_owned()
}

/// A folder with two clean files and one fixture, plus a database that
/// declares the fixture to be a threat.
struct Fixture {
    _dir: tempfile::TempDir,
    tree: PathBuf,
    threat: PathBuf,
    database: PathBuf,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let tree = dir.path().join("tree");
    fs::create_dir_all(tree.join("nested")).unwrap();
    fs::write(tree.join("readme.txt"), "nothing to see here").unwrap();
    fs::write(tree.join("nested/data.bin"), [7u8; 4096]).unwrap();
    let threat = tree.join("nested/fixture.bin");
    fs::write(
        &threat,
        "harmless bytes that the test database calls a threat",
    )
    .unwrap();

    let list = dir.path().join("hashes.txt");
    fs::write(&list, format!("# test signatures\n{}\n", hash_of(&threat))).unwrap();
    let database = dir.path().join("test.wdb");
    warden()
        .args(["sigdb", "build", "--name", "Test.Fixture", "--out"])
        .arg(&database)
        .arg("--hashes")
        .arg(&list)
        .assert()
        .success();
    Fixture {
        _dir: dir,
        tree,
        threat,
        database,
    }
}

#[test]
fn version_and_help_work() {
    warden()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")));
    warden()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("scan").and(predicate::str::contains("sigdb")));
    warden().assert().failure().code(2);
}

#[test]
fn a_clean_folder_exits_zero() {
    let fixture = fixture();
    warden()
        .arg("scan")
        .arg(&fixture.tree)
        .assert()
        .success()
        .stdout(
            predicate::str::contains("No threats found.")
                .and(predicate::str::contains("Scanned     3 files"))
                .and(predicate::str::contains("Signatures  1 built-in")),
        );
}

#[test]
fn a_detection_exits_one_and_explains_itself() {
    let fixture = fixture();
    warden()
        .arg("scan")
        .arg(&fixture.tree)
        .arg("--sigdb")
        .arg(&fixture.database)
        .assert()
        .code(1)
        .stdout(
            predicate::str::contains("1 detection")
                .and(predicate::str::contains("MALICIOUS"))
                .and(predicate::str::contains("Test.Fixture"))
                .and(predicate::str::contains("fixture.bin"))
                .and(predicate::str::contains(hash_of(&fixture.threat)))
                .and(predicate::str::contains(
                    "matches an entry in the signature database",
                ))
                .and(predicate::str::contains("1 from database")),
        );
}

#[test]
fn the_database_can_come_from_the_environment() {
    let fixture = fixture();
    warden()
        .env("WARDEN_SIGDB", &fixture.database)
        .arg("scan")
        .arg(&fixture.tree)
        .assert()
        .code(1);
}

#[test]
fn json_output_is_the_full_report() {
    let fixture = fixture();
    let report_file = fixture.tree.parent().unwrap().join("report.json");
    let output = stdout_of(
        warden()
            .arg("scan")
            .arg(&fixture.tree)
            .arg("--sigdb")
            .arg(&fixture.database)
            .arg("--json")
            .arg("--report")
            .arg(&report_file),
    );
    let json: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(json["schema"], 2);
    assert_eq!(json["stats"]["files_scanned"], 3);
    assert_eq!(json["stats"]["detections"], 1);
    assert_eq!(json["detections"][0]["verdict"], "malicious");
    assert_eq!(json["detections"][0]["findings"][0]["name"], "Test.Fixture");
    assert_eq!(json["detections"][0]["sha256"], hash_of(&fixture.threat));

    let written: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&report_file).unwrap()).unwrap();
    assert_eq!(written["detections"], json["detections"]);
}

#[test]
fn exclusions_are_honoured() {
    let fixture = fixture();
    warden()
        .arg("scan")
        .arg(&fixture.tree)
        .arg("--sigdb")
        .arg(&fixture.database)
        .arg("--exclude")
        .arg(fixture.tree.join("nested"))
        .assert()
        .success()
        .stdout(
            predicate::str::contains("No threats found.")
                .and(predicate::str::contains("Excluded    1")),
        );
}

#[test]
fn impossible_requests_exit_two_with_a_message() {
    let dir = tempfile::tempdir().unwrap();
    warden()
        .arg("scan")
        .arg(dir.path().join("missing"))
        .assert()
        .code(2)
        .stderr(predicate::str::contains("error: cannot scan"));
    warden().arg("scan").assert().code(2);

    let not_a_database = dir.path().join("notes.txt");
    fs::write(&not_a_database, "x".repeat(500)).unwrap();
    warden()
        .arg("scan")
        .arg(dir.path())
        .arg("--sigdb")
        .arg(&not_a_database)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("not a Warden signature database"));
}

#[test]
fn sigdb_build_info_and_lookup_agree() {
    let dir = tempfile::tempdir().unwrap();
    let list = dir.path().join("list.txt");
    let csv = dir.path().join("named.csv");
    let known = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    let named = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    fs::write(&list, format!("{known}\n{known}\ngarbage\n")).unwrap();
    fs::write(
        &csv,
        format!("sha256,name,category\n{named},Adware.Named,pup\n"),
    )
    .unwrap();

    let build = |out: &Path| {
        let mut command = warden();
        command
            .args(["sigdb", "build", "--created", "1800000000", "--out"])
            .arg(out)
            .arg("--hashes")
            .arg(&list)
            .arg("--csv")
            .arg(&csv);
        command
    };
    let first = dir.path().join("first.wdb");
    let second = dir.path().join("second.wdb");
    build(&first).assert().success().stdout(
        predicate::str::contains("entries     2")
            .and(predicate::str::contains("duplicates  1 dropped"))
            .and(predicate::str::contains("1 invalid"))
            .and(predicate::str::contains("created     2027-01-15T08:00:00Z")),
    );
    build(&second).assert().success();
    assert_eq!(
        fs::read(&first).unwrap(),
        fs::read(&second).unwrap(),
        "two builds of the same input with the same creation time must be identical"
    );

    warden()
        .args(["sigdb", "info"])
        .arg(&first)
        .assert()
        .success()
        .stdout(
            predicate::str::contains("format      version 1")
                .and(predicate::str::contains("entries     2"))
                .and(predicate::str::contains("names       2")),
        );
    warden()
        .args(["sigdb", "lookup"])
        .arg(&first)
        .arg(known)
        .assert()
        .success()
        .stdout(predicate::str::contains("found: Malware.Generic (malware)"));
    warden()
        .args(["sigdb", "lookup"])
        .arg(&first)
        .arg(named.to_uppercase())
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "found: Adware.Named (potentially_unwanted)",
        ));
    warden()
        .args(["sigdb", "lookup"])
        .arg(&first)
        .arg("0".repeat(64))
        .assert()
        .code(1)
        .stdout(predicate::str::contains("not found"));
    warden()
        .args(["sigdb", "lookup"])
        .arg(&first)
        .arg("xyz")
        .assert()
        .code(2);
}

#[test]
fn sigdb_build_needs_an_input() {
    let dir = tempfile::tempdir().unwrap();
    warden()
        .args(["sigdb", "build", "--out"])
        .arg(dir.path().join("empty.wdb"))
        .assert()
        .code(2)
        .stderr(predicate::str::contains("nothing to build from"));
}

#[test]
fn hash_prints_published_test_vectors() {
    let dir = tempfile::tempdir().unwrap();
    let abc = dir.path().join("abc.txt");
    let empty = dir.path().join("empty");
    fs::write(&abc, "abc").unwrap();
    fs::write(&empty, "").unwrap();
    warden()
        .arg("hash")
        .arg(&abc)
        .arg(&empty)
        .assert()
        .success()
        .stdout(
            predicate::str::contains(
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            )
            .and(predicate::str::contains(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            )),
        );
    warden()
        .arg("hash")
        .arg(dir.path().join("missing"))
        .assert()
        .code(2);
}

/// The demo flow: write the EICAR test file in its three forms, scan them,
/// and see each one detected by the layer that is meant to catch it.
///
/// Like the engine's on-disk test, this only touches the disk where that is
/// safe to do without setting off a resident antivirus: in the folder named
/// by `WARDEN_EICAR_DIR`, or, on systems other than Windows, in a temporary
/// folder. `WARDEN_REQUIRE_EICAR=1` turns a run that was skipped or blocked
/// into a failure.
#[test]
fn eicar_write_then_scan_detects_every_form() {
    let strict = std::env::var_os("WARDEN_REQUIRE_EICAR").is_some_and(|value| value == "1");
    let not_exercised = |why: &str| {
        let note = format!("EICAR demo flow not exercised: {why}. See docs/TESTING.md.");
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
        Some(base) => base.join(format!("cli-{}", std::process::id())),
        None => temp.path().join("zone"),
    };

    let write = warden()
        .args(["eicar", "write", "--kind", "all"])
        .arg(&dir)
        .assert();
    let written = write.get_output().status.success();
    let scan = warden().arg("scan").arg(&dir).arg("--json").assert();
    let output = scan.get_output().clone();
    for name in ["eicar.com", "eicar-padded.com", "eicar.zip"] {
        let _ = fs::remove_file(dir.join(name));
    }
    let _ = fs::remove_dir(&dir);

    let report: Option<serde_json::Value> = serde_json::from_slice(&output.stdout).ok();
    let scanned = report
        .as_ref()
        .and_then(|json| json["stats"]["files_scanned"].as_u64())
        .unwrap_or(0);
    if !written || scanned < 3 {
        not_exercised("the test files could not be written, or were removed before the scan");
        return;
    }
    let report = report.unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(report["stats"]["detections"], 3);
    assert_eq!(report["stats"]["archives_unpacked"], 1);

    // Detections are sorted by path: eicar-padded.com, eicar.com, eicar.zip.
    let detections = report["detections"].as_array().unwrap();
    let detectors = |index: usize| -> Vec<&str> {
        detections[index]["findings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|finding| finding["detector"].as_str().unwrap())
            .collect()
    };
    for detection in detections {
        assert_eq!(detection["verdict"], "malicious");
        assert_eq!(detection["findings"][0]["name"], "EICAR-Test-File");
        assert_eq!(detection["findings"][0]["category"], "test_file");
    }

    // A line break changes the hash, so only the rule catches the padded form.
    assert!(
        detections[0]["path"]
            .as_str()
            .unwrap()
            .ends_with("eicar-padded.com")
    );
    assert_eq!(detectors(0), ["yara"]);

    // The plain form is known to both layers.
    assert!(
        detections[1]["path"]
            .as_str()
            .unwrap()
            .ends_with("eicar.com")
    );
    assert_eq!(detectors(1), ["hash", "yara"]);
    assert_eq!(
        detections[1]["sha256"],
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    );

    // Inside the zip, the finding names the member.
    assert!(
        detections[2]["path"]
            .as_str()
            .unwrap()
            .ends_with("eicar.zip")
    );
    assert_eq!(detectors(2), ["hash", "yara"]);
    let member = &detections[2]["findings"][0]["member"];
    assert_eq!(member["path"], serde_json::json!(["eicar.com"]));
    assert_eq!(member["size"], 68);
    assert_eq!(
        member["sha256"],
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    );
}

#[test]
fn bench_reports_every_run_as_json_and_text() {
    let fixture = fixture();
    let results_file = fixture.tree.parent().unwrap().join("bench.json");
    let output = stdout_of(
        warden()
            .arg("bench")
            .arg(&fixture.tree)
            .args([
                "--runs",
                "2",
                "--threads",
                "1,2",
                "--label",
                "unit test",
                "--json",
            ])
            .arg("--output")
            .arg(&results_file),
    );
    let json: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(json["schema"], 2);
    assert_eq!(json["label"], "unit test");
    assert!(json["system"]["logical_cpus"].as_u64().unwrap() >= 1);
    let configurations = json["configurations"].as_array().unwrap();
    assert_eq!(configurations.len(), 2);
    assert_eq!(configurations[0]["threads"], 1);
    assert_eq!(configurations[1]["threads"], 2);
    for configuration in configurations {
        let runs = configuration["runs"].as_array().unwrap();
        assert_eq!(runs.len(), 2);
        assert_eq!(runs[0]["files_scanned"], 3);
        assert!(
            configuration["repeat_median_files_per_second"]
                .as_f64()
                .unwrap()
                > 0.0
        );
    }
    // Only the very first run of the benchmark is marked as the first read.
    assert_eq!(configurations[0]["runs"][0]["first"], true);
    assert_eq!(configurations[0]["runs"][1]["first"], false);
    assert_eq!(configurations[1]["runs"][0]["first"], false);
    assert!(results_file.exists());

    warden()
        .arg("bench")
        .arg(&fixture.tree)
        .args(["--runs", "3"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("benchmark")
                .and(predicate::str::contains("first"))
                .and(predicate::str::contains("median"))
                .and(predicate::str::contains("Files/s")),
        );
    // A single run is the first read, so there is nothing to take a median of.
    let single = stdout_of(
        warden()
            .arg("bench")
            .arg(&fixture.tree)
            .args(["--runs", "1", "--json"]),
    );
    let single: serde_json::Value = serde_json::from_str(&single).unwrap();
    assert!(single["configurations"][0]["repeat_median_files_per_second"].is_null());
    warden()
        .arg("bench")
        .arg(&fixture.tree)
        .args(["--runs", "0"])
        .assert()
        .code(2);
}

/// Harmless rules for the tests below: they match marker strings.
const MARKER_RULES: &str = r#"
rule Test_Marker_High
{
    meta:
        description = "contains the high marker"
        score = 90
        license_url = "https://example.test/LICENSE"
    strings:
        $marker = "WARDEN-CLI-HIGH"
    condition:
        $marker
}

rule Test_Marker_Medium
{
    meta:
        score = 70
    strings:
        $marker = "WARDEN-CLI-MEDIUM"
    condition:
        $marker
}

rule Test_Broken
{
    condition:
        this_identifier_does_not_exist
}
"#;

/// Writes the marker rules and compiles them into a bundle.
fn marker_bundle(dir: &Path) -> PathBuf {
    let rules = dir.join("markers.yar");
    fs::write(&rules, MARKER_RULES).unwrap();
    let bundle = dir.join("markers.wrb");
    warden()
        .args(["rules", "build", "--created", "1800000000", "--out"])
        .arg(&bundle)
        .arg(&rules)
        .assert()
        .success();
    bundle
}

#[test]
fn rules_build_and_info_describe_a_bundle() {
    let dir = tempfile::tempdir().unwrap();
    let rules = dir.path().join("markers.yar");
    fs::write(&rules, MARKER_RULES).unwrap();
    let bundle = dir.path().join("markers.wrb");

    warden()
        .args([
            "rules",
            "build",
            "--created",
            "1800000000",
            "--show-skipped",
            "--out",
        ])
        .arg(&bundle)
        .arg(&rules)
        .assert()
        .success()
        .stdout(
            predicate::str::contains("Compiled 3 rules from 2 files")
                .and(predicate::str::contains("warden/builtin.yar: 1 rule"))
                .and(predicate::str::contains("markers.yar: 2 rules, 1 left out"))
                .and(predicate::str::contains(
                    "Left out 1 rule that could not be used.",
                ))
                .and(predicate::str::contains("Test_Broken: "))
                .and(predicate::str::contains("this_identifier_does_not_exist"))
                .and(predicate::str::contains("markers.wrb")),
        );

    warden()
        .args(["rules", "info"])
        .arg(&bundle)
        .assert()
        .success()
        .stdout(
            predicate::str::contains("Rules        3")
                .and(predicate::str::contains(
                    "Built        2027-01-15T08:00:00Z",
                ))
                .and(predicate::str::contains("Engine       yara-x "))
                .and(predicate::str::contains("malicious      for 2 rules"))
                .and(predicate::str::contains("suspicious     for 1 rule "))
                .and(predicate::str::contains("https://example.test/LICENSE"))
                .and(predicate::str::contains("(none named)")),
        );

    let json: serde_json::Value = serde_json::from_str(&stdout_of(
        warden().args(["rules", "info", "--json"]).arg(&bundle),
    ))
    .unwrap();
    assert_eq!(json["rules"], 3);
    assert_eq!(json["created_unix_secs"], 1_800_000_000u64);
    assert_eq!(json["sources"][1]["name"], "markers.yar");
    assert_eq!(json["sources"][1]["rules"], 2);
    assert_eq!(json["sources"][1]["skipped"], 1);
    assert_eq!(json["scores"]["malicious"], 2);
    assert_eq!(json["scores"]["suspicious"], 1);
    assert_eq!(json["digest"].as_str().unwrap().len(), 64);

    // A file that is not a bundle is refused with a clear message.
    warden()
        .args(["rules", "info"])
        .arg(&rules)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("not a Warden rule bundle"));
    // So is a build with nothing to compile.
    warden()
        .args(["rules", "build", "--no-builtin", "--out"])
        .arg(dir.path().join("empty.wrb"))
        .arg(dir.path().join("does-not-exist.yar"))
        .assert()
        .code(2);
}

#[test]
fn a_rule_bundle_adds_detections_and_scores_decide_the_verdict() {
    let dir = tempfile::tempdir().unwrap();
    let bundle = marker_bundle(dir.path());
    let tree = dir.path().join("tree");
    fs::create_dir_all(&tree).unwrap();
    fs::write(tree.join("high.txt"), "text with WARDEN-CLI-HIGH in it").unwrap();
    fs::write(tree.join("medium.txt"), "text with WARDEN-CLI-MEDIUM in it").unwrap();
    fs::write(tree.join("clean.txt"), "text with nothing in it").unwrap();

    // Without the bundle the markers mean nothing.
    warden().arg("scan").arg(&tree).assert().success();

    warden()
        .arg("scan")
        .arg(&tree)
        .arg("--rules")
        .arg(&bundle)
        .assert()
        .code(1)
        .stdout(
            predicate::str::contains("Rules       3 YARA rules from 2 files")
                .and(predicate::str::contains("2 detections"))
                .and(predicate::str::contains("MALICIOUS   Test_Marker_High"))
                .and(predicate::str::contains("SUSPICIOUS  Test_Marker_Medium"))
                .and(predicate::str::contains(
                    "yara [malware]: YARA rule Test_Marker_High matched: contains the high marker",
                ))
                .and(predicate::str::contains(
                    "Patterns found: $marker at offset 0xa",
                )),
        );

    // The bundle can come from the environment, and YARA can be switched off.
    warden()
        .env("WARDEN_RULES", &bundle)
        .arg("scan")
        .arg(&tree)
        .assert()
        .code(1);
    warden()
        .env("WARDEN_RULES", &bundle)
        .arg("scan")
        .arg(&tree)
        .arg("--no-yara")
        .assert()
        .success()
        .stdout(predicate::str::contains("Rules ").not());
}

/// A zip with one member that the fixture database calls a threat, one
/// password-protected member and one clean member.
fn fixture_zip(threat: &[u8]) -> Vec<u8> {
    use std::io::Write as _;
    use zip::unstable::write::FileOptionsExt as _;
    use zip::write::SimpleFileOptions;

    let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let plain = SimpleFileOptions::default();
    writer.start_file("docs/readme.txt", plain).unwrap();
    writer.write_all(b"nothing to see here").unwrap();
    writer.start_file("bin/fixture.bin", plain).unwrap();
    writer.write_all(threat).unwrap();
    writer
        .start_file(
            "locked/secret.bin",
            plain.with_deprecated_encryption(b"password").unwrap(),
        )
        .unwrap();
    writer
        .write_all(b"cannot be read without the password")
        .unwrap();
    writer.finish().unwrap().into_inner()
}

#[test]
fn threats_inside_zip_archives_are_found_and_shown_with_their_place() {
    let fixture = fixture();
    let threat = fs::read(&fixture.threat).unwrap();
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("bundle.zip"), fixture_zip(&threat)).unwrap();

    warden()
        .arg("scan")
        .arg(dir.path())
        .arg("--sigdb")
        .arg(&fixture.database)
        .arg("--show-skipped")
        .assert()
        .code(1)
        .stdout(
            predicate::str::contains("Archives    1 unpacked, 2 files inside")
                .and(predicate::str::contains(
                    "In part     1 file not checked in full (encrypted_archive: 1)",
                ))
                .and(predicate::str::contains("MALICIOUS   Test.Fixture"))
                .and(predicate::str::contains("bundle.zip"))
                .and(predicate::str::contains(
                    "inside: bin/fixture.bin (52 bytes, sha256 ",
                ))
                .and(predicate::str::contains("Files not checked in full"))
                .and(predicate::str::contains(
                    "locked/secret.bin is password-protected",
                )),
        );

    // With archives switched off the zip is only a file, and it is clean.
    warden()
        .arg("scan")
        .arg(dir.path())
        .arg("--sigdb")
        .arg(&fixture.database)
        .arg("--no-archives")
        .assert()
        .success()
        .stdout(predicate::str::contains("Archives ").not());
}

#[test]
fn false_positives_reports_what_was_flagged_in_clean_files() {
    let dir = tempfile::tempdir().unwrap();
    let bundle = marker_bundle(dir.path());
    let tree = dir.path().join("clean-files");
    fs::create_dir_all(&tree).unwrap();
    for index in 0..8 {
        fs::write(
            tree.join(format!("file-{index}.txt")),
            format!("clean file {index}"),
        )
        .unwrap();
    }

    // Nothing flagged: exit code 0 and a rate of zero.
    let results = dir.path().join("fp.json");
    warden()
        .arg("false-positives")
        .arg(&tree)
        .arg("--rules")
        .arg(&bundle)
        .args(["--label", "unit test", "--no-progress", "--output"])
        .arg(&results)
        .assert()
        .success()
        .stdout(
            predicate::str::contains("false-positive check").and(predicate::str::contains(
                "Flagged     0 of 8 files (0.000 %)",
            )),
        );
    let json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&results).unwrap()).unwrap();
    assert_eq!(json["schema"], 1);
    assert_eq!(json["label"], "unit test");
    assert_eq!(json["files_scanned"], 8);
    assert_eq!(json["flagged_malicious"], 0);
    assert_eq!(json["flagged"], serde_json::json!([]));
    assert!(json["system"]["logical_cpus"].as_u64().unwrap() >= 1);

    // Two files that the rules flag although they are "clean" by decree.
    fs::write(tree.join("oops-1.txt"), "WARDEN-CLI-MEDIUM").unwrap();
    fs::write(
        tree.join("oops-2.txt"),
        "WARDEN-CLI-MEDIUM and WARDEN-CLI-HIGH",
    )
    .unwrap();
    let output = warden()
        .arg("fp")
        .arg(&tree)
        .arg("--rules")
        .arg(&bundle)
        .arg("--json")
        .assert()
        .code(1)
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["files_scanned"], 10);
    assert_eq!(json["flagged_malicious"], 1);
    assert_eq!(json["flagged_suspicious"], 1);
    assert_eq!(json["flagged_percent"], 20.0);
    assert_eq!(json["by_name"][0]["name"], "Test_Marker_Medium");
    assert_eq!(json["by_name"][0]["files"], 2);
    assert_eq!(json["by_name"][1]["name"], "Test_Marker_High");
    assert_eq!(json["flagged"].as_array().unwrap().len(), 2);
    assert_eq!(json["flagged"][1]["verdict"], "malicious");
    assert_eq!(
        json["flagged"][1]["names"],
        serde_json::json!(["Test_Marker_High", "Test_Marker_Medium"])
    );
}

/// The whole path of a false positive: a rule flags a clean file, the rule
/// goes on the exclusion list with that file as evidence, and the next
/// bundle no longer flags it.
#[test]
fn a_rule_that_flags_a_clean_file_can_be_excluded_with_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let rules = dir.path().join("markers.yar");
    fs::write(&rules, MARKER_RULES).unwrap();
    let tree = dir.path().join("clean-files");
    fs::create_dir_all(&tree).unwrap();
    let innocent = tree.join("innocent.txt");
    fs::write(&innocent, "a clean file that holds WARDEN-CLI-MEDIUM").unwrap();
    fs::write(tree.join("other.txt"), "another clean file").unwrap();

    // Before: the rule flags the clean file.
    let before = marker_bundle(dir.path());
    let output = warden()
        .arg("false-positives")
        .arg(&tree)
        .arg("--rules")
        .arg(&before)
        .arg("--json")
        .assert()
        .code(1)
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["by_name"][0]["name"], "Test_Marker_Medium");
    let flagged_hash = json["flagged"][0]["sha256"].as_str().unwrap().to_owned();
    assert_eq!(flagged_hash, hash_of(&innocent));

    // The rule goes on the list, with the flagged file as evidence.
    let list = dir.path().join("exclusions.toml");
    fs::write(
        &list,
        format!(
            "[[rule]]\n\
             name = \"Test_Marker_Medium\"\n\
             reason = \"Matches a marker that clean files hold too.\"\n\
             \n\
             [[rule.evidence]]\n\
             file = '{}'\n\
             sha256 = \"{flagged_hash}\"\n\
             seen = 2026-11-18\n\
             machine = \"test suite\"\n\
             \n\
             [[rule]]\n\
             name = \"Test_Marker_Renamed_Since\"\n\
             reason = \"No longer in the rule file.\"\n\
             \n\
             [[rule.evidence]]\n\
             file = 'elsewhere.bin'\n\
             sha256 = \"{flagged_hash}\"\n\
             seen = 2026-11-18\n\
             machine = \"test suite\"\n",
            innocent.display()
        ),
    )
    .unwrap();

    let after = dir.path().join("after.wrb");
    warden()
        .args(["rules", "build", "--created", "1800000000", "--exclusions"])
        .arg(&list)
        .arg("--out")
        .arg(&after)
        .arg(&rules)
        .assert()
        .success()
        .stdout(
            predicate::str::contains("Compiled 2 rules from 2 files")
                .and(predicate::str::contains(
                    "markers.yar: 1 rule, 1 left out, 1 excluded",
                ))
                .and(predicate::str::contains("Excluded 1 rule, named in "))
                .and(predicate::str::contains(
                    "  Test_Marker_Medium (in markers.yar)",
                ))
                .and(predicate::str::contains(
                    "The list also names 1 rule that no rule file declares:",
                ))
                .and(predicate::str::contains("  Test_Marker_Renamed_Since"))
                .and(predicate::str::contains(
                    "Left out 1 rule that could not be used.",
                )),
        );

    // The bundle says what was left out, and by which list.
    let list_hash = hash_of(&list);
    warden()
        .args(["rules", "info"])
        .arg(&after)
        .assert()
        .success()
        .stdout(
            predicate::str::contains("Rules        2")
                .and(predicate::str::contains(
                    "markers.yar: 1 rule, 1 left out, 1 excluded",
                ))
                .and(predicate::str::contains(
                    "Excluded on purpose\n  Test_Marker_Medium\n",
                ))
                .and(predicate::str::contains(format!(
                    "named by the exclusion list with sha256 {list_hash}"
                ))),
        );
    let json: serde_json::Value = serde_json::from_str(&stdout_of(
        warden().args(["rules", "info", "--json"]).arg(&after),
    ))
    .unwrap();
    assert_eq!(json["exclusions"]["sha256"], list_hash.as_str());
    assert_eq!(
        json["exclusions"]["rules"],
        serde_json::json!(["Test_Marker_Medium"])
    );
    assert_eq!(json["sources"][1]["excluded"], 1);
    // A bundle that was built without a list has no such record.
    let json: serde_json::Value = serde_json::from_str(&stdout_of(
        warden().args(["rules", "info", "--json"]).arg(&before),
    ))
    .unwrap();
    assert_eq!(json["exclusions"], serde_json::Value::Null);
    warden()
        .args(["rules", "info"])
        .arg(&before)
        .assert()
        .success()
        .stdout(predicate::str::contains("Excluded").not());

    // After: the clean file is no longer flagged, and the report shows
    // that a rule was left out on purpose.
    let output = warden()
        .arg("false-positives")
        .arg(&tree)
        .arg("--rules")
        .arg(&after)
        .arg("--json")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["files_scanned"], 2);
    assert_eq!(json["flagged"], serde_json::json!([]));
    let yara = json["detectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|detector| detector["id"] == "yara")
        .unwrap();
    assert_eq!(yara["details"]["rules"], 2);
    assert_eq!(yara["details"]["rules_excluded"], 1);
    warden()
        .arg("scan")
        .arg(&tree)
        .arg("--rules")
        .arg(&after)
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Rules       2 YARA rules from 2 files, 1 excluded",
        ));
    // The other rule of the file still works.
    fs::write(tree.join("high.txt"), "WARDEN-CLI-HIGH").unwrap();
    warden()
        .arg("scan")
        .arg(&tree)
        .arg("--rules")
        .arg(&after)
        .assert()
        .code(1)
        .stdout(predicate::str::contains("MALICIOUS   Test_Marker_High"));
}

#[test]
fn an_exclusion_list_that_cannot_be_used_stops_the_build() {
    let dir = tempfile::tempdir().unwrap();
    let rules = dir.path().join("markers.yar");
    fs::write(&rules, MARKER_RULES).unwrap();
    let out = dir.path().join("never-written.wrb");
    let build_with = |list: &Path| {
        let mut command = warden();
        command
            .args(["rules", "build", "--exclusions"])
            .arg(list)
            .arg("--out")
            .arg(&out)
            .arg(&rules);
        command
    };
    let entry = |name: &str, evidence: bool| {
        let mut text = format!("[[rule]]\nname = \"{name}\"\nreason = \"For a test.\"\n");
        if evidence {
            text.push_str(&format!(
                "[[rule.evidence]]\nfile = 'a.bin'\nsha256 = \"{}\"\nseen = 2026-11-18\nmachine = \"test suite\"\n",
                "0".repeat(64)
            ));
        }
        text
    };
    let list = dir.path().join("exclusions.toml");

    // No list at that path.
    build_with(&list)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("cannot use the exclusion list"));

    // An entry that only claims a rule is noisy.
    fs::write(&list, entry("Test_Marker_Medium", false)).unwrap();
    build_with(&list)
        .assert()
        .code(2)
        .stderr(
            predicate::str::contains("exclusions.toml").and(predicate::str::contains(
                "Test_Marker_Medium has no evidence",
            )),
        );

    // A misspelt field.
    fs::write(
        &list,
        entry("Test_Marker_Medium", true).replace("reason", "raeson"),
    )
    .unwrap();
    build_with(&list)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("raeson"));

    // A rule that must stay.
    fs::write(&list, entry("Warden_EICAR_Test_File", true)).unwrap();
    build_with(&list)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("built into Warden"));

    assert!(!out.exists());
}

/// `warden inspect` shows what the heuristics see. The executables are
/// inert fixtures, handed over on standard input so that nothing that looks
/// packed is ever written to disk on a machine with an antivirus.
#[test]
fn inspect_shows_the_structure_and_every_indicator_that_applies() {
    let packed = warden_pe::fixture::Fixture::packed_looking().build();
    let output = warden()
        .args(["inspect", "-"])
        .write_stdin(packed.clone())
        .assert()
        .get_output()
        .clone();
    let text = String::from_utf8(output.stdout).unwrap();
    for expected in [
        "File        (standard input)",
        "Size        17,408 bytes",
        "Kind        Windows program, 32-bit, x86, console",
        "Linked      the header gives no time",
        "Entry point 0xdf00, in section \"UPX1\"",
        "  UPX0                   0        36,864  rwx-     0.00",
        "  UPX1              16,384        16,384  rwx-     7.99",
        "Imports     3 functions from 1 library",
        "  KERNEL32.DLL (3): LoadLibraryA, GetProcAddress, ExitProcess",
        "Tables      imports",
        "Rich header absent",
        "Signature   none embedded",
        "After the last section: nothing",
        "A section has a name that a packer or protector writes: sections \"UPX0\", \"UPX1\", \"UPX2\"",
        "An executable section looks compressed or encrypted: section \"UPX1\" has an entropy of 7.99 bits per byte",
        "The imports are little more than what is needed to load other functions: imports LoadLibraryA and GetProcAddress",
        "   +10  A section is both writable and executable: sections \"UPX0\", \"UPX1\"",
        "    +9  An executable section looks compressed or encrypted",
        "Also seen, and not scored",
        "     ·  A section has a name that a packer or protector writes",
        "Score       28",
        "Verdict     not suspicious: a file counts as suspicious from a score of 32",
        "docs/HEURISTICS.md",
    ] {
        assert!(text.contains(expected), "missing {expected:?} in:\n{text}");
    }
    assert!(text.contains(&sha256_hex(&packed)), "{text}");
    // Packed, and nothing else: that is not suspicious, and not a failure.
    assert!(output.status.success());

    // The same as JSON: the facts and the assessment in full.
    let json: serde_json::Value = serde_json::from_str(&stdout_of(
        warden()
            .args(["inspect", "-", "--json"])
            .write_stdin(packed),
    ))
    .unwrap();
    assert_eq!(json["schema"], 1);
    assert_eq!(json["windows_executable"], true);
    assert_eq!(json["size_bytes"], 17_408);
    assert_eq!(json["facts"]["format"], "pe32");
    assert_eq!(json["facts"]["sections"][1]["name"], "UPX1");
    assert_eq!(
        json["facts"]["imports"][0]["functions"][1],
        "GetProcAddress"
    );
    let hits: Vec<&str> = json["assessment"]["hits"]
        .as_array()
        .unwrap()
        .iter()
        .map(|hit| hit["indicator"]["id"].as_str().unwrap())
        .collect();
    assert!(hits.contains(&"sections.packer_name"), "{hits:?}");
    assert!(
        hits.contains(&"sections.writable_and_executable"),
        "{hits:?}"
    );
    let first = &json["assessment"]["hits"][0];
    assert!(first["indicator"]["rationale"].as_str().unwrap().len() > 60);
    assert!(first["detail"].as_str().unwrap().contains("UPX0"));
    assert_eq!(first["indicator"]["weight"], 0);
    assert_eq!(json["assessment"]["score"], 28);
    assert_eq!(json["assessment"]["suspicious_from"], 32);
    assert_eq!(json["assessment"]["suspicious"], false);
}

/// A file whose score reaches the threshold: `inspect` says so, lists what
/// the score is made of, and ends with the exit code of a detection.
#[test]
fn inspect_calls_a_file_suspicious_when_its_score_reaches_the_threshold() {
    let file = warden_pe::fixture::Fixture::suspicious_looking().build();
    let output = warden()
        .args(["inspect", "-"])
        .write_stdin(file.clone())
        .assert()
        .code(1)
        .get_output()
        .clone();
    let text = String::from_utf8(output.stdout).unwrap();
    for expected in [
        "Imports     0 functions from 0 libraries",
        "After the last section: 16,384 bytes with an entropy of 7.99",
        "   +10  A section is both writable and executable",
        "    +8  The program imports nothing: the import table is empty or missing",
        "    +5  A quarter of the file or more sits after the last section",
        "Score       41",
        "Verdict     suspicious: a file counts as suspicious from a score of 32",
        "It is not proof of",
    ] {
        assert!(text.contains(expected), "missing {expected:?} in:\n{text}");
    }

    let json: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(
        &warden()
            .args(["inspect", "-", "--json"])
            .write_stdin(file)
            .assert()
            .code(1)
            .get_output()
            .stdout,
    ))
    .unwrap();
    assert_eq!(json["assessment"]["score"], 41);
    assert_eq!(json["assessment"]["suspicious"], true);
    // The weights of the scored hits add up to the score.
    let sum: u64 = json["assessment"]["hits"]
        .as_array()
        .unwrap()
        .iter()
        .map(|hit| hit["indicator"]["weight"].as_u64().unwrap())
        .sum();
    assert_eq!(sum, 41);
}

/// The heuristic layer in a scan. The files are inert fixtures, but two of
/// them look packed, so they are written only where the EICAR test file may
/// be written: see `eicar_write_then_scan_detects_every_form`.
#[test]
fn scan_reports_a_suspicious_structure_and_says_what_it_is_made_of() {
    use warden_pe::fixture::Fixture;

    let strict = std::env::var_os("WARDEN_REQUIRE_EICAR").is_some_and(|value| value == "1");
    let configured = std::env::var_os("WARDEN_EICAR_DIR")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from);
    if cfg!(windows) && configured.is_none() {
        let note = "heuristic scan not exercised: WARDEN_EICAR_DIR is not set to an antivirus-excluded folder. See docs/TESTING.md.";
        assert!(!strict, "{note}");
        eprintln!("note: {note}");
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let dir = match &configured {
        Some(base) => base.join(format!("heuristic-{}", std::process::id())),
        None => temp.path().join("zone"),
    };
    fs::create_dir_all(&dir).unwrap();
    let files = [
        ("plain.exe", Fixture::plain().build()),
        ("packed-looking.exe", Fixture::packed_looking().build()),
        (
            "suspicious-looking.exe",
            Fixture::suspicious_looking().build(),
        ),
        // The same file inside an archive.
        (
            "bundle.zip",
            fixture_zip(&Fixture::suspicious_looking().build()),
        ),
    ];
    for (name, content) in &files {
        fs::write(dir.join(name), content).unwrap();
    }

    let json = warden().arg("scan").arg(&dir).arg("--json").assert();
    let json = json.get_output().clone();
    let text = warden().arg("scan").arg(&dir).assert();
    let text = text.get_output().clone();
    let without = warden()
        .arg("scan")
        .arg(&dir)
        .arg("--no-heuristics")
        .assert();
    let without = without.get_output().clone();
    for (name, _) in &files {
        let _ = fs::remove_file(dir.join(name));
    }
    let _ = fs::remove_dir(&dir);

    assert_eq!(json.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(report["stats"]["files_scanned"], 4);
    let detections = report["detections"].as_array().unwrap();
    // Sorted by path: bundle.zip, suspicious-looking.exe. The plain and the
    // packed-looking file are not among them.
    assert_eq!(detections.len(), 2, "{report:#}");
    for (detection, name) in detections
        .iter()
        .zip(["bundle.zip", "suspicious-looking.exe"])
    {
        assert!(detection["path"].as_str().unwrap().ends_with(name));
        assert_eq!(detection["verdict"], "suspicious");
        let finding = &detection["findings"][0];
        assert_eq!(finding["detector"], "heuristic");
        assert_eq!(finding["name"], "Heuristic.SuspiciousExecutable");
        assert_eq!(finding["confidence"], "medium");
        assert_eq!(
            finding["reasons"][0],
            "The structure of the file scores 41; a file counts as suspicious from 32"
        );
        assert_eq!(
            finding["reasons"][1],
            "+10 A section is both writable and executable: sections \"UPX0\", \"UPX1\""
        );
    }
    assert_eq!(
        detections[0]["findings"][0]["member"]["path"],
        serde_json::json!(["bin/fixture.bin"])
    );
    assert_eq!(
        detections[1]["findings"][0]["member"],
        serde_json::Value::Null
    );
    let heuristic = report["detectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|detector| detector["id"] == "heuristic")
        .unwrap();
    assert_eq!(heuristic["details"]["suspicious_from"], 32);

    assert_eq!(text.status.code(), Some(1));
    let text = String::from_utf8(text.stdout).unwrap();
    for expected in [
        "Heuristics  13 scored indicators of a Windows executable's structure, suspicious from a score of 32",
        "2 detections",
        "SUSPICIOUS  Heuristic.SuspiciousExecutable",
        "+8 The program imports nothing: the import table is empty or missing",
    ] {
        assert!(text.contains(expected), "missing {expected:?} in:\n{text}");
    }
    assert!(!text.contains("MALICIOUS"), "{text}");

    // Without the layer nothing is left to report.
    assert_eq!(without.status.code(), Some(0));
    let without = String::from_utf8(without.stdout).unwrap();
    assert!(without.contains("No threats found."), "{without}");
    assert!(!without.contains("Heuristics"), "{without}");
}

#[test]
fn inspect_finds_little_in_an_ordinary_program() {
    let plain = warden_pe::fixture::Fixture::plain().build();
    let text = stdout_of(warden().args(["inspect", "-"]).write_stdin(plain.clone()));
    for expected in [
        "Kind        Windows program, 64-bit, x64, console",
        "Linked      2025-01-01T00:00:00Z, as the header claims",
        "Entry point 0x1000, in section \".text\"",
        "  .text             12,288        12,288  r-xc     6.46",
        "Imports     27 functions from 2 libraries",
        "GetCommandLineW, GetModuleHandleW, GetStdHandle, WriteFile, CreateFileW, ReadFile, CloseHandle, GetLastError, and 16 more",
        "Tables      imports, resources, exception handling, relocations, debug, load configuration",
        "Rich header present",
    ] {
        assert!(text.contains(expected), "missing {expected:?} in:\n{text}");
    }
    assert!(!text.contains("packer"), "{text}");
    // --all lists every import.
    let text = stdout_of(warden().args(["inspect", "-", "--all"]).write_stdin(plain));
    assert!(text.contains("RtlVirtualUnwind"), "{text}");
    assert!(!text.contains("more"), "{text}");
}

#[test]
fn inspect_says_so_when_a_file_is_not_a_windows_executable() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("notes.txt");
    fs::write(&path, "MZ is how this text file happens to start, and then it goes on for more than sixty-four bytes.").unwrap();
    warden()
        .arg("inspect")
        .arg(&path)
        .assert()
        .success()
        .stdout(
            predicate::str::contains("notes.txt")
                .and(predicate::str::contains(
                    "Kind        not a Windows executable: there is no PE header where the DOS header points",
                ))
                .and(predicate::str::contains("have nothing to say")),
        );
    let json: serde_json::Value =
        serde_json::from_str(&stdout_of(warden().arg("inspect").arg(&path).arg("--json"))).unwrap();
    assert_eq!(json["windows_executable"], false);
    assert_eq!(
        json["not_an_executable_because"],
        "there is no PE header where the DOS header points"
    );
    assert_eq!(json["facts"], serde_json::Value::Null);
    assert_eq!(json["sha256"], hash_of(&path).as_str());

    warden()
        .arg("inspect")
        .arg(dir.path().join("missing.exe"))
        .assert()
        .code(2)
        .stderr(predicate::str::contains("cannot open"));
}

/// Section names and import names come from the file. A file that puts
/// terminal control codes there must not get them printed.
#[test]
fn inspect_does_not_pass_on_control_characters_from_the_file() {
    let mut fixture = warden_pe::fixture::Fixture::plain();
    fixture.sections[1].name = "\u{1b}[2J\u{7}".to_owned();
    let text = stdout_of(warden().args(["inspect", "-"]).write_stdin(fixture.build()));
    assert!(!text.contains('\u{1b}'), "{text:?}");
    assert!(!text.contains('\u{7}'), "{text:?}");
    assert!(text.contains("\u{fffd}[2J\u{fffd}"), "{text}");
}

/// A file name can hold characters that would rewrite the terminal. The
/// text report must not pass them through. (Windows does not allow such
/// names, so this can only be tried elsewhere.)
#[cfg(unix)]
#[test]
fn control_characters_in_file_names_do_not_reach_the_terminal() {
    let fixture = fixture();
    let threat = fs::read(&fixture.threat).unwrap();
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("evil\u{1b}[2Jname.bin"), threat).unwrap();

    let text = stdout_of(
        warden()
            .arg("scan")
            .arg(dir.path())
            .arg("--sigdb")
            .arg(&fixture.database),
    );
    assert!(text.contains("MALICIOUS   Test.Fixture"));
    assert!(text.contains("evil\u{fffd}[2Jname.bin"));
    assert!(!text.contains('\u{1b}'));

    // The JSON report keeps the real name, escaped as JSON requires.
    let json = stdout_of(
        warden()
            .arg("scan")
            .arg(dir.path())
            .arg("--sigdb")
            .arg(&fixture.database)
            .arg("--json"),
    );
    assert!(json.contains("evil\\u001b[2Jname.bin"));
}

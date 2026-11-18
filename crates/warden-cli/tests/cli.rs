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
        .env_remove("SOURCE_DATE_EPOCH");
    command
}

fn stdout_of(command: &mut Command) -> String {
    String::from_utf8(command.assert().get_output().stdout.clone()).unwrap()
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
    assert_eq!(json["schema"], 1);
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

/// The demo flow: write the EICAR test file, scan it, see it detected.
///
/// Like the engine's on-disk test, this only touches the disk where that is
/// safe to do without setting off a resident antivirus: in the folder named
/// by `WARDEN_EICAR_DIR`, or, on systems other than Windows, in a temporary
/// folder. `WARDEN_REQUIRE_EICAR=1` turns a run that was skipped or blocked
/// into a failure.
#[test]
fn eicar_write_then_scan_detects_it() {
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

    let write = warden().args(["eicar", "write"]).arg(&dir).assert();
    let written = write.get_output().status.success();
    let scan = warden().arg("scan").arg(&dir).arg("--json").assert();
    let output = scan.get_output().clone();
    let _ = fs::remove_file(dir.join("eicar.com"));
    let _ = fs::remove_dir(&dir);

    let report: Option<serde_json::Value> = serde_json::from_slice(&output.stdout).ok();
    let scanned = report
        .as_ref()
        .and_then(|json| json["stats"]["files_scanned"].as_u64())
        .unwrap_or(0);
    if !written || scanned == 0 {
        not_exercised("the test file could not be written, or was removed before the scan");
        return;
    }
    let report = report.unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        report["detections"][0]["findings"][0]["name"],
        "EICAR-Test-File"
    );
    assert_eq!(
        report["detections"][0]["findings"][0]["category"],
        "test_file"
    );
    assert_eq!(
        report["detections"][0]["sha256"],
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

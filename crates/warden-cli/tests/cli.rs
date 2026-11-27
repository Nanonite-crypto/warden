//! Tests of the `warden` binary as a user would run it.

#![allow(clippy::unwrap_used)]
// The program itself may not print with `eprintln!` (see clippy.toml); a test
// that says why it was skipped may.
#![allow(clippy::disallowed_macros)]

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
        .env_remove("WARDEN_QUARANTINE")
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

/// SHA-256 of a file, as printed by `warden hash`. If the program prints
/// none, what it said instead is the message of the failure.
fn hash_of(path: &Path) -> String {
    let output = warden().arg("hash").arg(path).assert().get_output().clone();
    let printed = String::from_utf8_lossy(&output.stdout);
    match printed.split_whitespace().next() {
        Some(digest) => digest.to_owned(),
        None => panic!(
            "`warden hash {}` printed no digest, but: {}",
            path.display(),
            String::from_utf8_lossy(&output.stderr)
        ),
    }
}

/// Reads a file that was written a moment ago, and waits a little if it is
/// not handed out at once. On a machine with a resident antivirus that can
/// happen: the antivirus looks at what was written, and for that moment
/// Windows may refuse the file to others. Returns the bytes, if they could
/// be read within ten seconds, and what Windows said each time it
/// refused, with its error number: a caller that passes still has it to
/// show, and one that fails has its reason.
fn read_patiently(path: &Path) -> (Option<Vec<u8>>, Vec<String>) {
    let mut refusals: Vec<String> = Vec::new();
    let mut last = String::new();
    for attempt in 1..=100 {
        match fs::read(path) {
            Ok(bytes) => return (Some(bytes), refusals),
            Err(error) => {
                let said = error.to_string();
                // The same answer again is not written down again.
                if said != last {
                    refusals.push(format!("attempt {attempt}: {said}"));
                    last = said;
                }
                if error.kind() == std::io::ErrorKind::NotFound {
                    // Nothing to wait for: the file is not there.
                    break;
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    (None, refusals)
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
    assert_eq!(json["schema"], 5);
    assert_eq!(json["stats"]["files_scanned"], 3);
    assert_eq!(json["stats"]["detections"], 1);
    // The scan says what it would have asked who signed a file. A hash
    // match yields to no signature, so nobody was asked.
    assert_eq!(json["trust_check"]["available"], cfg!(windows));
    assert!(json["trust_check"]["publishers"].as_u64().unwrap() >= 1);
    assert_eq!(
        json["trust_check"]["trust_list"].as_str().unwrap().len(),
        64
    );
    assert_eq!(json["stats"]["trust_checks"], 0);
    assert!(json["detections"][0].get("trust").is_none());
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

/// Called by a test that took the right to list a folder away and found
/// that this process can list it all the same. There is nothing to test
/// then.
///
/// Access rights do not apply to root on Unix. On Windows they do not apply
/// to the listing of folders for a process whose backup privilege is
/// switched on, and the Git Bash of an administrator switches it on for
/// every program it starts, `warden` included.
///
/// The test passes with a note. `WARDEN_REQUIRE_ACCESS_TESTS=1` turns the
/// note into a failure; CI sets it, so that these tests run for real there.
fn access_rights_do_not_apply(what: &str) {
    let note = format!(
        "{what} was not exercised: access rights do not apply to this process. \
         See docs/TESTING.md."
    );
    let strict = std::env::var_os("WARDEN_REQUIRE_ACCESS_TESTS").is_some_and(|value| value == "1");
    assert!(!strict, "{note}");
    eprintln!("note: {note}");
}

/// Makes a folder impossible to list, the way `C:\Program Files\WindowsApps`
/// is for a program without administrator rights. Says `false` if this
/// process can list it all the same, see [`access_rights_do_not_apply`].
#[cfg(unix)]
fn close_folder(folder: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(folder, fs::Permissions::from_mode(0o000)).unwrap();
    if fs::read_dir(folder).is_ok() {
        open_folder(folder);
        return false;
    }
    true
}

#[cfg(unix)]
fn open_folder(folder: &Path) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(folder, fs::Permissions::from_mode(0o700)).unwrap();
}

#[cfg(windows)]
fn icacls(folder: &Path, arguments: &[&str]) {
    let status = std::process::Command::new("icacls")
        .arg(folder)
        .args(arguments)
        .stdout(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "icacls {arguments:?}");
}

/// Everyone (S-1-1-0) is denied the right to list the folder. A denial comes
/// before every permission, an administrator's included. Says `false` if
/// this process can list the folder all the same, see
/// [`access_rights_do_not_apply`].
#[cfg(windows)]
fn close_folder(folder: &Path) -> bool {
    icacls(folder, &["/deny", "*S-1-1-0:(RD)"]);
    if fs::read_dir(folder).is_ok() {
        open_folder(folder);
        return false;
    }
    true
}

#[cfg(windows)]
fn open_folder(folder: &Path) {
    icacls(folder, &["/remove:d", "*S-1-1-0"]);
}

#[test]
fn a_folder_that_cannot_be_opened_is_named_and_counted_apart_from_files() {
    let dir = tempfile::tempdir().unwrap();
    let tree = dir.path().join("tree");
    let closed = tree.join("closed");
    fs::create_dir_all(closed.join("deeper")).unwrap();
    fs::write(tree.join("open.txt"), "one file that can be read").unwrap();
    for name in ["a.txt", "b.txt", "deeper/c.txt"] {
        fs::write(closed.join(name), "three files that cannot").unwrap();
    }
    if !close_folder(&closed) {
        access_rights_do_not_apply("a folder that cannot be opened");
        return;
    }

    let check = warden()
        .arg("false-positives")
        .arg(&tree)
        .arg("--json")
        .output()
        .unwrap();
    let check_text = warden()
        .arg("false-positives")
        .arg(&tree)
        .arg("--no-progress")
        .output()
        .unwrap();
    let scan = warden()
        .arg("scan")
        .arg(&tree)
        .arg("--show-skipped")
        .output()
        .unwrap();
    let bench = warden()
        .arg("bench")
        .arg(&tree)
        .args(["--runs", "1", "--json"])
        .output()
        .unwrap();
    // Before anything can fail: the temporary folder has to go away again.
    open_folder(&closed);

    // One file was scanned. The folder is one entry, and it is not a file.
    assert_eq!(check.status.code(), Some(0));
    let json: serde_json::Value = serde_json::from_slice(&check.stdout).unwrap();
    assert_eq!(json["files_scanned"], 1);
    assert_eq!(json["files_skipped"], 0);
    assert_eq!(json["folders_skipped"], 1);
    let skipped = json["skipped"].as_array().unwrap();
    assert_eq!(skipped.len(), 1);
    assert_eq!(skipped[0]["folder"], true);
    assert_eq!(skipped[0]["reason"], "access_denied");
    assert!(skipped[0]["path"].as_str().unwrap().ends_with("closed"));
    assert!(!skipped[0]["detail"].as_str().unwrap().is_empty());
    assert_eq!(json["skipped_truncated"], false);

    let text = String::from_utf8(check_text.stdout).unwrap();
    assert!(
        text.contains("Not covered 1 folder could not be opened\n"),
        "{text}"
    );
    assert!(
        text.contains("was not scanned and is not counted."),
        "{text}"
    );
    let listed = text
        .split("Folders that could not be opened\n")
        .nth(1)
        .unwrap_or_else(|| panic!("{text}"));
    assert!(listed.starts_with("  access_denied  "), "{text}");
    assert!(listed.lines().next().unwrap().ends_with("closed"), "{text}");
    assert!(!text.contains("Files that could not be read"), "{text}");

    assert_eq!(scan.status.code(), Some(0));
    let text = String::from_utf8(scan.stdout).unwrap();
    assert!(
        text.contains("Skipped     1 folder (access_denied: 1)\n"),
        "{text}"
    );
    assert!(
        text.contains("What is in a folder that could not be opened was not scanned."),
        "{text}"
    );
    assert!(
        text.contains("Folders that could not be opened\n  access_denied  "),
        "{text}"
    );
    assert!(!text.contains("Skipped files"), "{text}");

    let json: serde_json::Value = serde_json::from_slice(&bench.stdout).unwrap();
    let run = &json["configurations"][0]["runs"][0];
    assert_eq!(run["files_scanned"], 1);
    assert_eq!(run["files_skipped"], 0);
    assert_eq!(run["folders_skipped"], 1);
}

/// Runs `warden` with a standard output, or a standard error, whose reader
/// has already left: `warden … | head` after `head` has had enough.
fn run_with_closed(
    stream: fn(&mut std::process::Command, std::io::PipeWriter),
    arguments: &[&std::ffi::OsStr],
) -> std::process::Output {
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_warden"));
    command
        .args(arguments)
        .env_remove("WARDEN_SIGDB")
        .env_remove("WARDEN_RULES")
        .env_remove("WARDEN_QUARANTINE")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    stream(&mut command, writer);
    command.spawn().unwrap().wait_with_output().unwrap()
}

#[test]
fn a_reader_that_leaves_ends_the_command_quietly() {
    let fixture = fixture();
    let commands: [&[&std::ffi::OsStr]; 5] = [
        // One line.
        &["hash".as_ref(), fixture.threat.as_os_str()],
        // A report, as text and as JSON.
        &["scan".as_ref(), fixture.tree.as_os_str()],
        &["scan".as_ref(), "--json".as_ref(), fixture.tree.as_os_str()],
        // Many lines, one write each.
        &[
            "sigdb".as_ref(),
            "info".as_ref(),
            fixture.database.as_os_str(),
        ],
        &["false-positives".as_ref(), fixture.tree.as_os_str()],
    ];
    for arguments in commands {
        let output = run_with_closed(
            |command, writer| {
                command.stdout(writer);
            },
            arguments,
        );
        // Not 0 and not 1: the command did not get to say what it found.
        // And not 101, which is how a panic ends.
        assert_eq!(output.status.code(), Some(2), "{arguments:?}");
        assert_eq!(String::from_utf8_lossy(&output.stderr), "", "{arguments:?}");
    }
}

#[test]
fn a_closed_error_stream_does_not_turn_an_error_into_a_panic() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("not-here");
    let output = run_with_closed(
        |command, writer| {
            command.stderr(writer);
        },
        &["hash".as_ref(), missing.as_os_str()],
    );
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(String::from_utf8_lossy(&output.stdout), "");
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
    assert_eq!(json["schema"], 4);
    assert_eq!(json["label"], "unit test");
    assert!(json["system"]["logical_cpus"].as_u64().unwrap() >= 1);
    assert_eq!(json["trust_check"]["available"], cfg!(windows));
    let configurations = json["configurations"].as_array().unwrap();
    assert_eq!(configurations.len(), 2);
    assert_eq!(configurations[0]["threads"], 1);
    assert_eq!(configurations[1]["threads"], 2);
    for configuration in configurations {
        let runs = configuration["runs"].as_array().unwrap();
        assert_eq!(runs.len(), 2);
        assert_eq!(runs[0]["files_scanned"], 3);
        assert_eq!(runs[0]["trust_checks"], 0);
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
                .and(predicate::str::contains("markers.wrb"))
                .and(predicate::str::contains("contents under a cipher")),
        );

    warden()
        .args(["rules", "info"])
        .arg(&bundle)
        .assert()
        .success()
        .stdout(
            predicate::str::contains("Rules        3")
                .and(predicate::str::contains(
                    "Format       version 2, contents under a cipher",
                ))
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
    assert_eq!(json["format_version"], 2);
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

/// Whether `needle` occurs anywhere in `haystack`.
fn holds(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[test]
fn a_bundle_is_written_under_a_cipher_unless_plain_is_asked_for() {
    let dir = tempfile::tempdir().unwrap();
    let sealed = marker_bundle(dir.path());
    let rules = dir.path().join("markers.yar");
    let plain = dir.path().join("plain.wrb");
    warden()
        .args([
            "rules",
            "build",
            "--plain",
            "--created",
            "1800000000",
            "--out",
        ])
        .arg(&plain)
        .arg(&rules)
        .assert()
        .success()
        .stdout(
            predicate::str::contains("contents as they are")
                .and(predicate::str::contains("An antivirus may take a bundle")),
        );

    // What the rules look for can be read in the plain bundle and not in
    // the other one. That is what an antivirus goes by.
    let sealed_bytes = fs::read(&sealed).unwrap();
    let plain_bytes = fs::read(&plain).unwrap();
    for pattern in [
        &b"WARDEN-CLI-HIGH"[..],
        b"WARDEN-CLI-MEDIUM",
        b"markers.yar",
    ] {
        let shown = String::from_utf8_lossy(pattern);
        assert!(holds(&plain_bytes, pattern), "{shown} in the plain bundle");
        assert!(
            !holds(&sealed_bytes, pattern),
            "{shown} in the sealed bundle"
        );
    }

    // `rules info` says which is which, and describes the same rules.
    let info_of = |bundle: &Path| -> serde_json::Value {
        serde_json::from_str(&stdout_of(
            warden().args(["rules", "info", "--json"]).arg(bundle),
        ))
        .unwrap()
    };
    let (sealed_info, plain_info) = (info_of(&sealed), info_of(&plain));
    assert_eq!(sealed_info["format_version"], 2);
    assert_eq!(plain_info["format_version"], 1);
    for field in ["rules", "created_unix_secs", "engine", "sources", "scores"] {
        assert_eq!(sealed_info[field], plain_info[field], "{field}");
    }
    assert_ne!(sealed_info["digest"], plain_info["digest"]);
    warden()
        .args(["rules", "info"])
        .arg(&plain)
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Format       version 1, contents as they are",
        ));

    // A scan finds the same with either.
    let tree = dir.path().join("tree");
    fs::create_dir_all(&tree).unwrap();
    fs::write(tree.join("high.txt"), "text with WARDEN-CLI-HIGH in it").unwrap();
    fs::write(tree.join("clean.txt"), "text with nothing in it").unwrap();
    for bundle in [&sealed, &plain] {
        warden()
            .arg("scan")
            .arg(&tree)
            .arg("--rules")
            .arg(bundle)
            .assert()
            .code(1)
            .stdout(
                predicate::str::contains("Rules       3 YARA rules from 2 files")
                    .and(predicate::str::contains("1 detection"))
                    .and(predicate::str::contains("MALICIOUS   Test_Marker_High")),
            );
    }

    // Built a second time, by another run of the program, a bundle comes
    // out the same byte for byte.
    let again = dir.path().join("again.wrb");
    warden()
        .args(["rules", "build", "--created", "1800000000", "--out"])
        .arg(&again)
        .arg(&rules)
        .assert()
        .success();
    assert_eq!(fs::read(&again).unwrap(), sealed_bytes);
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
    assert_eq!(json["schema"], 4);
    assert_eq!(json["label"], "unit test");
    assert_eq!(json["trust_check"]["available"], cfg!(windows));
    assert_eq!(json["trust_checks"], 0);
    assert_eq!(json["files_trusted"], 0);
    assert_eq!(json["files_scanned"], 8);
    assert_eq!(json["flagged_malicious"], 0);
    assert_eq!(json["flagged"], serde_json::json!([]));
    assert_eq!(json["recorded_files"], 0);
    assert_eq!(json["recorded"], serde_json::json!([]));
    assert_eq!(json["recorded_truncated"], false);
    assert_eq!(json["files_skipped"], 0);
    assert_eq!(json["folders_skipped"], 0);
    assert_eq!(json["skipped"], serde_json::json!([]));
    assert_eq!(json["skipped_truncated"], false);
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
    // Where signatures can be checked, the check was asked about both
    // files before they were reported, and found nothing: they are text.
    if cfg!(windows) {
        assert_eq!(json["trust_checks"], 2);
        assert_eq!(json["files_trusted"], 0);
        for flagged in json["flagged"].as_array().unwrap() {
            assert_eq!(flagged["trust"]["answer"], "not_trusted");
            assert_eq!(flagged["trust"]["reason"], "no_signature");
        }
    } else {
        assert_eq!(json["trust_checks"], 0);
        assert!(json["flagged"][0].get("trust").is_none());
    }

    // With the check switched off, the result says so by saying nothing.
    let output = warden()
        .arg("fp")
        .arg(&tree)
        .arg("--rules")
        .arg(&bundle)
        .args(["--no-trust", "--json"])
        .assert()
        .code(1)
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert!(json["trust_check"].is_null());
    assert_eq!(json["trust_checks"], 0);
    assert!(json["flagged"][0].get("trust").is_none());
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

/// A rule that says a tool made it, like the generated rules of the public
/// rule sets. It matches every file that starts the way a Windows
/// executable does, which is about as much as some of those rules know.
const GENERATED_RULE: &str = r#"
rule Test_Generated_Starts_Like_A_Program
{
    meta:
        description = "autogenerated rule brought to you by yara-signator"
        score = 75
        tool = "yara-signator v0.6.0"
    condition:
        uint16(0) == 0x5A4D
}
"#;

/// The second sign end to end: a generated rule alone changes nothing, and
/// together with an unusual structure it makes a file suspicious. The
/// files are inert fixtures, but two of them look packed, so they are
/// written only where the EICAR test file may be written: see
/// `eicar_write_then_scan_detects_every_form`.
#[test]
fn a_generated_rule_counts_only_together_with_an_unusual_structure() {
    use warden_pe::fixture::Fixture;

    let strict = std::env::var_os("WARDEN_REQUIRE_EICAR").is_some_and(|value| value == "1");
    let configured = std::env::var_os("WARDEN_EICAR_DIR")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from);
    if cfg!(windows) && configured.is_none() {
        let note = "second sign not exercised: WARDEN_EICAR_DIR is not set to an antivirus-excluded folder. See docs/TESTING.md.";
        assert!(!strict, "{note}");
        eprintln!("note: {note}");
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let rules = temp.path().join("generated.yar");
    fs::write(&rules, GENERATED_RULE).unwrap();
    let bundle = temp.path().join("generated.wrb");
    let built = stdout_of(
        warden()
            .args(["rules", "build", "--no-builtin", "--out"])
            .arg(&bundle)
            .arg(&rules),
    );
    assert!(
        built.contains("A tool generated 1 of them. A match of one counts only together"),
        "{built}"
    );
    let info = stdout_of(warden().args(["rules", "info"]).arg(&bundle));
    assert!(
        info.contains("suspicious, and only with a second sign from another layer,")
            && info.contains("for 1 rule that a tool generated"),
        "{info}"
    );
    let info: serde_json::Value = serde_json::from_str(&stdout_of(
        warden().args(["rules", "info", "--json"]).arg(&bundle),
    ))
    .unwrap();
    assert_eq!(info["scores"]["with_second_sign"], 1);
    assert_eq!(info["scores"]["suspicious"], 0);

    let dir = match &configured {
        Some(base) => base.join(format!("second-sign-{}", std::process::id())),
        None => temp.path().join("zone"),
    };
    fs::create_dir_all(&dir).unwrap();
    let files = [
        // The rule matches all four. Only the structure tells them apart.
        (
            "a-note.txt",
            b"MZ is how every Windows program starts".to_vec(),
        ),
        ("b-plain.exe", Fixture::plain().build()),
        ("c-packed-looking.exe", Fixture::packed_looking().build()),
        (
            "d-suspicious-looking.exe",
            Fixture::suspicious_looking().build(),
        ),
    ];
    for (name, content) in &files {
        fs::write(dir.join(name), content).unwrap();
    }

    let run = |arguments: &[&str]| {
        let mut command = warden();
        command
            .arg(arguments[0])
            .arg(&dir)
            .arg("--rules")
            .arg(&bundle);
        command.args(&arguments[1..]);
        command.assert().get_output().clone()
    };
    let json = run(&["scan", "--json"]);
    let text = run(&["scan"]);
    let without = run(&["scan", "--no-heuristics", "--json"]);
    let check = run(&["false-positives", "--json"]);
    let check_text = run(&["false-positives", "--no-progress"]);
    for (name, _) in &files {
        let _ = fs::remove_file(dir.join(name));
    }
    let _ = fs::remove_dir(&dir);

    // Two files are flagged, and two are on record with a clean verdict.
    assert_eq!(json.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(report["stats"]["files_scanned"], 4);
    assert_eq!(report["stats"]["detections"], 2);
    assert_eq!(report["stats"]["files_recorded"], 2);
    let yara = report["detectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|detector| detector["id"] == "yara")
        .unwrap();
    assert_eq!(yara["details"]["rules_generated"], 1);

    let detections = report["detections"].as_array().unwrap();
    assert_eq!(detections.len(), 2, "{report:#}");
    // Packed-looking: the structure is not suspicious by itself. It is the
    // second sign the rule was waiting for.
    let packed = &detections[0];
    assert!(
        packed["path"]
            .as_str()
            .unwrap()
            .ends_with("c-packed-looking.exe")
    );
    assert_eq!(packed["verdict"], "suspicious");
    let findings = packed["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 2, "{packed:#}");
    assert_eq!(findings[0]["detector"], "yara");
    assert_eq!(findings[0]["name"], "Test_Generated_Starts_Like_A_Program");
    assert_eq!(findings[0]["counts"], "with_second_sign");
    assert_eq!(findings[0]["confidence"], "medium");
    // Where signatures can be checked, the scan asks who signed the file
    // before it reports the match, and the finding says what that came to
    // in a line of its own.
    let reasons = findings[0]["reasons"].as_array().unwrap();
    let counts = reasons.len() - if cfg!(windows) { 2 } else { 1 };
    assert_eq!(
        reasons[counts],
        "Counts, because another layer has something to say about the same file: heuristic"
    );
    if cfg!(windows) {
        assert!(
            reasons[counts + 1].as_str().unwrap().starts_with(
                "No signature of a publisher on the trust list speaks for the file: no \
                 signature was found"
            ),
            "{reasons:?}"
        );
        assert_eq!(packed["trust"]["reason"], "no_signature");
    } else {
        assert!(packed.get("trust").is_none());
    }
    assert_eq!(findings[1]["detector"], "heuristic");
    assert_eq!(findings[1]["name"], "Heuristic.UnusualExecutable");
    assert_eq!(findings[1]["counts"], "as_second_sign");
    assert_eq!(findings[1]["confidence"], "low");
    assert_eq!(
        findings[1]["reasons"][0],
        "The structure of the file scores 28: less than the 32 that make a file suspicious, \
         and at least the 14 from which it backs up a finding of another layer"
    );
    // Suspicious-looking: flagged by its structure anyway, and the rule
    // counts next to it.
    let suspicious = &detections[1];
    assert!(
        suspicious["path"]
            .as_str()
            .unwrap()
            .ends_with("d-suspicious-looking.exe")
    );
    assert_eq!(suspicious["verdict"], "suspicious");
    assert_eq!(suspicious["findings"][0]["confidence"], "medium");
    assert_eq!(
        suspicious["findings"][1]["name"],
        "Heuristic.SuspiciousExecutable"
    );
    assert!(suspicious["findings"][1].get("counts").is_none());

    // The plain program and the text file: the rule matched, nothing backs
    // it up, the verdict is clean, and the match is on record.
    let recorded = report["recorded"].as_array().unwrap();
    assert_eq!(recorded.len(), 2, "{report:#}");
    for (entry, name) in recorded.iter().zip(["a-note.txt", "b-plain.exe"]) {
        assert!(entry["path"].as_str().unwrap().ends_with(name));
        let findings = entry["findings"].as_array().unwrap();
        assert_eq!(findings.len(), 1, "{entry:#}");
        assert_eq!(findings[0]["counts"], "with_second_sign");
        assert_eq!(findings[0]["confidence"], "low");
        let reasons = findings[0]["reasons"].as_array().unwrap();
        assert!(
            reasons[reasons.len() - 2]
                .as_str()
                .unwrap()
                .starts_with("The rule was generated by a tool, yara-signator v0.6.0, "),
            "{reasons:?}"
        );
        assert_eq!(
            reasons[reasons.len() - 1],
            "No other layer has anything to say about this file, so this is recorded and does \
             not change the verdict"
        );
    }

    assert_eq!(text.status.code(), Some(1));
    let text = String::from_utf8(text.stdout).unwrap();
    for expected in [
        "Rules       1 YARA rule from 1 file",
        "; a tool generated 1 of them, and a match of one counts only with a second sign",
        "suspicious from a score of 32, a second sign from 14",
        "2 detections",
        "SUSPICIOUS  Test_Generated_Starts_Like_A_Program, Heuristic.UnusualExecutable",
        "SUSPICIOUS  Test_Generated_Starts_Like_A_Program, Heuristic.SuspiciousExecutable",
        "2 files have findings on record that did not count. The verdict of those files is clean.",
        "  ON RECORD   Test_Generated_Starts_Like_A_Program",
    ] {
        assert!(text.contains(expected), "missing {expected:?} in:\n{text}");
    }

    // Without the heuristic layer nobody offers a second sign: nothing is
    // flagged, and all four matches are on record.
    assert_eq!(without.status.code(), Some(0));
    let without: serde_json::Value = serde_json::from_slice(&without.stdout).unwrap();
    assert_eq!(without["stats"]["detections"], 0);
    assert_eq!(without["stats"]["files_recorded"], 4);

    // The check of clean files counts both kinds, and keeps them apart.
    assert_eq!(check.status.code(), Some(1));
    let check: serde_json::Value = serde_json::from_slice(&check.stdout).unwrap();
    assert_eq!(check["schema"], 4);
    assert_eq!(check["flagged_suspicious"], 2);
    assert_eq!(check["flagged_malicious"], 0);
    assert_eq!(check["recorded_files"], 2);
    assert_eq!(
        check["recorded_by_name"],
        serde_json::json!([{"name": "Test_Generated_Starts_Like_A_Program", "files": 2}])
    );
    let listed = check["recorded"].as_array().unwrap();
    assert_eq!(listed.len(), 2);
    assert!(listed[0]["path"].as_str().unwrap().ends_with("a-note.txt"));
    assert_eq!(listed[0]["sha256"].as_str().unwrap().len(), 64);
    assert_eq!(
        listed[0]["names"],
        serde_json::json!(["Test_Generated_Starts_Like_A_Program"])
    );
    assert_eq!(check["recorded_truncated"], false);
    let check_text = String::from_utf8(check_text.stdout).unwrap();
    for expected in [
        "Flagged     2 of 4 files",
        "On record   2 files have findings that did not count; the verdict is clean",
        "On record, by the name of the finding",
        "  ON RECORD   ",
    ] {
        assert!(
            check_text.contains(expected),
            "missing {expected:?} in:\n{check_text}"
        );
    }
}

/// What `inspect` says about the second sign.
#[test]
fn inspect_says_whether_a_structure_is_enough_for_a_second_sign() {
    use warden_pe::fixture::Fixture;

    let look = |file: Vec<u8>, code: i32| {
        let output = warden()
            .args(["inspect", "-"])
            .write_stdin(file)
            .assert()
            .code(code)
            .get_output()
            .clone();
        String::from_utf8(output.stdout).unwrap()
    };
    let packed = look(Fixture::packed_looking().build(), 0);
    assert!(packed.contains("Score       28"), "{packed}");
    assert!(
        packed
            .contains("Verdict     not suspicious: a file counts as suspicious from a score of 32"),
        "{packed}"
    );
    assert!(
        packed.contains(
            "Second sign yes: it backs up a finding of another layer that does not count alone, which takes a score of 14"
        ),
        "{packed}"
    );
    let plain = look(Fixture::plain().build(), 0);
    assert!(
        plain.contains(
            "Second sign no: to back up a finding of another layer that does not count alone takes a score of 14"
        ),
        "{plain}"
    );
    // A suspicious file has no need of the line.
    let suspicious = look(Fixture::suspicious_looking().build(), 1);
    assert!(!suspicious.contains("Second sign"), "{suspicious}");

    let json: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(
        &warden()
            .args(["inspect", "-", "--json"])
            .write_stdin(Fixture::packed_looking().build())
            .assert()
            .success()
            .get_output()
            .stdout,
    ))
    .unwrap();
    assert_eq!(json["assessment"]["second_sign_from"], 14);
    assert_eq!(json["assessment"]["second_sign"], true);
    assert_eq!(json["assessment"]["suspicious"], false);
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

/// Harmless bytes that stand in for a file somebody wants out of the way.
/// The marker is what a scanner "would look for".
const QUARANTINE_MARKER: &str = "WARDEN-CLI-QUARANTINE-MARKER";

fn suspect_bytes() -> Vec<u8> {
    format!("some bytes, then {QUARANTINE_MARKER}, then some more\n")
        .repeat(40)
        .into_bytes()
}

/// A moment long past, with a fraction of a second: 2021-03-04 05:06:07.5 UTC.
fn long_ago() -> std::time::SystemTime {
    std::time::UNIX_EPOCH + std::time::Duration::new(1_614_834_367, 500_000_000)
}

fn write_dated(path: &Path, bytes: &[u8]) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
    let file = fs::File::options().write(true).open(path).unwrap();
    file.set_times(fs::FileTimes::new().set_modified(long_ago()))
        .unwrap();
}

/// The acceptance test of the quarantine: a file goes in and comes back
/// with its content, its timestamp and its permissions.
#[test]
fn quarantine_moves_a_file_out_and_puts_it_back_as_it_was() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("quarantine");
    let file = dir.path().join("files").join("suspect.bin");
    let bytes = suspect_bytes();
    write_dated(&file, &bytes);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&file, fs::Permissions::from_mode(0o640)).unwrap();
    }
    let digest = sha256_hex(&bytes);
    let shown = file.to_string_lossy().into_owned();

    let added = stdout_of(
        warden()
            .args(["quarantine", "add"])
            .arg(&file)
            .args(["--reason", "a test of the round trip", "--dir"])
            .arg(&store),
    );
    assert!(added.contains(&format!("Quarantined  {shown}")), "{added}");
    assert!(
        added.contains(&format!("sha256     {digest} (2,480 bytes)")),
        "{added}"
    );
    assert!(!file.exists(), "the file is gone from its place");

    // What lies in the quarantine is not the file.
    let stored: Vec<PathBuf> = fs::read_dir(store.join("items"))
        .unwrap()
        .map(|item| item.unwrap().path())
        .collect();
    assert_eq!(stored.len(), 1);
    let on_disk = fs::read(&stored[0]).unwrap();
    assert!(
        !on_disk
            .windows(QUARANTINE_MARKER.len())
            .any(|window| window == QUARANTINE_MARKER.as_bytes())
    );

    let listed = stdout_of(warden().args(["quarantine", "list", "--dir"]).arg(&store));
    for expected in [
        "1 entry",
        shown.as_str(),
        "2,480 bytes",
        "reason: a test of the round trip",
    ] {
        assert!(
            listed.contains(expected),
            "missing {expected:?} in:\n{listed}"
        );
    }
    let json: serde_json::Value = serde_json::from_str(&stdout_of(
        warden()
            .args(["quarantine", "list", "--json", "--dir"])
            .arg(&store),
    ))
    .unwrap();
    let entry = &json["entries"][0];
    let id = entry["id"].as_str().unwrap().to_owned();
    assert_eq!(id.len(), 16);
    assert_eq!(entry["original_path"], shown.as_str());
    assert_eq!(entry["size"], 2480);
    assert_eq!(entry["sha256"], digest.as_str());
    assert_eq!(entry["reason"]["note"], "a test of the round trip");
    assert_eq!(entry["cipher"]["algorithm"], "chacha20");
    assert_eq!(entry["times"]["modified"]["secs"], 1_614_834_367);
    assert_eq!(entry["times"]["modified"]["nanos"], 500_000_000);
    assert_eq!(json["damaged"], serde_json::json!([]));

    // The start of the identifier is enough from here on.
    let short = &id[..6];
    let info = stdout_of(
        warden()
            .args(["quarantine", "info", short, "--dir"])
            .arg(&store),
    );
    for expected in [
        format!("Entry        {id}"),
        format!("Was at       {shown}"),
        format!("SHA-256      {digest}"),
        "Modified     2021-03-04T05:06:07Z and 500,000,000 ns".to_owned(),
        "Reason       a test of the round trip".to_owned(),
    ] {
        assert!(info.contains(&expected), "missing {expected:?} in:\n{info}");
    }

    let restored = stdout_of(
        warden()
            .args(["quarantine", "restore", short, "--dir"])
            .arg(&store),
    );
    for expected in [
        format!("Restored  {shown}"),
        format!("sha256  {digest} (2,480 bytes), as recorded"),
        "Its timestamps and permissions are what they were.".to_owned(),
    ] {
        assert!(
            restored.contains(&expected),
            "missing {expected:?} in:\n{restored}"
        );
    }
    let metadata = fs::metadata(&file).unwrap();
    assert_eq!(metadata.modified().unwrap(), long_ago());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o640);
    }
    assert_eq!(fs::read(&file).unwrap(), bytes);
    assert_eq!(hash_of(&file), digest);

    let empty = stdout_of(warden().args(["quarantine", "list", "--dir"]).arg(&store));
    assert!(empty.contains("Nothing is in quarantine."), "{empty}");
}

/// The quarantine's guard is about files of Windows. An ordinary file goes
/// in whether or not the flag past the guard is given, and nothing is said
/// about it. What the guard does with a file of Windows is tried on
/// Windows, in `quarantine_windows.rs`.
#[test]
fn quarantine_takes_an_ordinary_file_with_and_without_the_flag_past_its_guard() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("quarantine");

    for (name, flag) in [
        ("plain.bin", None),
        ("insisted.bin", Some("--even-if-signed-by-windows")),
    ] {
        let file = dir.path().join(name);
        fs::write(&file, suspect_bytes()).unwrap();
        let mut command = warden();
        command.args(["quarantine", "add"]).arg(&file);
        if let Some(flag) = flag {
            command.arg(flag);
        }
        command
            .arg("--dir")
            .arg(&store)
            .assert()
            .success()
            .stdout(predicate::str::contains("Quarantined"))
            .stdout(predicate::str::contains("although").not())
            .stderr(predicate::str::is_empty());
        assert!(!file.exists(), "{name} is gone from its place");
    }

    let help = stdout_of(warden().args(["quarantine", "add", "--help"]));
    assert!(help.contains("--even-if-signed-by-windows"), "{help}");
    assert!(
        help.contains("A file that is part of Windows stays where it is"),
        "{help}"
    );
}

#[test]
fn quarantine_says_no_and_why_and_leaves_things_as_they_are() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("quarantine");
    let file = dir.path().join("files").join("suspect.bin");
    let bytes = suspect_bytes();
    write_dated(&file, &bytes);
    // The folder comes from the environment in this test.
    let quarantine = || {
        let mut command = warden();
        command.env("WARDEN_QUARANTINE", &store).arg("quarantine");
        command
    };

    // A folder is not a file, and one refusal does not stop the others.
    let other = dir.path().join("files").join("other.bin");
    write_dated(&other, b"another file");
    quarantine()
        .arg("add")
        .arg(file.parent().unwrap())
        .arg(&other)
        .assert()
        .code(2)
        .stderr(predicate::str::contains(
            "is a folder, and only a regular file can be quarantined",
        ))
        .stdout(predicate::str::contains("Quarantined  "));
    assert!(!other.exists() && file.exists());

    // Identifiers are hexadecimal, so no entry can start with this.
    quarantine()
        .args(["restore", "xyz"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("there is no quarantine entry xyz"));

    // Something else has taken the file's place by the time it comes back.
    let added = stdout_of(quarantine().arg("add").arg(&file));
    let id = added
        .lines()
        .find_map(|line| line.trim().strip_prefix("entry"))
        .unwrap()
        .trim()
        .to_owned();
    fs::write(&file, b"a newer file").unwrap();
    quarantine()
        .args(["restore", &id])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("exists already"));
    assert_eq!(fs::read(&file).unwrap(), b"a newer file");

    // Somewhere else it can go.
    let elsewhere = dir.path().join("elsewhere.bin");
    quarantine()
        .args(["restore", &id, "--to"])
        .arg(&elsewhere)
        .assert()
        .success();
    assert_eq!(fs::read(&elsewhere).unwrap(), bytes);

    // Or over what is there, if that is asked for.
    let added = stdout_of(quarantine().arg("add").arg(&elsewhere));
    let id = added
        .lines()
        .find_map(|line| line.trim().strip_prefix("entry"))
        .unwrap()
        .trim()
        .to_owned();
    quarantine()
        .args(["restore", &id, "--overwrite", "--to"])
        .arg(&file)
        .assert()
        .success();
    assert_eq!(fs::read(&file).unwrap(), bytes);

    // Deleting is for good, and takes the other entry with it here.
    let listed: serde_json::Value =
        serde_json::from_str(&stdout_of(quarantine().args(["list", "--json"]))).unwrap();
    let left = listed["entries"].as_array().unwrap();
    assert_eq!(left.len(), 1);
    let last = left[0]["id"].as_str().unwrap().to_owned();
    quarantine()
        .args(["delete", &last, "xyz"])
        .assert()
        .code(2)
        .stdout(predicate::str::contains(format!("Deleted  {last}")))
        .stderr(predicate::str::contains("there is no quarantine entry xyz"));
    assert!(stdout_of(quarantine().arg("list")).contains("Nothing is in quarantine."));
    assert!(!other.exists());
}

/// A run that died in the middle, as the next command meets it. The crash
/// is made with the library's own switch for it, and the command line is
/// what a person would type next.
#[test]
fn quarantine_settles_what_an_interrupted_run_left_behind() {
    use warden_quarantine::{Quarantine, QuarantineError, Reason, RestoreOptions, Step};

    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("quarantine");
    let file = dir.path().join("files").join("suspect.bin");
    let bytes = suspect_bytes();
    write_dated(&file, &bytes);
    let shown = file.to_string_lossy().into_owned();

    // Dies when the copy is safe and the original is still there.
    {
        let (mut quarantine, _) = Quarantine::open(&store).unwrap();
        quarantine.interrupt_after(Step::EntryCommitted);
        let died = quarantine.add(&file, Reason::default()).unwrap_err();
        assert!(matches!(died, QuarantineError::Interrupted(_)), "{died}");
    }
    assert!(file.exists());

    let next = warden()
        .args(["quarantine", "list", "--dir"])
        .arg(&store)
        .assert()
        .success();
    let output = next.get_output();
    let said = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        said.contains(&format!(
            "note: Quarantining {shown} had been cut off after the copy was safe. It was finished: the file is in quarantine as "
        )),
        "{said}"
    );
    let listed = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(listed.contains("1 entry"), "{listed}");
    assert!(!file.exists(), "the original is gone now");

    // Dies while the file is being written back.
    let id = {
        let (mut quarantine, recovered) = Quarantine::open(&store).unwrap();
        assert!(recovered.is_empty(), "the command before settled it");
        let id = quarantine.list().unwrap().entries[0].info.id.clone();
        quarantine.interrupt_after(Step::RestoreWritten);
        quarantine
            .restore(&id, &RestoreOptions::default())
            .unwrap_err();
        id
    };
    assert!(!file.exists());
    assert_eq!(fs::read_dir(file.parent().unwrap()).unwrap().count(), 1);

    let next = warden()
        .args(["quarantine", "restore", &id, "--dir"])
        .arg(&store)
        .assert()
        .success();
    let said = String::from_utf8_lossy(&next.get_output().stderr).into_owned();
    assert!(
        said.contains(&format!(
            "note: Restoring {shown} had been cut off before the file was back. It was undone: entry {id} is still in quarantine."
        )),
        "{said}"
    );
    // The same command then did what it was asked to.
    assert_eq!(fs::read(&file).unwrap(), bytes);
    assert_eq!(fs::read_dir(file.parent().unwrap()).unwrap().count(), 1);
}

/// The EICAR test file through the quarantine. It is written only where
/// the test file may be written: see `eicar_write_then_scan_detects_every_form`.
#[test]
fn the_test_file_is_harmless_in_quarantine_and_itself_again_afterwards() {
    let strict = std::env::var_os("WARDEN_REQUIRE_EICAR").is_some_and(|value| value == "1");
    let not_exercised = |why: &str| {
        let note = format!("EICAR in quarantine not exercised: {why}. See docs/TESTING.md.");
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
        Some(base) => base.join(format!("quarantine-{}", std::process::id())),
        None => temp.path().join("zone"),
    };
    let store = temp.path().join("quarantine");
    let file = dir.join("eicar.com");
    let scan = |path: &Path| {
        let output = warden().arg("scan").arg(path).assert().get_output().clone();
        (
            output.status.code(),
            String::from_utf8_lossy(&output.stdout).into_owned(),
        )
    };

    let written = warden()
        .args(["eicar", "write"])
        .arg(&dir)
        .assert()
        .get_output()
        .status
        .success();
    let before = scan(&dir);
    if !written || before.0 != Some(1) {
        let _ = fs::remove_file(&file);
        let _ = fs::remove_dir(&dir);
        not_exercised("the test file could not be written, or was removed before the scan");
        return;
    }

    let added = warden()
        .args(["quarantine", "add"])
        .arg(&file)
        .args(["--reason", "detected as EICAR-Test-File", "--dir"])
        .arg(&store)
        .assert()
        .get_output()
        .clone();
    let in_place = scan(&dir);
    let in_store = scan(&store);
    let id: Option<String> = String::from_utf8_lossy(&added.stdout)
        .lines()
        .find_map(|line| {
            line.trim()
                .strip_prefix("entry")
                .map(|id| id.trim().to_owned())
        });
    let restored = id.as_ref().map(|id| {
        warden()
            .args(["quarantine", "restore", id, "--dir"])
            .arg(&store)
            .assert()
            .get_output()
            .clone()
    });
    // Read here and not by a second `warden`: if Windows does not hand
    // the file out, its reason is wanted. Then the scan, of a file that
    // can be read.
    let (read_back, refusals) = read_patiently(&file);
    let after = scan(&dir);
    let _ = fs::remove_file(&file);
    let _ = fs::remove_dir(&dir);
    if !refusals.is_empty() {
        eprintln!("note: the restored test file was not handed out at once: {refusals:?}");
    }

    assert!(added.status.success(), "{added:?}");
    // Where the file was, there is nothing left to find.
    assert_eq!(in_place.0, Some(0), "{}", in_place.1);
    // And what is kept does not set off a scanner: not this one, and for
    // the same reason not a resident antivirus that watches the folder.
    assert_eq!(in_store.0, Some(0), "{}", in_store.1);
    assert!(in_store.1.contains("No threats found."), "{}", in_store.1);

    let restored = restored.expect("the quarantine named no entry");
    assert!(restored.status.success(), "{restored:?}");
    assert_eq!(
        read_back.as_deref().map(sha256_hex).as_deref(),
        Some("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"),
        "the restored file could not be read, or is not the test file: {refusals:?}"
    );
    assert_eq!(after.0, Some(1), "it is detected again: {}", after.1);
}

#[test]
fn trust_list_shows_the_publishers_that_are_part_of_the_program() {
    warden().args(["trust", "list"]).assert().success().stdout(
        predicate::str::contains("on the trust list that is part of this program")
            .and(predicate::str::contains("Microsoft Corporation"))
            .and(predicate::str::contains(
                "has to pass through one of Microsoft's own root certificates",
            ))
            .and(predicate::str::contains("Seen ")),
    );

    let output = stdout_of(warden().args(["trust", "list", "--json"]));
    let json: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(json["sha256"].as_str().unwrap().len(), 64);
    let publishers = json["publishers"].as_array().unwrap();
    assert!(!publishers.is_empty());
    for publisher in publishers {
        for field in ["name", "common_name", "anchor", "signs", "reason", "added"] {
            assert!(
                publisher[field]
                    .as_str()
                    .is_some_and(|text| !text.is_empty()),
                "{field} of {publisher}"
            );
        }
        // Nobody is on the list without a file that was seen with such a
        // signature.
        let evidence = publisher["evidence"].as_array().unwrap();
        assert!(!evidence.is_empty(), "{publisher}");
        for seen in evidence {
            assert_eq!(seen["sha256"].as_str().unwrap().len(), 64);
            assert!(
                ["embedded", "windows_catalog", "package"]
                    .contains(&seen["route"].as_str().unwrap())
            );
        }
    }

    // The scan reports the same list: its digest is in every report.
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("note.txt"), "nothing to see here").unwrap();
    let report = stdout_of(warden().arg("scan").arg(dir.path()).arg("--json"));
    let report: serde_json::Value = serde_json::from_str(&report).unwrap();
    assert_eq!(report["trust_check"]["trust_list"], json["sha256"]);
    assert_eq!(report["trust_check"]["publishers"], publishers.len());
}

#[test]
fn trust_check_explains_a_file_that_nobody_signed() {
    let dir = tempfile::tempdir().unwrap();
    let note = dir.path().join("note.txt");
    fs::write(&note, "nothing to see here").unwrap();

    let assert = warden()
        .args(["trust", "check"])
        .arg(&note)
        .assert()
        .code(1);
    let output = warden()
        .args(["trust", "check", "--json"])
        .arg(&note)
        .assert()
        .code(1)
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let file = &json[0];
    assert!(file["path"].as_str().unwrap().ends_with("note.txt"));
    assert_eq!(file["trust"]["answer"], "not_trusted");

    if cfg!(windows) {
        assert.stdout(
            predicate::str::contains("Trusted     no")
                .and(predicate::str::contains("no Windows executable"))
                .and(predicate::str::contains(sha256_hex(b"nothing to see here"))),
        );
        assert_eq!(file["trust"]["reason"], "no_signature");
        assert_eq!(file["executable"], false);
        assert_eq!(file["sha256"], sha256_hex(b"nothing to see here"));
        let routes = file["routes"].as_array().unwrap();
        assert_eq!(routes.len(), 3, "every route is accounted for: {routes:?}");
        assert_eq!(routes[0]["route"], "embedded");
        assert_eq!(routes[0]["found"], "not_applicable");
        assert_eq!(routes[1]["route"], "windows_catalog");
        assert_eq!(routes[1]["found"], "not_applicable");
        assert_eq!(routes[2]["route"], "package");
        assert_eq!(routes[2]["found"], "nothing");
    } else {
        assert.stdout(predicate::str::contains(
            "Trusted     no: signatures can only be checked on Windows",
        ));
        assert_eq!(file["trust"]["reason"], "unavailable");
    }

    // A file that is not there is not trusted either, and that is not an
    // error of the command.
    warden()
        .args(["trust", "check"])
        .arg(dir.path().join("no-such-file.exe"))
        .assert()
        .code(1);
    warden().args(["trust", "check"]).assert().code(2);
}

#[test]
fn trust_survey_counts_what_it_finds_in_a_folder() {
    let dir = tempfile::tempdir().unwrap();
    let tree = dir.path().join("tree");
    fs::create_dir_all(tree.join("nested")).unwrap();
    fs::write(tree.join("note.txt"), "nothing to see here").unwrap();
    fs::write(tree.join("nested/data.bin"), [7u8; 4096]).unwrap();

    if !cfg!(windows) {
        warden()
            .args(["trust", "survey"])
            .arg(&tree)
            .assert()
            .code(2)
            .stderr(predicate::str::contains(
                "signatures can only be checked on Windows",
            ));
        return;
    }

    let results = dir.path().join("survey.json");
    warden()
        .args(["trust", "survey"])
        .arg(&tree)
        .args(["--label", "unit test", "--threads", "2", "--output"])
        .arg(&results)
        .assert()
        .success()
        .stdout(
            predicate::str::contains("who signed what")
                .and(predicate::str::contains("Checked      2 files"))
                .and(predicate::str::contains(
                    "0 Windows executables, 2 other files",
                ))
                .and(predicate::str::contains("no signature found")),
        );
    let json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&results).unwrap()).unwrap();
    assert_eq!(json["schema"], 1);
    assert_eq!(json["label"], "unit test");
    assert_eq!(json["files"], 2);
    assert_eq!(json["executables"], 0);
    assert_eq!(json["files_trusted"], 0);
    assert_eq!(json["threads"], 2);
    assert_eq!(json["network"], true);
    assert_eq!(json["not_trusted"][0]["reason"], "no_signature");
    assert_eq!(json["not_trusted"][0]["files"], 2);
    assert_eq!(json["signers"], serde_json::json!([]));
    assert_eq!(json["timing"][0]["outcome"], "all");
    assert_eq!(json["timing"][0]["files"], 2);

    warden()
        .args(["trust", "survey"])
        .arg(dir.path().join("no-such-folder"))
        .assert()
        .code(2);
}

#[test]
fn a_scan_says_whether_it_checks_signatures_and_can_be_told_not_to() {
    let dir = tempfile::tempdir().unwrap();
    let bundle = marker_bundle(dir.path());
    let tree = dir.path().join("tree");
    fs::create_dir_all(&tree).unwrap();
    fs::write(tree.join("high.txt"), "text with WARDEN-CLI-HIGH in it").unwrap();

    let expected = if cfg!(windows) {
        "on the trust list; the match of a bundle's rule yields to a valid signature of one. \
         Checked for 1 file, 0 of them signed by a trusted publisher"
    } else {
        "Trust       signatures can only be checked on Windows, so no rule match yields to one"
    };
    let assert = warden()
        .arg("scan")
        .arg(&tree)
        .arg("--rules")
        .arg(&bundle)
        .assert()
        .code(1)
        .stdout(predicate::str::contains(expected));
    if cfg!(windows) {
        // The match is reported, and it says that nobody vouches for the
        // file.
        assert.stdout(predicate::str::contains(
            "No signature of a publisher on the trust list speaks for the file",
        ));
    }

    let output = warden()
        .arg("scan")
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
    let finding = &json["detections"][0]["findings"][0];
    assert_eq!(finding["name"], "Test_Marker_High");
    assert_eq!(
        finding["yields_to_trust"], true,
        "a rule that came with a bundle"
    );
    assert_eq!(finding["confidence"], "high");
    assert_eq!(json["stats"]["trust_checks"], u64::from(cfg!(windows)));
    assert_eq!(json["stats"]["files_trusted"], 0);

    // Switched off: no line, no check, and the same detection.
    warden()
        .arg("scan")
        .arg(&tree)
        .arg("--rules")
        .arg(&bundle)
        .arg("--no-trust")
        .assert()
        .code(1)
        .stdout(predicate::str::contains("Trust ").not());
    let output = warden()
        .arg("scan")
        .arg(&tree)
        .arg("--rules")
        .arg(&bundle)
        .args(["--no-trust", "--offline", "--json"])
        .assert()
        .code(1)
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert!(json["trust_check"].is_null());
    assert_eq!(json["stats"]["trust_checks"], 0);
    let reasons = json["detections"][0]["findings"][0]["reasons"]
        .as_array()
        .unwrap();
    assert!(
        reasons
            .iter()
            .all(|reason| !reason.as_str().unwrap().contains("trust list")),
        "{reasons:?}"
    );
}

#[test]
fn autostart_has_its_three_commands_and_says_what_they_are_for() {
    let help = stdout_of(warden().args(["autostart", "--help"]));
    for expected in [
        "find",
        "Show what starts a file, and change nothing",
        "list",
        "Show every autostart entry Warden looks at",
        "remove",
        "Go on removing what starts a quarantined file",
    ] {
        assert!(help.contains(expected), "{expected} is missing:\n{help}");
    }
    let help = stdout_of(warden().args(["quarantine", "add", "--help"]));
    assert!(
        help.contains("What makes Windows start the file goes with it"),
        "{help}"
    );
}

/// The entries Warden looks at exist on Windows. Elsewhere the commands
/// say so, succeed, and keep the shape of their output.
#[cfg(not(windows))]
#[test]
fn on_another_system_autostart_says_that_it_looks_on_windows_only() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("file.bin");
    fs::write(&file, suspect_bytes()).unwrap();

    let listed = stdout_of(warden().args(["autostart", "list"]));
    assert!(listed.contains("on Windows only"), "{listed}");
    let found = stdout_of(warden().args(["autostart", "find"]).arg(&file));
    assert!(found.contains("on Windows only"), "{found}");

    for arguments in [
        vec!["autostart", "list", "--json"],
        vec!["autostart", "find", "--json", file.to_str().unwrap()],
    ] {
        let json: serde_json::Value =
            serde_json::from_str(&stdout_of(warden().args(&arguments))).unwrap();
        assert_eq!(json["entries"].as_array().unwrap().len(), 0);
        assert!(
            json["problems"][0]
                .as_str()
                .unwrap()
                .contains("on Windows only")
        );
    }
}

/// A file that nothing starts goes into the quarantine with no record of
/// autostart entries, and every command says the same about that.
#[test]
fn a_quarantined_file_that_nothing_started_has_nothing_to_remove_or_put_back() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("quarantine");
    let file = dir.path().join("lonely.bin");
    fs::write(&file, suspect_bytes()).unwrap();

    let added = stdout_of(
        warden()
            .args(["quarantine", "add"])
            .arg(&file)
            .arg("--dir")
            .arg(&store),
    );
    assert!(!added.contains("removed    "), "{added}");
    assert!(!added.contains("left       "), "{added}");
    let id = added
        .lines()
        .find_map(|line| line.trim().strip_prefix("entry"))
        .unwrap()
        .trim()
        .to_owned();

    let listed = stdout_of(warden().args(["quarantine", "list", "--dir"]).arg(&store));
    assert!(!listed.contains("removed with it"), "{listed}");
    assert!(!listed.contains("Still owed"), "{listed}");
    let json: serde_json::Value = serde_json::from_str(&stdout_of(
        warden()
            .args(["quarantine", "list", "--json", "--dir"])
            .arg(&store),
    ))
    .unwrap();
    assert_eq!(json["autostart"].as_array().unwrap().len(), 0);
    let info = stdout_of(
        warden()
            .args(["quarantine", "info", &id, "--dir"])
            .arg(&store),
    );
    assert!(!info.contains("What started it"), "{info}");

    let removed = stdout_of(
        warden()
            .args(["autostart", "remove", &id[..8], "--dir"])
            .arg(&store),
    );
    assert!(
        removed.contains("Nothing is left to remove for")
            && removed.contains("no entry that starts it was written down"),
        "{removed}"
    );
    // An entry that is not in the quarantine is an error, as everywhere.
    warden()
        .args(["autostart", "remove", "ffffffff", "--dir"])
        .arg(&store)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("ffffffff"));

    let restored = stdout_of(
        warden()
            .args(["quarantine", "restore", &id, "--dir"])
            .arg(&store),
    );
    assert!(!restored.contains("What started it"), "{restored}");
    assert!(file.exists());
}

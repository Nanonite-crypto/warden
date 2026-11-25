//! The quarantine's guard on Windows, with the real `warden` and real
//! signatures: a file of Windows stays where it is, and goes when that is
//! asked for in as many words.
//!
//! The files are copies of two files that every Windows has, one signed in
//! the file itself and one through a catalogue. Nothing in System32 is
//! touched: a catalogue goes by a file's content and an embedded signature
//! travels with the file, so a copy in a temporary folder is a file of
//! Windows as much as the original.

#![cfg(windows)]
#![allow(clippy::unwrap_used)]
// A test that says why it was skipped may print.
#![allow(clippy::disallowed_macros)]

use std::fs;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use predicates::prelude::*;

const FLAG: &str = "--even-if-signed-by-windows";

fn warden() -> Command {
    let mut command = assert_cmd::cargo_bin_cmd!("warden");
    command
        .env_remove("WARDEN_SIGDB")
        .env_remove("WARDEN_RULES")
        .env_remove("WARDEN_QUARANTINE")
        .env_remove("SOURCE_DATE_EPOCH");
    command
}

fn system32(name: &str) -> PathBuf {
    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
    PathBuf::from(root).join("System32").join(name)
}

/// The entries of a quarantine, as `list --json` gives them.
fn entries(store: &Path) -> Vec<serde_json::Value> {
    let output = warden()
        .args(["quarantine", "list", "--json", "--dir"])
        .arg(store)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let listed: serde_json::Value = serde_json::from_slice(&output).unwrap();
    listed["entries"].as_array().unwrap().clone()
}

#[test]
fn a_file_of_windows_stays_unless_it_is_asked_for_in_as_many_words() {
    // ntdll.dll carries its signature; whoami.exe is in a catalogue.
    for name in ["ntdll.dll", "whoami.exe"] {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("quarantine");
        let copy = dir.path().join(name);
        fs::copy(system32(name), &copy).unwrap();
        let bytes = fs::read(&copy).unwrap();

        // Without the flag: refused, with the reason and the way past it.
        warden()
            .args(["quarantine", "add"])
            .arg(&copy)
            .arg("--dir")
            .arg(&store)
            .assert()
            .code(2)
            .stdout(predicate::str::contains("Quarantined").not())
            .stderr(predicate::str::contains(format!(
                "{} was left where it is: it is part of the operating system (signed for Microsoft Windows, found in ",
                copy.display()
            )))
            .stderr(predicate::str::contains(FLAG));
        assert_eq!(fs::read(&copy).unwrap(), bytes, "{name} is untouched");
        assert!(entries(&store).is_empty(), "{name} left nothing behind");

        // With it: taken, and the output says what was taken all the same.
        warden()
            .args(["quarantine", "add", FLAG])
            .arg(&copy)
            .arg("--dir")
            .arg(&store)
            .assert()
            .success()
            .stdout(predicate::str::contains(
                "although   it is part of the operating system (signed for Microsoft Windows, found in ",
            ));
        assert!(!copy.exists(), "{name} is gone from its place");
        let listed = entries(&store);
        assert_eq!(listed.len(), 1);

        // And it comes back as it was.
        warden()
            .args(["quarantine", "restore"])
            .arg(listed[0]["id"].as_str().unwrap())
            .arg("--dir")
            .arg(&store)
            .assert()
            .success();
        assert_eq!(fs::read(&copy).unwrap(), bytes, "{name} is back");
    }
}

#[test]
fn a_file_that_windows_did_not_sign_goes_as_before() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("quarantine");

    // No executable at all.
    let text = dir.path().join("notes.txt");
    fs::write(&text, "nothing that anybody signed").unwrap();
    // A file of Windows with one byte more: no catalogue lists this
    // content, so it is nobody's any longer.
    let changed = dir.path().join("whoami-changed.exe");
    let mut bytes = fs::read(system32("whoami.exe")).unwrap();
    bytes.push(0);
    fs::write(&changed, &bytes).unwrap();

    for file in [&text, &changed] {
        warden()
            .args(["quarantine", "add"])
            .arg(file)
            .arg("--dir")
            .arg(&store)
            .assert()
            .success()
            .stdout(predicate::str::contains("Quarantined"))
            .stdout(predicate::str::contains("although").not())
            .stderr(predicate::str::is_empty());
        assert!(!file.exists(), "{} is gone", file.display());
    }
    assert_eq!(entries(&store).len(), 2);
}

#[test]
fn one_of_microsofts_applications_is_not_windows() {
    // Signed for Microsoft Corporation, which is on the trust list and is
    // not the operating system. The guard is about Windows and nothing
    // more.
    let program_files = PathBuf::from(
        std::env::var_os("ProgramFiles").unwrap_or_else(|| "C:\\Program Files".into()),
    );
    let Some(program) = [
        program_files.join("PowerShell\\7\\pwsh.exe"),
        program_files.join("dotnet\\dotnet.exe"),
    ]
    .into_iter()
    .find(|candidate| candidate.exists()) else {
        eprintln!("skipped: none of the candidate programs of Microsoft's is on this machine");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("quarantine");
    let copy = dir.path().join("a-program-of-microsofts.exe");
    fs::copy(&program, &copy).unwrap();

    warden()
        .args(["quarantine", "add"])
        .arg(&copy)
        .arg("--dir")
        .arg(&store)
        .assert()
        .success()
        .stdout(predicate::str::contains("although").not());
    assert!(!copy.exists());
}

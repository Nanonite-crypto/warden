//! What starts a file, removed with it and put back with it, on a real
//! Windows with the real `warden`.
//!
//! The entries are made with Windows' own tools: `reg`, `schtasks`, `sc`,
//! and the shell's object for shortcuts. What those tools show of an
//! entry before the file is quarantined is what they have to show again
//! after it is restored, to the letter.
//!
//! Two of the tests only read, and run everywhere. The others register a
//! service, tasks, Run values and a Startup shortcut on the machine they
//! run on, and run only where the environment says in as many words that
//! the machine may be changed: on the hosted runner of the CI, which is
//! deleted after the job, and in the virtual machine, from the kit. A
//! developer's `cargo test` does not run them.

#![cfg(windows)]
#![allow(clippy::unwrap_used)]
// A test may print: why it was skipped, and what Windows showed.
#![allow(clippy::disallowed_macros)]

// The entries are the same as in the tests of `warden-autostart`, which
// try the library on them. Here the whole program is tried.
#[path = "../../warden-autostart/tests/scene/mod.rs"]
mod scene;

use std::fs;

use assert_cmd::Command;
use scene::{ENTRIES, Report, Scene, print_views};

fn warden() -> Command {
    let mut command = assert_cmd::cargo_bin_cmd!("warden");
    command
        .env_remove("WARDEN_SIGDB")
        .env_remove("WARDEN_RULES")
        .env_remove("WARDEN_QUARANTINE")
        .env_remove("SOURCE_DATE_EPOCH");
    command
}

/// Runs `warden`. Returns whether it succeeded, and what it printed on
/// both streams.
fn run(command: &mut Command) -> (bool, String) {
    let output = command.output().unwrap();
    (
        output.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )
}

/// Every entry of the scene has to be named in what `warden` printed.
fn names_all(report: &mut Report, what: &str, text: &str) {
    for name in scene::names() {
        report.check(text.contains(&name), || {
            format!("{what} does not name {name}:\n{text}")
        });
    }
}

/// The identifier that `warden quarantine add` printed for the file.
fn entry_of(added: &str) -> String {
    added
        .lines()
        .find_map(|line| line.trim().strip_prefix("entry "))
        .unwrap_or_else(|| panic!("no entry was named in:\n{added}"))
        .trim()
        .to_owned()
}

#[test]
fn what_is_there_can_be_listed_without_changing_anything() {
    let output = warden()
        .args(["autostart", "list", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let listed: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let entries = listed["entries"].as_array().unwrap();
    // Every Windows has services, and each of them has a program.
    let services = entries
        .iter()
        .filter(|entry| entry["entry"]["kind"] == "service")
        .count();
    assert!(services > 50, "only {services} services were found");
    assert!(entries.iter().all(|entry| entry["lines"].is_array()));
    assert!(listed["problems"].is_array());

    // The same for people to read: a count for each of the four places.
    // The list itself is never printed, not even when something is wrong
    // with it: on a person's machine it says what is installed there.
    let output = warden().args(["autostart", "list"]).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout);
    for heading in [
        "Run and RunOnce values: ",
        "Scheduled tasks: ",
        "Services and drivers: ",
        "Shortcuts in the Startup folders: ",
    ] {
        assert!(text.contains(heading), "{heading} is missing");
    }
}

#[test]
fn a_file_that_nothing_starts_is_said_to_be_so() {
    let dir = tempfile::tempdir().unwrap();
    let lonely = dir.path().join("lonely.exe");
    fs::write(&lonely, b"nothing starts this").unwrap();
    let (ok, text) = run(warden().args(["autostart", "find"]).arg(&lonely));
    assert!(ok, "{text}");
    assert!(
        text.contains("Nothing that Warden looks at starts"),
        "{text}"
    );

    // A file that is not there cannot be looked for.
    let (ok, text) = run(warden()
        .args(["autostart", "find"])
        .arg(dir.path().join("missing.exe")));
    assert!(!ok);
    assert!(text.contains("is not a file that is there"), "{text}");
}

#[test]
fn what_starts_a_file_goes_with_it_and_comes_back_as_windows_showed_it() {
    if !scene::may_change_the_machine() {
        return;
    }
    let scene = Scene::set_up();
    let store = scene.dir().join("quarantine");
    let before = scene.shown_by_windows();
    print_views("what Windows' tools show of the scene", &before);
    let mut report = Report::default();
    report.all_there(&before);

    // Looking changes nothing.
    let (ok, found) = run(warden().args(["autostart", "find"]).arg(scene.threat()));
    println!("{found}");
    report.check(ok, || "autostart find failed".to_owned());
    names_all(&mut report, "autostart find", &found);
    report.check(
        found.contains(&format!("is started by {ENTRIES} entries")),
        || format!("autostart find does not count {ENTRIES} entries"),
    );
    // Each with its command line: the shortcut's as a person would write
    // it, the value with a variable in it as Windows fills it in.
    for line in [
        "threat.exe --from-shortcut",
        "threat.exe\",Start",
        "--from-boot-task",
    ] {
        report.check(found.contains(line), || {
            format!("autostart find does not show the command line with {line}")
        });
    }
    report.check(!found.contains("%SystemDrive%"), || {
        "autostart find shows a variable that it could have filled in".to_owned()
    });
    let (ok, json) = run(warden()
        .args(["autostart", "find", "--json"])
        .arg(scene.threat()));
    report.check(ok, || "autostart find --json failed".to_owned());
    match serde_json::from_str::<serde_json::Value>(&json) {
        Ok(value) => report.check(
            value["entries"].as_array().map(Vec::len) == Some(ENTRIES),
            || format!("autostart find --json does not hold {ENTRIES} entries:\n{json}"),
        ),
        Err(error) => report.wrong(format!("autostart find --json: {error}\n{json}")),
    }
    report.same_as_before(&before, &scene.shown_by_windows());

    // Quarantined: the file and everything that started it are gone.
    let (ok, added) = run(warden()
        .args(["quarantine", "add", "--dir"])
        .arg(&store)
        .arg(scene.threat()));
    println!("{added}");
    assert!(ok, "quarantine add failed:\n{added}");
    let id = entry_of(&added);
    names_all(&mut report, "quarantine add", &added);
    report.check(added.matches("  removed    ").count() == ENTRIES, || {
        format!("quarantine add did not remove {ENTRIES} entries")
    });
    report.check(!added.contains("  left       "), || {
        "quarantine add left an entry".to_owned()
    });
    report.check(!scene.threat().exists(), || {
        "the file is still at its place".to_owned()
    });
    report.all_gone(&scene.shown_by_windows());
    let (_, listed) = run(warden().args(["autostart", "list"]));
    report.check(!listed.contains("WardenTestThreat"), || {
        "autostart list still names an entry of the scene".to_owned()
    });

    // The quarantine says what it holds for the file.
    let (ok, info) = run(warden()
        .args(["quarantine", "info", &id, "--dir"])
        .arg(&store));
    println!("{info}");
    report.check(ok, || "quarantine info failed".to_owned());
    names_all(&mut report, "quarantine info", &info);
    let (ok, in_store) = run(warden().args(["quarantine", "list", "--dir"]).arg(&store));
    println!("{in_store}");
    report.check(ok && in_store.contains("removed with it"), || {
        "quarantine list does not say what was removed with the file".to_owned()
    });

    // Restored: the file is back, and Windows shows every entry as it
    // showed it before.
    let (ok, restored) = run(warden()
        .args(["quarantine", "restore", &id, "--dir"])
        .arg(&store));
    println!("{restored}");
    report.check(ok, || "quarantine restore failed".to_owned());
    names_all(&mut report, "quarantine restore", &restored);
    for reservation in ["Not put back", "not in every detail", "could not be"] {
        report.check(!restored.contains(reservation), || {
            format!("quarantine restore says \"{reservation}\"")
        });
    }
    report.check(scene.threat().exists(), || {
        "the file is not back".to_owned()
    });
    let after = scene.shown_by_windows();
    print_views("what Windows' tools show after the restore", &after);
    report.same_as_before(&before, &after);

    // Nothing is left in the quarantine, of the file or of its entries.
    let (ok, listed) = run(warden().args(["quarantine", "list", "--dir"]).arg(&store));
    report.check(ok && listed.contains("Nothing is in quarantine."), || {
        format!("the quarantine is not empty:\n{listed}")
    });
    report.check(!listed.contains("Still owed"), || {
        format!("something is still owed:\n{listed}")
    });
    report.finish();
}

#[test]
fn deleting_the_file_for_good_leaves_nothing_of_what_started_it() {
    if !scene::may_change_the_machine() {
        return;
    }
    let scene = Scene::set_up();
    let store = scene.dir().join("quarantine");
    let mut report = Report::default();

    let (ok, added) = run(warden()
        .args(["quarantine", "add", "--dir"])
        .arg(&store)
        .arg(scene.threat()));
    assert!(ok, "quarantine add failed:\n{added}");
    let id = entry_of(&added);
    let (ok, deleted) = run(warden()
        .args(["quarantine", "delete", &id, "--dir"])
        .arg(&store));
    println!("{deleted}");
    report.check(ok, || format!("quarantine delete failed:\n{deleted}"));
    report.all_gone(&scene.shown_by_windows());
    let (_, listed) = run(warden().args(["quarantine", "list", "--dir"]).arg(&store));
    report.check(listed.contains("Nothing is in quarantine."), || {
        format!("the quarantine is not empty:\n{listed}")
    });
    report.finish();
}

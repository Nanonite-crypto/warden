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

/// The entry of a driver that Windows loads while it starts, made with
/// `sc` for a file that is no driver. Removed again when it goes, whatever
/// happened: Windows would look at such an entry the next time it starts,
/// and this one is never there for that.
struct BootDriver {
    name: &'static str,
}

impl BootDriver {
    fn register(name: &'static str, file: &std::path::Path) -> Self {
        // What an earlier run may have left.
        let _ = scene::tool("sc", &["delete", name]);
        let driver = Self { name };
        scene::must(
            "sc",
            &[
                "create",
                name,
                "type=",
                "kernel",
                "start=",
                "boot",
                // If Windows ever did get to it: go on without it.
                "error=",
                "ignore",
                "binPath=",
                &file.display().to_string(),
                "DisplayName=",
                "Warden test boot driver",
            ],
        );
        driver
    }

    /// What `sc` and `reg` show of the entry: its settings, and its whole
    /// key. An entry that is not there shows as `None`.
    fn shown(&self) -> (Option<String>, Option<String>) {
        let key = format!(r"HKLM\SYSTEM\CurrentControlSet\Services\{}", self.name);
        let view = |(ok, text): (bool, String)| ok.then_some(text);
        (
            view(scene::tool("sc", &["qc", self.name])),
            view(scene::tool("reg", &["query", &key, "/s"])),
        )
    }
}

impl Drop for BootDriver {
    fn drop(&mut self) {
        let _ = scene::tool("sc", &["delete", self.name]);
    }
}

/// The second guard of the quarantine, on a real Windows: a file that
/// Windows loads as a driver while it starts is left where it is, with
/// the driver's name. With the flag of its own it is taken, its entry
/// goes with it, and a restore brings both back as `sc` and `reg` showed
/// them.
#[test]
fn a_driver_that_windows_loads_while_it_starts_stays_unless_the_flag_is_given() {
    if !scene::may_change_the_machine() {
        return;
    }
    const NAME: &str = "WardenTestBootDriver";
    const WHY: &str = "Windows loads it as the driver WardenTestBootDriver while it starts";
    const FLAG: &str = "--even-if-loaded-at-boot";

    // A folder with blanks in its name, and a real program in it that is
    // no driver and that nothing ever loads: a copy of this test.
    let dir = tempfile::Builder::new()
        .prefix("Warden boot driver ")
        .tempdir()
        .unwrap();
    let file = dir.path().join("wardentest.sys");
    fs::copy(std::env::current_exe().unwrap(), &file).unwrap();
    let store = dir.path().join("quarantine");
    let driver = BootDriver::register(NAME, &file);
    let before = driver.shown();
    println!("{before:#?}");
    assert!(before.0.is_some() && before.1.is_some(), "{before:?}");

    // Warden sees which driver the file is.
    let (ok, found) = run(warden().args(["autostart", "find"]).arg(&file));
    println!("{found}");
    assert!(ok, "{found}");
    assert!(found.contains(&format!("the driver {NAME}")), "{found}");

    // Left where it is, with the reason and the way past it. Nothing is
    // changed: not the file, not the entry, and nothing is in quarantine.
    let (ok, refused) = run(warden()
        .args(["quarantine", "add", "--dir"])
        .arg(&store)
        .arg(&file));
    println!("{refused}");
    assert!(!ok, "{refused}");
    assert!(
        refused.contains(&format!("was left where it is: {WHY}")),
        "{refused}"
    );
    assert!(refused.contains(&format!("add {FLAG}.")), "{refused}");
    // It is no file of Windows, so the other flag is not asked for.
    assert!(
        !refused.contains("--even-if-signed-by-windows"),
        "{refused}"
    );
    assert!(file.exists());
    assert_eq!(driver.shown(), before);
    let (_, listed) = run(warden().args(["quarantine", "list", "--dir"]).arg(&store));
    assert!(listed.contains("Nothing is in quarantine."), "{listed}");

    // The flag for files of Windows is not the flag for this.
    let (ok, wrong_flag) = run(warden()
        .args(["quarantine", "add", "--even-if-signed-by-windows", "--dir"])
        .arg(&store)
        .arg(&file));
    assert!(!ok, "{wrong_flag}");
    assert!(file.exists());

    // With its own flag the file is taken, and the output says what was
    // set aside. The entry goes with the file.
    let (ok, added) = run(warden()
        .args(["quarantine", "add", FLAG, "--dir"])
        .arg(&store)
        .arg(&file));
    println!("{added}");
    assert!(ok, "{added}");
    assert!(added.contains(&format!("although   {WHY}")), "{added}");
    assert!(
        added.contains(&format!("removed    the driver {NAME}")),
        "{added}"
    );
    assert!(!file.exists());
    assert_eq!(driver.shown(), (None, None));

    // Restored: the file, and the entry as Windows showed it before.
    let id = entry_of(&added);
    let (ok, restored) = run(warden()
        .args(["quarantine", "restore", &id, "--dir"])
        .arg(&store));
    println!("{restored}");
    assert!(ok, "{restored}");
    assert!(file.exists());
    assert!(
        restored.contains(&format!("the driver {NAME}")),
        "{restored}"
    );
    let after = driver.shown();
    println!("{after:#?}");
    assert_eq!(after, before, "the entry is not what it was");
}

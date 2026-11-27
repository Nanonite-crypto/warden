//! The script that runs the tests of this crate in a virtual machine has
//! to know the names of what they make.
//!
//! `scripts/win/autostart-remedy.ps1` runs the tests of `on_windows.rs`
//! as a program, on a machine that is kept. The tests remove what they
//! make, and the script removes it once more with Windows' own tools, in
//! case the program died half way: above all the driver that Windows
//! would load at its next start. It also leaves one test out by its name.
//! The names are written in two places then, here and in the script, and
//! this test fails when the two no longer agree. It reads both as text
//! and runs on every system.

use std::fs;
use std::path::{Path, PathBuf};

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &str) -> String {
    let path = repository().join(path);
    fs::read_to_string(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

/// The string constants of a Rust source file, by their names: the lines
/// of the form `const NAME: &str = "value";`, with `pub` or without, and
/// with a raw string or an ordinary one. No constant of these tests holds
/// a quote or an escape, so the text between the quotes is the value.
fn constants(source: &str) -> Vec<(String, String)> {
    let mut found = Vec::new();
    for line in source.lines() {
        let line = line.trim();
        let line = line.strip_prefix("pub ").unwrap_or(line);
        let Some(rest) = line.strip_prefix("const ") else {
            continue;
        };
        let Some((name, value)) = rest.split_once(": &str = ") else {
            continue;
        };
        let value = value.strip_prefix('r').unwrap_or(value);
        let Some(value) = value
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix("\";"))
        else {
            panic!("a constant this test cannot read: {line}");
        };
        assert!(
            !value.contains('"') && !value.contains("\\\\"),
            "a constant with a quote or an escape in it: {line}"
        );
        found.push((name.to_owned(), value.to_owned()));
    }
    found
}

#[test]
fn the_script_for_the_virtual_machine_knows_every_name_the_tests_use() {
    let script = read("scripts/win/autostart-remedy.ps1");
    let scene = read("crates/warden-autostart/tests/scene/mod.rs");
    let tests = read("crates/warden-autostart/tests/on_windows.rs");

    let mut names = constants(&scene);
    names.extend(constants(&tests));
    let known: Vec<&str> = names.iter().map(|(name, _)| name.as_str()).collect();
    // What this test expects to find. A new constant has to be put here,
    // and into the script if it names something that is made on the
    // machine.
    let expected = [
        "ALLOW",
        "ALLOWED",
        "RUN_KEY",
        "USER_VALUE",
        "MACHINE_VALUE",
        "OLD_VIEW_VALUE",
        "TASK",
        "BOOT_TASK",
        "SERVICE",
        "SHORTCUT",
        "BOOT_DRIVER",
        "ELSEWHERE",
    ];
    assert_eq!(
        known, expected,
        "the string constants of the tests on a real Windows have changed: \
         see to scripts/win/autostart-remedy.ps1, then to this list"
    );

    let mut missing = Vec::new();
    for (name, value) in &names {
        // The script sets the variable that allows the tests, and holds
        // every other name as a text of its own between single quotes.
        let in_script = if name == "ALLOW" {
            format!("$env:{value} = ")
        } else {
            format!("'{value}'")
        };
        if !script.contains(&in_script) {
            missing.push(format!("{name}: {in_script}"));
        }
    }
    assert!(
        missing.is_empty(),
        "scripts/win/autostart-remedy.ps1 does not have these, which the tests on a real \
         Windows use: {missing:?}"
    );

    // The folder of the two tasks, which the script removes by its name.
    let folder = names
        .iter()
        .find(|(name, _)| name == "TASK")
        .and_then(|(_, task)| task.trim_start_matches('\\').split('\\').next())
        .expect("the task has a folder");
    assert!(
        script.contains(&format!("$testTaskFolder = '{folder}'")),
        "the script does not know the folder of the tests' tasks: {folder}"
    );

    // The file of the driver, which is a name inside a path there.
    let file = "wardentest.sys";
    assert!(scene.contains(&format!(".join(\"{file}\")")));
    assert!(
        script.contains(&format!("System32\\drivers\\{file}'")),
        "the script does not know the file of the tests' driver: {file}"
    );

    // The test that the script leaves out unless it is told otherwise.
    let left_out = script
        .lines()
        .find_map(|line| line.trim().strip_prefix("$bootDriverTestName = '"))
        .and_then(|rest| rest.strip_suffix('\''))
        .expect("the script names the test that registers a driver with the start \"boot\"");
    assert!(
        tests.contains(&format!("fn {left_out}()")),
        "the script leaves out a test that is not there: {left_out}"
    );
    // That test, and no other, is the one that makes such a driver.
    let body = tests
        .split(&format!("fn {left_out}()"))
        .nth(1)
        .expect("the test has a body");
    assert!(body.contains("BootDriver::register()"));
    assert_eq!(
        tests.matches("BootDriver::register()").count(),
        1,
        "more than one test registers a driver with the start \"boot\", and the script leaves \
         out one"
    );
}

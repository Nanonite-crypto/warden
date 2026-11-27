//! The stand-in writes down each start, and that is all it does.

#![allow(clippy::unwrap_used)]

use std::fs;
use std::process::Command;

#[test]
fn each_start_adds_one_line_next_to_the_program() {
    let dir = tempfile::tempdir().unwrap();
    let name = if cfg!(windows) { "dummy.exe" } else { "dummy" };
    let program = dir.path().join(name);
    fs::copy(env!("CARGO_BIN_EXE_warden-dummy"), &program).unwrap();
    let log = dir.path().join("warden-dummy-starts.log");
    assert!(!log.exists());

    for arguments in [vec!["--from-run"], vec!["--service", "two words"], vec![]] {
        let output = Command::new(&program).args(&arguments).output().unwrap();
        assert!(output.status.success());
        // It says nothing, to anybody.
        assert!(output.stdout.is_empty() && output.stderr.is_empty());
    }

    let written = fs::read_to_string(&log).unwrap();
    let lines: Vec<&str> = written.lines().collect();
    assert_eq!(lines.len(), 3, "{written}");
    assert!(lines[0].ends_with(" args=--from-run"), "{written}");
    assert!(lines[1].ends_with(" args=--service two words"), "{written}");
    assert!(lines[2].ends_with(" args="), "{written}");
    for line in &lines {
        let seconds: u64 = line.split(' ').next().unwrap().parse().unwrap();
        // After the year 2020.
        assert!(seconds > 1_577_836_800, "{line}");
        assert!(line.contains(" pid=") && line.contains(" user="), "{line}");
    }

    // Nothing else appeared next to it.
    let mut names: Vec<String> = fs::read_dir(dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names, [name, "warden-dummy-starts.log"]);
}

/// The stand-in is started on a Windows that nobody has prepared, as Warden
/// is: the virtual machine it is made for was installed and nothing else.
/// So it may not ask for a library that only comes with Microsoft's Visual
/// C++ runtime, or Windows could not start it there. The build setting that
/// sees to it is in `.cargo/config.toml`, and holds for every program of
/// this workspace.
#[cfg(windows)]
#[test]
fn it_needs_no_library_that_a_fresh_windows_lacks() {
    let bytes = fs::read(env!("CARGO_BIN_EXE_warden-dummy")).unwrap();
    let facts = warden_pe::read(&bytes).unwrap();
    let libraries: Vec<String> = facts
        .imports
        .iter()
        .map(|library| library.name.to_ascii_lowercase())
        .collect();
    assert!(
        libraries.iter().any(|name| name == "kernel32.dll"),
        "the import table was not read: {libraries:?}"
    );
    let not_part_of_windows = [
        "vcruntime",
        "msvcp",
        "msvcr",
        "vccorlib",
        "concrt",
        "ucrtbased",
    ];
    let missing_on_a_fresh_windows: Vec<&String> = libraries
        .iter()
        .filter(|name| {
            not_part_of_windows
                .iter()
                .any(|family| name.starts_with(family))
        })
        .collect();
    assert!(
        missing_on_a_fresh_windows.is_empty(),
        "warden-dummy.exe loads {missing_on_a_fresh_windows:?}, which a fresh Windows does not have; \
         is RUSTFLAGS set, so that .cargo/config.toml is ignored?"
    );
}

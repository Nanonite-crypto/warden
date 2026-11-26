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

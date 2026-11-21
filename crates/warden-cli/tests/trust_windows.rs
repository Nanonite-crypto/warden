//! The whole path on Windows, with the real `warden` and real signatures:
//! a rule that matches every program, a folder of programs that different
//! people signed, and what a scan of it reports.
//!
//! The rule stands in for a published rule that is wrong about clean
//! software. The programs are a copy of one that Microsoft signed, which is
//! on every hosted runner, and, where CI has made them, programs with the
//! signatures that have to be turned down, see
//! `.github/scripts/signed-test-files.ps1`.

#![cfg(windows)]
#![allow(clippy::unwrap_used)]
// A test that says why it was skipped may print.
#![allow(clippy::disallowed_macros)]

use std::fs;
use std::path::{Path, PathBuf};

use assert_cmd::Command;

const RULES: &str = r#"
rule Test_Any_Windows_Program
{
    meta:
        description = "starts the way a Windows program starts"
        score = 90
    condition:
        uint16(0) == 0x5A4D
}
"#;

fn warden() -> Command {
    let mut command = assert_cmd::cargo_bin_cmd!("warden");
    command
        .env_remove("WARDEN_SIGDB")
        .env_remove("WARDEN_RULES")
        .env_remove("WARDEN_QUARANTINE")
        .env_remove("SOURCE_DATE_EPOCH");
    command
}

fn required() -> bool {
    std::env::var("WARDEN_REQUIRE_SIGNED_FIXTURES").is_ok_and(|value| value == "1")
}

fn bundle(dir: &Path) -> PathBuf {
    let rules = dir.join("any-program.yar");
    fs::write(&rules, RULES).unwrap();
    let bundle = dir.join("any-program.wrb");
    warden()
        .args(["rules", "build", "--created", "1800000000", "--out"])
        .arg(&bundle)
        .arg(&rules)
        .assert()
        .success();
    bundle
}

/// A program on this machine that Microsoft signed as Microsoft
/// Corporation, in the file itself.
fn a_program_of_microsofts() -> Option<PathBuf> {
    let program_files = PathBuf::from(
        std::env::var_os("ProgramFiles").unwrap_or_else(|| "C:\\Program Files".into()),
    );
    [
        program_files.join("PowerShell\\7\\pwsh.exe"),
        program_files.join("dotnet\\dotnet.exe"),
        program_files.join("Microsoft VS Code\\Code.exe"),
    ]
    .into_iter()
    .find(|candidate| {
        candidate.exists()
            && warden()
                .args(["trust", "check"])
                .arg(candidate)
                .assert()
                .get_output()
                .status
                .success()
    })
}

fn json_of(command: &mut Command, code: i32) -> serde_json::Value {
    let output = command.assert().code(code).get_output().stdout.clone();
    serde_json::from_slice(&output).unwrap()
}

/// The entry of a list of files whose path ends in `name`.
fn entry<'a>(list: &'a serde_json::Value, name: &str) -> &'a serde_json::Value {
    list.as_array()
        .unwrap()
        .iter()
        .find(|file| file["path"].as_str().unwrap().ends_with(name))
        .unwrap_or_else(|| panic!("{name} is not in {list}"))
}

#[test]
fn a_rule_match_is_reported_unless_a_trusted_publisher_signed_the_file() {
    let Some(microsofts) = a_program_of_microsofts() else {
        assert!(
            !required(),
            "no program on this machine is trusted as Microsoft Corporation"
        );
        eprintln!("skipped: no program of Microsoft's among the candidates on this machine");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let bundle = bundle(dir.path());
    let tree = dir.path().join("tree");
    fs::create_dir_all(&tree).unwrap();
    // A copy keeps its signature: the signature is part of the file.
    fs::copy(&microsofts, tree.join("from-microsoft.exe")).unwrap();
    // Two bytes of a program and nothing of a signature.
    fs::write(
        tree.join("from-nobody.exe"),
        b"MZ and then nothing of a program",
    )
    .unwrap();

    let mut expected_flagged = vec!["from-nobody.exe"];
    let fixtures = std::env::var_os("WARDEN_SIGNED_FIXTURES").map(PathBuf::from);
    match &fixtures {
        Some(fixtures) if fixtures.join("signed.exe").exists() => {
            for name in [
                "plain.exe",
                "signed.exe",
                "tampered.exe",
                "padded.exe",
                "lookalike.exe",
            ] {
                fs::copy(fixtures.join(name), tree.join(name)).unwrap();
                expected_flagged.push(name);
            }
        }
        _ => assert!(
            !required(),
            "WARDEN_SIGNED_FIXTURES does not point at the signed test files"
        ),
    }
    expected_flagged.sort_unstable();

    let check = json_of(
        warden()
            .arg("false-positives")
            .arg(&tree)
            .arg("--rules")
            .arg(&bundle)
            .args(["--json", "--no-progress"]),
        1,
    );
    println!("{}", serde_json::to_string_pretty(&check).unwrap());

    // Every file matched the rule, so every file was asked about.
    let files = expected_flagged.len() as u64 + 1;
    assert_eq!(check["files_scanned"], files);
    assert_eq!(check["trust_check"]["available"], true);
    assert_eq!(check["trust_checks"], files);
    assert_eq!(check["files_trusted"], 1);

    // The program of Microsoft's is on record and not flagged.
    assert_eq!(check["recorded_files"], 1);
    let recorded = entry(&check["recorded"], "from-microsoft.exe");
    assert_eq!(recorded["names"][0], "Test_Any_Windows_Program");
    assert_eq!(recorded["trust"]["answer"], "trusted");
    assert_eq!(recorded["trust"]["publisher"], "Microsoft Corporation");
    assert_eq!(recorded["trust"]["route"], "embedded");

    // Everything else is flagged, each for its own reason.
    let flagged: Vec<&str> = check["flagged"]
        .as_array()
        .unwrap()
        .iter()
        .map(|file| {
            Path::new(file["path"].as_str().unwrap())
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
        })
        .collect();
    assert_eq!(flagged, expected_flagged);
    let nobody = entry(&check["flagged"], "from-nobody.exe");
    assert_eq!(nobody["trust"]["reason"], "no_signature");
    if fixtures.is_some() && expected_flagged.len() > 1 {
        let reason_of = |name: &str| entry(&check["flagged"], name)["trust"]["reason"].clone();
        assert_eq!(reason_of("plain.exe"), "no_signature");
        // Valid signatures, both, and neither is of a trusted publisher.
        assert_eq!(reason_of("signed.exe"), "not_listed");
        assert_eq!(reason_of("lookalike.exe"), "not_listed");
        assert_eq!(reason_of("tampered.exe"), "invalid");
        assert_eq!(reason_of("padded.exe"), "invalid");
        let lookalike = entry(&check["flagged"], "lookalike.exe");
        assert!(
            lookalike["trust"]["detail"]
                .as_str()
                .unwrap()
                .contains("signed for Microsoft Corporation"),
            "{lookalike}"
        );
    }

    // The scan says why the one file was left alone.
    let text = warden()
        .arg("scan")
        .arg(&tree)
        .arg("--rules")
        .arg(&bundle)
        .arg("--no-progress")
        .assert()
        .code(1)
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8_lossy(&text);
    assert!(
        text.contains(
            "does not change the verdict: signed for Microsoft Corporation, found in the file \
             itself"
        ),
        "{text}"
    );
    assert!(
        text.contains("ON RECORD   Test_Any_Windows_Program"),
        "{text}"
    );

    // Without the check, the same scan flags the program of Microsoft's
    // too. That is the false positive the check is there for.
    let without = json_of(
        warden()
            .arg("false-positives")
            .arg(&tree)
            .arg("--rules")
            .arg(&bundle)
            .args(["--no-trust", "--json", "--no-progress"]),
        1,
    );
    assert_eq!(without["recorded_files"], 0);
    assert_eq!(
        without["flagged"].as_array().unwrap().len() as u64,
        files,
        "{without}"
    );
}

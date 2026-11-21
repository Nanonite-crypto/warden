//! The check against Windows itself: real signatures, real catalogues, a
//! real package.
//!
//! Everything else in this crate is tested with a stand-in that answers
//! for Windows. These tests ask Windows.
//!
//! Some of them need nothing but a Windows installation: they look at
//! files of Windows and of Microsoft's that are on every machine. They may
//! use the network, because Windows asks over it whether a certificate was
//! revoked.
//!
//! The others need signatures that nobody hands out: a valid one of a
//! publisher on no trust list, one on a file that was changed afterwards,
//! one with bytes added next to it, one that carries Microsoft's names
//! under a root of somebody else's, and a signed app package. CI makes
//! them on a machine that is thrown away afterwards, see
//! `.github/scripts/signed-test-files.ps1`, and points
//! `WARDEN_SIGNED_FIXTURES` at them. Without that variable these tests
//! pass with a note, unless `WARDEN_REQUIRE_SIGNED_FIXTURES` is `1`, as it
//! is in CI.

#![cfg(windows)]
#![allow(clippy::unwrap_used)]
// A test that says why it was skipped, or what it found, may print.
#![allow(clippy::disallowed_macros)]

use std::path::{Path, PathBuf};

use warden_trust::{
    Examination, Found, Options, Reason, Revocation, Route, Signer, Trust, TrustList, Verifier,
};

fn verifier() -> Verifier {
    Verifier::new(TrustList::builtin().unwrap(), Options::default())
}

fn required(variable: &str) -> bool {
    std::env::var(variable).is_ok_and(|value| value == "1")
}

/// The folder with the signed test files, or nothing, with a note, where
/// there is none and none is required.
fn fixtures() -> Option<PathBuf> {
    match std::env::var_os("WARDEN_SIGNED_FIXTURES") {
        Some(folder) if Path::new(&folder).join("signed.exe").exists() => {
            Some(PathBuf::from(folder))
        }
        _ if required("WARDEN_REQUIRE_SIGNED_FIXTURES") => {
            panic!("WARDEN_SIGNED_FIXTURES does not point at the signed test files")
        }
        _ => {
            eprintln!("skipped: WARDEN_SIGNED_FIXTURES is not set, see docs/TESTING.md");
            None
        }
    }
}

/// Whether the tests that depend on what is installed and on the network
/// have to find what they look for.
fn strict() -> bool {
    required("WARDEN_REQUIRE_SIGNED_FIXTURES")
}

fn examine(path: &Path) -> Examination {
    let examination = verifier().examine(path, None, true);
    println!(
        "{}\n{}",
        path.display(),
        serde_json::to_string_pretty(&examination).unwrap()
    );
    examination
}

fn found(examination: &Examination, route: Route) -> &Found {
    &examination
        .routes
        .iter()
        .find(|report| report.route == route)
        .unwrap_or_else(|| panic!("no report for {route:?}"))
        .found
}

fn signer(examination: &Examination, route: Route) -> &Signer {
    match found(examination, route) {
        Found::Valid { signer, .. } => signer,
        other => panic!("{route:?} found no valid signature: {other:?}"),
    }
}

fn reason(examination: &Examination) -> Reason {
    match &examination.trust {
        Trust::NotTrusted { reason, .. } => *reason,
        Trust::Trusted { .. } => panic!("trusted: {:?}", examination.trust),
    }
}

fn detail(examination: &Examination) -> &str {
    match &examination.trust {
        Trust::NotTrusted { detail, .. } => detail,
        Trust::Trusted { .. } => panic!("trusted: {:?}", examination.trust),
    }
}

fn system32() -> PathBuf {
    PathBuf::from(std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into()))
        .join("System32")
}

// --- Files that are on every Windows machine --------------------------------

#[test]
fn files_of_windows_are_signed_under_a_root_of_microsofts_in_the_file_or_in_a_catalogue() {
    let verifier = verifier();
    let mut embedded = 0;
    let mut catalogue = 0;
    for name in [
        "ntdll.dll",
        "kernel32.dll",
        "user32.dll",
        "cmd.exe",
        "whoami.exe",
        "find.exe",
        "tasklist.exe",
        "crypt32.dll",
        "wintrust.dll",
        "notepad.exe",
    ] {
        let path = system32().join(name);
        if !path.exists() {
            continue;
        }
        let examination = verifier.examine(&path, None, false);
        let Some((route, signer)) =
            examination
                .routes
                .iter()
                .find_map(|report| match &report.found {
                    Found::Valid { signer, .. } => Some((report.route, signer)),
                    _ => None,
                })
        else {
            println!("{name}: {:?}", examination.trust);
            continue;
        };
        println!(
            "{name}: {} / {} by {route:?}, a root of Microsoft's: {}, revocation {:?}, chain {:?}, {:?}",
            signer.common_name,
            signer.organization,
            signer.microsoft_root,
            signer.revocation,
            signer
                .chain
                .iter()
                .map(|certificate| certificate.subject.as_str())
                .collect::<Vec<_>>(),
            examination.trust
        );
        assert!(
            signer.microsoft_root,
            "{name} is signed under a root that is not Microsoft's"
        );
        assert!(signer.chain.len() >= 2, "{name}: {:?}", signer.chain);
        assert!(signer.common_name.starts_with("Microsoft"), "{name}");
        if strict() {
            assert_eq!(signer.revocation, Revocation::Checked, "{name}");
        }
        match route {
            Route::Embedded => embedded += 1,
            Route::WindowsCatalog => catalogue += 1,
            Route::Package => panic!("{name} is in no package"),
        }
    }
    println!("{embedded} signed in the file, {catalogue} in a catalogue");
    assert!(
        embedded + catalogue >= 5,
        "too few files of Windows have a signature that Warden finds"
    );
    assert!(
        catalogue >= 1,
        "no file was found through a catalogue, the way most of Windows is signed"
    );
}

#[test]
fn an_application_of_microsofts_is_trusted() {
    let program_files = PathBuf::from(
        std::env::var_os("ProgramFiles").unwrap_or_else(|| "C:\\Program Files".into()),
    );
    let candidates = [
        program_files.join("PowerShell\\7\\pwsh.exe"),
        program_files.join("dotnet\\dotnet.exe"),
        program_files.join("Microsoft VS Code\\Code.exe"),
        program_files.join("Windows Defender\\MpCmdRun.exe"),
    ];
    let verifier = verifier();
    let mut trusted = 0;
    for path in candidates.iter().filter(|path| path.exists()) {
        let examination = verifier.examine(path, None, false);
        println!("{}: {:?}", path.display(), examination.trust);
        if let Trust::Trusted { publisher, route } = &examination.trust
            && publisher == "Microsoft Corporation"
        {
            assert_eq!(*route, Route::Embedded);
            let signer = signer(&examination, Route::Embedded);
            assert_eq!(signer.common_name, "Microsoft Corporation");
            assert_eq!(signer.organization, "Microsoft Corporation");
            assert!(signer.microsoft_root);
            assert_eq!(signer.revocation, Revocation::Checked);
            trusted += 1;
        }
    }
    if trusted == 0 {
        assert!(
            !strict(),
            "none of the candidates is there and trusted as Microsoft Corporation"
        );
        eprintln!("skipped: no application of Microsoft's among the candidates on this machine");
    }
}

#[test]
fn the_answer_is_about_the_content_that_was_scanned() {
    let path = system32().join("ntdll.dll");
    let verifier = verifier();
    let now = verifier.examine(&path, None, false);
    let sha256 = now.sha256.clone().unwrap();
    let mut scanned = [0u8; 32];
    for (byte, pair) in scanned.iter_mut().zip(sha256.as_bytes().chunks(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
    }
    // With the digest the file has, the answer is the same as without.
    assert_eq!(verifier.trust(&path, Some(&scanned)), now.trust);
    // With another one, the file counts as changed, whoever signed it.
    scanned[0] ^= 1;
    let changed = verifier.examine(&path, Some(&scanned), false);
    assert_eq!(reason(&changed), Reason::Changed);
    assert!(changed.routes.is_empty(), "nothing was asked about it");
}

// --- Files that CI makes ------------------------------------------------------

#[test]
fn a_program_nobody_signed_has_no_signature() {
    let Some(fixtures) = fixtures() else { return };
    let examination = examine(&fixtures.join("plain.exe"));
    assert_eq!(examination.executable, Some(true));
    assert_eq!(found(&examination, Route::Embedded), &Found::Nothing);
    assert_eq!(found(&examination, Route::WindowsCatalog), &Found::Nothing);
    assert_eq!(found(&examination, Route::Package), &Found::Nothing);
    assert_eq!(reason(&examination), Reason::NoSignature);
}

#[test]
fn a_valid_signature_of_a_publisher_on_no_list_is_not_enough() {
    let Some(fixtures) = fixtures() else { return };
    let examination = examine(&fixtures.join("signed.exe"));
    // Windows accepts the signature: the machine trusts the root.
    let signer = signer(&examination, Route::Embedded);
    assert_eq!(signer.common_name, "Warden Test Publisher");
    assert_eq!(signer.organization, "Warden Test");
    assert!(!signer.microsoft_root);
    assert_eq!(signer.chain.len(), 1, "the certificate is its own root");
    assert_eq!(signer.chain[0].sha256.len(), 64);
    // And Warden does not trust the file.
    assert_eq!(reason(&examination), Reason::NotListed);
    assert!(
        detail(&examination).contains("Warden Test Publisher"),
        "{}",
        detail(&examination)
    );
    // A file with a signature table is not looked up in the catalogues:
    // their hash does not cover that table.
    assert!(matches!(
        found(&examination, Route::WindowsCatalog),
        Found::NotApplicable { .. }
    ));
}

#[test]
fn a_file_that_was_changed_after_signing_does_not_pass() {
    let Some(fixtures) = fixtures() else { return };
    let examination = examine(&fixtures.join("tampered.exe"));
    let Found::Invalid { why } = found(&examination, Route::Embedded) else {
        panic!("{:?}", found(&examination, Route::Embedded));
    };
    assert!(why.contains("changed after it was signed"), "{why}");
    assert_eq!(reason(&examination), Reason::Invalid);
}

#[test]
fn bytes_added_next_to_a_signature_do_not_pass() {
    let Some(fixtures) = fixtures() else { return };
    let examination = examine(&fixtures.join("padded.exe"));
    // Windows, asked the usual way, calls this file validly signed: the
    // added bytes are in the one place a signature does not cover. Warden
    // looks through that place itself and does not get as far as asking.
    let Found::Invalid { why } = found(&examination, Route::Embedded) else {
        panic!("{:?}", found(&examination, Route::Embedded));
    };
    assert!(
        why.ends_with("so what the file carries as a signature does not count"),
        "{why}"
    );
    assert_eq!(reason(&examination), Reason::Invalid);
}

#[test]
fn microsofts_names_under_somebody_elses_root_are_not_microsoft() {
    let Some(fixtures) = fixtures() else { return };
    let examination = examine(&fixtures.join("lookalike.exe"));
    // The signature is valid, and it says Microsoft Corporation twice.
    let signer = signer(&examination, Route::Embedded);
    assert_eq!(signer.common_name, "Microsoft Corporation");
    assert_eq!(signer.organization, "Microsoft Corporation");
    assert_eq!(signer.chain.len(), 2);
    // What it does not have is a root of Microsoft's, by Windows' own
    // check of the root's key. So the names are worth nothing.
    assert!(!signer.microsoft_root);
    assert_eq!(reason(&examination), Reason::NotListed);
    // The certificate names no place to ask whether it was revoked.
    assert_eq!(signer.revocation, Revocation::Unknown);
}

#[test]
fn a_file_of_a_signed_package_is_vouched_for_by_the_package() {
    let Some(fixtures) = fixtures() else { return };
    let package = fixtures.join("package");
    if !package.exists() {
        assert!(
            !strict(),
            "the signed test package was not made: the tools for it were not found"
        );
        eprintln!("skipped: no test package among the signed test files");
        return;
    }

    // A text file: no signature of its own is even looked for.
    let notes = examine(&package.join("notes.txt"));
    assert_eq!(notes.executable, Some(false));
    let Found::Valid { signer, place } = found(&notes, Route::Package) else {
        panic!("{:?}", found(&notes, Route::Package));
    };
    assert_eq!(signer.common_name, "Warden Test Publisher");
    assert!(!signer.microsoft_root);
    assert!(
        place
            .as_deref()
            .is_some_and(|place| place.ends_with("package")),
        "{place:?}"
    );
    // The publisher is on no list, so the file is still not trusted. What
    // is tested here is that the route finds the signature.
    assert_eq!(reason(&notes), Reason::NotListed);
    assert!(
        detail(&notes).contains("the signature of the file's package"),
        "{}",
        detail(&notes)
    );

    // A program in a folder of the package, not signed itself.
    let tool = examine(&package.join("tools").join("tool.exe"));
    assert_eq!(tool.executable, Some(true));
    assert_eq!(found(&tool, Route::Embedded), &Found::Nothing);
    assert!(matches!(found(&tool, Route::Package), Found::Valid { .. }));

    // The files that make up the signature are part of the folder, and
    // the block map does not list itself.
    let block_map = examine(&package.join("AppxBlockMap.xml"));
    assert!(matches!(
        found(&block_map, Route::Package),
        Found::Invalid { .. }
    ));
}

#[test]
fn a_file_that_was_changed_or_added_in_a_package_is_not_vouched_for() {
    let Some(fixtures) = fixtures() else { return };
    if !fixtures.join("package-changed").exists() {
        assert!(!strict(), "the signed test package was not made");
        eprintln!("skipped: no test package among the signed test files");
        return;
    }

    let changed = examine(&fixtures.join("package-changed").join("notes.txt"));
    let Found::Invalid { why } = found(&changed, Route::Package) else {
        panic!("{:?}", found(&changed, Route::Package));
    };
    assert!(why.contains("not the one that the block map"), "{why}");
    assert_eq!(reason(&changed), Reason::Invalid);
    // Its neighbours are what they were.
    let untouched = examine(&fixtures.join("package-changed").join("logo.png"));
    assert!(matches!(
        found(&untouched, Route::Package),
        Found::Valid { .. }
    ));

    let added = examine(&fixtures.join("package-added").join("added.txt"));
    let Found::Invalid { why } = found(&added, Route::Package) else {
        panic!("{:?}", found(&added, Route::Package));
    };
    assert!(why.contains("does not list the file"), "{why}");
}

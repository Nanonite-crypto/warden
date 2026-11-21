//! What Windows keeps about a file besides its content, through the
//! quarantine and back: attribute bits, all three timestamps, the mark of
//! the internet, and the security descriptor.
//!
//! Whether something came back is checked by quarantining the restored
//! file a second time: the second record has to say what the first one
//! said. For the access rights there is an independent witness as well,
//! `icacls`, which prints them as Windows sees them.

#![cfg(windows)]
#![allow(clippy::unwrap_used)]

use std::fs;
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use warden_quarantine::{
    Entry, Outcome, Quarantine, QuarantineError, Reason, RestoreOptions, Step, sd,
};

const READ_ONLY: u32 = 0x1;
const HIDDEN: u32 = 0x2;
const SYSTEM: u32 = 0x4;

/// The built-in groups "Users" and "Administrators" and the system's own
/// account, by their identifiers: their names depend on the language of
/// the Windows installation.
const USERS: &str = "*S-1-5-32-545";
const ADMINISTRATORS: &str = "*S-1-5-32-544";
const SYSTEM_ACCOUNT: &str = "*S-1-5-18";

struct Scene {
    dir: tempfile::TempDir,
}

impl Scene {
    /// A temporary folder with a folder `files` in it for the files of a
    /// test.
    ///
    /// What rights a new file starts with depends on where the machine
    /// keeps its temporary files, and that is the machine's business. So
    /// `files` gets rights of its own, all of which it hands down: full
    /// control for the user who runs the test, and reading for the
    /// built-in group "Users". A file made in it has exactly those two
    /// entries, both taken from the folder.
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let files = dir.path().join("files");
        fs::create_dir(&files).unwrap();
        let shown = files.to_string_lossy().into_owned();
        let user = std::env::var("USERNAME").unwrap();
        run(
            "icacls",
            &[
                &shown,
                "/inheritance:r",
                "/grant:r",
                &format!("{user}:(OI)(CI)F"),
                "/grant:r",
                &format!("{USERS}:(OI)(CI)R"),
                "/remove:g",
                ADMINISTRATORS,
                "/remove:g",
                SYSTEM_ACCOUNT,
            ],
        );
        Self { dir }
    }

    fn quarantine(&self) -> Quarantine {
        Quarantine::open(self.dir.path().join("quarantine"))
            .unwrap()
            .0
    }

    fn file(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.dir.path().join("files").join(name);
        fs::write(&path, bytes).unwrap();
        path
    }
}

fn run(program: &str, arguments: &[&str]) -> String {
    let output = Command::new(program).args(arguments).output().unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.status.success(), "{program} {arguments:?}: {text}");
    text
}

/// The access rights of a file as `icacls` prints them, without the path
/// and the summary line.
fn rights(path: &Path) -> Vec<String> {
    let shown = path.to_string_lossy().into_owned();
    let mut lines: Vec<String> = run("icacls", &[&shown])
        .lines()
        .map(|line| line.replace(&shown, "").trim().to_owned())
        .filter(|line| !line.is_empty() && !line.starts_with("Successfully processed"))
        .collect();
    lines.sort();
    lines
}

/// Gives a file access rights of its own: none from its folder, `granted`
/// for the user who runs the test, and reading for the built-in group
/// "Users".
fn give_own_rights(path: &Path, granted: &str) {
    let shown = path.to_string_lossy().into_owned();
    let user = std::env::var("USERNAME").unwrap();
    run(
        "icacls",
        &[
            &shown,
            "/inheritance:r",
            "/grant:r",
            &format!("{user}:{granted}"),
            "/grant:r",
            &format!("{USERS}:R"),
        ],
    );
}

/// The security descriptor in an entry's record, in hexadecimal.
fn descriptor(entry: &Entry) -> String {
    entry
        .info
        .windows
        .as_ref()
        .unwrap()
        .security_descriptor
        .clone()
        .unwrap()
}

/// Quarantines a file and brings it back, and returns both records: the
/// one made on the way in, and the one a second quarantining makes of the
/// restored file.
fn there_and_back(quarantine: &Quarantine, path: &Path) -> (Entry, Entry, Vec<String>) {
    let first = quarantine.add(path, Reason::default()).unwrap();
    assert!(!path.exists());
    let restored = quarantine
        .restore(&first.info.id, &RestoreOptions::default())
        .unwrap();
    let second = quarantine.add(path, Reason::default()).unwrap();
    quarantine
        .restore(&second.info.id, &RestoreOptions::default())
        .unwrap();
    (first, second, restored.notes)
}

#[test]
fn an_ordinary_file_comes_back_without_a_remark() {
    let scene = Scene::new();
    let quarantine = scene.quarantine();
    // One file with rights that are known, and one as this machine makes a
    // file in its temporary folder, whatever rights that gives it.
    let prepared = scene.file("plain.txt", b"nothing special about this file");
    let as_it_comes = scene.dir.path().join("plain.txt");
    fs::write(&as_it_comes, b"nothing special about this file").unwrap();

    for path in [prepared, as_it_comes] {
        let shown = path.display();
        let before = fs::metadata(&path).unwrap();
        let rights_before = rights(&path);

        let (first, second, notes) = there_and_back(&quarantine, &path);
        assert_eq!(notes, Vec::<String>::new(), "{shown}");

        let windows = first.info.windows.as_ref().unwrap();
        assert!(first.info.unix.is_none());
        assert!(windows.security_descriptor.is_some());
        assert_eq!(windows.zone_identifier, None);
        assert_eq!(first.info.windows, second.info.windows, "{shown}");
        assert_eq!(first.info.times, second.info.times, "{shown}");

        let after = fs::metadata(&path).unwrap();
        assert_eq!(after.creation_time(), before.creation_time());
        assert_eq!(after.last_write_time(), before.last_write_time());
        assert_eq!(after.file_attributes(), before.file_attributes());
        assert_eq!(rights(&path), rights_before, "{shown}");
        assert_eq!(fs::read(&path).unwrap(), b"nothing special about this file");
    }
}

#[test]
fn attribute_bits_come_back() {
    let scene = Scene::new();
    let quarantine = scene.quarantine();
    for (name, flags, bits) in [
        ("read-only.bin", &["+r"][..], READ_ONLY),
        ("hidden.bin", &["+h"][..], HIDDEN),
        (
            "system-hidden-read-only.bin",
            &["+s", "+h", "+r"][..],
            SYSTEM | HIDDEN | READ_ONLY,
        ),
    ] {
        let path = scene.file(name, b"content");
        let shown = path.to_string_lossy().into_owned();
        let mut arguments = flags.to_vec();
        arguments.push(&shown);
        run("attrib", &arguments);
        let before = fs::metadata(&path).unwrap().file_attributes();
        assert_eq!(before & (READ_ONLY | HIDDEN | SYSTEM), bits, "{name}");

        let (first, second, notes) = there_and_back(&quarantine, &path);
        assert_eq!(notes, Vec::<String>::new(), "{name}");
        assert_eq!(first.info.windows.as_ref().unwrap().attributes, before);
        assert_eq!(
            second.info.windows.as_ref().unwrap().attributes & (READ_ONLY | HIDDEN | SYSTEM),
            bits,
            "{name}"
        );
        let after = fs::metadata(&path).unwrap().file_attributes();
        assert_eq!(after & (READ_ONLY | HIDDEN | SYSTEM), bits, "{name}");
        assert_eq!(fs::read(&path).unwrap(), b"content");
    }
}

#[test]
fn the_mark_of_the_internet_comes_back() {
    let scene = Scene::new();
    let path = scene.file("downloaded.exe", b"not really a program");
    let zone = b"[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://example.test/downloaded.exe\r\n";
    let stream = format!("{}:Zone.Identifier", path.display());
    fs::write(&stream, zone).unwrap();

    let quarantine = scene.quarantine();
    let (first, second, notes) = there_and_back(&quarantine, &path);
    assert_eq!(notes, Vec::<String>::new());
    let recorded = first.info.windows.as_ref().unwrap().zone_identifier.clone();
    assert_eq!(recorded, Some(warden_sigdb::hex::encode(zone)));
    assert_eq!(
        second.info.windows.as_ref().unwrap().zone_identifier,
        recorded
    );
    // A file that came from the internet still says so.
    assert_eq!(fs::read(&stream).unwrap(), zone);
    assert_eq!(fs::read(&path).unwrap(), b"not really a program");
}

#[test]
fn access_rights_of_its_own_come_back() {
    let scene = Scene::new();
    let path = scene.file("locked-down.bin", b"for a few eyes only");
    // No rights from the folder any more. The user who runs the test keeps
    // full control, and the built-in group "Users" may read.
    give_own_rights(&path, "F");
    let rights_before = rights(&path);
    assert_eq!(rights_before.len(), 2, "{rights_before:?}");
    assert!(
        rights_before.iter().all(|line| !line.contains("(I)")),
        "nothing inherited: {rights_before:?}"
    );

    let quarantine = scene.quarantine();
    let (first, second, notes) = there_and_back(&quarantine, &path);
    assert_eq!(notes, Vec::<String>::new());
    assert_eq!(rights(&path), rights_before);

    let shape = |hex: &str| {
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).unwrap())
            .collect();
        sd::check(&bytes).unwrap()
    };
    let before = shape(&descriptor(&first));
    assert!(before.owner && before.group && before.dacl);
    assert!(before.dacl_protected, "inheritance was switched off");
    assert_eq!(shape(&descriptor(&second)), before);
    // Byte for byte: owner, group, list and the flags that go with them.
    assert_eq!(descriptor(&second), descriptor(&first));
}

#[test]
fn rights_taken_from_the_folder_are_still_taken_from_the_folder() {
    let scene = Scene::new();
    let path = scene.file("ordinary.bin", b"content");
    let rights_before = rights(&path);
    assert_eq!(rights_before.len(), 2, "{rights_before:?}");
    assert!(
        rights_before.iter().all(|line| line.contains("(I)")),
        "all inherited: {rights_before:?}"
    );
    let quarantine = scene.quarantine();
    let (first, second, notes) = there_and_back(&quarantine, &path);
    assert_eq!(notes, Vec::<String>::new());
    assert_eq!(rights(&path), rights_before);
    assert_eq!(
        first.info.windows.as_ref().unwrap().security_descriptor,
        second.info.windows.as_ref().unwrap().security_descriptor
    );
}

/// The rights of a file can deny the one who restores it everything but
/// reading. They are put back all the same, and they do not get in the way
/// of putting the file back.
#[test]
fn rights_that_shut_out_whoever_restores_the_file_come_back_too() {
    let scene = Scene::new();
    let path = scene.file("look-do-not-touch.bin", b"look, do not touch");
    give_own_rights(&path, "R");
    let rights_before = rights(&path);
    let writable = |path: &Path| fs::OpenOptions::new().append(true).open(path).is_ok();
    assert!(!writable(&path), "the test could write to the file");

    let quarantine = scene.quarantine();
    let (first, second, notes) = there_and_back(&quarantine, &path);
    assert_eq!(notes, Vec::<String>::new());
    assert_eq!(rights(&path), rights_before);
    assert_eq!(descriptor(&second), descriptor(&first));
    assert!(!writable(&path), "the restored file can be written to");
    assert_eq!(fs::read(&path).unwrap(), b"look, do not touch");
}

/// The read-only bit and the access rights go on after the file has its
/// name. A restore that dies in between is finished when the quarantine is
/// next opened, and the file gets both then.
#[test]
fn a_restore_cut_off_after_the_file_had_its_name_still_gives_it_its_rights() {
    let scene = Scene::new();
    let path = scene.file("cut-off.bin", b"content");
    give_own_rights(&path, "F");
    let shown = path.to_string_lossy().into_owned();
    run("attrib", &["+r", &shown]);
    let rights_before = rights(&path);
    let store = scene.dir.path().join("quarantine");

    let id = {
        let (mut quarantine, _) = Quarantine::open(&store).unwrap();
        let entry = quarantine.add(&path, Reason::default()).unwrap();
        quarantine.interrupt_after(Step::RestoreCommitted);
        let died = quarantine
            .restore(&entry.info.id, &RestoreOptions::default())
            .unwrap_err();
        assert!(matches!(died, QuarantineError::Interrupted(_)), "{died}");
        entry.info.id
    };
    // The file is back, so far as its folder makes a new file.
    assert_eq!(fs::read(&path).unwrap(), b"content");
    assert_ne!(rights(&path), rights_before);
    assert_eq!(
        fs::metadata(&path).unwrap().file_attributes() & READ_ONLY,
        0
    );

    let (quarantine, recovered) = Quarantine::open(&store).unwrap();
    assert_eq!(recovered.len(), 1, "{recovered:?}");
    assert_eq!(recovered[0].id, id);
    assert_eq!(recovered[0].outcome, Outcome::Finished);
    assert!(quarantine.list().unwrap().entries.is_empty());
    assert_eq!(rights(&path), rights_before);
    assert_eq!(
        fs::metadata(&path).unwrap().file_attributes() & READ_ONLY,
        READ_ONLY
    );
    assert_eq!(fs::read(&path).unwrap(), b"content");
}

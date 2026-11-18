//! A file goes into the quarantine and comes back as it was.
//!
//! Nothing here is malware. The files are made-up bytes, and what stands in
//! for "something a scanner would look for" is a marker string.

#![allow(clippy::unwrap_used)]

use std::fs::{self, File, FileTimes};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use warden_quarantine::{Quarantine, QuarantineError, Reason, RestoreOptions, Stamp, format};

const MARKER: &[u8] = b"WARDEN-QUARANTINE-TEST-MARKER";

/// Content that holds the marker and does not repeat.
fn content(seed: u8, len: usize) -> Vec<u8> {
    let mut state = u32::from(seed) + 1;
    let mut bytes: Vec<u8> = (0..len)
        .map(|_| {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (state >> 24) as u8
        })
        .collect();
    if bytes.len() >= MARKER.len() {
        bytes[..MARKER.len()].copy_from_slice(MARKER);
    }
    bytes
}

struct Scene {
    dir: tempfile::TempDir,
}

impl Scene {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
        }
    }

    fn quarantine(&self) -> Quarantine {
        let (quarantine, recovered) = Quarantine::open(self.dir.path().join("quarantine")).unwrap();
        assert!(recovered.is_empty(), "{recovered:?}");
        quarantine
    }

    /// A file in a folder of its own, with timestamps of a day long past.
    fn file(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let folder = self.dir.path().join("files");
        fs::create_dir_all(&folder).unwrap();
        let path = folder.join(name);
        fs::write(&path, bytes).unwrap();
        set_times(&path, MODIFIED, ACCESSED);
        path
    }

    /// Every file under the quarantine folder, by its path within it.
    fn stored(&self) -> Vec<PathBuf> {
        let root = self.dir.path().join("quarantine");
        let mut files = Vec::new();
        let mut folders = vec![root.clone()];
        while let Some(folder) = folders.pop() {
            for item in fs::read_dir(folder).unwrap() {
                let path = item.unwrap().path();
                if path.is_dir() {
                    folders.push(path);
                } else {
                    files.push(path.strip_prefix(&root).unwrap().to_path_buf());
                }
            }
        }
        files.sort();
        files
    }
}

/// 2021-03-04 05:06:07.1234567 UTC and a moment in 2019, both with a
/// fraction of a second that a careless copy would lose. The fractions are
/// whole steps of 100 ns, which is the finest that Windows keeps.
const MODIFIED: Duration = Duration::new(1_614_834_367, 123_456_700);
const ACCESSED: Duration = Duration::new(1_560_000_000, 987_654_300);

fn set_times(path: &Path, modified: Duration, accessed: Duration) {
    let file = File::options().write(true).open(path).unwrap();
    file.set_times(
        FileTimes::new()
            .set_modified(UNIX_EPOCH + modified)
            .set_accessed(UNIX_EPOCH + accessed),
    )
    .unwrap();
}

fn times(path: &Path) -> (SystemTime, SystemTime) {
    let metadata = fs::metadata(path).unwrap();
    (metadata.modified().unwrap(), metadata.accessed().unwrap())
}

fn note() -> Reason {
    Reason::note("a test")
}

#[test]
fn a_file_comes_back_with_its_content_and_its_timestamps() {
    let scene = Scene::new();
    let bytes = content(1, 5000);
    let path = scene.file("document.bin", &bytes);
    let before = times(&path);
    assert_eq!(before, (UNIX_EPOCH + MODIFIED, UNIX_EPOCH + ACCESSED));

    let quarantine = scene.quarantine();
    let entry = quarantine.add(&path, note()).unwrap();
    assert!(!path.exists(), "the original is gone");
    assert_eq!(entry.info.size, 5000);
    assert_eq!(entry.info.original_path, path.to_string_lossy());
    assert_eq!(
        entry.info.sha256,
        warden_sigdb::hex::encode(&warden_sigdb_sha256(&bytes))
    );
    assert_eq!(
        entry.info.times.modified,
        Stamp::of(UNIX_EPOCH + MODIFIED),
        "with its fraction of a second"
    );
    assert_eq!(entry.info.reason.note.as_deref(), Some("a test"));
    assert_eq!(entry.info.warden_version, env!("CARGO_PKG_VERSION"));

    let restored = quarantine
        .restore(&entry.info.id, &RestoreOptions::default())
        .unwrap();
    assert_eq!(restored.path, path);
    assert_eq!(restored.notes, Vec::<String>::new());
    assert_eq!(times(&path), before, "read before the content is");
    assert_eq!(fs::read(&path).unwrap(), bytes);
    assert!(quarantine.list().unwrap().entries.is_empty());
    // Nothing is left behind next to the file either.
    let neighbours: Vec<_> = fs::read_dir(path.parent().unwrap())
        .unwrap()
        .map(|item| item.unwrap().file_name())
        .collect();
    assert_eq!(neighbours, ["document.bin"]);
}

fn warden_sigdb_sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(bytes).into()
}

#[cfg(unix)]
#[test]
fn a_file_comes_back_with_its_permission_bits() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let scene = Scene::new();
    let quarantine = scene.quarantine();
    // Read-only for everybody, private, and with the bit that makes a
    // program run as its owner: the one a careless restore drops.
    for (name, mode) in [
        ("read-only", 0o444),
        ("private", 0o600),
        ("as-owner", 0o4755),
    ] {
        let path = scene.file(name, &content(2, 300));
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        let before = fs::metadata(&path).unwrap();

        let entry = quarantine.add(&path, note()).unwrap();
        let unix = entry.info.unix.unwrap();
        assert_eq!(unix.mode, mode, "{name}");
        assert_eq!((unix.uid, unix.gid), (before.uid(), before.gid()));
        assert!(!path.exists());

        let restored = quarantine
            .restore(&entry.info.id, &RestoreOptions::default())
            .unwrap();
        assert_eq!(restored.notes, Vec::<String>::new(), "{name}");
        let after = fs::metadata(&path).unwrap();
        assert_eq!(after.mode() & 0o7777, mode, "{name}");
        assert_eq!((after.uid(), after.gid()), (before.uid(), before.gid()));
        assert_eq!(after.modified().unwrap(), before.modified().unwrap());
    }
}

#[test]
fn what_lies_in_the_quarantine_is_not_the_file() {
    let scene = Scene::new();
    let bytes = content(3, 40_000);
    let path = scene.file("marked.bin", &bytes);
    let quarantine = scene.quarantine();
    let entry = quarantine.add(&path, note()).unwrap();

    // One entry file, the lock, and nothing in the journal or left over.
    let stored = scene.stored();
    assert_eq!(
        stored,
        [
            PathBuf::from("items").join(format!("{}.{}", entry.info.id, format::EXTENSION)),
            PathBuf::from("lock"),
        ]
    );
    let on_disk = fs::read(&entry.file).unwrap();
    assert!(on_disk.len() > bytes.len());
    assert!(
        !on_disk.windows(MARKER.len()).any(|window| window == MARKER),
        "the marker can be found in the entry file"
    );
    assert_eq!(&on_disk[..8], &format::MAGIC);
    assert_eq!(&on_disk[on_disk.len() - 8..], &format::END_MAGIC);
    // The record is readable as it is: that is what `list` shows.
    let text = String::from_utf8_lossy(&on_disk);
    assert!(text.contains("\"original_path\""));
    assert!(text.contains("marked.bin"));
}

#[test]
fn files_of_every_size_come_back() {
    let scene = Scene::new();
    let quarantine = scene.quarantine();
    for (index, len) in [0usize, 1, 255, 256 * 1024, 256 * 1024 + 1, 700_000]
        .into_iter()
        .enumerate()
    {
        let bytes = content(index as u8, len);
        let path = scene.file(&format!("size-{len}.bin"), &bytes);
        let entry = quarantine.add(&path, Reason::default()).unwrap();
        assert_eq!(entry.info.size, len as u64);
        assert!(entry.info.reason.is_empty());
        quarantine
            .restore(&entry.info.id, &RestoreOptions::default())
            .unwrap();
        assert_eq!(fs::read(&path).unwrap(), bytes, "{len} bytes");
    }
}

#[test]
fn two_files_with_the_same_content_are_two_entries_with_two_keys() {
    let scene = Scene::new();
    let bytes = content(4, 2000);
    let first = scene.file("first.bin", &bytes);
    let second = scene.file("second.bin", &bytes);
    let quarantine = scene.quarantine();
    let one = quarantine.add(&first, note()).unwrap();
    let two = quarantine.add(&second, note()).unwrap();

    assert_ne!(one.info.id, two.info.id);
    assert_eq!(one.info.sha256, two.info.sha256);
    assert_ne!(one.info.cipher.key, two.info.cipher.key);
    // So the same content does not look the same in the quarantine.
    let stored_one = fs::read(&one.file).unwrap();
    let stored_two = fs::read(&two.file).unwrap();
    assert_ne!(stored_one[12..2012], stored_two[12..2012]);
}

#[test]
fn restoring_does_not_replace_a_file_unless_asked() {
    let scene = Scene::new();
    let bytes = content(5, 1000);
    let path = scene.file("taken.bin", &bytes);
    let quarantine = scene.quarantine();
    let entry = quarantine.add(&path, note()).unwrap();

    // Somebody puts another file where the first one was.
    fs::write(&path, b"a newer file").unwrap();
    let refused = quarantine
        .restore(&entry.info.id, &RestoreOptions::default())
        .unwrap_err();
    assert!(
        matches!(refused, QuarantineError::TargetExists { .. }),
        "{refused}"
    );
    assert_eq!(fs::read(&path).unwrap(), b"a newer file");
    assert_eq!(quarantine.list().unwrap().entries.len(), 1, "still there");
    assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 1);

    let restored = quarantine
        .restore(
            &entry.info.id,
            &RestoreOptions {
                overwrite: true,
                ..RestoreOptions::default()
            },
        )
        .unwrap();
    assert_eq!(restored.path, path);
    assert_eq!(fs::read(&path).unwrap(), bytes);
    assert!(quarantine.list().unwrap().entries.is_empty());
}

#[test]
fn a_folder_is_never_replaced() {
    let scene = Scene::new();
    let path = scene.file("name.bin", &content(6, 100));
    let quarantine = scene.quarantine();
    let entry = quarantine.add(&path, note()).unwrap();
    fs::create_dir(&path).unwrap();
    let refused = quarantine
        .restore(
            &entry.info.id,
            &RestoreOptions {
                overwrite: true,
                ..RestoreOptions::default()
            },
        )
        .unwrap_err();
    assert!(matches!(refused, QuarantineError::TargetExists { .. }));
    assert!(path.is_dir());
}

#[test]
fn a_file_can_be_restored_to_another_place() {
    let scene = Scene::new();
    let bytes = content(7, 1000);
    let path = scene.file("moved.bin", &bytes);
    let quarantine = scene.quarantine();
    let entry = quarantine.add(&path, note()).unwrap();

    let elsewhere = scene.dir.path().join("elsewhere");
    fs::create_dir(&elsewhere).unwrap();
    let to = elsewhere.join("under another name.bin");
    let restored = quarantine
        .restore(
            &entry.info.id,
            &RestoreOptions {
                to: Some(to.clone()),
                overwrite: false,
            },
        )
        .unwrap();
    assert_eq!(restored.path, to);
    assert_eq!(fs::read(&to).unwrap(), bytes);
    assert_eq!(times(&to).0, UNIX_EPOCH + MODIFIED);
    assert!(!path.exists());
}

#[test]
fn restoring_into_a_folder_that_is_gone_fails_and_keeps_the_entry() {
    let scene = Scene::new();
    let path = scene.file("orphan.bin", &content(8, 1000));
    let quarantine = scene.quarantine();
    let entry = quarantine.add(&path, note()).unwrap();
    fs::remove_dir(path.parent().unwrap()).unwrap();

    let refused = quarantine
        .restore(&entry.info.id, &RestoreOptions::default())
        .unwrap_err();
    assert!(
        matches!(&refused, QuarantineError::NoTargetFolder { path } if path.ends_with("files")),
        "{refused}"
    );
    assert_eq!(quarantine.list().unwrap().entries.len(), 1);
}

#[test]
fn only_a_regular_file_can_be_quarantined() {
    let scene = Scene::new();
    let quarantine = scene.quarantine();
    let folder = scene.dir.path().join("a folder");
    fs::create_dir(&folder).unwrap();
    let refused = quarantine.add(&folder, note()).unwrap_err();
    assert!(
        matches!(&refused, QuarantineError::NotAFile { what, .. } if *what == "a folder"),
        "{refused}"
    );
    let missing = quarantine
        .add(&scene.dir.path().join("not there"), note())
        .unwrap_err();
    assert!(matches!(missing, QuarantineError::Io { .. }), "{missing}");
    assert!(quarantine.list().unwrap().entries.is_empty());
    assert_eq!(scene.stored(), [PathBuf::from("lock")]);
}

#[cfg(unix)]
#[test]
fn a_link_is_not_followed() {
    let scene = Scene::new();
    let target = scene.file("the real file.bin", &content(9, 500));
    let link = target.with_file_name("a link to it");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    let quarantine = scene.quarantine();
    let refused = quarantine.add(&link, note()).unwrap_err();
    assert!(
        matches!(&refused, QuarantineError::NotAFile { what, .. } if *what == "a link"),
        "{refused}"
    );
    assert!(target.exists() && link.exists());
}

#[test]
fn an_entry_is_found_by_the_start_of_its_identifier() {
    let scene = Scene::new();
    let quarantine = scene.quarantine();
    // Seventeen entries: identifiers are hexadecimal, so at least two of
    // them start with the same digit.
    let mut ids = Vec::new();
    for index in 0..17u8 {
        let path = scene.file(&format!("file-{index}.bin"), &content(index, 64));
        ids.push(quarantine.add(&path, note()).unwrap().info.id);
    }
    for id in &ids {
        assert_eq!(id.len(), 16);
        assert!(id.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(&quarantine.find(id).unwrap().info.id, id);
    }
    let crowded = ('0'..='9')
        .chain('a'..='f')
        .map(|digit| digit.to_string())
        .find(|digit| {
            ids.iter()
                .filter(|id| id.starts_with(digit.as_str()))
                .count()
                > 1
        })
        .unwrap();
    let refused = quarantine.find(&crowded).unwrap_err();
    assert!(
        matches!(&refused, QuarantineError::Ambiguous { count, .. } if *count > 1),
        "{refused}"
    );
    // A prefix that fits exactly one.
    let alone = &ids[0];
    let shortest = (1..=16)
        .map(|length| &alone[..length])
        .find(|prefix| ids.iter().filter(|id| id.starts_with(prefix)).count() == 1)
        .unwrap();
    assert_eq!(&quarantine.find(shortest).unwrap().info.id, alone);

    assert!(matches!(
        quarantine.find("zz").unwrap_err(),
        QuarantineError::NotFound(_)
    ));
    assert!(matches!(
        quarantine.find("").unwrap_err(),
        QuarantineError::NotFound(_)
    ));
}

#[test]
fn the_list_is_oldest_first_and_survives_reopening() {
    let scene = Scene::new();
    let mut ids = Vec::new();
    {
        let quarantine = scene.quarantine();
        for index in 0..4u8 {
            let path = scene.file(&format!("file-{index}.bin"), &content(index, 100));
            ids.push(quarantine.add(&path, note()).unwrap().info.id);
            std::thread::sleep(Duration::from_millis(3));
        }
    }
    let quarantine = scene.quarantine();
    let listing = quarantine.list().unwrap();
    assert!(listing.damaged.is_empty());
    let listed: Vec<&str> = listing
        .entries
        .iter()
        .map(|entry| entry.info.id.as_str())
        .collect();
    assert_eq!(listed, ids);
    assert!(
        listing
            .entries
            .windows(2)
            .all(|pair| pair[0].info.quarantined_unix_ms <= pair[1].info.quarantined_unix_ms)
    );
}

#[test]
fn a_deleted_entry_is_gone_for_good() {
    let scene = Scene::new();
    let path = scene.file("unwanted.bin", &content(10, 100));
    let quarantine = scene.quarantine();
    let entry = quarantine.add(&path, note()).unwrap();

    let deleted = quarantine.delete(&entry.info.id[..8]).unwrap().unwrap();
    assert_eq!(deleted.id, entry.info.id);
    assert!(quarantine.list().unwrap().entries.is_empty());
    assert!(!path.exists());
    assert_eq!(scene.stored(), [PathBuf::from("lock")]);
    assert!(matches!(
        quarantine.delete(&entry.info.id).unwrap_err(),
        QuarantineError::NotFound(_)
    ));
    assert!(matches!(
        quarantine
            .restore(&entry.info.id, &RestoreOptions::default())
            .unwrap_err(),
        QuarantineError::NotFound(_)
    ));
}

#[test]
fn damaged_content_is_not_restored() {
    let scene = Scene::new();
    let path = scene.file("precious.bin", &content(11, 4000));
    let quarantine = scene.quarantine();
    let entry = quarantine.add(&path, note()).unwrap();

    // One bit of the stored content flips: a failing disk, say.
    let mut stored = fs::read(&entry.file).unwrap();
    stored[12 + 2000] ^= 0x04;
    fs::write(&entry.file, &stored).unwrap();

    // The record is intact, so the entry is listed as usual.
    assert_eq!(quarantine.list().unwrap().entries.len(), 1);
    let refused = quarantine
        .restore(&entry.info.id, &RestoreOptions::default())
        .unwrap_err();
    assert!(
        matches!(
            &refused,
            QuarantineError::Damaged {
                problem: warden_quarantine::Problem::WrongContent,
                ..
            }
        ),
        "{refused}"
    );
    // A file with wrong content is worse than no file: nothing was put at
    // the destination, not even for a moment under its real name.
    assert!(!path.exists());
    assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 0);
    assert_eq!(quarantine.list().unwrap().entries.len(), 1);
}

#[test]
fn an_entry_with_a_damaged_record_is_listed_as_damaged_and_can_be_deleted() {
    let scene = Scene::new();
    let good = scene.file("good.bin", &content(12, 500));
    let bad = scene.file("bad.bin", &content(13, 500));
    let quarantine = scene.quarantine();
    let good = quarantine.add(&good, note()).unwrap();
    let bad = quarantine.add(&bad, note()).unwrap();

    // The record sits behind the content. Change one character of it.
    let mut stored = fs::read(&bad.file).unwrap();
    let at = stored.len() - 100;
    stored[at] ^= 0x01;
    fs::write(&bad.file, &stored).unwrap();
    // And a file that only looks like an entry by its name.
    let stray = bad.file.with_file_name("ffffffffffffffff.wq");
    fs::write(&stray, b"not an entry at all").unwrap();
    // Other files in the folder are nobody's business.
    fs::write(bad.file.with_file_name("notes.txt"), b"hello").unwrap();

    let listing = quarantine.list().unwrap();
    assert_eq!(listing.entries.len(), 1);
    assert_eq!(listing.entries[0].info.id, good.info.id);
    assert_eq!(listing.damaged.len(), 2, "{:?}", listing.damaged);
    let problems: Vec<&str> = listing
        .damaged
        .iter()
        .map(|damaged| damaged.problem.as_str())
        .collect();
    assert!(problems.contains(&"its record is damaged: it does not match its digest"));
    assert!(problems.contains(&"it is not a quarantine entry"));

    let refused = quarantine
        .restore(&bad.info.id, &RestoreOptions::default())
        .unwrap_err();
    assert!(
        matches!(refused, QuarantineError::Damaged { .. }),
        "{refused}"
    );
    // By its whole identifier it can still be thrown away.
    assert!(matches!(
        quarantine.delete(&bad.info.id[..4]).unwrap_err(),
        QuarantineError::Damaged { .. }
    ));
    assert_eq!(quarantine.delete(&bad.info.id).unwrap(), None);
    assert_eq!(quarantine.list().unwrap().damaged.len(), 1);
}

#[test]
fn only_one_program_has_the_quarantine_open() {
    use std::sync::mpsc;

    let scene = Scene::new();
    let first = scene.quarantine();
    let dir = first.dir().to_path_buf();
    let (opened, wait) = mpsc::channel();
    let second = std::thread::spawn(move || {
        let (quarantine, _) = Quarantine::open(dir).unwrap();
        opened.send(()).unwrap();
        quarantine.list().unwrap().entries.len()
    });
    assert!(
        wait.recv_timeout(Duration::from_millis(300)).is_err(),
        "the second one got in while the first was open"
    );
    drop(first);
    wait.recv_timeout(Duration::from_secs(20)).unwrap();
    assert_eq!(second.join().unwrap(), 0);
}

#[cfg(unix)]
#[test]
fn the_quarantine_folder_is_private() {
    use std::os::unix::fs::PermissionsExt;

    let scene = Scene::new();
    let quarantine = scene.quarantine();
    for folder in ["", "items", "journal", "tmp"] {
        let mode = fs::metadata(quarantine.dir().join(folder))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700, "{folder:?}");
    }
}

#[cfg(unix)]
#[test]
fn a_file_name_that_is_not_unicode_comes_back_byte_for_byte() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let scene = Scene::new();
    let bytes = content(14, 300);
    let folder = scene.dir.path().join("files");
    fs::create_dir_all(&folder).unwrap();
    let path = folder.join(OsStr::from_bytes(b"odd-\xff\xfe-name.bin"));
    if fs::write(&path, &bytes).is_err() {
        // A file system that insists on Unicode names: nothing to test.
        return;
    }
    let quarantine = scene.quarantine();
    let entry = quarantine.add(&path, note()).unwrap();
    assert!(entry.info.original_exact.is_some());
    assert!(entry.info.original_path.contains('\u{fffd}'));
    assert!(!path.exists());

    let restored = quarantine
        .restore(&entry.info.id, &RestoreOptions::default())
        .unwrap();
    assert_eq!(restored.path, path);
    assert_eq!(fs::read(&path).unwrap(), bytes);
}

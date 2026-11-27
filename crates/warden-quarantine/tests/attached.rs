//! Records that are kept with an entry.
//!
//! The quarantine does not know what is in them. What is tried here is
//! that it keeps them whole, gives them back as they were, lets go of them
//! when their entry is deleted, and holds on to them when it is restored.

#![allow(clippy::unwrap_used)]

use std::fs;
use std::path::PathBuf;

use warden_quarantine::{Quarantine, QuarantineError, Reason, RestoreOptions};

struct Scene {
    dir: tempfile::TempDir,
}

impl Scene {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
        }
    }

    fn store(&self) -> PathBuf {
        self.dir.path().join("quarantine")
    }

    fn quarantine(&self) -> Quarantine {
        let (quarantine, recovered) = Quarantine::open(self.store()).unwrap();
        assert!(recovered.is_empty(), "{recovered:?}");
        quarantine
    }

    /// A file in quarantine, and its identifier.
    fn entry(&self, quarantine: &Quarantine, name: &str) -> (PathBuf, String) {
        let folder = self.dir.path().join("files");
        fs::create_dir_all(&folder).unwrap();
        let path = folder.join(name);
        fs::write(&path, name.as_bytes()).unwrap();
        let entry = quarantine.add(&path, Reason::note("a test")).unwrap();
        (path, entry.info.id)
    }
}

#[test]
fn a_record_is_kept_replaced_and_removed() {
    let scene = Scene::new();
    let quarantine = scene.quarantine();
    let (_, id) = scene.entry(&quarantine, "one.bin");

    assert_eq!(quarantine.attached(&id, "autostart").unwrap(), None);
    quarantine.attach(&id, "autostart", b"first").unwrap();
    assert_eq!(
        quarantine.attached(&id, "autostart").unwrap().as_deref(),
        Some(b"first".as_slice())
    );
    // Another kind is another record.
    assert_eq!(quarantine.attached(&id, "notes").unwrap(), None);

    // A second one of the same kind takes the place of the first.
    quarantine
        .attach(&id, "autostart", b"second, longer")
        .unwrap();
    assert_eq!(
        quarantine.attached(&id, "autostart").unwrap().as_deref(),
        Some(b"second, longer".as_slice())
    );
    // An empty record is a record.
    quarantine.attach(&id, "notes", b"").unwrap();
    assert_eq!(
        quarantine.attached(&id, "notes").unwrap().as_deref(),
        Some(b"".as_slice())
    );

    quarantine.detach(&id, "autostart").unwrap();
    quarantine.detach(&id, "autostart").unwrap();
    assert_eq!(quarantine.attached(&id, "autostart").unwrap(), None);
    assert!(quarantine.attached(&id, "notes").unwrap().is_some());
}

#[test]
fn a_record_survives_reopening_and_nothing_half_written_is_left() {
    let scene = Scene::new();
    let quarantine = scene.quarantine();
    let (_, id) = scene.entry(&quarantine, "one.bin");
    quarantine.attach(&id, "autostart", b"kept").unwrap();
    // What a write that was cut off leaves behind: a file under a
    // temporary name, never the record's own.
    fs::write(
        scene
            .store()
            .join("tmp")
            .join(format!("{id}.autostart.0a0b0c0d")),
        b"half a rec",
    )
    .unwrap();
    drop(quarantine);

    let quarantine = scene.quarantine();
    assert_eq!(
        quarantine.attached(&id, "autostart").unwrap().as_deref(),
        Some(b"kept".as_slice())
    );
    assert_eq!(fs::read_dir(scene.store().join("tmp")).unwrap().count(), 0);
    // The record is one file, under the entry's identifier.
    let files: Vec<_> = fs::read_dir(scene.store().join("attached"))
        .unwrap()
        .map(|item| item.unwrap().file_name())
        .collect();
    assert_eq!(files, [format!("{id}.autostart").as_str()]);
}

#[test]
fn a_record_goes_with_a_deleted_entry_and_outlives_a_restored_one() {
    let scene = Scene::new();
    let quarantine = scene.quarantine();
    let (_, deleted) = scene.entry(&quarantine, "deleted.bin");
    let (path, restored) = scene.entry(&quarantine, "restored.bin");
    for id in [&deleted, &restored] {
        quarantine
            .attach(id, "autostart", b"what started it")
            .unwrap();
        quarantine.attach(id, "notes", b"more").unwrap();
    }
    let mut both = vec![deleted.clone(), restored.clone()];
    both.sort();
    assert_eq!(quarantine.attached_ids("autostart").unwrap(), both);

    // Deleted by the start of its identifier: the records are found by
    // the whole one.
    quarantine.delete(&deleted[..6]).unwrap();
    assert_eq!(quarantine.attached(&deleted, "autostart").unwrap(), None);
    assert_eq!(quarantine.attached(&deleted, "notes").unwrap(), None);

    // Restored: the file is back, the entry is gone, and the record waits
    // for whoever wrote it.
    quarantine
        .restore(&restored, &RestoreOptions::default())
        .unwrap();
    assert!(path.exists());
    assert!(quarantine.list().unwrap().entries.is_empty());
    assert_eq!(
        quarantine
            .attached(&restored, "autostart")
            .unwrap()
            .as_deref(),
        Some(b"what started it".as_slice())
    );
    assert_eq!(
        quarantine.attached_ids("autostart").unwrap(),
        std::slice::from_ref(&restored)
    );
    quarantine.detach(&restored, "autostart").unwrap();
    assert!(quarantine.attached_ids("autostart").unwrap().is_empty());
    assert_eq!(quarantine.attached_ids("notes").unwrap(), [restored]);
}

#[test]
fn a_record_is_filed_under_names_that_cannot_lead_elsewhere() {
    let scene = Scene::new();
    let quarantine = scene.quarantine();
    let (_, id) = scene.entry(&quarantine, "one.bin");

    for bad_id in [
        "",
        "abc",
        &id[..15],
        "../../../../etc/passwd",
        "0123456789ABCDEF",
        "0123456789abcdeg",
        "0123456789abcdef0",
    ] {
        for result in [
            quarantine.attach(bad_id, "autostart", b"x").err(),
            quarantine.attached(bad_id, "autostart").err(),
            quarantine.detach(bad_id, "autostart").err(),
        ] {
            assert!(
                matches!(result, Some(QuarantineError::BadRecordName(_))),
                "{bad_id:?}: {result:?}"
            );
        }
    }
    for bad_kind in [
        "",
        "Autostart",
        "auto start",
        "auto.start",
        "../x",
        "a/b",
        "a-very-long-kind-of-record-that-nobody-needs",
    ] {
        for result in [
            quarantine.attach(&id, bad_kind, b"x").err(),
            quarantine.attached(&id, bad_kind).err(),
            quarantine.detach(&id, bad_kind).err(),
            quarantine.attached_ids(bad_kind).err(),
        ] {
            assert!(
                matches!(result, Some(QuarantineError::BadRecordName(_))),
                "{bad_kind:?}: {result:?}"
            );
        }
    }
    // Nothing was written anywhere.
    assert_eq!(
        fs::read_dir(scene.store().join("attached"))
            .unwrap()
            .count(),
        0
    );

    // A record can be kept for an identifier that has no entry: the entry
    // may have been restored a moment ago.
    quarantine
        .attach("0123456789abcdef", "autostart", b"x")
        .unwrap();
}

#[test]
fn a_record_has_a_size_it_cannot_exceed() {
    let scene = Scene::new();
    let quarantine = scene.quarantine();
    let (_, id) = scene.entry(&quarantine, "one.bin");

    let most = vec![0x5Au8; 16 * 1024 * 1024];
    quarantine.attach(&id, "autostart", &most).unwrap();
    assert_eq!(
        quarantine
            .attached(&id, "autostart")
            .unwrap()
            .map(|r| r.len()),
        Some(most.len())
    );

    let mut too_much = most;
    too_much.push(0);
    let error = quarantine.attach(&id, "autostart", &too_much).unwrap_err();
    assert!(
        matches!(error, QuarantineError::RecordTooLarge { .. }),
        "{error}"
    );
    // The record that was there is still there, whole.
    assert_eq!(
        quarantine
            .attached(&id, "autostart")
            .unwrap()
            .map(|r| r.len()),
        Some(16 * 1024 * 1024)
    );
}

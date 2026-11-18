//! What becomes of a file when the program dies in the middle.
//!
//! Each test stops an operation right after one of its steps, the way a
//! crash or a power cut would, leaves everything as it then is, and opens
//! the quarantine again. What has to hold afterwards is always the same:
//! the file is in exactly one place, whole, and nothing half-done is left.

#![allow(clippy::unwrap_used)]

use std::fs;
use std::path::{Path, PathBuf};

use proptest::prelude::*;
use warden_quarantine::{
    Operation, Outcome, Quarantine, QuarantineError, Reason, Recovered, RestoreOptions, Step,
};

const ADD_STEPS: [Step; 4] = [
    Step::Noted,
    Step::EntryWritten,
    Step::EntryCommitted,
    Step::OriginalRemoved,
];
const RESTORE_STEPS: [Step; 4] = [
    Step::Noted,
    Step::RestoreWritten,
    Step::RestoreCommitted,
    Step::EntryRemoved,
];

fn content(seed: u8, len: usize) -> Vec<u8> {
    let mut state = u32::from(seed) + 7;
    (0..len)
        .map(|_| {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (state >> 24) as u8
        })
        .collect()
}

struct Scene {
    dir: tempfile::TempDir,
}

impl Scene {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("files")).unwrap();
        Self { dir }
    }

    fn store(&self) -> PathBuf {
        self.dir.path().join("quarantine")
    }

    fn file(&self, name: &str) -> PathBuf {
        self.dir.path().join("files").join(name)
    }

    fn open(&self) -> (Quarantine, Vec<Recovered>) {
        Quarantine::open(self.store()).unwrap()
    }

    /// Opens the quarantine so that its next operation dies after `step`.
    fn open_to_die_after(&self, step: Step) -> Quarantine {
        let (mut quarantine, recovered) = self.open();
        assert!(recovered.is_empty(), "{recovered:?}");
        quarantine.interrupt_after(step);
        quarantine
    }

    /// The names in a folder, sorted.
    fn names(&self, folder: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(folder)
            .unwrap()
            .map(|item| item.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    /// After recovery nothing is in flight: no note, no half-written copy.
    fn assert_settled(&self) {
        assert_eq!(
            self.names(&self.store().join("journal")),
            Vec::<String>::new()
        );
        assert_eq!(self.names(&self.store().join("tmp")), Vec::<String>::new());
        // And opening once more finds nothing to do.
        let (_, again) = self.open();
        assert!(again.is_empty(), "{again:?}");
    }
}

fn died(result: Result<impl std::fmt::Debug, QuarantineError>, step: Step) {
    match result {
        Err(QuarantineError::Interrupted(at)) => assert_eq!(at, step),
        other => panic!("the operation did not stop after {step:?}: {other:?}"),
    }
}

#[test]
fn quarantining_that_dies_before_the_copy_is_safe_is_undone() {
    for step in [Step::Noted, Step::EntryWritten] {
        let scene = Scene::new();
        let bytes = content(1, 3000);
        let path = scene.file("victim.bin");
        fs::write(&path, &bytes).unwrap();

        let quarantine = scene.open_to_die_after(step);
        died(quarantine.add(&path, Reason::default()), step);
        drop(quarantine);
        // The moment after the crash: the file is where it was, and a note
        // says that something was going on.
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!(scene.names(&scene.store().join("journal")).len(), 1);
        assert_eq!(
            scene.names(&scene.store().join("tmp")).len(),
            usize::from(step == Step::EntryWritten)
        );

        let (quarantine, recovered) = scene.open();
        assert_eq!(recovered.len(), 1, "{step:?}");
        assert_eq!(recovered[0].operation, Operation::Quarantine);
        assert_eq!(recovered[0].outcome, Outcome::Undone, "{step:?}");
        assert_eq!(recovered[0].path, path.to_string_lossy());
        assert!(
            recovered[0]
                .to_string()
                .ends_with("It was undone: the file is where it was"),
            "{}",
            recovered[0]
        );
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert!(quarantine.list().unwrap().entries.is_empty());
        drop(quarantine);
        scene.assert_settled();
    }
}

#[test]
fn quarantining_that_dies_once_the_copy_is_safe_is_finished() {
    for step in [Step::EntryCommitted, Step::OriginalRemoved] {
        let scene = Scene::new();
        let bytes = content(2, 3000);
        let path = scene.file("victim.bin");
        fs::write(&path, &bytes).unwrap();

        let quarantine = scene.open_to_die_after(step);
        died(quarantine.add(&path, Reason::note("found by a scan")), step);
        drop(quarantine);
        // The dangerous moment is the first of the two: the file is in the
        // quarantine and still at its place.
        assert_eq!(path.exists(), step == Step::EntryCommitted);

        let (quarantine, recovered) = scene.open();
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].outcome, Outcome::Finished, "{step:?}");
        assert!(
            recovered[0]
                .to_string()
                .contains("It was finished: the file is in quarantine as "),
            "{}",
            recovered[0]
        );
        assert!(!path.exists(), "{step:?}: the original is gone");
        let listing = quarantine.list().unwrap();
        assert_eq!(listing.entries.len(), 1);
        assert_eq!(listing.entries[0].info.id, recovered[0].id);
        assert_eq!(
            listing.entries[0].info.reason.note.as_deref(),
            Some("found by a scan")
        );

        // And it is the whole file that is in there.
        quarantine
            .restore(&recovered[0].id, &RestoreOptions::default())
            .unwrap();
        assert_eq!(fs::read(&path).unwrap(), bytes);
        drop(quarantine);
        scene.assert_settled();
    }
}

#[test]
fn a_file_that_changed_after_the_crash_is_not_removed() {
    let scene = Scene::new();
    let path = scene.file("victim.bin");
    fs::write(&path, content(3, 3000)).unwrap();

    let quarantine = scene.open_to_die_after(Step::EntryCommitted);
    died(
        quarantine.add(&path, Reason::default()),
        Step::EntryCommitted,
    );
    drop(quarantine);
    // Before the next start, something else is written to that place.
    fs::write(&path, b"a different file under the same name").unwrap();

    let (quarantine, recovered) = scene.open();
    assert_eq!(recovered.len(), 1);
    let Outcome::LeftAlone(why) = &recovered[0].outcome else {
        panic!("{:?}", recovered[0].outcome);
    };
    assert!(why.contains("another file has its place now"), "{why}");
    // Both are kept: the copy that was made, and the file that is there now.
    assert_eq!(
        fs::read(&path).unwrap(),
        b"a different file under the same name"
    );
    assert_eq!(quarantine.list().unwrap().entries.len(), 1);
    drop(quarantine);
    scene.assert_settled();
}

#[test]
fn restoring_that_dies_before_the_file_is_back_is_undone() {
    for step in [Step::Noted, Step::RestoreWritten] {
        let scene = Scene::new();
        let bytes = content(4, 3000);
        let path = scene.file("victim.bin");
        fs::write(&path, &bytes).unwrap();
        let id = {
            let (quarantine, _) = scene.open();
            quarantine.add(&path, Reason::default()).unwrap().info.id
        };

        let quarantine = scene.open_to_die_after(step);
        died(quarantine.restore(&id, &RestoreOptions::default()), step);
        drop(quarantine);
        // The file does not have its name yet. What may lie next to its
        // place is a copy under a temporary name.
        assert!(!path.exists());
        let beside = scene.names(path.parent().unwrap());
        assert_eq!(beside.len(), usize::from(step == Step::RestoreWritten));

        let (quarantine, recovered) = scene.open();
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].operation, Operation::Restore);
        assert_eq!(recovered[0].outcome, Outcome::Undone, "{step:?}");
        assert!(
            recovered[0]
                .to_string()
                .ends_with(&format!("entry {id} is still in quarantine")),
            "{}",
            recovered[0]
        );
        assert!(!path.exists());
        assert_eq!(
            scene.names(path.parent().unwrap()),
            Vec::<String>::new(),
            "{step:?}: the temporary copy is cleared away"
        );
        assert_eq!(quarantine.list().unwrap().entries.len(), 1);

        // Trying again works.
        quarantine.restore(&id, &RestoreOptions::default()).unwrap();
        assert_eq!(fs::read(&path).unwrap(), bytes);
        drop(quarantine);
        scene.assert_settled();
    }
}

#[test]
fn restoring_that_dies_once_the_file_is_back_is_finished() {
    for step in [Step::RestoreCommitted, Step::EntryRemoved] {
        let scene = Scene::new();
        let bytes = content(5, 3000);
        let path = scene.file("victim.bin");
        fs::write(&path, &bytes).unwrap();
        let id = {
            let (quarantine, _) = scene.open();
            quarantine.add(&path, Reason::default()).unwrap().info.id
        };

        let quarantine = scene.open_to_die_after(step);
        died(quarantine.restore(&id, &RestoreOptions::default()), step);
        drop(quarantine);
        assert_eq!(fs::read(&path).unwrap(), bytes, "the file is back");

        let (quarantine, recovered) = scene.open();
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].outcome, Outcome::Finished, "{step:?}");
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!(scene.names(path.parent().unwrap()), ["victim.bin"]);
        // It is in one place, not in two.
        assert!(quarantine.list().unwrap().entries.is_empty());
        drop(quarantine);
        scene.assert_settled();
    }
}

#[test]
fn a_restore_that_dies_while_the_file_has_two_names_is_finished() {
    // Giving a restored file its name is "add the real name, then take the
    // temporary one away". Between the two the file has both.
    let scene = Scene::new();
    let bytes = content(10, 3000);
    let path = scene.file("victim.bin");
    fs::write(&path, &bytes).unwrap();
    let id = {
        let (quarantine, _) = scene.open();
        quarantine.add(&path, Reason::default()).unwrap().info.id
    };
    let quarantine = scene.open_to_die_after(Step::RestoreWritten);
    died(
        quarantine.restore(&id, &RestoreOptions::default()),
        Step::RestoreWritten,
    );
    drop(quarantine);
    let beside = scene.names(path.parent().unwrap());
    assert_eq!(beside.len(), 1);
    if fs::hard_link(path.with_file_name(&beside[0]), &path).is_err() {
        // A file system without hard links never gets into this state.
        return;
    }

    let (quarantine, recovered) = scene.open();
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0].outcome, Outcome::Finished);
    assert_eq!(scene.names(path.parent().unwrap()), ["victim.bin"]);
    assert_eq!(fs::read(&path).unwrap(), bytes);
    assert!(quarantine.list().unwrap().entries.is_empty());
    drop(quarantine);
    scene.assert_settled();
}

#[test]
fn a_note_that_was_never_finished_changes_nothing() {
    let scene = Scene::new();
    let bytes = content(6, 500);
    let path = scene.file("bystander.bin");
    fs::write(&path, &bytes).unwrap();
    let kept = {
        let (quarantine, _) = scene.open();
        let other = scene.file("already-in.bin");
        fs::write(&other, content(7, 500)).unwrap();
        quarantine.add(&other, Reason::default()).unwrap().info.id
    };
    // A crash while the note itself was being written, and one that left a
    // stray temporary file.
    fs::write(
        scene.store().join("journal").join("0123456789abcdef.json"),
        b"{\"operation\":\"add\",\"id\":\"0123",
    )
    .unwrap();
    fs::write(
        scene.store().join("tmp").join("0123456789abcdef.partial"),
        b"half",
    )
    .unwrap();

    let (quarantine, recovered) = scene.open();
    assert!(recovered.is_empty(), "{recovered:?}");
    assert_eq!(fs::read(&path).unwrap(), bytes);
    let listing = quarantine.list().unwrap();
    assert_eq!(listing.entries.len(), 1);
    assert_eq!(listing.entries[0].info.id, kept);
    drop(quarantine);
    scene.assert_settled();
}

#[test]
fn two_interrupted_operations_are_both_settled() {
    let scene = Scene::new();
    let first = scene.file("first.bin");
    let second = scene.file("second.bin");
    fs::write(&first, content(8, 800)).unwrap();
    fs::write(&second, content(9, 800)).unwrap();

    let quarantine = scene.open_to_die_after(Step::EntryCommitted);
    died(
        quarantine.add(&first, Reason::default()),
        Step::EntryCommitted,
    );
    drop(quarantine);
    // The second crash happens before the first one is ever looked at: a
    // process that was killed twice in a row, with recovery switched off
    // by hand here.
    let note = scene.names(&scene.store().join("journal"));
    assert_eq!(note.len(), 1);
    let hidden = scene.dir.path().join("note-kept-aside.json");
    fs::rename(scene.store().join("journal").join(&note[0]), &hidden).unwrap();
    let quarantine = scene.open_to_die_after(Step::Noted);
    died(quarantine.add(&second, Reason::default()), Step::Noted);
    drop(quarantine);
    fs::rename(&hidden, scene.store().join("journal").join(&note[0])).unwrap();

    let (quarantine, recovered) = scene.open();
    assert_eq!(recovered.len(), 2);
    let outcome_for = |path: &Path| {
        recovered
            .iter()
            .find(|entry| entry.path == path.to_string_lossy())
            .map(|entry| entry.outcome.clone())
            .unwrap()
    };
    assert_eq!(outcome_for(&first), Outcome::Finished);
    assert_eq!(outcome_for(&second), Outcome::Undone);
    assert!(!first.exists());
    assert!(second.exists());
    assert_eq!(quarantine.list().unwrap().entries.len(), 1);
    drop(quarantine);
    scene.assert_settled();
}

/// Where a file is, once everything has settled.
#[derive(Debug, PartialEq, Eq)]
enum Place {
    AtItsPlace,
    InQuarantine,
}

fn place_of(scene: &Scene, quarantine: &Quarantine, path: &Path, bytes: &[u8]) -> Place {
    let entries = quarantine.list().unwrap().entries;
    match (path.exists(), entries.len()) {
        (true, 0) => {
            assert_eq!(fs::read(path).unwrap(), bytes);
            Place::AtItsPlace
        }
        (false, 1) => {
            // Whole: it restores, and to the same bytes.
            let to = scene.dir.path().join("checked.bin");
            let _ = fs::remove_file(&to);
            quarantine
                .restore(
                    &entries[0].info.id,
                    &RestoreOptions {
                        to: Some(to.clone()),
                        overwrite: false,
                    },
                )
                .unwrap();
            assert_eq!(fs::read(&to).unwrap(), bytes);
            Place::InQuarantine
        }
        (at_place, entries) => panic!(
            "the file is at its place: {at_place}, and there are {entries} entries; it has to be exactly one of the two"
        ),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// Whatever the content and wherever the program dies, afterwards the
    /// file is whole and in exactly one place: never lost, never doubled.
    #[test]
    fn a_file_is_never_lost_and_never_doubled(
        bytes in proptest::collection::vec(any::<u8>(), 0..5000),
        add_step in proptest::option::of(0..ADD_STEPS.len()),
        restore_step in proptest::option::of(0..RESTORE_STEPS.len()),
    ) {
        let scene = Scene::new();
        let path = scene.file("victim.bin");
        fs::write(&path, &bytes).unwrap();

        // Quarantine it, dying somewhere on the way or not at all.
        {
            let (mut quarantine, _) = scene.open();
            if let Some(step) = add_step {
                quarantine.interrupt_after(ADD_STEPS[step]);
            }
            let result = quarantine.add(&path, Reason::default());
            prop_assert_eq!(result.is_ok(), add_step.is_none());
        }
        let (quarantine, recovered) = scene.open();
        prop_assert_eq!(recovered.len(), usize::from(add_step.is_some()));
        let expected = match add_step.map(|step| ADD_STEPS[step]) {
            Some(Step::Noted | Step::EntryWritten) => Place::AtItsPlace,
            _ => Place::InQuarantine,
        };
        let entries = quarantine.list().unwrap().entries;
        prop_assert_eq!(entries.len(), usize::from(expected == Place::InQuarantine));
        prop_assert_eq!(path.exists(), expected == Place::AtItsPlace);
        if expected == Place::AtItsPlace {
            prop_assert_eq!(&fs::read(&path).unwrap(), &bytes);
            return Ok(());
        }
        let id = entries[0].info.id.clone();
        drop(quarantine);

        // Bring it back, dying somewhere on the way or not at all.
        {
            let (mut quarantine, _) = scene.open();
            if let Some(step) = restore_step {
                quarantine.interrupt_after(RESTORE_STEPS[step]);
            }
            let result = quarantine.restore(&id, &RestoreOptions::default());
            prop_assert_eq!(result.is_ok(), restore_step.is_none());
        }
        let (quarantine, recovered) = scene.open();
        prop_assert_eq!(recovered.len(), usize::from(restore_step.is_some()));
        let expected = match restore_step.map(|step| RESTORE_STEPS[step]) {
            Some(Step::Noted | Step::RestoreWritten) => Place::InQuarantine,
            _ => Place::AtItsPlace,
        };
        prop_assert_eq!(place_of(&scene, &quarantine, &path, &bytes), expected);
        drop(quarantine);
        scene.assert_settled();
    }
}

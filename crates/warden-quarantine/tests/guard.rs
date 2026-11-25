//! A quarantine with a guard: the last look at a file before it goes.
//!
//! The guards here are made up. One leaves every file whose name says so,
//! one lets everything pass, and both count how often they were asked.
//! Which files Warden really leaves alone is not this crate's business;
//! what is tried here is that the quarantine asks, listens, and can be
//! told to go ahead all the same.

#![allow(clippy::unwrap_used)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;

use sha2::{Digest, Sha256};
use warden_quarantine::{
    AddOptions, Guard, Quarantine, QuarantineError, Reason, RestoreOptions, Verdict,
};

struct Scene {
    dir: tempfile::TempDir,
}

impl Scene {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
        }
    }

    fn quarantine(&self, guard: impl Guard + 'static) -> Quarantine {
        let (mut quarantine, recovered) =
            Quarantine::open(self.dir.path().join("quarantine")).unwrap();
        assert!(recovered.is_empty(), "{recovered:?}");
        quarantine.set_guard(Box::new(guard));
        quarantine
    }

    fn file(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let folder = self.dir.path().join("files");
        fs::create_dir_all(&folder).unwrap();
        let path = folder.join(name);
        fs::write(&path, bytes).unwrap();
        path
    }

    /// Every file under the quarantine folder except its lock, by its path
    /// within it.
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
        files.retain(|file| file != Path::new("lock"));
        files.sort();
        files
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// What a guard was asked about, in order.
#[derive(Debug, Clone, Default)]
struct Asked(Arc<Mutex<Vec<PathBuf>>>);

impl Asked {
    fn note(&self, path: &Path) {
        self.0.lock().unwrap().push(path.to_path_buf());
    }

    fn paths(&self) -> Vec<PathBuf> {
        self.0.lock().unwrap().clone()
    }
}

/// Leaves every file whose name starts with "keep".
#[derive(Debug)]
struct KeepsSome {
    asked: Asked,
}

impl Guard for KeepsSome {
    fn look_at(&self, path: &Path) -> Verdict {
        self.asked.note(path);
        let name = path.file_name().unwrap().to_string_lossy();
        if name.starts_with("keep") {
            Verdict::Leave {
                why: "its name says that it is needed".to_owned(),
            }
        } else {
            Verdict::Take { sha256: None }
        }
    }
}

/// Lets every file pass, and says which content it looked at.
#[derive(Debug)]
struct Saw {
    sha256: [u8; 32],
}

impl Guard for Saw {
    fn look_at(&self, _: &Path) -> Verdict {
        Verdict::Take {
            sha256: Some(self.sha256),
        }
    }
}

fn note() -> Reason {
    Reason::note("a test")
}

#[test]
fn a_file_the_guard_would_leave_stays_and_leaves_no_trace() {
    let scene = Scene::new();
    let asked = Asked::default();
    let quarantine = scene.quarantine(KeepsSome {
        asked: asked.clone(),
    });
    let path = scene.file("keep-me.dll", b"the system needs this");

    let error = quarantine.add(&path, note()).unwrap_err();
    let QuarantineError::Guarded { path: named, why } = &error else {
        panic!("another error: {error}");
    };
    assert_eq!(Path::new(named), path);
    assert_eq!(why, "its name says that it is needed");
    assert_eq!(
        error.to_string(),
        format!(
            "{} was left where it is: its name says that it is needed",
            path.display()
        )
    );

    // The file is where it was, and the quarantine holds nothing: no
    // entry, no half-written copy, no note of something to finish.
    assert_eq!(fs::read(&path).unwrap(), b"the system needs this");
    assert!(scene.stored().is_empty(), "{:?}", scene.stored());
    assert!(quarantine.list().unwrap().entries.is_empty());
    drop(quarantine);
    let (_, recovered) = Quarantine::open(scene.dir.path().join("quarantine")).unwrap();
    assert!(recovered.is_empty(), "{recovered:?}");

    assert_eq!(asked.paths(), [path]);
}

#[test]
fn the_guard_is_asked_about_every_file_and_by_its_full_path() {
    let scene = Scene::new();
    let asked = Asked::default();
    let quarantine = scene.quarantine(KeepsSome {
        asked: asked.clone(),
    });
    let first = scene.file("one.bin", b"one");
    let second = scene.file("keep-two.bin", b"two");
    let third = scene.file("three.bin", b"three");

    let entry = quarantine.add(&first, note()).unwrap();
    assert!(!first.exists());
    assert!(matches!(
        quarantine.add(&second, note()),
        Err(QuarantineError::Guarded { .. })
    ));
    quarantine.add(&third, note()).unwrap();

    assert_eq!(asked.paths(), [first.clone(), second.clone(), third]);
    assert!(asked.paths().iter().all(|path| path.is_absolute()));
    assert!(second.exists());
    assert_eq!(quarantine.list().unwrap().entries.len(), 2);

    // A file that passed the guard comes back like any other.
    quarantine
        .restore(&entry.info.id, &RestoreOptions::default())
        .unwrap();
    assert_eq!(fs::read(&first).unwrap(), b"one");
}

#[test]
fn a_file_can_be_taken_past_the_guard_when_that_is_asked_for() {
    let scene = Scene::new();
    let asked = Asked::default();
    let quarantine = scene.quarantine(KeepsSome {
        asked: asked.clone(),
    });
    let path = scene.file("keep-me.dll", b"taken on purpose");

    // The plain way and the default options both stop at the guard.
    assert!(quarantine.add(&path, note()).is_err());
    assert!(
        quarantine
            .add_with(&path, note(), &AddOptions::default())
            .is_err()
    );
    assert_eq!(asked.paths().len(), 2);

    let entry = quarantine
        .add_with(
            &path,
            note(),
            &AddOptions {
                overrule_guard: true,
            },
        )
        .unwrap();
    assert!(!path.exists());
    assert_eq!(entry.info.size, 16);
    // Overruled, the guard is not asked.
    assert_eq!(asked.paths().len(), 2);

    quarantine
        .restore(&entry.info.id, &RestoreOptions::default())
        .unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"taken on purpose");
}

#[test]
fn what_the_guard_let_through_is_the_content_it_looked_at() {
    let scene = Scene::new();
    let bytes = b"what the guard saw".as_slice();
    let path = scene.file("tool.exe", bytes);

    // The guard saw another content than the one that is there now: as
    // if the file had been swapped between the look and the copy.
    let quarantine = scene.quarantine(Saw {
        sha256: sha256(b"something else"),
    });
    let error = quarantine.add(&path, note()).unwrap_err();
    assert!(
        matches!(error, QuarantineError::Changed { .. }),
        "another error: {error}"
    );
    assert_eq!(fs::read(&path).unwrap(), bytes);
    assert!(scene.stored().is_empty(), "{:?}", scene.stored());
    drop(quarantine);

    // The content it saw is the content that goes.
    let quarantine = scene.quarantine(Saw {
        sha256: sha256(bytes),
    });
    let entry = quarantine.add(&path, note()).unwrap();
    assert!(!path.exists());
    assert_eq!(entry.info.sha256.len(), 64);
}

#[test]
fn a_guard_is_not_asked_about_what_cannot_be_quarantined_anyway() {
    let scene = Scene::new();
    let asked = Asked::default();
    let quarantine = scene.quarantine(KeepsSome {
        asked: asked.clone(),
    });
    let folder = scene.dir.path().join("files");
    fs::create_dir_all(&folder).unwrap();

    assert!(matches!(
        quarantine.add(&folder, note()),
        Err(QuarantineError::NotAFile { .. })
    ));
    assert!(quarantine.add(&folder.join("not-there"), note()).is_err());
    assert!(asked.paths().is_empty());
}

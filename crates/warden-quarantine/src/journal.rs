//! The journal: a note of what is about to be done, written before it is
//! done.
//!
//! Quarantining a file is three steps that cannot happen at once: the copy
//! is written, the copy gets its final name, the original is removed.
//! Restoring is the same three in the other direction. If the machine goes
//! down in between, the note is what tells the next start what was going
//! on. It does not record how far things got: that is read off the disk,
//! where it cannot disagree with the facts.

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::info::ExactPath;

/// A path as a note holds it: as text, and exactly where text is not enough.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct NotedPath {
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exact: Option<ExactPath>,
}

impl NotedPath {
    pub(crate) fn of(path: &Path) -> Self {
        Self {
            text: path.to_string_lossy().into_owned(),
            exact: ExactPath::needed_for(path),
        }
    }

    pub(crate) fn to_path(&self) -> Option<PathBuf> {
        match &self.exact {
            Some(exact) => exact.to_path(),
            None => Some(PathBuf::from(&self.text)),
        }
    }
}

/// What was about to be done.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub(crate) enum Note {
    /// A file was being moved into the quarantine.
    Add { id: String, original: NotedPath },
    /// An entry was being put back.
    Restore {
        id: String,
        target: NotedPath,
        /// The temporary name the file has until it is complete.
        partial: NotedPath,
    },
}

impl Note {
    pub(crate) fn id(&self) -> &str {
        match self {
            Self::Add { id, .. } | Self::Restore { id, .. } => id,
        }
    }
}

/// Where the note for an entry lies.
pub(crate) fn path_for(journal: &Path, id: &str) -> PathBuf {
    journal.join(format!("{id}.json"))
}

/// Writes a note and makes sure it is on disk before anything it speaks of
/// is touched.
pub(crate) fn write(journal: &Path, note: &Note) -> io::Result<()> {
    let path = path_for(journal, note.id());
    let text = serde_json::to_vec_pretty(note).map_err(io::Error::other)?;
    let mut file = File::options().write(true).create_new(true).open(&path)?;
    file.write_all(&text)?;
    file.sync_all()?;
    sync_dir(journal);
    Ok(())
}

/// Removes the note for an entry. That there is none is not an error.
pub(crate) fn remove(journal: &Path, id: &str) -> io::Result<()> {
    match fs::remove_file(path_for(journal, id)) {
        Ok(()) => {
            sync_dir(journal);
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// Every note that is there, with the file it was read from. A note that
/// cannot be read comes back as `None`: it was being written when the
/// machine went down, so nothing it speaks of had been touched yet.
pub(crate) fn read_all(journal: &Path) -> io::Result<Vec<(PathBuf, Option<Note>)>> {
    let mut notes = Vec::new();
    for entry in fs::read_dir(journal)? {
        let path = entry?.path();
        let note = fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok());
        notes.push((path, note));
    }
    notes.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(notes)
}

/// Makes a change to a folder's list of names durable: a new name, a
/// rename, a removal. Without it a file can be on disk in full and still
/// have no name after a power cut. Windows has no call for this and keeps
/// a journal of its own.
pub(crate) fn sync_dir(dir: &Path) {
    #[cfg(unix)]
    if let Ok(dir) = File::open(dir) {
        // Best effort: a file system that cannot do this still works.
        let _ = dir.sync_all();
    }
    #[cfg(not(unix))]
    let _ = dir;
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn a_note_can_be_written_read_and_removed() {
        let dir = tempfile::tempdir().unwrap();
        let note = Note::Add {
            id: "00aa".to_owned(),
            original: NotedPath::of(Path::new("/somewhere/a file")),
        };
        write(dir.path(), &note).unwrap();
        // A second note for the same entry would mean two operations on it
        // at once.
        assert_eq!(
            write(dir.path(), &note).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );

        let read = read_all(dir.path()).unwrap();
        assert_eq!(read.len(), 1);
        assert_eq!(read[0].1.as_ref(), Some(&note));
        assert_eq!(read[0].0, path_for(dir.path(), "00aa"));

        remove(dir.path(), "00aa").unwrap();
        remove(dir.path(), "00aa").unwrap();
        assert!(read_all(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn a_note_that_was_cut_short_is_told_apart_from_a_whole_one() {
        let dir = tempfile::tempdir().unwrap();
        let whole = Note::Restore {
            id: "00bb".to_owned(),
            target: NotedPath::of(Path::new("/somewhere/back")),
            partial: NotedPath::of(Path::new("/somewhere/.warden-restore-00bb")),
        };
        write(dir.path(), &whole).unwrap();
        fs::write(path_for(dir.path(), "00cc"), b"{\"operation\": \"ad").unwrap();
        fs::write(path_for(dir.path(), "00dd"), b"").unwrap();

        let read = read_all(dir.path()).unwrap();
        assert_eq!(read.len(), 3);
        assert_eq!(read[0].1.as_ref(), Some(&whole));
        assert_eq!(read[1].1, None);
        assert_eq!(read[2].1, None);
    }

    #[test]
    fn the_note_is_plain_json() {
        let note = Note::Add {
            id: "00aa".to_owned(),
            original: NotedPath::of(Path::new("/somewhere/a file")),
        };
        let json: serde_json::Value = serde_json::to_value(&note).unwrap();
        assert_eq!(json["operation"], "add");
        assert_eq!(json["original"]["text"], "/somewhere/a file");
        assert!(json["original"].get("exact").is_none());
    }
}

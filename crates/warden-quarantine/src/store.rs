//! The quarantine: a folder of entries, and what can be done with them.

use std::fmt;
use std::fs::{self, File};
use std::io::{self, BufWriter, Read};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use crate::format::{self, EXTENSION, Problem};
use crate::info::{CIPHER, Cipher, EntryInfo, ExactPath, Reason};
use crate::journal::{self, Note, NotedPath, create_new_private, sync_dir};
use crate::{hex, meta};

/// Why something could not be done with the quarantine.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum QuarantineError {
    /// The file system said no.
    #[error("{context}: {source}")]
    Io {
        /// What was being done.
        context: String,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
    /// Only regular files can be quarantined.
    #[error("{path} is {what}, and only a regular file can be quarantined")]
    NotAFile {
        /// What was to be quarantined.
        path: String,
        /// What it is instead.
        what: &'static str,
    },
    /// The file was replaced or written to while it was being quarantined.
    #[error("{path} changed while it was being quarantined, so it was left where it is")]
    Changed {
        /// The file.
        path: String,
    },
    /// No entry has this identifier.
    #[error("there is no quarantine entry {0}")]
    NotFound(String),
    /// More than one entry starts with these characters.
    #[error("{count} quarantine entries start with {prefix}; give more of the identifier")]
    Ambiguous {
        /// What was given.
        prefix: String,
        /// How many entries it fits.
        count: usize,
    },
    /// The entry file cannot be used.
    #[error("the quarantine entry {file} cannot be used: {problem}")]
    Damaged {
        /// The entry file.
        file: String,
        /// What is wrong with it.
        #[source]
        problem: Problem,
    },
    /// Something is already where the file would be restored to.
    #[error("{path} exists already; restore to another place, or ask to overwrite it")]
    TargetExists {
        /// Where the file would go.
        path: String,
    },
    /// The folder the file would be restored into is not there.
    #[error("the folder {path} does not exist; make it, or restore to another place")]
    NoTargetFolder {
        /// The folder.
        path: String,
    },
    /// The entry's record does not say where the file was in a way this
    /// system understands.
    #[error(
        "entry {0} does not say where the file was in a form this system can use; say where to put it"
    )]
    NoTarget(String),
    /// The operation was stopped on purpose, see
    /// [`Quarantine::interrupt_after`].
    #[error("stopped after the step {0:?}, as a test asked for")]
    Interrupted(Step),
}

fn failed(context: impl Into<String>) -> impl FnOnce(io::Error) -> QuarantineError {
    let context = context.into();
    move |source| QuarantineError::Io { context, source }
}

/// The points at which an operation can be cut off, in the order they are
/// reached. See [`Quarantine::interrupt_after`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Step {
    /// The note of what is about to be done is on disk.
    Noted,
    /// Quarantining: the copy is written, under a temporary name.
    EntryWritten,
    /// Quarantining: the copy has its final name. From here on the file is
    /// safe in the quarantine, and the original is still at its place.
    EntryCommitted,
    /// Quarantining: the original is gone. Only the note is left to remove.
    OriginalRemoved,
    /// Restoring: the file is written, under a temporary name.
    RestoreWritten,
    /// Restoring: the file has its name back. The entry is still there,
    /// and on Windows the file does not have its read-only bit and its
    /// access rights yet.
    RestoreCommitted,
    /// Restoring: the entry is gone. Only the note is left to remove.
    EntryRemoved,
}

/// One quarantined file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The record of the file.
    pub info: EntryInfo,
    /// The entry file that holds it.
    pub file: PathBuf,
}

/// An entry file that cannot be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Damaged {
    /// The entry file.
    pub file: PathBuf,
    /// What is wrong with it.
    pub problem: String,
}

/// Everything in the quarantine.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Listing {
    /// The entries, oldest first.
    pub entries: Vec<Entry>,
    /// Entry files that cannot be read, by name.
    pub damaged: Vec<Damaged>,
}

/// How to restore.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RestoreOptions {
    /// Where to put the file. Its original place if not given.
    pub to: Option<PathBuf>,
    /// Replace a file that is already there.
    pub overwrite: bool,
}

/// A file that was put back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Restored {
    /// The record of the file. Its entry is gone.
    pub info: EntryInfo,
    /// Where the file is now.
    pub path: PathBuf,
    /// What could not be put back the way it was, one sentence each. The
    /// content is never among it: a file whose content cannot be verified
    /// is not restored at all.
    pub notes: Vec<String>,
}

/// Which operation was cut off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    /// A file was being moved into the quarantine.
    Quarantine,
    /// An entry was being put back.
    Restore,
}

/// What became of an operation that was cut off.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The file was already safe at its destination, so the rest was done.
    Finished,
    /// The file was not yet at its destination, so it stays where it came
    /// from and what had been started was cleared away.
    Undone,
    /// It could neither be finished nor undone without a risk to a file.
    /// Nothing was removed.
    LeftAlone(String),
}

/// An operation that an earlier run did not finish, and what was done
/// about it when the quarantine was opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recovered {
    /// What was going on.
    pub operation: Operation,
    /// The entry it was about.
    pub id: String,
    /// The file it was about.
    pub path: String,
    /// What was done about it.
    pub outcome: Outcome,
}

impl fmt::Display for Recovered {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { id, path, .. } = self;
        match (self.operation, &self.outcome) {
            (Operation::Quarantine, Outcome::Finished) => write!(
                formatter,
                "Quarantining {path} had been cut off after the copy was safe. It was finished: the file is in quarantine as {id}"
            ),
            (Operation::Quarantine, Outcome::Undone) => write!(
                formatter,
                "Quarantining {path} had been cut off before the copy was complete. It was undone: the file is where it was"
            ),
            (Operation::Quarantine, Outcome::LeftAlone(why)) => write!(
                formatter,
                "Quarantining {path} had been cut off, and nothing more was done: {why}"
            ),
            (Operation::Restore, Outcome::Finished) => write!(
                formatter,
                "Restoring {path} had been cut off after the file was back. It was finished: entry {id} is gone from the quarantine"
            ),
            (Operation::Restore, Outcome::Undone) => write!(
                formatter,
                "Restoring {path} had been cut off before the file was back. It was undone: entry {id} is still in quarantine"
            ),
            (Operation::Restore, Outcome::LeftAlone(why)) => write!(
                formatter,
                "Restoring {path} had been cut off, and nothing more was done: {why}"
            ),
        }
    }
}

/// How a file on disk compares with what an entry holds.
enum Compared {
    Absent,
    Same,
    Different,
    Unreadable(io::Error),
}

/// A quarantine folder, open and locked.
///
/// Only one program has a quarantine open at a time: opening waits until
/// the others are done. That is what lets [`Quarantine::open`] treat every
/// note in the journal as left behind by a run that died, and never as the
/// work of one that is still going.
#[derive(Debug)]
pub struct Quarantine {
    dir: PathBuf,
    items: PathBuf,
    journal: PathBuf,
    tmp: PathBuf,
    /// Held for as long as this value lives.
    _lock: File,
    interrupt_after: Option<Step>,
}

impl Quarantine {
    /// Opens the quarantine in `dir`, making the folder if it is not there,
    /// and deals with whatever an earlier run left unfinished.
    ///
    /// # Errors
    ///
    /// Fails if the folder cannot be made, locked or read.
    pub fn open(dir: impl Into<PathBuf>) -> Result<(Self, Vec<Recovered>), QuarantineError> {
        let dir = dir.into();
        // In full, so that what is printed later says where things are
        // whatever folder the program was started in.
        let dir = std::path::absolute(&dir)
            .map_err(failed(format!("cannot tell where {} is", dir.display())))?;
        let items = dir.join("items");
        let journal = dir.join("journal");
        let tmp = dir.join("tmp");
        for folder in [&dir, &items, &journal, &tmp] {
            make_private_dir(folder).map_err(failed(format!(
                "cannot make the folder {}",
                folder.display()
            )))?;
        }
        let mut lock = File::options();
        lock.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            lock.mode(0o600);
        }
        let lock = lock
            .open(dir.join("lock"))
            .and_then(|file| {
                file.lock()?;
                Ok(file)
            })
            .map_err(failed(format!(
                "cannot lock the quarantine in {}",
                dir.display()
            )))?;

        let quarantine = Self {
            dir,
            items,
            journal,
            tmp,
            _lock: lock,
            interrupt_after: None,
        };
        let recovered = quarantine.recover().map_err(failed(format!(
            "cannot read the journal of the quarantine in {}",
            quarantine.dir.display()
        )))?;
        Ok((quarantine, recovered))
    }

    /// The folder this quarantine lives in.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Makes the next operation stop right after `step`, and leave
    /// everything the way a program that died at that point would: nothing
    /// is cleaned up, and the note stays in the journal.
    ///
    /// This exists for tests. It is how "the machine went down in the
    /// middle" is tried without taking a machine down: stop here, drop the
    /// quarantine, open it again, and look at what recovery made of it.
    #[doc(hidden)]
    pub fn interrupt_after(&mut self, step: Step) {
        self.interrupt_after = Some(step);
    }

    fn reached(&self, step: Step) -> Result<(), QuarantineError> {
        if self.interrupt_after == Some(step) {
            Err(QuarantineError::Interrupted(step))
        } else {
            Ok(())
        }
    }

    fn entry_path(&self, id: &str) -> PathBuf {
        self.items.join(format!("{id}.{EXTENSION}"))
    }

    fn partial_path(&self, id: &str) -> PathBuf {
        self.tmp.join(format!("{id}.partial"))
    }

    /// An identifier that no entry has yet: sixteen random hexadecimal
    /// digits.
    fn new_id(&self) -> io::Result<String> {
        loop {
            let id = hex::encode(&random::<8>()?);
            if !self.entry_path(&id).exists() && !journal::path_for(&self.journal, &id).exists() {
                return Ok(id);
            }
        }
    }

    /// Moves a file into the quarantine.
    ///
    /// When this returns, the file is no longer at its place, and its
    /// content, timestamps and permissions are in an entry. If it fails,
    /// the file is where it was and nothing is left in the quarantine.
    ///
    /// # Errors
    ///
    /// Fails if `path` is not a regular file, cannot be read or cannot be
    /// removed, if it changes while it is being read, or if the quarantine
    /// cannot be written to.
    pub fn add(&self, path: &Path, reason: Reason) -> Result<Entry, QuarantineError> {
        let path = std::path::absolute(path)
            .map_err(failed(format!("cannot tell where {} is", path.display())))?;
        let shown = path.display().to_string();

        // Without following a link: what gets quarantined is what has this
        // name, not what it points to.
        let listed =
            fs::symlink_metadata(&path).map_err(failed(format!("cannot look at {shown}")))?;
        if !listed.file_type().is_file() {
            return Err(QuarantineError::NotAFile {
                path: shown,
                what: kind_of(&listed),
            });
        }
        let mut source = File::open(&path).map_err(failed(format!("cannot open {shown}")))?;
        let opened = source
            .metadata()
            .map_err(failed(format!("cannot look at {shown}")))?;
        if !opened.is_file() || !same_file(&listed, &opened) {
            return Err(QuarantineError::Changed { path: shown });
        }
        let captured = meta::capture(&source, &opened, &path);

        let id = self
            .new_id()
            .map_err(failed("cannot get random bytes from the system"))?;
        let (key, nonce) = random::<32>()
            .and_then(|key| Ok((key, random::<12>()?)))
            .map_err(failed("cannot get random bytes from the system"))?;
        journal::write(
            &self.journal,
            &Note::Add {
                id: id.clone(),
                original: NotedPath::of(&path),
            },
        )
        .map_err(failed("cannot write to the quarantine's journal"))?;
        self.reached(Step::Noted)?;

        let partial = self.partial_path(&id);
        let written = (|| -> io::Result<EntryInfo> {
            let mut out = BufWriter::new(create_new_private(&partial)?);
            let info = format::write_entry(&mut source, &mut out, &key, &nonce, |size, sha256| {
                EntryInfo {
                    id: id.clone(),
                    quarantined_unix_ms: now_unix_ms(),
                    original_path: path.to_string_lossy().into_owned(),
                    original_exact: ExactPath::needed_for(&path),
                    size,
                    sha256: hex::encode(&sha256),
                    cipher: Cipher {
                        algorithm: CIPHER.to_owned(),
                        key: hex::encode(&key),
                        nonce: hex::encode(&nonce),
                    },
                    times: captured.times,
                    unix: captured.unix,
                    windows: captured.windows.clone(),
                    reason,
                    warden_version: env!("CARGO_PKG_VERSION").to_owned(),
                }
            })?;
            let file = out.into_inner().map_err(io::IntoInnerError::into_error)?;
            file.sync_all()?;
            Ok(info)
        })();
        drop(source);
        let info = match written {
            Ok(info) => info,
            Err(source) => {
                let _ = fs::remove_file(&partial);
                let _ = journal::remove(&self.journal, &id);
                return Err(QuarantineError::Io {
                    context: format!("cannot copy {shown} into the quarantine"),
                    source,
                });
            }
        };
        self.reached(Step::EntryWritten)?;

        let entry_file = self.entry_path(&id);
        if let Err(source) = fs::rename(&partial, &entry_file) {
            let _ = fs::remove_file(&partial);
            let _ = journal::remove(&self.journal, &id);
            return Err(QuarantineError::Io {
                context: "cannot give the quarantine entry its name".to_owned(),
                source,
            });
        }
        sync_dir(&self.items);
        self.reached(Step::EntryCommitted)?;

        // The copy is safe. Before the original goes, make sure it is still
        // the file that was copied: same file, same size, not written since.
        let unchanged = fs::symlink_metadata(&path).is_ok_and(|now| {
            now.file_type().is_file()
                && same_file(&opened, &now)
                && now.len() == info.size
                && now.modified().ok() == opened.modified().ok()
        });
        let undo = |error: QuarantineError| {
            let _ = fs::remove_file(&entry_file);
            sync_dir(&self.items);
            let _ = journal::remove(&self.journal, &id);
            error
        };
        if !unchanged {
            return Err(undo(QuarantineError::Changed { path: shown }));
        }
        if let Err(source) = meta::make_removable(&path).and_then(|()| fs::remove_file(&path)) {
            return Err(undo(QuarantineError::Io {
                context: format!("cannot remove {shown}, so it was not quarantined"),
                source,
            }));
        }
        if let Some(parent) = path.parent() {
            sync_dir(parent);
        }
        self.reached(Step::OriginalRemoved)?;

        journal::remove(&self.journal, &id)
            .map_err(failed("cannot clear the quarantine's journal"))?;
        Ok(Entry {
            info,
            file: entry_file,
        })
    }

    /// Everything in the quarantine, oldest first.
    ///
    /// # Errors
    ///
    /// Fails if the quarantine folder cannot be read. An entry file that
    /// cannot be read is listed as damaged and is not an error.
    pub fn list(&self) -> Result<Listing, QuarantineError> {
        let read_failed = || format!("cannot read the quarantine in {}", self.dir.display());
        let mut listing = Listing::default();
        for item in fs::read_dir(&self.items).map_err(failed(read_failed()))? {
            let file = item.map_err(failed(read_failed()))?.path();
            if file
                .extension()
                .is_none_or(|extension| extension != EXTENSION)
            {
                continue;
            }
            let read = File::open(&file)
                .map_err(Problem::Io)
                .and_then(|mut entry| format::read_info(&mut entry));
            match read {
                Ok(info)
                    if file
                        .file_stem()
                        .is_some_and(|stem| stem == info.id.as_str()) =>
                {
                    listing.entries.push(Entry { info, file });
                }
                Ok(_) => listing.damaged.push(Damaged {
                    file,
                    problem: "its name is not the identifier in its record".to_owned(),
                }),
                Err(problem) => listing.damaged.push(Damaged {
                    file,
                    problem: problem.to_string(),
                }),
            }
        }
        listing.entries.sort_by(|left, right| {
            (left.info.quarantined_unix_ms, &left.info.id)
                .cmp(&(right.info.quarantined_unix_ms, &right.info.id))
        });
        listing
            .damaged
            .sort_by(|left, right| left.file.cmp(&right.file));
        Ok(listing)
    }

    /// The entry with this identifier, or the only one whose identifier
    /// starts with these characters.
    ///
    /// # Errors
    ///
    /// Fails if no entry fits, if more than one does, or if the one that
    /// fits is damaged.
    pub fn find(&self, id: &str) -> Result<Entry, QuarantineError> {
        let listing = self.list()?;
        if id.is_empty() {
            return Err(QuarantineError::NotFound(id.to_owned()));
        }
        let mut fitting: Vec<Entry> = listing
            .entries
            .into_iter()
            .filter(|entry| entry.info.id.starts_with(id))
            .collect();
        if let Some(exact) = fitting.iter().position(|entry| entry.info.id == id) {
            return Ok(fitting.swap_remove(exact));
        }
        match fitting.len() {
            1 => Ok(fitting.swap_remove(0)),
            0 => {
                // Not among the readable ones. If it is there and damaged,
                // say that, and not that it does not exist.
                let damaged = listing.damaged.into_iter().find(|damaged| {
                    damaged
                        .file
                        .file_stem()
                        .is_some_and(|stem| stem.to_string_lossy().starts_with(id))
                });
                match damaged {
                    Some(damaged) => {
                        let problem = File::open(&damaged.file)
                            .map_err(Problem::Io)
                            .and_then(|mut entry| format::read_info(&mut entry).map(|_| ()))
                            .err()
                            .unwrap_or(Problem::Record("its name is not the identifier in it"));
                        Err(QuarantineError::Damaged {
                            file: damaged.file.display().to_string(),
                            problem,
                        })
                    }
                    None => Err(QuarantineError::NotFound(id.to_owned())),
                }
            }
            count => Err(QuarantineError::Ambiguous {
                prefix: id.to_owned(),
                count,
            }),
        }
    }

    /// Puts a quarantined file back, with the content, the timestamps and
    /// the permissions it had, and removes its entry.
    ///
    /// The file is written under a temporary name next to its destination
    /// and checked against the SHA-256 in the record before it gets its
    /// name. If anything fails before that, the entry stays in quarantine
    /// and nothing is left at the destination.
    ///
    /// # Errors
    ///
    /// Fails if no entry fits `id`, if the entry is damaged, if something
    /// is already at the destination and overwriting was not asked for, or
    /// if the destination cannot be written.
    pub fn restore(&self, id: &str, options: &RestoreOptions) -> Result<Restored, QuarantineError> {
        let Entry {
            info,
            file: entry_file,
        } = self.find(id)?;
        let target = match &options.to {
            Some(to) => to.clone(),
            None => info
                .original()
                .ok_or_else(|| QuarantineError::NoTarget(info.id.clone()))?,
        };
        let target = std::path::absolute(&target)
            .map_err(failed(format!("cannot tell where {} is", target.display())))?;
        let shown = target.display().to_string();

        let existing = match fs::symlink_metadata(&target) {
            Ok(metadata) => Some(metadata),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(source) => {
                return Err(QuarantineError::Io {
                    context: format!("cannot look at {shown}"),
                    source,
                });
            }
        };
        if existing
            .as_ref()
            .is_some_and(|there| !options.overwrite || !there.file_type().is_file())
        {
            return Err(QuarantineError::TargetExists { path: shown });
        }
        let parent = target
            .parent()
            .filter(|parent| parent.is_dir())
            .ok_or_else(|| QuarantineError::NoTargetFolder {
                path: target
                    .parent()
                    .map_or_else(|| shown.clone(), |parent| parent.display().to_string()),
            })?;

        // Next to the destination, so that giving the file its name is one
        // step of the file system and not a copy.
        let partial = parent.join(format!(".warden-restore-{}", info.id));
        let _ = fs::remove_file(&partial);
        journal::write(
            &self.journal,
            &Note::Restore {
                id: info.id.clone(),
                target: NotedPath::of(&target),
                partial: NotedPath::of(&partial),
            },
        )
        .map_err(failed("cannot write to the quarantine's journal"))?;
        self.reached(Step::Noted)?;

        let give_up = |error: QuarantineError| {
            let _ = fs::remove_file(&partial);
            let _ = journal::remove(&self.journal, &info.id);
            error
        };
        let written = (|| -> Result<(File, Vec<String>), Problem> {
            let mut out = BufWriter::new(meta::create(&partial, &info)?);
            let mut entry = File::open(&entry_file)?;
            format::write_content(&mut entry, &info, &mut out)?;
            let file = out.into_inner().map_err(io::IntoInnerError::into_error)?;
            let notes = meta::apply(&file, &partial, &info);
            file.sync_all()?;
            Ok((file, notes))
        })();
        // The file stays open until the end: what it gets after it has its
        // name goes on through this handle.
        let (file, mut notes) = match written {
            Ok(written) => written,
            Err(Problem::Io(source)) => {
                return Err(give_up(QuarantineError::Io {
                    context: format!("cannot write {shown}"),
                    source,
                }));
            }
            Err(problem) => {
                return Err(give_up(QuarantineError::Damaged {
                    file: entry_file.display().to_string(),
                    problem,
                }));
            }
        };
        self.reached(Step::RestoreWritten)?;

        let committed = if existing.is_some() {
            meta::make_removable(&target).and_then(|()| fs::rename(&partial, &target))
        } else {
            name_without_replacing(&partial, &target)
        };
        match committed {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                return Err(give_up(QuarantineError::TargetExists { path: shown }));
            }
            Err(source) => {
                return Err(give_up(QuarantineError::Io {
                    context: format!("cannot give {shown} its name"),
                    source,
                }));
            }
        }
        sync_dir(parent);
        self.reached(Step::RestoreCommitted)?;
        if partial.exists() && fs::remove_file(&partial).is_err() {
            notes.push(format!(
                "A second name of the file was left behind and can be deleted: {}",
                partial.display()
            ));
        }
        notes.extend(meta::apply_after_commit(&file, &info));
        drop(file);

        fs::remove_file(&entry_file).map_err(failed(format!(
            "{shown} is back, but its quarantine entry could not be removed"
        )))?;
        sync_dir(&self.items);
        self.reached(Step::EntryRemoved)?;
        journal::remove(&self.journal, &info.id)
            .map_err(failed("cannot clear the quarantine's journal"))?;
        Ok(Restored {
            info,
            path: target,
            notes,
        })
    }

    /// Removes an entry for good. The file it held cannot be brought back.
    ///
    /// Returns the record of what was removed. A damaged entry can be
    /// removed too, by its whole identifier, and then there is no record to
    /// return.
    ///
    /// # Errors
    ///
    /// Fails if no entry fits `id`, or if the entry file cannot be removed.
    pub fn delete(&self, id: &str) -> Result<Option<EntryInfo>, QuarantineError> {
        let (file, info) = match self.find(id) {
            Ok(entry) => (entry.file, Some(entry.info)),
            Err(QuarantineError::Damaged { .. }) if self.entry_path(id).is_file() => {
                (self.entry_path(id), None)
            }
            Err(error) => return Err(error),
        };
        fs::remove_file(&file).map_err(failed(format!(
            "cannot remove the quarantine entry {}",
            file.display()
        )))?;
        sync_dir(&self.items);
        Ok(info)
    }

    /// Deals with every note an earlier run left in the journal.
    fn recover(&self) -> io::Result<Vec<Recovered>> {
        let mut recovered = Vec::new();
        for (note_file, note) in journal::read_all(&self.journal)? {
            match note {
                Some(Note::Add { id, original }) => {
                    recovered.push(self.recover_add(&id, &original));
                }
                Some(Note::Restore {
                    id,
                    target,
                    partial,
                }) => recovered.push(self.recover_restore(&id, &target, &partial)),
                // The note itself was never finished, so nothing it speaks
                // of had been touched.
                None => {}
            }
            fs::remove_file(&note_file)?;
        }
        sync_dir(&self.journal);
        // Nothing of value is ever only in here.
        for stray in fs::read_dir(&self.tmp)? {
            let _ = fs::remove_file(stray?.path());
        }
        Ok(recovered)
    }

    fn read_entry(&self, id: &str) -> Option<EntryInfo> {
        let mut file = File::open(self.entry_path(id)).ok()?;
        format::read_info(&mut file).ok()
    }

    fn recover_add(&self, id: &str, original: &NotedPath) -> Recovered {
        let _ = fs::remove_file(self.partial_path(id));
        let outcome = match (self.read_entry(id), original.to_path()) {
            // The copy never got its name: the file is where it was.
            (None, _) => Outcome::Undone,
            (Some(_), None) => Outcome::LeftAlone(
                "the note does not say where the file was in a form this system can use".to_owned(),
            ),
            // The copy is safe, so quarantining goes through: what was
            // asked for was a file out of harm's way.
            (Some(info), Some(path)) => match compare(&path, &info) {
                Compared::Absent => Outcome::Finished,
                Compared::Same => {
                    match meta::make_removable(&path).and_then(|()| fs::remove_file(&path)) {
                        Ok(()) => Outcome::Finished,
                        Err(error) => Outcome::LeftAlone(format!(
                            "the file is in quarantine as {id}, and it is also still at its place, where it could not be removed ({error})"
                        )),
                    }
                }
                Compared::Different => Outcome::LeftAlone(format!(
                    "the file is in quarantine as {id}, and another file has its place now, which was not touched"
                )),
                Compared::Unreadable(error) => Outcome::LeftAlone(format!(
                    "the file is in quarantine as {id}; whether it is also still at its place could not be found out ({error})"
                )),
            },
        };
        Recovered {
            operation: Operation::Quarantine,
            id: id.to_owned(),
            path: original.text.clone(),
            outcome,
        }
    }

    fn recover_restore(&self, id: &str, target: &NotedPath, partial: &NotedPath) -> Recovered {
        if let Some(partial) = partial.to_path() {
            let _ = fs::remove_file(partial);
        }
        let outcome = match (self.read_entry(id), target.to_path()) {
            (None, _) if self.entry_path(id).exists() => {
                Outcome::LeftAlone(format!("entry {id} cannot be read"))
            }
            // The entry is gone: only the note was left to clear.
            (None, _) => Outcome::Finished,
            (Some(_), None) => Outcome::Undone,
            (Some(info), Some(path)) => match compare(&path, &info) {
                // The file is back, whole. What it gets after it has its
                // name may be missing, and the entry is left over. In this
                // order: the entry holds what the file is to get.
                Compared::Same => {
                    meta::apply_after_commit_at(&path, &info);
                    match fs::remove_file(self.entry_path(id)) {
                        Ok(()) => Outcome::Finished,
                        Err(error) => Outcome::LeftAlone(format!(
                            "the file is back, and entry {id} could not be removed ({error})"
                        )),
                    }
                }
                Compared::Absent | Compared::Different | Compared::Unreadable(_) => Outcome::Undone,
            },
        };
        Recovered {
            operation: Operation::Restore,
            id: id.to_owned(),
            path: target.text.clone(),
            outcome,
        }
    }
}

/// Where the quarantine is kept if nobody says otherwise: a folder of the
/// user who runs Warden, which other users cannot read.
///
/// A quarantine for the whole machine needs a program that owns it and
/// runs with rights of its own. That is the Windows service of a later
/// phase.
#[must_use]
pub fn default_dir() -> Option<PathBuf> {
    let from = |name: &str| {
        std::env::var_os(name)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
    };
    if cfg!(windows) {
        Some(from("LOCALAPPDATA")?.join("Warden").join("Quarantine"))
    } else {
        let data = from("XDG_DATA_HOME").or_else(|| Some(from("HOME")?.join(".local/share")))?;
        Some(data.join("warden").join("quarantine"))
    }
}

/// Makes a folder that only its owner can enter, where the system has such
/// a thing as permission bits. A folder that is already there is left as it
/// is.
fn make_private_dir(path: &Path) -> io::Result<()> {
    if path.is_dir() {
        return Ok(());
    }
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
}

fn kind_of(metadata: &fs::Metadata) -> &'static str {
    let kind = metadata.file_type();
    if kind.is_dir() {
        "a folder"
    } else if kind.is_symlink() {
        "a link"
    } else {
        "not a regular file"
    }
}

/// Whether two looks at a path saw the same file, as far as the system
/// lets a program tell.
#[cfg(unix)]
fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    // No identity to compare without more of the Windows API. Kind and
    // creation time are what is there.
    left.file_type() == right.file_type() && left.created().ok() == right.created().ok()
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        })
}

fn random<const N: usize>() -> io::Result<[u8; N]> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).map_err(|error| io::Error::other(error.to_string()))?;
    Ok(bytes)
}

/// Gives `partial` the name `target`, and fails if something has that name
/// already. A plain rename would replace it.
fn name_without_replacing(partial: &Path, target: &Path) -> io::Result<()> {
    match fs::hard_link(partial, target) {
        // The file now has both names. The temporary one is removed by the
        // caller, who can say so if that fails.
        Ok(()) => {
            let _ = fs::remove_file(partial);
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Err(error),
        Err(_) => {
            // A file system without hard links: some network shares, and
            // the FAT family. Look, then rename.
            if fs::symlink_metadata(target).is_ok() {
                return Err(io::ErrorKind::AlreadyExists.into());
            }
            fs::rename(partial, target)
        }
    }
}

fn sha256_of(path: &Path) -> io::Result<[u8; 32]> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut chunk = vec![0u8; 256 * 1024];
    loop {
        match file.read(&mut chunk) {
            Ok(0) => return Ok(hasher.finalize().into()),
            Ok(read) => hasher.update(&chunk[..read]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

fn compare(path: &Path, info: &EntryInfo) -> Compared {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Compared::Absent,
        Err(error) => return Compared::Unreadable(error),
    };
    if !metadata.file_type().is_file() || metadata.len() != info.size {
        return Compared::Different;
    }
    match sha256_of(path) {
        Ok(digest) if hex::encode(&digest) == info.sha256 => Compared::Same,
        Ok(_) => Compared::Different,
        Err(error) => Compared::Unreadable(error),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::info::{Stamp, Times, UnixMeta, WindowsMeta};

    /// A quarantine folder can be carried from one machine to another, and
    /// then holds entries whose owner and access rights mean nothing where
    /// they are restored. The content and the timestamps still do.
    #[test]
    fn an_entry_from_the_other_kind_of_system_comes_back_with_a_remark() {
        let dir = tempfile::tempdir().unwrap();
        let (quarantine, _) = Quarantine::open(dir.path().join("quarantine")).unwrap();
        let target = dir.path().join("travelled.bin");
        let bytes = b"quarantined on another machine. ".repeat(100);
        let modified = Stamp {
            secs: 1_614_834_367,
            nanos: 500_000_000,
        };

        // An entry file as `add` writes it, with the record that the other
        // kind of system makes.
        let (key, nonce) = ([7u8; 32], [9u8; 12]);
        let id = "00000000000000aa";
        let mut entry = Vec::new();
        format::write_entry(
            &mut bytes.as_slice(),
            &mut entry,
            &key,
            &nonce,
            |size, sha256| EntryInfo {
                id: id.to_owned(),
                quarantined_unix_ms: 1_700_000_000_000,
                original_path: target.to_string_lossy().into_owned(),
                original_exact: None,
                size,
                sha256: hex::encode(&sha256),
                cipher: Cipher {
                    algorithm: CIPHER.to_owned(),
                    key: hex::encode(&key),
                    nonce: hex::encode(&nonce),
                },
                times: Times {
                    modified: Some(modified),
                    accessed: None,
                    created: None,
                },
                unix: cfg!(windows).then_some(UnixMeta {
                    mode: 0o644,
                    uid: 1000,
                    gid: 1000,
                }),
                windows: cfg!(unix).then(|| WindowsMeta {
                    // Read-only and "archive".
                    attributes: 0x21,
                    security_descriptor: None,
                    zone_identifier: Some(hex::encode(b"[ZoneTransfer]\r\nZoneId=3\r\n")),
                }),
                reason: Reason::note("made elsewhere"),
                warden_version: "0.1.0".to_owned(),
            },
        )
        .unwrap();
        fs::write(quarantine.entry_path(id), entry).unwrap();

        let listed = quarantine.list().unwrap();
        assert!(listed.damaged.is_empty(), "{:?}", listed.damaged);
        assert_eq!(listed.entries.len(), 1);

        let restored = quarantine
            .restore("00", &RestoreOptions::default())
            .unwrap();
        assert_eq!(restored.path, target);
        assert_eq!(fs::read(&target).unwrap(), bytes);
        assert_eq!(
            fs::metadata(&target).unwrap().modified().ok(),
            modified.to_system_time()
        );
        let remark = if cfg!(windows) {
            "The entry comes from a Unix system; its owner and permission bits mean nothing on Windows"
        } else if cfg!(unix) {
            "The entry comes from Windows, and its access rights mean nothing on this system. Only the owner of the file can read and write it"
        } else {
            return;
        };
        assert_eq!(restored.notes, [remark]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Not what a new file gets by default, which others could read.
            let mode = fs::metadata(&target).unwrap().permissions().mode();
            assert_eq!(mode & 0o7777, 0o600);
        }
    }
}

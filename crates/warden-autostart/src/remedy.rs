//! Finding what starts a file, taking it away with the file, and putting
//! it back.
//!
//! The order of things is what makes this safe to cut off:
//!
//! 1. The entries are found while the file is still there.
//! 2. The file goes into the quarantine. Until here nothing was touched.
//! 3. A record of every entry, whole, is kept with the file's entry. From
//!    here on each entry is in its place, in the record, or in both.
//! 4. The entries are removed one by one, and the record says after each
//!    what became of it.
//!
//! Putting back reads the record and looks before it writes: an entry
//! that is in its place is left, whether it was never removed or is back
//! already, and only one that is missing is created. Doing it twice
//! therefore does no more than doing it once, and a restore that was cut
//! off can simply be done again. The record goes when everything is back.

use std::io;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use warden_quarantine::{AddOptions, Quarantine, QuarantineError, Reason, RestoreOptions};

use crate::entry::{Entry, Service, Shortcut, Task};
use crate::record::{Item, KIND, Record, SCHEMA, State};
use crate::starts::{Spellings, starts};
use crate::system::{Seen, System};
use crate::task;

/// What starts a file.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Found {
    /// The entries that start it.
    pub starting: Vec<Seen>,
    /// What could not be looked at. An entry that starts the file can be
    /// among what is missing.
    pub problems: Vec<String>,
}

/// Finds the entries that start a file. The file has to be there still:
/// the system is asked for the other ways its path is written.
#[must_use]
pub fn find(system: &dyn System, file: &Path) -> Found {
    let mut paths = vec![file.to_string_lossy().into_owned()];
    paths.extend(system.spellings(file));
    let spellings = Spellings::new(paths);
    let survey = system.survey();
    Found {
        starting: survey
            .seen
            .into_iter()
            .filter(|seen| starts(&seen.lines, &spellings))
            .collect(),
        problems: survey.problems,
    }
}

/// The points at which an operation can be cut off, for tests. See
/// [`Remedy::interrupt_after`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Removing: the record is kept, and nothing is removed yet.
    Recorded,
    /// Removing: the entry with this number is gone from the system, and
    /// the record does not say so yet.
    Removed(usize),
    /// Putting back: the entry with this number is dealt with, and the
    /// record still holds everything.
    PutBack(usize),
}

/// What can go wrong with a record.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AutostartError {
    /// The quarantine said no.
    #[error(transparent)]
    Quarantine(#[from] QuarantineError),
    /// A record that the quarantine holds cannot be read.
    #[error("the record of what was removed with entry {id} cannot be used: {problem}")]
    BadRecord {
        /// The entry the record belongs to.
        id: String,
        /// What is wrong with it.
        problem: String,
    },
    /// The operation was stopped on purpose, see
    /// [`Remedy::interrupt_after`].
    #[error("stopped after the step {0:?}, as a test asked for")]
    Interrupted(Step),
}

/// Why an entry stays where it is.
struct Refused {
    why: String,
    needs_rights: bool,
}

/// An entry that was not removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Left {
    /// The entry. It is in its place.
    pub entry: Entry,
    /// Why, as a clause that can follow "because".
    pub why: String,
    /// Whether it could be removed with more rights.
    pub needs_rights: bool,
}

/// What became of the entries that started a file.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Removal {
    /// The entries that were removed. They are in the record.
    pub removed: Vec<Entry>,
    /// The entries that are still in their place.
    pub left: Vec<Left>,
}

/// What became of one entry when it was to be put back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// It was created again. With it comes what could not be made the way
    /// it was, one sentence each.
    Back(Vec<String>),
    /// It was in its place already, the same as in the record.
    InPlace,
    /// It had never been removed, for the reason given at the time.
    NeverRemoved(String),
    /// Something else is at its place now. Nothing was replaced, and the
    /// record keeps the entry.
    Occupied,
    /// It could not be put back, for this reason. The record keeps the
    /// entry, and putting back can be tried again.
    Failed(String),
    /// It is gone and nothing is left to put back: a shortcut that was
    /// not in the quarantine and is not at its place.
    Lost,
}

impl Outcome {
    /// Whether the entry is still owed: it is in the record and not in
    /// its place.
    #[must_use]
    pub fn is_owed(&self) -> bool {
        matches!(self, Self::Occupied | Self::Failed(_))
    }
}

/// What became of the entries of a record when they were put back.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PutBack {
    /// Each entry of the record with what became of it, in the record's
    /// order.
    pub entries: Vec<(Entry, Outcome)>,
}

impl PutBack {
    /// Whether something is still owed. The record is kept then, and
    /// putting back can be tried again.
    #[must_use]
    pub fn is_owing(&self) -> bool {
        self.entries.iter().any(|(_, outcome)| outcome.is_owed())
    }
}

/// Removes and puts back what starts quarantined files.
#[derive(Debug)]
pub struct Remedy<'a> {
    system: &'a dyn System,
    quarantine: &'a Quarantine,
    interrupt_after: Option<Step>,
}

impl<'a> Remedy<'a> {
    /// A remedy that works on this system and keeps its records in this
    /// quarantine.
    #[must_use]
    pub fn new(system: &'a dyn System, quarantine: &'a Quarantine) -> Self {
        Self {
            system,
            quarantine,
            interrupt_after: None,
        }
    }

    /// Makes the next operation stop right after `step`, and leave
    /// everything the way a program that died at that point would. This
    /// exists for tests.
    #[doc(hidden)]
    pub fn interrupt_after(&mut self, step: Step) {
        self.interrupt_after = Some(step);
    }

    fn reached(&self, step: Step) -> Result<(), AutostartError> {
        if self.interrupt_after == Some(step) {
            Err(AutostartError::Interrupted(step))
        } else {
            Ok(())
        }
    }

    /// Removes the entries that started a file, once the file is in the
    /// quarantine as entry `id`. `file` is where the file lay, and
    /// `starting` is what [`find`] found while it was still there.
    ///
    /// An entry that could not be put back afterwards is not removed: a
    /// task or a service that runs with a stored password, which nobody
    /// gives back.
    ///
    /// # Errors
    ///
    /// Fails if the record cannot be kept. Nothing was removed then. An
    /// entry that cannot be removed is no error; it is among those that
    /// were [left](Removal::left).
    pub fn remove(
        &self,
        id: &str,
        file: &str,
        starting: Vec<Seen>,
    ) -> Result<Removal, AutostartError> {
        if starting.is_empty() {
            return Ok(Removal::default());
        }
        let mut record = Record {
            schema: SCHEMA,
            entry: id.to_owned(),
            file: file.to_owned(),
            made_unix_ms: now_unix_ms(),
            warden_version: env!("CARGO_PKG_VERSION").to_owned(),
            items: starting
                .into_iter()
                .map(|seen| {
                    let obstacle = cannot_be_put_back(&seen.entry);
                    Item {
                        what: seen.entry,
                        state: if obstacle.is_some() {
                            State::Left
                        } else {
                            State::Recorded
                        },
                        quarantined_as: None,
                        note: obstacle,
                        needs_rights: false,
                    }
                })
                .collect(),
        };
        self.keep(&record)?;
        self.reached(Step::Recorded)?;
        self.work_through(&mut record)
    }

    /// Goes on with a removal that did not get to its end: because it was
    /// cut off, or because entries were left for want of rights and the
    /// rights are there now. Entries that were left for another reason
    /// stay.
    ///
    /// # Errors
    ///
    /// Fails if there is no usable record for `id`, or if it cannot be
    /// kept.
    pub fn finish_removing(&self, id: &str) -> Result<Removal, AutostartError> {
        let Some(mut record) = self.record(id)? else {
            return Ok(Removal::default());
        };
        for item in &mut record.items {
            if item.state == State::Left && item.needs_rights {
                item.state = State::Recorded;
                item.note = None;
                item.needs_rights = false;
            }
        }
        self.work_through(&mut record)
    }

    fn work_through(&self, record: &mut Record) -> Result<Removal, AutostartError> {
        for index in 0..record.items.len() {
            if record.items[index].state != State::Recorded {
                continue;
            }
            let taken = self.take_away(record, index);
            let item = &mut record.items[index];
            match taken {
                Ok(quarantined_as) => {
                    item.state = State::Removed;
                    if quarantined_as.is_some() {
                        item.quarantined_as = quarantined_as;
                    }
                }
                Err(Refused { why, needs_rights }) => {
                    item.state = State::Left;
                    item.note = Some(why);
                    item.needs_rights = needs_rights;
                }
            }
            self.reached(Step::Removed(index))?;
            self.keep(record)?;
        }

        let mut removal = Removal::default();
        for item in &record.items {
            match item.state {
                State::Removed | State::Recorded => removal.removed.push(item.what.clone()),
                State::Left => removal.left.push(Left {
                    entry: item.what.clone(),
                    why: item.note.clone().unwrap_or_default(),
                    needs_rights: item.needs_rights,
                }),
            }
        }
        if removal.removed.is_empty() && !removal.left.iter().any(|left| left.needs_rights) {
            // Nothing was taken and nothing waits for more rights, so
            // there is nothing to keep a record for.
            self.quarantine.detach(&record.entry, KIND)?;
        }
        Ok(removal)
    }

    /// Takes one entry away. For a shortcut, returns the identifier its
    /// file has in the quarantine.
    fn take_away(&self, record: &Record, index: usize) -> Result<Option<String>, Refused> {
        let left = |why: String, needs_rights: bool| Refused { why, needs_rights };
        match &record.items[index].what {
            Entry::Shortcut(shortcut) => {
                // Cut off after the shortcut went and before the record
                // said so: it is in the quarantine already.
                if let Some(id) = self.shortcut_in_quarantine(shortcut, &record.entry) {
                    return Ok(Some(id));
                }
                let reason = Reason::note(shortcut_note(&record.file, &record.entry));
                match self.quarantine.add_with(
                    Path::new(&shortcut.path),
                    reason,
                    &AddOptions::default(),
                ) {
                    Ok(entry) => Ok(Some(entry.info.id)),
                    Err(QuarantineError::Guarded { why, .. }) => Err(left(why, false)),
                    Err(QuarantineError::Io { source, .. })
                        if source.kind() == io::ErrorKind::NotFound =>
                    {
                        // Somebody else took it away in the meantime.
                        Ok(None)
                    }
                    Err(QuarantineError::Io { context, source }) => Err(left(
                        format!("{context}: {source}"),
                        source.kind() == io::ErrorKind::PermissionDenied,
                    )),
                    Err(other) => Err(left(other.to_string(), false)),
                }
            }
            other => self
                .system
                .remove(other)
                .map(|()| None)
                .map_err(|failure| left(failure.reason, failure.needs_rights)),
        }
    }

    /// Puts back what was removed together with entry `id`, after the
    /// file itself is back. Returns nothing if no record is kept for
    /// `id`.
    ///
    /// Every entry of the record is looked at first. One that is in its
    /// place and the same is left. One that is missing is created and
    /// read back. One whose place something else has taken is not
    /// replaced. If everything is in its place afterwards, the record is
    /// let go; otherwise it stays with what is still owed, and this can
    /// be done again.
    ///
    /// # Errors
    ///
    /// Fails if the record cannot be read or kept. An entry that cannot
    /// be put back is no error; what became of it is in the result.
    pub fn put_back(&self, id: &str) -> Result<Option<PutBack>, AutostartError> {
        let Some(mut record) = self.record(id)? else {
            return Ok(None);
        };
        let mut result = PutBack::default();
        for index in 0..record.items.len() {
            let outcome = self.put_one_back(&record, index);
            result
                .entries
                .push((record.items[index].what.clone(), outcome));
            self.reached(Step::PutBack(index))?;
        }

        let mut owed = Vec::new();
        for (item, (_, outcome)) in record.items.drain(..).zip(&result.entries) {
            if outcome.is_owed() {
                owed.push(Item {
                    state: State::Removed,
                    note: match outcome {
                        Outcome::Occupied => Some(
                            "something else was at its place when it was to be put back".to_owned(),
                        ),
                        Outcome::Failed(why) => Some(why.clone()),
                        _ => None,
                    },
                    ..item
                });
            }
        }
        if owed.is_empty() {
            self.quarantine.detach(id, KIND)?;
        } else {
            record.items = owed;
            self.keep(&record)?;
        }
        Ok(Some(result))
    }

    fn put_one_back(&self, record: &Record, index: usize) -> Outcome {
        let item = &record.items[index];
        if item.state == State::Left {
            return Outcome::NeverRemoved(item.note.clone().unwrap_or_default());
        }
        match &item.what {
            Entry::Shortcut(shortcut) => {
                let child = item
                    .quarantined_as
                    .clone()
                    .or_else(|| self.shortcut_in_quarantine(shortcut, &record.entry));
                let Some(child) = child else {
                    return if Path::new(&shortcut.path).exists() {
                        Outcome::InPlace
                    } else {
                        Outcome::Lost
                    };
                };
                match self.quarantine.restore(&child, &RestoreOptions::default()) {
                    Ok(restored) => Outcome::Back(restored.notes),
                    Err(QuarantineError::NotFound(_)) => {
                        if Path::new(&shortcut.path).exists() {
                            Outcome::InPlace
                        } else {
                            Outcome::Lost
                        }
                    }
                    Err(QuarantineError::TargetExists { .. }) => Outcome::Occupied,
                    Err(other) => Outcome::Failed(other.to_string()),
                }
            }
            entry => match self.system.current(entry) {
                Ok(Some(now)) if now == *entry => Outcome::InPlace,
                Ok(Some(_)) => Outcome::Occupied,
                Ok(None) => match self.system.create(entry) {
                    Ok(mut notes) => {
                        match self.system.current(entry) {
                            Ok(Some(now)) if now == *entry => {}
                            Ok(Some(_)) => notes
                                .push("it is back, but not in every detail as it was".to_owned()),
                            Ok(None) => {
                                return Outcome::Failed(
                                    "the system took it and does not show it".to_owned(),
                                );
                            }
                            Err(failure) => notes.push(format!(
                                "it could not be read back to compare, because {failure}"
                            )),
                        }
                        Outcome::Back(notes)
                    }
                    Err(failure) => Outcome::Failed(failure.reason),
                },
                Err(failure) => Outcome::Failed(failure.reason),
            },
        }
    }

    /// The record that is kept for entry `id`, if there is one.
    ///
    /// # Errors
    ///
    /// Fails if the record cannot be read, or is not one.
    pub fn record(&self, id: &str) -> Result<Option<Record>, AutostartError> {
        let Some(bytes) = self.quarantine.attached(id, KIND)? else {
            return Ok(None);
        };
        Record::from_bytes(&bytes)
            .map(Some)
            .map_err(|problem| AutostartError::BadRecord {
                id: id.to_owned(),
                problem,
            })
    }

    /// Every record the quarantine holds, with whether the file it
    /// belongs to is still in the quarantine. A record whose file is back
    /// holds what could not be put back with it.
    ///
    /// # Errors
    ///
    /// Fails if the quarantine cannot be read. A record that cannot be
    /// read is left out.
    pub fn records(&self) -> Result<Vec<(Record, bool)>, AutostartError> {
        let entries = self.quarantine.list()?.entries;
        let mut records = Vec::new();
        for id in self.quarantine.attached_ids(KIND)? {
            if let Ok(Some(record)) = self.record(&id) {
                let in_quarantine = entries.iter().any(|entry| entry.info.id == id);
                records.push((record, in_quarantine));
            }
        }
        Ok(records)
    }

    /// Lets go of what is kept for entry `id` beyond the file: the
    /// shortcuts that went into the quarantine with it are deleted, and
    /// the record is removed. For when the file's entry is deleted, or
    /// when what could not be put back is given up.
    ///
    /// # Errors
    ///
    /// Fails if the record cannot be read or removed.
    pub fn forget(&self, id: &str) -> Result<(), AutostartError> {
        if let Some(record) = self.record(id)? {
            for item in &record.items {
                if let Some(child) = &item.quarantined_as {
                    match self.quarantine.delete(child) {
                        Ok(_) | Err(QuarantineError::NotFound(_)) => {}
                        Err(other) => return Err(other.into()),
                    }
                }
            }
        }
        self.quarantine.detach(id, KIND)?;
        Ok(())
    }

    fn keep(&self, record: &Record) -> Result<(), AutostartError> {
        self.quarantine
            .attach(&record.entry, KIND, &record.to_bytes())?;
        Ok(())
    }

    /// The entry a shortcut file has in the quarantine, if it went there
    /// together with entry `parent`: found by where it lay and by the
    /// note it was given.
    fn shortcut_in_quarantine(&self, shortcut: &Shortcut, parent: &str) -> Option<String> {
        let marker = shortcut_marker(parent);
        self.quarantine
            .list()
            .ok()?
            .entries
            .into_iter()
            .rev()
            .find(|entry| {
                entry
                    .info
                    .original_path
                    .eq_ignore_ascii_case(&shortcut.path)
                    && entry
                        .info
                        .reason
                        .note
                        .as_deref()
                        .is_some_and(|note| note.ends_with(&marker))
            })
            .map(|entry| entry.info.id)
    }
}

fn shortcut_marker(parent: &str) -> String {
    format!("as entry {parent}")
}

fn shortcut_note(file: &str, parent: &str) -> String {
    format!(
        "a shortcut that started {file}, which is in the quarantine {}",
        shortcut_marker(parent)
    )
}

/// Why an entry could not be put back once it is removed, if that is so.
fn cannot_be_put_back(entry: &Entry) -> Option<String> {
    match entry {
        Entry::Task(Task { xml, .. }) => match task::read(xml) {
            Ok(definition) if definition.logon.needs_password() => Some(
                "it runs with a stored password, which nobody could give back to it".to_owned(),
            ),
            Ok(_) => None,
            Err(problem) => Some(problem),
        },
        Entry::Service(service) if needs_password(service) => Some(format!(
            "it runs as {} with a stored password, which nobody could give back to it",
            service.account
        )),
        _ => None,
    }
}

/// Whether a service runs as an account whose password the service
/// manager keeps. The system's own accounts have none, and neither have
/// the accounts Windows makes up for single services.
fn needs_password(service: &Service) -> bool {
    const WITHOUT_PASSWORD: [&str; 6] = [
        "LocalSystem",
        r".\LocalSystem",
        r"NT AUTHORITY\SYSTEM",
        r"NT AUTHORITY\LocalService",
        r"NT AUTHORITY\NetworkService",
        r"NT AUTHORITY\LOCAL SERVICE",
    ];
    let account = service.account.as_str();
    !(account.is_empty()
        || service.is_driver()
        || WITHOUT_PASSWORD
            .iter()
            .any(|known| known.eq_ignore_ascii_case(account))
        || account.eq_ignore_ascii_case(r"NT AUTHORITY\NETWORK SERVICE")
        || account
            .get(..11)
            .is_some_and(|start| start.eq_ignore_ascii_case(r"NT SERVICE\")))
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|since| u64::try_from(since.as_millis()).ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::RegKey;

    fn service(account: &str, service_type: u32) -> Service {
        Service {
            name: "svc".to_owned(),
            display_name: "svc".to_owned(),
            service_type,
            start_type: 2,
            error_control: 1,
            image_path: r"C:\x\svc.exe".to_owned(),
            load_order_group: String::new(),
            dependencies: Vec::new(),
            account: account.to_owned(),
            security: None,
            key: RegKey::default(),
        }
    }

    #[test]
    fn only_an_account_with_a_stored_password_stands_in_the_way() {
        for account in [
            "LocalSystem",
            "localsystem",
            r"NT AUTHORITY\LocalService",
            r"NT AUTHORITY\NetworkService",
            r"nt authority\network service",
            r"NT SERVICE\svc",
            "",
        ] {
            assert!(
                cannot_be_put_back(&Entry::Service(service(account, 0x10))).is_none(),
                "{account}"
            );
        }
        for account in [r".\someone", r"DOMAIN\svc-account", "someone@example.test"] {
            let obstacle = cannot_be_put_back(&Entry::Service(service(account, 0x10)));
            assert!(
                obstacle.is_some_and(|why| why.contains(account)),
                "{account}"
            );
        }
        // A driver has no account, whatever the field says.
        assert!(cannot_be_put_back(&Entry::Service(service("odd", 0x1))).is_none());
    }

    #[test]
    fn a_task_with_a_stored_password_or_an_unreadable_one_stands_in_the_way() {
        let task = |principal: &str| {
            Entry::Task(Task {
                path: r"\t".to_owned(),
                xml: format!("<Task><Principals>{principal}</Principals></Task>"),
                security: None,
            })
        };
        assert!(
            cannot_be_put_back(&task(
                "<Principal><UserId>u</UserId><LogonType>Password</LogonType></Principal>"
            ))
            .is_some()
        );
        assert!(
            cannot_be_put_back(&task(
                "<Principal><UserId>u</UserId><LogonType>InteractiveToken</LogonType></Principal>"
            ))
            .is_none()
        );
        let unreadable = Entry::Task(Task {
            path: r"\t".to_owned(),
            xml: "not a definition".to_owned(),
            security: None,
        });
        assert!(cannot_be_put_back(&unreadable).is_some());
    }
}

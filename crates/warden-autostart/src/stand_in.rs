//! A stand-in for Windows that holds its autostart entries in memory, for
//! tests here and of the code that uses a [`Remedy`](crate::Remedy).
//!
//! It behaves like the real thing where the logic depends on it: an
//! entry that is removed is gone from the next survey, a place that needs
//! rights refuses, and a shortcut is there for as long as its file is.

use std::cell::RefCell;
use std::path::{Path, PathBuf};

use crate::command::{Variables, commands};
use crate::entry::{Entry, Shortcut};
use crate::system::{Failure, Seen, Survey, System};

#[derive(Debug, Default)]
struct State {
    entries: Vec<Entry>,
    shortcuts: Vec<Shortcut>,
    protected: Vec<Entry>,
    spellings: Vec<(PathBuf, String)>,
    variables: Variables,
    problems: Vec<String>,
    refuses_to_create: Vec<Entry>,
}

/// A machine with no autostart entries but those it is given.
#[derive(Debug, Default)]
pub struct Machine {
    state: RefCell<State>,
}

impl Machine {
    /// A machine with nothing on it.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Puts an entry on the machine. For a shortcut this says what the
    /// file at its path points at; the file itself is the test's to make,
    /// and the shortcut is there for as long as the file is.
    pub fn add(&self, entry: Entry) {
        let mut state = self.state.borrow_mut();
        match entry {
            Entry::Shortcut(shortcut) => state.shortcuts.push(shortcut),
            other => state.entries.push(other),
        }
    }

    /// Makes the place of `entry` one that only somebody with more rights
    /// may change.
    pub fn protect(&self, entry: &Entry) {
        self.state.borrow_mut().protected.push(entry.clone());
    }

    /// From now on the rights are there for every place.
    pub fn grant_rights(&self) {
        self.state.borrow_mut().protected.clear();
    }

    /// Makes the machine refuse to create an entry at the place of
    /// `entry`, as Windows does while it has not finished removing a
    /// service.
    pub fn refuse_to_create(&self, entry: &Entry) {
        self.state
            .borrow_mut()
            .refuses_to_create
            .push(entry.clone());
    }

    /// Lets the machine create everything again.
    pub fn allow_to_create(&self) {
        self.state.borrow_mut().refuses_to_create.clear();
    }

    /// Says that the machine also writes the path of `file` as
    /// `spelling`.
    pub fn spell(&self, file: &Path, spelling: &str) {
        self.state
            .borrow_mut()
            .spellings
            .push((file.to_path_buf(), spelling.to_owned()));
    }

    /// The variables the machine fills in.
    pub fn set_variables(&self, variables: Variables) {
        self.state.borrow_mut().variables = variables;
    }

    /// Makes every survey report that something could not be looked at.
    pub fn report_problem(&self, problem: &str) {
        self.state.borrow_mut().problems.push(problem.to_owned());
    }

    /// What the machine has now, shortcuts whose file is gone left out.
    #[must_use]
    pub fn entries(&self) -> Vec<Entry> {
        let state = self.state.borrow();
        state
            .entries
            .iter()
            .cloned()
            .chain(
                state
                    .shortcuts
                    .iter()
                    .filter(|shortcut| Path::new(&shortcut.path).exists())
                    .cloned()
                    .map(Entry::Shortcut),
            )
            .collect()
    }

    fn check_rights(&self, entry: &Entry) -> Result<(), Failure> {
        if self
            .state
            .borrow()
            .protected
            .iter()
            .any(|protected| protected.same_place(entry))
        {
            Err(Failure::denied(
                "it belongs to the machine, and this is not an administrator's session",
            ))
        } else {
            Ok(())
        }
    }
}

impl System for Machine {
    fn survey(&self) -> Survey {
        let variables = self.state.borrow().variables.clone();
        Survey {
            seen: self
                .entries()
                .into_iter()
                .map(|entry| Seen {
                    lines: commands(&entry, &variables),
                    entry,
                })
                .collect(),
            problems: self.state.borrow().problems.clone(),
        }
    }

    fn spellings(&self, file: &Path) -> Vec<String> {
        self.state
            .borrow()
            .spellings
            .iter()
            .filter(|(known, _)| known == file)
            .map(|(_, spelling)| spelling.clone())
            .collect()
    }

    fn current(&self, entry: &Entry) -> Result<Option<Entry>, Failure> {
        Ok(self
            .entries()
            .into_iter()
            .find(|known| known.same_place(entry)))
    }

    fn remove(&self, entry: &Entry) -> Result<(), Failure> {
        if matches!(entry, Entry::Shortcut(_)) {
            return Err(Failure::new(
                "a shortcut is a file, and files go to the quarantine",
            ));
        }
        if self.current(entry)?.is_none() {
            return Ok(());
        }
        self.check_rights(entry)?;
        self.state
            .borrow_mut()
            .entries
            .retain(|known| !known.same_place(entry));
        Ok(())
    }

    fn create(&self, entry: &Entry) -> Result<Vec<String>, Failure> {
        if matches!(entry, Entry::Shortcut(_)) {
            return Err(Failure::new(
                "a shortcut is a file, and files come from the quarantine",
            ));
        }
        if self.current(entry)?.is_some() {
            return Err(Failure::new("there is one at its place already"));
        }
        self.check_rights(entry)?;
        if self
            .state
            .borrow()
            .refuses_to_create
            .iter()
            .any(|refused| refused.same_place(entry))
        {
            return Err(Failure::new(
                "the system has not finished removing the old one",
            ));
        }
        self.state.borrow_mut().entries.push(entry.clone());
        Ok(Vec::new())
    }
}

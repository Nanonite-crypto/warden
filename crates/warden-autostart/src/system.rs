//! What Warden asks of the system about autostart entries.
//!
//! Finding, removing and putting back are written against the [`System`]
//! trait, which Windows answers in one module and a stand-in answers in
//! tests. The logic that decides what to remove and in which order, and
//! what to do when it is cut off, is therefore tried on every system the
//! tests run on, and only the calls into Windows are left to Windows.

use std::fmt;
use std::path::Path;

use crate::entry::Entry;
use crate::starts::{Spellings, starts};

/// An entry as the system has it, with the command lines it stands for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seen {
    /// The entry.
    pub entry: Entry,
    /// Its command lines, as written and with variables filled in.
    pub lines: Vec<String>,
}

/// Everything the system has that Warden looks at, as far as the process
/// was allowed to see it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Survey {
    /// The entries.
    pub seen: Vec<Seen>,
    /// What could not be looked at, one sentence each. An entry that
    /// starts a file can be among what is missing here.
    pub problems: Vec<String>,
}

/// A driver that Windows loads while it starts, by its name and the
/// command lines that name its file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootDriver {
    /// The name the service manager knows the driver by.
    pub name: String,
    /// Its command lines, as written and with variables filled in.
    pub lines: Vec<String>,
}

impl BootDriver {
    /// Whether the driver's file is the one with these spellings.
    #[must_use]
    pub fn is_file(&self, file: &Spellings) -> bool {
        starts(&self.lines, file)
    }
}

impl Survey {
    /// The drivers among what was seen that Windows loads while it
    /// starts. Taking the file of one away can leave a machine that does
    /// not start, and then nothing is left to put the file back with.
    ///
    /// A driver whose key names no file is not among what a survey sees:
    /// Windows then loads the file of the driver's name from its drivers
    /// folder. Drivers that come with Windows can be like that.
    #[must_use]
    pub fn boot_drivers(&self) -> Vec<BootDriver> {
        self.seen
            .iter()
            .filter_map(|seen| match &seen.entry {
                Entry::Service(service) if service.is_loaded_at_boot() => Some(BootDriver {
                    name: service.name.clone(),
                    lines: seen.lines.clone(),
                }),
                _ => None,
            })
            .collect()
    }
}

/// Why the system did not do what it was asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    /// What went wrong, as a clause that can follow "because".
    pub reason: String,
    /// Whether it would work with more rights: the entry belongs to the
    /// machine or to somebody else, and the process is not an
    /// administrator's.
    pub needs_rights: bool,
}

impl Failure {
    /// A failure that more rights would not help with.
    #[must_use]
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            needs_rights: false,
        }
    }

    /// A failure for want of rights.
    #[must_use]
    pub fn denied(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            needs_rights: true,
        }
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.reason)
    }
}

/// The system's side of autostart entries.
///
/// Shortcuts are the exception among the four kinds: a shortcut is a
/// file, so it is taken away and put back by the quarantine, and
/// [`remove`](Self::remove) and [`create`](Self::create) are never asked
/// to do it.
pub trait System: fmt::Debug {
    /// Looks at every place and reports what is there.
    fn survey(&self) -> Survey;

    /// The other ways the system writes the path of a file that exists,
    /// such as with short names. Asked while the file is still there.
    fn spellings(&self, file: &Path) -> Vec<String>;

    /// The entry that is at the place of `entry` now, if there is one.
    ///
    /// # Errors
    ///
    /// Fails if the place cannot be looked at.
    fn current(&self, entry: &Entry) -> Result<Option<Entry>, Failure>;

    /// Removes the entry at the place of `entry`. That there is none is
    /// not a failure.
    ///
    /// # Errors
    ///
    /// Fails if the entry is there and cannot be removed.
    fn remove(&self, entry: &Entry) -> Result<(), Failure>;

    /// Creates `entry` as it is written down, at a place where there is
    /// none. Returns what could not be made the way it was, one sentence
    /// each.
    ///
    /// # Errors
    ///
    /// Fails if the entry cannot be created. Nothing is replaced: an
    /// entry at that place is a failure.
    fn create(&self, entry: &Entry) -> Result<Vec<String>, Failure>;
}

/// A system without the autostart entries Warden looks at: every system
/// that is not Windows. There is nothing to find on it, and nothing can
/// be put on it.
#[derive(Debug, Clone, Copy, Default)]
pub struct Nowhere;

impl System for Nowhere {
    fn survey(&self) -> Survey {
        Survey::default()
    }

    fn spellings(&self, _: &Path) -> Vec<String> {
        Vec::new()
    }

    fn current(&self, _: &Entry) -> Result<Option<Entry>, Failure> {
        Ok(None)
    }

    fn remove(&self, _: &Entry) -> Result<(), Failure> {
        Ok(())
    }

    fn create(&self, _: &Entry) -> Result<Vec<String>, Failure> {
        Err(Failure::new(
            "entries like it exist on Windows only, and this is another system",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::{Variables, commands};
    use crate::entry::{RegKey, Service};

    /// A service or a driver as a survey sees it on a machine whose
    /// Windows is in `C:\Windows`.
    fn seen(name: &str, service_type: u32, start_type: u32, image_path: &str) -> Seen {
        let entry = Entry::Service(Service {
            name: name.to_owned(),
            display_name: String::new(),
            service_type,
            start_type,
            error_control: 1,
            image_path: image_path.to_owned(),
            load_order_group: String::new(),
            dependencies: Vec::new(),
            account: String::new(),
            security: None,
            key: RegKey::default(),
        });
        let variables = Variables::new([("SystemRoot".to_owned(), r"C:\Windows".to_owned())]);
        let lines = commands(&entry, &variables);
        Seen { entry, lines }
    }

    fn file(path: &str) -> Spellings {
        Spellings::new([path.to_owned()])
    }

    #[test]
    fn the_boot_drivers_of_a_survey_are_its_drivers_with_a_start_at_boot() {
        let survey = Survey {
            seen: vec![
                seen("disk", 0x1, 0, r"System32\drivers\disk.sys"),
                seen("filter", 0x2, 0, r"\SystemRoot\System32\drivers\filter.sys"),
                seen("vendor", 0x1, 0, r"\??\C:\Program Files\Vendor\vendor.sys"),
                // A driver that the system loads later, one that is loaded
                // on demand, and a program that starts with Windows.
                seen("later", 0x1, 1, r"System32\drivers\later.sys"),
                seen("demand", 0x1, 3, r"System32\drivers\demand.sys"),
                seen("program", 0x10, 2, r"C:\Program Files\Vendor\program.exe"),
            ],
            problems: Vec::new(),
        };
        let names: Vec<String> = survey
            .boot_drivers()
            .into_iter()
            .map(|driver| driver.name)
            .collect();
        assert_eq!(names, ["disk", "filter", "vendor"]);
        assert!(Survey::default().boot_drivers().is_empty());
    }

    #[test]
    fn a_boot_driver_is_known_by_its_file_however_its_key_writes_the_path() {
        let survey = Survey {
            seen: vec![
                seen("disk", 0x1, 0, r"System32\drivers\disk.sys"),
                seen("filter", 0x2, 0, r"\SystemRoot\System32\drivers\filter.sys"),
                seen("vendor", 0x1, 0, r"\??\C:\Program Files\Vendor\vendor.sys"),
            ],
            problems: Vec::new(),
        };
        let drivers = survey.boot_drivers();
        let driver_of = |path: &str| -> Option<&str> {
            drivers
                .iter()
                .find(|driver| driver.is_file(&file(path)))
                .map(|driver| driver.name.as_str())
        };
        // From the Windows folder on, from the kernel's name for that
        // folder, and by the kernel's way of writing a drive.
        assert_eq!(
            driver_of(r"C:\Windows\System32\drivers\disk.sys"),
            Some("disk")
        );
        assert_eq!(
            driver_of(r"C:\Windows\System32\drivers\filter.sys"),
            Some("filter")
        );
        assert_eq!(
            driver_of(r"C:\Program Files\Vendor\vendor.sys"),
            Some("vendor")
        );
        // Upper and lower case make no difference, as on Windows.
        assert_eq!(
            driver_of(r"c:\windows\SYSTEM32\DRIVERS\DISK.SYS"),
            Some("disk")
        );
        // Another file, a file that only begins the same way, and the
        // same name in another folder.
        assert_eq!(driver_of(r"C:\Windows\System32\drivers\other.sys"), None);
        assert_eq!(driver_of(r"C:\Windows\System32\drivers\disk.sys.bak"), None);
        assert_eq!(driver_of(r"D:\Windows\System32\drivers\disk.sys"), None);
    }
}

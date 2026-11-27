//! What makes Windows start a file again, and what Warden does about it
//! when the file goes into the quarantine.
//!
//! A program that wants to stay arranges to be started: with a value
//! under a `Run` key, a scheduled task, a service, a shortcut in the
//! Startup folder. Taking the file away leaves those entries pointing at
//! nothing. Windows then complains at every start, or something else is
//! put at that path one day and gets started. And putting the file back
//! without what started it has not undone the quarantine.
//!
//! This crate finds the entries that start a file, removes them once the
//! file is in the quarantine, and puts them back when the file is
//! restored, each as it was.
//!
//! # What it looks at
//!
//! Four places ([`Entry`]):
//!
//! - values under the `Run` and `RunOnce` keys, of the machine and of the
//!   users whose settings are loaded;
//! - scheduled tasks;
//! - services and drivers, by their program and by the library that a
//!   shared service host loads for them;
//! - shortcuts in the two Startup folders.
//!
//! Windows has many more places that start programs. These four are the
//! ones every textbook names, and the documentation lists what is left
//! out.
//!
//! # What "starts the file" means
//!
//! The file's full path stands in the entry's command line, as the
//! program or as something passed to the program, once the variables in
//! it are filled in ([`stands_in`]). `rundll32 C:\x\a.dll,Start` starts
//! `a.dll`. A bare name that Windows would look up along its search path
//! is not followed.
//!
//! # Nothing is destroyed
//!
//! Before an entry is touched, everything it is goes into a record that
//! the quarantine keeps with the file ([`Record`]): a registry value with
//! its type and its bytes, a task as the definition the Task Scheduler
//! gives out, a service as the service manager describes it together with
//! its registry key. A shortcut is a file and goes into the quarantine as
//! one. An entry that could not be put back, such as a task that runs
//! with a stored password, is not removed.
//!
//! Putting back looks before it writes ([`Remedy::put_back`]). An entry
//! that is in its place is left. One whose place something else has taken
//! is not replaced. What cannot be put back stays in the record, and it
//! can be tried again.
//!
//! # How it is built
//!
//! The logic is written against the [`System`] trait and tried against a
//! stand-in on every system the tests run on. The calls into Windows are
//! in one module, which is the only one with `unsafe` code.

mod command;
mod entry;
mod hex;
mod record;
mod remedy;
mod starts;
mod system;
pub mod task;

#[cfg(windows)]
mod windows;

#[doc(hidden)]
pub mod stand_in;

pub use command::{
    REG_EXPAND_SZ, REG_SZ, Variables, commands, expand, reg_string, reg_string_bytes,
};
pub use entry::{Entry, Hive, RegKey, RegValue, RunValue, Service, Shortcut, SubKey, Task, View};
pub use record::{Item, KIND, Record, SCHEMA, State};
pub use remedy::{
    AutostartError, Found, Left, Outcome, PutBack, Remedy, Removal, Step, find, find_in,
};
pub use starts::{Spellings, stands_in, starts};
pub use system::{BootDriver, Failure, Nowhere, Seen, Survey, System};

/// Whether this is a system with the autostart entries Warden looks at.
/// Windows is; nothing else.
pub const ON_THIS_SYSTEM: bool = cfg!(windows);

/// The other ways this system writes the path of a file that exists, such
/// as with short names: what [`System::spellings`] gives for the system
/// the program runs on. It needs nothing that belongs to one thread, so
/// it can be asked from anywhere. On a system that is not Windows a path
/// is written one way, and the answer is empty.
#[must_use]
pub fn spellings_here(file: &std::path::Path) -> Vec<String> {
    #[cfg(windows)]
    {
        windows::spellings(file)
    }
    #[cfg(not(windows))]
    {
        let _ = file;
        Vec::new()
    }
}

/// The system this program runs on. On Windows that is Windows; anywhere
/// else it is [`Nowhere`], on which there is nothing to find.
///
/// What comes back talks to the Task Scheduler and the shell from the
/// thread that asked, and stays on it.
#[must_use]
pub fn this_system() -> Box<dyn System> {
    #[cfg(windows)]
    {
        Box::new(windows::Windows::new())
    }
    #[cfg(not(windows))]
    {
        Box::new(Nowhere)
    }
}

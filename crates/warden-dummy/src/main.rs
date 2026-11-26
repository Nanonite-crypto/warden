//! A harmless stand-in for a program that somebody set to start with
//! Windows.
//!
//! When it is started it adds one line to a file next to itself: when it
//! was started, as which process, by which user and with which arguments.
//! Then it ends. It does nothing else. It reads no input, opens no
//! connection, starts no program and touches no file but that one.
//!
//! Warden's removal of autostart entries is tried with it on a real
//! machine. The test registers this program in the places Windows starts
//! programs from, each entry with an argument of its own, and reads the
//! file afterwards: a line for each start shows which entries Windows
//! followed. Once Warden has quarantined the program and removed the
//! entries, a restart of Windows adds no line. After a restore it adds
//! them again.
//!
//! It is not part of Warden and is never installed with it.

// No window: Windows starts it at logon, and a console that flashes up for
// every entry would be in the way of whoever sits there.
#![cfg_attr(windows, windows_subsystem = "windows")]

use std::fs::OpenOptions;
use std::io::Write;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

/// The name of the file the starts are written to, next to the program.
const LOG: &str = "warden-dummy-starts.log";

fn main() -> ExitCode {
    match note_the_start() {
        Ok(()) => ExitCode::SUCCESS,
        // Nowhere to say why: there is no window, and nobody waits.
        Err(_) => ExitCode::FAILURE,
    }
}

fn note_the_start() -> std::io::Result<()> {
    let log = std::env::current_exe()?.with_file_name(LOG);
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    let user = std::env::var("USERNAME").unwrap_or_default();
    let arguments: Vec<String> = std::env::args_os()
        .skip(1)
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect();
    // One write for the whole line: several of these can start at the same
    // moment at logon, and a line must not end up inside another.
    let line = format!(
        "{seconds} pid={} user={user} args={}\n",
        std::process::id(),
        arguments.join(" ")
    );
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(log)?
        .write_all(line.as_bytes())
}

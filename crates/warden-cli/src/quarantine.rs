//! `warden quarantine`: move files out of harm's way, and back.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, anyhow};
use clap::{Args, Subcommand};
use serde::Serialize;
use warden_quarantine::{
    Damaged, Entry, EntryInfo, Quarantine, Reason, RestoreOptions, Stamp, default_dir,
};

use crate::EXIT_ERROR;
use crate::render::{group_digits, human_timestamp, shown, shown_path};

/// Where the quarantine is.
#[derive(Debug, Args)]
pub struct Place {
    /// The quarantine folder (default: a folder in your own user account)
    #[arg(long = "dir", value_name = "FOLDER", env = "WARDEN_QUARANTINE")]
    dir: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
pub enum QuarantineCommand {
    /// Move files into the quarantine
    ///
    /// The file disappears from its place. Its content is kept in a form
    /// that cannot be run and that other scanners find nothing in, together
    /// with its timestamps and permissions, so that `restore` can put it
    /// back exactly as it was.
    Add {
        /// Files to quarantine
        #[arg(required = true, value_name = "FILE")]
        files: Vec<PathBuf>,

        /// Why, in your own words; kept with the entry
        #[arg(long, value_name = "TEXT")]
        reason: Option<String>,

        #[command(flatten)]
        place: Place,
    },

    /// List what is in the quarantine
    List {
        /// Print the entries' records as JSON
        #[arg(long)]
        json: bool,

        #[command(flatten)]
        place: Place,
    },

    /// Show everything that is recorded about one entry
    Info {
        /// The entry's identifier, or enough of its start to tell it apart
        #[arg(value_name = "ID")]
        id: String,

        /// Print the record as JSON
        #[arg(long)]
        json: bool,

        #[command(flatten)]
        place: Place,
    },

    /// Put a quarantined file back
    ///
    /// The file returns to where it was, with the content, the timestamps
    /// and the permissions it had, and its entry is removed. The content is
    /// checked against the SHA-256 that was recorded when it was
    /// quarantined; a file that does not pass is not restored.
    Restore {
        /// The entry's identifier, or enough of its start to tell it apart
        #[arg(value_name = "ID")]
        id: String,

        /// Put the file here instead of where it was
        #[arg(long, value_name = "PATH")]
        to: Option<PathBuf>,

        /// Replace a file that is already there
        #[arg(long)]
        overwrite: bool,

        #[command(flatten)]
        place: Place,
    },

    /// Remove entries for good
    ///
    /// The files they hold cannot be brought back afterwards.
    Delete {
        /// Identifiers of the entries, or enough of their start
        #[arg(required = true, value_name = "ID")]
        ids: Vec<String>,

        #[command(flatten)]
        place: Place,
    },
}

/// Opens the quarantine, and says what it found left over from a run that
/// did not finish.
fn open(place: &Place) -> anyhow::Result<Quarantine> {
    let dir = match &place.dir {
        Some(dir) => dir.clone(),
        None => default_dir().ok_or_else(|| {
            anyhow!("cannot tell where your user account keeps its data; say where the quarantine is with --dir")
        })?,
    };
    let (quarantine, recovered) = Quarantine::open(dir)?;
    for entry in &recovered {
        errln!("note: {}.", shown(&entry.to_string()));
    }
    Ok(quarantine)
}

fn when(unix_ms: u64) -> String {
    human_timestamp(unix_ms / 1000)
}

fn stamp(stamp: Option<Stamp>) -> String {
    match stamp {
        Some(stamp) if stamp.secs >= 0 => {
            let whole = human_timestamp(stamp.secs.unsigned_abs());
            // Seconds are what a person reads; the record keeps the rest.
            if stamp.nanos == 0 {
                whole
            } else {
                format!("{whole} and {} ns", group_digits(u64::from(stamp.nanos)))
            }
        }
        Some(stamp) => format!("{} s before 1970", group_digits(stamp.secs.unsigned_abs())),
        None => "not recorded".to_owned(),
    }
}

/// The attribute bits of a Windows file, by name where they have one that
/// people know, and in full as a number.
fn attributes(bits: u32) -> String {
    const NAMED: [(u32, &str); 5] = [
        (0x0001, "read-only"),
        (0x0002, "hidden"),
        (0x0004, "system"),
        (0x0020, "archive"),
        (0x2000, "not indexed"),
    ];
    let names: Vec<&str> = NAMED
        .iter()
        .filter(|(bit, _)| bits & bit != 0)
        .map(|(_, name)| *name)
        .collect();
    if names.is_empty() {
        format!("{bits:#06x}")
    } else {
        format!("{} ({bits:#06x})", names.join(", "))
    }
}

fn add(files: &[PathBuf], reason: Option<&String>, place: &Place) -> anyhow::Result<ExitCode> {
    let quarantine = open(place)?;
    let mut failed = false;
    for file in files {
        let reason = reason.map_or_else(Reason::default, Reason::note);
        match quarantine.add(file, reason) {
            Ok(entry) => {
                outln!("Quarantined  {}", shown(&entry.info.original_path))?;
                outln!("  entry      {}", entry.info.id)?;
                outln!(
                    "  sha256     {} ({} bytes)",
                    entry.info.sha256,
                    group_digits(entry.info.size)
                )?;
            }
            Err(error) => {
                failed = true;
                errln!("error: {}", shown(&error.to_string()));
            }
        }
    }
    if failed {
        return Ok(ExitCode::from(EXIT_ERROR));
    }
    outln!(
        "`warden quarantine restore <entry>` puts a file back. The first few characters of the entry are enough."
    )?;
    Ok(ExitCode::SUCCESS)
}

#[derive(Debug, Serialize)]
struct ListedDamaged {
    file: String,
    problem: String,
}

#[derive(Debug, Serialize)]
struct Listed<'a> {
    dir: String,
    entries: Vec<&'a EntryInfo>,
    damaged: Vec<ListedDamaged>,
}

fn damaged_line(damaged: &Damaged) -> String {
    format!("{}: {}", shown_path(&damaged.file), shown(&damaged.problem))
}

fn list(json: bool, place: &Place) -> anyhow::Result<ExitCode> {
    let quarantine = open(place)?;
    let listing = quarantine.list()?;
    if json {
        let listed = Listed {
            dir: quarantine.dir().to_string_lossy().into_owned(),
            entries: listing.entries.iter().map(|entry| &entry.info).collect(),
            damaged: listing
                .damaged
                .iter()
                .map(|damaged| ListedDamaged {
                    file: damaged.file.to_string_lossy().into_owned(),
                    problem: damaged.problem.clone(),
                })
                .collect(),
        };
        outln!(
            "{}",
            serde_json::to_string_pretty(&listed).context("cannot write the list as JSON")?
        )?;
        return Ok(ExitCode::SUCCESS);
    }

    outln!("Quarantine  {}", shown_path(quarantine.dir()))?;
    match listing.entries.len() {
        0 => outln!("Nothing is in quarantine.")?,
        1 => outln!("1 entry")?,
        count => outln!("{} entries", group_digits(count as u64))?,
    }
    for Entry { info, .. } in &listing.entries {
        outln!()?;
        outln!(
            "  {}  {}  {} bytes",
            info.id,
            when(info.quarantined_unix_ms),
            group_digits(info.size)
        )?;
        outln!("    {}", shown(&info.original_path))?;
        if !info.reason.detections.is_empty() {
            outln!(
                "    detected as {}",
                shown(&info.reason.detections.join(", "))
            )?;
        }
        if let Some(note) = &info.reason.note {
            outln!("    reason: {}", shown(note))?;
        }
    }
    if !listing.damaged.is_empty() {
        outln!()?;
        outln!(
            "{} that cannot be read:",
            if listing.damaged.len() == 1 {
                "1 entry file".to_owned()
            } else {
                format!("{} entry files", listing.damaged.len())
            }
        )?;
        for damaged in &listing.damaged {
            outln!("  {}", damaged_line(damaged))?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn info(id: &str, json: bool, place: &Place) -> anyhow::Result<ExitCode> {
    let quarantine = open(place)?;
    let Entry { info, file } = quarantine.find(id)?;
    if json {
        outln!(
            "{}",
            serde_json::to_string_pretty(&info).context("cannot write the record as JSON")?
        )?;
        return Ok(ExitCode::SUCCESS);
    }
    outln!("Entry        {}", info.id)?;
    outln!("Quarantined  {}", when(info.quarantined_unix_ms))?;
    outln!("Was at       {}", shown(&info.original_path))?;
    outln!("Size         {} bytes", group_digits(info.size))?;
    outln!("SHA-256      {}", info.sha256)?;
    outln!("Modified     {}", stamp(info.times.modified))?;
    outln!("Last read    {}", stamp(info.times.accessed))?;
    outln!("Created      {}", stamp(info.times.created))?;
    if let Some(unix) = info.unix {
        outln!(
            "Permissions  {:04o}, user {}, group {}",
            unix.mode,
            unix.uid,
            unix.gid
        )?;
    }
    if let Some(windows) = &info.windows {
        outln!("Attributes   {}", attributes(windows.attributes))?;
        match &windows.security_descriptor {
            Some(descriptor) => outln!(
                "Access       owner, group and access-control list recorded ({} bytes)",
                descriptor.len() / 2
            )?,
            None => outln!("Access       not recorded: it could not be read")?,
        }
        outln!(
            "Internet     {}",
            if windows.zone_identifier.is_some() {
                "the file carried the mark of a download, and gets it back"
            } else {
                "the file carried no mark of a download"
            }
        )?;
    }
    if !info.reason.detections.is_empty() {
        outln!("Detected as  {}", shown(&info.reason.detections.join(", ")))?;
    }
    if let Some(note) = &info.reason.note {
        outln!("Reason       {}", shown(note))?;
    }
    outln!("Made by      Warden {}", shown(&info.warden_version))?;
    outln!("Kept in      {}", shown_path(&file))?;
    Ok(ExitCode::SUCCESS)
}

fn restore(
    id: &str,
    to: Option<&Path>,
    overwrite: bool,
    place: &Place,
) -> anyhow::Result<ExitCode> {
    let quarantine = open(place)?;
    let restored = quarantine.restore(
        id,
        &RestoreOptions {
            to: to.map(Path::to_path_buf),
            overwrite,
        },
    )?;
    outln!("Restored  {}", shown_path(&restored.path))?;
    outln!(
        "  sha256  {} ({} bytes), as recorded",
        restored.info.sha256,
        group_digits(restored.info.size)
    )?;
    if restored.notes.is_empty() {
        outln!("  Its timestamps and permissions are what they were.")?;
        if !cfg!(windows) {
            // Only Windows lets a program set the time a file was made.
            outln!(
                "  The time it was made is the exception: this system gives a file that time itself, so it is the time of the restore."
            )?;
        }
    } else {
        outln!("  Not everything is what it was:")?;
        for note in &restored.notes {
            outln!("  - {}", shown(note))?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn delete(ids: &[String], place: &Place) -> anyhow::Result<ExitCode> {
    let quarantine = open(place)?;
    let mut failed = false;
    for id in ids {
        match quarantine.delete(id) {
            Ok(Some(info)) => outln!("Deleted  {}  {}", info.id, shown(&info.original_path))?,
            Ok(None) => outln!("Deleted  {}  (its record could not be read)", shown(id))?,
            Err(error) => {
                failed = true;
                errln!("error: {}", shown(&error.to_string()));
            }
        }
    }
    if failed {
        return Ok(ExitCode::from(EXIT_ERROR));
    }
    outln!("What was deleted cannot be brought back.")?;
    Ok(ExitCode::SUCCESS)
}

pub fn run(command: &QuarantineCommand) -> anyhow::Result<ExitCode> {
    match command {
        QuarantineCommand::Add {
            files,
            reason,
            place,
        } => add(files, reason.as_ref(), place),
        QuarantineCommand::List { json, place } => list(*json, place),
        QuarantineCommand::Info { id, json, place } => info(id, *json, place),
        QuarantineCommand::Restore {
            id,
            to,
            overwrite,
            place,
        } => restore(id, to.as_deref(), *overwrite, place),
        QuarantineCommand::Delete { ids, place } => delete(ids, place),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attribute_bits_are_named_where_they_have_a_name() {
        assert_eq!(attributes(0x0020), "archive (0x0020)");
        assert_eq!(
            attributes(0x2027),
            "read-only, hidden, system, archive, not indexed (0x2027)"
        );
        // A bit without a name here still shows, in the number.
        assert_eq!(attributes(0x0821), "read-only, archive (0x0821)");
        assert_eq!(attributes(0x0080), "0x0080");
    }

    #[test]
    fn a_timestamp_is_shown_to_the_second_and_says_what_is_left() {
        assert_eq!(stamp(None), "not recorded");
        assert_eq!(
            stamp(Some(Stamp {
                secs: 1_614_834_367,
                nanos: 0
            })),
            "2021-03-04T05:06:07Z"
        );
        assert_eq!(
            stamp(Some(Stamp {
                secs: 1_614_834_367,
                nanos: 123_456_700
            })),
            "2021-03-04T05:06:07Z and 123,456,700 ns"
        );
        assert_eq!(
            stamp(Some(Stamp {
                secs: -86_400,
                nanos: 0
            })),
            "86,400 s before 1970"
        );
    }
}

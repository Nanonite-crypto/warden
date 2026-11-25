//! `warden autostart`: what makes Windows start a program.
//!
//! `find` and `list` only look. What is removed together with a
//! quarantined file, and put back with it, is the business of
//! `warden quarantine`; the printing of it is here, so that both speak
//! of an entry in the same words.

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Context;
use clap::Subcommand;
use serde::Serialize;
use warden_autostart::{
    Entry, ON_THIS_SYSTEM, Outcome, PutBack, Record, Remedy, Removal, Seen, State, find,
    this_system,
};

use crate::quarantine::{Place, open};
use crate::render::{group_digits, shown, shown_path};

#[derive(Debug, Subcommand)]
pub enum AutostartCommand {
    /// Show what starts a file, and change nothing
    ///
    /// Looks through the Run and RunOnce values of the registry, the
    /// scheduled tasks, the services and drivers, and the shortcuts in the
    /// Startup folders, and prints the entries whose command line names
    /// this file by its full path. `warden quarantine add` removes those
    /// entries together with the file, and `restore` puts them back.
    Find {
        /// The file
        #[arg(value_name = "FILE")]
        file: PathBuf,

        /// Print the entries as JSON, whole
        #[arg(long)]
        json: bool,
    },

    /// Show every autostart entry Warden looks at
    List {
        /// Print the entries as JSON
        #[arg(long)]
        json: bool,
    },

    /// Go on removing what starts a quarantined file
    ///
    /// When a file was quarantined without an administrator's rights, the
    /// entries that belong to the machine were left in place and named.
    /// From an administrator's prompt this removes them. It also finishes
    /// a removal that was cut off.
    Remove {
        /// The entry of the file in the quarantine, or enough of its start
        #[arg(value_name = "ID")]
        id: String,

        #[command(flatten)]
        place: Place,
    },
}

const ONLY_ON_WINDOWS: &str = "Warden looks for autostart entries on Windows only. This system starts programs in other ways, which Warden does not look at.";

/// The answer on a system that is not Windows. As JSON it has the shape
/// it has on Windows, with nothing found and the reason among the
/// problems, so that whoever reads it need not know the system.
fn only_on_windows(json: bool) -> anyhow::Result<ExitCode> {
    if json {
        outln!("{}", as_json(&[], &[ONLY_ON_WINDOWS.to_owned()])?)?;
    } else {
        outln!("{ONLY_ON_WINDOWS}")?;
    }
    Ok(ExitCode::SUCCESS)
}

#[derive(Debug, Serialize)]
struct Shown<'a> {
    entries: Vec<ShownEntry<'a>>,
    problems: &'a [String],
}

#[derive(Debug, Serialize)]
struct ShownEntry<'a> {
    entry: &'a Entry,
    lines: &'a [String],
}

fn as_json(seen: &[Seen], problems: &[String]) -> anyhow::Result<String> {
    serde_json::to_string_pretty(&Shown {
        entries: seen
            .iter()
            .map(|seen| ShownEntry {
                entry: &seen.entry,
                lines: &seen.lines,
            })
            .collect(),
        problems,
    })
    .context("cannot write the entries as JSON")
}

fn print_problems(problems: &[String]) -> anyhow::Result<()> {
    if !problems.is_empty() {
        outln!()?;
        outln!("Not everything could be looked at:")?;
        for problem in problems {
            outln!("  - {}", shown(problem))?;
        }
    }
    Ok(())
}

fn print_seen(seen: &Seen) -> anyhow::Result<()> {
    outln!("  {}", shown(&seen.entry.to_string()))?;
    // The last line is the one with the variables filled in.
    if let Some(line) = seen.lines.last() {
        outln!("      {}", shown(line))?;
    }
    Ok(())
}

fn find_command(file: &PathBuf, json: bool) -> anyhow::Result<ExitCode> {
    if !ON_THIS_SYSTEM {
        return only_on_windows(json);
    }
    let path = std::path::absolute(file)
        .with_context(|| format!("cannot tell where {} is", file.display()))?;
    if !path.is_file() {
        anyhow::bail!(
            "{} is not a file that is there; what starts a file can only be found while the file exists",
            path.display()
        );
    }
    let system = this_system();
    let found = find(system.as_ref(), &path);
    if json {
        outln!("{}", as_json(&found.starting, &found.problems)?)?;
        return Ok(ExitCode::SUCCESS);
    }
    match found.starting.len() {
        0 => outln!("Nothing that Warden looks at starts {}.", shown_path(&path))?,
        1 => outln!("{} is started by 1 entry:", shown_path(&path))?,
        count => outln!("{} is started by {count} entries:", shown_path(&path))?,
    }
    for seen in &found.starting {
        print_seen(seen)?;
    }
    print_problems(&found.problems)?;
    if !found.starting.is_empty() {
        outln!()?;
        outln!(
            "Nothing was changed. `warden quarantine add` removes these together with the file, and `warden quarantine restore` puts them back."
        )?;
    }
    Ok(ExitCode::SUCCESS)
}

fn list_command(json: bool) -> anyhow::Result<ExitCode> {
    if !ON_THIS_SYSTEM {
        return only_on_windows(json);
    }
    let system = this_system();
    let survey = system.survey();
    if json {
        outln!("{}", as_json(&survey.seen, &survey.problems)?)?;
        return Ok(ExitCode::SUCCESS);
    }
    outln!(
        "{} entries in the four places Warden looks at",
        group_digits(survey.seen.len() as u64)
    )?;
    for (kind, heading) in [
        ("run value", "Run and RunOnce values"),
        ("task", "Scheduled tasks"),
        ("service", "Services and drivers"),
        ("shortcut", "Shortcuts in the Startup folders"),
    ] {
        let of_kind: Vec<&Seen> = survey
            .seen
            .iter()
            .filter(|seen| seen.entry.kind() == kind)
            .collect();
        outln!()?;
        outln!("{heading}: {}", group_digits(of_kind.len() as u64))?;
        for seen in of_kind {
            print_seen(seen)?;
        }
    }
    print_problems(&survey.problems)?;
    Ok(ExitCode::SUCCESS)
}

fn remove_command(id: &str, place: &Place) -> anyhow::Result<ExitCode> {
    let quarantine = open(place)?;
    let entry = quarantine.find(id)?;
    let system = this_system();
    let remedy = Remedy::new(system.as_ref(), &quarantine);
    if remedy.record(&entry.info.id)?.is_none() {
        outln!(
            "Nothing is left to remove for {}: no entry that starts it was written down.",
            shown(&entry.info.original_path)
        )?;
        return Ok(ExitCode::SUCCESS);
    }
    let removal = remedy.finish_removing(&entry.info.id)?;
    outln!("For {}:", shown(&entry.info.original_path))?;
    print_removal(&removal, &entry.info.id)?;
    Ok(ExitCode::SUCCESS)
}

pub fn run(command: &AutostartCommand) -> anyhow::Result<ExitCode> {
    match command {
        AutostartCommand::Find { file, json } => find_command(file, *json),
        AutostartCommand::List { json } => list_command(*json),
        AutostartCommand::Remove { id, place } => remove_command(id, place),
    }
}

/// Says what became of the entries that started a quarantined file.
pub fn print_removal(removal: &Removal, id: &str) -> anyhow::Result<()> {
    for entry in &removal.removed {
        outln!("  removed    {}", shown(&entry.to_string()))?;
    }
    for left in &removal.left {
        outln!(
            "  left       {}, because {}",
            shown(&left.entry.to_string()),
            shown(&left.why)
        )?;
    }
    if !removal.removed.is_empty() {
        outln!("             what was removed started the file, and a restore puts it back")?;
    }
    if removal.left.iter().any(|left| left.needs_rights) {
        outln!(
            "             `warden autostart remove {id}` from an administrator's prompt removes what was left for want of rights"
        )?;
    }
    Ok(())
}

/// Says what became of the entries of a record when they were put back.
/// `id` is how to name the record when something is still owed.
pub fn print_put_back(back: &PutBack, id: &str) -> anyhow::Result<()> {
    let mut returned = Vec::new();
    let mut owed = Vec::new();
    for (entry, outcome) in &back.entries {
        let place = shown(&entry.to_string());
        match outcome {
            Outcome::Back(notes) if notes.is_empty() => returned.push(place),
            Outcome::Back(notes) => {
                returned.push(format!("{place} ({})", shown(&notes.join("; "))));
            }
            Outcome::InPlace => returned.push(format!("{place} (it was in its place)")),
            Outcome::NeverRemoved(_) => {
                returned.push(format!("{place} (it had never been removed)"));
            }
            Outcome::Lost => owed.push(format!(
                "{place}: it is gone, and it was not in the quarantine"
            )),
            Outcome::Occupied => owed.push(format!(
                "{place}: something else is at its place now, and it was not replaced"
            )),
            Outcome::Failed(why) => owed.push(format!("{place}: {}", shown(why))),
        }
    }
    if !returned.is_empty() {
        outln!("  What started it is back as well:")?;
        for line in &returned {
            outln!("  - {line}")?;
        }
    }
    if !owed.is_empty() {
        outln!("  Not put back:")?;
        for line in &owed {
            outln!("  - {line}")?;
        }
    }
    if back.is_owing() {
        outln!(
            "  `warden quarantine restore {id}` tries those again, and `warden quarantine delete {id}` gives them up."
        )?;
    }
    Ok(())
}

/// One line for each entry of a record, for `warden quarantine info`.
pub fn print_record(record: &Record) -> anyhow::Result<()> {
    for item in &record.items {
        let place = shown(&item.what.to_string());
        match (item.state, &item.note) {
            (State::Left, Some(why)) => outln!("  left in place: {place}, because {}", shown(why))?,
            (State::Left, None) => outln!("  left in place: {place}")?,
            (_, Some(note)) => outln!("  removed: {place} ({})", shown(note))?,
            (_, None) => outln!("  removed: {place}")?,
        }
    }
    Ok(())
}

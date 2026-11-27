//! `warden quarantine`: move files out of harm's way, and back.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, anyhow};
use clap::{Args, Subcommand};
use serde::Serialize;
use warden_autostart::{
    BootDriver, Record, Remedy, Spellings, Survey, find_in, spellings_here, this_system,
};
use warden_quarantine::{
    AddOptions, Damaged, Entry, EntryInfo, Guard, Quarantine, QuarantineError, Reason,
    RestoreOptions, Stamp, Verdict, default_dir,
};
use warden_trust::{Options, Origin, TrustList, Verifier};

use crate::EXIT_ERROR;
use crate::autostart::{print_put_back, print_record, print_removal};
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
    ///
    /// A file that is part of Windows stays where it is: Windows may not
    /// start without it, and then nothing is left to restore it with.
    /// Warden tells such a file by its signature, see `warden trust check`.
    /// A driver that Windows loads while it starts stays as well, whoever
    /// made it. Each of the two has a flag that takes the file all the
    /// same.
    ///
    /// What makes Windows start the file goes with it: values under the
    /// Run keys, scheduled tasks, services, and shortcuts in the Startup
    /// folders that name the file by its full path. Each is written down
    /// whole before it is removed, and `restore` puts it back. See
    /// `warden autostart find`.
    Add {
        /// Files to quarantine
        #[arg(required = true, value_name = "FILE")]
        files: Vec<PathBuf>,

        /// Why, in your own words; kept with the entry
        #[arg(long, value_name = "TEXT")]
        reason: Option<String>,

        /// Quarantine a file even if it is part of Windows, or if it
        /// could not be checked whether it is
        #[arg(long)]
        even_if_signed_by_windows: bool,

        /// Quarantine a file even if Windows loads it as a driver while
        /// it starts
        #[arg(long)]
        even_if_loaded_at_boot: bool,

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
    ///
    /// What started the file and was removed with it is put back as it
    /// was. An entry whose place something else has taken is not
    /// replaced. What could not be put back is kept, and running the
    /// command again with the same identifier tries once more.
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
    /// The files they hold cannot be brought back afterwards, and neither
    /// can what started them and was removed with them.
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
pub fn open(place: &Place) -> anyhow::Result<Quarantine> {
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

/// The flags that take a file past a guard, as they are typed.
const PAST_SYSTEM_FILES: &str = "--even-if-signed-by-windows";
const PAST_BOOT_DRIVERS: &str = "--even-if-loaded-at-boot";

/// Which guards the user has waved a file past.
#[derive(Debug, Clone, Copy, Default)]
struct Past {
    system_files: bool,
    boot_drivers: bool,
}

/// The first guard of this quarantine: a file that is part of the
/// operating system stays where it is.
///
/// Which signature makes a file part of the operating system is not
/// written here. The trust list marks the publisher, and
/// [`Verifier::origin`] finds its signature by any of the three routes.
/// The check asks nothing over the network: whether a certificate was
/// revoked makes no difference to this answer.
#[derive(Debug)]
struct SystemFiles {
    verifier: Verifier,
}

impl SystemFiles {
    fn new() -> anyhow::Result<Self> {
        let list = TrustList::builtin().context("the built-in trust list is broken")?;
        Ok(Self {
            verifier: Verifier::new(list, Options { network: false }),
        })
    }
}

impl Guard for SystemFiles {
    fn look_at(&self, path: &Path) -> Verdict {
        let (examination, origin) = self.verifier.origin(path);
        match origin {
            Origin::OperatingSystem {
                publisher, route, ..
            } => Verdict::Leave {
                why: format!(
                    "it is part of the operating system (signed for {publisher}, found in {})",
                    route.in_words()
                ),
            },
            // Not knowing is no reason to take the file: where Windows
            // cannot be asked, every file of Windows would pass.
            Origin::Unknown { why } => Verdict::Leave {
                why: format!(
                    "it could not be checked whether it is part of the operating system ({why})"
                ),
            },
            // On a system without such signatures there is nothing to
            // guard, and nothing was read.
            Origin::Elsewhere | Origin::Unavailable => Verdict::Take {
                sha256: examination.sha256_bytes(),
            },
        }
    }
}

/// The second guard: a file that Windows loads as a driver while it starts
/// stays where it is, whoever made it.
///
/// The first guard knows the files of Windows by their signature. A driver
/// of another maker that the loader reads in together with the kernel is
/// no such file, and a machine may not start without it all the same: a
/// driver for the disk Windows is on, say. Which files those are is in
/// the registry, and a survey of what starts programs has read it.
#[derive(Debug)]
struct BootDrivers {
    drivers: Vec<BootDriver>,
}

impl BootDrivers {
    fn of(survey: &Survey) -> Self {
        Self {
            drivers: survey.boot_drivers(),
        }
    }

    /// The driver whose file this is, if it is one's. The path is looked
    /// for in every way the system writes it.
    fn driver_of(&self, path: &Path) -> Option<&BootDriver> {
        let mut paths = vec![path.to_string_lossy().into_owned()];
        paths.extend(spellings_here(path));
        let file = Spellings::new(paths);
        self.drivers.iter().find(|driver| driver.is_file(&file))
    }
}

impl Guard for BootDrivers {
    fn look_at(&self, path: &Path) -> Verdict {
        match self.driver_of(path) {
            Some(driver) => Verdict::Leave {
                why: format!(
                    "Windows loads it as the driver {} while it starts",
                    driver.name
                ),
            },
            // Nothing was read, so there is no content to hold the file to.
            None => Verdict::Take { sha256: None },
        }
    }
}

/// A guard that the quarantine asks, and that this program can ask again:
/// for what it would have said about a file that was waved past it, and
/// for which of the guards it was that left a file.
#[derive(Debug)]
struct Shared<T>(Arc<T>);

impl<T: Guard> Guard for Shared<T> {
    fn look_at(&self, path: &Path) -> Verdict {
        self.0.look_at(path)
    }
}

/// Several guards as one. The first that would leave a file decides, and
/// a file is taken if none would.
#[derive(Debug)]
struct Guards(Vec<Box<dyn Guard>>);

impl Guard for Guards {
    fn look_at(&self, path: &Path) -> Verdict {
        let mut content = None;
        for guard in &self.0 {
            match guard.look_at(path) {
                Verdict::Leave { why } => return Verdict::Leave { why },
                // The content one of them read is the content to hold
                // the file to.
                Verdict::Take { sha256 } => content = content.or(sha256),
            }
        }
        Verdict::Take { sha256: content }
    }
}

fn add(
    files: &[PathBuf],
    reason: Option<&String>,
    past: Past,
    place: &Place,
) -> anyhow::Result<ExitCode> {
    let mut quarantine = open(place)?;
    // What starts programs on this machine, looked at once for all files.
    let system = this_system();
    let survey = system.survey();
    // A guard that the user waved a file past is not given to the
    // quarantine. It is still asked here, so that what was taken all the
    // same can be said.
    let system_files = Arc::new(SystemFiles::new()?);
    let boot_drivers = Arc::new(BootDrivers::of(&survey));
    let mut asked: Vec<Box<dyn Guard>> = Vec::new();
    if !past.boot_drivers {
        asked.push(Box::new(Shared(Arc::clone(&boot_drivers))));
    }
    if !past.system_files {
        asked.push(Box::new(Shared(Arc::clone(&system_files))));
    }
    quarantine.set_guard(Box::new(Guards(asked)));
    let options = AddOptions::default();
    let remedy = Remedy::new(system.as_ref(), &quarantine);
    let leaves = |guard: &dyn Guard, path: &Path| match guard.look_at(path) {
        Verdict::Leave { why } => Some(why),
        Verdict::Take { .. } => None,
    };

    let mut failed = false;
    // Which flags would have taken the files that were left.
    let mut left = Past::default();
    for file in files {
        let reason = reason.map_or_else(Reason::default, Reason::note);
        let absolute = std::path::absolute(file).ok();
        // What a guard would have said that the file was waved past.
        let of_windows = absolute
            .as_deref()
            .filter(|_| past.system_files)
            .and_then(|path| leaves(system_files.as_ref(), path));
        let boot_driver = absolute
            .as_deref()
            .filter(|_| past.boot_drivers)
            .and_then(|path| leaves(boot_drivers.as_ref(), path));
        // While the file is still there: the system is asked for the
        // other ways its path is written.
        let starting = absolute
            .as_deref()
            .map(|path| find_in(system.as_ref(), &survey, path).starting)
            .unwrap_or_default();
        match quarantine.add_with(file, reason, &options) {
            Ok(entry) => {
                outln!("Quarantined  {}", shown(&entry.info.original_path))?;
                outln!("  entry      {}", entry.info.id)?;
                outln!(
                    "  sha256     {} ({} bytes)",
                    entry.info.sha256,
                    group_digits(entry.info.size)
                )?;
                for why in boot_driver.iter().chain(&of_windows) {
                    outln!("  although   {}", shown(why))?;
                }
                if of_windows.is_some() {
                    // A file of Windows can have services of Windows that
                    // start it. They stay.
                    for seen in &starting {
                        outln!(
                            "  kept       {}, which starts it",
                            shown(&seen.entry.to_string())
                        )?;
                    }
                } else {
                    match remedy.remove(&entry.info.id, &entry.info.original_path, starting) {
                        Ok(removal) => print_removal(&removal, &entry.info.id)?,
                        Err(error) => {
                            failed = true;
                            errln!(
                                "error: the file is in the quarantine, and what starts it could not be removed: {}",
                                shown(&error.to_string())
                            );
                        }
                    }
                }
            }
            Err(error) => {
                failed = true;
                if let (QuarantineError::Guarded { .. }, Some(path)) = (&error, &absolute) {
                    // Which of the guards would leave it: each has a flag
                    // of its own, and a file can need both.
                    left.boot_drivers |=
                        !past.boot_drivers && leaves(boot_drivers.as_ref(), path).is_some();
                    left.system_files |=
                        !past.system_files && leaves(system_files.as_ref(), path).is_some();
                }
                errln!("error: {}", shown(&error.to_string()));
            }
        }
    }
    for problem in &survey.problems {
        errln!(
            "note: not everything that starts programs could be looked at: {}",
            shown(problem)
        );
    }
    if left.system_files {
        errln!(
            "Without a file of its own the system may not start, and then nothing is left to restore the file with. To quarantine such a file all the same, add {PAST_SYSTEM_FILES}."
        );
    }
    if left.boot_drivers {
        errln!(
            "Without a driver that it loads while it starts, Windows may not start, and then nothing is left to restore the file with. To quarantine such a file all the same, add {PAST_BOOT_DRIVERS}."
        );
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
    /// What was removed together with files because it started them.
    autostart: Vec<&'a Record>,
}

fn damaged_line(damaged: &Damaged) -> String {
    format!("{}: {}", shown_path(&damaged.file), shown(&damaged.problem))
}

fn list(json: bool, place: &Place) -> anyhow::Result<ExitCode> {
    let quarantine = open(place)?;
    let listing = quarantine.list()?;
    let system = this_system();
    let records = Remedy::new(system.as_ref(), &quarantine).records()?;
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
            autostart: records.iter().map(|(record, _)| record).collect(),
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
        if let Some((record, _)) = records.iter().find(|(record, _)| record.entry == info.id) {
            let removed = record
                .items
                .iter()
                .filter(|item| item.state != warden_autostart::State::Left)
                .count();
            if removed > 0 {
                outln!(
                    "    removed with it: {removed} of what started it; a restore puts {} back",
                    if removed == 1 { "it" } else { "them" }
                )?;
            }
        }
    }
    let owed: Vec<&Record> = records
        .iter()
        .filter(|(_, in_quarantine)| !in_quarantine)
        .map(|(record, _)| record)
        .collect();
    if !owed.is_empty() {
        outln!()?;
        outln!("Still owed to files that are back:")?;
        for record in owed {
            outln!("  {}  {}", record.entry, shown(&record.file))?;
            for item in &record.items {
                outln!(
                    "    {}{}",
                    shown(&item.what.to_string()),
                    item.note
                        .as_ref()
                        .map(|note| format!(": {}", shown(note)))
                        .unwrap_or_default()
                )?;
            }
        }
        outln!(
            "  `warden quarantine restore <entry>` tries to put them back again, and `warden quarantine delete <entry>` gives them up."
        )?;
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
    let system = this_system();
    if let Some(record) = Remedy::new(system.as_ref(), &quarantine).record(&info.id)? {
        outln!("What started it, and a restore puts back:")?;
        print_record(&record)?;
    }
    Ok(ExitCode::SUCCESS)
}

fn restore(
    id: &str,
    to: Option<&Path>,
    overwrite: bool,
    place: &Place,
) -> anyhow::Result<ExitCode> {
    let quarantine = open(place)?;
    let system = this_system();
    let remedy = Remedy::new(system.as_ref(), &quarantine);
    let restored = match quarantine.restore(
        id,
        &RestoreOptions {
            to: to.map(Path::to_path_buf),
            overwrite,
        },
    ) {
        Ok(restored) => restored,
        Err(QuarantineError::NotFound(missing)) => {
            // The file may be back already, with something still owed.
            let Some(record) = owed_record(&remedy, id)? else {
                return Err(QuarantineError::NotFound(missing).into());
            };
            outln!(
                "{} is back already. Trying again to put back what started it.",
                shown(&record.file)
            )?;
            if let Some(back) = remedy.put_back(&record.entry)? {
                print_put_back(&back, &record.entry)?;
            }
            return Ok(ExitCode::SUCCESS);
        }
        Err(other) => return Err(other.into()),
    };
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
    let at_its_place = restored
        .info
        .original()
        .is_some_and(|original| original == restored.path);
    if at_its_place {
        if let Some(back) = remedy.put_back(&restored.info.id)? {
            print_put_back(&back, &restored.info.id)?;
        }
    } else if remedy.record(&restored.info.id)?.is_some() {
        // An entry that started the file names the place it was at.
        let id = &restored.info.id;
        outln!(
            "  What started it was not put back, because the file is in another place now. `warden quarantine restore {id}` puts it back all the same, and `warden quarantine delete {id}` gives it up."
        )?;
    }
    Ok(ExitCode::SUCCESS)
}

/// The record of a file that is back, if something is still owed to it
/// and its identifier starts with these characters.
fn owed_record(remedy: &Remedy<'_>, id: &str) -> anyhow::Result<Option<Record>> {
    if id.is_empty() {
        return Ok(None);
    }
    Ok(remedy
        .records()?
        .into_iter()
        .find(|(record, in_quarantine)| !in_quarantine && record.entry.starts_with(id))
        .map(|(record, _)| record))
}

fn delete(ids: &[String], place: &Place) -> anyhow::Result<ExitCode> {
    let quarantine = open(place)?;
    let system = this_system();
    let remedy = Remedy::new(system.as_ref(), &quarantine);
    let mut failed = false;
    for id in ids {
        // What was removed together with the file goes first: the
        // shortcuts that are in the quarantine on its account, and the
        // record of the rest.
        match quarantine.find(id) {
            Ok(entry) => {
                if let Err(error) = remedy.forget(&entry.info.id) {
                    failed = true;
                    errln!("error: {}", shown(&error.to_string()));
                    continue;
                }
            }
            Err(QuarantineError::NotFound(_)) => {
                // Not a file in the quarantine. Something owed to a file
                // that is back, perhaps.
                if let Some(record) = owed_record(&remedy, id)? {
                    remedy.forget(&record.entry)?;
                    outln!(
                        "Gave up  {}  what could not be put back with {}",
                        record.entry,
                        shown(&record.file)
                    )?;
                    continue;
                }
            }
            // A damaged entry, or an identifier that fits several: for
            // the quarantine to say.
            Err(_) => {}
        }
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
            even_if_signed_by_windows,
            even_if_loaded_at_boot,
            place,
        } => add(
            files,
            reason.as_ref(),
            Past {
                system_files: *even_if_signed_by_windows,
                boot_drivers: *even_if_loaded_at_boot,
            },
            place,
        ),
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
    use warden_trust::sigarea::executable_with_table;
    use warden_trust::stand_in::{Answers, signer, valid, verifier};
    use warden_trust::{Found, Revocation};

    use super::*;

    /// A guard that asks the stand-in for Windows, with the list that is
    /// part of the program: what it leaves alone is what that list marks.
    fn guard(answers: Answers) -> SystemFiles {
        let list = TrustList::builtin().expect("the built-in list");
        SystemFiles {
            verifier: verifier(list, answers).0,
        }
    }

    /// A Windows executable without a signature of its own, which is what
    /// most files of Windows are: the catalogues vouch for them.
    fn system_file(dir: &tempfile::TempDir) -> PathBuf {
        let path = dir.path().join("kernel.dll");
        std::fs::write(&path, executable_with_table(&[])).expect("a file");
        path
    }

    fn windows() -> warden_trust::Signer {
        signer("Microsoft Windows", "Microsoft Corporation", true)
    }

    fn boot_driver(name: &str, line: &str) -> BootDriver {
        BootDriver {
            name: name.to_owned(),
            lines: vec![line.to_owned()],
        }
    }

    #[test]
    fn the_second_guard_leaves_a_file_that_windows_loads_as_a_driver_at_boot() {
        let guard = BootDrivers {
            drivers: vec![
                boot_driver("disk", r"C:\Windows\System32\drivers\disk.sys"),
                boot_driver("vendor", r"C:\Program Files\Vendor\vendor.sys"),
            ],
        };
        assert_eq!(
            guard.look_at(Path::new(r"C:\Program Files\Vendor\vendor.sys")),
            Verdict::Leave {
                why: "Windows loads it as the driver vendor while it starts".to_owned()
            }
        );
        // However the path is cased.
        assert!(matches!(
            guard.look_at(Path::new(r"c:\windows\system32\DRIVERS\DISK.SYS")),
            Verdict::Leave { .. }
        ));
        // Another file in the same folder, and the same name elsewhere.
        // Nothing was read, so no content is named.
        for other in [
            r"C:\Program Files\Vendor\vendor.exe",
            r"D:\Vendor\vendor.sys",
        ] {
            assert_eq!(
                guard.look_at(Path::new(other)),
                Verdict::Take { sha256: None },
                "{other}"
            );
        }
        // On a machine without such drivers, as on every system that is
        // not Windows, every file passes.
        let nothing = BootDrivers::of(&Survey::default());
        assert_eq!(
            nothing.look_at(Path::new(r"C:\Windows\System32\drivers\disk.sys")),
            Verdict::Take { sha256: None }
        );
    }

    /// A guard that always says the same.
    #[derive(Debug)]
    struct Says(Verdict);

    impl Guard for Says {
        fn look_at(&self, _: &Path) -> Verdict {
            self.0.clone()
        }
    }

    #[test]
    fn several_guards_leave_a_file_if_one_of_them_would() {
        let take = || Says(Verdict::Take { sha256: None });
        let read = |byte: u8| {
            Says(Verdict::Take {
                sha256: Some([byte; 32]),
            })
        };
        let leave = |why: &str| {
            Says(Verdict::Leave {
                why: why.to_owned(),
            })
        };
        let path = Path::new("any");
        let all = |guards: Vec<Says>| {
            Guards(
                guards
                    .into_iter()
                    .map(|guard| Box::new(guard) as Box<dyn Guard>)
                    .collect(),
            )
            .look_at(path)
        };

        // No guard at all takes everything, and so do guards that agree.
        assert_eq!(all(vec![]), Verdict::Take { sha256: None });
        assert_eq!(all(vec![take(), take()]), Verdict::Take { sha256: None });
        // The content that one of them read is what the file is held to.
        assert_eq!(
            all(vec![take(), read(7)]),
            Verdict::Take {
                sha256: Some([7; 32])
            }
        );
        assert_eq!(
            all(vec![read(7), take()]),
            Verdict::Take {
                sha256: Some([7; 32])
            }
        );
        // One that would leave the file is enough, wherever it stands,
        // and the first one to say so gives the reason.
        for guards in [
            vec![leave("first"), take()],
            vec![take(), leave("first")],
            vec![read(7), leave("first"), leave("second")],
        ] {
            assert_eq!(
                all(guards),
                Verdict::Leave {
                    why: "first".to_owned()
                }
            );
        }
    }

    #[test]
    fn a_shared_guard_says_what_the_guard_says() {
        let guard = Arc::new(Says(Verdict::Leave {
            why: "it says so".to_owned(),
        }));
        assert_eq!(
            Shared(Arc::clone(&guard)).look_at(Path::new("any")),
            guard.look_at(Path::new("any"))
        );
    }

    #[test]
    fn the_guard_leaves_a_file_that_windows_signed() {
        let dir = tempfile::tempdir().expect("temporary folder");
        let path = system_file(&dir);
        let verdict = guard(Answers {
            catalog: valid(windows()),
            ..Answers::default()
        })
        .look_at(&path);
        assert_eq!(
            verdict,
            Verdict::Leave {
                why: "it is part of the operating system (signed for Microsoft Windows, found in a catalogue of Windows)".to_owned()
            }
        );

        // Also when its certificates could not be looked up, which is the
        // normal case here: the guard asks nothing over the network.
        let mut unchecked = windows();
        unchecked.revocation = Revocation::Unknown;
        let verdict = guard(Answers {
            catalog: valid(unchecked),
            ..Answers::default()
        })
        .look_at(&path);
        assert!(matches!(verdict, Verdict::Leave { .. }), "{verdict:?}");
    }

    #[test]
    fn the_guard_takes_what_windows_did_not_sign() {
        let dir = tempfile::tempdir().expect("temporary folder");
        let path = system_file(&dir);
        let content = std::fs::read(&path).expect("the file");
        let expected: [u8; 32] = warden_engine::sha256(&content);

        for (what, catalog) in [
            ("no signature", Found::Nothing),
            // One of Microsoft's applications is not Windows.
            (
                "Microsoft Corporation",
                valid(signer(
                    "Microsoft Corporation",
                    "Microsoft Corporation",
                    true,
                )),
            ),
            // The names of Windows under somebody else's root.
            (
                "the names without the root",
                valid(signer("Microsoft Windows", "Microsoft Corporation", false)),
            ),
        ] {
            let verdict = guard(Answers {
                catalog,
                ..Answers::default()
            })
            .look_at(&path);
            // It says which content it let through.
            assert_eq!(
                verdict,
                Verdict::Take {
                    sha256: Some(expected)
                },
                "{what}"
            );
        }
    }

    #[test]
    fn the_guard_leaves_a_file_it_could_not_check() {
        let dir = tempfile::tempdir().expect("temporary folder");
        let path = system_file(&dir);
        let verdict = guard(Answers {
            catalog: Found::Failed {
                why: "the catalogues of Windows could not be opened".to_owned(),
            },
            ..Answers::default()
        })
        .look_at(&path);
        assert_eq!(
            verdict,
            Verdict::Leave {
                why: "it could not be checked whether it is part of the operating system (the catalogues of Windows could not be opened)".to_owned()
            }
        );
    }

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

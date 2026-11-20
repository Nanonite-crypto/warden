//! `warden false-positives`: scan files that are known to be clean and
//! report what was flagged anyway.
//!
//! A finding that did not count is not a false positive: the file kept its
//! clean verdict. Such findings are reported next to the flagged files all
//! the same, because they are what the verdict policy held back, and a
//! check of clean files is where one wants to see that it did.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, bail};
use clap::Args;
use serde::Serialize;
use warden_engine::{DetectorInfo, ENGINE_VERSION, Finding, ScanReport, SkipReason, Verdict};

use crate::EXIT_FOUND;
use crate::render::{
    ProgressLine, group_digits, heuristic_summary, human_bytes, human_duration, rule_summary,
    shown, shown_path, signature_summary,
};
use crate::scan::{LayerArgs, build_scanner, cancel_on_ctrl_c};
use crate::system::{SystemInfo, system_info};

/// How many flagged files are listed one by one.
const MAX_LISTED: usize = 1000;

#[derive(Debug, Args)]
pub struct FpArgs {
    /// Files or folders that are expected to be clean
    #[arg(required = true, value_name = "PATH")]
    paths: Vec<PathBuf>,

    #[command(flatten)]
    layers: LayerArgs,

    /// Worker threads (default: one per logical CPU, up to 16)
    #[arg(long, value_name = "N")]
    threads: Option<usize>,

    /// Print the results as JSON on standard output
    #[arg(long)]
    json: bool,

    /// Also write the JSON results to this file
    #[arg(long, value_name = "FILE")]
    output: Option<PathBuf>,

    /// Free text stored with the results, for example what was scanned
    #[arg(long, value_name = "TEXT")]
    label: Option<String>,

    /// Do not draw the progress line
    #[arg(long)]
    no_progress: bool,
}

#[derive(Debug, Serialize)]
struct NameCount {
    name: String,
    files: u64,
}

#[derive(Debug, Serialize)]
struct FlaggedFile {
    path: String,
    verdict: Verdict,
    size: u64,
    sha256: String,
    /// The detection names, each once.
    names: Vec<String>,
}

/// A file that kept its clean verdict and has findings on record.
#[derive(Debug, Serialize)]
struct RecordedFile {
    path: String,
    size: u64,
    sha256: String,
    /// The names of the findings, each once.
    names: Vec<String>,
}

/// A file that could not be read, or a folder that could not be opened.
#[derive(Debug, Serialize)]
struct NotRead {
    path: String,
    /// A folder hides what is in it: none of that was scanned or counted.
    folder: bool,
    reason: SkipReason,
    /// What the operating system said.
    detail: String,
}

/// Version of the JSON layout below. Version 2 added the files with
/// findings on record. Version 3 lists what could not be read and counts
/// folders apart from files: `files_skipped` used to count both.
const FP_SCHEMA: u32 = 3;

#[derive(Debug, Serialize)]
struct FpReport {
    schema: u32,
    label: Option<String>,
    engine_version: &'static str,
    system: SystemInfo,
    paths: Vec<String>,
    detectors: Vec<DetectorInfo>,
    threads: usize,
    duration_ms: u64,
    files_scanned: u64,
    bytes_scanned: u64,
    /// Files that could not be read.
    files_skipped: u64,
    /// Folders that could not be opened. Nothing in them was scanned or
    /// counted, so the check covers less than its numbers say, by an amount
    /// that nobody knows.
    folders_skipped: u64,
    files_partially_scanned: u64,
    archive_members_scanned: u64,
    files_per_second: f64,
    megabytes_per_second: f64,
    flagged_malicious: u64,
    flagged_suspicious: u64,
    /// Flagged files as a share of the files scanned, in percent.
    flagged_percent: f64,
    /// How many files each detection name was reported on, most first.
    by_name: Vec<NameCount>,
    /// The flagged files, sorted by path. At most 1000 are listed.
    flagged: Vec<FlaggedFile>,
    flagged_truncated: bool,
    /// Files that kept a clean verdict and have findings on record: what
    /// the detectors noticed and the verdict policy did not count.
    recorded_files: u64,
    /// How many of those files each finding name is on record for, most
    /// first.
    recorded_by_name: Vec<NameCount>,
    /// Those files, sorted by path. At most 1000 are listed.
    recorded: Vec<RecordedFile>,
    recorded_truncated: bool,
    /// What could not be read: the folders first, then the files, each
    /// sorted by path. At most 1000 are listed.
    skipped: Vec<NotRead>,
    skipped_truncated: bool,
}

/// The names of the findings, each once, in the order they were found.
fn names_of(findings: &[Finding]) -> Vec<&str> {
    let mut names: Vec<&str> = Vec::new();
    for finding in findings {
        if !names.contains(&finding.name.as_str()) {
            names.push(&finding.name);
        }
    }
    names
}

/// Counts per name, the most frequent first.
fn ranked(by_name: BTreeMap<&str, u64>) -> Vec<NameCount> {
    let mut ranked: Vec<NameCount> = by_name
        .into_iter()
        .map(|(name, files)| NameCount {
            name: name.to_owned(),
            files,
        })
        .collect();
    ranked.sort_by(|left, right| {
        right
            .files
            .cmp(&left.files)
            .then_with(|| left.name.cmp(&right.name))
    });
    ranked
}

fn summarise(report: &ScanReport, label: Option<String>, paths: &[PathBuf]) -> FpReport {
    let stats = &report.stats;
    let mut by_name: BTreeMap<&str, u64> = BTreeMap::new();
    let mut flagged = Vec::new();
    let (mut malicious, mut suspicious) = (0u64, 0u64);
    for detection in &report.detections {
        match detection.verdict {
            Verdict::Malicious => malicious += 1,
            Verdict::Suspicious => suspicious += 1,
            Verdict::Clean => {}
        }
        let names = names_of(&detection.findings);
        for name in &names {
            *by_name.entry(name).or_insert(0) += 1;
        }
        if flagged.len() < MAX_LISTED {
            flagged.push(FlaggedFile {
                path: detection.path.to_string_lossy().into_owned(),
                verdict: detection.verdict,
                size: detection.size,
                sha256: detection.sha256.clone(),
                names: names.into_iter().map(str::to_owned).collect(),
            });
        }
    }
    let by_name = ranked(by_name);

    // The scan lists at most ten thousand of these files; its count of
    // them is complete. The names are counted over the files it lists.
    let mut recorded_by_name: BTreeMap<&str, u64> = BTreeMap::new();
    let mut recorded = Vec::new();
    for entry in &report.recorded {
        let names = names_of(&entry.findings);
        for name in &names {
            *recorded_by_name.entry(name).or_insert(0) += 1;
        }
        if recorded.len() < MAX_LISTED {
            recorded.push(RecordedFile {
                path: entry.path.to_string_lossy().into_owned(),
                size: entry.size,
                sha256: entry.sha256.clone(),
                names: names.into_iter().map(str::to_owned).collect(),
            });
        }
    }

    // Folders first: one of them can stand for more than all the files
    // after it together.
    let mut skipped: Vec<NotRead> = report
        .skipped
        .iter()
        .map(|entry| NotRead {
            path: entry.path.to_string_lossy().into_owned(),
            folder: entry.folder,
            reason: entry.reason,
            detail: entry.detail.clone(),
        })
        .collect();
    skipped.sort_by(|left, right| {
        right
            .folder
            .cmp(&left.folder)
            .then_with(|| left.path.cmp(&right.path))
    });
    let skipped_truncated = report.skipped_truncated || skipped.len() > MAX_LISTED;
    skipped.truncate(MAX_LISTED);

    let flagged_total = malicious + suspicious;
    FpReport {
        schema: FP_SCHEMA,
        label,
        engine_version: ENGINE_VERSION,
        system: system_info(),
        paths: paths
            .iter()
            .map(|path| {
                std::path::absolute(path)
                    .unwrap_or_else(|_| path.clone())
                    .to_string_lossy()
                    .into_owned()
            })
            .collect(),
        detectors: report.detectors.clone(),
        threads: report.threads,
        duration_ms: u64::try_from(report.duration.as_millis()).unwrap_or(u64::MAX),
        files_scanned: stats.files_scanned,
        bytes_scanned: stats.bytes_scanned,
        files_skipped: stats.files_skipped,
        folders_skipped: stats.folders_skipped,
        files_partially_scanned: stats.files_partially_scanned,
        archive_members_scanned: stats.archive_members_scanned,
        files_per_second: stats.files_per_second,
        megabytes_per_second: stats.megabytes_per_second,
        flagged_malicious: malicious,
        flagged_suspicious: suspicious,
        flagged_percent: if stats.files_scanned == 0 {
            0.0
        } else {
            flagged_total as f64 * 100.0 / stats.files_scanned as f64
        },
        by_name,
        flagged_truncated: flagged_total > flagged.len() as u64,
        flagged,
        recorded_files: stats.files_recorded,
        recorded_by_name: ranked(recorded_by_name),
        recorded_truncated: stats.files_recorded > recorded.len() as u64,
        recorded,
        skipped,
        skipped_truncated,
    }
}

fn text(report: &FpReport, duration: std::time::Duration) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(out, "Warden {} false-positive check", report.engine_version);
    if let Some(label) = &report.label {
        let _ = writeln!(out, "Label       {label}");
    }
    for path in &report.paths {
        let _ = writeln!(out, "Path        {}", shown(path));
    }
    let _ = writeln!(out, "System      {}", report.system.line());
    let _ = writeln!(out, "Signatures  {}", signature_summary(&report.detectors));
    if let Some(rules) = rule_summary(&report.detectors) {
        let _ = writeln!(out, "Rules       {rules}");
    }
    if let Some(heuristics) = heuristic_summary(&report.detectors) {
        let _ = writeln!(out, "Heuristics  {heuristics}");
    }
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "Scanned     {} files, {} in {}",
        group_digits(report.files_scanned),
        human_bytes(report.bytes_scanned),
        human_duration(duration)
    );
    let _ = writeln!(
        out,
        "Speed       {} files/s, {:.1} MB/s on {} threads",
        group_digits(report.files_per_second.round() as u64),
        report.megabytes_per_second,
        report.threads
    );
    if report.archive_members_scanned > 0 {
        let _ = writeln!(
            out,
            "Archives    {} files inside archives were checked too",
            group_digits(report.archive_members_scanned)
        );
    }
    if let Some(line) = not_covered(
        report.folders_skipped,
        report.files_skipped,
        report.files_partially_scanned,
    ) {
        let _ = writeln!(out, "Not covered {line}");
    }
    if report.folders_skipped > 0 {
        let _ = writeln!(
            out,
            "            What is in a folder that could not be opened was not scanned \
             and is not counted."
        );
    }
    let _ = writeln!(out);
    let flagged = report.flagged_malicious + report.flagged_suspicious;
    let _ = writeln!(
        out,
        "Flagged     {} of {} files ({:.3} %): {} malicious, {} suspicious",
        group_digits(flagged),
        group_digits(report.files_scanned),
        report.flagged_percent,
        group_digits(report.flagged_malicious),
        group_digits(report.flagged_suspicious)
    );
    if report.recorded_files > 0 {
        let _ = writeln!(
            out,
            "On record   {} {} that did not count; the verdict is clean",
            group_digits(report.recorded_files),
            if report.recorded_files == 1 {
                "file has findings"
            } else {
                "files have findings"
            },
        );
    }

    let by_name = |out: &mut String, title: &str, entries: &[NameCount]| {
        let _ = writeln!(out);
        let _ = writeln!(out, "{title}");
        for entry in entries {
            let _ = writeln!(
                out,
                "  {:>7}  {}",
                group_digits(entry.files),
                shown(&entry.name)
            );
        }
    };

    if flagged > 0 {
        by_name(&mut out, "By detection name", &report.by_name);
        let _ = writeln!(out);
        let _ = writeln!(out, "Flagged files");
        for file in &report.flagged {
            let verdict = match file.verdict {
                Verdict::Malicious => "MALICIOUS ",
                Verdict::Suspicious => "SUSPICIOUS",
                Verdict::Clean => "CLEAN     ",
            };
            let _ = writeln!(
                out,
                "  {verdict}  {}  ({})",
                shown_path(std::path::Path::new(&file.path)),
                shown(&file.names.join(", "))
            );
        }
        if report.flagged_truncated {
            let _ = writeln!(out, "  ... and more; the list was cut short.");
        }
    }

    if report.recorded_files > 0 {
        by_name(
            &mut out,
            "On record, by the name of the finding",
            &report.recorded_by_name,
        );
        let _ = writeln!(out);
        let _ = writeln!(out, "Files with findings on record");
        for file in &report.recorded {
            let _ = writeln!(
                out,
                "  ON RECORD   {}  ({})",
                shown_path(std::path::Path::new(&file.path)),
                shown(&file.names.join(", "))
            );
        }
        if report.recorded_truncated {
            let _ = writeln!(out, "  ... and more; the list was cut short.");
        }
    }

    for (folders, title) in [
        (true, "Folders that could not be opened"),
        (false, "Files that could not be read"),
    ] {
        let mut entries = report
            .skipped
            .iter()
            .filter(|entry| entry.folder == folders)
            .peekable();
        if entries.peek().is_none() {
            continue;
        }
        let _ = writeln!(out);
        let _ = writeln!(out, "{title}");
        for entry in entries {
            let _ = writeln!(
                out,
                "  {}  {}",
                entry.reason.as_str(),
                shown_path(std::path::Path::new(&entry.path))
            );
        }
    }
    if report.skipped_truncated {
        let _ = writeln!(out, "  ... and more; the list was cut short.");
    }
    out
}

/// What a check did not cover, in words, or `None` if it covered everything.
fn not_covered(folders: u64, files: u64, partial: u64) -> Option<String> {
    let mut parts = Vec::new();
    if folders > 0 {
        parts.push(format!(
            "{} {} could not be opened",
            group_digits(folders),
            if folders == 1 { "folder" } else { "folders" }
        ));
    }
    if files > 0 {
        parts.push(format!(
            "{} {} could not be read",
            group_digits(files),
            if files == 1 { "file" } else { "files" }
        ));
    }
    if partial > 0 {
        parts.push(format!(
            "{} {} not checked in full",
            group_digits(partial),
            if partial == 1 { "file" } else { "files" }
        ));
    }
    (!parts.is_empty()).then(|| parts.join(", "))
}

pub fn run(args: &FpArgs) -> anyhow::Result<ExitCode> {
    let scanner = build_scanner(&args.layers, args.threads, Vec::new())?;
    let cancel = cancel_on_ctrl_c();

    let mut progress = ProgressLine::new(!args.json && !args.no_progress);
    let outcome = scanner.scan(&args.paths, &mut progress, &cancel);
    progress.clear();
    let scan = outcome?;
    if scan.cancelled {
        bail!("the check was cancelled");
    }

    let report = summarise(&scan, args.label.clone(), &args.paths);
    if let Some(path) = &args.output {
        std::fs::write(path, serde_json::to_string_pretty(&report)?)
            .with_context(|| format!("cannot write the results to {}", path.display()))?;
    }
    if args.json {
        outln!("{}", serde_json::to_string_pretty(&report)?)?;
    } else {
        out!("{}", text(&report, scan.duration))?;
    }
    Ok(
        if report.flagged_malicious + report.flagged_suspicious == 0 {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(EXIT_FOUND)
        },
    )
}

#[cfg(test)]
mod tests {
    use super::not_covered;

    #[test]
    fn what_was_not_covered_is_said_kind_by_kind() {
        assert_eq!(not_covered(0, 0, 0), None);
        assert_eq!(
            not_covered(1, 0, 0).as_deref(),
            Some("1 folder could not be opened")
        );
        assert_eq!(
            not_covered(3, 1, 1_060).as_deref(),
            Some(
                "3 folders could not be opened, 1 file could not be read, \
                 1,060 files not checked in full"
            )
        );
        assert_eq!(
            not_covered(0, 34, 0).as_deref(),
            Some("34 files could not be read")
        );
    }
}

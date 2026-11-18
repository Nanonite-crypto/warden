//! `warden false-positives`: scan files that are known to be clean and
//! report what was flagged anyway.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, bail};
use clap::Args;
use serde::Serialize;
use warden_engine::{DetectorInfo, ENGINE_VERSION, ScanReport, Verdict};

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
    files_skipped: u64,
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
        let mut names: Vec<&str> = Vec::new();
        for finding in &detection.findings {
            if !names.contains(&finding.name.as_str()) {
                names.push(&finding.name);
            }
        }
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
    let mut by_name: Vec<NameCount> = by_name
        .into_iter()
        .map(|(name, files)| NameCount {
            name: name.to_owned(),
            files,
        })
        .collect();
    by_name.sort_by(|left, right| {
        right
            .files
            .cmp(&left.files)
            .then_with(|| left.name.cmp(&right.name))
    });

    let flagged_total = malicious + suspicious;
    FpReport {
        schema: 1,
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
    if report.files_skipped > 0 || report.files_partially_scanned > 0 {
        let _ = writeln!(
            out,
            "Not covered {} skipped, {} not checked in full",
            group_digits(report.files_skipped),
            group_digits(report.files_partially_scanned)
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
    if flagged == 0 {
        return out;
    }

    let _ = writeln!(out);
    let _ = writeln!(out, "By detection name");
    for entry in &report.by_name {
        let _ = writeln!(
            out,
            "  {:>7}  {}",
            group_digits(entry.files),
            shown(&entry.name)
        );
    }
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
    out
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
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print!("{}", text(&report, scan.duration));
    }
    Ok(
        if report.flagged_malicious + report.flagged_suspicious == 0 {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(EXIT_FOUND)
        },
    )
}

//! `warden bench`: measure scan throughput on a folder.

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, bail};
use clap::Args;
use serde::Serialize;
use warden_engine::{DetectorInfo, ENGINE_VERSION, NoObserver, ScanReport};

use crate::render::{
    group_digits, heuristic_summary, human_bytes, human_duration, rule_summary, signature_summary,
};
use crate::scan::{LayerArgs, build_scanner, cancel_on_ctrl_c};
use crate::system::{SystemInfo, system_info};

#[derive(Debug, Args)]
pub struct BenchArgs {
    /// File or folder to scan repeatedly; it is only read, never changed
    #[arg(value_name = "PATH")]
    path: PathBuf,

    /// Timed runs per thread count
    #[arg(long, default_value_t = 3, value_name = "N")]
    runs: u32,

    /// Thread counts to compare, comma-separated (default: automatic)
    #[arg(long, value_delimiter = ',', value_name = "N,N,...")]
    threads: Vec<usize>,

    #[command(flatten)]
    layers: LayerArgs,

    /// Print the results as JSON on standard output
    #[arg(long)]
    json: bool,

    /// Also write the JSON results to this file
    #[arg(long, value_name = "FILE")]
    output: Option<PathBuf>,

    /// Free text stored with the results, for example the machine's name
    #[arg(long, value_name = "TEXT")]
    label: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct Run {
    /// True for the first run of the whole benchmark. It reads whatever the
    /// operating system had not cached yet, so it is kept out of the median.
    first: bool,
    duration_ms: f64,
    files_scanned: u64,
    bytes_scanned: u64,
    /// Files that could not be read.
    files_skipped: u64,
    /// Folders that could not be opened; what is in them was not scanned.
    folders_skipped: u64,
    detections: u64,
    files_per_second: f64,
    megabytes_per_second: f64,
}

impl Run {
    fn from_report(report: &ScanReport, first: bool) -> Self {
        Self {
            first,
            duration_ms: report.duration.as_secs_f64() * 1000.0,
            files_scanned: report.stats.files_scanned,
            bytes_scanned: report.stats.bytes_scanned,
            files_skipped: report.stats.files_skipped,
            folders_skipped: report.stats.folders_skipped,
            detections: report.stats.detections,
            files_per_second: report.stats.files_per_second,
            megabytes_per_second: report.stats.megabytes_per_second,
        }
    }
}

#[derive(Debug, Serialize)]
struct Configuration {
    threads: usize,
    runs: Vec<Run>,
    /// Median over the repeat runs, which the file cache can serve. Absent
    /// when the only run was the first of the benchmark.
    repeat_median_files_per_second: Option<f64>,
    repeat_median_megabytes_per_second: Option<f64>,
}

/// Version of the JSON layout below. Version 2 marked the first run and
/// took the median over the runs after it. Version 3 counts folders that
/// could not be opened apart from files that could not be read:
/// `files_skipped` used to count both.
const BENCH_SCHEMA: u32 = 3;

#[derive(Debug, Serialize)]
struct BenchReport {
    schema: u32,
    label: Option<String>,
    path: String,
    engine_version: &'static str,
    system: SystemInfo,
    detectors: Vec<DetectorInfo>,
    configurations: Vec<Configuration>,
}

fn median(mut values: Vec<f64>) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.sort_by(f64::total_cmp);
    let middle = values.len() / 2;
    if values.len() % 2 == 1 {
        values[middle]
    } else {
        f64::midpoint(values[middle - 1], values[middle])
    }
}

/// Median of one figure over the repeat runs, or `None` when there are none.
fn repeat_median(runs: &[Run], figure: impl Fn(&Run) -> f64) -> Option<f64> {
    let repeats: Vec<f64> = runs.iter().filter(|run| !run.first).map(figure).collect();
    (!repeats.is_empty()).then(|| median(repeats))
}

pub fn run(args: &BenchArgs) -> anyhow::Result<ExitCode> {
    if args.runs == 0 {
        bail!("--runs must be at least 1");
    }
    let cancel = cancel_on_ctrl_c();
    let thread_counts: Vec<Option<usize>> = if args.threads.is_empty() {
        vec![None]
    } else {
        args.threads.iter().copied().map(Some).collect()
    };
    let roots = [args.path.clone()];

    let mut detectors = Vec::new();
    let mut configurations = Vec::new();
    let mut first = true;
    for threads in thread_counts {
        let scanner = build_scanner(&args.layers, threads, Vec::new())?;
        let mut runs = Vec::new();
        let mut used_threads = 0;
        for number in 1..=args.runs {
            if !args.json {
                errln!(
                    "run {number} of {} with {} threads ...",
                    args.runs,
                    scanner.options().effective_threads()
                );
            }
            let report = scanner.scan(&roots, &mut NoObserver, &cancel)?;
            if report.cancelled {
                bail!("the benchmark was cancelled");
            }
            used_threads = report.threads;
            if detectors.is_empty() {
                detectors.clone_from(&report.detectors);
            }
            runs.push(Run::from_report(&report, first));
            first = false;
        }
        configurations.push(Configuration {
            threads: used_threads,
            repeat_median_files_per_second: repeat_median(&runs, |run| run.files_per_second),
            repeat_median_megabytes_per_second: repeat_median(&runs, |run| {
                run.megabytes_per_second
            }),
            runs,
        });
    }

    let report = BenchReport {
        schema: BENCH_SCHEMA,
        label: args.label.clone(),
        path: std::path::absolute(&args.path)
            .unwrap_or_else(|_| args.path.clone())
            .to_string_lossy()
            .into_owned(),
        engine_version: ENGINE_VERSION,
        system: system_info(),
        detectors,
        configurations,
    };

    if let Some(path) = &args.output {
        std::fs::write(path, serde_json::to_string_pretty(&report)?)
            .with_context(|| format!("cannot write the results to {}", path.display()))?;
    }
    if args.json {
        outln!("{}", serde_json::to_string_pretty(&report)?)?;
    } else {
        out!("{}", text(&report))?;
    }
    Ok(ExitCode::SUCCESS)
}

fn text(report: &BenchReport) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(out, "Warden {} benchmark", report.engine_version);
    if let Some(label) = &report.label {
        let _ = writeln!(out, "Label       {label}");
    }
    let _ = writeln!(out, "Path        {}", report.path);
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
        "{:>7}  {:>6}  {:>10}  {:>10}  {:>9}  {:>9}  {:>8}",
        "Threads", "Run", "Time", "Files", "Data", "Files/s", "MB/s"
    );
    for configuration in &report.configurations {
        for (index, run) in configuration.runs.iter().enumerate() {
            let label = if run.first {
                "first".to_owned()
            } else {
                (index + 1).to_string()
            };
            let _ = writeln!(
                out,
                "{:>7}  {:>6}  {:>10}  {:>10}  {:>9}  {:>9}  {:>8.1}",
                configuration.threads,
                label,
                human_duration(std::time::Duration::from_secs_f64(run.duration_ms / 1000.0)),
                group_digits(run.files_scanned),
                human_bytes(run.bytes_scanned),
                group_digits(run.files_per_second.round() as u64),
                run.megabytes_per_second,
            );
        }
        if let (Some(files), Some(megabytes)) = (
            configuration.repeat_median_files_per_second,
            configuration.repeat_median_megabytes_per_second,
        ) {
            let _ = writeln!(
                out,
                "{:>7}  {:>6}  {:>10}  {:>10}  {:>9}  {:>9}  {:>8.1}",
                configuration.threads,
                "median",
                "",
                "",
                "",
                group_digits(files.round() as u64),
                megabytes,
            );
        }
    }
    let _ = writeln!(out);
    let has_median = report
        .configurations
        .iter()
        .any(|configuration| configuration.repeat_median_files_per_second.is_some());
    let note = if has_median {
        "The first run reads whatever the operating system had not cached yet, so the \
         median covers only the runs after it."
    } else {
        "A single run reads whatever the operating system had not cached yet. \
         Use --runs 3 for a median over repeat runs."
    };
    let _ = writeln!(out, "{note}");
    out
}

#[cfg(test)]
mod tests {
    use super::{Run, median, repeat_median};

    fn run(first: bool, files_per_second: f64) -> Run {
        Run {
            first,
            duration_ms: 1.0,
            files_scanned: 1,
            bytes_scanned: 1,
            files_skipped: 0,
            folders_skipped: 0,
            detections: 0,
            files_per_second,
            megabytes_per_second: files_per_second / 10.0,
        }
    }

    #[test]
    fn median_of_odd_and_even_counts() {
        assert_eq!(median(vec![]), 0.0);
        assert_eq!(median(vec![5.0]), 5.0);
        assert_eq!(median(vec![3.0, 1.0, 2.0]), 2.0);
        assert_eq!(median(vec![4.0, 1.0, 3.0, 2.0]), 2.5);
    }

    #[test]
    fn the_first_run_is_kept_out_of_the_median() {
        let cold_then_warm = [run(true, 10.0), run(false, 100.0), run(false, 120.0)];
        assert_eq!(
            repeat_median(&cold_then_warm, |run| run.files_per_second),
            Some(110.0)
        );
        assert_eq!(
            repeat_median(&cold_then_warm, |run| run.megabytes_per_second),
            Some(11.0)
        );

        let all_repeats = [run(false, 90.0), run(false, 100.0), run(false, 120.0)];
        assert_eq!(
            repeat_median(&all_repeats, |run| run.files_per_second),
            Some(100.0)
        );

        let only_the_first = [run(true, 10.0)];
        assert_eq!(
            repeat_median(&only_the_first, |run| run.files_per_second),
            None
        );
    }
}

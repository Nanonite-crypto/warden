//! `warden bench`: measure scan throughput on a folder.

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, bail};
use clap::Args;
use serde::Serialize;
use warden_engine::{DetectorInfo, ENGINE_VERSION, NoObserver, ScanReport};

use crate::render::{group_digits, human_bytes, human_duration, signature_summary};
use crate::scan::{build_scanner, cancel_on_ctrl_c};

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

    /// Signature database to use on top of the built-in signatures
    #[arg(long, value_name = "FILE", env = "WARDEN_SIGDB")]
    sigdb: Option<PathBuf>,

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
    duration_ms: f64,
    files_scanned: u64,
    bytes_scanned: u64,
    files_skipped: u64,
    detections: u64,
    files_per_second: f64,
    megabytes_per_second: f64,
}

impl Run {
    fn from_report(report: &ScanReport) -> Self {
        Self {
            duration_ms: report.duration.as_secs_f64() * 1000.0,
            files_scanned: report.stats.files_scanned,
            bytes_scanned: report.stats.bytes_scanned,
            files_skipped: report.stats.files_skipped,
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
    median_files_per_second: f64,
    median_megabytes_per_second: f64,
}

#[derive(Debug, Serialize)]
struct SystemInfo {
    os: &'static str,
    arch: &'static str,
    logical_cpus: usize,
    cpu: Option<String>,
}

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

fn cpu_name() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let info = std::fs::read_to_string("/proc/cpuinfo").ok()?;
        info.lines()
            .find(|line| line.starts_with("model name"))
            .and_then(|line| line.split_once(':'))
            .map(|(_, name)| name.trim().to_owned())
    }
    #[cfg(windows)]
    {
        std::env::var("PROCESSOR_IDENTIFIER").ok()
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        None
    }
}

fn system_info() -> SystemInfo {
    SystemInfo {
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
        logical_cpus: std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get),
        cpu: cpu_name(),
    }
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
    for threads in thread_counts {
        let scanner = build_scanner(args.sigdb.as_ref(), threads, Vec::new())?;
        let mut runs = Vec::new();
        let mut used_threads = 0;
        for number in 1..=args.runs {
            if !args.json {
                eprintln!(
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
            runs.push(Run::from_report(&report));
        }
        configurations.push(Configuration {
            threads: used_threads,
            median_files_per_second: median(runs.iter().map(|run| run.files_per_second).collect()),
            median_megabytes_per_second: median(
                runs.iter().map(|run| run.megabytes_per_second).collect(),
            ),
            runs,
        });
    }

    let report = BenchReport {
        schema: 1,
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
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print!("{}", text(&report));
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
    let _ = writeln!(
        out,
        "System      {} {}, {} logical CPUs{}",
        report.system.os,
        report.system.arch,
        report.system.logical_cpus,
        report
            .system
            .cpu
            .as_ref()
            .map(|cpu| format!(", {cpu}"))
            .unwrap_or_default()
    );
    let _ = writeln!(out, "Signatures  {}", signature_summary(&report.detectors));
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "{:>7}  {:>6}  {:>10}  {:>10}  {:>9}  {:>9}  {:>8}",
        "Threads", "Run", "Time", "Files", "Data", "Files/s", "MB/s"
    );
    for configuration in &report.configurations {
        for (index, run) in configuration.runs.iter().enumerate() {
            let _ = writeln!(
                out,
                "{:>7}  {:>6}  {:>10}  {:>10}  {:>9}  {:>9}  {:>8.1}",
                configuration.threads,
                index + 1,
                human_duration(std::time::Duration::from_secs_f64(run.duration_ms / 1000.0)),
                group_digits(run.files_scanned),
                human_bytes(run.bytes_scanned),
                group_digits(run.files_per_second.round() as u64),
                run.megabytes_per_second,
            );
        }
        let _ = writeln!(
            out,
            "{:>7}  {:>6}  {:>10}  {:>10}  {:>9}  {:>9}  {:>8.1}",
            configuration.threads,
            "median",
            "",
            "",
            "",
            group_digits(configuration.median_files_per_second.round() as u64),
            configuration.median_megabytes_per_second,
        );
    }
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "The first run may include files that were not yet in the operating system's \
         file cache. Later runs are warm."
    );
    out
}

#[cfg(test)]
mod tests {
    use super::median;

    #[test]
    fn median_of_odd_and_even_counts() {
        assert_eq!(median(vec![]), 0.0);
        assert_eq!(median(vec![5.0]), 5.0);
        assert_eq!(median(vec![3.0, 1.0, 2.0]), 2.0);
        assert_eq!(median(vec![4.0, 1.0, 3.0, 2.0]), 2.5);
    }
}

//! `warden scan`.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::Context;
use clap::Args;
use warden_engine::{CancelToken, HashDetector, ScanOptions, Scanner};
use warden_sigdb::SigDb;

use crate::EXIT_FOUND;
use crate::render::{self, ProgressLine};

#[derive(Debug, Args)]
pub struct ScanArgs {
    /// Files or folders to scan
    #[arg(required = true, value_name = "PATH")]
    paths: Vec<PathBuf>,

    /// Signature database to use on top of the built-in signatures
    #[arg(long, value_name = "FILE", env = "WARDEN_SIGDB")]
    sigdb: Option<PathBuf>,

    /// Worker threads (default: one per logical CPU, up to 16)
    #[arg(long, value_name = "N")]
    threads: Option<usize>,

    /// Path to leave out; may be given more than once
    #[arg(long, value_name = "PATH")]
    exclude: Vec<PathBuf>,

    /// Print the full report as JSON on standard output
    #[arg(long)]
    json: bool,

    /// Also write the full JSON report to this file
    #[arg(long, value_name = "FILE")]
    report: Option<PathBuf>,

    /// List every skipped file instead of only counting them
    #[arg(long)]
    show_skipped: bool,

    /// Do not draw the progress line
    #[arg(long)]
    no_progress: bool,
}

/// Builds a scanner with the hash layer and an optional signature database.
pub fn build_scanner(
    sigdb: Option<&PathBuf>,
    threads: Option<usize>,
    exclude: Vec<PathBuf>,
) -> anyhow::Result<Scanner> {
    let detector = match sigdb {
        Some(path) => HashDetector::with_database(Arc::new(SigDb::open(path)?)),
        None => HashDetector::new(),
    };
    let options = ScanOptions {
        threads: threads.unwrap_or(0),
        exclude,
        ..ScanOptions::default()
    };
    Ok(Scanner::builder()
        .detector(detector)
        .options(options)
        .build())
}

/// Installs a Ctrl-C handler: the first press cancels the scan and lets it
/// report what it has; the second press ends the program at once.
pub fn cancel_on_ctrl_c() -> CancelToken {
    let token = CancelToken::new();
    let handler_token = token.clone();
    let installed = ctrlc::set_handler(move || {
        if handler_token.is_cancelled() {
            std::process::exit(130);
        }
        handler_token.cancel();
        eprintln!("\nCancelling. Press Ctrl-C again to stop immediately.");
    });
    if let Err(error) = installed {
        eprintln!("warning: Ctrl-C will not cancel cleanly ({error})");
    }
    token
}

pub fn run(args: &ScanArgs) -> anyhow::Result<ExitCode> {
    let scanner = build_scanner(args.sigdb.as_ref(), args.threads, args.exclude.clone())?;
    let cancel = cancel_on_ctrl_c();

    let mut progress = ProgressLine::new(!args.json && !args.no_progress);
    let outcome = scanner.scan(&args.paths, &mut progress, &cancel);
    progress.clear();
    let report = outcome?;

    if let Some(path) = &args.report {
        let json = serde_json::to_string_pretty(&report)?;
        std::fs::write(path, json)
            .with_context(|| format!("cannot write the report to {}", path.display()))?;
    }
    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print!("{}", render::report_text(&report, args.show_skipped));
    }

    Ok(if report.is_clean() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(EXIT_FOUND)
    })
}

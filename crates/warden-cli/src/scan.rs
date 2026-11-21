//! `warden scan`.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::Context;
use clap::Args;
use warden_engine::{ArchiveOptions, CancelToken, HashDetector, ScanOptions, Scanner};
use warden_pe::PeDetector;
use warden_sigdb::SigDb;
use warden_trust::{TrustList, Verifier};
use warden_yara::{RuleBundle, YaraDetector};

use crate::EXIT_FOUND;
use crate::render::{self, ProgressLine};

/// Which detection layers run, and with what.
#[derive(Debug, Clone, Default, Args)]
pub struct LayerArgs {
    /// Signature database to use on top of the built-in signatures
    #[arg(long, value_name = "FILE", env = "WARDEN_SIGDB")]
    pub sigdb: Option<PathBuf>,

    /// Rule bundle to use instead of only the built-in YARA rules
    #[arg(long, value_name = "FILE", env = "WARDEN_RULES")]
    pub rules: Option<PathBuf>,

    /// Do not run YARA rules, not even the built-in ones
    #[arg(long)]
    pub no_yara: bool,

    /// Do not judge Windows executables by their structure
    #[arg(long)]
    pub no_heuristics: bool,

    /// Do not look inside zip archives
    #[arg(long)]
    pub no_archives: bool,

    /// Do not check who signed a file: report every match of a rule from
    /// the bundle, also in a file that a trusted publisher signed
    #[arg(long)]
    pub no_trust: bool,

    /// Do not use the network. A scan uses it for one thing: when it
    /// checks who signed a file, Windows may ask whether a certificate was
    /// revoked. Without the network a certificate that Windows has
    /// nothing stored about counts as not checked, and its file is not
    /// trusted
    #[arg(long)]
    pub offline: bool,
}

#[derive(Debug, Args)]
pub struct ScanArgs {
    /// Files or folders to scan
    #[arg(required = true, value_name = "PATH")]
    paths: Vec<PathBuf>,

    #[command(flatten)]
    layers: LayerArgs,

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

    /// List every skipped and partially scanned file instead of only
    /// counting them
    #[arg(long)]
    show_skipped: bool,

    /// Do not draw the progress line
    #[arg(long)]
    no_progress: bool,
}

/// Builds a scanner with the layers the options ask for: hash matching
/// always, YARA rules and the heuristics unless switched off. The layers
/// run in this order, the most certain first. Unless that is switched off
/// too, the scanner checks who signed a file before it reports the match
/// of a bundle's rule.
pub fn build_scanner(
    layers: &LayerArgs,
    threads: Option<usize>,
    exclude: Vec<PathBuf>,
) -> anyhow::Result<Scanner> {
    let hash = match &layers.sigdb {
        Some(path) => HashDetector::with_database(Arc::new(SigDb::open(path)?)),
        None => HashDetector::new(),
    };
    let options = ScanOptions {
        threads: threads.unwrap_or(0),
        exclude,
        archives: ArchiveOptions {
            enabled: !layers.no_archives,
            ..ArchiveOptions::default()
        },
        ..ScanOptions::default()
    };
    let mut builder = Scanner::builder().detector(hash).options(options);
    if !layers.no_yara {
        let yara = match &layers.rules {
            Some(path) => YaraDetector::new(RuleBundle::open(path)?),
            None => YaraDetector::builtin().context("the built-in YARA rules are broken")?,
        };
        builder = builder.detector(yara);
    }
    if !layers.no_heuristics {
        builder = builder.detector(PeDetector::new());
    }
    if !layers.no_trust {
        let list = TrustList::builtin().context("the built-in trust list is broken")?;
        let options = warden_trust::Options {
            network: !layers.offline,
        };
        builder = builder.trust(Verifier::new(list, options));
    }
    Ok(builder.build())
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
        errln!("\nCancelling. Press Ctrl-C again to stop immediately.");
    });
    if let Err(error) = installed {
        errln!("warning: Ctrl-C will not cancel cleanly ({error})");
    }
    token
}

pub fn run(args: &ScanArgs) -> anyhow::Result<ExitCode> {
    let scanner = build_scanner(&args.layers, args.threads, args.exclude.clone())?;
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
        outln!("{}", serde_json::to_string_pretty(&report)?)?;
    } else {
        out!("{}", render::report_text(&report, args.show_skipped))?;
    }

    Ok(if report.is_clean() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(EXIT_FOUND)
    })
}

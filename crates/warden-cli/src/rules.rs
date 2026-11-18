//! `warden rules`: build and inspect YARA rule bundles.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::Context;
use clap::Subcommand;
use serde::Serialize;
use warden_sigdb::hex;
use warden_yara::{BundleBuilder, RuleBundle, SourceInfo, YaraDetector, write_bundle};

use crate::render::{group_digits, human_bytes, human_duration, human_timestamp, shown};

/// How many licences `rules info` lists before summing up the rest.
const LICENCES_SHOWN: usize = 12;

#[derive(Debug, Subcommand)]
pub enum RulesCommand {
    /// Compile YARA rule files into a rule bundle
    ///
    /// Takes rule files (.yar, .yara), folders of them, and zip packages of
    /// them, such as the packages YARA Forge publishes. A rule that does not
    /// compile is left out and counted; it does not stop the build.
    Build {
        /// Rule files, folders of rule files, or zip packages of rule files
        #[arg(required = true, value_name = "PATH")]
        sources: Vec<PathBuf>,

        /// Where to write the bundle
        #[arg(long, short, value_name = "FILE")]
        out: PathBuf,

        /// Leave out the rules that ship inside Warden
        #[arg(long)]
        no_builtin: bool,

        /// Creation time to record, in seconds since the Unix epoch
        #[arg(long, value_name = "SECONDS", env = "SOURCE_DATE_EPOCH")]
        created: Option<u64>,

        /// List every rule that was left out, with the reason
        #[arg(long)]
        show_skipped: bool,
    },

    /// Show what is in a rule bundle
    Info {
        /// The bundle to describe
        #[arg(value_name = "FILE")]
        bundle: PathBuf,

        /// Print the description as JSON
        #[arg(long)]
        json: bool,
    },
}

pub fn run(command: RulesCommand) -> anyhow::Result<ExitCode> {
    match command {
        RulesCommand::Build {
            sources,
            out,
            no_builtin,
            created,
            show_skipped,
        } => build(&sources, &out, no_builtin, created, show_skipped),
        RulesCommand::Info { bundle, json } => info(&bundle, json),
    }
}

fn rule_count(count: u64) -> String {
    format!(
        "{} {}",
        group_digits(count),
        if count == 1 { "rule" } else { "rules" }
    )
}

fn build(
    sources: &[PathBuf],
    out: &Path,
    no_builtin: bool,
    created: Option<u64>,
    show_skipped: bool,
) -> anyhow::Result<ExitCode> {
    let mut builder = BundleBuilder::new().builtin_rules(!no_builtin);
    if let Some(created) = created {
        builder = builder.created_unix_secs(created);
    }
    for source in sources {
        builder.add_path(source)?;
    }
    let built = builder.build()?;
    write_bundle(out, &built.bytes)?;

    let report = &built.report;
    println!(
        "Compiled {} from {} {} in {}",
        rule_count(report.rules),
        group_digits(report.sources.len() as u64),
        if report.sources.len() == 1 {
            "file"
        } else {
            "files"
        },
        human_duration(report.compile_time)
    );
    for source in &report.sources {
        let mut line = format!("  {}: {}", shown(&source.name), rule_count(source.rules));
        if source.skipped > 0 {
            line.push_str(&format!(", {} left out", group_digits(source.skipped)));
        }
        if source.replaced_invalid_text {
            line.push_str(", contained bytes that are not valid text");
        }
        println!("{line}");
    }
    if report.skipped_total > 0 {
        println!(
            "Left out {} that did not compile.",
            rule_count(report.skipped_total)
        );
        if show_skipped {
            for skipped in &report.skipped {
                println!("  {}: {}", shown(&skipped.rule), shown(&skipped.reason));
            }
            if report.skipped_total > report.skipped.len() as u64 {
                println!("  ... and more; the list was cut short.");
            }
        } else {
            println!("Run again with --show-skipped to list them with the reason.");
        }
    }
    if report.warnings > 0 {
        println!(
            "The compiler issued {} {} about rules it did compile.",
            group_digits(report.warnings),
            if report.warnings == 1 {
                "warning"
            } else {
                "warnings"
            }
        );
    }
    println!(
        "Wrote {} ({}), digest {}",
        out.display(),
        human_bytes(built.bundle.size_bytes()),
        hex::encode(&built.bundle.digest())
    );
    println!("Rules keep the licences their authors gave them. `warden rules info` lists them.");
    Ok(ExitCode::SUCCESS)
}

#[derive(Debug, Serialize)]
struct Scores {
    /// Rules whose matches are reported as malicious.
    malicious: u64,
    /// Rules whose matches are reported as suspicious.
    suspicious: u64,
    /// Rules whose matches are recorded without changing the verdict.
    recorded_only: u64,
    /// Rules that state no score and are given the default.
    unscored: u64,
}

#[derive(Debug, Serialize)]
struct LicenceCount {
    /// The licence as the rules name it; empty when they name none.
    licence: String,
    rules: u64,
}

#[derive(Debug, Serialize)]
struct BundleInfo<'a> {
    path: String,
    rules: u32,
    created_unix_secs: u64,
    created: String,
    engine: &'a str,
    size_bytes: u64,
    digest: String,
    sources: &'a [SourceInfo],
    scores: Scores,
    licences: Vec<LicenceCount>,
}

fn info(path: &Path, json: bool) -> anyhow::Result<ExitCode> {
    let bundle = RuleBundle::open(path)?;
    let detector = YaraDetector::new(bundle);
    let stats = detector.rule_stats();
    let bundle = detector.bundle();

    let mut licences: Vec<LicenceCount> = stats
        .licences
        .into_iter()
        .map(|(licence, rules)| LicenceCount { licence, rules })
        .collect();
    licences.sort_by(|left, right| {
        right
            .rules
            .cmp(&left.rules)
            .then_with(|| left.licence.cmp(&right.licence))
    });
    let description = BundleInfo {
        path: path.display().to_string(),
        rules: bundle.rule_count(),
        created_unix_secs: bundle.created_unix_secs(),
        created: human_timestamp(bundle.created_unix_secs()),
        engine: &bundle.manifest().engine,
        size_bytes: bundle.size_bytes(),
        digest: hex::encode(&bundle.digest()),
        sources: &bundle.manifest().sources,
        scores: Scores {
            malicious: stats.high,
            suspicious: stats.medium,
            recorded_only: stats.low,
            unscored: stats.unscored,
        },
        licences,
    };

    if json {
        let text = serde_json::to_string_pretty(&description)
            .context("cannot describe the bundle as JSON")?;
        println!("{text}");
        return Ok(ExitCode::SUCCESS);
    }

    println!("Rule bundle  {}", description.path);
    println!(
        "Rules        {}",
        group_digits(u64::from(description.rules))
    );
    println!("Built        {}", description.created);
    println!("Engine       {}", description.engine);
    println!("Size         {}", human_bytes(description.size_bytes));
    println!("Digest       {}", description.digest);
    println!();
    println!("A match is reported as");
    println!(
        "  malicious      for {} (score 80 and above)",
        rule_count(description.scores.malicious)
    );
    println!(
        "  suspicious     for {} (score 60 to 79)",
        rule_count(description.scores.suspicious)
    );
    println!(
        "  recorded only  for {} (score below 60)",
        rule_count(description.scores.recorded_only)
    );
    if description.scores.unscored > 0 {
        println!(
            "  {} state no score and count as 75.",
            rule_count(description.scores.unscored)
        );
    }
    println!();
    println!("Rule files");
    for source in description.sources {
        let mut line = format!("  {}: {}", shown(&source.name), rule_count(source.rules));
        if source.skipped > 0 {
            line.push_str(&format!(", {} left out", group_digits(source.skipped)));
        }
        println!("{line}");
        println!("    sha256 {}", source.sha256);
    }
    println!();
    println!("Licences named by the rules");
    for entry in description.licences.iter().take(LICENCES_SHOWN) {
        let name = if entry.licence.is_empty() {
            "(none named)".to_owned()
        } else {
            shown(&entry.licence)
        };
        println!("  {:>7}  {name}", group_digits(entry.rules));
    }
    if description.licences.len() > LICENCES_SHOWN {
        let rest: u64 = description.licences[LICENCES_SHOWN..]
            .iter()
            .map(|entry| entry.rules)
            .sum();
        println!(
            "  {:>7}  under {} other licences (use --json for all of them)",
            group_digits(rest),
            description.licences.len() - LICENCES_SHOWN
        );
    }
    Ok(ExitCode::SUCCESS)
}

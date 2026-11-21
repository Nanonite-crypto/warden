//! `warden rules`: build and inspect YARA rule bundles.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::Context;
use clap::Subcommand;
use serde::Serialize;
use warden_sigdb::hex;
use warden_yara::{
    BundleBuilder, ExclusionInfo, ExclusionList, Layout, RuleBundle, SourceInfo, YaraDetector,
    write_bundle,
};

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
    ///
    /// Rules that flag clean files can be left out with --exclusions. The
    /// bundle records which list it was built with and which rules that
    /// removed, and `warden rules info` shows it.
    ///
    /// A bundle keeps its contents under a cipher. Rules are made of the
    /// byte patterns of the malware they describe, and an antivirus that
    /// finds those patterns in a file removes the file. The cipher is not a
    /// secret: the key is in the bundle.
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

        /// Leave out the rules named in this exclusion list
        ///
        /// The list is a TOML file. Every entry names a rule and gives the
        /// evidence against it: a clean file the rule flagged, with its
        /// SHA-256, the day and the machine. See docs/RULES.md.
        #[arg(long, value_name = "FILE")]
        exclusions: Option<PathBuf>,

        /// Creation time to record, in seconds since the Unix epoch
        #[arg(long, value_name = "SECONDS", env = "SOURCE_DATE_EPOCH")]
        created: Option<u64>,

        /// Store the rules as they are, not under a cipher
        ///
        /// An antivirus may take such a bundle for malware and remove it.
        /// Use this to look at what a bundle holds with other tools.
        #[arg(long)]
        plain: bool,

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
            exclusions,
            created,
            plain,
            show_skipped,
        } => build(
            &sources,
            &out,
            no_builtin,
            exclusions.as_deref(),
            created,
            if plain { Layout::Plain } else { Layout::Sealed },
            show_skipped,
        ),
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

/// How `rules build` and `rules info` name a layout.
fn layout_in_words(layout: Layout) -> &'static str {
    match layout {
        Layout::Plain => "contents as they are",
        Layout::Sealed => "contents under a cipher",
    }
}

fn build(
    sources: &[PathBuf],
    out: &Path,
    no_builtin: bool,
    exclusions: Option<&Path>,
    created: Option<u64>,
    layout: Layout,
    show_skipped: bool,
) -> anyhow::Result<ExitCode> {
    let mut builder = BundleBuilder::new()
        .builtin_rules(!no_builtin)
        .layout(layout);
    if let Some(created) = created {
        builder = builder.created_unix_secs(created);
    }
    if let Some(path) = exclusions {
        let list = ExclusionList::load(path)
            .with_context(|| format!("cannot use the exclusion list {}", path.display()))?;
        builder = builder.exclusions(list);
    }
    for source in sources {
        builder.add_path(source)?;
    }
    let built = builder.build()?;
    write_bundle(out, &built.bytes)?;

    let report = &built.report;
    outln!(
        "Compiled {} from {} {} in {}",
        rule_count(report.rules),
        group_digits(report.sources.len() as u64),
        if report.sources.len() == 1 {
            "file"
        } else {
            "files"
        },
        human_duration(report.compile_time)
    )?;
    for source in &report.sources {
        let mut line = format!("  {}: {}", shown(&source.name), rule_count(source.rules));
        if source.skipped > 0 {
            line.push_str(&format!(", {} left out", group_digits(source.skipped)));
        }
        if source.excluded > 0 {
            line.push_str(&format!(", {} excluded", group_digits(source.excluded)));
        }
        if source.replaced_invalid_text {
            line.push_str(", contained bytes that are not valid text");
        }
        outln!("{line}")?;
    }
    let generated = built.bundle.generated_rules();
    if generated > 0 {
        outln!(
            "A tool generated {} of them. A match of one counts only together with a sign from another layer.",
            group_digits(generated)
        )?;
    }
    if let Some(path) = exclusions {
        if report.excluded.is_empty() {
            outln!(
                "The exclusion list {} names no rule that is in these files.",
                path.display()
            )?;
        } else {
            outln!(
                "Excluded {}, named in {}:",
                rule_count(report.excluded.len() as u64),
                path.display()
            )?;
            for entry in &report.excluded {
                outln!("  {} (in {})", shown(&entry.rule), shown(&entry.source))?;
            }
        }
        if !report.unused_exclusions.is_empty() {
            outln!(
                "The list also names {} that no rule file declares:",
                rule_count(report.unused_exclusions.len() as u64)
            )?;
            for name in &report.unused_exclusions {
                outln!("  {}", shown(name))?;
            }
            outln!("Check the spelling, or remove the entry if the rule set dropped the rule.")?;
        }
    }
    if report.skipped_total > 0 {
        outln!(
            "Left out {} that could not be used.",
            rule_count(report.skipped_total)
        )?;
        if show_skipped {
            for skipped in &report.skipped {
                outln!("  {}: {}", shown(&skipped.rule), shown(&skipped.reason))?;
            }
            if report.skipped_total > report.skipped.len() as u64 {
                outln!("  ... and more; the list was cut short.")?;
            }
        } else {
            outln!("Run again with --show-skipped to list them with the reason.")?;
        }
    }
    if report.warnings > 0 {
        outln!(
            "The compiler issued {} {} about rules it did compile.",
            group_digits(report.warnings),
            if report.warnings == 1 {
                "warning"
            } else {
                "warnings"
            }
        )?;
    }
    outln!(
        "Wrote {} ({}, {}), digest {}",
        out.display(),
        human_bytes(built.bundle.size_bytes()),
        layout_in_words(built.bundle.layout()),
        hex::encode(&built.bundle.digest())
    )?;
    if built.bundle.layout() == Layout::Plain {
        outln!(
            "An antivirus may take a bundle with its contents as they are for malware and remove it."
        )?;
    }
    outln!("Rules keep the licences their authors gave them. `warden rules info` lists them.")?;
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
    /// Rules that a tool generated. A match counts only together with a
    /// sign from another layer, and is then reported as suspicious.
    with_second_sign: u64,
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
    /// Version of the bundle format: 1 stores the contents as they are, 2
    /// under a cipher.
    format_version: u32,
    rules: u32,
    created_unix_secs: u64,
    created: String,
    engine: &'a str,
    size_bytes: u64,
    digest: String,
    sources: &'a [SourceInfo],
    /// The exclusion list the bundle was built with, if any.
    exclusions: Option<&'a ExclusionInfo>,
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
        format_version: bundle.layout().version(),
        rules: bundle.rule_count(),
        created_unix_secs: bundle.created_unix_secs(),
        created: human_timestamp(bundle.created_unix_secs()),
        engine: &bundle.manifest().engine,
        size_bytes: bundle.size_bytes(),
        digest: hex::encode(&bundle.digest()),
        sources: &bundle.manifest().sources,
        exclusions: bundle.manifest().exclusions.as_ref(),
        scores: Scores {
            malicious: stats.high,
            suspicious: stats.medium,
            recorded_only: stats.low,
            with_second_sign: stats.generated,
            unscored: stats.unscored,
        },
        licences,
    };

    if json {
        let text = serde_json::to_string_pretty(&description)
            .context("cannot describe the bundle as JSON")?;
        outln!("{text}")?;
        return Ok(ExitCode::SUCCESS);
    }

    outln!("Rule bundle  {}", description.path)?;
    outln!(
        "Format       version {}, {}",
        description.format_version,
        layout_in_words(bundle.layout())
    )?;
    outln!(
        "Rules        {}",
        group_digits(u64::from(description.rules))
    )?;
    outln!("Built        {}", description.created)?;
    outln!("Engine       {}", description.engine)?;
    outln!("Size         {}", human_bytes(description.size_bytes))?;
    outln!("Digest       {}", description.digest)?;
    outln!()?;
    outln!("A match is reported as")?;
    outln!(
        "  malicious      for {} (score 80 and above)",
        rule_count(description.scores.malicious)
    )?;
    outln!(
        "  suspicious     for {} (score 60 to 79)",
        rule_count(description.scores.suspicious)
    )?;
    outln!(
        "  recorded only  for {} (score below 60)",
        rule_count(description.scores.recorded_only)
    )?;
    if description.scores.with_second_sign > 0 {
        outln!(
            "  suspicious, and only with a second sign from another layer,\n                 for {} that a tool generated",
            rule_count(description.scores.with_second_sign)
        )?;
    }
    if description.scores.unscored > 0 {
        outln!(
            "  {} state no score and count as 75.",
            rule_count(description.scores.unscored)
        )?;
    }
    outln!()?;
    outln!("Rule files")?;
    for source in description.sources {
        let mut line = format!("  {}: {}", shown(&source.name), rule_count(source.rules));
        if source.skipped > 0 {
            line.push_str(&format!(", {} left out", group_digits(source.skipped)));
        }
        if source.excluded > 0 {
            line.push_str(&format!(", {} excluded", group_digits(source.excluded)));
        }
        outln!("{line}")?;
        outln!("    sha256 {}", source.sha256)?;
    }
    outln!()?;
    if let Some(exclusions) = description.exclusions {
        outln!("Excluded on purpose")?;
        if exclusions.rules.is_empty() {
            outln!("  (nothing: the exclusion list named no rule that was in the rule files)")?;
        }
        for rule in &exclusions.rules {
            outln!("  {}", shown(rule))?;
        }
        outln!(
            "  named by the exclusion list with sha256 {}",
            exclusions.sha256
        )?;
        outln!()?;
    }
    outln!("Licences named by the rules")?;
    for entry in description.licences.iter().take(LICENCES_SHOWN) {
        let name = if entry.licence.is_empty() {
            "(none named)".to_owned()
        } else {
            shown(&entry.licence)
        };
        outln!("  {:>7}  {name}", group_digits(entry.rules))?;
    }
    if description.licences.len() > LICENCES_SHOWN {
        let rest: u64 = description.licences[LICENCES_SHOWN..]
            .iter()
            .map(|entry| entry.rules)
            .sum();
        outln!(
            "  {:>7}  under {} other licences (use --json for all of them)",
            group_digits(rest),
            description.licences.len() - LICENCES_SHOWN
        )?;
    }
    Ok(ExitCode::SUCCESS)
}

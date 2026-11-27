//! `warden trust`: who signed a file, and whether Warden trusts that
//! publisher.
//!
//! `check` explains one file route by route. `list` shows the publishers
//! that are part of the program. `survey` checks every file of a folder
//! and counts: how many files each route covers, who signs them, and how
//! long a check takes. That is where the numbers in `docs/BENCHMARKS.md`
//! come from.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use clap::{Args, Subcommand};
use serde::Serialize;
use warden_engine::ENGINE_VERSION;
use warden_trust::{
    Anchor, Examination, Found, Options, Reason, Revocation, Route, Signer, Trust, TrustList,
    Verifier,
};

use crate::EXIT_FOUND;
use crate::render::{group_digits, human_duration, shown, shown_path};
use crate::system::{SystemInfo, system_info};

#[derive(Debug, Subcommand)]
pub enum TrustCommand {
    /// Say who signed files, and whether Warden trusts the publisher
    ///
    /// For each file, shows what the three routes to a signature found:
    /// a signature inside the file, a catalogue of Windows that lists the
    /// file, and the signature of the app package the file belongs to.
    /// Exits with 1 if a file is not trusted.
    Check(CheckArgs),

    /// Show the trusted publishers that are part of the program
    List(ListArgs),

    /// Check every file in folders and count what was found
    ///
    /// Counts the files each route covers, who signed them, and how long
    /// a check takes. Signers that are not on the trust list are counted
    /// and not named, unless --signers is given.
    Survey(SurveyArgs),
}

#[derive(Debug, Args)]
pub struct CheckArgs {
    /// Files to check
    #[arg(required = true, value_name = "FILE")]
    files: Vec<PathBuf>,

    /// Print the results as JSON on standard output
    #[arg(long)]
    json: bool,

    /// Do not let Windows ask over the network whether a certificate was
    /// revoked; use only what it has stored
    #[arg(long)]
    offline: bool,
}

#[derive(Debug, Args)]
pub struct ListArgs {
    /// Print the list as JSON on standard output
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
pub struct SurveyArgs {
    /// Folders or files to go through
    #[arg(required = true, value_name = "PATH")]
    paths: Vec<PathBuf>,

    /// Worker threads (default: one per logical CPU, up to 16)
    #[arg(long, value_name = "N")]
    threads: Option<usize>,

    /// Name every signer that was seen, also those not on the trust list
    #[arg(long)]
    signers: bool,

    /// Name one file for each line of the counts: one that was trusted
    /// for each publisher and route, and one for each reason a file was
    /// not. This names files of programs that are installed, so think
    /// before publishing results made with it
    #[arg(long)]
    examples: bool,

    /// Do not let Windows ask over the network whether a certificate was
    /// revoked; use only what it has stored
    #[arg(long)]
    offline: bool,

    /// Print the results as JSON on standard output
    #[arg(long)]
    json: bool,

    /// Also write the JSON results to this file
    #[arg(long, value_name = "FILE")]
    output: Option<PathBuf>,

    /// Free text stored with the results, for example what was surveyed
    #[arg(long, value_name = "TEXT")]
    label: Option<String>,
}

pub fn run(command: &TrustCommand) -> anyhow::Result<ExitCode> {
    match command {
        TrustCommand::Check(args) => check(args),
        TrustCommand::List(args) => list(args),
        TrustCommand::Survey(args) => survey(args),
    }
}

/// The verifier every command uses: the built-in list, on this system.
fn verifier(offline: bool) -> anyhow::Result<Verifier> {
    let list = TrustList::builtin().context("the built-in trust list is broken")?;
    Ok(Verifier::new(list, Options { network: !offline }))
}

// --- check ----------------------------------------------------------------

#[derive(Debug, Serialize)]
struct CheckedFile<'a> {
    path: String,
    #[serde(flatten)]
    examination: &'a Examination,
}

fn check(args: &CheckArgs) -> anyhow::Result<ExitCode> {
    let verifier = verifier(args.offline)?;
    let examined: Vec<(&PathBuf, Examination)> = args
        .files
        .iter()
        .map(|path| (path, verifier.examine(path, None, true)))
        .collect();

    if args.json {
        let files: Vec<CheckedFile<'_>> = examined
            .iter()
            .map(|(path, examination)| CheckedFile {
                path: path.to_string_lossy().into_owned(),
                examination,
            })
            .collect();
        outln!("{}", serde_json::to_string_pretty(&files)?)?;
    } else {
        for (index, (path, examination)) in examined.iter().enumerate() {
            if index > 0 {
                outln!()?;
            }
            out!("{}", check_text(path, examination))?;
        }
    }

    let all_trusted = examined
        .iter()
        .all(|(_, examination)| examination.trust.is_trusted());
    Ok(if all_trusted {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(EXIT_FOUND)
    })
}

/// A route's name at the start of a line.
fn route_label(route: Route) -> &'static str {
    match route {
        Route::Embedded => "In the file",
        Route::WindowsCatalog => "Catalogue",
        Route::Package => "Package",
    }
}

fn signer_lines(out: &mut String, signer: &Signer) {
    let organization =
        if signer.organization.is_empty() || signer.organization == signer.common_name {
            String::new()
        } else {
            format!(" ({})", shown(&signer.organization))
        };
    out.push_str(&format!(
        "              signed for {}{organization}\n",
        shown(&signer.common_name)
    ));
    let chain: Vec<String> = signer
        .chain
        .iter()
        .map(|certificate| shown(&certificate.subject))
        .collect();
    out.push_str(&format!("              chain: {}\n", chain.join(" < ")));
    out.push_str(&format!(
        "              the chain ends in a root of Microsoft's: {}; revocation: {}\n",
        if signer.microsoft_root { "yes" } else { "no" },
        match signer.revocation {
            Revocation::Checked => "checked, nothing revoked",
            Revocation::Unknown => "could not be checked",
        }
    ));
}

fn check_text(path: &Path, examination: &Examination) -> String {
    let mut out = format!("{}\n", shown_path(path));
    match &examination.trust {
        Trust::Trusted { publisher, route } => out.push_str(&format!(
            "  Trusted     yes: signed for {}, a publisher on the trust list, found in {}\n",
            shown(publisher),
            route.in_words()
        )),
        Trust::NotTrusted { detail, .. } => {
            out.push_str(&format!("  Trusted     no: {}\n", shown(detail)));
        }
    }
    if let Some(sha256) = &examination.sha256 {
        out.push_str(&format!("  SHA-256     {sha256}\n"));
    }
    for report in &examination.routes {
        let label = route_label(report.route);
        match &report.found {
            Found::Nothing => out.push_str(&format!("  {label:<11} no signature\n")),
            Found::Valid { signer, place } => {
                out.push_str(&format!("  {label:<11} a signature that holds"));
                if let Some(place) = place {
                    out.push_str(&format!(", in {}", shown(place)));
                }
                out.push('\n');
                signer_lines(&mut out, signer);
            }
            Found::Invalid { why } => {
                out.push_str(&format!("  {label:<11} does not hold: {}\n", shown(why)))
            }
            Found::NotApplicable { why } => {
                out.push_str(&format!("  {label:<11} not tried: {}\n", shown(why)));
            }
            Found::Failed { why } => {
                out.push_str(&format!(
                    "  {label:<11} could not be tried: {}\n",
                    shown(why)
                ));
            }
        }
    }
    out
}

// --- list -----------------------------------------------------------------

#[derive(Debug, Serialize)]
struct ListedEvidence<'a> {
    file: &'a str,
    sha256: &'a str,
    route: Route,
    seen: &'a str,
    machine: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<&'a str>,
}

#[derive(Debug, Serialize)]
struct ListedPublisher<'a> {
    name: &'a str,
    common_name: &'a str,
    organization: &'a str,
    anchor: String,
    operating_system: bool,
    signs: &'a str,
    reason: &'a str,
    added: &'a str,
    evidence: Vec<ListedEvidence<'a>>,
}

#[derive(Debug, Serialize)]
struct ListReport<'a> {
    sha256: &'a str,
    publishers: Vec<ListedPublisher<'a>>,
}

fn anchor_in_words(anchor: &Anchor) -> String {
    match anchor {
        Anchor::MicrosoftRoot => "one of Microsoft's own root certificates".to_owned(),
        Anchor::Certificate(_) => format!("the certificate {anchor}"),
    }
}

fn list(args: &ListArgs) -> anyhow::Result<ExitCode> {
    let list = TrustList::builtin().context("the built-in trust list is broken")?;
    if args.json {
        let report = ListReport {
            sha256: list.digest(),
            publishers: list
                .publishers()
                .iter()
                .map(|publisher| ListedPublisher {
                    name: &publisher.name,
                    common_name: &publisher.common_name,
                    organization: &publisher.organization,
                    anchor: publisher.anchor.to_string(),
                    operating_system: publisher.operating_system,
                    signs: &publisher.signs,
                    reason: &publisher.reason,
                    added: &publisher.added,
                    evidence: publisher
                        .evidence
                        .iter()
                        .map(|evidence| ListedEvidence {
                            file: &evidence.file,
                            sha256: &evidence.sha256,
                            route: evidence.route,
                            seen: &evidence.seen,
                            machine: &evidence.machine,
                            note: evidence.note.as_deref(),
                        })
                        .collect(),
                })
                .collect(),
        };
        outln!("{}", serde_json::to_string_pretty(&report)?)?;
        return Ok(ExitCode::SUCCESS);
    }

    outln!(
        "{} on the trust list that is part of this program (SHA-256 {})",
        match list.len() {
            1 => "1 publisher".to_owned(),
            count => format!("{count} publishers"),
        },
        list.digest()
    )?;
    for publisher in list.publishers() {
        outln!()?;
        outln!("{}", shown(&publisher.name))?;
        outln!(
            "  Certificate  name {:?}, organisation {:?}",
            publisher.common_name,
            publisher.organization
        )?;
        outln!(
            "  Chain        has to pass through {}",
            anchor_in_words(&publisher.anchor)
        )?;
        if publisher.operating_system {
            outln!(
                "  Quarantine   leaves its files where they are: this is the operating system itself"
            )?;
        }
        outln!("  Signs        {}", shown(&publisher.signs))?;
        outln!("  Why          {}", shown(&publisher.reason))?;
        outln!("  Added        {}", publisher.added)?;
        for evidence in &publisher.evidence {
            outln!(
                "  Seen         {} on {}, found in {}:",
                evidence.seen,
                shown(&evidence.machine),
                evidence.route.in_words()
            )?;
            outln!("               {}", shown(&evidence.file))?;
            outln!("               SHA-256 {}", evidence.sha256)?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

// --- survey ---------------------------------------------------------------

/// How one file came out, for the timing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Outcome {
    Trusted(Route),
    NotTrusted,
}

impl Outcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Trusted(route) => route.as_str(),
            Self::NotTrusted => "not_trusted",
        }
    }
}

/// A number of files, and how many of them are Windows executables.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
struct Count {
    files: u64,
    executables: u64,
}

impl Count {
    fn add(&mut self, executable: bool) {
        self.files += 1;
        self.executables += u64::from(executable);
    }

    fn merge(&mut self, other: Self) {
        self.files += other.files;
        self.executables += other.executables;
    }
}

/// Who signed, as far as a survey tells signers apart.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SignerKey {
    common_name: String,
    organization: String,
    microsoft_root: bool,
}

#[derive(Debug, Default, Clone)]
struct SignerSeen {
    files: u64,
    by_route: BTreeMap<Route, u64>,
    listed_as: Option<String>,
    revocation_unknown: u64,
    /// The root the first such chain ended in: who it is for, and its
    /// SHA-256.
    root: Option<(String, String)>,
}

/// What one worker counted.
#[derive(Debug, Default)]
struct Tally {
    all: Count,
    trusted: BTreeMap<(String, Route), Count>,
    not_trusted: BTreeMap<Reason, Count>,
    signers: BTreeMap<SignerKey, SignerSeen>,
    /// What the check said where a signature did not hold or could not be
    /// checked, with one file each. Those explanations name no file and no
    /// signer.
    details: BTreeMap<(Reason, String), (u64, String)>,
    micros: BTreeMap<Outcome, Vec<u32>>,
    examples: BTreeMap<(String, Route), (String, String)>,
    /// One file for each reason a file was not trusted.
    untrusted_examples: BTreeMap<Reason, String>,
    walk_errors: u64,
}

impl Tally {
    fn add(&mut self, list: &TrustList, path: &Path, examination: &Examination, took: Duration) {
        let executable = examination.executable == Some(true);
        self.all.add(executable);
        let outcome = match &examination.trust {
            Trust::Trusted { publisher, route } => {
                let key = (publisher.clone(), *route);
                if let Some(sha256) = &examination.sha256 {
                    self.examples
                        .entry(key.clone())
                        .or_insert_with(|| (path.to_string_lossy().into_owned(), sha256.clone()));
                }
                self.trusted.entry(key).or_default().add(executable);
                Outcome::Trusted(*route)
            }
            Trust::NotTrusted { reason, detail } => {
                self.not_trusted.entry(*reason).or_default().add(executable);
                self.untrusted_examples
                    .entry(*reason)
                    .or_insert_with(|| path.to_string_lossy().into_owned());
                if matches!(
                    reason,
                    Reason::Invalid | Reason::NotChecked | Reason::Changed
                ) {
                    self.details
                        .entry((*reason, detail.clone()))
                        .or_insert_with(|| (0, path.to_string_lossy().into_owned()))
                        .0 += 1;
                }
                Outcome::NotTrusted
            }
        };
        self.micros
            .entry(outcome)
            .or_default()
            .push(u32::try_from(took.as_micros()).unwrap_or(u32::MAX));

        // Every signature that holds, on whichever route it was found. A
        // file can have two: its own, and the one of its package. Whether
        // a signer is on the list is for the list to say, not for the
        // answer about the file: a file can be trusted through its package
        // and carry a signature of somebody else.
        for report in &examination.routes {
            let Found::Valid { signer, .. } = &report.found else {
                continue;
            };
            let seen = self
                .signers
                .entry(SignerKey {
                    common_name: signer.common_name.clone(),
                    organization: signer.organization.clone(),
                    microsoft_root: signer.microsoft_root,
                })
                .or_default();
            seen.files += 1;
            *seen.by_route.entry(report.route).or_insert(0) += 1;
            if signer.revocation == Revocation::Unknown {
                seen.revocation_unknown += 1;
            }
            if seen.root.is_none() {
                seen.root = signer
                    .chain
                    .last()
                    .map(|root| (root.subject.clone(), root.sha256.clone()));
            }
            if seen.listed_as.is_none() {
                seen.listed_as = list
                    .publisher_of(signer)
                    .map(|publisher| publisher.name.clone());
            }
        }
    }

    fn merge(&mut self, other: Self) {
        self.all.merge(other.all);
        self.walk_errors += other.walk_errors;
        for (key, count) in other.trusted {
            self.trusted.entry(key).or_default().merge(count);
        }
        for (key, count) in other.not_trusted {
            self.not_trusted.entry(key).or_default().merge(count);
        }
        for (key, seen) in other.signers {
            let mine = self.signers.entry(key).or_default();
            mine.files += seen.files;
            mine.revocation_unknown += seen.revocation_unknown;
            for (route, count) in seen.by_route {
                *mine.by_route.entry(route).or_insert(0) += count;
            }
            if mine.listed_as.is_none() {
                mine.listed_as = seen.listed_as;
            }
            if mine.root.is_none() {
                mine.root = seen.root;
            }
        }
        for (outcome, micros) in other.micros {
            self.micros.entry(outcome).or_default().extend(micros);
        }
        for (key, example) in other.examples {
            self.examples.entry(key).or_insert(example);
        }
        for (reason, example) in other.untrusted_examples {
            self.untrusted_examples.entry(reason).or_insert(example);
        }
        for (key, (files, example)) in other.details {
            self.details.entry(key).or_insert((0, example)).0 += files;
        }
    }
}

#[derive(Debug, Serialize)]
struct Timing {
    outcome: &'static str,
    files: u64,
    mean_ms: f64,
    median_ms: f64,
    p95_ms: f64,
    max_ms: f64,
}

fn timing(outcome: &'static str, micros: &mut [u32]) -> Option<Timing> {
    if micros.is_empty() {
        return None;
    }
    micros.sort_unstable();
    let ms = |micros: u32| f64::from(micros) / 1000.0;
    let at = |fraction: f64| {
        let index = ((micros.len() - 1) as f64 * fraction).round() as usize;
        ms(micros[index.min(micros.len() - 1)])
    };
    let total: u64 = micros.iter().map(|&value| u64::from(value)).sum();
    Some(Timing {
        outcome,
        files: micros.len() as u64,
        mean_ms: total as f64 / micros.len() as f64 / 1000.0,
        median_ms: at(0.5),
        p95_ms: at(0.95),
        max_ms: ms(micros[micros.len() - 1]),
    })
}

#[derive(Debug, Serialize)]
struct TrustedCount {
    publisher: String,
    route: Route,
    #[serde(flatten)]
    count: Count,
    #[serde(skip_serializing_if = "Option::is_none")]
    example: Option<Example>,
}

#[derive(Debug, Serialize)]
struct Example {
    path: String,
    sha256: String,
}

#[derive(Debug, Serialize)]
struct ReasonCount {
    reason: Reason,
    #[serde(flatten)]
    count: Count,
    /// One such file, with --examples.
    #[serde(skip_serializing_if = "Option::is_none")]
    example: Option<String>,
}

/// What the check said about files whose signature did not hold or could
/// not be checked.
#[derive(Debug, Serialize)]
struct DetailCount {
    reason: Reason,
    detail: String,
    files: u64,
    /// One such file, with --examples.
    #[serde(skip_serializing_if = "Option::is_none")]
    example: Option<String>,
}

/// How many different explanations a survey lists.
const DETAILS_LISTED: usize = 40;

#[derive(Debug, Serialize)]
struct SignerCount {
    common_name: String,
    organization: String,
    microsoft_root: bool,
    /// The name the trust list has for this signer, if it is on it.
    #[serde(skip_serializing_if = "Option::is_none")]
    listed_as: Option<String>,
    /// Files a signature of this signer was found on that holds, and by
    /// which route. A file with a signature of its own in a signed package
    /// counts for both signers, unless its own signature already made it
    /// trusted: the check stops there.
    files: u64,
    embedded: u64,
    windows_catalog: u64,
    package: u64,
    revocation_unknown: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    root_sha256: Option<String>,
}

/// Signers that are not on the trust list, counted and not named.
#[derive(Debug, Default, Serialize)]
struct Unlisted {
    signers: u64,
    /// Files with a signature of one of them that holds. Such a file can
    /// still be trusted, through its package.
    files: u64,
    /// How many of those signers have a chain that ends in a root of
    /// Microsoft's.
    signers_under_a_microsoft_root: u64,
    files_under_a_microsoft_root: u64,
}

/// Version of the JSON layout below.
const SURVEY_SCHEMA: u32 = 1;

#[derive(Debug, Serialize)]
struct SurveyReport {
    schema: u32,
    label: Option<String>,
    engine_version: &'static str,
    system: SystemInfo,
    paths: Vec<String>,
    /// SHA-256 of the trust list in use.
    trust_list: String,
    publishers_listed: u64,
    /// Whether Windows could ask over the network if a certificate was
    /// revoked.
    network: bool,
    threads: usize,
    duration_ms: u64,
    /// Files checked, and how many of them are Windows executables. Only
    /// for those is a signature looked for in the file and in the
    /// catalogues; any other file can be trusted as part of a package and
    /// no other way.
    files: u64,
    executables: u64,
    /// Folders and entries that could not be listed.
    could_not_list: u64,
    files_trusted: u64,
    executables_trusted: u64,
    /// Trusted files by publisher and by the route the signature was
    /// found by.
    trusted: Vec<TrustedCount>,
    /// Files that are not trusted, by reason.
    not_trusted: Vec<ReasonCount>,
    /// Where a signature did not hold or could not be checked: what the
    /// check said, most files first. At most 40 are listed.
    details: Vec<DetailCount>,
    details_truncated: bool,
    /// Signers with a signature that holds: all of them with --signers,
    /// otherwise the ones on the trust list.
    signers: Vec<SignerCount>,
    signers_not_listed: Unlisted,
    /// How long one file took, from opening it to the answer. The file is
    /// read once for its SHA-256 and again by whatever checks it.
    timing: Vec<Timing>,
}

fn reason_in_words(reason: Reason) -> &'static str {
    match reason {
        Reason::NoSignature => "no signature found",
        Reason::Invalid => "a signature that does not hold, or does not cover the file",
        Reason::NotListed => "signed, by a publisher that is not on the list",
        Reason::RevocationUnknown => "a listed publisher, revocation could not be checked",
        Reason::Changed => "changed while it was checked",
        Reason::NotChecked => "could not be checked",
        Reason::Unavailable => "signatures cannot be checked on this system",
    }
}

/// What a survey was asked for, as far as the report shows it.
struct SurveyContext<'a> {
    label: Option<String>,
    paths: Vec<String>,
    list: &'a TrustList,
    network: bool,
    threads: usize,
    duration: Duration,
    /// Name every signer, also those not on the list.
    signers: bool,
    /// Name one file per listed publisher and route.
    examples: bool,
}

fn report_of(mut tally: Tally, context: SurveyContext<'_>) -> SurveyReport {
    let mut examples = if context.examples {
        std::mem::take(&mut tally.examples)
    } else {
        BTreeMap::new()
    };
    let trusted: Vec<TrustedCount> = tally
        .trusted
        .iter()
        .map(|((publisher, route), &count)| TrustedCount {
            publisher: publisher.clone(),
            route: *route,
            count,
            example: examples
                .remove(&(publisher.clone(), *route))
                .map(|(path, sha256)| Example { path, sha256 }),
        })
        .collect();
    let mut all_trusted = Count::default();
    for entry in &trusted {
        all_trusted.merge(entry.count);
    }
    let not_trusted: Vec<ReasonCount> = tally
        .not_trusted
        .iter()
        .map(|(&reason, &count)| ReasonCount {
            reason,
            count,
            example: tally
                .untrusted_examples
                .remove(&reason)
                .filter(|_| context.examples),
        })
        .collect();
    let mut details: Vec<DetailCount> = std::mem::take(&mut tally.details)
        .into_iter()
        .map(|((reason, detail), (files, example))| DetailCount {
            reason,
            detail,
            files,
            example: context.examples.then_some(example),
        })
        .collect();
    details.sort_by(|left, right| {
        right
            .files
            .cmp(&left.files)
            .then_with(|| left.detail.cmp(&right.detail))
    });
    let details_truncated = details.len() > DETAILS_LISTED;
    details.truncate(DETAILS_LISTED);

    let mut unlisted = Unlisted::default();
    let mut signers = Vec::new();
    for (key, seen) in &tally.signers {
        if seen.listed_as.is_none() {
            unlisted.signers += 1;
            unlisted.files += seen.files;
            if key.microsoft_root {
                unlisted.signers_under_a_microsoft_root += 1;
                unlisted.files_under_a_microsoft_root += seen.files;
            }
            if !context.signers {
                continue;
            }
        }
        let route = |route| seen.by_route.get(&route).copied().unwrap_or(0);
        signers.push(SignerCount {
            common_name: key.common_name.clone(),
            organization: key.organization.clone(),
            microsoft_root: key.microsoft_root,
            listed_as: seen.listed_as.clone(),
            files: seen.files,
            embedded: route(Route::Embedded),
            windows_catalog: route(Route::WindowsCatalog),
            package: route(Route::Package),
            revocation_unknown: seen.revocation_unknown,
            root: seen.root.as_ref().map(|(subject, _)| subject.clone()),
            root_sha256: seen.root.as_ref().map(|(_, sha256)| sha256.clone()),
        });
    }
    signers.sort_by(|left, right| {
        right
            .files
            .cmp(&left.files)
            .then_with(|| left.common_name.cmp(&right.common_name))
    });

    let mut all: Vec<u32> = tally.micros.values().flatten().copied().collect();
    let mut timings: Vec<Timing> = timing("all", &mut all).into_iter().collect();
    for (outcome, micros) in &mut tally.micros {
        timings.extend(timing(outcome.as_str(), micros));
    }

    SurveyReport {
        schema: SURVEY_SCHEMA,
        label: context.label,
        engine_version: ENGINE_VERSION,
        system: system_info(),
        paths: context.paths,
        trust_list: context.list.digest().to_owned(),
        publishers_listed: context.list.len() as u64,
        network: context.network,
        threads: context.threads,
        duration_ms: u64::try_from(context.duration.as_millis()).unwrap_or(u64::MAX),
        files: tally.all.files,
        executables: tally.all.executables,
        could_not_list: tally.walk_errors,
        files_trusted: all_trusted.files,
        executables_trusted: all_trusted.executables,
        trusted,
        not_trusted,
        details,
        details_truncated,
        signers,
        signers_not_listed: unlisted,
        timing: timings,
    }
}

fn survey(args: &SurveyArgs) -> anyhow::Result<ExitCode> {
    let verifier = verifier(args.offline)?;
    if !verifier.available() {
        bail!("signatures can only be checked on Windows, so there is nothing to survey here");
    }
    for path in &args.paths {
        if !path.exists() {
            bail!("{} does not exist", path.display());
        }
    }
    let threads = args
        .threads
        .unwrap_or_else(|| {
            std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
        })
        .clamp(1, 16);

    // One walker for all workers: each takes the next file when it is
    // free. Links are not followed, as in a scan.
    let walker = Mutex::new(
        args.paths
            .iter()
            .flat_map(|path| walkdir::WalkDir::new(path).follow_links(false)),
    );
    let started = Instant::now();
    let mut tally = Tally::default();
    std::thread::scope(|scope| {
        let workers: Vec<_> = (0..threads)
            .map(|_| {
                scope.spawn(|| {
                    let mut tally = Tally::default();
                    loop {
                        let next = walker
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .next();
                        let entry = match next {
                            None => break,
                            Some(Ok(entry)) => entry,
                            Some(Err(_)) => {
                                tally.walk_errors += 1;
                                continue;
                            }
                        };
                        if !entry.file_type().is_file() {
                            continue;
                        }
                        let before = Instant::now();
                        let examination = verifier.examine(entry.path(), None, false);
                        tally.add(
                            verifier.list(),
                            entry.path(),
                            &examination,
                            before.elapsed(),
                        );
                    }
                    tally
                })
            })
            .collect();
        for worker in workers {
            if let Ok(counted) = worker.join() {
                tally.merge(counted);
            }
        }
    });
    let duration = started.elapsed();

    let report = report_of(
        tally,
        SurveyContext {
            label: args.label.clone(),
            paths: args
                .paths
                .iter()
                .map(|path| {
                    std::path::absolute(path)
                        .unwrap_or_else(|_| path.clone())
                        .to_string_lossy()
                        .into_owned()
                })
                .collect(),
            list: verifier.list(),
            network: !args.offline,
            threads,
            duration,
            signers: args.signers,
            examples: args.examples,
        },
    );

    if let Some(path) = &args.output {
        std::fs::write(path, serde_json::to_string_pretty(&report)?)
            .with_context(|| format!("cannot write the results to {}", path.display()))?;
    }
    if args.json {
        outln!("{}", serde_json::to_string_pretty(&report)?)?;
    } else {
        out!("{}", survey_text(&report, duration, args.signers))?;
    }
    Ok(ExitCode::SUCCESS)
}

fn percent(part: u64, whole: u64) -> String {
    if whole == 0 {
        "0 %".to_owned()
    } else {
        format!("{:.1} %", part as f64 * 100.0 / whole as f64)
    }
}

fn survey_text(report: &SurveyReport, duration: Duration, named: bool) -> String {
    let others = report.files - report.executables;
    let others_trusted = report.files_trusted - report.executables_trusted;
    let mut out = format!("Warden {}: who signed what\n\n", report.engine_version);
    if let Some(label) = &report.label {
        out.push_str(&format!("Label        {}\n", shown(label)));
    }
    for path in &report.paths {
        out.push_str(&format!("Path         {}\n", shown(path)));
    }
    out.push_str(&format!("System       {}\n", report.system.line()));
    out.push_str(&format!(
        "Trust list   {} {}; revocation {}\n",
        report.publishers_listed,
        if report.publishers_listed == 1 {
            "publisher"
        } else {
            "publishers"
        },
        if report.network {
            "asked over the network where Windows has nothing stored"
        } else {
            "from what Windows has stored only"
        }
    ));
    out.push_str(&format!(
        "\nChecked      {} files in {} on {} threads: {} Windows executables, {} other files\n",
        group_digits(report.files),
        human_duration(duration),
        report.threads,
        group_digits(report.executables),
        group_digits(others)
    ));
    if report.could_not_list > 0 {
        out.push_str(&format!(
            "Not listed   {} folders or entries could not be listed, so what is in them was not checked\n",
            group_digits(report.could_not_list)
        ));
    }
    out.push_str(&format!(
        "\nTrusted      {} of {} executables ({}), {} of {} other files ({})\n",
        group_digits(report.executables_trusted),
        group_digits(report.executables),
        percent(report.executables_trusted, report.executables),
        group_digits(others_trusted),
        group_digits(others),
        percent(others_trusted, others)
    ));
    for entry in &report.trusted {
        out.push_str(&format!(
            "  {:>9}  {}, found in {} ({} executables)\n",
            group_digits(entry.count.files),
            shown(&entry.publisher),
            entry.route.in_words(),
            group_digits(entry.count.executables)
        ));
        if let Some(example) = &entry.example {
            out.push_str(&format!(
                "             for example {}\n",
                shown(&example.path)
            ));
        }
    }
    let files_not_trusted: u64 = report
        .not_trusted
        .iter()
        .map(|entry| entry.count.files)
        .sum();
    out.push_str(&format!(
        "\nNot trusted  {} files\n",
        group_digits(files_not_trusted)
    ));
    for entry in &report.not_trusted {
        out.push_str(&format!(
            "  {:>9}  {} ({} executables)\n",
            group_digits(entry.count.files),
            reason_in_words(entry.reason),
            group_digits(entry.count.executables)
        ));
        if let Some(example) = &entry.example {
            out.push_str(&format!("             for example {}\n", shown(example)));
        }
    }
    if !report.details.is_empty() {
        out.push_str(
            "\nWhat the check said where a signature did not hold or could not be checked\n",
        );
        for entry in &report.details {
            out.push_str(&format!(
                "  {:>9}  {}\n",
                group_digits(entry.files),
                shown(&entry.detail)
            ));
            if let Some(example) = &entry.example {
                out.push_str(&format!("             for example {}\n", shown(example)));
            }
        }
        if report.details_truncated {
            out.push_str("             ... and more; the list was cut short.\n");
        }
    }
    let unlisted = &report.signers_not_listed;
    if unlisted.signers > 0 {
        out.push_str(&format!(
            "\nSigners that are not on the list: {}, with signatures on {} files. {} of them, on \
             {} files, have a chain that ends in a root of Microsoft's.\n",
            group_digits(unlisted.signers),
            group_digits(unlisted.files),
            group_digits(unlisted.signers_under_a_microsoft_root),
            group_digits(unlisted.files_under_a_microsoft_root)
        ));
    }
    if !report.signers.is_empty() {
        out.push_str(if named {
            "\nSigners\n"
        } else {
            "\nSigners on the list\n"
        });
        for signer in &report.signers {
            out.push_str(&format!(
                "  {:>9}  {}{}{}\n",
                group_digits(signer.files),
                shown(&signer.common_name),
                if signer.organization.is_empty() || signer.organization == signer.common_name {
                    String::new()
                } else {
                    format!(" ({})", shown(&signer.organization))
                },
                match &signer.listed_as {
                    Some(_) => ", on the list",
                    None if signer.microsoft_root =>
                        ", not on the list, under a root of Microsoft's",
                    None => ", not on the list",
                }
            ));
        }
    }
    out.push_str("\nTime for one file, read once to hash it and again to check it\n");
    for timing in &report.timing {
        out.push_str(&format!(
            "  {:<12} {:>9} files: half under {:.1} ms, 95 % under {:.1} ms, longest {:.0} ms\n",
            match timing.outcome {
                "all" => "all",
                "embedded" => "in the file",
                "windows_catalog" => "catalogue",
                "package" => "package",
                _ => "not trusted",
            },
            group_digits(timing.files),
            timing.median_ms,
            timing.p95_ms,
            timing.max_ms
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use warden_trust::{Certificate, RouteReport};

    use super::*;

    #[test]
    fn timing_of_a_few_values() {
        let mut micros = vec![1000, 2000, 3000, 4000, 100_000];
        let timing = timing("all", &mut micros).expect("values");
        assert_eq!(timing.files, 5);
        assert!((timing.median_ms - 3.0).abs() < 1e-9);
        assert!((timing.max_ms - 100.0).abs() < 1e-9);
        assert!((timing.mean_ms - 22.0).abs() < 1e-9);
        assert!(super::timing("all", &mut []).is_none());
    }

    #[test]
    fn percentages() {
        assert_eq!(percent(1, 4), "25.0 %");
        assert_eq!(percent(0, 0), "0 %");
    }

    fn signer(common_name: &str, microsoft_root: bool) -> Signer {
        Signer {
            common_name: common_name.to_owned(),
            organization: "An organisation".to_owned(),
            chain: vec![
                Certificate {
                    subject: common_name.to_owned(),
                    sha256: "11".repeat(32),
                },
                Certificate {
                    subject: "A root".to_owned(),
                    sha256: "22".repeat(32),
                },
            ],
            microsoft_root,
            revocation: Revocation::Checked,
        }
    }

    /// An examination as the verifier would hand it out.
    fn examined(executable: bool, route: Route, found: Found, trust: Trust) -> Examination {
        Examination {
            sha256: Some("ab".repeat(32)),
            executable: Some(executable),
            routes: vec![RouteReport { route, found }],
            trust,
        }
    }

    fn trusted(executable: bool, route: Route) -> Examination {
        examined(
            executable,
            route,
            Found::Valid {
                signer: signer("Listed Software", true),
                place: None,
            },
            Trust::Trusted {
                publisher: "Listed".to_owned(),
                route,
            },
        )
    }

    fn not_listed(common_name: &str, microsoft_root: bool) -> Examination {
        examined(
            true,
            Route::Embedded,
            Found::Valid {
                signer: signer(common_name, microsoft_root),
                place: None,
            },
            Trust::NotTrusted {
                reason: Reason::NotListed,
                detail: "not on the list".to_owned(),
            },
        )
    }

    fn does_not_hold(why: &str) -> Examination {
        examined(
            true,
            Route::Embedded,
            Found::Invalid {
                why: why.to_owned(),
            },
            Trust::NotTrusted {
                reason: Reason::Invalid,
                detail: why.to_owned(),
            },
        )
    }

    fn unsigned(executable: bool) -> Examination {
        examined(
            executable,
            Route::Embedded,
            Found::Nothing,
            Trust::NotTrusted {
                reason: Reason::NoSignature,
                detail: "no signature".to_owned(),
            },
        )
    }

    /// A list with the one publisher that the examinations above call
    /// trusted.
    fn list() -> TrustList {
        TrustList::parse(&format!(
            r#"
[[publisher]]
name = "Listed"
common_name = "Listed Software"
organization = "An organisation"
anchor = "microsoft-root"
signs = "The files of these tests."
reason = "These tests need a publisher."
added = 2026-11-21

[[publisher.evidence]]
file = "a.exe"
sha256 = "{}"
route = "embedded"
seen = 2026-11-21
machine = "a test"
"#,
            "ab".repeat(32)
        ))
        .expect("a well-formed list")
    }

    /// Counts one file as a worker would.
    fn count(tally: &mut Tally, name: &str, examination: &Examination) {
        tally.add(
            &list(),
            Path::new(name),
            examination,
            Duration::from_millis(2),
        );
    }

    /// Two workers' worth of files, merged.
    fn counted() -> Tally {
        let mut first = Tally::default();
        count(&mut first, "a.exe", &trusted(true, Route::Embedded));
        count(&mut first, "b.dll", &trusted(true, Route::WindowsCatalog));
        count(&mut first, "c.png", &trusted(false, Route::Package));
        count(&mut first, "d.exe", &not_listed("Somebody Else", false));
        first.walk_errors = 1;
        let mut second = Tally::default();
        count(&mut second, "e.exe", &trusted(true, Route::Embedded));
        count(&mut second, "f.exe", &not_listed("Somebody Else", false));
        count(&mut second, "g.sys", &not_listed("A Driver Maker", true));
        count(&mut second, "h.exe", &unsigned(true));
        count(&mut second, "i.txt", &unsigned(false));
        first.merge(second);
        first
    }

    /// The same with three files whose signature does not hold, for two
    /// different reasons.
    fn counted_with_broken_signatures() -> Tally {
        let mut first = counted();
        count(&mut first, "j.exe", &does_not_hold("changed"));
        let mut second = Tally::default();
        count(&mut second, "k.exe", &does_not_hold("changed"));
        count(&mut second, "l.exe", &does_not_hold("padded"));
        first.merge(second);
        first
    }

    fn surveyed(signers: bool, examples: bool) -> SurveyReport {
        reported(counted(), signers, examples)
    }

    fn reported(tally: Tally, signers: bool, examples: bool) -> SurveyReport {
        let list = list();
        report_of(
            tally,
            SurveyContext {
                label: Some("a test".to_owned()),
                paths: vec!["somewhere".to_owned()],
                list: &list,
                network: true,
                threads: 2,
                duration: Duration::from_secs(1),
                signers,
                examples,
            },
        )
    }

    #[test]
    fn a_signer_is_on_the_list_only_if_the_list_says_so() {
        // A program in a package: it carries a signature of somebody who
        // is on no list, and its package is signed by a listed publisher.
        // The file is trusted, through the package. Its own signer is
        // still not on the list.
        let in_a_package = Examination {
            sha256: Some("ab".repeat(32)),
            executable: Some(true),
            routes: vec![
                RouteReport {
                    route: Route::Embedded,
                    found: Found::Valid {
                        signer: signer("Somebody Else", true),
                        place: None,
                    },
                },
                RouteReport {
                    route: Route::WindowsCatalog,
                    found: Found::NotApplicable {
                        why: "it has a signature table".to_owned(),
                    },
                },
                RouteReport {
                    route: Route::Package,
                    found: Found::Valid {
                        signer: signer("Listed Software", true),
                        place: Some("a folder".to_owned()),
                    },
                },
            ],
            trust: Trust::Trusted {
                publisher: "Listed".to_owned(),
                route: Route::Package,
            },
        };
        let mut tally = Tally::default();
        count(&mut tally, "tool.exe", &in_a_package);
        let report = reported(tally, true, false);

        assert_eq!((report.files, report.files_trusted), (1, 1));
        let by_name: Vec<(&str, Option<&str>, u64, u64)> = report
            .signers
            .iter()
            .map(|signer| {
                (
                    signer.common_name.as_str(),
                    signer.listed_as.as_deref(),
                    signer.embedded,
                    signer.package,
                )
            })
            .collect();
        assert_eq!(
            by_name,
            [
                ("Listed Software", Some("Listed"), 0, 1),
                ("Somebody Else", None, 1, 0)
            ]
        );
        let unlisted = &report.signers_not_listed;
        assert_eq!((unlisted.signers, unlisted.files), (1, 1));
        assert_eq!(unlisted.signers_under_a_microsoft_root, 1);

        let text = survey_text(&report, Duration::from_secs(1), true);
        assert!(
            text.contains("Somebody Else (An organisation), not on the list"),
            "{text}"
        );
    }

    #[test]
    fn a_survey_counts_files_by_route_and_by_reason() {
        let report = surveyed(false, false);
        assert_eq!((report.files, report.executables), (9, 7));
        assert_eq!((report.files_trusted, report.executables_trusted), (4, 3));
        assert_eq!(report.could_not_list, 1);

        let by_route: Vec<(Route, u64, u64)> = report
            .trusted
            .iter()
            .map(|entry| (entry.route, entry.count.files, entry.count.executables))
            .collect();
        assert_eq!(
            by_route,
            [
                (Route::Embedded, 2, 2),
                (Route::WindowsCatalog, 1, 1),
                (Route::Package, 1, 0)
            ]
        );
        assert!(report.trusted.iter().all(|entry| entry.example.is_none()));

        let by_reason: Vec<(Reason, u64, u64)> = report
            .not_trusted
            .iter()
            .map(|entry| (entry.reason, entry.count.files, entry.count.executables))
            .collect();
        assert_eq!(
            by_reason,
            [(Reason::NoSignature, 2, 1), (Reason::NotListed, 3, 3)]
        );

        let all = &report.timing[0];
        assert_eq!((all.outcome, all.files), ("all", 9));
        let outcomes: Vec<&str> = report.timing.iter().map(|timing| timing.outcome).collect();
        assert_eq!(
            outcomes,
            [
                "all",
                "embedded",
                "windows_catalog",
                "package",
                "not_trusted"
            ]
        );
    }

    #[test]
    fn signers_that_are_not_on_the_list_are_counted_and_not_named() {
        let report = surveyed(false, false);
        let names: Vec<&str> = report
            .signers
            .iter()
            .map(|signer| signer.common_name.as_str())
            .collect();
        assert_eq!(names, ["Listed Software"]);
        assert_eq!(report.signers[0].listed_as.as_deref(), Some("Listed"));
        assert_eq!(
            (
                report.signers[0].files,
                report.signers[0].embedded,
                report.signers[0].windows_catalog,
                report.signers[0].package
            ),
            (4, 2, 1, 1)
        );
        let unlisted = &report.signers_not_listed;
        assert_eq!((unlisted.signers, unlisted.files), (2, 3));
        assert_eq!(
            (
                unlisted.signers_under_a_microsoft_root,
                unlisted.files_under_a_microsoft_root
            ),
            (1, 1)
        );

        // Neither the JSON nor the text gives the others away.
        let json = serde_json::to_string(&report).expect("serializes");
        let text = survey_text(&report, Duration::from_secs(1), false);
        for output in [&json, &text] {
            assert!(!output.contains("Somebody Else"), "{output}");
            assert!(!output.contains("A Driver Maker"), "{output}");
            assert!(!output.contains("d.exe"), "{output}");
        }
        assert!(
            text.contains("Signers that are not on the list: 2, with signatures on 3 files."),
            "{text}"
        );
    }

    #[test]
    fn signers_and_examples_are_named_on_request() {
        let report = surveyed(true, true);
        let names: Vec<&str> = report
            .signers
            .iter()
            .map(|signer| signer.common_name.as_str())
            .collect();
        assert_eq!(
            names,
            ["Listed Software", "Somebody Else", "A Driver Maker"],
            "most files first"
        );
        assert_eq!(report.signers[1].root.as_deref(), Some("A root"));
        let examples: Vec<Option<&str>> = report
            .trusted
            .iter()
            .map(|entry| entry.example.as_ref().map(|example| example.path.as_str()))
            .collect();
        assert_eq!(examples, [Some("a.exe"), Some("b.dll"), Some("c.png")]);

        let text = survey_text(&report, Duration::from_secs(1), true);
        assert!(
            text.contains(
                "A Driver Maker (An organisation), not on the list, under a root of Microsoft's"
            ),
            "{text}"
        );
        assert!(text.contains("for example a.exe"), "{text}");
    }

    #[test]
    fn what_the_check_said_about_broken_signatures_is_counted() {
        let report = reported(counted_with_broken_signatures(), false, false);
        let details: Vec<(Reason, &str, u64)> = report
            .details
            .iter()
            .map(|entry| (entry.reason, entry.detail.as_str(), entry.files))
            .collect();
        assert_eq!(
            details,
            [
                (Reason::Invalid, "changed", 2),
                (Reason::Invalid, "padded", 1)
            ],
            "most files first; a file that is only not on the list is not here"
        );
        assert!(report.details.iter().all(|entry| entry.example.is_none()));
        assert!(!report.details_truncated);
        let text = survey_text(&report, Duration::from_secs(1), false);
        assert!(!text.contains("j.exe"), "{text}");

        let report = reported(counted_with_broken_signatures(), false, true);
        assert_eq!(report.details[0].example.as_deref(), Some("j.exe"));
        assert_eq!(report.details[1].example.as_deref(), Some("l.exe"));
        let invalid = report
            .not_trusted
            .iter()
            .find(|entry| entry.reason == Reason::Invalid)
            .expect("counted");
        assert_eq!(invalid.count.files, 3);
        assert_eq!(invalid.example.as_deref(), Some("j.exe"));
        let text = survey_text(&report, Duration::from_secs(1), false);
        assert!(text.contains("for example j.exe"), "{text}");
    }

    #[test]
    fn one_file_is_explained_route_by_route() {
        let examination = Examination {
            sha256: Some("ab".repeat(32)),
            executable: Some(true),
            routes: vec![
                RouteReport {
                    route: Route::Embedded,
                    found: Found::Nothing,
                },
                RouteReport {
                    route: Route::WindowsCatalog,
                    found: Found::Valid {
                        signer: signer("Listed Software", true),
                        place: Some("example.cat (by SHA-256)".to_owned()),
                    },
                },
                RouteReport {
                    route: Route::Package,
                    found: Found::Invalid {
                        why: "the block map does not list the file".to_owned(),
                    },
                },
            ],
            trust: Trust::Trusted {
                publisher: "Listed".to_owned(),
                route: Route::WindowsCatalog,
            },
        };
        let text = check_text(Path::new("tool.exe"), &examination);
        let expected = format!(
            "tool.exe\n\
             \x20 Trusted     yes: signed for Listed, a publisher on the trust list, found in a \
             catalogue of Windows\n\
             \x20 SHA-256     {}\n\
             \x20 In the file no signature\n\
             \x20 Catalogue   a signature that holds, in example.cat (by SHA-256)\n\
             \x20             signed for Listed Software (An organisation)\n\
             \x20             chain: Listed Software < A root\n\
             \x20             the chain ends in a root of Microsoft's: yes; revocation: checked, \
             nothing revoked\n\
             \x20 Package     does not hold: the block map does not list the file\n",
            "ab".repeat(32)
        );
        assert_eq!(text, expected);

        let refused = Examination {
            sha256: None,
            executable: None,
            routes: Vec::new(),
            trust: Trust::NotTrusted {
                reason: Reason::NotChecked,
                detail: "the file cannot be read".to_owned(),
            },
        };
        assert_eq!(
            check_text(Path::new("gone.exe"), &refused),
            "gone.exe\n  Trusted     no: the file cannot be read\n"
        );
    }

    #[test]
    fn a_survey_reads_well_as_json() {
        let json = serde_json::to_value(surveyed(false, true)).expect("serializes");
        assert_eq!(json["schema"], 1);
        assert_eq!(json["label"], "a test");
        assert_eq!(json["files"], 9);
        assert_eq!(json["executables"], 7);
        assert_eq!(json["trusted"][0]["publisher"], "Listed");
        assert_eq!(json["trusted"][0]["route"], "embedded");
        assert_eq!(json["trusted"][0]["files"], 2);
        assert_eq!(json["trusted"][0]["executables"], 2);
        assert_eq!(json["trusted"][0]["example"]["path"], "a.exe");
        assert_eq!(json["not_trusted"][0]["reason"], "no_signature");
        assert_eq!(json["not_trusted"][0]["files"], 2);
        assert_eq!(json["signers_not_listed"]["signers"], 2);
        assert_eq!(json["timing"][0]["outcome"], "all");
        assert_eq!(json["trust_list"].as_str().map(str::len), Some(64));
    }
}

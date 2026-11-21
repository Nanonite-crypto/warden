//! The detector that runs a rule bundle over file content.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use warden_engine::text::printable;
use warden_engine::{
    Confidence, Detector, DetectorError, DetectorInfo, FileView, Finding, InfoValue, Session,
    ThreatCategory,
};
use yara_x::MetaValue;

use crate::builder::{BUILTIN_SOURCE, BundleBuilder};
use crate::bundle::{BundleError, ENGINE, RuleBundle};

/// Longest rule name or threat name carried into a finding.
const MAX_NAME_CHARS: usize = 120;
/// Longest piece of rule metadata carried into a reason.
const MAX_TEXT_CHARS: usize = 300;
/// How many matched patterns a reason names.
const PATTERNS_SHOWN: usize = 3;

/// How rule matches become findings.
///
/// A rule states how much a match means with a `score` from 0 to 100 in its
/// metadata, a convention shared by most public rule sets. The thresholds
/// here turn that score into a confidence, and the engine's verdict policy
/// turns the confidence into a verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YaraOptions {
    /// Lowest score reported with high confidence. With the default verdict
    /// policy that makes the file malicious.
    pub high_at: i64,
    /// Lowest score reported with medium confidence: suspicious, shown to
    /// the user, never acted on automatically. Anything lower is reported
    /// with low confidence.
    pub medium_at: i64,
    /// Score assumed for a rule that does not state one.
    pub default_score: i64,
    /// Longest time one file may take before the scan of it is given up.
    pub timeout: Duration,
    /// Most rule matches reported for one file. When more rules match, the
    /// ones with the highest scores are kept.
    pub max_matches: usize,
}

impl Default for YaraOptions {
    fn default() -> Self {
        Self {
            high_at: 80,
            medium_at: 60,
            default_score: 75,
            timeout: Duration::from_secs(30),
            max_matches: 10,
        }
    }
}

/// Detection layer 2: YARA rules.
///
/// Rules describe byte patterns and file structure, so they still match
/// when a file has been changed and its hash is no longer known. The engine
/// underneath is YARA-X.
///
/// A rule that is part of the program was written for Warden, to match one
/// thing. A rule that came with a bundle was written by somebody else, for
/// uses of their own, and published rules are known to match clean
/// software now and then. So the match of a bundle's rule
/// [yields to a trusted signature](warden_engine::Finding::yields_to_trust),
/// and the match of a built-in rule does not. The detector cannot tell a
/// published rule in a bundle from one its user wrote, so this goes for
/// every rule of a bundle.
pub struct YaraDetector {
    bundle: Arc<RuleBundle>,
    options: YaraOptions,
    builtin_only: bool,
}

/// How the rules of a detector are spread over scores and licences.
///
/// Every rule is counted once under `high`, `medium`, `low` or `generated`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleStats {
    /// Rules whose matches are reported with high confidence.
    pub high: u64,
    /// Rules whose matches are reported with medium confidence.
    pub medium: u64,
    /// Rules whose matches are reported with low confidence.
    pub low: u64,
    /// Rules that a tool generated, see [`generator`], whatever their
    /// score. A match of one counts only with a second sign from another
    /// layer, and then with medium confidence at most.
    pub generated: u64,
    /// Rules that state no score. They are also counted above, by the
    /// default score or as generated.
    pub unscored: u64,
    /// How many rules name each licence, by the `license_url` or `license`
    /// in their metadata. Rules that name none are counted under an empty
    /// string.
    pub licences: BTreeMap<String, u64>,
}

impl std::fmt::Debug for YaraDetector {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("YaraDetector")
            .field("bundle", &self.bundle)
            .field("options", &self.options)
            .finish()
    }
}

impl YaraDetector {
    /// Identifier of this detector in findings and reports.
    pub const ID: &'static str = "yara";

    /// Creates a detector with only the rules that ship inside the program.
    ///
    /// # Errors
    ///
    /// Fails only if the built-in rules do not compile, which a test guards
    /// against.
    pub fn builtin() -> Result<Self, BundleError> {
        let mut detector = Self::new(BundleBuilder::new().build()?.bundle);
        detector.builtin_only = true;
        Ok(detector)
    }

    /// Creates a detector that runs the rules in `bundle`.
    #[must_use]
    pub fn new(bundle: RuleBundle) -> Self {
        Self::shared(Arc::new(bundle))
    }

    /// Creates a detector that runs a bundle other owners hold too.
    #[must_use]
    pub fn shared(bundle: Arc<RuleBundle>) -> Self {
        Self {
            bundle,
            options: YaraOptions::default(),
            builtin_only: false,
        }
    }

    /// Replaces the default options.
    #[must_use]
    pub fn with_options(mut self, options: YaraOptions) -> Self {
        self.options = options;
        self
    }

    /// The rule bundle in use.
    #[must_use]
    pub fn bundle(&self) -> &RuleBundle {
        &self.bundle
    }

    /// The options in use.
    #[must_use]
    pub fn options(&self) -> &YaraOptions {
        &self.options
    }

    /// Counts the rules by the confidence their matches get and by the
    /// licence they name.
    #[must_use]
    pub fn rule_stats(&self) -> RuleStats {
        let mut stats = RuleStats::default();
        for rule in self.bundle.rules().iter() {
            let mut score = None;
            let mut licence_url = None;
            let mut licence = None;
            let mut generated = false;
            for (key, value) in rule.metadata() {
                match (key, value) {
                    ("tool", MetaValue::String(text)) => generated |= generator(text).is_some(),
                    ("score", MetaValue::Integer(number)) => score = Some(number.clamp(0, 100)),
                    ("license_url", MetaValue::String(text)) => licence_url = Some(text.trim()),
                    ("license", MetaValue::String(text)) => licence = Some(text.trim()),
                    _ => {}
                }
            }
            if score.is_none() {
                stats.unscored += 1;
            }
            let score = score.unwrap_or(self.options.default_score);
            if generated {
                stats.generated += 1;
            } else if score >= self.options.high_at {
                stats.high += 1;
            } else if score >= self.options.medium_at {
                stats.medium += 1;
            } else {
                stats.low += 1;
            }
            let named = [licence_url, licence]
                .into_iter()
                .flatten()
                .find(|text| !text.is_empty() && !text.eq_ignore_ascii_case("n/a"))
                .unwrap_or("");
            *stats
                .licences
                .entry(printable(named, MAX_TEXT_CHARS))
                .or_insert(0) += 1;
        }
        stats
    }
}

impl Detector for YaraDetector {
    fn id(&self) -> &'static str {
        Self::ID
    }

    fn needs_content(&self) -> bool {
        true
    }

    fn describe(&self) -> DetectorInfo {
        let bundle = &self.bundle;
        let mut details = BTreeMap::new();
        details.insert("rules", InfoValue::Count(u64::from(bundle.rule_count())));
        details.insert(
            "rule_files",
            InfoValue::Count(bundle.manifest().sources.len() as u64),
        );
        if bundle.manifest().exclusions.is_some() {
            // Present only for a bundle that was built with an exclusion
            // list, so a report shows that rules were left out on purpose.
            let excluded = bundle
                .manifest()
                .sources
                .iter()
                .map(|source| source.excluded)
                .sum();
            details.insert("rules_excluded", InfoValue::Count(excluded));
        }
        // How many of the rules count only with a second sign. Without this
        // number a report could not say why a rule match changed nothing.
        details.insert(
            "rules_generated",
            InfoValue::Count(bundle.generated_rules()),
        );
        details.insert("engine", InfoValue::Text(ENGINE.to_owned()));
        details.insert(
            "origin",
            InfoValue::Text(
                if self.builtin_only {
                    "built-in rules"
                } else {
                    "rule bundle"
                }
                .to_owned(),
            ),
        );
        details.insert(
            "bundle_digest",
            InfoValue::Text(warden_sigdb::hex::encode(&bundle.digest())),
        );
        details.insert(
            "bundle_created_unix_secs",
            InfoValue::Count(bundle.created_unix_secs()),
        );
        DetectorInfo {
            id: Self::ID,
            details,
        }
    }

    fn session(&self) -> Box<dyn Session + '_> {
        let mut scanner = yara_x::Scanner::new(self.bundle.rules());
        scanner.set_timeout(self.options.timeout);
        // A finding needs to know that a pattern occurs, not every place it
        // occurs, so the search for a pattern can stop at its first match
        // wherever the rule does not count or locate matches.
        scanner.fast_scan(true);
        Box::new(YaraSession {
            options: &self.options,
            scanner,
        })
    }
}

/// One thread's YARA-X scanner. A scanner keeps the state of the rule
/// engine and can only be used from one thread at a time.
struct YaraSession<'d> {
    options: &'d YaraOptions,
    scanner: yara_x::Scanner<'d>,
}

impl Session for YaraSession<'_> {
    fn inspect(&mut self, file: &FileView<'_>) -> Result<Vec<Finding>, DetectorError> {
        let Some(content) = file.content() else {
            return Ok(Vec::new());
        };
        let options = self.options;
        let results = self.scanner.scan(content).map_err(|error| match error {
            yara_x::ScanError::Timeout => DetectorError::TimedOut(format!(
                "the rules did not finish within {} seconds",
                options.timeout.as_secs()
            )),
            other => DetectorError::Failed(other.to_string()),
        })?;

        let mut scored: Vec<(i64, Finding)> = results
            .matching_rules()
            .map(|rule| finding_for(&rule, options))
            .collect();
        // Strongest first, and by name within a score so that the order
        // never depends on the order rules were compiled in.
        scored.sort_by(|left, right| {
            right
                .0
                .cmp(&left.0)
                .then_with(|| left.1.name.cmp(&right.1.name))
        });
        let unlisted = scored.len().saturating_sub(options.max_matches);
        scored.truncate(options.max_matches);
        let mut findings: Vec<Finding> = scored.into_iter().map(|(_, finding)| finding).collect();
        if unlisted > 0
            && let Some(first) = findings.first_mut()
        {
            first.reasons.push(format!(
                "{unlisted} more {} matched this file and are not listed",
                if unlisted == 1 { "rule" } else { "rules" }
            ));
        }
        Ok(findings)
    }
}

/// The tool that generated a rule, going by the rule's `tool` metadata.
///
/// Most rules are written by a person who decided what each pattern is
/// evidence of. Some are written by a program. yara-signator, the tool
/// behind the Malpedia rules, takes the samples of one malware family and
/// picks instruction sequences they have in common and that its collection
/// of other families does not have. Clean software is not part of that
/// comparison, so a sequence from a library that the family links in, a
/// compression routine or a C runtime, can end up in a rule. Such a rule
/// matches every clean program built with that library.
///
/// Warden therefore lets the match of a generated rule count only together
/// with a sign from another layer, see
/// [`Counts::WithSecondSign`](warden_engine::Counts). Returns the tool's
/// name as the rule gives it, or nothing for a rule that names no tool
/// Warden knows.
#[must_use]
pub fn generator(tool: &str) -> Option<&str> {
    let tool = tool.trim();
    let known = tool
        .get(..GENERATOR.len())
        .is_some_and(|start| start.eq_ignore_ascii_case(GENERATOR));
    known.then_some(tool)
}

/// The one rule generator met so far. Its rules say `tool = "yara-signator
/// v0.6.0"`.
const GENERATOR: &str = "yara-signator";

impl RuleBundle {
    /// How many of the rules a tool generated, see [`generator`]. A match
    /// of one counts only together with a sign from another layer.
    #[must_use]
    pub fn generated_rules(&self) -> u64 {
        self.rules()
            .iter()
            .filter(|rule| {
                rule.metadata().into_iter().any(|(key, value)| {
                    matches!((key, value), ("tool", MetaValue::String(text)) if generator(text).is_some())
                })
            })
            .count() as u64
    }
}

/// Turns one matching rule into a finding, and returns its score with it.
fn finding_for(rule: &yara_x::Rule<'_, '_>, options: &YaraOptions) -> (i64, Finding) {
    let mut threat_name = None;
    let mut description = None;
    let mut author = None;
    let mut reference = None;
    let mut generated_by = None;
    let mut category = ThreatCategory::Malware;
    let mut score = options.default_score;

    for (key, value) in rule.metadata() {
        match (key, value) {
            ("threat_name", MetaValue::String(text)) if !text.trim().is_empty() => {
                threat_name.get_or_insert(text);
            }
            ("description", MetaValue::String(text)) if !text.trim().is_empty() => {
                description.get_or_insert(text);
            }
            ("author", MetaValue::String(text)) if !text.trim().is_empty() => {
                author.get_or_insert(text);
            }
            ("reference", MetaValue::String(text)) if !text.trim().is_empty() => {
                reference.get_or_insert(text);
            }
            ("category", MetaValue::String(text)) => {
                category = parse_category(text).unwrap_or(category);
            }
            ("tool", MetaValue::String(text)) => {
                generated_by = generated_by.or(generator(text));
            }
            ("score", MetaValue::Integer(number)) => score = number.clamp(0, 100),
            _ => {}
        }
    }

    let mut confidence = if score >= options.high_at {
        Confidence::High
    } else if score >= options.medium_at {
        Confidence::Medium
    } else {
        Confidence::Low
    };
    if generated_by.is_some() {
        // Whatever score its tool gave it: with a second sign a generated
        // rule makes a file suspicious, and nothing more than that.
        confidence = confidence.min(Confidence::Medium);
    }

    let identifier = printable(rule.identifier(), MAX_NAME_CHARS);
    let mut reasons = Vec::with_capacity(3);
    reasons.push(match description {
        Some(description) => format!(
            "YARA rule {identifier} matched: {}",
            printable(description.trim(), MAX_TEXT_CHARS)
        ),
        None => format!("YARA rule {identifier} matched"),
    });

    let mut matched = 0usize;
    let mut shown = Vec::with_capacity(PATTERNS_SHOWN);
    for pattern in rule.patterns() {
        if let Some(first) = pattern.matches().next() {
            matched += 1;
            if shown.len() < PATTERNS_SHOWN {
                shown.push(format!(
                    "{} at offset {:#x}",
                    printable(pattern.identifier(), MAX_NAME_CHARS),
                    first.range().start
                ));
            }
        }
    }
    if matched > 0 {
        let mut line = format!("Patterns found: {}", shown.join(", "));
        if matched > shown.len() {
            line.push_str(&format!(", and {} more", matched - shown.len()));
        }
        reasons.push(line);
    }

    let mut origin = format!("Rule score {score} of 100");
    if let Some(author) = author {
        origin.push_str(&format!(
            ", written by {}",
            printable(author.trim(), MAX_NAME_CHARS)
        ));
    }
    if let Some(reference) = reference {
        origin.push_str(&format!(
            ", see {}",
            printable(reference.trim(), MAX_TEXT_CHARS)
        ));
    }
    reasons.push(origin);
    if let Some(tool) = generated_by {
        reasons.push(format!(
            "The rule was generated by a tool, {}, from samples of one malware family. Such a \
             rule also matches code that those samples share with clean software, so its match \
             counts only together with a sign from another layer",
            printable(tool, MAX_NAME_CHARS)
        ));
    }

    let name = match threat_name {
        Some(name) => printable(name.trim(), MAX_NAME_CHARS),
        None => identifier,
    };
    let mut finding = Finding::new(YaraDetector::ID, name, category, confidence, reasons);
    if generated_by.is_some() {
        finding = finding.with_second_sign();
    }
    if rule.namespace() != BUILTIN_SOURCE {
        finding = finding.yielding_to_trust();
    }
    (score, finding)
}

fn parse_category(text: &str) -> Option<ThreatCategory> {
    match text.trim().to_ascii_lowercase().as_str() {
        "malware" => Some(ThreatCategory::Malware),
        "test_file" | "test-file" | "test" => Some(ThreatCategory::TestFile),
        "potentially_unwanted" | "potentially-unwanted" | "pup" | "pua" => {
            Some(ThreatCategory::PotentiallyUnwanted)
        }
        _ => None,
    }
}

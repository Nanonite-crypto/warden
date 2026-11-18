//! Turns counts into the numbers the heuristics rest on: how often each
//! indicator applies to malicious and to benign files, the weights that
//! are fitted to that, the threshold, and what the score does with them.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use anyhow::{Context as _, bail};
use serde::Serialize;
use warden_pe::indicators;

use crate::collect::{Collected, IMPORT_BINS, Subset};
use crate::fit::{self, Cell, DECIBANS_PER_NAT};

/// An indicator is offered to the fit only if it applies to at least this
/// many malicious files of the training part. Below that, whatever weight
/// comes out is a guess.
pub const MIN_MALICIOUS_HITS: u64 = 500;
/// An indicator keeps a weight only if the fit gives it at least this
/// many decibans: 3 decibans double the odds. Weaker ones are taken out,
/// the weakest first, and the rest is fitted again.
pub const MIN_DECIBANS: f64 = 3.0;
/// No indicator weighs more than this, however lopsided its counts. A
/// single indicator should not be able to settle the matter.
pub const MAX_WEIGHT: u8 = 20;
/// The threshold is the lowest score that at most this share of the
/// benign training files of any kind reaches: one file in 5,000.
pub const MAX_FALSE_ALARMS: f64 = 0.0002;

/// Indicators that are measured and not offered to the fit, with the
/// reason. They stay visible in `warden inspect` and never add to a score.
pub const NOT_OFFERED: &[(&str, &str)] = &[(
    "signature.none",
    "whether a signature is present says nothing about whether it is valid, and one can be \
     appended to any file",
)];

/// The kinds of file that are told apart, by what a file says about
/// itself: a .NET assembly has a CLR header, a library has the DLL flag,
/// and everything else is a program.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FileKind {
    Program,
    Library,
    DotNet,
}

impl FileKind {
    pub const ALL: [Self; 3] = [Self::Program, Self::Library, Self::DotNet];

    pub fn name(self) -> &'static str {
        match self {
            Self::Program => "program",
            Self::Library => "library",
            Self::DotNet => ".NET",
        }
    }

    fn index(self) -> usize {
        self as usize
    }
}

/// How often something applies to malicious and to benign files.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Rates {
    pub malicious_hits: u64,
    pub malicious_files: u64,
    pub benign_hits: u64,
    pub benign_files: u64,
}

impl Rates {
    fn add(&mut self, malicious: bool, files: u64, hit: bool) {
        let (hits, total) = if malicious {
            (&mut self.malicious_hits, &mut self.malicious_files)
        } else {
            (&mut self.benign_hits, &mut self.benign_files)
        };
        *total += files;
        if hit {
            *hits += files;
        }
    }

    /// Share of the malicious files it applies to.
    pub fn malicious_share(&self) -> f64 {
        share(self.malicious_hits, self.malicious_files)
    }

    /// Share of the benign files it applies to.
    pub fn benign_share(&self) -> f64 {
        share(self.benign_hits, self.benign_files)
    }

    /// How many times more likely it is in a malicious file than in a
    /// benign one. Half a file is added to each count, so that an indicator
    /// that no benign file shows does not get an infinite ratio.
    pub fn ratio(&self) -> f64 {
        let malicious = (self.malicious_hits as f64 + 0.5) / (self.malicious_files as f64 + 1.0);
        let benign = (self.benign_hits as f64 + 0.5) / (self.benign_files as f64 + 1.0);
        malicious / benign
    }

    /// The ratio as a weight of evidence: ten times its base-ten logarithm.
    pub fn decibans(&self) -> f64 {
        10.0 * self.ratio().log10()
    }
}

fn share(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        0.0
    } else {
        part as f64 / whole as f64
    }
}

/// What the fit made of an indicator.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "outcome")]
pub enum Fitted {
    /// It has a weight: so many decibans, before rounding.
    Kept { decibans: f64 },
    /// It was fitted and taken out, because it came out below
    /// [`MIN_DECIBANS`].
    Removed { decibans: f64 },
    /// It applies to fewer than [`MIN_MALICIOUS_HITS`] malicious files.
    TooRare,
    /// It is in [`NOT_OFFERED`].
    NotOffered,
}

/// The measurement of one indicator or probe.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Measured {
    pub id: String,
    /// The weight the scanner uses. `None` for a probe.
    pub weight_in_use: Option<u8>,
    /// The weight these counts give. Zero for a probe.
    pub weight_by_rule: u8,
    /// What the fit made of it. `None` for a probe.
    pub fitted: Option<Fitted>,
    /// On the training part, all kinds of file together.
    pub train: Rates,
    /// On the test part: the weeks after the training part.
    pub test: Rates,
    /// On the training part, per kind of file.
    pub train_by_kind: BTreeMap<String, Rates>,
}

/// So many files of so many.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Flagged {
    pub flagged: u64,
    pub of: u64,
}

impl Flagged {
    pub fn share(&self) -> f64 {
        share(self.flagged, self.of)
    }
}

/// What a threshold does: the files with at least that score.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ThresholdRow {
    pub threshold: u32,
    pub train_malicious: Flagged,
    pub train_benign: Flagged,
    pub test_malicious: Flagged,
    pub test_benign: Flagged,
    /// The challenge set: malicious files that no antivirus product
    /// detected when they were first seen.
    pub challenge: Flagged,
    /// Files of a Windows installation's system folder.
    pub system: Flagged,
    /// Files of installed software.
    pub software: Flagged,
}

/// What a score does on one kind of file, or on all of them.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct KindScores {
    /// `None` for all kinds together.
    pub kind: Option<FileKind>,
    /// Probability that a malicious file scores higher than a benign one,
    /// with ties counted half: the area under the ROC curve.
    pub train_auc: f64,
    pub test_auc: f64,
    /// One row per score that occurs, lowest first.
    pub rows: Vec<ThresholdRow>,
}

impl KindScores {
    /// What the given threshold does. A threshold above every score that
    /// occurs flags nothing.
    pub fn at(&self, threshold: u32) -> ThresholdRow {
        match self.rows.iter().find(|row| row.threshold >= threshold) {
            Some(row) => ThresholdRow {
                threshold,
                ..row.clone()
            },
            None => {
                let mut row = self.rows.first().cloned().unwrap_or(ThresholdRow {
                    threshold,
                    train_malicious: Flagged::default(),
                    train_benign: Flagged::default(),
                    test_malicious: Flagged::default(),
                    test_benign: Flagged::default(),
                    challenge: Flagged::default(),
                    system: Flagged::default(),
                    software: Flagged::default(),
                });
                row.threshold = threshold;
                for part in [
                    &mut row.train_malicious,
                    &mut row.train_benign,
                    &mut row.test_malicious,
                    &mut row.test_benign,
                    &mut row.challenge,
                    &mut row.system,
                    &mut row.software,
                ] {
                    part.flagged = 0;
                }
                row
            }
        }
    }
}

/// A set of weights with a threshold, and what they do.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Scoring {
    /// The weights that are not zero, by indicator.
    pub weights: BTreeMap<String, u8>,
    /// The score from which a file counts as suspicious.
    pub suspicious_from: u32,
    /// Per kind of file, and last for all kinds together.
    pub by_kind: Vec<KindScores>,
}

/// Number of files in one part of the counts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Population {
    pub subset: Subset,
    pub kind: FileKind,
    pub malicious: u64,
    pub benign: u64,
}

/// An indicator the fit took out.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Removal {
    pub id: String,
    /// What the fit gave it when it was taken out.
    pub decibans: f64,
}

/// How the weights were fitted.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FitReport {
    /// Indicators that were not offered on purpose, with the reason.
    pub not_offered: Vec<(String, String)>,
    /// Indicators that apply to too few malicious files.
    pub too_rare: Vec<String>,
    /// Indicators the fit held at zero: given the others, they say nothing
    /// that speaks against a file.
    pub nothing: Vec<String>,
    /// Indicators that were taken out one by one, in that order.
    pub removed: Vec<Removal>,
    /// The fitted weights of the indicators that remain, in decibans.
    pub weights: BTreeMap<String, f64>,
    /// The fitted term of each kind of file, in decibans. Not part of the
    /// score.
    pub kind_terms: BTreeMap<String, f64>,
}

/// The constants of the rules, written into the report so that it
/// explains itself.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RuleInfo {
    pub min_malicious_hits: u64,
    pub min_decibans: f64,
    pub max_weight: u8,
    pub max_false_alarms: f64,
    /// Whether the indicators in [`NOT_OFFERED`] were offered after all,
    /// to see what they would do.
    pub offer_all: bool,
}

/// Everything computed from the counts.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Report {
    pub rule: RuleInfo,
    pub populations: Vec<Population>,
    pub indicators: Vec<Measured>,
    pub probes: Vec<Measured>,
    pub fit: FitReport,
    /// The weights and the threshold the scanner has.
    pub in_use: Scoring,
    /// The weights and the threshold these counts give.
    pub by_rule: Scoring,
    /// Whether the scanner's weights are the weights these counts give.
    pub weights_match: bool,
    /// Whether the scanner's threshold is the one these counts give.
    pub threshold_matches: bool,
    /// Counts per range of a number, see [`Collected`].
    pub distributions: BTreeMap<String, Vec<u64>>,
}

/// What to compute.
#[derive(Debug, Clone, Copy, Default)]
pub struct Options {
    /// Offer the indicators in [`NOT_OFFERED`] to the fit as well.
    pub offer_all: bool,
}

struct Row {
    subset: Subset,
    kind: FileKind,
    malicious: bool,
    pattern: u128,
    files: u64,
}

fn rows_of(collected: &Collected) -> anyhow::Result<Vec<Row>> {
    let bit_of = |id: &str| {
        collected
            .bits
            .iter()
            .position(|name| name == id)
            .with_context(|| format!("the counts do not hold {id}, which tells the kinds apart"))
    };
    let library = 1u128 << bit_of("probe.is_dll")?;
    let dotnet = 1u128 << bit_of("probe.is_dotnet")?;
    collected
        .groups
        .iter()
        .map(|group| {
            let pattern = u128::from_str_radix(&group.pattern, 16)
                .with_context(|| format!("{:?} is not a pattern", group.pattern))?;
            let kind = if pattern & dotnet != 0 {
                FileKind::DotNet
            } else if pattern & library != 0 {
                FileKind::Library
            } else {
                FileKind::Program
            };
            Ok(Row {
                subset: group.subset,
                kind,
                malicious: group.malicious,
                pattern,
                files: group.files,
            })
        })
        .collect()
}

fn measure(rows: &[Row], bit: usize, id: &str, weight_in_use: Option<u8>) -> Measured {
    let mut train = Rates::default();
    let mut test = Rates::default();
    let mut by_kind: BTreeMap<String, Rates> = BTreeMap::new();
    for row in rows {
        let hit = row.pattern & (1 << bit) != 0;
        match row.subset {
            Subset::Train => {
                train.add(row.malicious, row.files, hit);
                by_kind.entry(row.kind.name().to_owned()).or_default().add(
                    row.malicious,
                    row.files,
                    hit,
                );
            }
            Subset::Test => test.add(row.malicious, row.files, hit),
            Subset::Challenge | Subset::System | Subset::Software => {}
        }
    }
    Measured {
        id: id.to_owned(),
        weight_in_use,
        weight_by_rule: 0,
        fitted: None,
        train,
        test,
        train_by_kind: by_kind,
    }
}

/// An indicator as the fit sees it: its bit in the patterns and its name.
type Candidate = (usize, String);

/// Fits weights to the training part: all candidates together, then
/// without the weakest one for as long as one is below [`MIN_DECIBANS`].
fn fit_weights(rows: &[Row], mut candidates: Vec<Candidate>) -> anyhow::Result<FitReport> {
    let mut nothing = Vec::new();
    let mut removed = Vec::new();
    loop {
        let cells = fit::cells(
            rows.iter()
                .filter(|row| row.subset == Subset::Train)
                .map(|row| {
                    let mut features = 0u64;
                    for (index, (bit, _)) in candidates.iter().enumerate() {
                        if row.pattern & (1 << bit) != 0 {
                            features |= 1 << index;
                        }
                    }
                    let files = row.files as f64;
                    Cell {
                        kind: row.kind.index(),
                        features,
                        malicious: if row.malicious { files } else { 0.0 },
                        benign: if row.malicious { 0.0 } else { files },
                    }
                }),
        );
        let fitted = fit::fit(&cells, candidates.len(), FileKind::ALL.len())?;
        let decibans: Vec<f64> = fitted
            .weights
            .iter()
            .map(|weight| weight * DECIBANS_PER_NAT)
            .collect();

        // What the fit holds at zero changes nothing by leaving.
        if decibans.contains(&0.0) {
            let mut kept = Vec::new();
            for (candidate, value) in candidates.into_iter().zip(&decibans) {
                if *value == 0.0 {
                    nothing.push(candidate.1);
                } else {
                    kept.push(candidate);
                }
            }
            candidates = kept;
            continue;
        }
        let weakest = decibans
            .iter()
            .enumerate()
            .min_by(|left, right| left.1.total_cmp(right.1));
        match weakest {
            Some((index, value)) if *value < MIN_DECIBANS => {
                let (_, id) = candidates.remove(index);
                removed.push(Removal {
                    id,
                    decibans: *value,
                });
            }
            _ => {
                return Ok(FitReport {
                    not_offered: Vec::new(),
                    too_rare: Vec::new(),
                    nothing,
                    removed,
                    weights: candidates
                        .into_iter()
                        .map(|(_, id)| id)
                        .zip(decibans)
                        .collect(),
                    kind_terms: FileKind::ALL
                        .iter()
                        .zip(&fitted.kind_terms)
                        .map(|(kind, term)| (kind.name().to_owned(), term * DECIBANS_PER_NAT))
                        .collect(),
                });
            }
        }
    }
}

/// The weight a fitted number of decibans becomes.
fn rounded(decibans: f64) -> u8 {
    (decibans.round().clamp(0.0, f64::from(MAX_WEIGHT))) as u8
}

/// Scores per file count: `[malicious, benign]` by score.
type Spread = BTreeMap<u32, [u64; 2]>;

fn flagged(spread: &Spread, threshold: u32, malicious: bool) -> Flagged {
    let column = usize::from(!malicious);
    Flagged {
        flagged: spread
            .range(threshold..)
            .map(|(_, counts)| counts[column])
            .sum(),
        of: spread.values().map(|counts| counts[column]).sum(),
    }
}

fn auc(spread: &Spread) -> f64 {
    let malicious: u64 = spread.values().map(|counts| counts[0]).sum();
    let benign: u64 = spread.values().map(|counts| counts[1]).sum();
    if malicious == 0 || benign == 0 {
        return 0.0;
    }
    let mut benign_below = 0u64;
    let mut area = 0.0;
    for counts in spread.values() {
        area += counts[0] as f64 * (benign_below as f64 + counts[1] as f64 / 2.0);
        benign_below += counts[1];
    }
    area / (malicious as f64 * benign as f64)
}

/// The scores of the files of every part, for one kind or for all.
#[derive(Default)]
struct Spreads {
    by_subset: BTreeMap<Subset, Spread>,
}

impl Spreads {
    fn add(&mut self, row: &Row, score: u32) {
        self.by_subset
            .entry(row.subset)
            .or_default()
            .entry(score)
            .or_default()[usize::from(!row.malicious)] += row.files;
    }

    fn of(&self, subset: Subset) -> &Spread {
        static EMPTY: Spread = Spread::new();
        self.by_subset.get(&subset).unwrap_or(&EMPTY)
    }

    fn scores(&self, kind: Option<FileKind>) -> KindScores {
        let mut thresholds: Vec<u32> = self
            .by_subset
            .values()
            .flat_map(|spread| spread.keys().copied())
            .filter(|score| *score > 0)
            .collect();
        thresholds.sort_unstable();
        thresholds.dedup();
        KindScores {
            kind,
            train_auc: auc(self.of(Subset::Train)),
            test_auc: auc(self.of(Subset::Test)),
            rows: thresholds
                .into_iter()
                .map(|threshold| ThresholdRow {
                    threshold,
                    train_malicious: flagged(self.of(Subset::Train), threshold, true),
                    train_benign: flagged(self.of(Subset::Train), threshold, false),
                    test_malicious: flagged(self.of(Subset::Test), threshold, true),
                    test_benign: flagged(self.of(Subset::Test), threshold, false),
                    challenge: flagged(self.of(Subset::Challenge), threshold, true),
                    system: flagged(self.of(Subset::System), threshold, false),
                    software: flagged(self.of(Subset::Software), threshold, false),
                })
                .collect(),
        }
    }
}

/// The lowest score that at most [`MAX_FALSE_ALARMS`] of the benign
/// training files of every kind reach.
fn threshold_by_rule(by_kind: &[Spreads]) -> u32 {
    by_kind
        .iter()
        .map(|spreads| {
            let benign = spreads.of(Subset::Train);
            let total: u64 = benign.values().map(|counts| counts[1]).sum();
            let allowed = (total as f64 * MAX_FALSE_ALARMS).floor() as u64;
            // Walk down from the highest score for as long as the benign
            // files at or above it stay within what is allowed.
            let mut at_or_above = 0u64;
            let mut threshold = benign.keys().next_back().map_or(1, |highest| highest + 1);
            for (score, counts) in benign.iter().rev() {
                at_or_above += counts[1];
                if at_or_above > allowed {
                    break;
                }
                threshold = *score;
            }
            threshold.max(1)
        })
        .max()
        .unwrap_or(1)
}

/// `weights` holds, for every scored indicator, its bit in the patterns,
/// its name and its weight. Without a threshold, the rule sets it.
fn scoring(rows: &[Row], weights: &[(usize, String, u8)], suspicious_from: Option<u32>) -> Scoring {
    let score = |pattern: u128| -> u32 {
        weights
            .iter()
            .filter(|(bit, _, _)| pattern & (1 << bit) != 0)
            .map(|(_, _, weight)| u32::from(*weight))
            .sum()
    };
    let mut by_kind: Vec<Spreads> = FileKind::ALL.iter().map(|_| Spreads::default()).collect();
    let mut all = Spreads::default();
    for row in rows {
        let value = score(row.pattern);
        by_kind[row.kind.index()].add(row, value);
        all.add(row, value);
    }
    Scoring {
        weights: weights
            .iter()
            .filter(|(_, _, weight)| *weight > 0)
            .map(|(_, id, weight)| (id.clone(), *weight))
            .collect(),
        suspicious_from: suspicious_from.unwrap_or_else(|| threshold_by_rule(&by_kind)),
        by_kind: FileKind::ALL
            .iter()
            .zip(&by_kind)
            .map(|(kind, spreads)| spreads.scores(Some(*kind)))
            .chain(std::iter::once(all.scores(None)))
            .collect(),
    }
}

/// Computes the report from counts.
///
/// The counts name what each of their bits stands for, so they stay usable
/// when indicators are reordered or taken out of the scanner. What the
/// counts hold and the scanner no longer has is reported with the probes.
///
/// # Errors
///
/// Fails if the scanner has an indicator that the counts do not hold: it
/// was added after they were made, and they have to be collected again.
/// Fails if the counts hold no training part to fit weights to.
pub fn report(collected: &Collected, options: Options) -> anyhow::Result<Report> {
    let bit_of = |id: &str| collected.bits.iter().position(|name| name == id);
    let missing: Vec<&str> = indicators::all()
        .map(|indicator| indicator.id)
        .filter(|id| bit_of(id).is_none())
        .collect();
    if !missing.is_empty() {
        bail!(
            "the counts hold nothing about {}; collect them again",
            missing.join(", ")
        );
    }
    let rows = rows_of(collected)?;

    let mut populations: BTreeMap<(Subset, FileKind), [u64; 2]> = BTreeMap::new();
    for row in &rows {
        populations.entry((row.subset, row.kind)).or_default()[usize::from(!row.malicious)] +=
            row.files;
    }

    let mut measured: Vec<Measured> = indicators::all()
        .filter_map(|indicator| {
            let bit = bit_of(indicator.id)?;
            Some(measure(&rows, bit, indicator.id, Some(indicator.weight)))
        })
        .collect();
    let probes: Vec<Measured> = collected
        .bits
        .iter()
        .enumerate()
        .filter(|(_, id)| indicators::by_id(id).is_none())
        .map(|(bit, id)| measure(&rows, bit, id, None))
        .collect();

    // Which indicators the fit is offered.
    let mut candidates = Vec::new();
    let mut not_offered = Vec::new();
    let mut too_rare = Vec::new();
    for entry in &mut measured {
        let reason = NOT_OFFERED
            .iter()
            .find(|(id, _)| *id == entry.id)
            .map(|(_, reason)| *reason);
        if let (Some(reason), false) = (reason, options.offer_all) {
            not_offered.push((entry.id.clone(), reason.to_owned()));
            entry.fitted = Some(Fitted::NotOffered);
        } else if entry.train.malicious_hits < MIN_MALICIOUS_HITS {
            too_rare.push(entry.id.clone());
            entry.fitted = Some(Fitted::TooRare);
        } else if let Some(bit) = bit_of(&entry.id) {
            candidates.push((bit, entry.id.clone()));
        }
    }
    let mut fit = fit_weights(&rows, candidates).context("the weights cannot be fitted")?;
    fit.not_offered = not_offered;
    fit.too_rare = too_rare;
    for entry in &mut measured {
        if let Some(decibans) = fit.weights.get(&entry.id) {
            entry.weight_by_rule = rounded(*decibans);
            entry.fitted = Some(Fitted::Kept {
                decibans: *decibans,
            });
        } else if let Some(removal) = fit.removed.iter().find(|removal| removal.id == entry.id) {
            entry.fitted = Some(Fitted::Removed {
                decibans: removal.decibans,
            });
        } else if fit.nothing.contains(&entry.id) {
            entry.fitted = Some(Fitted::Removed { decibans: 0.0 });
        }
    }

    let weights = |pick: &dyn Fn(&Measured) -> u8| -> Vec<(usize, String, u8)> {
        measured
            .iter()
            .filter_map(|entry| Some((bit_of(&entry.id)?, entry.id.clone(), pick(entry))))
            .collect()
    };
    let in_use = weights(&|entry| entry.weight_in_use.unwrap_or(0));
    let by_rule = weights(&|entry| entry.weight_by_rule);
    let weights_match = in_use == by_rule;
    let in_use = scoring(&rows, &in_use, Some(warden_pe::SUSPICIOUS_FROM));
    let by_rule = scoring(&rows, &by_rule, None);
    Ok(Report {
        rule: RuleInfo {
            min_malicious_hits: MIN_MALICIOUS_HITS,
            min_decibans: MIN_DECIBANS,
            max_weight: MAX_WEIGHT,
            max_false_alarms: MAX_FALSE_ALARMS,
            offer_all: options.offer_all,
        },
        populations: populations
            .into_iter()
            .map(|((subset, kind), [malicious, benign])| Population {
                subset,
                kind,
                malicious,
                benign,
            })
            .collect(),
        weights_match,
        threshold_matches: in_use.suspicious_from == by_rule.suspicious_from,
        in_use,
        by_rule,
        indicators: measured,
        probes,
        fit,
        distributions: collected.distributions.clone(),
    })
}

fn percent(value: f64) -> String {
    if value == 0.0 {
        "0".to_owned()
    } else if value < 0.001 {
        format!("{:.4}", value * 100.0)
    } else {
        format!("{:.2}", value * 100.0)
    }
}

fn grouped(value: u64) -> String {
    let digits = value.to_string();
    let mut out = String::new();
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            out.push(',');
        }
        out.push(digit);
    }
    out
}

/// A share of files with the counts it rests on: `12.34 % (5 of 40)`.
fn counted(part: Flagged) -> String {
    if part.of == 0 {
        "-".to_owned()
    } else {
        format!(
            "{} % ({} of {})",
            percent(part.share()),
            grouped(part.flagged),
            grouped(part.of)
        )
    }
}

fn decibans_of(rates: Option<&Rates>) -> String {
    match rates {
        // Too few files of this kind show it to say anything.
        Some(rates) if rates.malicious_hits + rates.benign_hits >= 100 => {
            format!("{:.1}", rates.decibans())
        }
        _ => "-".to_owned(),
    }
}

fn measured_lines(out: &mut String, list: &[Measured]) {
    let _ = writeln!(
        out,
        "  {:<36} {:>8} {:>8} {:>6} {:>7}   {:>7} {:>7} {:>7}   {:>6} {:>4} {:>4}",
        "",
        "mal %",
        "ben %",
        "dB",
        "dB test",
        "program",
        "library",
        ".NET",
        "fitted",
        "rule",
        "use"
    );
    for entry in list {
        let fitted = match &entry.fitted {
            Some(Fitted::Kept { decibans } | Fitted::Removed { decibans }) => {
                format!("{decibans:.2}")
            }
            Some(Fitted::TooRare) => "rare".to_owned(),
            Some(Fitted::NotOffered) => "no".to_owned(),
            None => "-".to_owned(),
        };
        let _ = writeln!(
            out,
            "  {:<36} {:>8} {:>8} {:>6.1} {:>7.1}   {:>7} {:>7} {:>7}   {:>6} {:>4} {:>4}",
            entry.id,
            percent(entry.train.malicious_share()),
            percent(entry.train.benign_share()),
            entry.train.decibans(),
            entry.test.decibans(),
            decibans_of(entry.train_by_kind.get(FileKind::Program.name())),
            decibans_of(entry.train_by_kind.get(FileKind::Library.name())),
            decibans_of(entry.train_by_kind.get(FileKind::DotNet.name())),
            fitted,
            if entry.fitted.is_some() {
                entry.weight_by_rule.to_string()
            } else {
                "-".to_owned()
            },
            entry
                .weight_in_use
                .map_or_else(|| "-".to_owned(), |weight| weight.to_string()),
        );
    }
}

fn fit_lines(out: &mut String, report: &Report) {
    let fit = &report.fit;
    for (id, reason) in &fit.not_offered {
        let _ = writeln!(out, "  Not offered to the fit: {id}, because {reason}.");
    }
    if report.rule.offer_all {
        let _ = writeln!(
            out,
            "  Every indicator was offered to the fit, also those the scanner leaves out on purpose."
        );
    }
    if !fit.too_rare.is_empty() {
        let _ = writeln!(
            out,
            "  Applies to fewer than {} malicious training files, so not offered: {}.",
            report.rule.min_malicious_hits,
            fit.too_rare.join(", ")
        );
    }
    if !fit.nothing.is_empty() {
        let _ = writeln!(
            out,
            "  Held at zero by the fit: next to the others they say nothing against a file.\n    {}",
            fit.nothing.join(", ")
        );
    }
    if !fit.removed.is_empty() {
        let _ = writeln!(
            out,
            "  Taken out one at a time, weakest first, because the fit gave less than {} dB:",
            report.rule.min_decibans
        );
        for removal in &fit.removed {
            let _ = writeln!(out, "    {:<36} {:>5.2} dB", removal.id, removal.decibans);
        }
    }
    let _ = writeln!(out, "  The weights that remain:");
    for entry in &report.indicators {
        if let Some(Fitted::Kept { decibans }) = &entry.fitted {
            let _ = writeln!(
                out,
                "    {:<36} {:>5.2} dB  ->  {:>2}",
                entry.id, decibans, entry.weight_by_rule
            );
        }
    }
    let terms: Vec<String> = FileKind::ALL
        .iter()
        .filter_map(|kind| {
            fit.kind_terms
                .get(kind.name())
                .map(|term| format!("{} {term:.1} dB", kind.name()))
        })
        .collect();
    let _ = writeln!(
        out,
        "  The terms for the kind of file, which are not part of the score: {}.",
        terms.join(", ")
    );
}

fn kind_name(kind: Option<FileKind>) -> &'static str {
    kind.map_or("all kinds", FileKind::name)
}

/// What one threshold does, per kind and per part.
fn threshold_lines(out: &mut String, scoring: &Scoring) {
    let threshold = scoring.suspicious_from;
    let _ = writeln!(
        out,
        "  {:<10} {:<10} {:>34} {:>30}",
        "", "", "malicious files flagged", "benign files flagged"
    );
    for scores in &scoring.by_kind {
        let row = scores.at(threshold);
        for (part, malicious, benign) in [
            ("train", Some(row.train_malicious), Some(row.train_benign)),
            ("test", Some(row.test_malicious), Some(row.test_benign)),
            ("challenge", Some(row.challenge), None),
            ("system", None, Some(row.system)),
            ("software", None, Some(row.software)),
        ] {
            if malicious.is_none_or(|part| part.of == 0) && benign.is_none_or(|part| part.of == 0) {
                continue;
            }
            let _ = writeln!(
                out,
                "  {:<10} {:<10} {:>34} {:>30}",
                kind_name(scores.kind),
                part,
                malicious.map_or_else(String::new, counted),
                benign.map_or_else(String::new, counted),
            );
        }
    }
}

/// What every threshold near the one in use does on one kind of file.
fn score_lines(out: &mut String, scores: &KindScores, around: u32) {
    let _ = writeln!(
        out,
        "  {}: area under the ROC curve {:.4} on the training part, {:.4} on the test part",
        kind_name(scores.kind),
        scores.train_auc,
        scores.test_auc
    );
    let _ = writeln!(
        out,
        "    {:>5} {:>9} {:>9} {:>9} {:>9} {:>9} {:>16} {:>16}",
        "score",
        "train mal",
        "train ben",
        "test mal",
        "test ben",
        "challenge",
        "system",
        "software"
    );
    let installed = |part: Flagged| {
        if part.of == 0 {
            "-".to_owned()
        } else {
            format!("{} of {}", grouped(part.flagged), grouped(part.of))
        }
    };
    for row in scores
        .rows
        .iter()
        .filter(|row| row.threshold + 16 >= around && row.threshold <= around.saturating_add(10))
    {
        let _ = writeln!(
            out,
            "    {:>5} {:>9} {:>9} {:>9} {:>9} {:>9} {:>16} {:>16}",
            format!(">={}", row.threshold),
            percent(row.train_malicious.share()),
            percent(row.train_benign.share()),
            percent(row.test_malicious.share()),
            percent(row.test_benign.share()),
            percent(row.challenge.share()),
            installed(row.system),
            installed(row.software),
        );
    }
}

fn distribution_lines(out: &mut String, report: &Report) {
    let get = |subset: &str, label: &str, name: &str| {
        report
            .distributions
            .get(&format!("{subset}/{label}/{name}"))
    };
    for (name, title) in [
        (
            "max_code_entropy",
            "Entropy of the most evenly spread executable section",
        ),
        ("file_entropy", "Entropy of the whole file"),
    ] {
        let (Some(malicious), Some(benign)) = (
            get("train", "malicious", name),
            get("train", "benign", name),
        ) else {
            continue;
        };
        let _ = writeln!(out, "{title} (training part): share of files at or above");
        let total = |counts: &[u64]| counts.iter().sum::<u64>();
        for start in [16usize, 20, 22, 24, 25, 26, 27, 28, 29, 30, 31] {
            let at_or_above = |counts: &[u64]| {
                // The last range is "no section to measure".
                let measured = &counts[..counts.len() - 1];
                share(measured.iter().skip(start).sum(), total(counts))
            };
            let _ = writeln!(
                out,
                "  >= {:<5} malicious {:>7} %   benign {:>7} %",
                format!("{:.2}", start as f64 * crate::collect::ENTROPY_BIN),
                percent(at_or_above(malicious)),
                percent(at_or_above(benign)),
            );
        }
    }
    if let (Some(malicious), Some(benign)) = (
        get("train", "malicious", "import_count"),
        get("train", "benign", "import_count"),
    ) {
        let _ = writeln!(
            out,
            "Number of imported functions (training part, native programs with an entry point)"
        );
        let native = |counts: &[u64]| counts[..=IMPORT_BINS.len()].iter().sum::<u64>();
        let mut lower = 0usize;
        for (index, upper) in IMPORT_BINS.iter().enumerate() {
            let label = if lower == *upper {
                format!("{upper}")
            } else {
                format!("{lower}-{upper}")
            };
            let _ = writeln!(
                out,
                "  {:<9} malicious {:>7} %   benign {:>7} %",
                label,
                percent(share(malicious[index], native(malicious))),
                percent(share(benign[index], native(benign))),
            );
            lower = upper + 1;
        }
        let _ = writeln!(
            out,
            "  {:<9} malicious {:>7} %   benign {:>7} %",
            format!("{lower}+"),
            percent(share(malicious[IMPORT_BINS.len()], native(malicious))),
            percent(share(benign[IMPORT_BINS.len()], native(benign))),
        );
    }
    if let (Some(malicious), Some(benign)) = (
        get("train", "malicious", "section_count"),
        get("train", "benign", "section_count"),
    ) {
        let _ = writeln!(out, "Number of sections (training part)");
        let total = |counts: &[u64]| counts.iter().sum::<u64>();
        for index in 0..malicious.len() {
            let label = if index + 1 == malicious.len() {
                format!("{index}+")
            } else {
                index.to_string()
            };
            let _ = writeln!(
                out,
                "  {:<9} malicious {:>7} %   benign {:>7} %",
                label,
                percent(share(malicious[index], total(malicious))),
                percent(share(benign[index], total(benign))),
            );
        }
    }
}

/// The report as text for a terminal, a build log or the repository.
pub fn render_text(collected: &Collected, report: &Report) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "What was counted\n  (seen: the records of a dataset file, or the files in a folder; repeats: records of a file that was already counted; of other kinds: not Windows executables)"
    );
    for input in &collected.inputs {
        let _ = writeln!(
            out,
            "  {}: {} seen, {} counted, {} repeats, {} of other kinds, {} not readable as an executable, {} without a label, {} unreadable",
            input.name,
            grouped(input.records),
            grouped(input.counted),
            grouped(input.duplicates),
            grouped(input.other_kinds),
            grouped(input.not_parsed_as_pe),
            grouped(input.unlabelled),
            grouped(input.unreadable),
        );
    }
    for error in &collected.first_errors {
        let _ = writeln!(out, "  unreadable: {error}");
    }
    let _ = writeln!(
        out,
        "\nFiles by part and kind\n  (train, test, challenge: the EMBER2024 dataset; system, software: files of a Windows machine, taken to be benign)"
    );
    for population in &report.populations {
        let _ = writeln!(
            out,
            "  {:<10} {:<8} {:>10} malicious {:>10} benign",
            population.subset.name(),
            population.kind.name(),
            grouped(population.malicious),
            grouped(population.benign),
        );
    }
    let _ = writeln!(
        out,
        "\nIndicators, each on its own\n  mal %, ben %: share of the malicious and of the benign training files it applies to\n  dB: ten times the base-ten logarithm of the ratio of the two; dB test: the same on the test part\n  program, library, .NET: dB among the training files of that kind\n  fitted: the weight the fit gives it next to the others, in dB; rule: that weight as these counts make it; use: the weight the scanner has"
    );
    measured_lines(&mut out, &report.indicators);
    let _ = writeln!(
        out,
        "\nProbes: other thresholds and properties, for comparison. They are not part of the scanner."
    );
    measured_lines(&mut out, &report.probes);

    let _ = writeln!(out, "\nThe fit");
    fit_lines(&mut out, report);
    let _ = writeln!(
        out,
        "\nThe threshold\n  The lowest score that at most one in {} of the benign training files of every kind reaches: {}.",
        grouped((1.0 / report.rule.max_false_alarms).round() as u64),
        report.by_rule.suspicious_from
    );

    let _ = writeln!(
        out,
        "\nThe scanner\n  Its weights are {} these counts give. Its threshold is {}, {}",
        if report.weights_match {
            "the weights"
        } else {
            "NOT the weights"
        },
        report.in_use.suspicious_from,
        if report.threshold_matches {
            "which is the threshold these counts give."
        } else {
            "which is NOT the threshold these counts give."
        }
    );
    let shown = if report.weights_match && report.threshold_matches {
        &report.in_use
    } else {
        let _ = writeln!(
            out,
            "  What follows is for the weights and the threshold these counts give."
        );
        &report.by_rule
    };
    let _ = writeln!(out, "\nWhat a threshold of {} does", shown.suspicious_from);
    threshold_lines(&mut out, shown);
    let _ = writeln!(
        out,
        "\nOther thresholds\n  (share of the files with at least that score; system and software as counts)"
    );
    for scores in &shown.by_kind {
        score_lines(&mut out, scores, shown.suspicious_from);
    }
    out.push('\n');
    distribution_lines(&mut out, report);
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::collect::{Group, Kind, SCHEMA, bit_names};

    fn close(left: f64, right: f64) -> bool {
        (left - right).abs() < 1e-9
    }

    #[test]
    fn ratios_follow_from_counts() {
        // 30 % of malicious and 3 % of benign files: ten to one, 10 dB.
        let rates = Rates {
            malicious_hits: 30_000,
            malicious_files: 100_000,
            benign_hits: 3_000,
            benign_files: 100_000,
        };
        assert!(close(rates.malicious_share(), 0.3));
        assert!(close(rates.benign_share(), 0.03));
        assert!((rates.ratio() - 10.0).abs() < 0.01);
        assert!((rates.decibans() - 10.0).abs() < 0.01);

        // No benign file at all: a large ratio, and not an infinite one.
        let never_benign = Rates {
            benign_hits: 0,
            ..rates
        };
        assert!(never_benign.ratio().is_finite());
        assert!(never_benign.decibans() > 40.0);
        // Nothing counted.
        assert!(close(Rates::default().malicious_share(), 0.0));
        assert!(close(Rates::default().decibans(), 0.0));
    }

    #[test]
    fn the_area_under_the_curve_is_exact_for_small_cases() {
        // Every malicious file scores above every benign one.
        let apart = Spread::from([(0, [0, 10]), (5, [10, 0])]);
        assert!(close(auc(&apart), 1.0));
        // Indistinguishable.
        let same = Spread::from([(3, [10, 10])]);
        assert!(close(auc(&same), 0.5));
        // Half of the malicious files stand out.
        let half = Spread::from([(0, [5, 10]), (5, [5, 0])]);
        assert!(close(auc(&half), 0.75));
        assert_eq!(flagged(&half, 1, true), Flagged { flagged: 5, of: 10 });
        assert!(close(flagged(&half, 1, false).share(), 0.0));
        assert!(close(flagged(&half, 0, false).share(), 1.0));
        assert!(close(auc(&Spread::new()), 0.0));
        assert!(close(Flagged::default().share(), 0.0));
    }

    #[test]
    fn weights_are_rounded_and_capped() {
        assert_eq!(rounded(3.0), 3);
        assert_eq!(rounded(3.49), 3);
        assert_eq!(rounded(3.5), 4);
        assert_eq!(rounded(18.15), 18);
        assert_eq!(rounded(31.9), MAX_WEIGHT);
        assert_eq!(rounded(-1.0), 0);
    }

    fn collected(groups: Vec<Group>) -> Collected {
        Collected {
            schema: SCHEMA,
            inputs: Vec::new(),
            bits: bit_names(),
            groups,
            distributions: BTreeMap::new(),
            first_errors: Vec::new(),
        }
    }

    fn group(subset: Subset, malicious: bool, bits: &[&str], files: u64) -> Group {
        let names = bit_names();
        let mut pattern = 0u128;
        for bit in bits {
            pattern |= 1 << names.iter().position(|name| name == bit).unwrap();
        }
        Group {
            subset,
            // What the dataset calls the file plays no part in the report.
            kind: Kind::Win32,
            malicious,
            pattern: format!("{pattern:x}"),
            files,
        }
    }

    const WRITABLE: &str = "sections.writable_and_executable";
    const TLS: &str = "tables.tls";
    const LIBRARY: &str = "probe.is_dll";

    /// Programs are mostly malicious and libraries mostly benign. In both,
    /// a writable code section multiplies the odds by twenty, and a TLS
    /// table changes nothing.
    fn two_kinds() -> Vec<Group> {
        use Subset::{Challenge, Software, System, Test, Train};
        vec![
            // Programs: odds 3 to 1 without the section, 60 to 1 with it.
            group(Train, true, &[], 1_500),
            group(Train, true, &[TLS], 1_500),
            group(Train, false, &[], 500),
            group(Train, false, &[TLS], 500),
            group(Train, true, &[WRITABLE], 3_000),
            group(Train, true, &[WRITABLE, TLS], 3_000),
            group(Train, false, &[WRITABLE], 50),
            group(Train, false, &[WRITABLE, TLS], 50),
            // Libraries: odds 1 to 90 without it, 2 to 9 with it.
            group(Train, true, &[LIBRARY], 50),
            group(Train, true, &[LIBRARY, TLS], 50),
            group(Train, false, &[LIBRARY], 4_500),
            group(Train, false, &[LIBRARY, TLS], 4_500),
            group(Train, true, &[LIBRARY, WRITABLE], 100),
            group(Train, true, &[LIBRARY, WRITABLE, TLS], 100),
            group(Train, false, &[LIBRARY, WRITABLE], 450),
            group(Train, false, &[LIBRARY, WRITABLE, TLS], 450),
            // The weeks after.
            group(Test, true, &[WRITABLE], 300),
            group(Test, true, &[], 700),
            group(Test, false, &[WRITABLE], 20),
            group(Test, false, &[], 980),
            group(Challenge, true, &[WRITABLE], 1),
            group(Challenge, true, &[], 3),
            // Files of a machine.
            group(System, false, &[LIBRARY], 990),
            group(System, false, &[LIBRARY, WRITABLE], 10),
            group(Software, false, &[], 500),
        ]
    }

    #[test]
    fn a_report_measures_fits_and_scores() {
        let counts = collected(two_kinds());
        let report = report(&counts, Options::default()).unwrap();

        let population = |subset: Subset, kind: FileKind| {
            report
                .populations
                .iter()
                .find(|entry| entry.subset == subset && entry.kind == kind)
                .unwrap()
        };
        assert_eq!(
            population(Subset::Train, FileKind::Program).malicious,
            9_000
        );
        assert_eq!(population(Subset::Train, FileKind::Program).benign, 1_100);
        assert_eq!(population(Subset::Train, FileKind::Library).malicious, 300);
        assert_eq!(population(Subset::Train, FileKind::Library).benign, 9_900);
        assert_eq!(population(Subset::System, FileKind::Library).benign, 1_000);

        let by_id = |id: &str| {
            report
                .indicators
                .iter()
                .find(|entry| entry.id == id)
                .unwrap()
        };
        let writable = by_id(WRITABLE);
        assert_eq!(writable.train.malicious_hits, 6_200);
        assert_eq!(writable.train.benign_hits, 1_000);
        assert_eq!(writable.test.malicious_hits, 300);
        assert_eq!(writable.train_by_kind["library"].malicious_hits, 200);
        // Twenty to one is 13.01 decibans, in both kinds, whatever the kinds
        // themselves are like.
        let Some(Fitted::Kept { decibans }) = writable.fitted else {
            panic!("{:?}", writable.fitted);
        };
        assert!((decibans - 10.0 * 20f64.log10()).abs() < 1e-3, "{decibans}");
        assert_eq!(writable.weight_by_rule, 13);
        // The table changes nothing and gets nothing.
        assert_eq!(by_id(TLS).weight_by_rule, 0);
        assert!(matches!(by_id(TLS).fitted, Some(Fitted::Removed { .. })));
        // What no file shows is too rare to say anything about.
        assert_eq!(by_id("sections.packer_name").fitted, Some(Fitted::TooRare));
        assert!(
            report
                .fit
                .too_rare
                .contains(&"sections.packer_name".to_owned())
        );
        assert!((report.fit.kind_terms["program"] - 10.0 * 3f64.log10()).abs() < 1e-3);
        assert!((report.fit.kind_terms["library"] + 10.0 * 90f64.log10()).abs() < 1e-3);

        let probe = report
            .probes
            .iter()
            .find(|entry| entry.id == LIBRARY)
            .unwrap();
        assert_eq!(probe.weight_in_use, None);
        assert_eq!(probe.fitted, None);
        assert_eq!(probe.train.malicious_hits, 300);

        assert_eq!(
            report.by_rule.weights,
            BTreeMap::from([(WRITABLE.to_owned(), 13)])
        );
        // Far too many benign files have the section for a score of 13 to
        // be a threshold, so the threshold is beyond every score.
        assert_eq!(report.by_rule.suspicious_from, 14);

        let scores = |kind: Option<FileKind>| {
            report
                .by_rule
                .by_kind
                .iter()
                .find(|scores| scores.kind == kind)
                .unwrap()
        };
        let programs = scores(Some(FileKind::Program));
        assert_eq!(programs.rows.len(), 1);
        let row = &programs.rows[0];
        assert_eq!(row.threshold, 13);
        assert_eq!(
            row.train_malicious,
            Flagged {
                flagged: 6_000,
                of: 9_000
            }
        );
        assert_eq!(
            row.train_benign,
            Flagged {
                flagged: 100,
                of: 1_100
            }
        );
        assert_eq!(
            row.test_malicious,
            Flagged {
                flagged: 300,
                of: 1_000
            }
        );
        assert_eq!(row.challenge, Flagged { flagged: 1, of: 4 });
        assert_eq!(
            row.software,
            Flagged {
                flagged: 0,
                of: 500
            }
        );
        // 30 % stand out, the rest tie with 98 % of the benign files.
        assert!((programs.test_auc - (0.3 * 0.99 + 0.7 * 0.98 * 0.5)).abs() < 1e-9);
        let libraries = scores(Some(FileKind::Library));
        assert_eq!(
            libraries.rows[0].system,
            Flagged {
                flagged: 10,
                of: 1_000
            }
        );
        // All kinds together: every part adds up.
        assert_eq!(scores(None).rows[0].train_malicious.of, 9_300);
        // Beyond every score nothing is flagged, and the totals stay.
        let beyond = programs.at(14);
        assert_eq!(beyond.threshold, 14);
        assert_eq!(
            beyond.train_malicious,
            Flagged {
                flagged: 0,
                of: 9_000
            }
        );
        assert_eq!(programs.at(13), programs.rows[0]);
        assert_eq!(programs.at(1).train_malicious.flagged, 6_000);

        let text = render_text(&counts, &report);
        for expected in [
            WRITABLE,
            ">=13",
            "13.01 dB  ->  13",
            "NOT the weights",
            "Not offered to the fit: signature.none",
        ] {
            assert!(
                text.contains(expected),
                "{expected:?} is missing in\n{text}"
            );
        }
    }

    #[test]
    fn the_threshold_is_the_lowest_score_few_benign_files_reach() {
        let spreads = |scores: &[(u32, u64)]| {
            let mut spreads = Spreads::default();
            spreads.by_subset.insert(
                Subset::Train,
                scores
                    .iter()
                    .map(|(score, benign)| (*score, [0, *benign]))
                    .collect(),
            );
            spreads
        };
        // 100,000 benign files: 20 may reach the threshold. Ten have a
        // score of 10 or more, and with those of 5 or more it is thirty.
        let first = spreads(&[(0, 99_970), (5, 20), (10, 8), (20, 2)]);
        assert_eq!(threshold_by_rule(std::slice::from_ref(&first)), 10);
        // 50,000 benign files, of which eleven score 30: one too many, so
        // the threshold is beyond every score.
        let second = spreads(&[(0, 49_989), (30, 11)]);
        assert_eq!(threshold_by_rule(std::slice::from_ref(&second)), 31);
        // The limit holds for every kind.
        assert_eq!(threshold_by_rule(&[first, second]), 31);
        // A threshold of zero would flag everything.
        assert_eq!(threshold_by_rule(&[spreads(&[(0, 5)])]), 1);
        assert_eq!(threshold_by_rule(&[Spreads::default()]), 1);
    }

    #[test]
    fn an_indicator_is_left_out_on_purpose_unless_asked() {
        let signature = "signature.none";
        let counts = collected(vec![
            group(Subset::Train, true, &[signature], 9_000),
            group(Subset::Train, true, &[], 1_000),
            group(Subset::Train, false, &[signature], 4_000),
            group(Subset::Train, false, &[], 6_000),
        ]);
        let find = |report: &Report| {
            report
                .indicators
                .iter()
                .find(|entry| entry.id == signature)
                .unwrap()
                .clone()
        };
        let by_default = report(&counts, Options::default()).unwrap();
        assert_eq!(find(&by_default).fitted, Some(Fitted::NotOffered));
        assert_eq!(find(&by_default).weight_by_rule, 0);
        assert_eq!(by_default.fit.not_offered[0].0, signature);
        assert!(by_default.by_rule.weights.is_empty());

        // Odds of 9 to 4 with it and 1 to 6 without: 13.5 to 1, 11.3 dB.
        let offered = report(&counts, Options { offer_all: true }).unwrap();
        assert_eq!(find(&offered).weight_by_rule, 11);
        assert!(offered.fit.not_offered.is_empty());
        assert!(offered.rule.offer_all);
    }

    #[test]
    fn counts_are_matched_to_indicators_by_name() {
        let expected = report(&collected(two_kinds()), Options::default()).unwrap();

        // The same counts with their bits in another order, and with a bit
        // for an indicator the scanner no longer has.
        let mut shuffled = collected(two_kinds());
        shuffled.bits.insert(0, "retired.indicator".to_owned());
        for group in &mut shuffled.groups {
            let pattern = u128::from_str_radix(&group.pattern, 16).unwrap();
            // Everything moved up by one; the retired bit is set everywhere.
            group.pattern = format!("{:x}", (pattern << 1) | 1);
        }
        let report_of_shuffled = report(&shuffled, Options::default()).unwrap();
        assert_eq!(report_of_shuffled.indicators, expected.indicators);
        assert_eq!(report_of_shuffled.by_rule, expected.by_rule);
        assert_eq!(report_of_shuffled.populations, expected.populations);
        let retired = report_of_shuffled
            .probes
            .iter()
            .find(|entry| entry.id == "retired.indicator")
            .unwrap();
        assert_eq!(retired.train.malicious_hits, 9_300);

        // Counts that lack an indicator the scanner has cannot be used.
        let mut lacking = collected(two_kinds());
        lacking.bits.retain(|name| name != WRITABLE);
        let error = report(&lacking, Options::default()).unwrap_err();
        assert!(error.to_string().contains(WRITABLE), "{error}");
        // Nor can counts that do not tell the kinds of file apart.
        let mut kindless = collected(two_kinds());
        for name in &mut kindless.bits {
            if name == LIBRARY {
                *name = "probe.something_else".to_owned();
            }
        }
        let error = report(&kindless, Options::default()).unwrap_err();
        assert!(error.to_string().contains(LIBRARY), "{error}");
        // Without a training part there is nothing to fit weights to.
        let no_training = collected(vec![group(Subset::Test, true, &[], 5)]);
        assert!(report(&no_training, Options::default()).is_err());
    }

    /// The counts in `calibration/` are what the weights and the threshold
    /// in the scanner come from, and `calibration/report.txt` is what this
    /// tool prints for them. If a weight is changed by hand, or the counts
    /// are replaced without fitting again, this fails.
    #[test]
    fn the_scanner_has_what_the_counts_in_the_repository_give() {
        let folder = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../calibration");
        let counts = crate::collect::merge(vec![
            Collected::read(&folder.join("ember2024-counts.zip")).unwrap(),
            Collected::read(&folder.join("installed-counts.json")).unwrap(),
        ])
        .unwrap();
        let report = report(&counts, Options::default()).unwrap();

        let differing: Vec<String> = report
            .indicators
            .iter()
            .filter(|entry| entry.weight_in_use != Some(entry.weight_by_rule))
            .map(|entry| {
                format!(
                    "{} has {:?} and the counts give {}",
                    entry.id, entry.weight_in_use, entry.weight_by_rule
                )
            })
            .collect();
        assert!(differing.is_empty(), "{differing:#?}");
        assert!(report.weights_match);
        assert_eq!(
            warden_pe::SUSPICIOUS_FROM,
            report.by_rule.suspicious_from,
            "the threshold in the scanner is not the one the counts give"
        );
        assert!(report.threshold_matches);
        assert_eq!(report.in_use, report.by_rule);

        // No fitted weight sits so close to a half that rounding could go
        // the other way on another machine.
        for (id, decibans) in &report.fit.weights {
            let from_half = ((decibans - decibans.floor()) - 0.5).abs();
            assert!(from_half > 1e-3, "{id} is fitted at {decibans}");
            assert!(
                *decibans >= MIN_DECIBANS + 1e-3,
                "{id} is fitted at {decibans}"
            );
        }

        // No file of the Windows installation that was counted is flagged.
        let all = report.in_use.by_kind.last().unwrap();
        assert_eq!(all.kind, None);
        let at_threshold = all.at(report.in_use.suspicious_from);
        assert!(at_threshold.system.of > 5_000 && at_threshold.software.of > 5_000);
        assert_eq!(at_threshold.system.flagged, 0);
        assert_eq!(at_threshold.software.flagged, 0);

        let written = std::fs::read_to_string(folder.join("report.txt")).unwrap();
        assert!(
            written == render_text(&counts, &report),
            "calibration/report.txt is not what the tool prints for the counts; write it again \
             with the command in calibration/README.md"
        );
    }

    #[test]
    fn numbers_are_written_for_people() {
        assert_eq!(grouped(0), "0");
        assert_eq!(grouped(999), "999");
        assert_eq!(grouped(1_000), "1,000");
        assert_eq!(grouped(1_234_567), "1,234,567");
        assert_eq!(percent(0.0), "0");
        assert_eq!(percent(0.5), "50.00");
        assert_eq!(percent(0.001), "0.10");
        assert_eq!(percent(0.000_171), "0.0171");
        assert_eq!(percent(0.000_012), "0.0012");
        assert_eq!(
            counted(Flagged {
                flagged: 5,
                of: 40_000
            }),
            "0.0125 % (5 of 40,000)"
        );
        assert_eq!(counted(Flagged::default()), "-");
    }
}

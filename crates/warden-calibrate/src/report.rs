//! Turns counts into the numbers the heuristics rest on: how often each
//! indicator applies to malicious and to benign files, the weight that
//! follows from it, and what the score built from the weights does.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use anyhow::{Context as _, bail};
use serde::Serialize;
use warden_pe::indicators;

use crate::collect::{Collected, IMPORT_BINS, Kind, Subset};

/// An indicator gets a weight only if it applies to at least this many
/// malicious files of the training part. Below that, the ratio is a guess.
pub const MIN_MALICIOUS_HITS: u64 = 500;
/// An indicator gets a weight only if it is at least twice as common in
/// malicious files as in benign ones: 3 decibans.
pub const MIN_DECIBANS: f64 = 3.0;
/// No indicator weighs more than this, however lopsided its counts. A
/// ratio of a hundred to one rests on very few benign files, and a single
/// indicator should not be able to settle the matter.
pub const MAX_WEIGHT: u8 = 20;

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

    /// The weight the rule gives: the decibans, rounded, if there is enough
    /// to go on, and nothing otherwise.
    pub fn weight(&self) -> u8 {
        let decibans = self.decibans();
        if self.malicious_hits < MIN_MALICIOUS_HITS || decibans < MIN_DECIBANS {
            return 0;
        }
        (decibans.round() as u8).min(MAX_WEIGHT)
    }
}

fn share(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        0.0
    } else {
        part as f64 / whole as f64
    }
}

/// The measurement of one indicator or probe.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Measured {
    pub id: String,
    /// The weight the scanner uses. `None` for a probe.
    pub weight_in_use: Option<u8>,
    /// The weight the rule gives from the training part.
    pub weight_by_rule: u8,
    /// On the training part, all kinds of file together.
    pub train: Rates,
    /// On the test part: the weeks after the training part.
    pub test: Rates,
    /// On the training part, per kind of file.
    pub train_by_kind: BTreeMap<String, Rates>,
    pub train_decibans: f64,
    pub test_decibans: f64,
}

/// What a score threshold does.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ThresholdRow {
    /// Files with at least this score are flagged.
    pub threshold: u32,
    /// Share of the malicious and of the benign files that are flagged.
    pub train_detected: f64,
    pub train_false_alarms: f64,
    pub test_detected: f64,
    pub test_false_alarms: f64,
    /// On the test part, per kind of file: detected, false alarms.
    pub test_by_kind: BTreeMap<String, (f64, f64)>,
    /// Share of the challenge set that is flagged. All of it is malicious.
    pub challenge_detected: f64,
}

/// What a set of weights does as a score.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ScoreTable {
    /// The weights, by indicator.
    pub weights: BTreeMap<String, u8>,
    /// Probability that a malicious file scores higher than a benign one,
    /// with ties counted half: the area under the ROC curve.
    pub train_auc: f64,
    pub test_auc: f64,
    pub rows: Vec<ThresholdRow>,
}

/// Number of files in one part of the dataset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Population {
    pub subset: Subset,
    pub kind: Kind,
    pub malicious: u64,
    pub benign: u64,
}

/// Everything computed from the counts.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Report {
    /// The rule that turns counts into weights.
    pub rule: RuleInfo,
    pub populations: Vec<Population>,
    pub indicators: Vec<Measured>,
    pub probes: Vec<Measured>,
    /// The score with the weights the scanner uses.
    pub in_use: ScoreTable,
    /// The score with the weights the rule gives from these counts.
    pub by_rule: ScoreTable,
    /// Whether the two are the same weights.
    pub weights_match: bool,
    /// Shares of files per range of a number, see [`Collected`].
    pub distributions: BTreeMap<String, Vec<u64>>,
}

/// The constants of the weight rule, written into the report so that it
/// explains itself.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RuleInfo {
    pub min_malicious_hits: u64,
    pub min_decibans: f64,
    pub max_weight: u8,
}

struct Row {
    subset: Subset,
    kind: Kind,
    malicious: bool,
    pattern: u128,
    files: u64,
}

fn rows_of(collected: &Collected) -> anyhow::Result<Vec<Row>> {
    collected
        .groups
        .iter()
        .map(|group| {
            Ok(Row {
                subset: group.subset,
                kind: group.kind,
                malicious: group.malicious,
                pattern: u128::from_str_radix(&group.pattern, 16)
                    .with_context(|| format!("{:?} is not a pattern", group.pattern))?,
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
            Subset::Challenge => {}
        }
    }
    Measured {
        id: id.to_owned(),
        weight_in_use,
        weight_by_rule: train.weight(),
        train_decibans: train.decibans(),
        test_decibans: test.decibans(),
        train,
        test,
        train_by_kind: by_kind,
    }
}

/// Scores per file count: `[malicious, benign]` by score.
type Spread = BTreeMap<u32, [u64; 2]>;

fn flagged_share(spread: &Spread, threshold: u32, malicious: bool) -> f64 {
    let column = usize::from(!malicious);
    let total: u64 = spread.values().map(|counts| counts[column]).sum();
    let flagged: u64 = spread
        .range(threshold..)
        .map(|(_, counts)| counts[column])
        .sum();
    share(flagged, total)
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

/// `weights` holds, for every indicator, its bit in the patterns, its
/// identifier and its weight.
fn score_table(rows: &[Row], weights: &[(usize, String, u8)]) -> ScoreTable {
    let score = |pattern: u128| -> u32 {
        weights
            .iter()
            .filter(|(bit, _, _)| pattern & (1 << bit) != 0)
            .map(|(_, _, weight)| u32::from(*weight))
            .sum()
    };
    let mut train = Spread::new();
    let mut test = Spread::new();
    let mut challenge = Spread::new();
    let mut test_by_kind: BTreeMap<Kind, Spread> = BTreeMap::new();
    for row in rows {
        let value = score(row.pattern);
        let column = usize::from(!row.malicious);
        let spread = match row.subset {
            Subset::Train => &mut train,
            Subset::Test => {
                test_by_kind
                    .entry(row.kind)
                    .or_default()
                    .entry(value)
                    .or_default()[column] += row.files;
                &mut test
            }
            Subset::Challenge => &mut challenge,
        };
        spread.entry(value).or_default()[column] += row.files;
    }

    let mut thresholds: Vec<u32> = train
        .keys()
        .chain(test.keys())
        .chain(challenge.keys())
        .copied()
        .filter(|score| *score > 0)
        .collect();
    thresholds.sort_unstable();
    thresholds.dedup();
    let rows = thresholds
        .into_iter()
        .map(|threshold| ThresholdRow {
            threshold,
            train_detected: flagged_share(&train, threshold, true),
            train_false_alarms: flagged_share(&train, threshold, false),
            test_detected: flagged_share(&test, threshold, true),
            test_false_alarms: flagged_share(&test, threshold, false),
            test_by_kind: test_by_kind
                .iter()
                .map(|(kind, spread)| {
                    (
                        kind.name().to_owned(),
                        (
                            flagged_share(spread, threshold, true),
                            flagged_share(spread, threshold, false),
                        ),
                    )
                })
                .collect(),
            challenge_detected: flagged_share(&challenge, threshold, true),
        })
        .collect();
    ScoreTable {
        weights: weights
            .iter()
            .filter(|(_, _, weight)| *weight > 0)
            .map(|(_, id, weight)| (id.clone(), *weight))
            .collect(),
        train_auc: auc(&train),
        test_auc: auc(&test),
        rows,
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
pub fn report(collected: &Collected) -> anyhow::Result<Report> {
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

    let mut populations: BTreeMap<(Subset, Kind), [u64; 2]> = BTreeMap::new();
    for row in &rows {
        populations.entry((row.subset, row.kind)).or_default()[usize::from(!row.malicious)] +=
            row.files;
    }

    let measured: Vec<Measured> = indicators::all()
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

    let weights = |pick: &dyn Fn(&Measured) -> u8| -> Vec<(usize, String, u8)> {
        measured
            .iter()
            .filter_map(|entry| Some((bit_of(&entry.id)?, entry.id.clone(), pick(entry))))
            .collect()
    };
    let in_use = weights(&|entry| entry.weight_in_use.unwrap_or(0));
    let by_rule = weights(&|entry| entry.weight_by_rule);
    Ok(Report {
        rule: RuleInfo {
            min_malicious_hits: MIN_MALICIOUS_HITS,
            min_decibans: MIN_DECIBANS,
            max_weight: MAX_WEIGHT,
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
        weights_match: in_use == by_rule,
        in_use: score_table(&rows, &in_use),
        by_rule: score_table(&rows, &by_rule),
        indicators: measured,
        probes,
        distributions: collected.distributions.clone(),
    })
}

fn percent(value: f64) -> String {
    if value == 0.0 {
        "0".to_owned()
    } else if value < 0.0001 {
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

fn measured_lines(out: &mut String, list: &[Measured]) {
    let _ = writeln!(
        out,
        "  {:<36} {:>8} {:>8} {:>8} {:>6} {:>6} {:>4} {:>4}   dB Win32 / Win64 / .NET",
        "id", "mal %", "ben %", "ratio", "dB", "dBtest", "use", "rule"
    );
    for entry in list {
        let kinds: Vec<String> = Kind::ALL
            .iter()
            .map(|kind| {
                entry.train_by_kind.get(kind.name()).map_or_else(
                    || "-".to_owned(),
                    |rates| format!("{:.1}", rates.decibans()),
                )
            })
            .collect();
        let _ = writeln!(
            out,
            "  {:<36} {:>8} {:>8} {:>8.2} {:>6.1} {:>6.1} {:>4} {:>4}   {}",
            entry.id,
            percent(entry.train.malicious_share()),
            percent(entry.train.benign_share()),
            entry.train.ratio(),
            entry.train_decibans,
            entry.test_decibans,
            entry
                .weight_in_use
                .map_or_else(|| "-".to_owned(), |weight| weight.to_string()),
            entry.weight_by_rule,
            kinds.join(" / "),
        );
    }
}

fn score_lines(out: &mut String, table: &ScoreTable) {
    let _ = writeln!(
        out,
        "  area under the ROC curve: {:.4} on the training part, {:.4} on the test part",
        table.train_auc, table.test_auc
    );
    let _ = writeln!(
        out,
        "  {:>5} {:>9} {:>9} {:>9} {:>9}   {:<32} {:>9}",
        "score",
        "train det",
        "train FA",
        "test det",
        "test FA",
        "test FA Win32 / Win64 / .NET",
        "challenge"
    );
    for row in &table.rows {
        let kinds: Vec<String> = Kind::ALL
            .iter()
            .map(|kind| {
                row.test_by_kind.get(kind.name()).map_or_else(
                    || "-".to_owned(),
                    |(_, false_alarms)| percent(*false_alarms),
                )
            })
            .collect();
        let _ = writeln!(
            out,
            "  {:>5} {:>9} {:>9} {:>9} {:>9}   {:<32} {:>9}",
            format!(">={}", row.threshold),
            percent(row.train_detected),
            percent(row.train_false_alarms),
            percent(row.test_detected),
            percent(row.test_false_alarms),
            kinds.join(" / "),
            percent(row.challenge_detected),
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

/// The report as text for a terminal or a build log.
pub fn render_text(collected: &Collected, report: &Report) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Dataset files");
    for input in &collected.inputs {
        let _ = writeln!(
            out,
            "  {}: {} records, {} counted, {} of other kinds, {} not parsed as an executable, {} without a label, {} unreadable lines",
            input.name,
            grouped(input.records),
            grouped(input.counted),
            grouped(input.other_kinds),
            grouped(input.not_parsed_as_pe),
            grouped(input.unlabelled),
            grouped(input.unreadable),
        );
    }
    for error in &collected.first_errors {
        let _ = writeln!(out, "  unreadable: {error}");
    }
    let _ = writeln!(out, "\nFiles counted");
    for population in &report.populations {
        let _ = writeln!(
            out,
            "  {:<10} {:<6} {:>10} malicious {:>10} benign",
            population.subset.name(),
            population.kind.name(),
            grouped(population.malicious),
            grouped(population.benign),
        );
    }
    let _ = writeln!(
        out,
        "\nIndicators, measured on the training part\n  (mal %, ben %: share of the malicious and of the benign files it applies to; dB: ten times the base-ten logarithm of the ratio; use: the weight the scanner has; rule: the weight these counts give)"
    );
    measured_lines(&mut out, &report.indicators);
    let _ = writeln!(
        out,
        "\nProbes: other thresholds and properties, for comparison"
    );
    measured_lines(&mut out, &report.probes);
    let _ = writeln!(out, "\nThe score with the weights the scanner has");
    score_lines(&mut out, &report.in_use);
    if report.weights_match {
        let _ = writeln!(
            out,
            "\nThe weights the scanner has are the weights the rule gives from these counts."
        );
    } else {
        let _ = writeln!(
            out,
            "\nThe score with the weights the rule gives from these counts"
        );
        score_lines(&mut out, &report.by_rule);
    }
    out.push('\n');
    distribution_lines(&mut out, report);
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::collect::{Group, SCHEMA, bit_names};

    fn close(left: f64, right: f64) -> bool {
        (left - right).abs() < 1e-9
    }

    #[test]
    fn ratios_and_weights_follow_from_counts() {
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
        assert_eq!(rates.weight(), 10);

        // Too few malicious files to go on.
        let rare = Rates {
            malicious_hits: 499,
            benign_hits: 1,
            ..rates
        };
        assert!(rare.decibans() > 20.0);
        assert_eq!(rare.weight(), 0);
        // As common in benign files: no evidence.
        let even = Rates {
            benign_hits: 20_000,
            ..rates
        };
        assert_eq!(even.weight(), 0);
        // No benign file at all: a large weight, and not an infinite one.
        let never_benign = Rates {
            benign_hits: 0,
            ..rates
        };
        assert!(never_benign.ratio().is_finite());
        assert_eq!(never_benign.weight(), MAX_WEIGHT);
        // Nothing counted.
        assert_eq!(Rates::default().weight(), 0);
        assert!(close(Rates::default().malicious_share(), 0.0));
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
        assert!(close(flagged_share(&half, 1, true), 0.5));
        assert!(close(flagged_share(&half, 1, false), 0.0));
        assert!(close(flagged_share(&half, 0, false), 1.0));
        assert!(close(auc(&Spread::new()), 0.0));
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
            kind: Kind::Win32,
            malicious,
            pattern: format!("{pattern:x}"),
            files,
        }
    }

    #[test]
    fn a_report_measures_each_indicator_and_scores_with_the_rule() {
        let packer = "sections.packer_name";
        let tls = "tables.tls";
        let counts = collected(vec![
            // Training part: the packer name is in 40 % of malicious and
            // 1 % of benign files; the TLS table is as common in both.
            group(Subset::Train, true, &[packer, tls], 2_000),
            group(Subset::Train, true, &[packer], 2_000),
            group(Subset::Train, true, &[tls], 3_000),
            group(Subset::Train, true, &[], 3_000),
            group(Subset::Train, false, &[packer], 100),
            group(Subset::Train, false, &[tls], 5_000),
            group(Subset::Train, false, &[], 4_900),
            // Test part.
            group(Subset::Test, true, &[packer], 300),
            group(Subset::Test, true, &[], 700),
            group(Subset::Test, false, &[packer], 20),
            group(Subset::Test, false, &[], 980),
            group(Subset::Challenge, true, &[packer], 1),
            group(Subset::Challenge, true, &[], 3),
        ]);
        let report = report(&counts).unwrap();

        assert_eq!(report.populations.len(), 3);
        assert_eq!(report.populations[0].malicious, 10_000);
        assert_eq!(report.populations[0].benign, 10_000);

        let by_id = |id: &str| {
            report
                .indicators
                .iter()
                .find(|entry| entry.id == id)
                .unwrap()
        };
        let measured = by_id(packer);
        assert_eq!(measured.train.malicious_hits, 4_000);
        assert_eq!(measured.train.benign_hits, 100);
        assert!((measured.train.ratio() - 40.0).abs() < 0.3);
        assert_eq!(measured.weight_by_rule, 16);
        assert_eq!(measured.test.malicious_hits, 300);
        assert_eq!(by_id(tls).weight_by_rule, 0);

        let probe = report
            .probes
            .iter()
            .find(|entry| entry.id == "probe.is_dll")
            .unwrap();
        assert_eq!(probe.weight_in_use, None);
        assert_eq!(probe.train.malicious_files, 10_000);

        // With the rule's weights, a score of 16 is the packer name alone.
        assert_eq!(
            report.by_rule.weights,
            BTreeMap::from([(packer.to_owned(), 16)])
        );
        assert_eq!(report.by_rule.rows.len(), 1);
        let row = &report.by_rule.rows[0];
        assert_eq!(row.threshold, 16);
        assert!(close(row.train_detected, 0.4));
        assert!(close(row.train_false_alarms, 0.01));
        assert!(close(row.test_detected, 0.3));
        assert!(close(row.test_false_alarms, 0.02));
        assert!(close(row.challenge_detected, 0.25));
        assert!(close(row.test_by_kind["Win32"].1, 0.02));
        // 30 % stand out, the rest tie with 98 % of the benign files.
        assert!((report.by_rule.test_auc - (0.3 * 0.99 + 0.7 * 0.98 * 0.5)).abs() < 1e-9);

        let text = render_text(&counts, &report);
        assert!(text.contains("sections.packer_name"), "{text}");
        assert!(text.contains(">=16"), "{text}");
    }

    #[test]
    fn counts_are_matched_to_indicators_by_name() {
        let packer = "sections.packer_name";
        let groups = vec![
            group(Subset::Train, true, &[packer], 6_000),
            group(Subset::Train, true, &[], 4_000),
            group(Subset::Train, false, &[packer], 600),
            group(Subset::Train, false, &[], 9_400),
        ];
        let expected = report(&collected(groups.clone())).unwrap();

        // The same counts with their bits in another order, and with a bit
        // for an indicator the scanner no longer has.
        let mut shuffled = collected(groups);
        let old_bit = shuffled
            .bits
            .iter()
            .position(|name| name == packer)
            .unwrap();
        shuffled.bits.insert(0, "retired.indicator".to_owned());
        for group in &mut shuffled.groups {
            let pattern = u128::from_str_radix(&group.pattern, 16).unwrap();
            assert!(pattern == 0 || pattern == 1 << old_bit);
            // Everything moved up by one; the retired bit is set everywhere.
            group.pattern = format!("{:x}", (pattern << 1) | 1);
        }
        let report_of_shuffled = report(&shuffled).unwrap();
        assert_eq!(report_of_shuffled.indicators, expected.indicators);
        assert_eq!(report_of_shuffled.by_rule, expected.by_rule);
        let retired = report_of_shuffled
            .probes
            .iter()
            .find(|entry| entry.id == "retired.indicator")
            .unwrap();
        assert_eq!(retired.train.malicious_hits, 10_000);

        // Counts that lack an indicator the scanner has cannot be used.
        let mut lacking = collected(Vec::new());
        lacking.bits.retain(|name| name != packer);
        let error = report(&lacking).unwrap_err();
        assert!(error.to_string().contains(packer), "{error}");
    }

    #[test]
    fn numbers_are_written_for_people() {
        assert_eq!(grouped(0), "0");
        assert_eq!(grouped(999), "999");
        assert_eq!(grouped(1_000), "1,000");
        assert_eq!(grouped(1_234_567), "1,234,567");
        assert_eq!(percent(0.0), "0");
        assert_eq!(percent(0.5), "50.00");
        assert_eq!(percent(0.000_012), "0.0012");
    }
}

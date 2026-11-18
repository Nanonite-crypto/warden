//! Reads dataset files and counts which indicators apply to which files.
//!
//! The result is small: for every combination of indicators that occurs,
//! the number of files that show exactly that combination, split by part of
//! the dataset, kind of file and label. Everything the report needs can be
//! computed from those counts, for any choice of weights, without reading
//! the dataset again.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context as _, bail};
use serde::{Deserialize, Serialize};
use warden_pe::PeFacts;
use warden_pe::indicators::{self, Context, evaluate};

use crate::ember::Record;

/// Version of the file that [`Collected`] is written to.
pub const SCHEMA: u32 = 1;

/// The longest line that is parsed. A record with a very long import table
/// is a few megabytes.
const MAX_LINE_BYTES: usize = 256 * 1024 * 1024;

/// Which part of the dataset a file belongs to. The authors split it by
/// time: the first 52 weeks are for training, the last 12 for testing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Subset {
    /// The first 52 weeks.
    Train,
    /// The last 12 weeks.
    Test,
    /// Malicious files that no antivirus product detected at first.
    Challenge,
}

impl Subset {
    /// Tells the part from the name of a dataset file, which contains it.
    pub fn from_name(name: &str) -> Option<Self> {
        let name = name.to_ascii_lowercase();
        if name.contains("challenge") {
            Some(Self::Challenge)
        } else if name.contains("train") {
            Some(Self::Train)
        } else if name.contains("test") {
            Some(Self::Test)
        } else {
            None
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Train => "train",
            Self::Test => "test",
            Self::Challenge => "challenge",
        }
    }
}

/// The dataset's three kinds of Windows executable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Kind {
    /// 32-bit native code.
    Win32,
    /// 64-bit native code.
    Win64,
    /// .NET assemblies.
    #[serde(rename = "Dot_Net")]
    DotNet,
}

impl Kind {
    pub const ALL: [Self; 3] = [Self::Win32, Self::Win64, Self::DotNet];

    fn from_name(name: &str) -> Option<Self> {
        match name {
            "Win32" => Some(Self::Win32),
            "Win64" => Some(Self::Win64),
            "Dot_Net" => Some(Self::DotNet),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Win32 => "Win32",
            Self::Win64 => "Win64",
            Self::DotNet => ".NET",
        }
    }
}

/// A question about a file that is asked only here, to see what another
/// threshold would do. A probe never reaches the scanner.
struct Probe {
    id: &'static str,
    test: fn(&PeFacts) -> bool,
}

fn max_code_entropy(facts: &PeFacts) -> Option<f64> {
    facts
        .sections
        .iter()
        .filter(|section| section.is_executable() && section.raw_size >= 1024)
        .map(|section| section.entropy)
        .max_by(f64::total_cmp)
}

fn max_data_entropy(facts: &PeFacts) -> Option<f64> {
    facts
        .sections
        .iter()
        .filter(|section| !section.is_executable() && section.raw_size >= 4096)
        .filter(|section| {
            !matches!(
                section.name.to_ascii_lowercase().as_str(),
                ".rsrc" | ".reloc"
            )
        })
        .map(|section| section.entropy)
        .max_by(f64::total_cmp)
}

fn runs_native_code(facts: &PeFacts) -> bool {
    !facts.is_dotnet() && facts.entry_point != 0
}

fn overlay_share(facts: &PeFacts) -> f64 {
    if facts.file_size == 0 {
        return 0.0;
    }
    let beyond = facts
        .overlay
        .size
        .saturating_sub(u64::from(facts.signature_size));
    beyond as f64 / facts.file_size as f64
}

const PROBES: &[Probe] = &[
    Probe {
        id: "probe.code_entropy_ge_6.5",
        test: |facts| max_code_entropy(facts).is_some_and(|entropy| entropy >= 6.5),
    },
    Probe {
        id: "probe.code_entropy_ge_6.8",
        test: |facts| max_code_entropy(facts).is_some_and(|entropy| entropy >= 6.8),
    },
    Probe {
        id: "probe.code_entropy_ge_7.2",
        test: |facts| max_code_entropy(facts).is_some_and(|entropy| entropy >= 7.2),
    },
    Probe {
        id: "probe.code_entropy_ge_7.5",
        test: |facts| max_code_entropy(facts).is_some_and(|entropy| entropy >= 7.5),
    },
    Probe {
        id: "probe.data_entropy_ge_7.0",
        test: |facts| max_data_entropy(facts).is_some_and(|entropy| entropy >= 7.0),
    },
    Probe {
        id: "probe.data_entropy_ge_7.5",
        test: |facts| max_data_entropy(facts).is_some_and(|entropy| entropy >= 7.5),
    },
    Probe {
        id: "probe.file_entropy_ge_6.8",
        test: |facts| facts.file_size >= 16 * 1024 && facts.file_entropy >= 6.8,
    },
    Probe {
        id: "probe.file_entropy_ge_7.0",
        test: |facts| facts.file_size >= 16 * 1024 && facts.file_entropy >= 7.0,
    },
    Probe {
        id: "probe.file_entropy_ge_7.5",
        test: |facts| facts.file_size >= 16 * 1024 && facts.file_entropy >= 7.5,
    },
    Probe {
        id: "probe.imports_1_to_3",
        test: |facts| runs_native_code(facts) && (1..=3).contains(&facts.import_count()),
    },
    Probe {
        id: "probe.imports_1_to_10",
        test: |facts| runs_native_code(facts) && (1..=10).contains(&facts.import_count()),
    },
    Probe {
        id: "probe.imports_1_to_20",
        test: |facts| runs_native_code(facts) && (1..=20).contains(&facts.import_count()),
    },
    Probe {
        id: "probe.overlay_share_ge_10",
        test: |facts| overlay_share(facts) >= 0.10,
    },
    Probe {
        id: "probe.overlay_share_ge_50",
        test: |facts| overlay_share(facts) >= 0.50,
    },
    Probe {
        id: "probe.sections_le_2",
        test: |facts| facts.sections.len() <= 2,
    },
    Probe {
        id: "probe.sections_ge_8",
        test: |facts| facts.sections.len() >= 8,
    },
    Probe {
        id: "probe.size_lt_16k",
        test: |facts| facts.file_size < 16 * 1024,
    },
    Probe {
        id: "probe.size_ge_10m",
        test: |facts| facts.file_size >= 10 * 1024 * 1024,
    },
    Probe {
        id: "probe.no_guard_cf",
        test: |facts| facts.image_flags & warden_pe::image_flags::GUARD_CF == 0,
    },
    Probe {
        id: "probe.no_high_entropy_va_64",
        test: |facts| {
            facts.format == warden_pe::Format::Pe32Plus
                && facts.image_flags & warden_pe::image_flags::HIGH_ENTROPY_VA == 0
        },
    },
    Probe {
        id: "probe.program_with_exports",
        test: |facts| !facts.is_dll && facts.exports > 0,
    },
    Probe {
        id: "probe.driver",
        test: |facts| facts.subsystem == 1,
    },
    Probe {
        id: "probe.is_dll",
        test: |facts| facts.is_dll,
    },
    Probe {
        id: "probe.is_dotnet",
        test: PeFacts::is_dotnet,
    },
    Probe {
        id: "probe.has_signature",
        test: |facts| facts.signature_size > 0,
    },
    Probe {
        id: "probe.no_entry_point",
        test: |facts| facts.entry_point == 0,
    },
];

/// The names of the bits of a pattern, lowest bit first: every indicator,
/// then every probe.
pub fn bit_names() -> Vec<String> {
    indicators::all()
        .map(|indicator| indicator.id.to_owned())
        .chain(PROBES.iter().map(|probe| probe.id.to_owned()))
        .collect()
}

/// Which indicators and probes apply to a file, one bit each.
fn pattern_of(facts: &PeFacts, context: &Context) -> u128 {
    let mut pattern = 0u128;
    let hits = evaluate(facts, context);
    let mut hit_ids = hits.iter().map(|hit| hit.indicator.id).peekable();
    let mut bit = 0u32;
    // Hits come in the order of the indicators.
    for indicator in indicators::all() {
        if hit_ids.peek() == Some(&indicator.id) {
            pattern |= 1 << bit;
            hit_ids.next();
        }
        bit += 1;
    }
    for probe in PROBES {
        if (probe.test)(facts) {
            pattern |= 1 << bit;
        }
        bit += 1;
    }
    pattern
}

/// Files that show one combination of indicators.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Group {
    pub subset: Subset,
    pub kind: Kind,
    pub malicious: bool,
    /// The combination, as a hexadecimal number with one bit per entry of
    /// [`Collected::bits`].
    pub pattern: String,
    pub files: u64,
}

/// How the values of one number are spread over the files.
pub const DISTRIBUTIONS: [&str; 4] = [
    "max_code_entropy",
    "file_entropy",
    "import_count",
    "section_count",
];

/// Upper ends of the ranges that import counts are sorted into; the last
/// range is open.
pub const IMPORT_BINS: [usize; 8] = [0, 5, 10, 20, 50, 100, 200, 500];
/// Entropy is sorted into ranges this wide. A file without a section to
/// measure gets a range of its own, after the last.
pub const ENTROPY_BIN: f64 = 0.25;
const ENTROPY_BINS: usize = 33;
const SECTION_BINS: usize = 14;

fn distribution_bins(facts: &PeFacts) -> [usize; 4] {
    let entropy_bin = |entropy: f64| ((entropy / ENTROPY_BIN) as usize).min(ENTROPY_BINS - 2);
    let import_bin = if runs_native_code(facts) {
        let count = facts.import_count();
        IMPORT_BINS
            .iter()
            .position(|upper| count <= *upper)
            .unwrap_or(IMPORT_BINS.len())
    } else {
        // Not a native program: outside the ranges.
        IMPORT_BINS.len() + 1
    };
    [
        max_code_entropy(facts).map_or(ENTROPY_BINS - 1, entropy_bin),
        entropy_bin(facts.file_entropy),
        import_bin,
        facts.sections.len().min(SECTION_BINS - 1),
    ]
}

fn distribution_len(index: usize) -> usize {
    match index {
        0 | 1 => ENTROPY_BINS,
        2 => IMPORT_BINS.len() + 2,
        _ => SECTION_BINS,
    }
}

/// What was read from one dataset file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputSummary {
    pub name: String,
    /// Lines that held a record.
    pub records: u64,
    /// Records of Windows executables with a label, which were counted.
    pub counted: u64,
    /// Records of other kinds of file: Android packages, PDF and ELF files.
    pub other_kinds: u64,
    /// Records the dataset's own parser could not read as an executable.
    pub not_parsed_as_pe: u64,
    /// Records without a label.
    pub unlabelled: u64,
    /// Lines that are not a record.
    pub unreadable: u64,
}

/// Everything that was counted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Collected {
    pub schema: u32,
    /// The dataset files, in the order they were given.
    pub inputs: Vec<InputSummary>,
    /// Names of the bits of a pattern, lowest bit first.
    pub bits: Vec<String>,
    /// One entry per combination of indicators that occurs.
    pub groups: Vec<Group>,
    /// Counts per range, by `subset/label/number`, for the numbers in
    /// [`DISTRIBUTIONS`].
    pub distributions: BTreeMap<String, Vec<u64>>,
    /// The first lines that could not be read, to see what is wrong.
    pub first_errors: Vec<String>,
}

#[derive(Default)]
struct Tally {
    groups: HashMap<(Subset, Kind, bool, u128), u64>,
    distributions: HashMap<(Subset, bool, usize), Vec<u64>>,
    inputs: BTreeMap<usize, InputSummary>,
    errors: Vec<String>,
}

impl Tally {
    fn merge(&mut self, other: Tally) {
        for (key, files) in other.groups {
            *self.groups.entry(key).or_insert(0) += files;
        }
        for (key, counts) in other.distributions {
            let total = self
                .distributions
                .entry(key)
                .or_insert_with(|| vec![0; counts.len()]);
            for (sum, count) in total.iter_mut().zip(counts) {
                *sum += count;
            }
        }
        for (index, summary) in other.inputs {
            let total = self.inputs.entry(index).or_default();
            total.name = summary.name;
            total.records += summary.records;
            total.counted += summary.counted;
            total.other_kinds += summary.other_kinds;
            total.not_parsed_as_pe += summary.not_parsed_as_pe;
            total.unlabelled += summary.unlabelled;
            total.unreadable += summary.unreadable;
        }
        self.errors.extend(other.errors);
    }
}

/// One file of records: a `.jsonl` file, or one inside a zip archive.
#[derive(Debug, Clone)]
struct Unit {
    input: usize,
    path: PathBuf,
    /// Index of the member, for a zip archive.
    member: Option<usize>,
    name: String,
    subset: Subset,
}

fn units_of(input: usize, path: &Path) -> anyhow::Result<Vec<Unit>> {
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let is_zip = path
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("zip"));
    if !is_zip {
        let Some(subset) = Subset::from_name(&file_name) else {
            bail!(
                "{}: the name says neither train, test nor challenge",
                path.display()
            );
        };
        return Ok(vec![Unit {
            input,
            path: path.to_owned(),
            member: None,
            name: file_name,
            subset,
        }]);
    }

    let file = File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
    let mut archive = zip::ZipArchive::new(BufReader::new(file))
        .with_context(|| format!("cannot read {} as a zip archive", path.display()))?;
    let mut units = Vec::new();
    for index in 0..archive.len() {
        let member = archive.by_index_raw(index)?;
        let name = member.name()?.into_owned();
        drop(member);
        if !name.to_ascii_lowercase().ends_with(".jsonl") {
            continue;
        }
        // The part is in the member's name, and failing that in the
        // archive's.
        let Some(subset) = Subset::from_name(&name).or_else(|| Subset::from_name(&file_name))
        else {
            bail!(
                "{} in {}: the name says neither train, test nor challenge",
                name,
                path.display()
            );
        };
        units.push(Unit {
            input,
            path: path.to_owned(),
            member: Some(index),
            name,
            subset,
        });
    }
    if units.is_empty() {
        bail!("{} holds no .jsonl file", path.display());
    }
    Ok(units)
}

fn count_unit(
    unit: &Unit,
    tally: &mut Tally,
    sample: &Mutex<Option<String>>,
) -> anyhow::Result<()> {
    let file =
        File::open(&unit.path).with_context(|| format!("cannot open {}", unit.path.display()))?;
    match unit.member {
        None => count_lines(unit, BufReader::with_capacity(1 << 20, file), tally, sample),
        Some(index) => {
            let mut archive = zip::ZipArchive::new(BufReader::new(file))?;
            let member = archive.by_index(index)?;
            count_lines(
                unit,
                BufReader::with_capacity(1 << 20, member),
                tally,
                sample,
            )
        }
    }
}

fn count_lines(
    unit: &Unit,
    mut reader: impl BufRead,
    tally: &mut Tally,
    sample: &Mutex<Option<String>>,
) -> anyhow::Result<()> {
    let summary = tally.inputs.entry(unit.input).or_default();
    let mut line = String::new();
    let mut line_number = 0u64;
    loop {
        line.clear();
        let read = (&mut reader)
            .take(MAX_LINE_BYTES as u64)
            .read_line(&mut line)
            .with_context(|| format!("cannot read {}", unit.name))?;
        if read == 0 {
            break;
        }
        line_number += 1;
        if line.trim().is_empty() {
            continue;
        }
        let record: Record = match serde_json::from_str(&line) {
            Ok(record) => record,
            Err(error) => {
                summary.unreadable += 1;
                if tally.errors.len() < 5 {
                    tally
                        .errors
                        .push(format!("{} line {line_number}: {error}", unit.name));
                }
                continue;
            }
        };
        summary.records += 1;
        let Some(kind) = record.file_type.as_deref().and_then(Kind::from_name) else {
            summary.other_kinds += 1;
            continue;
        };
        if !record.is_pe() {
            summary.not_parsed_as_pe += 1;
            continue;
        }
        let malicious = match record.label {
            Some(1) => true,
            Some(0) => false,
            _ => {
                summary.unlabelled += 1;
                continue;
            }
        };
        summary.counted += 1;

        if let Ok(mut slot) = sample.lock()
            && slot.is_none()
        {
            *slot = Some(outline_of(&line));
        }

        let facts = record.facts();
        // A link time is "in the future" relative to the day the file was
        // first seen.
        let context = Context {
            now_unix_secs: record
                .first_submission_date
                .map_or(0, |seconds| seconds.max(0.0) as u64),
        };
        *tally
            .groups
            .entry((unit.subset, kind, malicious, pattern_of(&facts, &context)))
            .or_insert(0) += 1;
        for (index, bin) in distribution_bins(&facts).into_iter().enumerate() {
            tally
                .distributions
                .entry((unit.subset, malicious, index))
                .or_insert_with(|| vec![0; distribution_len(index)])[bin] += 1;
        }
    }
    Ok(())
}

/// The shape of a record: its fields and what kind of value each holds,
/// with long lists cut short. Printed once, so that a run shows what the
/// dataset's records look like.
fn outline_of(line: &str) -> String {
    fn outline(value: &serde_json::Value, depth: usize, out: &mut String) {
        use serde_json::Value;
        match value {
            Value::Object(fields) => {
                if depth >= 4 {
                    out.push_str("{...}");
                    return;
                }
                out.push('{');
                for (index, (name, field)) in fields.iter().enumerate() {
                    if index == 40 {
                        out.push_str(", ...");
                        break;
                    }
                    if index > 0 {
                        out.push_str(", ");
                    }
                    out.push_str(name);
                    out.push_str(": ");
                    outline(field, depth + 1, out);
                }
                out.push('}');
            }
            Value::Array(items) => {
                out.push_str(&format!("[{} x ", items.len()));
                match items.first() {
                    Some(first) => outline(first, depth + 1, out),
                    None => out.push_str("nothing"),
                }
                if let Some(second) = items.get(1).filter(|_| depth < 2) {
                    out.push_str(" | ");
                    outline(second, depth + 1, out);
                }
                out.push(']');
            }
            Value::String(text) => {
                let shown: String = text.chars().take(40).collect();
                out.push_str(&format!("{shown:?}"));
            }
            other => out.push_str(&other.to_string()),
        }
    }
    match serde_json::from_str::<serde_json::Value>(line) {
        Ok(value) => {
            let mut out = String::new();
            outline(&value, 0, &mut out);
            out
        }
        Err(error) => format!("(not JSON: {error})"),
    }
}

/// Counts the records in the given dataset files, using `threads` threads.
/// Returns the counts and the shape of the first record that was counted.
pub fn collect(paths: &[PathBuf], threads: usize) -> anyhow::Result<(Collected, Option<String>)> {
    let mut units = VecDeque::new();
    let mut names = Vec::new();
    for (input, path) in paths.iter().enumerate() {
        names.push(
            path.file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default(),
        );
        units.extend(units_of(input, path)?);
    }
    let queue = Mutex::new(units);
    let sample = Mutex::new(None);
    let failure: Mutex<Option<anyhow::Error>> = Mutex::new(None);

    let mut total = Tally::default();
    std::thread::scope(|scope| {
        let workers: Vec<_> = (0..threads.max(1))
            .map(|_| {
                scope.spawn(|| {
                    let mut tally = Tally::default();
                    loop {
                        let unit = match queue.lock() {
                            Ok(mut queue) => queue.pop_front(),
                            Err(_) => None,
                        };
                        let Some(unit) = unit else {
                            break;
                        };
                        if let Err(error) = count_unit(&unit, &mut tally, &sample) {
                            if let Ok(mut slot) = failure.lock() {
                                slot.get_or_insert(error);
                            }
                            break;
                        }
                    }
                    tally
                })
            })
            .collect();
        for worker in workers {
            if let Ok(tally) = worker.join() {
                total.merge(tally);
            }
        }
    });
    if let Some(error) = failure.into_inner().ok().flatten() {
        return Err(error);
    }

    let mut inputs = Vec::with_capacity(names.len());
    for (index, name) in names.into_iter().enumerate() {
        let mut summary = total.inputs.remove(&index).unwrap_or_default();
        summary.name = name;
        inputs.push(summary);
    }
    let mut groups: Vec<Group> = total
        .groups
        .into_iter()
        .map(|((subset, kind, malicious, pattern), files)| Group {
            subset,
            kind,
            malicious,
            pattern: format!("{pattern:x}"),
            files,
        })
        .collect();
    groups.sort_by(|left, right| {
        (left.subset, left.kind, left.malicious, &left.pattern).cmp(&(
            right.subset,
            right.kind,
            right.malicious,
            &right.pattern,
        ))
    });
    let distributions = total
        .distributions
        .into_iter()
        .map(|((subset, malicious, index), counts)| {
            let label = if malicious { "malicious" } else { "benign" };
            (
                format!("{}/{label}/{}", subset.name(), DISTRIBUTIONS[index]),
                counts,
            )
        })
        .collect();
    total.errors.sort();
    total.errors.truncate(5);

    let sample = sample.into_inner().ok().flatten();
    Ok((
        Collected {
            schema: SCHEMA,
            inputs,
            bits: bit_names(),
            groups,
            distributions,
            first_errors: total.errors,
        },
        sample,
    ))
}

/// Adds up the counts of several runs. They must have been made with the
/// same indicators.
pub fn merge(parts: Vec<Collected>) -> anyhow::Result<Collected> {
    let mut parts = parts.into_iter();
    let Some(mut total) = parts.next() else {
        bail!("nothing to merge");
    };
    let mut groups: BTreeMap<(Subset, Kind, bool, String), u64> = BTreeMap::new();
    let mut add_groups = |list: Vec<Group>| {
        for group in list {
            *groups
                .entry((group.subset, group.kind, group.malicious, group.pattern))
                .or_insert(0) += group.files;
        }
    };
    add_groups(std::mem::take(&mut total.groups));
    for part in parts {
        if part.schema != total.schema || part.bits != total.bits {
            bail!("the counts were made with different indicators and cannot be added up");
        }
        add_groups(part.groups);
        total.inputs.extend(part.inputs);
        for (key, counts) in part.distributions {
            let sums = total
                .distributions
                .entry(key)
                .or_insert_with(|| vec![0; counts.len()]);
            for (sum, count) in sums.iter_mut().zip(counts) {
                *sum += count;
            }
        }
        total.first_errors.extend(part.first_errors);
    }
    total.first_errors.truncate(5);
    total.groups = groups
        .into_iter()
        .map(|((subset, kind, malicious, pattern), files)| Group {
            subset,
            kind,
            malicious,
            pattern,
            files,
        })
        .collect();
    Ok(total)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::io::Write;

    use warden_pe::fixture::Fixture;

    use super::*;
    use crate::ember::record_json;

    fn lines() -> (String, String) {
        let plain = warden_pe::read(&Fixture::plain().build()).unwrap();
        let packed = warden_pe::read(&Fixture::packed_looking().build()).unwrap();
        let mut train = String::new();
        for _ in 0..3 {
            train.push_str(&record_json(&plain, 0, "Win64", 1_700_000_000));
            train.push('\n');
        }
        for _ in 0..2 {
            train.push_str(&record_json(&packed, 1, "Win32", 1_700_000_000));
            train.push('\n');
        }
        train.push_str("this line is not a record\n\n");
        train.push_str(r#"{"label": 1, "file_type": "APK", "general": {"is_pe": 0}}"#);
        train.push('\n');
        train.push_str(r#"{"label": 1, "file_type": "Win32", "general": {"is_pe": 0}}"#);
        train.push('\n');
        train.push_str(
            &record_json(&plain, 0, "Win64", 1_700_000_000)
                .replace(r#""label":0"#, r#""label":null"#),
        );
        train.push('\n');
        let test = format!("{}\n", record_json(&packed, 1, "Dot_Net", 1_700_000_000));
        (train, test)
    }

    #[test]
    fn records_are_counted_by_part_kind_label_and_combination() {
        let dir = tempfile::tempdir().unwrap();
        let (train, test) = lines();
        let train_path = dir.path().join("2023-09-24_Win_train.jsonl");
        std::fs::write(&train_path, &train).unwrap();
        // The test part comes inside a zip archive, as the dataset ships.
        let zip_path = dir.path().join("Dot_Net_test.zip");
        let mut archive = zip::ZipWriter::new(File::create(&zip_path).unwrap());
        let options = zip::write::SimpleFileOptions::default();
        archive.start_file("readme.txt", options).unwrap();
        archive.write_all(b"not records").unwrap();
        archive
            .start_file("2024-11-03_Dot_Net_test.jsonl", options)
            .unwrap();
        archive.write_all(test.as_bytes()).unwrap();
        archive.finish().unwrap();

        let (collected, sample) = collect(&[train_path, zip_path], 3).unwrap();
        assert_eq!(collected.schema, SCHEMA);
        assert_eq!(collected.bits, bit_names());
        assert_eq!(collected.inputs.len(), 2);
        let first = &collected.inputs[0];
        assert_eq!(first.name, "2023-09-24_Win_train.jsonl");
        assert_eq!(
            (
                first.records,
                first.counted,
                first.other_kinds,
                first.not_parsed_as_pe,
                first.unlabelled,
                first.unreadable
            ),
            (8, 5, 1, 1, 1, 1)
        );
        assert_eq!(collected.inputs[1].counted, 1);
        assert_eq!(collected.first_errors.len(), 1);
        assert!(
            collected.first_errors[0].contains("line 6"),
            "{:?}",
            collected.first_errors
        );

        let summary: Vec<(Subset, Kind, bool, u64)> = collected
            .groups
            .iter()
            .map(|group| (group.subset, group.kind, group.malicious, group.files))
            .collect();
        assert_eq!(
            summary,
            [
                (Subset::Train, Kind::Win32, true, 2),
                (Subset::Train, Kind::Win64, false, 3),
                (Subset::Test, Kind::DotNet, true, 1),
            ]
        );
        // The packed-looking file sets the bit of the packer-name indicator.
        let bit = collected
            .bits
            .iter()
            .position(|name| name == "sections.packer_name")
            .unwrap();
        let pattern =
            |index: usize| u128::from_str_radix(&collected.groups[index].pattern, 16).unwrap();
        assert_ne!(pattern(0) & (1 << bit), 0);
        assert_eq!(pattern(1) & (1 << bit), 0);

        let sections = &collected.distributions["train/benign/section_count"];
        assert_eq!(sections.iter().sum::<u64>(), 3);
        assert_eq!(sections[6], 3);
        let imports = &collected.distributions["train/malicious/import_count"];
        assert_eq!(imports[1], 2, "{imports:?}");

        let sample = sample.unwrap();
        assert!(sample.contains("general: {"), "{sample}");
        assert!(sample.contains("histogram: [3 x 1"), "{sample}");

        // Counts of separate runs add up.
        let doubled = merge(vec![collected.clone(), collected.clone()]).unwrap();
        assert_eq!(doubled.groups.len(), 3);
        assert_eq!(
            doubled.groups.iter().map(|group| group.files).sum::<u64>(),
            12
        );
        assert_eq!(doubled.inputs.len(), 4);
        assert_eq!(doubled.distributions["train/benign/section_count"][6], 6);
        let mut other = collected.clone();
        other.bits.pop();
        assert!(merge(vec![collected, other]).is_err());
    }

    #[test]
    fn a_file_whose_name_does_not_say_its_part_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("records.jsonl");
        std::fs::write(&path, "{}\n").unwrap();
        let error = collect(&[path], 1).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("neither train, test nor challenge")
        );
    }

    #[test]
    fn every_bit_has_a_name_and_they_fit() {
        let names = bit_names();
        assert!(names.len() <= 128);
        let unique: std::collections::BTreeSet<&String> = names.iter().collect();
        assert_eq!(unique.len(), names.len());
        assert_eq!(Subset::from_name("Win32_TRAIN.zip"), Some(Subset::Train));
        assert_eq!(Subset::from_name("challenge.zip"), Some(Subset::Challenge));
        assert_eq!(
            Subset::from_name("2024-10-01_Win64_test.jsonl"),
            Some(Subset::Test)
        );
        assert_eq!(Subset::from_name("notes.txt"), None);
    }
}

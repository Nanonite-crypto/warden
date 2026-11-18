//! Turning numbers and reports into text for people.

use std::fmt::Write as _;
use std::io::{IsTerminal, Write as _};
use std::time::Duration;

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use warden_engine::text::printable;
use warden_engine::{
    DetectorInfo, Finding, InfoValue, Member, Progress, ScanObserver, ScanReport, ThreatCategory,
    Verdict,
};

/// Longest path or message printed on one line.
const MAX_LINE_CHARS: usize = 2000;
/// How many detection names are shown in the heading of one detection.
const NAMES_SHOWN: usize = 4;
/// How many files with findings on record are printed in full. The JSON
/// report holds them all.
const RECORDED_SHOWN: usize = 20;

/// Makes text that comes from the scanned system safe to print: file names
/// can hold control characters that would rewrite the terminal.
pub fn shown(text: &str) -> String {
    printable(text, MAX_LINE_CHARS)
}

/// A path, made safe to print.
pub fn shown_path(path: &std::path::Path) -> String {
    shown(&path.to_string_lossy())
}

/// Formats an integer with thousands separators: `1234567` becomes `1,234,567`.
pub fn group_digits(value: u64) -> String {
    let digits = value.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            out.push(',');
        }
        out.push(digit);
    }
    out
}

/// Formats a byte count with decimal units, the same units as "MB/s".
pub fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "kB", "MB", "GB", "TB"];
    if bytes < 1000 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1000.0 && unit < UNITS.len() - 1 {
        value /= 1000.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

/// Formats a duration as milliseconds, seconds or minutes and seconds.
///
/// Durations under ten milliseconds keep one decimal, so that a very quick
/// scan does not read as "0 ms".
pub fn human_duration(duration: Duration) -> String {
    let seconds = duration.as_secs_f64();
    if seconds < 0.01 {
        format!("{:.1} ms", seconds * 1000.0)
    } else if seconds < 1.0 {
        format!("{} ms", duration.as_millis())
    } else if seconds < 60.0 {
        format!("{seconds:.2} s")
    } else {
        let whole = duration.as_secs();
        format!("{} min {} s", whole / 60, whole % 60)
    }
}

/// Formats seconds since the Unix epoch as an RFC 3339 UTC timestamp.
pub fn human_timestamp(unix_secs: u64) -> String {
    i64::try_from(unix_secs)
        .ok()
        .and_then(|secs| OffsetDateTime::from_unix_timestamp(secs).ok())
        .and_then(|moment| moment.format(&Rfc3339).ok())
        .unwrap_or_else(|| format!("{unix_secs} s after the Unix epoch"))
}

fn count(details: &DetectorInfo, key: &str) -> Option<u64> {
    match details.details.get(key) {
        Some(InfoValue::Count(value)) => Some(*value),
        _ => None,
    }
}

fn text<'a>(details: &'a DetectorInfo, key: &str) -> Option<&'a str> {
    match details.details.get(key) {
        Some(InfoValue::Text(value)) => Some(value),
        _ => None,
    }
}

/// One line describing which YARA rules a scan used, if it used any.
pub fn rule_summary(detectors: &[DetectorInfo]) -> Option<String> {
    let yara = detectors.iter().find(|detector| detector.id == "yara")?;
    let rules = count(yara, "rules").unwrap_or(0);
    if text(yara, "origin") == Some("built-in rules") {
        return Some(format!(
            "{} built-in YARA {}",
            group_digits(rules),
            plural(rules, "rule", "rules")
        ));
    }
    let files = count(yara, "rule_files").unwrap_or(0);
    let mut line = format!(
        "{} YARA {} from {} {}",
        group_digits(rules),
        plural(rules, "rule", "rules"),
        group_digits(files),
        plural(files, "file", "files")
    );
    if let Some(excluded) = count(yara, "rules_excluded").filter(|excluded| *excluded > 0) {
        let _ = write!(line, ", {} excluded", group_digits(excluded));
    }
    if let Some(created) = count(yara, "bundle_created_unix_secs") {
        let _ = write!(line, " (bundle built {})", human_timestamp(created));
    }
    if let Some(generated) = count(yara, "rules_generated").filter(|generated| *generated > 0) {
        let _ = write!(
            line,
            "; a tool generated {} of them, and a match of one counts only with a second sign",
            group_digits(generated)
        );
    }
    Some(line)
}

/// One line describing which signatures a scan used.
/// What the heuristic layer runs with, if it runs.
pub fn heuristic_summary(detectors: &[DetectorInfo]) -> Option<String> {
    let heuristic = detectors
        .iter()
        .find(|detector| detector.id == "heuristic")?;
    let scored = count(heuristic, "indicators_scored").unwrap_or(0);
    let mut line = format!(
        "{} scored {} of a Windows executable's structure, suspicious from a score of {}",
        group_digits(scored),
        plural(scored, "indicator", "indicators"),
        group_digits(count(heuristic, "suspicious_from").unwrap_or(0)),
    );
    if let Some(bar) = count(heuristic, "second_sign_from") {
        let _ = write!(line, ", a second sign from {}", group_digits(bar));
    }
    Some(line)
}

pub fn signature_summary(detectors: &[DetectorInfo]) -> String {
    let Some(hash) = detectors.iter().find(|detector| detector.id == "hash") else {
        return "none".to_owned();
    };
    let builtin = count(hash, "builtin_signatures").unwrap_or(0);
    let mut line = format!("{} built-in", group_digits(builtin));
    if let Some(database) = count(hash, "database_signatures") {
        let _ = write!(line, ", {} from database", group_digits(database));
        if let Some(created) = count(hash, "database_created_unix_secs") {
            let _ = write!(line, " (built {})", human_timestamp(created));
        }
    }
    line
}

fn plural(count: u64, singular: &'static str, plural: &'static str) -> &'static str {
    if count == 1 { singular } else { plural }
}

fn category_label(category: ThreatCategory) -> &'static str {
    match category {
        ThreatCategory::Malware => "malware",
        ThreatCategory::TestFile => "test file",
        ThreatCategory::PotentiallyUnwanted => "potentially unwanted",
    }
}

/// The names of the findings, each once, in the order they were found.
fn detection_names(findings: &[Finding]) -> String {
    let mut names: Vec<&str> = Vec::new();
    for finding in findings {
        if !names.contains(&finding.name.as_str()) {
            names.push(&finding.name);
        }
    }
    let mut line = names
        .iter()
        .take(NAMES_SHOWN)
        .map(|name| shown(name))
        .collect::<Vec<_>>()
        .join(", ");
    if names.len() > NAMES_SHOWN {
        let _ = write!(line, ", and {} more", names.len() - NAMES_SHOWN);
    }
    line
}

fn member_line(member: &Member) -> String {
    format!(
        "inside: {} ({} bytes, sha256 {})",
        shown(&member.path.join(" > ")),
        group_digits(member.size),
        member.sha256
    )
}

/// The findings about one file, a line per reason.
fn findings_text(out: &mut String, findings: &[Finding], omitted: u64) {
    // Findings about the same archive member follow one another, so the
    // member is named once, above them.
    let mut current: Option<&Member> = None;
    for finding in findings {
        let member = finding.member.as_ref();
        if member != current {
            if let Some(member) = member {
                let _ = writeln!(out, "    {}", member_line(member));
            }
            current = member;
        }
        let indent = if member.is_some() { "      " } else { "    " };
        let category = category_label(finding.category);
        for reason in &finding.reasons {
            let _ = writeln!(
                out,
                "{indent}{} [{category}]: {}",
                finding.detector,
                shown(reason)
            );
        }
    }
    if omitted > 0 {
        let _ = writeln!(
            out,
            "    ... and {} more {}",
            group_digits(omitted),
            plural(omitted, "finding", "findings")
        );
    }
}

/// Renders a scan report as plain text.
pub fn report_text(report: &ScanReport, show_skipped: bool) -> String {
    let stats = &report.stats;
    let mut out = String::new();
    let _ = writeln!(out, "Warden {}", report.engine_version);
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "Scanned     {} {}, {} in {}",
        group_digits(stats.files_scanned),
        plural(stats.files_scanned, "file", "files"),
        human_bytes(stats.bytes_scanned),
        human_duration(report.duration),
    );
    let _ = writeln!(
        out,
        "Speed       {} files/s, {:.1} MB/s on {} {}",
        group_digits(stats.files_per_second.round() as u64),
        stats.megabytes_per_second,
        report.threads,
        plural(report.threads as u64, "thread", "threads"),
    );
    let _ = writeln!(out, "Signatures  {}", signature_summary(&report.detectors));
    if let Some(rules) = rule_summary(&report.detectors) {
        let _ = writeln!(out, "Rules       {rules}");
    }
    if let Some(heuristics) = heuristic_summary(&report.detectors) {
        let _ = writeln!(out, "Heuristics  {heuristics}");
    }
    if stats.archives_unpacked > 0 {
        let _ = writeln!(
            out,
            "Archives    {} unpacked, {} {} inside ({})",
            group_digits(stats.archives_unpacked),
            group_digits(stats.archive_members_scanned),
            plural(stats.archive_members_scanned, "file", "files"),
            human_bytes(stats.archive_member_bytes),
        );
    }
    if stats.files_skipped > 0 {
        let reasons: Vec<String> = stats
            .skipped_by_reason
            .iter()
            .map(|(reason, count)| format!("{}: {}", reason.as_str(), group_digits(*count)))
            .collect();
        let _ = writeln!(
            out,
            "Skipped     {} ({})",
            group_digits(stats.files_skipped),
            reasons.join(", ")
        );
    }
    if stats.files_partially_scanned > 0 {
        let reasons: Vec<String> = stats
            .partial_by_reason
            .iter()
            .map(|(reason, count)| format!("{}: {}", reason.as_str(), group_digits(*count)))
            .collect();
        let _ = writeln!(
            out,
            "In part     {} {} not checked in full ({})",
            group_digits(stats.files_partially_scanned),
            plural(stats.files_partially_scanned, "file", "files"),
            reasons.join(", ")
        );
    }
    if stats.links_not_followed > 0 {
        let _ = writeln!(
            out,
            "Links       {} not followed",
            group_digits(stats.links_not_followed)
        );
    }
    if stats.excluded > 0 {
        let _ = writeln!(out, "Excluded    {}", group_digits(stats.excluded));
    }
    if report.cancelled {
        let _ = writeln!(out);
        let _ = writeln!(out, "The scan was cancelled. These results are partial.");
    }

    let _ = writeln!(out);
    if report.detections.is_empty() {
        let _ = writeln!(out, "No threats found.");
    } else {
        let _ = writeln!(
            out,
            "{} {}",
            group_digits(stats.detections),
            plural(stats.detections, "detection", "detections")
        );
        for detection in &report.detections {
            let verdict = match detection.verdict {
                Verdict::Malicious => "MALICIOUS ",
                Verdict::Suspicious => "SUSPICIOUS",
                Verdict::Clean => "CLEAN     ",
            };
            let _ = writeln!(out);
            let _ = writeln!(out, "  {verdict}  {}", detection_names(&detection.findings));
            let _ = writeln!(out, "    {}", shown_path(&detection.path));
            let _ = writeln!(
                out,
                "    sha256 {} ({} bytes)",
                detection.sha256,
                group_digits(detection.size)
            );
            findings_text(&mut out, &detection.findings, detection.findings_omitted);
        }
    }

    if stats.files_recorded > 0 {
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "{} {} on record that did not count. The verdict of {} is clean.",
            group_digits(stats.files_recorded),
            plural(
                stats.files_recorded,
                "file has findings",
                "files have findings"
            ),
            plural(stats.files_recorded, "that file", "those files"),
        );
        for recorded in report.recorded.iter().take(RECORDED_SHOWN) {
            let _ = writeln!(out);
            let _ = writeln!(out, "  ON RECORD   {}", detection_names(&recorded.findings));
            let _ = writeln!(out, "    {}", shown_path(&recorded.path));
            let _ = writeln!(
                out,
                "    sha256 {} ({} bytes)",
                recorded.sha256,
                group_digits(recorded.size)
            );
            findings_text(&mut out, &recorded.findings, recorded.findings_omitted);
        }
        let unlisted = stats.files_recorded - report.recorded.len().min(RECORDED_SHOWN) as u64;
        if unlisted > 0 {
            let _ = writeln!(out);
            let _ = writeln!(
                out,
                "  ... and {} more. The JSON report lists them.",
                group_digits(unlisted)
            );
        }
    }

    let anything_to_list = stats.files_skipped > 0 || stats.files_partially_scanned > 0;
    if show_skipped {
        if !report.skipped.is_empty() {
            let _ = writeln!(out);
            let _ = writeln!(out, "Skipped files");
            for skipped in &report.skipped {
                let _ = writeln!(
                    out,
                    "  {}  {}  ({})",
                    skipped.reason.as_str(),
                    shown_path(&skipped.path),
                    shown(&skipped.detail)
                );
            }
            if report.skipped_truncated {
                let _ = writeln!(out, "  ... and more; the list was cut short.");
            }
        }
        if !report.partially_scanned.is_empty() {
            let _ = writeln!(out);
            let _ = writeln!(out, "Files not checked in full");
            for partial in &report.partially_scanned {
                let _ = writeln!(
                    out,
                    "  {}  {}  ({})",
                    partial.reason.as_str(),
                    shown_path(&partial.path),
                    shown(&partial.detail)
                );
            }
            if report.partially_scanned_truncated {
                let _ = writeln!(out, "  ... and more; the list was cut short.");
            }
        }
    } else if anything_to_list {
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "Run again with --show-skipped to list the files that were skipped or not checked in full."
        );
    }
    out
}

/// A single self-overwriting status line on standard error.
#[derive(Debug)]
pub struct ProgressLine {
    enabled: bool,
    drawn: usize,
}

impl ProgressLine {
    /// Creates a progress line. It only draws when asked to and when
    /// standard error is a terminal, so redirected output stays clean.
    pub fn new(wanted: bool) -> Self {
        Self {
            enabled: wanted && std::io::stderr().is_terminal(),
            drawn: 0,
        }
    }

    /// Erases the line, so that regular output can follow.
    pub fn clear(&mut self) {
        if self.drawn > 0 {
            let mut stderr = std::io::stderr().lock();
            let _ = write!(stderr, "\r{}\r", " ".repeat(self.drawn));
            let _ = stderr.flush();
            self.drawn = 0;
        }
    }
}

impl ScanObserver for ProgressLine {
    fn on_progress(&mut self, progress: &Progress) {
        if !self.enabled {
            return;
        }
        let seconds = progress.elapsed.as_secs_f64().max(0.001);
        let line = format!(
            "  {} files, {}, {} files/s, {} detected",
            group_digits(progress.files_scanned),
            human_bytes(progress.bytes_scanned),
            group_digits((progress.files_scanned as f64 / seconds).round() as u64),
            group_digits(progress.detections),
        );
        let padding = self.drawn.saturating_sub(line.len());
        let mut stderr = std::io::stderr().lock();
        let _ = write!(stderr, "\r{line}{}", " ".repeat(padding));
        let _ = stderr.flush();
        self.drawn = line.len();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digits_are_grouped_in_threes() {
        assert_eq!(group_digits(0), "0");
        assert_eq!(group_digits(999), "999");
        assert_eq!(group_digits(1000), "1,000");
        assert_eq!(group_digits(1_234_567), "1,234,567");
        assert_eq!(group_digits(u64::MAX), "18,446,744,073,709,551,615");
    }

    #[test]
    fn bytes_use_decimal_units() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(999), "999 B");
        assert_eq!(human_bytes(1000), "1.0 kB");
        assert_eq!(human_bytes(1_500_000), "1.5 MB");
        assert_eq!(human_bytes(2_000_000_000), "2.0 GB");
    }

    #[test]
    fn durations_pick_a_sensible_unit() {
        assert_eq!(human_duration(Duration::from_micros(830)), "0.8 ms");
        assert_eq!(human_duration(Duration::from_millis(7)), "7.0 ms");
        assert_eq!(human_duration(Duration::from_millis(250)), "250 ms");
        assert_eq!(human_duration(Duration::from_millis(1500)), "1.50 s");
        assert_eq!(human_duration(Duration::from_secs(125)), "2 min 5 s");
    }

    #[test]
    fn timestamps_are_rfc_3339() {
        assert_eq!(human_timestamp(0), "1970-01-01T00:00:00Z");
        assert_eq!(human_timestamp(1_800_000_000), "2027-01-15T08:00:00Z");
    }
}

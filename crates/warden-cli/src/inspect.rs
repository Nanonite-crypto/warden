//! `warden inspect`: what the heuristic layer sees in one file, and why it
//! scores the file the way it does.

use std::fmt::Write as _;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context as _, bail};
use clap::Args;
use serde::Serialize;
use warden_engine::ScanOptions;
use warden_pe::{Assessment, Context, Directory, Format, Group, Hit, PeFacts, assess, read};

use crate::EXIT_FOUND;
use crate::render::{group_digits, human_timestamp, shown, shown_path};

/// Version of the JSON this command prints.
const SCHEMA: u32 = 1;
/// Functions listed per library unless everything is asked for.
const FUNCTIONS_SHOWN: usize = 8;
/// Libraries listed unless everything is asked for.
const LIBRARIES_SHOWN: usize = 20;
/// Width that explanations are wrapped to.
const WRAP_AT: usize = 78;

#[derive(Debug, Args)]
pub struct InspectArgs {
    /// The file to inspect, or - to read it from standard input
    #[arg(value_name = "FILE")]
    file: PathBuf,

    /// Print the facts and the assessment as JSON
    #[arg(long)]
    json: bool,

    /// List every import, and explain the indicators that are not scored
    /// too
    #[arg(long)]
    all: bool,
}

#[derive(Serialize)]
struct Inspection<'a> {
    schema: u32,
    engine_version: &'static str,
    path: String,
    size_bytes: u64,
    sha256: String,
    /// Whether the file was read as a Windows executable.
    windows_executable: bool,
    /// Why not, if it was not.
    #[serde(skip_serializing_if = "Option::is_none")]
    not_an_executable_because: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    facts: Option<&'a PeFacts>,
    #[serde(skip_serializing_if = "Option::is_none")]
    assessment: Option<&'a Assessment>,
}

fn read_file(path: &Path) -> anyhow::Result<Vec<u8>> {
    let limit = ScanOptions::default().max_content_bytes;
    let from_stdin = path.as_os_str() == "-";
    let name = if from_stdin {
        "standard input".to_owned()
    } else {
        path.display().to_string()
    };
    let mut content = Vec::new();
    let read = if from_stdin {
        std::io::stdin()
            .lock()
            .take(limit.saturating_add(1))
            .read_to_end(&mut content)
    } else {
        std::fs::File::open(path)
            .with_context(|| format!("cannot open {name}"))?
            .take(limit.saturating_add(1))
            .read_to_end(&mut content)
    };
    read.with_context(|| format!("cannot read {name}"))?;
    if content.len() as u64 > limit {
        bail!("{name} is larger than {limit} bytes, the most that is read into memory");
    }
    Ok(content)
}

pub fn run(args: &InspectArgs) -> anyhow::Result<ExitCode> {
    let content = read_file(&args.file)?;
    let sha256 = warden_sigdb::hex::encode(&warden_engine::sha256(&content));
    let outcome = read(&content);
    let assessment = outcome
        .as_ref()
        .ok()
        .map(|facts| assess(facts, &Context::now()));

    if args.json {
        let inspection = Inspection {
            schema: SCHEMA,
            engine_version: env!("CARGO_PKG_VERSION"),
            path: args.file.to_string_lossy().into_owned(),
            size_bytes: content.len() as u64,
            sha256,
            windows_executable: outcome.is_ok(),
            not_an_executable_because: outcome.as_ref().err().map(ToString::to_string),
            facts: outcome.as_ref().ok(),
            assessment: assessment.as_ref(),
        };
        println!("{}", serde_json::to_string_pretty(&inspection)?);
    } else {
        let mut out = String::new();
        let _ = writeln!(out, "Warden {} inspect", env!("CARGO_PKG_VERSION"));
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "File        {}",
            if args.file.as_os_str() == "-" {
                "(standard input)".to_owned()
            } else {
                shown_path(&args.file)
            }
        );
        let _ = writeln!(
            out,
            "Size        {} bytes",
            group_digits(content.len() as u64)
        );
        let _ = writeln!(out, "SHA-256     {sha256}");
        match (&outcome, &assessment) {
            (Ok(facts), Some(assessment)) => {
                facts_text(&mut out, facts, args.all);
                assessment_text(&mut out, assessment, args.all);
            }
            (Err(reason), _) => {
                let _ = writeln!(out, "Kind        not a Windows executable: {reason}");
                let _ = writeln!(out);
                let _ = writeln!(
                    out,
                    "The heuristics look at Windows executables only and have nothing to say\nabout this file."
                );
            }
            (Ok(_), None) => {}
        }
        print!("{out}");
    }

    let suspicious = assessment.is_some_and(|assessment| assessment.suspicious);
    Ok(if suspicious {
        ExitCode::from(EXIT_FOUND)
    } else {
        ExitCode::SUCCESS
    })
}

fn machine_name(machine: u16) -> String {
    match machine {
        0x014c => "x86".to_owned(),
        0x8664 => "x64".to_owned(),
        0xaa64 => "ARM64".to_owned(),
        0x01c0 | 0x01c4 => "ARM".to_owned(),
        0x0200 => "Itanium".to_owned(),
        other => format!("processor type {other:#06x}"),
    }
}

fn subsystem_name(subsystem: u16) -> String {
    match subsystem {
        1 => "driver or native program".to_owned(),
        2 => "windowed".to_owned(),
        3 => "console".to_owned(),
        10..=13 => "EFI".to_owned(),
        16 => "boot application".to_owned(),
        other => format!("subsystem {other}"),
    }
}

fn directory_name(directory: Directory) -> &'static str {
    match directory {
        Directory::Export => "exports",
        Directory::Import => "imports",
        Directory::Resource => "resources",
        Directory::Exception => "exception handling",
        Directory::Signature => "embedded signature",
        Directory::BaseRelocation => "relocations",
        Directory::Debug => "debug",
        Directory::Tls => "thread-local storage",
        Directory::LoadConfig => "load configuration",
        Directory::DelayImport => "delayed imports",
        Directory::ClrHeader => ".NET header",
    }
}

fn facts_text(out: &mut String, facts: &PeFacts, all: bool) {
    let mut kind = String::from(if facts.is_dll {
        "Windows library (DLL)"
    } else {
        "Windows program"
    });
    let _ = write!(
        kind,
        ", {}, {}, {}",
        match facts.format {
            Format::Pe32 => "32-bit",
            Format::Pe32Plus => "64-bit",
        },
        machine_name(facts.machine),
        subsystem_name(facts.subsystem)
    );
    if facts.is_dotnet() {
        kind.push_str(", .NET assembly");
    }
    let _ = writeln!(out, "Kind        {kind}");
    let _ = writeln!(
        out,
        "Linked      {}",
        if facts.timestamp == 0 {
            "the header gives no time".to_owned()
        } else {
            format!(
                "{}, as the header claims",
                human_timestamp(u64::from(facts.timestamp))
            )
        }
    );
    let entry = if facts.entry_point == 0 {
        "none".to_owned()
    } else {
        match facts.entry_section() {
            Some(section) => format!(
                "{:#x}, in section {}",
                facts.entry_point,
                shown(&format!("{:?}", section.name))
            ),
            None => format!("{:#x}, in none of the sections", facts.entry_point),
        }
    };
    let _ = writeln!(out, "Entry point {entry}");

    let _ = writeln!(out);
    let _ = writeln!(out, "Sections");
    let _ = writeln!(
        out,
        "  {:<10} {:>13} {:>13}  {:<5} {:>7}",
        "name", "bytes in file", "in memory", "flags", "entropy"
    );
    for section in &facts.sections {
        let _ = writeln!(
            out,
            "  {:<10} {:>13} {:>13}  {:<5} {:>7.2}",
            shown(&section.name),
            group_digits(u64::from(section.raw_size)),
            group_digits(u64::from(section.virtual_size)),
            section.flag_letters(),
            section.entropy
        );
    }
    if facts.sections.is_empty() {
        let _ = writeln!(out, "  (none)");
    }
    let _ = writeln!(
        out,
        "  Flags: r readable, w writable, x executable, c declared as code."
    );
    let _ = writeln!(
        out,
        "  Entropy: 0 to 8 bits per byte. Code is around 6; packed or encrypted data is close to 8."
    );
    let _ = writeln!(out, "  The whole file: {:.2}.", facts.file_entropy);

    let _ = writeln!(out);
    let functions = facts.import_count() as u64;
    let libraries = facts.imports.len() as u64;
    let _ = writeln!(
        out,
        "Imports     {} {} from {} {}",
        group_digits(functions),
        if functions == 1 {
            "function"
        } else {
            "functions"
        },
        group_digits(libraries),
        if libraries == 1 {
            "library"
        } else {
            "libraries"
        },
    );
    let library_limit = if all { usize::MAX } else { LIBRARIES_SHOWN };
    let function_limit = if all { usize::MAX } else { FUNCTIONS_SHOWN };
    for library in facts.imports.iter().take(library_limit) {
        let mut names: Vec<String> = library
            .functions
            .iter()
            .take(function_limit)
            .map(|function| shown(function))
            .collect();
        if library.functions.len() > function_limit {
            names.push(format!(
                "and {} more",
                group_digits((library.functions.len() - function_limit) as u64)
            ));
        }
        let _ = writeln!(
            out,
            "  {} ({}): {}",
            shown(&library.name),
            library.functions.len(),
            names.join(", ")
        );
    }
    if facts.imports.len() > library_limit {
        let _ = writeln!(
            out,
            "  and {} more libraries; --all lists everything",
            facts.imports.len() - library_limit
        );
    }
    if facts.exports > 0 {
        let _ = writeln!(
            out,
            "Exports     {} functions",
            group_digits(u64::from(facts.exports))
        );
    }

    let tables: Vec<&str> = Directory::ALL
        .into_iter()
        .filter(|directory| facts.has_directory(*directory))
        .map(directory_name)
        .collect();
    let _ = writeln!(
        out,
        "Tables      {}",
        if tables.is_empty() {
            "none".to_owned()
        } else {
            tables.join(", ")
        }
    );
    let _ = writeln!(
        out,
        "Rich header {}",
        if facts.has_rich_header {
            "present: Microsoft's linker built the file, or something that imitates it"
        } else {
            "absent"
        }
    );
    let _ = writeln!(
        out,
        "Signature   {}",
        if facts.signature_size > 0 {
            format!(
                "{} bytes are embedded; whether they are a valid signature is not checked",
                group_digits(u64::from(facts.signature_size))
            )
        } else {
            "none embedded".to_owned()
        }
    );
    let _ = writeln!(
        out,
        "After the last section: {}",
        if facts.overlay.size == 0 {
            "nothing".to_owned()
        } else {
            format!(
                "{} bytes with an entropy of {:.2}{}",
                group_digits(facts.overlay.size),
                facts.overlay.entropy,
                if facts.signature_size > 0 {
                    ", the embedded signature included"
                } else {
                    ""
                }
            )
        }
    );
    if !facts.anomalies.is_empty() {
        let _ = writeln!(out, "Damage or oddities in the structure");
        for anomaly in &facts.anomalies {
            let _ = writeln!(out, "  {}", shown(&anomaly.to_string()));
        }
    }
}

/// Breaks `text` into lines of at most `width` characters, each starting
/// with `indent`.
fn wrapped(text: &str, indent: &str, width: usize) -> String {
    let mut out = String::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        if !line.is_empty() && indent.len() + line.len() + 1 + word.len() > width {
            let _ = writeln!(out, "{indent}{line}");
            line.clear();
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        let _ = writeln!(out, "{indent}{line}");
    }
    out
}

fn hit_text(out: &mut String, hit: &Hit, explain: bool) {
    let points = if hit.indicator.weight > 0 {
        format!("+{}", hit.indicator.weight)
    } else {
        "·".to_owned()
    };
    let _ = writeln!(
        out,
        "  {:>4}  {}: {}",
        points,
        hit.indicator.summary,
        shown(&hit.detail)
    );
    if explain {
        out.push_str(&wrapped(hit.indicator.rationale, "        ", WRAP_AT));
    }
}

fn assessment_text(out: &mut String, assessment: &Assessment, all: bool) {
    let _ = writeln!(out);
    let scored: Vec<&Hit> = assessment.scored().collect();
    let unscored: Vec<&Hit> = assessment.unscored().collect();
    if scored.is_empty() {
        let _ = writeln!(out, "Indicators  none that add to the score");
    } else {
        let _ = writeln!(out, "Indicators that add to the score");
        for group in [Group::Packing, Group::Layout, Group::Imports, Group::Header] {
            for hit in scored.iter().filter(|hit| hit.indicator.group == group) {
                hit_text(out, hit, true);
            }
        }
    }
    if !unscored.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "Also seen, and not scored: measured next to the others these add nothing, or they are left out on purpose"
        );
        for hit in &unscored {
            hit_text(out, hit, all);
        }
    }

    let _ = writeln!(out);
    let _ = writeln!(out, "Score       {}", assessment.score);
    let verdict = if assessment.suspicious {
        format!(
            "suspicious: a file counts as suspicious from a score of {}",
            assessment.suspicious_from
        )
    } else {
        format!(
            "not suspicious: a file counts as suspicious from a score of {}",
            assessment.suspicious_from
        )
    };
    let _ = writeln!(out, "Verdict     {verdict}");
    let _ = writeln!(out);
    out.push_str(&wrapped(
        "A weight says how much an indicator shifts the odds that a file is malicious: 10 is tenfold, 20 a hundredfold. The weights are fitted to the 2.3 million files of the training weeks of the EMBER2024 dataset; docs/HEURISTICS.md has the numbers.",
        "",
        WRAP_AT,
    ));
    let _ = writeln!(out);
    out.push_str(&wrapped(
        "The score says how unusual the structure of the file is. It is not proof of anything: clean programs are packed and protected too, and malware can be built to look plain.",
        "",
        WRAP_AT,
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_is_wrapped_at_word_boundaries() {
        let text = "one two three four five six seven eight nine ten";
        assert_eq!(
            wrapped(text, "  ", 16),
            "  one two three\n  four five six\n  seven eight\n  nine ten\n"
        );
        assert_eq!(wrapped("", "  ", 16), "");
        // A word longer than the width gets a line to itself.
        assert_eq!(
            wrapped("a extraordinarily b", "", 5),
            "a\nextraordinarily\nb\n"
        );
    }

    #[test]
    fn machines_and_subsystems_have_names() {
        assert_eq!(machine_name(0x8664), "x64");
        assert_eq!(machine_name(0x1234), "processor type 0x1234");
        assert_eq!(subsystem_name(3), "console");
        assert_eq!(subsystem_name(99), "subsystem 99");
    }
}

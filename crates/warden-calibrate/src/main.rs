//! Measures Warden's heuristic indicators and fits their weights.
//!
//! This is a development tool. It is not part of the scanner and nothing
//! in it runs when a file is scanned. It exists so that the weight of every
//! indicator can be traced back to counts over a public dataset, and so
//! that anyone can repeat the measurement.
//!
//! ```text
//! warden-calibrate collect Win64_test.zip --out win64-test.json
//! warden-calibrate collect-files --as system C:\Windows\System32 --out system.json
//! warden-calibrate report win64-test.json system.json
//! ```
//!
//! `collect` reads files of the EMBER2024 dataset (the `.zip` archives as
//! published, or `.jsonl` files) and writes counts. The dataset holds
//! features and labels only; no file content, and no malware, is involved
//! at any point. `collect-files` counts the same things on the executables
//! in folders of a machine that is taken to be clean. `report` adds counts
//! up, fits the weights to the training part of the dataset, derives the
//! threshold, and prints what the score does with them: on the weeks the
//! fit has not seen, and on the files of the machine.

mod collect;
mod ember;
mod fit;
mod installed;
mod report;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::Context as _;
use clap::{Parser, Subcommand, ValueEnum};

use crate::collect::{Collected, Subset};

#[derive(Parser)]
#[command(
    name = "warden-calibrate",
    about = "Measures Warden's heuristic indicators and fits their weights",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Count which indicators apply to the files of the dataset
    ///
    /// Takes the dataset's zip archives as they are published, or .jsonl
    /// files. The name of each file has to say which part of the dataset
    /// it is: train, test or challenge.
    Collect {
        /// Dataset files
        #[arg(required = true, value_name = "FILE")]
        inputs: Vec<PathBuf>,

        /// Where to write the counts
        #[arg(long, value_name = "FILE")]
        out: PathBuf,

        /// Number of threads; by default one per processor
        #[arg(long, value_name = "N")]
        threads: Option<usize>,

        /// Print the shape of the first record that was counted
        #[arg(long)]
        sample: bool,
    },

    /// Count which indicators apply to the executables in folders of this
    /// machine, which is taken to be clean
    ///
    /// Files are read and not changed. The counts hold nothing about a
    /// single file.
    CollectFiles {
        /// Folders to read, with everything below them
        #[arg(required = true, value_name = "FOLDER")]
        folders: Vec<PathBuf>,

        /// What the folders hold
        #[arg(long = "as", value_name = "PART", value_enum)]
        part: Part,

        /// Where to write the counts
        #[arg(long, value_name = "FILE")]
        out: PathBuf,

        /// Number of threads; by default one per processor
        #[arg(long, value_name = "N")]
        threads: Option<usize>,
    },

    /// Add up the counts of several runs into one file
    Merge {
        /// Files written by `collect`
        #[arg(required = true, value_name = "COUNTS")]
        counts: Vec<PathBuf>,

        /// Where to write the sum
        #[arg(long, value_name = "FILE")]
        out: PathBuf,
    },

    /// Print what follows from counts: the measurement of every indicator,
    /// the weights, and what the score does at each threshold
    Report {
        /// Files written by `collect` or `merge`
        #[arg(required = true, value_name = "COUNTS")]
        counts: Vec<PathBuf>,

        /// Also write the report as JSON
        #[arg(long, value_name = "FILE")]
        json: Option<PathBuf>,

        /// Offer the fit every indicator, also those the scanner leaves
        /// out on purpose, to see what they would do
        #[arg(long)]
        offer_all: bool,
    },
}

/// What a folder of this machine holds.
#[derive(Debug, Clone, Copy, ValueEnum)]
enum Part {
    /// The system files of a Windows installation
    System,
    /// Installed software
    Software,
}

fn default_threads() -> usize {
    std::thread::available_parallelism().map_or(1, std::num::NonZero::get)
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::from(2)
        }
    }
}

fn read_counts(paths: &[PathBuf]) -> anyhow::Result<Collected> {
    let parts = paths
        .iter()
        .map(|path| Collected::read(path))
        .collect::<anyhow::Result<Vec<_>>>()?;
    collect::merge(parts)
}

fn write_json(path: &Path, value: &impl serde::Serialize) -> anyhow::Result<()> {
    let mut text = serde_json::to_string(value)?;
    text.push('\n');
    fs::write(path, text).with_context(|| format!("cannot write {}", path.display()))
}

fn run(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Command::Collect {
            inputs,
            out,
            threads,
            sample,
        } => {
            let threads = threads.unwrap_or_else(default_threads);
            let started = std::time::Instant::now();
            let (collected, outline) = collect::collect(&inputs, threads)?;
            for input in &collected.inputs {
                println!(
                    "{}: {} records, {} counted, {} repeats of a file already counted, {} of other kinds, {} not parsed as an executable, {} without a label, {} unreadable lines",
                    input.name,
                    input.records,
                    input.counted,
                    input.duplicates,
                    input.other_kinds,
                    input.not_parsed_as_pe,
                    input.unlabelled,
                    input.unreadable
                );
            }
            for error in &collected.first_errors {
                println!("unreadable: {error}");
            }
            println!(
                "{} combinations of indicators, in {:.1} s on {threads} threads",
                collected.groups.len(),
                started.elapsed().as_secs_f64()
            );
            if sample {
                match outline {
                    Some(outline) => {
                        println!("The first record that was counted has this shape:\n{outline}")
                    }
                    None => println!("No record was counted."),
                }
            }
            write_json(&out, &collected)
        }
        Command::CollectFiles {
            folders,
            part,
            out,
            threads,
        } => {
            let threads = threads.unwrap_or_else(default_threads);
            let subset = match part {
                Part::System => Subset::System,
                Part::Software => Subset::Software,
            };
            let started = std::time::Instant::now();
            let (collected, unlisted) = installed::collect_files(&folders, subset, threads)?;
            for input in &collected.inputs {
                println!(
                    "{}: {} files, {} executables counted, {} other files, {} that start like an executable and are not one, {} unreadable or too large",
                    input.name,
                    input.records,
                    input.counted,
                    input.other_kinds,
                    input.not_parsed_as_pe,
                    input.unreadable
                );
            }
            if unlisted > 0 {
                println!("{unlisted} folders could not be listed");
            }
            println!(
                "{} combinations of indicators, in {:.1} s on {threads} threads",
                collected.groups.len(),
                started.elapsed().as_secs_f64()
            );
            write_json(&out, &collected)
        }
        Command::Merge { counts, out } => {
            let merged = read_counts(&counts)?;
            println!(
                "{} inputs, {} combinations of indicators",
                merged.inputs.len(),
                merged.groups.len()
            );
            write_json(&out, &merged)
        }
        Command::Report {
            counts,
            json,
            offer_all,
        } => {
            let merged = read_counts(&counts)?;
            let report = report::report(&merged, report::Options { offer_all })?;
            print!("{}", report::render_text(&merged, &report));
            if let Some(path) = json {
                write_json(&path, &report)?;
            }
            Ok(())
        }
    }
}

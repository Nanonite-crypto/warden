//! Measures Warden's heuristic indicators on the EMBER2024 dataset.
//!
//! This is a development tool. It is not part of the scanner and nothing
//! in it runs when a file is scanned. It exists so that the weight of every
//! indicator can be traced back to counts over a public dataset, and so
//! that anyone can repeat the measurement.
//!
//! ```text
//! warden-calibrate collect Win64_test.zip --out win64-test.json
//! warden-calibrate report win64-test.json other.json
//! ```
//!
//! `collect` reads dataset files (the `.zip` archives as published, or
//! `.jsonl` files) and writes counts. `report` adds counts up and prints
//! what follows from them. The dataset holds features and labels only; no
//! file content, and no malware, is involved at any point.

mod collect;
mod ember;
mod report;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::Context as _;
use clap::{Parser, Subcommand};

use crate::collect::Collected;

#[derive(Parser)]
#[command(
    name = "warden-calibrate",
    about = "Measures Warden's heuristic indicators on the EMBER2024 dataset",
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
    },
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
    let mut parts = Vec::with_capacity(paths.len());
    for path in paths {
        let text =
            fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
        let part: Collected = serde_json::from_str(&text)
            .with_context(|| format!("{} does not hold counts", path.display()))?;
        parts.push(part);
    }
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
            let threads = threads.unwrap_or_else(|| {
                std::thread::available_parallelism().map_or(1, std::num::NonZero::get)
            });
            let started = std::time::Instant::now();
            let (collected, outline) = collect::collect(&inputs, threads)?;
            for input in &collected.inputs {
                println!(
                    "{}: {} records, {} counted, {} of other kinds, {} not parsed as an executable, {} without a label, {} unreadable lines",
                    input.name,
                    input.records,
                    input.counted,
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
        Command::Merge { counts, out } => {
            let merged = read_counts(&counts)?;
            println!(
                "{} dataset files, {} combinations of indicators",
                merged.inputs.len(),
                merged.groups.len()
            );
            write_json(&out, &merged)
        }
        Command::Report { counts, json } => {
            let merged = read_counts(&counts)?;
            let report = report::report(&merged)?;
            print!("{}", report::render_text(&merged, &report));
            if let Some(path) = json {
                write_json(&path, &report)?;
            }
            Ok(())
        }
    }
}

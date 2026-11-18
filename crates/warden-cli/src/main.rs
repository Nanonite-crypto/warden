//! Warden command-line scanner.
//!
//! Exit codes follow the convention of other scanners:
//!
//! - `0`: the command succeeded and, for a scan, nothing was detected;
//! - `1`: a scan found at least one detection (or a lookup found nothing);
//! - `2`: the command could not be carried out.

#![forbid(unsafe_code)]

mod bench;
mod fp;
mod misc;
mod render;
mod rules;
mod scan;
mod sigdb;
mod system;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

/// Exit code for "the scan found something" and "the lookup found nothing".
const EXIT_FOUND: u8 = 1;
/// Exit code for errors.
const EXIT_ERROR: u8 = 2;

#[derive(Debug, Parser)]
#[command(
    name = "warden",
    version,
    about = "Warden anti-malware scanner",
    long_about = "Warden anti-malware scanner.\n\n\
        Scans files and folders, and the files inside zip archives, for known threats: \
        by hash against a signature database, and by content against YARA rules. \
        Without a database or a rule bundle it knows the harmless EICAR antivirus \
        test file, which is enough to check that everything works."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Scan files and folders
    Scan(scan::ScanArgs),

    /// Build and inspect signature databases
    #[command(subcommand)]
    Sigdb(sigdb::SigdbCommand),

    /// Build and inspect YARA rule bundles
    #[command(subcommand)]
    Rules(rules::RulesCommand),

    /// Measure scan throughput on a folder
    Bench(bench::BenchArgs),

    /// Scan files that are known to be clean and report what was flagged
    #[command(name = "false-positives", visible_alias = "fp")]
    FalsePositives(fp::FpArgs),

    /// Print the SHA-256 of files
    Hash {
        /// Files to hash
        #[arg(required = true, value_name = "FILE")]
        files: Vec<PathBuf>,
    },

    /// Work with the EICAR antivirus test file
    #[command(subcommand)]
    Eicar(misc::EicarCommand),
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let outcome = match cli.command {
        Command::Scan(args) => scan::run(&args),
        Command::Sigdb(command) => sigdb::run(command),
        Command::Rules(command) => rules::run(command),
        Command::Bench(args) => bench::run(&args),
        Command::FalsePositives(args) => fp::run(&args),
        Command::Hash { files } => misc::hash(&files),
        Command::Eicar(command) => misc::eicar(&command),
    };
    match outcome {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::from(EXIT_ERROR)
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    #[test]
    fn command_line_definition_is_consistent() {
        super::Cli::command().debug_assert();
    }
}

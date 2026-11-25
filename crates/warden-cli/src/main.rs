//! Warden command-line scanner.
//!
//! Exit codes follow the convention of other scanners:
//!
//! - `0`: the command succeeded and, for a scan, nothing was detected;
//! - `1`: a scan found at least one detection (or a lookup found nothing);
//! - `2`: the command could not be carried out, or whoever was reading
//!   its output stopped reading before the end.

#![forbid(unsafe_code)]

// First, because the modules after it print with its macros.
#[macro_use]
mod out;

mod autostart;
mod bench;
mod fp;
mod inspect;
mod misc;
mod quarantine;
mod render;
mod rules;
mod scan;
mod sigdb;
mod system;
mod trust;

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

    /// Show what the heuristics see in one Windows executable, and why
    ///
    /// Prints the file's structure (sections, imports, tables), then every
    /// indicator that applies to it with the points it adds to the score
    /// and the reason it counts. Exits with 1 if the file is suspicious.
    Inspect(inspect::InspectArgs),

    /// Move files out of harm's way, and put them back
    ///
    /// A quarantined file is gone from its place and not lost: it can be
    /// restored with the content, the timestamps and the permissions it
    /// had. See `warden quarantine add --help`.
    #[command(subcommand)]
    Quarantine(quarantine::QuarantineCommand),

    /// Show what makes Windows start a program
    ///
    /// Values under the Run keys, scheduled tasks, services and drivers,
    /// and shortcuts in the Startup folders. When a file is quarantined,
    /// the entries that start it are removed with it, and a restore puts
    /// them back; these commands show them and change nothing, except
    /// `remove`, which finishes such a removal. Windows only.
    #[command(subcommand)]
    Autostart(autostart::AutostartCommand),

    /// Check who signed a file, and whether Warden trusts the publisher
    ///
    /// A match of a rule that came with a rule bundle is recorded and not
    /// reported when the file has a valid signature of a publisher on
    /// Warden's trust list. These commands show what that check finds.
    /// Signatures can only be checked on Windows.
    #[command(subcommand)]
    Trust(trust::TrustCommand),

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
        Command::Inspect(args) => inspect::run(&args),
        Command::Quarantine(command) => quarantine::run(&command),
        Command::Autostart(command) => autostart::run(&command),
        Command::Trust(command) => trust::run(&command),
        Command::Hash { files } => misc::hash(&files),
        Command::Eicar(command) => misc::eicar(&command),
    };
    match outcome {
        Ok(code) => code,
        Err(error) => {
            // `warden scan … | head`: nobody is left to tell.
            let reader_has_left = error
                .chain()
                .filter_map(|cause| cause.downcast_ref::<out::OutputError>())
                .any(out::OutputError::reader_has_left);
            if !reader_has_left {
                errln!("error: {error:#}");
            }
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

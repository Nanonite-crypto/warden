//! `warden sigdb`: build and inspect signature databases.

use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use anyhow::{Context, bail};
use clap::Subcommand;
use warden_sigdb::import::{self, ImportStats};
use warden_sigdb::{Category, FORMAT_VERSION, SigDb, SigDbBuilder, hex};

use crate::EXIT_FOUND;
use crate::render::{group_digits, human_bytes, human_duration, human_timestamp};

#[derive(Debug, Subcommand)]
pub enum SigdbCommand {
    /// Build a signature database from hash lists
    Build {
        /// File to write, conventionally ending in .wdb
        #[arg(long, short, value_name = "FILE")]
        out: PathBuf,

        /// Text file with one SHA-256 per line; may be given more than once
        #[arg(long, value_name = "FILE")]
        hashes: Vec<PathBuf>,

        /// Detection name for the hashes from --hashes files
        #[arg(long, default_value = "Malware.Generic", value_name = "NAME")]
        name: String,

        /// Category for the hashes from --hashes files
        #[arg(long, default_value = "malware", value_name = "CATEGORY")]
        category: Category,

        /// CSV file with one "sha256,name" or "sha256,name,category" row per signature;
        /// may be given more than once
        #[arg(long, value_name = "FILE")]
        csv: Vec<PathBuf>,

        /// Creation time to record, in seconds since 1970 (default: now)
        #[arg(long, env = "SOURCE_DATE_EPOCH", value_name = "SECONDS")]
        created: Option<u64>,
    },

    /// Show what a signature database contains
    Info {
        /// Signature database to inspect
        #[arg(value_name = "FILE")]
        file: PathBuf,
    },

    /// Look up one SHA-256 in a signature database
    Lookup {
        /// Signature database to search
        #[arg(value_name = "FILE")]
        file: PathBuf,

        /// The hash, as 64 hexadecimal characters
        #[arg(value_name = "SHA256")]
        sha256: String,
    },
}

pub fn run(command: SigdbCommand) -> anyhow::Result<ExitCode> {
    match command {
        SigdbCommand::Build {
            out,
            hashes,
            name,
            category,
            csv,
            created,
        } => build(&out, &hashes, &name, category, &csv, created),
        SigdbCommand::Info { file } => info(&file),
        SigdbCommand::Lookup { file, sha256 } => lookup(&file, &sha256),
    }
}

fn open_input(path: &Path) -> anyhow::Result<BufReader<File>> {
    let file = File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
    Ok(BufReader::new(file))
}

fn print_import(path: &Path, stats: &ImportStats) {
    println!(
        "{}: {} added, {} invalid, {} comment or blank",
        path.display(),
        group_digits(stats.added),
        group_digits(stats.invalid),
        group_digits(stats.ignored),
    );
    for sample in &stats.invalid_samples {
        println!("  line {}: {}", sample.line, sample.reason);
    }
    if stats.invalid > stats.invalid_samples.len() as u64 {
        println!("  ... and more invalid lines");
    }
}

fn build(
    out: &Path,
    hashes: &[PathBuf],
    name: &str,
    category: Category,
    csv: &[PathBuf],
    created: Option<u64>,
) -> anyhow::Result<ExitCode> {
    if hashes.is_empty() && csv.is_empty() {
        bail!("nothing to build from: give at least one --hashes or --csv file");
    }
    let mut builder = SigDbBuilder::new();
    if let Some(created) = created {
        builder = builder.with_created_unix_secs(created);
    }
    for path in hashes {
        let stats = import::import_hash_list(open_input(path)?, &mut builder, name, category)
            .with_context(|| format!("while importing {}", path.display()))?;
        print_import(path, &stats);
    }
    for path in csv {
        let stats = import::import_csv(open_input(path)?, &mut builder, category)
            .with_context(|| format!("while importing {}", path.display()))?;
        print_import(path, &stats);
    }

    let stats = builder.write_to(out)?;
    println!();
    println!("Wrote {}", out.display());
    println!("  entries     {}", group_digits(stats.entries));
    println!("  names       {}", group_digits(u64::from(stats.names)));
    println!(
        "  duplicates  {} dropped",
        group_digits(stats.duplicates_dropped)
    );
    println!("  size        {}", human_bytes(stats.bytes));
    println!("  created     {}", human_timestamp(stats.created_unix_secs));
    println!("  digest      {}", hex::encode(&stats.digest));
    if stats.entries == 0 {
        eprintln!("warning: the database is empty");
    }
    Ok(ExitCode::SUCCESS)
}

fn info(file: &Path) -> anyhow::Result<ExitCode> {
    let clock = Instant::now();
    let db = SigDb::open(file)?;
    let verified_in = clock.elapsed();
    println!("{}", file.display());
    println!("  format      version {FORMAT_VERSION}");
    println!("  entries     {}", group_digits(db.len() as u64));
    println!("  names       {}", group_digits(db.name_count() as u64));
    println!("  size        {}", human_bytes(db.size_bytes()));
    println!("  created     {}", human_timestamp(db.created_unix_secs()));
    println!("  digest      {}", hex::encode(&db.digest()));
    println!("  verified    in {}", human_duration(verified_in));
    Ok(ExitCode::SUCCESS)
}

fn lookup(file: &Path, sha256: &str) -> anyhow::Result<ExitCode> {
    let Some(hash) = hex::decode_sha256(sha256.trim()) else {
        bail!("{sha256:?} is not a SHA-256: expected 64 hexadecimal characters");
    };
    let db = SigDb::open(file)?;
    match db.lookup(&hash) {
        Some(signature) => {
            println!("found: {} ({})", signature.name, signature.category);
            Ok(ExitCode::SUCCESS)
        }
        None => {
            println!("not found");
            Ok(ExitCode::from(EXIT_FOUND))
        }
    }
}

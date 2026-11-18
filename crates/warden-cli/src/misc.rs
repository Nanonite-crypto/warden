//! Small commands: `warden hash` and `warden eicar`.

use std::fs::File;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::Context;
use clap::{Subcommand, ValueEnum};
use warden_engine::eicar;
use warden_sigdb::hex;

/// File name of the test file with a line break added.
pub const PADDED_FILE_NAME: &str = "eicar-padded.com";
/// File name of the zip archive that holds the test file.
pub const ZIP_FILE_NAME: &str = "eicar.zip";

/// The forms of the test file that `warden eicar write` produces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum EicarKind {
    /// eicar.com: the 68-byte test file
    Plain,
    /// eicar-padded.com: the test file followed by a line break, which
    /// gives it a different hash
    Padded,
    /// eicar.zip: a zip archive with eicar.com inside
    Zip,
    /// All three
    All,
}

#[derive(Debug, Subcommand)]
pub enum EicarCommand {
    /// Write the EICAR test file into a folder
    ///
    /// EICAR is a harmless 68-byte file that every antivirus product detects
    /// on purpose. Your resident antivirus will remove it within moments
    /// unless the folder is excluded from it.
    Write {
        /// Folder to write into; created if missing
        #[arg(value_name = "DIR")]
        dir: PathBuf,

        /// Which form of the test file to write
        #[arg(long, value_enum, default_value = "plain")]
        kind: EicarKind,
    },
}

fn zipped_test_file() -> anyhow::Result<Vec<u8>> {
    let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    writer.start_file(eicar::FILE_NAME, zip::write::SimpleFileOptions::default())?;
    writer.write_all(&eicar::test_file())?;
    Ok(writer.finish()?.into_inner())
}

pub fn eicar(command: &EicarCommand) -> anyhow::Result<ExitCode> {
    match command {
        EicarCommand::Write { dir, kind } => {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("cannot create {}", dir.display()))?;
            let mut files: Vec<(&str, Vec<u8>)> = Vec::new();
            if matches!(kind, EicarKind::Plain | EicarKind::All) {
                files.push((eicar::FILE_NAME, eicar::test_file()));
            }
            if matches!(kind, EicarKind::Padded | EicarKind::All) {
                let mut padded = eicar::test_file();
                padded.extend_from_slice(b"\r\n");
                files.push((PADDED_FILE_NAME, padded));
            }
            if matches!(kind, EicarKind::Zip | EicarKind::All) {
                files.push((ZIP_FILE_NAME, zipped_test_file()?));
            }
            for (name, bytes) in files {
                let path = dir.join(name);
                std::fs::write(&path, bytes)
                    .with_context(|| format!("cannot write {}", path.display()))?;
                println!("Wrote {}", path.display());
            }
            println!(
                "This is the harmless EICAR test file. If it disappears, your resident \
                 antivirus removed it: see docs/TESTING.md."
            );
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn sha256_of_file(path: &Path) -> std::io::Result<[u8; 32]> {
    // The engine's own streaming hash, so `warden hash` and `warden scan`
    // agree by construction, and large files need no large buffer.
    warden_engine::sha256_reader(&mut File::open(path)?)
}

pub fn hash(files: &[PathBuf]) -> anyhow::Result<ExitCode> {
    for path in files {
        let digest =
            sha256_of_file(path).with_context(|| format!("cannot read {}", path.display()))?;
        println!("{}  {}", hex::encode(&digest), path.display());
    }
    Ok(ExitCode::SUCCESS)
}

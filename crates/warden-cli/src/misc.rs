//! Small commands: `warden hash` and `warden eicar`.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::Context;
use clap::Subcommand;
use warden_engine::eicar;
use warden_sigdb::hex;

#[derive(Debug, Subcommand)]
pub enum EicarCommand {
    /// Write the EICAR test file into a folder
    ///
    /// EICAR is a harmless 68-byte file that every antivirus product detects
    /// on purpose. Your resident antivirus will remove it within moments
    /// unless the folder is excluded from it.
    Write {
        /// Folder to write eicar.com into; created if missing
        #[arg(value_name = "DIR")]
        dir: PathBuf,
    },
}

pub fn eicar(command: &EicarCommand) -> anyhow::Result<ExitCode> {
    match command {
        EicarCommand::Write { dir } => {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("cannot create {}", dir.display()))?;
            let path = dir.join(eicar::FILE_NAME);
            std::fs::write(&path, eicar::test_file())
                .with_context(|| format!("cannot write {}", path.display()))?;
            println!("Wrote {}", path.display());
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

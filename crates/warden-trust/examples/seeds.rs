//! Writes small well-formed inputs for the fuzz targets of this crate, one
//! folder for each target.
//!
//! ```text
//! cargo run -p warden-trust --example seeds -- fuzz/corpus
//! ```
//!
//! A fuzzer gets further when it starts from input that the code accepts.
//! None of these files is signed, and none of them is a program that could
//! run: the executable is a header with nothing behind it.

use std::path::PathBuf;

use std::io::Cursor;

use warden_trust::package::{BlockMap, digests, unsigned_signature_file};
use warden_trust::sigarea::{SignatureArea, executable_with_table, inspect, table_with_signature};

/// A block map as a package has it, for two files. The hashes are of the
/// right length and of nothing in particular.
const BLOCK_MAP: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<BlockMap xmlns="http://schemas.microsoft.com/appx/2010/blockmap" HashMethod="http://www.w3.org/2001/04/xmlenc#sha256">
<File Name="AppxManifest.xml" Size="1200" LfhSize="46"><Block Hash="AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=" Size="600"/></File>
<File Name="tools\tool.exe" Size="70000" LfhSize="44"><Block Hash="AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="/><Block Hash="Hx4dHBsaGRgXFhUUExIREA8ODQwLCgkIBwYFBAMCAQA=" Size="3000"/></File>
</BlockMap>
"#;

fn main() -> std::io::Result<()> {
    let Some(folder) = std::env::args_os().nth(1).map(PathBuf::from) else {
        eprintln!("usage: seeds <folder>");
        std::process::exit(2);
    };

    // The list of digests that a package's signature signs: a name of four
    // bytes and a SHA-256 for each part of the package.
    let mut digest_list = b"APPX".to_vec();
    for (index, name) in [b"AXPC", b"AXCD", b"AXCT", b"AXBM", b"AXCI"]
        .into_iter()
        .enumerate()
    {
        digest_list.extend_from_slice(name);
        digest_list.extend_from_slice(&[index as u8 + 1; 32]);
    }

    // Stands in for a signature inside an executable: one value of the
    // encoding that signatures use, with nothing of a signature in it.
    let mut placeholder = vec![0x30, 0x82, 0x00, 0x7C];
    placeholder.resize(128, 0x5A);

    let seeds: [(&str, &str, Vec<u8>); 4] = [
        (
            "trust_signature_file",
            "digests.p7x",
            unsigned_signature_file(&digest_list),
        ),
        (
            "trust_block_map",
            "two-files.xml",
            BLOCK_MAP.as_bytes().to_vec(),
        ),
        (
            "trust_signature_area",
            "with-a-table.exe",
            executable_with_table(&table_with_signature(&placeholder)),
        ),
        (
            "trust_signature_area",
            "without-a-table.exe",
            executable_with_table(&[]),
        ),
    ];
    for (target, name, bytes) in seeds {
        // A seed that the code refuses is no seed.
        let accepted = match target {
            "trust_signature_file" => digests(&bytes).is_ok(),
            "trust_block_map" => BlockMap::parse(&bytes).is_ok_and(|map| map.len() == 2),
            _ => matches!(
                inspect(&mut Cursor::new(&bytes)),
                Ok(SignatureArea::Tidy | SignatureArea::NoTable)
            ),
        };
        if !accepted {
            eprintln!("the seed {name} for {target} is not well-formed any more");
            std::process::exit(1);
        }
        let target_folder = folder.join(target);
        std::fs::create_dir_all(&target_folder)?;
        let path = target_folder.join(name);
        std::fs::write(&path, bytes)?;
        println!("{}", path.display());
    }
    Ok(())
}

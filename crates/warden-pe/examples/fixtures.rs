//! Writes the inert test executables to a folder, to try `warden inspect`
//! on or to seed a fuzzer with.
//!
//! ```text
//! cargo run -p warden-pe --example fixtures -- some/folder
//! ```
//!
//! The files have the structure of Windows executables and no behaviour:
//! see `warden_pe::fixture`. An antivirus that judges files by structure
//! may still object to `packed-looking.exe` and `suspicious-looking.exe`,
//! which is the point of them.

use std::path::PathBuf;

use warden_pe::fixture::Fixture;

fn main() -> std::io::Result<()> {
    let Some(folder) = std::env::args_os().nth(1).map(PathBuf::from) else {
        eprintln!("usage: fixtures <folder>");
        std::process::exit(2);
    };
    std::fs::create_dir_all(&folder)?;
    for (name, fixture) in [
        ("plain.exe", Fixture::plain()),
        ("packed-looking.exe", Fixture::packed_looking()),
        ("suspicious-looking.exe", Fixture::suspicious_looking()),
    ] {
        let path = folder.join(name);
        std::fs::write(&path, fixture.build())?;
        println!("{}", path.display());
    }
    Ok(())
}

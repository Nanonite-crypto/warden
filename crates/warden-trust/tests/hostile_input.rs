//! The three readers of this crate, fed with damaged input.
//!
//! Each of them reads bytes that nobody has vouched for yet: the signature
//! file and the block map of an app package, and the part of an executable
//! that holds its signature. Here each gets a well-formed input cut short
//! at every length, with every byte changed, and with a few thousand
//! random changes. None of that may make it panic. The fuzz targets in
//! `fuzz/` look for the same thing with a tool that is better at it, when
//! they are run; this runs with every `cargo test`.

use std::io::Cursor;

use warden_trust::package::{BlockMap, digests, unsigned_signature_file};
use warden_trust::sigarea::{executable_with_table, inspect, table_with_signature};

const BLOCK_MAP: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<BlockMap xmlns="http://schemas.microsoft.com/appx/2010/blockmap" HashMethod="http://www.w3.org/2001/04/xmlenc#sha256">
<File Name="AppxManifest.xml" Size="1200" LfhSize="46"><Block Hash="AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=" Size="600"/></File>
<File Name="tools\tool.exe" Size="70000" LfhSize="44"><Block Hash="AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="/><Block Hash="Hx4dHBsaGRgXFhUUExIREA8ODQwLCgkIBwYFBAMCAQA=" Size="3000"/></File>
</BlockMap>
"#;

fn signature_file() -> Vec<u8> {
    let mut digest_list = b"APPX".to_vec();
    for (index, name) in [b"AXPC", b"AXCD", b"AXCT", b"AXBM", b"AXCI"]
        .into_iter()
        .enumerate()
    {
        digest_list.extend_from_slice(name);
        digest_list.extend_from_slice(&[index as u8 + 1; 32]);
    }
    unsigned_signature_file(&digest_list)
}

fn executable() -> Vec<u8> {
    let mut placeholder = vec![0x30, 0x82, 0x00, 0x7C];
    placeholder.resize(128, 0x5A);
    executable_with_table(&table_with_signature(&placeholder))
}

/// A small generator of numbers that gives the same numbers every time, so
/// that a failure can be had again.
struct Numbers(u64);

impl Numbers {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, limit: usize) -> usize {
        (self.next() % limit as u64) as usize
    }
}

/// Hands `read` the input cut short at every length, with every byte
/// changed three ways, and with random changes. Returns how many inputs
/// that was.
fn damage(good: &[u8], mut read: impl FnMut(&[u8])) -> usize {
    let mut inputs = 0;
    for length in 0..=good.len() {
        read(&good[..length]);
        inputs += 1;
    }
    let mut changed = good.to_vec();
    for index in 0..good.len() {
        for value in [0x00, 0xFF, good[index] ^ 0x80] {
            changed[index] = value;
            read(&changed);
            inputs += 1;
        }
        changed[index] = good[index];
    }
    let mut numbers = Numbers(0x5EED_0FA7_E570_2026);
    for _ in 0..4000 {
        let mut changed = good.to_vec();
        for _ in 0..=numbers.below(8) {
            match numbers.below(4) {
                // Another value in one place.
                0 => {
                    let index = numbers.below(changed.len().max(1));
                    if let Some(byte) = changed.get_mut(index) {
                        *byte = numbers.next() as u8;
                    }
                }
                // A piece taken out.
                1 if changed.len() > 1 => {
                    let from = numbers.below(changed.len());
                    let to = (from + 1 + numbers.below(16)).min(changed.len());
                    changed.drain(from..to);
                }
                // A piece put in twice.
                2 if !changed.is_empty() => {
                    let from = numbers.below(changed.len());
                    let to = (from + 1 + numbers.below(16)).min(changed.len());
                    let piece = changed[from..to].to_vec();
                    let at = numbers.below(changed.len() + 1);
                    changed.splice(at..at, piece);
                }
                // A length field of four bytes made very large.
                _ => {
                    let index = numbers.below(changed.len().max(1));
                    for byte in changed.iter_mut().skip(index).take(4) {
                        *byte = 0xFF;
                    }
                }
            }
        }
        read(&changed);
        inputs += 1;
    }
    inputs
}

#[test]
fn a_damaged_signature_file_is_refused_or_read_and_never_a_panic() {
    let good = signature_file();
    assert!(digests(&good).is_ok());
    let mut accepted = 0;
    let inputs = damage(&good, |bytes| {
        accepted += usize::from(digests(bytes).is_ok());
    });
    assert!(inputs > 4000);
    // Most damage has to be noticed: the encoding states every length.
    assert!(
        accepted * 2 < inputs,
        "{accepted} of {inputs} damaged files were accepted"
    );
}

#[test]
fn a_damaged_block_map_is_refused_or_read_and_never_a_panic() {
    let good = BLOCK_MAP.as_bytes();
    assert_eq!(BlockMap::parse(good).map(|map| map.len()).ok(), Some(2));
    let inputs = damage(good, |bytes| {
        let Ok(block_map) = BlockMap::parse(bytes) else {
            return;
        };
        // What was read has to be usable without a panic too.
        for name in ["AppxManifest.xml", "tools\\tool.exe"] {
            if let Some(file) = block_map.file(name) {
                let _ = file.matches(&mut Cursor::new(bytes));
            }
        }
    });
    assert!(inputs > 4000);
}

#[test]
fn a_damaged_executable_is_looked_through_without_a_panic() {
    let good = executable();
    let inputs = damage(&good, |bytes| {
        // Reading from memory cannot fail, so there is always an answer.
        assert!(inspect(&mut Cursor::new(bytes)).is_ok());
    });
    assert!(inputs > 4000);
}

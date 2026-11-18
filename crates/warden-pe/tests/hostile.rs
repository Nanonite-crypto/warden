//! The reader against input that is wrong in every way a test can think
//! of: random bytes, valid files with bytes changed, valid files cut short,
//! and every header field set to the values that make arithmetic overflow.
//!
//! The reader never fails these tests by returning something odd; it fails
//! by panicking, by reading past the end (which panics), or by returning
//! facts that break its own limits. The fuzz targets in `fuzz/` hunt for
//! the same failures with coverage guidance; these tests run everywhere,
//! on every `cargo test`.

#![allow(clippy::unwrap_used)]

use proptest::prelude::*;
use warden_pe::fixture::{Filler, Fixture, FixtureImport};
use warden_pe::indicators::{Context, evaluate};
use warden_pe::{MAX_FUNCTIONS, MAX_LIBRARIES, MAX_SECTIONS, PeFacts, assess, read};

const NOW: Context = Context {
    now_unix_secs: 1_748_736_000,
};

/// What must hold for any facts the reader returns, whatever the input.
fn check(facts: &PeFacts, input_len: usize) {
    assert_eq!(facts.file_size, input_len as u64);
    assert!(facts.sections.len() <= MAX_SECTIONS);
    assert!(facts.imports.len() <= MAX_LIBRARIES);
    assert!(facts.import_count() <= MAX_FUNCTIONS);
    assert!(facts.overlay.size <= facts.file_size);
    assert!((0.0..=8.0).contains(&facts.file_entropy));
    assert!((0.0..=8.0).contains(&facts.overlay.entropy));
    for section in &facts.sections {
        assert!(
            (0.0..=8.0).contains(&section.entropy),
            "{}",
            section.entropy
        );
        assert!(section.name.chars().count() <= 8);
        assert!(!section.name.chars().any(char::is_control));
    }
    if let Some(index) = facts.entry_section {
        assert!(index < facts.sections.len());
        assert_ne!(facts.entry_point, 0);
    }
    for library in &facts.imports {
        assert!(!library.name.is_empty());
        assert!(
            library
                .name
                .bytes()
                .all(|byte| (0x21..0x7f).contains(&byte))
        );
        for function in &library.functions {
            assert!(function.bytes().all(|byte| (0x21..0x7f).contains(&byte)));
        }
    }
    // Whatever the facts are, judging them must work.
    let hits = evaluate(facts, &NOW);
    for hit in &hits {
        assert!(!hit.detail.is_empty());
    }
    let assessment = assess(facts, &NOW);
    assert_eq!(assessment.hits.len(), hits.len());
}

fn read_and_check(data: &[u8]) {
    if let Ok(facts) = read(data) {
        check(&facts, data.len());
    }
}

/// The fixtures the mutations start from: both formats, with imports by
/// name and by number, an overlay and a signature block.
fn seeds() -> Vec<Vec<u8>> {
    let mut filler = Filler::new(21);
    let mut varied = Fixture::plain();
    varied.wide = false;
    varied.imports[1].1.push(FixtureImport::Number(17));
    varied.overlay = filler.packed(700);
    varied.signature_len = 256;
    vec![
        Fixture::plain().build(),
        Fixture::packed_looking().build(),
        varied.build(),
    ]
}

/// Sets every 32-bit field in the headers, the section table and the import
/// section to the values that sit on the edges of the arithmetic: zero, the
/// largest numbers, the size of the file and its neighbours.
#[test]
fn every_header_field_survives_extreme_values() {
    for seed in seeds() {
        let len = seed.len() as u32;
        let extremes = [
            0u32,
            1,
            0x7fff_ffff,
            0x8000_0000,
            0xffff_fffe,
            0xffff_ffff,
            len.wrapping_sub(1),
            len,
            len.wrapping_add(1),
        ];
        // The headers, and the last section, which holds the import table.
        let import_section = seed.len().saturating_sub(0x800);
        let regions = [0..0x400usize.min(seed.len()), import_section..seed.len()];
        let mut file = seed.clone();
        for region in regions {
            for offset in region.step_by(2) {
                if offset + 4 > file.len() {
                    break;
                }
                let original = [
                    file[offset],
                    file[offset + 1],
                    file[offset + 2],
                    file[offset + 3],
                ];
                for value in extremes {
                    file[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
                    read_and_check(&file);
                }
                file[offset..offset + 4].copy_from_slice(&original);
            }
        }
    }
}

/// Every prefix of a valid file is a file that ends somewhere it should
/// not.
#[test]
fn a_file_cut_short_anywhere_is_handled() {
    for seed in seeds() {
        // Every length through the headers, then in steps.
        for len in (0..0x600.min(seed.len())).chain((0x600..seed.len()).step_by(61)) {
            read_and_check(&seed[..len]);
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn random_bytes_are_handled(data in proptest::collection::vec(any::<u8>(), 0..4096)) {
        read_and_check(&data);
    }

    /// Random bytes behind a header that passes the first checks get much
    /// further into the reader than random bytes alone.
    #[test]
    fn random_bytes_behind_a_valid_start_are_handled(
        tail in proptest::collection::vec(any::<u8>(), 0..2048),
        wide in any::<bool>(),
    ) {
        let mut data = vec![0u8; 0x80];
        data[..2].copy_from_slice(b"MZ");
        data[0x3c] = 0x40;
        data[0x40..0x44].copy_from_slice(b"PE\0\0");
        let magic: u16 = if wide { 0x20b } else { 0x10b };
        data[0x58..0x5a].copy_from_slice(&magic.to_le_bytes());
        data.truncate(0x5a);
        data.extend_from_slice(&tail);
        read_and_check(&data);
    }

    #[test]
    fn a_valid_file_with_bytes_changed_is_handled(
        seed in 0usize..3,
        changes in proptest::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..24),
        header_changes in proptest::collection::vec((0usize..0x400, any::<u8>()), 0..12),
        cut in proptest::option::of(any::<prop::sample::Index>()),
    ) {
        let mut file = seeds().swap_remove(seed);
        for (position, value) in changes {
            let position = position.index(file.len());
            file[position] = value;
        }
        for (position, value) in header_changes {
            if position < file.len() {
                file[position] = value;
            }
        }
        if let Some(cut) = cut {
            file.truncate(cut.index(file.len()));
        }
        read_and_check(&file);
    }
}

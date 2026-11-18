//! File-based round trips: build, write, memory-map, query.

#![allow(clippy::unwrap_used)]

use std::fs;

use warden_sigdb::{Category, SigDb, SigDbBuilder, SigDbError, hex};

fn hash(seed: u64) -> [u8; 32] {
    // SplitMix64: a tiny deterministic generator, good enough to spread test
    // hashes over every prefix bucket.
    let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    let mut out = [0u8; 32];
    for chunk in out.chunks_exact_mut(8) {
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        chunk.copy_from_slice(&(z ^ (z >> 31)).to_le_bytes());
    }
    out
}

#[test]
fn written_database_is_mapped_and_answers_lookups() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("signatures.wdb");

    let mut builder = SigDbBuilder::new().with_created_unix_secs(1_800_000_000);
    for seed in 0..5_000u64 {
        let (name, category) = match seed % 3 {
            0 => ("Trojan.Example", Category::Malware),
            1 => ("Adware.Example", Category::PotentiallyUnwanted),
            _ => ("Test.Example", Category::TestFile),
        };
        builder.add(hash(seed), name, category).unwrap();
    }
    let stats = builder.write_to(&path).unwrap();
    assert_eq!(stats.entries, 5_000);
    assert_eq!(stats.names, 3);

    let db = SigDb::open(&path).unwrap();
    assert!(db.is_memory_mapped());
    assert_eq!(db.len(), 5_000);
    assert_eq!(db.name_count(), 3);
    assert_eq!(db.created_unix_secs(), 1_800_000_000);
    assert_eq!(db.digest(), stats.digest);
    assert_eq!(db.size_bytes(), fs::metadata(&path).unwrap().len());

    for seed in 0..5_000u64 {
        let hit = db
            .lookup(&hash(seed))
            .unwrap_or_else(|| panic!("seed {seed} is missing"));
        let expected = match seed % 3 {
            0 => ("Trojan.Example", Category::Malware),
            1 => ("Adware.Example", Category::PotentiallyUnwanted),
            _ => ("Test.Example", Category::TestFile),
        };
        assert_eq!((hit.name, hit.category), expected);
    }
    for seed in 5_000..10_000u64 {
        assert!(!db.contains(&hash(seed)), "seed {seed} must not be present");
    }
}

#[test]
fn iteration_is_sorted_and_complete() {
    let mut builder = SigDbBuilder::new();
    for seed in 0..500u64 {
        builder.add(hash(seed), "Name", Category::Malware).unwrap();
    }
    let db = SigDb::from_bytes(builder.build().unwrap().0).unwrap();
    let hashes: Vec<[u8; 32]> = db.iter().map(|(hash, _)| hash).collect();
    assert_eq!(hashes.len(), 500);
    assert_eq!(db.iter().len(), 500);
    assert!(hashes.windows(2).all(|pair| pair[0] < pair[1]));
    assert!(
        (&db)
            .into_iter()
            .all(|(_, signature)| signature.name == "Name")
    );
}

#[test]
fn every_prefix_boundary_is_reachable() {
    // Hashes that differ only in their first two bytes land in different
    // buckets, including the first and the last one.
    let mut builder = SigDbBuilder::new();
    let prefixes = [
        0x0000u16, 0x0001, 0x00ff, 0x0100, 0x7fff, 0x8000, 0xfffe, 0xffff,
    ];
    for prefix in prefixes {
        let mut value = [0x55u8; 32];
        value[..2].copy_from_slice(&prefix.to_be_bytes());
        builder.add(value, "Boundary", Category::Malware).unwrap();
    }
    let db = SigDb::from_bytes(builder.build().unwrap().0).unwrap();
    for prefix in prefixes {
        let mut value = [0x55u8; 32];
        value[..2].copy_from_slice(&prefix.to_be_bytes());
        assert!(db.contains(&value), "prefix {prefix:#06x}");
        value[31] ^= 1;
        assert!(!db.contains(&value), "near miss for prefix {prefix:#06x}");
    }
}

#[test]
fn open_reports_missing_empty_and_foreign_files() {
    let dir = tempfile::tempdir().unwrap();

    let missing = SigDb::open(dir.path().join("missing.wdb"));
    assert!(matches!(missing, Err(SigDbError::Io { .. })));

    let empty = dir.path().join("empty.wdb");
    fs::write(&empty, b"").unwrap();
    assert!(matches!(
        SigDb::open(&empty),
        Err(SigDbError::Truncated { actual: 0, .. })
    ));

    let foreign = dir.path().join("foreign.wdb");
    fs::write(&foreign, vec![b'x'; 4096]).unwrap();
    assert!(matches!(SigDb::open(&foreign), Err(SigDbError::BadMagic)));
}

#[test]
fn debug_output_shows_the_digest() {
    let (bytes, stats) = SigDbBuilder::new()
        .with_created_unix_secs(1)
        .build()
        .unwrap();
    let db = SigDb::from_bytes(bytes).unwrap();
    let debug = format!("{db:?}");
    assert!(debug.contains(&hex::encode(&stats.digest)));
    assert!(debug.contains("memory_mapped: false"));
}

/// While a database is open, Windows must refuse to modify, replace or delete
/// the file. This is what makes the memory mapping sound, and it is the first
/// brick of the self-protection work planned for later phases.
#[cfg(windows)]
#[test]
fn an_open_database_cannot_be_changed_or_deleted() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("locked.wdb");
    let mut builder = SigDbBuilder::new();
    builder.add(hash(1), "Locked", Category::Malware).unwrap();
    builder.write_to(&path).unwrap();

    let db = SigDb::open(&path).unwrap();
    assert!(
        fs::write(&path, b"overwritten").is_err(),
        "overwrite must be refused"
    );
    assert!(fs::remove_file(&path).is_err(), "delete must be refused");
    let mut replacement = SigDbBuilder::new();
    replacement
        .add(hash(2), "Replacement", Category::Malware)
        .unwrap();
    assert!(
        replacement.write_to(&path).is_err(),
        "replace must be refused"
    );
    // A second reader is still welcome.
    assert!(SigDb::open(&path).unwrap().contains(&hash(1)));
    assert!(db.contains(&hash(1)));

    drop(db);
    fs::remove_file(&path).unwrap();
}

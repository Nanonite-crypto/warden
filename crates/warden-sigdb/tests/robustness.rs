//! Hostile-input tests: a damaged or crafted database must be rejected with
//! an error, never with a panic, and a database that is accepted must answer
//! every query consistently.

#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;

use proptest::prelude::*;
use sha2::{Digest, Sha256};
use warden_sigdb::{Category, HEADER_LEN, SigDb, SigDbBuilder, SigDbError};

const DIGEST_OFFSET: usize = 96;
const NAMES: [&str; 4] = ["Trojan.A", "Trojan.B", "Adware.C", "Test.D"];
const CATEGORIES: [Category; 3] = [
    Category::Malware,
    Category::TestFile,
    Category::PotentiallyUnwanted,
];

fn sample_database() -> Vec<u8> {
    let mut builder = SigDbBuilder::new().with_created_unix_secs(1_800_000_000);
    for index in 0u8..40 {
        let mut hash = [index; 32];
        hash[0] = index.wrapping_mul(37);
        hash[1] = index.wrapping_mul(11);
        builder
            .add(
                hash,
                NAMES[usize::from(index) % NAMES.len()],
                CATEGORIES[usize::from(index) % CATEGORIES.len()],
            )
            .unwrap();
    }
    builder.build().unwrap().0
}

/// Recomputes the header digest, so that tests can reach the structural
/// checks that sit behind the digest check.
fn reseal(bytes: &mut [u8]) {
    let mut hasher = Sha256::new();
    hasher.update(&bytes[..DIGEST_OFFSET]);
    hasher.update(&bytes[HEADER_LEN..]);
    let digest: [u8; 32] = hasher.finalize().into();
    bytes[DIGEST_OFFSET..HEADER_LEN].copy_from_slice(&digest);
}

#[test]
fn truncation_is_always_an_error() {
    let bytes = sample_database();
    let mut lengths: Vec<usize> = (0..=HEADER_LEN + 8).collect();
    lengths.extend((1..=64).map(|back| bytes.len() - back));
    lengths.extend((0..bytes.len()).step_by(7919));
    for length in lengths {
        let result = SigDb::from_bytes(&bytes[..length]);
        assert!(
            result.is_err(),
            "a database cut to {length} bytes was accepted"
        );
    }
}

#[test]
fn appended_bytes_are_an_error() {
    let mut bytes = sample_database();
    bytes.push(0);
    assert!(SigDb::from_bytes(bytes).is_err());
}

#[test]
fn every_header_byte_is_protected() {
    let bytes = sample_database();
    for position in 0..HEADER_LEN {
        let mut damaged = bytes.clone();
        damaged[position] ^= 0x01;
        assert!(
            SigDb::from_bytes(damaged).is_err(),
            "flipping header byte {position} went unnoticed"
        );
    }
}

#[test]
fn body_damage_is_caught_by_the_digest() {
    let bytes = sample_database();
    for position in (HEADER_LEN..bytes.len())
        .step_by(4099)
        .chain([bytes.len() - 1])
    {
        let mut damaged = bytes.clone();
        damaged[position] ^= 0x80;
        assert!(
            matches!(SigDb::from_bytes(damaged), Err(SigDbError::DigestMismatch)),
            "flipping body byte {position} was not reported as a digest mismatch"
        );
    }
}

#[test]
fn crafted_structures_with_a_valid_digest_are_rejected() {
    let bytes = sample_database();
    let fanout_start = HEADER_LEN;
    let hashes_start = HEADER_LEN + 65536 * 4;
    let name_ids_start = hashes_start + 40 * 32;

    // A prefix index that claims more entries than exist.
    let mut inflated = bytes.clone();
    inflated[fanout_start..fanout_start + 4].copy_from_slice(&1000u32.to_le_bytes());
    reseal(&mut inflated);
    assert!(matches!(
        SigDb::from_bytes(inflated),
        Err(SigDbError::Corrupt(_))
    ));

    // Two hashes swapped, so the table is no longer sorted.
    let mut unsorted = bytes.clone();
    let (first, second) = unsorted[hashes_start..hashes_start + 64].split_at_mut(32);
    first.swap_with_slice(second);
    reseal(&mut unsorted);
    assert!(matches!(
        SigDb::from_bytes(unsorted),
        Err(SigDbError::Corrupt(_))
    ));

    // An entry that points at a detection name that does not exist.
    let mut dangling = bytes.clone();
    dangling[name_ids_start..name_ids_start + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    reseal(&mut dangling);
    assert!(matches!(
        SigDb::from_bytes(dangling),
        Err(SigDbError::Corrupt(_))
    ));

    // An entry count far larger than the file.
    let mut oversized = bytes.clone();
    oversized[24..32].copy_from_slice(&u64::from(u32::MAX).to_le_bytes());
    reseal(&mut oversized);
    assert!(SigDb::from_bytes(oversized).is_err());

    // A detection name that is not UTF-8.
    let mut bad_name = bytes;
    let last = bad_name.len() - 1;
    bad_name[last] = 0xff;
    reseal(&mut bad_name);
    assert!(matches!(
        SigDb::from_bytes(bad_name),
        Err(SigDbError::Corrupt(_))
    ));
}

fn arbitrary_hash() -> impl Strategy<Value = [u8; 32]> {
    // A small set of leading bytes forces many hashes into the same prefix
    // bucket, which is where the binary search has to work.
    (0u8..4, 0u8..4, any::<[u8; 30]>()).prop_map(|(first, second, rest)| {
        let mut hash = [0u8; 32];
        hash[0] = first;
        hash[1] = second;
        hash[2..].copy_from_slice(&rest);
        hash
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn every_added_hash_is_found_with_its_first_signature(
        entries in prop::collection::vec(
            (arbitrary_hash(), 0usize..NAMES.len(), 0usize..CATEGORIES.len()),
            0..120,
        ),
        probes in prop::collection::vec(arbitrary_hash(), 0..40),
    ) {
        let mut expected: BTreeMap<[u8; 32], (&str, Category)> = BTreeMap::new();
        let mut builder = SigDbBuilder::new();
        for (hash, name, category) in &entries {
            builder.add(*hash, NAMES[*name], CATEGORIES[*category]).unwrap();
            expected.entry(*hash).or_insert((NAMES[*name], CATEGORIES[*category]));
        }
        let (bytes, stats) = builder.build().unwrap();
        prop_assert_eq!(stats.entries, expected.len() as u64);
        prop_assert_eq!(stats.duplicates_dropped, (entries.len() - expected.len()) as u64);

        let db = SigDb::from_bytes(bytes).unwrap();
        prop_assert_eq!(db.len(), expected.len());
        for (hash, (name, category)) in &expected {
            let hit = db.lookup(hash);
            prop_assert_eq!(hit.map(|signature| (signature.name, signature.category)), Some((*name, *category)));
        }
        for probe in &probes {
            prop_assert_eq!(db.contains(probe), expected.contains_key(probe));
        }
        let listed: Vec<[u8; 32]> = db.iter().map(|(hash, _)| hash).collect();
        let sorted: Vec<[u8; 32]> = expected.keys().copied().collect();
        prop_assert_eq!(listed, sorted);
    }

    #[test]
    fn arbitrary_bytes_are_rejected_without_panicking(
        bytes in prop::collection::vec(any::<u8>(), 0..2048),
    ) {
        prop_assert!(SigDb::from_bytes(bytes).is_err());
    }

    #[test]
    fn resealed_damage_never_panics(
        edits in prop::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..12),
        header_edits in prop::collection::vec((24usize..DIGEST_OFFSET, any::<u8>()), 0..3),
        probes in prop::collection::vec(arbitrary_hash(), 1..20),
    ) {
        let mut bytes = sample_database();
        let body_len = bytes.len() - HEADER_LEN;
        for (position, value) in &edits {
            bytes[HEADER_LEN + position.index(body_len)] = *value;
        }
        for (position, value) in &header_edits {
            bytes[*position] = *value;
        }
        reseal(&mut bytes);

        // Either outcome is fine. What must hold: no panic, and an accepted
        // database behaves like a sorted set.
        if let Ok(db) = SigDb::from_bytes(bytes) {
            let listed: Vec<[u8; 32]> = db.iter().map(|(hash, _)| hash).collect();
            prop_assert!(listed.windows(2).all(|pair| pair[0] < pair[1]));
            for hash in &listed {
                prop_assert!(db.contains(hash));
            }
            for probe in &probes {
                let _ = db.lookup(probe);
            }
        }
    }
}

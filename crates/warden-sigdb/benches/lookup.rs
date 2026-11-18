//! Micro-benchmarks for the signature database.
//!
//! Run with `cargo bench -p warden-sigdb`. Numbers quoted in
//! `docs/BENCHMARKS.md` come from this harness.

#![allow(clippy::unwrap_used, missing_docs)]

use std::hint::black_box;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use warden_sigdb::{Category, SigDb, SigDbBuilder};

const ENTRIES: u64 = 1_000_000;

/// SplitMix64, expanded to 32 bytes: deterministic, uniformly spread hashes.
fn hash(seed: u64) -> [u8; 32] {
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

fn million_entry_database() -> Vec<u8> {
    let mut builder = SigDbBuilder::new().with_created_unix_secs(0);
    for seed in 0..ENTRIES {
        builder
            .add(hash(seed), "Benchmark.Entry", Category::Malware)
            .unwrap();
    }
    builder.build().unwrap().0
}

fn benchmarks(criterion: &mut Criterion) {
    let bytes = million_entry_database();
    let db = SigDb::from_bytes(bytes.clone()).unwrap();
    let present: Vec<[u8; 32]> = (0..1024).map(|index| hash(index * 977)).collect();
    let absent: Vec<[u8; 32]> = (0..1024).map(|index| hash(ENTRIES + index)).collect();

    let mut group = criterion.benchmark_group("sigdb_1m_entries");
    group.bench_function("lookup_hit", |bencher| {
        let mut index = 0usize;
        bencher.iter(|| {
            index = (index + 1) & 1023;
            black_box(db.lookup(black_box(&present[index])))
        });
    });
    group.bench_function("lookup_miss", |bencher| {
        let mut index = 0usize;
        bencher.iter(|| {
            index = (index + 1) & 1023;
            black_box(db.lookup(black_box(&absent[index])))
        });
    });
    group.sample_size(10);
    group.bench_function("verify_on_open", |bencher| {
        bencher.iter_batched(
            || bytes.clone(),
            |copy| black_box(SigDb::from_bytes(copy).unwrap()),
            BatchSize::LargeInput,
        );
    });
    group.finish();
}

criterion_group!(benches, benchmarks);
criterion_main!(benches);

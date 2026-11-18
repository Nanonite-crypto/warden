//! Micro-benchmark for the hashing that every scanned byte goes through.
//!
//! Run with `cargo bench -p warden-engine`. This is the ceiling for scan
//! throughput per core: a scan can never be faster than it can hash.

#![allow(missing_docs)]

use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};

fn benchmarks(criterion: &mut Criterion) {
    let megabyte = vec![0xA5u8; 1024 * 1024];
    let mut group = criterion.benchmark_group("sha256");
    group.throughput(Throughput::Bytes(megabyte.len() as u64));
    group.bench_function("one_mebibyte", |bencher| {
        bencher.iter(|| black_box(warden_engine::sha256(black_box(&megabyte))));
    });
    group.finish();
}

criterion_group!(benches, benchmarks);
criterion_main!(benches);

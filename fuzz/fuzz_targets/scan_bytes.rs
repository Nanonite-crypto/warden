//! The scan pipeline on one buffer: hashing, unpacking zip archives within
//! their limits, and the heuristic layer on whatever comes out.
//!
//! The YARA layer is left out. It is the YARA-X project's code, which has
//! fuzzers of its own, and it would make every run of this one many times
//! slower.

#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use warden_engine::{HashDetector, Scanner};
use warden_pe::PeDetector;

fn scanner() -> &'static Scanner {
    static SCANNER: OnceLock<Scanner> = OnceLock::new();
    SCANNER.get_or_init(|| {
        Scanner::builder()
            .detector(HashDetector::new())
            .detector(PeDetector::new())
            .build()
    })
}

fuzz_target!(|data: &[u8]| {
    let _ = scanner().scan_bytes(data);
});

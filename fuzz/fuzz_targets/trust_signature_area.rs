//! The part of an executable that holds its signature and that no
//! signature covers.
//!
//! Warden looks through it before it asks Windows about a signature, so
//! this code sees files that nothing has vouched for yet. Whatever the
//! bytes are, looking through them must not panic.

#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use warden_trust::sigarea::inspect;

fuzz_target!(|data: &[u8]| {
    let _ = inspect(&mut Cursor::new(data));
});

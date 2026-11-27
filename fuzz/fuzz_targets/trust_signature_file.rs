//! The signature file of an app package: the list of digests is dug out of
//! the encoding that signatures use.
//!
//! The file lies in a folder that anyone may have written to, and it is
//! read before Windows has said a word about it. Whatever the bytes are,
//! reading them must not panic.

#![no_main]

use libfuzzer_sys::fuzz_target;
use warden_trust::package::digests;

fuzz_target!(|data: &[u8]| {
    let _ = digests(data);
});

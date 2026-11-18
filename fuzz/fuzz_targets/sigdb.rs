//! The signature database reader. A database is a file someone hands to
//! Warden, so it is read like any other untrusted file.
//!
//! The reader checks a digest over the whole file before it trusts any of
//! it, and a fuzzer cannot guess a SHA-256. So this target reaches the
//! checks in front of the digest: the magic, the version, the lengths. What
//! comes behind the digest is covered by the reader's own tests, which
//! damage a database and fix the digest up again.

#![no_main]

use libfuzzer_sys::fuzz_target;
use warden_sigdb::SigDb;

fuzz_target!(|data: &[u8]| {
    let Ok(database) = SigDb::from_bytes(data) else {
        return;
    };
    // A database that loads must also be safe to use.
    let _ = database.lookup(&[0u8; 32]);
    let _ = database.lookup(&[0xffu8; 32]);
    for signature in database.iter().take(64) {
        let _ = signature;
    }
});

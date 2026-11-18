//! The reader for Windows executables, and the indicators on top of it.
//!
//! Whatever the bytes are, reading them must not panic, and the facts that
//! come back must stay within the reader's limits.

#![no_main]

use libfuzzer_sys::fuzz_target;
use warden_pe::indicators::{Context, evaluate};
use warden_pe::{MAX_FUNCTIONS, MAX_LIBRARIES, MAX_SECTIONS, read};

fuzz_target!(|data: &[u8]| {
    let Ok(facts) = read(data) else {
        return;
    };
    assert!(facts.sections.len() <= MAX_SECTIONS);
    assert!(facts.imports.len() <= MAX_LIBRARIES);
    assert!(facts.import_count() <= MAX_FUNCTIONS);
    assert!(facts.overlay.size <= data.len() as u64);
    if let Some(index) = facts.entry_section {
        assert!(index < facts.sections.len());
    }
    let context = Context {
        now_unix_secs: 1_748_736_000,
    };
    let _ = evaluate(&facts, &context);
});

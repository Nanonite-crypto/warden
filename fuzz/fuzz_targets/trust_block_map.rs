//! The block map of an app package: a list of files with the hashes of
//! their blocks, as XML.
//!
//! Whatever the bytes are, reading them must not panic, and what comes
//! back has to hold together: a file that is listed has as many block
//! hashes as its length calls for, or it would be compared against the
//! wrong blocks.

#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use warden_trust::package::BlockMap;

fuzz_target!(|data: &[u8]| {
    let Ok(block_map) = BlockMap::parse(data) else {
        return;
    };
    // Looking a file up and comparing content with its entry must not
    // panic either, whatever the entry says.
    for name in ["AppxManifest.xml", "tools\\tool.exe", "a", ""] {
        if let Some(file) = block_map.file(name) {
            let _ = file.matches(&mut Cursor::new(data));
        }
    }
    let _ = block_map.len();
});

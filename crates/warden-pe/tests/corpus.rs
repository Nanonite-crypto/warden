//! The reader against real Windows executables, checked by a second reader.
//!
//! The other tests use fixtures that this project builds itself. This one
//! reads whatever executables are in the folder named by `WARDEN_PE_CORPUS`
//! (on the Windows CI runner: `C:\Windows\System32`) with Warden's reader
//! and with the `object` crate, and compares what the two see. Without the
//! variable the test does nothing, because a Linux machine has no such
//! folder.
//!
//! `WARDEN_PE_CORPUS_LIMIT` sets how many executables are compared; the
//! default is 1,000.

#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};

use object::LittleEndian as LE;
use object::read::pe::{ImageNtHeaders, ImageOptionalHeader, PeFile, PeFile32, PeFile64};
use warden_pe::{Anomaly, Format, PeFacts, looks_like_pe, read};

/// Files larger than this are left out, to keep the test quick.
const MAX_FILE_BYTES: u64 = 32 * 1024 * 1024;

fn files_under(root: &Path, limit: usize) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut pending = vec![root.to_owned()];
    while let Some(folder) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&folder) else {
            continue;
        };
        let mut entries: Vec<_> = entries.filter_map(Result::ok).collect();
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_dir() {
                pending.push(entry.path());
            } else if kind.is_file() {
                found.push(entry.path());
                if found.len() >= limit {
                    return found;
                }
            }
        }
    }
    found
}

/// What the two readers disagree on for one file, if anything.
fn disagreement<Pe: ImageNtHeaders>(file: &PeFile<'_, Pe>, facts: &PeFacts) -> Option<String> {
    let optional = file.nt_headers().optional_header();
    if optional.address_of_entry_point() != facts.entry_point {
        return Some("the entry point".to_owned());
    }
    if optional.dll_characteristics() != facts.image_flags
        || optional.subsystem() != facts.subsystem
    {
        return Some("the loader flags or the subsystem".to_owned());
    }
    if file.nt_headers().file_header().time_date_stamp.get(LE) != facts.timestamp {
        return Some("the link time".to_owned());
    }

    let table = file.section_table();
    if table.len() != facts.sections.len() {
        return Some(format!(
            "the number of sections: {} and {}",
            table.len(),
            facts.sections.len()
        ));
    }
    for (theirs, ours) in table.iter().zip(&facts.sections) {
        if theirs.size_of_raw_data.get(LE) != ours.raw_size
            || theirs.virtual_size.get(LE) != ours.virtual_size
            || theirs.characteristics.get(LE) != ours.characteristics
        {
            return Some(format!("section {:?}", ours.name));
        }
    }

    // Imports are compared when both readers got through the table without
    // complaint. Where one gives up and the other does not, the file is
    // damaged, and there is no right answer to agree on.
    let ours_complained = facts.anomalies.iter().any(|anomaly| {
        matches!(
            anomaly,
            Anomaly::ImportTableUnreadable
                | Anomaly::ImportNamesUnreadable { .. }
                | Anomaly::ImportsCutShort
        )
    });
    if ours_complained {
        return None;
    }
    let Ok(Some(import_table)) = file.import_table() else {
        return None;
    };
    let Ok(mut descriptors) = import_table.descriptors() else {
        return None;
    };
    let mut theirs: Vec<(String, Vec<String>)> = Vec::new();
    while let Ok(Some(descriptor)) = descriptors.next() {
        let Ok(library) = import_table.name(descriptor.name.get(LE)) else {
            return None;
        };
        let lookup = descriptor.original_first_thunk.get(LE);
        let list = if lookup != 0 {
            lookup
        } else {
            descriptor.first_thunk.get(LE)
        };
        let Ok(mut thunks) = import_table.thunks(list) else {
            return None;
        };
        let mut functions = Vec::new();
        loop {
            match thunks.next::<Pe>() {
                Ok(Some(thunk)) => match import_table.import::<Pe>(thunk) {
                    Ok(object::read::pe::Import::Ordinal(number)) => {
                        functions.push(format!("#{number}"));
                    }
                    Ok(object::read::pe::Import::Name(_, name)) => {
                        functions.push(String::from_utf8_lossy(name).into_owned());
                    }
                    Err(_) => return None,
                },
                Ok(None) => break,
                Err(_) => return None,
            }
        }
        theirs.push((String::from_utf8_lossy(library).into_owned(), functions));
    }
    let ours: Vec<(String, Vec<String>)> = facts
        .imports
        .iter()
        .map(|library| (library.name.clone(), library.functions.clone()))
        .collect();
    (theirs != ours).then(|| {
        format!(
            "the imports: {} libraries with {} functions, and {} with {}",
            theirs.len(),
            theirs
                .iter()
                .map(|(_, functions)| functions.len())
                .sum::<usize>(),
            ours.len(),
            facts.import_count()
        )
    })
}

#[test]
fn the_reader_agrees_with_a_second_reader_on_real_executables() {
    let Some(root) = std::env::var_os("WARDEN_PE_CORPUS").filter(|value| !value.is_empty()) else {
        eprintln!("note: WARDEN_PE_CORPUS is not set; no real executables were read.");
        return;
    };
    let limit: usize = std::env::var("WARDEN_PE_CORPUS_LIMIT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(1_000);

    let mut compared = 0usize;
    let mut only_ours = 0usize;
    let mut with_anomalies = 0usize;
    let mut disagreements = Vec::new();
    // Most files in a system folder are not executables, so many more are
    // looked at than are compared.
    for path in files_under(Path::new(&root), limit.saturating_mul(20)) {
        if compared >= limit {
            break;
        }
        let Ok(metadata) = std::fs::metadata(&path) else {
            continue;
        };
        if metadata.len() > MAX_FILE_BYTES {
            continue;
        }
        let Ok(data) = std::fs::read(&path) else {
            continue;
        };
        if !looks_like_pe(&data) {
            continue;
        }
        let Ok(facts) = read(&data) else {
            continue;
        };
        if !facts.anomalies.is_empty() {
            with_anomalies += 1;
        }
        let found = match facts.format {
            Format::Pe32 => PeFile32::parse(&*data)
                .ok()
                .map(|file| disagreement(&file, &facts)),
            Format::Pe32Plus => PeFile64::parse(&*data)
                .ok()
                .map(|file| disagreement(&file, &facts)),
        };
        match found {
            Some(Some(what)) => disagreements.push(format!("{}: {what}", path.display())),
            Some(None) => compared += 1,
            None => only_ours += 1,
        }
    }

    eprintln!(
        "note: compared {compared} executables under {}; {} disagreements; {only_ours} that only Warden's reader accepted; {with_anomalies} with structural oddities.",
        Path::new(&root).display(),
        disagreements.len()
    );
    assert!(
        disagreements.is_empty(),
        "the readers disagree on {} files, for example:\n{}",
        disagreements.len(),
        disagreements
            .iter()
            .take(10)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
    assert!(
        compared > 0,
        "WARDEN_PE_CORPUS is set, and no executable under it could be compared"
    );
}

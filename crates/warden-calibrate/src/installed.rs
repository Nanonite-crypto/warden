//! Counts the same things on real files: the executables in folders of a
//! Windows machine.
//!
//! The dataset says how often an indicator applies to benign files that
//! were uploaded to a scanning service. That is not the same population as
//! the files of a Windows installation, and false alarms happen on the
//! latter. So the files of a machine that is taken to be clean are counted
//! the same way, and the report shows what the score does on them.
//!
//! Files are read and never changed. Nothing about a single file is
//! written down: the result holds counts per combination of indicators.

use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::bail;
use warden_pe::indicators::Context;

use crate::collect::{Collected, Kind, Subset, Tally};

/// Larger files are left out. Executables of this size are installers and
/// games; reading them whole would decide how long a run takes.
pub const MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;

/// Every regular file under `root`. Symbolic links and junctions are not
/// followed, so no file is counted twice and the walk ends. Folders that
/// cannot be listed are counted in `unlisted`.
fn files_under(root: &Path, unlisted: &mut u64) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut folders = vec![root.to_path_buf()];
    while let Some(folder) = folders.pop() {
        let Ok(entries) = fs::read_dir(&folder) else {
            *unlisted += 1;
            continue;
        };
        for entry in entries.flatten() {
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_dir() {
                folders.push(entry.path());
            } else if kind.is_file() {
                found.push(entry.path());
            }
        }
    }
    // The order in which a folder lists its files is not defined.
    found.sort();
    found
}

/// What became of one file.
enum Outcome {
    Counted,
    NotAnExecutable,
    LooksLikeOneAndIsNot,
    Unreadable,
}

fn count_file(path: &Path, subset: Subset, context: &Context, tally: &mut Tally) -> Outcome {
    let Ok(mut file) = File::open(path) else {
        return Outcome::Unreadable;
    };
    let mut start = [0u8; 2];
    match file.read(&mut start) {
        Ok(2) if &start == b"MZ" => {}
        Ok(_) => return Outcome::NotAnExecutable,
        Err(_) => return Outcome::Unreadable,
    }
    let size = file.metadata().map_or(0, |metadata| metadata.len());
    if size > MAX_FILE_BYTES {
        return Outcome::Unreadable;
    }
    let mut content = Vec::with_capacity(size as usize);
    content.extend_from_slice(&start);
    if file.read_to_end(&mut content).is_err() {
        return Outcome::Unreadable;
    }
    match warden_pe::read(&content) {
        Ok(facts) => {
            tally.count(subset, Kind::of(&facts), false, &facts, context);
            Outcome::Counted
        }
        Err(_) => Outcome::LooksLikeOneAndIsNot,
    }
}

/// Counts the Windows executables under the given folders as benign files
/// of the part `subset`, using `threads` threads.
///
/// In the summary of each folder, `records` is the number of files found,
/// `counted` the executables that were counted, `other_kinds` the files
/// that are not executables, `not_parsed_as_pe` those that start like one
/// and are not, and `unreadable` those that could not be opened or read or
/// are larger than [`MAX_FILE_BYTES`].
///
/// # Errors
///
/// Fails if `subset` is a part of the dataset, or if a folder does not
/// exist.
pub fn collect_files(
    roots: &[PathBuf],
    subset: Subset,
    threads: usize,
) -> anyhow::Result<(Collected, u64)> {
    if subset.is_dataset() {
        bail!("files of a machine are counted as \"system\" or \"software\"");
    }
    let context = Context::now();
    let mut total = Tally::default();
    let mut unlisted = 0u64;
    let mut names = Vec::with_capacity(roots.len());
    for (input, root) in roots.iter().enumerate() {
        if !root.is_dir() {
            bail!("{} is not a folder", root.display());
        }
        names.push(root.display().to_string());
        let files = files_under(root, &mut unlisted);
        let next = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            let workers: Vec<_> = (0..threads.max(1))
                .map(|_| {
                    scope.spawn(|| {
                        let mut tally = Tally::default();
                        while let Some(path) = files.get(next.fetch_add(1, Ordering::Relaxed)) {
                            let outcome = count_file(path, subset, &context, &mut tally);
                            let summary = tally.inputs.entry(input).or_default();
                            summary.records += 1;
                            match outcome {
                                Outcome::Counted => summary.counted += 1,
                                Outcome::NotAnExecutable => summary.other_kinds += 1,
                                Outcome::LooksLikeOneAndIsNot => summary.not_parsed_as_pe += 1,
                                Outcome::Unreadable => summary.unreadable += 1,
                            }
                        }
                        tally
                    })
                })
                .collect();
            for worker in workers {
                if let Ok(tally) = worker.join() {
                    total.merge(tally);
                }
            }
        });
    }
    Ok((total.finish(names), unlisted))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use warden_pe::fixture::Fixture;

    use super::*;

    #[test]
    fn executables_in_a_folder_are_counted_and_other_files_are_not() {
        let folder = tempfile::tempdir().unwrap();
        let nested = folder.path().join("a").join("b");
        fs::create_dir_all(&nested).unwrap();
        // The plain fixture only: nothing that looks packed is written to
        // disk, where an antivirus product would take it away.
        fs::write(folder.path().join("one.exe"), Fixture::plain().build()).unwrap();
        fs::write(nested.join("two.dll"), {
            let mut library = Fixture::plain();
            library.dll = true;
            library.build()
        })
        .unwrap();
        fs::write(nested.join("notes.txt"), "MZ is how an executable starts").unwrap();
        fs::write(folder.path().join("readme.md"), "not one").unwrap();
        fs::write(folder.path().join("empty"), "").unwrap();

        let (collected, unlisted) =
            collect_files(&[folder.path().to_path_buf()], Subset::Software, 3).unwrap();
        assert_eq!(unlisted, 0);
        let summary = &collected.inputs[0];
        assert_eq!(summary.records, 5);
        assert_eq!(summary.counted, 2);
        assert_eq!(summary.not_parsed_as_pe, 1);
        assert_eq!(summary.other_kinds, 2);
        assert_eq!(summary.unreadable, 0);

        assert_eq!(
            collected
                .groups
                .iter()
                .map(|group| group.files)
                .sum::<u64>(),
            2
        );
        assert!(collected.groups.iter().all(|group| {
            group.subset == Subset::Software && !group.malicious && group.kind == Kind::Win64
        }));
        // A program and a library differ in at least the probe that says so.
        assert_eq!(collected.groups.len(), 2);
    }

    #[test]
    fn a_part_of_the_dataset_is_not_a_name_for_files_of_a_machine() {
        let folder = tempfile::tempdir().unwrap();
        assert!(collect_files(&[folder.path().to_path_buf()], Subset::Train, 1).is_err());
        assert!(
            collect_files(&[folder.path().join("missing")], Subset::System, 1).is_err(),
            "a folder that does not exist is an error, not zero files"
        );
    }
}

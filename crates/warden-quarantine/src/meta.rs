//! What a file has besides its content, and how it gets it back.
//!
//! Timestamps are kept on every system. Beyond that, what "the same file
//! again" means depends on the system:
//!
//! - On Unix a file has an owner, a group and permission bits.
//! - On Windows it has attribute bits, a security descriptor (owner, group
//!   and access-control list) and possibly a `Zone.Identifier` stream, the
//!   mark Windows puts on files that came from the internet. A restore that
//!   lost that mark would hand back a file that Windows trusts more than
//!   before, which is the opposite of what a quarantine is for.
//!
//! Not kept, on any system: extended attributes, other named streams, the
//! compressed and encrypted states of NTFS, and hard links. A quarantined
//! file that had other names keeps them; only the name that was given is
//! removed. Of the attribute bits of Windows, the ones a program may set
//! come back if the file had them. The "archive" bit, which Windows sets
//! on every file that is written, is set on a restored file whether the
//! original had it or not.
//!
//! # The order of things on restore
//!
//! A file appears under its name with its content whole, or not at all:
//! it is written under a temporary name and gets its own name in one step.
//! What it has besides its content is put back in two parts around that
//! step.
//!
//! Before it: what must be true the moment the file appears. On Unix that
//! is the owner and the permission bits, on Windows the mark of the
//! internet, and on both the timestamps.
//!
//! After it, on Windows: the read-only bit and the access rights. Either
//! can take away what the step itself needs. A read-only file cannot be
//! given another name, and access rights can deny the user who restores
//! the file everything but reading it. They go on through the handle the
//! file was written with, which keeps the rights it was opened with.

use std::fs::{File, FileTimes, Metadata};
use std::io;
use std::path::Path;

use crate::info::{EntryInfo, Stamp, Times, UnixMeta, WindowsMeta};

/// What was read from a file before it was quarantined.
#[derive(Debug, Clone, Default)]
pub(crate) struct Captured {
    pub times: Times,
    pub unix: Option<UnixMeta>,
    pub windows: Option<WindowsMeta>,
}

fn times_of(metadata: &Metadata) -> Times {
    Times {
        modified: metadata.modified().ok().and_then(Stamp::of),
        accessed: metadata.accessed().ok().and_then(Stamp::of),
        created: metadata.created().ok().and_then(Stamp::of),
    }
}

/// Reads what `file` has besides its content. `metadata` is that of the
/// open file, so everything here belongs to the file whose content is
/// read, whatever happens to its name in the meantime.
#[cfg(unix)]
pub(crate) fn capture(_file: &File, metadata: &Metadata, _path: &Path) -> Captured {
    use std::os::unix::fs::MetadataExt;
    Captured {
        times: times_of(metadata),
        unix: Some(UnixMeta {
            mode: metadata.mode() & 0o7777,
            uid: metadata.uid(),
            gid: metadata.gid(),
        }),
        windows: None,
    }
}

#[cfg(windows)]
pub(crate) fn capture(file: &File, metadata: &Metadata, path: &Path) -> Captured {
    use std::os::windows::fs::MetadataExt;
    Captured {
        times: times_of(metadata),
        unix: None,
        windows: Some(WindowsMeta {
            attributes: metadata.file_attributes(),
            security_descriptor: crate::windows::read_security_descriptor(file)
                .ok()
                .map(|bytes| crate::hex::encode(&bytes)),
            // A named stream can only be asked for by the file's name.
            zone_identifier: std::fs::read(crate::windows::zone_stream(path))
                .ok()
                .map(|bytes| crate::hex::encode(&bytes)),
        }),
    }
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn capture(_file: &File, metadata: &Metadata, _path: &Path) -> Captured {
    Captured {
        times: times_of(metadata),
        unix: None,
        windows: None,
    }
}

fn file_times(times: &Times) -> FileTimes {
    let mut out = FileTimes::new();
    if let Some(modified) = times.modified.and_then(Stamp::to_system_time) {
        out = out.set_modified(modified);
    }
    if let Some(accessed) = times.accessed.and_then(Stamp::to_system_time) {
        out = out.set_accessed(accessed);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileTimesExt;
        if let Some(created) = times.created.and_then(Stamp::to_system_time) {
            out = out.set_created(created);
        }
    }
    out
}

/// Creates the file a restore writes to, under its temporary name. It must
/// not exist yet.
///
/// Nobody but its owner can read it until it has the permission bits of
/// the original: a file that was private is not readable for everybody
/// while it is being put together.
#[cfg(unix)]
pub(crate) fn create(path: &Path, _info: &EntryInfo) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    File::options()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

/// Creates the file a restore writes to, under its temporary name. It must
/// not exist yet.
///
/// It is created with the attribute bits of the original that a file can
/// be created with, and with a handle through which its access rights can
/// be set at the end.
#[cfg(windows)]
pub(crate) fn create(path: &Path, info: &EntryInfo) -> io::Result<File> {
    let attributes = info.windows.as_ref().map_or(0, |windows| {
        windows.attributes & crate::windows::RESTORABLE_ATTRIBUTES
    });
    crate::windows::create_for_restore(path, attributes)
}

/// Creates the file a restore writes to, under its temporary name. It must
/// not exist yet.
#[cfg(not(any(unix, windows)))]
pub(crate) fn create(path: &Path, _info: &EntryInfo) -> io::Result<File> {
    File::options().write(true).create_new(true).open(path)
}

/// Gives a restored file back what it has to have the moment it appears
/// under its name. The file still has its temporary name; `file` is open
/// for writing and holds the whole content. Returns what could not be put
/// back, one sentence each: the content is what matters most, so none of
/// this stops a restore.
pub(crate) fn apply(file: &File, path: &Path, info: &EntryInfo) -> Vec<String> {
    let mut notes = Vec::new();
    apply_system(file, path, info, &mut notes);
    // Last, because what comes before can touch the timestamps.
    if let Err(error) = file.set_times(file_times(&info.times)) {
        notes.push(format!("Its timestamps could not be set: {error}"));
    }
    notes
}

#[cfg(unix)]
fn apply_system(file: &File, _path: &Path, info: &EntryInfo, notes: &mut Vec<String>) {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let Some(unix) = info.unix else {
        if info.windows.is_some() {
            notes.push(
                "The entry comes from Windows, and its access rights mean nothing on this system. Only the owner of the file can read and write it"
                    .to_owned(),
            );
        }
        return;
    };
    // The owner first: changing it clears the set-user-id bit.
    let now = file.metadata().ok();
    let differs = now
        .as_ref()
        .is_none_or(|now| now.uid() != unix.uid || now.gid() != unix.gid);
    if differs && let Err(error) = std::os::unix::fs::fchown(file, Some(unix.uid), Some(unix.gid)) {
        notes.push(format!(
            "Its owner could not be set back to user {} and group {}: {error}",
            unix.uid, unix.gid
        ));
    }
    if let Err(error) = file.set_permissions(std::fs::Permissions::from_mode(unix.mode)) {
        notes.push(format!(
            "Its permission bits could not be set back to {:o}: {error}",
            unix.mode
        ));
    }
}

#[cfg(windows)]
fn apply_system(_file: &File, path: &Path, info: &EntryInfo, notes: &mut Vec<String>) {
    let Some(windows) = &info.windows else {
        if info.unix.is_some() {
            notes.push(
                "The entry comes from a Unix system; its owner and permission bits mean nothing on Windows"
                    .to_owned(),
            );
        }
        return;
    };
    // The mark of the internet has to be on the file before it has its
    // name: Windows asks for it when the file is opened.
    if let Some(zone) = &windows.zone_identifier {
        let written = crate::hex::decode(zone)
            .ok_or_else(|| io::Error::other("the record does not hold it in a readable form"))
            .and_then(|bytes| std::fs::write(crate::windows::zone_stream(path), bytes));
        if let Err(error) = written {
            notes.push(format!(
                "The mark that the file came from the internet could not be put back: {error}"
            ));
        }
    }
}

#[cfg(not(any(unix, windows)))]
fn apply_system(_file: &File, _path: &Path, _info: &EntryInfo, _notes: &mut Vec<String>) {}

/// Gives a restored file what it can only get once it has its final name,
/// through a handle that was opened before: see the notes on the order of
/// things at the top of this file. Returns what could not be put back.
#[cfg(windows)]
pub(crate) fn apply_after_commit(file: &File, info: &EntryInfo) -> Vec<String> {
    let mut notes = Vec::new();
    if let Some(windows) = &info.windows {
        // The read-only bit first: setting it is one of the things the
        // access rights may forbid.
        if windows.attributes & crate::windows::FILE_ATTRIBUTE_READONLY != 0 {
            let made_read_only = file.metadata().and_then(|metadata| {
                let mut permissions = metadata.permissions();
                permissions.set_readonly(true);
                file.set_permissions(permissions)
            });
            if let Err(error) = made_read_only {
                notes.push(format!("It could not be made read-only again: {error}"));
            }
        }
        match &windows.security_descriptor {
            Some(descriptor) => {
                if let Some(note) = crate::windows::restore_security_descriptor(file, descriptor) {
                    notes.push(note);
                }
            }
            None => notes.push(
                "The entry holds no access rights for the file, so it has those of its folder"
                    .to_owned(),
            ),
        }
    }
    // The timestamps once more, in case naming the file has touched one.
    // They were set before, and a failure was reported then.
    let _ = file.set_times(file_times(&info.times));
    let _ = file.sync_all();
    notes
}

/// Gives a restored file what it can only get once it has its final name:
/// nothing, on systems where the permission bits travel with the file.
#[cfg(not(windows))]
pub(crate) fn apply_after_commit(_file: &File, _info: &EntryInfo) -> Vec<String> {
    Vec::new()
}

/// The same for a restore that was cut off after the file had its name.
/// The handle it was written with is gone, so the file is opened once more
/// for this. It is done as far as it can be done: nobody is there to be
/// told what was left out.
pub(crate) fn apply_after_commit_at(path: &Path, info: &EntryInfo) {
    #[cfg(windows)]
    if let Ok(file) = crate::windows::open_for_metadata(path) {
        let _ = apply_after_commit(&file, info);
    }
    #[cfg(not(windows))]
    let _ = (path, info);
}

/// Makes a file deletable where being read-only would prevent it.
pub(crate) fn make_removable(path: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        let metadata = std::fs::symlink_metadata(path)?;
        let mut permissions = metadata.permissions();
        if permissions.readonly() {
            // On Windows this clears the read-only attribute and nothing
            // else. The lint is about Unix, where it would make the file
            // writable for everybody, and this code is not built there.
            #[allow(clippy::permissions_set_readonly_false)]
            permissions.set_readonly(false);
            std::fs::set_permissions(path, permissions)?;
        }
    }
    #[cfg(not(windows))]
    let _ = path;
    Ok(())
}

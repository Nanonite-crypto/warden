//! The few places where the engine talks to the operating system directly.

use std::fs::{File, Metadata, OpenOptions};
use std::io;
use std::path::Path;

use crate::report::SkipReason;

/// Opens a file for one front-to-back read.
///
/// The file is opened with the default sharing mode, which lets other
/// programs keep reading, writing, renaming and deleting it: a scanner must
/// never be the reason another program fails.
pub(crate) fn open_for_scan(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_SEQUENTIAL_SCAN: u32 = 0x0800_0000;
        options.custom_flags(FILE_FLAG_SEQUENTIAL_SCAN);
    }
    options.open(path)
}

/// Returns a reason not to read a file that exists, if there is one.
///
/// On Windows, cloud storage providers such as OneDrive leave placeholder
/// files on disk whose content is fetched on first read. Reading them would
/// download the user's whole cloud drive, so they are skipped and reported.
pub(crate) fn reason_not_to_read(metadata: &Metadata) -> Option<SkipReason> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_OFFLINE: u32 = 0x0000_1000;
        const FILE_ATTRIBUTE_RECALL_ON_OPEN: u32 = 0x0004_0000;
        const FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS: u32 = 0x0040_0000;
        const NOT_ON_DISK: u32 = FILE_ATTRIBUTE_OFFLINE
            | FILE_ATTRIBUTE_RECALL_ON_OPEN
            | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS;
        if metadata.file_attributes() & NOT_ON_DISK != 0 {
            return Some(SkipReason::CloudPlaceholder);
        }
    }
    #[cfg(not(windows))]
    let _ = metadata;
    None
}

/// Maps an I/O error from opening or reading a file to a skip reason.
pub(crate) fn classify_io_error(error: &io::Error) -> SkipReason {
    #[cfg(windows)]
    {
        const ERROR_SHARING_VIOLATION: i32 = 32;
        const ERROR_LOCK_VIOLATION: i32 = 33;
        const ERROR_CANT_ACCESS_FILE: i32 = 1920;
        match error.raw_os_error() {
            Some(ERROR_SHARING_VIOLATION | ERROR_LOCK_VIOLATION) => return SkipReason::InUse,
            // Reparse points that are not files, such as app execution aliases.
            Some(ERROR_CANT_ACCESS_FILE) => return SkipReason::SpecialFile,
            _ => {}
        }
    }
    match error.kind() {
        io::ErrorKind::NotFound => SkipReason::NotFound,
        io::ErrorKind::PermissionDenied => SkipReason::AccessDenied,
        _ => SkipReason::ReadError,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_kinds_map_to_reasons() {
        let not_found = io::Error::from(io::ErrorKind::NotFound);
        assert_eq!(classify_io_error(&not_found), SkipReason::NotFound);
        let denied = io::Error::from(io::ErrorKind::PermissionDenied);
        assert_eq!(classify_io_error(&denied), SkipReason::AccessDenied);
        let other = io::Error::other("disk on fire");
        assert_eq!(classify_io_error(&other), SkipReason::ReadError);
    }

    #[cfg(windows)]
    #[test]
    fn windows_sharing_violations_mean_in_use() {
        assert_eq!(
            classify_io_error(&io::Error::from_raw_os_error(32)),
            SkipReason::InUse
        );
        assert_eq!(
            classify_io_error(&io::Error::from_raw_os_error(1920)),
            SkipReason::SpecialFile
        );
    }
}

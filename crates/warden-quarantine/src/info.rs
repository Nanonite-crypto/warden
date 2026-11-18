//! What a quarantine entry records about the file it holds.
//!
//! Everything here is plain data. It is written as JSON at the end of an
//! entry file, and it is what `warden quarantine list` shows.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// The record of one quarantined file.
///
/// It holds what is needed to put the file back as it was: where it lay,
/// what it was (size and SHA-256), the key its content is stored under, and
/// the timestamps and permissions it had.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntryInfo {
    /// The entry's identifier: sixteen random hexadecimal digits. Its first
    /// few are enough to name it wherever one is asked for.
    pub id: String,
    /// When the file was quarantined, in milliseconds since the Unix epoch.
    pub quarantined_unix_ms: u64,
    /// Where the file lay, written for people. If the path is not valid
    /// Unicode, the parts that are not are replaced here, and `original_exact`
    /// holds the path as it really was.
    pub original_path: String,
    /// The path exactly, when `original_path` could not hold it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_exact: Option<ExactPath>,
    /// Size of the file in bytes.
    pub size: u64,
    /// SHA-256 of the file, in lowercase hexadecimal.
    pub sha256: String,
    /// How the content is stored.
    pub cipher: Cipher,
    /// The file's timestamps.
    pub times: Times,
    /// Owner and permission bits, for a file from a Unix system.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unix: Option<UnixMeta>,
    /// Attributes, access rights and origin mark, for a file from Windows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub windows: Option<WindowsMeta>,
    /// Why the file was quarantined, as far as that was said.
    #[serde(default, skip_serializing_if = "Reason::is_empty")]
    pub reason: Reason,
    /// The version of Warden that made the entry.
    pub warden_version: String,
}

impl EntryInfo {
    /// Where the file lay.
    ///
    /// Returns nothing if the path was not valid Unicode and the entry was
    /// made on another kind of system than this one, so that its exact form
    /// means nothing here.
    #[must_use]
    pub fn original(&self) -> Option<PathBuf> {
        match &self.original_exact {
            Some(exact) => exact.to_path(),
            None => Some(PathBuf::from(&self.original_path)),
        }
    }
}

/// A path that is not valid Unicode, in the form its system has it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExactPath {
    /// The bytes of a Unix path, in hexadecimal.
    UnixBytes(String),
    /// The 16-bit units of a Windows path.
    WindowsUnits(Vec<u16>),
}

impl ExactPath {
    /// The exact form of a path, if its text form would lose something.
    #[must_use]
    pub fn needed_for(path: &Path) -> Option<Self> {
        if path.to_str().is_some() {
            return None;
        }
        Self::of(path)
    }

    #[cfg(unix)]
    fn of(path: &Path) -> Option<Self> {
        use std::os::unix::ffi::OsStrExt;
        Some(Self::UnixBytes(warden_sigdb::hex::encode(
            path.as_os_str().as_bytes(),
        )))
    }

    #[cfg(windows)]
    fn of(path: &Path) -> Option<Self> {
        use std::os::windows::ffi::OsStrExt;
        Some(Self::WindowsUnits(path.as_os_str().encode_wide().collect()))
    }

    #[cfg(not(any(unix, windows)))]
    fn of(_path: &Path) -> Option<Self> {
        None
    }

    /// The path, on the kind of system it comes from.
    #[must_use]
    pub fn to_path(&self) -> Option<PathBuf> {
        match self {
            #[cfg(unix)]
            Self::UnixBytes(hex) => {
                use std::os::unix::ffi::OsStrExt;
                let bytes = crate::hex::decode(hex)?;
                Some(PathBuf::from(std::ffi::OsStr::from_bytes(&bytes)))
            }
            #[cfg(windows)]
            Self::WindowsUnits(units) => {
                use std::os::windows::ffi::OsStringExt;
                Some(PathBuf::from(std::ffi::OsString::from_wide(units)))
            }
            _ => None,
        }
    }
}

/// How the content of an entry is stored.
///
/// The key lies next to the content it unlocks, on purpose. The cipher is
/// not there to keep anything secret. It is there so that the bytes on disk
/// are not the file: they cannot be run, another scanner finds nothing in
/// them, and an indexer does not read them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cipher {
    /// The cipher's name. Always `chacha20`.
    pub algorithm: String,
    /// The 256-bit key, in hexadecimal. Made at random for every entry.
    pub key: String,
    /// The 96-bit nonce, in hexadecimal. Made at random for every entry.
    pub nonce: String,
}

/// The name of the one cipher entries are written with.
pub const CIPHER: &str = "chacha20";

/// A moment in time, to the nanosecond.
///
/// That is as fine as any clock here gets: Linux keeps file times to the
/// nanosecond, Windows in steps of 100 ns. A stamp therefore holds what
/// the system said without rounding it.
///
/// `secs` counts whole seconds since the Unix epoch and is negative for a
/// moment before it; `nanos` is always added on top.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Stamp {
    /// Whole seconds since the Unix epoch, rounded down.
    pub secs: i64,
    /// Nanoseconds past that second, below one thousand million.
    pub nanos: u32,
}

impl Stamp {
    /// The stamp of a system time. Nothing is lost on the way.
    #[must_use]
    pub fn of(time: SystemTime) -> Option<Self> {
        match time.duration_since(UNIX_EPOCH) {
            Ok(after) => Some(Self {
                secs: i64::try_from(after.as_secs()).ok()?,
                nanos: after.subsec_nanos(),
            }),
            Err(error) => {
                let before = error.duration();
                let secs = i64::try_from(before.as_secs()).ok()?;
                if before.subsec_nanos() == 0 {
                    Some(Self {
                        secs: -secs,
                        nanos: 0,
                    })
                } else {
                    // Half a second before the epoch is second -1 plus half
                    // a second.
                    Some(Self {
                        secs: -secs - 1,
                        nanos: 1_000_000_000 - before.subsec_nanos(),
                    })
                }
            }
        }
    }

    /// The system time of a stamp, if this system can express it.
    #[must_use]
    pub fn to_system_time(self) -> Option<SystemTime> {
        if self.nanos >= 1_000_000_000 {
            return None;
        }
        let nanos = Duration::from_nanos(u64::from(self.nanos));
        if self.secs >= 0 {
            UNIX_EPOCH
                .checked_add(Duration::from_secs(self.secs.unsigned_abs()))?
                .checked_add(nanos)
        } else {
            UNIX_EPOCH
                .checked_sub(Duration::from_secs(self.secs.unsigned_abs()))?
                .checked_add(nanos)
        }
    }
}

/// The timestamps of a file. One is absent where the file system or the
/// operating system does not keep it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Times {
    /// When the content was last changed.
    pub modified: Option<Stamp>,
    /// When the file was last read.
    pub accessed: Option<Stamp>,
    /// When the file was made. Windows lets a program set this; on other
    /// systems it is recorded and cannot be put back.
    pub created: Option<Stamp>,
}

/// What a Unix system keeps about who may do what with a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnixMeta {
    /// The permission bits, including set-user-id, set-group-id and sticky:
    /// the lowest twelve bits of the file's mode.
    pub mode: u32,
    /// The owner's user id.
    pub uid: u32,
    /// The owner's group id.
    pub gid: u32,
}

/// What Windows keeps about a file besides its content.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsMeta {
    /// The file's attribute bits: read-only, hidden, system and so on.
    pub attributes: u32,
    /// Owner, group and access-control list, as the self-relative security
    /// descriptor Windows hands out, in hexadecimal. Absent if it could not
    /// be read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_descriptor: Option<String>,
    /// The content of the file's `Zone.Identifier` stream, in hexadecimal:
    /// the mark that says a file came from the internet. Absent if the
    /// file had none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone_identifier: Option<String>,
}

/// Why a file was quarantined.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reason {
    /// The names of the detections that led to it, if a scan did.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub detections: Vec<String>,
    /// Anything a person said about it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl Reason {
    /// A reason that is only a note.
    #[must_use]
    pub fn note(text: impl Into<String>) -> Self {
        Self {
            detections: Vec::new(),
            note: Some(text.into()),
        }
    }

    /// Whether nothing was said.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.detections.is_empty() && self.note.is_none()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn a_stamp_keeps_a_system_time_exactly() {
        let cases = [
            UNIX_EPOCH,
            UNIX_EPOCH + Duration::new(1_795_000_000, 123_456_789),
            UNIX_EPOCH + Duration::new(0, 1),
            UNIX_EPOCH - Duration::new(1, 0),
            UNIX_EPOCH - Duration::new(0, 500_000_000),
            UNIX_EPOCH - Duration::new(86_400, 1),
        ];
        for time in cases {
            let stamp = Stamp::of(time).unwrap();
            assert!(stamp.nanos < 1_000_000_000);
            assert_eq!(stamp.to_system_time(), Some(time), "{stamp:?}");
        }
        assert_eq!(
            Stamp::of(UNIX_EPOCH - Duration::new(0, 500_000_000)),
            Some(Stamp {
                secs: -1,
                nanos: 500_000_000
            })
        );
    }

    #[test]
    fn stamps_sort_in_the_order_of_time() {
        // The smallest step that every system's clock can take: Windows
        // counts time in steps of 100 ns, and a smaller one is lost there
        // before a stamp is made of it.
        let step = Duration::new(0, 100);
        let earlier = Stamp::of(UNIX_EPOCH - step).unwrap();
        let epoch = Stamp::of(UNIX_EPOCH).unwrap();
        let later = Stamp::of(UNIX_EPOCH + step).unwrap();
        assert!(earlier < epoch && epoch < later);
        assert_eq!(
            earlier,
            Stamp {
                secs: -1,
                nanos: 999_999_900
            }
        );
        assert_eq!(
            later,
            Stamp {
                secs: 0,
                nanos: 100
            }
        );

        // Stamps as they are stored sort the same way, whatever clock
        // made them.
        let stamps = [
            Stamp {
                secs: -2,
                nanos: 999_999_999,
            },
            Stamp { secs: -1, nanos: 0 },
            Stamp {
                secs: -1,
                nanos: 999_999_999,
            },
            Stamp { secs: 0, nanos: 0 },
            Stamp { secs: 0, nanos: 1 },
            Stamp { secs: 1, nanos: 0 },
        ];
        assert!(stamps.is_sorted());
    }

    #[test]
    fn a_stamp_that_makes_no_sense_gives_no_time() {
        assert_eq!(
            Stamp {
                secs: 0,
                nanos: 1_000_000_000
            }
            .to_system_time(),
            None
        );
    }

    #[test]
    fn an_ordinary_path_needs_no_exact_form() {
        assert_eq!(
            ExactPath::needed_for(Path::new("/home/someone/a file.txt")),
            None
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_path_that_is_not_unicode_is_kept_byte_for_byte() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let path = Path::new(OsStr::from_bytes(b"/tmp/odd-\xff-name"));
        let exact = ExactPath::needed_for(path).unwrap();
        assert_eq!(
            exact,
            ExactPath::UnixBytes("2f746d702f6f64642dff2d6e616d65".to_owned())
        );
        assert_eq!(exact.to_path().as_deref(), Some(path));
        // The other system's form means nothing here.
        assert_eq!(ExactPath::WindowsUnits(vec![0x43, 0x3a]).to_path(), None);
    }
}

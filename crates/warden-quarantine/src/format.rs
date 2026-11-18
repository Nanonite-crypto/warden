//! The entry file: one quarantined file's content, and the record of it.
//!
//! ```text
//! offset  bytes  what
//!      0      8  "WRDNQRT\0"
//!      8      4  format version, little-endian: 1
//!     12   size  the file's content, under the cipher
//!    ...      n  the record: an `EntryInfo` as JSON
//!    ...     32  SHA-256 of the record
//!    ...      8  n, little-endian
//!    ...      8  "WRDNQEND"
//! ```
//!
//! The record comes last so that a file can be quarantined in one pass: its
//! size and its SHA-256 are known only when the last byte has been read,
//! and reading it twice would leave room for it to change in between. A
//! file that does not end in the closing signature was cut short, which is
//! how an entry that was being written when the machine went down is told
//! from a finished one.

use std::io::{self, Read, Seek, SeekFrom, Write};

use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use sha2::{Digest, Sha256};

use crate::hex;
use crate::info::{CIPHER, EntryInfo};

/// First eight bytes of every entry file.
pub const MAGIC: [u8; 8] = *b"WRDNQRT\0";
/// Last eight bytes of every finished entry file.
pub const END_MAGIC: [u8; 8] = *b"WRDNQEND";
/// Version of the layout this crate reads and writes.
pub const FORMAT_VERSION: u32 = 1;
/// The file name extension of an entry.
pub const EXTENSION: &str = "wq";

const PREFIX_LEN: u64 = 12;
const TRAILER_LEN: u64 = 32 + 8 + 8;
/// Upper bound for the record, which is a few hundred bytes of text plus,
/// on Windows, a security descriptor.
const MAX_RECORD_BYTES: u64 = 4 * 1024 * 1024;
const CHUNK_BYTES: usize = 256 * 1024;

/// What is wrong with an entry file.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Problem {
    /// Reading or writing failed.
    #[error("{0}")]
    Io(#[from] io::Error),
    /// The file does not start with the entry signature.
    #[error("it is not a quarantine entry")]
    NotAnEntry,
    /// The file uses a layout this crate does not know.
    #[error("it uses entry format {0}, which this version of Warden does not know")]
    UnsupportedVersion(u32),
    /// The file does not end the way a finished entry does.
    #[error("it was cut short: the end of the entry is missing")]
    CutShort,
    /// The record does not match its digest, or makes no sense.
    #[error("its record is damaged: {0}")]
    Record(&'static str),
    /// The stored content is not the size the record states.
    #[error("it holds {found} bytes of content where its record says {recorded}")]
    WrongSize {
        /// The size in the record.
        recorded: u64,
        /// The size of the stored content.
        found: u64,
    },
    /// The content does not have the SHA-256 the record states.
    #[error("its content is damaged: it does not have the SHA-256 that was recorded")]
    WrongContent,
}

fn cipher_for(key: &[u8; 32], nonce: &[u8; 12]) -> ChaCha20 {
    ChaCha20::new(&(*key).into(), &(*nonce).into())
}

/// Writes `source` to `out` as an entry and returns its record.
///
/// The record is whatever `describe` makes of the size and the SHA-256 of
/// what was read. It has to name `key` and `nonce`, or the entry cannot be
/// opened again.
pub(crate) fn write_entry(
    source: &mut impl Read,
    out: &mut impl Write,
    key: &[u8; 32],
    nonce: &[u8; 12],
    describe: impl FnOnce(u64, [u8; 32]) -> EntryInfo,
) -> io::Result<EntryInfo> {
    out.write_all(&MAGIC)?;
    out.write_all(&FORMAT_VERSION.to_le_bytes())?;

    let mut cipher = cipher_for(key, nonce);
    let mut hasher = Sha256::new();
    let mut size = 0u64;
    let mut chunk = vec![0u8; CHUNK_BYTES];
    loop {
        let read = match source.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        hasher.update(&chunk[..read]);
        cipher.apply_keystream(&mut chunk[..read]);
        out.write_all(&chunk[..read])?;
        size += read as u64;
    }

    let info = describe(size, hasher.finalize().into());
    let record = serde_json::to_vec(&info).map_err(io::Error::other)?;
    out.write_all(&record)?;
    out.write_all(&Sha256::digest(&record))?;
    out.write_all(&(record.len() as u64).to_le_bytes())?;
    out.write_all(&END_MAGIC)?;
    Ok(info)
}

/// Reads the record of an entry file, and checks everything about the file
/// that can be checked without reading its content.
pub(crate) fn read_info(file: &mut (impl Read + Seek)) -> Result<EntryInfo, Problem> {
    let length = file.seek(SeekFrom::End(0))?;
    file.seek(SeekFrom::Start(0))?;
    let mut prefix = [0u8; PREFIX_LEN as usize];
    if length < PREFIX_LEN {
        return Err(if length == 0 {
            Problem::CutShort
        } else {
            Problem::NotAnEntry
        });
    }
    file.read_exact(&mut prefix)?;
    if prefix[..8] != MAGIC {
        return Err(Problem::NotAnEntry);
    }
    let version = u32::from_le_bytes([prefix[8], prefix[9], prefix[10], prefix[11]]);
    if version != FORMAT_VERSION {
        return Err(Problem::UnsupportedVersion(version));
    }
    if length < PREFIX_LEN + TRAILER_LEN {
        return Err(Problem::CutShort);
    }

    let mut trailer = [0u8; TRAILER_LEN as usize];
    file.seek(SeekFrom::Start(length - TRAILER_LEN))?;
    file.read_exact(&mut trailer)?;
    if trailer[40..] != END_MAGIC {
        return Err(Problem::CutShort);
    }
    let mut record_len = [0u8; 8];
    record_len.copy_from_slice(&trailer[32..40]);
    let record_len = u64::from_le_bytes(record_len);
    if record_len > MAX_RECORD_BYTES || record_len > length - PREFIX_LEN - TRAILER_LEN {
        return Err(Problem::Record("its length is not possible"));
    }

    let record_start = length - TRAILER_LEN - record_len;
    file.seek(SeekFrom::Start(record_start))?;
    // The length was checked against the limit above, so it fits.
    let mut record = vec![0u8; record_len as usize];
    file.read_exact(&mut record)?;
    if Sha256::digest(&record)[..] != trailer[..32] {
        return Err(Problem::Record("it does not match its digest"));
    }
    let info: EntryInfo =
        serde_json::from_slice(&record).map_err(|_| Problem::Record("it cannot be read"))?;

    if info.cipher.algorithm != CIPHER {
        return Err(Problem::Record("it names a cipher that is not known"));
    }
    if key_of(&info).is_none() {
        return Err(Problem::Record("its key is not a key"));
    }
    if hex::decode_exact::<32>(&info.sha256).is_none() {
        return Err(Problem::Record("its SHA-256 is not a SHA-256"));
    }
    let found = record_start - PREFIX_LEN;
    if found != info.size {
        return Err(Problem::WrongSize {
            recorded: info.size,
            found,
        });
    }
    Ok(info)
}

fn key_of(info: &EntryInfo) -> Option<([u8; 32], [u8; 12])> {
    Some((
        hex::decode_exact(&info.cipher.key)?,
        hex::decode_exact(&info.cipher.nonce)?,
    ))
}

/// Writes the content of an entry to `out` as it was before it was
/// quarantined, and checks it against the record on the way.
///
/// `info` has to be the record [`read_info`] returned for this file. If the
/// content turns out not to be what the record says, the error comes after
/// the bytes: the caller has to throw away what was written.
pub(crate) fn write_content(
    file: &mut (impl Read + Seek),
    info: &EntryInfo,
    out: &mut impl Write,
) -> Result<(), Problem> {
    let (key, nonce) = key_of(info).ok_or(Problem::Record("its key is not a key"))?;
    let expected: [u8; 32] =
        hex::decode_exact(&info.sha256).ok_or(Problem::Record("its SHA-256 is not a SHA-256"))?;

    file.seek(SeekFrom::Start(PREFIX_LEN))?;
    let mut cipher = cipher_for(&key, &nonce);
    let mut hasher = Sha256::new();
    let mut left = info.size;
    let mut chunk = vec![0u8; CHUNK_BYTES];
    while left > 0 {
        let want = usize::try_from(left).map_or(CHUNK_BYTES, |left| left.min(CHUNK_BYTES));
        file.read_exact(&mut chunk[..want])?;
        cipher.apply_keystream(&mut chunk[..want]);
        hasher.update(&chunk[..want]);
        out.write_all(&chunk[..want])?;
        left -= want as u64;
    }
    let found: [u8; 32] = hasher.finalize().into();
    if found != expected {
        return Err(Problem::WrongContent);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::io::Cursor;

    use super::*;
    use crate::info::{Cipher, Reason, Times};

    const KEY: [u8; 32] = [7; 32];
    const NONCE: [u8; 12] = [9; 12];

    fn info(size: u64, sha256: [u8; 32]) -> EntryInfo {
        EntryInfo {
            id: "0000000000000000".to_owned(),
            quarantined_unix_ms: 1,
            original_path: "/somewhere/file.bin".to_owned(),
            original_exact: None,
            size,
            sha256: hex::encode(&sha256),
            cipher: Cipher {
                algorithm: CIPHER.to_owned(),
                key: hex::encode(&KEY),
                nonce: hex::encode(&NONCE),
            },
            times: Times::default(),
            unix: None,
            windows: None,
            reason: Reason::default(),
            warden_version: "test".to_owned(),
        }
    }

    fn entry_of(content: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        write_entry(&mut Cursor::new(content), &mut out, &KEY, &NONCE, info).unwrap();
        out
    }

    fn content_of(entry: &[u8]) -> Result<Vec<u8>, Problem> {
        let mut file = Cursor::new(entry);
        let info = read_info(&mut file)?;
        let mut out = Vec::new();
        write_content(&mut file, &info, &mut out)?;
        Ok(out)
    }

    #[test]
    fn content_comes_back_as_it_went_in() {
        for content in [
            &b""[..],
            b"a",
            b"harmless bytes that stand in for a file",
            &vec![0x5a; CHUNK_BYTES],
            &vec![0xa5; CHUNK_BYTES + 1],
            &vec![1; 3 * CHUNK_BYTES - 1],
        ] {
            let entry = entry_of(content);
            assert_eq!(
                entry.len() as u64,
                PREFIX_LEN + content.len() as u64 + TRAILER_LEN + record_len(&entry)
            );
            assert_eq!(content_of(&entry).unwrap(), content);
        }
    }

    fn record_len(entry: &[u8]) -> u64 {
        let at = entry.len() - 16;
        u64::from_le_bytes(entry[at..at + 8].try_into().unwrap())
    }

    #[test]
    fn the_stored_bytes_are_not_the_file() {
        // The whole point: what lies on disk must not hold the content.
        let content =
            b"WARDEN-QUARANTINE-MARKER, a stand-in for what a scanner looks for. ".repeat(50);
        let entry = entry_of(&content);
        let needle = &content[..24];
        assert!(!entry.windows(needle.len()).any(|window| window == needle));
        // Nor does it look like it: long runs of one byte do not survive.
        let zeros = entry_of(&vec![0u8; 4096]);
        let stored = &zeros[PREFIX_LEN as usize..PREFIX_LEN as usize + 4096];
        assert!(stored.iter().filter(|byte| **byte == 0).count() < 64);
    }

    #[test]
    fn the_record_says_what_was_read() {
        let content = b"some content";
        let entry = entry_of(content);
        let info = read_info(&mut Cursor::new(&entry)).unwrap();
        assert_eq!(info.size, content.len() as u64);
        assert_eq!(info.sha256, hex::encode(&Sha256::digest(content)));
        assert_eq!(info.original_path, "/somewhere/file.bin");
    }

    #[test]
    fn an_entry_that_was_cut_short_is_recognised() {
        let entry = entry_of(&vec![3u8; 5000]);
        for keep in [0, 5, 12, 13, 2000, entry.len() - 1] {
            let problem = read_info(&mut Cursor::new(&entry[..keep])).unwrap_err();
            assert!(
                matches!(problem, Problem::CutShort | Problem::NotAnEntry),
                "{keep} bytes: {problem}"
            );
        }
        assert!(matches!(
            read_info(&mut Cursor::new(&entry[..5])).unwrap_err(),
            Problem::NotAnEntry
        ));
        assert!(matches!(
            read_info(&mut Cursor::new(&entry[..2000])).unwrap_err(),
            Problem::CutShort
        ));
    }

    #[test]
    fn other_files_and_other_versions_are_refused() {
        let mut entry = entry_of(b"content");
        assert!(matches!(
            read_info(&mut Cursor::new(
                b"MZ, an ordinary file that is long enough to hold a trailer and a prefix as well"
            ))
            .unwrap_err(),
            Problem::NotAnEntry
        ));
        entry[8] = 2;
        assert!(matches!(
            read_info(&mut Cursor::new(&entry)).unwrap_err(),
            Problem::UnsupportedVersion(2)
        ));
    }

    #[test]
    fn a_changed_record_is_noticed() {
        let content = vec![6u8; 300];
        let entry = entry_of(&content);
        let record_start = PREFIX_LEN as usize + content.len();
        let record_end = entry.len() - TRAILER_LEN as usize;

        // Any byte of the record: here the path it would be restored to.
        let position = entry[record_start..record_end]
            .windows(9)
            .position(|window| window == b"somewhere")
            .unwrap();
        let mut changed = entry.clone();
        changed[record_start + position] = b'S';
        assert!(matches!(
            read_info(&mut Cursor::new(&changed)).unwrap_err(),
            Problem::Record("it does not match its digest")
        ));

        // The digest itself, and the length next to it.
        let mut changed = entry.clone();
        changed[record_end] ^= 1;
        assert!(matches!(
            read_info(&mut Cursor::new(&changed)).unwrap_err(),
            Problem::Record(_)
        ));
        let mut changed = entry.clone();
        changed[record_end + 32 + 7] = 0x7f;
        assert!(matches!(
            read_info(&mut Cursor::new(&changed)).unwrap_err(),
            Problem::Record("its length is not possible")
        ));
    }

    #[test]
    fn changed_content_is_noticed_when_it_is_read_back() {
        let content = vec![6u8; 300];
        let mut entry = entry_of(&content);
        entry[PREFIX_LEN as usize + 150] ^= 0x10;
        // The record is fine, so listing works.
        assert!(read_info(&mut Cursor::new(&entry)).is_ok());
        assert!(matches!(
            content_of(&entry).unwrap_err(),
            Problem::WrongContent
        ));
    }

    #[test]
    fn content_of_another_length_than_recorded_is_noticed() {
        let content = vec![6u8; 300];
        let entry = entry_of(&content);
        // Take ten bytes out of the content and leave the rest in place.
        let mut shorter = entry[..PREFIX_LEN as usize + 100].to_vec();
        shorter.extend_from_slice(&entry[PREFIX_LEN as usize + 110..]);
        assert!(matches!(
            read_info(&mut Cursor::new(&shorter)).unwrap_err(),
            Problem::WrongSize {
                recorded: 300,
                found: 290
            }
        ));
    }

    #[test]
    fn a_record_with_a_key_that_is_no_key_is_refused() {
        let mut out = Vec::new();
        write_entry(
            &mut Cursor::new(b"abc"),
            &mut out,
            &KEY,
            &NONCE,
            |size, sha256| {
                let mut info = info(size, sha256);
                info.cipher.key = "00".to_owned();
                info
            },
        )
        .unwrap();
        assert!(matches!(
            read_info(&mut Cursor::new(&out)).unwrap_err(),
            Problem::Record("its key is not a key")
        ));

        let mut out = Vec::new();
        write_entry(
            &mut Cursor::new(b"abc"),
            &mut out,
            &KEY,
            &NONCE,
            |size, sha256| {
                let mut info = info(size, sha256);
                info.cipher.algorithm = "rot13".to_owned();
                info
            },
        )
        .unwrap();
        assert!(matches!(
            read_info(&mut Cursor::new(&out)).unwrap_err(),
            Problem::Record("it names a cipher that is not known")
        ));
    }
}

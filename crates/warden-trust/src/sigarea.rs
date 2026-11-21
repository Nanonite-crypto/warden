//! The part of a Windows executable that holds its signature, and whether
//! anything else is in there.
//!
//! A signed executable carries its signature at its very end, in a table
//! that the file's header points to. The signature covers the whole file
//! except that table: it could not cover itself. Windows therefore accepts
//! a signed file as unchanged even when the table has grown, as long as the
//! signature inside it is intact. Since 2013 this is known as a way to hide
//! data in a file that still shows a valid signature, and Windows keeps the
//! stricter check optional, because programs exist that store their own
//! data there.
//!
//! For Warden a valid signature is a reason to hold a finding back, so the
//! question matters: a rule may have matched exactly those added bytes.
//! This module looks through the table and says whether it holds one
//! signature and nothing else. If it holds more, the file is treated as if
//! its signature did not count.
//!
//! What this does not see: bytes inside the signature's own structure, in
//! the parts of it that are not signed. That is a smaller door, and
//! `docs/TRUST.md` names it as a limit.

use std::io::{self, Read, Seek, SeekFrom};

use crate::der;

/// Largest signature table that is looked through. A real one is a few
/// kilobytes.
const MAX_TABLE_BYTES: u32 = 16 * 1024 * 1024;
/// How much of the file's header is read to find the table.
const HEADER_BYTES: usize = 1024;
/// The kind of table entry that holds an Authenticode signature.
const PKCS_SIGNED_DATA: u16 = 0x0002;

/// What the signature table of a file looks like.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureArea {
    /// The file is no Windows executable.
    NotExecutable,
    /// An executable whose header points to no signature table. Every
    /// byte of such a file goes into the hash that a catalogue lists.
    NoTable,
    /// One signature and nothing else.
    Tidy,
    /// Something that does not belong there. The text says what.
    Untidy(String),
}

/// Looks through the signature table of a file.
///
/// # Errors
///
/// Passes on an error of reading the file.
pub fn inspect(file: &mut (impl Read + Seek)) -> io::Result<SignatureArea> {
    let length = file.seek(SeekFrom::End(0))?;
    let (offset, size) = match locate(file, length)? {
        Located::NotExecutable => return Ok(SignatureArea::NotExecutable),
        Located::NoTable => return Ok(SignatureArea::NoTable),
        Located::Table { offset, size } => (offset, size),
    };
    let untidy = |why: &str| Ok(SignatureArea::Untidy(why.to_owned()));

    let end = u64::from(offset) + u64::from(size);
    if end > length {
        return untidy("the signature table reaches beyond the end of the file");
    }
    if end < length {
        return untidy("bytes follow the signature table");
    }
    if size > MAX_TABLE_BYTES {
        return untidy("the signature table is too large to look through");
    }

    let mut table = vec![0u8; size as usize];
    file.seek(SeekFrom::Start(u64::from(offset)))?;
    file.read_exact(&mut table)?;
    Ok(match look_through(&table) {
        Ok(()) => SignatureArea::Tidy,
        Err(why) => SignatureArea::Untidy(why.to_owned()),
    })
}

/// What the header of a file says about its signature table.
enum Located {
    NotExecutable,
    NoTable,
    Table { offset: u32, size: u32 },
}

/// Finds the signature table: where it starts in the file and how long it
/// is.
fn locate(file: &mut (impl Read + Seek), length: u64) -> io::Result<Located> {
    let mut start = [0u8; 0x40];
    file.seek(SeekFrom::Start(0))?;
    if length < start.len() as u64 {
        return Ok(Located::NotExecutable);
    }
    file.read_exact(&mut start)?;
    if &start[..2] != b"MZ" {
        return Ok(Located::NotExecutable);
    }
    let header_at = u64::from(u32_at(&start, 0x3C).unwrap_or(0));
    if header_at == 0 || header_at >= length {
        return Ok(Located::NotExecutable);
    }

    let mut header = vec![0u8; HEADER_BYTES.min((length - header_at) as usize)];
    file.seek(SeekFrom::Start(header_at))?;
    file.read_exact(&mut header)?;
    if header.get(..4) != Some(b"PE\0\0") {
        return Ok(Located::NotExecutable);
    }
    // After the four bytes come 20 bytes of file header, then the optional
    // header, whose length the file header states.
    let optional_len = usize::from(u16_at(&header, 4 + 16).unwrap_or(0));
    let Some(optional) = header.get(24..24 + optional_len) else {
        return Ok(Located::NotExecutable);
    };
    // The table of tables comes after 96 bytes in a 32-bit executable and
    // after 112 in a 64-bit one; the count of its entries is the four
    // bytes before it. The signature table is entry number 4.
    let tables_at = match u16_at(optional, 0) {
        Some(0x10B) => 96,
        Some(0x20B) => 112,
        _ => return Ok(Located::NotExecutable),
    };
    let Some(count) = u32_at(optional, tables_at - 4) else {
        return Ok(Located::NotExecutable);
    };
    if count <= 4 {
        return Ok(Located::NoTable);
    }
    let entry = tables_at + 4 * 8;
    match (u32_at(optional, entry), u32_at(optional, entry + 4)) {
        (Some(0), Some(0)) => Ok(Located::NoTable),
        (Some(offset), Some(size)) => Ok(Located::Table { offset, size }),
        // The header ends before the entry: not a header Windows would
        // load, and nothing to rely on.
        _ => Ok(Located::NotExecutable),
    }
}

/// Checks that a signature table holds one signature and nothing else.
fn look_through(table: &[u8]) -> Result<(), &'static str> {
    // Each entry starts with its length, a revision and its kind.
    let entry_len =
        u32_at(table, 0).ok_or("the signature table is too short for an entry")? as usize;
    let kind = u16_at(table, 6).ok_or("the signature table is too short for an entry")?;
    if entry_len < 8 || entry_len > table.len() {
        return Err("the first entry of the signature table has a length that cannot be right");
    }
    if kind != PKCS_SIGNED_DATA {
        return Err("the signature table holds something that is not a signature");
    }

    // Entries are aligned to eight bytes, so up to seven bytes may follow
    // the first one. More than that would be a second entry, and Windows
    // checks only the first.
    let after = &table[entry_len..];
    if after.len() >= 8 {
        return Err("the signature table holds more than one entry");
    }
    if after.iter().any(|&byte| byte != 0) {
        return Err("bytes follow the signature in the signature table");
    }

    // Inside the entry, the signature is one DER value. What follows it
    // can only be the padding to eight bytes, and padding is zeros.
    let content = &table[8..entry_len];
    let signature_len = der::encoded_len(content).map_err(|_| "the signature cannot be read")?;
    let padding = &content[signature_len..];
    if padding.len() >= 8 {
        return Err("bytes follow the signature inside its entry");
    }
    if padding.iter().any(|&byte| byte != 0) {
        return Err("the padding after the signature is not empty");
    }
    Ok(())
}

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    let slice = bytes.get(at..at.checked_add(2)?)?;
    Some(u16::from_le_bytes(slice.try_into().ok()?))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    let slice = bytes.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes(slice.try_into().ok()?))
}

/// Builds the smallest file that this module takes for an executable with
/// the given signature table at its end. For tests, here and of the code
/// that uses this module; Windows would not run it.
#[doc(hidden)]
#[must_use]
pub fn executable_with_table(table: &[u8]) -> Vec<u8> {
    const HEADER_AT: usize = 0x40;
    const OPTIONAL_LEN: usize = 240;
    let body_len = HEADER_AT + 24 + OPTIONAL_LEN;
    // The table starts on a boundary of eight bytes, as Windows writes it.
    let table_at = body_len.next_multiple_of(8);

    let mut file = vec![0u8; table_at];
    file[..2].copy_from_slice(b"MZ");
    file[0x3C..0x40].copy_from_slice(&(HEADER_AT as u32).to_le_bytes());
    file[HEADER_AT..HEADER_AT + 4].copy_from_slice(b"PE\0\0");
    file[HEADER_AT + 4 + 16..HEADER_AT + 4 + 18]
        .copy_from_slice(&(OPTIONAL_LEN as u16).to_le_bytes());
    let optional = HEADER_AT + 24;
    file[optional..optional + 2].copy_from_slice(&0x20Bu16.to_le_bytes());
    file[optional + 108..optional + 112].copy_from_slice(&16u32.to_le_bytes());
    let entry = optional + 112 + 4 * 8;
    if !table.is_empty() {
        file[entry..entry + 4].copy_from_slice(&(table_at as u32).to_le_bytes());
        file[entry + 4..entry + 8].copy_from_slice(&(table.len() as u32).to_le_bytes());
    }
    file.extend_from_slice(table);
    file
}

/// Builds a signature table with one entry around the given bytes, padded
/// to eight bytes as Windows pads it. For tests.
#[doc(hidden)]
#[must_use]
pub fn table_with_signature(signature: &[u8]) -> Vec<u8> {
    let entry_len = (8 + signature.len()).next_multiple_of(8);
    let mut table = Vec::with_capacity(entry_len);
    table.extend_from_slice(&(entry_len as u32).to_le_bytes());
    table.extend_from_slice(&0x0200u16.to_le_bytes());
    table.extend_from_slice(&PKCS_SIGNED_DATA.to_le_bytes());
    table.extend_from_slice(signature);
    table.resize(entry_len, 0);
    table
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    /// A DER value of the given length in all, standing in for a signature.
    fn signature(total: usize) -> Vec<u8> {
        assert!((4..=0xFFFF).contains(&total));
        let content = total - 4;
        let mut value = vec![0x30, 0x82, (content >> 8) as u8, content as u8];
        value.resize(total, 0x5A);
        value
    }

    fn area(file: Vec<u8>) -> SignatureArea {
        inspect(&mut Cursor::new(file)).expect("reading from memory does not fail")
    }

    #[test]
    fn a_file_that_is_no_executable_is_told_apart() {
        assert_eq!(area(Vec::new()), SignatureArea::NotExecutable);
        assert_eq!(
            area(b"plain text, and long enough to hold the first header of an executable".to_vec()),
            SignatureArea::NotExecutable
        );
        let mut not_pe = executable_with_table(&[]);
        not_pe[0x40] = b'X';
        assert_eq!(area(not_pe), SignatureArea::NotExecutable);
    }

    #[test]
    fn an_executable_without_a_signature_has_no_signature_table() {
        assert_eq!(area(executable_with_table(&[])), SignatureArea::NoTable);
    }

    #[test]
    fn a_table_with_a_start_and_no_length_or_the_other_way_round_is_untidy() {
        let mut file = executable_with_table(&table_with_signature(&signature(100)));
        let entry = 0x40 + 24 + 112 + 4 * 8;
        // A length of zero with a start.
        file[entry + 4..entry + 8].copy_from_slice(&0u32.to_le_bytes());
        assert!(matches!(area(file.clone()), SignatureArea::Untidy(_)));
        // A start of zero with a length.
        file[entry..entry + 4].copy_from_slice(&0u32.to_le_bytes());
        file[entry + 4..entry + 8].copy_from_slice(&64u32.to_le_bytes());
        assert!(matches!(area(file), SignatureArea::Untidy(_)));
    }

    #[test]
    fn one_signature_and_its_padding_is_tidy() {
        for total in [100, 101, 103, 104, 107, 1000] {
            let table = table_with_signature(&signature(total));
            assert_eq!(table.len() % 8, 0);
            assert_eq!(
                area(executable_with_table(&table)),
                SignatureArea::Tidy,
                "length {total}"
            );
        }
    }

    #[test]
    fn bytes_added_to_the_entry_are_found() {
        // The classic way: the entry and the table are made longer, and
        // the added bytes come after the signature.
        let mut table = table_with_signature(&signature(100));
        let hidden = b"<script>something a rule might match</script>...";
        table.extend_from_slice(hidden);
        table.resize(table.len().next_multiple_of(8), 0);
        let entry_len = table.len() as u32;
        table[..4].copy_from_slice(&entry_len.to_le_bytes());
        assert!(matches!(
            area(executable_with_table(&table)),
            SignatureArea::Untidy(_)
        ));
    }

    #[test]
    fn padding_that_is_not_zeros_is_found() {
        let mut table = table_with_signature(&signature(101));
        let last = table.len() - 1;
        table[last] = 0x41;
        assert!(matches!(
            area(executable_with_table(&table)),
            SignatureArea::Untidy(_)
        ));
    }

    #[test]
    fn a_second_entry_is_found() {
        let mut table = table_with_signature(&signature(100));
        table.extend(table_with_signature(&signature(64)));
        assert!(matches!(
            area(executable_with_table(&table)),
            SignatureArea::Untidy(_)
        ));
    }

    #[test]
    fn bytes_after_the_table_are_found() {
        let mut file = executable_with_table(&table_with_signature(&signature(100)));
        file.extend_from_slice(b"appended");
        assert!(matches!(area(file), SignatureArea::Untidy(_)));
    }

    #[test]
    fn a_table_that_reaches_beyond_the_file_is_found() {
        let mut file = executable_with_table(&table_with_signature(&signature(100)));
        file.truncate(file.len() - 8);
        assert!(matches!(area(file), SignatureArea::Untidy(_)));
    }

    #[test]
    fn an_entry_that_is_no_signature_or_cannot_be_read_is_found() {
        let mut other_kind = table_with_signature(&signature(100));
        other_kind[6..8].copy_from_slice(&0x0001u16.to_le_bytes());
        assert!(matches!(
            area(executable_with_table(&other_kind)),
            SignatureArea::Untidy(_)
        ));

        let mut bad_length = table_with_signature(&signature(100));
        bad_length[..4].copy_from_slice(&4u32.to_le_bytes());
        assert!(matches!(
            area(executable_with_table(&bad_length)),
            SignatureArea::Untidy(_)
        ));

        // A "signature" whose own length says it is longer than its entry.
        let mut cut = signature(100);
        cut.truncate(60);
        assert!(matches!(
            area(executable_with_table(&table_with_signature(&cut))),
            SignatureArea::Untidy(_)
        ));

        assert!(matches!(
            area(executable_with_table(&[1, 2, 3, 4])),
            SignatureArea::Untidy(_)
        ));
    }

    #[test]
    fn a_32_bit_executable_is_read_too() {
        // Rebuild the header by hand in the 32-bit layout.
        let table = table_with_signature(&signature(100));
        let mut file = vec![0u8; 0x40 + 24 + 224];
        file[..2].copy_from_slice(b"MZ");
        file[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        file[0x40..0x44].copy_from_slice(b"PE\0\0");
        file[0x40 + 20..0x40 + 22].copy_from_slice(&224u16.to_le_bytes());
        let optional = 0x40 + 24;
        file[optional..optional + 2].copy_from_slice(&0x10Bu16.to_le_bytes());
        file[optional + 92..optional + 96].copy_from_slice(&16u32.to_le_bytes());
        let entry = optional + 96 + 4 * 8;
        let table_at = file.len() as u32;
        file[entry..entry + 4].copy_from_slice(&table_at.to_le_bytes());
        file[entry + 4..entry + 8].copy_from_slice(&(table.len() as u32).to_le_bytes());
        file.extend_from_slice(&table);
        assert_eq!(area(file), SignatureArea::Tidy);
    }
}

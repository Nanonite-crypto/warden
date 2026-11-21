//! What the quarantine needs from Windows that the Rust standard library
//! does not offer: reading the security descriptor of a file, and writing
//! it back.
//!
//! Both are done on a file that is already open, through its handle, and
//! never through its name. A name can be given to another file between two
//! looks at it; a handle stays with the file it was opened for. A handle
//! also keeps the rights it was opened with, which is what makes it
//! possible to put back access rights that deny the very program that
//! restores the file: see [`create_for_restore`].
//!
//! This is the only module of the crate with `unsafe` code. Each block is
//! one call of a Windows function, with what makes it sound written next to
//! it. Bytes that come out of an entry's record are checked by
//! [`crate::sd`] before they get here.

#![allow(unsafe_code)]

use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};

use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, GetKernelObjectSecurity,
    OWNER_SECURITY_INFORMATION, SetKernelObjectSecurity,
};

/// The file is read-only.
pub(crate) const FILE_ATTRIBUTE_READONLY: u32 = 0x0000_0001;
const FILE_ATTRIBUTE_HIDDEN: u32 = 0x0000_0002;
const FILE_ATTRIBUTE_SYSTEM: u32 = 0x0000_0004;
const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x0000_0020;
const FILE_ATTRIBUTE_NOT_CONTENT_INDEXED: u32 = 0x0000_2000;
/// The attribute bits a file can simply be created with.
pub(crate) const RESTORABLE_ATTRIBUTES: u32 = FILE_ATTRIBUTE_HIDDEN
    | FILE_ATTRIBUTE_SYSTEM
    | FILE_ATTRIBUTE_ARCHIVE
    | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED;

// Rights a handle can carry, by the numbers Windows gives them.
/// Reading attribute bits and timestamps.
const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
/// Changing attribute bits and timestamps.
const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;
/// Reading the security descriptor.
const READ_CONTROL: u32 = 0x0002_0000;
/// Changing the access-control list.
const WRITE_DAC: u32 = 0x0004_0000;
/// Changing the owner and the group.
const WRITE_OWNER: u32 = 0x0008_0000;
/// Writing: content, attribute bits and timestamps.
const GENERIC_WRITE: u32 = 0x4000_0000;

/// The error code for "the buffer is too small".
const ERROR_INSUFFICIENT_BUFFER: i32 = 122;

/// The name of the stream that marks a file as coming from the internet.
pub(crate) fn zone_stream(path: &Path) -> PathBuf {
    let mut name = OsString::from(path.as_os_str());
    name.push(":Zone.Identifier");
    PathBuf::from(name)
}

/// Opens a file with as many of the rights over its security descriptor as
/// Windows hands out: first asking for the right to change the owner and
/// the access-control list, then for the list alone, then for neither.
/// `open` gets the rights to ask for on top of its own.
fn open_with_most(open: impl Fn(u32) -> io::Result<File>) -> io::Result<File> {
    let refused = |result: &io::Result<File>| matches!(result, Err(error) if error.kind() == io::ErrorKind::PermissionDenied);
    let mut opened = open(WRITE_DAC | WRITE_OWNER);
    if refused(&opened) {
        opened = open(WRITE_DAC);
    }
    if refused(&opened) {
        opened = open(0);
    }
    opened
}

/// Creates the file a restore writes to. It must not exist yet.
///
/// The handle is asked to carry, besides the right to write, the rights to
/// change the file's access-control list and its owner. Those are used at
/// the very end, when the file has its content and its name: the access
/// rights of the original may deny the user who restores it what the steps
/// before needed, and a handle keeps what it was opened with. Where
/// Windows does not hand out one of the rights, the file is created
/// without it, and putting back that part fails later and is reported
/// then.
pub(crate) fn create_for_restore(path: &Path, attributes: u32) -> io::Result<File> {
    open_with_most(|rights| {
        let mut options = File::options();
        options
            .write(true)
            .create_new(true)
            .access_mode(GENERIC_WRITE | FILE_READ_ATTRIBUTES | READ_CONTROL | rights);
        if attributes != 0 {
            options.attributes(attributes);
        }
        options.open(path)
    })
}

/// Opens a file that is there already, for giving it attribute bits,
/// access rights and timestamps and for nothing else. That is what is left
/// to do when a restore was cut off after the file had its name.
pub(crate) fn open_for_metadata(path: &Path) -> io::Result<File> {
    open_with_most(|rights| {
        File::options()
            .access_mode(FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | READ_CONTROL | rights)
            .open(path)
    })
}

/// Reads the owner, the group and the access-control list of an open file,
/// as one self-relative security descriptor.
pub(crate) fn read_security_descriptor(file: &File) -> io::Result<Vec<u8>> {
    let handle = file.as_raw_handle();
    let wanted =
        OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;

    let mut needed = 0u32;
    // SAFETY: `handle` belongs to `file`, which is borrowed for the whole
    // function and so stays open. The buffer is null and its length is
    // given as zero, so nothing is written to it; the function only stores
    // the size it would need in `needed`, which is a valid place for a
    // `u32`.
    let fitted = unsafe {
        GetKernelObjectSecurity(handle, wanted, std::ptr::null_mut(), 0, &raw mut needed)
    };
    if fitted == 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER) {
            return Err(error);
        }
    }
    if needed == 0 {
        return Err(io::Error::other(
            "Windows gave no size for the security descriptor",
        ));
    }

    // A descriptor is made of 32-bit fields, so the buffer is one of 32-bit
    // words: that gives it the alignment the fields need.
    let mut words = vec![0u32; (needed as usize).div_ceil(4)];
    let capacity = u32::try_from(words.len() * 4)
        .map_err(|_| io::Error::other("the security descriptor is implausibly large"))?;
    let mut written = 0u32;
    // SAFETY: `handle` is as above. `words` is a live buffer of `capacity`
    // bytes, and the function is told exactly that length, so it cannot
    // write past it. `written` is a valid place for a `u32`.
    let read = unsafe {
        GetKernelObjectSecurity(
            handle,
            wanted,
            words.as_mut_ptr().cast(),
            capacity,
            &raw mut written,
        )
    };
    if read == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut bytes: Vec<u8> = words.iter().flat_map(|word| word.to_ne_bytes()).collect();
    bytes.truncate((written as usize).min(bytes.len()));
    // Windows wrote it, and what goes into a record is checked all the same.
    crate::sd::check(&bytes).map_err(io::Error::other)?;
    Ok(bytes)
}

/// Writes the parts of `descriptor` that `parts` names onto an open file.
fn write_security_descriptor(file: &File, parts: u32, descriptor: &[u32]) -> io::Result<()> {
    // SAFETY: the handle belongs to `file`, which is borrowed through the
    // call and so stays open. `descriptor` is a live buffer of 32-bit
    // words that holds a security descriptor in self-relative form with
    // every offset and length inside the buffer: the caller got it from
    // `sd::for_writing`. The function reads the descriptor and does not
    // write to it, so handing over a pointer made from a shared reference
    // is sound.
    let written = unsafe {
        SetKernelObjectSecurity(
            file.as_raw_handle(),
            parts,
            descriptor.as_ptr().cast_mut().cast(),
        )
    };
    if written == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Gives an open file the security descriptor that an entry's record
/// holds, in hexadecimal. Returns a sentence if something could not be put
/// back.
pub(crate) fn restore_security_descriptor(file: &File, hex: &str) -> Option<String> {
    let Some(read) = crate::hex::decode(hex) else {
        return Some("The entry's access rights are not in a readable form, so the file has those of its folder".to_owned());
    };
    let (shape, bytes) = match crate::sd::for_writing(&read) {
        Ok(prepared) => prepared,
        Err(problem) => {
            return Some(format!(
                "The entry's access rights were not used, because the security descriptor is damaged: {problem}. The file has those of its folder"
            ));
        }
    };
    // The same bytes in a buffer of 32-bit words, for the alignment.
    let words: Vec<u32> = bytes
        .chunks(4)
        .map(|chunk| {
            let mut word = [0u8; 4];
            word[..chunk.len()].copy_from_slice(chunk);
            u32::from_ne_bytes(word)
        })
        .collect();

    // Whether the list takes entries from the folder above, and whether it
    // was put together from them, are flags of the descriptor itself. They
    // go along in `words`, as `sd::for_writing` has prepared them.
    let list = if shape.dacl {
        DACL_SECURITY_INFORMATION
    } else {
        0
    };
    let mut owner = 0;
    if shape.owner {
        owner |= OWNER_SECURITY_INFORMATION;
    }
    if shape.group {
        owner |= GROUP_SECURITY_INFORMATION;
    }

    if list | owner == 0 {
        return Some(
            "The entry's security descriptor names no owner and no access-control list, so the file has those of its folder"
                .to_owned(),
        );
    }
    // Everything at once. Making somebody else the owner takes a privilege
    // an ordinary user does not have, so if that fails the list is set
    // alone: it is the part that decides who may do what.
    match write_security_descriptor(file, list | owner, &words) {
        Ok(()) => None,
        Err(first) if list != 0 && owner != 0 => {
            match write_security_descriptor(file, list, &words) {
                Ok(()) => Some(format!(
                    "Its access-control list was put back, its owner was not: {first}"
                )),
                Err(error) => Some(format!("Its access rights could not be set: {error}")),
            }
        }
        Err(error) => Some(format!("Its access rights could not be set: {error}")),
    }
}

//! Reads the facts out of a Windows executable.
//!
//! The reader is written for files that lie. Every offset, count and length
//! in the file is checked before it is used, every loop has a fixed upper
//! bound, and no table is followed for longer than its limit. A file that
//! breaks the format's rules is still read as far as it goes, and what was
//! wrong with it is noted as an [`Anomaly`]: for the heuristics, a broken
//! rule is a finding and not a failure.
//!
//! Where the format leaves room, the reader does what the `pefile` Python
//! library does. The facts of the EMBER2024 dataset were extracted with
//! `pefile`, and the indicators were measured on that dataset, so a file on
//! disk has to be described the way the dataset describes it.

use crate::bytes::Bytes;
use crate::entropy;
use crate::facts::{Anomaly, Directory, Format, ImportedLibrary, Overlay, PeFacts, Section};

/// Why a file is not read as a Windows executable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NotPe {
    /// The first two bytes are not `MZ`.
    #[error("the file does not start with the letters MZ")]
    NoDosHeader,
    /// The file ends before the headers do.
    #[error("the file ends before its headers do")]
    HeaderCutShort,
    /// The DOS header does not lead to a PE header.
    #[error("there is no PE header where the DOS header points")]
    NoPeHeader,
    /// The optional header is neither PE32 nor PE32+.
    #[error("the header is neither PE32 nor PE32+")]
    UnknownFormat,
}

/// Windows refuses an image with more sections than this.
pub const MAX_SECTIONS: usize = 96;
/// Most libraries that are read from an import table.
pub const MAX_LIBRARIES: usize = 512;
/// Most functions that are read for one library.
pub const MAX_FUNCTIONS_PER_LIBRARY: usize = 16_384;
/// Most functions that are read from one file.
pub const MAX_FUNCTIONS: usize = 65_536;
/// Longest library name that is accepted, in bytes.
pub const MAX_LIBRARY_NAME: usize = 256;
/// Longest function name that is accepted, in bytes.
pub const MAX_FUNCTION_NAME: usize = 512;
/// Most entries of an export table that are counted.
pub const MAX_EXPORTS: usize = 65_536;

const DOS_HEADER_LEN: usize = 64;
const PE_SIGNATURE: u32 = 0x0000_4550;
const COFF_HEADER_LEN: usize = 20;
const SECTION_HEADER_LEN: usize = 40;
const IMPORT_DESCRIPTOR_LEN: usize = 20;
const IMAGE_FILE_DLL: u16 = 0x2000;
/// The loader reads section data from offsets that are multiples of this.
const SECTOR: u32 = 0x200;

/// True if `data` starts like a Windows executable: an `MZ` header that
/// leads to a `PE` header. Cheap enough to ask of every file.
#[must_use]
pub fn looks_like_pe(data: &[u8]) -> bool {
    pe_header_offset(Bytes(data)).is_ok()
}

fn pe_header_offset(bytes: Bytes<'_>) -> Result<usize, NotPe> {
    if bytes.slice(0, 2) != Some(b"MZ") {
        return Err(NotPe::NoDosHeader);
    }
    if bytes.len() < DOS_HEADER_LEN {
        return Err(NotPe::HeaderCutShort);
    }
    let offset = bytes.u32(0x3c).ok_or(NotPe::HeaderCutShort)? as usize;
    match bytes.u32(offset) {
        Some(PE_SIGNATURE) => Ok(offset),
        Some(_) => Err(NotPe::NoPeHeader),
        // The DOS header points past the end. Such a file is a DOS program
        // or something else that starts with MZ.
        None => Err(NotPe::NoPeHeader),
    }
}

/// A section's place in the file and in memory.
#[derive(Debug, Clone, Copy)]
struct Placement {
    virtual_address: u32,
    virtual_size: u32,
    /// Where the section's bytes start in the file, as the loader sees it.
    raw_offset: u32,
    raw_size: u32,
    /// The section claims more bytes than the file holds.
    beyond_file: bool,
}

impl Placement {
    /// Number of bytes of memory that belong to the section.
    fn span(&self) -> u32 {
        if self.beyond_file {
            self.virtual_size
        } else {
            self.virtual_size.max(self.raw_size)
        }
    }

    fn contains(&self, address: u32) -> bool {
        address >= self.virtual_address && address - self.virtual_address < self.span()
    }
}

/// What is needed to turn an address in memory into an offset in the file.
struct Layout<'a> {
    bytes: Bytes<'a>,
    placements: Vec<Placement>,
    size_of_headers: u32,
}

impl Layout<'_> {
    /// The file offset of the byte that is loaded at `address`, if that
    /// byte comes from the file.
    fn offset_of(&self, address: u32) -> Option<usize> {
        for placement in &self.placements {
            if placement.contains(address) {
                let into = address - placement.virtual_address;
                if into >= placement.raw_size {
                    // The zero-filled tail of a section: no bytes in the file.
                    return None;
                }
                let offset = (placement.raw_offset as usize).checked_add(into as usize)?;
                return (offset < self.bytes.len()).then_some(offset);
            }
        }
        // Outside every section, an address below the size of the headers
        // is in the headers, which are loaded as they are. An image without
        // sections is loaded as it is in full.
        let limit = if self.placements.is_empty() {
            self.bytes.len()
        } else {
            (self.size_of_headers as usize).min(self.bytes.len())
        };
        ((address as usize) < limit).then_some(address as usize)
    }
}

/// Reads the facts out of a Windows executable.
///
/// # Errors
///
/// Fails if `data` is not a Windows executable at all, see [`NotPe`]. A
/// file that is one, however damaged, gives facts, with the damage listed in
/// [`PeFacts::anomalies`].
pub fn read(data: &[u8]) -> Result<PeFacts, NotPe> {
    let bytes = Bytes(data);
    let pe_offset = pe_header_offset(bytes)?;
    let cut_short = NotPe::HeaderCutShort;

    // The COFF file header.
    let coff = pe_offset + 4;
    let machine = bytes.u16(coff).ok_or(cut_short)?;
    let announced_sections = bytes.u16(coff + 2).ok_or(cut_short)?;
    let timestamp = bytes.u32(coff + 4).ok_or(cut_short)?;
    let optional_len = bytes.u16(coff + 16).ok_or(cut_short)?;
    let characteristics = bytes.u16(coff + 18).ok_or(cut_short)?;

    // The optional header. The two formats differ in the width of four
    // fields, which moves everything after them.
    let optional = coff + COFF_HEADER_LEN;
    let (format, directory_count_at, directories_at) = match bytes.u16(optional).ok_or(cut_short)? {
        0x10b => (Format::Pe32, 92, 96),
        0x20b => (Format::Pe32Plus, 108, 112),
        _ => return Err(NotPe::UnknownFormat),
    };
    let entry_point = bytes.u32(optional + 16).ok_or(cut_short)?;
    let file_alignment = bytes.u32(optional + 36).ok_or(cut_short)?;
    let size_of_headers = bytes.u32(optional + 60).ok_or(cut_short)?;
    let checksum = bytes.u32(optional + 64).ok_or(cut_short)?;
    let subsystem = bytes.u16(optional + 68).ok_or(cut_short)?;
    let image_flags = bytes.u16(optional + 70).ok_or(cut_short)?;
    let directory_count = bytes.u32(optional + directory_count_at).ok_or(cut_short)?;

    let mut anomalies = Vec::new();

    // The data directories: sixteen at most, each an address and a size.
    let mut directories = [(0u32, 0u32); 16];
    let mut directory_cut_short = false;
    for (index, slot) in directories
        .iter_mut()
        .enumerate()
        .take(directory_count.min(16) as usize)
    {
        let at = optional + directories_at + index * 8;
        match (bytes.u32(at), bytes.u32(at + 4)) {
            (Some(address), Some(size)) => *slot = (address, size),
            _ => {
                directory_cut_short = true;
                break;
            }
        }
    }
    if directory_cut_short {
        anomalies.push(Anomaly::HeaderCutShort);
    }
    let directory = |which: Directory| {
        let (address, size) = directories[which as usize];
        (address != 0 && size != 0).then_some((address, size))
    };
    let mut directory_bits = 0u16;
    for which in Directory::ALL {
        if directory(which).is_some() {
            directory_bits |= which.bit();
        }
    }

    // The section table follows the optional header, wherever that ends.
    let section_table = optional + usize::from(optional_len);
    if usize::from(announced_sections) > MAX_SECTIONS {
        anomalies.push(Anomaly::TooManySections {
            announced: u32::from(announced_sections),
        });
    }
    let mut sections = Vec::new();
    let mut placements = Vec::new();
    // Sections that do not overlap cannot hold more bytes than the file.
    // Past that, entropy is no longer worked out: a file that maps the same
    // megabytes into a hundred sections is not allowed to cost a hundred
    // passes over them.
    let mut entropy_budget = data.len();
    for index in 0..usize::from(announced_sections).min(MAX_SECTIONS) {
        let at = section_table + index * SECTION_HEADER_LEN;
        let Some(header) = bytes.slice(at, SECTION_HEADER_LEN) else {
            anomalies.push(Anomaly::SectionTableCutShort);
            break;
        };
        let header = Bytes(header);
        let field = |offset| header.u32(offset).unwrap_or(0);
        let virtual_size = field(8);
        let virtual_address = field(12);
        let raw_size = field(16);
        let raw_pointer = field(20);
        let characteristics = field(36);

        let raw_offset = if file_alignment >= SECTOR {
            raw_pointer & !(SECTOR - 1)
        } else {
            raw_pointer
        };
        let name = section_name(&header.0[..8]);
        let beyond_file = raw_size > 0
            && (raw_offset as usize)
                .checked_add(raw_size as usize)
                .is_none_or(|end| end > data.len());
        if beyond_file {
            anomalies.push(Anomaly::SectionDataBeyondFile {
                section: name.clone(),
            });
        }
        let content = bytes.slice_clipped(raw_offset as usize, raw_size as usize);
        let entropy = if content.len() <= entropy_budget {
            entropy_budget -= content.len();
            entropy::of(content)
        } else {
            0.0
        };
        placements.push(Placement {
            virtual_address,
            virtual_size,
            raw_offset,
            raw_size,
            beyond_file,
        });
        sections.push(Section {
            name,
            raw_size,
            virtual_size,
            characteristics,
            entropy,
        });
    }

    let entry_section = if entry_point == 0 {
        None
    } else {
        let found = placements
            .iter()
            .position(|placement| placement.contains(entry_point));
        if found.is_none() {
            anomalies.push(Anomaly::EntryPointOutsideSections);
        }
        found
    };

    // Everything after the last byte that belongs to a section.
    let mut image_end = (optional + usize::from(optional_len)).min(data.len());
    for placement in &placements {
        let end = (placement.raw_offset as usize).saturating_add(placement.raw_size as usize);
        if placement.raw_size > 0 && end <= data.len() {
            image_end = image_end.max(end);
        }
    }
    let overlay = if image_end < data.len() {
        Overlay {
            size: (data.len() - image_end) as u64,
            entropy: entropy::of(&data[image_end..]),
        }
    } else {
        Overlay::default()
    };

    let layout = Layout {
        bytes,
        placements,
        size_of_headers,
    };
    let imports = match directory(Directory::Import) {
        Some((address, _)) => read_imports(&layout, address, format, &mut anomalies),
        None => Vec::new(),
    };
    let exports = match directory(Directory::Export) {
        Some((address, _)) => count_exports(&layout, address),
        None => 0,
    };

    Ok(PeFacts {
        file_size: data.len() as u64,
        file_entropy: entropy::of(data),
        format,
        machine,
        is_dll: characteristics & IMAGE_FILE_DLL != 0,
        pe_header_offset: pe_offset as u32,
        timestamp,
        checksum,
        subsystem,
        image_flags,
        entry_point,
        entry_section,
        sections,
        imports,
        exports,
        directories: directory_bits,
        signature_size: directory(Directory::Signature).map_or(0, |(_, size)| size),
        overlay,
        has_rich_header: has_rich_header(bytes, optional),
        anomalies,
    })
}

/// The name in a section header: eight bytes, padded with zeroes.
fn section_name(raw: &[u8]) -> String {
    let start = raw.iter().position(|byte| *byte != 0).unwrap_or(raw.len());
    let end = raw
        .iter()
        .rposition(|byte| *byte != 0)
        .map_or(start, |last| last + 1);
    warden_engine::text::printable(&String::from_utf8_lossy(&raw[start..end]), 8)
}

/// Follows the import table: one descriptor per library, each pointing to
/// the library's name and to a list of the functions taken from it.
fn read_imports(
    layout: &Layout<'_>,
    table_address: u32,
    format: Format,
    anomalies: &mut Vec<Anomaly>,
) -> Vec<ImportedLibrary> {
    let bytes = layout.bytes;
    let Some(table) = layout.offset_of(table_address) else {
        anomalies.push(Anomaly::ImportTableUnreadable);
        return Vec::new();
    };
    let (entry_len, by_number_flag) = match format {
        Format::Pe32 => (4usize, 1u64 << 31),
        Format::Pe32Plus => (8usize, 1u64 << 63),
    };

    let mut libraries = Vec::new();
    let mut total_functions = 0usize;
    let mut unreadable_names = 0u32;
    let mut cut_short = false;
    let mut unreadable = false;
    for index in 0.. {
        if index == MAX_LIBRARIES {
            cut_short = true;
            break;
        }
        let Some(descriptor) =
            bytes.slice(table + index * IMPORT_DESCRIPTOR_LEN, IMPORT_DESCRIPTOR_LEN)
        else {
            // The table ran into the end of the file without its closing
            // entry.
            unreadable = true;
            break;
        };
        let descriptor = Bytes(descriptor);
        let field = |offset| descriptor.u32(offset).unwrap_or(0);
        let lookup_table = field(0);
        let name_address = field(12);
        let address_table = field(16);
        if name_address == 0 || descriptor.0.iter().all(|byte| *byte == 0) {
            break;
        }

        let Some(name) = layout
            .offset_of(name_address)
            .and_then(|offset| bytes.name(offset, MAX_LIBRARY_NAME))
        else {
            unreadable_names += 1;
            continue;
        };

        // The lookup table is the list as the linker wrote it. Old linkers
        // wrote none, and then the address table holds the same list until
        // the loader overwrites it.
        let list_address = if lookup_table != 0 {
            lookup_table
        } else {
            address_table
        };
        let mut functions = Vec::new();
        if let Some(list) = layout.offset_of(list_address) {
            for entry_index in 0.. {
                if entry_index == MAX_FUNCTIONS_PER_LIBRARY || total_functions == MAX_FUNCTIONS {
                    cut_short = true;
                    break;
                }
                let at = list + entry_index * entry_len;
                let entry = match format {
                    Format::Pe32 => bytes.u32(at).map(u64::from),
                    Format::Pe32Plus => bytes.u64(at),
                };
                let Some(entry) = entry else {
                    unreadable = true;
                    break;
                };
                if entry == 0 {
                    break;
                }
                if entry & by_number_flag != 0 {
                    functions.push(format!("#{}", entry & 0xffff));
                    total_functions += 1;
                    continue;
                }
                // Two bytes of hint, then the name.
                let name = u32::try_from(entry)
                    .ok()
                    .and_then(|address| layout.offset_of(address))
                    .and_then(|offset| bytes.name(offset.checked_add(2)?, MAX_FUNCTION_NAME));
                match name {
                    Some(name) => {
                        functions.push(name.to_owned());
                        total_functions += 1;
                    }
                    None => unreadable_names += 1,
                }
            }
        } else {
            unreadable = true;
        }
        libraries.push(ImportedLibrary {
            name: name.to_owned(),
            functions,
        });
        if total_functions == MAX_FUNCTIONS {
            cut_short = true;
            break;
        }
    }

    if unreadable {
        anomalies.push(Anomaly::ImportTableUnreadable);
    }
    if unreadable_names > 0 {
        anomalies.push(Anomaly::ImportNamesUnreadable {
            count: unreadable_names,
        });
    }
    if cut_short {
        anomalies.push(Anomaly::ImportsCutShort);
    }
    libraries
}

/// Counts the functions an export table offers: the entries of its address
/// list that are not empty.
fn count_exports(layout: &Layout<'_>, table_address: u32) -> u32 {
    let bytes = layout.bytes;
    let Some(table) = layout.offset_of(table_address) else {
        return 0;
    };
    let (Some(announced), Some(list_address)) = (bytes.u32(table + 20), bytes.u32(table + 28))
    else {
        return 0;
    };
    let Some(list) = layout.offset_of(list_address) else {
        return 0;
    };
    let mut count = 0;
    for index in 0..(announced as usize).min(MAX_EXPORTS) {
        match bytes.u32(list + index * 4) {
            Some(0) => {}
            Some(_) => count += 1,
            None => break,
        }
    }
    count
}

/// Looks for the Rich header that Microsoft's linker writes between the DOS
/// program and the PE header.
///
/// It starts at offset 0x80 with the letters `DanS` and ends with `Rich`,
/// followed by a key that everything before is XORed with. Other toolchains
/// (MinGW, Go, Rust with the GNU linker, Delphi) write none.
fn has_rich_header(bytes: Bytes<'_>, optional_header: usize) -> bool {
    const START: usize = 0x80;
    const DANS: u32 = 0x536e_6144;
    const RICH: u32 = 0x6863_6952;
    let mut at = START + 16;
    while at + 8 <= optional_header {
        if bytes.u32(at) == Some(RICH) {
            let Some(key) = bytes.u32(at + 4) else {
                return false;
            };
            return bytes.u32(START).map(|first| first ^ key) == Some(DANS)
                && bytes.u32(START + 4) == Some(key)
                && bytes.u32(START + 8) == Some(key);
        }
        at += 4;
    }
    false
}

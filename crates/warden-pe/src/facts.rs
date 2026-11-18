//! What the heuristics know about one Windows executable.
//!
//! [`PeFacts`] is the only thing the indicators see. It is filled by
//! [`read`](crate::read) from a file, and it can be filled from a record of
//! the EMBER2024 dataset, which describes a file with the same facts. That
//! is what makes the indicators measurable: the code that judges a file on
//! disk is the code that was run over the dataset.
//!
//! The rule that follows from it: nothing goes into `PeFacts` that only one
//! of the two sources can supply.

use std::fmt;

use serde::Serialize;

/// Flags of a section, from its header.
pub mod section_flags {
    /// The section holds code.
    pub const CODE: u32 = 0x0000_0020;
    /// The section holds initialised data.
    pub const INITIALIZED_DATA: u32 = 0x0000_0040;
    /// The section holds data that starts out as zeroes.
    pub const UNINITIALIZED_DATA: u32 = 0x0000_0080;
    /// The section can be run.
    pub const EXECUTE: u32 = 0x2000_0000;
    /// The section can be read.
    pub const READ: u32 = 0x4000_0000;
    /// The section can be written to.
    pub const WRITE: u32 = 0x8000_0000;
}

/// Flags from the optional header that say how the image may be loaded.
pub mod image_flags {
    /// The image can be loaded at any address in a 64-bit address space.
    pub const HIGH_ENTROPY_VA: u16 = 0x0020;
    /// The image can be moved when it is loaded (ASLR).
    pub const DYNAMIC_BASE: u16 = 0x0040;
    /// Data pages of the image may not be run (DEP).
    pub const NX_COMPAT: u16 = 0x0100;
    /// The image was built with Control Flow Guard.
    pub const GUARD_CF: u16 = 0x4000;
}

/// The two layouts of a Windows executable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    /// PE32: addresses are 32 bits wide.
    Pe32,
    /// PE32+: addresses are 64 bits wide.
    Pe32Plus,
}

/// The tables an executable can point to from its header.
///
/// The discriminant is the table's position in the header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Directory {
    /// Functions the file offers to others.
    Export = 0,
    /// Functions the file takes from libraries.
    Import = 1,
    /// Icons, dialogs, version information and the like.
    Resource = 2,
    /// Exception handling tables.
    Exception = 3,
    /// The embedded Authenticode signature.
    Signature = 4,
    /// What to patch when the image is moved.
    BaseRelocation = 5,
    /// Where to find debug information.
    Debug = 6,
    /// Thread-local storage, which can hold code that runs before the entry
    /// point.
    Tls = 9,
    /// Load configuration: security cookies, guard tables.
    LoadConfig = 10,
    /// Imports that are resolved when first used.
    DelayImport = 13,
    /// The .NET runtime header.
    ClrHeader = 14,
}

impl Directory {
    /// All tables the facts keep track of.
    pub const ALL: [Self; 11] = [
        Self::Export,
        Self::Import,
        Self::Resource,
        Self::Exception,
        Self::Signature,
        Self::BaseRelocation,
        Self::Debug,
        Self::Tls,
        Self::LoadConfig,
        Self::DelayImport,
        Self::ClrHeader,
    ];

    /// The bit that stands for this table in [`PeFacts::directories`].
    #[must_use]
    pub const fn bit(self) -> u16 {
        1 << (self as u16)
    }
}

/// One section of an executable.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Section {
    /// The name from the section header, without trailing zero bytes.
    /// Bytes that are not text are replaced.
    pub name: String,
    /// Number of bytes the section takes up in the file.
    pub raw_size: u32,
    /// Number of bytes the section takes up in memory.
    pub virtual_size: u32,
    /// The section's flags, see [`section_flags`].
    pub characteristics: u32,
    /// Entropy of the section's bytes in the file, in bits per byte.
    pub entropy: f64,
}

impl Section {
    /// True if the section can be run.
    #[must_use]
    pub fn is_executable(&self) -> bool {
        self.characteristics & section_flags::EXECUTE != 0
    }

    /// True if the section can be written to.
    #[must_use]
    pub fn is_writable(&self) -> bool {
        self.characteristics & section_flags::WRITE != 0
    }

    /// The flags as the letters used in listings: `r`, `w`, `x`, and `c`
    /// for a section that is declared to hold code.
    #[must_use]
    pub fn flag_letters(&self) -> String {
        let mut letters = String::with_capacity(4);
        for (flag, letter) in [
            (section_flags::READ, 'r'),
            (section_flags::WRITE, 'w'),
            (section_flags::EXECUTE, 'x'),
            (section_flags::CODE, 'c'),
        ] {
            letters.push(if self.characteristics & flag != 0 {
                letter
            } else {
                '-'
            });
        }
        letters
    }
}

/// A library an executable imports from, with the functions it takes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImportedLibrary {
    /// The library's file name, as written in the import table.
    pub name: String,
    /// The imported functions. A function that is imported by number
    /// instead of by name is written `#` followed by the number.
    pub functions: Vec<String>,
}

/// Data that follows the last section in the file.
///
/// The loader ignores it. Installers keep their payload there, and so do
/// some droppers. An embedded signature also sits there and is counted in.
#[derive(Debug, Clone, Copy, PartialEq, Default, Serialize)]
pub struct Overlay {
    /// Number of bytes after the last section. Zero if there are none.
    pub size: u64,
    /// Entropy of those bytes, in bits per byte.
    pub entropy: f64,
}

/// Something about a file's structure that a linker would not produce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Anomaly {
    /// The entry point is set, and no section contains it.
    EntryPointOutsideSections,
    /// A section claims more bytes than the file holds.
    SectionDataBeyondFile {
        /// The section's name.
        section: String,
    },
    /// The header announces more sections than Windows accepts.
    TooManySections {
        /// The announced number.
        announced: u32,
    },
    /// The section table runs past the end of the file.
    SectionTableCutShort,
    /// The header runs past the end of the file.
    HeaderCutShort,
    /// The import table is announced, but cannot be followed.
    ImportTableUnreadable,
    /// Some names in the import table could not be read as names.
    ImportNamesUnreadable {
        /// How many.
        count: u32,
    },
    /// The import table is larger than the reader's limits, and the rest
    /// was not read.
    ImportsCutShort,
}

impl fmt::Display for Anomaly {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EntryPointOutsideSections => {
                write!(formatter, "the entry point is in none of the sections")
            }
            Self::SectionDataBeyondFile { section } => write!(
                formatter,
                "section {section:?} claims more bytes than the file holds"
            ),
            Self::TooManySections { announced } => write!(
                formatter,
                "the header announces {announced} sections, more than Windows accepts"
            ),
            Self::SectionTableCutShort => {
                write!(formatter, "the section table runs past the end of the file")
            }
            Self::HeaderCutShort => write!(formatter, "the header runs past the end of the file"),
            Self::ImportTableUnreadable => {
                write!(formatter, "the import table cannot be followed")
            }
            Self::ImportNamesUnreadable { count } => write!(
                formatter,
                "{count} names in the import table are not readable as names"
            ),
            Self::ImportsCutShort => write!(
                formatter,
                "the import table is larger than the reader's limits and was not read to the end"
            ),
        }
    }
}

/// What the heuristics know about one Windows executable.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PeFacts {
    /// Size of the file in bytes.
    pub file_size: u64,
    /// Entropy of the whole file, in bits per byte.
    pub file_entropy: f64,
    /// The layout of the image.
    pub format: Format,
    /// The processor the image is for, as the number from the header:
    /// `0x14c` for x86, `0x8664` for x64, `0xaa64` for ARM64.
    pub machine: u16,
    /// The file is a library (DLL), not a program.
    pub is_dll: bool,
    /// Where the PE header starts in the file. Linkers put it right after a
    /// small DOS program, at an offset between 64 and a few hundred.
    pub pe_header_offset: u32,
    /// When the file was linked, in seconds since 1970, as the header
    /// claims. Reproducible builds put a hash here instead.
    pub timestamp: u32,
    /// The checksum from the header. Zero means none was written.
    pub checksum: u32,
    /// The environment the image is for, as the number from the header: 2
    /// for a windowed program, 3 for a console program, 1 for a driver.
    pub subsystem: u16,
    /// Loader flags, see [`image_flags`].
    pub image_flags: u16,
    /// Where execution starts, relative to the start of the image in
    /// memory. Zero means that there is no entry point.
    pub entry_point: u32,
    /// The section that contains the entry point, as an index into
    /// `sections`.
    pub entry_section: Option<usize>,
    /// The sections, in the order of the section table.
    pub sections: Vec<Section>,
    /// The libraries the file imports from, in the order of the import
    /// table.
    pub imports: Vec<ImportedLibrary>,
    /// Number of functions the file exports.
    pub exports: u32,
    /// Which tables the header points to: one bit per [`Directory`].
    pub directories: u16,
    /// Size of the embedded signature in bytes. Zero if there is none.
    /// Nothing here says whether a signature is valid.
    pub signature_size: u32,
    /// Data after the last section.
    pub overlay: Overlay,
    /// The file has a Rich header, which Microsoft's linker writes.
    pub has_rich_header: bool,
    /// Structural oddities found while reading.
    pub anomalies: Vec<Anomaly>,
}

impl PeFacts {
    /// True if the header points to this table.
    #[must_use]
    pub fn has_directory(&self, directory: Directory) -> bool {
        self.directories & directory.bit() != 0
    }

    /// True if the file is a .NET assembly. Its code is run by the .NET
    /// runtime, so its sections and imports say little about what it does.
    #[must_use]
    pub fn is_dotnet(&self) -> bool {
        self.has_directory(Directory::ClrHeader)
    }

    /// Number of imported functions, over all libraries.
    #[must_use]
    pub fn import_count(&self) -> usize {
        self.imports
            .iter()
            .map(|library| library.functions.len())
            .sum()
    }

    /// True if any library supplies a function with one of these names.
    #[must_use]
    pub fn imports_any(&self, names: &[&str]) -> bool {
        self.imports
            .iter()
            .flat_map(|library| &library.functions)
            .any(|function| names.contains(&function.as_str()))
    }

    /// The first of these names that the file imports.
    #[must_use]
    pub fn first_import_of<'n>(&self, names: &[&'n str]) -> Option<&'n str> {
        names.iter().copied().find(|name| {
            self.imports
                .iter()
                .flat_map(|library| &library.functions)
                .any(|function| function == name)
        })
    }

    /// The section that contains the entry point.
    #[must_use]
    pub fn entry_section(&self) -> Option<&Section> {
        self.entry_section
            .and_then(|index| self.sections.get(index))
    }

    /// The file's size without the data after the last section.
    #[must_use]
    pub fn size_without_overlay(&self) -> u64 {
        self.file_size.saturating_sub(self.overlay.size)
    }
}

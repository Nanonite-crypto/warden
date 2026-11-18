//! Inert Windows executables, built in memory, for tests and demonstrations.
//!
//! Nothing in this module is used when scanning. It exists because the
//! heuristics need files to be tried on, and the project never handles real
//! malware. A fixture has the structure the indicators look at: sections
//! with chosen names, flags and entropy, an import table with chosen
//! function names, data after the last section. It has no behaviour. Its
//! sections hold filler bytes, and the byte at its entry point is a single
//! `ret` instruction, so a fixture that is run returns at once.
//!
//! A fixture that imports `WriteProcessMemory` is a file with those letters
//! in a table. It never calls the function.

use crate::facts::{Directory, image_flags, section_flags};

const FILE_ALIGNMENT: u32 = 0x200;
const SECTION_ALIGNMENT: u32 = 0x1000;
const RICH_KEY: u32 = 0x5741_5244;

/// A source of filler bytes that gives the same bytes every time.
#[derive(Debug, Clone)]
pub struct Filler(u64);

impl Filler {
    /// A filler that starts from `seed`.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1)
    }

    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// Bytes spread as evenly as compressed or encrypted data: close to 8
    /// bits of entropy per byte.
    pub fn packed(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| (self.next() >> 32) as u8).collect()
    }

    /// Bytes spread about as unevenly as compiled code: around 6.5 bits of
    /// entropy per byte.
    pub fn code_like(&mut self, len: usize) -> Vec<u8> {
        (0..len)
            .map(|_| {
                let value = self.next();
                ((value >> 32) & (value >> 40)) as u8
            })
            .collect()
    }

    /// Bytes spread as unevenly as tables and text: around 4 bits of
    /// entropy per byte.
    pub fn data_like(&mut self, len: usize) -> Vec<u8> {
        (0..len)
            .map(|_| {
                let value = self.next();
                ((value >> 32) & (value >> 40) & (value >> 48)) as u8
            })
            .collect()
    }
}

/// One section of a fixture.
#[derive(Debug, Clone)]
pub struct FixtureSection {
    /// Up to eight bytes.
    pub name: String,
    /// The bytes the section has in the file.
    pub data: Vec<u8>,
    /// The size in memory. `None` for the length of `data`.
    pub virtual_size: Option<u32>,
    /// See [`section_flags`].
    pub characteristics: u32,
}

impl FixtureSection {
    /// A section that holds code: readable and executable.
    #[must_use]
    pub fn code(name: &str, data: Vec<u8>) -> Self {
        Self {
            name: name.to_owned(),
            data,
            virtual_size: None,
            characteristics: section_flags::CODE | section_flags::EXECUTE | section_flags::READ,
        }
    }

    /// A section that holds constants: readable.
    #[must_use]
    pub fn read_only(name: &str, data: Vec<u8>) -> Self {
        Self {
            name: name.to_owned(),
            data,
            virtual_size: None,
            characteristics: section_flags::INITIALIZED_DATA | section_flags::READ,
        }
    }

    /// A section that holds variables: readable and writable.
    #[must_use]
    pub fn writable(name: &str, data: Vec<u8>) -> Self {
        Self {
            name: name.to_owned(),
            data,
            virtual_size: None,
            characteristics: section_flags::INITIALIZED_DATA
                | section_flags::READ
                | section_flags::WRITE,
        }
    }

    /// The same section with other flags.
    #[must_use]
    pub fn with_characteristics(mut self, characteristics: u32) -> Self {
        self.characteristics = characteristics;
        self
    }

    /// The same section with a size in memory that differs from its size in
    /// the file.
    #[must_use]
    pub fn with_virtual_size(mut self, virtual_size: u32) -> Self {
        self.virtual_size = Some(virtual_size);
        self
    }
}

/// A function taken from a library.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FixtureImport {
    /// Imported by name.
    Name(String),
    /// Imported by number.
    Number(u16),
}

/// The description of a fixture. [`Fixture::build`] turns it into the bytes
/// of a file.
#[derive(Debug, Clone)]
pub struct Fixture {
    /// PE32+ (64-bit) if true, PE32 if false.
    pub wide: bool,
    /// A library instead of a program.
    pub dll: bool,
    /// The sections, in order. An import section is added after them if
    /// there are imports.
    pub sections: Vec<FixtureSection>,
    /// Libraries and the functions taken from each.
    pub imports: Vec<(String, Vec<FixtureImport>)>,
    /// The name of the section that is added for the imports.
    pub import_section_name: String,
    /// The section the entry point is in, and how far into it. `None` for a
    /// file without an entry point.
    pub entry: Option<(usize, u32)>,
    /// The link time for the header.
    pub timestamp: u32,
    /// See [`image_flags`].
    pub image_flags: u16,
    /// The checksum for the header.
    pub checksum: u32,
    /// Whether to write a Rich header.
    pub rich_header: bool,
    /// Tables the header points to, besides the import table. They point
    /// into the first section and hold nothing that makes sense.
    pub directories: Vec<Directory>,
    /// Bytes after the last section.
    pub overlay: Vec<u8>,
    /// Length of a block at the very end of the file that the header
    /// declares to be a signature. It holds zeroes: this is the place of a
    /// signature, not a signature.
    pub signature_len: u32,
}

impl Fixture {
    /// A fixture that looks like what a current compiler and linker make:
    /// code, constants, variables, resources and relocations in sections
    /// with the usual names, a Rich header, a debug table, the flags for
    /// ASLR and DEP, and the imports of a small C program.
    #[must_use]
    pub fn plain() -> Self {
        let mut filler = Filler::new(1);
        let mut code = filler.code_like(0x3000);
        // A program that returns at once.
        code[0] = 0xc3;
        let names = |list: &[&str]| -> Vec<FixtureImport> {
            list.iter()
                .map(|name| FixtureImport::Name((*name).to_owned()))
                .collect()
        };
        Self {
            wide: true,
            dll: false,
            sections: vec![
                FixtureSection::code(".text", code),
                FixtureSection::read_only(".rdata", filler.data_like(0x1800)),
                FixtureSection::writable(".data", filler.data_like(0x400)),
                FixtureSection::read_only(".rsrc", filler.data_like(0x600)),
                FixtureSection::read_only(".reloc", filler.data_like(0x200)),
            ],
            imports: vec![
                (
                    "KERNEL32.dll".to_owned(),
                    names(&[
                        "GetCommandLineW",
                        "GetModuleHandleW",
                        "GetStdHandle",
                        "WriteFile",
                        "CreateFileW",
                        "ReadFile",
                        "CloseHandle",
                        "GetLastError",
                        "HeapAlloc",
                        "HeapFree",
                        "GetProcessHeap",
                        "ExitProcess",
                        "QueryPerformanceCounter",
                        "GetSystemTimeAsFileTime",
                        "GetCurrentProcessId",
                        "GetCurrentThreadId",
                        "IsProcessorFeaturePresent",
                        "SetUnhandledExceptionFilter",
                        "UnhandledExceptionFilter",
                        "TerminateProcess",
                        "GetCurrentProcess",
                        "RtlCaptureContext",
                        "RtlLookupFunctionEntry",
                        "RtlVirtualUnwind",
                    ]),
                ),
                (
                    "USER32.dll".to_owned(),
                    names(&["MessageBoxW", "LoadIconW", "GetSystemMetrics"]),
                ),
            ],
            import_section_name: ".idata".to_owned(),
            entry: Some((0, 0)),
            // 2025-01-01
            timestamp: 1_735_689_600,
            image_flags: image_flags::HIGH_ENTROPY_VA
                | image_flags::DYNAMIC_BASE
                | image_flags::NX_COMPAT
                | image_flags::GUARD_CF,
            checksum: 0,
            rich_header: true,
            directories: vec![
                Directory::Resource,
                Directory::BaseRelocation,
                Directory::Debug,
                Directory::LoadConfig,
                Directory::Exception,
            ],
            overlay: Vec::new(),
            signature_len: 0,
        }
    }

    /// A fixture with the structure a simple packer leaves behind: an empty
    /// executable section to unpack into, a second one that is writable,
    /// executable and full of evenly spread bytes with the entry point in
    /// it, a third for the three imports, section names of the UPX packer,
    /// and none of the tables or flags a linker writes.
    ///
    /// The evenly spread bytes are filler from [`Filler`], not a packed
    /// program.
    #[must_use]
    pub fn packed_looking() -> Self {
        let mut filler = Filler::new(2);
        let mut stub = filler.packed(0x4000);
        stub[0x3f00] = 0xc3;
        let read_write_execute = section_flags::INITIALIZED_DATA
            | section_flags::READ
            | section_flags::WRITE
            | section_flags::EXECUTE;
        Self {
            wide: false,
            dll: false,
            sections: vec![
                FixtureSection::code("UPX0", Vec::new())
                    .with_virtual_size(0x9000)
                    .with_characteristics(
                        section_flags::UNINITIALIZED_DATA
                            | section_flags::READ
                            | section_flags::WRITE
                            | section_flags::EXECUTE,
                    ),
                FixtureSection::code("UPX1", stub).with_characteristics(read_write_execute),
            ],
            imports: vec![(
                "KERNEL32.DLL".to_owned(),
                ["LoadLibraryA", "GetProcAddress", "ExitProcess"]
                    .iter()
                    .map(|name| FixtureImport::Name((*name).to_owned()))
                    .collect(),
            )],
            import_section_name: "UPX2".to_owned(),
            entry: Some((1, 0x3f00)),
            timestamp: 0,
            image_flags: 0,
            checksum: 0,
            rich_header: false,
            directories: Vec::new(),
            overlay: Vec::new(),
            signature_len: 0,
        }
    }

    /// The bytes of the file this fixture describes.
    ///
    /// # Panics
    ///
    /// Panics if the description cannot be laid out: more than 90 sections,
    /// or an entry point in a section that does not exist. A fixture is
    /// made by a test, and a test with such a mistake should fail loudly.
    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        let mut sections = self.sections.clone();
        assert!(sections.len() <= 90, "too many sections for a fixture");

        // Where the headers end decides where everything else goes.
        let pe_offset: usize = if self.rich_header { 0xa8 } else { 0x80 };
        let optional_len: usize = if self.wide { 240 } else { 224 };
        let section_count = sections.len() + usize::from(!self.imports.is_empty());
        let headers_len = pe_offset + 24 + optional_len + section_count * 40;
        let size_of_headers = align(headers_len as u32, FILE_ALIGNMENT);

        // Virtual addresses of the sections that are given.
        let mut next_address = align(size_of_headers, SECTION_ALIGNMENT);
        let mut addresses = Vec::with_capacity(section_count);
        for section in &sections {
            addresses.push(next_address);
            let size = section
                .virtual_size
                .unwrap_or(section.data.len() as u32)
                .max(section.data.len() as u32)
                .max(1);
            next_address = align(next_address + size, SECTION_ALIGNMENT);
        }

        // The import section comes last, at a known address.
        let mut import_directory = (0u32, 0u32);
        if !self.imports.is_empty() {
            let (data, descriptors_len) = self.import_section(next_address);
            import_directory = (next_address, descriptors_len);
            addresses.push(next_address);
            next_address = align(next_address + data.len() as u32, SECTION_ALIGNMENT);
            sections.push(FixtureSection::writable(&self.import_section_name, data));
        }
        let size_of_image = next_address;

        // Offsets in the file.
        let mut next_offset = size_of_headers;
        let mut offsets = Vec::with_capacity(sections.len());
        for section in &sections {
            if section.data.is_empty() {
                offsets.push(0);
            } else {
                offsets.push(next_offset);
                next_offset = align(next_offset + section.data.len() as u32, FILE_ALIGNMENT);
            }
        }
        let sections_end = next_offset as usize;
        let signature_offset = align((sections_end + self.overlay.len()) as u32, 8);

        let mut file = vec![0u8; size_of_headers as usize];
        // DOS header: the magic and the offset of the PE header.
        file[0..2].copy_from_slice(b"MZ");
        put32(&mut file, 0x3c, pe_offset as u32);
        if self.rich_header {
            // DanS, three times the key, two entries, Rich, the key.
            let words = [
                0x536e_6144 ^ RICH_KEY,
                RICH_KEY,
                RICH_KEY,
                RICH_KEY,
                0x0104_7809 ^ RICH_KEY,
                12 ^ RICH_KEY,
                0x0102_7809 ^ RICH_KEY,
                1 ^ RICH_KEY,
                0x6863_6952,
                RICH_KEY,
            ];
            for (index, word) in words.iter().enumerate() {
                put32(&mut file, 0x80 + index * 4, *word);
            }
        }

        // PE signature and COFF header.
        file[pe_offset..pe_offset + 4].copy_from_slice(b"PE\0\0");
        let coff = pe_offset + 4;
        put16(&mut file, coff, if self.wide { 0x8664 } else { 0x014c });
        put16(&mut file, coff + 2, sections.len() as u16);
        put32(&mut file, coff + 4, self.timestamp);
        put16(&mut file, coff + 16, optional_len as u16);
        let mut characteristics = 0x0002 | 0x0020;
        if !self.wide {
            characteristics |= 0x0100;
        }
        if self.dll {
            characteristics |= 0x2000;
        }
        put16(&mut file, coff + 18, characteristics);

        // Optional header.
        let optional = coff + 20;
        put16(&mut file, optional, if self.wide { 0x20b } else { 0x10b });
        file[optional + 2] = 14;
        let entry_point = self.entry.map_or(0, |(section, into)| {
            assert!(
                section < sections.len(),
                "the entry point names a section that does not exist"
            );
            addresses[section] + into
        });
        put32(&mut file, optional + 16, entry_point);
        put32(
            &mut file,
            optional + 20,
            addresses.first().copied().unwrap_or(0),
        );
        if self.wide {
            put64(&mut file, optional + 24, 0x1_4000_0000);
        } else {
            put32(&mut file, optional + 28, 0x0040_0000);
        }
        put32(&mut file, optional + 32, SECTION_ALIGNMENT);
        put32(&mut file, optional + 36, FILE_ALIGNMENT);
        put16(&mut file, optional + 40, 6);
        put16(&mut file, optional + 48, 6);
        put32(&mut file, optional + 56, size_of_image);
        put32(&mut file, optional + 60, size_of_headers);
        put32(&mut file, optional + 64, self.checksum);
        put16(&mut file, optional + 68, 3);
        put16(&mut file, optional + 70, self.image_flags);
        let (count_at, directories_at) = if self.wide { (108, 112) } else { (92, 96) };
        put32(&mut file, optional + count_at, 16);
        let mut set_directory = |which: Directory, address: u32, size: u32| {
            let at = optional + directories_at + (which as usize) * 8;
            put32(&mut file, at, address);
            put32(&mut file, at + 4, size);
        };
        if import_directory.0 != 0 {
            set_directory(Directory::Import, import_directory.0, import_directory.1);
        }
        for which in &self.directories {
            if !matches!(which, Directory::Import | Directory::Signature) {
                set_directory(*which, addresses.first().copied().unwrap_or(0x1000), 0x40);
            }
        }
        if self.signature_len > 0 {
            // The one table whose address is an offset in the file.
            set_directory(Directory::Signature, signature_offset, self.signature_len);
        }

        // Section table.
        let table = optional + optional_len;
        for (index, section) in sections.iter().enumerate() {
            let at = table + index * 40;
            let name = section.name.as_bytes();
            let len = name.len().min(8);
            file[at..at + len].copy_from_slice(&name[..len]);
            put32(
                &mut file,
                at + 8,
                section.virtual_size.unwrap_or(section.data.len() as u32),
            );
            put32(&mut file, at + 12, addresses[index]);
            put32(
                &mut file,
                at + 16,
                align(section.data.len() as u32, FILE_ALIGNMENT),
            );
            put32(&mut file, at + 20, offsets[index]);
            put32(&mut file, at + 36, section.characteristics);
        }

        // Section data, each padded to the file alignment.
        for (index, section) in sections.iter().enumerate() {
            if section.data.is_empty() {
                continue;
            }
            debug_assert_eq!(file.len(), offsets[index] as usize);
            file.extend_from_slice(&section.data);
            file.resize(align(file.len() as u32, FILE_ALIGNMENT) as usize, 0);
        }
        file.extend_from_slice(&self.overlay);
        if self.signature_len > 0 {
            file.resize(signature_offset as usize + self.signature_len as usize, 0);
        }
        file
    }

    /// The content of the import section if it is loaded at `address`, and
    /// the length of the descriptors at its start.
    fn import_section(&self, address: u32) -> (Vec<u8>, u32) {
        let entry_len: usize = if self.wide { 8 } else { 4 };
        let descriptors_len = (self.imports.len() + 1) * 20;
        let lists_len: usize = self
            .imports
            .iter()
            .map(|(_, functions)| (functions.len() + 1) * entry_len)
            .sum();
        // Descriptors, lookup lists, address lists, then names.
        let lookup_start = descriptors_len;
        let address_start = lookup_start + lists_len;
        let names_start = address_start + lists_len;

        let mut data = vec![0u8; names_start];
        let mut list_at = 0usize;
        for (index, (library, functions)) in self.imports.iter().enumerate() {
            let descriptor = index * 20;
            put32(
                &mut data,
                descriptor,
                address + (lookup_start + list_at) as u32,
            );
            put32(
                &mut data,
                descriptor + 16,
                address + (address_start + list_at) as u32,
            );
            for (position, function) in functions.iter().enumerate() {
                let entry: u64 = match function {
                    FixtureImport::Number(number) => {
                        let flag = if self.wide { 1u64 << 63 } else { 1u64 << 31 };
                        flag | u64::from(*number)
                    }
                    FixtureImport::Name(name) => {
                        let at = data.len();
                        data.extend_from_slice(&[0, 0]);
                        data.extend_from_slice(name.as_bytes());
                        data.push(0);
                        if data.len() % 2 == 1 {
                            data.push(0);
                        }
                        u64::from(address) + at as u64
                    }
                };
                for start in [lookup_start, address_start] {
                    let at = start + list_at + position * entry_len;
                    if self.wide {
                        put64(&mut data, at, entry);
                    } else {
                        put32(&mut data, at, entry as u32);
                    }
                }
            }
            list_at += (functions.len() + 1) * entry_len;
            let name_at = data.len();
            data.extend_from_slice(library.as_bytes());
            data.push(0);
            put32(&mut data, descriptor + 12, address + name_at as u32);
        }
        (data, descriptors_len as u32)
    }
}

fn align(value: u32, to: u32) -> u32 {
    value.div_ceil(to) * to
}

fn put16(buffer: &mut [u8], at: usize, value: u16) {
    buffer[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn put32(buffer: &mut [u8], at: usize, value: u32) {
    buffer[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put64(buffer: &mut [u8], at: usize, value: u64) {
    buffer[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

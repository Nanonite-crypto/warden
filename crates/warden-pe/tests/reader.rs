//! The reader against files whose content is known: fixtures built in
//! memory, read back, and compared with what was put in. A second,
//! independent reader (the `object` crate) reads the same bytes, so that a
//! mistake shared by the builder and the reader does not go unnoticed.

#![allow(clippy::unwrap_used)]

use object::LittleEndian as LE;
use object::read::pe::{ImageNtHeaders, ImageOptionalHeader, PeFile32, PeFile64};
use warden_pe::fixture::{Filler, Fixture, FixtureImport, FixtureSection};
use warden_pe::{
    Anomaly, Directory, Format, NotPe, PeFacts, entropy, image_flags, looks_like_pe, read,
    section_flags,
};

fn names(list: &[&str]) -> Vec<FixtureImport> {
    list.iter()
        .map(|name| FixtureImport::Name((*name).to_owned()))
        .collect()
}

/// Reads `data` with the `object` crate and checks that it sees the same
/// sections, entry point and imports as Warden's reader.
fn agrees_with_object(data: &[u8], facts: &PeFacts) {
    fn compare<Pe: ImageNtHeaders>(file: &object::read::pe::PeFile<'_, Pe>, facts: &PeFacts) {
        let optional = file.nt_headers().optional_header();
        assert_eq!(optional.address_of_entry_point(), facts.entry_point);
        assert_eq!(optional.check_sum(), facts.checksum);
        assert_eq!(optional.dll_characteristics(), facts.image_flags);
        assert_eq!(optional.subsystem(), facts.subsystem);
        assert_eq!(
            file.nt_headers().file_header().time_date_stamp.get(LE),
            facts.timestamp
        );

        let table = file.section_table();
        assert_eq!(table.len(), facts.sections.len());
        for (theirs, ours) in table.iter().zip(&facts.sections) {
            let name = String::from_utf8_lossy(theirs.raw_name()).into_owned();
            assert_eq!(name, ours.name);
            assert_eq!(theirs.size_of_raw_data.get(LE), ours.raw_size);
            assert_eq!(theirs.virtual_size.get(LE), ours.virtual_size);
            assert_eq!(theirs.characteristics.get(LE), ours.characteristics);
        }

        let mut their_imports = Vec::new();
        if let Some(import_table) = file.import_table().unwrap() {
            let mut descriptors = import_table.descriptors().unwrap();
            while let Some(descriptor) = descriptors.next().unwrap() {
                let library = import_table.name(descriptor.name.get(LE)).unwrap();
                let mut functions = Vec::new();
                let mut thunks = import_table
                    .thunks(descriptor.original_first_thunk.get(LE))
                    .unwrap();
                while let Some(thunk) = thunks.next::<Pe>().unwrap() {
                    match import_table.import::<Pe>(thunk).unwrap() {
                        object::read::pe::Import::Ordinal(number) => {
                            functions.push(format!("#{number}"));
                        }
                        object::read::pe::Import::Name(_, name) => {
                            functions.push(String::from_utf8_lossy(name).into_owned());
                        }
                    }
                }
                their_imports.push((String::from_utf8_lossy(library).into_owned(), functions));
            }
        }
        let our_imports: Vec<(String, Vec<String>)> = facts
            .imports
            .iter()
            .map(|library| (library.name.clone(), library.functions.clone()))
            .collect();
        assert_eq!(their_imports, our_imports);
    }

    match facts.format {
        Format::Pe32 => compare(&PeFile32::parse(data).unwrap(), facts),
        Format::Pe32Plus => compare(&PeFile64::parse(data).unwrap(), facts),
    }
}

#[test]
fn an_ordinary_program_is_read_back_as_it_was_built() {
    let fixture = Fixture::plain();
    let file = fixture.build();
    assert!(looks_like_pe(&file));
    let facts = read(&file).unwrap();
    agrees_with_object(&file, &facts);

    assert_eq!(facts.format, Format::Pe32Plus);
    assert_eq!(facts.machine, 0x8664);
    assert!(!facts.is_dll);
    assert!(!facts.is_dotnet());
    assert_eq!(facts.file_size, file.len() as u64);
    assert_eq!(facts.timestamp, fixture.timestamp);
    assert_eq!(facts.pe_header_offset, 0xa8);
    assert!(facts.has_rich_header);
    assert_ne!(facts.image_flags & image_flags::DYNAMIC_BASE, 0);
    assert_ne!(facts.image_flags & image_flags::NX_COMPAT, 0);
    assert_eq!(facts.anomalies, []);

    let section_names: Vec<&str> = facts
        .sections
        .iter()
        .map(|section| section.name.as_str())
        .collect();
    assert_eq!(
        section_names,
        [".text", ".rdata", ".data", ".rsrc", ".reloc", ".idata"]
    );
    let text = &facts.sections[0];
    assert!(text.is_executable() && !text.is_writable());
    assert_eq!(text.flag_letters(), "r-xc");
    assert_eq!(text.raw_size, 0x3000);
    // The filler for code is made to look like code to an entropy measure.
    assert!((6.0..7.0).contains(&text.entropy), "{}", text.entropy);
    assert!(facts.sections[1].entropy < 5.0);
    assert_eq!(facts.entry_section, Some(0));
    assert_eq!(facts.entry_section().unwrap().name, ".text");

    assert_eq!(facts.imports.len(), 2);
    assert_eq!(facts.imports[0].name, "KERNEL32.dll");
    assert_eq!(facts.imports[0].functions.len(), 24);
    assert_eq!(facts.imports[0].functions[0], "GetCommandLineW");
    assert_eq!(
        facts.imports[1].functions,
        ["MessageBoxW", "LoadIconW", "GetSystemMetrics"]
    );
    assert_eq!(facts.import_count(), 27);
    assert!(facts.imports_any(&["nothing", "ExitProcess"]));
    assert_eq!(
        facts.first_import_of(&["VirtualAllocEx", "ReadFile", "WriteFile"]),
        Some("ReadFile")
    );

    for present in [
        Directory::Import,
        Directory::Resource,
        Directory::BaseRelocation,
        Directory::Debug,
        Directory::LoadConfig,
        Directory::Exception,
    ] {
        assert!(facts.has_directory(present), "{present:?}");
    }
    for absent in [
        Directory::Export,
        Directory::Signature,
        Directory::Tls,
        Directory::DelayImport,
        Directory::ClrHeader,
    ] {
        assert!(!facts.has_directory(absent), "{absent:?}");
    }
    assert_eq!(facts.overlay.size, 0);
    assert_eq!(facts.signature_size, 0);
    assert_eq!(facts.exports, 0);
    assert!((facts.file_entropy - entropy::of(&file)).abs() < 1e-12);
}

#[test]
fn a_packed_looking_program_is_read_back_as_it_was_built() {
    let file = Fixture::packed_looking().build();
    let facts = read(&file).unwrap();
    agrees_with_object(&file, &facts);

    assert_eq!(facts.format, Format::Pe32);
    assert_eq!(facts.machine, 0x14c);
    assert!(!facts.has_rich_header);
    assert_eq!(facts.pe_header_offset, 0x80);
    assert_eq!(facts.timestamp, 0);
    assert_eq!(facts.image_flags, 0);

    let empty = &facts.sections[0];
    assert_eq!(
        (empty.name.as_str(), empty.raw_size, empty.virtual_size),
        ("UPX0", 0, 0x9000)
    );
    assert_eq!(empty.entropy, 0.0);
    assert!(empty.is_executable() && empty.is_writable());
    let stub = &facts.sections[1];
    assert_eq!(stub.name, "UPX1");
    assert!(stub.entropy > 7.9, "{}", stub.entropy);
    assert_eq!(stub.flag_letters(), "rwx-");
    assert_eq!(facts.entry_section, Some(1));
    assert_eq!(facts.sections[2].name, "UPX2");
    assert_eq!(
        facts.imports[0].functions,
        ["LoadLibraryA", "GetProcAddress", "ExitProcess"]
    );
    assert_eq!(facts.anomalies, []);
    assert_eq!(facts.directories, Directory::Import.bit());
}

#[test]
fn imports_by_number_overlays_signatures_and_libraries_are_read() {
    let mut filler = Filler::new(7);
    for wide in [false, true] {
        let mut fixture = Fixture::plain();
        fixture.wide = wide;
        fixture.dll = true;
        fixture.entry = None;
        fixture.imports = vec![
            (
                "WS2_32.dll".to_owned(),
                vec![
                    FixtureImport::Number(115),
                    FixtureImport::Name("connect".to_owned()),
                    FixtureImport::Number(3),
                ],
            ),
            ("ADVAPI32.dll".to_owned(), names(&["RegOpenKeyExW"])),
        ];
        fixture.overlay = filler.packed(10_000);
        fixture.signature_len = 0x1800;
        fixture.directories.push(Directory::Tls);
        fixture.directories.push(Directory::ClrHeader);
        let file = fixture.build();
        let facts = read(&file).unwrap();
        agrees_with_object(&file, &facts);

        assert_eq!(
            facts.format,
            if wide { Format::Pe32Plus } else { Format::Pe32 }
        );
        assert!(facts.is_dll);
        assert!(facts.is_dotnet());
        assert_eq!(facts.entry_point, 0);
        assert_eq!(facts.entry_section, None);
        // No entry point is not the same as an entry point in the wrong place.
        assert_eq!(facts.anomalies, []);
        assert_eq!(facts.imports[0].functions, ["#115", "connect", "#3"]);
        assert_eq!(facts.imports[1].name, "ADVAPI32.dll");
        assert!(facts.has_directory(Directory::Tls));
        assert!(facts.has_directory(Directory::Signature));
        assert_eq!(facts.signature_size, 0x1800);
        // The overlay is everything after the last section, with the
        // signature and the padding in front of it.
        assert!(facts.overlay.size >= 10_000 + 0x1800);
        assert!(facts.overlay.size < 10_000 + 0x1800 + 8);
        assert_eq!(
            facts.size_without_overlay() + facts.overlay.size,
            file.len() as u64
        );
        assert!(facts.overlay.entropy > 5.0);
    }
}

#[test]
fn files_that_are_not_windows_executables_are_told_apart() {
    let cases: [(&[u8], NotPe); 6] = [
        (b"", NotPe::NoDosHeader),
        (b"\x7fELF\x02\x01\x01", NotPe::NoDosHeader),
        (b"PK\x03\x04", NotPe::NoDosHeader),
        (b"MZ", NotPe::HeaderCutShort),
        (&[b'M', b'Z', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0x7f], NotPe::NoPeHeader),
        (b"MZ this is a text file that happens to start with two letters, and it goes on for a while", NotPe::NoPeHeader),
    ];
    for (data, expected) in cases {
        assert_eq!(read(data).unwrap_err(), expected, "{data:?}");
        assert!(!looks_like_pe(data));
    }

    // A DOS program: the header points at something that is not "PE".
    let mut dos = vec![0u8; 0x200];
    dos[..2].copy_from_slice(b"MZ");
    dos[0x3c] = 0x80;
    assert_eq!(read(&dos).unwrap_err(), NotPe::NoPeHeader);

    // A PE header with a format that is neither PE32 nor PE32+.
    let mut file = Fixture::plain().build();
    let optional = 0xa8 + 24;
    file[optional..optional + 2].copy_from_slice(&0x107u16.to_le_bytes());
    assert!(looks_like_pe(&file));
    assert_eq!(read(&file).unwrap_err(), NotPe::UnknownFormat);

    // A file that ends inside its header.
    let file = Fixture::plain().build();
    assert_eq!(read(&file[..0xa8 + 30]).unwrap_err(), NotPe::HeaderCutShort);
    assert_eq!(
        read(&file[..0xa8 + 24 + 100]).unwrap_err(),
        NotPe::HeaderCutShort
    );
}

#[test]
fn damage_is_reported_and_does_not_stop_the_reader() {
    let whole = Fixture::plain().build();

    // Cut in the middle of the section data.
    let cut = &whole[..0x1000];
    let facts = read(cut).unwrap();
    assert_eq!(facts.sections.len(), 6);
    assert!(facts.anomalies.contains(&Anomaly::SectionDataBeyondFile {
        section: ".text".to_owned()
    }));
    // The import section is gone, so the table that is announced cannot be
    // followed.
    assert!(facts.anomalies.contains(&Anomaly::ImportTableUnreadable));
    assert!(facts.imports.is_empty());
    assert_eq!(facts.sections[5].entropy, 0.0);

    // Cut inside the section table.
    let table = 0xa8 + 24 + 240;
    let facts = read(&whole[..table + 40 * 2 + 10]).unwrap();
    assert_eq!(facts.sections.len(), 2);
    assert!(facts.anomalies.contains(&Anomaly::SectionTableCutShort));

    // An entry point that no section contains.
    let mut moved = whole.clone();
    let optional = 0xa8 + 24;
    moved[optional + 16..optional + 20].copy_from_slice(&0x0090_0000u32.to_le_bytes());
    let facts = read(&moved).unwrap();
    assert_eq!(facts.entry_section, None);
    assert!(
        facts
            .anomalies
            .contains(&Anomaly::EntryPointOutsideSections)
    );

    // More sections announced than Windows accepts.
    let mut crowded = whole.clone();
    crowded[0xa8 + 6..0xa8 + 8].copy_from_slice(&5000u16.to_le_bytes());
    let facts = read(&crowded).unwrap();
    assert!(
        facts
            .anomalies
            .contains(&Anomaly::TooManySections { announced: 5000 })
    );
    assert!(facts.sections.len() <= warden_pe::MAX_SECTIONS);
}

#[test]
fn an_import_table_without_an_end_is_cut_at_the_limits() {
    // A library with more functions than the reader follows.
    let mut fixture = Fixture::plain();
    let many: Vec<FixtureImport> = (0..warden_pe::MAX_FUNCTIONS_PER_LIBRARY + 50)
        .map(|index| FixtureImport::Number((index % 60_000) as u16))
        .collect();
    fixture.imports = vec![("BIG.dll".to_owned(), many)];
    let facts = read(&fixture.build()).unwrap();
    assert_eq!(
        facts.imports[0].functions.len(),
        warden_pe::MAX_FUNCTIONS_PER_LIBRARY
    );
    assert!(facts.anomalies.contains(&Anomaly::ImportsCutShort));

    // More libraries than the reader follows.
    let mut fixture = Fixture::plain();
    fixture.imports = (0..warden_pe::MAX_LIBRARIES + 5)
        .map(|index| (format!("LIB{index}.dll"), vec![FixtureImport::Number(1)]))
        .collect();
    let facts = read(&fixture.build()).unwrap();
    assert_eq!(facts.imports.len(), warden_pe::MAX_LIBRARIES);
    assert!(facts.anomalies.contains(&Anomaly::ImportsCutShort));
}

#[test]
fn names_that_are_not_names_are_counted_and_left_out() {
    let mut fixture = Fixture::plain();
    fixture.imports = vec![(
        "KERNEL32.dll".to_owned(),
        names(&["ExitProcess", "bad\u{1}name", "Sleep"]),
    )];
    let facts = read(&fixture.build()).unwrap();
    assert_eq!(facts.imports[0].functions, ["ExitProcess", "Sleep"]);
    assert!(
        facts
            .anomalies
            .contains(&Anomaly::ImportNamesUnreadable { count: 1 })
    );
}

#[test]
fn sections_that_share_their_bytes_are_not_measured_over_and_over() {
    // Sixty sections, patched so that all of them claim the megabyte of the
    // first. A file like that must not cost sixty passes over the megabyte.
    const COPIES: usize = 60;
    let mut fixture = Fixture::plain();
    fixture.imports.clear();
    fixture.sections = vec![FixtureSection::code(
        ".text",
        Filler::new(3).packed(1 << 20),
    )];
    for _ in 1..COPIES {
        fixture
            .sections
            .push(FixtureSection::read_only(".copy", vec![0; 16]));
    }
    let mut file = fixture.build();
    let table = 0xa8 + 24 + 240;
    let size_and_pointer: Vec<u8> = file[table + 16..table + 24].to_vec();
    for index in 1..COPIES {
        let header = table + index * 40;
        file[header + 16..header + 24].copy_from_slice(&size_and_pointer);
    }

    let facts = read(&file).unwrap();
    assert_eq!(facts.sections.len(), COPIES);
    assert!(
        facts
            .sections
            .iter()
            .all(|section| section.raw_size == 1 << 20)
    );
    assert!(facts.sections[0].entropy > 7.9);
    // Sections that do not overlap cannot hold more bytes than the file, so
    // that is as many bytes as get measured.
    let measured = facts
        .sections
        .iter()
        .filter(|section| section.entropy > 0.0)
        .count();
    assert_eq!(measured, 1);
}

#[test]
fn section_flags_have_their_documented_values() {
    assert_eq!(section_flags::EXECUTE, 0x2000_0000);
    assert_eq!(section_flags::WRITE, 0x8000_0000);
    assert_eq!(image_flags::DYNAMIC_BASE, 0x40);
    assert_eq!(image_flags::NX_COMPAT, 0x100);
    assert_eq!(Directory::Signature.bit(), 1 << 4);
    assert_eq!(Directory::ClrHeader.bit(), 1 << 14);
}

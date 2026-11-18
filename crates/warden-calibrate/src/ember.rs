//! Records of the EMBER2024 dataset, and how one becomes [`PeFacts`].
//!
//! EMBER2024 (Joyce et al., 2025, <https://arxiv.org/abs/2506.05074>)
//! describes 3.2 million files by features that were extracted with the
//! `pefile` Python library, one JSON object per file. No file content is
//! part of it. The field names below are those written by the dataset's
//! own extraction code, `thrember/features.py`.
//!
//! The mapping is as literal as it can be. Where the dataset cannot say
//! what Warden's reader would say, the comment at that place says so.

use std::collections::BTreeMap;

use serde::Deserialize;
use warden_pe::{
    Anomaly, Directory, Format, ImportedLibrary, Overlay, PeFacts, Section, image_flags,
    section_flags,
};

/// One line of a dataset file. Only the fields the mapping needs are
/// declared; the byte histograms and string statistics are skipped.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Record {
    /// 1 for malicious, 0 for benign.
    pub label: Option<i64>,
    /// `Win32`, `Win64`, `Dot_Net`, `APK`, `ELF` or `PDF`.
    pub file_type: Option<String>,
    /// When the file was first submitted to VirusTotal, in seconds since
    /// 1970.
    pub first_submission_date: Option<f64>,
    general: General,
    header: Header,
    section: SectionInfo,
    imports: BTreeMap<String, Vec<String>>,
    exports: Vec<serde_json::Value>,
    datadirectories: Vec<DataDirectory>,
    richheader: Vec<serde_json::Value>,
    pefilewarnings: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct General {
    size: f64,
    entropy: f64,
    is_pe: i64,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct Header {
    coff: Coff,
    optional: Optional,
    dos: Dos,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct Coff {
    timestamp: f64,
    machine: String,
    characteristics: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct Optional {
    magic: f64,
    subsystem: String,
    address_of_entrypoint: f64,
    checksum: f64,
    dll_characteristics: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct Dos {
    e_lfanew: f64,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct SectionInfo {
    entry: String,
    sections: Vec<EmberSection>,
    overlay: EmberOverlay,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct EmberSection {
    name: String,
    size: f64,
    entropy: f64,
    vsize: f64,
    props: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct EmberOverlay {
    size: f64,
    entropy: f64,
}

/// An element of `datadirectories`. The first element of the list holds
/// two flags instead and has none of these fields.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct DataDirectory {
    name: String,
    size: f64,
    virtual_address: f64,
}

const ENTRY_OUTSIDE: &str = "AddressOfEntryPoint lies outside the sections' boundaries...";
const RAW_DATA_BEYOND_FILE: [&str; 2] = [
    "...SizeOfRawData is larger than file.",
    "...PointerToRawData points beyond the end of the file.",
];

fn to_u32(value: f64) -> u32 {
    if value.is_finite() && value > 0.0 {
        value.min(f64::from(u32::MAX)) as u32
    } else {
        0
    }
}

fn to_u64(value: f64) -> u64 {
    if value.is_finite() && value > 0.0 {
        value as u64
    } else {
        0
    }
}

impl Record {
    /// True if the dataset's own parser read the file as a Windows
    /// executable. The others have no header or section features.
    pub fn is_pe(&self) -> bool {
        self.general.is_pe == 1
    }

    /// The facts about the file, as far as the record holds them.
    pub fn facts(&self) -> PeFacts {
        let sections: Vec<Section> = self
            .section
            .sections
            .iter()
            .map(|section| Section {
                // The dataset stores names in lowercase.
                name: section.name.clone(),
                raw_size: to_u32(section.size),
                virtual_size: to_u32(section.vsize),
                characteristics: section_characteristics(&section.props),
                entropy: section.entropy,
            })
            .collect();

        let entry_point = to_u32(self.header.optional.address_of_entrypoint);
        let mut anomalies = Vec::new();
        // The dataset names the section that contains the entry point, and
        // if none does it names the first executable section instead. The
        // parser's warning tells the two apart. A section is found by its
        // name, so of two sections with the same name the first is taken.
        let outside = self.warns(ENTRY_OUTSIDE);
        let entry_section = if outside || entry_point == 0 || self.section.entry.is_empty() {
            None
        } else {
            sections
                .iter()
                .position(|section| section.name == self.section.entry)
        };
        if outside && entry_point != 0 {
            anomalies.push(Anomaly::EntryPointOutsideSections);
        }
        if RAW_DATA_BEYOND_FILE
            .iter()
            .any(|warning| self.warns(warning))
        {
            // The warning does not carry over which section it was.
            anomalies.push(Anomaly::SectionDataBeyondFile {
                section: String::new(),
            });
        }

        let mut directories = 0u16;
        let mut signature_size = 0u32;
        for entry in &self.datadirectories {
            let Some(which) = directory_named(&entry.name) else {
                continue;
            };
            if entry.size > 0.0 && entry.virtual_address > 0.0 {
                directories |= which.bit();
                if which == Directory::Signature {
                    signature_size = to_u32(entry.size);
                }
            }
        }

        let imports = self
            .imports
            .iter()
            .map(|(library, functions)| ImportedLibrary {
                name: library.clone(),
                functions: functions
                    .iter()
                    .map(|function| import_name(library, function))
                    .collect(),
            })
            .collect();

        PeFacts {
            file_size: to_u64(self.general.size),
            file_entropy: self.general.entropy,
            format: if to_u32(self.header.optional.magic) == 0x20b {
                Format::Pe32Plus
            } else {
                Format::Pe32
            },
            machine: machine_number(&self.header.coff.machine),
            is_dll: self
                .header
                .coff
                .characteristics
                .iter()
                .any(|flag| flag == "DLL"),
            pe_header_offset: to_u32(self.header.dos.e_lfanew),
            timestamp: to_u32(self.header.coff.timestamp),
            checksum: to_u32(self.header.optional.checksum),
            subsystem: subsystem_number(&self.header.optional.subsystem),
            image_flags: loader_flags(&self.header.optional.dll_characteristics),
            entry_point,
            entry_section,
            sections,
            imports,
            exports: self.exports.len().min(u32::MAX as usize) as u32,
            directories,
            signature_size,
            overlay: Overlay {
                size: to_u64(self.section.overlay.size),
                entropy: self.section.overlay.entropy,
            },
            has_rich_header: !self.richheader.is_empty(),
            anomalies,
        }
    }

    fn warns(&self, warning: &str) -> bool {
        self.pefilewarnings.iter().any(|entry| entry == warning)
    }
}

/// The dataset writes an import by number as `library:ordinal123`.
fn import_name(library: &str, function: &str) -> String {
    function
        .strip_prefix(library)
        .and_then(|rest| rest.strip_prefix(":ordinal"))
        .filter(|number| !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit()))
        .map_or_else(|| function.to_owned(), |number| format!("#{number}"))
}

fn section_characteristics(props: &[String]) -> u32 {
    props
        .iter()
        .map(|prop| match prop.as_str() {
            "CNT_CODE" => section_flags::CODE,
            "CNT_INITIALIZED_DATA" => section_flags::INITIALIZED_DATA,
            "CNT_UNINITIALIZED_DATA" => section_flags::UNINITIALIZED_DATA,
            "MEM_EXECUTE" => section_flags::EXECUTE,
            "MEM_READ" => section_flags::READ,
            "MEM_WRITE" => section_flags::WRITE,
            _ => 0,
        })
        .fold(0, |flags, flag| flags | flag)
}

fn loader_flags(names: &[String]) -> u16 {
    names
        .iter()
        .map(|name| match name.as_str() {
            "HIGH_ENTROPY_VA" => image_flags::HIGH_ENTROPY_VA,
            "DYNAMIC_BASE" => image_flags::DYNAMIC_BASE,
            "FORCE_INTEGRITY" => 0x0080,
            "NX_COMPAT" => image_flags::NX_COMPAT,
            "NO_ISOLATION" => 0x0200,
            "NO_SEH" => 0x0400,
            "NO_BIND" => 0x0800,
            "APPCONTAINER" => 0x1000,
            "WDM_DRIVER" => 0x2000,
            "GUARD_CF" => image_flags::GUARD_CF,
            "TERMINAL_SERVER_AWARE" => 0x8000,
            _ => 0,
        })
        .fold(0, |flags, flag| flags | flag)
}

fn directory_named(name: &str) -> Option<Directory> {
    Some(match name {
        "EXPORT" => Directory::Export,
        "IMPORT" => Directory::Import,
        "RESOURCE" => Directory::Resource,
        "EXCEPTION" => Directory::Exception,
        "SECURITY" => Directory::Signature,
        "BASERELOC" => Directory::BaseRelocation,
        "DEBUG" => Directory::Debug,
        "TLS" => Directory::Tls,
        "LOAD_CONFIG" => Directory::LoadConfig,
        "DELAY_IMPORT" => Directory::DelayImport,
        "COM_DESCRIPTOR" => Directory::ClrHeader,
        _ => return None,
    })
}

fn machine_number(name: &str) -> u16 {
    match name {
        "IMAGE_FILE_MACHINE_I386" => 0x014c,
        "IMAGE_FILE_MACHINE_AMD64" => 0x8664,
        "IMAGE_FILE_MACHINE_ARM64" => 0xaa64,
        "IMAGE_FILE_MACHINE_ARMNT" => 0x01c4,
        "IMAGE_FILE_MACHINE_ARM" => 0x01c0,
        "IMAGE_FILE_MACHINE_IA64" => 0x0200,
        _ => 0,
    }
}

fn subsystem_number(name: &str) -> u16 {
    match name {
        "IMAGE_SUBSYSTEM_NATIVE" => 1,
        "IMAGE_SUBSYSTEM_WINDOWS_GUI" => 2,
        "IMAGE_SUBSYSTEM_WINDOWS_CUI" => 3,
        "IMAGE_SUBSYSTEM_OS2_CUI" => 5,
        "IMAGE_SUBSYSTEM_POSIX_CUI" => 7,
        "IMAGE_SUBSYSTEM_NATIVE_WINDOWS" => 8,
        "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI" => 9,
        "IMAGE_SUBSYSTEM_EFI_APPLICATION" => 10,
        "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER" => 11,
        "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER" => 12,
        "IMAGE_SUBSYSTEM_EFI_ROM" => 13,
        "IMAGE_SUBSYSTEM_XBOX" => 14,
        "IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION" => 16,
        _ => 0,
    }
}

/// Writes facts the way the dataset would record them. Used by tests to
/// check that the mapping above loses nothing the indicators need.
#[cfg(test)]
pub fn record_json(facts: &PeFacts, label: i64, file_type: &str, first_seen: u64) -> String {
    use serde_json::json;

    let props = |section: &Section| -> Vec<&str> {
        [
            (section_flags::CODE, "CNT_CODE"),
            (section_flags::INITIALIZED_DATA, "CNT_INITIALIZED_DATA"),
            (section_flags::UNINITIALIZED_DATA, "CNT_UNINITIALIZED_DATA"),
            (section_flags::EXECUTE, "MEM_EXECUTE"),
            (section_flags::READ, "MEM_READ"),
            (section_flags::WRITE, "MEM_WRITE"),
        ]
        .iter()
        .filter(|(flag, _)| section.characteristics & flag != 0)
        .map(|(_, name)| *name)
        .collect()
    };
    let mut warnings = Vec::new();
    for anomaly in &facts.anomalies {
        match anomaly {
            Anomaly::EntryPointOutsideSections => warnings.push(ENTRY_OUTSIDE),
            Anomaly::SectionDataBeyondFile { .. } => warnings.push(RAW_DATA_BEYOND_FILE[0]),
            _ => {}
        }
    }
    let mut directories = vec![json!({"has_relocs": 0, "has_dynamic_relocs": 0})];
    for (index, name) in [
        "EXPORT",
        "IMPORT",
        "RESOURCE",
        "EXCEPTION",
        "SECURITY",
        "BASERELOC",
        "DEBUG",
        "COPYRIGHT",
        "GLOBALPTR",
        "TLS",
        "LOAD_CONFIG",
        "BOUND_IMPORT",
        "IAT",
        "DELAY_IMPORT",
        "COM_DESCRIPTOR",
        "RESERVED",
    ]
    .iter()
    .enumerate()
    {
        let present = facts.directories & (1 << index) != 0;
        let size = if *name == "SECURITY" {
            facts.signature_size
        } else if present {
            0x40
        } else {
            0
        };
        directories.push(json!({
            "name": name,
            "size": size,
            "virtual_address": if present { 0x2000 } else { 0 },
        }));
    }
    let imports: serde_json::Map<String, serde_json::Value> = facts
        .imports
        .iter()
        .map(|library| {
            let functions: Vec<String> = library
                .functions
                .iter()
                .map(|function| match function.strip_prefix('#') {
                    Some(number) => format!("{}:ordinal{number}", library.name),
                    None => function.clone(),
                })
                .collect();
            (library.name.clone(), json!(functions))
        })
        .collect();
    let mut flags = Vec::new();
    for (flag, name) in [
        (image_flags::HIGH_ENTROPY_VA, "HIGH_ENTROPY_VA"),
        (image_flags::DYNAMIC_BASE, "DYNAMIC_BASE"),
        (image_flags::NX_COMPAT, "NX_COMPAT"),
        (image_flags::GUARD_CF, "GUARD_CF"),
    ] {
        if facts.image_flags & flag != 0 {
            flags.push(name);
        }
    }
    json!({
        "sha256": "00",
        "tlsh": "T1",
        "first_submission_date": first_seen,
        "label": label,
        "file_type": file_type,
        "family": null,
        "general": {"size": facts.file_size, "entropy": facts.file_entropy, "is_pe": 1, "start_bytes": [77, 90, 144, 0]},
        "histogram": [1, 2, 3],
        "byteentropy": [4, 5, 6],
        "strings": {"numstrings": 3, "avlength": 5.5, "printabledist": [1, 2], "printables": 3, "entropy": 4.5, "string_counts": {"url": 1}},
        "header": {
            "coff": {
                "timestamp": facts.timestamp,
                "machine": if facts.format == Format::Pe32Plus { "IMAGE_FILE_MACHINE_AMD64" } else { "IMAGE_FILE_MACHINE_I386" },
                "number_of_sections": facts.sections.len(),
                "characteristics": if facts.is_dll { vec!["EXECUTABLE_IMAGE", "DLL"] } else { vec!["EXECUTABLE_IMAGE"] },
            },
            "optional": {
                "magic": if facts.format == Format::Pe32Plus { 0x20b } else { 0x10b },
                "subsystem": "IMAGE_SUBSYSTEM_WINDOWS_CUI",
                "address_of_entrypoint": facts.entry_point,
                "image_base": 5_368_709_120u64,
                "checksum": facts.checksum,
                "dll_characteristics": flags,
            },
            "dos": {"e_magic": 23117, "e_lfanew": facts.pe_header_offset},
        },
        "section": {
            "entry": facts.entry_section().map_or(String::new(), |section| section.name.to_lowercase()),
            "sections": facts.sections.iter().map(|section| json!({
                "name": section.name.to_lowercase(),
                "size": section.raw_size,
                "entropy": section.entropy,
                "vsize": section.virtual_size,
                "size_ratio": 0.5,
                "vsize_ratio": 1.0,
                "props": props(section),
            })).collect::<Vec<_>>(),
            "overlay": {"size": facts.overlay.size, "size_ratio": 0.0, "entropy": facts.overlay.entropy},
        },
        "imports": imports,
        "exports": (0..facts.exports).map(|index| format!("export{index}")).collect::<Vec<_>>(),
        "datadirectories": directories,
        "richheader": if facts.has_rich_header { vec![1, 2, 3, 4] } else { vec![] },
        "authenticode": {"num_certs": 0, "self_signed": 0},
        "pefilewarnings": warnings,
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::collections::BTreeSet;

    use warden_pe::fixture::{Filler, Fixture, FixtureImport};
    use warden_pe::indicators::{Context, evaluate};

    use super::*;

    fn ids(facts: &PeFacts, context: &Context) -> BTreeSet<&'static str> {
        evaluate(facts, context)
            .into_iter()
            .map(|hit| hit.indicator.id)
            .collect()
    }

    /// A file's facts, written as a record and read back, must set off the
    /// same indicators as the file itself. If they did not, the weights
    /// measured on the dataset would not be about the files Warden scans.
    #[test]
    fn a_record_sets_off_the_same_indicators_as_the_file_it_describes() {
        let context = Context {
            now_unix_secs: 1_748_736_000,
        };
        let mut filler = Filler::new(5);
        let mut fixtures = vec![Fixture::plain(), Fixture::packed_looking()];

        let mut library = Fixture::plain();
        library.dll = true;
        library.entry = None;
        library.imports.clear();
        fixtures.push(library);

        let mut signed_installer = Fixture::plain();
        signed_installer.overlay = filler.packed(0x9000);
        signed_installer.signature_len = 0x1800;
        signed_installer.checksum = 0x1234;
        fixtures.push(signed_installer);

        let mut injector = Fixture::plain();
        injector.wide = false;
        injector.rich_header = false;
        injector.timestamp = 708_992_537;
        injector.image_flags = 0;
        injector.directories.clear();
        injector.directories.push(Directory::Tls);
        injector.overlay = filler.packed(0x9000);
        injector.imports = vec![
            (
                "KERNEL32.dll".to_owned(),
                [
                    "VirtualAllocEx",
                    "WriteProcessMemory",
                    "CreateRemoteThread",
                    "CreateToolhelp32Snapshot",
                    "Process32FirstW",
                    "Process32NextW",
                    "WinExec",
                ]
                .iter()
                .map(|name| FixtureImport::Name((*name).to_owned()))
                .collect(),
            ),
            ("WS2_32.dll".to_owned(), vec![FixtureImport::Number(115)]),
        ];
        fixtures.push(injector);

        let mut dotnet = Fixture::plain();
        dotnet.directories.push(Directory::ClrHeader);
        dotnet.imports = vec![(
            "mscoree.dll".to_owned(),
            vec![FixtureImport::Name("_CorExeMain".to_owned())],
        )];
        fixtures.push(dotnet);

        for (index, fixture) in fixtures.iter().enumerate() {
            let direct = warden_pe::read(&fixture.build()).unwrap();
            let json = record_json(&direct, 1, "Win64", context.now_unix_secs);
            let record: Record = serde_json::from_str(&json).unwrap();
            assert!(record.is_pe());
            let mapped = record.facts();
            assert_eq!(
                ids(&mapped, &context),
                ids(&direct, &context),
                "fixture {index}"
            );
            assert_eq!(mapped.import_count(), direct.import_count());
            assert_eq!(mapped.directories, direct.directories);
            assert_eq!(mapped.entry_section, direct.entry_section);
        }

        // Damage that the dataset records as parser warnings.
        let whole = Fixture::plain().build();
        let mut moved = whole.clone();
        let optional = 0xa8 + 24;
        moved[optional + 16..optional + 20].copy_from_slice(&0x0090_0000u32.to_le_bytes());
        for damaged in [&whole[..0x2000], &moved[..]] {
            let direct = warden_pe::read(damaged).unwrap();
            let json = record_json(&direct, 0, "Win64", context.now_unix_secs);
            let mapped = serde_json::from_str::<Record>(&json).unwrap().facts();
            assert_eq!(ids(&mapped, &context), ids(&direct, &context));
        }
    }

    /// A record written out by hand from the dataset's extraction code,
    /// with the parts Warden does not use left in.
    #[test]
    fn a_record_in_the_datasets_own_words_is_understood() {
        let line = r#"{"sha256": "aa", "tlsh": "T1", "first_submission_date": 1700000000,
            "last_analysis_date": 1710000000, "detection_ratio": 0.7, "label": 1,
            "file_type": "Win32", "family": "upatre", "family_confidence": 0.9,
            "behavior": ["downloader"], "file_property": [], "packer": ["upx"], "exploit": [], "group": [],
            "general": {"size": 73728, "entropy": 7.61, "is_pe": 1, "start_bytes": [77, 90, 144, 0]},
            "histogram": [5, 4], "byteentropy": [0, 1],
            "strings": {"numstrings": 12, "avlength": 6.0, "printabledist": [1], "printables": 72, "entropy": 5.1, "string_counts": {}},
            "header": {
              "coff": {"timestamp": 1699990000, "machine": "IMAGE_FILE_MACHINE_I386", "number_of_sections": 3,
                       "number_of_symbols": 0, "sizeof_optional_header": 224, "pointer_to_symbol_table": 0,
                       "characteristics": ["RELOCS_STRIPPED", "EXECUTABLE_IMAGE", "32BIT_MACHINE"]},
              "optional": {"magic": 267, "subsystem": "IMAGE_SUBSYSTEM_WINDOWS_GUI", "major_linker_version": 6,
                           "sizeof_code": 28672, "address_of_entrypoint": 73200, "base_of_code": 45056,
                           "image_base": 4194304, "section_alignment": 4096, "checksum": 0,
                           "number_of_rvas_and_sizes": 16, "dll_characteristics": []},
              "dos": {"e_magic": 23117, "e_cblp": 144, "e_lfanew": 216}},
            "section": {"entry": "upx1",
              "sections": [
                {"name": "upx0", "size": 0, "entropy": 0.0, "vsize": 40960, "size_ratio": 0.0, "vsize_ratio": 0.0,
                 "props": ["CNT_UNINITIALIZED_DATA", "MEM_EXECUTE", "MEM_READ", "MEM_WRITE"]},
                {"name": "upx1", "size": 28672, "entropy": 7.89, "vsize": 28672, "size_ratio": 0.39, "vsize_ratio": 1.0,
                 "props": ["CNT_INITIALIZED_DATA", "MEM_EXECUTE", "MEM_READ", "MEM_WRITE"]},
                {"name": ".rsrc", "size": 4096, "entropy": 3.2, "vsize": 4096, "size_ratio": 0.05, "vsize_ratio": 1.0,
                 "props": ["CNT_INITIALIZED_DATA", "MEM_READ", "MEM_WRITE"]}],
              "overlay": {"size": 0, "size_ratio": 0, "entropy": 0}},
            "imports": {"KERNEL32.DLL": ["LoadLibraryA", "GetProcAddress", "ExitProcess"],
                        "WS2_32.dll": ["WS2_32.dll:ordinal115"]},
            "exports": [],
            "datadirectories": [{"has_relocs": 0, "has_dynamic_relocs": 0},
              {"name": "EXPORT", "size": 0, "virtual_address": 0},
              {"name": "IMPORT", "size": 200, "virtual_address": 77000},
              {"name": "RESOURCE", "size": 2000, "virtual_address": 73728},
              {"name": "SECURITY", "size": 0, "virtual_address": 0},
              {"name": "TLS", "size": 0, "virtual_address": 0}],
            "richheader": [],
            "authenticode": {"num_certs": 0, "self_signed": 0, "empty_program_name": 0, "no_countersigner": 0,
                             "parse_error": 0, "chain_max_depth": 0, "latest_signing_time": 0, "signing_time_diff": 0},
            "pefilewarnings": ["Suspicious flags set for section..."]}"#;
        let record: Record = serde_json::from_str(line).unwrap();
        assert_eq!(record.label, Some(1));
        assert_eq!(record.file_type.as_deref(), Some("Win32"));
        assert_eq!(record.first_submission_date, Some(1_700_000_000.0));
        assert!(record.is_pe());

        let facts = record.facts();
        assert_eq!(facts.format, Format::Pe32);
        assert_eq!(facts.machine, 0x14c);
        assert_eq!(facts.subsystem, 2);
        assert_eq!(facts.file_size, 73_728);
        assert_eq!(facts.pe_header_offset, 216);
        assert_eq!(facts.entry_section, Some(1));
        assert_eq!(facts.sections.len(), 3);
        assert!(facts.sections[0].is_executable() && facts.sections[0].is_writable());
        assert_eq!(facts.sections[0].virtual_size, 40_960);
        assert_eq!(facts.imports[1].functions, ["#115"]);
        assert!(facts.has_directory(Directory::Import));
        assert!(facts.has_directory(Directory::Resource));
        assert!(!facts.has_directory(Directory::Signature));
        assert!(!facts.has_rich_header);

        let context = Context {
            now_unix_secs: 1_700_000_000,
        };
        let hits = ids(&facts, &context);
        for expected in [
            "sections.packer_name",
            "sections.writable_and_executable",
            "sections.code_without_file_data",
            "sections.high_entropy_code",
            "file.high_entropy",
            "entry.in_writable_section",
            "imports.few",
            "imports.loader_only",
            "header.no_aslr",
            "header.no_dep",
            "header.no_rich_header",
            "tables.no_debug",
            "tables.no_relocations",
            "signature.none",
        ] {
            assert!(
                hits.contains(expected),
                "{expected} is missing from {hits:?}"
            );
        }
        assert!(!hits.contains("header.timestamp_in_future"));
        assert!(!hits.contains("entry.outside_sections"));
    }

    #[test]
    fn records_of_files_that_are_not_windows_executables_are_recognised() {
        let apk = r#"{"label": 0, "file_type": "APK", "general": {"size": 10, "entropy": 1.0, "is_pe": 0},
                      "header": {}, "section": {}, "imports": {}, "exports": [], "datadirectories": [],
                      "richheader": [], "pefilewarnings": []}"#;
        let record: Record = serde_json::from_str(apk).unwrap();
        assert!(!record.is_pe());
        // Nothing in such a record can make the mapping fail.
        let facts = record.facts();
        assert!(facts.sections.is_empty());
        // Neither can a record with nothing in it.
        assert!(!serde_json::from_str::<Record>("{}").unwrap().is_pe());
    }

    #[test]
    fn imports_by_number_are_rewritten_and_names_are_kept() {
        assert_eq!(import_name("ws2_32.dll", "ws2_32.dll:ordinal23"), "#23");
        assert_eq!(import_name("ws2_32.dll", "connect"), "connect");
        assert_eq!(import_name("a.dll", "b.dll:ordinal23"), "b.dll:ordinal23");
        assert_eq!(import_name("a.dll", "a.dll:ordinal"), "a.dll:ordinal");
        assert_eq!(import_name("a.dll", "a.dll:ordinalx"), "a.dll:ordinalx");
    }
}

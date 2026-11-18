//! The indicators: things about a Windows executable that are worth a
//! second look.
//!
//! An indicator is a yes-or-no question about [`PeFacts`], with a weight.
//! None of them proves anything by itself. A game protected against
//! cheating is packed, a debugger writes into other processes, an installer
//! carries megabytes of compressed data behind its last section. What
//! counts is how much an indicator shifts the odds, and that is measured,
//! not assumed: the weights are fitted to the EMBER2024 dataset, all
//! together, and a test fails if a weight in this file is not what the
//! counts in `calibration/` give. `docs/HEURISTICS.md` has the numbers.
//!
//! Most indicators have the weight zero. They are shown by
//! `warden inspect` and add nothing to the score, for one of three
//! reasons: clean files show them as often as malicious ones; or they say
//! nothing that the scored indicators do not already say, as the name of a
//! packer's section does next to a writable code section with high
//! entropy; or they are left out on purpose, as the missing signature is.
//! The list is longer than the scored part because what was measured and
//! found useless is worth knowing too.

use serde::Serialize;

use crate::facts::{Anomaly, Directory, PeFacts, Section, image_flags};

/// What an indicator is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Group {
    /// Signs that the program's real content is compressed or encrypted and
    /// unpacked when it runs.
    Packing,
    /// Where execution starts, and how the file is laid out.
    Layout,
    /// What the program asks Windows for.
    Imports,
    /// Fields of the header and tables a linker normally writes.
    Header,
}

impl Group {
    /// A heading for the group.
    #[must_use]
    pub fn title(self) -> &'static str {
        match self {
            Self::Packing => "Packing",
            Self::Layout => "Layout",
            Self::Imports => "Imports",
            Self::Header => "Header",
        }
    }
}

/// One indicator.
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct Indicator {
    /// Stable identifier, such as `sections.packer_name`.
    pub id: &'static str,
    /// What the indicator is about.
    pub group: Group,
    /// What was seen, as a short sentence without a full stop.
    pub summary: &'static str,
    /// Why that matters, and which clean software does the same.
    pub rationale: &'static str,
    /// How much a hit adds to the score, in decibans: ten times the
    /// base-ten logarithm of the factor by which the indicator multiplies
    /// the odds that a file is malicious, next to all the other
    /// indicators. Ten is tenfold. Zero for an indicator that is shown and
    /// not scored.
    pub weight: u8,
}

/// An indicator that applies to a file, with what exactly was seen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Hit {
    /// The indicator.
    pub indicator: &'static Indicator,
    /// The specifics, such as the name of the section in question.
    pub detail: String,
}

/// What the indicators need to know besides the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Context {
    /// The time to compare a link timestamp against, in seconds since
    /// 1970: now for a file on disk, the day a file was first seen for a
    /// record of a dataset.
    pub now_unix_secs: u64,
}

impl Context {
    /// A context for a file that is inspected now.
    #[must_use]
    pub fn now() -> Self {
        Self {
            now_unix_secs: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_secs()),
        }
    }
}

type Check = fn(&PeFacts, &Context) -> Option<String>;

struct Definition {
    indicator: Indicator,
    check: Check,
}

/// Section names that packers and protectors give to the sections they
/// create, in lowercase.
const PACKER_SECTION_NAMES: &[&str] = &[
    // UPX
    "upx0", "upx1", "upx2", "upx3", "upx!", ".upx0", ".upx1", ".upx2", // ASPack
    ".aspack", ".adata", "aspack", // NsPack
    ".nsp0", ".nsp1", ".nsp2", "nsp0", "nsp1", "nsp2", // PECompact
    "pec1", "pec2", "pec3", "pec4", "pec5", "pec6", "pec2to", "pec2mo", "pecompac",
    // MPRESS
    ".mpress1", ".mpress2", // Themida and WinLicense
    ".themida", "themida", ".winlice", "winlicen", // VMProtect
    ".vmp0", ".vmp1", ".vmp2", // Enigma Protector
    ".enigma1", ".enigma2", // Petite
    ".petite",  // Y0da
    ".yp", ".y0da", // RLPack
    ".rlpack", ".packed", // tElock and TSULoader
    ".tsuarch", ".tsustub", // Upack
    ".upack", ".bylbcr", // Neolite
    ".neolit", ".neolite", // WWPack
    ".wwpack", ".wwp32",
    // Others: kkrunchy, PELock, MEW, SVKP, JDPack, Simple Pack, eXPressor,
    // PEBundle, Shrinker
    "kkrunchy", "pelock", "mew", ".svkp", ".jdpack", ".spack", ".ex_cod", "pebundle", ".shrink1",
    ".shrink2", ".shrink3",
];

/// Section names that compilers, linkers and common tools write, in
/// lowercase. MinGW names debug sections `/4`, `/19` and so on; those are
/// matched by their slash.
const STANDARD_SECTION_NAMES: &[&str] = &[
    ".text", ".data", ".rdata", ".rsrc", ".reloc", ".pdata", ".xdata", ".idata", ".edata", ".tls",
    ".bss", ".crt", ".debug", ".didat", ".gfids", ".00cfg", ".giats", ".mrdata", ".rodata",
    ".eh_fram", ".buildid", ".retplne", ".voltbl", ".rtc", ".shared", ".msvcjmc", ".sxdata",
    ".orpc", ".cormeta", ".fptable", ".symtab", ".ctors", ".dtors", ".stab", ".stabstr",
    ".drectve", ".ndata", ".itext", ".didata", ".rustc", ".a64xrm", ".hexpthk", "code", "data",
    "bss", "init", "page", "pagelk", "pagekd", "text", "const",
];

const LOAD_LIBRARY: &[&str] = &[
    "LoadLibraryA",
    "LoadLibraryW",
    "LoadLibraryExA",
    "LoadLibraryExW",
];
const REMOTE_ALLOCATION: &[&str] = &[
    "VirtualAllocEx",
    "NtAllocateVirtualMemory",
    "ZwAllocateVirtualMemory",
];
const REMOTE_WRITE: &[&str] = &[
    "WriteProcessMemory",
    "NtWriteVirtualMemory",
    "ZwWriteVirtualMemory",
];
const REMOTE_THREAD: &[&str] = &[
    "CreateRemoteThread",
    "CreateRemoteThreadEx",
    "NtCreateThreadEx",
    "ZwCreateThreadEx",
    "RtlCreateUserThread",
    "QueueUserAPC",
    "NtQueueApcThread",
];
const UNMAP_SECTION: &[&str] = &["NtUnmapViewOfSection", "ZwUnmapViewOfSection"];
const SET_THREAD_CONTEXT: &[&str] = &[
    "SetThreadContext",
    "NtSetContextThread",
    "ZwSetContextThread",
    "Wow64SetThreadContext",
];
const RESUME_THREAD: &[&str] = &["ResumeThread", "NtResumeThread", "ZwResumeThread"];
const WINDOWS_HOOK: &[&str] = &["SetWindowsHookExA", "SetWindowsHookExW"];
const KEY_STATE: &[&str] = &["GetAsyncKeyState", "GetKeyState", "GetKeyboardState"];
const DOWNLOAD_TO_FILE: &[&str] = &[
    "URLDownloadToFileA",
    "URLDownloadToFileW",
    "URLDownloadToCacheFileA",
    "URLDownloadToCacheFileW",
];
const LOOKUP_PRIVILEGE: &[&str] = &["LookupPrivilegeValueA", "LookupPrivilegeValueW"];
const PROCESS_FIRST: &[&str] = &["Process32First", "Process32FirstW"];
const PROCESS_NEXT: &[&str] = &["Process32Next", "Process32NextW"];
const CREATE_SERVICE: &[&str] = &["CreateServiceA", "CreateServiceW"];

/// Entropy from which an executable section counts as compressed or
/// encrypted. Compiled code stays well below it.
pub const HIGH_ENTROPY_CODE: f64 = 7.0;
/// Entropy from which data, or a whole file, counts as compressed or
/// encrypted.
pub const HIGH_ENTROPY_DATA: f64 = 7.2;
/// The first second of the year 2000.
const YEAR_2000: u32 = 946_684_800;
const DAY_SECS: u64 = 86_400;

fn lower(name: &str) -> String {
    name.to_ascii_lowercase()
}

fn is_standard_name(name: &str) -> bool {
    let name = lower(name);
    STANDARD_SECTION_NAMES.contains(&name.as_str())
        || (name.starts_with('/') && name[1..].bytes().all(|byte| byte.is_ascii_digit()))
}

/// The names of the sections that pass `test`, quoted and joined.
fn sections_where(facts: &PeFacts, test: impl Fn(&Section) -> bool) -> Option<String> {
    let names: Vec<String> = facts
        .sections
        .iter()
        .filter(|section| test(section))
        .map(|section| format!("{:?}", section.name))
        .collect();
    match names.len() {
        0 => None,
        1 => Some(format!("section {}", names[0])),
        _ => Some(format!("sections {}", names.join(", "))),
    }
}

/// True for a native program or library that can be run: the indicators
/// about imports say nothing about a .NET assembly, whose only import is
/// the runtime, or about a library that holds resources and no code.
fn runs_native_code(facts: &PeFacts) -> bool {
    !facts.is_dotnet() && facts.entry_point != 0
}

/// Bytes after the last section that are not the embedded signature.
fn overlay_beyond_signature(facts: &PeFacts) -> u64 {
    facts
        .overlay
        .size
        .saturating_sub(u64::from(facts.signature_size))
}

/// The detail text for a set of imports, if the file imports one of each
/// group.
fn imports_one_of_each(facts: &PeFacts, groups: &[&[&str]]) -> Option<String> {
    let found: Option<Vec<&str>> = groups
        .iter()
        .map(|group| facts.first_import_of(group))
        .collect();
    let found = found?;
    Some(match found.as_slice() {
        [only] => format!("imports {only}"),
        [first @ .., last] => format!("imports {} and {last}", first.join(", ")),
        [] => return None,
    })
}

macro_rules! definitions {
    ($( $id:literal, $group:ident, $weight:literal, $summary:literal, $rationale:literal, $check:expr; )+) => {
        &[ $( Definition {
            indicator: Indicator {
                id: $id,
                group: Group::$group,
                summary: $summary,
                rationale: $rationale,
                weight: $weight,
            },
            check: $check,
        }, )+ ]
    };
}

static DEFINITIONS: &[Definition] = definitions![
    // ---- Packing ---------------------------------------------------------
    "sections.packer_name", Packing, 0,
    "A section has a name that a packer or protector writes",
    "Packers such as UPX, ASPack, Themida and VMProtect compress or encrypt a program and name the sections they create. Malware is packed to hide from scanners. Clean software is packed too, to save space or to protect against copying, though far less often.",
    |facts, _| sections_where(facts, |section| PACKER_SECTION_NAMES.contains(&lower(&section.name).as_str()));

    "sections.writable_and_executable", Packing, 10,
    "A section is both writable and executable",
    "Code that rewrites itself needs memory that can be written and run. Linkers keep code read-only, so this is the mark of a packer's unpacking stub or of code that patches itself. Some older compilers and a few game protections produce it too.",
    |facts, _| sections_where(facts, |section| section.is_writable() && section.is_executable());

    "sections.code_without_file_data", Packing, 0,
    "An executable section takes up memory and no bytes in the file",
    "The section is empty until the program fills it when it runs. That is where a packer unpacks the real program to.",
    |facts, _| sections_where(facts, |section| section.is_executable() && section.raw_size == 0 && section.virtual_size > 0);

    "sections.code_mostly_in_memory", Packing, 4,
    "An executable section is several times larger in memory than in the file",
    "The section grows when the program is loaded, and the extra room is filled when it runs. A linker writes code out in full, so room like this is where a packer unpacks to.",
    |facts, _| {
        sections_where(facts, |section| {
            section.is_executable()
                && section.raw_size > 0
                && u64::from(section.virtual_size) >= 4 * u64::from(section.raw_size)
        })
    };

    "sections.high_entropy_code", Packing, 9,
    "An executable section looks compressed or encrypted",
    "Compiled code has an entropy around 6 bits per byte. Above 7, the bytes are too evenly spread to be instructions: the section holds packed or encrypted content.",
    |facts, _| {
        facts
            .sections
            .iter()
            .filter(|section| section.is_executable() && section.raw_size >= 1024)
            .filter(|section| section.entropy >= HIGH_ENTROPY_CODE)
            .max_by(|left, right| left.entropy.total_cmp(&right.entropy))
            .map(|section| format!("section {:?} has an entropy of {:.2} bits per byte", section.name, section.entropy))
    };

    "sections.high_entropy_data", Packing, 8,
    "A data section looks compressed or encrypted",
    "A large block of evenly spread bytes in a data section is compressed or encrypted content, such as a payload that is decrypted when the program runs. Programs that embed compressed files have it too. The resource section is not counted, because icons and images are compressed.",
    |facts, _| {
        facts
            .sections
            .iter()
            .filter(|section| !section.is_executable() && section.raw_size >= 4096)
            .filter(|section| !matches!(lower(&section.name).as_str(), ".rsrc" | ".reloc"))
            .filter(|section| section.entropy >= HIGH_ENTROPY_DATA)
            .max_by(|left, right| left.entropy.total_cmp(&right.entropy))
            .map(|section| format!("section {:?} has an entropy of {:.2} bits per byte", section.name, section.entropy))
    };

    "sections.no_standard_name", Packing, 0,
    "No section has a name that a compiler writes",
    "Compilers and linkers use a small set of section names: .text, .data, .rdata and so on. A file without a single one of them was built or rewritten by something else, often a packer that renames or removes them.",
    |facts, _| {
        (!facts.sections.is_empty() && !facts.sections.iter().any(|section| is_standard_name(&section.name)))
            .then(|| {
                let names: Vec<String> = facts.sections.iter().take(6).map(|section| format!("{:?}", section.name)).collect();
                format!("the sections are named {}", names.join(", "))
            })
    };

    "file.high_entropy", Packing, 0,
    "The file as a whole looks compressed or encrypted",
    "A program is a mix of code, text and tables, and its entropy as a whole stays well below that of compressed data. A file that is almost all evenly spread bytes is packed, or it is a small program wrapped around a large compressed payload, such as an installer.",
    |facts, _| {
        (facts.file_size >= 16 * 1024 && facts.file_entropy >= HIGH_ENTROPY_DATA)
            .then(|| format!("the whole file has an entropy of {:.2} bits per byte", facts.file_entropy))
    };

    "overlay.large_unsigned", Packing, 5,
    "A quarter of the file or more sits after the last section",
    "Windows does not load what follows the last section. Installers and self-extracting archives keep their payload there, and so do droppers. An embedded signature is not counted.",
    |facts, _| {
        let beyond = overlay_beyond_signature(facts);
        (facts.file_size > 0 && beyond >= 4096 && beyond.saturating_mul(4) >= facts.file_size)
            .then(|| format!("{beyond} of {} bytes come after the last section", facts.file_size))
    };

    "overlay.high_entropy", Packing, 0,
    "Data after the last section looks compressed or encrypted",
    "Appended data that is evenly spread is a compressed or encrypted payload. Only files without an embedded signature are judged, because a signature sits in the same place.",
    |facts, _| {
        (facts.signature_size == 0 && facts.overlay.size >= 4096 && facts.overlay.entropy >= HIGH_ENTROPY_DATA)
            .then(|| format!("{} bytes after the last section have an entropy of {:.2} bits per byte", facts.overlay.size, facts.overlay.entropy))
    };

    // ---- Layout ----------------------------------------------------------
    "entry.outside_sections", Layout, 10,
    "The entry point is in none of the sections",
    "Execution starts in the headers or outside the image. A linker cannot produce that; it is done by hand, to confuse tools that analyse the file.",
    |facts, _| {
        facts
            .anomalies
            .contains(&Anomaly::EntryPointOutsideSections)
            .then(|| format!("the entry point is at {:#x}", facts.entry_point))
    };

    "entry.in_last_section", Layout, 0,
    "The entry point is in the last section",
    "Linkers put code first. Execution that starts in the last section is typical of a packer's stub and of a virus that has appended itself to a program.",
    |facts, _| {
        let index = facts.entry_section?;
        (facts.sections.len() >= 2 && index + 1 == facts.sections.len())
            .then(|| format!("the entry point is in section {:?}, the last of {}", facts.sections[index].name, facts.sections.len()))
    };

    "entry.not_in_first_section", Layout, 0,
    "The entry point is not in the first section",
    "Linkers put the code first, and the entry point with it. Execution that starts further back is typical of packers, which put their stub behind the packed program.",
    |facts, _| {
        let index = facts.entry_section?;
        (index > 0).then(|| {
            format!(
                "the entry point is in section {:?}, number {} of {}",
                facts.sections[index].name,
                index + 1,
                facts.sections.len()
            )
        })
    };

    "entry.in_writable_section", Layout, 0,
    "The entry point is in a writable section",
    "The code that runs first can be overwritten while it runs. That is how an unpacking stub works.",
    |facts, _| {
        facts
            .entry_section()
            .filter(|section| section.is_writable())
            .map(|section| format!("the entry point is in section {:?}, which is writable", section.name))
    };

    "entry.in_non_executable_section", Layout, 7,
    "The entry point is in a section that is not marked executable",
    "Windows refuses to run code in such a section unless data execution prevention is switched off for the program. A linker marks the section that holds the entry point as executable.",
    |facts, _| {
        facts
            .entry_section()
            .filter(|section| !section.is_executable())
            .map(|section| format!("the entry point is in section {:?}, which is not executable", section.name))
    };

    "header.pe_header_in_dos_header", Layout, 18,
    "The PE header starts inside the DOS header",
    "The two headers overlap. Linkers never do that; it is the mark of a file that was built by hand to be as small or as confusing as possible.",
    |facts, _| (facts.pe_header_offset < 0x40).then(|| format!("the PE header starts at offset {:#x}", facts.pe_header_offset));

    "sections.beyond_file", Layout, 0,
    "A section claims more bytes than the file holds",
    "The file was cut short, or its section table was edited. Downloads that broke off look like this, and so do files that were damaged on purpose to make analysis tools stumble.",
    |facts, _| {
        let names: Vec<String> = facts
            .anomalies
            .iter()
            .filter_map(|anomaly| match anomaly {
                Anomaly::SectionDataBeyondFile { section } => Some(format!("{section:?}")),
                _ => None,
            })
            .collect();
        (!names.is_empty()).then(|| format!("section {}", names.join(", ")))
    };

    // ---- Imports ---------------------------------------------------------
    "imports.none", Imports, 8,
    "The program imports nothing",
    "A program has to ask Windows for everything it does. One that imports no function at all finds them by itself when it runs, which is what packed programs and shellcode loaders do.",
    |facts, _| (runs_native_code(facts) && facts.import_count() == 0).then(|| "the import table is empty or missing".to_owned());

    "imports.few", Imports, 0,
    "The program imports five functions or fewer",
    "Even a small program built by a compiler imports dozens of functions through its runtime library. A handful means that the real imports are resolved when the program runs.",
    |facts, _| {
        let count = facts.import_count();
        (runs_native_code(facts) && (1..=5).contains(&count)).then(|| format!("{count} imported functions"))
    };

    "imports.single_library", Imports, 0,
    "Everything the program imports comes from one library",
    "A program built by a compiler takes functions from several libraries: the C runtime, the user interface, the kernel. One library alone, usually the kernel's, is what a packed program or a program written in assembly imports.",
    |facts, _| {
        (runs_native_code(facts) && facts.imports.len() == 1 && facts.import_count() > 0)
            .then(|| format!("the only library is {:?}", facts.imports[0].name))
    };

    "imports.loader_only", Imports, 0,
    "The imports are little more than what is needed to load other functions",
    "LoadLibrary and GetProcAddress find any other function by name while the program runs. A program that imports those and almost nothing else is hiding what it uses. This is the import table a packer leaves behind.",
    |facts, _| {
        (runs_native_code(facts) && facts.import_count() <= 10)
            .then(|| imports_one_of_each(facts, &[LOAD_LIBRARY, &["GetProcAddress"]]))
            .flatten()
    };

    "imports.process_injection", Imports, 0,
    "The imports allow running code inside another process",
    "Writing into another process's memory and starting a thread there is how malware hides inside a trusted program. Debuggers and a few system tools do the same.",
    |facts, _| runs_native_code(facts).then(|| imports_one_of_each(facts, &[REMOTE_WRITE, REMOTE_THREAD])).flatten();

    "imports.process_hollowing", Imports, 0,
    "The imports allow replacing the code of another process",
    "Unmapping a suspended process's image, writing a different one and resuming it is known as process hollowing: the process keeps the name of a trusted program and runs something else.",
    |facts, _| {
        runs_native_code(facts)
            .then(|| imports_one_of_each(facts, &[UNMAP_SECTION, REMOTE_WRITE, SET_THREAD_CONTEXT, RESUME_THREAD]))
            .flatten()
    };

    "imports.remote_memory", Imports, 6,
    "The imports allow writing into the memory of another process",
    "Allocating memory in another process and writing to it is the first half of code injection. Debuggers, profilers and game trainers do it as well.",
    |facts, _| runs_native_code(facts).then(|| imports_one_of_each(facts, &[REMOTE_ALLOCATION, REMOTE_WRITE])).flatten();

    "imports.keyboard_hook", Imports, 0,
    "The imports allow watching the keyboard in other programs",
    "A system-wide hook together with reading key states is how a keylogger is built. Hotkey tools, screen readers and remote-control software use the same functions.",
    |facts, _| runs_native_code(facts).then(|| imports_one_of_each(facts, &[WINDOWS_HOOK, KEY_STATE])).flatten();

    "imports.debugger_checks", Imports, 0,
    "The program checks whether another process is being debugged",
    "CheckRemoteDebuggerPresent is used to notice analysis and behave differently under it. Copy protection uses it too.",
    |facts, _| runs_native_code(facts).then(|| imports_one_of_each(facts, &[&["CheckRemoteDebuggerPresent"]])).flatten();

    "imports.download_to_file", Imports, 5,
    "The program can download a file with a single call",
    "URLDownloadToFile fetches a file from the internet and stores it on disk. It is the shortest way to write a downloader, and rare in other software.",
    |facts, _| runs_native_code(facts).then(|| imports_one_of_each(facts, &[DOWNLOAD_TO_FILE])).flatten();

    "imports.winexec", Imports, 0,
    "The program starts other programs with WinExec",
    "Windows keeps WinExec only for programs written for 16-bit Windows; everything since is meant to use CreateProcess. It survives in code that was written by hand or copied from old examples, which describes a lot of small malware, and in old clean software.",
    |facts, _| runs_native_code(facts).then(|| imports_one_of_each(facts, &[&["WinExec"]])).flatten();

    "imports.token_privileges", Imports, 0,
    "The program can switch on privileges for itself",
    "Looking up and enabling a privilege is how a program gets the right to debug other processes or to shut the system down. Administration tools and installers do it for good reasons.",
    |facts, _| {
        runs_native_code(facts)
            .then(|| imports_one_of_each(facts, &[&["AdjustTokenPrivileges"], LOOKUP_PRIVILEGE]))
            .flatten()
    };

    "imports.process_listing", Imports, 0,
    "The program can list the running processes",
    "Walking the process list is how malware looks for a process to inject into, or for security tools to stop. Task managers and installers that close a running copy of a program do it too.",
    |facts, _| {
        runs_native_code(facts)
            .then(|| imports_one_of_each(facts, &[&["CreateToolhelp32Snapshot"], PROCESS_FIRST, PROCESS_NEXT]))
            .flatten()
    };

    "imports.creates_service", Imports, 0,
    "The program can install a Windows service",
    "A service starts with Windows and runs without a user. Malware installs one to stay on a machine, and so does every driver installer.",
    |facts, _| runs_native_code(facts).then(|| imports_one_of_each(facts, &[CREATE_SERVICE])).flatten();

    // ---- Header ----------------------------------------------------------
    "header.no_aslr", Header, 0,
    "The image cannot be moved in memory (no ASLR)",
    "Current linkers mark images as movable unless told otherwise, so that an attacker cannot know where they are loaded. A file without the mark was built with old tools, or by a packer or a builder that does not bother.",
    |facts, _| (facts.image_flags & image_flags::DYNAMIC_BASE == 0).then(|| "the header does not set the flag for address space layout randomisation".to_owned());

    "header.no_dep", Header, 0,
    "Data in the image may be run as code (no DEP)",
    "Current linkers mark images as compatible with data execution prevention unless told otherwise. Without the mark, a 32-bit program may run code from its data, which self-modifying code needs.",
    |facts, _| (facts.image_flags & image_flags::NX_COMPAT == 0).then(|| "the header does not set the flag for data execution prevention".to_owned());

    "header.timestamp_zero", Header, 0,
    "The link time in the header is zero",
    "The field was wiped. Some build tools do that to make builds repeatable; some malware builders do it to hide when a sample was made.",
    |facts, _| (facts.timestamp == 0).then(|| "the header gives no link time".to_owned());

    "header.timestamp_in_future", Header, 0,
    "The link time in the header is in the future",
    "The field does not hold a real time. Microsoft's linker writes a hash there in repeatable builds, which is as likely to look like a future date as a past one, so this is common in clean files. It is also what a forged date looks like.",
    |facts, context| {
        (u64::from(facts.timestamp) > context.now_unix_secs.saturating_add(DAY_SECS))
            .then(|| format!("the header gives {} seconds since 1970 as the link time", facts.timestamp))
    };

    "header.timestamp_before_2000", Header, 0,
    "The link time in the header is before the year 2000",
    "Either the file is very old or the field does not hold a real time. Delphi writes the same date in 1992 into every program it builds.",
    |facts, _| {
        (facts.timestamp != 0 && facts.timestamp < YEAR_2000)
            .then(|| format!("the header gives {} seconds since 1970 as the link time", facts.timestamp))
    };

    "header.no_checksum", Header, 5,
    "The header holds no checksum",
    "Windows checks the field only for drivers, and most linkers leave it empty unless asked. Software from large vendors usually has it.",
    |facts, _| (facts.checksum == 0).then(|| "the checksum field is zero".to_owned());

    "header.no_rich_header", Header, 0,
    "The file has no Rich header",
    "Microsoft's linker records the tools that built a file in an undocumented header. A file without it was built with another toolchain, such as MinGW, Go, Rust or Delphi, or the header was removed.",
    |facts, _| (!facts.is_dotnet() && !facts.has_rich_header).then(|| "no Rich header between the DOS program and the PE header".to_owned());

    "tables.no_resources", Header, 4,
    "The program has no resources",
    "Icons, version information and the manifest are resources, and a program built for users has them. Command-line tools often do not, and neither does malware that is never meant to be looked at.",
    |facts, _| (!facts.is_dll && !facts.has_directory(Directory::Resource)).then(|| "the header points to no resource table".to_owned());

    "tables.no_debug", Header, 0,
    "The file has no debug table",
    "Microsoft's linker usually writes a small table that says where debug information can be found, into release builds too. Other toolchains often write none, and packers drop it.",
    |facts, _| (!facts.has_directory(Directory::Debug)).then(|| "the header points to no debug table".to_owned());

    "tables.tls", Header, 0,
    "The file uses thread-local storage",
    "The table for thread-local storage can name functions that Windows runs before the entry point, which is a way to run code before a debugger stops. Most files that have the table use it for ordinary thread-local variables.",
    |facts, _| facts.has_directory(Directory::Tls).then(|| "the header points to a thread-local storage table".to_owned());

    "tables.no_relocations", Header, 0,
    "The program has no relocation table",
    "Without the table Windows cannot move the program in memory. Old linkers left it out of programs; current ones keep it.",
    |facts, _| (!facts.is_dll && !facts.has_directory(Directory::BaseRelocation)).then(|| "the header points to no relocation table".to_owned());

    "signature.none", Header, 0,
    "The file has no embedded signature",
    "Most malware is not signed. Neither is most open-source software, and Windows itself signs its system files in separate catalogues, so their files have no embedded signature either. Whether a signature that is there is valid is not checked.",
    |facts, _| (facts.signature_size == 0).then(|| "the header points to no signature".to_owned());
];

/// Every indicator, in the order they are evaluated and shown.
pub fn all() -> impl Iterator<Item = &'static Indicator> {
    DEFINITIONS.iter().map(|definition| &definition.indicator)
}

/// The indicator with this identifier.
#[must_use]
pub fn by_id(id: &str) -> Option<&'static Indicator> {
    all().find(|indicator| indicator.id == id)
}

/// Asks every indicator about a file and returns those that apply.
#[must_use]
pub fn evaluate(facts: &PeFacts, context: &Context) -> Vec<Hit> {
    DEFINITIONS
        .iter()
        .filter_map(|definition| {
            (definition.check)(facts, context).map(|detail| Hit {
                indicator: &definition.indicator,
                detail,
            })
        })
        .collect()
}

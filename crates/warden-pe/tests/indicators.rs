//! Every indicator, tried on a fixture that was built to have what the
//! indicator looks for, and on one that was built not to.
//!
//! The fixtures are inert: see `warden_pe::fixture`.

#![allow(clippy::unwrap_used)]

use std::collections::BTreeSet;

use warden_pe::fixture::{Filler, Fixture, FixtureImport, FixtureSection};
use warden_pe::indicators::{self, Context, evaluate};
use warden_pe::{Directory, Group, PeFacts, read, section_flags};

/// 2025-06-01, a few months after the link time of the plain fixture.
const NOW: Context = Context {
    now_unix_secs: 1_748_736_000,
};

fn facts_of(fixture: &Fixture) -> PeFacts {
    read(&fixture.build()).unwrap()
}

fn hits_of(fixture: &Fixture) -> BTreeSet<&'static str> {
    evaluate(&facts_of(fixture), &NOW)
        .into_iter()
        .map(|hit| hit.indicator.id)
        .collect()
}

fn names(list: &[&str]) -> Vec<FixtureImport> {
    list.iter()
        .map(|name| FixtureImport::Name((*name).to_owned()))
        .collect()
}

/// The plain fixture with other imports from one library.
fn importing(functions: &[&str]) -> Fixture {
    let mut fixture = Fixture::plain();
    fixture.imports = vec![("KERNEL32.dll".to_owned(), names(functions))];
    fixture
}

/// Asserts that `changed` has the indicator and the plain fixture has not.
#[track_caller]
fn only_after_the_change(id: &str, changed: &Fixture) {
    assert!(
        indicators::by_id(id).is_some(),
        "there is no indicator {id}"
    );
    assert!(
        !hits_of(&Fixture::plain()).contains(id),
        "{id} applies to the plain fixture"
    );
    let hits = hits_of(changed);
    assert!(hits.contains(id), "{id} is missing from {hits:?}");
}

#[test]
fn an_ordinary_program_has_almost_nothing_to_show() {
    // No embedded signature and no checksum: true of most programs that
    // are not from a large vendor.
    assert_eq!(
        hits_of(&Fixture::plain()),
        BTreeSet::from(["header.no_checksum", "signature.none"])
    );
}

#[test]
fn a_packed_looking_program_shows_what_a_packer_leaves_behind() {
    let hits = hits_of(&Fixture::packed_looking());
    for expected in [
        "sections.packer_name",
        "sections.writable_and_executable",
        "sections.code_without_file_data",
        "sections.high_entropy_code",
        "sections.no_standard_name",
        "file.high_entropy",
        "entry.not_in_first_section",
        "entry.in_writable_section",
        "imports.few",
        "imports.single_library",
        "imports.loader_only",
        "header.no_aslr",
        "header.no_dep",
        "header.timestamp_zero",
        "header.no_rich_header",
        "tables.no_resources",
        "tables.no_debug",
        "tables.no_relocations",
    ] {
        assert!(
            hits.contains(expected),
            "{expected} is missing from {hits:?}"
        );
    }
    // What a hit says is specific to the file.
    let facts = facts_of(&Fixture::packed_looking());
    let hits = evaluate(&facts, &NOW);
    let detail = |id: &str| {
        hits.iter()
            .find(|hit| hit.indicator.id == id)
            .map(|hit| hit.detail.clone())
            .unwrap()
    };
    assert_eq!(
        detail("sections.packer_name"),
        r#"sections "UPX0", "UPX1", "UPX2""#
    );
    assert_eq!(
        detail("sections.code_without_file_data"),
        r#"section "UPX0""#
    );
    assert!(
        detail("sections.high_entropy_code").starts_with(r#"section "UPX1" has an entropy of 7.9"#)
    );
    assert_eq!(
        detail("entry.in_writable_section"),
        r#"the entry point is in section "UPX1", which is writable"#
    );
    assert_eq!(detail("imports.few"), "3 imported functions");
    assert_eq!(
        detail("imports.loader_only"),
        "imports LoadLibraryA and GetProcAddress"
    );
}

#[test]
fn packing_indicators() {
    let mut filler = Filler::new(11);

    let mut fixture = Fixture::plain();
    fixture.sections[0].name = ".vmp0".to_owned();
    only_after_the_change("sections.packer_name", &fixture);

    let mut fixture = Fixture::plain();
    fixture.sections[0].characteristics |= section_flags::WRITE;
    only_after_the_change("sections.writable_and_executable", &fixture);
    only_after_the_change("entry.in_writable_section", &fixture);

    let mut fixture = Fixture::plain();
    fixture.sections.insert(
        1,
        FixtureSection::code(".stub", Vec::new()).with_virtual_size(0x4000),
    );
    only_after_the_change("sections.code_without_file_data", &fixture);

    let mut fixture = Fixture::plain();
    fixture.sections[0].virtual_size = Some(0x3000 * 4);
    only_after_the_change("sections.code_mostly_in_memory", &fixture);
    fixture.sections[0].virtual_size = Some(0x3000 * 4 - 1);
    assert!(!hits_of(&fixture).contains("sections.code_mostly_in_memory"));

    let mut fixture = Fixture::plain();
    fixture.sections[0].data = filler.packed(0x3000);
    only_after_the_change("sections.high_entropy_code", &fixture);

    let mut fixture = Fixture::plain();
    fixture.sections[1].data = filler.packed(0x3000);
    only_after_the_change("sections.high_entropy_data", &fixture);
    // Compressed images in the resource section are normal.
    let mut fixture = Fixture::plain();
    fixture.sections[3].data = filler.packed(0x3000);
    assert!(!hits_of(&fixture).contains("sections.high_entropy_data"));
    // A few evenly spread bytes say nothing.
    let mut fixture = Fixture::plain();
    fixture.sections[1].data = filler.packed(0x200);
    assert!(!hits_of(&fixture).contains("sections.high_entropy_data"));

    let mut fixture = Fixture::plain();
    for (index, section) in fixture.sections.iter_mut().enumerate() {
        section.name = format!("s{index}");
    }
    fixture.imports.clear();
    only_after_the_change("sections.no_standard_name", &fixture);
    // MinGW's numbered debug sections are standard names.
    let mut fixture = Fixture::plain();
    fixture.sections[4].name = "/19".to_owned();
    assert!(!hits_of(&fixture).contains("sections.no_standard_name"));

    let mut fixture = Fixture::plain();
    fixture.sections[1].data = filler.packed(0x40000);
    only_after_the_change("file.high_entropy", &fixture);

    let mut fixture = Fixture::plain();
    fixture.overlay = filler.data_like(0x8000);
    only_after_the_change("overlay.large_unsigned", &fixture);
    assert!(!hits_of(&fixture).contains("overlay.high_entropy"));
    fixture.overlay = filler.packed(0x8000);
    only_after_the_change("overlay.high_entropy", &fixture);
    // A signature is in the same place and is not an overlay to judge.
    let mut fixture = Fixture::plain();
    fixture.signature_len = 0x8000;
    let hits = hits_of(&fixture);
    assert!(!hits.contains("overlay.large_unsigned"), "{hits:?}");
    assert!(!hits.contains("overlay.high_entropy"), "{hits:?}");
    assert!(!hits.contains("signature.none"), "{hits:?}");
}

#[test]
fn layout_indicators() {
    let mut fixture = Fixture::plain();
    fixture.imports.clear();
    fixture.entry = Some((4, 0));
    only_after_the_change("entry.not_in_first_section", &fixture);
    only_after_the_change("entry.in_last_section", &fixture);
    only_after_the_change("entry.in_non_executable_section", &fixture);
    let facts = facts_of(&fixture);
    let hits = evaluate(&facts, &NOW);
    let last = hits
        .iter()
        .find(|hit| hit.indicator.id == "entry.in_last_section")
        .unwrap();
    assert_eq!(
        last.detail,
        r#"the entry point is in section ".reloc", the last of 5"#
    );

    // An entry point that no section contains: patched into the built file.
    let mut file = Fixture::plain().build();
    let optional = 0xa8 + 24;
    file[optional + 16..optional + 20].copy_from_slice(&0x200u32.to_le_bytes());
    let hits: BTreeSet<&str> = evaluate(&read(&file).unwrap(), &NOW)
        .into_iter()
        .map(|hit| hit.indicator.id)
        .collect();
    assert!(hits.contains("entry.outside_sections"), "{hits:?}");

    // A file cut short.
    let file = Fixture::plain().build();
    let hits: BTreeSet<&str> = evaluate(&read(&file[..0x2000]).unwrap(), &NOW)
        .into_iter()
        .map(|hit| hit.indicator.id)
        .collect();
    assert!(hits.contains("sections.beyond_file"), "{hits:?}");
}

#[test]
fn import_indicators() {
    let mut fixture = Fixture::plain();
    fixture.imports.clear();
    only_after_the_change("imports.none", &fixture);

    only_after_the_change("imports.few", &importing(&["ExitProcess", "Sleep"]));
    only_after_the_change(
        "imports.single_library",
        &importing(&[
            "ExitProcess",
            "Sleep",
            "GetLastError",
            "CloseHandle",
            "ReadFile",
            "WriteFile",
        ]),
    );

    only_after_the_change(
        "imports.loader_only",
        &importing(&["LoadLibraryW", "GetProcAddress", "VirtualProtect"]),
    );
    only_after_the_change(
        "imports.process_injection",
        &importing(&[
            "OpenProcess",
            "WriteProcessMemory",
            "CreateRemoteThread",
            "CloseHandle",
            "Sleep",
            "ExitProcess",
        ]),
    );
    only_after_the_change(
        "imports.remote_memory",
        &importing(&[
            "VirtualAllocEx",
            "WriteProcessMemory",
            "CloseHandle",
            "Sleep",
            "ExitProcess",
            "OpenProcess",
        ]),
    );
    only_after_the_change(
        "imports.process_hollowing",
        &importing(&[
            "CreateProcessW",
            "NtUnmapViewOfSection",
            "WriteProcessMemory",
            "SetThreadContext",
            "ResumeThread",
            "ExitProcess",
        ]),
    );
    only_after_the_change(
        "imports.keyboard_hook",
        &importing(&[
            "SetWindowsHookExW",
            "GetAsyncKeyState",
            "CallNextHookEx",
            "GetMessageW",
            "ExitProcess",
            "Sleep",
        ]),
    );
    only_after_the_change(
        "imports.debugger_checks",
        &importing(&[
            "CheckRemoteDebuggerPresent",
            "GetCurrentProcess",
            "ExitProcess",
            "Sleep",
            "CloseHandle",
            "GetLastError",
        ]),
    );
    only_after_the_change(
        "imports.download_to_file",
        &importing(&[
            "URLDownloadToFileW",
            "ShellExecuteW",
            "ExitProcess",
            "Sleep",
            "CloseHandle",
            "GetLastError",
        ]),
    );
    only_after_the_change(
        "imports.winexec",
        &importing(&[
            "WinExec",
            "ExitProcess",
            "Sleep",
            "CloseHandle",
            "GetLastError",
            "GetTickCount",
        ]),
    );
    only_after_the_change(
        "imports.token_privileges",
        &importing(&[
            "OpenProcessToken",
            "LookupPrivilegeValueW",
            "AdjustTokenPrivileges",
            "ExitProcess",
            "Sleep",
            "CloseHandle",
        ]),
    );
    only_after_the_change(
        "imports.process_listing",
        &importing(&[
            "CreateToolhelp32Snapshot",
            "Process32FirstW",
            "Process32NextW",
            "CloseHandle",
            "ExitProcess",
            "Sleep",
        ]),
    );
    only_after_the_change(
        "imports.creates_service",
        &importing(&[
            "OpenSCManagerW",
            "CreateServiceW",
            "CloseServiceHandle",
            "ExitProcess",
            "Sleep",
            "CloseHandle",
        ]),
    );

    // Half of a combination is not the combination.
    let hits = hits_of(&importing(&[
        "WriteProcessMemory",
        "ReadProcessMemory",
        "OpenProcess",
        "CloseHandle",
        "ExitProcess",
        "Sleep",
    ]));
    assert!(!hits.contains("imports.process_injection"), "{hits:?}");
    assert!(!hits.contains("imports.remote_memory"), "{hits:?}");

    // Imports say nothing about a .NET assembly or about a library that
    // holds no code.
    let mut dotnet = importing(&["_CorExeMain"]);
    dotnet.directories.push(Directory::ClrHeader);
    let hits = hits_of(&dotnet);
    assert!(
        !hits.iter().any(|id| id.starts_with("imports.")),
        "{hits:?}"
    );
    assert!(!hits.contains("header.no_rich_header"));
    let mut resources_only = Fixture::plain();
    resources_only.dll = true;
    resources_only.entry = None;
    resources_only.imports.clear();
    let hits = hits_of(&resources_only);
    assert!(
        !hits.iter().any(|id| id.starts_with("imports.")),
        "{hits:?}"
    );
}

#[test]
fn header_indicators() {
    let mut fixture = Fixture::plain();
    fixture.image_flags = 0;
    only_after_the_change("header.no_aslr", &fixture);
    only_after_the_change("header.no_dep", &fixture);

    let mut fixture = Fixture::plain();
    fixture.timestamp = 0;
    only_after_the_change("header.timestamp_zero", &fixture);
    fixture.timestamp = 708_992_537; // what Delphi writes: a day in June 1992
    only_after_the_change("header.timestamp_before_2000", &fixture);
    assert!(!hits_of(&fixture).contains("header.timestamp_zero"));
    fixture.timestamp = (NOW.now_unix_secs + 3 * 86_400) as u32;
    only_after_the_change("header.timestamp_in_future", &fixture);
    // Clocks differ a little; a day ahead is not the future.
    fixture.timestamp = (NOW.now_unix_secs + 3_600) as u32;
    assert!(!hits_of(&fixture).contains("header.timestamp_in_future"));

    let mut fixture = Fixture::plain();
    fixture.checksum = 0x0001_2345;
    assert!(!hits_of(&fixture).contains("header.no_checksum"));

    let mut fixture = Fixture::plain();
    fixture.rich_header = false;
    only_after_the_change("header.no_rich_header", &fixture);

    let mut fixture = Fixture::plain();
    fixture.directories.clear();
    only_after_the_change("tables.no_resources", &fixture);
    only_after_the_change("tables.no_debug", &fixture);
    only_after_the_change("tables.no_relocations", &fixture);
    // A library needs neither resources nor, by this rule, relocations.
    fixture.dll = true;
    let hits = hits_of(&fixture);
    assert!(!hits.contains("tables.no_resources") && !hits.contains("tables.no_relocations"));

    let mut fixture = Fixture::plain();
    fixture.directories.push(Directory::Tls);
    only_after_the_change("tables.tls", &fixture);
}

#[test]
fn the_list_of_indicators_is_well_formed() {
    let all: Vec<_> = indicators::all().collect();
    let ids: BTreeSet<&str> = all.iter().map(|indicator| indicator.id).collect();
    assert_eq!(ids.len(), all.len(), "an identifier is used twice");
    for indicator in &all {
        let (prefix, rest) = indicator.id.split_once('.').unwrap();
        assert!(!prefix.is_empty() && !rest.is_empty(), "{}", indicator.id);
        assert!(
            indicator.id.bytes().all(|byte| byte.is_ascii_lowercase()
                || byte == b'.'
                || byte == b'_'
                || byte.is_ascii_digit()),
            "{}",
            indicator.id
        );
        assert!(!indicator.summary.ends_with('.'), "{}", indicator.id);
        assert!(indicator.rationale.ends_with('.'), "{}", indicator.id);
        assert!(indicator.rationale.len() > 60, "{}", indicator.id);
        assert!(indicators::by_id(indicator.id).is_some());
    }
    // Every group is in use.
    for group in [Group::Packing, Group::Layout, Group::Imports, Group::Header] {
        assert!(
            all.iter().any(|indicator| indicator.group == group),
            "{group:?}"
        );
        assert!(!group.title().is_empty());
    }
    assert!(indicators::by_id("no.such_indicator").is_none());
}

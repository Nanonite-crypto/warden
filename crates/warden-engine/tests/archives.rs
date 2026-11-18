//! Zip scanning: members are found, and every limit holds.
//!
//! Nothing here is malware. "Threats" are harmless files whose hashes the
//! test registers in a throwaway signature database, plus the EICAR
//! antivirus test file, which only ever exists in memory in this file. The
//! "zip bombs" are small archives of zeros, scanned with limits turned far
//! down.

#![allow(clippy::unwrap_used)]

use std::io::{Cursor, Write};
use std::path::Path;
use std::sync::Arc;

use proptest::prelude::*;
use warden_engine::{
    ArchiveOptions, CancelToken, FileResult, HashDetector, NoObserver, PartialReason, ScanOptions,
    Scanner, Verdict, eicar,
};
use warden_sigdb::{Category, SigDb, SigDbBuilder};
use zip::CompressionMethod;
use zip::unstable::write::FileOptionsExt;
use zip::write::SimpleFileOptions;

/// Deterministic, harmless content that does not compress well.
fn fixture(seed: u8, len: usize) -> Vec<u8> {
    let mut state = u32::from(seed) + 1;
    (0..len)
        .map(|_| {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (state >> 24) as u8
        })
        .collect()
}

fn zip_with(method: CompressionMethod, members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options = SimpleFileOptions::default().compression_method(method);
    for (name, bytes) in members {
        writer.start_file(*name, options).unwrap();
        writer.write_all(bytes).unwrap();
    }
    writer.finish().unwrap().into_inner()
}

fn zip_of(members: &[(&str, &[u8])]) -> Vec<u8> {
    zip_with(CompressionMethod::Deflated, members)
}

/// A harmless file that the scanner below treats as a threat.
fn threat() -> Vec<u8> {
    fixture(200, 300)
}

fn scanner_with(archives: ArchiveOptions) -> Scanner {
    let mut builder = SigDbBuilder::new();
    builder
        .add(
            warden_engine::sha256(&threat()),
            "Test.Packed",
            Category::Malware,
        )
        .unwrap();
    let database = Arc::new(SigDb::from_bytes(builder.build().unwrap().0).unwrap());
    Scanner::builder()
        .detector(HashDetector::with_database(database))
        .options(ScanOptions {
            archives,
            ..ScanOptions::default()
        })
        .build()
}

fn scanner() -> Scanner {
    scanner_with(ArchiveOptions::default())
}

fn reasons(result: &FileResult) -> Vec<PartialReason> {
    result
        .partial
        .iter()
        .map(|partial| partial.reason)
        .collect()
}

fn detail(result: &FileResult, reason: PartialReason) -> &str {
    &result
        .partial
        .iter()
        .find(|partial| partial.reason == reason)
        .unwrap()
        .detail
}

#[test]
fn eicar_inside_a_zip_is_found_and_the_finding_says_where() {
    let archive = zip_of(&[
        ("readme.txt", b"nothing to see here"),
        ("tools/eicar.com", &eicar::test_file()),
    ]);
    let result = scanner().scan_bytes(&archive);

    assert_eq!(result.verdict, Verdict::Malicious);
    assert!(result.unpacked);
    assert_eq!(result.members_scanned, 2);
    assert_eq!(result.member_bytes, 19 + 68);
    assert!(result.partial.is_empty());

    assert_eq!(result.findings.len(), 1);
    let finding = &result.findings[0];
    assert_eq!(finding.name, eicar::DETECTION_NAME);
    let member = finding.member.as_ref().unwrap();
    assert_eq!(member.path, ["tools/eicar.com"]);
    assert_eq!(member.size, 68);
    assert_eq!(member.sha256, eicar::SHA256_HEX);
    // The archive itself is what was scanned, so the result carries its hash.
    assert_eq!(result.sha256, warden_engine::sha256(&archive));
}

#[test]
fn members_that_are_stored_without_compression_are_checked_too() {
    let archive = zip_with(CompressionMethod::Stored, &[("plain.bin", &threat())]);
    let result = scanner().scan_bytes(&archive);
    assert_eq!(result.verdict, Verdict::Malicious);
    assert_eq!(
        result.findings[0].member.as_ref().unwrap().path,
        ["plain.bin"]
    );
}

#[test]
fn a_clean_archive_is_clean_and_fully_scanned() {
    let archive = zip_of(&[("a.txt", b"alpha"), ("dir/b.txt", b"beta")]);
    let result = scanner().scan_bytes(&archive);
    assert_eq!(result.verdict, Verdict::Clean);
    assert!(result.findings.is_empty());
    assert!(result.partial.is_empty());
    assert_eq!(result.members_scanned, 2);
}

#[test]
fn archives_inside_archives_are_followed_to_the_depth_limit() {
    let innermost = zip_of(&[("payload.bin", &threat())]);
    let middle = zip_of(&[("innermost.zip", &innermost)]);
    let outer = zip_of(&[("middle.zip", &middle)]);

    // Three archives deep is within the default limit of three.
    let result = scanner().scan_bytes(&outer);
    assert_eq!(result.verdict, Verdict::Malicious);
    assert_eq!(
        result.findings[0].member.as_ref().unwrap().path,
        ["middle.zip", "innermost.zip", "payload.bin"]
    );
    assert_eq!(result.members_scanned, 3);
    assert!(result.partial.is_empty());

    // With a limit of two, the innermost archive is checked as a file but
    // not opened, and the report says so.
    let shallow = scanner_with(ArchiveOptions {
        max_depth: 2,
        ..ArchiveOptions::default()
    });
    let result = shallow.scan_bytes(&outer);
    assert_eq!(result.verdict, Verdict::Clean);
    assert_eq!(result.members_scanned, 2);
    assert_eq!(reasons(&result), [PartialReason::ArchiveLimit]);
    let detail = detail(&result, PartialReason::ArchiveLimit);
    assert!(detail.contains("middle.zip > innermost.zip"), "{detail}");
    assert!(detail.contains("nested more than 2 deep"), "{detail}");

    // With a limit of one, only the outer archive is opened.
    let flat = scanner_with(ArchiveOptions {
        max_depth: 1,
        ..ArchiveOptions::default()
    });
    assert_eq!(flat.scan_bytes(&outer).members_scanned, 1);
}

#[test]
fn switching_archives_off_leaves_them_unopened() {
    let archive = zip_of(&[("payload.bin", &threat())]);
    for archives in [
        ArchiveOptions {
            enabled: false,
            ..ArchiveOptions::default()
        },
        ArchiveOptions {
            max_depth: 0,
            ..ArchiveOptions::default()
        },
    ] {
        let result = scanner_with(archives).scan_bytes(&archive);
        assert_eq!(result.verdict, Verdict::Clean);
        assert!(!result.unpacked);
        assert_eq!(result.members_scanned, 0);
        assert!(result.partial.is_empty());
    }
}

#[test]
fn the_member_limit_counts_every_entry_at_every_level() {
    let names: Vec<String> = (0..20)
        .map(|index| format!("file-{index:02}.bin"))
        .collect();
    let clean = fixture(1, 64);
    let threat = threat();
    let members: Vec<(&str, &[u8])> = names
        .iter()
        .enumerate()
        .map(|(index, name)| {
            let bytes: &[u8] = if index == 2 || index == 15 {
                &threat
            } else {
                &clean
            };
            (name.as_str(), bytes)
        })
        .collect();
    let archive = zip_of(&members);

    let limited = scanner_with(ArchiveOptions {
        max_members: 5,
        ..ArchiveOptions::default()
    });
    let result = limited.scan_bytes(&archive);

    // The third member was reached, the sixteenth was not.
    assert_eq!(result.members_scanned, 5);
    assert_eq!(result.findings.len(), 1);
    assert_eq!(
        result.findings[0].member.as_ref().unwrap().path,
        ["file-02.bin"]
    );
    assert_eq!(reasons(&result), [PartialReason::ArchiveLimit]);
    assert!(detail(&result, PartialReason::ArchiveLimit).contains("more than 5 archive members"));

    // Without the limit both are found.
    assert_eq!(scanner().scan_bytes(&archive).findings.len(), 2);
}

#[test]
fn a_member_over_the_size_limit_is_reported_and_the_rest_is_still_checked() {
    let big = fixture(3, 300_000);
    let archive = zip_of(&[("big.bin", &big), ("small.bin", &threat())]);
    let limited = scanner_with(ArchiveOptions {
        max_member_bytes: 100_000,
        ..ArchiveOptions::default()
    });
    let result = limited.scan_bytes(&archive);

    assert_eq!(result.verdict, Verdict::Malicious);
    assert_eq!(result.members_scanned, 1);
    assert_eq!(reasons(&result), [PartialReason::ArchiveLimit]);
    let detail = detail(&result, PartialReason::ArchiveLimit);
    assert!(
        detail.starts_with("big.bin unpacks to more than 100000 bytes"),
        "{detail}"
    );
}

#[test]
fn unpacking_stops_at_the_total_size_limit() {
    let block = fixture(4, 400_000);
    let archive = zip_of(&[
        ("1.bin", &block),
        ("2.bin", &block),
        ("3.bin", &block),
        ("4.bin", &block),
        ("late.bin", &threat()),
    ]);
    let limited = scanner_with(ArchiveOptions {
        max_total_bytes: 1_000_000,
        ..ArchiveOptions::default()
    });
    let result = limited.scan_bytes(&archive);

    // Two blocks fit into a megabyte; the third does not, and nothing after
    // it is unpacked.
    assert_eq!(result.members_scanned, 2);
    assert_eq!(result.member_bytes, 800_000);
    assert_eq!(result.verdict, Verdict::Clean);
    assert_eq!(reasons(&result), [PartialReason::ArchiveLimit]);
    let detail = detail(&result, PartialReason::ArchiveLimit);
    assert!(
        detail.starts_with("3.bin would take the unpacked total past 1000000 bytes"),
        "{detail}"
    );
}

#[test]
fn a_member_that_expands_too_much_is_stopped_by_the_ratio_limit() {
    // Eight mebibytes of zeros pack to a few kilobytes: about 1000 to 1.
    let zeros = vec![0u8; 8 * 1024 * 1024];
    // Half a mebibyte of zeros has the same ratio, but is too small for the
    // limit to care about.
    let small_zeros = vec![0u8; 512 * 1024];
    let archive = zip_of(&[
        ("zeros.bin", &zeros),
        ("small-zeros.bin", &small_zeros),
        ("after.bin", &threat()),
    ]);
    let packed_size = archive.len();
    assert!(
        packed_size < 64 * 1024,
        "the fixture should be tiny: {packed_size}"
    );

    let result = scanner().scan_bytes(&archive);

    assert_eq!(result.verdict, Verdict::Malicious);
    assert_eq!(result.members_scanned, 2);
    assert_eq!(reasons(&result), [PartialReason::ArchiveLimit]);
    let detail = detail(&result, PartialReason::ArchiveLimit);
    assert!(
        detail.starts_with("zeros.bin unpacks to more than 250 times its packed size"),
        "{detail}"
    );
}

/// A recursive zip bomb in miniature: every level holds ten copies of the
/// level below, and the bottom is a mebibyte of zeros. Four levels would
/// unpack to a gibibyte from a few kilobytes.
#[test]
fn a_nested_bomb_is_cut_off_by_the_budget_for_the_whole_file() {
    let mut level = vec![0u8; 1024 * 1024];
    for _ in 0..4 {
        let names: Vec<String> = (0..10).map(|index| format!("{index}.zip")).collect();
        let members: Vec<(&str, &[u8])> = names
            .iter()
            .map(|name| (name.as_str(), level.as_slice()))
            .collect();
        level = zip_of(&members);
    }
    let bomb = level;
    assert!(
        bomb.len() < 16 * 1024,
        "the bomb should be tiny: {}",
        bomb.len()
    );

    let limited = scanner_with(ArchiveOptions {
        max_depth: 8,
        max_members: 200,
        max_total_bytes: 20 * 1024 * 1024,
        ..ArchiveOptions::default()
    });
    let started = std::time::Instant::now();
    let result = limited.scan_bytes(&bomb);

    assert_eq!(result.verdict, Verdict::Clean);
    assert!(result.members_scanned <= 200);
    assert!(result.member_bytes <= 20 * 1024 * 1024);
    assert_eq!(reasons(&result), [PartialReason::ArchiveLimit]);
    // Every nesting level runs into the same limit, and the report says so
    // once, not once per level.
    let detail = detail(&result, PartialReason::ArchiveLimit);
    assert!(!detail.contains("; "), "{detail}");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(20),
        "limits should keep this quick, took {:?}",
        started.elapsed()
    );
}

/// Repeats the one directory entry of `archive`, so that `copies` entries
/// all point at the same packed data.
fn with_repeated_entry(archive: &[u8], copies: u16) -> Vec<u8> {
    // The end record is the last 22 bytes: these archives have no comment.
    let end = archive.len() - 22;
    assert_eq!(&archive[end..end + 4], b"PK\x05\x06");
    let size = u32::from_le_bytes(archive[end + 12..end + 16].try_into().unwrap());
    let start = u32::from_le_bytes(archive[end + 16..end + 20].try_into().unwrap());
    let entry = &archive[start as usize..(start + size) as usize];

    let mut repeated = archive[..start as usize].to_vec();
    for _ in 0..copies {
        repeated.extend_from_slice(entry);
    }
    repeated.extend_from_slice(b"PK\x05\x06\0\0\0\0");
    repeated.extend_from_slice(&copies.to_le_bytes());
    repeated.extend_from_slice(&copies.to_le_bytes());
    repeated.extend_from_slice(&(size * u32::from(copies)).to_le_bytes());
    repeated.extend_from_slice(&start.to_le_bytes());
    repeated.extend_from_slice(&0u16.to_le_bytes());
    repeated
}

/// The most compact zip bombs neither nest nor need an extreme ratio: their
/// directory lists the same packed data again and again. The overlap is not
/// detected as such. Every entry is unpacked as a member of its own, and
/// the budget for the whole file puts an end to it.
#[test]
fn directory_entries_that_share_their_data_are_stopped_by_the_total_limit() {
    let block = vec![0u8; 256 * 1024];
    let single = zip_of(&[("block.bin", &block)]);
    // 2,000 entries claim 500 MiB between them.
    let archive = with_repeated_entry(&single, 2000);
    assert!(archive.len() < 200 * 1024, "{}", archive.len());

    let limited = scanner_with(ArchiveOptions {
        max_total_bytes: 4 * 1024 * 1024,
        ..ArchiveOptions::default()
    });
    let result = limited.scan_bytes(&archive);

    // Sixteen blocks fill the four mebibytes. The seventeenth is refused.
    assert_eq!(result.members_scanned, 16);
    assert_eq!(result.member_bytes, 4 * 1024 * 1024);
    assert_eq!(result.verdict, Verdict::Clean);
    assert_eq!(reasons(&result), [PartialReason::ArchiveLimit]);
    let detail = detail(&result, PartialReason::ArchiveLimit);
    assert!(
        detail.starts_with("block.bin would take the unpacked total past 4194304 bytes"),
        "{detail}"
    );
}

#[test]
fn password_protected_members_are_reported_and_the_rest_is_checked() {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let plain = SimpleFileOptions::default();
    for name in ["secret-1.bin", "secret-2.bin"] {
        writer
            .start_file(name, plain.with_deprecated_encryption(b"infected").unwrap())
            .unwrap();
        writer.write_all(&threat()).unwrap();
    }
    writer.start_file("open.bin", plain).unwrap();
    writer.write_all(&threat()).unwrap();
    let archive = writer.finish().unwrap().into_inner();

    let result = scanner().scan_bytes(&archive);

    // Only the readable copy is found; the locked ones are named.
    assert_eq!(result.findings.len(), 1);
    assert_eq!(
        result.findings[0].member.as_ref().unwrap().path,
        ["open.bin"]
    );
    assert_eq!(reasons(&result), [PartialReason::EncryptedArchive]);
    assert_eq!(
        detail(&result, PartialReason::EncryptedArchive),
        "secret-1.bin is password-protected; secret-2.bin is password-protected"
    );
}

/// Rewrites the compression method in every local and central header.
fn with_method(mut archive: Vec<u8>, method: u16) -> Vec<u8> {
    for (signature, offset) in [(b"PK\x03\x04", 8), (b"PK\x01\x02", 10)] {
        let mut from = 0;
        while let Some(found) = archive[from..]
            .windows(4)
            .position(|window| window == signature)
        {
            let at = from + found + offset;
            archive[at..at + 2].copy_from_slice(&method.to_le_bytes());
            from = from + found + 4;
        }
    }
    archive
}

#[test]
fn a_member_packed_with_an_unknown_method_is_reported() {
    let stored = zip_with(
        CompressionMethod::Stored,
        &[("odd.bin", b"plain content, no magic")],
    );
    // Method 12 is bzip2, which this build does not unpack.
    let archive = with_method(stored, 12);
    let result = scanner().scan_bytes(&archive);

    assert_eq!(result.members_scanned, 0);
    assert_eq!(reasons(&result), [PartialReason::UnsupportedCompression]);
    assert!(
        detail(&result, PartialReason::UnsupportedCompression)
            .starts_with("odd.bin is packed with a method that cannot be unpacked")
    );
}

#[test]
fn a_truncated_archive_is_reported_as_damaged() {
    let archive = zip_of(&[("a.bin", &fixture(5, 4000)), ("b.bin", &threat())]);
    let truncated = &archive[..archive.len() / 2];
    let result = scanner().scan_bytes(truncated);

    assert_eq!(result.verdict, Verdict::Clean);
    assert_eq!(reasons(&result), [PartialReason::DamagedArchive]);
    assert!(
        detail(&result, PartialReason::DamagedArchive).starts_with("not a readable zip archive")
    );
}

#[test]
fn a_member_with_a_broken_tail_is_reported_and_checked_as_far_as_it_unpacks() {
    let content = fixture(6, 50_000);
    let mut archive = zip_of(&[("broken.bin", &content), ("fine.bin", &threat())]);
    // Damage the packed data of the first member, well past its beginning.
    let middle = 30 + "broken.bin".len() + 20_000;
    for byte in &mut archive[middle..middle + 64] {
        *byte ^= 0xA5;
    }
    let result = scanner().scan_bytes(&archive);

    // The second member is untouched and still found.
    assert_eq!(result.verdict, Verdict::Malicious);
    assert_eq!(
        result.findings[0].member.as_ref().unwrap().path,
        ["fine.bin"]
    );
    assert_eq!(result.members_scanned, 2);
    // Whether the damage shows up while unpacking depends on where it lands
    // in the packed stream; when it does, it is reported.
    for partial in &result.partial {
        assert_eq!(partial.reason, PartialReason::DamagedArchive);
        assert!(partial.detail.starts_with("broken.bin is damaged"));
    }
}

#[test]
fn a_zip_behind_other_data_is_found_and_other_files_are_left_alone() {
    // A self-extracting archive is a program with a zip attached to it.
    let mut attached = b"MZ this stands in for a small program ".repeat(40);
    attached.extend_from_slice(&zip_of(&[("payload.bin", &threat())]));
    let result = scanner().scan_bytes(&attached);
    assert_eq!(result.verdict, Verdict::Malicious);
    assert_eq!(
        result.findings[0].member.as_ref().unwrap().path,
        ["payload.bin"]
    );

    // A file that merely contains the four signature bytes near its end is
    // not an archive, and nothing is reported about it.
    let mut lookalike = fixture(7, 5000);
    lookalike.extend_from_slice(b"PK\x05\x06");
    lookalike.extend_from_slice(&fixture(8, 40));
    let result = scanner().scan_bytes(&lookalike);
    assert!(!result.unpacked);
    assert!(result.partial.is_empty());
}

#[test]
fn hostile_member_names_are_made_safe_before_they_reach_a_report() {
    let archive = zip_of(&[
        ("../../outside.bin", &threat()),
        ("line\u{1b}[2Kbreak\n.bin", &threat()),
    ]);
    let result = scanner().scan_bytes(&archive);

    let paths: Vec<&str> = result
        .findings
        .iter()
        .map(|finding| finding.member.as_ref().unwrap().path[0].as_str())
        .collect();
    // Nothing is ever written to disk, so a name that climbs out of the
    // archive is only a name. Control characters are replaced.
    assert_eq!(
        paths,
        ["../../outside.bin", "line\u{fffd}[2Kbreak\u{fffd}.bin"]
    );
}

#[test]
fn only_the_strongest_hundred_findings_are_kept() {
    let names: Vec<String> = (0..150)
        .map(|index| format!("copy-{index:03}.bin"))
        .collect();
    let threat = threat();
    let members: Vec<(&str, &[u8])> = names
        .iter()
        .map(|name| (name.as_str(), threat.as_slice()))
        .collect();
    let result = scanner().scan_bytes(&zip_of(&members));

    assert_eq!(result.verdict, Verdict::Malicious);
    assert_eq!(result.members_scanned, 150);
    assert_eq!(result.findings.len(), 100);
    assert_eq!(result.findings_omitted, 50);
}

#[test]
fn archives_on_disk_are_unpacked_and_counted_in_the_report() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("bundle.zip"),
        zip_of(&[("docs/readme.txt", b"hello"), ("bin/tool.bin", &threat())]),
    )
    .unwrap();
    std::fs::write(dir.path().join("plain.txt"), b"not an archive").unwrap();

    let report = scanner()
        .scan(
            &[dir.path().to_path_buf()],
            &mut NoObserver,
            &CancelToken::new(),
        )
        .unwrap();

    assert_eq!(report.stats.files_scanned, 2);
    assert_eq!(report.stats.archives_unpacked, 1);
    assert_eq!(report.stats.archive_members_scanned, 2);
    assert_eq!(report.stats.archive_member_bytes, 5 + 300);
    assert_eq!(report.stats.detections, 1);

    // The detection is the file on disk; the finding names the member.
    let detection = &report.detections[0];
    assert!(detection.path.ends_with(Path::new("bundle.zip")));
    let member = detection.findings[0].member.as_ref().unwrap();
    assert_eq!(member.path, ["bin/tool.bin"]);

    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(
        json["detections"][0]["findings"][0]["member"]["path"],
        serde_json::json!(["bin/tool.bin"])
    );
    assert_eq!(json["detections"][0]["findings"][0]["member"]["size"], 300);
    assert_eq!(json["stats"]["archives_unpacked"], 1);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Whatever is done to an archive, scanning it ends with a result and
    /// stays inside the limits.
    #[test]
    fn damaged_archives_never_panic_or_exceed_the_limits(
        cut in 0usize..2000,
        flips in proptest::collection::vec((0usize..2000, any::<u8>()), 0..12),
    ) {
        let inner = zip_of(&[("deep.bin", &fixture(9, 700))]);
        let mut archive = zip_of(&[
            ("a.txt", b"some text that is long enough to be packed"),
            ("inner.zip", &inner),
            ("b.bin", &fixture(10, 900)),
        ]);
        for (position, value) in flips {
            let index = position % archive.len();
            archive[index] ^= value;
        }
        archive.truncate(archive.len().saturating_sub(cut % archive.len()));

        let limited = scanner_with(ArchiveOptions {
            max_members: 50,
            max_total_bytes: 100_000,
            ..ArchiveOptions::default()
        });
        let result = limited.scan_bytes(&archive);
        prop_assert!(result.members_scanned <= 50);
        prop_assert!(result.member_bytes <= 100_000);
    }
}

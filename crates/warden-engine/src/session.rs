//! One thread's working state for a [`Scanner`], and the logic that turns one
//! file, with everything packed inside it, into a [`FileResult`].

use std::collections::BTreeMap;
use std::io::{self, Cursor, Read};
use std::path::Path;

use sha2::Digest;
use zip::ZipReadOptions;
use zip::read::Config;
use zip::unstable::read::ZipIterable;

use crate::Sha256;
use crate::archive::{self, Budget, Cap, ZipHint};
use crate::detector::{DetectorError, FileView, Session};
use crate::file;
use crate::finding::{Finding, Member, Verdict};
use crate::report::{Partial, PartialReason, SkipReason};
use crate::scanner::Scanner;

/// Read size for files that are hashed without being buffered.
pub(crate) const STREAM_CHUNK_BYTES: usize = 256 * 1024;
/// Buffers larger than this are released after the file that needed them,
/// so one huge file does not pin memory for the rest of the scan.
const RETAINED_BUFFER_BYTES: usize = 8 * 1024 * 1024;
/// How many examples are kept for each reason a file was scanned in part.
const EXAMPLES_PER_REASON: usize = 3;
/// How many findings are kept for one file. An archive can hold thousands of
/// members that all match; the strongest findings are the ones that stay.
pub(crate) const MAX_FINDINGS_PER_FILE: usize = 100;

/// The outcome of checking one file or one in-memory buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileResult {
    /// Number of bytes read.
    pub size: u64,
    /// SHA-256 of those bytes.
    pub sha256: Sha256,
    /// The decision.
    pub verdict: Verdict,
    /// What the detectors found, in the file and in anything packed inside
    /// it. At most 100 are kept; when there are more, the strongest stay.
    pub findings: Vec<Finding>,
    /// Findings left out because there were more than 100. They were never
    /// stronger than the ones that were kept.
    pub findings_omitted: u64,
    /// What was not examined, and why. Empty when the file was checked in
    /// full.
    pub partial: Vec<Partial>,
    /// Whether the file was unpacked as an archive.
    pub unpacked: bool,
    /// Archive members that were unpacked and checked, at every nesting
    /// level.
    pub members_scanned: u64,
    /// Total size of those members after unpacking, in bytes.
    pub member_bytes: u64,
}

/// Everything gathered while one file is being checked.
#[derive(Default)]
struct Collected {
    findings: Vec<Finding>,
    findings_omitted: u64,
    notes: BTreeMap<PartialReason, Notes>,
    unpacked: bool,
    members_scanned: u64,
    member_bytes: u64,
}

#[derive(Default)]
struct Notes {
    count: u64,
    examples: Vec<String>,
}

impl Collected {
    /// Records that something could not be examined.
    fn note(&mut self, reason: PartialReason, detail: impl Into<String>) {
        let notes = self.notes.entry(reason).or_default();
        notes.count += 1;
        if notes.examples.len() < EXAMPLES_PER_REASON {
            notes.examples.push(detail.into());
        }
    }

    /// Keeps a finding, or, when the list is full, keeps it only in place of
    /// a weaker one. The verdict depends on the strongest finding, so the
    /// strongest findings must never be the ones dropped.
    fn find(&mut self, finding: Finding) {
        if self.findings.len() < MAX_FINDINGS_PER_FILE {
            self.findings.push(finding);
            return;
        }
        self.findings_omitted += 1;
        let weakest = self
            .findings
            .iter_mut()
            .min_by_key(|kept| kept.confidence)
            .filter(|kept| kept.confidence < finding.confidence);
        if let Some(weakest) = weakest {
            *weakest = finding;
        }
    }

    /// One entry per reason, with a few examples and a count of the rest.
    fn partial(notes: BTreeMap<PartialReason, Notes>) -> Vec<Partial> {
        notes
            .into_iter()
            .map(|(reason, notes)| {
                let mut detail = notes.examples.join("; ");
                let more = notes.count - notes.examples.len() as u64;
                if more > 0 {
                    detail.push_str(&format!("; and {more} more"));
                }
                Partial { reason, detail }
            })
            .collect()
    }
}

/// One thread's working state for a [`Scanner`]: a session for every
/// detector, and buffers that are reused from file to file.
///
/// Create one with [`Scanner::session`] to check many buffers or files from
/// the same thread without setting the detectors up again for each.
pub struct ScanSession<'s> {
    scanner: &'s Scanner,
    sessions: Vec<Box<dyn Session + 's>>,
    /// Content of the file being scanned.
    content: Vec<u8>,
    /// Scratch space for streaming reads.
    chunk: Vec<u8>,
    /// Unpacked archive members, one buffer per nesting level.
    members: Vec<Vec<u8>>,
}

impl<'s> ScanSession<'s> {
    pub(crate) fn new(scanner: &'s Scanner) -> Self {
        Self {
            scanner,
            sessions: scanner
                .detectors
                .iter()
                .map(|detector| detector.session())
                .collect(),
            content: Vec::new(),
            chunk: vec![0u8; STREAM_CHUNK_BYTES],
            members: Vec::new(),
        }
    }

    /// Checks a buffer that is already in memory.
    pub fn scan_bytes(&mut self, bytes: &[u8]) -> FileResult {
        let sha256 = crate::sha256(bytes);
        self.inspect(Path::new(""), bytes.len() as u64, sha256, Some(bytes))
    }

    /// Reads one file once, hashing it on the way, and checks it.
    ///
    /// # Errors
    ///
    /// Returns why the file could not be read, in the form the report uses
    /// for skipped files.
    pub fn scan_file(&mut self, path: &Path) -> Result<FileResult, (SkipReason, String)> {
        let failed = |error: io::Error| (file::classify_io_error(&error), error.to_string());
        let mut file = file::open_for_scan(path).map_err(failed)?;
        let mut hasher = sha2::Sha256::new();

        if !self.scanner.needs_content {
            let size = hash_stream(&mut file, &mut hasher, &mut self.chunk).map_err(failed)?;
            return Ok(self.inspect(path, size, hasher.finalize().into(), None));
        }

        let limit = self.scanner.options.max_content_bytes;
        let mut content = std::mem::take(&mut self.content);
        content.clear();
        // Reading one byte past the limit tells us whether the file fits
        // without trusting the size the directory listing reported.
        let read = (&mut file)
            .take(limit.saturating_add(1))
            .read_to_end(&mut content);
        if let Err(error) = read {
            self.content = content;
            return Err(failed(error));
        }
        hasher.update(&content);

        if content.len() as u64 <= limit {
            let size = content.len() as u64;
            let result = self.inspect(path, size, hasher.finalize().into(), Some(&content));
            if content.capacity() <= RETAINED_BUFFER_BYTES {
                self.content = content;
            }
            return Ok(result);
        }

        // Too large to keep: let go of the buffer and finish the hash in a
        // streaming fashion.
        let already_read = content.len() as u64;
        drop(content);
        let rest = hash_stream(&mut file, &mut hasher, &mut self.chunk).map_err(failed)?;
        Ok(self.inspect(path, already_read + rest, hasher.finalize().into(), None))
    }

    /// Runs the detectors over a file and, if it is an archive, over what
    /// is packed inside it.
    fn inspect(
        &mut self,
        path: &Path,
        size: u64,
        sha256: Sha256,
        content: Option<&[u8]>,
    ) -> FileResult {
        let scanner = self.scanner;
        let mut collected = Collected::default();

        if content.is_none() && scanner.needs_content {
            collected.note(
                PartialReason::TooLarge,
                format!(
                    "larger than the content limit of {} bytes, so it was checked by hash only",
                    scanner.options.max_content_bytes
                ),
            );
        }
        let view = FileView::new(path, &[], size, &sha256, content);
        self.run_detectors(&view, None, &mut collected);

        let archives = &scanner.options.archives;
        if let Some(content) = content
            && archives.enabled
            && archives.max_depth > 0
            && let Some(hint) = archive::zip_hint(content)
        {
            let mut budget = Budget::new(archives);
            let mut chain = Vec::new();
            self.unpack(path, content, hint, &mut chain, &mut budget, &mut collected);
        }

        FileResult {
            size,
            sha256,
            verdict: scanner.policy.decide(&collected.findings),
            findings: collected.findings,
            findings_omitted: collected.findings_omitted,
            partial: Collected::partial(collected.notes),
            unpacked: collected.unpacked,
            members_scanned: collected.members_scanned,
            member_bytes: collected.member_bytes,
        }
    }

    /// Hands one file or archive member to every detector.
    fn run_detectors(
        &mut self,
        view: &FileView<'_>,
        member: Option<&Member>,
        collected: &mut Collected,
    ) {
        // Everything the layers say about this one file or member. The
        // policy settles what counts while it is still together: a second
        // sign is a sign about the same bytes, not about a neighbour in the
        // same archive.
        let mut found = Vec::new();
        let detectors = self.scanner.detectors.iter();
        for (detector, session) in detectors.zip(&mut self.sessions) {
            if detector.needs_content() && view.content().is_none() {
                continue;
            }
            match session.inspect(view) {
                Ok(findings) => found.extend(findings),
                Err(error) => {
                    let reason = match error {
                        DetectorError::Failed(_) => PartialReason::DetectorError,
                        DetectorError::TimedOut(_) => PartialReason::Timeout,
                    };
                    let place = match member {
                        Some(member) => format!(" on {}", archive::display_chain(&member.path)),
                        None => String::new(),
                    };
                    collected.note(reason, format!("{}{place}: {error}", detector.id()));
                }
            }
        }
        self.scanner.policy.settle(&mut found);
        for mut finding in found {
            finding.member = member.cloned();
            collected.find(finding);
        }
    }

    /// Unpacks a zip archive in memory and checks every member, going into
    /// archives inside it as far as the limits allow.
    ///
    /// `chain` holds the names of the enclosing archive members, and is the
    /// same again when this returns.
    fn unpack(
        &mut self,
        path: &Path,
        bytes: &[u8],
        hint: ZipHint,
        chain: &mut Vec<String>,
        budget: &mut Budget,
        collected: &mut Collected,
    ) {
        let scanner = self.scanner;
        let options = &scanner.options.archives;
        let place = |chain: &[String]| match chain {
            [] => String::new(),
            chain => format!("{}: ", archive::display_chain(chain)),
        };

        let mut zip = match ZipIterable::try_new(Cursor::new(bytes), Config::default()) {
            Ok(zip) => zip,
            Err(error) => {
                if hint == ZipHint::Declared {
                    collected.note(
                        archive::failure_reason(&error),
                        format!("{}not a readable zip archive ({error})", place(chain)),
                    );
                }
                return;
            }
        };
        let entries = match zip.files() {
            Ok(entries) => entries,
            Err(error) => {
                collected.note(
                    archive::failure_reason(&error),
                    format!(
                        "{}the list of members cannot be read ({error})",
                        place(chain)
                    ),
                );
                return;
            }
        };
        collected.unpacked = true;

        let depth = chain.len();
        let mut body = Cursor::new(bytes);
        let mut buffer = self.members.pop().unwrap_or_default();
        let read_options = ZipReadOptions::new().ignore_crc32(true);

        for entry in entries {
            if budget.spent {
                break;
            }
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    // The directory is broken from here on; the iterator ends
                    // itself after an error.
                    collected.note(
                        archive::failure_reason(&error),
                        format!("{}the list of members is damaged ({error})", place(chain)),
                    );
                    continue;
                }
            };
            if budget.members == 0 {
                collected.note(
                    PartialReason::ArchiveLimit,
                    format!(
                        "{}more than {} archive members, so the rest was not unpacked",
                        place(chain),
                        options.max_members
                    ),
                );
                budget.spent = true;
                break;
            }
            budget.members -= 1;
            if !entry.is_file() {
                // Folders have no content, and a link inside an archive is
                // only the text of its target.
                continue;
            }

            let name = match entry.name() {
                Ok(name) => archive::display_name(&name),
                Err(_) => archive::display_name(&String::from_utf8_lossy(entry.name_raw())),
            };
            chain.push(name);

            if entry.encrypted() {
                collected.note(
                    PartialReason::EncryptedArchive,
                    format!("{} is password-protected", archive::display_chain(chain)),
                );
                chain.pop();
                continue;
            }

            let method = entry.compression();
            if !zip::SUPPORTED_COMPRESSION_METHODS.contains(&method) {
                collected.note(
                    PartialReason::UnsupportedCompression,
                    format!(
                        "{} is packed with a method that cannot be unpacked ({method})",
                        archive::display_chain(chain)
                    ),
                );
                chain.pop();
                continue;
            }

            let (allowed, cap) = archive::allowance(options, budget, entry.compressed_size());
            let mut reader = match entry.with_reader(&mut body, read_options.clone()) {
                Ok(reader) => reader,
                Err(error) => {
                    collected.note(
                        archive::failure_reason(&error),
                        format!(
                            "{} cannot be unpacked ({error})",
                            archive::display_chain(chain)
                        ),
                    );
                    chain.pop();
                    continue;
                }
            };
            buffer.clear();
            let read = (&mut reader)
                .take(allowed.saturating_add(1))
                .read_to_end(&mut buffer);
            drop(reader);

            if buffer.len() as u64 > allowed {
                // The member is larger than it may be. It was not unpacked in
                // full, so there is nothing trustworthy to check.
                budget.bytes = budget.bytes.saturating_sub(allowed);
                let what = match cap {
                    Cap::Member => format!(
                        "unpacks to more than {} bytes, the limit for one member",
                        options.max_member_bytes
                    ),
                    Cap::Ratio => format!(
                        "unpacks to more than {} times its packed size",
                        options.max_ratio
                    ),
                    Cap::Total => format!(
                        "would take the unpacked total past {} bytes, the limit for one file",
                        options.max_total_bytes
                    ),
                };
                collected.note(
                    PartialReason::ArchiveLimit,
                    format!("{} {what}", archive::display_chain(chain)),
                );
                chain.pop();
                if cap == Cap::Total {
                    budget.spent = true;
                    break;
                }
                continue;
            }
            if let Err(error) = read {
                if buffer.is_empty() {
                    collected.note(
                        PartialReason::DamagedArchive,
                        format!(
                            "{} is damaged and cannot be unpacked ({error})",
                            archive::display_chain(chain)
                        ),
                    );
                    chain.pop();
                    continue;
                }
                // A damaged member is still checked as far as it unpacked: a
                // deliberately broken tail must not be a way past the scanner.
                collected.note(
                    PartialReason::DamagedArchive,
                    format!(
                        "{} is damaged and was checked only as far as it unpacks ({error})",
                        archive::display_chain(chain)
                    ),
                );
            }

            let size = buffer.len() as u64;
            budget.bytes = budget.bytes.saturating_sub(size);
            collected.members_scanned += 1;
            collected.member_bytes += size;

            let sha256 = crate::sha256(&buffer);
            let member = Member {
                path: chain.clone(),
                size,
                sha256: warden_sigdb::hex::encode(&sha256),
            };
            let view = FileView::new(path, chain, size, &sha256, Some(&buffer));
            self.run_detectors(&view, Some(&member), collected);

            if let Some(hint) = archive::zip_hint(&buffer) {
                // `depth` counts the archives around this member's archive.
                if depth as u64 + 1 < u64::from(options.max_depth) {
                    self.unpack(path, &buffer, hint, chain, budget, collected);
                } else if hint == ZipHint::Declared {
                    collected.note(
                        PartialReason::ArchiveLimit,
                        format!(
                            "{} is an archive nested more than {} deep, so it was not unpacked",
                            archive::display_chain(chain),
                            options.max_depth
                        ),
                    );
                }
            }
            chain.pop();
        }

        if buffer.capacity() <= RETAINED_BUFFER_BYTES {
            self.members.push(buffer);
        }
    }
}

/// Feeds the rest of `reader` into `hasher`. Returns the number of bytes read.
pub(crate) fn hash_stream(
    reader: &mut impl Read,
    hasher: &mut sha2::Sha256,
    chunk: &mut [u8],
) -> io::Result<u64> {
    let mut total = 0u64;
    loop {
        match reader.read(chunk) {
            Ok(0) => return Ok(total),
            Ok(read) => {
                hasher.update(&chunk[..read]);
                total += read as u64;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Confidence, ThreatCategory};

    fn finding(name: &str, confidence: Confidence) -> Finding {
        Finding::new(
            "test",
            name,
            ThreatCategory::Malware,
            confidence,
            Vec::new(),
        )
    }

    #[test]
    fn a_full_list_keeps_the_strongest_findings() {
        let mut collected = Collected::default();
        for index in 0..MAX_FINDINGS_PER_FILE {
            collected.find(finding(&format!("weak-{index}"), Confidence::Low));
        }
        collected.find(finding("strong", Confidence::High));
        collected.find(finding("another weak one", Confidence::Low));

        assert_eq!(collected.findings.len(), MAX_FINDINGS_PER_FILE);
        assert_eq!(collected.findings_omitted, 2);
        assert!(
            collected
                .findings
                .iter()
                .any(|kept| kept.name == "strong" && kept.confidence == Confidence::High)
        );
        assert!(
            !collected
                .findings
                .iter()
                .any(|kept| kept.name == "another weak one")
        );
    }

    #[test]
    fn notes_keep_a_few_examples_and_count_the_rest() {
        let mut collected = Collected::default();
        for index in 0..5 {
            collected.note(PartialReason::EncryptedArchive, format!("member {index}"));
        }
        collected.note(PartialReason::TooLarge, "too big");

        let partial = Collected::partial(collected.notes);
        assert_eq!(partial.len(), 2);
        assert_eq!(partial[0].reason, PartialReason::TooLarge);
        assert_eq!(partial[0].detail, "too big");
        assert_eq!(partial[1].reason, PartialReason::EncryptedArchive);
        assert_eq!(
            partial[1].detail,
            "member 0; member 1; member 2; and 2 more"
        );
    }
}

//! The rule bundle: one file that holds compiled YARA rules and a record of
//! where they came from. The layout is specified in `docs/RULES.md`.
//!
//! # Why the contents are under a cipher
//!
//! Compiled rules hold the byte patterns of the malware they describe, and
//! an antivirus that finds those patterns in a file takes the file for the
//! malware: Microsoft Defender removes a bundle whose contents lie open. So
//! a bundle keeps its contents under a stream cipher, with the key in its
//! own header. That hides nothing from anybody who wants to look, and is
//! not meant to. It only keeps the patterns from lying on disk as they are.
//! The quarantine does the same to the files it holds, for the same reason.

use std::borrow::Cow;
use std::fs;
use std::io::{self, Write};
use std::path::Path;

use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use serde::{Deserialize, Serialize};
use sha2::Digest;

/// First eight bytes of every rule bundle.
pub const MAGIC: [u8; 8] = *b"WRDNRUL\0";

/// How a bundle stores its contents: the manifest and the compiled rules.
///
/// This crate reads both layouts. It writes [`Layout::Sealed`] unless it is
/// told otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Layout {
    /// Format version 1: the contents as they are. An antivirus may take
    /// such a file for the malware its rules describe.
    Plain,
    /// Format version 2: the contents under ChaCha20, with the key in the
    /// header.
    #[default]
    Sealed,
}

impl Layout {
    /// The format version that stands for this layout in a bundle's header.
    #[must_use]
    pub const fn version(self) -> u32 {
        match self {
            Self::Plain => 1,
            Self::Sealed => 2,
        }
    }

    /// Size of the fixed header, in bytes. A sealed bundle keeps its key
    /// after the digest.
    #[must_use]
    pub const fn header_len(self) -> usize {
        match self {
            Self::Plain => DIGEST_END,
            Self::Sealed => DIGEST_END + KEY_LEN,
        }
    }

    const fn from_version(version: u32) -> Option<Self> {
        match version {
            1 => Some(Self::Plain),
            2 => Some(Self::Sealed),
            _ => None,
        }
    }
}

/// The YARA-X release this crate is built with. Compiled rules load only in
/// the release that compiled them, so every bundle records it.
pub const ENGINE: &str = "yara-x 1.23.0";

/// Where the digest sits in the header. It covers the whole file apart
/// from itself.
const DIGEST_OFFSET: usize = 64;
/// Where the digest ends. The headers of all layouts are alike up to here.
const DIGEST_END: usize = DIGEST_OFFSET + 32;
/// Size of the key of a sealed bundle, which follows the digest.
const KEY_LEN: usize = 32;
/// Upper bound for the manifest, which is small text.
const MAX_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;

/// Why a rule bundle could not be read or built.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BundleError {
    /// A file could not be read or written.
    #[error("{context}")]
    Io {
        /// What was being done.
        context: String,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
    /// The file does not start with the bundle signature.
    #[error("not a Warden rule bundle")]
    BadMagic,
    /// The file uses a layout version this crate does not know.
    #[error("rule bundle format version {0} is not supported")]
    UnsupportedVersion(u32),
    /// The file is shorter or longer than its header says.
    #[error(
        "the rule bundle is cut short or has extra data: expected {expected} bytes, found {actual}"
    )]
    WrongLength {
        /// Length according to the header.
        expected: u64,
        /// Length of the file.
        actual: u64,
    },
    /// The contents do not match the digest in the header.
    #[error("the rule bundle is damaged: its contents do not match its digest")]
    DigestMismatch,
    /// The digest is right but the contents make no sense.
    #[error("the rule bundle is malformed: {0}")]
    Corrupt(&'static str),
    /// The bundle was compiled by a different YARA-X release.
    #[error(
        "the rule bundle was built with {bundle}, but this program uses {this}: build the bundle again"
    )]
    EngineMismatch {
        /// The release recorded in the bundle.
        bundle: String,
        /// The release this crate is built with.
        this: &'static str,
    },
    /// YARA-X refused the compiled rules.
    #[error("the compiled rules cannot be loaded: {0}")]
    Rules(String),
    /// A rule source could not be used.
    #[error("{0}")]
    Source(String),
    /// The exclusion list asks for something that is refused.
    #[error("the exclusion list cannot be applied: {0}")]
    Exclusion(String),
    /// There is nothing to put in a bundle.
    #[error("no rule could be compiled, so there is nothing to put in a bundle")]
    Empty,
}

/// What a bundle records about itself, stored as JSON after the header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// The YARA-X release the rules were compiled with, see [`ENGINE`].
    pub engine: String,
    /// The rule files that went into the bundle, in the order they were
    /// compiled.
    pub sources: Vec<SourceInfo>,
    /// The exclusion list the bundle was built with. Absent if there was
    /// none, and in bundles written before exclusion lists existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exclusions: Option<ExclusionInfo>,
}

/// What a bundle records about the exclusion list it was built with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExclusionInfo {
    /// SHA-256 of the list, in lowercase hexadecimal.
    pub sha256: String,
    /// Names of the rules that were found in the rule files and left out
    /// because the list names them. Each name appears once, in the order
    /// the rules were found.
    pub rules: Vec<String>,
}

/// One rule file that went into a bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceInfo {
    /// The file's name, as given when the bundle was built.
    pub name: String,
    /// SHA-256 of the file, in lowercase hexadecimal.
    pub sha256: String,
    /// Size of the file in bytes.
    pub bytes: u64,
    /// Rules from this file that were compiled into the bundle.
    pub rules: u64,
    /// Rules from this file that could not be compiled and were left out.
    pub skipped: u64,
    /// Rules from this file that were left out because they are on the
    /// exclusion list.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub excluded: u64,
}

/// Serde hands `skip_serializing_if` a reference.
fn is_zero(count: &u64) -> bool {
    *count == 0
}

/// Compiled YARA rules, ready to scan with, plus their provenance.
///
/// # Trust
///
/// A bundle holds compiled code for the rule engine. Its digest protects
/// against damage, not against someone who can replace the file: they can
/// write a new digest too. Load bundles only from places that only trusted
/// users can write to. `docs/RULES.md` discusses this.
pub struct RuleBundle {
    rules: yara_x::Rules,
    manifest: Manifest,
    layout: Layout,
    rule_count: u32,
    created_unix_secs: u64,
    digest: [u8; 32],
    size_bytes: u64,
}

impl std::fmt::Debug for RuleBundle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuleBundle")
            .field("layout", &self.layout)
            .field("rule_count", &self.rule_count)
            .field("created_unix_secs", &self.created_unix_secs)
            .field("digest", &warden_sigdb::hex::encode(&self.digest))
            .field("size_bytes", &self.size_bytes)
            .field("manifest", &self.manifest)
            .finish_non_exhaustive()
    }
}

impl RuleBundle {
    /// Reads and verifies a bundle file.
    ///
    /// # Errors
    ///
    /// Fails if the file cannot be read, is not a bundle, is damaged, or was
    /// built with a different YARA-X release.
    pub fn open(path: &Path) -> Result<Self, BundleError> {
        let bytes = fs::read(path).map_err(|source| BundleError::Io {
            context: format!("cannot read rule bundle {}", path.display()),
            source,
        })?;
        Self::from_bytes(&bytes)
    }

    /// Verifies and loads a bundle that is already in memory.
    ///
    /// # Errors
    ///
    /// Fails if the bytes are not a bundle, are damaged, or were built with
    /// a different YARA-X release.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BundleError> {
        // The headers of all layouts are alike up to the end of the digest.
        let common = bytes.get(..DIGEST_END).ok_or(BundleError::WrongLength {
            expected: DIGEST_END as u64,
            actual: bytes.len() as u64,
        })?;
        if common[..8] != MAGIC {
            return Err(BundleError::BadMagic);
        }
        let version = read_u32(common, 8);
        let layout =
            Layout::from_version(version).ok_or(BundleError::UnsupportedVersion(version))?;
        let header_len = layout.header_len();
        if read_u32(common, 12) as usize != header_len {
            return Err(BundleError::Corrupt("unexpected header length"));
        }
        let rule_count = read_u32(common, 20);
        let created_unix_secs = read_u64(common, 24);
        let manifest_len = read_u64(common, 32);
        let rules_len = read_u64(common, 40);

        let expected = (header_len as u64)
            .checked_add(manifest_len)
            .and_then(|length| length.checked_add(rules_len))
            .ok_or(BundleError::Corrupt("section lengths overflow"))?;
        if expected != bytes.len() as u64 {
            return Err(BundleError::WrongLength {
                expected,
                actual: bytes.len() as u64,
            });
        }
        if manifest_len > MAX_MANIFEST_BYTES {
            return Err(BundleError::Corrupt("the manifest is implausibly large"));
        }

        // The lengths were checked against the slice above, so they fit.
        let (header, stored) = bytes.split_at(header_len);
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&header[DIGEST_OFFSET..DIGEST_END]);
        if compute_digest(header, stored) != digest {
            return Err(BundleError::DigestMismatch);
        }

        let contents: Cow<'_, [u8]> = match layout {
            Layout::Plain => Cow::Borrowed(stored),
            Layout::Sealed => {
                let mut key = [0u8; KEY_LEN];
                key.copy_from_slice(&header[DIGEST_END..]);
                let mut contents = stored.to_vec();
                apply_cipher(&key, &mut contents);
                // The key is the SHA-256 of what it opens. A key that is
                // anything else was not written by a builder.
                if sha256(&contents) != key {
                    return Err(BundleError::Corrupt(
                        "the key does not belong to the contents",
                    ));
                }
                Cow::Owned(contents)
            }
        };

        let (manifest_bytes, rule_bytes) = contents.split_at(manifest_len as usize);
        let manifest: Manifest = serde_json::from_slice(manifest_bytes)
            .map_err(|_| BundleError::Corrupt("the manifest is not valid"))?;
        if manifest.engine != ENGINE {
            return Err(BundleError::EngineMismatch {
                bundle: manifest.engine,
                this: ENGINE,
            });
        }
        let rules = yara_x::Rules::deserialize(rule_bytes)
            .map_err(|error| BundleError::Rules(error.to_string()))?;
        if rules.iter().len() != rule_count as usize {
            return Err(BundleError::Corrupt(
                "the number of rules does not match the header",
            ));
        }

        Ok(Self {
            rules,
            manifest,
            layout,
            rule_count,
            created_unix_secs,
            digest,
            size_bytes: bytes.len() as u64,
        })
    }

    /// Wraps freshly compiled rules as a bundle and returns it together with
    /// its serialised form.
    pub(crate) fn assemble(
        rules: yara_x::Rules,
        manifest: Manifest,
        created_unix_secs: u64,
        layout: Layout,
    ) -> Result<(Self, Vec<u8>), BundleError> {
        let rule_count = u32::try_from(rules.iter().len())
            .map_err(|_| BundleError::Corrupt("too many rules for one bundle"))?;
        let manifest_bytes = serde_json::to_vec(&manifest)
            .map_err(|_| BundleError::Corrupt("the manifest cannot be written"))?;
        let rule_bytes = rules
            .serialize()
            .map_err(|error| BundleError::Rules(error.to_string()))?;
        let header_len = layout.header_len();

        let mut bytes = Vec::with_capacity(header_len + manifest_bytes.len() + rule_bytes.len());
        bytes.extend_from_slice(&MAGIC);
        bytes.extend_from_slice(&layout.version().to_le_bytes());
        bytes.extend_from_slice(&(header_len as u32).to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes()); // flags
        bytes.extend_from_slice(&rule_count.to_le_bytes());
        bytes.extend_from_slice(&created_unix_secs.to_le_bytes());
        bytes.extend_from_slice(&(manifest_bytes.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&(rule_bytes.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&[0u8; 16]); // reserved
        debug_assert_eq!(bytes.len(), DIGEST_OFFSET);
        bytes.extend_from_slice(&[0u8; 32]); // digest, filled in below
        match layout {
            Layout::Plain => {
                bytes.extend_from_slice(&manifest_bytes);
                bytes.extend_from_slice(&rule_bytes);
            }
            Layout::Sealed => {
                // The key is the SHA-256 of the contents. The same rules
                // then give the same bundle, byte for byte, and building
                // one needs no source of random numbers.
                let mut hasher = sha2::Sha256::new();
                hasher.update(&manifest_bytes);
                hasher.update(&rule_bytes);
                let key: [u8; KEY_LEN] = hasher.finalize().into();
                bytes.extend_from_slice(&key);
                bytes.extend_from_slice(&manifest_bytes);
                bytes.extend_from_slice(&rule_bytes);
                apply_cipher(&key, &mut bytes[header_len..]);
            }
        }

        let (header, stored) = bytes.split_at(header_len);
        let digest = compute_digest(header, stored);
        bytes[DIGEST_OFFSET..DIGEST_END].copy_from_slice(&digest);

        let bundle = Self {
            rules,
            manifest,
            layout,
            rule_count,
            created_unix_secs,
            digest,
            size_bytes: bytes.len() as u64,
        };
        Ok((bundle, bytes))
    }

    /// The compiled rules.
    #[must_use]
    pub fn rules(&self) -> &yara_x::Rules {
        &self.rules
    }

    /// Where the rules came from.
    #[must_use]
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// How the bundle stores its contents.
    #[must_use]
    pub fn layout(&self) -> Layout {
        self.layout
    }

    /// Number of rules in the bundle.
    #[must_use]
    pub fn rule_count(&self) -> u32 {
        self.rule_count
    }

    /// When the bundle was built, in seconds since the Unix epoch.
    #[must_use]
    pub fn created_unix_secs(&self) -> u64 {
        self.created_unix_secs
    }

    /// SHA-256 over the bundle file as it is stored, apart from the digest
    /// itself.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Size of the bundle file, in bytes.
    #[must_use]
    pub fn size_bytes(&self) -> u64 {
        self.size_bytes
    }
}

/// Writes a serialised bundle to `path`, replacing an existing file in one
/// step so that a reader never sees half of one.
///
/// # Errors
///
/// Fails if the file cannot be written.
pub fn write_bundle(path: &Path, bytes: &[u8]) -> Result<(), BundleError> {
    let failed = |action: &str, source: io::Error| BundleError::Io {
        context: format!("cannot {action} rule bundle {}", path.display()),
        source,
    };
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(format!(".tmp-{}", std::process::id()));
    let temporary = std::path::PathBuf::from(temporary);

    let written = (|| {
        let mut file = fs::File::create(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()
    })();
    if let Err(error) = written {
        let _ = fs::remove_file(&temporary);
        return Err(failed("write", error));
    }
    fs::rename(&temporary, path).map_err(|error| {
        let _ = fs::remove_file(&temporary);
        failed("replace", error)
    })
}

/// SHA-256 of a whole bundle file apart from the digest in its header.
fn compute_digest(header: &[u8], stored: &[u8]) -> [u8; 32] {
    let mut hasher = sha2::Sha256::new();
    hasher.update(&header[..DIGEST_OFFSET]);
    hasher.update(&header[DIGEST_END..]);
    hasher.update(stored);
    hasher.finalize().into()
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    sha2::Sha256::digest(bytes).into()
}

/// Puts the contents of a bundle under the cipher, or takes them out again:
/// with a stream cipher that is one and the same operation.
///
/// The nonce is zero. A nonce keeps a key from making the same stream
/// twice, and here every key is made from the contents it is used on.
fn apply_cipher(key: &[u8; KEY_LEN], contents: &mut [u8]) {
    let nonce = [0u8; 12];
    ChaCha20::new(&(*key).into(), &nonce.into()).apply_keystream(contents);
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    let mut raw = [0u8; 4];
    raw.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_le_bytes(raw)
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(raw)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn tiny_rules() -> yara_x::Rules {
        yara_x::compile("rule tiny { condition: true }").unwrap()
    }

    fn manifest(engine: &str) -> Manifest {
        Manifest {
            engine: engine.to_owned(),
            sources: vec![SourceInfo {
                name: "tiny.yar".to_owned(),
                sha256: "00".repeat(32),
                bytes: 29,
                rules: 1,
                skipped: 0,
                excluded: 0,
            }],
            exclusions: None,
        }
    }

    fn assembled(layout: Layout) -> (RuleBundle, Vec<u8>) {
        RuleBundle::assemble(tiny_rules(), manifest(ENGINE), 1_234, layout).unwrap()
    }

    /// Whether `needle` occurs anywhere in `haystack`.
    fn holds(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    /// Writes the digest that belongs to the bytes as they are now, the way
    /// somebody would who changes a bundle on purpose.
    fn seal_again(bytes: &mut [u8], layout: Layout) {
        let (header, stored) = bytes.split_at(layout.header_len());
        let digest = compute_digest(header, stored);
        bytes[DIGEST_OFFSET..DIGEST_END].copy_from_slice(&digest);
    }

    #[test]
    fn the_header_of_a_plain_bundle_is_laid_out_as_documented() {
        let (bundle, bytes) = assembled(Layout::Plain);
        assert_eq!(bundle.layout(), Layout::Plain);
        assert_eq!(&bytes[..8], b"WRDNRUL\0");
        assert_eq!(read_u32(&bytes, 8), 1);
        assert_eq!(read_u32(&bytes, 12), 96);
        assert_eq!(read_u32(&bytes, 16), 0);
        assert_eq!(read_u32(&bytes, 20), 1);
        assert_eq!(read_u64(&bytes, 24), 1_234);
        let manifest_len = read_u64(&bytes, 32);
        let rules_len = read_u64(&bytes, 40);
        assert_eq!(bytes.len() as u64, 96 + manifest_len + rules_len);
        assert_eq!(&bytes[48..64], &[0u8; 16]);
        assert_eq!(&bytes[64..96], &bundle.digest());
        // The digest covers everything but itself.
        let mut covered = bytes[..64].to_vec();
        covered.extend_from_slice(&bytes[96..]);
        assert_eq!(sha256(&covered), bundle.digest());
        // The manifest is plain JSON right after the header.
        let stored: Manifest =
            serde_json::from_slice(&bytes[96..96 + manifest_len as usize]).unwrap();
        assert_eq!(&stored, bundle.manifest());

        let loaded = RuleBundle::from_bytes(&bytes).unwrap();
        assert_eq!(loaded.layout(), Layout::Plain);
        assert_eq!(loaded.rule_count(), 1);
        assert_eq!(loaded.created_unix_secs(), 1_234);
        assert_eq!(loaded.digest(), bundle.digest());
    }

    #[test]
    fn the_header_of_a_sealed_bundle_is_laid_out_as_documented() {
        let (bundle, bytes) = assembled(Layout::Sealed);
        assert_eq!(bundle.layout(), Layout::Sealed);
        assert_eq!(&bytes[..8], b"WRDNRUL\0");
        assert_eq!(read_u32(&bytes, 8), 2);
        assert_eq!(read_u32(&bytes, 12), 128);
        assert_eq!(read_u32(&bytes, 16), 0);
        assert_eq!(read_u32(&bytes, 20), 1);
        assert_eq!(read_u64(&bytes, 24), 1_234);
        let manifest_len = read_u64(&bytes, 32);
        let rules_len = read_u64(&bytes, 40);
        assert_eq!(bytes.len() as u64, 128 + manifest_len + rules_len);
        assert_eq!(&bytes[48..64], &[0u8; 16]);
        assert_eq!(&bytes[64..96], &bundle.digest());
        // The digest covers everything but itself: the key too.
        let mut covered = bytes[..64].to_vec();
        covered.extend_from_slice(&bytes[96..]);
        assert_eq!(sha256(&covered), bundle.digest());

        // Apart from the header, a sealed bundle is as long as a plain one,
        // and what the key opens is what the plain one stores.
        let (_, plain) = assembled(Layout::Plain);
        assert_eq!(bytes.len(), plain.len() + 32);
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes[96..128]);
        assert_eq!(key, sha256(&plain[96..]));
        let mut opened = bytes[128..].to_vec();
        apply_cipher(&key, &mut opened);
        assert_eq!(opened, &plain[96..]);

        let loaded = RuleBundle::from_bytes(&bytes).unwrap();
        assert_eq!(loaded.layout(), Layout::Sealed);
        assert_eq!(loaded.rule_count(), 1);
        assert_eq!(loaded.created_unix_secs(), 1_234);
        assert_eq!(loaded.digest(), bundle.digest());
        assert_eq!(loaded.manifest(), bundle.manifest());
    }

    #[test]
    fn the_cipher_is_chacha20_as_its_specification_defines_it() {
        // RFC 8439, section 2.4.2, gives a key, a nonce, a text and what
        // the cipher makes of them from block 1 on. A bundle starts at
        // block 0, so the text is put behind one block of padding here.
        let mut key = [0u8; 32];
        for (index, byte) in key.iter_mut().enumerate() {
            *byte = index as u8;
        }
        let nonce: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0x4a, 0, 0, 0, 0];
        let text = b"Ladies and Gentlemen of the class of '99: If I could offer you \
only one tip for the future, sunscreen would be it.";
        let mut padded = vec![0u8; 64];
        padded.extend_from_slice(text);
        ChaCha20::new(&key.into(), &nonce.into()).apply_keystream(&mut padded);
        assert_eq!(
            warden_sigdb::hex::encode(&padded[64..]),
            "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b\
             f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8\
             07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736\
             5af90bbf74a35be6b40b8eedf2785e42874d"
        );

        // A bundle uses the same cipher with a nonce of zeros.
        let mut by_hand = text.to_vec();
        ChaCha20::new(&key.into(), &[0u8; 12].into()).apply_keystream(&mut by_hand);
        let mut by_bundle = text.to_vec();
        apply_cipher(&key, &mut by_bundle);
        assert_eq!(by_bundle, by_hand);
        assert_ne!(&by_bundle[..], &text[..]);
        // Applying it a second time takes the cipher off again.
        apply_cipher(&key, &mut by_bundle);
        assert_eq!(&by_bundle[..], &text[..]);
    }

    #[test]
    fn a_sealed_bundle_does_not_show_what_a_plain_one_does() {
        let (_, plain) = assembled(Layout::Plain);
        let (_, sealed) = assembled(Layout::Sealed);
        // The plain bundle shows its manifest and the name of its rule.
        for visible in [&b"tiny.yar"[..], b"yara-x", b"tiny"] {
            assert!(holds(&plain, visible), "{visible:?} in the plain bundle");
            assert!(!holds(&sealed, visible), "{visible:?} in the sealed bundle");
        }
        // Byte for byte, the two agree about as often as chance has it:
        // one time in 256.
        let (plain, sealed) = (&plain[96..], &sealed[128..]);
        let alike = plain
            .iter()
            .zip(sealed)
            .filter(|(left, right)| left == right)
            .count();
        assert!(
            alike < plain.len() / 64 + 16,
            "{alike} of {} bytes are the same",
            plain.len()
        );
    }

    #[test]
    fn the_same_rules_give_the_same_sealed_bundle() {
        let (_, first) = assembled(Layout::Sealed);
        let (_, second) = assembled(Layout::Sealed);
        assert_eq!(first, second);
        // Different contents get a different key.
        let (_, other) = RuleBundle::assemble(
            yara_x::compile("rule other { condition: false }").unwrap(),
            manifest(ENGINE),
            1_234,
            Layout::Sealed,
        )
        .unwrap();
        assert_ne!(first[96..128], other[96..128]);
    }

    #[test]
    fn a_key_that_does_not_belong_to_the_contents_is_refused() {
        // Somebody puts the contents under a key of their own choice and
        // writes the digest that goes with the result.
        let (_, plain) = assembled(Layout::Plain);
        let (_, mut bytes) = assembled(Layout::Sealed);
        let own_key = [0x5au8; 32];
        bytes[96..128].copy_from_slice(&own_key);
        bytes[128..].copy_from_slice(&plain[96..]);
        apply_cipher(&own_key, &mut bytes[128..]);
        seal_again(&mut bytes, Layout::Sealed);
        let error = RuleBundle::from_bytes(&bytes).unwrap_err();
        assert!(
            matches!(error, BundleError::Corrupt(reason) if reason.contains("key")),
            "{error}"
        );

        // A changed key without a new digest does not get that far.
        let (_, mut bytes) = assembled(Layout::Sealed);
        bytes[100] ^= 0x01;
        assert!(matches!(
            RuleBundle::from_bytes(&bytes),
            Err(BundleError::DigestMismatch)
        ));
    }

    #[test]
    fn a_bundle_cannot_be_relabelled_as_the_other_layout() {
        for layout in [Layout::Plain, Layout::Sealed] {
            let other = match layout {
                Layout::Plain => Layout::Sealed,
                Layout::Sealed => Layout::Plain,
            };
            // With only the version changed, the header length does not fit
            // the version.
            let (_, mut bytes) = assembled(layout);
            bytes[8..12].copy_from_slice(&other.version().to_le_bytes());
            assert!(
                matches!(RuleBundle::from_bytes(&bytes), Err(BundleError::Corrupt(_))),
                "{layout:?}"
            );
            // With the header length changed as well, the lengths do not
            // add up to the file.
            bytes[12..16].copy_from_slice(&(other.header_len() as u32).to_le_bytes());
            assert!(
                matches!(
                    RuleBundle::from_bytes(&bytes),
                    Err(BundleError::WrongLength { .. })
                ),
                "{layout:?}"
            );
        }
    }

    #[test]
    fn a_manifest_without_the_exclusion_fields_reads_and_writes_as_before() {
        // This is what a manifest looked like before exclusion lists.
        let old = format!(
            r#"{{"engine":"{ENGINE}","sources":[{{"name":"tiny.yar","sha256":"{}","bytes":29,"rules":1,"skipped":0}}]}}"#,
            "00".repeat(32)
        );
        let read: Manifest = serde_json::from_str(&old).unwrap();
        assert_eq!(read, manifest(ENGINE));
        assert_eq!(read.exclusions, None);
        assert_eq!(read.sources[0].excluded, 0);
        // A bundle built without a list is written exactly as it was then.
        assert_eq!(serde_json::to_string(&read).unwrap(), old);
    }

    #[test]
    fn a_bundle_from_another_engine_release_is_refused_with_advice() {
        for layout in [Layout::Plain, Layout::Sealed] {
            let (_, bytes) =
                RuleBundle::assemble(tiny_rules(), manifest("yara-x 0.1.0"), 0, layout).unwrap();
            let error = RuleBundle::from_bytes(&bytes).unwrap_err();
            assert!(matches!(error, BundleError::EngineMismatch { .. }));
            let message = error.to_string();
            assert!(message.contains("yara-x 0.1.0"), "{message}");
            assert!(message.contains("build the bundle again"), "{message}");
        }
    }

    #[test]
    fn an_unknown_layout_version_is_refused() {
        for version in [0u32, 3, u32::MAX] {
            let (_, mut bytes) = assembled(Layout::Sealed);
            bytes[8..12].copy_from_slice(&version.to_le_bytes());
            assert!(
                matches!(
                    RuleBundle::from_bytes(&bytes),
                    Err(BundleError::UnsupportedVersion(found)) if found == version
                ),
                "version {version}"
            );
        }
    }

    #[test]
    fn lengths_that_do_not_add_up_are_refused_before_anything_is_read() {
        for layout in [Layout::Plain, Layout::Sealed] {
            let (_, mut bytes) = assembled(layout);
            // A manifest length close to the largest number must not
            // overflow.
            bytes[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
            assert!(
                matches!(RuleBundle::from_bytes(&bytes), Err(BundleError::Corrupt(_))),
                "{layout:?}"
            );
        }
    }
}

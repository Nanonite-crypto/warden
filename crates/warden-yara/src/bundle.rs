//! The rule bundle: one file that holds compiled YARA rules and a record of
//! where they came from. The layout is specified in `docs/RULES.md`.

use std::fs;
use std::io::{self, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::Digest;

/// First eight bytes of every rule bundle.
pub const MAGIC: [u8; 8] = *b"WRDNRUL\0";
/// Version of the bundle layout this crate reads and writes.
pub const FORMAT_VERSION: u32 = 1;
/// Size of the fixed header, in bytes.
pub const HEADER_LEN: usize = 96;
/// The YARA-X release this crate is built with. Compiled rules load only in
/// the release that compiled them, so every bundle records it.
pub const ENGINE: &str = "yara-x 1.23.0";

/// Where the digest sits in the header. Everything before it is covered.
const DIGEST_OFFSET: usize = 64;
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
    rule_count: u32,
    created_unix_secs: u64,
    digest: [u8; 32],
    size_bytes: u64,
}

impl std::fmt::Debug for RuleBundle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuleBundle")
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
        let header = bytes.get(..HEADER_LEN).ok_or(BundleError::WrongLength {
            expected: HEADER_LEN as u64,
            actual: bytes.len() as u64,
        })?;
        if header[..8] != MAGIC {
            return Err(BundleError::BadMagic);
        }
        let version = read_u32(header, 8);
        if version != FORMAT_VERSION {
            return Err(BundleError::UnsupportedVersion(version));
        }
        if read_u32(header, 12) as usize != HEADER_LEN {
            return Err(BundleError::Corrupt("unexpected header length"));
        }
        let rule_count = read_u32(header, 20);
        let created_unix_secs = read_u64(header, 24);
        let manifest_len = read_u64(header, 32);
        let rules_len = read_u64(header, 40);

        let expected = (HEADER_LEN as u64)
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

        let body = &bytes[HEADER_LEN..];
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&header[DIGEST_OFFSET..HEADER_LEN]);
        if compute_digest(&header[..DIGEST_OFFSET], body) != digest {
            return Err(BundleError::DigestMismatch);
        }

        // The lengths were checked against the slice above, so they fit.
        let (manifest_bytes, rule_bytes) = body.split_at(manifest_len as usize);
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
    ) -> Result<(Self, Vec<u8>), BundleError> {
        let rule_count = u32::try_from(rules.iter().len())
            .map_err(|_| BundleError::Corrupt("too many rules for one bundle"))?;
        let manifest_bytes = serde_json::to_vec(&manifest)
            .map_err(|_| BundleError::Corrupt("the manifest cannot be written"))?;
        let rule_bytes = rules
            .serialize()
            .map_err(|error| BundleError::Rules(error.to_string()))?;

        let mut bytes = Vec::with_capacity(HEADER_LEN + manifest_bytes.len() + rule_bytes.len());
        bytes.extend_from_slice(&MAGIC);
        bytes.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        bytes.extend_from_slice(&(HEADER_LEN as u32).to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes()); // flags
        bytes.extend_from_slice(&rule_count.to_le_bytes());
        bytes.extend_from_slice(&created_unix_secs.to_le_bytes());
        bytes.extend_from_slice(&(manifest_bytes.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&(rule_bytes.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&[0u8; 16]); // reserved
        debug_assert_eq!(bytes.len(), DIGEST_OFFSET);
        bytes.extend_from_slice(&[0u8; 32]); // digest, filled in below
        bytes.extend_from_slice(&manifest_bytes);
        bytes.extend_from_slice(&rule_bytes);

        let digest = compute_digest(&bytes[..DIGEST_OFFSET], &bytes[HEADER_LEN..]);
        bytes[DIGEST_OFFSET..HEADER_LEN].copy_from_slice(&digest);

        let bundle = Self {
            rules,
            manifest,
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

    /// SHA-256 over the bundle's header and contents.
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

fn compute_digest(header: &[u8], body: &[u8]) -> [u8; 32] {
    let mut hasher = sha2::Sha256::new();
    hasher.update(header);
    hasher.update(body);
    hasher.finalize().into()
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
            }],
        }
    }

    #[test]
    fn the_header_is_laid_out_as_documented() {
        let (bundle, bytes) = RuleBundle::assemble(tiny_rules(), manifest(ENGINE), 1_234).unwrap();
        assert_eq!(&bytes[..8], b"WRDNRUL\0");
        assert_eq!(read_u32(&bytes, 8), FORMAT_VERSION);
        assert_eq!(read_u32(&bytes, 12), 96);
        assert_eq!(read_u32(&bytes, 16), 0);
        assert_eq!(read_u32(&bytes, 20), 1);
        assert_eq!(read_u64(&bytes, 24), 1_234);
        let manifest_len = read_u64(&bytes, 32);
        let rules_len = read_u64(&bytes, 40);
        assert_eq!(bytes.len() as u64, 96 + manifest_len + rules_len);
        assert_eq!(&bytes[48..64], &[0u8; 16]);
        assert_eq!(&bytes[64..96], &bundle.digest());
        // The manifest is plain JSON right after the header.
        let stored: Manifest =
            serde_json::from_slice(&bytes[96..96 + manifest_len as usize]).unwrap();
        assert_eq!(&stored, bundle.manifest());

        let loaded = RuleBundle::from_bytes(&bytes).unwrap();
        assert_eq!(loaded.rule_count(), 1);
        assert_eq!(loaded.created_unix_secs(), 1_234);
        assert_eq!(loaded.digest(), bundle.digest());
    }

    #[test]
    fn a_bundle_from_another_engine_release_is_refused_with_advice() {
        let (_, bytes) = RuleBundle::assemble(tiny_rules(), manifest("yara-x 0.1.0"), 0).unwrap();
        let error = RuleBundle::from_bytes(&bytes).unwrap_err();
        assert!(matches!(error, BundleError::EngineMismatch { .. }));
        let message = error.to_string();
        assert!(message.contains("yara-x 0.1.0"), "{message}");
        assert!(message.contains("build the bundle again"), "{message}");
    }

    #[test]
    fn an_unknown_layout_version_is_refused() {
        let (_, mut bytes) = RuleBundle::assemble(tiny_rules(), manifest(ENGINE), 0).unwrap();
        bytes[8..12].copy_from_slice(&2u32.to_le_bytes());
        assert!(matches!(
            RuleBundle::from_bytes(&bytes),
            Err(BundleError::UnsupportedVersion(2))
        ));
    }

    #[test]
    fn lengths_that_do_not_add_up_are_refused_before_anything_is_read() {
        let (_, mut bytes) = RuleBundle::assemble(tiny_rules(), manifest(ENGINE), 0).unwrap();
        // A manifest length close to the largest number must not overflow.
        bytes[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(matches!(
            RuleBundle::from_bytes(&bytes),
            Err(BundleError::Corrupt(_))
        ));
    }
}

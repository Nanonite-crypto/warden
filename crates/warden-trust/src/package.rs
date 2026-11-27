//! An app package as it lies in its folder, and what its signature says
//! about a file in it.
//!
//! Apps from the Microsoft Store come as packages (MSIX, earlier APPX).
//! Windows unpacks a package into a folder of its own under
//! `C:\Program Files\WindowsApps`, and the files in it need no signature of
//! their own: the package is signed as a whole. Two files in the folder
//! carry that:
//!
//! - `AppxBlockMap.xml` lists every file of the package with its length and
//!   the SHA-256 of each 64 KiB block of it.
//! - `AppxSignature.p7x` is the signature. What it signs is a short list of
//!   digests, and one of them is the SHA-256 of the block map.
//!
//! So a file is vouched for by the package's signature if its blocks hash
//! to what the block map says, and the block map hashes to what the
//! signature says, and the signature holds. This module does the first two
//! steps, which are arithmetic. Whether the signature holds, and who made
//! it, is asked of Windows, with the very bytes this module read
//! ([`PackageFiles::signature`]).
//!
//! Three files of a package are not in its block map, because they are
//! what describes the package: the block map itself, `[Content_Types].xml`
//! and `AppxMetadata\CodeIntegrity.cat`. The signature names each of them
//! by a digest of its own, see [`PackageDigests::of_whole_file`]. The one
//! file that nothing vouches for is the signature file: a signature cannot
//! cover itself.
//!
//! Everything here is read from files that anyone may have written, so
//! every size has a limit and every step that fails says no.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

use base64::Engine as _;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::der::{self, CONTEXT_0, DerError, OBJECT_IDENTIFIER, OCTET_STRING, SEQUENCE};

/// Name of the signature in a package's folder.
pub const SIGNATURE_FILE: &str = "AppxSignature.p7x";
/// Name of the block map in a package's folder.
pub const BLOCK_MAP_FILE: &str = "AppxBlockMap.xml";
/// Name of the file that says what kinds of file a package holds.
pub const CONTENT_TYPES_FILE: &str = "[Content_Types].xml";
/// Name of the catalogue that lists the executables of a package, where a
/// package has one, with the backslash this module names files with.
pub const CODE_INTEGRITY_FILE: &str = "AppxMetadata\\CodeIntegrity.cat";
/// A block map hashes a file in blocks of this many bytes; the last block
/// of a file is whatever is left.
pub const BLOCK_BYTES: usize = 65_536;

/// The four bytes a package's signature file starts with. The signature
/// itself follows them.
const SIGNATURE_MAGIC: &[u8; 4] = b"PKCX";
/// Largest signature file that is read. Microsoft's own reader of packages
/// uses the same bound.
const MAX_SIGNATURE_BYTES: u64 = 2 * 1024 * 1024;
/// Largest block map that is read. A package with more files than fit in
/// this is not checked, and its files count as unsigned.
const MAX_BLOCK_MAP_BYTES: u64 = 32 * 1024 * 1024;
/// Most elements a block map may have.
const MAX_BLOCK_MAP_NODES: u32 = 2_000_000;
/// How far up from a file its package's folder is looked for.
const MAX_LEVELS_UP: usize = 32;

/// The start of the list of digests that a package's signature signs.
const DIGESTS_MAGIC: &[u8; 4] = b"APPX";
/// The entry of that list that holds the SHA-256 of the block map.
const DIGEST_BLOCK_MAP: &[u8; 4] = b"AXBM";
/// The entry that holds the SHA-256 of `[Content_Types].xml`.
const DIGEST_CONTENT_TYPES: &[u8; 4] = b"AXCT";
/// The entry that holds the SHA-256 of the code integrity catalogue.
const DIGEST_CODE_INTEGRITY: &[u8; 4] = b"AXCI";
/// Each entry is a name of four bytes and a SHA-256.
const DIGEST_ENTRY_BYTES: usize = 4 + 32;

/// `1.2.840.113549.1.7.2`: signed data.
const OID_SIGNED_DATA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02];
/// `1.3.6.1.4.1.311.2.1.4`: what an Authenticode signature signs, a
/// description of the signed thing and its digest.
const OID_INDIRECT_DATA: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x04];
/// `2.16.840.1.101.3.4.2.1`: SHA-256.
const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];

/// The hash method a block map has to name.
const HASH_METHOD_SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";

/// Why a package could not be used to vouch for a file.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PackageError {
    /// One of the package's two files could not be read.
    #[error("{what} cannot be read: {source}")]
    Io {
        /// Which file.
        what: &'static str,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
    /// One of the two files is larger than this module reads.
    #[error("{what} is larger than {limit} bytes")]
    TooLarge {
        /// Which file.
        what: &'static str,
        /// The limit.
        limit: u64,
    },
    /// The signature file is not built the way a package's signature is.
    #[error("the package's signature cannot be read: {0}")]
    Signature(&'static str),
    /// The block map is not built the way a block map is.
    #[error("the package's block map cannot be read: {0}")]
    BlockMap(String),
}

/// The digests a package's signature signs, as far as this module uses
/// them. Each is the SHA-256 of a whole file as it lies in the package's
/// folder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackageDigests {
    /// SHA-256 of the block map.
    pub block_map: [u8; 32],
    /// SHA-256 of `[Content_Types].xml`, if the signature names it.
    pub content_types: Option<[u8; 32]>,
    /// SHA-256 of `AppxMetadata\CodeIntegrity.cat`, if the package has
    /// one.
    pub code_integrity: Option<[u8; 32]>,
}

impl PackageDigests {
    /// The SHA-256 that the signature names for one of the files that
    /// describe the package, by the file's name inside the package's
    /// folder. Nothing for any other file: those are in the block map.
    #[must_use]
    pub fn of_whole_file(&self, name: &str) -> Option<[u8; 32]> {
        if name.eq_ignore_ascii_case(BLOCK_MAP_FILE) {
            Some(self.block_map)
        } else if name.eq_ignore_ascii_case(CONTENT_TYPES_FILE) {
            self.content_types
        } else if name.eq_ignore_ascii_case(CODE_INTEGRITY_FILE) {
            self.code_integrity
        } else {
            None
        }
    }
}

/// Reads the digests out of the bytes of a package's signature file.
///
/// This finds what is signed; it does not check the signature. The bytes
/// have to go to Windows for that, and only when Windows accepts them do
/// the digests mean anything.
///
/// # Errors
///
/// Fails if the bytes are not a package's signature as Windows writes it.
pub fn digests(signature_file: &[u8]) -> Result<PackageDigests, PackageError> {
    let unreadable = |_: DerError| PackageError::Signature("it is not built as a signature is");

    let message = signature_file
        .strip_prefix(SIGNATURE_MAGIC)
        .ok_or(PackageError::Signature("it does not start with PKCX"))?;

    // ContentInfo ::= SEQUENCE { contentType, [0] SignedData }
    let (content_info, _) = der::expect(message, SEQUENCE).map_err(unreadable)?;
    let (content_type, rest) = der::expect(content_info, OBJECT_IDENTIFIER).map_err(unreadable)?;
    if content_type != OID_SIGNED_DATA {
        return Err(PackageError::Signature("it is not signed data"));
    }
    let (wrapped, _) = der::expect(rest, CONTEXT_0).map_err(unreadable)?;

    // SignedData ::= SEQUENCE { version, digestAlgorithms, contentInfo, … }
    let (signed_data, _) = der::expect(wrapped, SEQUENCE).map_err(unreadable)?;
    let (_, _version, rest) = der::take(signed_data).map_err(unreadable)?;
    let (_, _digest_algorithms, rest) = der::take(rest).map_err(unreadable)?;
    let (signed, _) = der::expect(rest, SEQUENCE).map_err(unreadable)?;

    // What is signed: SEQUENCE { contentType, [0] SpcIndirectDataContent }
    let (signed_type, rest) = der::expect(signed, OBJECT_IDENTIFIER).map_err(unreadable)?;
    if signed_type != OID_INDIRECT_DATA {
        return Err(PackageError::Signature(
            "it does not sign a digest of a file",
        ));
    }
    let (wrapped, _) = der::expect(rest, CONTEXT_0).map_err(unreadable)?;

    // SpcIndirectDataContent ::= SEQUENCE { data, messageDigest }
    // messageDigest ::= SEQUENCE { digestAlgorithm, digest }
    let (indirect, _) = der::expect(wrapped, SEQUENCE).map_err(unreadable)?;
    let (_data, rest) = der::expect(indirect, SEQUENCE).map_err(unreadable)?;
    let (digest_info, _) = der::expect(rest, SEQUENCE).map_err(unreadable)?;
    let (algorithm, rest) = der::expect(digest_info, SEQUENCE).map_err(unreadable)?;
    let (algorithm_id, _) = der::expect(algorithm, OBJECT_IDENTIFIER).map_err(unreadable)?;
    if algorithm_id != OID_SHA256 {
        return Err(PackageError::Signature("its digests are not SHA-256"));
    }
    let (list, _) = der::expect(rest, OCTET_STRING).map_err(unreadable)?;

    let entries = list
        .strip_prefix(DIGESTS_MAGIC)
        .ok_or(PackageError::Signature(
            "its list of digests does not start with APPX",
        ))?;
    if entries.is_empty() || entries.len() % DIGEST_ENTRY_BYTES != 0 {
        return Err(PackageError::Signature(
            "its list of digests has an odd length",
        ));
    }
    let mut block_map = None;
    let mut content_types = None;
    let mut code_integrity = None;
    for entry in entries.chunks_exact(DIGEST_ENTRY_BYTES) {
        let (name, digest) = entry.split_at(4);
        let slot = if name == DIGEST_BLOCK_MAP {
            &mut block_map
        } else if name == DIGEST_CONTENT_TYPES {
            &mut content_types
        } else if name == DIGEST_CODE_INTEGRITY {
            &mut code_integrity
        } else {
            continue;
        };
        let digest: [u8; 32] = digest
            .try_into()
            .map_err(|_| PackageError::Signature("a digest has an odd length"))?;
        // Two digests for one file: which of them counts is not for a
        // reader to choose.
        if slot.replace(digest).is_some() {
            return Err(PackageError::Signature("it names one file twice"));
        }
    }
    block_map
        .map(|block_map| PackageDigests {
            block_map,
            content_types,
            code_integrity,
        })
        .ok_or(PackageError::Signature("it has no digest of the block map"))
}

/// One file as a block map describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappedFile {
    /// Length of the file in bytes.
    pub size: u64,
    /// SHA-256 of each block of [`BLOCK_BYTES`], in order.
    pub blocks: Vec<[u8; 32]>,
}

impl MappedFile {
    /// Whether what `reader` yields is this file: the same length, and
    /// block by block the same SHA-256.
    ///
    /// # Errors
    ///
    /// Passes on an error of the reader.
    pub fn matches(&self, reader: &mut impl Read) -> io::Result<bool> {
        let mut buffer = vec![0u8; BLOCK_BYTES];
        let mut total = 0u64;
        let mut blocks = self.blocks.iter();
        loop {
            let filled = fill(reader, &mut buffer)?;
            if filled == 0 {
                break;
            }
            total += filled as u64;
            let Some(expected) = blocks.next() else {
                return Ok(false);
            };
            let found: [u8; 32] = Sha256::digest(&buffer[..filled]).into();
            if found != *expected {
                return Ok(false);
            }
            if filled < BLOCK_BYTES {
                // A short block is the last one; make sure nothing follows.
                if fill(reader, &mut buffer[..1])? != 0 {
                    return Ok(false);
                }
                break;
            }
        }
        Ok(total == self.size && blocks.next().is_none())
    }
}

/// Reads until the buffer is full or the reader has nothing more, and
/// returns how many bytes were read.
fn fill(reader: &mut impl Read, buffer: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buffer.len() {
        match reader.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(filled)
}

/// The files of a package, by name, as its block map lists them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BlockMap {
    /// By lowercase name. `None` where two entries differ only in case, or
    /// where an entry does not add up: such a file is vouched for by
    /// nothing.
    files: HashMap<String, Option<MappedFile>>,
}

impl BlockMap {
    /// Reads a block map.
    ///
    /// # Errors
    ///
    /// Fails if the bytes are not a block map with SHA-256 hashes.
    pub fn parse(xml: &[u8]) -> Result<Self, PackageError> {
        let invalid = |what: &str| PackageError::BlockMap(what.to_owned());

        let text = std::str::from_utf8(xml).map_err(|_| invalid("it is not UTF-8"))?;
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
        let options = roxmltree::ParsingOptions {
            allow_dtd: false,
            nodes_limit: MAX_BLOCK_MAP_NODES,
            ..roxmltree::ParsingOptions::default()
        };
        let document = roxmltree::Document::parse_with_options(text, options)
            .map_err(|error| PackageError::BlockMap(error.to_string()))?;
        let root = document.root_element();
        if root.tag_name().name() != "BlockMap" {
            return Err(invalid("its outermost element is not BlockMap"));
        }
        if root.attribute("HashMethod") != Some(HASH_METHOD_SHA256) {
            return Err(invalid("its hashes are not SHA-256"));
        }

        let mut files: HashMap<String, Option<MappedFile>> = HashMap::new();
        for file in root
            .children()
            .filter(|node| node.has_tag_name_local("File"))
        {
            let name = file
                .attribute("Name")
                .ok_or_else(|| invalid("a file has no name"))?;
            let entry = mapped_file(file);
            match files.entry(name.to_lowercase()) {
                Entry::Vacant(slot) => {
                    slot.insert(entry);
                }
                Entry::Occupied(mut slot) => {
                    // Two entries for what Windows takes to be one name.
                    slot.insert(None);
                }
            }
        }
        Ok(Self { files })
    }

    /// The entry for a file, by its name inside the package with
    /// backslashes between folders, as a block map writes it. Upper and
    /// lower case make no difference, as they make none to Windows.
    #[must_use]
    pub fn file(&self, name: &str) -> Option<&MappedFile> {
        self.files.get(&name.to_lowercase())?.as_ref()
    }

    /// How many names the block map lists.
    #[must_use]
    pub fn len(&self) -> usize {
        self.files.len()
    }

    /// Whether the block map lists no file.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }
}

/// A shorthand that `roxmltree` does not have: an element with this name,
/// whatever its namespace.
trait LocalName {
    fn has_tag_name_local(&self, name: &str) -> bool;
}

impl LocalName for roxmltree::Node<'_, '_> {
    fn has_tag_name_local(&self, name: &str) -> bool {
        self.is_element() && self.tag_name().name() == name
    }
}

/// Reads one `File` element. Returns nothing if it does not add up: a
/// length that is no number, a hash that is no SHA-256, or a number of
/// blocks that does not fit the length.
fn mapped_file(file: roxmltree::Node<'_, '_>) -> Option<MappedFile> {
    let size: u64 = file.attribute("Size")?.parse().ok()?;
    let mut blocks = Vec::new();
    for block in file
        .children()
        .filter(|node| node.has_tag_name_local("Block"))
    {
        let hash = base64::engine::general_purpose::STANDARD
            .decode(block.attribute("Hash")?)
            .ok()?;
        blocks.push(<[u8; 32]>::try_from(hash).ok()?);
    }
    (blocks.len() as u64 == size.div_ceil(BLOCK_BYTES as u64))
        .then_some(MappedFile { size, blocks })
}

/// Finds the folder of the package a file lies in.
///
/// Returns that folder and the file's name inside it, with backslashes
/// between folders as a block map writes names. A folder counts as a
/// package's if it holds a block map and a signature; whether they are
/// worth anything is for the caller to find out.
#[must_use]
pub fn locate(path: &Path) -> Option<(PathBuf, String)> {
    let mut inside: Vec<&str> = vec![path.file_name()?.to_str()?];
    let mut folder = path.parent()?;
    for _ in 0..MAX_LEVELS_UP {
        if folder.join(BLOCK_MAP_FILE).is_file() && folder.join(SIGNATURE_FILE).is_file() {
            inside.reverse();
            return Some((folder.to_path_buf(), inside.join("\\")));
        }
        match folder.components().next_back()? {
            Component::Normal(name) => inside.push(name.to_str()?),
            _ => return None,
        }
        folder = folder.parent()?;
    }
    None
}

/// The two files of a package's folder that vouch for the others, read
/// into memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageFiles {
    signature: Vec<u8>,
    digests: PackageDigests,
    block_map: Vec<u8>,
}

impl PackageFiles {
    /// Reads the signature and the block map of the package in `folder`,
    /// and checks that the block map is the one the signature signs.
    ///
    /// # Errors
    ///
    /// Fails if either file cannot be read or is too large, if the
    /// signature file is not built as one, or if the block map is not the
    /// one the signature names.
    pub fn read(folder: &Path) -> Result<Self, PackageError> {
        let signature = read_bounded(
            &folder.join(SIGNATURE_FILE),
            MAX_SIGNATURE_BYTES,
            "the package's signature",
        )?;
        let signed = digests(&signature)?;
        let block_map = read_bounded(
            &folder.join(BLOCK_MAP_FILE),
            MAX_BLOCK_MAP_BYTES,
            "the package's block map",
        )?;
        let found: [u8; 32] = Sha256::digest(&block_map).into();
        if found != signed.block_map {
            return Err(PackageError::BlockMap(
                "it is not the block map that the package's signature signs".to_owned(),
            ));
        }
        Ok(Self {
            signature,
            digests: signed,
            block_map,
        })
    }

    /// The bytes of the signature file, to hand to Windows.
    #[must_use]
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// The digests the signature file names. Like the block map, they
    /// mean something once Windows has accepted
    /// [`signature`](Self::signature).
    #[must_use]
    pub fn digests(&self) -> &PackageDigests {
        &self.digests
    }

    /// Reads the block map. Call this once Windows has accepted
    /// [`signature`](Self::signature): until then the block map is
    /// anybody's.
    ///
    /// # Errors
    ///
    /// Fails if the block map cannot be read as one.
    pub fn block_map(&self) -> Result<BlockMap, PackageError> {
        BlockMap::parse(&self.block_map)
    }
}

/// Reads a whole file, unless it is larger than `limit`.
fn read_bounded(path: &Path, limit: u64, what: &'static str) -> Result<Vec<u8>, PackageError> {
    let failed = |source| PackageError::Io { what, source };
    let file = File::open(path).map_err(failed)?;
    let mut bytes = Vec::new();
    // One byte more than the limit shows whether the file fits, whatever
    // the directory says about its size.
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(failed)?;
    if bytes.len() as u64 > limit {
        return Err(PackageError::TooLarge { what, limit });
    }
    Ok(bytes)
}

/// Builds the bytes of a package's signature file around a list of
/// digests, without a signature in it. For tests, here and of the code
/// that uses this module.
#[doc(hidden)]
#[must_use]
pub fn unsigned_signature_file(digest_list: &[u8]) -> Vec<u8> {
    fn value(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        match content.len() {
            length @ 0..0x80 => out.push(length as u8),
            length @ 0x80..0x100 => out.extend([0x81, length as u8]),
            length => out.extend([0x82, (length >> 8) as u8, length as u8]),
        }
        out.extend_from_slice(content);
        out
    }
    let sequence = |parts: &[&[u8]]| value(SEQUENCE, &parts.concat());

    let algorithm = sequence(&[&value(OBJECT_IDENTIFIER, OID_SHA256), &[0x05, 0x00]]);
    let digest_info = sequence(&[&algorithm, &value(OCTET_STRING, digest_list)]);
    let data = sequence(&[&value(
        OBJECT_IDENTIFIER,
        &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x1E],
    )]);
    let indirect = sequence(&[&data, &digest_info]);
    let signed = sequence(&[
        &value(OBJECT_IDENTIFIER, OID_INDIRECT_DATA),
        &value(CONTEXT_0, &indirect),
    ]);
    let version = [0x02, 0x01, 0x01];
    let digest_algorithms = value(0x31, &algorithm);
    let signers = value(0x31, &[]);
    let signed_data = sequence(&[&version, &digest_algorithms, &signed, &signers]);
    let content_info = sequence(&[
        &value(OBJECT_IDENTIFIER, OID_SIGNED_DATA),
        &value(CONTEXT_0, &signed_data),
    ]);

    let mut file = SIGNATURE_MAGIC.to_vec();
    file.extend(content_info);
    file
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest_list(entries: &[(&[u8; 4], [u8; 32])]) -> Vec<u8> {
        let mut list = DIGESTS_MAGIC.to_vec();
        for (name, digest) in entries {
            list.extend_from_slice(*name);
            list.extend_from_slice(digest);
        }
        list
    }

    fn block_map_xml(files: &[(&str, &[u8])]) -> String {
        let mut xml = String::from(
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n\
             <BlockMap xmlns=\"http://schemas.microsoft.com/appx/2010/blockmap\" \
             HashMethod=\"http://www.w3.org/2001/04/xmlenc#sha256\">",
        );
        for (name, content) in files {
            xml.push_str(&format!(
                "<File Name=\"{name}\" Size=\"{}\" LfhSize=\"30\">",
                content.len()
            ));
            for block in content.chunks(BLOCK_BYTES) {
                let hash = base64::engine::general_purpose::STANDARD.encode(Sha256::digest(block));
                xml.push_str(&format!(
                    "<Block Hash=\"{hash}\" Size=\"{}\"/>",
                    block.len()
                ));
            }
            xml.push_str("</File>");
        }
        xml.push_str("</BlockMap>");
        xml
    }

    #[test]
    fn the_digest_of_the_block_map_is_found() {
        let list = digest_list(&[
            (b"AXPC", [1; 32]),
            (b"AXCD", [2; 32]),
            (b"AXCT", [3; 32]),
            (b"AXBM", [4; 32]),
            (b"AXCI", [5; 32]),
        ]);
        let file = unsigned_signature_file(&list);
        let found = digests(&file).expect("well-formed");
        assert_eq!(
            found,
            PackageDigests {
                block_map: [4; 32],
                content_types: Some([3; 32]),
                code_integrity: Some([5; 32]),
            }
        );
        // The three files that describe a package are named whole, by
        // any spelling of their names. Every other file is in the block
        // map, and the signature file is nowhere.
        assert_eq!(found.of_whole_file("AppxBlockMap.xml"), Some([4; 32]));
        assert_eq!(found.of_whole_file("appxblockmap.XML"), Some([4; 32]));
        assert_eq!(found.of_whole_file("[Content_Types].xml"), Some([3; 32]));
        assert_eq!(
            found.of_whole_file("AppxMetadata\\CodeIntegrity.cat"),
            Some([5; 32])
        );
        assert_eq!(found.of_whole_file("AppxManifest.xml"), None);
        assert_eq!(found.of_whole_file("AppxSignature.p7x"), None);
        assert_eq!(found.of_whole_file("folder\\AppxBlockMap.xml"), None);

        // A package without executables has no catalogue of them.
        let without = digests(&unsigned_signature_file(&digest_list(&[
            (b"AXCT", [3; 32]),
            (b"AXBM", [4; 32]),
        ])))
        .expect("well-formed");
        assert_eq!(without.code_integrity, None);
        assert_eq!(
            without.of_whole_file("AppxMetadata\\CodeIntegrity.cat"),
            None
        );
    }

    #[test]
    fn a_signature_file_that_is_not_one_is_refused() {
        let good = unsigned_signature_file(&digest_list(&[(b"AXBM", [4; 32])]));
        assert!(digests(&good).is_ok());

        // Not the four bytes it has to start with.
        assert!(matches!(
            digests(&good[4..]),
            Err(PackageError::Signature(_))
        ));
        assert!(matches!(digests(b""), Err(PackageError::Signature(_))));
        assert!(matches!(digests(b"PKCX"), Err(PackageError::Signature(_))));

        // Cut off anywhere.
        for length in 4..good.len() {
            assert!(digests(&good[..length]).is_err(), "cut off at {length}");
        }

        // No digest of the block map, or two.
        let none = unsigned_signature_file(&digest_list(&[(b"AXPC", [1; 32])]));
        assert!(matches!(digests(&none), Err(PackageError::Signature(_))));
        let twice =
            unsigned_signature_file(&digest_list(&[(b"AXBM", [1; 32]), (b"AXBM", [1; 32])]));
        assert!(matches!(digests(&twice), Err(PackageError::Signature(_))));

        // A list that does not start as one, or is cut short.
        let mut odd = digest_list(&[(b"AXBM", [4; 32])]);
        odd.pop();
        assert!(digests(&unsigned_signature_file(&odd)).is_err());
        assert!(digests(&unsigned_signature_file(b"XPPA")).is_err());
        assert!(digests(&unsigned_signature_file(b"APPX")).is_err());
    }

    #[test]
    fn a_block_map_lists_files_with_their_blocks() {
        let big = vec![7u8; BLOCK_BYTES + 10];
        let xml = block_map_xml(&[
            ("AppxManifest.xml", b"<Package/>"),
            ("bin\\tool.exe", &big),
            ("empty.txt", b""),
        ]);
        let map = BlockMap::parse(xml.as_bytes()).expect("well-formed");
        assert_eq!(map.len(), 3);

        let manifest = map.file("AppxManifest.xml").expect("listed");
        assert_eq!(manifest.size, 10);
        assert_eq!(manifest.blocks.len(), 1);

        let tool = map.file("bin\\tool.exe").expect("listed");
        assert_eq!(tool.size, big.len() as u64);
        assert_eq!(tool.blocks.len(), 2);

        assert_eq!(map.file("empty.txt").expect("listed").blocks.len(), 0);
        assert!(map.file("missing.dll").is_none());
        // Case makes no difference, as it makes none to Windows.
        assert!(map.file("BIN\\TOOL.EXE").is_some());
    }

    #[test]
    fn a_file_matches_its_entry_only_byte_for_byte() {
        let content = {
            let mut content = vec![0u8; 2 * BLOCK_BYTES + 123];
            for (index, byte) in content.iter_mut().enumerate() {
                *byte = (index % 251) as u8;
            }
            content
        };
        let xml = block_map_xml(&[("a.bin", &content)]);
        let map = BlockMap::parse(xml.as_bytes()).expect("well-formed");
        let entry = map.file("a.bin").expect("listed");
        assert_eq!(entry.blocks.len(), 3);

        assert!(entry.matches(&mut content.as_slice()).expect("reads"));

        let mut changed = content.clone();
        changed[BLOCK_BYTES + 5] ^= 1;
        assert!(!entry.matches(&mut changed.as_slice()).expect("reads"));

        let mut longer = content.clone();
        longer.push(0);
        assert!(!entry.matches(&mut longer.as_slice()).expect("reads"));

        let shorter = &content[..content.len() - 1];
        assert!(!entry.matches(&mut &shorter[..]).expect("reads"));
        assert!(!entry.matches(&mut &b""[..]).expect("reads"));
    }

    #[test]
    fn a_file_of_whole_blocks_and_an_empty_file_match() {
        let content = vec![9u8; 2 * BLOCK_BYTES];
        let xml = block_map_xml(&[("whole.bin", &content), ("empty.bin", b"")]);
        let map = BlockMap::parse(xml.as_bytes()).expect("well-formed");

        let whole = map.file("whole.bin").expect("listed");
        assert_eq!(whole.blocks.len(), 2);
        assert!(whole.matches(&mut content.as_slice()).expect("reads"));
        let mut longer = content.clone();
        longer.push(9);
        assert!(!whole.matches(&mut longer.as_slice()).expect("reads"));

        let empty = map.file("empty.bin").expect("listed");
        assert!(empty.matches(&mut &b""[..]).expect("reads"));
        assert!(!empty.matches(&mut &b"x"[..]).expect("reads"));
    }

    #[test]
    fn entries_that_do_not_add_up_vouch_for_nothing() {
        let head = "<BlockMap xmlns=\"http://schemas.microsoft.com/appx/2010/blockmap\" \
                    HashMethod=\"http://www.w3.org/2001/04/xmlenc#sha256\">";
        let hash = base64::engine::general_purpose::STANDARD.encode([0u8; 32]);

        // A length that needs two blocks, with one.
        let xml = format!(
            "{head}<File Name=\"a\" Size=\"70000\"><Block Hash=\"{hash}\"/></File></BlockMap>"
        );
        assert!(
            BlockMap::parse(xml.as_bytes())
                .expect("well-formed")
                .file("a")
                .is_none()
        );

        // A hash that is no SHA-256.
        let xml =
            format!("{head}<File Name=\"a\" Size=\"5\"><Block Hash=\"AAAA\"/></File></BlockMap>");
        assert!(
            BlockMap::parse(xml.as_bytes())
                .expect("well-formed")
                .file("a")
                .is_none()
        );

        // The same name twice, in different case.
        let xml = format!(
            "{head}<File Name=\"a.dll\" Size=\"5\"><Block Hash=\"{hash}\"/></File>\
             <File Name=\"A.DLL\" Size=\"5\"><Block Hash=\"{hash}\"/></File></BlockMap>"
        );
        let map = BlockMap::parse(xml.as_bytes()).expect("well-formed");
        assert!(map.file("a.dll").is_none());
        assert!(map.file("A.DLL").is_none());
    }

    #[test]
    fn what_is_not_a_block_map_is_refused() {
        assert!(BlockMap::parse(b"").is_err());
        assert!(BlockMap::parse(b"not xml").is_err());
        assert!(BlockMap::parse(&[0xFF, 0xFE, 0x00]).is_err());
        assert!(BlockMap::parse(b"<Other/>").is_err());
        // Another hash than SHA-256.
        assert!(
            BlockMap::parse(
                b"<BlockMap HashMethod=\"http://www.w3.org/2001/04/xmlenc#sha512\"></BlockMap>"
            )
            .is_err()
        );
        // A document type, which could define entities.
        assert!(
            BlockMap::parse(
                b"<!DOCTYPE BlockMap [<!ENTITY a \"b\">]><BlockMap \
                  HashMethod=\"http://www.w3.org/2001/04/xmlenc#sha256\"></BlockMap>"
            )
            .is_err()
        );
    }

    #[test]
    fn a_package_folder_is_found_from_a_file_inside_it() {
        let dir = tempfile::tempdir().expect("temporary folder");
        let root = dir.path().join("Vendor.App_1.0.0.0_x64__abcdefgh");
        std::fs::create_dir_all(root.join("bin").join("x64")).expect("folders");
        std::fs::write(root.join(BLOCK_MAP_FILE), b"").expect("file");
        std::fs::write(root.join(SIGNATURE_FILE), b"").expect("file");
        let file = root.join("bin").join("x64").join("tool.exe");
        std::fs::write(&file, b"MZ").expect("file");

        assert_eq!(
            locate(&file),
            Some((root.clone(), "bin\\x64\\tool.exe".to_owned()))
        );
        assert_eq!(
            locate(&root.join("AppxManifest.xml")),
            Some((root.clone(), "AppxManifest.xml".to_owned()))
        );

        // A folder with only one of the two files is no package.
        std::fs::remove_file(root.join(SIGNATURE_FILE)).expect("removed");
        assert_eq!(locate(&file), None);
    }

    #[test]
    fn a_package_is_read_only_if_its_block_map_is_the_signed_one() {
        let dir = tempfile::tempdir().expect("temporary folder");
        let xml = block_map_xml(&[("tool.exe", b"MZ\x90\x00")]);
        let digest: [u8; 32] = Sha256::digest(xml.as_bytes()).into();
        std::fs::write(dir.path().join(BLOCK_MAP_FILE), &xml).expect("file");
        std::fs::write(
            dir.path().join(SIGNATURE_FILE),
            unsigned_signature_file(&digest_list(&[(b"AXBM", digest)])),
        )
        .expect("file");

        let package = PackageFiles::read(dir.path()).expect("the block map is the signed one");
        assert!(package.signature().starts_with(b"PKCX"));
        let map = package.block_map().expect("well-formed");
        assert!(
            map.file("tool.exe")
                .expect("listed")
                .matches(&mut &b"MZ\x90\x00"[..])
                .expect("reads")
        );

        // One byte of the block map changed: it is no longer what the
        // signature signs.
        let mut changed = xml.into_bytes();
        let last = changed.len() - 1;
        changed[last] = b' ';
        std::fs::write(dir.path().join(BLOCK_MAP_FILE), &changed).expect("file");
        assert!(matches!(
            PackageFiles::read(dir.path()),
            Err(PackageError::BlockMap(_))
        ));
    }
}

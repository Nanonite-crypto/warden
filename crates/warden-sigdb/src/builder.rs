use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::Sha256;
use crate::error::SigDbError;
use crate::format::{self, Category, FANOUT_ENTRIES, HEADER_LEN, Header, Layout};

/// Summary of a finished build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildStats {
    /// Unique hashes written.
    pub entries: u64,
    /// Distinct detection names written.
    pub names: u32,
    /// Signatures dropped because their hash had already been added.
    pub duplicates_dropped: u64,
    /// Size of the database in bytes.
    pub bytes: u64,
    /// Digest stored in the header.
    pub digest: Sha256,
    /// Creation time stored in the header, in seconds since the Unix epoch.
    pub created_unix_secs: u64,
}

/// Collects signatures and writes them out as a database.
///
/// The output is canonical: it depends only on the set of signatures and the
/// creation time, not on the order in which signatures were added. When the
/// same hash is added more than once, the first signature wins.
#[derive(Debug, Default)]
pub struct SigDbBuilder {
    entries: Vec<(Sha256, u32)>,
    names: Vec<(String, Category)>,
    /// One name-to-id map per category, indexed by `category_slot`.
    name_ids: [HashMap<String, u32>; 3],
    created_unix_secs: Option<u64>,
}

const fn category_slot(category: Category) -> usize {
    match category {
        Category::Malware => 0,
        Category::TestFile => 1,
        Category::PotentiallyUnwanted => 2,
    }
}

impl SigDbBuilder {
    /// Creates an empty builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Fixes the creation time stored in the header.
    ///
    /// Without this the current time is used, which makes two builds of the
    /// same input differ. Set it for reproducible builds.
    #[must_use]
    pub fn with_created_unix_secs(mut self, secs: u64) -> Self {
        self.created_unix_secs = Some(secs);
        self
    }

    /// Number of signatures added so far, duplicates included.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no signature has been added yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Adds one signature.
    ///
    /// # Errors
    ///
    /// Fails if the name is empty, longer than [`crate::MAX_NAME_LEN`] bytes,
    /// has surrounding whitespace or contains control characters, or if the
    /// database would exceed a limit of the format.
    pub fn add(&mut self, hash: Sha256, name: &str, category: Category) -> Result<(), SigDbError> {
        if self.entries.len() >= u32::MAX as usize {
            return Err(SigDbError::LimitExceeded("more than 4,294,967,295 entries"));
        }
        let slot = category_slot(category);
        let id = if let Some(&id) = self.name_ids[slot].get(name) {
            id
        } else {
            format::check_name(name).map_err(|reason| SigDbError::InvalidName {
                name: name.to_owned(),
                reason,
            })?;
            let id = u32::try_from(self.names.len())
                .map_err(|_| SigDbError::LimitExceeded("too many distinct detection names"))?;
            self.names.push((name.to_owned(), category));
            self.name_ids[slot].insert(name.to_owned(), id);
            id
        };
        self.entries.push((hash, id));
        Ok(())
    }

    /// Builds the database in memory.
    ///
    /// # Errors
    ///
    /// Fails if the database would exceed a limit of the format.
    pub fn build(self) -> Result<(Vec<u8>, BuildStats), SigDbError> {
        let Self {
            mut entries,
            names,
            created_unix_secs,
            ..
        } = self;
        let added = entries.len() as u64;

        // The sort is stable, so among equal hashes the first one added stays
        // first and survives the dedup.
        entries.sort_by_key(|entry| entry.0);
        entries.dedup_by(|later, earlier| later.0 == earlier.0);
        let entry_count = entries.len() as u64;

        // Keep only names that are still referenced, in sorted order, so the
        // output does not depend on the order signatures were added in.
        let mut used: Vec<u32> = entries.iter().map(|entry| entry.1).collect();
        used.sort_unstable();
        used.dedup();
        used.sort_by(|left, right| names[*left as usize].cmp(&names[*right as usize]));
        let name_count = u32::try_from(used.len())
            .map_err(|_| SigDbError::LimitExceeded("too many distinct detection names"))?;
        let mut remap = vec![u32::MAX; names.len()];
        for (new_id, &old_id) in (0u32..).zip(&used) {
            remap[old_id as usize] = new_id;
        }

        let mut name_offsets = Vec::with_capacity((used.len() + 1) * 4);
        let mut name_categories = Vec::with_capacity(used.len());
        let mut name_blob = Vec::new();
        name_offsets.extend_from_slice(&0u32.to_le_bytes());
        for &old_id in &used {
            let (name, category) = &names[old_id as usize];
            name_blob.extend_from_slice(name.as_bytes());
            let end = u32::try_from(name_blob.len())
                .map_err(|_| SigDbError::LimitExceeded("detection names exceed 4 GiB"))?;
            name_offsets.extend_from_slice(&end.to_le_bytes());
            name_categories.push(category.as_u8());
        }

        let layout = Layout::new(entry_count, name_count, name_blob.len() as u64).ok_or(
            SigDbError::LimitExceeded("database does not fit in the address space"),
        )?;

        // Prefix index: fanout[p] is the number of hashes whose first two
        // bytes, read big-endian, are less than or equal to p.
        let mut fanout = vec![0u32; FANOUT_ENTRIES];
        for (hash, _) in &entries {
            fanout[usize::from(u16::from_be_bytes([hash[0], hash[1]]))] += 1;
        }
        let mut running = 0u32;
        for count in &mut fanout {
            running += *count;
            *count = running;
        }

        let mut out = Vec::with_capacity(layout.total_len());
        out.resize(HEADER_LEN, 0);
        for count in &fanout {
            out.extend_from_slice(&count.to_le_bytes());
        }
        for (hash, _) in &entries {
            out.extend_from_slice(hash);
        }
        for (_, old_id) in &entries {
            out.extend_from_slice(&remap[*old_id as usize].to_le_bytes());
        }
        out.extend_from_slice(&name_offsets);
        out.extend_from_slice(&name_categories);
        out.extend_from_slice(&name_blob);
        debug_assert_eq!(out.len(), layout.total_len());

        let created_unix_secs = created_unix_secs.unwrap_or_else(now_unix_secs);
        let mut header = Header {
            entry_count,
            name_count,
            created_unix_secs,
            offsets: layout.offsets(),
            digest: [0u8; 32],
        };
        header.digest = format::compute_digest(&header.encode(), &out[HEADER_LEN..]);
        out[..HEADER_LEN].copy_from_slice(&header.encode());

        let stats = BuildStats {
            entries: entry_count,
            names: name_count,
            duplicates_dropped: added - entry_count,
            bytes: out.len() as u64,
            digest: header.digest,
            created_unix_secs,
        };
        Ok((out, stats))
    }

    /// Builds the database and writes it to `path`.
    ///
    /// The file is written under a temporary name in the same directory,
    /// flushed to disk and then renamed into place, so a reader never sees a
    /// half-written database and a crash leaves any previous file intact.
    ///
    /// # Errors
    ///
    /// Fails on the same conditions as [`build`](Self::build), or if the file
    /// cannot be written.
    pub fn write_to(self, path: impl AsRef<Path>) -> Result<BuildStats, SigDbError> {
        let path = path.as_ref();
        let (bytes, stats) = self.build()?;
        write_atomically(path, &bytes)?;
        Ok(stats)
    }
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

fn write_atomically(path: &Path, bytes: &[u8]) -> Result<(), SigDbError> {
    let mut temp_name = path
        .file_name()
        .map(|name| name.to_os_string())
        .ok_or_else(|| {
            SigDbError::io(
                format!("cannot write {}", path.display()),
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no file name"),
            )
        })?;
    temp_name.push(format!(".tmp-{}", std::process::id()));
    let temp_path: PathBuf = path.with_file_name(temp_name);

    let result = (|| -> std::io::Result<()> {
        let mut file = File::create(&temp_path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temp_path, path)
    })();

    result.map_err(|source| {
        // Best effort: do not leave the temporary file behind.
        let _ = fs::remove_file(&temp_path);
        SigDbError::io(format!("cannot write {}", path.display()), source)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SigDb;

    fn hash(first: u8, second: u8, rest: u8) -> Sha256 {
        let mut out = [rest; 32];
        out[0] = first;
        out[1] = second;
        out
    }

    #[test]
    fn empty_database_is_valid() {
        let (bytes, stats) = SigDbBuilder::new()
            .with_created_unix_secs(42)
            .build()
            .unwrap();
        assert_eq!(stats.entries, 0);
        assert_eq!(stats.names, 0);
        let db = SigDb::from_bytes(bytes).unwrap();
        assert!(db.is_empty());
        assert_eq!(db.created_unix_secs(), 42);
        assert!(db.lookup(&[0u8; 32]).is_none());
        assert!(db.lookup(&[0xffu8; 32]).is_none());
    }

    #[test]
    fn first_signature_wins_for_a_duplicate_hash() {
        let mut builder = SigDbBuilder::new();
        builder
            .add(hash(1, 2, 3), "First", Category::Malware)
            .unwrap();
        builder
            .add(hash(1, 2, 3), "Second", Category::PotentiallyUnwanted)
            .unwrap();
        builder
            .add(hash(9, 9, 9), "Other", Category::Malware)
            .unwrap();
        let (bytes, stats) = builder.build().unwrap();
        assert_eq!(stats.entries, 2);
        assert_eq!(stats.duplicates_dropped, 1);
        // "Second" is no longer referenced, so it is not stored.
        assert_eq!(stats.names, 2);
        let db = SigDb::from_bytes(bytes).unwrap();
        let hit = db.lookup(&hash(1, 2, 3)).unwrap();
        assert_eq!((hit.name, hit.category), ("First", Category::Malware));
    }

    #[test]
    fn output_does_not_depend_on_insertion_order() {
        let signatures = [
            (hash(0, 0, 0), "Zeta", Category::Malware),
            (hash(0, 0, 1), "Alpha", Category::Malware),
            (hash(0xff, 0xff, 0xff), "Alpha", Category::TestFile),
            (hash(0x80, 0, 5), "Mid", Category::PotentiallyUnwanted),
        ];
        let build = |order: &[usize]| {
            let mut builder = SigDbBuilder::new().with_created_unix_secs(7);
            for &index in order {
                let (hash, name, category) = signatures[index];
                builder.add(hash, name, category).unwrap();
            }
            builder.build().unwrap().0
        };
        assert_eq!(build(&[0, 1, 2, 3]), build(&[3, 2, 1, 0]));
        assert_eq!(build(&[0, 1, 2, 3]), build(&[2, 0, 3, 1]));
    }

    #[test]
    fn same_name_in_two_categories_is_two_names() {
        let mut builder = SigDbBuilder::new();
        builder
            .add(hash(1, 0, 0), "Shared", Category::Malware)
            .unwrap();
        builder
            .add(hash(2, 0, 0), "Shared", Category::TestFile)
            .unwrap();
        let (bytes, stats) = builder.build().unwrap();
        assert_eq!(stats.names, 2);
        let db = SigDb::from_bytes(bytes).unwrap();
        assert_eq!(
            db.lookup(&hash(1, 0, 0)).unwrap().category,
            Category::Malware
        );
        assert_eq!(
            db.lookup(&hash(2, 0, 0)).unwrap().category,
            Category::TestFile
        );
    }

    #[test]
    fn invalid_names_are_rejected() {
        let mut builder = SigDbBuilder::new();
        for bad in ["", " lead", "trail ", "tab\there"] {
            assert!(matches!(
                builder.add([0u8; 32], bad, Category::Malware),
                Err(SigDbError::InvalidName { .. })
            ));
        }
        assert!(builder.is_empty());
    }

    #[test]
    fn write_to_replaces_the_target_and_leaves_no_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("signatures.wdb");
        fs::write(&path, b"old contents").unwrap();

        let mut builder = SigDbBuilder::new();
        builder
            .add(hash(4, 5, 6), "Written", Category::Malware)
            .unwrap();
        let stats = builder.write_to(&path).unwrap();

        assert_eq!(fs::metadata(&path).unwrap().len(), stats.bytes);
        let names: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("signatures.wdb")]);
        let db = SigDb::open(&path).unwrap();
        assert_eq!(db.lookup(&hash(4, 5, 6)).unwrap().name, "Written");
    }
}

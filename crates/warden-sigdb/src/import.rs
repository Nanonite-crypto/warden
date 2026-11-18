//! Importers that turn text feeds into signatures.
//!
//! Two formats are supported:
//!
//! - **hash lists**: one hexadecimal SHA-256 per line, as published by feeds
//!   such as MalwareBazaar's plain-text export. Every hash gets the same
//!   detection name and category.
//! - **Warden CSV**: `sha256,name[,category]`, for curated lists where each
//!   hash carries its own name.
//!
//! Both skip blank lines and lines starting with `#`, accept Windows line
//! endings, and count malformed lines instead of aborting, because public
//! feeds are not always clean.

use std::io::{self, BufRead};

use crate::builder::SigDbBuilder;
use crate::error::SigDbError;
use crate::format::{self, Category};
use crate::hex;

/// Longest line an importer accepts, in bytes. Longer lines count as invalid.
pub const MAX_LINE_LEN: usize = 4096;

/// How many invalid lines are kept as samples in [`ImportStats`].
const MAX_SAMPLES: usize = 5;

/// A line an importer could not use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidLine {
    /// One-based line number.
    pub line: u64,
    /// Why the line was rejected.
    pub reason: &'static str,
}

/// What an importer did with its input.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportStats {
    /// Lines read.
    pub lines: u64,
    /// Signatures handed to the builder.
    pub added: u64,
    /// Blank lines, comments and header rows.
    pub ignored: u64,
    /// Lines that could not be used.
    pub invalid: u64,
    /// The first few invalid lines, for error messages.
    pub invalid_samples: Vec<InvalidLine>,
}

impl ImportStats {
    fn reject(&mut self, reason: &'static str) {
        self.invalid += 1;
        if self.invalid_samples.len() < MAX_SAMPLES {
            self.invalid_samples.push(InvalidLine {
                line: self.lines,
                reason,
            });
        }
    }
}

/// Imports a list with one hexadecimal SHA-256 per line.
///
/// Every hash is added under `name` and `category`. A hash may be wrapped in
/// double quotes.
///
/// # Errors
///
/// Fails if the input cannot be read, if `name` is not an acceptable
/// detection name, or if the builder reaches a limit of the format.
pub fn import_hash_list<R: BufRead>(
    mut reader: R,
    builder: &mut SigDbBuilder,
    name: &str,
    category: Category,
) -> Result<ImportStats, SigDbError> {
    format::check_name(name).map_err(|reason| SigDbError::InvalidName {
        name: name.to_owned(),
        reason,
    })?;

    let mut stats = ImportStats::default();
    let mut buffer = Vec::new();
    while let Some(fits) = read_line(&mut reader, &mut buffer)? {
        stats.lines += 1;
        if !fits {
            stats.reject("line is longer than 4096 bytes");
            continue;
        }
        let line = String::from_utf8_lossy(&buffer);
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            stats.ignored += 1;
            continue;
        }
        match hex::decode_sha256(line.trim_matches('"')) {
            Some(hash) => {
                builder.add(hash, name, category)?;
                stats.added += 1;
            }
            None => stats.reject("not a 64-character hexadecimal SHA-256"),
        }
    }
    Ok(stats)
}

/// Imports Warden CSV: `sha256,name[,category]`.
///
/// A header row whose first field is `sha256` is skipped. Fields may be
/// double-quoted, with `""` standing for a literal quote. A missing or empty
/// category falls back to `default_category`.
///
/// # Errors
///
/// Fails if the input cannot be read or if the builder reaches a limit of the
/// format. Malformed rows are counted in the returned statistics instead.
pub fn import_csv<R: BufRead>(
    mut reader: R,
    builder: &mut SigDbBuilder,
    default_category: Category,
) -> Result<ImportStats, SigDbError> {
    let mut stats = ImportStats::default();
    let mut buffer = Vec::new();
    while let Some(fits) = read_line(&mut reader, &mut buffer)? {
        stats.lines += 1;
        if !fits {
            stats.reject("line is longer than 4096 bytes");
            continue;
        }
        let line = String::from_utf8_lossy(&buffer);
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            stats.ignored += 1;
            continue;
        }
        let Some(fields) = split_csv_line(line) else {
            stats.reject("unbalanced double quotes");
            continue;
        };
        if fields.len() < 2 || fields.len() > 3 {
            stats.reject("expected sha256,name[,category]");
            continue;
        }
        let Some(hash) = hex::decode_sha256(fields[0].trim()) else {
            if stats.added == 0 && fields[0].trim().eq_ignore_ascii_case("sha256") {
                stats.ignored += 1;
            } else {
                stats.reject("first field is not a 64-character hexadecimal SHA-256");
            }
            continue;
        };
        let name = fields[1].trim();
        if format::check_name(name).is_err() {
            stats.reject("detection name is empty, too long or contains control characters");
            continue;
        }
        let category = match fields.get(2).map(|field| field.trim()) {
            None | Some("") => default_category,
            Some(text) => match text.parse::<Category>() {
                Ok(category) => category,
                Err(_) => {
                    stats.reject("unknown category");
                    continue;
                }
            },
        };
        builder.add(hash, name, category)?;
        stats.added += 1;
    }
    Ok(stats)
}

/// Reads one line into `buffer`, without its line ending.
///
/// Returns `None` at end of input, `Some(true)` for a line that fits in
/// [`MAX_LINE_LEN`], and `Some(false)` for a longer line, which is skipped
/// without being buffered so that a hostile input cannot exhaust memory.
fn read_line<R: BufRead>(reader: &mut R, buffer: &mut Vec<u8>) -> Result<Option<bool>, SigDbError> {
    read_line_io(reader, buffer)
        .map_err(|source| SigDbError::io("cannot read signature list", source))
}

fn read_line_io<R: BufRead>(reader: &mut R, buffer: &mut Vec<u8>) -> io::Result<Option<bool>> {
    buffer.clear();
    let mut read_anything = false;
    let mut fits = true;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            if !read_anything {
                return Ok(None);
            }
            break;
        }
        read_anything = true;
        let newline = available.iter().position(|&byte| byte == b'\n');
        let chunk = &available[..newline.unwrap_or(available.len())];
        if fits {
            if buffer.len() + chunk.len() > MAX_LINE_LEN {
                fits = false;
                buffer.clear();
            } else {
                buffer.extend_from_slice(chunk);
            }
        }
        let consumed = chunk.len() + usize::from(newline.is_some());
        reader.consume(consumed);
        if newline.is_some() {
            break;
        }
    }
    if buffer.last() == Some(&b'\r') {
        buffer.pop();
    }
    Ok(Some(fits))
}

/// Splits one CSV record. Returns `None` if a quoted field is never closed.
fn split_csv_line(line: &str) -> Option<Vec<String>> {
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut in_quotes = false;
    let mut characters = line.chars().peekable();
    while let Some(character) = characters.next() {
        if in_quotes {
            if character == '"' {
                if characters.peek() == Some(&'"') {
                    characters.next();
                    field.push('"');
                } else {
                    in_quotes = false;
                }
            } else {
                field.push(character);
            }
        } else if character == ',' {
            fields.push(std::mem::take(&mut field));
        } else if character == '"' && field.trim().is_empty() {
            field.clear();
            in_quotes = true;
        } else {
            field.push(character);
        }
    }
    if in_quotes {
        return None;
    }
    fields.push(field);
    Some(fields)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SigDb;

    const HASH_A: &str = "00000000000000000000000000000000000000000000000000000000000000aa";
    const HASH_B: &str = "11111111111111111111111111111111111111111111111111111111111111bb";
    const HASH_C: &str = "22222222222222222222222222222222222222222222222222222222222222cc";

    fn finish(builder: SigDbBuilder) -> SigDb {
        SigDb::from_bytes(builder.build().unwrap().0).unwrap()
    }

    #[test]
    fn hash_list_skips_comments_blanks_and_bad_lines() {
        let input = format!(
            "# MalwareBazaar style header\r\n\r\n{HASH_A}\r\n\"{}\"\nnot-a-hash\n{HASH_C}",
            HASH_B.to_uppercase()
        );
        let mut builder = SigDbBuilder::new();
        let stats = import_hash_list(
            input.as_bytes(),
            &mut builder,
            "Feed.Generic",
            Category::Malware,
        )
        .unwrap();
        assert_eq!(stats.lines, 6);
        assert_eq!(stats.added, 3);
        assert_eq!(stats.ignored, 2);
        assert_eq!(stats.invalid, 1);
        assert_eq!(stats.invalid_samples[0].line, 5);

        let db = finish(builder);
        for text in [HASH_A, HASH_B, HASH_C] {
            let hit = db.lookup(&hex::decode_sha256(text).unwrap()).unwrap();
            assert_eq!(hit.name, "Feed.Generic");
        }
    }

    #[test]
    fn hash_list_rejects_a_bad_default_name_up_front() {
        let mut builder = SigDbBuilder::new();
        let result = import_hash_list(HASH_A.as_bytes(), &mut builder, "", Category::Malware);
        assert!(matches!(result, Err(SigDbError::InvalidName { .. })));
    }

    #[test]
    fn overlong_lines_are_counted_not_buffered() {
        let input = format!("{}\n{HASH_A}\n", "f".repeat(MAX_LINE_LEN * 3));
        let mut builder = SigDbBuilder::new();
        // A tiny buffer forces the long line to arrive in many pieces.
        let reader = io::BufReader::with_capacity(16, input.as_bytes());
        let stats =
            import_hash_list(reader, &mut builder, "Feed.Generic", Category::Malware).unwrap();
        assert_eq!((stats.lines, stats.added, stats.invalid), (2, 1, 1));
    }

    #[test]
    fn csv_reads_names_categories_quotes_and_header() {
        let input = format!(
            "sha256,name,category\n\
             {HASH_A},Trojan.Example,malware\n\
             {HASH_B},\"Adware, \"\"Bundled\"\"\",pup\n\
             {HASH_C},Test.File\n\
             {HASH_A},Bad.Category,virus\n\
             too,many,fields,here\n\
             {HASH_B},\"unterminated\n"
        );
        let mut builder = SigDbBuilder::new();
        let stats = import_csv(input.as_bytes(), &mut builder, Category::TestFile).unwrap();
        assert_eq!(stats.added, 3);
        assert_eq!(stats.ignored, 1);
        assert_eq!(stats.invalid, 3);

        let db = finish(builder);
        let a = db.lookup(&hex::decode_sha256(HASH_A).unwrap()).unwrap();
        assert_eq!((a.name, a.category), ("Trojan.Example", Category::Malware));
        let b = db.lookup(&hex::decode_sha256(HASH_B).unwrap()).unwrap();
        assert_eq!(
            (b.name, b.category),
            ("Adware, \"Bundled\"", Category::PotentiallyUnwanted)
        );
        let c = db.lookup(&hex::decode_sha256(HASH_C).unwrap()).unwrap();
        assert_eq!((c.name, c.category), ("Test.File", Category::TestFile));
    }

    #[test]
    fn csv_line_splitting() {
        assert_eq!(
            split_csv_line("a,b,c"),
            Some(vec!["a".into(), "b".into(), "c".into()])
        );
        assert_eq!(
            split_csv_line("a,,"),
            Some(vec!["a".into(), String::new(), String::new()])
        );
        assert_eq!(
            split_csv_line("\"a,b\",c"),
            Some(vec!["a,b".into(), "c".into()])
        );
        assert_eq!(split_csv_line("\"open"), None);
    }
}

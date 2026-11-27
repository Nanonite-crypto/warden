//! The record of what was removed together with a quarantined file.
//!
//! It is written before anything is touched and holds every entry whole,
//! so that from that moment on an entry is in its place, in the record,
//! or in both, and never in neither. The quarantine keeps it with the
//! file's entry ([`warden_quarantine::Quarantine::attach`]) as JSON, which
//! a person can read and check against what Windows' own tools print.

use serde::{Deserialize, Serialize};

use crate::entry::Entry;

/// The kind under which the quarantine keeps this record with an entry.
pub const KIND: &str = "autostart";

/// The version of the record's layout that this version of Warden
/// writes.
pub const SCHEMA: u32 = 1;

/// What was removed, or was to be removed, together with one quarantined
/// file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    /// The version of this layout.
    pub schema: u32,
    /// The identifier of the file's entry in the quarantine.
    pub entry: String,
    /// Where the file lay.
    pub file: String,
    /// When the record was made, in milliseconds since the Unix epoch.
    pub made_unix_ms: u64,
    /// The version of Warden that made it.
    pub warden_version: String,
    /// The entries that started the file.
    pub items: Vec<Item>,
}

/// One entry that started the file, and what became of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Item {
    /// The entry, whole.
    pub what: Entry,
    /// What became of it.
    pub state: State,
    /// For a shortcut: the identifier of the entry that the shortcut
    /// file itself has in the quarantine.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quarantined_as: Option<String>,
    /// Why it was left, or what went wrong with it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// Whether it was left for want of rights, so that somebody with more
    /// rights can go on where this stopped.
    #[serde(default, skip_serializing_if = "is_false")]
    pub needs_rights: bool,
}

/// In the form `skip_serializing_if` asks for.
fn is_false(flag: &bool) -> bool {
    !*flag
}

/// What became of an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    /// It is written down. Whether it has been removed is not known: the
    /// removal may have been cut off before or after it.
    Recorded,
    /// It was removed.
    Removed,
    /// It is still in its place, for the reason in the note.
    Left,
}

impl Record {
    /// The record as the bytes that are kept.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        // A record holds nothing that JSON cannot express: text, numbers
        // and bytes written as hexadecimal text.
        serde_json::to_vec_pretty(self).unwrap_or_default()
    }

    /// Reads a record.
    ///
    /// # Errors
    ///
    /// Fails with a sentence if the bytes are not a record, or one of a
    /// layout this version of Warden does not know.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let record: Self = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        if record.schema != SCHEMA {
            return Err(format!(
                "it has layout {}, and this version of Warden reads layout {SCHEMA}",
                record.schema
            ));
        }
        Ok(record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::Shortcut;

    fn record() -> Record {
        Record {
            schema: SCHEMA,
            entry: "0123456789abcdef".to_owned(),
            file: r"C:\x\a.exe".to_owned(),
            made_unix_ms: 1_795_000_000_000,
            warden_version: "0.1.0".to_owned(),
            items: vec![Item {
                what: Entry::Shortcut(Shortcut {
                    path: r"C:\Startup\a.lnk".to_owned(),
                    target: r"C:\x\a.exe".to_owned(),
                    arguments: String::new(),
                }),
                state: State::Removed,
                quarantined_as: Some("fedcba9876543210".to_owned()),
                note: None,
                needs_rights: false,
            }],
        }
    }

    #[test]
    fn a_record_survives_being_kept() {
        let record = record();
        let bytes = record.to_bytes();
        assert_eq!(Record::from_bytes(&bytes).unwrap(), record);
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains(r#""state": "removed""#), "{text}");
        assert!(text.contains(r#""kind": "shortcut""#), "{text}");
    }

    #[test]
    fn what_is_no_record_is_turned_down() {
        assert!(Record::from_bytes(b"").is_err());
        assert!(Record::from_bytes(b"{}").is_err());
        let newer = Record {
            schema: SCHEMA + 1,
            ..record()
        };
        assert!(
            Record::from_bytes(&newer.to_bytes())
                .unwrap_err()
                .contains("layout 2")
        );
        let mut extra: serde_json::Value = serde_json::from_slice(&record().to_bytes()).unwrap();
        extra["made_up"] = serde_json::json!(1);
        assert!(Record::from_bytes(extra.to_string().as_bytes()).is_err());
    }
}

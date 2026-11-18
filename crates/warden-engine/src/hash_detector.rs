use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use warden_sigdb::SigDb;

use crate::detector::{Detector, DetectorError, DetectorInfo, FileView, InfoValue, Session};
use crate::finding::{Confidence, Finding, ThreatCategory};
use crate::{Sha256, eicar};

struct Builtin {
    sha256: Sha256,
    name: &'static str,
    category: ThreatCategory,
    reason: &'static str,
}

/// Detection layer 1: exact matches on the SHA-256 of a file.
///
/// A hash match is the strongest evidence there is, and the cheapest to
/// compute, so this layer runs first. It is also the easiest to evade: one
/// changed byte gives a different hash. The layers planned on top of it
/// (YARA rules, then PE heuristics) exist to catch what this one cannot.
///
/// The detector always knows the EICAR test file, so a fresh install can be
/// checked without any signature database.
pub struct HashDetector {
    builtin: Vec<Builtin>,
    database: Option<Arc<SigDb>>,
}

impl HashDetector {
    /// Identifier of this detector in findings and reports.
    pub const ID: &'static str = "hash";

    /// Creates a detector with the built-in signatures only.
    #[must_use]
    pub fn new() -> Self {
        Self {
            builtin: vec![Builtin {
                sha256: crate::sha256(&eicar::test_file()),
                name: eicar::DETECTION_NAME,
                category: ThreatCategory::TestFile,
                reason: "SHA-256 matches the EICAR antivirus test file, \
                         a harmless file that every scanner detects on purpose",
            }],
            database: None,
        }
    }

    /// Creates a detector with the built-in signatures and a database.
    #[must_use]
    pub fn with_database(database: Arc<SigDb>) -> Self {
        Self {
            database: Some(database),
            ..Self::new()
        }
    }

    /// Number of built-in signatures.
    #[must_use]
    pub fn builtin_signatures(&self) -> usize {
        self.builtin.len()
    }

    /// The signature database in use, if any.
    #[must_use]
    pub fn database(&self) -> Option<&SigDb> {
        self.database.as_deref()
    }
}

impl Default for HashDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for HashDetector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HashDetector")
            .field("builtin_signatures", &self.builtin.len())
            .field("database", &self.database)
            .finish()
    }
}

impl Detector for HashDetector {
    fn id(&self) -> &'static str {
        Self::ID
    }

    fn describe(&self) -> DetectorInfo {
        let mut details = BTreeMap::new();
        details.insert(
            "builtin_signatures",
            InfoValue::Count(self.builtin.len() as u64),
        );
        if let Some(database) = &self.database {
            details.insert(
                "database_signatures",
                InfoValue::Count(database.len() as u64),
            );
            details.insert(
                "database_digest",
                InfoValue::Text(warden_sigdb::hex::encode(&database.digest())),
            );
            details.insert(
                "database_created_unix_secs",
                InfoValue::Count(database.created_unix_secs()),
            );
        }
        DetectorInfo {
            id: Self::ID,
            details,
        }
    }

    fn session(&self) -> Box<dyn Session + '_> {
        // A lookup needs no scratch state, so the detector is its own session.
        Box::new(self)
    }
}

impl Session for &HashDetector {
    fn inspect(&mut self, file: &FileView<'_>) -> Result<Vec<Finding>, DetectorError> {
        let sha256 = file.sha256();
        if let Some(builtin) = self.builtin.iter().find(|entry| &entry.sha256 == sha256) {
            return Ok(vec![Finding::new(
                HashDetector::ID,
                builtin.name,
                builtin.category,
                Confidence::Definitive,
                vec![builtin.reason.to_owned()],
            )]);
        }
        let Some(signature) = self.database.as_ref().and_then(|db| db.lookup(sha256)) else {
            return Ok(Vec::new());
        };
        Ok(vec![Finding::new(
            HashDetector::ID,
            signature.name,
            signature.category.into(),
            Confidence::Definitive,
            vec!["SHA-256 matches an entry in the signature database".to_owned()],
        )])
    }
}

#[cfg(test)]
mod tests {
    use warden_sigdb::{Category, SigDbBuilder};

    use super::*;

    fn inspect(detector: &HashDetector, bytes: &[u8]) -> Vec<Finding> {
        let sha256 = crate::sha256(bytes);
        let view = FileView::in_memory(bytes, &sha256);
        detector.session().inspect(&view).unwrap()
    }

    #[test]
    fn eicar_is_detected_without_a_database() {
        let findings = inspect(&HashDetector::new(), &eicar::test_file());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].name, eicar::DETECTION_NAME);
        assert_eq!(findings[0].category, ThreatCategory::TestFile);
        assert_eq!(findings[0].confidence, Confidence::Definitive);
        assert!(!findings[0].reasons.is_empty());
    }

    #[test]
    fn one_changed_byte_is_no_longer_a_match() {
        let mut bytes = eicar::test_file();
        bytes.push(b'\n');
        assert!(inspect(&HashDetector::new(), &bytes).is_empty());
    }

    #[test]
    fn database_entries_are_detected_with_their_name_and_category() {
        let known_bad = b"harmless bytes that this test declares to be bad";
        let mut builder = SigDbBuilder::new();
        builder
            .add(
                crate::sha256(known_bad),
                "Test.Fixture",
                Category::PotentiallyUnwanted,
            )
            .unwrap();
        let database = Arc::new(SigDb::from_bytes(builder.build().unwrap().0).unwrap());
        let detector = HashDetector::with_database(database);

        let findings = inspect(&detector, known_bad);
        assert_eq!(findings[0].name, "Test.Fixture");
        assert_eq!(findings[0].category, ThreatCategory::PotentiallyUnwanted);
        assert!(inspect(&detector, b"something else").is_empty());
        // The built-in signatures stay active next to a database.
        assert_eq!(inspect(&detector, &eicar::test_file()).len(), 1);
    }

    #[test]
    fn describe_reports_signature_counts() {
        let info = HashDetector::new().describe();
        assert_eq!(info.id, "hash");
        assert_eq!(info.details["builtin_signatures"], InfoValue::Count(1));
        assert!(!info.details.contains_key("database_signatures"));
    }
}

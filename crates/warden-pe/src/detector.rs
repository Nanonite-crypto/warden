//! The heuristic layer as a detector for the scan pipeline.

use std::collections::BTreeMap;

use warden_engine::{
    Confidence, Detector, DetectorError, DetectorInfo, FileView, Finding, InfoValue, Session,
    ThreatCategory,
};

use crate::assess::{Assessment, SUSPICIOUS_FROM, assess_with};
use crate::indicators::{self, Context};
use crate::reader::read;

/// The name of the finding this layer reports.
pub const FINDING_NAME: &str = "Heuristic.SuspiciousExecutable";

/// Judges Windows executables by their structure.
///
/// The finding it makes has [`Confidence::Medium`], which the default
/// verdict policy reports as suspicious: the file is shown to the user,
/// and nothing is done to it. Structure alone never makes a file malicious.
#[derive(Debug, Clone)]
pub struct PeDetector {
    suspicious_from: u32,
}

impl PeDetector {
    /// A detector with Warden's threshold.
    #[must_use]
    pub fn new() -> Self {
        Self {
            suspicious_from: SUSPICIOUS_FROM,
        }
    }

    /// A detector that counts a file as suspicious from another score.
    #[must_use]
    pub fn with_threshold(suspicious_from: u32) -> Self {
        Self { suspicious_from }
    }
}

impl Default for PeDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for PeDetector {
    fn id(&self) -> &'static str {
        "heuristic"
    }

    fn needs_content(&self) -> bool {
        true
    }

    fn describe(&self) -> DetectorInfo {
        let mut details = BTreeMap::new();
        details.insert(
            "indicators",
            InfoValue::Count(indicators::all().count() as u64),
        );
        details.insert(
            "indicators_scored",
            InfoValue::Count(
                indicators::all()
                    .filter(|indicator| indicator.weight > 0)
                    .count() as u64,
            ),
        );
        details.insert(
            "suspicious_from",
            InfoValue::Count(u64::from(self.suspicious_from)),
        );
        DetectorInfo {
            id: self.id(),
            details,
        }
    }

    fn session(&self) -> Box<dyn Session + '_> {
        Box::new(PeSession {
            suspicious_from: self.suspicious_from,
            context: Context::now(),
        })
    }
}

struct PeSession {
    suspicious_from: u32,
    context: Context,
}

impl Session for PeSession {
    fn inspect(&mut self, file: &FileView<'_>) -> Result<Vec<Finding>, DetectorError> {
        let Some(content) = file.content() else {
            return Ok(Vec::new());
        };
        let Ok(facts) = read(content) else {
            return Ok(Vec::new());
        };
        let assessment = assess_with(&facts, &self.context, self.suspicious_from);
        Ok(finding_for(&assessment).into_iter().collect())
    }
}

/// The finding an assessment amounts to: one if the file is suspicious,
/// none otherwise. Its reasons are the indicators behind the score.
#[must_use]
pub fn finding_for(assessment: &Assessment) -> Option<Finding> {
    if !assessment.suspicious {
        return None;
    }
    let mut reasons = vec![format!(
        "The structure of the file scores {}; a file counts as suspicious from {}",
        assessment.score, assessment.suspicious_from
    )];
    reasons.extend(assessment.scored().map(|hit| {
        format!(
            "+{} {}: {}",
            hit.indicator.weight, hit.indicator.summary, hit.detail
        )
    }));
    Some(Finding::new(
        "heuristic",
        FINDING_NAME,
        ThreatCategory::Malware,
        Confidence::Medium,
        reasons,
    ))
}

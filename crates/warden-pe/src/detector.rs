//! The heuristic layer as a detector for the scan pipeline.

use std::collections::BTreeMap;

use warden_engine::{
    Confidence, Detector, DetectorError, DetectorInfo, FileView, Finding, InfoValue, Session,
    ThreatCategory,
};

use crate::assess::{Assessment, Level, Thresholds, assess};
use crate::indicators::{self, Context};
use crate::reader::read;

/// The name of the finding this layer reports.
pub const FINDING_NAME: &str = "Heuristic.SuspiciousExecutable";

/// Judges Windows executables by their structure.
///
/// The strongest finding it makes has [`Confidence::Medium`], which the
/// default verdict policy reports as suspicious: a file is shown to the
/// user, and nothing is done to it. Structure alone never makes a file
/// malicious.
#[derive(Debug, Clone, Default)]
pub struct PeDetector {
    thresholds: Thresholds,
}

impl PeDetector {
    /// A detector with Warden's thresholds.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A detector with other thresholds.
    #[must_use]
    pub fn with_thresholds(thresholds: Thresholds) -> Self {
        Self { thresholds }
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
            InfoValue::Count(u64::from(self.thresholds.suspicious)),
        );
        details.insert(
            "noted_from",
            InfoValue::Count(u64::from(self.thresholds.noted)),
        );
        DetectorInfo {
            id: self.id(),
            details,
        }
    }

    fn session(&self) -> Box<dyn Session + '_> {
        Box::new(PeSession {
            thresholds: self.thresholds,
            context: Context::now(),
        })
    }
}

struct PeSession {
    thresholds: Thresholds,
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
        let assessment = assess(&facts, &self.context, &self.thresholds);
        Ok(finding_for(&assessment, &self.thresholds)
            .into_iter()
            .collect())
    }
}

/// The finding an assessment amounts to, if any.
#[must_use]
pub fn finding_for(assessment: &Assessment, thresholds: &Thresholds) -> Option<Finding> {
    let confidence = match assessment.level {
        Level::Unremarkable => return None,
        Level::Noted => Confidence::Low,
        Level::Suspicious => Confidence::Medium,
    };
    let mut reasons = vec![format!(
        "The file's structure scores {}; a file counts as suspicious from {}",
        assessment.score, thresholds.suspicious
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
        confidence,
        reasons,
    ))
}

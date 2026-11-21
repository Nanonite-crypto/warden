//! The heuristic layer as a detector for the scan pipeline.

use std::collections::BTreeMap;

use warden_engine::{
    Confidence, Detector, DetectorError, DetectorInfo, FileView, Finding, InfoValue, Session,
    ThreatCategory,
};

use crate::assess::{Assessment, Thresholds, assess_with};
use crate::indicators::{self, Context};
use crate::reader::read;

/// The name of the finding this layer reports about a suspicious file.
pub const FINDING_NAME: &str = "Heuristic.SuspiciousExecutable";

/// The name under which this layer offers a second sign.
pub const SECOND_SIGN_NAME: &str = "Heuristic.UnusualExecutable";

/// Judges Windows executables by their structure.
///
/// A file whose score reaches the threshold gets a finding with
/// [`Confidence::Medium`], which the default verdict policy reports as
/// suspicious: the file is shown to the user, and nothing is done to it.
/// Structure alone never makes a file malicious.
///
/// A file whose score stays below the threshold and reaches the lower bar
/// gets no finding of its own. The layer offers its assessment as a
/// [second sign](warden_engine::Counts::AsSecondSign): it is kept only if
/// another layer has a finding about the same file that waits for one.
#[derive(Debug, Clone)]
pub struct PeDetector {
    thresholds: Thresholds,
}

impl PeDetector {
    /// A detector with Warden's thresholds.
    #[must_use]
    pub fn new() -> Self {
        Self::with_thresholds(Thresholds::default())
    }

    /// A detector that goes by other scores.
    #[must_use]
    pub fn with_thresholds(thresholds: Thresholds) -> Self {
        Self { thresholds }
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
            InfoValue::Count(u64::from(self.thresholds.suspicious_from)),
        );
        details.insert(
            "second_sign_from",
            InfoValue::Count(u64::from(self.thresholds.second_sign_from)),
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
        let assessment = assess_with(&facts, &self.context, self.thresholds);
        Ok(finding_for(&assessment).into_iter().collect())
    }
}

/// What an assessment amounts to in a scan: a finding if the file is
/// suspicious, a second sign if its score reaches the lower bar, and
/// nothing otherwise. The reasons are the indicators behind the score.
#[must_use]
pub fn finding_for(assessment: &Assessment) -> Option<Finding> {
    let opening = if assessment.suspicious {
        format!(
            "The structure of the file scores {}; a file counts as suspicious from {}",
            assessment.score, assessment.suspicious_from
        )
    } else if assessment.second_sign {
        format!(
            "The structure of the file scores {}: less than the {} that make a file suspicious, \
             and at least the {} from which it backs up a finding of another layer",
            assessment.score, assessment.suspicious_from, assessment.second_sign_from
        )
    } else {
        return None;
    };
    let mut reasons = vec![opening];
    reasons.extend(assessment.scored().map(|hit| {
        format!(
            "+{} {}: {}",
            hit.indicator.weight, hit.indicator.summary, hit.detail
        )
    }));
    Some(if assessment.suspicious {
        Finding::new(
            "heuristic",
            FINDING_NAME,
            ThreatCategory::Malware,
            Confidence::Medium,
            reasons,
        )
    } else {
        Finding::new(
            "heuristic",
            SECOND_SIGN_NAME,
            ThreatCategory::Malware,
            Confidence::Low,
            reasons,
        )
        .as_second_sign()
    })
}

use serde::Serialize;

/// What kind of thing a finding identifies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatCategory {
    /// Malicious software.
    Malware,
    /// A harmless antivirus test file, such as the EICAR test file.
    TestFile,
    /// A potentially unwanted program: not malware, but rarely wanted.
    PotentiallyUnwanted,
}

impl From<warden_sigdb::Category> for ThreatCategory {
    fn from(category: warden_sigdb::Category) -> Self {
        match category {
            warden_sigdb::Category::Malware => Self::Malware,
            warden_sigdb::Category::TestFile => Self::TestFile,
            warden_sigdb::Category::PotentiallyUnwanted => Self::PotentiallyUnwanted,
        }
    }
}

/// How sure a detector is about a finding.
///
/// The order matters: later variants are stronger, and the verdict policy
/// compares against thresholds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// Worth recording, not worth acting on alone.
    Low,
    /// Unusual enough to show the user.
    Medium,
    /// Strong evidence short of an exact match.
    High,
    /// An exact match against a known-bad file.
    Definitive,
}

/// One thing a detector noticed about a file.
///
/// A finding always says why: `reasons` is the evidence, written for a
/// person, and is what the user interface shows under "why was this
/// flagged?".
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    /// Identifier of the detector that produced the finding.
    pub detector: &'static str,
    /// Detection name, for example `EICAR-Test-File`.
    pub name: String,
    /// What kind of thing was found.
    pub category: ThreatCategory,
    /// How sure the detector is.
    pub confidence: Confidence,
    /// The evidence, one human-readable sentence per item.
    pub reasons: Vec<String>,
}

/// The decision about one file, derived from its findings by a
/// [`VerdictPolicy`](crate::VerdictPolicy).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Nothing worth reporting.
    Clean,
    /// Unusual, shown to the user, never acted on automatically.
    Suspicious,
    /// Treated as a threat.
    Malicious,
}

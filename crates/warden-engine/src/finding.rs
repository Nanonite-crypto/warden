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

/// When a finding counts towards the verdict.
///
/// Most findings count by themselves. Some evidence is too weak for that
/// and still worth having. A rule that a tool generated from malware
/// samples also matches the library code those samples share with clean
/// software, and an executable with an odd structure is usually a packed
/// installer. Each is common enough among clean files; both about the same
/// file is not. So one layer can report a finding that waits for a second
/// sign, another layer can offer one, and
/// [`VerdictPolicy::settle`](crate::VerdictPolicy::settle) brings the two
/// together.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Counts {
    /// By itself, with the confidence it states.
    #[default]
    Alone,
    /// Only when another layer has something to say about the same file.
    /// Until then it is kept with low confidence, which changes nothing.
    WithSecondSign,
    /// Never by itself. It is the second sign that a finding of another
    /// layer may be waiting for, and it is dropped when none is.
    AsSecondSign,
}

impl Counts {
    /// Whether this is [`Counts::Alone`], the usual case.
    #[must_use]
    pub fn is_alone(&self) -> bool {
        *self == Self::Alone
    }
}

/// A file inside an archive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Member {
    /// The names leading from the scanned file to the member, outermost
    /// first: `["inner.zip", "tool.exe"]` is `tool.exe` inside `inner.zip`
    /// inside the scanned file. Names come from the archive, so control
    /// characters in them are replaced before they get here.
    pub path: Vec<String>,
    /// Size of the member after unpacking, in bytes.
    pub size: u64,
    /// SHA-256 of the unpacked member, in lowercase hexadecimal.
    pub sha256: String,
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
    /// How sure the detector is. For a finding that counts only with a
    /// second sign, this is what it is worth once it has one.
    pub confidence: Confidence,
    /// When the finding counts towards the verdict. Left out of a report
    /// when it counts by itself.
    #[serde(skip_serializing_if = "Counts::is_alone")]
    pub counts: Counts,
    /// The evidence, one human-readable sentence per item.
    pub reasons: Vec<String>,
    /// The archive member the finding is about. Absent when it is about the
    /// scanned file itself. Detectors leave this empty; the pipeline fills
    /// it in.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub member: Option<Member>,
}

impl Finding {
    /// Creates a finding about the file a detector was handed.
    #[must_use]
    pub fn new(
        detector: &'static str,
        name: impl Into<String>,
        category: ThreatCategory,
        confidence: Confidence,
        reasons: Vec<String>,
    ) -> Self {
        Self {
            detector,
            name: name.into(),
            category,
            confidence,
            counts: Counts::Alone,
            reasons,
            member: None,
        }
    }

    /// Makes this a finding that counts only when another layer has
    /// something to say about the same file.
    #[must_use]
    pub fn with_second_sign(mut self) -> Self {
        self.counts = Counts::WithSecondSign;
        self
    }

    /// Makes this a second sign: nothing by itself, and what a finding of
    /// another layer may be waiting for.
    #[must_use]
    pub fn as_second_sign(mut self) -> Self {
        self.counts = Counts::AsSecondSign;
        self
    }
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

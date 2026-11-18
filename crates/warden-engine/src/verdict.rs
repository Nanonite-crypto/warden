use crate::finding::{Confidence, Finding, Verdict};

/// Turns the findings for one file into a verdict.
///
/// Detectors describe what they saw; this policy decides what it means. With
/// the default thresholds a file is malicious as soon as one finding is at
/// least [`Confidence::High`], suspicious if the strongest finding is
/// [`Confidence::Medium`], and clean otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerdictPolicy {
    /// Weakest confidence that makes a file malicious.
    pub malicious_at: Confidence,
    /// Weakest confidence that makes a file suspicious.
    pub suspicious_at: Confidence,
}

impl Default for VerdictPolicy {
    fn default() -> Self {
        Self {
            malicious_at: Confidence::High,
            suspicious_at: Confidence::Medium,
        }
    }
}

impl VerdictPolicy {
    /// Decides the verdict for a file with the given findings.
    #[must_use]
    pub fn decide(&self, findings: &[Finding]) -> Verdict {
        match findings.iter().map(|finding| finding.confidence).max() {
            Some(strongest) if strongest >= self.malicious_at => Verdict::Malicious,
            Some(strongest) if strongest >= self.suspicious_at => Verdict::Suspicious,
            _ => Verdict::Clean,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::ThreatCategory;

    fn finding(confidence: Confidence) -> Finding {
        Finding {
            detector: "test",
            name: "Test.Finding".to_owned(),
            category: ThreatCategory::Malware,
            confidence,
            reasons: vec!["because the test says so".to_owned()],
        }
    }

    #[test]
    fn no_findings_is_clean() {
        assert_eq!(VerdictPolicy::default().decide(&[]), Verdict::Clean);
    }

    #[test]
    fn default_thresholds() {
        let policy = VerdictPolicy::default();
        assert_eq!(policy.decide(&[finding(Confidence::Low)]), Verdict::Clean);
        assert_eq!(
            policy.decide(&[finding(Confidence::Medium)]),
            Verdict::Suspicious
        );
        assert_eq!(
            policy.decide(&[finding(Confidence::High)]),
            Verdict::Malicious
        );
        assert_eq!(
            policy.decide(&[finding(Confidence::Definitive)]),
            Verdict::Malicious
        );
    }

    #[test]
    fn the_strongest_finding_decides() {
        let policy = VerdictPolicy::default();
        let findings = [
            finding(Confidence::Low),
            finding(Confidence::Definitive),
            finding(Confidence::Medium),
        ];
        assert_eq!(policy.decide(&findings), Verdict::Malicious);
    }

    #[test]
    fn thresholds_are_configurable() {
        let strict = VerdictPolicy {
            malicious_at: Confidence::Definitive,
            suspicious_at: Confidence::Low,
        };
        assert_eq!(
            strict.decide(&[finding(Confidence::High)]),
            Verdict::Suspicious
        );
        assert_eq!(
            strict.decide(&[finding(Confidence::Low)]),
            Verdict::Suspicious
        );
    }
}

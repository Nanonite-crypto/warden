use crate::finding::{Confidence, Counts, Finding, Verdict};

/// Turns the findings for one file into a verdict.
///
/// Detectors describe what they saw; this policy decides what it means. It
/// does so in two steps.
///
/// [`settle`](Self::settle) looks at everything the layers said about one
/// file, or about one member of an archive, and settles which findings
/// count: a finding that waits for a second sign counts if another layer
/// has something to say about the same file, and is kept with low
/// confidence if none has.
///
/// [`decide`](Self::decide) then goes by the strongest finding. With the
/// default thresholds a file is malicious as soon as one finding is at
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
    /// Settles which of the findings about one file count.
    ///
    /// `findings` is everything the detectors reported about one file, or
    /// about one member of an archive: a sign about one member says nothing
    /// about another. Afterwards the strongest finding decides, as
    /// [`decide`](Self::decide) has it, and no reader of the result needs to
    /// know that layers were combined: every finding carries its outcome in
    /// its confidence and says why in its last reason.
    ///
    /// - A finding that counts [with a second sign](Counts::WithSecondSign)
    ///   keeps its confidence if another detector backs it up. What backs
    ///   it up is a [second sign](Counts::AsSecondSign), another finding
    ///   that waits for one, or a finding that would make the file
    ///   suspicious by itself. Without any of these its confidence becomes
    ///   [`Confidence::Low`]: it stays on record and changes nothing.
    /// - A second sign always has low confidence, and it is dropped when no
    ///   finding of another detector waits for one. An executable with a
    ///   slightly unusual structure is not worth a line in a report.
    ///
    /// Two findings of the same detector never back each other up. Two
    /// rules that were generated from samples of related malware match the
    /// same shared code; that is one sign, seen twice.
    pub fn settle(&self, findings: &mut Vec<Finding>) {
        if findings.iter().all(|finding| finding.counts.is_alone()) {
            return;
        }

        // Who has something to lean on, and who is waiting.
        let backing: Vec<&'static str> = findings
            .iter()
            .filter(|finding| match finding.counts {
                Counts::WithSecondSign | Counts::AsSecondSign => true,
                Counts::Alone => finding.confidence >= self.suspicious_at,
            })
            .map(|finding| finding.detector)
            .collect();
        let waiting: Vec<&'static str> = findings
            .iter()
            .filter(|finding| finding.counts == Counts::WithSecondSign)
            .map(|finding| finding.detector)
            .collect();

        findings.retain_mut(|finding| match finding.counts {
            Counts::Alone => true,
            Counts::WithSecondSign => {
                let mut others: Vec<&str> = backing
                    .iter()
                    .copied()
                    .filter(|detector| *detector != finding.detector)
                    .collect();
                others.sort_unstable();
                others.dedup();
                if others.is_empty() {
                    finding.confidence = Confidence::Low;
                    finding.reasons.push(
                        "No other layer has anything to say about this file, so this is \
                         recorded and does not change the verdict"
                            .to_owned(),
                    );
                } else {
                    finding.reasons.push(format!(
                        "Counts, because another layer has something to say about the same \
                         file: {}",
                        others.join(", ")
                    ));
                }
                true
            }
            Counts::AsSecondSign => {
                finding.confidence = Confidence::Low;
                waiting.iter().any(|detector| *detector != finding.detector)
            }
        });
    }

    /// Decides the verdict for a file with the given findings, which have
    /// been [settled](Self::settle).
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
        Finding::new(
            "test",
            "Test.Finding",
            ThreatCategory::Malware,
            confidence,
            vec!["because the test says so".to_owned()],
        )
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

    fn from(detector: &'static str, confidence: Confidence) -> Finding {
        Finding::new(
            detector,
            format!("{detector}.Finding"),
            ThreatCategory::Malware,
            confidence,
            vec![format!("because {detector} says so")],
        )
    }

    /// Settles the findings about one file and decides.
    fn settled(mut findings: Vec<Finding>) -> (Verdict, Vec<Finding>) {
        let policy = VerdictPolicy::default();
        policy.settle(&mut findings);
        (policy.decide(&findings), findings)
    }

    #[test]
    fn settling_leaves_ordinary_findings_alone() {
        let before = vec![
            from("rules", Confidence::Low),
            from("hashes", Confidence::Definitive),
        ];
        let (verdict, after) = settled(before.clone());
        assert_eq!(verdict, Verdict::Malicious);
        assert_eq!(after, before);
    }

    #[test]
    fn a_finding_that_waits_for_a_second_sign_is_only_recorded_without_one() {
        let (verdict, findings) =
            settled(vec![from("rules", Confidence::Medium).with_second_sign()]);
        assert_eq!(verdict, Verdict::Clean);
        assert_eq!(findings.len(), 1, "it stays on record");
        assert_eq!(findings[0].confidence, Confidence::Low);
        assert_eq!(findings[0].counts, Counts::WithSecondSign);
        let last = findings[0].reasons.last().map(String::as_str);
        assert!(
            last.is_some_and(|reason| reason.contains("does not change the verdict")),
            "{last:?}"
        );
    }

    #[test]
    fn a_second_sign_from_another_layer_makes_it_count() {
        let (verdict, findings) = settled(vec![
            from("rules", Confidence::Medium).with_second_sign(),
            from("structure", Confidence::Low).as_second_sign(),
        ]);
        assert_eq!(verdict, Verdict::Suspicious);
        assert_eq!(findings.len(), 2, "the second sign is part of the evidence");
        assert_eq!(findings[0].confidence, Confidence::Medium);
        let last = findings[0].reasons.last().map(String::as_str);
        assert!(
            last.is_some_and(|reason| reason.ends_with("same file: structure")),
            "{last:?}"
        );
        assert_eq!(findings[1].confidence, Confidence::Low);
    }

    #[test]
    fn a_second_sign_with_nothing_to_back_is_dropped() {
        let (verdict, findings) =
            settled(vec![from("structure", Confidence::Low).as_second_sign()]);
        assert_eq!(verdict, Verdict::Clean);
        assert!(findings.is_empty());

        // Next to an ordinary finding it is still nobody's second sign.
        let (verdict, findings) = settled(vec![
            from("rules", Confidence::Low),
            from("structure", Confidence::Low).as_second_sign(),
        ]);
        assert_eq!(verdict, Verdict::Clean);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].detector, "rules");
    }

    #[test]
    fn a_second_sign_never_counts_by_itself_whatever_confidence_it_claims() {
        let (verdict, findings) = settled(vec![
            from("rules", Confidence::Medium).with_second_sign(),
            from("structure", Confidence::Definitive).as_second_sign(),
        ]);
        assert_eq!(verdict, Verdict::Suspicious);
        assert_eq!(findings[1].confidence, Confidence::Low);
    }

    #[test]
    fn the_same_layer_does_not_back_itself_up() {
        // Two generated rules matching the same file are one sign, seen
        // twice.
        let (verdict, findings) = settled(vec![
            from("rules", Confidence::Medium).with_second_sign(),
            from("rules", Confidence::Medium).with_second_sign(),
        ]);
        assert_eq!(verdict, Verdict::Clean);
        assert!(
            findings
                .iter()
                .all(|finding| finding.confidence == Confidence::Low)
        );

        // And a layer's own second sign does not help its own finding.
        let (verdict, findings) = settled(vec![
            from("rules", Confidence::Medium).with_second_sign(),
            from("rules", Confidence::Low).as_second_sign(),
        ]);
        assert_eq!(verdict, Verdict::Clean);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn two_layers_that_both_wait_back_each_other_up() {
        let (verdict, findings) = settled(vec![
            from("rules", Confidence::Medium).with_second_sign(),
            from("model", Confidence::Medium).with_second_sign(),
        ]);
        assert_eq!(verdict, Verdict::Suspicious);
        assert!(
            findings
                .iter()
                .all(|finding| finding.confidence == Confidence::Medium)
        );
    }

    #[test]
    fn a_finding_that_counts_alone_backs_a_waiting_one_only_if_it_is_strong_enough() {
        let (verdict, findings) = settled(vec![
            from("rules", Confidence::Medium).with_second_sign(),
            from("structure", Confidence::Medium),
        ]);
        assert_eq!(verdict, Verdict::Suspicious);
        assert_eq!(findings[0].confidence, Confidence::Medium);

        // A finding that is itself only on record is nothing to lean on.
        let (verdict, findings) = settled(vec![
            from("rules", Confidence::Medium).with_second_sign(),
            from("structure", Confidence::Low),
        ]);
        assert_eq!(verdict, Verdict::Clean);
        assert_eq!(findings[0].confidence, Confidence::Low);
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn a_backed_finding_is_worth_what_it_states() {
        // The policy does not cap it: a detector that wants its backed
        // findings to stop at suspicious says medium.
        let (verdict, _) = settled(vec![
            from("rules", Confidence::High).with_second_sign(),
            from("structure", Confidence::Low).as_second_sign(),
        ]);
        assert_eq!(verdict, Verdict::Malicious);
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

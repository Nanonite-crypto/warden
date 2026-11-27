use crate::finding::{Confidence, Counts, Finding, Verdict};
use crate::trust::TrustAnswer;

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
/// [`settle_with_trust`](Self::settle_with_trust) does the same for a file
/// whose signature was checked.
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
        self.settle_with_trust(findings, None);
    }

    /// Whether it is worth asking who signed the file these findings are
    /// about: whether a finding that
    /// [yields to a trusted signature](Finding::yields_to_trust) would be
    /// reported if nobody asked.
    ///
    /// A signature check opens the file a second time and has the
    /// operating system work through certificates. Nearly every file has
    /// no finding at all, and for those this is `false` without looking
    /// further, so a scan asks about very few files.
    #[must_use]
    pub fn asks_about_trust(&self, findings: &[Finding]) -> bool {
        if !findings.iter().any(|finding| finding.yields_to_trust) {
            return false;
        }
        let mut unasked = findings.to_vec();
        self.settle(&mut unasked);
        unasked
            .iter()
            .any(|finding| finding.yields_to_trust && finding.confidence >= self.suspicious_at)
    }

    /// Settles which of the findings about one file count, as
    /// [`settle`](Self::settle) does, for a file whose signature was
    /// checked. `trust` is what the check said, or nothing if it was not
    /// asked.
    ///
    /// With a signature of a trusted publisher, every finding that
    /// [yields](Finding::yields_to_trust) is set aside before anything
    /// else is settled: its confidence becomes [`Confidence::Low`], it
    /// says why, and it backs nothing up. A finding that is itself only on
    /// record is nothing to lean on. All other findings are settled among
    /// themselves, so a hash match or a finding about the structure of the
    /// file counts exactly as it would without the signature.
    ///
    /// Without one, nothing changes except that a yielding finding that
    /// counts says what the check found.
    pub fn settle_with_trust(&self, findings: &mut Vec<Finding>, trust: Option<&TrustAnswer>) {
        let trusted = trust.is_some_and(TrustAnswer::is_trusted);
        let set_aside = |finding: &Finding| trusted && finding.yields_to_trust;

        let anything_to_combine = findings
            .iter()
            .any(|finding| !finding.counts.is_alone() && !set_aside(finding));
        if anything_to_combine {
            // Who has something to lean on, and who is waiting.
            let backing: Vec<&'static str> = findings
                .iter()
                .filter(|finding| !set_aside(finding))
                .filter(|finding| match finding.counts {
                    Counts::WithSecondSign | Counts::AsSecondSign => true,
                    Counts::Alone => finding.confidence >= self.suspicious_at,
                })
                .map(|finding| finding.detector)
                .collect();
            let waiting: Vec<&'static str> = findings
                .iter()
                .filter(|finding| !set_aside(finding))
                .filter(|finding| finding.counts == Counts::WithSecondSign)
                .map(|finding| finding.detector)
                .collect();

            findings.retain_mut(|finding| {
                if set_aside(finding) {
                    return true;
                }
                match finding.counts {
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
                                "No other layer has anything to say about this file, so this \
                                 is recorded and does not change the verdict"
                                    .to_owned(),
                            );
                        } else {
                            finding.reasons.push(format!(
                                "Counts, because another layer has something to say about the \
                                 same file: {}",
                                others.join(", ")
                            ));
                        }
                        true
                    }
                    Counts::AsSecondSign => {
                        finding.confidence = Confidence::Low;
                        waiting.iter().any(|detector| *detector != finding.detector)
                    }
                }
            });
        }

        match trust {
            Some(TrustAnswer::Trusted { detail, .. }) => {
                for finding in findings
                    .iter_mut()
                    .filter(|finding| finding.yields_to_trust)
                {
                    finding.confidence = Confidence::Low;
                    finding.reasons.push(format!(
                        "The file has a valid signature of a publisher on the trust list, so \
                         this is recorded and does not change the verdict: {detail}"
                    ));
                }
            }
            Some(TrustAnswer::NotTrusted { detail, .. }) => {
                let counting = findings.iter_mut().filter(|finding| {
                    finding.yields_to_trust && finding.confidence >= self.suspicious_at
                });
                for finding in counting {
                    finding.reasons.push(format!(
                        "No signature of a publisher on the trust list speaks for the file: \
                         {detail}"
                    ));
                }
            }
            None => {}
        }
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

    fn trusted() -> TrustAnswer {
        TrustAnswer::Trusted {
            publisher: "Example".to_owned(),
            route: "embedded",
            detail: "signed for Example, found in the file itself".to_owned(),
        }
    }

    fn unsigned() -> TrustAnswer {
        TrustAnswer::NotTrusted {
            reason: "no_signature",
            detail: "no signature was found".to_owned(),
        }
    }

    /// Settles the findings about one file whose signature was checked,
    /// and decides.
    fn settled_with(mut findings: Vec<Finding>, trust: &TrustAnswer) -> (Verdict, Vec<Finding>) {
        let policy = VerdictPolicy::default();
        policy.settle_with_trust(&mut findings, Some(trust));
        (policy.decide(&findings), findings)
    }

    #[test]
    fn nobody_is_asked_about_a_signature_without_a_finding_that_yields() {
        let policy = VerdictPolicy::default();
        assert!(!policy.asks_about_trust(&[]));
        assert!(!policy.asks_about_trust(&[from("hashes", Confidence::Definitive)]));
        assert!(!policy.asks_about_trust(&[
            from("rules", Confidence::Medium).with_second_sign(),
            from("structure", Confidence::Low).as_second_sign(),
        ]));
    }

    #[test]
    fn a_signature_is_asked_about_only_when_a_yielding_finding_would_be_reported() {
        let policy = VerdictPolicy::default();
        let yielding = |confidence| from("rules", confidence).yielding_to_trust();
        assert!(policy.asks_about_trust(&[yielding(Confidence::High)]));
        assert!(policy.asks_about_trust(&[yielding(Confidence::Medium)]));
        assert!(
            !policy.asks_about_trust(&[yielding(Confidence::Low)]),
            "it is only on record anyway"
        );

        // One that waits for a second sign is worth asking about once it
        // has one.
        let waiting = yielding(Confidence::Medium).with_second_sign();
        assert!(!policy.asks_about_trust(std::slice::from_ref(&waiting)));
        assert!(
            policy
                .asks_about_trust(&[waiting, from("structure", Confidence::Low).as_second_sign(),])
        );

        // Asking changes nothing about the findings themselves.
        let findings = vec![yielding(Confidence::High)];
        let before = findings.clone();
        let _ = policy.asks_about_trust(&findings);
        assert_eq!(findings, before);
    }

    #[test]
    fn a_trusted_signature_sets_a_yielding_finding_aside() {
        let (verdict, findings) = settled_with(
            vec![from("rules", Confidence::High).yielding_to_trust()],
            &trusted(),
        );
        assert_eq!(verdict, Verdict::Clean);
        assert_eq!(findings.len(), 1, "it stays on record");
        assert_eq!(findings[0].confidence, Confidence::Low);
        assert_eq!(
            findings[0].reasons.last().map(String::as_str),
            Some(
                "The file has a valid signature of a publisher on the trust list, so this is \
                 recorded and does not change the verdict: signed for Example, found in the \
                 file itself"
            )
        );
    }

    #[test]
    fn a_trusted_signature_changes_nothing_about_a_finding_that_does_not_yield() {
        let exact = from("hashes", Confidence::Definitive);
        let (verdict, findings) = settled_with(
            vec![
                from("rules", Confidence::High).yielding_to_trust(),
                exact.clone(),
                from("structure", Confidence::Medium),
            ],
            &trusted(),
        );
        assert_eq!(verdict, Verdict::Malicious);
        assert_eq!(findings[0].confidence, Confidence::Low);
        assert_eq!(findings[1], exact);
        assert_eq!(findings[2].confidence, Confidence::Medium);
        assert_eq!(findings[2].reasons.len(), 1, "nothing was added to it");
    }

    #[test]
    fn a_finding_that_was_set_aside_backs_nothing_up() {
        // Without a signature the rule match is what the model's finding
        // leans on.
        let findings = vec![
            from("rules", Confidence::Medium).yielding_to_trust(),
            from("model", Confidence::Medium).with_second_sign(),
        ];
        let (verdict, _) = settled(findings.clone());
        assert_eq!(verdict, Verdict::Suspicious);

        let (verdict, after) = settled_with(findings, &trusted());
        assert_eq!(verdict, Verdict::Clean);
        assert_eq!(after.len(), 2);
        assert!(
            after
                .iter()
                .all(|finding| finding.confidence == Confidence::Low)
        );
        let last = after[1].reasons.last().map(String::as_str);
        assert!(
            last.is_some_and(|reason| reason.starts_with("No other layer")),
            "{last:?}"
        );

        // The same when the rule match itself was waiting.
        let (verdict, _) = settled_with(
            vec![
                from("rules", Confidence::Medium)
                    .with_second_sign()
                    .yielding_to_trust(),
                from("model", Confidence::Medium).with_second_sign(),
            ],
            &trusted(),
        );
        assert_eq!(verdict, Verdict::Clean);
    }

    #[test]
    fn a_second_sign_goes_when_what_it_would_back_is_set_aside() {
        let findings = vec![
            from("rules", Confidence::Medium)
                .with_second_sign()
                .yielding_to_trust(),
            from("structure", Confidence::Low).as_second_sign(),
        ];
        let (verdict, kept) = settled(findings.clone());
        assert_eq!(verdict, Verdict::Suspicious);
        assert_eq!(kept.len(), 2);

        let (verdict, kept) = settled_with(findings, &trusted());
        assert_eq!(verdict, Verdict::Clean);
        assert_eq!(kept.len(), 1, "{kept:?}");
        assert_eq!(kept[0].detector, "rules");
        assert_eq!(kept[0].confidence, Confidence::Low);
        assert_eq!(
            kept[0].reasons.len(),
            2,
            "one reason for being set aside is enough: {:?}",
            kept[0].reasons
        );
    }

    #[test]
    fn without_a_trusted_signature_a_yielding_finding_counts_and_says_what_was_found() {
        let (verdict, findings) = settled_with(
            vec![
                from("rules", Confidence::High).yielding_to_trust(),
                from("rules", Confidence::Low).yielding_to_trust(),
                from("hashes", Confidence::Definitive),
            ],
            &unsigned(),
        );
        assert_eq!(verdict, Verdict::Malicious);
        assert_eq!(findings[0].confidence, Confidence::High);
        assert_eq!(
            findings[0].reasons.last().map(String::as_str),
            Some(
                "No signature of a publisher on the trust list speaks for the file: no \
                 signature was found"
            )
        );
        assert_eq!(
            findings[1].reasons.len(),
            1,
            "a finding that is only on record has nothing to explain"
        );
        assert_eq!(findings[2].reasons.len(), 1);
    }

    #[test]
    fn a_waiting_finding_that_yields_still_needs_its_second_sign_without_a_signature() {
        let (verdict, findings) = settled_with(
            vec![
                from("rules", Confidence::Medium)
                    .with_second_sign()
                    .yielding_to_trust(),
            ],
            &unsigned(),
        );
        assert_eq!(verdict, Verdict::Clean);
        assert_eq!(findings[0].confidence, Confidence::Low);
        let last = findings[0].reasons.last().map(String::as_str);
        assert!(
            last.is_some_and(|reason| reason.starts_with("No other layer")),
            "{last:?}"
        );
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

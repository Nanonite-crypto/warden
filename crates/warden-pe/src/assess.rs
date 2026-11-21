//! From indicators to a score, and from a score to a judgement.

use serde::Serialize;

use crate::facts::PeFacts;
use crate::indicators::{Context, Hit, evaluate};

/// The score from which a file counts as suspicious.
///
/// It is the lowest score that at most one in 5,000 of the benign files
/// of any kind reaches in the training weeks of EMBER2024. The calibration
/// tool computes it from the counts in `calibration/`, and a test fails if
/// this number is not what the counts give.
pub const SUSPICIOUS_FROM: u32 = 32;

/// The score from which the structure of a file is a second sign.
///
/// A score below [`SUSPICIOUS_FROM`] is not worth reporting: too many clean
/// files have one. It is still worth something next to a finding of another
/// layer that is itself too weak to count alone, such as the match of a
/// generated YARA rule. From this score on the heuristic layer offers its
/// assessment as that second sign, see
/// [`Counts::AsSecondSign`](warden_engine::Counts).
///
/// It is the lowest score that at most one in twenty of the benign files of
/// any kind reaches in the training weeks of EMBER2024. Like the threshold
/// it is computed by the calibration tool and held in place by a test.
pub const SECOND_SIGN_FROM: u32 = 14;

/// The two scores the heuristic layer goes by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Thresholds {
    /// The score from which the structure of a file is a second sign.
    pub second_sign_from: u32,
    /// The score from which a file counts as suspicious.
    pub suspicious_from: u32,
}

impl Default for Thresholds {
    /// Warden's own: [`SECOND_SIGN_FROM`] and [`SUSPICIOUS_FROM`].
    fn default() -> Self {
        Self {
            second_sign_from: SECOND_SIGN_FROM,
            suspicious_from: SUSPICIOUS_FROM,
        }
    }
}

/// The heuristic judgement of one file, with everything it rests on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Assessment {
    /// The sum of the weights of the indicators that apply.
    pub score: u32,
    /// The score from which a file counts as suspicious.
    pub suspicious_from: u32,
    /// Whether the score reaches it.
    pub suspicious: bool,
    /// The score from which the structure of a file is a second sign.
    pub second_sign_from: u32,
    /// Whether the score reaches that. True for a suspicious file as well.
    pub second_sign: bool,
    /// Every indicator that applies, in the order they are defined. Those
    /// with weight zero are listed and add nothing to the score.
    pub hits: Vec<Hit>,
}

impl Assessment {
    /// The hits that add to the score.
    pub fn scored(&self) -> impl Iterator<Item = &Hit> {
        self.hits.iter().filter(|hit| hit.indicator.weight > 0)
    }

    /// The hits that are shown and add nothing to the score.
    pub fn unscored(&self) -> impl Iterator<Item = &Hit> {
        self.hits.iter().filter(|hit| hit.indicator.weight == 0)
    }
}

/// The score of a set of hits: the sum of their weights.
#[must_use]
pub fn score_of(hits: &[Hit]) -> u32 {
    hits.iter().map(|hit| u32::from(hit.indicator.weight)).sum()
}

/// Judges a file by its facts, with Warden's thresholds.
#[must_use]
pub fn assess(facts: &PeFacts, context: &Context) -> Assessment {
    assess_with(facts, context, Thresholds::default())
}

/// Judges a file by its facts, with other thresholds.
#[must_use]
pub fn assess_with(facts: &PeFacts, context: &Context, thresholds: Thresholds) -> Assessment {
    let hits = evaluate(facts, context);
    let score = score_of(&hits);
    Assessment {
        score,
        suspicious_from: thresholds.suspicious_from,
        suspicious: score >= thresholds.suspicious_from,
        second_sign_from: thresholds.second_sign_from,
        second_sign: score >= thresholds.second_sign_from,
        hits,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::fixture::Fixture;
    use crate::reader::read;

    #[test]
    fn a_file_is_suspicious_from_the_threshold_on() {
        let facts = read(&Fixture::packed_looking().build()).unwrap();
        let context = Context::now();
        let score = assess(&facts, &context).score;
        assert!(score > 0, "the packed-looking fixture scores nothing");

        let from = |suspicious_from| Thresholds {
            suspicious_from,
            ..Thresholds::default()
        };
        let at = assess_with(&facts, &context, from(score));
        assert!(at.suspicious);
        assert_eq!(at.suspicious_from, score);
        let above = assess_with(&facts, &context, from(score + 1));
        assert!(!above.suspicious);
        assert_eq!(above.score, score);
        assert_eq!(above.hits, at.hits);
    }

    #[test]
    fn a_score_is_a_second_sign_from_its_own_bar_on() {
        let facts = read(&Fixture::packed_looking().build()).unwrap();
        let context = Context::now();
        let score = assess(&facts, &context).score;

        let bar = |second_sign_from| Thresholds {
            second_sign_from,
            suspicious_from: u32::MAX,
        };
        let at = assess_with(&facts, &context, bar(score));
        assert!(at.second_sign && !at.suspicious);
        assert_eq!(at.second_sign_from, score);
        assert!(!assess_with(&facts, &context, bar(score + 1)).second_sign);

        // A suspicious file has more than enough for a second sign.
        let suspicious = assess_with(
            &facts,
            &context,
            Thresholds {
                second_sign_from: 1,
                suspicious_from: score,
            },
        );
        assert!(suspicious.suspicious && suspicious.second_sign);
    }

    #[test]
    fn the_bar_for_a_second_sign_is_below_the_threshold() {
        let thresholds = Thresholds::default();
        assert!(thresholds.second_sign_from < thresholds.suspicious_from);
        assert_eq!(thresholds.second_sign_from, SECOND_SIGN_FROM);
        assert_eq!(thresholds.suspicious_from, SUSPICIOUS_FROM);
    }

    #[test]
    fn the_score_is_the_sum_of_the_weights_of_the_scored_hits() {
        let facts = read(&Fixture::packed_looking().build()).unwrap();
        let assessment = assess(&facts, &Context::now());
        let sum: u32 = assessment
            .scored()
            .map(|hit| u32::from(hit.indicator.weight))
            .sum();
        assert_eq!(assessment.score, sum);
        assert_eq!(
            assessment.scored().count() + assessment.unscored().count(),
            assessment.hits.len()
        );
    }
}

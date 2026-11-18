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

/// The heuristic judgement of one file, with everything it rests on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Assessment {
    /// The sum of the weights of the indicators that apply.
    pub score: u32,
    /// The score from which a file counts as suspicious.
    pub suspicious_from: u32,
    /// Whether the score reaches it.
    pub suspicious: bool,
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

/// Judges a file by its facts, with Warden's threshold.
#[must_use]
pub fn assess(facts: &PeFacts, context: &Context) -> Assessment {
    assess_with(facts, context, SUSPICIOUS_FROM)
}

/// Judges a file by its facts, with another threshold.
#[must_use]
pub fn assess_with(facts: &PeFacts, context: &Context, suspicious_from: u32) -> Assessment {
    let hits = evaluate(facts, context);
    let score = score_of(&hits);
    Assessment {
        score,
        suspicious_from,
        suspicious: score >= suspicious_from,
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

        let at = assess_with(&facts, &context, score);
        assert!(at.suspicious);
        assert_eq!(at.suspicious_from, score);
        let above = assess_with(&facts, &context, score + 1);
        assert!(!above.suspicious);
        assert_eq!(above.score, score);
        assert_eq!(above.hits, at.hits);
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

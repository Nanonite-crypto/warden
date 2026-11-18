//! From indicators to a score, and from a score to a level.

use serde::Serialize;

use crate::facts::PeFacts;
use crate::indicators::{Context, Hit, evaluate};

/// What a score amounts to.
///
/// The order matters: later levels are stronger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    /// Nothing that adds up to anything.
    Unremarkable,
    /// Worth recording in a report. No verdict follows from it.
    Noted,
    /// Unusual enough to show to the user as suspicious.
    Suspicious,
}

/// The scores at which the levels start.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Thresholds {
    /// Lowest score that is recorded.
    pub noted: u32,
    /// Lowest score that makes a file suspicious.
    pub suspicious: u32,
}

impl Thresholds {
    /// The thresholds Warden uses.
    ///
    /// Not set yet: the indicators have no weights until they have been
    /// measured, so no score can reach a level.
    pub const DEFAULT: Self = Self {
        noted: u32::MAX,
        suspicious: u32::MAX,
    };

    /// The level a score reaches.
    #[must_use]
    pub fn level(&self, score: u32) -> Level {
        if score >= self.suspicious {
            Level::Suspicious
        } else if score >= self.noted {
            Level::Noted
        } else {
            Level::Unremarkable
        }
    }
}

impl Default for Thresholds {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// The heuristic judgement of one file, with everything it rests on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Assessment {
    /// The sum of the weights of the indicators that apply.
    pub score: u32,
    /// What the score amounts to.
    pub level: Level,
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

/// Judges a file by its facts.
#[must_use]
pub fn assess(facts: &PeFacts, context: &Context, thresholds: &Thresholds) -> Assessment {
    let hits = evaluate(facts, context);
    let score = score_of(&hits);
    Assessment {
        score,
        level: thresholds.level(score),
        hits,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels_start_at_their_thresholds() {
        let thresholds = Thresholds {
            noted: 10,
            suspicious: 25,
        };
        assert_eq!(thresholds.level(0), Level::Unremarkable);
        assert_eq!(thresholds.level(9), Level::Unremarkable);
        assert_eq!(thresholds.level(10), Level::Noted);
        assert_eq!(thresholds.level(24), Level::Noted);
        assert_eq!(thresholds.level(25), Level::Suspicious);
        assert_eq!(thresholds.level(u32::MAX), Level::Suspicious);
        assert!(Level::Suspicious > Level::Noted && Level::Noted > Level::Unremarkable);
    }
}

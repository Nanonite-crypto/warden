//! Fits the weights of the indicators to counts.
//!
//! The score of a file is the sum of the weights of the indicators that
//! apply to it. Measuring each indicator on its own and adding the results
//! up counts the same thing several times: a packed file has a writable
//! code section, high entropy and an odd entry point all at once, and all
//! three say "packed". So the weights are fitted together.
//!
//! The model is a logistic regression: the odds that a file is malicious
//! are the odds for its kind of file, multiplied by a factor for every
//! indicator that applies. The kind of file (program, library, .NET
//! assembly) gets a term of its own because the dataset's malicious files
//! are mostly programs and its benign files mostly libraries; without the
//! term, "is a program" would be spread over every indicator that programs
//! show more often. The kind terms are fitted and then thrown away: the
//! score holds indicators only.
//!
//! No weight may be negative, because the score counts what is suspicious
//! and nothing may talk it down. The fit is a convex problem with one
//! solution, found here with Newton's method restricted to the weights that
//! are not held at zero. The same counts give the same weights on every
//! machine, up to rounding far below what survives the rounding to whole
//! numbers.

use std::collections::BTreeMap;

/// Decibans per natural unit of log odds: `10 / ln 10`.
pub const DECIBANS_PER_NAT: f64 = 4.342_944_819_032_518;

/// Strength of the penalty on large weights, per file. It is far too small
/// to move a weight by a hundredth of a deciban; it is there so that the
/// problem has one solution even if two indicators always occur together.
const PENALTY: f64 = 1e-7;

/// Newton steps before giving up. A fit takes about ten.
const MAX_STEPS: usize = 200;

/// The fit has converged when no weight could lower the loss per file by
/// more than this per unit of change.
const TOLERANCE: f64 = 1e-11;

/// The files that share a kind and a combination of features.
#[derive(Debug, Clone, PartialEq)]
pub struct Cell {
    /// Index of the kind of file.
    pub kind: usize,
    /// The features that apply, one bit each.
    pub features: u64,
    pub malicious: f64,
    pub benign: f64,
}

/// The result of a fit, in natural units of log odds.
#[derive(Debug, Clone, PartialEq)]
pub struct Fit {
    /// One weight per feature, none negative.
    pub weights: Vec<f64>,
    /// One term per kind of file.
    pub kind_terms: Vec<f64>,
    /// Newton steps taken.
    pub steps: usize,
    /// The loss per file at the solution.
    pub loss: f64,
}

/// Why a fit did not finish.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FitError {
    /// There is nothing to fit.
    #[error("there are no files to fit weights to")]
    NoFiles,
    /// A kind of file has only malicious or only benign files, so its term
    /// has no finite value.
    #[error("kind {0} has only malicious or only benign files")]
    OneSidedKind(usize),
    /// The steps did not settle.
    #[error("the fit did not converge in {MAX_STEPS} steps")]
    NotConverged,
}

/// Adds up cells that share a kind and a combination, in a fixed order, so
/// that sums over them come out the same on every run.
#[must_use]
pub fn cells(rows: impl IntoIterator<Item = Cell>) -> Vec<Cell> {
    let mut sums: BTreeMap<(usize, u64), (f64, f64)> = BTreeMap::new();
    for row in rows {
        let sum = sums.entry((row.kind, row.features)).or_insert((0.0, 0.0));
        sum.0 += row.malicious;
        sum.1 += row.benign;
    }
    sums.into_iter()
        .map(|((kind, features), (malicious, benign))| Cell {
            kind,
            features,
            malicious,
            benign,
        })
        .collect()
}

/// `ln(1 + e^z)` without overflow.
fn log1p_exp(z: f64) -> f64 {
    if z > 0.0 {
        z + (-z).exp().ln_1p()
    } else {
        z.exp().ln_1p()
    }
}

fn bits(mut features: u64) -> impl Iterator<Item = usize> {
    std::iter::from_fn(move || {
        if features == 0 {
            return None;
        }
        let bit = features.trailing_zeros() as usize;
        features &= features - 1;
        Some(bit)
    })
}

struct Problem<'a> {
    cells: &'a [Cell],
    features: usize,
    kinds: usize,
    files: f64,
}

impl Problem<'_> {
    fn size(&self) -> usize {
        self.features + self.kinds
    }

    fn log_odds(&self, cell: &Cell, theta: &[f64]) -> f64 {
        theta[self.features + cell.kind]
            + bits(cell.features)
                .map(|feature| theta[feature])
                .sum::<f64>()
    }

    /// The loss per file: how badly the model explains the labels, plus
    /// the penalty.
    fn loss(&self, theta: &[f64]) -> f64 {
        let mut total = 0.0;
        for cell in self.cells {
            let z = self.log_odds(cell, theta);
            total += (cell.malicious + cell.benign) * log1p_exp(z) - cell.malicious * z;
        }
        let penalty: f64 = theta[..self.features].iter().map(|w| w * w).sum();
        total / self.files + PENALTY * penalty
    }

    /// The slope of the loss and its curvature.
    fn slope_and_curvature(&self, theta: &[f64]) -> (Vec<f64>, Vec<f64>) {
        let size = self.size();
        let mut slope = vec![0.0; size];
        let mut curvature = vec![0.0; size * size];
        let mut members = Vec::with_capacity(65);
        for cell in self.cells {
            let z = self.log_odds(cell, theta);
            let probability = 1.0 / (1.0 + (-z).exp());
            let files = cell.malicious + cell.benign;
            let residual = files * probability - cell.malicious;
            let spread = files * probability * (1.0 - probability);
            members.clear();
            members.extend(bits(cell.features));
            members.push(self.features + cell.kind);
            for &row in &members {
                slope[row] += residual;
                for &column in &members {
                    curvature[row * size + column] += spread;
                }
            }
        }
        for value in &mut slope {
            *value /= self.files;
        }
        for value in &mut curvature {
            *value /= self.files;
        }
        for feature in 0..self.features {
            slope[feature] += 2.0 * PENALTY * theta[feature];
            curvature[feature * size + feature] += 2.0 * PENALTY;
        }
        (slope, curvature)
    }
}

/// Solves `matrix · x = rhs` for a symmetric positive definite matrix of
/// the given size, by Cholesky decomposition. `None` if the matrix is not
/// positive definite.
fn solve(matrix: &[f64], rhs: &[f64], size: usize) -> Option<Vec<f64>> {
    let mut lower = vec![0.0; size * size];
    for row in 0..size {
        for column in 0..=row {
            let mut sum = matrix[row * size + column];
            for k in 0..column {
                sum -= lower[row * size + k] * lower[column * size + k];
            }
            if row == column {
                if sum <= 0.0 {
                    return None;
                }
                lower[row * size + row] = sum.sqrt();
            } else {
                lower[row * size + column] = sum / lower[column * size + column];
            }
        }
    }
    let mut x = rhs.to_vec();
    for row in 0..size {
        for k in 0..row {
            x[row] -= lower[row * size + k] * x[k];
        }
        x[row] /= lower[row * size + row];
    }
    for row in (0..size).rev() {
        for k in row + 1..size {
            x[row] -= lower[k * size + row] * x[k];
        }
        x[row] /= lower[row * size + row];
    }
    Some(x)
}

/// Fits one weight per feature and one term per kind of file.
///
/// `cells` should come from [`cells`]. A feature that applies to no file
/// gets the weight zero.
///
/// # Errors
///
/// See [`FitError`].
pub fn fit(cells: &[Cell], features: usize, kinds: usize) -> Result<Fit, FitError> {
    assert!(features <= 64, "a combination holds at most 64 features");
    let files: f64 = cells.iter().map(|cell| cell.malicious + cell.benign).sum();
    if files <= 0.0 {
        return Err(FitError::NoFiles);
    }
    for kind in 0..kinds {
        let of_kind = || cells.iter().filter(move |cell| cell.kind == kind);
        let malicious: f64 = of_kind().map(|cell| cell.malicious).sum();
        let benign: f64 = of_kind().map(|cell| cell.benign).sum();
        if (malicious > 0.0) != (benign > 0.0) {
            return Err(FitError::OneSidedKind(kind));
        }
    }
    let problem = Problem {
        cells,
        features,
        kinds,
        files,
    };
    let size = problem.size();
    let mut theta = vec![0.0; size];
    let mut loss = problem.loss(&theta);

    for step in 0..MAX_STEPS {
        let (slope, curvature) = problem.slope_and_curvature(&theta);
        // A weight at zero whose slope says "lower" stays where it is.
        let held = |index: usize| index < features && theta[index] <= 0.0 && slope[index] >= 0.0;
        let worst = (0..size)
            .filter(|&index| !held(index))
            .map(|index| slope[index].abs())
            .fold(0.0, f64::max);
        if worst <= TOLERANCE {
            return Ok(Fit {
                weights: theta[..features].to_vec(),
                kind_terms: theta[features..].to_vec(),
                steps: step,
                loss,
            });
        }

        let free: Vec<usize> = (0..size).filter(|&index| !held(index)).collect();
        let reduced: Vec<f64> = free
            .iter()
            .flat_map(|&row| free.iter().map(move |&column| (row, column)))
            .map(|(row, column)| {
                // A kind without files has no curvature; a one on the
                // diagonal keeps its term at zero.
                let value = curvature[row * size + column];
                if row == column && value <= 0.0 {
                    1.0
                } else {
                    value
                }
            })
            .collect();
        let rhs: Vec<f64> = free.iter().map(|&index| -slope[index]).collect();
        let Some(direction) = solve(&reduced, &rhs, free.len()) else {
            return Err(FitError::NotConverged);
        };

        // Take the Newton step, or the largest halving of it that lowers
        // the loss enough. A weight that would go below zero stops at zero.
        let mut scale = 1.0;
        let mut moved = false;
        for _ in 0..60 {
            let mut candidate = theta.clone();
            for (&index, change) in free.iter().zip(&direction) {
                candidate[index] += scale * change;
                if index < features && candidate[index] < 0.0 {
                    candidate[index] = 0.0;
                }
            }
            let expected: f64 = (0..size)
                .map(|index| slope[index] * (candidate[index] - theta[index]))
                .sum();
            let candidate_loss = problem.loss(&candidate);
            if candidate_loss <= loss + 1e-4 * expected {
                moved = candidate != theta;
                theta = candidate;
                loss = candidate_loss;
                break;
            }
            scale /= 2.0;
        }
        if !moved {
            // No step lowers the loss any further: this is the solution to
            // the precision the numbers have.
            return Ok(Fit {
                weights: theta[..features].to_vec(),
                kind_terms: theta[features..].to_vec(),
                steps: step,
                loss,
            });
        }
    }
    Err(FitError::NotConverged)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn cell(kind: usize, features: u64, malicious: f64, benign: f64) -> Cell {
        Cell {
            kind,
            features,
            malicious,
            benign,
        }
    }

    fn close(left: f64, right: f64) -> bool {
        (left - right).abs() < 1e-4
    }

    #[test]
    fn one_feature_gets_the_logarithm_of_its_odds_ratio() {
        // Without the feature 100 malicious and 900 benign files, with it
        // 300 and 50: odds 1 to 9 and 6 to 1, a ratio of 54.
        let cells = cells([cell(0, 0, 100.0, 900.0), cell(0, 1, 300.0, 50.0)]);
        let fit = fit(&cells, 1, 1).unwrap();
        assert!(close(fit.weights[0], 54f64.ln()), "{fit:?}");
        assert!(close(fit.kind_terms[0], (1.0f64 / 9.0).ln()), "{fit:?}");
        assert!(fit.steps < 20);
    }

    #[test]
    fn a_feature_that_speaks_for_a_file_gets_no_weight() {
        // Rarer among malicious files than among benign ones: the weight
        // would be negative, and is held at zero.
        let cells = cells([cell(0, 0, 500.0, 500.0), cell(0, 1, 10.0, 200.0)]);
        let fit = fit(&cells, 1, 1).unwrap();
        assert_eq!(fit.weights[0], 0.0);
        // The kind term then describes all files together: 510 to 700.
        assert!(close(fit.kind_terms[0], (510.0f64 / 700.0).ln()), "{fit:?}");
    }

    #[test]
    fn the_kind_of_file_is_not_mistaken_for_evidence() {
        // Kind 0 is mostly malicious and kind 1 mostly benign, whatever the
        // feature says; the feature is far more common in kind 0. Within
        // each kind it changes nothing, so it must weigh nothing. Counted
        // over all files together it would look like strong evidence.
        let cells = cells([
            cell(0, 0, 900.0, 100.0),
            cell(0, 1, 9000.0, 1000.0),
            cell(1, 0, 1000.0, 9000.0),
            cell(1, 1, 10.0, 90.0),
        ]);
        let fit = fit(&cells, 1, 2).unwrap();
        assert!(fit.weights[0].abs() < 1e-6, "{fit:?}");
        assert!(close(fit.kind_terms[0], 9f64.ln()), "{fit:?}");
        assert!(close(fit.kind_terms[1], (1.0f64 / 9.0).ln()), "{fit:?}");

        let pooled = ((9010.0f64 / 10910.0) / (1090.0 / 10190.0)).ln();
        assert!(pooled > 2.0, "pooled, the feature would weigh {pooled}");
    }

    #[test]
    fn two_features_that_say_the_same_thing_share_the_weight() {
        // Features 0 and 1 always occur together. Alone, each would get the
        // whole weight; together they get it once, half each.
        let cells = cells([cell(0, 0, 100.0, 900.0), cell(0, 0b11, 300.0, 50.0)]);
        let fit = fit(&cells, 2, 1).unwrap();
        assert!(
            close(fit.weights[0] + fit.weights[1], 54f64.ln()),
            "{fit:?}"
        );
        assert!(close(fit.weights[0], fit.weights[1]), "{fit:?}");
    }

    #[test]
    fn a_feature_no_file_shows_gets_no_weight() {
        let cells = cells([cell(0, 0, 100.0, 900.0), cell(0, 1, 300.0, 50.0)]);
        let fit = fit(&cells, 3, 1).unwrap();
        assert_eq!(fit.weights[1], 0.0);
        assert_eq!(fit.weights[2], 0.0);
        assert!(close(fit.weights[0], 54f64.ln()));
    }

    #[test]
    fn cells_with_the_same_kind_and_combination_are_added_up() {
        let merged = cells([
            cell(1, 5, 1.0, 2.0),
            cell(0, 5, 10.0, 0.0),
            cell(1, 5, 3.0, 4.0),
        ]);
        assert_eq!(merged, vec![cell(0, 5, 10.0, 0.0), cell(1, 5, 4.0, 6.0)]);
    }

    #[test]
    fn what_cannot_be_fitted_is_an_error() {
        assert_eq!(fit(&[], 1, 1), Err(FitError::NoFiles));
        // A kind with malicious files only: its term would be infinite.
        let one_sided = cells([cell(0, 0, 5.0, 5.0), cell(1, 0, 5.0, 0.0)]);
        assert_eq!(fit(&one_sided, 1, 2), Err(FitError::OneSidedKind(1)));
        // A kind without any file is no obstacle.
        let empty_kind = cells([cell(0, 0, 5.0, 5.0)]);
        assert!(fit(&empty_kind, 1, 2).is_ok());
    }

    #[test]
    fn the_equations_are_solved() {
        // [[4, 2], [2, 3]] x = [10, 8] has the solution [1.75, 1.5].
        let x = solve(&[4.0, 2.0, 2.0, 3.0], &[10.0, 8.0], 2).unwrap();
        assert!(close(x[0], 1.75) && close(x[1], 1.5), "{x:?}");
        assert!(solve(&[1.0, 2.0, 2.0, 1.0], &[1.0, 1.0], 2).is_none());
    }
}

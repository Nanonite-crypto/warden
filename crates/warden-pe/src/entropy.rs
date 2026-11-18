//! Shannon entropy of bytes.
//!
//! Entropy says how evenly the 256 byte values are used: 0 bits per byte
//! for a run of one value, 8 for data in which every value is equally
//! likely. Compiled code sits around 6, text lower, and compressed or
//! encrypted data close to 8, which is why a packed program stands out.

/// Counts how often each byte value occurs.
#[must_use]
pub fn histogram(data: &[u8]) -> [u64; 256] {
    // Four tables, so that neighbouring bytes do not wait for each other's
    // increment. This is several times faster than one table on long runs
    // of the same value.
    let mut tables = [[0u64; 256]; 4];
    let mut chunks = data.chunks_exact(4);
    for chunk in &mut chunks {
        tables[0][usize::from(chunk[0])] += 1;
        tables[1][usize::from(chunk[1])] += 1;
        tables[2][usize::from(chunk[2])] += 1;
        tables[3][usize::from(chunk[3])] += 1;
    }
    for byte in chunks.remainder() {
        tables[0][usize::from(*byte)] += 1;
    }
    let mut counts = [0u64; 256];
    for table in &tables {
        for (total, count) in counts.iter_mut().zip(table) {
            *total += count;
        }
    }
    counts
}

/// Entropy of the data a histogram was made from, in bits per byte.
#[must_use]
pub fn of_histogram(counts: &[u64; 256]) -> f64 {
    let total: u64 = counts.iter().sum();
    if total == 0 {
        return 0.0;
    }
    let total = total as f64;
    let mut entropy = 0.0;
    for count in counts.iter().filter(|count| **count > 0) {
        let share = *count as f64 / total;
        entropy -= share * share.log2();
    }
    // Rounding can leave a hair below zero or above eight.
    entropy.clamp(0.0, 8.0)
}

/// Entropy of `data` in bits per byte. Zero for no data.
#[must_use]
pub fn of(data: &[u8]) -> f64 {
    of_histogram(&histogram(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn close(left: f64, right: f64) -> bool {
        (left - right).abs() < 1e-9
    }

    #[test]
    fn known_values() {
        assert!(close(of(&[]), 0.0));
        assert!(close(of(&[7; 1000]), 0.0));
        assert!(close(of(&[0, 1]), 1.0));
        assert!(close(of(&[0, 1, 2, 3, 0, 1, 2, 3]), 2.0));
        let every_value: Vec<u8> = (0..=255).collect();
        assert!(close(of(&every_value), 8.0));
        // Three quarters of one value, one quarter of another.
        let expected = -(0.75f64 * 0.75f64.log2() + 0.25 * 0.25f64.log2());
        assert!(close(of(&[1, 1, 1, 2]), expected));
    }

    #[test]
    fn the_histogram_counts_every_byte_once() {
        for len in [0usize, 1, 2, 3, 4, 5, 7, 8, 1023] {
            let data: Vec<u8> = (0..len).map(|index| (index % 7) as u8).collect();
            let counts = histogram(&data);
            assert_eq!(counts.iter().sum::<u64>(), len as u64);
            for (value, count) in counts.iter().enumerate() {
                let expected = data
                    .iter()
                    .filter(|byte| usize::from(**byte) == value)
                    .count();
                assert_eq!(*count, expected as u64, "len {len}, value {value}");
            }
        }
    }
}

//! Minimal hexadecimal helpers for SHA-256 digests.

use crate::Sha256;

const DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Encodes bytes as lowercase hexadecimal.
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

/// Parses exactly 64 hexadecimal characters (either case) into a SHA-256 digest.
///
/// Returns `None` for any other input, including surrounding whitespace.
#[must_use]
pub fn decode_sha256(text: &str) -> Option<Sha256> {
    let text = text.as_bytes();
    if text.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (index, pair) in text.chunks_exact(2).enumerate() {
        out[index] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(out)
}

fn nibble(character: u8) -> Option<u8> {
    match character {
        b'0'..=b'9' => Some(character - b'0'),
        b'a'..=b'f' => Some(character - b'a' + 10),
        b'A'..=b'F' => Some(character - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_lowercase() {
        assert_eq!(encode(&[0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
        assert_eq!(encode(&[]), "");
    }

    #[test]
    fn decodes_both_cases() {
        let lower = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let upper = lower.to_uppercase();
        let expected = decode_sha256(lower).unwrap();
        assert_eq!(decode_sha256(&upper), Some(expected));
        assert_eq!(encode(&expected), lower);
    }

    #[test]
    fn rejects_wrong_length_and_non_hex() {
        assert_eq!(decode_sha256(""), None);
        assert_eq!(decode_sha256(&"a".repeat(63)), None);
        assert_eq!(decode_sha256(&"a".repeat(65)), None);
        assert_eq!(decode_sha256(&"g".repeat(64)), None);
        assert_eq!(decode_sha256(&format!(" {}", "a".repeat(63))), None);
        // Multi-byte characters must not be mistaken for hex digits.
        assert_eq!(decode_sha256(&"é".repeat(32)), None);
    }
}

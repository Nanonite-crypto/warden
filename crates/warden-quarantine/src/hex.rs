//! Hexadecimal text for the binary values an entry's record holds.

pub(crate) use warden_sigdb::hex::encode;

/// Reads hexadecimal text of any even length, in either case.
pub(crate) fn decode(text: &str) -> Option<Vec<u8>> {
    let text = text.as_bytes();
    if !text.len().is_multiple_of(2) {
        return None;
    }
    text.chunks_exact(2)
        .map(|pair| Some((nibble(pair[0])? << 4) | nibble(pair[1])?))
        .collect()
}

/// Reads hexadecimal text that has to give exactly `N` bytes.
pub(crate) fn decode_exact<const N: usize>(text: &str) -> Option<[u8; N]> {
    decode(text)?.try_into().ok()
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
    fn text_of_any_even_length_is_read() {
        assert_eq!(decode(""), Some(Vec::new()));
        assert_eq!(decode("00ffA5"), Some(vec![0x00, 0xff, 0xa5]));
        assert_eq!(decode(&encode(b"quarantine")), Some(b"quarantine".to_vec()));
        assert_eq!(decode("abc"), None);
        assert_eq!(decode("zz"), None);
        // A character of several bytes is not two hexadecimal digits.
        assert_eq!(decode("é"), None);
    }

    #[test]
    fn a_fixed_length_is_enforced() {
        assert_eq!(decode_exact::<2>("0a0b"), Some([0x0a, 0x0b]));
        assert_eq!(decode_exact::<2>("0a0b0c"), None);
        assert_eq!(decode_exact::<2>("0a"), None);
    }
}

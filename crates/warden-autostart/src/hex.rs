//! Hexadecimal text for the bytes a record holds, so that a record can
//! be read by a person and checked against what `reg query` prints.

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

fn nibble(character: u8) -> Option<u8> {
    match character {
        b'0'..=b'9' => Some(character - b'0'),
        b'a'..=b'f' => Some(character - b'a' + 10),
        b'A'..=b'F' => Some(character - b'A' + 10),
        _ => None,
    }
}

/// Bytes as hexadecimal text, for `#[serde(with = ...)]`.
pub(crate) mod serde_bytes {
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub(crate) fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&super::encode(bytes))
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        super::decode(&text).ok_or_else(|| D::Error::custom("not hexadecimal text"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_of_any_even_length_is_read() {
        assert_eq!(decode(""), Some(Vec::new()));
        assert_eq!(decode("00ffA5"), Some(vec![0x00, 0xff, 0xa5]));
        assert_eq!(decode(&encode(b"autostart")), Some(b"autostart".to_vec()));
        assert_eq!(decode("abc"), None);
        assert_eq!(decode("zz"), None);
        // A character of several bytes is not two hexadecimal digits.
        assert_eq!(decode("é"), None);
    }
}

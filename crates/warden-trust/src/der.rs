//! Just enough of DER to find one field in a signature.
//!
//! DER writes every value as a tag, a length and the content. This reader
//! takes one such value off the front of a slice and hands out its content,
//! which for a sequence is again a row of values. It knows nothing about
//! what the tags mean; the caller says which tag it expects.
//!
//! Only what a signature written by Windows uses is accepted: tags below
//! 31 and lengths that say how long the content is. Anything else is an
//! error, and the caller then treats the signature as unreadable.

/// A sequence of values.
pub(crate) const SEQUENCE: u8 = 0x30;
/// An object identifier.
pub(crate) const OBJECT_IDENTIFIER: u8 = 0x06;
/// A string of bytes.
pub(crate) const OCTET_STRING: u8 = 0x04;
/// The explicitly tagged field number 0 of a sequence.
pub(crate) const CONTEXT_0: u8 = 0xA0;

/// Why a value could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DerError {
    /// The bytes end before the value does.
    Truncated,
    /// A tag or a length is written in a form this reader does not take.
    Unsupported,
    /// The value has another tag than the caller expects.
    Unexpected,
}

/// Takes one value off the front of `input`: its tag, its content, and
/// what follows it.
pub(crate) fn take(input: &[u8]) -> Result<(u8, &[u8], &[u8]), DerError> {
    let (&tag, rest) = input.split_first().ok_or(DerError::Truncated)?;
    if tag & 0x1F == 0x1F {
        // A tag number of 31 or more continues in the next bytes.
        return Err(DerError::Unsupported);
    }
    let (&first, rest) = rest.split_first().ok_or(DerError::Truncated)?;
    let (length, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let count = usize::from(first & 0x7F);
        // 0x80 alone means "until an end marker", which DER does not allow.
        // More than four bytes of length is more than any signature has.
        if count == 0 || count > 4 {
            return Err(DerError::Unsupported);
        }
        if rest.len() < count {
            return Err(DerError::Truncated);
        }
        let (digits, rest) = rest.split_at(count);
        let length = digits
            .iter()
            .fold(0usize, |length, &digit| (length << 8) | usize::from(digit));
        (length, rest)
    };
    if rest.len() < length {
        return Err(DerError::Truncated);
    }
    let (content, rest) = rest.split_at(length);
    Ok((tag, content, rest))
}

/// Takes one value with the given tag off the front of `input`, and
/// returns its content and what follows it.
pub(crate) fn expect(input: &[u8], tag: u8) -> Result<(&[u8], &[u8]), DerError> {
    let (found, content, rest) = take(input)?;
    if found == tag {
        Ok((content, rest))
    } else {
        Err(DerError::Unexpected)
    }
}

/// How many bytes the value at the front of `input` takes, tag and length
/// included.
pub(crate) fn encoded_len(input: &[u8]) -> Result<usize, DerError> {
    let (_, _, rest) = take(input)?;
    Ok(input.len() - rest.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_short_value() {
        let (tag, content, rest) = take(&[0x04, 0x02, 0xAA, 0xBB, 0xCC]).expect("well-formed");
        assert_eq!((tag, content, rest), (0x04, &[0xAA, 0xBB][..], &[0xCC][..]));
    }

    #[test]
    fn a_long_length() {
        let mut bytes = vec![0x30, 0x82, 0x01, 0x00];
        bytes.extend(std::iter::repeat_n(0x55, 256));
        bytes.push(0x99);
        let (tag, content, rest) = take(&bytes).expect("well-formed");
        assert_eq!(tag, SEQUENCE);
        assert_eq!(content.len(), 256);
        assert_eq!(rest, &[0x99]);
        assert_eq!(encoded_len(&bytes), Ok(260));
    }

    #[test]
    fn an_empty_value() {
        assert_eq!(take(&[0x05, 0x00]), Ok((0x05, &[][..], &[][..])));
    }

    #[test]
    fn what_is_cut_off_is_an_error() {
        assert_eq!(take(&[]), Err(DerError::Truncated));
        assert_eq!(take(&[0x30]), Err(DerError::Truncated));
        assert_eq!(take(&[0x30, 0x03, 0x01, 0x02]), Err(DerError::Truncated));
        assert_eq!(take(&[0x30, 0x82, 0x01]), Err(DerError::Truncated));
        assert_eq!(
            take(&[0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF, 0x00]),
            Err(DerError::Truncated)
        );
    }

    #[test]
    fn forms_that_der_does_not_allow_or_nobody_needs_are_refused() {
        // "Until an end marker".
        assert_eq!(take(&[0x30, 0x80, 0x00, 0x00]), Err(DerError::Unsupported));
        // Five bytes of length.
        assert_eq!(
            take(&[0x30, 0x85, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00]),
            Err(DerError::Unsupported)
        );
        // A tag number of 31 or more.
        assert_eq!(take(&[0x1F, 0x20, 0x00]), Err(DerError::Unsupported));
    }

    #[test]
    fn expecting_a_tag() {
        assert_eq!(
            expect(&[0x06, 0x01, 0x2A], OBJECT_IDENTIFIER),
            Ok((&[0x2A][..], &[][..]))
        );
        assert_eq!(
            expect(&[0x06, 0x01, 0x2A], SEQUENCE),
            Err(DerError::Unexpected)
        );
    }
}

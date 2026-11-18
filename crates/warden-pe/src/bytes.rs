//! Reading numbers and strings out of a byte slice without ever stepping
//! outside it.
//!
//! A file under inspection is hostile input: every offset and every length
//! in it may be a lie. All reads go through this module, every read is
//! checked, and a read that does not fit returns `None`.

/// A view of a file's bytes with checked little-endian reads.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Bytes<'a>(pub &'a [u8]);

impl<'a> Bytes<'a> {
    /// Number of bytes in the view.
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    /// `len` bytes starting at `offset`, if all of them exist.
    pub(crate) fn slice(&self, offset: usize, len: usize) -> Option<&'a [u8]> {
        let end = offset.checked_add(len)?;
        self.0.get(offset..end)
    }

    /// The bytes from `offset` to `offset + len`, cut off at the end of the
    /// view. Empty if `offset` is beyond the end.
    pub(crate) fn slice_clipped(&self, offset: usize, len: usize) -> &'a [u8] {
        let start = offset.min(self.0.len());
        let end = offset.saturating_add(len).min(self.0.len());
        &self.0[start..end]
    }

    pub(crate) fn u16(&self, offset: usize) -> Option<u16> {
        let bytes = self.slice(offset, 2)?;
        Some(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    pub(crate) fn u32(&self, offset: usize) -> Option<u32> {
        let bytes = self.slice(offset, 4)?;
        Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub(crate) fn u64(&self, offset: usize) -> Option<u64> {
        let bytes = self.slice(offset, 8)?;
        let mut array = [0u8; 8];
        array.copy_from_slice(bytes);
        Some(u64::from_le_bytes(array))
    }

    /// The text of a NUL-terminated string that starts at `offset`.
    ///
    /// `None` if the offset is outside the view, or if no terminator comes
    /// within `max_len` bytes, or if the string is empty or holds a byte
    /// that is not printable ASCII. Names in an executable (libraries,
    /// functions) are plain ASCII; anything else is not a name.
    pub(crate) fn name(&self, offset: usize, max_len: usize) -> Option<&'a str> {
        let window = self.slice_clipped(offset, max_len.saturating_add(1));
        let end = window.iter().position(|byte| *byte == 0)?;
        let text = &window[..end];
        if text.is_empty() || !text.iter().all(|byte| (0x21..0x7f).contains(byte)) {
            return None;
        }
        std::str::from_utf8(text).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_stay_inside_the_view() {
        let bytes = Bytes(&[0x34, 0x12, 0x78, 0x56, 1, 2, 3, 4]);
        assert_eq!(bytes.u16(0), Some(0x1234));
        assert_eq!(bytes.u32(0), Some(0x5678_1234));
        assert_eq!(bytes.u64(0), Some(0x0403_0201_5678_1234));
        assert_eq!(bytes.u16(7), None);
        assert_eq!(bytes.u32(5), None);
        assert_eq!(bytes.u64(1), None);
        assert_eq!(bytes.u16(usize::MAX), None);
        assert_eq!(bytes.slice(usize::MAX, 2), None);
        assert_eq!(bytes.slice(8, 0), Some(&[][..]));
        assert_eq!(bytes.slice(9, 0), None);
    }

    #[test]
    fn clipped_slices_never_fail() {
        let bytes = Bytes(&[1, 2, 3]);
        assert_eq!(bytes.slice_clipped(1, 10), &[2, 3]);
        assert_eq!(bytes.slice_clipped(3, 10), &[] as &[u8]);
        assert_eq!(bytes.slice_clipped(usize::MAX, usize::MAX), &[] as &[u8]);
    }

    #[test]
    fn names_are_printable_and_terminated() {
        let bytes = Bytes(b"KERNEL32.dll\0x\0\0bad\x01name\0unterminated");
        assert_eq!(bytes.name(0, 64), Some("KERNEL32.dll"));
        assert_eq!(bytes.name(13, 64), Some("x"));
        // Empty, unprintable, too long, never ending, out of range.
        assert_eq!(bytes.name(15, 64), None);
        assert_eq!(bytes.name(16, 64), None);
        assert_eq!(bytes.name(0, 5), None);
        assert_eq!(bytes.name(25, 64), None);
        assert_eq!(bytes.name(1000, 64), None);
        // The limit counts the characters, not the terminator.
        assert_eq!(bytes.name(0, 12), Some("KERNEL32.dll"));
        assert_eq!(bytes.name(0, 11), None);
    }
}

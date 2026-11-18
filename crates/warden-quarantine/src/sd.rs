//! A check of Windows security descriptors before they are handed back to
//! Windows.
//!
//! An entry's record holds the owner, the group and the access-control list
//! of the file as one block of bytes: a security descriptor in what Windows
//! calls self-relative form, where the parts are found through offsets in a
//! header. On restore those bytes go to a Windows function that follows the
//! offsets. A record that was damaged, or that somebody wrote by hand, must
//! not be able to send it outside the block, so every offset and every
//! length is checked here first, in ordinary code that runs and is tested
//! on every system.
//!
//! This is a check of shape, not of meaning. Whether the descriptor makes
//! sense is for Windows to say.

/// The descriptor's parts lie inside the block, behind the header.
const SE_SELF_RELATIVE: u16 = 0x8000;
/// The descriptor says what the access-control list is.
const SE_DACL_PRESENT: u16 = 0x0004;
/// The access-control list does not take entries from the folder above.
const SE_DACL_PROTECTED: u16 = 0x1000;
/// The access-control list was put together from what the folder above
/// hands down.
const SE_DACL_AUTO_INHERITED: u16 = 0x0400;
/// A request, in a descriptor that is handed to Windows, to keep the mark
/// above. A descriptor that Windows hands out never has it.
const SE_DACL_AUTO_INHERIT_REQ: u16 = 0x0100;

const HEADER_LEN: usize = 20;
/// A security identifier has at most this many numbers after its head.
const MAX_SUB_AUTHORITIES: usize = 15;

/// What a descriptor says about itself, as far as restoring needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Shape {
    /// Whether it names an owner.
    pub owner: bool,
    /// Whether it names a group.
    pub group: bool,
    /// Whether it says what the access-control list is. That can be "there
    /// is none", which Windows reads as every right for everybody: a file
    /// that had it that way gets it back that way.
    pub dacl: bool,
    /// Whether that list is protected from inheritance.
    pub dacl_protected: bool,
}

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    let pair = bytes.get(at..at.checked_add(2)?)?;
    Some(u16::from_le_bytes([pair[0], pair[1]]))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<usize> {
    let four = bytes.get(at..at.checked_add(4)?)?;
    usize::try_from(u32::from_le_bytes([four[0], four[1], four[2], four[3]])).ok()
}

/// The length of the security identifier that starts at `at`, if a whole
/// one lies inside `bytes`.
fn sid_len(bytes: &[u8], at: usize) -> Option<usize> {
    let head = bytes.get(at..at.checked_add(8)?)?;
    if head[0] != 1 {
        return None;
    }
    let count = usize::from(head[1]);
    if count > MAX_SUB_AUTHORITIES {
        return None;
    }
    let length = 8 + 4 * count;
    bytes.get(at..at.checked_add(length)?)?;
    Some(length)
}

/// Checks the access-control list that starts at `at`: it has to lie inside
/// `bytes`, and its entries have to lie inside it.
fn acl_fits(bytes: &[u8], at: usize) -> Option<()> {
    let size = usize::from(u16_at(bytes, at.checked_add(2)?)?);
    let count = usize::from(u16_at(bytes, at.checked_add(4)?)?);
    if size < 8 {
        return None;
    }
    let acl = bytes.get(at..at.checked_add(size)?)?;
    let mut position = 8usize;
    for _ in 0..count {
        let entry_size = usize::from(u16_at(acl, position.checked_add(2)?)?);
        if entry_size < 4 {
            return None;
        }
        let entry = acl.get(position..position.checked_add(entry_size)?)?;
        // The two everyday kinds, "allow" and "deny", are a set of rights
        // and then the identifier they are for.
        if matches!(entry[0], 0 | 1) && sid_len(entry, 8).is_none() {
            return None;
        }
        position += entry_size;
    }
    Some(())
}

/// Checks that `bytes` is a self-relative security descriptor whose parts
/// all lie inside it.
///
/// # Errors
///
/// Says what is wrong with it, for an error message.
pub fn check(bytes: &[u8]) -> Result<Shape, &'static str> {
    if bytes.len() < HEADER_LEN {
        return Err("it is shorter than its own header");
    }
    if bytes[0] != 1 {
        return Err("it is not revision 1");
    }
    let control = u16_at(bytes, 2).ok_or("it has no control word")?;
    if control & SE_SELF_RELATIVE == 0 {
        return Err("it is not in self-relative form");
    }
    let offset = |at: usize| u32_at(bytes, at).ok_or("its header is cut short");
    let (owner, group, sacl, dacl) = (offset(4)?, offset(8)?, offset(12)?, offset(16)?);
    for part in [owner, group, sacl, dacl] {
        if part != 0 && part < HEADER_LEN {
            return Err("a part of it lies inside its header");
        }
    }
    if owner != 0 && sid_len(bytes, owner).is_none() {
        return Err("its owner does not lie inside it");
    }
    if group != 0 && sid_len(bytes, group).is_none() {
        return Err("its group does not lie inside it");
    }
    if dacl != 0 && acl_fits(bytes, dacl).is_none() {
        return Err("its access-control list does not lie inside it");
    }
    if sacl != 0 && acl_fits(bytes, sacl).is_none() {
        return Err("its audit list does not lie inside it");
    }
    Ok(Shape {
        owner: owner != 0,
        group: group != 0,
        dacl: control & SE_DACL_PRESENT != 0,
        dacl_protected: control & SE_DACL_PROTECTED != 0,
    })
}

/// The descriptor as it has to be handed to Windows for the file to get
/// back the one that was read from it, together with its [`Shape`].
///
/// A descriptor carries a mark that says its access-control list was put
/// together from what the folder above hands down. Windows drops that mark
/// from a descriptor it is given, unless a second bit asks for it to be
/// kept, and a descriptor read from a file never has that second bit. So
/// it is set here. Without it the restored file would have the same list,
/// entry for entry, and a descriptor that differs from the original in one
/// bit.
///
/// # Errors
///
/// The same as [`check`]: what is handed to Windows has passed it.
pub fn for_writing(bytes: &[u8]) -> Result<(Shape, Vec<u8>), &'static str> {
    let shape = check(bytes)?;
    let mut prepared = bytes.to_vec();
    let control = u16::from_le_bytes([prepared[2], prepared[3]]);
    if control & SE_DACL_AUTO_INHERITED != 0 {
        prepared[2..4].copy_from_slice(&(control | SE_DACL_AUTO_INHERIT_REQ).to_le_bytes());
    }
    Ok((shape, prepared))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    /// S-1-5-32-544, the built-in administrators group.
    fn administrators() -> Vec<u8> {
        let mut sid = vec![1, 2, 0, 0, 0, 0, 0, 5];
        sid.extend_from_slice(&32u32.to_le_bytes());
        sid.extend_from_slice(&544u32.to_le_bytes());
        sid
    }

    /// An access-control list with one "allow" entry for `sid`.
    fn acl_for(sid: &[u8]) -> Vec<u8> {
        let entry_size = 8 + sid.len();
        let mut acl = vec![2, 0];
        acl.extend_from_slice(&((8 + entry_size) as u16).to_le_bytes());
        acl.extend_from_slice(&1u16.to_le_bytes());
        acl.extend_from_slice(&0u16.to_le_bytes());
        acl.extend_from_slice(&[0, 0]);
        acl.extend_from_slice(&(entry_size as u16).to_le_bytes());
        acl.extend_from_slice(&0x001f_01ffu32.to_le_bytes());
        acl.extend_from_slice(sid);
        acl
    }

    /// A descriptor with an owner, a group and a list, as Windows lays one
    /// out.
    fn descriptor(control: u16) -> Vec<u8> {
        let sid = administrators();
        let acl = acl_for(&sid);
        let owner = HEADER_LEN;
        let group = owner + sid.len();
        let dacl = group + sid.len();
        let mut bytes = vec![1, 0];
        bytes.extend_from_slice(&control.to_le_bytes());
        bytes.extend_from_slice(&(owner as u32).to_le_bytes());
        bytes.extend_from_slice(&(group as u32).to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&(dacl as u32).to_le_bytes());
        bytes.extend_from_slice(&sid);
        bytes.extend_from_slice(&sid);
        bytes.extend_from_slice(&acl);
        bytes
    }

    const PRESENT: u16 = SE_SELF_RELATIVE | SE_DACL_PRESENT;

    #[test]
    fn a_well_formed_descriptor_passes() {
        assert_eq!(
            check(&descriptor(PRESENT)),
            Ok(Shape {
                owner: true,
                group: true,
                dacl: true,
                dacl_protected: false
            })
        );
        assert!(
            check(&descriptor(PRESENT | SE_DACL_PROTECTED))
                .unwrap()
                .dacl_protected
        );
    }

    #[test]
    fn a_descriptor_for_writing_asks_to_keep_the_mark_of_inheritance() {
        // Nothing to keep: the bytes go to Windows as they are.
        for control in [PRESENT, PRESENT | SE_DACL_PROTECTED] {
            let read = descriptor(control);
            let (shape, prepared) = for_writing(&read).unwrap();
            assert_eq!(shape, check(&read).unwrap());
            assert_eq!(prepared, read);
        }
        // The mark is there: one bit more, and nothing else changes.
        for control in [
            PRESENT | SE_DACL_AUTO_INHERITED,
            PRESENT | SE_DACL_AUTO_INHERITED | SE_DACL_PROTECTED,
        ] {
            let read = descriptor(control);
            let (shape, prepared) = for_writing(&read).unwrap();
            assert_eq!(shape, check(&read).unwrap());
            assert_eq!(
                u16::from_le_bytes([prepared[2], prepared[3]]),
                control | SE_DACL_AUTO_INHERIT_REQ
            );
            assert_eq!(prepared[..2], read[..2]);
            assert_eq!(prepared[4..], read[4..]);
            // Asked for twice is asked for once.
            assert_eq!(for_writing(&prepared).unwrap().1, prepared);
        }
        // What does not pass the check is not prepared either.
        assert_eq!(
            for_writing(&[1; 19]),
            Err("it is shorter than its own header")
        );
    }

    #[test]
    fn a_descriptor_without_parts_passes_and_says_so() {
        let mut bytes = vec![1, 0];
        bytes.extend_from_slice(&SE_SELF_RELATIVE.to_le_bytes());
        bytes.extend_from_slice(&[0; 16]);
        assert_eq!(
            check(&bytes),
            Ok(Shape {
                owner: false,
                group: false,
                dacl: false,
                dacl_protected: false
            })
        );
    }

    #[test]
    fn a_descriptor_can_say_that_there_is_no_list() {
        // "Present", and no list to go with it: every right for everybody.
        let mut bytes = descriptor(PRESENT);
        bytes[16..20].copy_from_slice(&0u32.to_le_bytes());
        let shape = check(&bytes).unwrap();
        assert!(shape.dacl, "it says something about the list");
        // A list that is there and not declared is not what the descriptor
        // says, and still has to lie inside it.
        let undeclared = descriptor(SE_SELF_RELATIVE);
        assert!(!check(&undeclared).unwrap().dacl);
        let mut outside = undeclared.clone();
        outside[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            check(&outside),
            Err("its access-control list does not lie inside it")
        );
    }

    #[test]
    fn what_is_not_a_self_relative_descriptor_is_refused() {
        assert_eq!(check(&[]), Err("it is shorter than its own header"));
        assert_eq!(check(&[1; 19]), Err("it is shorter than its own header"));
        let mut other_revision = descriptor(PRESENT);
        other_revision[0] = 2;
        assert_eq!(check(&other_revision), Err("it is not revision 1"));
        // In absolute form the header holds pointers, not offsets.
        assert_eq!(
            check(&descriptor(0x0004)),
            Err("it is not in self-relative form")
        );
    }

    #[test]
    fn an_offset_that_leaves_the_block_is_refused() {
        let whole = descriptor(PRESENT);
        for (field, message) in [
            (4, "its owner does not lie inside it"),
            (8, "its group does not lie inside it"),
            (16, "its access-control list does not lie inside it"),
            (12, "its audit list does not lie inside it"),
        ] {
            for offset in [whole.len() as u32, whole.len() as u32 - 3, u32::MAX] {
                let mut bytes = whole.clone();
                bytes[field..field + 4].copy_from_slice(&offset.to_le_bytes());
                assert_eq!(
                    check(&bytes),
                    Err(message),
                    "field {field}, offset {offset}"
                );
            }
            let mut bytes = whole.clone();
            bytes[field..field + 4].copy_from_slice(&8u32.to_le_bytes());
            assert_eq!(check(&bytes), Err("a part of it lies inside its header"));
        }
    }

    #[test]
    fn a_part_that_claims_more_than_is_there_is_refused() {
        let whole = descriptor(PRESENT);
        let sid_len = administrators().len();

        // An owner with fifteen numbers where there is room for two.
        let mut bytes = whole.clone();
        bytes[HEADER_LEN + 1] = 15;
        // It now reaches into the group and the list, which is still inside
        // the block, so make the block end early.
        bytes.truncate(HEADER_LEN + 2 * sid_len);
        bytes[16..20].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(check(&bytes), Err("its owner does not lie inside it"));

        // More numbers than an identifier can have.
        let mut bytes = whole.clone();
        bytes[HEADER_LEN + 1] = 16;
        assert_eq!(check(&bytes), Err("its owner does not lie inside it"));

        // A list that says it is longer than the block.
        let dacl = HEADER_LEN + 2 * sid_len;
        let mut bytes = whole.clone();
        bytes[dacl + 2..dacl + 4].copy_from_slice(&u16::MAX.to_le_bytes());
        assert_eq!(
            check(&bytes),
            Err("its access-control list does not lie inside it")
        );

        // A list that announces more entries than it holds.
        let mut bytes = whole.clone();
        bytes[dacl + 4..dacl + 6].copy_from_slice(&2u16.to_le_bytes());
        assert_eq!(
            check(&bytes),
            Err("its access-control list does not lie inside it")
        );

        // An entry that says it is longer than its list.
        let mut bytes = whole.clone();
        bytes[dacl + 10..dacl + 12].copy_from_slice(&200u16.to_le_bytes());
        assert_eq!(
            check(&bytes),
            Err("its access-control list does not lie inside it")
        );

        // An entry whose identifier claims more than the entry holds.
        let mut bytes = whole;
        bytes[dacl + 8 + 8 + 1] = 9;
        assert_eq!(
            check(&bytes),
            Err("its access-control list does not lie inside it")
        );
    }

    #[test]
    fn no_input_makes_the_check_panic() {
        // Every prefix of a good descriptor, and a good one with each byte
        // in turn set to each of a few values.
        let whole = descriptor(PRESENT | SE_DACL_PROTECTED | SE_DACL_AUTO_INHERITED);
        for length in 0..whole.len() {
            let _ = check(&whole[..length]);
            let _ = for_writing(&whole[..length]);
        }
        for position in 0..whole.len() {
            for value in [0x00, 0x01, 0x7f, 0x80, 0xff] {
                let mut bytes = whole.clone();
                bytes[position] = value;
                let _ = check(&bytes);
                let _ = for_writing(&bytes);
            }
        }
    }
}

//! The EICAR Standard Anti-Virus Test File.
//!
//! EICAR is not malware. It is a 68-byte text string, agreed on by antivirus
//! vendors, that every product detects on purpose so that people can check an
//! installation works without touching anything dangerous. Warden uses it for
//! exactly that: its tests and demos never involve live malware.
//!
//! Two practical notes:
//!
//! - The string is assembled at run time from two halves, so no source or
//!   object file in this repository starts with the complete test string.
//!   That keeps antivirus products and repository scanners from flagging the
//!   project itself.
//! - Once the test file is written to disk, any resident antivirus
//!   (Microsoft Defender included) will remove it or block access to it
//!   within moments, unless the folder is excluded. See `docs/TESTING.md`.

/// Detection name Warden reports for the test file.
pub const DETECTION_NAME: &str = "EICAR-Test-File";

/// Conventional file name of the test file.
pub const FILE_NAME: &str = "eicar.com";

/// Published SHA-256 of the 68-byte test file, in lowercase hexadecimal.
///
/// The built-in signature is computed from [`test_file`], not copied from
/// this constant. A unit test checks that the two agree, which guards
/// against a typo in either one.
pub const SHA256_HEX: &str = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

const FIRST_HALF: &[u8] = br"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR";
const SECOND_HALF: &[u8] = b"-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

/// Returns the 68 bytes of the EICAR test file.
#[must_use]
pub fn test_file() -> Vec<u8> {
    [FIRST_HALF, SECOND_HALF].concat()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_matches_the_published_hash() {
        let bytes = test_file();
        assert_eq!(bytes.len(), 68);
        assert_eq!(
            warden_sigdb::hex::encode(&crate::sha256(&bytes)),
            SHA256_HEX
        );
    }
}

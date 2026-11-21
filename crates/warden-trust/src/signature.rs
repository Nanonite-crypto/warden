//! What a check of a file's signature can say.

use serde::Serialize;

/// Where a signature for a file can be.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Route {
    /// Inside the file itself.
    Embedded,
    /// In one of the catalogues that Windows keeps: lists of file hashes,
    /// each list signed as a whole. Most files of Windows are signed this
    /// way and carry nothing themselves.
    WindowsCatalog,
    /// In the signature of the app package the file belongs to.
    Package,
}

impl Route {
    /// The three routes, in the order they are tried.
    pub const ALL: [Self; 3] = [Self::Embedded, Self::WindowsCatalog, Self::Package];

    /// Stable lowercase identifier, as used in JSON output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Embedded => "embedded",
            Self::WindowsCatalog => "windows_catalog",
            Self::Package => "package",
        }
    }

    /// The route in a few words, to finish a sentence that starts "found
    /// in".
    #[must_use]
    pub const fn in_words(self) -> &'static str {
        match self {
            Self::Embedded => "the file itself",
            Self::WindowsCatalog => "a catalogue of Windows",
            Self::Package => "the signature of the file's package",
        }
    }
}

/// One certificate of a chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Certificate {
    /// Who the certificate is for, as Windows shows it.
    pub subject: String,
    /// SHA-256 of the certificate, in lowercase hexadecimal.
    pub sha256: String,
}

/// What is known about whether the certificates of a chain were revoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Revocation {
    /// Windows looked every certificate below the root up, and none is
    /// revoked.
    Checked,
    /// For at least one certificate it could not be found out: no network,
    /// no list to look in, or a certificate that names no place to ask.
    Unknown,
}

/// Who made a signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Signer {
    /// The name in the signer's certificate.
    pub common_name: String,
    /// The organisation in the signer's certificate. Empty if it names
    /// none.
    pub organization: String,
    /// The chain of certificates Windows built, the signer's first and the
    /// root last.
    pub chain: Vec<Certificate>,
    /// Whether the chain ends in one of Microsoft's own roots, by Windows'
    /// own check of the root's key. A root that only carries Microsoft's
    /// name does not pass it.
    pub microsoft_root: bool,
    /// Whether the chain was checked for revocation.
    pub revocation: Revocation,
}

/// What one route found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "found", rename_all = "snake_case")]
pub enum Found {
    /// No signature this way.
    Nothing,
    /// A signature that holds.
    Valid {
        /// Who made it.
        signer: Signer,
        /// Where exactly it was found, where that is worth saying: the
        /// catalogue, or the package's folder.
        #[serde(skip_serializing_if = "Option::is_none")]
        place: Option<String>,
    },
    /// A signature that does not hold, or a file it does not cover.
    Invalid {
        /// What is wrong, for a person to read.
        why: String,
    },
    /// The route does not apply to this file, so it was not tried.
    NotApplicable {
        /// Why not.
        why: String,
    },
    /// The route could not be tried: Windows could not be asked.
    Failed {
        /// What went wrong.
        why: String,
    },
}

/// What one route found, with the route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RouteReport {
    /// The route.
    pub route: Route,
    /// What it found.
    #[serde(flatten)]
    pub found: Found,
}

/// Why a file is not trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    /// No route found a signature.
    NoSignature,
    /// A signature was found that does not hold, or that does not cover
    /// this file: a file in the folder of a package that the package's
    /// signature knows nothing of, for one.
    Invalid,
    /// A signature holds, and its signer is not on the trust list.
    NotListed,
    /// A signature of a listed publisher holds, and it could not be found
    /// out whether its certificates were revoked.
    RevocationUnknown,
    /// The file is not the one that was scanned: its content has another
    /// SHA-256 now.
    Changed,
    /// The check could not be carried out: the file could not be opened
    /// so that nobody can change it meanwhile, it could not be read, or
    /// Windows could not be asked.
    NotChecked,
    /// Signatures cannot be checked on this system.
    Unavailable,
}

impl Reason {
    /// Stable lowercase identifier, as used in JSON output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoSignature => "no_signature",
            Self::Invalid => "invalid",
            Self::NotListed => "not_listed",
            Self::RevocationUnknown => "revocation_unknown",
            Self::Changed => "changed",
            Self::NotChecked => "not_checked",
            Self::Unavailable => "unavailable",
        }
    }
}

/// The answer about one file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "answer", rename_all = "snake_case")]
pub enum Trust {
    /// A signature holds, its certificates are not revoked, and its signer
    /// is on the trust list.
    Trusted {
        /// The publisher, by the name the trust list gives it.
        publisher: String,
        /// The route the signature was found by.
        route: Route,
    },
    /// Anything else.
    NotTrusted {
        /// Why, as one of a few kinds.
        reason: Reason,
        /// Why, for a person to read.
        detail: String,
    },
}

impl Trust {
    /// Whether the file is trusted.
    #[must_use]
    pub fn is_trusted(&self) -> bool {
        matches!(self, Self::Trusted { .. })
    }
}

/// Everything a check found out about one file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Examination {
    /// SHA-256 of the file as it was checked, in lowercase hexadecimal.
    /// Absent if the file could not be read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// Whether the file is a Windows executable. Only for those is a
    /// signature looked for in the file and in the catalogues; any other
    /// file can be trusted as part of a package and no other way. Absent
    /// if the file could not be read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executable: Option<bool>,
    /// What each route found, for the routes that were tried or ruled out.
    pub routes: Vec<RouteReport>,
    /// The answer.
    pub trust: Trust,
}

/// Lowercase hexadecimal.
pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // Writing to a String cannot fail.
        let _ = write!(text, "{byte:02x}");
    }
    text
}

/// Reads 64 hexadecimal digits as a SHA-256.
pub(crate) fn sha256_from_hex(text: &str) -> Option<[u8; 32]> {
    let digits = text.as_bytes();
    if digits.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (byte, pair) in out.iter_mut().zip(digits.chunks_exact(2)) {
        let high = char::from(pair[0]).to_digit(16)?;
        let low = char::from(pair[1]).to_digit(16)?;
        *byte = (high * 16 + low) as u8;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hexadecimal_round_trip() {
        let bytes: [u8; 32] = std::array::from_fn(|index| (index * 7) as u8);
        let text = hex(&bytes);
        assert_eq!(text.len(), 64);
        assert_eq!(sha256_from_hex(&text), Some(bytes));
        assert_eq!(sha256_from_hex(&text.to_uppercase()), Some(bytes));
        assert_eq!(sha256_from_hex(&text[1..]), None);
        assert_eq!(sha256_from_hex(&text.replace('0', "g")), None);
    }

    #[test]
    fn an_answer_reads_well_as_json() {
        let trusted = Trust::Trusted {
            publisher: "Example".to_owned(),
            route: Route::WindowsCatalog,
        };
        assert_eq!(
            serde_json::to_string(&trusted).expect("serializes"),
            r#"{"answer":"trusted","publisher":"Example","route":"windows_catalog"}"#
        );
        let report = RouteReport {
            route: Route::Embedded,
            found: Found::Invalid {
                why: "changed".to_owned(),
            },
        };
        assert_eq!(
            serde_json::to_string(&report).expect("serializes"),
            r#"{"route":"embedded","found":"invalid","why":"changed"}"#
        );
    }
}

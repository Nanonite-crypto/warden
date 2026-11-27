//! The publishers whose signature Warden trusts.
//!
//! A valid signature says who a file comes from and that it has not been
//! changed since. It does not say that the file is harmless: malware is
//! signed too, with certificates that were bought under a made-up name or
//! stolen from somebody. So Warden does not trust signatures. It trusts a
//! short list of publishers, and a signature is the proof that a file comes
//! from one of them.
//!
//! The list is a TOML file, `trust/publishers.toml`, and it is part of the
//! program: [`TrustList::builtin`] reads the copy that was compiled in.
//! Whoever can write next to the program cannot add a publisher.
//!
//! ```toml
//! [[publisher]]
//! name = "Example Software"
//! common_name = "Example Software Ltd"
//! organization = "Example Software Ltd"
//! anchor = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
//! signs = "The programs of Example Software, and nothing by anyone else."
//! reason = "A rule flagged its updater on two machines."
//! added = 2026-11-21
//!
//! [[publisher.evidence]]
//! file = 'C:\Program Files\Example\update.exe'
//! sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
//! route = "embedded"
//! seen = 2026-11-21
//! machine = "Windows 11 desktop"
//! ```
//!
//! An entry names a signing identity, not a company: the two fields of the
//! signer's certificate that say who it is for, and the certificate its
//! chain has to pass through. A name alone could be put into a certificate
//! by anyone who runs a certificate authority of their own. The `anchor`
//! is what ties the name to somebody who was checked:
//!
//! - `"microsoft-root"`: the chain ends in one of Microsoft's own root
//!   certificates. Windows knows those by their keys and checks that
//!   itself.
//! - `"sha256:…"`: a certificate with this SHA-256 is in the chain: the
//!   publisher's own, the one of the authority that issued it, or the root.
//!
//! No entry gets on the list without evidence: a real file with such a
//! signature, where it was seen, and by which route. `docs/TRUST.md` says
//! what else an entry takes.
//!
//! An entry can also say `operating_system = true`: this identity signs
//! the operating system itself. The scan does nothing with that. The
//! quarantine goes by it when it leaves such a file where it is
//! ([`Verifier::origin`](crate::Verifier::origin)). Only an entry with the
//! anchor `"microsoft-root"` can say so.

use std::collections::BTreeSet;

use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::signature::{Route, Signer, hex, sha256_from_hex};

/// The list that is compiled into the program.
const BUILTIN: &str = include_str!("../../../trust/publishers.toml");

/// Most publishers a list may name.
const MAX_PUBLISHERS: usize = 1_000;
/// Most pieces of evidence one publisher may carry.
const MAX_EVIDENCE: usize = 1_000;
/// Longest free-text field, in bytes.
const MAX_TEXT_BYTES: usize = 2_000;

/// Why a trust list could not be used.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ListError {
    /// The text is not valid TOML, or has fields that are not part of the
    /// format.
    #[error("the trust list cannot be read: {0}")]
    Syntax(String),
    /// The text is well-formed, but an entry breaks one of the rules for
    /// entries.
    #[error("the trust list is not acceptable: {0}")]
    Invalid(String),
}

/// What ties a publisher's name to somebody who was checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Anchor {
    /// The chain ends in one of Microsoft's own root certificates, by
    /// Windows' own check.
    MicrosoftRoot,
    /// A certificate with this SHA-256 is in the chain.
    Certificate([u8; 32]),
}

impl Anchor {
    fn parse(text: &str) -> Option<Self> {
        if text == "microsoft-root" {
            return Some(Self::MicrosoftRoot);
        }
        sha256_from_hex(text.strip_prefix("sha256:")?).map(Self::Certificate)
    }

    /// Whether a signer's chain passes through this anchor.
    #[must_use]
    pub fn holds_for(&self, signer: &Signer) -> bool {
        match self {
            Self::MicrosoftRoot => signer.microsoft_root,
            Self::Certificate(sha256) => {
                let wanted = hex(sha256);
                signer
                    .chain
                    .iter()
                    .any(|certificate| certificate.sha256 == wanted)
            }
        }
    }
}

impl std::fmt::Display for Anchor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MicrosoftRoot => formatter.write_str("microsoft-root"),
            Self::Certificate(sha256) => write!(formatter, "sha256:{}", hex(sha256)),
        }
    }
}

/// One file that was seen with a publisher's signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    /// Path of the file on the machine where it was seen.
    pub file: String,
    /// SHA-256 of the file, in lowercase hexadecimal.
    pub sha256: String,
    /// The route its signature was found by.
    pub route: Route,
    /// The day it was seen, as `YYYY-MM-DD`.
    pub seen: String,
    /// The machine it was seen on, in a few words.
    pub machine: String,
    /// Anything else worth knowing, if the list says.
    pub note: Option<String>,
}

/// A publisher on the list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Publisher {
    /// The name Warden uses for the publisher in its own output.
    pub name: String,
    /// The name in the signer's certificate, which has to be this exactly.
    pub common_name: String,
    /// The organisation in the signer's certificate, which has to be this
    /// exactly.
    pub organization: String,
    /// What the chain has to pass through.
    pub anchor: Anchor,
    /// Whether this identity signs the operating system itself. The
    /// quarantine leaves a file with such a signature where it is unless
    /// somebody insists, because the system may not start without it.
    pub operating_system: bool,
    /// What this identity signs, and what it does not.
    pub signs: String,
    /// Why it is on the list.
    pub reason: String,
    /// The day it was added, as `YYYY-MM-DD`.
    pub added: String,
    /// Files that were seen with its signature. Never empty.
    pub evidence: Vec<Evidence>,
}

impl Publisher {
    /// Whether a signature was made by this publisher: the two names in
    /// the signer's certificate are the listed ones, and the chain passes
    /// through the anchor.
    #[must_use]
    pub fn made(&self, signer: &Signer) -> bool {
        self.common_name == signer.common_name
            && self.organization == signer.organization
            && self.anchor.holds_for(signer)
    }
}

/// A list of trusted publishers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustList {
    publishers: Vec<Publisher>,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawList {
    #[serde(default)]
    publisher: Vec<RawPublisher>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPublisher {
    name: String,
    common_name: String,
    organization: String,
    anchor: String,
    #[serde(default)]
    operating_system: bool,
    signs: String,
    reason: String,
    added: toml::value::Datetime,
    #[serde(default)]
    evidence: Vec<RawEvidence>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEvidence {
    file: String,
    sha256: String,
    route: String,
    seen: toml::value::Datetime,
    machine: String,
    #[serde(default)]
    note: Option<String>,
}

impl TrustList {
    /// The list that is part of the program.
    ///
    /// # Errors
    ///
    /// Fails only if the list in the repository is not acceptable, which a
    /// test guards against.
    pub fn builtin() -> Result<Self, ListError> {
        Self::parse(BUILTIN)
    }

    /// A list that trusts nobody.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            publishers: Vec::new(),
            sha256: hex(&Sha256::digest(b"")),
        }
    }

    /// Reads a trust list from TOML text.
    ///
    /// # Errors
    ///
    /// Fails if the text is not valid TOML, uses a field that is not part
    /// of the format, names a publisher or a signing identity twice, has
    /// an entry without evidence, or marks an entry as the operating
    /// system whose anchor is not `"microsoft-root"`.
    pub fn parse(text: &str) -> Result<Self, ListError> {
        let raw: RawList =
            toml::from_str(text).map_err(|error| ListError::Syntax(error.to_string()))?;
        if raw.publisher.len() > MAX_PUBLISHERS {
            return Err(invalid(format!(
                "it names more than {MAX_PUBLISHERS} publishers"
            )));
        }

        let mut names = BTreeSet::new();
        let mut identities = BTreeSet::new();
        let mut publishers = Vec::with_capacity(raw.publisher.len());
        for entry in raw.publisher {
            check_text("a publisher", "name", &entry.name)?;
            let name = entry.name;
            if !names.insert(name.clone()) {
                return Err(invalid(format!("{name} is listed twice")));
            }
            for (field, value) in [
                ("common_name", &entry.common_name),
                ("organization", &entry.organization),
                ("signs", &entry.signs),
                ("reason", &entry.reason),
            ] {
                check_text(&name, field, value)?;
            }
            let anchor = Anchor::parse(&entry.anchor).ok_or_else(|| {
                invalid(format!(
                    "{name}: the anchor must be \"microsoft-root\" or \"sha256:\" followed by 64 hexadecimal digits"
                ))
            })?;
            // A name and a certificate say who a publisher is. That a file
            // is part of the system is a claim about Windows, and it rests
            // on Windows' own check of the root.
            if entry.operating_system && anchor != Anchor::MicrosoftRoot {
                return Err(invalid(format!(
                    "{name}: only an entry with the anchor \"microsoft-root\" can be marked as the operating system"
                )));
            }
            let identity = (
                entry.common_name.clone(),
                entry.organization.clone(),
                anchor,
            );
            if !identities.insert(identity) {
                return Err(invalid(format!(
                    "{name}: the same names with the same anchor are listed twice"
                )));
            }
            let added = date(&name, "added", &entry.added)?;
            if entry.evidence.is_empty() {
                return Err(invalid(format!(
                    "{name} has no evidence: every entry must name at least one file that was seen with this signature"
                )));
            }
            if entry.evidence.len() > MAX_EVIDENCE {
                return Err(invalid(format!(
                    "{name} has more than {MAX_EVIDENCE} pieces of evidence"
                )));
            }
            let mut evidence = Vec::with_capacity(entry.evidence.len());
            for item in entry.evidence {
                check_text(&name, "file", &item.file)?;
                check_text(&name, "machine", &item.machine)?;
                if let Some(note) = &item.note {
                    check_text(&name, "note", note)?;
                }
                if sha256_from_hex(&item.sha256).is_none() {
                    return Err(invalid(format!(
                        "{name}: the sha256 of {} must be 64 hexadecimal digits",
                        shorten(&item.file)
                    )));
                }
                let route = Route::ALL
                    .into_iter()
                    .find(|route| route.as_str() == item.route)
                    .ok_or_else(|| {
                        invalid(format!(
                            "{name}: the route of {} must be one of embedded, windows_catalog and package",
                            shorten(&item.file)
                        ))
                    })?;
                evidence.push(Evidence {
                    file: item.file,
                    sha256: item.sha256.to_ascii_lowercase(),
                    route,
                    seen: date(&name, "seen", &item.seen)?,
                    machine: item.machine,
                    note: item.note,
                });
            }
            publishers.push(Publisher {
                name,
                common_name: entry.common_name,
                organization: entry.organization,
                anchor,
                operating_system: entry.operating_system,
                signs: entry.signs,
                reason: entry.reason,
                added,
                evidence,
            });
        }

        Ok(Self {
            publishers,
            sha256: hex(&Sha256::digest(text.as_bytes())),
        })
    }

    /// The listed publishers, in the order of the file.
    #[must_use]
    pub fn publishers(&self) -> &[Publisher] {
        &self.publishers
    }

    /// Number of listed publishers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.publishers.len()
    }

    /// True if the list names nobody.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.publishers.is_empty()
    }

    /// SHA-256 of the list's text, in lowercase hexadecimal. A report
    /// records it, so that it can be told which list an answer came from.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.sha256
    }

    /// The publisher that made a signature, if it is on the list.
    #[must_use]
    pub fn publisher_of(&self, signer: &Signer) -> Option<&Publisher> {
        self.publishers
            .iter()
            .find(|publisher| publisher.made(signer))
    }

    /// A listed publisher whose two names a signature carries without the
    /// chain that the list asks of that publisher. Such a signature is not
    /// that publisher's. This is for saying why a file is not trusted:
    /// "not on the list" would read oddly next to a name that is on it.
    #[must_use]
    pub fn namesake_of(&self, signer: &Signer) -> Option<&Publisher> {
        self.publishers.iter().find(|publisher| {
            publisher.common_name == signer.common_name
                && publisher.organization == signer.organization
                && !publisher.anchor.holds_for(signer)
        })
    }
}

fn invalid(message: String) -> ListError {
    ListError::Invalid(message)
}

/// A piece of text for an error message, cut short and without control
/// characters.
fn shorten(text: &str) -> String {
    let mut short: String = text
        .chars()
        .take(80)
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect();
    if text.chars().count() > 80 {
        short.push('…');
    }
    short
}

fn check_text(owner: &str, field: &str, value: &str) -> Result<(), ListError> {
    if value.trim().is_empty() {
        return Err(invalid(format!("{}: \"{field}\" is empty", shorten(owner))));
    }
    if value.len() > MAX_TEXT_BYTES {
        return Err(invalid(format!(
            "{}: \"{field}\" is longer than {MAX_TEXT_BYTES} bytes",
            shorten(owner)
        )));
    }
    Ok(())
}

fn date(owner: &str, field: &str, value: &toml::value::Datetime) -> Result<String, ListError> {
    if value.date.is_none() || value.time.is_some() || value.offset.is_some() {
        return Err(invalid(format!(
            "{owner}: \"{field}\" must be a date without a time, such as 2026-11-21"
        )));
    }
    Ok(value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::{Certificate, Revocation};

    const ZEROS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    fn entry(name: &str, anchor: &str) -> String {
        format!(
            r#"
[[publisher]]
name = "{name}"
common_name = "{name} Ltd"
organization = "{name} Ltd"
anchor = "{anchor}"
signs = "Its own programs."
reason = "A rule flagged one of its files."
added = 2026-11-21

[[publisher.evidence]]
file = 'C:\Program Files\{name}\tool.exe'
sha256 = "{ZEROS}"
route = "embedded"
seen = 2026-11-21
machine = "a test"
"#
        )
    }

    fn signer(
        common_name: &str,
        organization: &str,
        microsoft_root: bool,
        chain: &[&str],
    ) -> Signer {
        Signer {
            common_name: common_name.to_owned(),
            organization: organization.to_owned(),
            chain: chain
                .iter()
                .map(|sha256| Certificate {
                    subject: "a certificate".to_owned(),
                    sha256: (*sha256).to_owned(),
                })
                .collect(),
            microsoft_root,
            revocation: Revocation::Checked,
        }
    }

    #[test]
    fn the_list_in_the_repository_is_acceptable() {
        let list = TrustList::builtin().expect("the built-in list");
        assert!(
            !list.is_empty(),
            "a list that trusts nobody is not what ships"
        );
        assert_eq!(list.digest().len(), 64);
        for publisher in list.publishers() {
            assert!(!publisher.evidence.is_empty(), "{}", publisher.name);
        }
        // What the quarantine leaves alone is Windows, and nothing else on
        // the list: not Microsoft's applications.
        let system: Vec<&str> = list
            .publishers()
            .iter()
            .filter(|publisher| publisher.operating_system)
            .map(|publisher| publisher.name.as_str())
            .collect();
        assert_eq!(system, ["Microsoft Windows"]);
    }

    #[test]
    fn an_entry_can_be_marked_as_the_operating_system() {
        let plain = entry("Alpha", "microsoft-root");
        let list = TrustList::parse(&plain).expect("acceptable");
        assert!(!list.publishers()[0].operating_system);

        let marked = plain.replace(
            "anchor = \"microsoft-root\"",
            "anchor = \"microsoft-root\"\noperating_system = true",
        );
        let list = TrustList::parse(&marked).expect("acceptable");
        assert!(list.publishers()[0].operating_system);
        // The mark is not who the publisher is: the same signatures count.
        let signature = signer("Alpha Ltd", "Alpha Ltd", true, &[]);
        assert!(list.publisher_of(&signature).is_some());

        // A pinned certificate says who signed. It does not make a file
        // part of Windows.
        let pinned = entry("Beta", &format!("sha256:{}", "ab".repeat(32)))
            .replace("signs =", "operating_system = true\nsigns =");
        let error = TrustList::parse(&pinned).expect_err("a pin is no system");
        assert!(matches!(error, ListError::Invalid(_)), "{error}");
        assert!(error.to_string().contains("operating system"), "{error}");
    }

    #[test]
    fn an_empty_list_trusts_nobody() {
        let list = TrustList::empty();
        assert!(list.is_empty());
        assert!(
            list.publisher_of(&signer("Anyone", "Anyone", true, &[]))
                .is_none()
        );
        assert_eq!(TrustList::parse("").expect("an empty file is a list"), list);
    }

    #[test]
    fn a_publisher_is_found_by_both_names_and_the_anchor() {
        let pinned = "ab".repeat(32);
        let text = format!(
            "{}{}",
            entry("Alpha", "microsoft-root"),
            entry("Beta", &format!("sha256:{pinned}"))
        );
        let list = TrustList::parse(&text).expect("acceptable");
        assert_eq!(list.len(), 2);

        // Both names right, and the chain ends in a root of Microsoft's.
        let found = list.publisher_of(&signer("Alpha Ltd", "Alpha Ltd", true, &[]));
        assert_eq!(
            found.map(|publisher| publisher.name.as_str()),
            Some("Alpha")
        );
        // The names alone are not enough. The list can say whose names
        // they are, for the explanation.
        let borrowed = signer("Alpha Ltd", "Alpha Ltd", false, &[]);
        assert!(list.publisher_of(&borrowed).is_none());
        assert_eq!(
            list.namesake_of(&borrowed)
                .map(|publisher| publisher.name.as_str()),
            Some("Alpha")
        );
        // A signature that is the publisher's borrows nothing, and neither
        // does one with other names.
        assert!(
            list.namesake_of(&signer("Alpha Ltd", "Alpha Ltd", true, &[]))
                .is_none()
        );
        assert!(
            list.namesake_of(&signer("Alpha Ltd", "Someone Else", false, &[]))
                .is_none()
        );
        // One name wrong.
        assert!(
            list.publisher_of(&signer("Alpha Ltd", "Someone Else", true, &[]))
                .is_none()
        );
        assert!(
            list.publisher_of(&signer("alpha ltd", "Alpha Ltd", true, &[]))
                .is_none()
        );

        // A pinned certificate anywhere in the chain.
        let other = "cd".repeat(32);
        let found = list.publisher_of(&signer("Beta Ltd", "Beta Ltd", false, &[&other, &pinned]));
        assert_eq!(found.map(|publisher| publisher.name.as_str()), Some("Beta"));
        let renewed = signer("Beta Ltd", "Beta Ltd", false, &[&other]);
        assert!(list.publisher_of(&renewed).is_none());
        assert_eq!(
            list.namesake_of(&renewed)
                .map(|publisher| publisher.name.as_str()),
            Some("Beta")
        );
        // A root of Microsoft's does not stand in for a pinned certificate.
        assert!(
            list.publisher_of(&signer("Beta Ltd", "Beta Ltd", true, &[&other]))
                .is_none()
        );
    }

    #[test]
    fn an_entry_needs_evidence() {
        let without = entry("Alpha", "microsoft-root");
        let cut = without
            .find("[[publisher.evidence]]")
            .expect("the entry has evidence");
        let error = TrustList::parse(&without[..cut]).expect_err("no evidence");
        assert!(matches!(error, ListError::Invalid(_)), "{error}");
        assert!(error.to_string().contains("no evidence"), "{error}");
    }

    #[test]
    fn entries_that_break_a_rule_are_refused() {
        let good = entry("Alpha", "microsoft-root");
        assert!(TrustList::parse(&good).is_ok());

        for (what, text) in [
            (
                "an anchor that is none",
                good.replace("microsoft-root", "any-root"),
            ),
            (
                "a pin that is too short",
                good.replace("microsoft-root", "sha256:abcd"),
            ),
            (
                "an empty name in the certificate",
                good.replace("common_name = \"Alpha Ltd\"", "common_name = \" \""),
            ),
            ("a hash that is none", good.replace(ZEROS, "1234")),
            (
                "a route that is none",
                good.replace("route = \"embedded\"", "route = \"hearsay\""),
            ),
            (
                "a day with a time",
                good.replace("seen = 2026-11-21", "seen = 2026-11-21T10:00:00"),
            ),
            ("the same publisher twice", format!("{good}{good}")),
            (
                "the same identity under two names",
                format!(
                    "{good}{}",
                    good.replace("name = \"Alpha\"", "name = \"Alpha again\"")
                ),
            ),
        ] {
            let error = TrustList::parse(&text).expect_err(what);
            assert!(matches!(error, ListError::Invalid(_)), "{what}: {error}");
        }

        let unknown_field = good.replace("signs =", "trusted_since = 2020\nsigns =");
        assert!(matches!(
            TrustList::parse(&unknown_field),
            Err(ListError::Syntax(_))
        ));
        assert!(matches!(
            TrustList::parse("not toml ["),
            Err(ListError::Syntax(_))
        ));
    }

    #[test]
    fn an_anchor_reads_back_as_it_was_written() {
        let pinned = format!("sha256:{}", "0f".repeat(32));
        for text in ["microsoft-root", pinned.as_str()] {
            assert_eq!(Anchor::parse(text).expect("an anchor").to_string(), text);
        }
        assert_eq!(Anchor::parse("sha256:"), None);
        assert_eq!(Anchor::parse("Microsoft-Root"), None);
    }

    #[test]
    fn the_digest_follows_the_text() {
        let one = TrustList::parse(&entry("Alpha", "microsoft-root")).expect("acceptable");
        let other = TrustList::parse(&entry("Beta", "microsoft-root")).expect("acceptable");
        assert_ne!(one.digest(), other.digest());
    }
}

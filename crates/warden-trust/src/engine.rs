//! The check as the scan engine asks for it.

use std::path::Path;

use warden_engine::{Sha256, TrustAnswer, TrustCheck, TrustCheckInfo};

use crate::signature::Trust;
use crate::verify::Verifier;

impl TrustCheck for Verifier {
    fn describe(&self) -> TrustCheckInfo {
        TrustCheckInfo {
            available: self.available(),
            trust_list: self.list().digest().to_owned(),
            publishers: self.list().len() as u64,
        }
    }

    /// Checks the file and stops at the first route that makes it trusted.
    /// A file that has other content now than `sha256` says is not
    /// trusted.
    fn check(&self, path: &Path, sha256: &Sha256) -> TrustAnswer {
        match self.trust(path, Some(sha256)) {
            Trust::Trusted { publisher, route } => TrustAnswer::Trusted {
                detail: format!("signed for {publisher}, found in {}", route.in_words()),
                publisher,
                route: route.as_str(),
            },
            Trust::NotTrusted { reason, detail } => TrustAnswer::NotTrusted {
                reason: reason.as_str(),
                detail,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::list::TrustList;
    use crate::sigarea::executable_with_table;
    use crate::verify::stand_in::{Answers, signer, valid, verifier};

    fn signed_by_microsoft() -> Answers {
        Answers {
            catalog: valid(signer(
                "Microsoft Corporation",
                "Microsoft Corporation",
                true,
            )),
            ..Answers::default()
        }
    }

    #[test]
    fn the_engine_gets_the_answer_in_its_own_terms() {
        let dir = tempfile::tempdir().expect("a temporary folder");
        let path = dir.path().join("tool.exe");
        let content = executable_with_table(&[]);
        std::fs::write(&path, &content).expect("writing a file");
        let scanned: [u8; 32] = Sha256::digest(&content).into();

        let list = TrustList::builtin().expect("the built-in list");
        let (signed, _) = verifier(list, signed_by_microsoft());
        assert_eq!(
            signed.check(&path, &scanned),
            TrustAnswer::Trusted {
                publisher: "Microsoft Corporation".to_owned(),
                route: "windows_catalog",
                detail: "signed for Microsoft Corporation, found in a catalogue of Windows"
                    .to_owned(),
            }
        );

        // The answer has to be about the content that was scanned.
        let other = [0u8; 32];
        let answer = signed.check(&path, &other);
        assert!(
            matches!(
                answer,
                TrustAnswer::NotTrusted {
                    reason: "changed",
                    ..
                }
            ),
            "{answer:?}"
        );

        // Nobody on an empty list is trusted, whatever the signature.
        let (nobody, _) = verifier(TrustList::empty(), signed_by_microsoft());
        let answer = nobody.check(&path, &scanned);
        assert!(
            matches!(
                &answer,
                TrustAnswer::NotTrusted { reason: "not_listed", detail }
                    if detail.contains("Microsoft Corporation")
            ),
            "{answer:?}"
        );
    }

    #[test]
    fn the_description_names_the_list() {
        let list = TrustList::builtin().expect("the built-in list");
        let digest = list.digest().to_owned();
        let publishers = list.len() as u64;
        let (verifier, _) = verifier(list, Answers::default());
        let info = verifier.describe();
        assert!(info.available);
        assert_eq!(info.trust_list, digest);
        assert_eq!(info.publishers, publishers);
        assert_eq!(info.trust_list.len(), 64);

        // The real thing says whether it can work on this system.
        let real = Verifier::new(
            TrustList::builtin().expect("the built-in list"),
            crate::Options::default(),
        );
        assert_eq!(real.describe().available, cfg!(windows));
    }
}

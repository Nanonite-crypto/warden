//! Rules that are left out of a bundle on purpose.
//!
//! Public rule sets contain rules that flag clean files. When one is found,
//! it is written into an exclusion list together with the evidence: the
//! clean file it flagged, that file's SHA-256, the day and the machine.
//! [`crate::BundleBuilder::exclusions`] then leaves the rule out, and the
//! bundle records that it did. No rule gets on the list without evidence.
//!
//! The list is a TOML file:
//!
//! ```toml
//! [[rule]]
//! name = "Vendor_Loud_Rule"
//! reason = "Matches every program built with a common packer."
//!
//! [[rule.evidence]]
//! file = 'C:\Windows\System32\example.dll'
//! sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
//! seen = 2026-11-18
//! machine = "Windows 11 desktop"
//! ```

use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::path::Path;

use serde::Deserialize;
use thiserror::Error;
use yara_x_parser::Parser;
use yara_x_parser::cst::{CSTStream, Event, SyntaxKind};

/// Name of a YARA module that does not exist. A rule on the exclusion list
/// is replaced by one that uses this module, and the compiler is told to
/// leave out every rule that does. That way the compiler itself keeps track
/// of rules that depend on an excluded rule, and leaves those out as well.
pub(crate) const EXCLUSION_MODULE: &str = "warden_excluded";

/// Largest exclusion list that is read.
const MAX_LIST_BYTES: u64 = 4 * 1024 * 1024;
/// Most rules a list may name.
const MAX_RULES: usize = 10_000;
/// Most pieces of evidence one rule may carry.
const MAX_EVIDENCE: usize = 1_000;
/// Longest free-text field, in bytes.
const MAX_TEXT_BYTES: usize = 2_000;

/// Why an exclusion list could not be used.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ExclusionError {
    /// The file could not be read.
    #[error("{context}")]
    Io {
        /// What was being done.
        context: String,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
    /// The file is not valid TOML, or has fields this crate does not know.
    #[error("the exclusion list cannot be read: {0}")]
    Syntax(String),
    /// The file is well-formed, but an entry breaks one of the rules for
    /// entries.
    #[error("the exclusion list is not acceptable: {0}")]
    Invalid(String),
}

/// One clean file that a rule flagged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    /// Path of the clean file on the machine where it was seen.
    pub file: String,
    /// SHA-256 of that file, in lowercase hexadecimal.
    pub sha256: String,
    /// The day it was seen, as `YYYY-MM-DD`.
    pub seen: String,
    /// The machine it was seen on, in a few words.
    pub machine: String,
}

/// A rule that is left out, with the reason and the evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExcludedRule {
    /// The rule's name.
    pub name: String,
    /// Why the rule is left out, in a sentence.
    pub reason: String,
    /// Where the rule comes from, if the list says.
    pub source: Option<String>,
    /// Anything else worth knowing, if the list says.
    pub note: Option<String>,
    /// The clean files it flagged. Never empty.
    pub evidence: Vec<Evidence>,
}

/// A list of rules to leave out of a bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExclusionList {
    rules: Vec<ExcludedRule>,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawList {
    #[serde(default)]
    rule: Vec<RawRule>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
    name: String,
    reason: String,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    note: Option<String>,
    #[serde(default)]
    evidence: Vec<RawEvidence>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEvidence {
    file: String,
    sha256: String,
    seen: toml::value::Datetime,
    machine: String,
}

impl ExclusionList {
    /// Reads an exclusion list from a file.
    ///
    /// # Errors
    ///
    /// Fails if the file cannot be read or is not an acceptable list, see
    /// [`ExclusionList::parse`].
    pub fn load(path: &Path) -> Result<Self, ExclusionError> {
        let failed = |source| ExclusionError::Io {
            context: format!("cannot read {}", path.display()),
            source,
        };
        let file = fs::File::open(path).map_err(failed)?;
        let mut bytes = Vec::new();
        file.take(MAX_LIST_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(failed)?;
        if bytes.len() as u64 > MAX_LIST_BYTES {
            return Err(ExclusionError::Invalid(format!(
                "{} is larger than {MAX_LIST_BYTES} bytes",
                path.display()
            )));
        }
        let text = String::from_utf8(bytes)
            .map_err(|_| ExclusionError::Syntax("the file is not UTF-8 text".to_owned()))?;
        Self::parse(&text)
    }

    /// Reads an exclusion list from TOML text.
    ///
    /// # Errors
    ///
    /// Fails if the text is not valid TOML, uses a field that is not part
    /// of the format, names a rule twice, or has an entry without evidence.
    pub fn parse(text: &str) -> Result<Self, ExclusionError> {
        let raw: RawList =
            toml::from_str(text).map_err(|error| ExclusionError::Syntax(error.to_string()))?;
        if raw.rule.len() > MAX_RULES {
            return Err(invalid(format!("it names more than {MAX_RULES} rules")));
        }

        let mut seen_names = BTreeSet::new();
        let mut rules = Vec::with_capacity(raw.rule.len());
        for entry in raw.rule {
            if !is_identifier(&entry.name) {
                return Err(invalid(format!(
                    "{:?} is not a rule name",
                    shorten(&entry.name)
                )));
            }
            let name = entry.name;
            if !seen_names.insert(name.clone()) {
                return Err(invalid(format!("{name} is listed twice")));
            }
            check_text(&name, "reason", &entry.reason)?;
            for (field, value) in [("source", &entry.source), ("note", &entry.note)] {
                if let Some(value) = value {
                    check_text(&name, field, value)?;
                }
            }
            if entry.evidence.is_empty() {
                return Err(invalid(format!(
                    "{name} has no evidence: every entry must name at least one clean file that the rule flagged"
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
                if warden_sigdb::hex::decode_sha256(&item.sha256).is_none() {
                    return Err(invalid(format!(
                        "{name}: the sha256 of {} must be 64 hexadecimal digits",
                        shorten(&item.file)
                    )));
                }
                if item.seen.date.is_none()
                    || item.seen.time.is_some()
                    || item.seen.offset.is_some()
                {
                    return Err(invalid(format!(
                        "{name}: \"seen\" must be a date without a time, such as 2026-11-18"
                    )));
                }
                evidence.push(Evidence {
                    file: item.file,
                    sha256: item.sha256.to_ascii_lowercase(),
                    seen: item.seen.to_string(),
                    machine: item.machine,
                });
            }
            rules.push(ExcludedRule {
                name,
                reason: entry.reason,
                source: entry.source,
                note: entry.note,
                evidence,
            });
        }

        Ok(Self {
            rules,
            sha256: warden_sigdb::hex::encode(&warden_engine::sha256(text.as_bytes())),
        })
    }

    /// The listed rules, in the order of the file.
    #[must_use]
    pub fn rules(&self) -> &[ExcludedRule] {
        &self.rules
    }

    /// Number of listed rules.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// True if the list names no rule.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// SHA-256 of the list's text, in lowercase hexadecimal. A bundle
    /// records it, so that it can be told which list it was built with.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.sha256
    }

    /// The entry for a rule, if it is listed.
    #[must_use]
    pub fn get(&self, rule: &str) -> Option<&ExcludedRule> {
        self.rules.iter().find(|entry| entry.name == rule)
    }
}

fn invalid(message: String) -> ExclusionError {
    ExclusionError::Invalid(message)
}

fn shorten(text: &str) -> String {
    warden_engine::text::printable(text, 80)
}

/// Free text of an entry: not empty, not huge, and nothing in it that
/// could rewrite a terminal line when the list is shown.
fn check_text(rule: &str, field: &str, value: &str) -> Result<(), ExclusionError> {
    if value.trim().is_empty() {
        return Err(invalid(format!("{rule}: \"{field}\" is empty")));
    }
    if value.len() > MAX_TEXT_BYTES {
        return Err(invalid(format!(
            "{rule}: \"{field}\" is longer than {MAX_TEXT_BYTES} bytes"
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(invalid(format!(
            "{rule}: \"{field}\" contains a control character"
        )));
    }
    Ok(())
}

/// YARA identifiers: a letter or underscore, then letters, digits and
/// underscores, 128 bytes at most.
fn is_identifier(name: &str) -> bool {
    let mut bytes = name.bytes();
    let starts_well = bytes
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == b'_');
    starts_well
        && name.len() <= 128
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

/// One rule file after the listed rules were taken out of it.
#[derive(Debug)]
pub(crate) struct Rewritten {
    /// The text to compile in place of the original.
    pub text: String,
    /// Names of the rules that were replaced, in the order of the file.
    pub rules: Vec<String>,
}

/// A listed rule that must stay, with the reason.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct CannotExclude {
    /// The rule's name.
    pub rule: String,
    /// Why leaving it out is refused.
    pub reason: &'static str,
}

/// Below this many names, a rule file is first searched for the names as
/// plain text, which is much faster than parsing it. With more names the
/// searches would take longer than the parser.
const SEARCH_FIRST_UP_TO: usize = 64;

/// Replaces every rule of `text` whose name is in `listed` by a stub that
/// the compiler leaves out. `Ok(None)` means that the text declares none of
/// the rules and is to be compiled as it is.
///
/// A stub is a rule of the same name whose condition uses the module
/// [`EXCLUSION_MODULE`]. It takes up as many lines as the rule it replaces,
/// so that compile errors elsewhere in the file still point at the right
/// line. Everything outside the replaced rules stays byte for byte.
///
/// # Errors
///
/// A `global` rule is not replaced: its condition applies to every other
/// rule in the file, so leaving it out would make all of those match more.
pub(crate) fn stub_out(
    text: &str,
    listed: &BTreeSet<&str>,
) -> Result<Option<Rewritten>, CannotExclude> {
    if listed.is_empty()
        || (listed.len() <= SEARCH_FIRST_UP_TO && !listed.iter().any(|name| text.contains(name)))
    {
        return Ok(None);
    }

    /// A rule declaration that the parser is in the middle of.
    #[derive(Default)]
    struct Declaration<'a> {
        /// Where its first keyword starts.
        start: Option<usize>,
        seen_rule_keyword: bool,
        global: bool,
        name: Option<&'a str>,
    }

    // Start, end and name of every declaration that is to go.
    let mut found: Vec<(usize, usize, &str)> = Vec::new();
    let mut current: Option<Declaration<'_>> = None;
    // This is the parser the compiler uses, so both see the same rules.
    // Spaces and comments are not needed to find them.
    let events = CSTStream::from(Parser::new(text.as_bytes()))
        .whitespaces(false)
        .newlines(false)
        .comments(false);
    for event in events {
        match event {
            Event::Begin {
                kind: SyntaxKind::RULE_DECL,
                ..
            } => current = Some(Declaration::default()),
            Event::Token { kind, span } => {
                let Some(declaration) = current.as_mut() else {
                    continue;
                };
                if declaration.start.is_none() {
                    declaration.start = Some(span.start());
                }
                match kind {
                    SyntaxKind::GLOBAL_KW if !declaration.seen_rule_keyword => {
                        declaration.global = true;
                    }
                    SyntaxKind::RULE_KW => declaration.seen_rule_keyword = true,
                    SyntaxKind::IDENT
                        if declaration.seen_rule_keyword && declaration.name.is_none() =>
                    {
                        // A name that cannot be read is no name on the list.
                        declaration.name = Some(text.get(span.range()).unwrap_or_default());
                    }
                    _ => {}
                }
            }
            Event::End {
                kind: SyntaxKind::RULE_DECL,
                span,
            } => {
                let Some(declaration) = current.take() else {
                    continue;
                };
                let (Some(start), Some(name)) = (declaration.start, declaration.name) else {
                    continue;
                };
                if !listed.contains(name) {
                    continue;
                }
                if declaration.global {
                    return Err(CannotExclude {
                        rule: name.to_owned(),
                        reason: "it is a global rule, and leaving it out would loosen every other rule in its file",
                    });
                }
                let end = span.end();
                let after_last = found
                    .last()
                    .is_none_or(|(_, last_end, _)| *last_end <= start);
                if after_last
                    && start < end
                    && text.is_char_boundary(start)
                    && text.is_char_boundary(end)
                {
                    found.push((start, end, name));
                }
            }
            _ => {}
        }
    }
    if found.is_empty() {
        return Ok(None);
    }

    let mut rewritten = String::with_capacity(text.len());
    let mut rules = Vec::with_capacity(found.len());
    let mut position = 0;
    for (start, end, name) in found {
        rewritten.push_str(&text[position..start]);
        if rules.is_empty() {
            // One import serves every stub in the file. It sits on the line
            // of the first one, so no line is added.
            rewritten.push_str("import \"");
            rewritten.push_str(EXCLUSION_MODULE);
            rewritten.push_str("\" ");
        }
        rewritten.push_str("rule ");
        rewritten.push_str(name);
        rewritten.push_str(" { condition: ");
        rewritten.push_str(EXCLUSION_MODULE);
        rewritten.push_str(".listed }");
        let lines = text[start..end]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count();
        rewritten.extend(std::iter::repeat_n('\n', lines));
        rules.push(name.to_owned());
        position = end;
    }
    rewritten.push_str(&text[position..]);
    Ok(Some(Rewritten {
        text: rewritten,
        rules,
    }))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    const LIST: &str = r#"
# A comment.
[[rule]]
name = "Loud_Rule"
reason = "Matches a system library."
source = "Some rule set"

[[rule.evidence]]
file = 'C:\Windows\System32\example.dll'
sha256 = "AB00000000000000000000000000000000000000000000000000000000000000"
seen = 2026-11-18
machine = "Windows 11 desktop"
"#;

    #[test]
    fn a_list_is_read_with_its_evidence() {
        let list = ExclusionList::parse(LIST).unwrap();
        assert_eq!(list.len(), 1);
        let rule = &list.rules()[0];
        assert_eq!(rule.name, "Loud_Rule");
        assert_eq!(rule.source.as_deref(), Some("Some rule set"));
        assert_eq!(rule.note, None);
        assert_eq!(rule.evidence.len(), 1);
        assert_eq!(rule.evidence[0].file, r"C:\Windows\System32\example.dll");
        // Hashes are compared in lowercase everywhere else.
        assert!(rule.evidence[0].sha256.starts_with("ab00"));
        assert_eq!(rule.evidence[0].seen, "2026-11-18");
        assert_eq!(list.digest().len(), 64);
        assert!(list.get("Loud_Rule").is_some());
        assert!(list.get("Other").is_none());
    }

    #[test]
    fn an_empty_file_is_an_empty_list() {
        let list = ExclusionList::parse("# nothing yet\n").unwrap();
        assert!(list.is_empty());
    }

    #[test]
    fn entries_without_evidence_are_refused() {
        let text = "[[rule]]\nname = \"A\"\nreason = \"because\"\n";
        let error = ExclusionList::parse(text).unwrap_err();
        assert!(matches!(error, ExclusionError::Invalid(_)), "{error}");
        assert!(error.to_string().contains("no evidence"), "{error}");
    }

    #[test]
    fn mistakes_in_a_list_are_refused() {
        let with = |from: &str, to: &str| LIST.replace(from, to);
        let cases = [
            // A misspelt field must not be skipped silently.
            (with("reason =", "reasn ="), "Syntax"),
            (with("machine =", "where ="), "Syntax"),
            (with("\"Loud_Rule\"", "\"not a name\""), "Invalid"),
            (with("\"Loud_Rule\"", "\"\""), "Invalid"),
            (with("\"AB000", "\"XY000"), "Invalid"),
            (with("\"AB000", "\"AB00"), "Invalid"),
            (
                with("seen = 2026-11-18", "seen = 2026-11-18T10:00:00"),
                "Invalid",
            ),
            (with("seen = 2026-11-18", "seen = \"yesterday\""), "Syntax"),
            (with("\"Matches a system library.\"", "\" \""), "Invalid"),
            (format!("{LIST}{LIST}"), "Invalid"),
            ("[[rule]\n".to_owned(), "Syntax"),
        ];
        for (text, expected) in cases {
            let error = ExclusionList::parse(&text).unwrap_err();
            let kind = match error {
                ExclusionError::Syntax(_) => "Syntax",
                ExclusionError::Invalid(_) => "Invalid",
                ExclusionError::Io { .. } => "Io",
            };
            assert_eq!(kind, expected, "{error}\n{text}");
        }
    }

    #[test]
    fn listed_rules_are_replaced_and_everything_else_stays() {
        let text = "rule Keep_One { condition: true }\n\
                    // A comment that belongs to the next rule.\n\
                    private rule Loud_Rule : tag {\n\
                    \x20 strings:\n\
                    \x20   $a = \"rule Other { }\"\n\
                    \x20 condition:\n\
                    \x20   $a\n\
                    } // trailing\n\
                    rule Keep_Two { condition: Keep_One }\n";
        let listed = BTreeSet::from(["Loud_Rule", "Not_There"]);
        let rewritten = stub_out(text, &listed).unwrap().unwrap();
        assert_eq!(rewritten.rules, ["Loud_Rule"]);

        let before: Vec<&str> = text.lines().collect();
        let after: Vec<&str> = rewritten.text.lines().collect();
        assert_eq!(after.len(), before.len());
        assert_eq!(after[..2], before[..2]);
        assert_eq!(
            after[2],
            "import \"warden_excluded\" rule Loud_Rule { condition: warden_excluded.listed }"
        );
        assert_eq!(after[3..7], ["", "", "", ""]);
        assert_eq!(after[7], " // trailing");
        assert_eq!(after[8], before[8]);
    }

    #[test]
    fn one_import_serves_several_stubs() {
        let text = "rule A { condition: true } rule B { condition: true }\r\n\
                    rule C {\r\n condition: true\r\n}\r\nrule D { condition: C }";
        let listed = BTreeSet::from(["A", "C"]);
        let rewritten = stub_out(text, &listed).unwrap().unwrap();
        assert_eq!(rewritten.rules, ["A", "C"]);
        assert_eq!(rewritten.text.matches("import").count(), 1);
        assert_eq!(
            rewritten.text,
            "import \"warden_excluded\" rule A { condition: warden_excluded.listed } \
             rule B { condition: true }\r\n\
             rule C { condition: warden_excluded.listed }\n\n\r\nrule D { condition: C }"
        );
    }

    #[test]
    fn text_without_a_listed_rule_is_left_alone() {
        let listed = BTreeSet::from(["Loud_Rule"]);
        let untouched = |text: &str| stub_out(text, &listed).unwrap().is_none();
        assert!(untouched("rule Quiet { condition: true }"));
        // The name appears, but not as the name of a rule.
        assert!(untouched(
            "rule Quiet { strings: $a = \"Loud_Rule\" condition: $a }"
        ));
        assert!(untouched("rule Quiet : Loud_Rule { condition: true }"));
        assert!(untouched("// rule Loud_Rule { condition: true }"));
        // A longer name that starts the same way is another rule.
        assert!(untouched("rule Loud_Rule_2 { condition: true }"));
        // Without a list there is nothing to look for.
        assert!(
            stub_out("rule Loud_Rule { condition: true }", &BTreeSet::new())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn a_global_rule_is_not_taken_out() {
        let listed = BTreeSet::from(["Gate"]);
        for text in [
            "global rule Gate { condition: filesize < 1MB }",
            "private global rule Gate { condition: filesize < 1MB }",
            "global private rule Gate { condition: filesize < 1MB }",
        ] {
            let refused = stub_out(text, &listed).unwrap_err();
            assert_eq!(refused.rule, "Gate");
            assert!(refused.reason.contains("global"), "{}", refused.reason);
        }
        // "global" in the rule before does not make the listed rule global.
        let text = "global rule Other { condition: true } rule Gate { condition: true }";
        assert!(stub_out(text, &listed).unwrap().is_some());
    }

    #[test]
    fn many_names_are_found_without_the_plain_text_search() {
        let names: Vec<String> = (0..200).map(|index| format!("Rule_{index}")).collect();
        let listed: BTreeSet<&str> = names.iter().map(String::as_str).collect();
        let text = "rule Rule_7 { condition: true }\nrule Other { condition: true }";
        let rewritten = stub_out(text, &listed).unwrap().unwrap();
        assert_eq!(rewritten.rules, ["Rule_7"]);
        assert!(
            stub_out("rule Other { condition: true }", &listed)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn a_broken_rule_file_does_not_break_the_search() {
        let listed = BTreeSet::from(["Loud_Rule"]);
        // Whatever the parser makes of these, the result must be usable.
        for text in [
            "rule Loud_Rule {",
            "rule Loud_Rule { condition: }",
            "rule { condition: true } rule Loud_Rule",
            "}}}} rule Loud_Rule { condition: true } {{{{",
            "rule Loud_Rule { condition: true } rule Loud_Rule { condition: false }",
            "\u{feff}rule Loud_Rule { condition: true }",
        ] {
            if let Ok(Some(rewritten)) = stub_out(text, &listed) {
                assert_eq!(
                    rewritten.text.matches('\n').count(),
                    text.matches('\n').count(),
                    "{text}"
                );
                assert!(rewritten.rules.iter().all(|rule| rule == "Loud_Rule"));
            }
        }
    }
}

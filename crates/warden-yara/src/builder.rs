//! Compiling rule files into a [`RuleBundle`].

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::bundle::{BundleError, ENGINE, Manifest, RuleBundle, SourceInfo};

/// Name under which the built-in rules appear in a bundle.
pub const BUILTIN_SOURCE: &str = "warden/builtin.yar";

/// The rules that ship inside the program.
const BUILTIN_RULES: &str = include_str!("../rules/builtin.yar");

/// YARA modules this build does not include. Rules that need one are left
/// out of the bundle and counted, instead of failing the whole file.
const MODULES_NOT_BUILT: [&str; 8] = ["crx", "cuckoo", "dex", "magic", "msi", "olecf", "vt", "zip"];

/// How many skipped rules and error messages a report lists in full.
const MAX_LISTED: usize = 500;
/// Largest rule file that is read, whether from disk or from a package.
const MAX_SOURCE_BYTES: u64 = 256 * 1024 * 1024;
/// Most rule files taken from one package.
const MAX_PACKAGE_MEMBERS: usize = 10_000;

struct Source {
    name: String,
    text: String,
    replaced_invalid_text: bool,
}

/// Collects rule files and compiles them into a bundle.
///
/// The built-in rules are always part of a bundle unless they are switched
/// off, so a scan with a bundle catches everything a scan without one does.
pub struct BundleBuilder {
    sources: Vec<Source>,
    builtin: bool,
    created_unix_secs: Option<u64>,
}

impl Default for BundleBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// A rule that was left out of a bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedRule {
    /// The rule's name.
    pub rule: String,
    /// Why it could not be compiled.
    pub reason: String,
}

/// What happened to one rule file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceReport {
    /// The file's name.
    pub name: String,
    /// Size of the file in bytes.
    pub bytes: u64,
    /// Rules that were compiled.
    pub rules: u64,
    /// Rules that were left out.
    pub skipped: u64,
    /// Whether the file held bytes that are not valid UTF-8, which were
    /// replaced before compiling.
    pub replaced_invalid_text: bool,
}

/// The outcome of building a bundle, for a person to read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildReport {
    /// One entry per rule file, in the order they were compiled.
    pub sources: Vec<SourceReport>,
    /// Rules in the bundle.
    pub rules: u64,
    /// Rules that were left out. The list is cut after the first 500;
    /// `skipped_total` is complete.
    pub skipped: Vec<SkippedRule>,
    /// Number of rules that were left out.
    pub skipped_total: u64,
    /// The first line of each compile error. Cut after the first 500;
    /// `error_total` is complete.
    pub errors: Vec<String>,
    /// Number of compile errors.
    pub error_total: u64,
    /// Number of warnings the compiler issued.
    pub warnings: u64,
    /// How long compiling took.
    pub compile_time: Duration,
}

/// A freshly built bundle.
#[derive(Debug)]
pub struct Built {
    /// The bundle, ready to scan with.
    pub bundle: RuleBundle,
    /// The bundle in the form that is written to a file.
    pub bytes: Vec<u8>,
    /// What happened to each rule file and rule.
    pub report: BuildReport,
}

impl BundleBuilder {
    /// Starts a bundle that holds the built-in rules.
    #[must_use]
    pub fn new() -> Self {
        Self {
            sources: Vec::new(),
            builtin: true,
            created_unix_secs: None,
        }
    }

    /// Chooses whether the built-in rules are part of the bundle.
    #[must_use]
    pub fn builtin_rules(mut self, include: bool) -> Self {
        self.builtin = include;
        self
    }

    /// Fixes the creation time recorded in the bundle, for reproducible
    /// builds. The default is the current time.
    #[must_use]
    pub fn created_unix_secs(mut self, seconds: u64) -> Self {
        self.created_unix_secs = Some(seconds);
        self
    }

    /// Number of rule files added so far, not counting the built-in rules.
    #[must_use]
    pub fn source_count(&self) -> usize {
        self.sources.len()
    }

    /// Adds the text of one rule file.
    pub fn add_source(&mut self, name: impl Into<String>, text: impl Into<String>) -> &mut Self {
        self.push(name.into(), text.into(), false);
        self
    }

    /// Adds a rule file, every rule file below a folder, or every rule file
    /// in a zip package such as the ones YARA Forge publishes. Rule files
    /// are recognised by the extensions `.yar` and `.yara`.
    ///
    /// Returns the number of rule files that were added.
    ///
    /// # Errors
    ///
    /// Fails if the path cannot be read, or holds no rule file.
    pub fn add_path(&mut self, path: &Path) -> Result<usize, BundleError> {
        let before = self.sources.len();
        let metadata = fs::metadata(path).map_err(|source| BundleError::Io {
            context: format!("cannot read {}", path.display()),
            source,
        })?;
        if metadata.is_dir() {
            self.add_folder(path, path)?;
        } else if has_extension(path, &["zip"]) {
            self.add_package(path)?;
        } else {
            let bytes = read_limited(path)?;
            self.push_bytes(file_name(path), bytes);
        }
        let added = self.sources.len() - before;
        if added == 0 {
            return Err(BundleError::Source(format!(
                "{} holds no .yar or .yara file",
                path.display()
            )));
        }
        Ok(added)
    }

    fn add_folder(&mut self, root: &Path, folder: &Path) -> Result<(), BundleError> {
        let failed = |source| BundleError::Io {
            context: format!("cannot list {}", folder.display()),
            source,
        };
        let mut entries = fs::read_dir(folder)
            .map_err(failed)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(failed)?;
        // Directory order differs between systems; sorting makes the same
        // folder give the same bundle everywhere.
        entries.sort_by_key(fs::DirEntry::file_name);
        for entry in entries {
            let path = entry.path();
            let kind = entry.file_type().map_err(failed)?;
            if kind.is_dir() {
                self.add_folder(root, &path)?;
            } else if kind.is_file() && has_extension(&path, &["yar", "yara"]) {
                let bytes = read_limited(&path)?;
                let relative = path.strip_prefix(root).unwrap_or(&path);
                let name = relative
                    .components()
                    .map(|part| part.as_os_str().to_string_lossy())
                    .collect::<Vec<_>>()
                    .join("/");
                self.push_bytes(name, bytes);
            }
        }
        Ok(())
    }

    fn add_package(&mut self, path: &Path) -> Result<(), BundleError> {
        let unreadable = |detail: String| {
            BundleError::Source(format!("cannot read package {}: {detail}", path.display()))
        };
        let file = fs::File::open(path).map_err(|source| BundleError::Io {
            context: format!("cannot open {}", path.display()),
            source,
        })?;
        let mut archive = zip::ZipArchive::new(std::io::BufReader::new(file))
            .map_err(|error| unreadable(error.to_string()))?;
        if archive.len() > MAX_PACKAGE_MEMBERS {
            return Err(unreadable(format!(
                "it has more than {MAX_PACKAGE_MEMBERS} members"
            )));
        }
        let package = file_name(path);
        for index in 0..archive.len() {
            let member = archive
                .by_index(index)
                .map_err(|error| unreadable(error.to_string()))?;
            let Ok(member_name) = member.name().map(|name| name.into_owned()) else {
                continue;
            };
            if !member.is_file() || !has_extension(Path::new(&member_name), &["yar", "yara"]) {
                continue;
            }
            let mut bytes = Vec::new();
            member
                .take(MAX_SOURCE_BYTES + 1)
                .read_to_end(&mut bytes)
                .map_err(|error| unreadable(format!("{member_name}: {error}")))?;
            if bytes.len() as u64 > MAX_SOURCE_BYTES {
                return Err(unreadable(format!(
                    "{member_name} is larger than {MAX_SOURCE_BYTES} bytes"
                )));
            }
            self.push_bytes(format!("{package}/{member_name}"), bytes);
        }
        Ok(())
    }

    fn push_bytes(&mut self, name: String, bytes: Vec<u8>) {
        match String::from_utf8(bytes) {
            Ok(text) => self.push(name, text, false),
            Err(error) => {
                let text = String::from_utf8_lossy(error.as_bytes()).into_owned();
                self.push(name, text, true);
            }
        }
    }

    fn push(&mut self, name: String, text: String, replaced_invalid_text: bool) {
        // Every file is compiled into a namespace of its own, named after
        // the file, so names must not repeat.
        let mut unique = name.clone();
        let mut attempt = 2;
        while unique == BUILTIN_SOURCE || self.sources.iter().any(|source| source.name == unique) {
            unique = format!("{name} ({attempt})");
            attempt += 1;
        }
        self.sources.push(Source {
            name: unique,
            text,
            replaced_invalid_text,
        });
    }

    /// Compiles everything that was added.
    ///
    /// A rule that does not compile is left out and listed in the report;
    /// it does not stop the build.
    ///
    /// # Errors
    ///
    /// Fails if not a single rule could be compiled.
    pub fn build(self) -> Result<Built, BundleError> {
        let mut sources = Vec::with_capacity(self.sources.len() + 1);
        if self.builtin {
            sources.push(Source {
                name: BUILTIN_SOURCE.to_owned(),
                text: BUILTIN_RULES.to_owned(),
                replaced_invalid_text: false,
            });
        }
        sources.extend(self.sources);

        let started = Instant::now();
        let mut compiler = yara_x::Compiler::new();
        // Many public rules were written for the original YARA, which
        // accepts some regular expressions that YARA-X is strict about.
        compiler.relaxed_re_syntax(true);
        for module in MODULES_NOT_BUILT {
            compiler.ignore_module(module);
        }

        let mut skipped_per_source = Vec::with_capacity(sources.len());
        for source in &sources {
            let skipped_before = compiler.ignored_rules().len();
            compiler.new_namespace(&source.name);
            // An error here means that some rule in the file did not
            // compile. The compiler keeps the rules that did and remembers
            // the error, which is read back below.
            let code = yara_x::SourceCode::from(source.text.as_str()).with_origin(&source.name);
            let _ = compiler.add_source(code);
            skipped_per_source.push((compiler.ignored_rules().len() - skipped_before) as u64);
        }

        let skipped_total = compiler.ignored_rules().len() as u64;
        let skipped = compiler
            .ignored_rules()
            .take(MAX_LISTED)
            .map(|(rule, reason)| SkippedRule {
                rule: rule.to_owned(),
                reason: describe(&reason),
            })
            .collect();
        let error_total = compiler.errors().len() as u64;
        let errors = compiler
            .errors()
            .iter()
            .take(MAX_LISTED)
            .map(|error| first_line(&error.to_string()))
            .collect();
        let warnings = compiler.warnings().len() as u64;

        let rules = compiler.build();
        let compile_time = started.elapsed();
        if rules.iter().len() == 0 {
            return Err(BundleError::Empty);
        }

        let mut compiled_per_source: BTreeMap<&str, u64> = BTreeMap::new();
        for rule in rules.iter() {
            *compiled_per_source.entry(rule.namespace()).or_insert(0) += 1;
        }
        let mut manifest = Manifest {
            engine: ENGINE.to_owned(),
            sources: Vec::with_capacity(sources.len()),
        };
        let mut reports = Vec::with_capacity(sources.len());
        for (source, skipped) in sources.iter().zip(skipped_per_source) {
            let compiled = compiled_per_source
                .get(source.name.as_str())
                .copied()
                .unwrap_or(0);
            manifest.sources.push(SourceInfo {
                name: source.name.clone(),
                sha256: warden_sigdb::hex::encode(&warden_engine::sha256(source.text.as_bytes())),
                bytes: source.text.len() as u64,
                rules: compiled,
                skipped,
            });
            reports.push(SourceReport {
                name: source.name.clone(),
                bytes: source.text.len() as u64,
                rules: compiled,
                skipped,
                replaced_invalid_text: source.replaced_invalid_text,
            });
        }
        drop(compiled_per_source);

        let rule_total = rules.iter().len() as u64;
        let created = self.created_unix_secs.unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_secs())
        });
        let (bundle, bytes) = RuleBundle::assemble(rules, manifest, created)?;
        Ok(Built {
            bundle,
            bytes,
            report: BuildReport {
                sources: reports,
                rules: rule_total,
                skipped,
                skipped_total,
                errors,
                error_total,
                warnings,
                compile_time,
            },
        })
    }
}

fn describe(reason: &yara_x::IgnoredRuleReason<'_>) -> String {
    match reason {
        yara_x::IgnoredRuleReason::IgnoredModule(module) => {
            format!("needs the YARA module \"{module}\", which this build does not include")
        }
        yara_x::IgnoredRuleReason::IgnoredRule(rule) => {
            format!("depends on the rule {rule}, which was left out")
        }
        yara_x::IgnoredRuleReason::CompileError(error) => first_line(&error.to_string()),
    }
}

/// Compile errors come as multi-line reports with a source excerpt. The
/// first line says what is wrong.
fn first_line(message: &str) -> String {
    message.lines().next().unwrap_or_default().trim().to_owned()
}

fn has_extension(path: &Path, wanted: &[&str]) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            wanted
                .iter()
                .any(|candidate| extension.eq_ignore_ascii_case(candidate))
        })
}

fn file_name(path: &Path) -> String {
    path.file_name().map_or_else(
        || path.to_string_lossy().into_owned(),
        |name| name.to_string_lossy().into_owned(),
    )
}

fn read_limited(path: &Path) -> Result<Vec<u8>, BundleError> {
    let failed = |source| BundleError::Io {
        context: format!("cannot read {}", path.display()),
        source,
    };
    let file = fs::File::open(path).map_err(failed)?;
    let mut bytes = Vec::new();
    file.take(MAX_SOURCE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(failed)?;
    if bytes.len() as u64 > MAX_SOURCE_BYTES {
        return Err(BundleError::Source(format!(
            "{} is larger than {MAX_SOURCE_BYTES} bytes",
            path.display()
        )));
    }
    Ok(bytes)
}

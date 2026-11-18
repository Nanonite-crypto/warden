use std::any::Any;
use std::io::{self, Read};
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crossbeam_channel::{Receiver, RecvTimeoutError, Sender, bounded};
use sha2::Digest;
use time::OffsetDateTime;
use walkdir::WalkDir;

use crate::cancel::CancelToken;
use crate::detector::{Detector, FileView};
use crate::error::ScanError;
use crate::file;
use crate::finding::{Finding, Verdict};
use crate::observer::{Progress, ScanObserver};
use crate::options::ScanOptions;
use crate::paths::{self, ExcludeSet};
use crate::report::{Detection, DetectorFailure, ScanReport, ScanStats, SkipReason, Skipped};
use crate::verdict::VerdictPolicy;
use crate::{ENGINE_VERSION, REPORT_SCHEMA, Sha256};

/// How often the observer hears about progress.
const PROGRESS_INTERVAL: Duration = Duration::from_millis(100);
/// Read size for files that are hashed without being buffered.
pub(crate) const STREAM_CHUNK_BYTES: usize = 256 * 1024;
/// Content buffers larger than this are released after the file that needed
/// them, so one huge file does not pin memory for the rest of the scan.
const RETAINED_CONTENT_BYTES: usize = 8 * 1024 * 1024;
/// Queue slots per worker. Bounded queues give back-pressure: the walker
/// cannot run far ahead of the workers and fill memory with paths.
const QUEUE_SLOTS_PER_THREAD: usize = 64;

/// The outcome of checking one file or one in-memory buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileResult {
    /// Number of bytes read.
    pub size: u64,
    /// SHA-256 of those bytes.
    pub sha256: Sha256,
    /// The decision.
    pub verdict: Verdict,
    /// What the detectors found.
    pub findings: Vec<Finding>,
    /// Whether the file was too large for content detectors.
    pub content_scan_skipped: bool,
    /// Detectors that failed on this file, as `id: message`.
    pub detector_errors: Vec<String>,
}

/// Configures and creates a [`Scanner`].
#[derive(Default)]
pub struct ScannerBuilder {
    detectors: Vec<Arc<dyn Detector>>,
    policy: VerdictPolicy,
    options: ScanOptions,
}

impl ScannerBuilder {
    /// Adds a detector. Detectors run in the order they are added.
    #[must_use]
    pub fn detector(mut self, detector: impl Detector + 'static) -> Self {
        self.detectors.push(Arc::new(detector));
        self
    }

    /// Adds a detector that is shared with other owners.
    #[must_use]
    pub fn shared_detector(mut self, detector: Arc<dyn Detector>) -> Self {
        self.detectors.push(detector);
        self
    }

    /// Replaces the default verdict policy.
    #[must_use]
    pub fn policy(mut self, policy: VerdictPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Replaces the default options.
    #[must_use]
    pub fn options(mut self, options: ScanOptions) -> Self {
        self.options = options;
        self
    }

    /// Creates the scanner.
    #[must_use]
    pub fn build(self) -> Scanner {
        let needs_content = self
            .detectors
            .iter()
            .any(|detector| detector.needs_content());
        Scanner {
            detectors: self.detectors,
            policy: self.policy,
            options: self.options,
            needs_content,
        }
    }
}

/// Runs detectors over files and collects the results.
///
/// A scanner is immutable and can be shared between threads. See the
/// [crate documentation](crate) for how a scan proceeds.
pub struct Scanner {
    detectors: Vec<Arc<dyn Detector>>,
    policy: VerdictPolicy,
    options: ScanOptions,
    needs_content: bool,
}

impl std::fmt::Debug for Scanner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let detectors: Vec<&str> = self
            .detectors
            .iter()
            .map(|detector| detector.id())
            .collect();
        formatter
            .debug_struct("Scanner")
            .field("detectors", &detectors)
            .field("policy", &self.policy)
            .field("options", &self.options)
            .finish()
    }
}

impl Scanner {
    /// Starts configuring a scanner.
    #[must_use]
    pub fn builder() -> ScannerBuilder {
        ScannerBuilder::default()
    }

    /// The options this scanner was built with.
    #[must_use]
    pub fn options(&self) -> &ScanOptions {
        &self.options
    }

    /// Checks a buffer that is already in memory.
    #[must_use]
    pub fn scan_bytes(&self, bytes: &[u8]) -> FileResult {
        let sha256 = crate::sha256(bytes);
        let view = FileView::new(Path::new(""), bytes.len() as u64, &sha256, Some(bytes));
        self.run_detectors(&view, sha256, false)
    }

    /// Scans files and directory trees.
    ///
    /// Blocks until the scan is finished or cancelled. `observer` is called
    /// on the calling thread.
    ///
    /// # Errors
    ///
    /// Fails only if the request as a whole cannot be carried out: no roots,
    /// or a root or exclusion that does not exist or cannot be resolved.
    /// Problems with individual files are recorded in the report instead.
    pub fn scan(
        &self,
        roots: &[PathBuf],
        observer: &mut dyn ScanObserver,
        cancel: &CancelToken,
    ) -> Result<ScanReport, ScanError> {
        if roots.is_empty() {
            return Err(ScanError::NoRoots);
        }
        let mut absolute_roots = Vec::with_capacity(roots.len());
        for root in roots {
            let root_error = |source| ScanError::Root {
                path: root.clone(),
                source,
            };
            let absolute = paths::absolute(root).map_err(root_error)?;
            std::fs::metadata(&absolute).map_err(root_error)?;
            absolute_roots.push(absolute);
        }
        let excludes = ExcludeSet::new(&self.options.exclude)
            .map_err(|(path, source)| ScanError::Root { path, source })?;

        let threads = self.options.effective_threads();
        let queue_slots = threads * QUEUE_SLOTS_PER_THREAD;
        let (job_sender, job_receiver) = bounded::<PathBuf>(queue_slots);
        let (outcome_sender, outcome_receiver) = bounded::<Outcome>(queue_slots);

        let started_at = OffsetDateTime::now_utc();
        let clock = Instant::now();
        let mut tally = Tally::new(self.options.max_recorded_skips);

        thread::scope(|scope| {
            let walker_outcomes = outcome_sender.clone();
            let roots = &absolute_roots;
            let excludes = &excludes;
            scope.spawn(move || {
                walk_guarded(roots, excludes, &job_sender, &walker_outcomes, cancel);
            });
            for _ in 0..threads {
                let jobs = job_receiver.clone();
                let outcomes = outcome_sender.clone();
                scope.spawn(move || self.work(&jobs, &outcomes, cancel));
            }
            // Only the spawned threads may keep the channels open, otherwise
            // the loop below would never see them close.
            drop(job_receiver);
            drop(outcome_sender);

            let mut last_progress = Instant::now();
            loop {
                match outcome_receiver.recv_timeout(PROGRESS_INTERVAL) {
                    Ok(outcome) => tally.record(outcome, observer),
                    Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => break,
                }
                if last_progress.elapsed() >= PROGRESS_INTERVAL {
                    observer.on_progress(&tally.progress(clock.elapsed()));
                    last_progress = Instant::now();
                }
            }
        });

        let duration = clock.elapsed();
        observer.on_progress(&tally.progress(duration));
        Ok(tally.into_report(ReportContext {
            started_at,
            duration,
            cancelled: cancel.is_cancelled(),
            roots: absolute_roots,
            threads,
            detectors: self
                .detectors
                .iter()
                .map(|detector| detector.describe())
                .collect(),
        }))
    }

    /// Worker thread body: takes paths until the queue closes.
    fn work(&self, jobs: &Receiver<PathBuf>, outcomes: &Sender<Outcome>, cancel: &CancelToken) {
        let mut buffers = Buffers::new();
        for path in jobs {
            if cancel.is_cancelled() {
                // Keep draining so the walker is never blocked on a full queue.
                continue;
            }
            // A panic in a detector must not take the scan down with it. The
            // file is reported as skipped and the worker carries on.
            let attempt =
                panic::catch_unwind(AssertUnwindSafe(|| self.scan_file(&path, &mut buffers)));
            let outcome = match attempt {
                Ok(Ok(result)) => Outcome::Scanned { path, result },
                Ok(Err((reason, detail))) => Outcome::Skipped(Skipped {
                    path,
                    reason,
                    detail,
                }),
                Err(payload) => {
                    buffers = Buffers::new();
                    Outcome::Skipped(Skipped {
                        path,
                        reason: SkipReason::InternalError,
                        detail: format!("a detector panicked: {}", panic_message(&*payload)),
                    })
                }
            };
            if outcomes.send(outcome).is_err() {
                return;
            }
        }
    }

    /// Reads one file once, hashing it on the way, and runs the detectors.
    fn scan_file(
        &self,
        path: &Path,
        buffers: &mut Buffers,
    ) -> Result<FileResult, (SkipReason, String)> {
        let failed = |error: io::Error| (file::classify_io_error(&error), error.to_string());
        let mut file = file::open_for_scan(path).map_err(failed)?;
        let mut hasher = sha2::Sha256::new();

        if self.needs_content {
            let limit = self.options.max_content_bytes;
            buffers.content.clear();
            // Reading one byte past the limit tells us whether the file fits
            // without trusting the size the directory listing reported.
            (&mut file)
                .take(limit.saturating_add(1))
                .read_to_end(&mut buffers.content)
                .map_err(failed)?;
            hasher.update(&buffers.content);
            if buffers.content.len() as u64 <= limit {
                let sha256: Sha256 = hasher.finalize().into();
                let size = buffers.content.len() as u64;
                let view = FileView::new(path, size, &sha256, Some(&buffers.content));
                let result = self.run_detectors(&view, sha256, false);
                buffers.release_excess();
                return Ok(result);
            }
            // Too large to keep: finish the hash in streaming fashion.
            let already_read = buffers.content.len() as u64;
            buffers.content = Vec::new();
            let rest = hash_stream(&mut file, &mut hasher, &mut buffers.chunk).map_err(failed)?;
            let sha256: Sha256 = hasher.finalize().into();
            let view = FileView::new(path, already_read + rest, &sha256, None);
            return Ok(self.run_detectors(&view, sha256, true));
        }

        let size = hash_stream(&mut file, &mut hasher, &mut buffers.chunk).map_err(failed)?;
        let sha256: Sha256 = hasher.finalize().into();
        let view = FileView::new(path, size, &sha256, None);
        Ok(self.run_detectors(&view, sha256, false))
    }

    fn run_detectors(
        &self,
        view: &FileView<'_>,
        sha256: Sha256,
        content_scan_skipped: bool,
    ) -> FileResult {
        let mut findings = Vec::new();
        let mut detector_errors = Vec::new();
        for detector in &self.detectors {
            if detector.needs_content() && view.content().is_none() {
                continue;
            }
            match detector.inspect(view) {
                Ok(mut found) => findings.append(&mut found),
                Err(error) => detector_errors.push(format!("{}: {error}", detector.id())),
            }
        }
        FileResult {
            size: view.size(),
            sha256,
            verdict: self.policy.decide(&findings),
            findings,
            content_scan_skipped,
            detector_errors,
        }
    }
}

/// Per-worker scratch memory, reused from file to file.
struct Buffers {
    content: Vec<u8>,
    chunk: Vec<u8>,
}

impl Buffers {
    fn new() -> Self {
        Self {
            content: Vec::new(),
            chunk: vec![0u8; STREAM_CHUNK_BYTES],
        }
    }

    fn release_excess(&mut self) {
        if self.content.capacity() > RETAINED_CONTENT_BYTES {
            self.content = Vec::new();
        }
    }
}

/// Feeds the rest of `reader` into `hasher`. Returns the number of bytes read.
pub(crate) fn hash_stream(
    reader: &mut impl Read,
    hasher: &mut sha2::Sha256,
    chunk: &mut [u8],
) -> io::Result<u64> {
    let mut total = 0u64;
    loop {
        match reader.read(chunk) {
            Ok(0) => return Ok(total),
            Ok(read) => {
                hasher.update(&chunk[..read]);
                total += read as u64;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

fn panic_message(payload: &(dyn Any + Send)) -> &str {
    if let Some(message) = payload.downcast_ref::<&str>() {
        message
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message
    } else {
        "no message"
    }
}

/// What the walker and the workers report to the collecting thread.
enum Outcome {
    Scanned { path: PathBuf, result: FileResult },
    Skipped(Skipped),
    LinkNotFollowed,
    Excluded,
}

/// Walker thread body, with the same panic isolation as the workers.
fn walk_guarded(
    roots: &[PathBuf],
    excludes: &ExcludeSet,
    jobs: &Sender<PathBuf>,
    outcomes: &Sender<Outcome>,
    cancel: &CancelToken,
) {
    let attempt = panic::catch_unwind(AssertUnwindSafe(|| {
        walk(roots, excludes, jobs, outcomes, cancel);
    }));
    if let Err(payload) = attempt {
        let _ = outcomes.send(Outcome::Skipped(Skipped {
            path: PathBuf::new(),
            reason: SkipReason::InternalError,
            detail: format!("directory traversal panicked: {}", panic_message(&*payload)),
        }));
    }
}

/// Enumerates the roots and queues every regular file.
fn walk(
    roots: &[PathBuf],
    excludes: &ExcludeSet,
    jobs: &Sender<PathBuf>,
    outcomes: &Sender<Outcome>,
    cancel: &CancelToken,
) {
    // A closed channel means the scan is being torn down; just stop.
    let report = |outcome: Outcome| outcomes.send(outcome).is_ok();

    for root in roots {
        let mut entries = WalkDir::new(root).follow_links(false).into_iter();
        loop {
            if cancel.is_cancelled() {
                return;
            }
            let entry = match entries.next() {
                None => break,
                Some(Ok(entry)) => entry,
                Some(Err(error)) => {
                    let reason = match error.io_error().map(io::Error::kind) {
                        Some(io::ErrorKind::PermissionDenied) => SkipReason::AccessDenied,
                        Some(io::ErrorKind::NotFound) => SkipReason::NotFound,
                        _ => SkipReason::WalkError,
                    };
                    let skipped = Skipped {
                        path: error.path().map(Path::to_path_buf).unwrap_or_default(),
                        reason,
                        detail: error.to_string(),
                    };
                    if !report(Outcome::Skipped(skipped)) {
                        return;
                    }
                    continue;
                }
            };

            let file_type = entry.file_type();
            if excludes.excludes(entry.path()) {
                if file_type.is_dir() {
                    entries.skip_current_dir();
                }
                if !report(Outcome::Excluded) {
                    return;
                }
                continue;
            }
            if file_type.is_dir() {
                continue;
            }
            if file_type.is_symlink() {
                if !report(Outcome::LinkNotFollowed) {
                    return;
                }
                continue;
            }
            if !file_type.is_file() {
                let skipped = Skipped {
                    path: entry.into_path(),
                    reason: SkipReason::SpecialFile,
                    detail: "not a regular file".to_owned(),
                };
                if !report(Outcome::Skipped(skipped)) {
                    return;
                }
                continue;
            }
            // On Windows this metadata comes for free with the directory
            // listing, so the placeholder check costs no extra system call.
            if let Some(reason) = entry
                .metadata()
                .ok()
                .as_ref()
                .and_then(file::reason_not_to_read)
            {
                let skipped = Skipped {
                    path: entry.into_path(),
                    reason,
                    detail: "content is not stored on this disk".to_owned(),
                };
                if !report(Outcome::Skipped(skipped)) {
                    return;
                }
                continue;
            }
            if jobs.send(entry.into_path()).is_err() {
                return;
            }
        }
    }
}

/// Everything the collecting thread accumulates.
struct Tally {
    stats: ScanStats,
    detections: Vec<Detection>,
    skipped: Vec<Skipped>,
    skipped_truncated: bool,
    detector_failures: Vec<DetectorFailure>,
    max_recorded: usize,
}

struct ReportContext {
    started_at: OffsetDateTime,
    duration: Duration,
    cancelled: bool,
    roots: Vec<PathBuf>,
    threads: usize,
    detectors: Vec<crate::detector::DetectorInfo>,
}

impl Tally {
    fn new(max_recorded: usize) -> Self {
        Self {
            stats: ScanStats::default(),
            detections: Vec::new(),
            skipped: Vec::new(),
            skipped_truncated: false,
            detector_failures: Vec::new(),
            max_recorded,
        }
    }

    fn record(&mut self, outcome: Outcome, observer: &mut dyn ScanObserver) {
        match outcome {
            Outcome::Scanned { path, result } => {
                self.stats.files_scanned += 1;
                self.stats.bytes_scanned += result.size;
                if result.content_scan_skipped {
                    self.stats.content_scans_skipped += 1;
                }
                for message in result.detector_errors {
                    self.stats.detector_errors += 1;
                    if self.detector_failures.len() < self.max_recorded {
                        self.detector_failures.push(DetectorFailure {
                            path: path.clone(),
                            message,
                        });
                    }
                }
                if result.verdict != Verdict::Clean {
                    self.stats.detections += 1;
                    let detection = Detection {
                        path,
                        size: result.size,
                        sha256: warden_sigdb::hex::encode(&result.sha256),
                        verdict: result.verdict,
                        findings: result.findings,
                    };
                    observer.on_detection(&detection);
                    self.detections.push(detection);
                }
            }
            Outcome::Skipped(skipped) => {
                self.stats.files_skipped += 1;
                *self
                    .stats
                    .skipped_by_reason
                    .entry(skipped.reason)
                    .or_insert(0) += 1;
                observer.on_skipped(&skipped);
                if self.skipped.len() < self.max_recorded {
                    self.skipped.push(skipped);
                } else {
                    self.skipped_truncated = true;
                }
            }
            Outcome::LinkNotFollowed => self.stats.links_not_followed += 1,
            Outcome::Excluded => self.stats.excluded += 1,
        }
    }

    fn progress(&self, elapsed: Duration) -> Progress {
        Progress {
            files_scanned: self.stats.files_scanned,
            bytes_scanned: self.stats.bytes_scanned,
            files_skipped: self.stats.files_skipped,
            detections: self.stats.detections,
            elapsed,
        }
    }

    fn into_report(mut self, context: ReportContext) -> ScanReport {
        // Workers finish in no particular order; sorting makes two scans of
        // the same tree produce the same report.
        self.detections
            .sort_by(|left, right| left.path.cmp(&right.path));
        self.skipped
            .sort_by(|left, right| left.path.cmp(&right.path));
        self.detector_failures
            .sort_by(|left, right| left.path.cmp(&right.path));

        let seconds = context.duration.as_secs_f64();
        if seconds > 0.0 {
            self.stats.files_per_second = self.stats.files_scanned as f64 / seconds;
            self.stats.megabytes_per_second =
                self.stats.bytes_scanned as f64 / 1_000_000.0 / seconds;
        }

        ScanReport {
            schema: REPORT_SCHEMA,
            engine_version: ENGINE_VERSION,
            started_at: context.started_at,
            finished_at: context.started_at + context.duration,
            duration: context.duration,
            cancelled: context.cancelled,
            roots: context.roots,
            threads: context.threads,
            detectors: context.detectors,
            stats: self.stats,
            detections: self.detections,
            skipped: self.skipped,
            skipped_truncated: self.skipped_truncated,
            detector_failures: self.detector_failures,
        }
    }
}

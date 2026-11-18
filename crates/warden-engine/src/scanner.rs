use std::any::Any;
use std::io;
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crossbeam_channel::{Receiver, RecvTimeoutError, Sender, bounded};
use time::OffsetDateTime;
use walkdir::WalkDir;

use crate::cancel::CancelToken;
use crate::detector::Detector;
use crate::error::ScanError;
use crate::file;
use crate::finding::Verdict;
use crate::observer::{Progress, ScanObserver};
use crate::options::ScanOptions;
use crate::paths::{self, ExcludeSet};
use crate::report::{Detection, PartialScan, Recorded, ScanReport, ScanStats, SkipReason, Skipped};
use crate::session::{FileResult, ScanSession};
use crate::verdict::VerdictPolicy;
use crate::{ENGINE_VERSION, REPORT_SCHEMA};

/// How often the observer hears about progress.
const PROGRESS_INTERVAL: Duration = Duration::from_millis(100);
/// Queue slots per worker. Bounded queues give back-pressure: the walker
/// cannot run far ahead of the workers and fill memory with paths.
const QUEUE_SLOTS_PER_THREAD: usize = 64;

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
        // Unpacking an archive needs its bytes just as a content detector
        // does.
        let needs_content = self.options.archives.enabled
            || self
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
    pub(crate) detectors: Vec<Arc<dyn Detector>>,
    pub(crate) policy: VerdictPolicy,
    pub(crate) options: ScanOptions,
    /// Whether files are buffered: a detector reads content, or archives
    /// are unpacked.
    pub(crate) needs_content: bool,
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

    /// Sets up one thread's working state: a session for every detector and
    /// buffers that are reused from file to file.
    ///
    /// Use this to check many buffers or files from one thread. [`scan`]
    /// does it for its own worker threads.
    ///
    /// [`scan`]: Scanner::scan
    #[must_use]
    pub fn session(&self) -> ScanSession<'_> {
        ScanSession::new(self)
    }

    /// Checks a buffer that is already in memory.
    ///
    /// This sets the detectors up for a single use. To check many buffers,
    /// keep a [`session`](Scanner::session) and call
    /// [`ScanSession::scan_bytes`] on it.
    #[must_use]
    pub fn scan_bytes(&self, bytes: &[u8]) -> FileResult {
        self.session().scan_bytes(bytes)
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
        let mut session = self.session();
        for path in jobs {
            if cancel.is_cancelled() {
                // Keep draining so the walker is never blocked on a full queue.
                continue;
            }
            // A panic in a detector must not take the scan down with it. The
            // file is reported as skipped and the worker carries on.
            let attempt = panic::catch_unwind(AssertUnwindSafe(|| session.scan_file(&path)));
            let outcome = match attempt {
                Ok(Ok(result)) => Outcome::Scanned {
                    path,
                    result: Box::new(result),
                },
                Ok(Err((reason, detail))) => Outcome::Skipped(Skipped {
                    path,
                    reason,
                    detail,
                }),
                Err(payload) => {
                    // Whatever the detectors were in the middle of is gone;
                    // start them afresh for the next file.
                    session = self.session();
                    Outcome::Skipped(Skipped {
                        path,
                        reason: SkipReason::InternalError,
                        detail: format!(
                            "checking this file panicked: {}",
                            panic_message(&*payload)
                        ),
                    })
                }
            };
            if outcomes.send(outcome).is_err() {
                return;
            }
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
    Scanned {
        path: PathBuf,
        result: Box<FileResult>,
    },
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
    recorded: Vec<Recorded>,
    recorded_truncated: bool,
    skipped: Vec<Skipped>,
    skipped_truncated: bool,
    partially_scanned: Vec<PartialScan>,
    partially_scanned_truncated: bool,
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
            recorded: Vec::new(),
            recorded_truncated: false,
            skipped: Vec::new(),
            skipped_truncated: false,
            partially_scanned: Vec::new(),
            partially_scanned_truncated: false,
            max_recorded,
        }
    }

    fn record(&mut self, outcome: Outcome, observer: &mut dyn ScanObserver) {
        match outcome {
            Outcome::Scanned { path, result } => {
                let result = *result;
                self.stats.files_scanned += 1;
                self.stats.bytes_scanned += result.size;
                self.stats.archives_unpacked += u64::from(result.unpacked);
                self.stats.archive_members_scanned += result.members_scanned;
                self.stats.archive_member_bytes += result.member_bytes;
                if !result.partial.is_empty() {
                    self.stats.files_partially_scanned += 1;
                }
                for partial in result.partial {
                    *self
                        .stats
                        .partial_by_reason
                        .entry(partial.reason)
                        .or_insert(0) += 1;
                    if self.partially_scanned.len() < self.max_recorded {
                        self.partially_scanned.push(PartialScan {
                            path: path.clone(),
                            reason: partial.reason,
                            detail: partial.detail,
                        });
                    } else {
                        self.partially_scanned_truncated = true;
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
                        findings_omitted: result.findings_omitted,
                    };
                    observer.on_detection(&detection);
                    self.detections.push(detection);
                } else if !result.findings.is_empty() {
                    self.stats.files_recorded += 1;
                    let recorded = Recorded {
                        path,
                        size: result.size,
                        sha256: warden_sigdb::hex::encode(&result.sha256),
                        findings: result.findings,
                        findings_omitted: result.findings_omitted,
                    };
                    observer.on_recorded(&recorded);
                    if self.recorded.len() < self.max_recorded {
                        self.recorded.push(recorded);
                    } else {
                        self.recorded_truncated = true;
                    }
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
        self.recorded
            .sort_by(|left, right| left.path.cmp(&right.path));
        self.skipped
            .sort_by(|left, right| left.path.cmp(&right.path));
        self.partially_scanned
            .sort_by(|left, right| (&left.path, left.reason).cmp(&(&right.path, right.reason)));

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
            recorded: self.recorded,
            recorded_truncated: self.recorded_truncated,
            skipped: self.skipped,
            skipped_truncated: self.skipped_truncated,
            partially_scanned: self.partially_scanned,
            partially_scanned_truncated: self.partially_scanned_truncated,
        }
    }
}

//! # Full-System Scanner & Scheduler
//!
//! `scan_all.rs` orchestrates machine-wide antivirus scanning on top of the
//! existing [`FileSystemScanner`] single-file / single-directory engine.
//!
//! ## Design goals
//!
//! | Goal | Mechanism |
//! |------|-----------|
//! | Don't scan forever | Skip large / low-risk files, OS system dirs, and hash-cache for clean results |
//! | Hit the riskiest spots first | Priority-path list is scanned before generic directories |
//! | Avoid redundant work across runs | Incremental mode: skip files unchanged since last scan |
//! | Use all CPU cores | Thread pool — one `FileSystemScanner` per worker thread |
//! | Automated periodic protection | `ScanScheduler` fires full scans on a configurable interval |
//!
//! ## Architecture overview
//!
//! ```text
//! ScanScheduler
//!   └── fires SystemScanner::scan() every N hours (background thread)
//!         ├── 1. collect_paths()  — walk roots, apply skip rules, sort by priority
//!         ├── 2. filter_cached()  — drop files unchanged since last scan (mtime + size)
//!         └── 3. parallel_scan() — thread pool (FileSystemScanner per thread)
//!               ├── worker-0: scan_file() → ScanResult
//!               ├── worker-1: scan_file() → ScanResult
//!               └── worker-N: scan_file() → ScanResult
//! ```

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use walkdir::WalkDir;

use crate::core::file_system::scanner::{FileSystemScanner, ScanStatistics};
use crate::core::types::{ScanResult, ThreatLevel};

// ─── Constants ────────────────────────────────────────────────────────────────

/// Files larger than this are skipped (default 256 MB).
/// Malware rarely exceeds this size; scanning multi-GB VM disks or ISOs would
/// dominate total scan time without a meaningful security benefit.
const DEFAULT_MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;

/// Default number of worker threads in the scan thread pool.
const DEFAULT_THREAD_COUNT: usize = 4;

/// Hard ceiling on worker threads (to avoid thrashing on low-core machines).
const MAX_THREADS: usize = 16;

/// Extensions excluded from scanning by default.
///
/// These formats are media/data containers that are almost never used as malware
/// vectors and can be extremely large, dominating scan time.
/// Scripts, executables, documents, and archives are intentionally NOT excluded.
const SKIP_EXTENSIONS: &[&str] = &[
    // Video
    "mp4", "mkv", "avi", "mov", "wmv", "flv", "webm", "m4v", "ts",
    // Audio
    "mp3", "wav", "flac", "aac", "ogg", "m4a", "wma",
    // Raw image / design
    "jpg", "jpeg", "png", "gif", "bmp", "tiff", "tif", "webp",
    "psd", "xcf", "ai", "indd",
    // Disk / VM images (very large, not directly executable)
    "iso", "img", "vmdk", "vhd", "vhdx", "qcow2",
];

/// Windows system paths skipped by default (trusted OS components, not writable
/// by user-space malware without elevation, and very large).
///
/// Note: `C:\Windows\System32` itself is NOT excluded — malware frequently
/// drops files or DLL-hijacks there — only the known-large package caches are.
#[cfg(windows)]
const DEFAULT_SKIP_DIRS: &[&str] = &[
    // Side-by-side component store — ~10 GB, fully trusted, read-only for users
    r"C:\Windows\WinSxS",
    // MSI installer cache — large, trusted
    r"C:\Windows\Installer",
    // Windows Update download cache
    r"C:\Windows\SoftwareDistribution\Download",
    // Recycle bin
    r"C:\$Recycle.Bin",
    // Volume shadow / restore — not accessible without elevation
    r"C:\System Volume Information",
];

#[cfg(not(windows))]
const DEFAULT_SKIP_DIRS: &[&str] = &[
    "/proc",
    "/sys",
    "/dev",
];

/// Keyword fragments in a path that bump it to the front of the scan queue.
///
/// These directories host the most common initial-infection vectors:
/// downloaded files, temporary drop zones, autorun startup folders, and
/// the roaming profile (common persistence target).
const PRIORITY_FRAGMENTS: &[&str] = &[
    "Downloads",
    "Desktop",
    "Temp",
    "tmp",
    // Startup persistence locations
    "Startup",
    "Start Menu",
    // Common malware drop zones
    "AppData\\Local\\Temp",
    "AppData\\Roaming",
    // Script and task directories
    "Tasks",
    "Scheduled Tasks",
];

// ─── Progress / threat callbacks ──────────────────────────────────────────────

/// Called during a scan with `(files_done, files_total, current_path)`.
pub type ProgressFn = Arc<dyn Fn(usize, usize, &Path) + Send + Sync>;

/// Called for every non-clean result found during a scheduled or manual scan.
pub type ThreatFn = Arc<dyn Fn(&ScanResult) + Send + Sync>;

// ─── SystemScanConfig ─────────────────────────────────────────────────────────

/// Full configuration for a system-wide scan.
///
/// # Example — quick scan of user directories only
///
/// ```rust,ignore
/// let config = SystemScanConfig {
///     roots: vec![PathBuf::from(r"C:\Users")],
///     max_file_bytes: 64 * 1024 * 1024, // 64 MB limit
///     num_threads: 2,
///     incremental: true,
///     ..SystemScanConfig::default()
/// };
/// ```
#[derive(Debug, Clone)]
pub struct SystemScanConfig {
    /// Root directories to walk. Defaults to all common Windows locations.
    pub roots: Vec<PathBuf>,

    /// Directories that are never entered during the walk.
    /// The defaults come from [`DEFAULT_SKIP_DIRS`].
    pub skip_dirs: Vec<PathBuf>,

    /// File extensions that are skipped without scanning.
    /// The defaults come from [`SKIP_EXTENSIONS`].
    pub skip_extensions: Vec<String>,

    /// Files larger than this (in bytes) are skipped.
    pub max_file_bytes: u64,

    /// Number of worker threads. Clamped to `[1, MAX_THREADS]`.
    pub num_threads: usize,

    /// When `true`, skip files whose `(mtime, size)` pair matches a previous
    /// clean result stored in the in-memory [`FileStateCache`].
    pub incremental: bool,

    /// Optional directory containing custom `.yar` / `.yara` rules.
    /// Each worker thread loads the same directory independently.
    pub yara_rules_dir: Option<PathBuf>,
}

impl Default for SystemScanConfig {
    fn default() -> Self {
        Self {
            roots: SystemScanner::default_roots(),
            skip_dirs: DEFAULT_SKIP_DIRS
                .iter()
                .map(|s| PathBuf::from(s))
                .collect(),
            skip_extensions: SKIP_EXTENSIONS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            num_threads: DEFAULT_THREAD_COUNT,
            incremental: true,
            yara_rules_dir: None,
        }
    }
}

impl SystemScanConfig {
    /// Returns `true` if `path` should be skipped (extension or size filters).
    fn should_skip_file(&self, path: &Path, size: u64) -> bool {
        if size > self.max_file_bytes {
            return true;
        }
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            let lower = ext.to_lowercase();
            return self.skip_extensions.iter().any(|e| e == &lower);
        }
        false
    }

    /// Returns `true` if `dir` matches any entry in the skip list
    /// (exact prefix match, case-insensitive on Windows).
    fn should_skip_dir(&self, dir: &Path) -> bool {
        let dir_str = dir.to_string_lossy().to_lowercase();
        self.skip_dirs.iter().any(|skip| {
            let skip_str = skip.to_string_lossy().to_lowercase();
            dir_str.starts_with(&*skip_str)
        })
    }

    /// Returns `true` if `path` contains any priority fragment.
    fn is_priority(&self, path: &Path) -> bool {
        let s = path.to_string_lossy();
        PRIORITY_FRAGMENTS.iter().any(|frag| {
            s.contains(frag)
        })
    }
}

// ─── ScanAllResult ────────────────────────────────────────────────────────────

/// Result of a full system scan.
#[derive(Debug)]
pub struct ScanAllResult {
    /// All individual file scan results (clean + non-clean).
    pub results: Vec<ScanResult>,
    /// Aggregate statistics for this run.
    pub stats: ScanStatistics,
    /// Wall-clock duration of the scan in seconds.
    pub duration_secs: f64,
    /// Number of files skipped (size / extension filter or skip-dir).
    pub skipped_files: usize,
    /// Number of files served from the incremental cache (no re-scan needed).
    pub cached_hits: usize,
    /// When this scan was started.
    pub scan_time: SystemTime,
}

impl ScanAllResult {
    /// Convenience: only non-clean results.
    pub fn threats(&self) -> impl Iterator<Item = &ScanResult> {
        self.results.iter().filter(|r| r.level != ThreatLevel::Clean)
    }

    /// `true` if any malicious file was found.
    pub fn has_malicious(&self) -> bool {
        self.results.iter().any(|r| r.level == ThreatLevel::Malicious)
    }
}

// ─── FileStateCache ───────────────────────────────────────────────────────────

/// Per-file scan state, stored in the incremental cache.
#[derive(Debug, Clone)]
struct CachedFileState {
    /// File modification time as seconds since the Unix epoch.
    mtime_secs: u64,
    /// File size in bytes at the time of the last scan.
    file_size: u64,
    /// Verdict from the last scan.
    level: ThreatLevel,
}

/// In-memory cache mapping `PathBuf → CachedFileState`.
///
/// When incremental mode is on, a file is re-scanned only when either its
/// modification time or its size has changed since the last scan.
///
/// Non-clean entries are never cached — they are always re-evaluated so that
/// remediated files are promptly reclassified.
pub struct FileStateCache {
    inner: HashMap<PathBuf, CachedFileState>,
}

impl FileStateCache {
    pub fn new() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }

    /// Returns the cached `ThreatLevel` for `path` if the file is unchanged,
    /// or `None` if the file must be re-scanned.
    fn check(&self, path: &Path, mtime_secs: u64, file_size: u64) -> Option<ThreatLevel> {
        let state = self.inner.get(path)?;
        if state.mtime_secs == mtime_secs && state.file_size == file_size {
            Some(state.level.clone())
        } else {
            None
        }
    }

    /// Inserts or updates the cached state for `path`.
    /// Only `Clean` results are stored; non-clean results must always be
    /// re-scanned so they are never served stale from the cache.
    fn update(&mut self, path: PathBuf, mtime_secs: u64, file_size: u64, level: ThreatLevel) {
        if level == ThreatLevel::Clean {
            self.inner.insert(path, CachedFileState { mtime_secs, file_size, level });
        } else {
            // Remove any stale clean entry for a path that is now a threat.
            self.inner.remove(&path);
        }
    }

    /// Drops all entries — call before a non-incremental full scan to ensure a
    /// completely fresh pass.
    pub fn clear(&mut self) {
        self.inner.clear();
    }

    /// Number of cached entries.
    pub fn len(&self) -> usize {
        self.inner.len()
    }
}

impl Default for FileStateCache {
    fn default() -> Self { Self::new() }
}

// ─── SystemScanner ────────────────────────────────────────────────────────────

/// Orchestrates a full-system scan over configurable root directories.
///
/// Internally it:
/// 1. Walks the filesystem and applies skip / priority rules.
/// 2. Checks each file against the incremental cache.
/// 3. Dispatches remaining paths to a thread pool for parallel scanning.
///
/// # Thread safety
///
/// `SystemScanner` is `Send + Sync` and can be wrapped in an `Arc` for
/// shared use between a [`ScanScheduler`] background thread and the main thread.
pub struct SystemScanner {
    config: SystemScanConfig,
    /// Shared incremental cache — updated after every scan.
    cache: Arc<Mutex<FileStateCache>>,
}

impl SystemScanner {
    /// Creates a new scanner with default configuration.
    pub fn new() -> Self {
        Self {
            config: SystemScanConfig::default(),
            cache: Arc::new(Mutex::new(FileStateCache::new())),
        }
    }

    /// Creates a scanner with a custom configuration.
    pub fn with_config(config: SystemScanConfig) -> Self {
        Self {
            config,
            cache: Arc::new(Mutex::new(FileStateCache::new())),
        }
    }

    /// Clears the incremental cache, forcing a full re-scan next time.
    pub fn clear_cache(&self) {
        self.cache.lock().unwrap().clear();
    }

    // ── Root discovery ────────────────────────────────────────────────────────

    /// Returns a default set of scan roots for the current platform.
    ///
    /// On Windows this covers:
    /// - All user home directories
    /// - Program Files
    /// - ProgramData
    /// - The Windows directory (excluding the large package-cache skip-dirs)
    /// - Common temp directories
    pub fn default_roots() -> Vec<PathBuf> {
        let mut roots: Vec<PathBuf> = Vec::new();

        #[cfg(windows)]
        {
            // Users directory (covers all profiles)
            if let Ok(users) = std::env::var("SystemDrive") {
                let p = PathBuf::from(format!("{}\\Users", users));
                if p.exists() { roots.push(p); }
                // Windows directory (threats often land in System32, Temp, etc.)
                let win = PathBuf::from(format!("{}\\Windows", users));
                if win.exists() { roots.push(win); }
            }

            // Program files
            for var in &["ProgramFiles", "ProgramFiles(x86)", "ProgramData"] {
                if let Ok(p) = std::env::var(var) {
                    let pb = PathBuf::from(p);
                    if pb.exists() { roots.push(pb); }
                }
            }

            // System temp
            if let Ok(tmp) = std::env::var("TEMP") {
                let pb = PathBuf::from(tmp);
                if pb.exists() { roots.push(pb); }
            }
        }

        #[cfg(not(windows))]
        {
            for p in &["/home", "/usr/local/bin", "/tmp", "/var/tmp", "/opt"] {
                let pb = PathBuf::from(p);
                if pb.exists() { roots.push(pb); }
            }
        }

        roots
    }

    // ── Path collection ───────────────────────────────────────────────────────

    /// Walks all configured roots and builds two sorted path lists:
    /// - `priority_paths` — files under [`PRIORITY_FRAGMENTS`] directories
    /// - `normal_paths`   — all other eligible files
    ///
    /// Returns `(priority_paths, normal_paths, skipped_count)`.
    fn collect_paths(&self) -> (Vec<(PathBuf, u64)>, Vec<(PathBuf, u64)>, usize) {
        let mut priority: Vec<(PathBuf, u64)> = Vec::new();
        let mut normal: Vec<(PathBuf, u64)> = Vec::new();
        let mut skipped = 0usize;

        for root in &self.config.roots {
            if !root.exists() { continue; }

            for entry in WalkDir::new(root)
                .follow_links(false)
                .into_iter()
                .filter_entry(|e| {
                    // Prune entire skip-dirs early (avoids descending into them)
                    if e.file_type().is_dir() {
                        !self.config.should_skip_dir(e.path())
                    } else {
                        true
                    }
                })
            {
                let entry = match entry {
                    Ok(e) => e,
                    Err(_) => { skipped += 1; continue; }
                };

                if !entry.file_type().is_file() { continue; }

                let path = entry.path().to_path_buf();
                let size = entry.metadata().map(|m| m.len()).unwrap_or(0);

                if self.config.should_skip_file(&path, size) {
                    skipped += 1;
                    continue;
                }

                if self.config.is_priority(&path) {
                    priority.push((path, size));
                } else {
                    normal.push((path, size));
                }
            }
        }

        (priority, normal, skipped)
    }

    // ── Incremental cache filtering ───────────────────────────────────────────

    /// Removes from `paths` any entry whose `(mtime, size)` matches the cache,
    /// inserting a synthetic clean `ScanResult` for each cache hit.
    ///
    /// Returns `(paths_to_scan, cache_hit_results, cache_hit_count)`.
    fn filter_cached(
        &self,
        paths: Vec<(PathBuf, u64)>,
        cache: &FileStateCache,
    ) -> (Vec<(PathBuf, u64)>, Vec<ScanResult>, usize) {
        let mut to_scan: Vec<(PathBuf, u64)> = Vec::new();
        let mut from_cache: Vec<ScanResult> = Vec::new();
        let mut hits = 0usize;

        for (path, size) in paths {
            // Obtain mtime as seconds since epoch (fails gracefully)
            let mtime_secs = std::fs::metadata(&path)
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);

            if let Some(cached_level) = cache.check(&path, mtime_secs, size) {
                hits += 1;
                // Synthesise a lightweight result for the cache hit
                from_cache.push(ScanResult::clean(path, None));
                let _ = cached_level; // already Clean by construction (we only cache Clean)
            } else {
                to_scan.push((path, size));
            }
        }

        (to_scan, from_cache, hits)
    }

    // ── Parallel scan engine ──────────────────────────────────────────────────

    /// Distributes `paths` across a thread pool and collects `ScanResult`s.
    ///
    /// Each worker thread owns its own [`FileSystemScanner`] instance to avoid
    /// any synchronisation overhead on the scanner state itself.
    /// If `progress` is provided, it is called after every completed file.
    fn parallel_scan(
        &self,
        paths: Vec<(PathBuf, u64)>,
        progress: Option<ProgressFn>,
    ) -> Vec<ScanResult> {
        if paths.is_empty() { return Vec::new(); }

        let total = paths.len();
        let num_threads = self.config.num_threads.clamp(1, MAX_THREADS);
        let yara_dir = self.config.yara_rules_dir.clone();

        // ── Work channel: main thread → workers ───────────────────────────────
        let (work_tx, work_rx) = mpsc::channel::<PathBuf>();
        let work_rx = Arc::new(Mutex::new(work_rx));

        // ── Result channel: workers → collector ───────────────────────────────
        let (result_tx, result_rx) = mpsc::channel::<ScanResult>();

        // ── Spawn worker threads ───────────────────────────────────────────────
        let handles: Vec<_> = (0..num_threads)
            .map(|_| {
                let rx = Arc::clone(&work_rx);
                let tx = result_tx.clone();
                let yara = yara_dir.clone();

                thread::spawn(move || {
                    // Each thread builds its own scanner — no shared mutable state.
                    let mut scanner = FileSystemScanner::new();
                    if let Some(ref dir) = yara {
                        scanner.load_yara_rules(dir).ok();
                    }

                    loop {
                        let path = {
                            // Hold the lock only for the recv() call.
                            match rx.lock().unwrap().recv() {
                                Ok(p) => p,
                                Err(_) => break, // channel closed, no more work
                            }
                        };

                        match scanner.scan_file(&path) {
                            Ok(result) => { tx.send(result).ok(); }
                            Err(e) => {
                                // Send an error result so the total count stays consistent.
                                tx.send(ScanResult::error(path, e.to_string())).ok();
                            }
                        }
                    }
                })
            })
            .collect();

        // Drop the extra sender so result_rx drains when all workers finish.
        drop(result_tx);

        // ── Feed paths to workers ──────────────────────────────────────────────
        for (path, _size) in paths {
            work_tx.send(path).ok();
        }
        drop(work_tx); // signal workers: no more work coming

        // ── Collect results with optional progress reporting ───────────────────
        let mut results: Vec<ScanResult> = Vec::with_capacity(total);
        for result in result_rx {
            if let Some(ref cb) = progress {
                cb(results.len() + 1, total, &result.path);
            }
            results.push(result);
        }

        // Wait for all threads to exit cleanly.
        for h in handles { h.join().ok(); }

        results
    }

    // ── Public scan entry point ───────────────────────────────────────────────

    /// Run a full system scan and return aggregated results.
    ///
    /// **Steps:**
    /// 1. Walk all roots → collect eligible paths (skipping large/media files and OS dirs).
    /// 2. Sort: priority paths first.
    /// 3. If `incremental` is enabled, check each path against the cache.
    /// 4. Dispatch uncached paths to the thread pool.
    /// 5. Merge cache-hit results + freshly scanned results.
    /// 6. Update the incremental cache with new verdicts.
    ///
    /// # Arguments
    ///
    /// * `progress` — optional callback `(done, total, current_path)`.
    pub fn scan(&self, progress: Option<ProgressFn>) -> ScanAllResult {
        let scan_time = SystemTime::now();
        let timer = Instant::now();

        // ── Step 1: collect paths ──────────────────────────────────────────────
        let (mut priority_paths, normal_paths, mut skipped_files) =
            self.collect_paths();

        // Priority paths are scanned first; normal paths follow.
        priority_paths.extend(normal_paths);
        let all_paths = priority_paths;

        // ── Step 2: incremental cache filter ──────────────────────────────────
        let (paths_to_scan, mut results, cached_hits) = if self.config.incremental {
            let cache = self.cache.lock().unwrap();
            self.filter_cached(all_paths, &cache)
        } else {
            (all_paths, Vec::new(), 0)
        };

        skipped_files += cached_hits;

        // ── Step 3: parallel scan ─────────────────────────────────────────────
        let fresh_results = self.parallel_scan(paths_to_scan, progress);

        // ── Step 4: update incremental cache ──────────────────────────────────
        {
            let mut cache = self.cache.lock().unwrap();
            for r in &fresh_results {
                let size = std::fs::metadata(&r.path).map(|m| m.len()).unwrap_or(0);
                let mtime_secs = std::fs::metadata(&r.path)
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                cache.update(r.path.clone(), mtime_secs, size, r.level.clone());
            }
        }

        results.extend(fresh_results);

        // ── Step 5: aggregate statistics ─────────────────────────────────────
        let mut stats = ScanStatistics::new();
        for r in &results {
            let size = std::fs::metadata(&r.path).map(|m| m.len()).unwrap_or(0);
            stats.update(r, size);
        }

        ScanAllResult {
            results,
            stats,
            duration_secs: timer.elapsed().as_secs_f64(),
            skipped_files,
            cached_hits,
            scan_time,
        }
    }
}

impl Default for SystemScanner {
    fn default() -> Self { Self::new() }
}

// ─── ScanScheduler ────────────────────────────────────────────────────────────

/// Runs [`SystemScanner::scan`] automatically on a configurable interval.
///
/// The scheduler spawns a single background thread that wakes up every minute
/// to check whether the configured interval has elapsed.  This avoids blocking
/// the main thread and allows the interval to be changed without restarting.
///
/// # Example — hourly background scan
///
/// ```rust,ignore
/// let scheduler = ScanScheduler::builder()
///     .interval(Duration::from_secs(3600))
///     .on_threat(|result| {
///         eprintln!("[THREAT] {} — {:?}", result.path.display(), result.level);
///     })
///     .build();
///
/// scheduler.start();
/// // ... application runs ...
/// scheduler.stop(); // waits for current scan to finish
/// ```
pub struct ScanScheduler {
    scanner: Arc<SystemScanner>,
    /// How often a full scan is triggered.
    interval: Duration,
    /// Shared: last time a scan completed successfully.
    last_scan: Arc<Mutex<Option<SystemTime>>>,
    /// Shared flag — set to `false` to stop the background thread.
    running: Arc<Mutex<bool>>,
    /// Handle to the background thread (held so we can join on `stop()`).
    thread_handle: Mutex<Option<thread::JoinHandle<()>>>,
    /// Called for every non-clean result discovered during scheduled scans.
    on_threat: ThreatFn,
}

impl ScanScheduler {
    // ── Construction ──────────────────────────────────────────────────────────

    /// Creates a scheduler with default configuration.
    ///
    /// Default interval: **6 hours**.
    /// Default threat handler: logs to stderr.
    pub fn new(scanner: SystemScanner) -> Self {
        Self::with_options(
            Arc::new(scanner),
            Duration::from_secs(6 * 3600),
            Arc::new(|r: &ScanResult| {
                eprintln!(
                    "[AegisAI THREAT] {:?} — {}",
                    r.level, r.path.display()
                );
            }),
        )
    }

    fn with_options(
        scanner: Arc<SystemScanner>,
        interval: Duration,
        on_threat: ThreatFn,
    ) -> Self {
        Self {
            scanner,
            interval,
            last_scan: Arc::new(Mutex::new(None)),
            running: Arc::new(Mutex::new(false)),
            thread_handle: Mutex::new(None),
            on_threat,
        }
    }

    /// Returns a [`SchedulerBuilder`] for fluent configuration.
    pub fn builder() -> SchedulerBuilder {
        SchedulerBuilder::default()
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    /// Starts the background scan loop.
    ///
    /// If the scheduler is already running this is a no-op.
    pub fn start(&self) {
        let mut handle = self.thread_handle.lock().unwrap();
        if handle.is_some() { return; } // already started

        *self.running.lock().unwrap() = true;

        let scanner  = Arc::clone(&self.scanner);
        let interval = self.interval;
        let last_scan = Arc::clone(&self.last_scan);
        let running  = Arc::clone(&self.running);
        let on_threat = Arc::clone(&self.on_threat);

        *handle = Some(thread::spawn(move || {
            // The thread wakes every 60 seconds to check if a scan is due.
            // This gives the scheduler sub-minute responsiveness to interval
            // changes without burning CPU in a tight loop.
            let tick = Duration::from_secs(60);

            loop {
                // Check the stop flag first.
                if !*running.lock().unwrap() { break; }

                let now = SystemTime::now();
                let should_fire = {
                    let last = last_scan.lock().unwrap();
                    match *last {
                        None => true, // first run
                        Some(t) => now.duration_since(t).unwrap_or_default() >= interval,
                    }
                };

                if should_fire {
                    eprintln!("[ScanScheduler] Starting scheduled full-system scan…");
                    let result = scanner.scan(None);

                    // Report all non-clean findings via the callback.
                    for r in result.threats() {
                        on_threat(r);
                    }

                    eprintln!(
                        "[ScanScheduler] Scan complete in {:.1}s — \
                         {} file(s) scanned, {} threat(s) found, {} cached.",
                        result.duration_secs,
                        result.stats.total_files,
                        result.stats.suspicious_files + result.stats.malicious_files,
                        result.cached_hits,
                    );

                    *last_scan.lock().unwrap() = Some(SystemTime::now());
                }

                // Sleep in small increments so we can react to a stop() call
                // without waiting a full tick.
                let mut slept = Duration::ZERO;
                while slept < tick {
                    thread::sleep(Duration::from_secs(5));
                    slept += Duration::from_secs(5);
                    if !*running.lock().unwrap() { return; }
                }
            }
        }));
    }

    /// Signals the background thread to stop and waits for it to exit.
    ///
    /// If a scan is in progress, this blocks until the scan finishes.
    pub fn stop(&self) {
        *self.running.lock().unwrap() = false;
        if let Some(h) = self.thread_handle.lock().unwrap().take() {
            h.join().ok();
        }
    }

    /// Returns `true` if the background loop is currently running.
    pub fn is_running(&self) -> bool {
        *self.running.lock().unwrap()
    }

    /// Returns the timestamp of the last completed scheduled scan, if any.
    pub fn last_scan_time(&self) -> Option<SystemTime> {
        *self.last_scan.lock().unwrap()
    }

    /// Immediately triggers a scan from the calling thread (blocking).
    ///
    /// Useful for "Scan Now" buttons in a UI — runs outside the scheduler loop
    /// so it does not reset the scheduler's timing.
    pub fn trigger_now(&self, progress: Option<ProgressFn>) -> ScanAllResult {
        self.scanner.scan(progress)
    }

    /// Returns a reference to the underlying [`SystemScanner`].
    pub fn scanner(&self) -> &SystemScanner {
        &self.scanner
    }
}

impl Drop for ScanScheduler {
    /// Automatically stops the background thread when the scheduler is dropped.
    fn drop(&mut self) {
        self.stop();
    }
}

// ─── SchedulerBuilder ─────────────────────────────────────────────────────────

/// Fluent builder for [`ScanScheduler`].
///
/// # Example
///
/// ```rust,ignore
/// let scheduler = ScanScheduler::builder()
///     .scanner(SystemScanner::with_config(config))
///     .interval(Duration::from_secs(3600))
///     .on_threat(|r| println!("Threat: {}", r.path.display()))
///     .build();
/// ```
pub struct SchedulerBuilder {
    scanner:  Option<SystemScanner>,
    interval: Duration,
    on_threat: Option<ThreatFn>,
}

impl Default for SchedulerBuilder {
    fn default() -> Self {
        Self {
            scanner:  None,
            interval: Duration::from_secs(6 * 3600),
            on_threat: None,
        }
    }
}

impl SchedulerBuilder {
    /// Sets the scanner instance (required).
    pub fn scanner(mut self, s: SystemScanner) -> Self {
        self.scanner = Some(s);
        self
    }

    /// Sets the scan interval.
    pub fn interval(mut self, d: Duration) -> Self {
        self.interval = d;
        self
    }

    /// Sets the callback invoked for every non-clean result.
    pub fn on_threat<F>(mut self, f: F) -> Self
    where
        F: Fn(&ScanResult) + Send + Sync + 'static,
    {
        self.on_threat = Some(Arc::new(f));
        self
    }

    /// Builds the [`ScanScheduler`].
    ///
    /// # Panics
    ///
    /// Panics if `scanner()` was not called.
    pub fn build(self) -> ScanScheduler {
        let scanner = self.scanner.expect("ScanScheduler requires a SystemScanner");
        let on_threat = self.on_threat.unwrap_or_else(|| {
            Arc::new(|r: &ScanResult| {
                eprintln!("[AegisAI THREAT] {:?} — {}", r.level, r.path.display());
            })
        });
        ScanScheduler::with_options(Arc::new(scanner), self.interval, on_threat)
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Basic smoke test: scan a temp directory we control.
    #[test]
    fn test_scan_temp_dir() {
        let dir = std::env::temp_dir().join("aegis_scan_all_test");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("clean.txt"), "hello world").unwrap();

        let config = SystemScanConfig {
            roots: vec![dir.clone()],
            ..SystemScanConfig::default()
        };
        let scanner = SystemScanner::with_config(config);
        let result = scanner.scan(None);

        assert!(result.stats.total_files >= 1, "should have scanned at least one file");
        assert_eq!(result.stats.malicious_files, 0, "clean txt should not be malicious");

        fs::remove_dir_all(&dir).ok();
    }

    /// Verify that EICAR planted in a temp dir is detected.
    #[test]
    fn test_scan_detects_eicar() {
        let dir = std::env::temp_dir().join("aegis_eicar_all_test");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("eicar.com"),
            "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
        )
        .unwrap();

        let config = SystemScanConfig {
            roots: vec![dir.clone()],
            incremental: false,
            ..SystemScanConfig::default()
        };
        let scanner = SystemScanner::with_config(config);
        let result = scanner.scan(None);

        assert!(result.has_malicious(), "EICAR should be detected as malicious");

        fs::remove_dir_all(&dir).ok();
    }

    /// Verify that media files are skipped.
    #[test]
    fn test_skip_media_files() {
        let dir = std::env::temp_dir().join("aegis_skip_test");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("movie.mp4"), vec![0u8; 1024]).unwrap();
        fs::write(dir.join("song.mp3"), vec![0u8; 512]).unwrap();

        let config = SystemScanConfig {
            roots: vec![dir.clone()],
            ..SystemScanConfig::default()
        };
        let scanner = SystemScanner::with_config(config);
        let result = scanner.scan(None);

        // Both files should be skipped, not scanned.
        assert_eq!(result.stats.total_files, 0, "media files should be skipped");
        assert!(result.skipped_files >= 2);

        fs::remove_dir_all(&dir).ok();
    }

    /// Verify that large files beyond the size limit are skipped.
    #[test]
    fn test_skip_large_files() {
        let dir = std::env::temp_dir().join("aegis_large_test");
        fs::create_dir_all(&dir).unwrap();
        let large_file = dir.join("bigfile.bin");
        // Write 5 bytes — but configure the limit to 0 bytes so it counts as "large"
        fs::write(&large_file, b"hello").unwrap();

        let config = SystemScanConfig {
            roots: vec![dir.clone()],
            max_file_bytes: 0, // everything is "too large"
            ..SystemScanConfig::default()
        };
        let scanner = SystemScanner::with_config(config);
        let result = scanner.scan(None);

        assert_eq!(result.stats.total_files, 0, "file over size limit should be skipped");

        fs::remove_dir_all(&dir).ok();
    }

    /// Verify that the incremental cache skips unchanged clean files on re-scan.
    #[test]
    fn test_incremental_cache() {
        let dir = std::env::temp_dir().join("aegis_cache_test");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("note.txt"), "harmless content").unwrap();

        let config = SystemScanConfig {
            roots: vec![dir.clone()],
            incremental: true,
            num_threads: 1,
            ..SystemScanConfig::default()
        };
        let scanner = SystemScanner::with_config(config);

        // First scan — no cache hits.
        let r1 = scanner.scan(None);
        assert_eq!(r1.cached_hits, 0, "first scan should have no cache hits");

        // Second scan — unchanged file should be served from cache.
        let r2 = scanner.scan(None);
        assert!(r2.cached_hits >= 1, "unchanged clean file should be a cache hit");

        fs::remove_dir_all(&dir).ok();
    }

    /// Smoke-test the scheduler builder and immediate trigger.
    #[test]
    fn test_scheduler_trigger_now() {
        let dir = std::env::temp_dir().join("aegis_sched_test");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("file.txt"), "content").unwrap();

        let config = SystemScanConfig {
            roots: vec![dir.clone()],
            ..SystemScanConfig::default()
        };

        let scheduler = ScanScheduler::builder()
            .scanner(SystemScanner::with_config(config))
            .interval(Duration::from_secs(999_999))
            .build();

        let result = scheduler.trigger_now(None);
        assert!(result.duration_secs >= 0.0);

        std::fs::remove_dir_all(&dir).ok();
    }
}

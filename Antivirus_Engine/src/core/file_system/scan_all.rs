//! # Full-System Scanner, Prioritizer & Scheduler
//!
//! `scan_all.rs` orchestrates machine-wide antivirus scanning on top of the
//! existing [`FileSystemScanner`] single-file / single-directory engine.
//!
//! ## Design goals
//!
//! | Goal | Mechanism |
//! |------|-----------|
//! | Don't scan forever | Skip large / low-risk files, OS system dirs, and hash-cache for clean results |
//! | Hit the riskiest spots first | [`ScanPrioritizer`] scores every file on 4 axes and sorts before scanning |
//! | Avoid redundant work across runs | Incremental mode: skip files unchanged since last scan |
//! | Use all CPU cores | Thread pool — one `FileSystemScanner` per worker thread |
//! | Automated periodic protection | `ScanScheduler` fires full scans on a configurable interval |
//!
//! ## Architecture overview
//!
//! ```text
//! ScanScheduler
//!   └── fires SystemScanner::scan() every N hours (background thread)
//!         ├── 1. collect_paths()  — walk roots, apply skip rules → (path, size, mtime)[]
//!         ├── 2. ScanPrioritizer  — score each file on 4 axes, stable-sort highest first
//!         ├── 3. filter_cached()  — drop files unchanged since last scan (mtime + size)
//!         └── 4. parallel_scan() — thread pool (FileSystemScanner per thread)
//!               ├── worker-0: scan_file() → ScanResult
//!               ├── worker-1: scan_file() → ScanResult
//!               └── worker-N: scan_file() → ScanResult
//! ```
//!
//! ## Three components
//!
//! | Component | Role |
//! |-----------|------|
//! | [`SystemScanner`] | Walk filesystem, drive cache + thread pool |
//! | [`ScanPrioritizer`] | Score & sort candidate files before they enter the queue |
//! | [`ScanScheduler`] | Fire [`SystemScanner::scan`] automatically on a configurable interval |

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
const DEFAULT_MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;

/// Default number of worker threads in the scan thread pool.
const DEFAULT_THREAD_COUNT: usize = 4;

/// Hard ceiling on worker threads (to avoid thrashing on low-core machines).
const MAX_THREADS: usize = 16;

/// Extensions excluded from scanning by default.
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

/// Windows system paths skipped by default.
#[cfg(windows)]
const DEFAULT_SKIP_DIRS: &[&str] = &[
    r"C:\Windows\WinSxS",
    r"C:\Windows\Installer",
    r"C:\Windows\SoftwareDistribution\Download",
    r"C:\$Recycle.Bin",
    r"C:\System Volume Information",
];

#[cfg(not(windows))]
const DEFAULT_SKIP_DIRS: &[&str] = &[
    "/proc",
    "/sys",
    "/dev",
];

/// Keyword fragments that bump a path to the front of the priority split
/// (before [`ScanPrioritizer`] applies fine-grained scoring within each group).
const PRIORITY_FRAGMENTS: &[&str] = &[
    "Downloads",
    "Desktop",
    "Temp",
    "tmp",
    "Startup",
    "Start Menu",
    "AppData\\Local\\Temp",
    "AppData\\Roaming",
    "Tasks",
    "Scheduled Tasks",
];

// ─── ScanPrioritizer constants ────────────────────────────────────────────────

/// Path fragments that indicate a high-infection-risk location (score 30).
const HIGH_RISK_LOCATIONS: &[&str] = &[
    "AppData\\Local\\Temp",
    "AppData\\Roaming",
    "Downloads",
    "Desktop",
    "Temp",
    "tmp",
    "Startup",
    "Start Menu",
    "Tasks",
    "Scheduled Tasks",
    "ProgramData",
];

/// Path fragments that indicate a medium-infection-risk location (score 15).
const MEDIUM_RISK_LOCATIONS: &[&str] = &[
    "System32",
    "SysWOW64",
    "drivers",
    "Program Files",
    "Program Files (x86)",
];

/// File-stem substrings frequently found in malware samples.
/// Case-insensitive substring match is used.
const SUSPICIOUS_STEMS: &[&str] = &[
    "payload", "dropper", "loader", "inject", "exploit", "shellcode",
    "ransomware", "cryptor", "locker", "wiper", "stealer", "keylogger",
    "backdoor", "rootkit", "trojan", "meterpreter", "mimikatz",
    "beacon", "empire", "havoc", "sliver", "cobalt",
    "brute", "crack", "rat", "c2", "cnc", "bot",
];

// ─── ScanPrioritizer ──────────────────────────────────────────────────────────

/// Decides the order in which candidate files are fed to the scan thread pool.
///
/// Each file receives a **priority score in `0..=100`**; files with higher
/// scores are scanned earlier.  The scorer is completely read-only — it uses
/// only the path string, file size, and precomputed mtime from
/// [`SystemScanner::collect_paths`]; it never opens files or modifies state.
///
/// ## Scoring breakdown
///
/// | Factor              | Max pts | Signal                                         |
/// |---------------------|---------|------------------------------------------------|
/// | Extension risk tier | 40      | Executables → scripts → archives → documents  |
/// | Location risk tier  | 30      | Temp/Downloads > AppData > System32 > other    |
/// | Recency             | 20      | Last hour scores highest; >30 days scores 0    |
/// | Filename anomaly    | 10      | Double-ext, suspicious stem, high-entropy name |
///
/// ## Integration
///
/// `SystemScanner` holds a `ScanPrioritizer` and calls [`ScanPrioritizer::sort`]
/// after path collection and before dispatching work to threads.
///
/// The sort is **stable** so that equal-score files preserve the relative order
/// from `collect_paths` (priority-location files remain ahead of normal files).
pub struct ScanPrioritizer;

impl ScanPrioritizer {
    pub fn new() -> Self { Self }

    /// Computes the priority score for a single file.
    ///
    /// * `path`       — absolute path to the file
    /// * `size`       — file size in bytes
    /// * `mtime_secs` — modification time as Unix seconds
    /// * `now_secs`   — current time as Unix seconds (capture once per batch)
    pub fn score(&self, path: &Path, _size: u64, mtime_secs: u64, now_secs: u64) -> u32 {
        let ext_score  = self.score_extension(path);
        let loc_score  = self.score_location(path);
        let age_score  = self.score_recency(mtime_secs, now_secs);
        let name_score = self.score_filename(path);
        ext_score + loc_score + age_score + name_score
    }

    /// Sorts `paths` in-place, highest-scoring files first.
    ///
    /// Stable sort: equal-score files preserve the order already set by
    /// `collect_paths` (priority-location bucket is at the front of the slice).
    pub fn sort(&self, paths: &mut Vec<(PathBuf, u64, u64)>, now_secs: u64) {
        paths.sort_by(|(pa, sa, ma), (pb, sb, mb)| {
            let sa = self.score(pa, *sa, *ma, now_secs);
            let sb = self.score(pb, *sb, *mb, now_secs);
            sb.cmp(&sa) // descending
        });
    }

    // ── Factor: extension risk tier (0–40) ────────────────────────────────────

    fn score_extension(&self, path: &Path) -> u32 {
        let ext = match path.extension().and_then(|e| e.to_str()) {
            Some(e) => e.to_lowercase(),
            None    => return 5, // no extension — low but non-zero default
        };
        match ext.as_str() {
            // Tier 1 — native executables / drivers
            "exe" | "dll" | "sys" | "drv" | "ocx" | "scr" | "cpl" | "com" => 40,

            // Tier 2 — scripts, macro-enabled docs, launchers
            "ps1" | "psm1" | "psd1"                            // PowerShell
            | "bat" | "cmd"                                     // Windows batch
            | "vbs" | "vbe"                                     // VBScript
            | "js"  | "jse"                                     // JScript
            | "hta" | "wsf" | "wsh"                            // Windows scripting
            | "msi" | "msp" | "mst"                            // Windows Installer
            | "reg"                                             // Registry import
            | "xlsm" | "docm" | "pptm" | "xltm" | "dotm"     // Office macros
            | "lnk" | "url" => 30,                             // Shortcuts / launchers

            // Tier 3 — archives (may contain executables)
            "zip" | "7z" | "rar" | "tar" | "gz" | "bz2" | "xz" | "cab" | "arj" => 15,

            // Tier 4 — documents (can carry exploits)
            "pdf" | "doc" | "xls" | "ppt" | "rtf" | "odt" | "ods" | "odp" => 10,

            _ => 5,
        }
    }

    // ── Factor: location risk tier (0–30) ─────────────────────────────────────

    fn score_location(&self, path: &Path) -> u32 {
        let s = path.to_string_lossy();
        for frag in HIGH_RISK_LOCATIONS {
            if s.contains(frag) { return 30; }
        }
        for frag in MEDIUM_RISK_LOCATIONS {
            if s.contains(frag) { return 15; }
        }
        0
    }

    // ── Factor: recency (0–20) ────────────────────────────────────────────────

    fn score_recency(&self, mtime_secs: u64, now_secs: u64) -> u32 {
        let age = now_secs.saturating_sub(mtime_secs);
        match age {
            0..=3_599            => 20, // < 1 hour
            3_600..=86_399       => 15, // 1 h – 24 h
            86_400..=604_799     => 10, // 1 day – 7 days
            604_800..=2_591_999  => 5,  // 1 week – 30 days
            _                    => 0,  // older
        }
    }

    // ── Factor: filename anomalies (0–10) ─────────────────────────────────────

    fn score_filename(&self, path: &Path) -> u32 {
        let mut pts = 0u32;

        let stem = match path.file_stem().and_then(|s| s.to_str()) {
            Some(s) => s.to_lowercase(),
            None    => return 0,
        };

        // Double extension: "document.pdf.exe" — the stem itself still has an extension.
        if Path::new(&stem).extension().is_some() {
            pts = pts.max(10);
        }

        // Suspicious keyword in the stem.
        if SUSPICIOUS_STEMS.iter().any(|kw| stem.contains(kw)) {
            pts = pts.max(8);
        }

        // High-entropy stem (≥8 chars) — random-looking names common in droppers.
        if stem.len() >= 8 && Self::stem_entropy(&stem) > 4.0 {
            pts = pts.max(5);
        }

        // Very short stem (≤3 chars) on any file — unusual, warrants early look.
        if stem.len() <= 3 {
            pts = pts.max(3);
        }

        pts.min(10)
    }

    // ── Helper: Shannon entropy of a file stem (bits per char) ───────────────

    fn stem_entropy(s: &str) -> f32 {
        let mut freq = [0u32; 256];
        for b in s.bytes() {
            freq[b as usize] += 1;
        }
        let len = s.len() as f32;
        freq.iter()
            .filter(|&&c| c > 0)
            .map(|&c| { let p = c as f32 / len; -p * p.log2() })
            .sum()
    }
}

impl Default for ScanPrioritizer {
    fn default() -> Self { Self }
}

// ─── Progress / threat callbacks ──────────────────────────────────────────────

/// Called during a scan with `(files_done, files_total, current_path)`.
pub type ProgressFn = Arc<dyn Fn(usize, usize, &Path) + Send + Sync>;

/// Called for every non-clean result found during a scheduled or manual scan.
pub type ThreatFn = Arc<dyn Fn(&ScanResult) + Send + Sync>;

// ─── SystemScanConfig ─────────────────────────────────────────────────────────

/// Full configuration for a system-wide scan.
#[derive(Debug, Clone)]
pub struct SystemScanConfig {
    /// Root directories to walk. Defaults to all common Windows locations.
    pub roots: Vec<PathBuf>,

    /// Directories that are never entered during the walk.
    pub skip_dirs: Vec<PathBuf>,

    /// File extensions that are skipped without scanning.
    pub skip_extensions: Vec<String>,

    /// Files larger than this (in bytes) are skipped.
    pub max_file_bytes: u64,

    /// Number of worker threads. Clamped to `[1, MAX_THREADS]`.
    pub num_threads: usize,

    /// When `true`, skip files whose `(mtime, size)` pair matches a previous
    /// clean result stored in the in-memory [`FileStateCache`].
    pub incremental: bool,

    /// Optional directory containing custom `.yar` / `.yara` rules.
    pub yara_rules_dir: Option<PathBuf>,

    /// Maximum directory walk depth.  `None` = unlimited (default for full
    /// scan).  Set to a small value (e.g. `Some(3)`) for quick scan so that
    /// large temp trees are only surface-scanned.
    pub max_depth: Option<usize>,

    /// Hard cap on the total number of files passed to the scan thread pool.
    /// Applied **after** `ScanPrioritizer` sorts the queue, so the first N
    /// files are always the highest-risk ones.  `None` = no cap (default for
    /// full scan).  Set to a few thousand for quick scans so that even a
    /// bloated `%TEMP%` directory cannot make the scan run indefinitely.
    pub max_files: Option<usize>,

    /// When `false`, worker threads use SHA-256 only (skipping MD5 and
    /// SHA-512).  Halves the per-file I/O for quick scans where full
    /// multi-hash is unnecessary.  `true` by default (full scan).
    pub enable_multi_hash: bool,
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
            max_depth: None,
            max_files: None,
            enable_multi_hash: true,
        }
    }
}

impl SystemScanConfig {
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

    fn should_skip_dir(&self, dir: &Path) -> bool {
        let dir_str = dir.to_string_lossy().to_lowercase();
        self.skip_dirs.iter().any(|skip| {
            let skip_str = skip.to_string_lossy().to_lowercase();
            dir_str.starts_with(&*skip_str)
        })
    }

    /// Returns `true` if `path` contains any priority fragment (coarse split
    /// before fine-grained prioritizer scoring).
    fn is_priority(&self, path: &Path) -> bool {
        let s = path.to_string_lossy();
        PRIORITY_FRAGMENTS.iter().any(|frag| s.contains(frag))
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

#[derive(Debug, Clone)]
struct CachedFileState {
    mtime_secs: u64,
    file_size: u64,
    level: ThreatLevel,
}

/// In-memory cache mapping `PathBuf → CachedFileState`.
///
/// Non-clean entries are never cached — they are always re-evaluated so that
/// remediated files are promptly reclassified.
pub struct FileStateCache {
    inner: HashMap<PathBuf, CachedFileState>,
}

impl FileStateCache {
    pub fn new() -> Self {
        Self { inner: HashMap::new() }
    }

    fn check(&self, path: &Path, mtime_secs: u64, file_size: u64) -> Option<ThreatLevel> {
        let state = self.inner.get(path)?;
        if state.mtime_secs == mtime_secs && state.file_size == file_size {
            Some(state.level.clone())
        } else {
            None
        }
    }

    fn update(&mut self, path: PathBuf, mtime_secs: u64, file_size: u64, level: ThreatLevel) {
        if level == ThreatLevel::Clean {
            self.inner.insert(path, CachedFileState { mtime_secs, file_size, level });
        } else {
            self.inner.remove(&path);
        }
    }

    pub fn clear(&mut self) {
        self.inner.clear();
    }

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
/// 2. Runs [`ScanPrioritizer`] to sort the queue highest-risk first.
/// 3. Checks each file against the incremental cache.
/// 4. Dispatches remaining paths to a thread pool for parallel scanning.
pub struct SystemScanner {
    config: SystemScanConfig,
    /// Shared incremental cache — updated after every scan.
    cache: Arc<Mutex<FileStateCache>>,
    /// Scores and sorts candidate files before the scan queue is built.
    prioritizer: ScanPrioritizer,
}

impl SystemScanner {
    pub fn new() -> Self {
        Self {
            config: SystemScanConfig::default(),
            cache: Arc::new(Mutex::new(FileStateCache::new())),
            prioritizer: ScanPrioritizer::new(),
        }
    }

    pub fn with_config(config: SystemScanConfig) -> Self {
        Self {
            config,
            cache: Arc::new(Mutex::new(FileStateCache::new())),
            prioritizer: ScanPrioritizer::new(),
        }
    }

    pub fn clear_cache(&self) {
        self.cache.lock().unwrap().clear();
    }

    /// Returns a reference to the [`ScanPrioritizer`] used by this scanner.
    ///
    /// Useful for callers that want to inspect or test scoring without running
    /// a full scan (e.g. the UI showing why a file was queued first).
    pub fn prioritizer(&self) -> &ScanPrioritizer {
        &self.prioritizer
    }

    // ── Root discovery ────────────────────────────────────────────────────────

    pub fn default_roots() -> Vec<PathBuf> {
        let mut roots: Vec<PathBuf> = Vec::new();

        #[cfg(windows)]
        {
            if let Ok(users) = std::env::var("SystemDrive") {
                let p = PathBuf::from(format!("{}\\Users", users));
                if p.exists() { roots.push(p); }
                let win = PathBuf::from(format!("{}\\Windows", users));
                if win.exists() { roots.push(win); }
            }

            for var in &["ProgramFiles", "ProgramFiles(x86)", "ProgramData"] {
                if let Ok(p) = std::env::var(var) {
                    let pb = PathBuf::from(p);
                    if pb.exists() { roots.push(pb); }
                }
            }

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

    /// Roots for the quick scan — 6 bounded, high-signal directories only.
    ///
    /// | Directory | Rationale |
    /// |-----------|-----------|
    /// | Downloads | Primary malware landing zone |
    /// | Desktop   | Common user-run location |
    /// | TEMP (depth-limited) | Dropper staging; walk capped at 3 levels |
    /// | User Startup folder | Per-user autorun persistence |
    /// | All-users Startup folder | System-wide autorun persistence |
    /// | System32\Tasks | Scheduled-task XML persistence |
    ///
    /// **System32\drivers is intentionally excluded.** Every legitimate kernel
    /// driver (.sys) accumulates enough heuristic signal (PE header + high
    /// entropy + imported API strings) to cross the Malicious threshold, producing
    /// ~50 % false-positive rates with no real gain — rootkit drivers are caught
    /// by the process scanner when they load.  A path-trust-tier cap in
    /// `heuristics.rs` suppresses the same class of FPs for full scans.
    pub fn quick_roots() -> Vec<PathBuf> {
        let mut roots: Vec<PathBuf> = Vec::new();

        #[cfg(windows)]
        {
            // Landing zones
            if let Ok(profile) = std::env::var("USERPROFILE") {
                let base = PathBuf::from(&profile);
                for sub in &["Downloads", "Desktop"] {
                    let p = base.join(sub);
                    if p.exists() { roots.push(p); }
                }
            }

            // Dropper staging (depth is capped by the quick scan config)
            for var in &["TEMP", "TMP"] {
                if let Ok(p) = std::env::var(var) {
                    let pb = PathBuf::from(p);
                    if pb.exists() && !roots.contains(&pb) { roots.push(pb); }
                }
            }

            // Persistence — autorun startup folders
            if let Ok(profile) = std::env::var("USERPROFILE") {
                let p = PathBuf::from(profile)
                    .join("AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup");
                if p.exists() { roots.push(p); }
            }
            if let Ok(pd) = std::env::var("ProgramData") {
                let p = PathBuf::from(pd)
                    .join("Microsoft\\Windows\\Start Menu\\Programs\\Startup");
                if p.exists() { roots.push(p); }
            }

            // Persistence — scheduled tasks
            if let Ok(sys) = std::env::var("SystemRoot") {
                let p = PathBuf::from(sys).join("System32\\Tasks");
                if p.exists() { roots.push(p); }
            }
        }

        #[cfg(not(windows))]
        {
            for p in &["/tmp", "/var/tmp"] {
                let pb = PathBuf::from(p);
                if pb.exists() { roots.push(pb); }
            }
        }

        roots
    }

    // ── Path collection ───────────────────────────────────────────────────────

    /// Walks all configured roots and returns two sorted path lists with
    /// per-file metadata already read: `(priority, normal, skipped_count)`.
    ///
    /// Each element is `(path, size_bytes, mtime_unix_secs)`.
    /// Reading mtime here avoids a second `stat` call in `filter_cached`.
    fn collect_paths(&self) -> (Vec<(PathBuf, u64, u64)>, Vec<(PathBuf, u64, u64)>, usize) {
        let mut priority: Vec<(PathBuf, u64, u64)> = Vec::new();
        let mut normal:   Vec<(PathBuf, u64, u64)> = Vec::new();
        let mut skipped = 0usize;

        for root in &self.config.roots {
            if !root.exists() { continue; }

            let walker = {
                let w = WalkDir::new(root).follow_links(false);
                if let Some(d) = self.config.max_depth { w.max_depth(d) } else { w }
            };
            for entry in walker
                .into_iter()
                .filter_entry(|e| {
                    if e.file_type().is_dir() {
                        !self.config.should_skip_dir(e.path())
                    } else {
                        true
                    }
                })
            {
                let entry = match entry {
                    Ok(e)  => e,
                    Err(_) => { skipped += 1; continue; }
                };

                if !entry.file_type().is_file() { continue; }

                let path = entry.path().to_path_buf();

                // Read size and mtime together from one metadata call.
                let meta = entry.metadata();
                let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
                let mtime_secs = meta.ok()
                    .and_then(|m| m.modified().ok())
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0);

                if self.config.should_skip_file(&path, size) {
                    skipped += 1;
                    continue;
                }

                if self.config.is_priority(&path) {
                    priority.push((path, size, mtime_secs));
                } else {
                    normal.push((path, size, mtime_secs));
                }
            }
        }

        (priority, normal, skipped)
    }

    // ── Incremental cache filtering ───────────────────────────────────────────

    /// Removes from `paths` any entry whose `(mtime, size)` matches the cache.
    /// Returns `(paths_to_scan, cache_hit_results, cache_hit_count)`.
    fn filter_cached(
        &self,
        paths: Vec<(PathBuf, u64, u64)>,
        cache: &FileStateCache,
    ) -> (Vec<PathBuf>, Vec<ScanResult>, usize) {
        let mut to_scan: Vec<PathBuf> = Vec::new();
        let mut from_cache: Vec<ScanResult> = Vec::new();
        let mut hits = 0usize;

        for (path, size, mtime_secs) in paths {
            if let Some(_cached_level) = cache.check(&path, mtime_secs, size) {
                hits += 1;
                from_cache.push(ScanResult::clean(path, None));
            } else {
                to_scan.push(path);
            }
        }

        (to_scan, from_cache, hits)
    }

    // ── Parallel scan engine ──────────────────────────────────────────────────

    /// Distributes `paths` across a thread pool and collects `ScanResult`s.
    fn parallel_scan(
        &self,
        paths: Vec<PathBuf>,
        progress: Option<ProgressFn>,
    ) -> Vec<ScanResult> {
        if paths.is_empty() { return Vec::new(); }

        let total = paths.len();
        let num_threads      = self.config.num_threads.clamp(1, MAX_THREADS);
        let yara_dir         = self.config.yara_rules_dir.clone();
        let enable_multi_hash = self.config.enable_multi_hash;

        let (work_tx, work_rx) = mpsc::channel::<PathBuf>();
        let work_rx = Arc::new(Mutex::new(work_rx));

        let (result_tx, result_rx) = mpsc::channel::<ScanResult>();

        let handles: Vec<_> = (0..num_threads)
            .map(|_| {
                let rx   = Arc::clone(&work_rx);
                let tx   = result_tx.clone();
                let yara = yara_dir.clone();

                thread::spawn(move || {
                    let mut scanner = FileSystemScanner::with_options(
                        enable_multi_hash, // MD5+SHA512 only when explicitly requested
                        true,              // deep scan (heuristics) always on
                        true,              // YARA always on
                    );
                    if let Some(ref dir) = yara {
                        scanner.load_yara_rules(dir).ok();
                    }

                    loop {
                        let path = match rx.lock().unwrap().recv() {
                            Ok(p)  => p,
                            Err(_) => break,
                        };

                        match scanner.scan_file(&path) {
                            Ok(result) => { tx.send(result).ok(); }
                            Err(e)     => {
                                tx.send(ScanResult::error(path, e.to_string())).ok();
                            }
                        }
                    }
                })
            })
            .collect();

        drop(result_tx);

        for path in paths {
            work_tx.send(path).ok();
        }
        drop(work_tx);

        let mut results: Vec<ScanResult> = Vec::with_capacity(total);
        for result in result_rx {
            if let Some(ref cb) = progress {
                cb(results.len() + 1, total, &result.path);
            }
            results.push(result);
        }

        for h in handles { h.join().ok(); }

        results
    }

    // ── Public scan entry point ───────────────────────────────────────────────

    /// Run a full system scan and return aggregated results.
    ///
    /// **Steps:**
    /// 1. Walk all roots → collect eligible paths with precomputed `(size, mtime)`.
    /// 2. Coarse sort: priority-location paths first, normal paths after.
    /// 3. [`ScanPrioritizer`] stable-sorts each group by risk score (highest first).
    /// 4. If `incremental` is enabled, check each path against the cache.
    /// 5. Dispatch uncached paths to the thread pool.
    /// 6. Merge cache-hit results + freshly scanned results.
    /// 7. Update the incremental cache with new verdicts.
    pub fn scan(&self, progress: Option<ProgressFn>) -> ScanAllResult {
        let scan_time = SystemTime::now();
        let timer = Instant::now();

        // Capture current time once for consistent recency scoring across the batch.
        let now_secs = scan_time
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // ── Step 1: collect paths ──────────────────────────────────────────────
        let (mut priority_paths, normal_paths, mut skipped_files) =
            self.collect_paths();

        // Priority-location paths first; normal paths follow.
        priority_paths.extend(normal_paths);
        let mut all_paths = priority_paths;

        // ── Step 2: fine-grained priority sort ────────────────────────────────
        // ScanPrioritizer stable-sorts: highest-risk files bubble to the front.
        // Equal-score files preserve the coarse order (priority bucket before
        // normal bucket) because sort_by is stable.
        self.prioritizer.sort(&mut all_paths, now_secs);

        // ── Step 2b: max_files cap ────────────────────────────────────────────
        // Applied after sorting so the truncated slice always contains the
        // highest-risk files.  Excess paths are counted as skipped.
        if let Some(cap) = self.config.max_files {
            if all_paths.len() > cap {
                skipped_files += all_paths.len() - cap;
                all_paths.truncate(cap);
            }
        }

        // ── Step 3: incremental cache filter ──────────────────────────────────
        let (paths_to_scan, mut results, cached_hits) = if self.config.incremental {
            let cache = self.cache.lock().unwrap();
            self.filter_cached(all_paths, &cache)
        } else {
            let paths: Vec<PathBuf> = all_paths.into_iter().map(|(p, _, _)| p).collect();
            (paths, Vec::new(), 0)
        };

        skipped_files += cached_hits;

        // ── Step 4: parallel scan ─────────────────────────────────────────────
        let fresh_results = self.parallel_scan(paths_to_scan, progress);

        // ── Step 5: update incremental cache ──────────────────────────────────
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

        // ── Step 6: aggregate statistics ──────────────────────────────────────
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
    interval: Duration,
    last_scan: Arc<Mutex<Option<SystemTime>>>,
    running: Arc<Mutex<bool>>,
    thread_handle: Mutex<Option<thread::JoinHandle<()>>>,
    on_threat: ThreatFn,
}

impl ScanScheduler {
    pub fn new(scanner: SystemScanner) -> Self {
        Self::with_options(
            Arc::new(scanner),
            Duration::from_secs(6 * 3600),
            Arc::new(|r: &ScanResult| {
                eprintln!("[AegisAI THREAT] {:?} — {}", r.level, r.path.display());
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

    pub fn builder() -> SchedulerBuilder {
        SchedulerBuilder::default()
    }

    pub fn start(&self) {
        let mut handle = self.thread_handle.lock().unwrap();
        if handle.is_some() { return; }

        *self.running.lock().unwrap() = true;

        let scanner   = Arc::clone(&self.scanner);
        let interval  = self.interval;
        let last_scan = Arc::clone(&self.last_scan);
        let running   = Arc::clone(&self.running);
        let on_threat = Arc::clone(&self.on_threat);

        *handle = Some(thread::spawn(move || {
            let tick = Duration::from_secs(60);

            loop {
                if !*running.lock().unwrap() { break; }

                let now = SystemTime::now();
                let should_fire = {
                    let last = last_scan.lock().unwrap();
                    match *last {
                        None    => true,
                        Some(t) => now.duration_since(t).unwrap_or_default() >= interval,
                    }
                };

                if should_fire {
                    eprintln!("[ScanScheduler] Starting scheduled full-system scan…");
                    let result = scanner.scan(None);

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

                let mut slept = Duration::ZERO;
                while slept < tick {
                    thread::sleep(Duration::from_secs(5));
                    slept += Duration::from_secs(5);
                    if !*running.lock().unwrap() { return; }
                }
            }
        }));
    }

    pub fn stop(&self) {
        *self.running.lock().unwrap() = false;
        if let Some(h) = self.thread_handle.lock().unwrap().take() {
            h.join().ok();
        }
    }

    pub fn is_running(&self) -> bool {
        *self.running.lock().unwrap()
    }

    pub fn last_scan_time(&self) -> Option<SystemTime> {
        *self.last_scan.lock().unwrap()
    }

    pub fn trigger_now(&self, progress: Option<ProgressFn>) -> ScanAllResult {
        self.scanner.scan(progress)
    }

    pub fn scanner(&self) -> &SystemScanner {
        &self.scanner
    }
}

impl Drop for ScanScheduler {
    fn drop(&mut self) {
        self.stop();
    }
}

// ─── SchedulerBuilder ─────────────────────────────────────────────────────────

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
    pub fn scanner(mut self, s: SystemScanner) -> Self {
        self.scanner = Some(s);
        self
    }

    pub fn interval(mut self, d: Duration) -> Self {
        self.interval = d;
        self
    }

    pub fn on_threat<F>(mut self, f: F) -> Self
    where
        F: Fn(&ScanResult) + Send + Sync + 'static,
    {
        self.on_threat = Some(Arc::new(f));
        self
    }

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

    // ── ScanPrioritizer unit tests ─────────────────────────────────────────────

    /// Extension tier ordering: executables > scripts > archives > documents.
    #[test]
    fn test_prioritizer_extension_tiers() {
        let p = ScanPrioritizer::new();
        let now = 0u64;

        let score = |name: &str| -> u32 {
            p.score(Path::new(name), 0, 0, now)
        };

        assert!(score("malware.exe") > score("script.ps1"),  "exe > ps1");
        assert!(score("script.bat") > score("archive.zip"), "bat > zip");
        assert!(score("archive.zip") > score("report.pdf"), "zip > pdf");
        assert!(score("report.pdf") > score("data.csv"),    "pdf > csv (default tier)");
    }

    /// Location scoring: Temp/Downloads outscores system dirs.
    #[test]
    fn test_prioritizer_location_tiers() {
        let p = ScanPrioritizer::new();
        let now = 1_000_000u64;

        let score = |path: &str| -> u32 {
            p.score(Path::new(path), 0, now, now)
        };

        // High-risk locations
        let temp_score = score(r"C:\Users\user\AppData\Local\Temp\evil.exe");
        // Medium-risk locations
        let sys32_score = score(r"C:\Windows\System32\legit.exe");
        // Unknown location
        let other_score = score(r"C:\SomeDir\file.exe");

        assert!(temp_score > sys32_score,  "Temp > System32");
        assert!(sys32_score > other_score, "System32 > unknown location");
    }

    /// Recency: recently modified files score higher than old ones.
    #[test]
    fn test_prioritizer_recency() {
        let p = ScanPrioritizer::new();
        let now = 100_000_000u64; // large enough to subtract years without overflow
        let one_hour_ago = now - 1_800;          // 30 minutes old
        let one_week_ago = now - 7 * 86_400;
        let one_year_ago = now - 365 * 86_400;

        let path = Path::new("file.txt");
        let s_recent = p.score(path, 0, one_hour_ago, now);
        let s_week   = p.score(path, 0, one_week_ago, now);
        let s_year   = p.score(path, 0, one_year_ago, now);

        assert!(s_recent > s_week, "recent > week-old");
        assert!(s_week   > s_year, "week-old > year-old");
    }

    /// Double-extension filenames should receive the maximum filename score.
    #[test]
    fn test_prioritizer_double_extension() {
        let p = ScanPrioritizer::new();
        let now = 0u64;

        // score_filename caps at 10; double-ext should hit that cap
        let score_double = p.score(Path::new("invoice.pdf.exe"), 0, 0, now);
        let score_single = p.score(Path::new("invoice.exe"), 0, 0, now);

        // Both are exe so ext score is equal; the double-ext gets the filename bonus.
        assert!(score_double > score_single, "double extension boosts score");
    }

    /// Suspicious stems (keywords like "dropper", "payload") score higher.
    #[test]
    fn test_prioritizer_suspicious_stem() {
        let p = ScanPrioritizer::new();
        let now = 0u64;

        let score_suspicious = p.score(Path::new("payload.txt"), 0, 0, now);
        let score_normal     = p.score(Path::new("readme.txt"), 0, 0, now);

        assert!(score_suspicious > score_normal, "suspicious stem > normal stem");
    }

    /// sort() orders files highest-score first.
    #[test]
    fn test_prioritizer_sort_order() {
        let p = ScanPrioritizer::new();
        let now = 10_000_000u64;

        let mut paths: Vec<(PathBuf, u64, u64)> = vec![
            (PathBuf::from(r"C:\SomeDir\harmless.txt"), 0, 0),
            (PathBuf::from(r"C:\Users\user\Downloads\payload.exe"), 0, now - 60),
            (PathBuf::from(r"C:\Windows\System32\legit.dll"), 0, now - 86_400),
        ];

        p.sort(&mut paths, now);

        // The exe in Downloads modified 1 minute ago should be first.
        assert!(
            paths[0].0.to_string_lossy().contains("payload.exe"),
            "highest-risk file should be first: {:?}", paths[0].0
        );
    }

    // ── SystemScanner integration tests ───────────────────────────────────────

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

        assert!(result.stats.total_files >= 1);
        assert_eq!(result.stats.malicious_files, 0);

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_scan_detects_eicar() {
        let dir = std::env::temp_dir().join("aegis_eicar_all_test");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("eicar.com"),
            "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
        ).unwrap();

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

        assert_eq!(result.stats.total_files, 0);
        assert!(result.skipped_files >= 2);

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_skip_large_files() {
        let dir = std::env::temp_dir().join("aegis_large_test");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("bigfile.bin"), b"hello").unwrap();

        let config = SystemScanConfig {
            roots: vec![dir.clone()],
            max_file_bytes: 0,
            ..SystemScanConfig::default()
        };
        let scanner = SystemScanner::with_config(config);
        let result = scanner.scan(None);

        assert_eq!(result.stats.total_files, 0);

        fs::remove_dir_all(&dir).ok();
    }

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

        let r1 = scanner.scan(None);
        assert_eq!(r1.cached_hits, 0);

        let r2 = scanner.scan(None);
        assert!(r2.cached_hits >= 1);

        fs::remove_dir_all(&dir).ok();
    }

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

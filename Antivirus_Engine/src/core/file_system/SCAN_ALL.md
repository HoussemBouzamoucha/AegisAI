# `scan_all.rs` — Full-System Scanner & Scheduler

## Overview

`scan_all.rs` adds **machine-wide scanning** to AegisAI on top of the existing
per-file / per-directory `FileSystemScanner`.  It introduces two public types:

| Type | Purpose |
|------|---------|
| `SystemScanner` | Collects paths, applies skip/priority rules, and dispatches to a thread pool |
| `ScanScheduler` | Wraps `SystemScanner` and fires full scans automatically on a configurable interval |

---

## Architecture

```
ScanScheduler (background thread)
  └── fires SystemScanner::scan() every N hours
        │
        ├── 1. collect_paths()
        │     ├── Walk all configured roots (WalkDir)
        │     ├── Prune skip-dirs early (no descent into Windows\WinSxS etc.)
        │     ├── Filter individual files (extension, size limit)
        │     └── Partition into priority_paths / normal_paths
        │
        ├── 2. filter_cached()          [incremental mode only]
        │     └── Compare (mtime_secs, file_size) against FileStateCache
        │         → unchanged clean files → synthetic Clean result (no re-scan)
        │         → changed / unknown files → passed to parallel_scan
        │
        └── 3. parallel_scan()
              ├── N worker threads (each owns its own FileSystemScanner)
              ├── Work channel: main → workers  (Arc<Mutex<Receiver<PathBuf>>>)
              ├── Result channel: workers → collector
              └── Optional progress callback: (done, total, &Path)
```

---

## Key Optimisations

### 1 — Smart skip rules

Two levels of filtering keep scan time bounded:

**Directory-level pruning** (applied before descending — avoids walking millions
of irrelevant files):

| Skipped directory | Reason |
|-------------------|--------|
| `C:\Windows\WinSxS` | ~10 GB side-by-side component store; read-only, trusted |
| `C:\Windows\Installer` | MSI cache; trusted, large |
| `C:\Windows\SoftwareDistribution\Download` | Windows Update cache |
| `C:\$Recycle.Bin` | Not a malware vector; contents already scanned when dropped |
| `C:\System Volume Information` | Not accessible without elevation |
| `/proc`, `/sys`, `/dev` (Linux) | Virtual filesystems, not real files |

> **`C:\Windows\System32` is NOT excluded** — DLL hijacking and malware drops
> frequently target it.

**File-level filtering** (applied to every discovered file):

| Filter | Default | Rationale |
|--------|---------|-----------|
| File size | 256 MB | Malware rarely exceeds this; scanning VM disks would dominate time |
| Media extensions | mp4, mkv, avi, mp3, wav, jpg, png, iso … | Almost zero malware risk, extremely large |

---

### 2 — Priority-first scanning

High-risk directories are scanned **before** generic ones so the most likely
infection vectors surface early in the result stream:

- `Downloads`, `Desktop` — common initial drop locations
- `Temp`, `AppData\Local\Temp` — dropper staging areas
- `AppData\Roaming` — malware persistence target
- `Startup`, `Start Menu\Programs\Startup` — autorun persistence
- `Tasks`, `Scheduled Tasks` — task-based persistence

---

### 3 — Thread pool

Each worker thread owns its own `FileSystemScanner` instance — no lock contention
on scanner state.

```
main thread: walk → collect Vec<PathBuf> → push to work_tx channel
worker-0:    recv path → FileSystemScanner::scan_file() → send ScanResult
worker-1:    recv path → FileSystemScanner::scan_file() → send ScanResult
...
collector:   recv ScanResult, update progress, append to Vec
```

Default thread count: **4**. Configurable via `SystemScanConfig::num_threads`
(clamped to `[1, 16]`).

---

### 4 — Incremental scan cache (`FileStateCache`)

The in-memory cache maps `PathBuf → (mtime_secs, file_size, ThreatLevel)`.

**Cache hit condition:** `mtime_secs == cached` **AND** `file_size == cached`  
→ file is treated as unchanged → previous verdict is reused without re-scanning.

**Cache miss** (file changed, or first scan): full `scan_file()` pipeline runs;
result is stored only if verdict is `Clean` (non-clean results are always
re-evaluated to catch remediated files promptly).

On a repeat scan of a fully clean, unchanged system, nearly 100% of files are
served from the cache — only the walking and metadata reads remain.

---

## Public API

### `SystemScanConfig`

```rust
pub struct SystemScanConfig {
    pub roots:            Vec<PathBuf>,   // directories to walk
    pub skip_dirs:        Vec<PathBuf>,   // directories to never enter
    pub skip_extensions:  Vec<String>,    // file extensions to skip
    pub max_file_bytes:   u64,            // skip files larger than this
    pub num_threads:      usize,          // worker thread count
    pub incremental:      bool,           // use FileStateCache
    pub yara_rules_dir:   Option<PathBuf>,// custom YARA rules for workers
}
```

`SystemScanConfig::default()` scans all common Windows locations with safe
defaults (256 MB limit, 4 threads, incremental enabled).

---

### `SystemScanner`

```rust
// Construction
SystemScanner::new()                          // default config
SystemScanner::with_config(config)            // custom config
SystemScanner::default_roots() -> Vec<PathBuf>// helper: platform default roots

// Operations
scanner.scan(progress: Option<ProgressFn>) -> ScanAllResult
scanner.clear_cache()                         // force full re-scan next time
```

`ProgressFn = Arc<dyn Fn(done: usize, total: usize, path: &Path) + Send + Sync>`

---

### `ScanAllResult`

```rust
pub struct ScanAllResult {
    pub results:       Vec<ScanResult>, // all scanned files
    pub stats:         ScanStatistics,  // totals per threat level
    pub duration_secs: f64,
    pub skipped_files: usize,           // skipped by filters or cache
    pub cached_hits:   usize,           // files served from incremental cache
    pub scan_time:     SystemTime,
}

// Convenience
result.threats()       // Iterator over non-clean results
result.has_malicious() // true if any Malicious file found
```

---

### `ScanScheduler`

```rust
// Builder (recommended)
let scheduler = ScanScheduler::builder()
    .scanner(SystemScanner::with_config(config))
    .interval(Duration::from_secs(3600))       // every hour
    .on_threat(|r| { /* called per threat */ })
    .build();

// Lifecycle
scheduler.start();                             // spawn background thread
scheduler.stop();                              // signal + join (blocks)
scheduler.is_running() -> bool
scheduler.last_scan_time() -> Option<SystemTime>

// Manual trigger (blocking, outside the scheduler loop)
let result: ScanAllResult = scheduler.trigger_now(progress_fn);
```

**Default interval:** 6 hours.  
**Tick resolution:** the background thread wakes every 5 seconds to check the
stop flag, and every 60 seconds to re-evaluate whether a scan is due.  
**`Drop` impl:** `stop()` is called automatically when the `ScanScheduler` goes
out of scope.

---

## Usage Examples

### Minimal — on-demand full scan

```rust
use crate::core::file_system::scan_all::SystemScanner;

let scanner = SystemScanner::new();
let result = scanner.scan(None);

println!("Scanned {} files in {:.1}s", result.stats.total_files, result.duration_secs);
for threat in result.threats() {
    println!("[{:?}] {}", threat.level, threat.path.display());
}
```

---

### Custom config — quick scan of user directories only

```rust
use std::path::PathBuf;
use crate::core::file_system::scan_all::{SystemScanner, SystemScanConfig};

let config = SystemScanConfig {
    roots: vec![PathBuf::from(r"C:\Users")],
    max_file_bytes: 64 * 1024 * 1024,  // 64 MB
    num_threads: 2,
    incremental: true,
    ..SystemScanConfig::default()
};

let scanner = SystemScanner::with_config(config);
let result = scanner.scan(Some(std::sync::Arc::new(|done, total, path| {
    print!("\r[{}/{}] {}", done, total, path.display());
})));
```

---

### Scheduled background scan every 6 hours

```rust
use std::time::Duration;
use crate::core::file_system::scan_all::{ScanScheduler, SystemScanner};

let scheduler = ScanScheduler::builder()
    .scanner(SystemScanner::new())
    .interval(Duration::from_secs(6 * 3600))
    .on_threat(|result| {
        eprintln!(
            "[THREAT] {:?} confidence={:.0}% — {}",
            result.level,
            result.confidence_score * 100.0,
            result.path.display(),
        );
        // Hook into EntityManager, alert UI, quarantine, etc.
    })
    .build();

scheduler.start();
// Application continues running; scans fire in the background.
// scheduler.stop() is called automatically on Drop.
```

---

### Trigger an immediate scan from the UI ("Scan Now" button)

```rust
// scheduler is already started and running its normal interval
let result = scheduler.trigger_now(None);
// result is available immediately in the calling thread
```

---

## Integration with the AegisAI daemon

`SystemScanner` and `ScanScheduler` are **not yet wired into `main.rs`**.
Suggested integration points:

1. **Daemon startup** — construct a `ScanScheduler` alongside the other scanner
   instances and call `scheduler.start()`.

2. **New daemon command** — add `"full-scan"` to the JSON-RPC dispatch table:
   ```json
   { "id": "...", "cmd": "full-scan", "incremental": true }
   ```
   The handler calls `scheduler.trigger_now(None)` and streams the
   `ScanAllResult` back as JSON.

3. **Threat callback** — in the callback, call
   `entity_manager.ingest_file_result(result)` so detections feed into the
   entity graph for correlation and attack-chain analysis.

4. **Tauri IPC** — add an `invoke('full_scan', { incremental: bool })` command
   in `UI/src-tauri/src/main.rs` that proxies to the daemon and streams progress
   via a Tauri event channel.

---

## File map

| File | Role |
|------|------|
| `scan_all.rs` | This module — `SystemScanner` + `ScanScheduler` |
| `scanner.rs` | Per-file / per-directory scanner (called by `SystemScanner`) |
| `heuristics.rs` | Heuristic analysis layer (used by `scanner.rs`) |
| `yara_engine.rs` | YARA rule engine (used by `scanner.rs`) |
| `signature.rs` | Hash signature database (used by `scanner.rs`) |
| `context.rs` | Directory-level context analysis (used by `scanner.rs`) |

---

## Design decisions

**One scanner per thread, not one shared scanner**  
`FileSystemScanner` holds mutable YARA engine state.  Sharing it across threads
would require a `Mutex<FileSystemScanner>` that serialises all scanning — defeating
the purpose of the thread pool.  Creating one instance per thread costs a YARA
rule compilation at thread start-up, but amortises to zero over thousands of
files per thread.

**`mtime + size` as cache key, not SHA-256**  
Computing SHA-256 requires reading the whole file.  A metadata-only check
(two syscalls) is orders of magnitude cheaper and sufficient for an incremental
cache: if both mtime and size are unchanged, the content is overwhelmingly likely
to be unchanged.  A paranoid mode could add SHA-256 verification on top.

**Clean-only caching**  
Non-clean results are never stored in the cache so that a remediated file
(deleted/quarantined payload, patched binary) is always re-evaluated on the
next scan rather than served a stale `Suspicious`/`Malicious` verdict.

**Directory pruning vs. file filtering**  
Skip-dirs are applied via `WalkDir::filter_entry` (prunes the entire subtree —
no descent, no stat calls for children).  Extension / size filters are applied
file-by-file after the walk.  This order matters: pruning `WinSxS` avoids
~150 000 file stat calls before any extension check runs.

**60-second scheduler tick**  
The background thread wakes every 5 seconds to check the stop flag (fast
`Mutex` read) and every 60 seconds to evaluate whether the scan interval has
elapsed.  This keeps CPU usage at zero between scans while still allowing the
scheduler to shut down within 5 seconds of `stop()` being called.

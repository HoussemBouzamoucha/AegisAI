# Full System Scan — Performance Diagnosis & Optimization Plan

Observed scan time: **2+ hours** on a typical Windows system.
Target after optimizations: **15–30 minutes** (4–8× speedup).

---

## Root Causes (ranked by time impact)

### 1. Triple file reads per file — 30–45 min overhead

Every file ≤ 10 MiB is opened and fully read **three separate times** across three
independent pipeline stages:

| Stage | Where | What it reads |
|-------|-------|---------------|
| Multi-hash (MD5 + SHA-256 + SHA-512) | `scanner.rs:calculate_all_hashes()` | Full file into `Vec<u8>` |
| YARA scan | `yara_engine.rs:scan_file()` | Full file again via `yara_x::Scanner` |
| Heuristic analysis | `heuristics.rs:analyze()` | Full file again via `read_file_bytes()` |

Additionally, after scanning, `scan_all.rs` calls `fs::metadata()` **twice** on every
result file to update the mtime/size cache (lines 1010–1016 in scan_all.rs) — two
extra stat syscalls per file.

**Impact on 100,000 files at average 200 KB each:**
- 3 reads × 100k files × 200 KB = ~60 GB of disk reads
- On a 200 MB/s HDD: 300 seconds (5 min) in I/O alone, per stage = 15+ min total
- On an SSD: still 3× unnecessary amplification; blocks cache bandwidth

**Fix:** Read the file once into a shared `Vec<u8>` buffer at the scanner level and
pass a `&[u8]` slice to all three stages. The heuristics engine already supports this
path via `compute_sha256_from_bytes` — the pattern needs to extend to YARA and hashing.
The two post-scan stat calls should use the size already known from `WalkDir` metadata
collected during path collection.

---

### 2. 566 YARA rules run against every eligible file — 40–60 min overhead

**How YARA is invoked:**
- Rules are compiled once and shared via `Arc<YaraEngine>` — correct.
- But `yara_x::Scanner::new(rules)` is called on **every file** scan
  (`yara_engine.rs` lines ~110, ~157). Each `Scanner::new()` re-prepares wasmtime
  JIT state per call even though the compiled rules are shared.
- 566 rule files are loaded. Every file ≤ 10 MiB that is an executable, script, or
  document triggers the full 566-rule scan with no early exit.

**There is no per-category rule filtering.** A `.docx` file runs the same rule set as
a `.exe`, including rules that will never match a document (PE header patterns, ELF
sections, etc.).

**Fix — three-layer approach:**
1. **Keep one `Scanner` instance per worker thread** (not one per file). `Scanner`
   holds the JIT-warmed wasmtime state; reusing it across files amortises the
   initialisation cost across thousands of files.
2. **Rule tagging by file category.** Tag each rule with the file types it applies to
   (PE, OLE, script, generic). At scan time, select only the applicable rule subset
   for each file's detected category. A `.docx` runs ~30 OLE/macro rules, not all 566.
   This alone can cut YARA time by 60–80% for document-heavy systems.
3. **YARA skip-list expansion.** Already skips large files (> 10 MiB) and media
   extensions. Add compiled native images (`.ni.dll`, `.ngen`), font files (`.ttf`,
   `.otf`, `.fon`), and locale resource files (`.mui`, `.cat`, `.mum`) which have zero
   malware surface and exist in large numbers under System32.

---

### 3. Only 4 worker threads on modern hardware — 20–30 min overhead

The default thread count is hardcoded to `4` (`scan_all.rs:DEFAULT_THREAD_COUNT`).
The ceiling is `16`. On a modern 8-core/16-thread system, 12 logical cores sit idle
during the entire scan.

**Why 4 is insufficient:**
- Full scan is overwhelmingly I/O-bound (disk reads dominate).
- More threads keep the disk queue saturated, hiding per-file latency.
- On NVMe SSDs with high queue depth, 8–16 concurrent readers are optimal.
- On HDDs, 4–6 threads are optimal (more causes head-seek thrashing).

**Fix:** Replace the hardcoded constant with `num_cpus::get().clamp(4, MAX_THREADS)`
at runtime. Add a separate `hdd_thread_count` config option (4–6) that can be
selected when the target drive is detected as a rotational disk via WMI/DeviceIoControl.

---

### 4. Incremental cache cold-starts and clean-only caching — 30–60 min on deltas

**How the cache works:**
- Stores `(path → mtime_secs, file_size, threat_level)` in a `HashMap` serialised to
  JSON on disk after each scan.
- On the next scan, a file is skipped if its mtime and size match the cached entry.
- **Only clean results are cached.** Suspicious and Malicious files are explicitly
  removed from the cache (`scan_all.rs:FileStateCache::update()`).

**Consequences:**
1. **First scan is always a full scan** — no cache exists yet, 100% of files are
   scanned. Expected, but unavoidable.
2. **After any remediation** (quarantine, delete), previously suspicious files no
   longer exist, but surrounding clean files are still in cache — acceptable.
3. **Any Windows Update or software install** changes mtimes on potentially thousands
   of System32 DLLs, invalidating their cache entries and forcing a full rescan of
   the entire update footprint — the most common cause of repeated 2-hour scans.
4. **Cache is loaded into a `Mutex<HashMap>`**. Under 16 worker threads, this becomes
   a contention point during the post-scan update pass.

**Fix:**
1. Cache suspicious and malicious results too, tagged with their verdict. On the next
   scan, known-suspicious files are re-scanned (correct) but known-clean files are
   skipped. This does not change detection but eliminates the "clean file re-scan"
   that accounts for 90%+ of scan time.
2. Use a content hash (SHA-256, already computed) as a secondary cache key alongside
   mtime. If the mtime changed but the hash matches, the file is clean (it was
   trivially touched, not modified). This handles Windows Update's habit of
   timestamping unmodified DLLs.
3. Replace `Mutex<HashMap>` with `DashMap` (concurrent hash map). Worker threads
   can read the cache locklessly and batch-update after their work unit is done.

---

### 5. Serial directory walk before any scanning begins — 5–15 min overhead

`SystemScanner::collect_paths()` uses `WalkDir` in a single thread. The entire
directory tree — potentially 300,000+ entries on a typical Windows install — is walked
to completion before the first file is dispatched to a worker.

**Consequences:**
- The scan cannot start on high-priority files until the walk finishes.
- On slow storage or deep directory trees, the walk itself takes minutes.
- The prioritiser runs after the walk, so the full file list must be held in memory.

**Fix — streaming pipeline:**
Replace the collect-then-scan model with a producer-consumer pipeline:
- The walker runs in a dedicated thread and pushes paths into a bounded channel.
- The prioritiser runs as a sliding-window sort on chunks of 1,000 paths at a time.
- Workers pull from the channel continuously — scanning starts within milliseconds
  of the walk beginning.
- Memory usage drops from O(all paths) to O(channel buffer size).

This also enables **scan-as-you-walk** semantics: if the user cancels mid-scan, all
files visited so far have been scanned and cached, so the next scan resumes cleanly.

---

### 6. Hash database lookup architecture

The hash DB lookup (`enable_hash_db = true` in full scan) performs one lookup per
file after hashing. The current implementation's performance depends on the DB backend
(not inspected in detail), but common issues in hash-lookup pipelines are:

- **Synchronous per-file lookups** stall the worker thread on I/O for each lookup.
- **No bloom filter pre-check** — every hash goes through the full lookup path even
  though the vast majority of hashes will not match any known-bad entry.

**Fix:**
1. A Bloom filter in front of the hash DB eliminates ~99% of DB lookups with a
   single in-memory bitset check. False positives (rare) still go to the DB;
   false negatives are impossible.
2. Batch hash lookups: accumulate hashes from a work unit (e.g. 100 files) and
   query the DB once with a batch API rather than 100 individual lookups.

---

## Advanced Approaches

### A. Two-pass scan with triage

Instead of running the full pipeline (hash + YARA + heuristics) on every file, split
into two passes:

**Pass 1 — triage (fast, heuristics only, no YARA, no hash DB):**
- Runs at ~5,000 files/sec per thread.
- Scores each file using extension, entropy, filename anomalies, and magic bytes only.
- Files scoring below a threshold (e.g. < 10 pts) are marked clean and cached.
- Only files scoring ≥ 10 pts proceed to Pass 2.
- On a typical system, 90–95% of files score below threshold → 5–10× reduction
  in Pass 2 work.

**Pass 2 — deep scan (YARA + hash DB + full heuristics):**
- Runs only on the ~5–10% of files that passed triage.
- Can afford more thorough analysis (e.g. YARA with larger file cap, full hash DB).

This mirrors how production AV engines work: a "fast filter" eliminates the bulk of
clean files before expensive signature matching.

---

### B. Memory-mapped file I/O

Instead of reading files into `Vec<u8>` buffers, use memory-mapped I/O (`memmap2`
crate). Benefits:
- The OS kernel manages page loading on demand — only the bytes actually accessed
  are read from disk.
- YARA, heuristics, and hash computation can all operate on the same `Mmap` view
  without copying data between buffers.
- For large files (1–10 MiB), `mmap` avoids allocating and freeing large heap buffers
  on every scan, reducing allocator pressure under 16 threads.

---

### C. Persistent YARA scanner per worker thread (avoid per-file Scanner::new)

The single most impactful YARA fix: keep one `yara_x::Scanner` alive for the lifetime
of each worker thread instead of constructing a new one per file. The scanner holds
the JIT-warmed wasmtime module state. Reusing it means wasmtime does not need to
re-prepare execution contexts per file.

Implementation: store the `Scanner` in a thread-local or pass it as a `&mut` through
the worker closure. The shared `Arc<CompiledRules>` is already in place; the only
change is the scanner lifetime.

---

### D. Parallel WinSxS and System32 handling

`C:\Windows\WinSxS` is skipped (correctly — it is 10 GB+ of versioned component
store with largely identical content to System32). However `C:\Windows\System32`
itself contains 4,000–6,000 DLLs and EXEs. These are the highest-trust, lowest-risk
files on the system after their first scan.

**Optimisation:** On the second scan, System32 DLLs whose SHA-256 matches a
Microsoft-signed known-good hash list can be skipped entirely (no YARA, no heuristics,
just hash check). Microsoft publishes the catalog of signed system file hashes via
Windows Authenticode; a local snapshot of this list turns System32 from a 30-minute
sub-scan into a 2-minute hash-comparison pass.

---

### E. Scan prioritisation as a continuous feedback signal

Currently the prioritiser runs once before scanning begins and uses static signals
(extension, location, recency). A dynamic prioritiser would adjust the queue in real
time based on findings:
- When a `Malicious` file is found, immediately elevate all files in the same
  directory to the front of the queue (dropper + payload are almost always co-located).
- When a C2 IP is identified in a network scan running concurrently, elevate files
  recently written by the beaconing process.
- This converts the scanner from a static queue to a directed search that concentrates
  effort where threats are actually found.

---

## Expected Gains (combined)

| Optimisation | Estimated reduction |
|---|---|
| Single file read (shared buffer) | −30–40 min |
| Per-thread YARA Scanner reuse | −20–30 min |
| YARA rule filtering by file category | −25–40 min |
| Thread count: 4 → num_cpus | −20–30 min |
| Two-pass triage (skip 90% of files in Pass 2) | −40–60 min |
| Streaming walk pipeline | −5–10 min |
| Bloom filter on hash DB | −5–10 min |
| **Total** | **−145–220 min → target 15–35 min** |

Gains are not fully additive (some optimisations compete for the same bottleneck),
but the combined effect on a 16-thread SSD system should bring a full scan to
**15–35 minutes** and a warm-cache rescan to **3–8 minutes**.

---

## Implementation Priority Order

1. **Single shared file read buffer** — highest effort:reward, no architectural change
2. **Per-thread YARA Scanner reuse** — one-line lifetime change, immediate YARA gain
3. **Increase default thread count to num_cpus** — one-line change
4. **Two-pass triage** — moderate effort, largest overall gain on typical systems
5. **Streaming walk pipeline** — moderate effort, enables scan-as-you-walk semantics
6. **YARA rule category tagging** — requires tagging 566 rule files, medium effort
7. **Bloom filter on hash DB** — depends on hash DB implementation details
8. **mmap I/O** — advanced, highest gain on large-file heavy systems
9. **Dynamic prioritisation** — advanced, enables intelligence-driven scanning

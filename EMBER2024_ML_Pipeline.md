# EMBER2024 ML Inference Pipeline

## Overview

AegisAI's file scanner uses a second-opinion ML layer on top of YARA rules and heuristics.
When the user clicks **Apply ML** in the Scanner panel, the engine runs every file that
heuristics flagged as Suspicious or Malicious through one of five LightGBM models trained
on the EMBER 2024 dataset.  The result — a malice probability score between 0 and 1 — is
shown alongside the heuristic verdict and can escalate a Suspicious file to Malicious if
the model score is >= 0.8.

---

## Architecture

```
User clicks "Apply ML"
        |
        v
UI (Scanner.tsx) → Zustand applyEmberMl()
        |
        v
Tauri invoke('apply_ember_ml', { paths: [...] })          [300 s timeout]
        |
        v
Daemon (main.rs) — "apply-ember-ml" command
        |
        v
EmberServer::analyze_batch(paths)
        |
        +-- writes one path to bridge.py stdin
        +-- waits for one JSON result on bridge.py stdout
        +-- repeats for every path
        |
        v
bridge.py --server  (persistent Python process, models loaded once)
        |
        +-- magic-byte routing (MZ → PE, %PDF → PDF, else All)
        +-- selects LightGBM model (Win32 / Win64 / DotNet / PDF / All)
        +-- calls thrember.predict_sample(model, file_bytes) → float
        +-- writes JSON result line to stdout
        |
        v
Daemon serialises results → Tauri → store → Scanner.tsx renders badges
```

### File-type routing

| Magic bytes / condition | Model used |
|------------------------|------------|
| Starts with `MZ` + CLR directory present | `EMBER2024_Dot_Net.model` |
| Starts with `MZ` + 64-bit machine code | `EMBER2024_Win64.model` |
| Starts with `MZ` (default PE) | `EMBER2024_Win32.model` |
| Starts with `%PDF` | `EMBER2024_PDF.model` |
| No recognised magic bytes | `EMBER2024_all.model` (catch-all) |
| File is empty (0 bytes) | Short-circuited — score 0.0, clean |
| File deleted / locked at scan time | Skipped — `skip_reason: file_unavailable` |

Extension is only used as a last-resort fallback for files shorter than 4 bytes; magic bytes
always take priority, so a `.tmp` that starts with `MZ` is correctly routed to a PE model.

### Score interpretation

| Score range | Meaning | UI badge |
|------------|---------|----------|
| >= 0.8 | Malicious | red **Malicious** |
| 0.5 – 0.79 | Suspicious | amber **Suspicious** |
| < 0.5 | Clean | green **Clean** |
| — | Skipped / error | grey (reason shown in tooltip) |

---

## Key Components

### `bridge.py` — Python ML bridge
**Location:** `Antivirus_Engine/src/core/file_system/Ember2024/bridge.py`

- Loads all five LightGBM models once at module import (`_load_models()`).
- Provides three invocation modes:
  - `python bridge.py <file>` — single file, JSON object output.
  - `python bridge.py --batch <f1> <f2> ...` — multiple files, JSON array output.
  - `python bridge.py --server` — persistent server; reads one path per stdin line,
    writes one JSON result per stdout line; never exits until stdin is closed.
- Contains a venv bootstrap: if the system Python lacks `thrember`/`lightgbm`, the script
  re-launches itself under `ai_agent/.venv/Scripts/python.exe` automatically.

### `EmberServer` — Rust persistent server handle
**Location:** `Antivirus_Engine/src/core/file_system/scanner.rs`

- Spawned once at daemon startup (eager, not lazy).
- Communicates via stdin/stdout pipes using the `--server` protocol.
- `analyze_batch(paths)`: sequential send-one → receive-one loop per file.
  - First file timeout: **120 s** (covers Python startup + model loading).
  - Subsequent files: **20 s** each (inference only; models already warm).
- If the server crashes or times out, it is killed and the fallback batch subprocess
  (`run_ember_ml_batch`) is used for the remaining files.

### `daemon_apply_ember_ml` — Daemon command handler
**Location:** `Antivirus_Engine/src/main.rs`

- Handles the `"apply-ember-ml"` JSON-RPC command.
- Checks whether the `EmberServer` is still alive; restarts it if it crashed.
- Falls back to `run_ember_ml_batch` (one-shot subprocess with 80 s kill timeout)
  if the server is unavailable.
- Returns a JSON array: `[{ path, file_type, score, malicious } | { path, skipped, skip_reason }]`.

### `apply_ember_ml` — Tauri command
**Location:** `UI/src-tauri/src/main.rs`

- Forwards the path list to the daemon with a **300 s** timeout.
- Passes raw results back to the UI store.

### `applyEmberMl` — Zustand action
**Location:** `UI/src/store/index.ts`

- Collects paths of all Suspicious/Malicious files from the current scan result.
- Invokes `apply_ember_ml` in a single batch call.
- Maps raw entries to `EmberMlFileResult[]` (score, file_type, malicious, skipReason).
- Escalates confirmed-malicious files in the scan result store.

---

## Issues Encountered and Fixes Applied

### Issue 1 — "unsupported" verdict for context-escalated Suspicious files

**Root cause:**  
Files below the raw heuristic threshold (< 4 points) can be escalated to Suspicious by
directory context analysis (e.g., ransom notes found in the same folder).  When the original
"Apply ML" implementation re-ran these files through the full scan pipeline, they scored
below the threshold again and were classified as Clean — so the ML gate was never reached
and no signal was emitted.  The UI received an empty result and showed "unsupported".

**Fix:**  
Replaced the per-file re-scan approach with a dedicated `"apply-ember-ml"` daemon command
that bypasses the YARA/heuristics pipeline entirely and calls the ML bridge directly on the
file bytes.  Context-escalated files are now scored by the model the same as any other file.

---

### Issue 2 — Very slow inference (N Python process spawns)

**Root cause:**  
The original implementation spawned a fresh `python bridge.py <file>` subprocess for every
suspicious file.  Each spawn paid the full model-load cost (~5-10 s for five LightGBM
models), making the total time proportional to N × 10 s for N files.

**Fix — batch mode (intermediate):**  
All paths were passed to a single `bridge.py --batch` invocation.  Model load paid once;
inference cost ~0.1-0.3 s per file.

**Fix — persistent server mode (final):**  
`bridge.py --server` is now started once at daemon startup.  Models load once and stay in
memory for the entire daemon lifetime.  Subsequent "Apply ML" calls skip model loading
entirely and pay only inference cost per file.

---

### Issue 3 — Bootstrap `capture_output=True` broke the persistent server

**Root cause:**  
`bridge.py` contains a venv bootstrap that re-launches the script under the project venv
when the system Python is missing `thrember`/`lightgbm`.  For single-file and batch modes
this works correctly: the inner process exits, its stdout is captured, and it is forwarded
to Rust.  But for `--server` mode the inner process never exits (it loops reading stdin).
`capture_output=True` caused `_sp.run()` to block forever waiting for the inner process to
finish.  The outer Python was alive but produced no stdout; Rust's `recv_timeout` fired
after 30 s for every file, producing wall-to-wall timeouts.

**Fix:**  
Detect `--server` in `sys.argv` before the subprocess call.  When in server mode, launch
the venv Python with plain `_sp.run([...])` — no `capture_output` — so stdin/stdout pipes
pass straight through from Rust to the inner server process:

```python
if "--server" in _sys.argv[1:]:
    _sys.exit(_sp.run([_VENV_PYTHON, _SCRIPT] + _sys.argv[1:]).returncode)
```

---

### Issue 4 — Pipe buffer deadlock during model loading

**Root cause:**  
`analyze_batch` originally wrote **all** file paths to the server's stdin before reading any
responses.  While models were still loading (the server was not yet reading stdin), the OS
pipe buffer (~64 KiB) filled up.  The Rust daemon blocked on `writeln!`, the Python server
was still loading models and not reading, and neither side could progress — a classic
write-write deadlock.

**Fix:**  
Changed `analyze_batch` to a strict sequential protocol: **write one path → wait for one
response → repeat**.  The OS pipe buffer never fills because the server drains it one line
at a time before another line is written.

---

### Issue 5 — Model loading counted against the Tauri timeout

**Root cause:**  
`EmberServer::start()` was called lazily on the first `"apply-ember-ml"` request.  The
5-10 s model loading time was consumed inside the 100 s Tauri command window, leaving less
budget for actual inference.  On slower machines or after a daemon restart, this combined
with the other issues to exceed the timeout.

**Fix — eager start:**  
`EmberServer::start()` is now called immediately after the daemon initialises its scanners,
before the request loop begins.  Models load in the background while the daemon is idle.  By
the time the user clicks "Apply ML" the server is typically already warm.

**Fix — timeout increase:**  
The Tauri command timeout was raised from 100 s to 300 s to cover worst-case startup
(120 s warmup + 20 s × ~8 files + serialisation margin) on the very first call after a
daemon restart.

---

## Timing Budget (after all fixes)

| Phase | Time |
|-------|------|
| Python startup + 5-model LightGBM load | 5-15 s (background, during daemon idle) |
| First file warmup timeout | 120 s (safety net only) |
| Per-file inference (Win32/Win64/DotNet) | ~0.1-0.3 s |
| Per-file inference (PDF / All) | ~0.05-0.15 s |
| Tauri command timeout | 300 s |

In practice, clicking "Apply ML" after the daemon has been running for > 15 s should return
results in under 5 s for a typical batch of 10-20 suspicious files.

---

## Known Limitations

- **Thrember dependency**: `thrember` (the EMBER feature extractor Python package) must be
  installed in the venv.  If it is missing, all files are skipped with `error: no module`.
- **Non-PE/PDF files**: scripts, archives, office documents, and other file types are routed
  to the `All` model, which uses only byte-level features (histogram, entropy, string
  patterns).  PE-specific features (imports, sections, rich header) are zeroed out, so
  accuracy is lower than for the dedicated models.
- **Large files**: `bridge.py` reads the entire file into memory before feature extraction.
  Files larger than ~100 MB may cause memory pressure or slow inference.
- **Server crash recovery**: if the Python server crashes mid-batch (OOM, exception), all
  remaining files in that batch are marked `server_timeout`.  The server is restarted
  transparently on the next "Apply ML" call.
- **No model versioning**: model files are loaded by fixed filename from the `Models/`
  directory.  Replacing a model file requires restarting the daemon.

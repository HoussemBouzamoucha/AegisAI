File Scanner — Full Lifecycle

  There are 5 layers in the stack. A single file scan travels through all of them, top to bottom.

  ---
  Layer 0 — The UI triggers a scan

  The user types a path and clicks SCAN FILE.

  Scanner.tsx
    handleScanFile()
      → store.scanFile(path)
        → invoke('scan_file', { path })   // Tauri IPC bridge

  invoke is the Tauri JavaScript bridge. It serialises the call and sends it to the Rust desktop process
  (UI/src-tauri/src/main.rs).

  ---
  Layer 1 — Tauri wraps the request and forwards it to the daemon

  UI/src-tauri/src/main.rs  →  scan_file()

    builds JSON:  { "id": "<uuid>", "cmd": "scan-file", "path": "C:\..." }
    daemon_request() writes that line to the daemon's stdin
    waits up to 60 s for a response line on stdout

  The daemon is a separate process — a child of the Tauri app — that was spawned when the app started. All communication is
  one JSON line in, one JSON line out over stdin/stdout. This isolates crashes and keeps the heavy Rust engine from running
  inside the UI process.

  ---
  Layer 2 — The daemon receives and dispatches the command

  Antivirus_Engine/src/main.rs  →  run_daemon()

    reads one line from stdin
    parses JSON
    matches cmd → "scan-file"
      calls daemon_scan_file(&scanner, path, &id)

  The FileSystemScanner was created once at daemon startup — YARA rules compiled, signature DB loaded, heuristic engine
  initialised. No re-init per request.

  ---
  Layer 3 — FileSystemScanner::scan_file() — the 4-layer detection pipeline

  This is the core of the engine (scanner.rs). Each layer produces a numeric score; the final verdict is decided by the
  total.

                            ┌──────────────────────────────────────┐
                            │   FileSystemScanner::scan_file()     │
                            └──────────────────────────────────────┘

  Layer 3.1 — Hash signature database (instant block)

  compute_sha256(path)        // or MD5 + SHA-512 in multi-hash mode
  check_all_hashes(&hashes)   // O(1) HashSet lookup

  - If the hash is in the known-malware DB → immediately returns Malicious with confidence = 1.0. No further layers run.
  - This catches known ransomware, malware samples, EICAR test files.

  Layer 3.2 — YARA rules

  yara.scan_file(path, None)  // compiled yara-x rules, 5 s timeout per file

  - Only runs on executables and scripts (.exe, .dll, .ps1, .bat, .py, etc.). Documents are excluded to avoid false positives
   from generic rules.
  - Only runs on files ≤ 10 MiB.
  - Each matching rule adds to the score:
    - Strong rule (named malware family like WannaCry_Ransomware_Generic) → +10
    - Weak rule (generic patterns like contains_base64, powershell) → +1

  Layer 3.3 — Heuristics (heuristics.rs)

  The file is read once into memory (≤ 10 MiB). All checks share that buffer — no re-opening the file.

  ┌───────────────────────────────────────────────┬────────────────────────┐
  │                     Check                     │         Score          │
  ├───────────────────────────────────────────────┼────────────────────────┤
  │ Very high entropy > 7.5 (packed/encrypted)    │ +4                     │
  ├───────────────────────────────────────────────┼────────────────────────┤
  │ High entropy > 7.2 (executable only)          │ +2                     │
  ├───────────────────────────────────────────────┼────────────────────────┤
  │ Suspicious keyword in content                 │ +3 each, capped at +12 │
  ├───────────────────────────────────────────────┼────────────────────────┤
  │ PowerShell obfuscation patterns               │ +4                     │
  ├───────────────────────────────────────────────┼────────────────────────┤
  │ Ransomware content phrase                     │ +5 each, capped at +20 │
  ├───────────────────────────────────────────────┼────────────────────────┤
  │ Crypto wallet address detected                │ +5                     │
  ├───────────────────────────────────────────────┼────────────────────────┤
  │ Ransomware filename/extension                 │ +7/+8                  │
  ├───────────────────────────────────────────────┼────────────────────────┤
  │ File type mismatch (e.g. EXE header but .txt) │ +3                     │
  ├───────────────────────────────────────────────┼────────────────────────┤
  │ Double extension trick (.pdf.exe)             │ +4                     │
  ├───────────────────────────────────────────────┼────────────────────────┤
  │ Zero-byte or tiny executable dropper          │ +8/+6                  │
  └───────────────────────────────────────────────┴────────────────────────┘

  Files in System32 / SysWOW64 / WinSxS have their score capped below the Malicious threshold to suppress false positives on
  legitimate system binaries.

  SHA-256 is also computed here from the shared buffer (no extra I/O).

  Layer 3.4 — Ember2024 ML (gated — only on Suspicious/Malicious)

  Only runs if layers 3.1–3.3 already flagged the file as Suspicious or Malicious.

  run_ember_ml(path)
    → find_ember_script()   // locates bridge.py relative to the exe
    → spawn: python bridge.py <path>
    → parse JSON from stdout

  bridge.py does:
  1. Pre-check extension — only .exe, .dll, .sys, .pdf, etc.
  2. Reads the file bytes once
  3. Calls thrember.features_from_file(data) — extracts ~2000 EMBER2024 features (PE sections, imports, strings, entropy
  histogram, byte histogram, header fields, etc.)
  4. Detects file type:
    - CLR header present → .NET model
    - COFF Machine = 0x8664 → Win64 model
    - Otherwise → Win32 model
    - Extension .pdf → PDF model
  5. Calls lightgbm_model.predict(vector) — returns a score between 0.0 and 1.0
  6. Prints { "file_type": "Win64", "score": 0.923, "malicious": true }

  Back in Rust:
  - If Ember score ≥ 0.8 and the verdict was Suspicious → escalates to Malicious
  - Ember score is blended into confidence_score
  - An ember_ml signal is added to detection_signals (visible in the expanded row in the UI)

  ---
  Layer 4 — Verdict and serialisation

  total_score ≥ 10  →  Malicious
  total_score ≥ 4   →  Suspicious
  else              →  Clean

  confidence_score:
    Clean      → 1.0
    Suspicious → 0.55 + (score / 40).min(0.25)  + ember blend
    Malicious  → 0.70 + (score / 60).min(0.25)  + ember blend

  The ScanResult struct is serialised to JSON by serialize_result() in main.rs and written as a single line to stdout.

  ---
  Layer 5 — Response travels back up

  daemon stdout → Tauri daemon_request() reads the line
                → parse_scan_result() maps JSON → ScanOutput
                → Tauri IPC returns ScanOutput to JavaScript

  store/index.ts  normalizeScanResult()  →  ScanResult[]
                → set({ scanResults, scanStats, lastScanDurationMs })

  Scanner.tsx   re-renders:
                → stats bar updates
                → ResultRow appears with level badge + chevron
                → expand row → see confidence bar, detection signals, Ember ML signal

  ---
  Full flow diagram

  User clicks SCAN FILE
          │
          ▼
    Scanner.tsx  →  store.scanFile(path)
          │
          ▼  [Tauri IPC]
    UI/src-tauri/main.rs  →  daemon stdin: {"cmd":"scan-file","path":"..."}
          │
          ▼  [JSON-RPC over pipes]
    Antivirus_Engine/main.rs  →  daemon_scan_file()
          │
          ▼
    FileSystemScanner::scan_file()
          │
          ├─ [3.1] Hash DB lookup ──────────────── known hash? → Malicious ✗ done
          │                                                               │
          ├─ [3.2] YARA rules ──────── score += 1–10 per rule             │
          │                                                               │
          ├─ [3.3] Heuristics ──────── score += entropy/keywords/         │
          │         (single file read)          ransomware/structure      │
          │                                                               │
          ├─ Decision: score ≥ 10 → Malicious                             │
          │            score ≥ 4  → Suspicious                            │
          │            else       → Clean ──────────────────── skip 3.4   │
          │                                                               │
          └─ [3.4] Ember2024 ML (only if not Clean)                       │
                   python bridge.py <path>                                │
                     thrember features → LightGBM model                   │
                     score ≥ 0.8 + was Suspicious → escalate Malicious    │
                                                                          │
          ◄───────────────────────────────────────────────────────────────┘
          ScanResult { level, reason, confidence_score, detection_signals }
          │
          ▼  [JSON on stdout]
    Tauri parses → ScanOutput
          │
          ▼  [Tauri IPC]
    store: scanResults updated
          │
          ▼
    Scanner.tsx re-renders result list

  ---
  Key design choices explained

  Daemon mode — YARA rules are compiled once at startup via wasmtime JIT. Compiling them on each request would take seconds.
  The daemon stays alive and reuses the same compiled state for every request.

  Single-read heuristics — The file is opened once, buffered into Vec<u8>, and all heuristic checks (magic bytes, entropy,
  content scan, SHA-256) run on that buffer. Previously each check opened the file independently — 4 I/O operations per file.

  YARA gating — YARA only runs on executable/script extensions, not on .txt, .csv, .pdf etc. Generic rules like
  contains_base64 fire on legitimate content constantly; restricting by extension cuts false positives significantly.

  Ember ML gating — Running a Python subprocess for every file would make directory scans unusable. By gating on
  Suspicious/Malicious, the subprocess only fires for files the Rust layers already flagged — typically a tiny fraction of a
  scan.

  Score-based fusion — There is no single oracle. YARA, heuristics, and Ember each contribute evidence. A file that scores +3
   from heuristics (Suspicious) but +0.92 from Ember is escalated to Malicious. A file that scores +11 from YARA is already
  Malicious before Ember even runs.




  ┌──────────────────┬──────────────────────────────────────────────────────────┐
  │   File content   │                          Result                          │
  ├──────────────────┼──────────────────────────────────────────────────────────┤
  │ Starts with MZ   │ → PE model (Win32/Win64/DotNet), regardless of extension │
  ├──────────────────┼──────────────────────────────────────────────────────────┤
  │ Starts with %PDF │ → PDF model, regardless of extension                     │
  ├──────────────────┼──────────────────────────────────────────────────────────┤
  │ Neither          │ → skipped with not_pe_or_pdf                             │
  └──────────────────┴──────────────────────────────────────────────────────────┘

  Concrete cases this fixes:
  - .tmp files that are actually PE droppers (common malware staging tactic)
  - .dat, .bin, .cache files used as renamed payloads
  - Any PE file with a misleading or missing extension

  Files that correctly stay skipped: .js, .ps1, .bat, .py, .zip, .txt — none of these start with MZ or %PDF, so they're still
   unsupported, which is correct since no EMBER2024 model covers them.
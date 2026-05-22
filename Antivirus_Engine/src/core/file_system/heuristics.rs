// File: src/core/file_system/heuristics.rs
// Unified Scoring Heuristic Engine
//
// Scoring table:
//   Base64 payload (script only, line >400B)  +1
//   High entropy >7.2 (executable only)       +2
//   Very high entropy >7.7                    +3  (was +4 at 7.5 — NSIS/7z-SFX hit 7.5–7.7 legitimately)
//   Suspicious keyword (scripts)              +3  per keyword, capped at +12
//   Suspicious keyword (PE exec, specific)    +2  per keyword, capped at +6  (generic API strings excluded)
//   PowerShell obfuscation                    +4
//   PE executable                             +1  (binary PE header in correct ext)
//   File type mismatch                        +3
//   Ransomware content phrase                 +5  per match, capped at +20
//   Crypto address detected                   +5
//   Zero-byte executable                      +8
//   Small executable dropper (<512B, .exe)    +4  (was +6 at 1KB — stub DLLs/SYS can be <1KB)
//   Ransomware filename pattern               +7
//   Malware filename pattern (exec)           +5
//   Ransomware extension                      +8
//   Double extension trick                    +4
//   Timestamp manipulation                    +1  (reduced — common on copied files)
//   Future timestamp                          +2
//
// Thresholds:
//   score >= 10  → MALICIOUS
//   score >= 5   → SUSPICIOUS  (raised from 4 — PE+entropy+base64 = 4, too easy to reach)
//   else         → CLEAN
//
// Optimizations applied:
//   • File is read once into a Vec<u8>; magic bytes, entropy, content
//     analysis, and SHA-256 all share that buffer — no repeated file opens.
//   • Extension is lowercased once in `analyze()` and passed as `&str`.
//   • Extension arrays are sorted; lookups use binary_search (O(log n)).
//   • Static arrays replace per-call stack allocations for bad-name lists.
//   • `check_content` uses raw bytes + from_utf8_lossy — no silent failure
//     on binary files and no extra heap copy for case folding.
//   • Lower-casing uses to_ascii_lowercase (byte-level, skips Unicode folding).
//   • `memmem` helper replaces String::contains for byte-slice search.
//   • `contains_base64_payload` is a single-pass byte scan.
//   • Scripts (.py, .sh, .rb, etc.) are included in ransomware/keyword checks.
//   • `primary_category` is a zero-cost enum (no heap allocation).
//   • signal_source fields are &'static str (no per-signal String allocation).

use crate::core::types::{DetectionSignal, FileCategory, ScanResult, ThreatLevel};
use crate::core::utils::{compute_sha256, compute_sha256_from_bytes, calculate_entropy, is_pe_file};
use std::path::Path;
use std::fs::{self, File};
use std::io::Read;
use anyhow::Result;

// ─── Thresholds ───────────────────────────────────────────────────────────────

const MALICIOUS_THRESHOLD: i32 = 10;
const SUSPICIOUS_THRESHOLD: i32 = 5;
const MAX_CONTENT_SCAN_BYTES: usize = 10 * 1024 * 1024; // 10 MiB

// ─── Path trust tiers ─────────────────────────────────────────────────────────
//
// Mirrors the memory scanner's SystemOs / TrustedInstall model.  Files in
// known Microsoft system directories accumulate enough heuristic signal from
// ordinary PE structure and entropy to breach the Malicious threshold even
// though they are completely legitimate.  The cap prevents false positives
// without disabling detection entirely — a genuinely suspicious signal set
// can still produce a Suspicious verdict.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PathTrustTier {
    /// `C:\Windows\System32` and `C:\Windows\SysWOW64` — score capped below
    /// `MALICIOUS_THRESHOLD` so that normal kernel-mode / system files cannot
    /// be reported as Malicious on heuristics alone.
    TrustedSystem,
    /// `C:\Windows\WinSxS` and `C:\Windows\Installer` — same cap as
    /// `TrustedSystem`; component-store and installer payloads are similarly
    /// noisy but legitimate.
    TrustedInstall,
    /// All other paths — full heuristic scoring applies.
    Unknown,
}

/// Map a file path to its trust tier.
///
/// Case-insensitive prefix match; the lowercased path string is checked against
/// known Windows system directory fragments.  Non-Windows builds always return
/// `Unknown`.
#[cfg(windows)]
fn path_trust_tier(path: &Path) -> PathTrustTier {
    let s = path.to_string_lossy().to_ascii_lowercase();
    if s.contains(r"windows\system32") || s.contains(r"windows\syswow64") {
        return PathTrustTier::TrustedSystem;
    }
    if s.contains(r"windows\winsxs") || s.contains(r"windows\installer") {
        return PathTrustTier::TrustedInstall;
    }
    // Rust compiler proc-macro staging dirs and Cargo registry — compiler internals.
    if s.contains("proc-macro-srv") || s.contains(r".cargo\registry") {
        return PathTrustTier::TrustedInstall;
    }
    // Package manager / dependency caches — pre-built artefacts, not user code.
    // node_modules binaries, NuGet packages, and Chocolatey installs are signed
    // upstream; treating them like Unknown generates large numbers of false positives.
    if s.contains("node_modules")
        || s.contains(r".nuget\packages")
        || s.contains(r"chocolatey\lib")
    {
        return PathTrustTier::TrustedInstall;
    }
    // Vendor-installed software in Program Files — full scoring still applies inside
    // these directories; we only cap at TrustedInstall level so that a legitimately
    // packed installer (NSIS, Inno, 7z-SFX) cannot tip into Malicious on entropy
    // alone without a second corroborating signal.
    if s.contains(r"program files\") || s.contains(r"program files (x86)\") {
        return PathTrustTier::TrustedInstall;
    }
    PathTrustTier::Unknown
}

#[cfg(not(windows))]
#[inline]
fn path_trust_tier(_path: &Path) -> PathTrustTier {
    PathTrustTier::Unknown
}

// ─── Extension tables (MUST remain sorted — binary_search depends on order) ──

/// Text/document extensions — sorted ASCII.
const DOCUMENT_EXTENSIONS: &[&str] = &[
    "cfg", "csv", "doc", "docx", "htm", "html", "ini",
    "json", "log", "md", "pdf", "rst", "toml", "txt",
    "xls", "xlsx", "xml", "yaml", "yml",
];

/// Windows executable/script extensions — sorted ASCII.
const EXECUTABLE_EXTENSIONS: &[&str] = &[
    "bat", "cmd", "com", "cpl", "dll", "drv", "exe",
    "js", "jse", "msi", "msp", "ocx", "pif",
    "ps1", "scr", "sys", "vbe", "vbs", "wsf", "wsh",
];

/// Interpreted script extensions (not Windows execs, not documents) — sorted.
/// These can carry ransomware logic and must not be skipped by content checks.
const SCRIPT_EXTENSIONS: &[&str] = &[
    "lua", "php", "pl", "py", "rb", "sh",
];

#[inline] fn is_document_ext(ext: &str)   -> bool { DOCUMENT_EXTENSIONS.binary_search(&ext).is_ok() }
#[inline] fn is_executable_ext(ext: &str) -> bool { EXECUTABLE_EXTENSIONS.binary_search(&ext).is_ok() }
#[inline] fn is_script_ext(ext: &str)     -> bool { SCRIPT_EXTENSIONS.binary_search(&ext).is_ok() }

// ─── Ransomware content phrases ───────────────────────────────────────────────
// Full phrases only — single words like "decrypt", "ransom", "aes-256"
// are too common in security textbooks and ML course notes.

const RANSOMWARE_CONTENT: &[&str] = &[
    "your files have been encrypted",
    "all your files have been",
    "pay bitcoin",
    "pay btc",
    "send bitcoin",
    "to decrypt your files",
    "to recover your files",
    "your decryption key",
    "contact us to recover",
    "files are encrypted",
    "pay the ransom",
    "ransom demand",
    "purchase decryption",
    "bitcoin address",
    "monero address",
];

// ─── Suspicious keywords ──────────────────────────────────────────────────────
//
// Two tiers:
//
//  SUSPICIOUS_KEYWORDS_EXEC — used only for PE binary executables.
//    These are specific obfuscation patterns that have no legitimate reason to
//    appear as strings inside a compiled binary's string table.  Generic Windows
//    API names (CreateRemoteThread, WriteProcessMemory, curl_easy_setopt, eval)
//    are excluded because they appear in import tables of debuggers, libcurl
//    users, and COM-based apps without any malicious intent.
//    Score: +2 per hit, capped at +6.
//
//  SUSPICIOUS_KEYWORDS_SCRIPT — used for interpreted script files (.ps1, .vbs,
//    .bat, .js, .py, etc.).  In script context, all keywords are live code, not
//    strings in a binary — the full list applies at higher weight.
//    Score: +3 per hit, capped at +12.

/// High-confidence keywords for PE binary string-table scanning.
/// Only patterns that are specific to obfuscation / in-memory loading.
const SUSPICIOUS_KEYWORDS_EXEC: &[&str] = &[
    "-encodedcommand",
    "bitstransfer",
    "frombase64string",
    "iex(",
    "invoke-expression",
    "reflection.assembly",
];

/// Full keyword set for script files — every hit is live executable code.
const SUSPICIOUS_KEYWORDS_SCRIPT: &[&str] = &[
    "-enc ",
    "-encodedcommand",
    "bitstransfer",
    "createobject",
    "createremotethread",
    "curl_exec",
    "downloadfile",
    "downloadstring",
    "eval(",
    "frombase64string",
    "iex(",
    "invoke-expression",
    "net.webclient",
    "powershell",
    "reflection.assembly",
    "writeprocessmemory",
    "wscript.shell",
];
// Removed from both lists (too broad — appear in normal PE import tables or are
// universal low-level primitives):
//   "cmd.exe"          — standard shell path referenced by countless installers
//   "shellexecute"     — Windows shell API, normal in GUI apps and installers
//   "virtualalloc"     — Windows memory API, normal in every game / runtime
//   "wget"             — common download tool, appears in many build scripts
//   "curl_easy_setopt" — libcurl import, extremely common in network apps

// ─── Static name tables ───────────────────────────────────────────────────────

/// Substrings that identify ransomware note filenames (paired with doc extensions).
static RANSOMWARE_FILENAMES: &[&str] = &[
    "!!!",
    "decrypt_files",
    "decrypt_instructions",
    "encrypted",
    "files_encrypted",
    "how-to-decrypt",
    "how_to_decrypt",
    "howto_decrypt",
    "howto_recover",
    "locked",
    "ransom",
    "ransom_note",
    "read-me",
    "read_me",
    "recovery_instructions",
    "your_files_encrypted",
];

/// Substrings that identify malware-named executables.
///
/// Removed intentionally — too broad:
///   "crypt"   — matches bcrypt.dll, decryptor, winrar-crypt, cryptsetup
///   "virus"   — matches antivirus, virustotal, virus_definitions
///   "dropper" — matches eyedropper (colour-picker tools), update-dropper
static MALWARE_FILENAMES: &[&str] = &[
    "backdoor", "coinminer", "crypter", "exploit",
    "injector", "keylogger", "payload", "ransomware",
    "remoteadmintool", "stealer", "trojan", "worm",
];

/// Known ransomware file extensions.
static RANSOMWARE_EXTENSIONS: &[&str] = &[
    "cerber", "crypt", "crypted", "cryptolocker",
    "enc", "encrypted", "locky", "locked",
    "maze", "petya", "revil", "ryuk",
    "thor", "wannacry", "wncry", "wncryt", "zepto",
];

// ─── Internal types ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
enum ThreatCategory {
    Malware,
    Ransomware,
    Wiper,
}

impl ThreatCategory {
    #[inline]
    fn as_str(self) -> &'static str {
        match self {
            Self::Malware    => "Malware",
            Self::Ransomware => "Ransomware",
            Self::Wiper      => "Wiper",
        }
    }
}

struct ScoreContribution {
    score:         i32,
    reason:        String,
    signal_source: &'static str,
}

impl ScoreContribution {
    #[inline]
    fn new(score: i32, reason: impl Into<String>, source: &'static str) -> Self {
        Self { score, reason: reason.into(), signal_source: source }
    }
}

// ─── Analyzer ─────────────────────────────────────────────────────────────────

pub struct HeuristicAnalyzer;

impl HeuristicAnalyzer {
    pub fn new() -> Self { Self }

    /// Fast triage score — extension, filename, extension anomalies, magic bytes,
    /// and entropy only.  No content scan (no keyword / phrase search).
    ///
    /// Runs at ~5 000 files/sec per thread.  Files scoring below
    /// `SUSPICIOUS_THRESHOLD` (4) are almost certainly clean and skip the
    /// expensive YARA + full-content pass in `parallel_scan`.
    ///
    /// Returns the raw integer score (same scale as `analyze`).
    pub fn fast_score(path: &Path, file_size: u64, bytes: &[u8]) -> i32 {
        let ext_owned: String = path.extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase())
            .unwrap_or_default();
        let ext    = ext_owned.as_str();
        let is_doc  = is_document_ext(ext);
        let is_exec = is_executable_ext(ext);

        let mut score: i32 = 0;

        if let Some(c) = check_zero_byte(ext, file_size) { score += c.score; }
        if let Some(c) = check_filename(path, ext, is_exec) { score += c.score; }
        if let Some(c) = check_extension(path, ext, is_doc) { score += c.score; }
        if bytes.len() >= 2 {
            if let Some(c) = check_magic_bytes(bytes, ext, is_doc) { score += c.score; }
        }
        if is_exec && file_size > 100 && !bytes.is_empty() {
            if let Some(c) = check_entropy(bytes) { score += c.score; }
        }
        // Intentionally omits check_content and check_timestamps — those are
        // the slow paths; we run them only when fast_score >= threshold.
        score
    }

    /// Full analysis from **pre-read bytes** — avoids a second `fs::read` when
    /// the caller already holds the file buffer (e.g. from the single-read
    /// optimisation in `parallel_scan`).
    ///
    /// Semantically identical to `analyze(path)` but takes `bytes` and
    /// `file_size` instead of opening the file internally.
    pub fn analyze_from_bytes(
        &self,
        path: &Path,
        bytes: &[u8],
        file_size: u64,
    ) -> Result<(ScanResult, i32)> {
        self.analyze_impl(path, bytes, file_size)
    }

    /// Returns `(ScanResult, total_score)` so callers can add the score into a
    /// unified multi-layer total without re-parsing the reason string.
    pub fn analyze(&self, path: &Path) -> Result<(ScanResult, i32)> {
        let metadata  = fs::metadata(path)?;
        let file_size = metadata.len();

        // Read file once; all byte-level checks share this buffer.
        // Files > 10 MiB are skipped for content analysis.
        let file_bytes: Vec<u8> = if file_size > 0 && file_size as usize <= MAX_CONTENT_SCAN_BYTES {
            read_file_bytes(path, MAX_CONTENT_SCAN_BYTES).unwrap_or_default()
        } else {
            Vec::new()
        };

        let (result, score) = self.analyze_impl(path, &file_bytes, file_size)?;

        // Timestamp check needs fs::metadata — only available in this path.
        // (analyze_impl skips it when called from analyze_from_bytes.)
        if let Some(c) = check_timestamps(&metadata) {
            // Patch the score and reason into the result that analyze_impl built.
            // Simpler than threading metadata through analyze_impl.
            let _ = c; // timestamp signal is low-value; already included via analyze_impl below
        }

        Ok((result, score))
    }

    // ── Private shared implementation ─────────────────────────────────────────

    /// Full analysis over pre-read `bytes` (may be empty for files > 10 MiB).
    /// Called by both `analyze()` and `analyze_from_bytes()`.
    fn analyze_impl(
        &self,
        path: &Path,
        bytes: &[u8],
        file_size: u64,
    ) -> Result<(ScanResult, i32)> {
        let file_category = FileCategory::from_path(path);

        // ── Extension — computed once, passed everywhere ───────────────────────
        let ext_owned: String = path.extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase())
            .unwrap_or_default();
        let ext = ext_owned.as_str();

        let is_doc    = is_document_ext(ext);
        let is_exec   = is_executable_ext(ext);
        let is_script = is_script_ext(ext);

        let mut total_score: i32  = 0;
        let mut contributions: Vec<ScoreContribution> = Vec::new();
        let mut primary_category  = ThreatCategory::Malware;

        // ── Check 1: Zero-byte / tiny executable ─────────────────────────────
        if let Some(c) = check_zero_byte(ext, file_size) {
            total_score += c.score;
            contributions.push(c);
            primary_category = ThreatCategory::Wiper;
        }

        // ── Check 2: Filename patterns ────────────────────────────────────────
        if let Some(c) = check_filename(path, ext, is_exec) {
            total_score += c.score;
            if c.score >= 7 { primary_category = ThreatCategory::Ransomware; }
            contributions.push(c);
        }

        // ── Check 3: Extension anomalies ──────────────────────────────────────
        if let Some(c) = check_extension(path, ext, is_doc) {
            total_score += c.score;
            if c.score >= 8 { primary_category = ThreatCategory::Ransomware; }
            contributions.push(c);
        }

        // ── Check 4: Magic bytes — from buffer ────────────────────────────────
        if bytes.len() >= 2 {
            if let Some(c) = check_magic_bytes(bytes, ext, is_doc) {
                total_score += c.score;
                contributions.push(c);
            }
        }

        // ── Check 5: Entropy — executables only, from buffer ─────────────────
        if is_exec && file_size > 100 && !bytes.is_empty() {
            if let Some(c) = check_entropy(bytes) {
                total_score += c.score;
                contributions.push(c);
            }
        }

        // ── Check 6: Content analysis — from buffer ───────────────────────────
        if !bytes.is_empty() {
            for c in check_content(bytes, is_doc, is_exec, is_script) {
                total_score += c.score;
                contributions.push(c);
            }
        }

        // ── Check 7: Timestamps (best-effort — metadata not always available) ─
        // When called from analyze_from_bytes the metadata may have been read
        // already by the caller (scan_all).  Attempt it here; failure is silent.
        if let Ok(meta) = fs::metadata(path) {
            if let Some(c) = check_timestamps(&meta) {
                total_score += c.score;
                contributions.push(c);
            }
        }

        // ── Trust tier cap ────────────────────────────────────────────────────
        if path_trust_tier(path) != PathTrustTier::Unknown {
            total_score = total_score.min(MALICIOUS_THRESHOLD - 1);
        }

        // ── Decision ──────────────────────────────────────────────────────────
        let level = if total_score >= MALICIOUS_THRESHOLD {
            ThreatLevel::Malicious
        } else if total_score >= SUSPICIOUS_THRESHOLD {
            ThreatLevel::Suspicious
        } else {
            ThreatLevel::Clean
        };

        let confidence_score = match level {
            ThreatLevel::Clean      => 1.0,
            ThreatLevel::Suspicious => 0.55 + (total_score as f32 / 40.0).min(0.25),
            ThreatLevel::Malicious  => 0.70 + (total_score as f32 / 60.0).min(0.25),
        };

        let signature = if level != ThreatLevel::Clean {
            Some(format!("Behavioral.{}.{}",
                primary_category.as_str(),
                if level == ThreatLevel::Malicious { "Detected" } else { "Suspected" },
            ))
        } else {
            None
        };

        let reason = if contributions.is_empty() {
            "No threats detected (multi-layer scan)".to_string()
        } else {
            format!("Dynamic analysis (score: {}): {}",
                total_score,
                contributions.iter().map(|c| c.reason.as_str()).collect::<Vec<_>>().join("; "))
        };

        let detection_signals: Vec<DetectionSignal> = contributions.iter()
            .map(|c| DetectionSignal::new(
                c.signal_source.to_string(),
                c.reason.clone(),
                c.score,
            ))
            .collect();

        // SHA-256 from shared buffer for small files; streaming fallback for large.
        let hash = if !bytes.is_empty() {
            Some(compute_sha256_from_bytes(bytes))
        } else {
            compute_sha256(path).ok()
        };

        Ok((ScanResult {
            path: path.to_path_buf(),
            level,
            reason,
            hash,
            signature,
            confidence_score,
            detection_signals,
            file_category,
            context_flags: vec![],
        }, total_score))
    }
}

impl Default for HeuristicAnalyzer {
    fn default() -> Self { Self::new() }
}

// ─── Free check functions ─────────────────────────────────────────────────────
// Free (non-method) functions avoid `&self` parameter overhead and borrow
// conflicts when called from closures or other free functions in this module.

fn read_file_bytes(path: &Path, max: usize) -> std::io::Result<Vec<u8>> {
    let file = File::open(path)?;
    let mut buf = Vec::new();
    file.take(max as u64).read_to_end(&mut buf)?;
    Ok(buf)
}

fn check_zero_byte(ext: &str, file_size: u64) -> Option<ScoreContribution> {
    if file_size == 0 && is_executable_ext(ext) {
        return Some(ScoreContribution::new(
            8,
            "Zero-byte executable (data destruction indicator)",
            "metadata",
        ));
    }
    // Threshold tightened: 1KB → 512B, exe-only (was exe|dll|sys), +4 (was +6).
    // Stub DLLs (COM forwarding stubs, API-set shims) and minimal SYS drivers are
    // commonly under 1KB.  Dropper pattern is most relevant for standalone .exe files
    // that are too small to contain any real payload of their own.
    if file_size < 512 && file_size > 0 && ext == "exe" {
        return Some(ScoreContribution::new(
            4,
            format!("Unusually small executable ({}B — possible dropper stub)", file_size),
            "metadata",
        ));
    }
    None
}

fn check_filename(path: &Path, ext: &str, is_exec: bool) -> Option<ScoreContribution> {
    let name = path.file_name()?.to_str()?.to_ascii_lowercase();

    // Ransomware note filenames — compound phrases only.
    // Single words ("readme", "decrypt", "howto") excluded — appear in legitimate files.
    if matches!(ext, "txt" | "html" | "htm" | "hta") {
        for pattern in RANSOMWARE_FILENAMES {
            if name.contains(pattern) {
                return Some(ScoreContribution::new(
                    7,
                    format!("Ransomware note filename pattern: '{}'", pattern),
                    "filename",
                ));
            }
        }
    }

    // Malware-named executables.
    // Broad single words ("rat", "inject", "miner") excluded — match too broadly.
    if is_exec {
        for pattern in MALWARE_FILENAMES {
            if name.contains(pattern) {
                return Some(ScoreContribution::new(
                    5,
                    format!("Malware pattern in filename: '{}'", pattern),
                    "filename",
                ));
            }
        }
    }

    None
}

fn check_extension(path: &Path, ext: &str, is_doc: bool) -> Option<ScoreContribution> {
    for r_ext in RANSOMWARE_EXTENSIONS {
        if ext == *r_ext {
            return Some(ScoreContribution::new(
                8,
                format!("Known ransomware file extension: .{}", r_ext),
                "extension",
            ));
        }
    }

    // Double extension trick: document.pdf.exe
    if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
        if stem.contains('.') {
            if let Some(inner_ext) = stem.rsplit('.').next() {
                let inner = inner_ext.to_ascii_lowercase();
                if is_document_ext(&inner) && matches!(ext, "exe" | "scr" | "bat" | "cmd") {
                    return Some(ScoreContribution::new(
                        4,
                        format!("Double extension disguise: .{}.{}", inner, ext),
                        "extension",
                    ));
                }
            }
        }
    }

    let _ = is_doc; // reserved for future content-vs-extension cross-checks
    None
}

/// Detect PE header from the in-memory buffer — no file I/O.
fn check_magic_bytes(bytes: &[u8], ext: &str, is_doc: bool) -> Option<ScoreContribution> {
    if !is_pe_file(bytes) { return None; }

    if is_doc {
        return Some(ScoreContribution::new(
            3,
            format!("PE executable content in .{} file (type mismatch)", ext),
            "structure",
        ));
    }

    if matches!(ext, "exe" | "dll" | "sys" | "scr") {
        // +1 only — being a valid PE is not a threat signal on its own.
        // The old +3 combined with entropy alone pushed legitimate packed
        // installers (NSIS, 7z-SFX) over the Malicious threshold.
        return Some(ScoreContribution::new(1, "PE executable", "structure"));
    }

    None
}

/// Entropy check from in-memory buffer — no file I/O.
///
/// Threshold raised from 7.5 → 7.7 for the high-score band:
/// NSIS, Inno Setup, and 7z self-extracting archives routinely sit at 7.5–7.7
/// (compressed payload inside a signed launcher).  Genuine packers/crypters
/// push past 7.7.  Lowering the false-positive floor here prevents packed
/// legitimate installers from being flagged on entropy alone.
fn check_entropy(bytes: &[u8]) -> Option<ScoreContribution> {
    let entropy = calculate_entropy(bytes);
    if entropy > 7.7 {
        Some(ScoreContribution::new(
            3,
            format!("Very high entropy ({:.2}) — packed/crypted", entropy),
            "entropy",
        ))
    } else if entropy > 7.2 {
        Some(ScoreContribution::new(
            2,
            format!("High entropy ({:.2}) — possibly packed", entropy),
            "entropy",
        ))
    } else {
        None
    }
}

/// Content analysis — all checks operate on the shared byte buffer.
///
/// Key improvements over the old approach:
/// - No `read_to_string` → works on binary files (no silent bail-out).
/// - No `to_lowercase()` String allocation → single `to_ascii_lowercase` byte pass.
/// - No re-opening the file.
/// - Scripts (.py, .sh, .rb, .pl) are now included in phrase/keyword checks.
fn check_content(
    bytes:     &[u8],
    is_doc:    bool,
    is_exec:   bool,
    is_script: bool,
) -> Vec<ScoreContribution> {
    let mut out = Vec::new();

    // Build a lowercase byte slice once.  to_ascii_lowercase skips Unicode
    // folding — correct for all our purely ASCII search patterns.
    let lower: Vec<u8> = bytes.iter().map(|b| b.to_ascii_lowercase()).collect();

    // ── Ransomware phrases — documents, executables, and scripts ─────────────
    if is_doc || is_exec || is_script {
        let mut score = 0i32;
        let mut hits: Vec<&str> = Vec::new();
        for phrase in RANSOMWARE_CONTENT {
            if memmem(&lower, phrase.as_bytes()) {
                score += 5;
                hits.push(phrase);
                if score >= 20 { break; }
            }
        }
        if score > 0 {
            out.push(ScoreContribution::new(
                score,
                format!("Ransomware content phrases: {}", hits.join(", ")),
                "content",
            ));
        }
    }

    // ── Crypto wallet address ─────────────────────────────────────────────────
    // Entropy-gated: matches inside dense binary/crypto data (local entropy >6.5
    // bits/byte in a ±128-byte window) are suppressed to avoid false positives on
    // TLS / ASN.1 library DLLs whose DER byte sequences resemble wallet addresses.
    //
    // Additionally skip binary PE executables — packed installers (FitGirl, DODI,
    // NSIS, Squirrel) commonly embed a donation BTC address in their about section.
    // A donation address inside a binary is not a malicious signal; it only becomes
    // meaningful when found alongside ransomware phrases in a document or script.
    if !is_exec && contains_crypto_address(bytes) {
        out.push(ScoreContribution::new(5, "Cryptocurrency wallet address detected", "content"));
    }

    // ── Script files — full keyword list, higher weight ───────────────────────
    if is_script {
        let mut kw_score = 0i32;
        let mut kw_hits: Vec<&str> = Vec::new();
        for kw in SUSPICIOUS_KEYWORDS_SCRIPT {
            if memmem(&lower, kw.as_bytes()) {
                kw_score += 3;
                kw_hits.push(kw);
                if kw_score >= 12 { break; }
            }
        }
        if kw_score > 0 {
            out.push(ScoreContribution::new(
                kw_score,
                format!("Suspicious script keywords: {}", kw_hits.join(", ")),
                "keyword",
            ));
        }

        // Base64 payload in scripts — threshold raised to 400B to avoid false
        // positives on embedded certificates and icon data in resource scripts.
        if contains_base64_payload(bytes) {
            out.push(ScoreContribution::new(1, "Base64 encoded payload detected", "obfuscation"));
        }

        // PowerShell obfuscation (requires 2+ patterns)
        if contains_powershell_obfuscation(&lower) {
            out.push(ScoreContribution::new(
                4,
                "PowerShell obfuscation techniques detected",
                "obfuscation",
            ));
        }
    }

    // ── PE binary executables — specific obfuscation keywords only ────────────
    // Generic Windows API names (CreateRemoteThread, WriteProcessMemory, curl_*)
    // are excluded because they appear in import tables of legitimate debuggers,
    // libcurl consumers, and COM-based applications without malicious intent.
    // Score is +2/hit (not +3) because string-table hits are weaker than live code.
    if is_exec {
        let mut kw_score = 0i32;
        let mut kw_hits: Vec<&str> = Vec::new();
        for kw in SUSPICIOUS_KEYWORDS_EXEC {
            if memmem(&lower, kw.as_bytes()) {
                kw_score += 2;
                kw_hits.push(kw);
                if kw_score >= 6 { break; }
            }
        }
        if kw_score > 0 {
            out.push(ScoreContribution::new(
                kw_score,
                format!("Suspicious strings in PE binary: {}", kw_hits.join(", ")),
                "keyword",
            ));
        }

        // PowerShell obfuscation patterns embedded in PE — also meaningful for
        // droppers that bundle encoded PS scripts in their resource section.
        if contains_powershell_obfuscation(&lower) {
            out.push(ScoreContribution::new(
                4,
                "PowerShell obfuscation patterns embedded in PE",
                "obfuscation",
            ));
        }
    }

    out
}

fn check_timestamps(metadata: &fs::Metadata) -> Option<ScoreContribution> {
    use std::time::SystemTime;

    let modified = metadata.modified().ok()?;
    let created  = metadata.created().ok()?;

    // Reduced to +1 — very common on legitimately copied files.
    // Alone it must never reach the Suspicious threshold (4).
    if modified < created {
        return Some(ScoreContribution::new(
            1,
            "Timestamp: modified < created (common on copied files)",
            "timestamp",
        ));
    }

    if let Ok(dur) = modified.duration_since(SystemTime::UNIX_EPOCH) {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if dur.as_secs() > now + 365 * 24 * 3600 {
            return Some(ScoreContribution::new(2, "Suspicious future timestamp", "timestamp"));
        }
    }

    None
}

// ─── Byte-level helpers ───────────────────────────────────────────────────────

/// Byte-slice substring search (Boyer-Moore-like window scan).
/// Needle must already be in the same case as the haystack (both lowercased).
#[inline]
fn memmem(haystack: &[u8], needle: &[u8]) -> bool {
    let nlen = needle.len();
    if nlen == 0 { return true; }
    if haystack.len() < nlen { return false; }
    haystack.windows(nlen).any(|w| w == needle)
}

/// Detect a Bitcoin or Ethereum wallet address in a raw byte buffer.
///
/// Entropy-gated: a candidate match is only reported when the local Shannon
/// entropy of the ±128-byte window around the match is ≤ 6.5 bits/byte.
/// Dense binary/crypto data (DER, ASN.1, compressed sections) always exceeds
/// this threshold, so hex sequences that merely resemble addresses are silently
/// suppressed, eliminating the class of false positives on TLS library DLLs.
fn contains_crypto_address(bytes: &[u8]) -> bool {
    // ETH: 0x followed by exactly 40 hex digits
    if bytes.windows(42).enumerate().any(|(pos, w)| {
        w.starts_with(b"0x")
            && w[2..].iter().all(|b| b.is_ascii_hexdigit())
            && local_entropy_around(bytes, pos, 42) <= 6.5f64
    }) {
        return true;
    }

    // BTC: whitespace-delimited token, 26–35 bytes, starts with '1', '3', or "bc1"
    let mut i = 0usize;
    while i < bytes.len() {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() { i += 1; }
        let start = i;
        while i < bytes.len() && !bytes[i].is_ascii_whitespace() { i += 1; }
        let token = &bytes[start..i];
        let len = token.len();
        if (26..=35).contains(&len) {
            let is_btc = token[0] == b'1' || token[0] == b'3' || token.starts_with(b"bc1");
            if is_btc && local_entropy_around(bytes, start, len) <= 6.5f64 {
                return true;
            }
        }
    }

    false
}

/// Shannon entropy of a ±128-byte window centred on `bytes[pos .. pos+len]`.
#[inline]
fn local_entropy_around(bytes: &[u8], pos: usize, len: usize) -> f64 {
    let window_start = pos.saturating_sub(128);
    let window_end   = (pos + len + 128).min(bytes.len());
    calculate_entropy(&bytes[window_start..window_end])
}

/// Single-pass Base64 payload detector operating directly on bytes.
///
/// Returns `true` if any line is >400 bytes long and consists entirely of
/// Base64 characters (A-Z, a-z, 0-9, +, /) with at most 2 trailing `=`.
/// Threshold raised from 200 → 400: PEM certificates, embedded icons, and
/// base64-encoded config values in resource scripts routinely produce 200–400
/// character lines and would otherwise generate false positives.
fn contains_base64_payload(bytes: &[u8]) -> bool {
    for line in bytes.split(|&b| b == b'\n') {
        let t = trim_ascii(line);
        if t.len() <= 400 { continue; }
        let mut eq_count: usize = 0;
        let mut valid = true;
        for &b in t {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' => {}
                b'=' => {
                    eq_count += 1;
                    if eq_count > 2 { valid = false; break; }
                }
                _ => { valid = false; break; }
            }
        }
        if valid { return true; }
    }
    false
}

/// Strip leading and trailing ASCII whitespace from a byte slice.
#[inline]
fn trim_ascii(b: &[u8]) -> &[u8] {
    let start = b.iter().position(|c| !c.is_ascii_whitespace()).unwrap_or(b.len());
    let end = b.iter().rposition(|c| !c.is_ascii_whitespace()).map(|i| i + 1).unwrap_or(0);
    if start >= end { &[] } else { &b[start..end] }
}

/// PowerShell obfuscation heuristic — requires 2+ distinct patterns.
/// Operates on pre-lowercased bytes to avoid re-allocating.
fn contains_powershell_obfuscation(lower: &[u8]) -> bool {
    const PATTERNS: &[&[u8]] = &[
        b"-enc",
        b"-encodedcommand",
        b"invoke-expression",
        b"iex(",
        b"bitstransfer",
        b"reflection.assembly",
        b"[convert]::frombase64string",
    ];
    PATTERNS.iter().filter(|p| memmem(lower, p)).count() >= 2
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_ransomware_note_malicious() {
        let path = std::env::temp_dir().join("RANSOM_heuristic_test.txt");
        let mut f = File::create(&path).unwrap();
        writeln!(f, "All your files have been encrypted.").unwrap();
        writeln!(f, "Pay bitcoin to recover your files.").unwrap();
        writeln!(f, "Your decryption key will be deleted.").unwrap();
        let (result, _score) = HeuristicAnalyzer::new().analyze(&path).unwrap();
        assert!(result.level != ThreatLevel::Clean,
            "Ransomware note should be flagged. Reason: {}", result.reason);
        assert!(!result.detection_signals.is_empty());
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_ml_notes_clean() {
        let path = std::env::temp_dir().join("ml_heuristic_test.txt");
        std::fs::write(&path,
            "Batch Normalization: Standardizes outputs of each layer for stability. \
             Not strictly a regularizer, but often has a regularization effect. \
             Neural network-HowTo: gradient descent optimizer learning rate epoch."
        ).unwrap();
        let (result, _score) = HeuristicAnalyzer::new().analyze(&path).unwrap();
        assert_eq!(result.level, ThreatLevel::Clean,
            "ML notes wrongly flagged: {}", result.reason);
        assert_eq!(result.file_category, FileCategory::Document);
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_howto_filename_clean() {
        let path = std::env::temp_dir().join("Neural network-HowTo.txt");
        std::fs::write(&path, "Tutorial on neural networks.").unwrap();
        let (result, _score) = HeuristicAnalyzer::new().analyze(&path).unwrap();
        assert_eq!(result.level, ThreatLevel::Clean,
            "HowTo filename wrongly flagged: {}", result.reason);
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_signals_populated() {
        let path = std::env::temp_dir().join("signal_test_ransom.txt");
        std::fs::write(&path, "pay bitcoin to decrypt your files ransom demand").unwrap();
        let (result, _score) = HeuristicAnalyzer::new().analyze(&path).unwrap();
        if result.level != ThreatLevel::Clean {
            assert!(!result.detection_signals.is_empty(),
                "Flagged file should have detection signals");
        }
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_confidence_score_range() {
        let path = std::env::temp_dir().join("confidence_test.txt");
        std::fs::write(&path, "normal content").unwrap();
        let (result, _score) = HeuristicAnalyzer::new().analyze(&path).unwrap();
        assert!(result.confidence_score >= 0.0 && result.confidence_score <= 1.0);
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_zero_byte_exe() {
        let path = std::env::temp_dir().join("zero_heuristic2.exe");
        std::fs::write(&path, "").unwrap();
        let (result, _score) = HeuristicAnalyzer::new().analyze(&path).unwrap();
        assert!(result.level != ThreatLevel::Clean);
        assert_eq!(result.file_category, FileCategory::Executable);
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_timestamp_alone_not_suspicious() {
        let path = std::env::temp_dir().join("timestamp_alone.txt");
        std::fs::write(&path, "Clean content.").unwrap();
        let (result, _score) = HeuristicAnalyzer::new().analyze(&path).unwrap();
        assert_eq!(result.level, ThreatLevel::Clean,
            "Timestamp alone should not flag: {}", result.reason);
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_extension_arrays_sorted() {
        // Verify that binary_search preconditions are met.
        let doc_ok  = DOCUMENT_EXTENSIONS.windows(2).all(|w| w[0] <= w[1]);
        let exec_ok = EXECUTABLE_EXTENSIONS.windows(2).all(|w| w[0] <= w[1]);
        let scr_ok  = SCRIPT_EXTENSIONS.windows(2).all(|w| w[0] <= w[1]);
        assert!(doc_ok,  "DOCUMENT_EXTENSIONS is not sorted");
        assert!(exec_ok, "EXECUTABLE_EXTENSIONS is not sorted");
        assert!(scr_ok,  "SCRIPT_EXTENSIONS is not sorted");
    }

    #[test]
    fn test_binary_extensions_detected() {
        assert!(is_executable_ext("exe"));
        assert!(is_executable_ext("dll"));
        assert!(is_executable_ext("ps1"));
        assert!(!is_executable_ext("txt"));
        assert!(is_document_ext("pdf"));
        assert!(is_document_ext("docx"));
        assert!(!is_document_ext("exe"));
        assert!(is_script_ext("py"));
        assert!(is_script_ext("sh"));
        assert!(!is_script_ext("exe"));
    }

    #[test]
    fn test_base64_payload_detection() {
        // A long base64-like line (>400B) should be detected
        let b64_line = "A".repeat(401);
        assert!(contains_base64_payload(b64_line.as_bytes()));
        // Lines ≤400B should not trigger (PEM certs, embedded icons are typically shorter)
        let short_b64 = "A".repeat(300);
        assert!(!contains_base64_payload(short_b64.as_bytes()));
        // Short line should not trigger
        assert!(!contains_base64_payload(b"short"));
        // Non-base64 chars should not trigger even if long
        let bad_line = format!("{}!", "A".repeat(401));
        assert!(!contains_base64_payload(bad_line.as_bytes()));
    }

    #[test]
    fn test_memmem() {
        assert!(memmem(b"hello world", b"world"));
        assert!(!memmem(b"hello", b"world"));
        assert!(memmem(b"abc", b""));
    }
}

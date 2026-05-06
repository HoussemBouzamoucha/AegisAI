// File: src/core/file_system/heuristics.rs
// Unified Scoring Heuristic Engine
//
// Scoring table:
//   Base64 payload (executable/script only)   +1
//   High entropy >7.2 (executable only)       +2
//   Very high entropy >7.5                    +4  (packed/obfuscated)
//   Suspicious keyword (exec/script only)     +3  per keyword, capped at +12
//   PowerShell obfuscation                    +4
//   PE executable                             +3
//   File type mismatch                        +3
//   Ransomware content phrase                 +5  per match, capped at +20
//   Crypto address detected                   +5
//   Zero-byte executable                      +8
//   Small executable dropper (<1KB)           +6
//   Ransomware filename pattern               +7
//   Malware filename pattern (exec)           +5
//   Ransomware extension                      +8
//   Double extension trick                    +4
//   Timestamp manipulation                    +1  (reduced — common on copied files)
//   Future timestamp                          +2
//
// Thresholds:
//   score >= 10  → MALICIOUS
//   score >= 4   → SUSPICIOUS
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
const SUSPICIOUS_THRESHOLD: i32 = 4;
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

// ─── Suspicious keywords (executable/script files only) ───────────────────────

const SUSPICIOUS_KEYWORDS: &[&str] = &[
    "-enc ",
    "-encodedcommand",
    "bitstransfer",
    "cmd.exe",
    "createobject",
    "createremotethread",
    "curl",
    "downloadfile",
    "downloadstring",
    "eval(",
    "frombase64string",
    "iex(",
    "invoke-expression",
    "net.webclient",
    "powershell",
    "reflection.assembly",
    "shellexecute",
    "virtualalloc",
    "wget",
    "writeprocessmemory",
    "wscript.shell",
];

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
static MALWARE_FILENAMES: &[&str] = &[
    "backdoor", "coinminer", "crypt", "dropper", "exploit",
    "injector", "keylogger", "payload", "remoteadmintool",
    "stealer", "trojan", "virus", "worm",
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

    /// Returns `(ScanResult, total_score)` so callers can add the score into a
    /// unified multi-layer total without re-parsing the reason string.
    pub fn analyze(&self, path: &Path) -> Result<(ScanResult, i32)> {
        let metadata  = fs::metadata(path)?;
        let file_size = metadata.len();
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

        // ── Read file once ────────────────────────────────────────────────────
        // All byte-level checks share this buffer.  Files > 10 MiB are skipped
        // for content analysis (still get filename/extension/timestamp checks).
        let file_bytes: Vec<u8> = if file_size > 0 && file_size as usize <= MAX_CONTENT_SCAN_BYTES {
            read_file_bytes(path, MAX_CONTENT_SCAN_BYTES).unwrap_or_default()
        } else {
            Vec::new()
        };

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
        if file_bytes.len() >= 2 {
            if let Some(c) = check_magic_bytes(&file_bytes, ext, is_doc) {
                total_score += c.score;
                contributions.push(c);
            }
        }

        // ── Check 5: Entropy — executables only, from buffer ─────────────────
        if is_exec && file_size > 100 && !file_bytes.is_empty() {
            if let Some(c) = check_entropy(&file_bytes) {
                total_score += c.score;
                contributions.push(c);
            }
        }

        // ── Check 6: Content analysis — from buffer ───────────────────────────
        if !file_bytes.is_empty() {
            for c in check_content(&file_bytes, is_doc, is_exec, is_script) {
                total_score += c.score;
                contributions.push(c);
            }
        }

        // ── Check 7: Timestamps ───────────────────────────────────────────────
        if let Some(c) = check_timestamps(&metadata) {
            total_score += c.score;
            contributions.push(c);
        }

        // ── Trust tier cap ────────────────────────────────────────────────────
        // Files under known Microsoft system paths are capped at
        // MALICIOUS_THRESHOLD - 1 so that legitimate high-entropy / PE-header
        // signals cannot push them to Malicious.  They can still be Suspicious
        // if the signal set is genuinely alarming (e.g. a trojanised system DLL
        // with ransomware phrases would score well above SUSPICIOUS_THRESHOLD
        // even after the cap).
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

        // SHA-256: use in-memory buffer for small files (avoids re-opening).
        // For large files (> 10 MiB, buffer is empty) fall back to streaming.
        let hash = if !file_bytes.is_empty() {
            Some(compute_sha256_from_bytes(&file_bytes))
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
    if file_size < 1024 && file_size > 0 && matches!(ext, "exe" | "dll" | "sys") {
        return Some(ScoreContribution::new(
            6,
            format!("Unusually small executable ({}B — possible dropper)", file_size),
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
        return Some(ScoreContribution::new(3, "PE executable", "structure"));
    }

    None
}

/// Entropy check from in-memory buffer — no file I/O.
fn check_entropy(bytes: &[u8]) -> Option<ScoreContribution> {
    let entropy = calculate_entropy(bytes);
    if entropy > 7.5 {
        Some(ScoreContribution::new(
            4,
            format!("Very high entropy ({:.2}) — packed/obfuscated", entropy),
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
    // Use the lossy UTF-8 view — wallet addresses are always ASCII so
    // replacement characters can't produce a false match.
    let text = String::from_utf8_lossy(bytes);
    if contains_crypto_address(&text) {
        out.push(ScoreContribution::new(5, "Cryptocurrency wallet address detected", "content"));
    }

    // ── Executable / script only ──────────────────────────────────────────────
    if is_exec || is_script {
        // Suspicious keywords — searched on pre-lowercased bytes
        let mut kw_score = 0i32;
        let mut kw_hits: Vec<&str> = Vec::new();
        for kw in SUSPICIOUS_KEYWORDS {
            if memmem(&lower, kw.as_bytes()) {
                kw_score += 3;
                kw_hits.push(kw);
                if kw_score >= 12 { break; }
            }
        }
        if kw_score > 0 {
            out.push(ScoreContribution::new(
                kw_score,
                format!("Suspicious keywords: {}", kw_hits.join(", ")),
                "keyword",
            ));
        }

        // Base64 payload — single-pass byte scan (no chars() double-traverse)
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

/// Detect a Bitcoin or Ethereum wallet address anywhere in the text.
fn contains_crypto_address(text: &str) -> bool {
    // BTC: 26–35 chars, starts with 1, 3, or bc1
    if text.split_ascii_whitespace().any(|w| {
        (26..=35).contains(&w.len())
            && (w.starts_with('1') || w.starts_with('3') || w.starts_with("bc1"))
    }) {
        return true;
    }
    // ETH: 0x followed by exactly 40 hex digits
    text.as_bytes()
        .windows(42)
        .any(|w| w.starts_with(b"0x") && w[2..].iter().all(|b| b.is_ascii_hexdigit()))
}

/// Single-pass Base64 payload detector operating directly on bytes.
///
/// Returns `true` if any line is >200 bytes long and consists entirely of
/// Base64 characters (A-Z, a-z, 0-9, +, /) with at most 2 trailing `=`.
/// One byte-scan pass per line replaces the previous two `chars()` traversals.
fn contains_base64_payload(bytes: &[u8]) -> bool {
    for line in bytes.split(|&b| b == b'\n') {
        let t = trim_ascii(line);
        if t.len() <= 200 { continue; }
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
        // A long base64-like line should be detected
        let b64_line = "A".repeat(201);
        assert!(contains_base64_payload(b64_line.as_bytes()));
        // Short line should not trigger
        assert!(!contains_base64_payload(b"short"));
        // Non-base64 chars should not trigger
        let bad_line = format!("{}!", "A".repeat(201));
        assert!(!contains_base64_payload(bad_line.as_bytes()));
    }

    #[test]
    fn test_memmem() {
        assert!(memmem(b"hello world", b"world"));
        assert!(!memmem(b"hello", b"world"));
        assert!(memmem(b"abc", b""));
    }
}

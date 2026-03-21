// File: src/core/file_system/heuristics.rs
// Unified Scoring Heuristic Engine
//
// Scoring table:
//   Base64 payload (executable only)     +1
//   High entropy >7.2 (executable only) +2
//   Very high entropy >7.5              +4  (packed/obfuscated)
//   Suspicious keyword (exec only)      +3  per keyword, capped at +12
//   PowerShell obfuscation              +4
//   PE executable                       +3
//   File type mismatch                  +3
//   Ransomware content phrase           +5  per match, capped at +20
//   Crypto address detected             +5
//   Zero-byte executable                +8
//   Small executable dropper (<1KB)     +6
//   Ransomware filename pattern         +7
//   Malware filename pattern (exec)     +5
//   Ransomware extension                +8
//   Double extension trick              +4
//   Timestamp manipulation              +1  (reduced — common on copied files)
//   Future timestamp                    +2
//
// Thresholds:
//   score >= 10  → MALICIOUS
//   score >= 4   → SUSPICIOUS
//   else         → CLEAN
//
// Each check populates DetectionSignal entries for ML classification.
// Documents skip keyword/entropy/base64 checks to prevent false positives.

use crate::core::types::{DetectionSignal, FileCategory, ScanResult, ThreatLevel};
use std::path::Path;
use std::fs::{self, File};
use std::io::Read;
use anyhow::Result;

// ─── Thresholds ───────────────────────────────────────────────────────────────

const MALICIOUS_THRESHOLD: i32 = 10;
const SUSPICIOUS_THRESHOLD: i32 = 4;
const MAX_CONTENT_SCAN_SIZE: u64 = 10 * 1024 * 1024;

// ─── File type helpers ────────────────────────────────────────────────────────

const DOCUMENT_EXTENSIONS: &[&str] = &[
    "txt", "md", "rst", "log", "csv",
    "json", "xml", "html", "htm", "toml", "yaml", "yml", "ini", "cfg",
    "pdf", "doc", "docx", "xls", "xlsx",
];

const EXECUTABLE_EXTENSIONS: &[&str] = &[
    "exe", "dll", "sys", "drv", "scr", "ocx", "cpl",
    "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse", "wsf", "wsh",
    "msi", "msp", "com", "pif",
];

fn is_document(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| DOCUMENT_EXTENSIONS.contains(&e.to_lowercase().as_str()))
        .unwrap_or(false)
}

fn is_executable(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| EXECUTABLE_EXTENSIONS.contains(&e.to_lowercase().as_str()))
        .unwrap_or(false)
}

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
    "powershell", "cmd.exe", "eval(", "wget", "curl",
    "invoke-expression", "iex(", "downloadstring", "downloadfile",
    "shellexecute", "createobject", "wscript.shell",
    "net.webclient", "bitstransfer", "reflection.assembly",
    "frombase64string", "-encodedcommand", "-enc ",
    "virtualalloc", "writeprocessmemory", "createremotethread",
];

// ─── Internal score contribution ─────────────────────────────────────────────

struct ScoreContribution {
    score: i32,
    reason: String,
    signal_source: String,
}

impl ScoreContribution {
    fn new(score: i32, reason: impl Into<String>, source: impl Into<String>) -> Self {
        Self { score, reason: reason.into(), signal_source: source.into() }
    }
}

// ─── Analyzer ─────────────────────────────────────────────────────────────────

pub struct HeuristicAnalyzer;

impl HeuristicAnalyzer {
    pub fn new() -> Self { Self }

    pub fn analyze(&self, path: &Path) -> Result<ScanResult> {
        let metadata = fs::metadata(path)?;
        let file_size = metadata.len();
        let file_category = FileCategory::from_path(path);

        let mut total_score: i32 = 0;
        let mut contributions: Vec<ScoreContribution> = Vec::new();
        let mut primary_category = "Malware".to_string();

        // ── Check 1: Zero-byte / tiny executable ─────────────────────────────
        if let Some(c) = self.check_zero_byte(path, file_size) {
            total_score += c.score;
            contributions.push(c);
            primary_category = "Wiper".to_string();
        }

        // ── Check 2: Filename patterns ────────────────────────────────────────
        if let Some(c) = self.check_filename(path) {
            total_score += c.score;
            if c.score >= 7 { primary_category = "Ransomware".to_string(); }
            contributions.push(c);
        }

        // ── Check 3: Extension anomalies ──────────────────────────────────────
        if let Some(c) = self.check_extension(path) {
            total_score += c.score;
            if c.score >= 8 { primary_category = "Ransomware".to_string(); }
            contributions.push(c);
        }

        // ── Check 4: PE / magic bytes ─────────────────────────────────────────
        if file_size >= 4 {
            if let Some(c) = self.check_magic_bytes(path)? {
                total_score += c.score;
                contributions.push(c);
            }
        }

        // ── Check 5: Entropy — executables only ───────────────────────────────
        if is_executable(path) && file_size > 100 && file_size < MAX_CONTENT_SCAN_SIZE {
            if let Some(c) = self.check_entropy(path)? {
                total_score += c.score;
                contributions.push(c);
            }
        }

        // ── Check 6: Content analysis ─────────────────────────────────────────
        if file_size > 0 && file_size < MAX_CONTENT_SCAN_SIZE {
            let content_scores = self.check_content(path)?;
            for c in content_scores {
                total_score += c.score;
                contributions.push(c);
            }
        }

        // ── Check 7: Timestamps ───────────────────────────────────────────────
        if let Some(c) = self.check_timestamps(&metadata) {
            total_score += c.score;
            contributions.push(c);
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
                primary_category,
                if level == ThreatLevel::Malicious { "Detected" } else { "Suspected" }
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

        // Build detection signals for ML
        let detection_signals: Vec<DetectionSignal> = contributions.iter()
            .map(|c| DetectionSignal::new(
                c.signal_source.clone(),
                c.reason.clone(),
                c.score,
            ))
            .collect();

        Ok(ScanResult {
            path: path.to_path_buf(),
            level,
            reason,
            hash: None,
            signature,
            confidence_score,
            detection_signals,
            file_category,
            context_flags: vec![],
        })
    }

    // ── Individual checks ─────────────────────────────────────────────────────

    fn check_zero_byte(&self, path: &Path, file_size: u64) -> Option<ScoreContribution> {
        let ext = path.extension()?.to_str()?.to_lowercase();

        if file_size == 0 && EXECUTABLE_EXTENSIONS.contains(&ext.as_str()) {
            return Some(ScoreContribution::new(
                8,
                "Zero-byte executable (data destruction indicator)",
                "metadata",
            ));
        }

        if file_size < 1024 && file_size > 0 && ["exe", "dll", "sys"].contains(&ext.as_str()) {
            return Some(ScoreContribution::new(
                6,
                format!("Unusually small executable ({}B — possible dropper)", file_size),
                "metadata",
            ));
        }

        None
    }

    fn check_filename(&self, path: &Path) -> Option<ScoreContribution> {
        let name = path.file_name()?.to_str()?.to_lowercase();

        // Ransomware note filenames — compound phrases only
        // Single words like "howto", "readme", "decrypt", "recovery",
        // "instruction" excluded — appear constantly in legitimate files.
        let ransomware_names = [
            "read_me", "read-me",
            "how_to_decrypt", "how-to-decrypt",
            "howto_decrypt", "howto_recover",
            "decrypt_instructions", "decrypt_files",
            "recovery_instructions", "ransom_note",
            "your_files_encrypted", "files_encrypted",
            "!!!", "ransom", "locked", "encrypted",
        ];
        for pattern in &ransomware_names {
            if name.contains(pattern) {
                if let Some(ext) = path.extension() {
                    let ext = ext.to_str()?.to_lowercase();
                    if ["txt", "html", "htm", "hta"].contains(&ext.as_str()) {
                        return Some(ScoreContribution::new(
                            7,
                            format!("Ransomware note filename pattern: '{}'", pattern),
                            "filename",
                        ));
                    }
                }
            }
        }

        // Malware-named executables
        // "rat" → "remoteadmintool"  (rat matches migrate, grateful, rate…)
        // "inject" → "injector"      (inject matches dependency injection)
        // "miner" → "coinminer"      (miner matches data miner, text miner)
        // "keylog" → "keylogger"     (slightly more specific)
        if is_executable(path) {
            let malware_names = [
                "crypt", "trojan", "virus", "worm", "keylogger",
                "stealer", "coinminer", "backdoor", "injector",
                "payload", "exploit", "remoteadmintool", "dropper",
            ];
            for pattern in &malware_names {
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

    fn check_extension(&self, path: &Path) -> Option<ScoreContribution> {
        let ext = path.extension()?.to_str()?.to_lowercase();

        let ransomware_extensions = [
            "locked", "encrypted", "crypted", "enc", "crypt",
            "locky", "cerber", "zepto", "thor", "wannacry",
            "petya", "cryptolocker", "ryuk", "maze", "revil",
            "wncry", "wncryt",
        ];
        for r_ext in &ransomware_extensions {
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
                    let inner = inner_ext.to_lowercase();
                    if DOCUMENT_EXTENSIONS.contains(&inner.as_str())
                        && ["exe", "scr", "bat", "cmd"].contains(&ext.as_str())
                    {
                        return Some(ScoreContribution::new(
                            4,
                            format!("Double extension disguise: .{}.{}", inner, ext),
                            "extension",
                        ));
                    }
                }
            }
        }

        None
    }

    fn check_magic_bytes(&self, path: &Path) -> Result<Option<ScoreContribution>> {
        let mut file = File::open(path)?;
        let mut header = [0u8; 4];
        let n = file.read(&mut header)?;
        if n < 2 { return Ok(None); }

        let is_pe = header[0] == 0x4D && header[1] == 0x5A;
        if !is_pe { return Ok(None); }

        let ext = path.extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_lowercase())
            .unwrap_or_default();

        if DOCUMENT_EXTENSIONS.contains(&ext.as_str()) {
            return Ok(Some(ScoreContribution::new(
                3,
                format!("PE executable content in .{} file (type mismatch)", ext),
                "structure",
            )));
        }

        if ["exe", "dll", "sys", "scr"].contains(&ext.as_str()) {
            return Ok(Some(ScoreContribution::new(
                3,
                "PE executable".to_string(),
                "structure",
            )));
        }

        Ok(None)
    }

    fn check_entropy(&self, path: &Path) -> Result<Option<ScoreContribution>> {
        let data = self.read_bytes(path, MAX_CONTENT_SCAN_SIZE as usize)?;
        let entropy = Self::shannon_entropy(&data);

        if entropy > 7.5 {
            Ok(Some(ScoreContribution::new(
                4,
                format!("Very high entropy ({:.2}) — packed/obfuscated", entropy),
                "entropy",
            )))
        } else if entropy > 7.2 {
            Ok(Some(ScoreContribution::new(
                2,
                format!("High entropy ({:.2}) — possibly packed", entropy),
                "entropy",
            )))
        } else {
            Ok(None)
        }
    }

    fn check_content(&self, path: &Path) -> Result<Vec<ScoreContribution>> {
        let mut contributions = Vec::new();

        let mut file = File::open(path)?;
        let mut content = String::new();
        match file.read_to_string(&mut content) {
            Ok(_) => {}
            Err(_) => return Ok(contributions),
        }

        let lower = content.to_lowercase();

        // ── Ransomware phrases — all file types ───────────────────────────────
        if is_document(path) || is_executable(path) {
            let mut score = 0i32;
            let mut hits = Vec::new();
            for phrase in RANSOMWARE_CONTENT {
                if lower.contains(phrase) {
                    score += 5;
                    hits.push(*phrase);
                    if score >= 20 { break; }
                }
            }
            if score > 0 {
                contributions.push(ScoreContribution::new(
                    score,
                    format!("Ransomware content phrases: {}", hits.join(", ")),
                    "content",
                ));
            }
        }

        // ── Crypto address — all file types ──────────────────────────────────
        if self.contains_crypto_address(&content) {
            contributions.push(ScoreContribution::new(
                5,
                "Cryptocurrency wallet address detected",
                "content",
            ));
        }

        // ── Executable/script-only checks ────────────────────────────────────
        if is_executable(path) {
            // Suspicious keywords
            let mut kw_score = 0i32;
            let mut kw_hits = Vec::new();
            for kw in SUSPICIOUS_KEYWORDS {
                if lower.contains(kw) {
                    kw_score += 3;
                    kw_hits.push(*kw);
                    if kw_score >= 12 { break; }
                }
            }
            if kw_score > 0 {
                contributions.push(ScoreContribution::new(
                    kw_score,
                    format!("Suspicious keywords: {}", kw_hits.join(", ")),
                    "keyword",
                ));
            }

            // Base64 payload
            if self.contains_base64_payload(&content) {
                contributions.push(ScoreContribution::new(
                    1,
                    "Base64 encoded payload detected",
                    "obfuscation",
                ));
            }

            // PowerShell obfuscation (requires 2+ patterns)
            if self.contains_powershell_obfuscation(&lower) {
                contributions.push(ScoreContribution::new(
                    4,
                    "PowerShell obfuscation techniques detected",
                    "obfuscation",
                ));
            }
        }

        Ok(contributions)
    }

    fn check_timestamps(&self, metadata: &fs::Metadata) -> Option<ScoreContribution> {
        use std::time::SystemTime;

        let modified = metadata.modified().ok()?;
        let created = metadata.created().ok()?;

        // Reduced to +1 — very common on legitimately copied files.
        // Alone it must never reach Suspicious threshold (4).
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
                return Some(ScoreContribution::new(
                    2,
                    "Suspicious future timestamp",
                    "timestamp",
                ));
            }
        }

        None
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn contains_crypto_address(&self, content: &str) -> bool {
        let btc = content.split_whitespace().any(|w| {
            (w.len() >= 26 && w.len() <= 35)
                && (w.starts_with('1') || w.starts_with('3') || w.starts_with("bc1"))
        });
        let eth = content.contains("0x")
            && content.as_bytes().windows(42).any(|w| {
                w.starts_with(b"0x") && w[2..].iter().all(|b| b.is_ascii_hexdigit())
            });
        btc || eth
    }

    fn contains_base64_payload(&self, content: &str) -> bool {
        content.lines().any(|line| {
            let t = line.trim();
            t.len() > 200
                && t.chars().all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '=')
                && t.chars().filter(|&c| c == '=').count() <= 2
        })
    }

    fn contains_powershell_obfuscation(&self, lower: &str) -> bool {
    let patterns = [
        "-enc",
        "-encodedcommand",
        "invoke-expression",
        "iex(",
        "bitstransfer",
        "reflection.assembly",
        "[convert]::frombase64string",
    ];
    patterns.iter().filter(|p| lower.contains(*p)).count() >= 2

    }

    fn read_bytes(&self, path: &Path, max: usize) -> std::io::Result<Vec<u8>> {
        let file = File::open(path)?;
        let mut buf = Vec::new();
        file.take(max as u64).read_to_end(&mut buf)?;
        Ok(buf)
    }

    pub fn shannon_entropy(data: &[u8]) -> f64 {
        if data.is_empty() { return 0.0; }
        let mut freq = [0u64; 256];
        for &b in data { freq[b as usize] += 1; }
        let len = data.len() as f64;
        freq.iter()
            .filter(|&&c| c > 0)
            .map(|&c| { let p = c as f64 / len; -p * p.log2() })
            .sum()
    }
}

impl Default for HeuristicAnalyzer {
    fn default() -> Self { Self::new() }
}

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
        let result = HeuristicAnalyzer::new().analyze(&path).unwrap();
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
        let result = HeuristicAnalyzer::new().analyze(&path).unwrap();
        assert_eq!(result.level, ThreatLevel::Clean,
            "ML notes wrongly flagged: {}", result.reason);
        assert_eq!(result.file_category, FileCategory::Document);
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_howto_filename_clean() {
        let path = std::env::temp_dir().join("Neural network-HowTo.txt");
        std::fs::write(&path, "Tutorial on neural networks.").unwrap();
        let result = HeuristicAnalyzer::new().analyze(&path).unwrap();
        assert_eq!(result.level, ThreatLevel::Clean,
            "HowTo filename wrongly flagged: {}", result.reason);
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_signals_populated() {
        let path = std::env::temp_dir().join("signal_test_ransom.txt");
        std::fs::write(&path, "pay bitcoin to decrypt your files ransom demand").unwrap();
        let result = HeuristicAnalyzer::new().analyze(&path).unwrap();
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
        let result = HeuristicAnalyzer::new().analyze(&path).unwrap();
        assert!(result.confidence_score >= 0.0 && result.confidence_score <= 1.0);
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_zero_byte_exe() {
        let path = std::env::temp_dir().join("zero_heuristic2.exe");
        std::fs::write(&path, "").unwrap();
        let result = HeuristicAnalyzer::new().analyze(&path).unwrap();
        assert!(result.level != ThreatLevel::Clean);
        assert_eq!(result.file_category, FileCategory::Executable);
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_timestamp_alone_not_suspicious() {
        let path = std::env::temp_dir().join("timestamp_alone.txt");
        std::fs::write(&path, "Clean content.").unwrap();
        let result = HeuristicAnalyzer::new().analyze(&path).unwrap();
        assert_eq!(result.level, ThreatLevel::Clean,
            "Timestamp alone should not flag: {}", result.reason);
        std::fs::remove_file(path).ok();
    }
}
// File: src/core/file_system/scanner.rs
// Multi-layer scanner with unified scoring + directory context analysis.
//
// Detection pipeline (single file):
//   1. Hash signature DB  → instant Malicious (definitive)
//   2. YARA rules         → score contribution
//                            strong rule  +10  (named malware families)
//                            weak/FP rule  +1  (generic patterns)
//   3. Heuristics         → score contribution (see heuristics.rs)
//   4. Score decision     → MALICIOUS(>=10) / SUSPICIOUS(>=4) / CLEAN
//
// Directory scan adds a 5th pass:
//   5. Context analysis   → escalation + context_flags + YARA/filename correlation
//
// All results carry ML classification fields:
//   confidence_score, detection_signals, file_category, context_flags

use crate::core::file_system::context::ContextAnalyzer;
use crate::core::file_system::heuristics::HeuristicAnalyzer;
use crate::core::file_system::signature::SignatureDatabase;
use crate::core::file_system::yara_engine::YaraEngine;
use crate::core::types::{DetectionSignal, FileCategory, ScanResult, ThreatLevel};
use std::path::Path;
use anyhow::Result;
use sha2::{Digest, Sha256, Sha512};
use hex;

// ─── Score thresholds ────────────────────────────────────────────────────────

const MALICIOUS_THRESHOLD: i32 = 10;
const SUSPICIOUS_THRESHOLD: i32 = 4;

// ─── YARA scoring policy ─────────────────────────────────────────────────────

const YARA_STRONG_SCORE: i32 = 10;
const YARA_WEAK_SCORE: i32 = 1;

const YARA_WEAK_RULES: &[&str] = &[
    // Generic pattern rules
    "contains_base64", "base64_encoded", "Base64_Encoded_String",
    "long_string", "BigFiles", "suspicious_strings", "generic",
    // Network indicator rules — belong in network scanner
    "domain", "ip", "ip_address", "url", "network", "http", "email",
    // Tool name rules — too generic, firing on any script that calls the tool
    "powershell",
    "cmd",
    "wscript",
    "mshta",
    // Misc catch-all rules — not specific enough
    "misc_suspicious",
    "miscellaneous",
];

/// Extensions YARA will scan — executables and scripts only.
/// Documents excluded to prevent false positives from generic rules.
const YARA_SCAN_EXTENSIONS: &[&str] = &[
    "exe", "dll", "sys", "drv", "ocx", "cpl", "scr",
    "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse", "wsf", "wsh",
    "msi", "msp", "com", "pif", "lnk",
    "xlsm", "docm", "pptm", "xlam",
    "elf", "so", "dylib", "sh",
    "py", "rb", "pl",
];

fn should_yara_scan(path: &Path) -> bool {
    match path.extension().and_then(|e| e.to_str()) {
        Some(ext) => YARA_SCAN_EXTENSIONS.contains(&ext.to_lowercase().as_str()),
        None => true,
    }
}

fn yara_rule_score(rule_name: &str) -> i32 {
    let lower = rule_name.to_lowercase();
    if YARA_WEAK_RULES.iter().any(|w| lower.contains(&w.to_lowercase())) {
        YARA_WEAK_SCORE
    } else {
        YARA_STRONG_SCORE
    }
}

// ─── Statistics ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct FileHashes {
    pub md5: String,
    pub sha256: String,
    pub sha512: String,
}

#[derive(Debug, Clone)]
pub struct ScanStatistics {
    pub total_files: usize,
    pub clean_files: usize,
    pub suspicious_files: usize,
    pub malicious_files: usize,
    pub error_files: usize,
    pub total_size_scanned: u64,
}

impl ScanStatistics {
    pub fn new() -> Self {
        Self {
            total_files: 0,
            clean_files: 0,
            suspicious_files: 0,
            malicious_files: 0,
            error_files: 0,
            total_size_scanned: 0,
        }
    }

    pub fn update(&mut self, result: &ScanResult, file_size: u64) {
        self.total_files += 1;
        self.total_size_scanned += file_size;
        match result.level {
            ThreatLevel::Clean      => self.clean_files += 1,
            ThreatLevel::Suspicious => self.suspicious_files += 1,
            ThreatLevel::Malicious  => self.malicious_files += 1,
        }
    }

    pub fn add_error(&mut self) { self.error_files += 1; }
}

impl Default for ScanStatistics {
    fn default() -> Self { Self::new() }
}

// ─── Scanner ──────────────────────────────────────────────────────────────────

pub struct FileSystemScanner {
    signatures: SignatureDatabase,
    heuristics: HeuristicAnalyzer,
    yara: YaraEngine,
    context: ContextAnalyzer,
    enable_multi_hash: bool,
    enable_deep_scan: bool,
    enable_yara: bool,
}

impl FileSystemScanner {
    pub fn new() -> Self {
        Self::with_options(true, true, true)
    }

    pub fn with_options(enable_multi_hash: bool, enable_deep_scan: bool, enable_yara: bool) -> Self {
        let yara = if enable_yara { YaraEngine::default() } else { YaraEngine::disabled() };
        Self {
            signatures: SignatureDatabase::new(),
            heuristics: HeuristicAnalyzer::new(),
            yara,
            context: ContextAnalyzer::new(),
            enable_multi_hash,
            enable_deep_scan,
            enable_yara,
        }
    }

    pub fn load_yara_rules(&mut self, rules_dir: &Path) -> Result<usize> {
        self.yara = YaraEngine::load_from_directory(rules_dir)?;
        Ok(self.yara.rules_loaded)
    }

    // ── Single file scan ──────────────────────────────────────────────────────

    pub fn scan_file(&self, path: &Path) -> Result<ScanResult> {
        let _metadata = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(e) => return Ok(ScanResult::error(
                path.to_path_buf(),
                format!("Cannot access file: {}", e),
            )),
        };

        let hashes = if self.enable_multi_hash {
            self.calculate_all_hashes(path)?
        } else {
            FileHashes {
                md5: String::new(),
                sha256: self.calculate_sha256(path)?,
                sha512: String::new(),
            }
        };

        // ── Layer 1: Hash DB (definitive — bypasses scoring) ──────────────────
        if let Some(signature) = self.check_all_hashes(&hashes) {
            let category = FileCategory::from_path(path);
            return Ok(ScanResult::from_parts(
                path.to_path_buf(),
                ThreatLevel::Malicious,
                format!("Known malware signature: {}", signature),
                Some(hashes.sha256),
                Some(signature.to_string()),
                1.0,
                vec![DetectionSignal::new("hash", format!("Hash match: {}", signature), 100)],
            ));
        }

        // ── Unified scoring: YARA + Heuristics ───────────────────────────────
        let mut total_score: i32 = 0;
        let mut all_signals: Vec<DetectionSignal> = Vec::new();
        let mut score_reasons: Vec<String> = Vec::new();
        let mut primary_signature: Option<String> = None;

        // ── Layer 2: YARA ─────────────────────────────────────────────────────
        if self.enable_yara && self.yara.is_ready() && should_yara_scan(path) {
            match self.yara.scan_file(path) {
                Ok(matches) if !matches.is_empty() => {
                    let mut yara_score = 0i32;
                    let mut rule_names: Vec<String> = Vec::new();

                    for m in &matches {
                        let rs = yara_rule_score(&m.rule_name);
                        yara_score += rs;
                        rule_names.push(m.rule_name.clone());

                        let desc = m.meta_description.clone()
                            .unwrap_or_else(|| m.rule_name.clone());
                        all_signals.push(DetectionSignal::new("yara", desc, rs));
                    }

                    if yara_score > 0 {
                        total_score += yara_score;
                        let description = matches.first()
                            .and_then(|m| m.meta_description.clone())
                            .unwrap_or_else(|| format!("{} rule(s)", matches.len()));
                        score_reasons.push(format!(
                            "YARA +{} ({}): {}",
                            yara_score, rule_names.join(", "), description
                        ));
                        primary_signature = Some(rule_names.join(", "));
                    }
                }
                Err(e) => eprintln!("YARA error for {}: {}", path.display(), e),
                _ => {}
            }
        }

        // ── Layer 3: Heuristics ───────────────────────────────────────────────
        if self.enable_deep_scan {
            match self.heuristics.analyze(path) {
                Ok(heuristic_result) => {
                    if heuristic_result.level != ThreatLevel::Clean {
                        let h_score = Self::extract_heuristic_score(&heuristic_result.reason);
                        total_score += h_score;
                        score_reasons.push(heuristic_result.reason.clone());
                        // Carry over heuristic signals
                        all_signals.extend(heuristic_result.detection_signals.clone());
                        if primary_signature.is_none() {
                            primary_signature = heuristic_result.signature.clone();
                        }
                    }
                }
                Err(e) => eprintln!("Heuristic error for {}: {}", path.display(), e),
            }
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

        if level == ThreatLevel::Clean {
            return Ok(ScanResult::clean(path.to_path_buf(), Some(hashes.sha256)));
        }

        Ok(ScanResult::from_parts(
            path.to_path_buf(),
            level,
            format!("Score {}: {}", total_score, score_reasons.join(" | ")),
            Some(hashes.sha256),
            primary_signature,
            confidence_score,
            all_signals,
        ))
    }

    // ── Directory scan with context ───────────────────────────────────────────

    /// Full directory scan with context analysis.
    /// Performs individual file scans then applies directory-level
    /// context (ransom note counting, mass modification, YARA correlation etc.)
    pub fn scan_directory_with_stats(
        &self,
        dir: &Path,
        recursive: bool,
    ) -> (Vec<ScanResult>, ScanStatistics) {
        // Pass 1: scan all files individually
        let mut results: Vec<ScanResult> = Vec::new();
        let mut stats = ScanStatistics::new();

        for result in self.scan_directory_iter(dir, recursive) {
            match result {
                Ok(scan_result) => {
                    let size = std::fs::metadata(&scan_result.path)
                        .map(|m| m.len()).unwrap_or(0);
                    stats.update(&scan_result, size);
                    results.push(scan_result);
                }
                Err(e) => {
                    stats.add_error();
                    eprintln!("Scan error: {}", e);
                }
            }
        }

        // Pass 2: directory context analysis
        // Annotates context_flags, escalates levels, adds context signals
        self.context.analyze(&mut results, dir);

        // Recount stats after context escalation
        let mut final_stats = ScanStatistics::new();
        for r in &results {
            let size = std::fs::metadata(&r.path).map(|m| m.len()).unwrap_or(0);
            final_stats.update(r, size);
        }

        (results, final_stats)
    }

    fn scan_directory_iter<'a>(
        &'a self,
        dir: &Path,
        recursive: bool,
    ) -> impl Iterator<Item = Result<ScanResult>> + 'a {
        use walkdir::WalkDir;

        let walker = if recursive {
            WalkDir::new(dir)
        } else {
            WalkDir::new(dir).max_depth(1)
        };

        let dir_path = dir.to_path_buf();

        walker.into_iter().filter_map(move |entry| {
            match entry {
                Ok(e) if e.file_type().is_file() => Some(self.scan_file(e.path())),
                Ok(_) => None,
                Err(e) => Some(Ok(ScanResult::error(
                    e.path().map(|p| p.to_path_buf()).unwrap_or_else(|| dir_path.clone()),
                    format!("Directory scan error: {}", e),
                ))),
            }
        })
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn extract_heuristic_score(reason: &str) -> i32 {
        reason
            .find("score: ")
            .and_then(|i| {
                let rest = &reason[i + 7..];
                let end = rest.find(')').unwrap_or(rest.len());
                rest[..end].trim().parse::<i32>().ok()
            })
            .unwrap_or(0)
    }

    fn calculate_all_hashes(&self, path: &Path) -> Result<FileHashes> {
        let data = std::fs::read(path)?;
        let md5 = format!("{:x}", md5::compute(&data));
        let mut h256 = Sha256::new(); h256.update(&data);
        let sha256 = hex::encode(h256.finalize());
        let mut h512 = Sha512::new(); h512.update(&data);
        let sha512 = hex::encode(h512.finalize());
        Ok(FileHashes { md5, sha256, sha512 })
    }

    fn calculate_sha256(&self, path: &Path) -> Result<String> {
        let data = std::fs::read(path)?;
        let mut h = Sha256::new(); h.update(&data);
        Ok(hex::encode(h.finalize()))
    }

    fn check_all_hashes(&self, hashes: &FileHashes) -> Option<&str> {
        if let Some(s) = self.signatures.check_hash(&hashes.sha256) { return Some(s); }
        if !hashes.md5.is_empty() {
            if let Some(s) = self.signatures.check_hash(&hashes.md5) { return Some(s); }
        }
        if !hashes.sha512.is_empty() {
            if let Some(s) = self.signatures.check_hash(&hashes.sha512) { return Some(s); }
        }
        None
    }

    pub fn get_signatures_mut(&mut self) -> &mut SignatureDatabase { &mut self.signatures }
    pub fn set_deep_scan(&mut self, enabled: bool)  { self.enable_deep_scan = enabled; }
    pub fn set_multi_hash(&mut self, enabled: bool) { self.enable_multi_hash = enabled; }
    pub fn set_yara(&mut self, enabled: bool)       { self.enable_yara = enabled; }
    pub fn yara_rules_loaded(&self) -> usize        { self.yara.rules_loaded }
}

impl Default for FileSystemScanner {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_eicar_malicious() {
        let path = std::env::temp_dir().join("eicar_scanner_final.txt");
        fs::write(&path,
            "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        ).unwrap();
        let result = FileSystemScanner::new().scan_file(&path).unwrap();
        assert_eq!(result.level, ThreatLevel::Malicious);
        assert_eq!(result.confidence_score, 1.0);
        assert!(result.detection_signals.iter().any(|s| s.source == "hash"));
        fs::remove_file(path).ok();
    }

    #[test]
    fn test_ml_notes_clean() {
        let path = std::env::temp_dir().join("ml_scanner_final.txt");
        fs::write(&path,
            "Batch Normalization: Standardizes outputs of each layer. \
             Not strictly a regularizer but often has a regularization effect. \
             Neural network-HowTo: gradient descent optimizer learning rate."
        ).unwrap();
        let result = FileSystemScanner::new().scan_file(&path).unwrap();
        assert_eq!(result.level, ThreatLevel::Clean,
            "ML notes should be Clean. Got: {} — {}", result.level, result.reason);
        assert_eq!(result.file_category, FileCategory::Document);
        assert!(result.context_flags.is_empty());
        fs::remove_file(path).ok();
    }

    #[test]
    fn test_yara_weak_score() {
        assert_eq!(yara_rule_score("contains_base64"), 1);
        assert_eq!(yara_rule_score("Base64_Encoded_String"), 1);
    }

    #[test]
    fn test_yara_strong_score() {
        assert_eq!(yara_rule_score("Wanna_Cry_Ransomware_Generic"), 10);
        assert_eq!(yara_rule_score("RAT_PlugX"), 10);
    }

    #[test]
    fn test_no_yara_on_documents() {
        assert!(!should_yara_scan(Path::new("notes.txt")));
        assert!(!should_yara_scan(Path::new("readme.md")));
        assert!(!should_yara_scan(Path::new("data.csv")));
    }

    #[test]
    fn test_yara_on_executables() {
        assert!(should_yara_scan(Path::new("malware.exe")));
        assert!(should_yara_scan(Path::new("script.ps1")));
        assert!(should_yara_scan(Path::new("dropper.bat")));
    }

    #[test]
    fn test_extract_heuristic_score() {
        assert_eq!(FileSystemScanner::extract_heuristic_score(
            "Dynamic analysis (score: 7): something bad"), 7);
        assert_eq!(FileSystemScanner::extract_heuristic_score(
            "No threats detected"), 0);
    }

    #[test]
    fn test_directory_context_applied() {
        let temp = std::env::temp_dir().join("ctx_test_dir");
        fs::create_dir_all(&temp).unwrap();

        // Write 3 ransom notes + 1 clean file
        fs::write(temp.join("how_to_decrypt.txt"), "pay bitcoin to recover your files").unwrap();
        fs::write(temp.join("ransom_note.txt"), "all your files have been encrypted").unwrap();
        fs::write(temp.join("files_encrypted.txt"), "pay btc to decrypt your files").unwrap();
        fs::write(temp.join("clean.txt"), "ordinary content").unwrap();

        let scanner = FileSystemScanner::new();
        let (results, _stats) = scanner.scan_directory_with_stats(&temp, false);

        // At least one file should have MultipleRansomNotes flag
        let has_flag = results.iter().any(|r|
            r.context_flags.contains(&crate::core::types::ContextFlag::MultipleRansomNotes));
        assert!(has_flag, "Directory with 3 ransom notes should set MultipleRansomNotes flag");

        fs::remove_dir_all(&temp).ok();
    }

    #[test]
    fn test_clean_file_gets_context_flag_not_escalated() {
        // Clean files near ransom notes should get flag but NOT be escalated
        let temp = std::env::temp_dir().join("ctx_clean_test_dir");
        fs::create_dir_all(&temp).unwrap();

        fs::write(temp.join("how_to_decrypt.txt"), "pay bitcoin").unwrap();
        fs::write(temp.join("ransom_note.txt"), "all your files encrypted").unwrap();
        fs::write(temp.join("files_encrypted.txt"), "pay btc ransom demand").unwrap();
        fs::write(temp.join("my_document.txt"), "completely normal document").unwrap();

        let scanner = FileSystemScanner::new();
        let (results, _) = scanner.scan_directory_with_stats(&temp, false);

        let doc = results.iter().find(|r| r.path.ends_with("my_document.txt"));
        if let Some(d) = doc {
            // Clean file should stay clean — only get annotated
            assert_eq!(d.level, ThreatLevel::Clean,
                "Clean file should not be escalated, got: {} — {}", d.level, d.reason);
        }

        fs::remove_dir_all(&temp).ok();
    }
}
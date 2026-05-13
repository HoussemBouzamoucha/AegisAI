// File: src/core/file_system/scanner.rs
// Multi-layer scanner with unified scoring + per-directory context analysis.
//
// Detection pipeline (single file):
//   1. Hash signature DB  → instant Malicious (definitive)
//   2. YARA rules         → score contribution
//                            strong rule  +10  (named malware families)
//                            weak/FP rule  +1  (generic/network patterns)
//   3. Heuristics         → score contribution (see heuristics.rs)
//   4. Score decision     → MALICIOUS(>=10) / SUSPICIOUS(>=4) / CLEAN
//
// Directory scan adds a 5th pass:
//   5. Context analysis   → per-directory grouping prevents cross-subdir contamination
//                           ransom notes in subdir A do NOT escalate files in subdir B

use crate::core::file_system::context::ContextAnalyzer;
use crate::core::file_system::heuristics::HeuristicAnalyzer;
use crate::core::file_system::signature::SignatureDatabase;
use crate::core::file_system::yara_engine::YaraEngine;
use crate::core::types::{DetectionSignal, FileCategory, ScanResult, ThreatLevel};
use crate::core::utils::{compute_sha256, compute_sha256_from_bytes};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use anyhow::Result;
use sha2::{Digest, Sha512};
use hex;

// ─── Ember2024 ML bridge ──────────────────────────────────────────────────────

struct EmberResult {
    score: f32,
    file_type: String,
    malicious: bool,
}

/// Locate `bridge.py` relative to the running engine binary.
///
/// Layout:
///   Antivirus_Engine/target/{profile}/antivirus.exe
///   Antivirus_Engine/src/core/file_system/Ember2024/bridge.py
fn find_ember_script() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    // exe → target/{profile}/ → target/ → Antivirus_Engine/
    let engine_root = exe.parent()?.parent()?.parent()?;
    let script = engine_root
        .join("src").join("core").join("file_system")
        .join("Ember2024").join("bridge.py");
    if script.exists() { Some(script) } else { None }
}

/// Call `bridge.py <path>` via Python and parse the JSON result.
///
/// Returns `None` if:
/// - bridge.py cannot be located
/// - Python is not on PATH
/// - The file type is unsupported (bridge returns `{"skipped":true}`)
/// - Any other error occurs
///
/// This function is intentionally silent on failures — the caller continues
/// with heuristic-only scoring.
fn run_ember_ml(path: &Path) -> Option<EmberResult> {
    let script = find_ember_script()?;
    let path_str = path.to_str()?;
    let script_str = script.to_str()?;

    // Candidate order:
    //   1. Venv Python — has thrember + lightgbm installed
    //   2. System Python candidates — fallback if venv path changes
    let exe = std::env::current_exe().ok()?;
    let engine_root = exe.parent()?.parent()?.parent()?;
    let venv_python = engine_root
        .parent()                          // AegisAI/
        .map(|r| r.join("ai_agent").join(".venv").join("Scripts").join("python.exe"))
        .filter(|p| p.exists());

    let venv_str: Option<String> = venv_python.as_ref()
        .and_then(|p| p.to_str().map(|s| s.to_string()));

    let mut candidates: Vec<&str> = Vec::new();
    if let Some(ref s) = venv_str { candidates.push(s.as_str()); }
    candidates.extend_from_slice(&["python", "python3", "py"]);

    for py in &candidates {
        let output = match std::process::Command::new(py)
            .args([script_str, path_str])
            .output()
        {
            Ok(o) => o,
            Err(_) => continue,
        };

        if !output.status.success() {
            continue;
        }

        let stdout = match std::str::from_utf8(&output.stdout) {
            Ok(s) => s.trim().to_string(),
            Err(_) => continue,
        };
        let v: serde_json::Value = match serde_json::from_str(&stdout) {
            Ok(v) => v,
            Err(_) => continue,
        };

        // Bridge returns {"skipped": true} for unsupported file types — treat as no-op.
        if v.get("skipped").and_then(|b| b.as_bool()).unwrap_or(false) {
            return None;
        }
        // Bridge may return {"error": "..."} — treat as no-op.
        if v.get("error").is_some() {
            return None;
        }

        let score = match v.get("score").and_then(|s| s.as_f64()) {
            Some(s) => s as f32,
            None => continue,
        };
        let file_type = v.get("file_type")
            .and_then(|t| t.as_str())
            .unwrap_or("Unknown")
            .to_string();
        let malicious = v.get("malicious")
            .and_then(|b| b.as_bool())
            .unwrap_or(score >= 0.8);

        return Some(EmberResult { score, file_type, malicious });
    }

    None
}

// ─── Score thresholds ─────────────────────────────────────────────────────────

const MALICIOUS_THRESHOLD: i32 = 10;
const SUSPICIOUS_THRESHOLD: i32 = 4;

// ─── YARA scoring policy ──────────────────────────────────────────────────────

const YARA_STRONG_SCORE: i32 = 10;
const YARA_WEAK_SCORE: i32 = 1;

const YARA_WEAK_RULES: &[&str] = &[
    // Generic pattern rules — fire on legitimate content
    "contains_base64",
    "base64_encoded",
    "Base64_Encoded_String",
    "long_string",
    "BigFiles",
    "suspicious_strings",
    "generic",
    // Network indicator rules — kept as weak (+1) here because scripts can
    // legitimately embed URLs/IPs.  The network scanner uses pcap + ML and
    // does not have a YARA layer yet; these stay until that is added.
    // Tool name rules — too generic, fire on any script calling the tool
    "powershell",
    "cmd",
    "wscript",
    "mshta",
    // Misc catch-all rules
    "misc_suspicious",
    "miscellaneous",
];

/// Extensions YARA will scan — executables and scripts only.
/// Documents excluded to prevent false positives from generic rules.
pub const YARA_SCAN_EXTENSIONS: &[&str] = &[
    // Executables & libraries
    "exe", "dll", "sys", "drv", "ocx", "cpl", "scr",
    // Scripts
    "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse", "wsf", "wsh",
    // Installers
    "msi", "msp", "com", "pif", "lnk",
    // Office macro-enabled
    "xlsm", "docm", "pptm", "xlam",
    // Linux/Mac
    "elf", "so", "dylib", "sh",
    // Interpreted languages
    "py", "rb", "pl",
];

fn should_yara_scan(path: &Path) -> bool {
    match path.extension().and_then(|e| e.to_str()) {
        Some(ext) => YARA_SCAN_EXTENSIONS.contains(&ext.to_lowercase().as_str()),
        None => true, // No extension — could be Linux executable
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

// ─── Types ────────────────────────────────────────────────────────────────────

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
    /// Shared compiled YARA rules.  Wrapping in Arc means the rules are
    /// compiled exactly once and all worker threads share the same compiled
    /// bytecode — no concurrent wasmtime JIT initialisation races.
    yara: Arc<YaraEngine>,
    context: ContextAnalyzer,
    enable_multi_hash: bool,
    enable_deep_scan: bool,
    enable_yara: bool,
    /// When `false`, skip SHA-256 computation and hash-DB lookup entirely.
    /// Saves one full file read per file.  Intended for quick scans where the
    /// hash DB is unlikely to match and per-file I/O is the bottleneck.
    enable_hash_db: bool,
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
            yara: Arc::new(yara),
            context: ContextAnalyzer::new(),
            enable_multi_hash,
            enable_deep_scan,
            enable_yara,
            enable_hash_db: true,
        }
    }

    /// Create a scanner that shares pre-compiled YARA rules with other workers.
    ///
    /// Rules are compiled exactly once by the caller and the `Arc` is cloned
    /// cheaply for each thread — no concurrent wasmtime JIT compilation.
    pub fn with_shared_yara(
        enable_multi_hash: bool,
        enable_deep_scan: bool,
        yara: Arc<YaraEngine>,
    ) -> Self {
        let enable_yara = yara.is_ready();
        Self {
            signatures: SignatureDatabase::new(),
            heuristics: HeuristicAnalyzer::new(),
            yara,
            context: ContextAnalyzer::new(),
            enable_multi_hash,
            enable_deep_scan,
            enable_yara,
            enable_hash_db: true,
        }
    }

    pub fn load_yara_rules(&mut self, rules_dir: &Path) -> Result<usize> {
        let engine = YaraEngine::load_from_directory(rules_dir)?;
        let loaded = engine.rules_loaded;
        self.enable_yara = engine.is_ready();
        self.yara = Arc::new(engine);
        Ok(loaded)
    }

    // ── Single file scan ──────────────────────────────────────────────────────

    pub fn scan_file(&self, path: &Path) -> Result<ScanResult> {
        let metadata = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(e) => return Ok(ScanResult::error(
                path.to_path_buf(),
                format!("Cannot access file: {}", e),
            )),
        };
        let file_size = metadata.len();

        // ── Layer 1: Hash DB ──────────────────────────────────────────────────
        // Skipped when `enable_hash_db` is false (quick-scan mode) to avoid a
        // full file read on every candidate — YARA + heuristics catch threats
        // without the hash DB, and the DB rarely matches fresh downloads anyway.
        let hashes = if self.enable_hash_db {
            let h = if self.enable_multi_hash {
                self.calculate_all_hashes(path)?
            } else {
                FileHashes {
                    md5: String::new(),
                    sha256: compute_sha256(path)?,
                    sha512: String::new(),
                }
            };
            if let Some(signature) = self.check_all_hashes(&h) {
                return Ok(ScanResult::from_parts(
                    path.to_path_buf(),
                    ThreatLevel::Malicious,
                    format!("Known malware signature: {}", signature),
                    Some(h.sha256),
                    Some(signature.to_string()),
                    1.0,
                    vec![DetectionSignal::new("hash", format!("Hash match: {}", signature), 100)],
                ));
            }
            Some(h)
        } else {
            None
        };

        // ── Unified scoring: YARA + Heuristics ────────────────────────────────
        let mut total_score: i32 = 0;
        let mut all_signals: Vec<DetectionSignal> = Vec::new();
        let mut score_reasons: Vec<String> = Vec::new();
        let mut primary_signature: Option<String> = None;

        // ── Layer 2: YARA ─────────────────────────────────────────────────────
        // Skip YARA for files > 10 MiB — large files (game installers, media,
        // bundled runtimes) are almost never malware payloads and each one
        // would load its full content into the YARA scanner, making quick
        // scans 10-30× slower per file and pushing total time past the timeout.
        // A 5 s per-scan timeout in YaraEngine prevents pathological backtracking
        // in complex rules from hanging a worker thread indefinitely.
        const YARA_MAX_FILE_BYTES: u64 = 10 * 1024 * 1024;
        if self.enable_yara && self.yara.is_ready() && should_yara_scan(path)
            && file_size <= YARA_MAX_FILE_BYTES
        {
            // Pass `None` — no pre-read buffer at this point in the pipeline.
            // The heuristics buffer refactor (to share bytes across layers) is
            // tracked as future work; YaraEngine reads the file itself for now.
            match self.yara.scan_file(path, None) {
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
                Ok((heuristic_result, h_score)) => {
                    if heuristic_result.level != ThreatLevel::Clean {
                        total_score += h_score;
                        score_reasons.push(heuristic_result.reason.clone());
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
        let mut level = if total_score >= MALICIOUS_THRESHOLD {
            ThreatLevel::Malicious
        } else if total_score >= SUSPICIOUS_THRESHOLD {
            ThreatLevel::Suspicious
        } else {
            ThreatLevel::Clean
        };

        let mut confidence_score = match level {
            ThreatLevel::Clean      => 1.0,
            ThreatLevel::Suspicious => 0.55 + (total_score as f32 / 40.0).min(0.25),
            ThreatLevel::Malicious  => 0.70 + (total_score as f32 / 60.0).min(0.25),
        };

        // ── Layer 4: Ember2024 ML (gated — Suspicious/Malicious only) ─────────
        // Runs only on single-file scans so the Python subprocess cost does not
        // degrade directory or system-wide scan throughput.
        if level != ThreatLevel::Clean {
            if let Some(ember) = run_ember_ml(path) {
                all_signals.push(DetectionSignal::new(
                    "ember_ml",
                    format!("EMBER2024_{} score {:.4}", ember.file_type, ember.score),
                    // Audit-trail weight only; YARA+heuristics own the primary verdict.
                    if ember.malicious { 5 } else { 2 },
                ));
                score_reasons.push(format!(
                    "EMBER2024_{} {:.4} ({})",
                    ember.file_type,
                    ember.score,
                    if ember.malicious { "malicious" } else { "suspicious" },
                ));
                // Escalate Suspicious → Malicious when Ember concurs.
                if ember.malicious && level == ThreatLevel::Suspicious {
                    level = ThreatLevel::Malicious;
                }
                // Blend Ember confidence into the running score.
                let ember_confidence = 0.60 + (ember.score * 0.35).min(0.35);
                confidence_score = confidence_score.max(ember_confidence);
            }
        }

        // Use the SHA-256 from the hash-DB phase if available; heuristics may
        // also have computed it (stored inside heuristic_result.hash) but we
        // don't plumb it back here — clean results don't need the hash.
        let sha256 = hashes.as_ref().map(|h| h.sha256.clone());

        if level == ThreatLevel::Clean {
            return Ok(ScanResult::clean(path.to_path_buf(), sha256));
        }

        Ok(ScanResult::from_parts(
            path.to_path_buf(),
            level,
            format!("Score {}: {}", total_score, score_reasons.join(" | ")),
            sha256,
            primary_signature,
            confidence_score,
            all_signals,
        ))
    }

    // ── Optimised path: pre-read bytes + reusable YARA Scanner ───────────────

    /// Single-read, per-thread-scanner hot path used by `parallel_scan` workers.
    ///
    /// All three pipeline layers (hash, YARA, heuristics) operate on the same
    /// `bytes` slice — zero redundant disk reads per file.  The caller supplies
    /// a `yara_x::Scanner` that is created once per worker thread and reused
    /// across files, eliminating per-file wasmtime JIT re-initialisation.
    ///
    /// `file_size` must be the on-disk byte count (from `fs::metadata`), not
    /// `bytes.len()`, because large files (> 10 MiB) are passed with an empty
    /// `bytes` slice but still need accurate size metadata.
    pub fn scan_bytes_direct(
        &self,
        path: &Path,
        bytes: &[u8],
        file_size: u64,
        yara_scanner: Option<&mut yara_x::Scanner<'_>>,
    ) -> Result<ScanResult> {
        // ── Layer 1: Hash DB ──────────────────────────────────────────────────
        let hashes = if self.enable_hash_db && !bytes.is_empty() {
            let sha256 = compute_sha256_from_bytes(bytes);
            let (md5, sha512) = if self.enable_multi_hash {
                let md5_val = format!("{:x}", md5::compute(bytes));
                let mut h512 = sha2::Sha512::new();
                use sha2::Digest;
                h512.update(bytes);
                (md5_val, hex::encode(h512.finalize()))
            } else {
                (String::new(), String::new())
            };
            let h = FileHashes { md5, sha256, sha512 };
            if let Some(signature) = self.check_all_hashes(&h) {
                return Ok(ScanResult::from_parts(
                    path.to_path_buf(),
                    crate::core::types::ThreatLevel::Malicious,
                    format!("Known malware signature: {}", signature),
                    Some(h.sha256),
                    Some(signature.to_string()),
                    1.0,
                    vec![DetectionSignal::new("hash", format!("Hash match: {}", signature), 100)],
                ));
            }
            Some(h)
        } else if self.enable_hash_db {
            // file_size > 10 MiB; stream SHA-256 from disk
            if let Ok(sha256) = compute_sha256(path) {
                let h = FileHashes { md5: String::new(), sha256: sha256.clone(), sha512: String::new() };
                if let Some(sig) = self.check_all_hashes(&h) {
                    return Ok(ScanResult::from_parts(
                        path.to_path_buf(),
                        crate::core::types::ThreatLevel::Malicious,
                        format!("Known malware signature: {}", sig),
                        Some(sha256),
                        Some(sig.to_string()),
                        1.0,
                        vec![DetectionSignal::new("hash", format!("Hash match: {}", sig), 100)],
                    ));
                }
                Some(h)
            } else {
                None
            }
        } else {
            None
        };

        // ── Unified scoring ───────────────────────────────────────────────────
        let mut total_score: i32 = 0;
        let mut all_signals: Vec<DetectionSignal> = Vec::new();
        let mut score_reasons: Vec<String> = Vec::new();
        let mut primary_signature: Option<String> = None;

        // ── Layer 2: YARA ─────────────────────────────────────────────────────
        const YARA_MAX_FILE_BYTES: u64 = 10 * 1024 * 1024;
        if self.enable_yara && self.yara.is_ready() && should_yara_scan(path)
            && file_size <= YARA_MAX_FILE_BYTES && !bytes.is_empty()
        {
            let matches = match yara_scanner {
                Some(scanner) => YaraEngine::scan_data_reusing(scanner, bytes)
                    .unwrap_or_default(),
                None => self.yara.scan_file(path, Some(bytes))
                    .unwrap_or_default(),
            };

            if !matches.is_empty() {
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
        }

        // ── Layer 3: Heuristics from shared buffer ────────────────────────────
        if self.enable_deep_scan {
            match self.heuristics.analyze_from_bytes(path, bytes, file_size) {
                Ok((heuristic_result, h_score)) => {
                    if heuristic_result.level != crate::core::types::ThreatLevel::Clean {
                        total_score += h_score;
                        score_reasons.push(heuristic_result.reason.clone());
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
            crate::core::types::ThreatLevel::Malicious
        } else if total_score >= SUSPICIOUS_THRESHOLD {
            crate::core::types::ThreatLevel::Suspicious
        } else {
            crate::core::types::ThreatLevel::Clean
        };

        let confidence_score = match level {
            crate::core::types::ThreatLevel::Clean      => 1.0,
            crate::core::types::ThreatLevel::Suspicious => 0.55 + (total_score as f32 / 40.0).min(0.25),
            crate::core::types::ThreatLevel::Malicious  => 0.70 + (total_score as f32 / 60.0).min(0.25),
        };

        let sha256 = hashes.as_ref().map(|h| h.sha256.clone());

        if level == crate::core::types::ThreatLevel::Clean {
            return Ok(ScanResult::clean(path.to_path_buf(), sha256));
        }

        Ok(ScanResult::from_parts(
            path.to_path_buf(),
            level,
            format!("Score {}: {}", total_score, score_reasons.join(" | ")),
            sha256,
            primary_signature,
            confidence_score,
            all_signals,
        ))
    }

    // ── Directory scan with per-directory context ─────────────────────────────

    /// Full directory scan with context analysis.
    ///
    /// Context analysis is applied PER DIRECTORY — files are grouped by their
    /// immediate parent directory before context analysis runs. This prevents
    /// ransom notes in one subdirectory from escalating files in sibling dirs.
    ///
    /// Example: scanning C:\TestAV recursively
    ///   C:\TestAV\RansomDir\  → context analyzed together (ransom notes escalate each other)
    ///   C:\TestAV\SuspiciousOnly\ → context analyzed separately (not affected by RansomDir)
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

        // Pass 2: group results by immediate parent directory
        // then run context analysis per group independently
        let mut by_dir: HashMap<PathBuf, Vec<usize>> = HashMap::new();
        for (i, result) in results.iter().enumerate() {
            let parent = result.path.parent()
                .unwrap_or(dir)
                .to_path_buf();
            by_dir.entry(parent).or_default().push(i);
        }

        // Run context analyzer per directory group
        for (parent_dir, indices) in &by_dir {
            // Extract this group's results
            let mut group: Vec<ScanResult> = indices.iter()
                .map(|&i| results[i].clone())
                .collect();

            // Analyze context within this directory only
            self.context.analyze(&mut group, parent_dir);

            // Write annotated results back
            for (group_idx, &result_idx) in indices.iter().enumerate() {
                results[result_idx] = group[group_idx].clone();
            }
        }

        // Pass 3: recount stats after context escalation
        // (some Suspicious may have been escalated to Malicious by context)
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

    fn calculate_all_hashes(&self, path: &Path) -> Result<FileHashes> {
        let data = std::fs::read(path)?;
        let md5    = format!("{:x}", md5::compute(&data));
        let sha256 = compute_sha256_from_bytes(&data);
        let mut h512 = Sha512::new(); h512.update(&data);
        let sha512 = hex::encode(h512.finalize());
        Ok(FileHashes { md5, sha256, sha512 })
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
    pub fn set_hash_db(&mut self, enabled: bool)    { self.enable_hash_db = enabled; }
    pub fn yara_rules_loaded(&self) -> usize        { self.yara.rules_loaded }
    pub fn yara_arc(&self) -> Arc<YaraEngine>       { Arc::clone(&self.yara) }
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
        fs::remove_file(path).ok();
    }

    #[test]
    fn test_ml_notes_clean() {
        let path = std::env::temp_dir().join("ml_scanner_notes.txt");
        fs::write(&path,
            "Batch Normalization: Standardizes outputs of each layer. \
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
    fn test_per_directory_context_isolation() {
        let temp = std::env::temp_dir().join("isolation_test");
        let ransom_dir = temp.join("RansomDir");
        let clean_dir = temp.join("CleanDir");
        fs::create_dir_all(&ransom_dir).unwrap();
        fs::create_dir_all(&clean_dir).unwrap();

        // 3 ransom notes in RansomDir
        fs::write(ransom_dir.join("how_to_decrypt.txt"),
            "pay bitcoin to recover your files").unwrap();
        fs::write(ransom_dir.join("ransom_note.txt"),
            "all your files have been encrypted").unwrap();
        fs::write(ransom_dir.join("files_encrypted.txt"),
            "pay btc to decrypt your files").unwrap();

        // Clean file in CleanDir
        fs::write(clean_dir.join("document.txt"), "ordinary content").unwrap();

        let scanner = FileSystemScanner::new();
        let (results, _) = scanner.scan_directory_with_stats(&temp, true);

        // document.txt in CleanDir must stay Clean
        let doc = results.iter().find(|r| r.path.ends_with("document.txt"));
        if let Some(d) = doc {
            assert_eq!(d.level, ThreatLevel::Clean,
                "File in CleanDir should not be affected by RansomDir notes. Got: {}",
                d.reason);
        }

        fs::remove_dir_all(&temp).ok();
    }

    #[test]
    fn test_yara_weak_score() {
        assert_eq!(yara_rule_score("contains_base64"), 1);
        assert_eq!(yara_rule_score("domain"), 1);
        assert_eq!(yara_rule_score("powershell"), 1);
    }

    #[test]
    fn test_yara_strong_score() {
        assert_eq!(yara_rule_score("Wanna_Cry_Ransomware_Generic"), 10);
        assert_eq!(yara_rule_score("RAT_PlugX"), 10);
    }

}
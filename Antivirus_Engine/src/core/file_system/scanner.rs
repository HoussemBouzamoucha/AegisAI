// File: src/core/file_system/scanner.rs
// Multi-Hash Dynamic Scanner with YARA Integration

use crate::core::file_system::signature::SignatureDatabase;
use crate::core::file_system::heuristics::HeuristicAnalyzer;
use crate::core::file_system::yara_engine::YaraEngine;
use crate::core::types::{ScanResult, ThreatLevel};
use std::path::Path;
use anyhow::Result;
use sha2::{Sha256, Sha512, Digest};
use hex;

/// File hash information with multiple algorithms
#[derive(Debug, Clone)]
pub struct FileHashes {
    pub md5: String,
    pub sha256: String,
    pub sha512: String,
}

/// Scanning statistics
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
            ThreatLevel::Clean => self.clean_files += 1,
            ThreatLevel::Suspicious => self.suspicious_files += 1,
            ThreatLevel::Malicious => self.malicious_files += 1,
        }
    }

    pub fn add_error(&mut self) {
        self.error_files += 1;
    }
}

impl Default for ScanStatistics {
    fn default() -> Self {
        Self::new()
    }
}

pub struct FileSystemScanner {
    signatures: SignatureDatabase,
    heuristics: HeuristicAnalyzer,
    yara: YaraEngine,
    enable_multi_hash: bool,
    enable_deep_scan: bool,
    enable_yara: bool,
}

impl FileSystemScanner {
    pub fn new() -> Self {
        Self::with_options(true, true, true)
    }

    pub fn with_options(enable_multi_hash: bool, enable_deep_scan: bool, enable_yara: bool) -> Self {
        let yara = if enable_yara {
            YaraEngine::default()
        } else {
            YaraEngine::disabled()
        };

        Self {
            signatures: SignatureDatabase::new(),
            heuristics: HeuristicAnalyzer::new(),
            yara,
            enable_multi_hash,
            enable_deep_scan,
            enable_yara,
        }
    }

    /// Load YARA rules from a specific directory
    pub fn load_yara_rules(&mut self, rules_dir: &Path) -> Result<usize> {
        self.yara = YaraEngine::load_from_directory(rules_dir)?;
        Ok(self.yara.rules_loaded)
    }

    /// Main file scanning entry point with comprehensive analysis
    pub fn scan_file(&self, path: &Path) -> Result<ScanResult> {
        // 0. Get file metadata
        let _metadata = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(e) => {
                return Ok(ScanResult {
                    path: path.to_path_buf(),
                    level: ThreatLevel::Clean,
                    reason: format!("Cannot access file: {}", e),
                    hash: None,
                    signature: None,
                });
            }
        };

        // 1. Calculate file hashes
        let hashes = if self.enable_multi_hash {
            self.calculate_all_hashes(path)?
        } else {
            FileHashes {
                md5: String::new(),
                sha256: self.calculate_sha256(path)?,
                sha512: String::new(),
            }
        };

        // 2. Check hash signature database
        if let Some(signature) = self.check_all_hashes(&hashes) {
            return Ok(ScanResult {
                path: path.to_path_buf(),
                level: ThreatLevel::Malicious,
                reason: format!("Known malware signature: {}", signature),
                hash: Some(hashes.sha256.clone()),
                signature: Some(signature.to_string()),
            });
        }

        // 3. YARA rule matching
        if self.enable_yara && self.yara.is_ready() {
            match self.yara.scan_file(path) {
                Ok(matches) if !matches.is_empty() => {
                    // Default to Malicious — YARA rules are explicit detections.
                    // Only downgrade to Suspicious if the rule is explicitly
                    // tagged as informational or low-confidence.
                    let is_low_confidence = matches.iter().all(|m| {
                        m.tags.iter().any(|t| {
                            let t = t.to_lowercase();
                            t == "suspicious" || t == "info" || t == "informational"
                                || t == "low" || t == "fp_prone"
                        })
                    });

                    let level = if is_low_confidence {
                        ThreatLevel::Suspicious
                    } else {
                        ThreatLevel::Malicious
                    };

                    let rule_names: Vec<String> = matches
                        .iter()
                        .map(|m| m.rule_name.clone())
                        .collect();

                    let description = matches
                        .first()
                        .and_then(|m| m.meta_description.clone())
                        .unwrap_or_else(|| format!("Matched {} YARA rule(s)", matches.len()));

                    return Ok(ScanResult {
                        path: path.to_path_buf(),
                        level,
                        reason: format!("YARA match — {}: {}", rule_names.join(", "), description),
                        hash: Some(hashes.sha256.clone()),
                        signature: Some(rule_names.join(", ")),
                    });
                }
                Err(e) => {
                    eprintln!("YARA scan error for {}: {}", path.display(), e);
                }
                _ => {}
            }
        }

        // 4. Dynamic heuristic analysis
        if self.enable_deep_scan {
            match self.heuristics.analyze(path) {
                Ok(heuristic_result) => {
                    if heuristic_result.level != ThreatLevel::Clean {
                        return Ok(ScanResult {
                            path: path.to_path_buf(),
                            level: heuristic_result.level,
                            reason: heuristic_result.reason,
                            hash: Some(hashes.sha256),
                            signature: heuristic_result.signature,
                        });
                    }
                }
                Err(e) => {
                    eprintln!("Heuristic analysis error for {}: {}", path.display(), e);
                }
            }
        }

        // 5. File is clean
        Ok(ScanResult {
            path: path.to_path_buf(),
            level: ThreatLevel::Clean,
            reason: "No threats detected (multi-layer scan)".to_string(),
            hash: Some(hashes.sha256),
            signature: None,
        })
    }

    fn calculate_all_hashes(&self, path: &Path) -> Result<FileHashes> {
        let data = std::fs::read(path)?;

        let md5 = format!("{:x}", md5::compute(&data));

        let mut sha256_hasher = Sha256::new();
        sha256_hasher.update(&data);
        let sha256 = hex::encode(sha256_hasher.finalize());

        let mut sha512_hasher = Sha512::new();
        sha512_hasher.update(&data);
        let sha512 = hex::encode(sha512_hasher.finalize());

        Ok(FileHashes { md5, sha256, sha512 })
    }

    fn calculate_sha256(&self, path: &Path) -> Result<String> {
        let data = std::fs::read(path)?;
        let mut hasher = Sha256::new();
        hasher.update(&data);
        Ok(hex::encode(hasher.finalize()))
    }

    fn check_all_hashes(&self, hashes: &FileHashes) -> Option<&str> {
        if let Some(sig) = self.signatures.check_hash(&hashes.sha256) {
            return Some(sig);
        }
        if !hashes.md5.is_empty() {
            if let Some(sig) = self.signatures.check_hash(&hashes.md5) {
                return Some(sig);
            }
        }
        if !hashes.sha512.is_empty() {
            if let Some(sig) = self.signatures.check_hash(&hashes.sha512) {
                return Some(sig);
            }
        }
        None
    }

    pub fn scan_directory_with_stats(
        &self,
        dir: &Path,
        recursive: bool,
    ) -> (Vec<ScanResult>, ScanStatistics) {
        let mut results = Vec::new();
        let mut stats = ScanStatistics::new();

        for result in self.scan_directory(dir, recursive) {
            match result {
                Ok(scan_result) => {
                    let file_size = std::fs::metadata(&scan_result.path)
                        .map(|m| m.len())
                        .unwrap_or(0);
                    stats.update(&scan_result, file_size);
                    results.push(scan_result);
                }
                Err(e) => {
                    stats.add_error();
                    eprintln!("Scan error: {}", e);
                }
            }
        }

        (results, stats)
    }

    pub fn scan_directory<'a>(
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
                Err(e) => Some(Ok(ScanResult {
                    path: e.path()
                        .map(|p| p.to_path_buf())
                        .unwrap_or_else(|| dir_path.clone()),
                    level: ThreatLevel::Clean,
                    reason: format!("Directory scan error: {}", e),
                    hash: None,
                    signature: None,
                })),
            }
        })
    }

    pub fn get_signatures_mut(&mut self) -> &mut SignatureDatabase {
        &mut self.signatures
    }

    pub fn set_deep_scan(&mut self, enabled: bool) {
        self.enable_deep_scan = enabled;
    }

    pub fn set_multi_hash(&mut self, enabled: bool) {
        self.enable_multi_hash = enabled;
    }

    pub fn set_yara(&mut self, enabled: bool) {
        self.enable_yara = enabled;
    }

    pub fn yara_rules_loaded(&self) -> usize {
        self.yara.rules_loaded
    }
}

impl Default for FileSystemScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::fs::File;

    #[test]
    fn test_eicar_detection() {
        let temp_dir = std::env::temp_dir();
        let eicar_file = temp_dir.join("eicar.txt");
        let eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        std::fs::write(&eicar_file, eicar).unwrap();

        let scanner = FileSystemScanner::new();
        let result = scanner.scan_file(&eicar_file).unwrap();
        assert_eq!(result.level, ThreatLevel::Malicious);

        std::fs::remove_file(eicar_file).ok();
    }

    #[test]
    fn test_clean_file_scan() {
        let temp_dir = std::env::temp_dir();
        let clean_file = temp_dir.join("clean_test.txt");
        let mut file = File::create(&clean_file).unwrap();
        writeln!(file, "This is a completely clean file.").unwrap();

        let scanner = FileSystemScanner::new();
        let result = scanner.scan_file(&clean_file).unwrap();
        assert_eq!(result.level, ThreatLevel::Clean);

        std::fs::remove_file(clean_file).ok();
    }

    #[test]
    fn test_yara_engine_loads() {
        let scanner = FileSystemScanner::new();
        // Just verify it initializes without panicking
        // rules_loaded may be 0 if yara_rules dir isn't relative to test runner
        println!("YARA rules loaded: {}", scanner.yara_rules_loaded());
    }
}
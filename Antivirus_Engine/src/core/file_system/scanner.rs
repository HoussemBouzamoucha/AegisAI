// File: src/core/file_system/scanner.rs
// Multi-Hash Dynamic Scanner with YARA Integration

use crate::core::file_system::signature::SignatureDatabase;
use crate::core::file_system::heuristics::HeuristicAnalyzer;
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
    enable_multi_hash: bool,
    enable_deep_scan: bool,
}

impl FileSystemScanner {
    pub fn new() -> Self {
        Self::with_options(true, true)
    }
    
    pub fn with_options(enable_multi_hash: bool, enable_deep_scan: bool) -> Self {
        Self {
            signatures: SignatureDatabase::new(),
            heuristics: HeuristicAnalyzer::new(),
            enable_multi_hash,
            enable_deep_scan,
        }
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
        
        // 1. Calculate file hashes (multi-algorithm support)
        let hashes = if self.enable_multi_hash {
            self.calculate_all_hashes(path)?
        } else {
            FileHashes {
                md5: String::new(),
                sha256: self.calculate_sha256(path)?,
                sha512: String::new(),
            }
        };

        // 2. Check signature database (all hash types)
        if let Some(signature) = self.check_all_hashes(&hashes) {
            return Ok(ScanResult {
                path: path.to_path_buf(),
                level: ThreatLevel::Malicious,
                reason: format!("Known malware signature: {}", signature),
                hash: Some(hashes.sha256.clone()),
                signature: Some(signature.to_string()),
            });
        }

        // 3. DYNAMIC HEURISTIC ANALYSIS (Behavioral patterns)
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

        // 4. File is clean
        Ok(ScanResult {
            path: path.to_path_buf(),
            level: ThreatLevel::Clean,
            reason: "No threats detected (multi-layer scan)".to_string(),
            hash: Some(hashes.sha256),
            signature: None,
        })
    }
    
    /// Calculate all hash types for comprehensive detection
    fn calculate_all_hashes(&self, path: &Path) -> Result<FileHashes> {
        let data = std::fs::read(path)?;
        
        // MD5 hash
        let md5 = format!("{:x}", md5::compute(&data));
        
        // SHA-256 hash
        let mut sha256_hasher = Sha256::new();
        sha256_hasher.update(&data);
        let sha256 = hex::encode(sha256_hasher.finalize());
        
        // SHA-512 hash
        let mut sha512_hasher = Sha512::new();
        sha512_hasher.update(&data);
        let sha512 = hex::encode(sha512_hasher.finalize());
        
        Ok(FileHashes {
            md5,
            sha256,
            sha512,
        })
    }
    
    /// Calculate SHA-256 hash only (faster for basic checks)
    fn calculate_sha256(&self, path: &Path) -> Result<String> {
        let data = std::fs::read(path)?;
        let mut hasher = Sha256::new();
        hasher.update(&data);
        Ok(hex::encode(hasher.finalize()))
    }
    
    /// Check all hash types against signature database
    fn check_all_hashes(&self, hashes: &FileHashes) -> Option<&str> {
        // Check SHA-256 first (most common)
        if let Some(sig) = self.signatures.check_hash(&hashes.sha256) {
            return Some(sig);
        }
        
        // Check MD5
        if !hashes.md5.is_empty() {
            if let Some(sig) = self.signatures.check_hash(&hashes.md5) {
                return Some(sig);
            }
        }
        
        // Check SHA-512
        if !hashes.sha512.is_empty() {
            if let Some(sig) = self.signatures.check_hash(&hashes.sha512) {
                return Some(sig);
            }
        }
        
        None
    }

    /// Scan directory with statistics tracking
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
                Ok(e) if e.file_type().is_file() => {
                    Some(self.scan_file(e.path()))
                }
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
    
    /// Get file hashes for a specific file
    pub fn get_file_hashes(&self, path: &Path) -> Result<FileHashes> {
        self.calculate_all_hashes(path)
    }
    
    /// Enable or disable deep scanning
    pub fn set_deep_scan(&mut self, enabled: bool) {
        self.enable_deep_scan = enabled;
    }
    
    /// Enable or disable multi-hash calculation
    pub fn set_multi_hash(&mut self, enabled: bool) {
        self.enable_multi_hash = enabled;
    }
    
    /// Get signature database for manual updates
    pub fn get_signatures_mut(&mut self) -> &mut SignatureDatabase {
        &mut self.signatures
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
    fn test_multi_hash_calculation() {
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("hash_test.txt");
        
        let mut file = File::create(&test_file).unwrap();
        writeln!(file, "Test content for hashing").unwrap();
        
        let scanner = FileSystemScanner::new();
        let hashes = scanner.calculate_all_hashes(&test_file).unwrap();
        
        assert!(!hashes.md5.is_empty());
        assert!(!hashes.sha256.is_empty());
        assert!(!hashes.sha512.is_empty());
        assert_eq!(hashes.md5.len(), 32);
        assert_eq!(hashes.sha256.len(), 64);
        assert_eq!(hashes.sha512.len(), 128);
        
        std::fs::remove_file(test_file).ok();
    }
    
    #[test]
    fn test_eicar_detection() {
        let temp_dir = std::env::temp_dir();
        let eicar_file = temp_dir.join("eicar.txt");
        
        // EICAR test string
        let eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        std::fs::write(&eicar_file, eicar).unwrap();
        
        let scanner = FileSystemScanner::new();
        let result = scanner.scan_file(&eicar_file).unwrap();
        
        // Should be detected by hash
        assert_eq!(result.level, ThreatLevel::Malicious);
        
        std::fs::remove_file(eicar_file).ok();
    }
    
    #[test]
    fn test_clean_file_scan() {
        let temp_dir = std::env::temp_dir();
        let clean_file = temp_dir.join("clean.txt");
        
        let mut file = File::create(&clean_file).unwrap();
        writeln!(file, "This is a completely clean file.").unwrap();
        writeln!(file, "No malicious content here.").unwrap();
        
        let scanner = FileSystemScanner::new();
        let result = scanner.scan_file(&clean_file).unwrap();
        
        assert_eq!(result.level, ThreatLevel::Clean);
        
        std::fs::remove_file(clean_file).ok();
    }
    
    #[test]
    fn test_directory_scan_with_stats() {
        let temp_dir = std::env::temp_dir().join("scan_test");
        std::fs::create_dir_all(&temp_dir).ok();
        
        // Create test files
        let clean1 = temp_dir.join("clean1.txt");
        let clean2 = temp_dir.join("clean2.txt");
        
        std::fs::write(&clean1, "Clean content 1").unwrap();
        std::fs::write(&clean2, "Clean content 2").unwrap();
        
        let scanner = FileSystemScanner::new();
        let (results, stats) = scanner.scan_directory_with_stats(&temp_dir, false);
        
        assert_eq!(stats.total_files, 2);
        assert_eq!(stats.clean_files, 2);
        assert_eq!(results.len(), 2);
        
        std::fs::remove_dir_all(temp_dir).ok();
    }
    
    #[test]
    fn test_scanner_options() {
        let scanner1 = FileSystemScanner::with_options(true, true);
        assert!(scanner1.enable_multi_hash);
        assert!(scanner1.enable_deep_scan);
        
        let scanner2 = FileSystemScanner::with_options(false, false);
        assert!(!scanner2.enable_multi_hash);
        assert!(!scanner2.enable_deep_scan);
    }
}
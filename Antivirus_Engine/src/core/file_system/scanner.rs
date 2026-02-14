use crate::core::types::{ScanResult, ThreatLevel};
use crate::core::utils::compute_sha256;
use crate::core::file_system::heuristics::run_heuristics;
use crate::core::file_system::signature::SignatureDatabase;
use anyhow::Result;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use walkdir::WalkDir;

/// Statistics collected during a scan
#[derive(Debug, Clone, Default)]
pub struct ScanStatistics {
    pub total_files: usize,
    pub clean_files: usize,
    pub suspicious_files: usize,
    pub malicious_files: usize,
    pub errors: usize,
    pub total_bytes_scanned: u64,
}

impl ScanStatistics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn update(&mut self, result: &ScanResult) {
        self.total_files += 1;
        
        match result.level {
            ThreatLevel::Clean => self.clean_files += 1,
            ThreatLevel::Suspicious => self.suspicious_files += 1,
            ThreatLevel::Malicious => self.malicious_files += 1,
            ThreatLevel::Error => self.errors += 1,
        }
    }

    pub fn threat_count(&self) -> usize {
        self.suspicious_files + self.malicious_files
    }
}

pub struct FileSystemScanner {
    signatures: SignatureDatabase,
    stats: Arc<Mutex<ScanStatistics>>,
    max_file_size: Option<u64>, // Optional limit for scanning large files
}

impl FileSystemScanner {
    /// Create a new scanner with default settings
    pub fn new() -> Self {
        FileSystemScanner {
            signatures: SignatureDatabase::new(),
            stats: Arc::new(Mutex::new(ScanStatistics::new())),
            max_file_size: Some(100 * 1024 * 1024), // 100 MB default limit
        }
    }

    /// Create a scanner with custom signature database
    pub fn with_signatures(signatures: SignatureDatabase) -> Self {
        FileSystemScanner {
            signatures,
            stats: Arc::new(Mutex::new(ScanStatistics::new())),
            max_file_size: Some(100 * 1024 * 1024),
        }
    }

    /// Set maximum file size for scanning (in bytes)
    /// Files larger than this will be skipped with a warning
    pub fn set_max_file_size(&mut self, size: Option<u64>) {
        self.max_file_size = size;
    }

    /// Get current scan statistics
    pub fn get_statistics(&self) -> ScanStatistics {
        self.stats.lock().unwrap().clone()
    }

    /// Reset scan statistics
    pub fn reset_statistics(&self) {
        *self.stats.lock().unwrap() = ScanStatistics::new();
    }

    /// Scan a single file (does not scan directories)
    pub fn scan_file(&self, path: &Path) -> Result<ScanResult> {
        if !path.is_file() {
            let result = ScanResult::clean(path.to_path_buf());
            self.update_stats(&result);
            return Ok(result);
        }

        // Check file size limit
        if let Some(max_size) = self.max_file_size {
            if let Ok(metadata) = path.metadata() {
                if metadata.len() > max_size {
                    let result = ScanResult::error(
                        path.to_path_buf(),
                        format!(
                            "File too large to scan ({} bytes, limit: {} bytes)",
                            metadata.len(),
                            max_size
                        ),
                    );
                    self.update_stats(&result);
                    return Ok(result);
                }
            }
        }

        // 1. Compute hash
        let hash = match compute_sha256(path) {
            Ok(h) => h,
            Err(e) => {
                let result = ScanResult::error(
                    path.to_path_buf(),
                    format!("Failed to compute hash: {}", e),
                );
                self.update_stats(&result);
                return Ok(result);
            }
        };

        // 2. Check known signatures
        if let Some(malware) = self.signatures.check_hash(&hash) {
            let result = ScanResult::malicious(
                path.to_path_buf(),
                format!("Known hash signature: {}", malware),
                Some(malware.to_string()),
            );
            self.update_stats(&result);
            return Ok(result);
        }

        // 3. Run file-specific heuristics
        let heuristic_result = run_heuristics(path);
        if heuristic_result.level != ThreatLevel::Clean {
            self.update_stats(&heuristic_result);
            return Ok(heuristic_result);
        }

        // 4. Clean file
        let mut result = ScanResult::clean(path.to_path_buf());
        result.hash = Some(hash);
        self.update_stats(&result);
        Ok(result)
    }

    /// Scan a directory (recursive or non-recursive)
    pub fn scan_directory(
        &self,
        dir: &Path,
        recursive: bool,
    ) -> impl Iterator<Item = Result<ScanResult>> + '_ {
        let dir_path = dir.to_path_buf(); // Clone the path to avoid lifetime issues
        
        let walker = if recursive {
            WalkDir::new(dir).follow_links(false)
        } else {
            WalkDir::new(dir).max_depth(1).follow_links(false)
        };

        walker
            .into_iter()
            .filter_map(move |entry| {
                let entry = match entry {
                    Ok(e) => e,
                    Err(e) => {
                        // Create error result for failed directory entry
                        let path = e.path()
                            .map(|p| p.to_path_buf())
                            .unwrap_or_else(|| dir_path.clone());
                        let result = ScanResult::error(
                            path,
                            format!("Failed to read directory entry: {}", e),
                        );
                        return Some(Ok(result));
                    }
                };

                if !entry.file_type().is_file() {
                    return None;
                }

                Some(self.scan_file(entry.path()))
            })
    }

    /// Scan multiple paths (can be files or directories)
    pub fn scan_paths(
        &self,
        paths: &[PathBuf],
        recursive: bool,
    ) -> Vec<Result<ScanResult>> {
        let mut results = Vec::new();

        for path in paths {
            if path.is_file() {
                results.push(self.scan_file(path));
            } else if path.is_dir() {
                results.extend(self.scan_directory(path, recursive));
            } else {
                results.push(Ok(ScanResult::error(
                    path.clone(),
                    "Path does not exist or is not accessible".to_string(),
                )));
            }
        }

        results
    }

    /// Add a signature to the database
    pub fn add_signature(&mut self, hash: String, malware_name: String) {
        self.signatures.add_signature(hash, malware_name);
    }

    /// Load signatures from a file
    pub fn load_signatures_from_file(&mut self, path: &Path) -> Result<usize> {
        self.signatures.load_from_file(path)
    }

    /// Save signatures to a file
    pub fn save_signatures_to_file(&self, path: &Path) -> Result<()> {
        self.signatures.save_to_file(path)
    }

    /// Helper to update statistics
    fn update_stats(&self, result: &ScanResult) {
        if let Ok(mut stats) = self.stats.lock() {
            stats.update(result);
            
            // Update bytes scanned if available
            if let Ok(metadata) = result.path.metadata() {
                stats.total_bytes_scanned += metadata.len();
            }
        }
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
    use std::fs;
    use std::io::Write;

    #[test]
    fn test_scan_clean_file() {
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("test_clean.txt");
        
        let mut file = fs::File::create(&test_file).unwrap();
        file.write_all(b"This is a clean test file").unwrap();
        
        let scanner = FileSystemScanner::new();
        let result = scanner.scan_file(&test_file).unwrap();
        
        assert_eq!(result.level, ThreatLevel::Clean);
        assert!(result.hash.is_some());
        
        fs::remove_file(&test_file).unwrap();
    }

    #[test]
    fn test_scan_eicar() {
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("eicar.com");
        
        // EICAR test string
        let eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        
        let mut file = fs::File::create(&test_file).unwrap();
        file.write_all(eicar).unwrap();
        
        let scanner = FileSystemScanner::new();
        let result = scanner.scan_file(&test_file).unwrap();
        
        assert_eq!(result.level, ThreatLevel::Malicious);
        
        fs::remove_file(&test_file).unwrap();
    }

    #[test]
    fn test_statistics() {
        let scanner = FileSystemScanner::new();
        scanner.reset_statistics();
        
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("stats_test.txt");
        
        let mut file = fs::File::create(&test_file).unwrap();
        file.write_all(b"test content").unwrap();
        
        let _result = scanner.scan_file(&test_file).unwrap();
        
        let stats = scanner.get_statistics();
        assert_eq!(stats.total_files, 1);
        assert!(stats.total_bytes_scanned > 0);
        
        fs::remove_file(&test_file).unwrap();
    }
}
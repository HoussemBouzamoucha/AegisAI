// File: src/core/types.rs
// Core type definitions for the antivirus engine

use std::path::PathBuf;

/// Threat level classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ThreatLevel {
    /// No threat detected
    Clean,
    /// Potentially malicious, requires review
    Suspicious,
    /// Confirmed malicious
    Malicious,
}

impl ThreatLevel {
    pub fn as_str(&self) -> &str {
        match self {
            ThreatLevel::Clean => "Clean",
            ThreatLevel::Suspicious => "Suspicious",
            ThreatLevel::Malicious => "Malicious",
        }
    }
    
    pub fn emoji(&self) -> &str {
        match self {
            ThreatLevel::Clean => "✅",
            ThreatLevel::Suspicious => "⚠️",
            ThreatLevel::Malicious => "🚨",
        }
    }
    
    pub fn is_threat(&self) -> bool {
        matches!(self, ThreatLevel::Suspicious | ThreatLevel::Malicious)
    }
}

impl std::fmt::Display for ThreatLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Result of a file scan
#[derive(Debug, Clone)]
pub struct ScanResult {
    /// Path to the scanned file
    pub path: PathBuf,
    /// Detected threat level
    pub level: ThreatLevel,
    /// Human-readable reason for the classification
    pub reason: String,
    /// File hash (typically SHA-256)
    pub hash: Option<String>,
    /// Signature or pattern that matched (if any)
    pub signature: Option<String>,
}

impl ScanResult {
    /// Create a new scan result
    pub fn new(
        path: PathBuf,
        level: ThreatLevel,
        reason: String,
        hash: Option<String>,
        signature: Option<String>,
    ) -> Self {
        Self {
            path,
            level,
            reason,
            hash,
            signature,
        }
    }
    
    /// Create an error result (used for inaccessible files)
    pub fn error(path: PathBuf, reason: String) -> Self {
        Self {
            path,
            level: ThreatLevel::Clean,
            reason,
            hash: None,
            signature: None,
        }
    }
    
    /// Create a clean result
    pub fn clean(path: PathBuf, hash: Option<String>) -> Self {
        Self {
            path,
            level: ThreatLevel::Clean,
            reason: "No threats detected".to_string(),
            hash,
            signature: None,
        }
    }
    
    /// Create a suspicious result
    pub fn suspicious(
        path: PathBuf,
        reason: String,
        hash: Option<String>,
    ) -> Self {
        Self {
            path,
            level: ThreatLevel::Suspicious,
            reason,
            hash,
            signature: None,
        }
    }
    
    /// Create a malicious result
    pub fn malicious(
        path: PathBuf,
        reason: String,
        hash: Option<String>,
        signature: Option<String>,
    ) -> Self {
        Self {
            path,
            level: ThreatLevel::Malicious,
            reason,
            hash,
            signature,
        }
    }
    
    /// Get a formatted display string
    pub fn display(&self) -> String {
        format!(
            "{} {} - {}",
            self.level.emoji(),
            self.path.display(),
            self.reason
        )
    }
    
    /// Get file name only
    pub fn file_name(&self) -> String {
        self.path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string()
    }
}

impl std::fmt::Display for ScanResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display())
    }
}

/// Scan configuration options
#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// Enable multi-hash calculation (MD5, SHA256, SHA512)
    pub multi_hash: bool,
    /// Enable deep heuristic analysis
    pub deep_scan: bool,
    /// Enable YARA scanning (if compiled with yara feature)
    pub yara_scan: bool,
    /// Maximum file size to scan (in bytes)
    pub max_file_size: u64,
    /// Scan recursively in directories
    pub recursive: bool,
    /// Follow symbolic links
    pub follow_links: bool,
}

impl ScanConfig {
    /// Create a default configuration
    pub fn new() -> Self {
        Self {
            multi_hash: true,
            deep_scan: true,
            yara_scan: true,
            max_file_size: 100 * 1024 * 1024, // 100 MB
            recursive: true,
            follow_links: false,
        }
    }
    
    /// Create a fast scan configuration
    pub fn fast() -> Self {
        Self {
            multi_hash: false,
            deep_scan: false,
            yara_scan: false,
            max_file_size: 10 * 1024 * 1024, // 10 MB
            recursive: false,
            follow_links: false,
        }
    }
    
    /// Create a thorough scan configuration
    pub fn thorough() -> Self {
        Self {
            multi_hash: true,
            deep_scan: true,
            yara_scan: true,
            max_file_size: 500 * 1024 * 1024, // 500 MB
            recursive: true,
            follow_links: true,
        }
    }
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_threat_level_display() {
        assert_eq!(ThreatLevel::Clean.as_str(), "Clean");
        assert_eq!(ThreatLevel::Suspicious.as_str(), "Suspicious");
        assert_eq!(ThreatLevel::Malicious.as_str(), "Malicious");
    }
    
    #[test]
    fn test_threat_level_is_threat() {
        assert!(!ThreatLevel::Clean.is_threat());
        assert!(ThreatLevel::Suspicious.is_threat());
        assert!(ThreatLevel::Malicious.is_threat());
    }
    
    #[test]
    fn test_scan_result_creation() {
        let path = PathBuf::from("test.exe");
        
        let clean = ScanResult::clean(path.clone(), Some("abc123".to_string()));
        assert_eq!(clean.level, ThreatLevel::Clean);
        
        let suspicious = ScanResult::suspicious(
            path.clone(),
            "High entropy".to_string(),
            None,
        );
        assert_eq!(suspicious.level, ThreatLevel::Suspicious);
        
        let malicious = ScanResult::malicious(
            path.clone(),
            "Known malware".to_string(),
            Some("def456".to_string()),
            Some("Trojan.Generic".to_string()),
        );
        assert_eq!(malicious.level, ThreatLevel::Malicious);
        assert!(malicious.signature.is_some());
    }
    
    #[test]
    fn test_scan_config() {
        let default = ScanConfig::new();
        assert!(default.multi_hash);
        assert!(default.deep_scan);
        
        let fast = ScanConfig::fast();
        assert!(!fast.multi_hash);
        assert!(!fast.deep_scan);
        
        let thorough = ScanConfig::thorough();
        assert!(thorough.multi_hash);
        assert!(thorough.deep_scan);
        assert!(thorough.follow_links);
    }
}
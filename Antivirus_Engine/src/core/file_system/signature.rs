// File: src/core/file_system/signature.rs
// Multi-Hash Signature Database with Advanced Management

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

#[cfg(feature = "json")]
use serde::{Deserialize, Serialize};

/// Malware signature entry with metadata
#[cfg_attr(feature = "json", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct SignatureEntry {
    pub hash: String,
    pub hash_type: HashType,
    pub malware_name: String,
    pub severity: ThreatSeverity,
    pub family: Option<String>,
    pub description: Option<String>,
    pub added_date: Option<String>,
}

/// Hash algorithm type
#[cfg_attr(feature = "json", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashType {
    MD5,
    SHA1,
    SHA256,
    SHA512,
}

impl HashType {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "md5" => Some(HashType::MD5),
            "sha1" => Some(HashType::SHA1),
            "sha256" => Some(HashType::SHA256),
            "sha512" => Some(HashType::SHA512),
            _ => None,
        }
    }
    
    pub fn as_str(&self) -> &str {
        match self {
            HashType::MD5 => "md5",
            HashType::SHA1 => "sha1",
            HashType::SHA256 => "sha256",
            HashType::SHA512 => "sha512",
        }
    }
    
    pub fn expected_length(&self) -> usize {
        match self {
            HashType::MD5 => 32,
            HashType::SHA1 => 40,
            HashType::SHA256 => 64,
            HashType::SHA512 => 128,
        }
    }
}

/// Threat severity level
#[cfg_attr(feature = "json", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ThreatSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl ThreatSeverity {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "low" => ThreatSeverity::Low,
            "medium" => ThreatSeverity::Medium,
            "high" => ThreatSeverity::High,
            "critical" => ThreatSeverity::Critical,
            _ => ThreatSeverity::Medium,
        }
    }
    
    pub fn as_str(&self) -> &str {
        match self {
            ThreatSeverity::Low => "low",
            ThreatSeverity::Medium => "medium",
            ThreatSeverity::High => "high",
            ThreatSeverity::Critical => "critical",
        }
    }
}

/// Database of known malware signatures with multi-hash support
#[cfg_attr(feature = "json", derive(Serialize, Deserialize))]
pub struct SignatureDatabase {
    // Hash -> SignatureEntry mapping
    signatures: HashMap<String, SignatureEntry>,
    // Index by malware family for fast lookups
    family_index: HashMap<String, Vec<String>>,
}

impl SignatureDatabase {
    /// Create a new signature database with default signatures
    pub fn new() -> Self {
        let mut db = Self {
            signatures: HashMap::new(),
            family_index: HashMap::new(),
        };

        // Add default test signatures
        db.add_default_signatures();
        
        db
    }

    /// Create an empty signature database
    pub fn empty() -> Self {
        Self {
            signatures: HashMap::new(),
            family_index: HashMap::new(),
        }
    }

    /// Add default malware signatures (for testing and common threats)
    fn add_default_signatures(&mut self) {
        // EICAR test file (standard antivirus test)
        self.add_signature_entry(SignatureEntry {
            hash: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f".to_string(),
            hash_type: HashType::SHA256,
            malware_name: "EICAR-Test-File".to_string(),
            severity: ThreatSeverity::Low,
            family: Some("Test".to_string()),
            description: Some("Standard antivirus test file".to_string()),
            added_date: None,
        });
        
        // EICAR MD5
        self.add_signature_entry(SignatureEntry {
            hash: "44d88612fea8a8f36de82e1278abb02f".to_string(),
            hash_type: HashType::MD5,
            malware_name: "EICAR-Test-File".to_string(),
            severity: ThreatSeverity::Low,
            family: Some("Test".to_string()),
            description: Some("Standard antivirus test file".to_string()),
            added_date: None,
        });
        
        // Example ransomware signatures (placeholder - add real hashes)
        self.add_signature_entry(SignatureEntry {
            hash: "example_wannacry_hash_sha256".to_string(),
            hash_type: HashType::SHA256,
            malware_name: "WannaCry".to_string(),
            severity: ThreatSeverity::Critical,
            family: Some("Ransomware".to_string()),
            description: Some("WannaCry ransomware variant".to_string()),
            added_date: None,
        });
        
        self.add_signature_entry(SignatureEntry {
            hash: "example_emotet_hash_sha256".to_string(),
            hash_type: HashType::SHA256,
            malware_name: "Emotet".to_string(),
            severity: ThreatSeverity::High,
            family: Some("Trojan".to_string()),
            description: Some("Emotet banking trojan".to_string()),
            added_date: None,
        });
        
        self.add_signature_entry(SignatureEntry {
            hash: "example_mirai_hash_sha256".to_string(),
            hash_type: HashType::SHA256,
            malware_name: "Mirai".to_string(),
            severity: ThreatSeverity::High,
            family: Some("Botnet".to_string()),
            description: Some("Mirai IoT botnet malware".to_string()),
            added_date: None,
        });
    }

    /// Check if a hash matches a known malware signature (all hash types)
    pub fn check_hash(&self, hash: &str) -> Option<&str> {
        let normalized_hash = hash.to_lowercase();
        self.signatures
            .get(&normalized_hash)
            .map(|entry| entry.malware_name.as_str())
    }
    
    /// Get full signature entry for a hash
    pub fn get_signature(&self, hash: &str) -> Option<&SignatureEntry> {
        let normalized_hash = hash.to_lowercase();
        self.signatures.get(&normalized_hash)
    }

    /// Add a new signature entry to the database
    pub fn add_signature_entry(&mut self, entry: SignatureEntry) {
        let normalized_hash = entry.hash.to_lowercase();
        
        // Update family index
        if let Some(ref family) = entry.family {
            self.family_index
                .entry(family.clone())
                .or_insert_with(Vec::new)
                .push(normalized_hash.clone());
        }
        
        self.signatures.insert(normalized_hash, entry);
    }

    /// Add a simple signature (backward compatibility)
    pub fn add_signature(&mut self, hash: String, malware_name: String) {
        let hash_type = self.detect_hash_type(&hash);
        
        let entry = SignatureEntry {
            hash: hash.clone(),
            hash_type,
            malware_name,
            severity: ThreatSeverity::Medium,
            family: None,
            description: None,
            added_date: None,
        };
        
        self.add_signature_entry(entry);
    }
    
    /// Detect hash type from hash length
    fn detect_hash_type(&self, hash: &str) -> HashType {
        match hash.len() {
            32 => HashType::MD5,
            40 => HashType::SHA1,
            64 => HashType::SHA256,
            128 => HashType::SHA512,
            _ => HashType::SHA256, // Default
        }
    }

    /// Remove a signature from the database
    pub fn remove_signature(&mut self, hash: &str) -> Option<SignatureEntry> {
        let normalized_hash = hash.to_lowercase();
        
        if let Some(entry) = self.signatures.remove(&normalized_hash) {
            // Update family index
            if let Some(ref family) = entry.family {
                if let Some(hashes) = self.family_index.get_mut(family) {
                    hashes.retain(|h| h != &normalized_hash);
                    if hashes.is_empty() {
                        self.family_index.remove(family);
                    }
                }
            }
            Some(entry)
        } else {
            None
        }
    }

    /// Get the number of signatures in the database
    pub fn signature_count(&self) -> usize {
        self.signatures.len()
    }
    
    /// Get statistics by hash type
    pub fn stats_by_hash_type(&self) -> HashMap<HashType, usize> {
        let mut stats = HashMap::new();
        
        for entry in self.signatures.values() {
            *stats.entry(entry.hash_type).or_insert(0) += 1;
        }
        
        stats
    }
    
    /// Get statistics by severity
    pub fn stats_by_severity(&self) -> HashMap<ThreatSeverity, usize> {
        let mut stats = HashMap::new();
        
        for entry in self.signatures.values() {
            *stats.entry(entry.severity).or_insert(0) += 1;
        }
        
        stats
    }
    
    /// Get statistics by family
    pub fn stats_by_family(&self) -> HashMap<String, usize> {
        self.family_index
            .iter()
            .map(|(family, hashes)| (family.clone(), hashes.len()))
            .collect()
    }

    /// Check if the database is empty
    pub fn is_empty(&self) -> bool {
        self.signatures.is_empty()
    }

    /// Clear all signatures from the database
    pub fn clear(&mut self) {
        self.signatures.clear();
        self.family_index.clear();
    }

    /// Load signatures from a CSV file
    pub fn load_from_file(&mut self, path: &Path) -> Result<usize> {
        let file = File::open(path)
            .with_context(|| format!("Failed to open signature file: {}", path.display()))?;
        
        let reader = BufReader::new(file);
        let mut count = 0;
        let mut is_enhanced_format = false;

        for (line_num, line) in reader.lines().enumerate() {
            let line = line
                .with_context(|| format!("Failed to read line {} from {}", line_num + 1, path.display()))?;
            
            let trimmed = line.trim();
            
            // Skip empty lines and comments
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            
            // Check format on first data line
            if count == 0 && trimmed.contains(',') {
                let parts: Vec<&str> = trimmed.split(',').collect();
                is_enhanced_format = parts.len() >= 4;
            }

            // Parse based on format
            if is_enhanced_format {
                if let Some(entry) = self.parse_enhanced_line(trimmed, line_num + 1) {
                    self.add_signature_entry(entry);
                    count += 1;
                }
            } else {
                if let Some(entry) = self.parse_basic_line(trimmed, line_num + 1) {
                    self.add_signature_entry(entry);
                    count += 1;
                }
            }
        }

        Ok(count)
    }
    
    fn parse_enhanced_line(&self, line: &str, line_num: usize) -> Option<SignatureEntry> {
        let parts: Vec<&str> = line.splitn(6, ',').collect();
        
        if parts.len() < 3 {
            eprintln!("Warning: Skipping malformed line {}: {}", line_num, line);
            return None;
        }
        
        let hash = parts[0].trim().to_string();
        let hash_type = if parts.len() > 1 {
            HashType::from_str(parts[1].trim()).unwrap_or_else(|| self.detect_hash_type(&hash))
        } else {
            self.detect_hash_type(&hash)
        };
        let malware_name = parts[2].trim().to_string();
        let severity = if parts.len() > 3 {
            ThreatSeverity::from_str(parts[3].trim())
        } else {
            ThreatSeverity::Medium
        };
        let family = if parts.len() > 4 && !parts[4].trim().is_empty() {
            Some(parts[4].trim().to_string())
        } else {
            None
        };
        let description = if parts.len() > 5 && !parts[5].trim().is_empty() {
            Some(parts[5].trim().to_string())
        } else {
            None
        };
        
        if hash.is_empty() || malware_name.is_empty() {
            eprintln!("Warning: Skipping line {} with empty hash or name", line_num);
            return None;
        }
        
        Some(SignatureEntry {
            hash,
            hash_type,
            malware_name,
            severity,
            family,
            description,
            added_date: None,
        })
    }
    
    fn parse_basic_line(&self, line: &str, line_num: usize) -> Option<SignatureEntry> {
        let parts: Vec<&str> = line.splitn(2, ',').collect();
        
        if parts.len() != 2 {
            eprintln!("Warning: Skipping malformed line {}: {}", line_num, line);
            return None;
        }
        
        let hash = parts[0].trim().to_string();
        let malware_name = parts[1].trim().to_string();
        
        if hash.is_empty() || malware_name.is_empty() {
            eprintln!("Warning: Skipping line {} with empty hash or name", line_num);
            return None;
        }
        
        Some(SignatureEntry {
            hash: hash.clone(),
            hash_type: self.detect_hash_type(&hash),
            malware_name,
            severity: ThreatSeverity::Medium,
            family: None,
            description: None,
            added_date: None,
        })
    }

    /// Save signatures to a file in enhanced CSV format
    pub fn save_to_file(&self, path: &Path) -> Result<()> {
        let mut file = File::create(path)
            .with_context(|| format!("Failed to create signature file: {}", path.display()))?;

        // Write header
        writeln!(file, "# Malware Signature Database (Enhanced Format)")?;
        writeln!(file, "# Format: hash,hash_type,malware_name,severity,family,description")?;
        writeln!(file, "#")?;
        writeln!(file, "hash,hash_type,malware_name,severity,family,description")?;

        // Write all signatures
        for entry in self.signatures.values() {
            writeln!(
                file,
                "{},{},{},{},{},{}",
                entry.hash,
                entry.hash_type.as_str(),
                entry.malware_name,
                entry.severity.as_str(),
                entry.family.as_ref().unwrap_or(&String::new()),
                entry.description.as_ref().unwrap_or(&String::new())
            )?;
        }

        Ok(())
    }

    /// Merge another signature database into this one
    pub fn merge(&mut self, other: &SignatureDatabase) {
        for entry in other.signatures.values() {
            self.add_signature_entry(entry.clone());
        }
    }

    /// Get all signatures as a vector
    pub fn list_signatures(&self) -> Vec<SignatureEntry> {
        self.signatures.values().cloned().collect()
    }

    /// Search for signatures by malware name (case-insensitive partial match)
    pub fn search_by_name(&self, query: &str) -> Vec<SignatureEntry> {
        let query_lower = query.to_lowercase();
        
        self.signatures
            .values()
            .filter(|entry| entry.malware_name.to_lowercase().contains(&query_lower))
            .cloned()
            .collect()
    }
    
    /// Search signatures by family
    pub fn search_by_family(&self, family: &str) -> Vec<SignatureEntry> {
        self.family_index
            .get(family)
            .map(|hashes| {
                hashes
                    .iter()
                    .filter_map(|hash| self.signatures.get(hash).cloned())
                    .collect()
            })
            .unwrap_or_default()
    }
    
    /// Search signatures by severity
    pub fn search_by_severity(&self, severity: ThreatSeverity) -> Vec<SignatureEntry> {
        self.signatures
            .values()
            .filter(|entry| entry.severity == severity)
            .cloned()
            .collect()
    }
    
    /// Get all malware families
    pub fn list_families(&self) -> Vec<String> {
        self.family_index.keys().cloned().collect()
    }

    /// Export signatures as JSON
    #[cfg(feature = "json")]
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(&self.signatures)
            .context("Failed to serialize signatures to JSON")
    }

    /// Import signatures from JSON
    #[cfg(feature = "json")]
    pub fn from_json(json: &str) -> Result<Self> {
        let signatures: HashMap<String, SignatureEntry> = serde_json::from_str(json)
            .context("Failed to deserialize signatures from JSON")?;
        
        let mut db = Self::empty();
        for entry in signatures.values() {
            db.add_signature_entry(entry.clone());
        }
        
        Ok(db)
    }

    /// Load signatures from a JSON file
    #[cfg(feature = "json")]
    pub fn load_from_json_file(&mut self, path: &Path) -> Result<usize> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read JSON file: {}", path.display()))?;
        
        let loaded_db = Self::from_json(&content)?;
        let count = loaded_db.signature_count();
        
        self.merge(&loaded_db);
        
        Ok(count)
    }

    /// Save signatures to a JSON file
    #[cfg(feature = "json")]
    pub fn save_to_json_file(&self, path: &Path) -> Result<()> {
        let json = self.to_json()?;
        
        std::fs::write(path, json)
            .with_context(|| format!("Failed to write JSON file: {}", path.display()))?;
        
        Ok(())
    }
    
    /// Import signatures from a threat intelligence feed URL
    /// Format: hash,malware_name per line
    pub fn import_from_feed(&mut self, _url: &str) -> Result<usize> {
        // This would require an HTTP client - placeholder implementation
        // In production, use reqwest or similar
        Err(anyhow::anyhow!("Feed import not implemented - add reqwest dependency"))
    }
    
    /// Validate database integrity
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();
        
        for (hash, entry) in &self.signatures {
            // Check hash format
            if hash.len() != entry.hash_type.expected_length() {
                errors.push(format!(
                    "Hash length mismatch for {}: expected {} chars for {:?}",
                    entry.malware_name,
                    entry.hash_type.expected_length(),
                    entry.hash_type
                ));
            }
            
            // Check for invalid hex characters
            if !hash.chars().all(|c| c.is_ascii_hexdigit()) {
                errors.push(format!(
                    "Invalid hash characters for {}: {}",
                    entry.malware_name,
                    hash
                ));
            }
        }
        
        errors
    }
}

impl Default for SignatureDatabase {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_type_detection() {
        let db = SignatureDatabase::empty();
        
        assert_eq!(db.detect_hash_type("d41d8cd98f00b204e9800998ecf8427e"), HashType::MD5);
        assert_eq!(db.detect_hash_type("da39a3ee5e6b4b0d3255bfef95601890afd80709"), HashType::SHA1);
        assert_eq!(
            db.detect_hash_type("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            HashType::SHA256
        );
    }
    
    #[test]
    fn test_check_hash() {
        let db = SignatureDatabase::new();
        
        // EICAR hash should be recognized
        let eicar_sha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
        assert!(db.check_hash(eicar_sha256).is_some());
        
        let eicar_md5 = "44d88612fea8a8f36de82e1278abb02f";
        assert!(db.check_hash(eicar_md5).is_some());
        
        // Random hash should not be recognized
        assert!(db.check_hash("deadbeef").is_none());
    }

    #[test]
    fn test_add_remove_signature() {
        let mut db = SignatureDatabase::empty();
        
        let entry = SignatureEntry {
            hash: "abc123".to_string(),
            hash_type: HashType::MD5,
            malware_name: "TestMalware".to_string(),
            severity: ThreatSeverity::High,
            family: Some("Trojan".to_string()),
            description: Some("Test malware".to_string()),
            added_date: None,
        };
        
        db.add_signature_entry(entry);
        assert_eq!(db.signature_count(), 1);
        assert!(db.check_hash("abc123").is_some());
        
        db.remove_signature("abc123");
        assert_eq!(db.signature_count(), 0);
        assert!(db.check_hash("abc123").is_none());
    }

    #[test]
    fn test_case_insensitive() {
        let mut db = SignatureDatabase::empty();
        
        db.add_signature("ABC123".to_string(), "TestMalware".to_string());
        
        assert!(db.check_hash("abc123").is_some());
        assert!(db.check_hash("ABC123").is_some());
        assert!(db.check_hash("AbC123").is_some());
    }

    #[test]
    fn test_family_search() {
        let mut db = SignatureDatabase::empty();
        
        let entry1 = SignatureEntry {
            hash: "hash1".to_string(),
            hash_type: HashType::SHA256,
            malware_name: "Trojan1".to_string(),
            severity: ThreatSeverity::High,
            family: Some("Trojan".to_string()),
            description: None,
            added_date: None,
        };
        
        let entry2 = SignatureEntry {
            hash: "hash2".to_string(),
            hash_type: HashType::SHA256,
            malware_name: "Trojan2".to_string(),
            severity: ThreatSeverity::High,
            family: Some("Trojan".to_string()),
            description: None,
            added_date: None,
        };
        
        db.add_signature_entry(entry1);
        db.add_signature_entry(entry2);
        
        let trojans = db.search_by_family("Trojan");
        assert_eq!(trojans.len(), 2);
    }
    
    #[test]
    fn test_statistics() {
        let mut db = SignatureDatabase::empty();
        
        db.add_signature_entry(SignatureEntry {
            hash: "hash1".to_string(),
            hash_type: HashType::MD5,
            malware_name: "Malware1".to_string(),
            severity: ThreatSeverity::High,
            family: Some("Trojan".to_string()),
            description: None,
            added_date: None,
        });
        
        db.add_signature_entry(SignatureEntry {
            hash: "hash2".to_string(),
            hash_type: HashType::SHA256,
            malware_name: "Malware2".to_string(),
            severity: ThreatSeverity::Critical,
            family: Some("Ransomware".to_string()),
            description: None,
            added_date: None,
        });
        
        let hash_stats = db.stats_by_hash_type();
        assert_eq!(hash_stats.get(&HashType::MD5), Some(&1));
        assert_eq!(hash_stats.get(&HashType::SHA256), Some(&1));
        
        let severity_stats = db.stats_by_severity();
        assert_eq!(severity_stats.get(&ThreatSeverity::High), Some(&1));
        assert_eq!(severity_stats.get(&ThreatSeverity::Critical), Some(&1));
    }
}
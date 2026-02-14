use anyhow::{Context, Result};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

#[cfg(feature = "json")]
use serde::{Deserialize, Serialize};

/// Database of known malware signatures (hash-based)
#[cfg_attr(feature = "json", derive(Serialize, Deserialize))]
pub struct SignatureDatabase {
    known_hashes: HashMap<String, String>,
}

impl SignatureDatabase {
    /// Create a new signature database with default signatures
    pub fn new() -> Self {
        let mut db = Self {
            known_hashes: HashMap::new(),
        };

        // Add default test signatures
        db.add_default_signatures();
        
        db
    }

    /// Create an empty signature database
    pub fn empty() -> Self {
        Self {
            known_hashes: HashMap::new(),
        }
    }

    /// Add default malware signatures (mainly for testing)
    fn add_default_signatures(&mut self) {
        // Classic EICAR test file (SHA-256)
        // This is the standard antivirus test file
        self.known_hashes.insert(
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f".to_string(),
            "EICAR-Test-File".to_string(),
        );

        // EICAR with different line endings (sometimes used)
        self.known_hashes.insert(
            "3395856ce81f2b7382dee72602f798b642f14140".to_string(),
            "EICAR-Test-File-Variant".to_string(),
        );

        // Add more real-world hashes here as they become available
        // Example structure:
        // self.known_hashes.insert(
        //     "actual_malware_sha256_hash".to_string(),
        //     "Malware.Family.Name".to_string(),
        // );
    }

    /// Check if a hash matches a known malware signature
    pub fn check_hash(&self, hash: &str) -> Option<&str> {
        // Normalize hash to lowercase for comparison
        let normalized_hash = hash.to_lowercase();
        self.known_hashes.get(&normalized_hash).map(|s| s.as_str())
    }

    /// Add a new signature to the database
    pub fn add_signature(&mut self, hash: String, malware_name: String) {
        let normalized_hash = hash.to_lowercase();
        self.known_hashes.insert(normalized_hash, malware_name);
    }

    /// Remove a signature from the database
    pub fn remove_signature(&mut self, hash: &str) -> Option<String> {
        let normalized_hash = hash.to_lowercase();
        self.known_hashes.remove(&normalized_hash)
    }

    /// Get the number of signatures in the database
    pub fn signature_count(&self) -> usize {
        self.known_hashes.len()
    }

    /// Check if the database is empty
    pub fn is_empty(&self) -> bool {
        self.known_hashes.is_empty()
    }

    /// Clear all signatures from the database
    pub fn clear(&mut self) {
        self.known_hashes.clear();
    }

    /// Load signatures from a file
    /// 
    /// File format (CSV-like):
    /// ```
    /// hash,malware_name
    /// 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f,EICAR-Test-File
    /// ```
    /// 
    /// Lines starting with '#' are treated as comments and ignored.
    pub fn load_from_file(&mut self, path: &Path) -> Result<usize> {
        let file = File::open(path)
            .with_context(|| format!("Failed to open signature file: {}", path.display()))?;
        
        let reader = BufReader::new(file);
        let mut count = 0;

        for (line_num, line) in reader.lines().enumerate() {
            let line = line
                .with_context(|| format!("Failed to read line {} from {}", line_num + 1, path.display()))?;
            
            let trimmed = line.trim();
            
            // Skip empty lines and comments
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            // Parse CSV format: hash,malware_name
            let parts: Vec<&str> = trimmed.splitn(2, ',').collect();
            
            if parts.len() != 2 {
                eprintln!(
                    "Warning: Skipping malformed line {} in {}: {}",
                    line_num + 1,
                    path.display(),
                    trimmed
                );
                continue;
            }

            let hash = parts[0].trim().to_string();
            let malware_name = parts[1].trim().to_string();

            if hash.is_empty() || malware_name.is_empty() {
                eprintln!(
                    "Warning: Skipping line {} with empty hash or name",
                    line_num + 1
                );
                continue;
            }

            self.add_signature(hash, malware_name);
            count += 1;
        }

        Ok(count)
    }

    /// Save signatures to a file
    /// 
    /// Saves in CSV format with a header
    pub fn save_to_file(&self, path: &Path) -> Result<()> {
        let mut file = File::create(path)
            .with_context(|| format!("Failed to create signature file: {}", path.display()))?;

        // Write header
        writeln!(file, "# Malware Signature Database")?;
        writeln!(file, "# Format: hash,malware_name")?;
        writeln!(file, "#")?;

        // Write all signatures
        for (hash, malware_name) in &self.known_hashes {
            writeln!(file, "{},{}", hash, malware_name)?;
        }

        Ok(())
    }

    /// Merge another signature database into this one
    /// 
    /// If there are conflicts (same hash), the incoming database wins
    pub fn merge(&mut self, other: &SignatureDatabase) {
        for (hash, malware_name) in &other.known_hashes {
            self.known_hashes.insert(hash.clone(), malware_name.clone());
        }
    }

    /// Get all signatures as a vector of (hash, malware_name) tuples
    pub fn list_signatures(&self) -> Vec<(String, String)> {
        self.known_hashes
            .iter()
            .map(|(h, n)| (h.clone(), n.clone()))
            .collect()
    }

    /// Search for signatures by malware name (case-insensitive partial match)
    pub fn search_by_name(&self, query: &str) -> Vec<(String, String)> {
        let query_lower = query.to_lowercase();
        
        self.known_hashes
            .iter()
            .filter(|(_, name)| name.to_lowercase().contains(&query_lower))
            .map(|(h, n)| (h.clone(), n.clone()))
            .collect()
    }

    /// Export signatures as JSON (useful for API integration)
    /// 
    /// Requires the "json" feature to be enabled
    #[cfg(feature = "json")]
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(&self.known_hashes)
            .context("Failed to serialize signatures to JSON")
    }

    /// Import signatures from JSON
    /// 
    /// Requires the "json" feature to be enabled
    #[cfg(feature = "json")]
    pub fn from_json(json: &str) -> Result<Self> {
        let known_hashes: HashMap<String, String> = serde_json::from_str(json)
            .context("Failed to deserialize signatures from JSON")?;
        
        Ok(Self { known_hashes })
    }

    /// Load signatures from a JSON file
    /// 
    /// Requires the "json" feature to be enabled
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
    /// 
    /// Requires the "json" feature to be enabled
    #[cfg(feature = "json")]
    pub fn save_to_json_file(&self, path: &Path) -> Result<()> {
        let json = self.to_json()?;
        
        std::fs::write(path, json)
            .with_context(|| format!("Failed to write JSON file: {}", path.display()))?;
        
        Ok(())
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
    fn test_check_hash() {
        let db = SignatureDatabase::new();
        
        // EICAR hash should be recognized
        let eicar_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
        assert!(db.check_hash(eicar_hash).is_some());
        
        // Random hash should not be recognized
        assert!(db.check_hash("deadbeef").is_none());
    }

    #[test]
    fn test_add_remove_signature() {
        let mut db = SignatureDatabase::empty();
        
        db.add_signature("abc123".to_string(), "TestMalware".to_string());
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
        
        // Should match regardless of case
        assert!(db.check_hash("abc123").is_some());
        assert!(db.check_hash("ABC123").is_some());
        assert!(db.check_hash("AbC123").is_some());
    }

    #[test]
    fn test_save_load() {
        let temp_dir = std::env::temp_dir();
        let sig_file = temp_dir.join("test_signatures.csv");
        
        // Create and save database
        let mut db1 = SignatureDatabase::empty();
        db1.add_signature("hash1".to_string(), "Malware1".to_string());
        db1.add_signature("hash2".to_string(), "Malware2".to_string());
        
        db1.save_to_file(&sig_file).unwrap();
        
        // Load into new database
        let mut db2 = SignatureDatabase::empty();
        let count = db2.load_from_file(&sig_file).unwrap();
        
        assert_eq!(count, 2);
        assert_eq!(db2.signature_count(), 2);
        assert!(db2.check_hash("hash1").is_some());
        assert!(db2.check_hash("hash2").is_some());
        
        // Cleanup
        std::fs::remove_file(&sig_file).unwrap();
    }

    #[test]
    fn test_merge() {
        let mut db1 = SignatureDatabase::empty();
        db1.add_signature("hash1".to_string(), "Malware1".to_string());
        
        let mut db2 = SignatureDatabase::empty();
        db2.add_signature("hash2".to_string(), "Malware2".to_string());
        
        db1.merge(&db2);
        
        assert_eq!(db1.signature_count(), 2);
        assert!(db1.check_hash("hash1").is_some());
        assert!(db1.check_hash("hash2").is_some());
    }

    #[test]
    fn test_search_by_name() {
        let mut db = SignatureDatabase::empty();
        db.add_signature("hash1".to_string(), "Trojan.Generic".to_string());
        db.add_signature("hash2".to_string(), "Trojan.Specific".to_string());
        db.add_signature("hash3".to_string(), "Virus.Boot".to_string());
        
        let results = db.search_by_name("trojan");
        assert_eq!(results.len(), 2);
        
        let results = db.search_by_name("virus");
        assert_eq!(results.len(), 1);
    }

    #[cfg(feature = "json")]
    #[test]
    fn test_json_export_import() {
        let mut db1 = SignatureDatabase::empty();
        db1.add_signature("hash1".to_string(), "Malware1".to_string());
        db1.add_signature("hash2".to_string(), "Malware2".to_string());
        
        // Export to JSON
        let json = db1.to_json().unwrap();
        
        // Import from JSON
        let db2 = SignatureDatabase::from_json(&json).unwrap();
        
        assert_eq!(db2.signature_count(), 2);
        assert!(db2.check_hash("hash1").is_some());
        assert!(db2.check_hash("hash2").is_some());
    }

    #[cfg(feature = "json")]
    #[test]
    fn test_json_file_operations() {
        let temp_dir = std::env::temp_dir();
        let json_file = temp_dir.join("test_signatures.json");
        
        // Create and save database
        let mut db1 = SignatureDatabase::empty();
        db1.add_signature("hash1".to_string(), "Malware1".to_string());
        db1.add_signature("hash2".to_string(), "Malware2".to_string());
        
        db1.save_to_json_file(&json_file).unwrap();
        
        // Load into new database
        let mut db2 = SignatureDatabase::empty();
        let count = db2.load_from_json_file(&json_file).unwrap();
        
        assert_eq!(count, 2);
        assert_eq!(db2.signature_count(), 2);
        assert!(db2.check_hash("hash1").is_some());
        assert!(db2.check_hash("hash2").is_some());
        
        // Cleanup
        std::fs::remove_file(&json_file).unwrap();
    }
}
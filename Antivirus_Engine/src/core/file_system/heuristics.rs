// File: src/core/file_system/heuristics.rs
// Dynamic Behavioral Analysis Engine with Multi-Method Detection

use crate::core::types::{ScanResult, ThreatLevel};
use std::path::Path;
use std::fs::{self, File};
use std::io::Read;
use anyhow::Result;
use std::collections::HashMap;

pub struct HeuristicAnalyzer {
    behavioral_patterns: BehavioralPatternDatabase,
}

// Maximum file size to read for content analysis (10 MB)
const MAX_CONTENT_SCAN_SIZE: u64 = 10 * 1024 * 1024;

// Threat scoring system (0-100, higher = more threatening)
const MALICIOUS_THRESHOLD: i32 = 70;
const SUSPICIOUS_THRESHOLD: i32 = 40;

/// Database of behavioral patterns for dynamic analysis
struct BehavioralPatternDatabase {
    ransomware_indicators: HashMap<String, i32>,
    trojan_indicators: HashMap<String, i32>,
    worm_indicators: HashMap<String, i32>,
    rootkit_indicators: HashMap<String, i32>,
    spyware_indicators: HashMap<String, i32>,
}

impl BehavioralPatternDatabase {
    fn new() -> Self {
        let mut db = Self {
            ransomware_indicators: HashMap::new(),
            trojan_indicators: HashMap::new(),
            worm_indicators: HashMap::new(),
            rootkit_indicators: HashMap::new(),
            spyware_indicators: HashMap::new(),
        };
        
        // Ransomware patterns (HIGH RISK: 20-30 points each)
        db.ransomware_indicators.insert("encrypted".to_string(), 25);
        db.ransomware_indicators.insert("decrypt".to_string(), 25);
        db.ransomware_indicators.insert("bitcoin".to_string(), 30);
        db.ransomware_indicators.insert("btc".to_string(), 30);
        db.ransomware_indicators.insert("ransom".to_string(), 35);
        db.ransomware_indicators.insert("payment".to_string(), 15);
        db.ransomware_indicators.insert("recover".to_string(), 10);
        db.ransomware_indicators.insert("restore".to_string(), 10);
        db.ransomware_indicators.insert("aes-256".to_string(), 20);
        db.ransomware_indicators.insert("rsa-".to_string(), 20);
        db.ransomware_indicators.insert("your files".to_string(), 25);
        db.ransomware_indicators.insert("all files".to_string(), 20);
        db.ransomware_indicators.insert("locked".to_string(), 20);
        db.ransomware_indicators.insert("deadline".to_string(), 15);
        db.ransomware_indicators.insert("contact us".to_string(), 10);
        
        // Trojan patterns (MEDIUM-HIGH RISK: 15-25 points)
        db.trojan_indicators.insert("keylog".to_string(), 25);
        db.trojan_indicators.insert("backdoor".to_string(), 25);
        db.trojan_indicators.insert("remote access".to_string(), 20);
        db.trojan_indicators.insert("stealer".to_string(), 25);
        db.trojan_indicators.insert("credential".to_string(), 15);
        db.trojan_indicators.insert("password".to_string(), 10);
        db.trojan_indicators.insert("injection".to_string(), 20);
        db.trojan_indicators.insert("hook".to_string(), 15);
        
        // Worm patterns (MEDIUM RISK: 10-20 points)
        db.worm_indicators.insert("propagate".to_string(), 20);
        db.worm_indicators.insert("replicate".to_string(), 20);
        db.worm_indicators.insert("spread".to_string(), 15);
        db.worm_indicators.insert("network scan".to_string(), 15);
        db.worm_indicators.insert("autorun".to_string(), 15);
        
        // Rootkit patterns (HIGH RISK: 20-30 points)
        db.rootkit_indicators.insert("kernel".to_string(), 20);
        db.rootkit_indicators.insert("driver".to_string(), 15);
        db.rootkit_indicators.insert("hide process".to_string(), 30);
        db.rootkit_indicators.insert("hide file".to_string(), 30);
        db.rootkit_indicators.insert("privilege escalation".to_string(), 25);
        
        // Spyware patterns (MEDIUM RISK: 10-20 points)
        db.spyware_indicators.insert("screenshot".to_string(), 15);
        db.spyware_indicators.insert("clipboard".to_string(), 15);
        db.spyware_indicators.insert("monitor".to_string(), 10);
        db.spyware_indicators.insert("track".to_string(), 10);
        db.spyware_indicators.insert("spy".to_string(), 20);
        
        db
    }
    
    fn calculate_threat_score(&self, content: &str) -> (i32, Vec<String>) {
        let content_lower = content.to_lowercase();
        let mut total_score = 0;
        let mut matched_patterns = Vec::new();
        
        // Check all pattern databases
        for (pattern, score) in &self.ransomware_indicators {
            if content_lower.contains(pattern) {
                total_score += score;
                matched_patterns.push(format!("Ransomware:{}", pattern));
            }
        }
        
        for (pattern, score) in &self.trojan_indicators {
            if content_lower.contains(pattern) {
                total_score += score;
                matched_patterns.push(format!("Trojan:{}", pattern));
            }
        }
        
        for (pattern, score) in &self.worm_indicators {
            if content_lower.contains(pattern) {
                total_score += score;
                matched_patterns.push(format!("Worm:{}", pattern));
            }
        }
        
        for (pattern, score) in &self.rootkit_indicators {
            if content_lower.contains(pattern) {
                total_score += score;
                matched_patterns.push(format!("Rootkit:{}", pattern));
            }
        }
        
        for (pattern, score) in &self.spyware_indicators {
            if content_lower.contains(pattern) {
                total_score += score;
                matched_patterns.push(format!("Spyware:{}", pattern));
            }
        }
        
        (total_score, matched_patterns)
    }
}

impl HeuristicAnalyzer {
    pub fn new() -> Self {
        HeuristicAnalyzer {
            behavioral_patterns: BehavioralPatternDatabase::new(),
        }
    }

    /// Main dynamic analysis entry point
    pub fn analyze(&self, path: &Path) -> Result<ScanResult> {
        let metadata = fs::metadata(path)?;
        let file_size = metadata.len();
        
        let mut threat_score = 0;
        let mut threat_indicators = Vec::new();
        let mut threat_category = String::from("Unknown");
        
        // 1. File metadata analysis
        if let Some((score, category, reason)) = self.analyze_metadata(path, &metadata) {
            threat_score += score;
            threat_category = String::from(category);
            threat_indicators.push(reason);
        }
        
        // 2. Filename pattern analysis
        if let Some((score, reason)) = self.analyze_filename_patterns(path) {
            threat_score += score;
            threat_indicators.push(reason);
        }
        
        // 3. Extension analysis
        if let Some((score, reason)) = self.analyze_extension(path) {
            threat_score += score;
            threat_indicators.push(reason);
        }
        
        // 4. Content-based dynamic analysis (for small files)
        if file_size < MAX_CONTENT_SCAN_SIZE && file_size > 0 {
            if let Some((score, reasons, category)) = self.analyze_file_content(path, file_size)? {
                threat_score += score;
                threat_category = category;
                threat_indicators.extend(reasons);
            }
        }
        
        // 5. Structural analysis (PE headers, file signatures)
        if let Some((score, reason)) = self.analyze_file_structure(path, file_size)? {
            threat_score += score;
            threat_indicators.push(reason);
        }
        
        // 6. Entropy analysis (packed/encrypted detection)
        if file_size > 100 && file_size < MAX_CONTENT_SCAN_SIZE {
            if let Some((score, reason)) = self.analyze_entropy(path, file_size)? {
                threat_score += score;
                threat_indicators.push(reason);
            }
        }
        
        // 7. Temporal analysis (suspicious timestamps)
        if let Some((score, reason)) = self.analyze_timestamps(&metadata) {
            threat_score += score;
            threat_indicators.push(reason);
        }
        
        // Determine final threat level based on accumulated score
        let (level, signature) = self.classify_threat(threat_score, &threat_category);
        
        let reason = if threat_indicators.is_empty() {
            "Dynamic analysis: No suspicious patterns detected".to_string()
        } else {
            format!(
                "Dynamic analysis (score: {}): {}",
                threat_score,
                threat_indicators.join("; ")
            )
        };
        
        Ok(ScanResult {
            path: path.to_path_buf(),
            level,
            reason,
            hash: None,
            signature,
        })
    }
    
    /// Classify threat based on score and category
    fn classify_threat(&self, score: i32, category: &str) -> (ThreatLevel, Option<String>) {
        if score >= MALICIOUS_THRESHOLD {
            (
                ThreatLevel::Malicious,
                Some(format!("Behavioral.{}.Detected", category))
            )
        } else if score >= SUSPICIOUS_THRESHOLD {
            (
                ThreatLevel::Suspicious,
                Some(format!("Behavioral.{}.Suspected", category))
            )
        } else {
            (ThreatLevel::Clean, None)
        }
    }
    
    /// Analyze file metadata (permissions, size anomalies)
    fn analyze_metadata(&self, path: &Path, metadata: &fs::Metadata) -> Option<(i32, &'static str, String)> {
        let file_size = metadata.len();
        
        // Zero-byte executables are highly suspicious
        if file_size == 0 {
            if let Some(ext) = path.extension() {
                let ext_str = ext.to_str()?.to_lowercase();
                if ["exe", "bat", "cmd", "scr", "vbs", "ps1", "dll", "sys"].contains(&ext_str.as_str()) {
                    return Some((45, "Wiper", "Zero-byte executable (data destruction indicator)".to_string()));
                }
            }
        }
        
        // Extremely small executables (< 1KB) are suspicious
        if file_size < 1024 && file_size > 0 {
            if let Some(ext) = path.extension() {
                let ext_str = ext.to_str()?.to_lowercase();
                if ["exe", "dll", "sys"].contains(&ext_str.as_str()) {
                    return Some((35, "Dropper", "Unusually small executable (possible dropper)".to_string()));
                }
            }
        }
        
        // Very large script files are suspicious
        if file_size > 1_000_000 {
            if let Some(ext) = path.extension() {
                let ext_str = ext.to_str()?.to_lowercase();
                if ["bat", "cmd", "vbs", "ps1", "js"].contains(&ext_str.as_str()) {
                    return Some((20, "Obfuscated", "Unusually large script file".to_string()));
                }
            }
        }
        
        None
    }
    
    /// Analyze filename patterns for malicious indicators
    fn analyze_filename_patterns(&self, path: &Path) -> Option<(i32, String)> {
        let filename_lower = path.file_name()?.to_str()?.to_lowercase();
        
        // Ransomware note patterns (increased scores)
        let ransomware_patterns = [
            ("readme", 35),      // Increased from 20
            ("read_me", 35),     // Increased from 20
            ("decrypt", 45),     // Increased from 25
            ("recovery", 30),    // Increased from 15
            ("restore", 30),     // Increased from 15
            ("howto", 35),       // Increased from 20
            ("instruction", 35), // Increased from 20
            ("ransom", 50),      // Increased from 30
            ("locked", 45),      // Increased from 25
            ("encrypted", 45),   // Increased from 25
            ("!!!", 30),         // Increased from 15
        ];
        
        for (pattern, score) in &ransomware_patterns {
            if filename_lower.contains(pattern) {
                if let Some(ext) = path.extension() {
                    let ext_str = ext.to_str()?.to_lowercase();
                    if ["txt", "html", "htm", "hta"].contains(&ext_str.as_str()) {
                        return Some((*score, format!("Ransomware note pattern: '{}'", pattern)));
                    }
                }
            }
        }
        
        // Suspicious executable patterns (increased scores)
        let malware_patterns = [
            ("crypt", 35),       // Increased from 20
            ("lock", 35),        // Increased from 20
            ("trojan", 40),      // Increased from 25
            ("virus", 40),       // Increased from 25
            ("worm", 40),        // Increased from 25
            ("rat", 40),         // Increased from 25
            ("keylog", 45),      // Increased from 30
            ("stealer", 45),     // Increased from 30
            ("miner", 35),       // Increased from 20
            ("backdoor", 40),    // Increased from 25
            ("inject", 35),      // Increased from 20
            ("payload", 35),     // Increased from 20
            ("exploit", 40),     // Increased from 25
        ];
        
        if let Some(ext) = path.extension() {
            let ext_str = ext.to_str()?.to_lowercase();
            if ["exe", "dll", "bat", "cmd", "scr", "vbs", "ps1"].contains(&ext_str.as_str()) {
                for (pattern, score) in &malware_patterns {
                    if filename_lower.contains(pattern) {
                        return Some((*score, format!("Malware pattern in filename: '{}'", pattern)));
                    }
                }
            }
        }
        
        // Obfuscated filenames (random characters)
        if filename_lower.len() > 20 {
            let alpha_count = filename_lower.chars().filter(|c| c.is_alphabetic()).count();
            let digit_count = filename_lower.chars().filter(|c| c.is_numeric()).count();
            
            if digit_count > alpha_count && digit_count > 10 {
                return Some((40, "Obfuscated filename (high digit ratio)".to_string()));
            }
        }
        
        None
    }
    
    /// Analyze file extension for threats
    fn analyze_extension(&self, path: &Path) -> Option<(i32, String)> {
        let ext = path.extension()?.to_str()?.to_lowercase();
        
        // Known ransomware extensions (CRITICAL)
        let ransomware_extensions = [
            ("locked", 35),
            ("encrypted", 35),
            ("crypted", 35),
            ("enc", 30),
            ("crypt", 35),
            ("locky", 40),
            ("cerber", 40),
            ("zepto", 40),
            ("thor", 40),
            ("wannacry", 40),
            ("petya", 40),
            ("cryptolocker", 40),
            ("ryuk", 40),
            ("maze", 40),
            ("revil", 40),
        ];
        
        for (ransomware_ext, score) in &ransomware_extensions {
            if ext == *ransomware_ext {
                return Some((*score, format!("Ransomware extension: .{}", ransomware_ext)));
            }
        }
        
        // Double extensions (file.txt.exe)
        if let Some(stem) = path.file_stem() {
            if let Some(stem_str) = stem.to_str() {
                if stem_str.contains('.') {
                    let parts: Vec<&str> = stem_str.split('.').collect();
                    if parts.len() > 1 {
                        let inner_ext = parts.last()?.to_lowercase();
                        let outer_ext = ext.clone();
                        
                        // Dangerous combinations
                        if ["txt", "pdf", "doc", "jpg", "png"].contains(&inner_ext.as_str())
                            && ["exe", "scr", "bat", "cmd"].contains(&outer_ext.as_str())
                        {
                            return Some((25, format!("Double extension: .{}.{}", inner_ext, outer_ext)));
                        }
                    }
                }
            }
        }
        
        None
    }
    
    /// Deep content analysis with behavioral pattern matching
    fn analyze_file_content(&self, path: &Path, _file_size: u64) -> Result<Option<(i32, Vec<String>, String)>> {
        // Determine if we should analyze content based on extension
        let should_analyze = if let Some(ext) = path.extension() {
            let ext_str = ext.to_str().unwrap_or("").to_lowercase();
            ["txt", "html", "htm", "hta", "bat", "cmd", "vbs", "ps1", "js", "md"].contains(&ext_str.as_str())
        } else {
            false
        };
        
        if !should_analyze {
            return Ok(None);
        }
        
        // Read file content
        let mut file = File::open(path)?;
        let mut content = String::new();
        
        match file.read_to_string(&mut content) {
            Ok(_) => {},
            Err(_) => return Ok(None), // Binary file, skip
        }
        
        // Use behavioral pattern database for scoring
        let (score, matched_patterns) = self.behavioral_patterns.calculate_threat_score(&content);
        
        if score == 0 {
            return Ok(None);
        }
        
        // Determine primary category
        let category = self.determine_primary_category(&matched_patterns);
        
        // Additional crypto address check
        let mut total_score = score;
        let mut reasons = matched_patterns.iter()
            .map(|p| p.to_string())
            .collect::<Vec<String>>();
        
        if self.contains_crypto_address(&content) {
            total_score += 25;
            reasons.push("Cryptocurrency address detected".to_string());
        }
        
        // Check for base64 encoded payloads
        if self.contains_base64_payload(&content) {
            total_score += 15;
            reasons.push("Base64 encoded payload detected".to_string());
        }
        
        // Check for PowerShell obfuscation
        if self.contains_powershell_obfuscation(&content) {
            total_score += 20;
            reasons.push("PowerShell obfuscation detected".to_string());
        }
        
        Ok(Some((total_score, reasons, category)))
    }
    
    /// Determine primary threat category from matched patterns
    fn determine_primary_category(&self, patterns: &[String]) -> String {
        let mut category_counts: HashMap<&str, usize> = HashMap::new();
        
        for pattern in patterns {
            if let Some(category) = pattern.split(':').next() {
                *category_counts.entry(category).or_insert(0) += 1;
            }
        }
        
        // Find the most common category, or return "Malware" as default
        if let Some((cat, _)) = category_counts.into_iter().max_by_key(|(_, count)| *count) {
            // Match against known categories
            match cat {
                "Ransomware" => "Ransomware".to_string(),
                "Trojan" => "Trojan".to_string(),
                "Worm" => "Worm".to_string(),
                "Rootkit" => "Rootkit".to_string(),
                "Spyware" => "Spyware".to_string(),
                _ => "Malware".to_string(),
            }
        } else {
            "Malware".to_string()
        }
    }
    
    /// Detect cryptocurrency addresses
    fn contains_crypto_address(&self, content: &str) -> bool {
        // Bitcoin address pattern (33-34 chars, starts with 1, 3, or bc1)
        let has_btc_pattern = content.lines().any(|line| {
            line.split_whitespace().any(|word| {
                (word.len() >= 26 && word.len() <= 35) &&
                (word.starts_with('1') || word.starts_with('3') || word.starts_with("bc1"))
            })
        });
        
        // Ethereum address pattern (0x followed by 40 hex chars)
        let has_eth_pattern = content.contains("0x") && 
            content.chars().collect::<Vec<char>>()
                .windows(42)
                .any(|w| {
                    let s: String = w.iter().collect();
                    s.starts_with("0x") && s[2..].chars().all(|c| c.is_ascii_hexdigit())
                });
        
        // Monero address pattern (95 chars, starts with 4)
        let has_xmr_pattern = content.lines().any(|line| {
            line.split_whitespace().any(|word| {
                word.len() >= 95 && word.starts_with('4')
            })
        });
        
        has_btc_pattern || has_eth_pattern || has_xmr_pattern
    }
    
    /// Detect base64 encoded payloads
    fn contains_base64_payload(&self, content: &str) -> bool {
        // Look for long base64 strings (potential encoded malware)
        content.lines().any(|line| {
            let trimmed = line.trim();
            trimmed.len() > 200 &&
            trimmed.chars().all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '=') &&
            trimmed.chars().filter(|&c| c == '=').count() <= 2
        })
    }
    
    /// Detect PowerShell obfuscation techniques
    fn contains_powershell_obfuscation(&self, content: &str) -> bool {
        let content_lower = content.to_lowercase();
        
        // Common PowerShell obfuscation patterns
        let obfuscation_patterns = [
            "-enc",           // Encoded command
            "-encodedcommand",
            "invoke-expression",
            "iex",
            "invoke-webrequest",
            "downloadstring",
            "downloadfile",
            "bitstransfer",
            "reflection.assembly",
            "system.net.webclient",
            "[convert]::frombase64string",
        ];
        
        let mut matches = 0;
        for pattern in &obfuscation_patterns {
            if content_lower.contains(pattern) {
                matches += 1;
            }
        }
        
        matches >= 2
    }
    
    /// Analyze file structure (magic bytes, PE headers)
    fn analyze_file_structure(&self, path: &Path, file_size: u64) -> Result<Option<(i32, String)>> {
        if file_size < 4 {
            return Ok(None);
        }
        
        let mut file = File::open(path)?;
        let mut header = [0u8; 512];
        let bytes_read = file.read(&mut header)?;
        
        if bytes_read < 4 {
            return Ok(None);
        }
        
        // Check magic bytes
        let magic = &header[0..4];
        
        // PE executable check
        if magic[0..2] == [0x4D, 0x5A] { // "MZ"
            // Check if extension matches
            if let Some(ext) = path.extension() {
                let ext_str = ext.to_str().unwrap_or("").to_lowercase();
                
                // PE file with wrong extension
                if !["exe", "dll", "sys", "scr"].contains(&ext_str.as_str()) {
                    return Ok(Some((25, format!("PE executable disguised as .{}", ext_str))));
                }
            }
            
            // Check for suspicious PE characteristics
            if bytes_read >= 64 {
                // Look for PE signature
                let e_lfanew = u32::from_le_bytes([header[60], header[61], header[62], header[63]]) as usize;
                
                if e_lfanew < 512 && e_lfanew + 4 < bytes_read {
                    if &header[e_lfanew..e_lfanew+4] == b"PE\0\0" {
                        // Valid PE, check for suspicious sections
                        // This is a simplified check
                        return Ok(Some((5, "Valid PE structure".to_string())));
                    }
                }
            }
        }
        
        // Script file with executable magic bytes
        if let Some(ext) = path.extension() {
            let ext_str = ext.to_str().unwrap_or("").to_lowercase();
            if ["txt", "doc", "pdf", "jpg", "png"].contains(&ext_str.as_str()) {
                if magic[0..2] == [0x4D, 0x5A] {
                    return Ok(Some((30, "Executable code in non-executable file".to_string())));
                }
            }
        }
        
        Ok(None)
    }
    
    /// Entropy analysis for packed/encrypted detection
    fn analyze_entropy(&self, path: &Path, file_size: u64) -> Result<Option<(i32, String)>> {
        // Only check specific file types
        let should_check = if let Some(ext) = path.extension() {
            let ext_str = ext.to_str().unwrap_or("").to_lowercase();
            ["exe", "dll", "sys", "scr"].contains(&ext_str.as_str())
        } else {
            false
        };
        
        if !should_check {
            return Ok(None);
        }
        
        // Read file for entropy calculation
        let data = self.read_file_bytes(path, file_size as usize)?;
        let entropy_value = self.calculate_entropy(&data);
        
        // Entropy thresholds
        if entropy_value > 7.5 {
            Ok(Some((25, format!("Very high entropy ({:.2}): heavily packed/encrypted", entropy_value))))
        } else if entropy_value > 7.2 {
            Ok(Some((15, format!("High entropy ({:.2}): possibly packed", entropy_value))))
        } else if entropy_value < 1.0 {
            Ok(Some((10, format!("Extremely low entropy ({:.2}): suspicious padding", entropy_value))))
        } else {
            Ok(None)
        }
    }
    
    /// Analyze file timestamps for anomalies
    fn analyze_timestamps(&self, metadata: &fs::Metadata) -> Option<(i32, String)> {
        use std::time::SystemTime;
        
        if let Ok(modified) = metadata.modified() {
            if let Ok(created) = metadata.created() {
                // Check if modified time is before created time (timestomping)
                if modified < created {
                    return Some((20, "Timestamp manipulation detected (modified < created)".to_string()));
                }
            }
            
            // Check for files from far future
            if let Ok(duration) = modified.duration_since(SystemTime::UNIX_EPOCH) {
                let current_time = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                
                let file_time = duration.as_secs();
                
                // File timestamp more than 1 year in future
                if file_time > current_time + (365 * 24 * 60 * 60) {
                    return Some((15, "Suspicious timestamp (far future)".to_string()));
                }
                
                // File timestamp from before 2000
                if file_time < 946684800 { // Jan 1, 2000
                    return Some((10, "Suspicious timestamp (very old)".to_string()));
                }
            }
        }
        
        None
    }
    
    /// Read file bytes up to max size
    fn read_file_bytes(&self, path: &Path, max_bytes: usize) -> std::io::Result<Vec<u8>> {
        let file = File::open(path)?;
        let mut buffer = Vec::new();
        file.take(max_bytes as u64).read_to_end(&mut buffer)?;
        Ok(buffer)
    }
    
    /// Calculate Shannon entropy
    fn calculate_entropy(&self, data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        
        let mut frequency = [0u64; 256];
        for &byte in data {
            frequency[byte as usize] += 1;
        }
        
        let len = data.len() as f64;
        frequency
            .iter()
            .filter(|&&count| count > 0)
            .map(|&count| {
                let p = count as f64 / len;
                -p * p.log2()
            })
            .sum()
    }
}

impl Default for HeuristicAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    
    #[test]
    fn test_ransomware_note_detection() {
        let temp_dir = std::env::temp_dir();
        let note_path = temp_dir.join("README_FOR_DECRYPT.txt");
        
        let mut file = File::create(&note_path).unwrap();
        writeln!(file, "All your files have been encrypted using AES-256.").unwrap();
        writeln!(file, "To decrypt, pay 0.05 BTC to: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").unwrap();
        writeln!(file, "Payment deadline: 72 hours").unwrap();
        writeln!(file, "Contact us for recovery instructions.").unwrap();
        
        let analyzer = HeuristicAnalyzer::new();
        let result = analyzer.analyze(&note_path).unwrap();
        
        assert_eq!(result.level, ThreatLevel::Malicious);
        assert!(result.reason.contains("Ransomware") || result.reason.contains("score"));
        
        std::fs::remove_file(note_path).ok();
    }
    
    #[test]
    fn test_clean_file() {
        let temp_dir = std::env::temp_dir();
        let clean_path = temp_dir.join("clean_document.txt");
        
        let mut file = File::create(&clean_path).unwrap();
        writeln!(file, "This is a normal document.").unwrap();
        writeln!(file, "It contains no malicious patterns.").unwrap();
        
        let analyzer = HeuristicAnalyzer::new();
        let result = analyzer.analyze(&clean_path).unwrap();
        
        assert_eq!(result.level, ThreatLevel::Clean);
        
        std::fs::remove_file(clean_path).ok();
    }
    
    #[test]
    fn test_suspicious_executable_name() {
        let temp_dir = std::env::temp_dir();
        let sus_path = temp_dir.join("keylogger.exe");
        
        // Create empty file
        File::create(&sus_path).unwrap();
        
        let analyzer = HeuristicAnalyzer::new();
        let result = analyzer.analyze(&sus_path).unwrap();
        
        // Should be at least suspicious due to name
        assert!(result.level == ThreatLevel::Suspicious || result.level == ThreatLevel::Malicious);
        
        std::fs::remove_file(sus_path).ok();
    }
    
    #[test]
    fn test_trojan_patterns() {
        let temp_dir = std::env::temp_dir();
        let trojan_path = temp_dir.join("suspicious.txt");
        
        let mut file = File::create(&trojan_path).unwrap();
        writeln!(file, "This script includes keylog functionality.").unwrap();
        writeln!(file, "It establishes a backdoor connection.").unwrap();
        writeln!(file, "Credential stealer activated.").unwrap();
        
        let analyzer = HeuristicAnalyzer::new();
        let result = analyzer.analyze(&trojan_path).unwrap();
        
        assert!(result.level == ThreatLevel::Suspicious || result.level == ThreatLevel::Malicious);
        assert!(result.reason.contains("Trojan") || result.reason.contains("score"));
        
        std::fs::remove_file(trojan_path).ok();
    }
    
    #[test]
    fn test_double_extension() {
        let analyzer = HeuristicAnalyzer::new();
        let test_path = Path::new("document.pdf.exe");
        
        if let Some((score, reason)) = analyzer.analyze_extension(test_path) {
            assert!(score > 0);
            assert!(reason.contains("Double extension"));
        }
    }
    
    #[test]
    fn test_entropy_calculation() {
        let analyzer = HeuristicAnalyzer::new();
        
        // Low entropy (all same byte)
        let low_entropy_data = vec![0u8; 1000];
        let low_entropy = analyzer.calculate_entropy(&low_entropy_data);
        assert!(low_entropy < 0.1);
        
        // High entropy (random data)
        let high_entropy_data: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();
        let high_entropy = analyzer.calculate_entropy(&high_entropy_data);
        assert!(high_entropy > 5.0);
    }
    
    #[test]
    fn test_crypto_address_detection() {
        let analyzer = HeuristicAnalyzer::new();
        
        let btc_content = "Send payment to: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
        assert!(analyzer.contains_crypto_address(btc_content));
        
        let eth_content = "Wallet: 0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb5";
        assert!(analyzer.contains_crypto_address(eth_content));
        
        let clean_content = "This is a normal document with no crypto addresses.";
        assert!(!analyzer.contains_crypto_address(clean_content));
    }
    
    #[test]
    fn test_behavioral_scoring() {
        let db = BehavioralPatternDatabase::new();
        
        let ransomware_text = "Your files are encrypted. Pay bitcoin to decrypt.";
        let (score, patterns) = db.calculate_threat_score(ransomware_text);
        
        assert!(score > 50);
        assert!(patterns.iter().any(|p| p.contains("Ransomware")));
    }
}
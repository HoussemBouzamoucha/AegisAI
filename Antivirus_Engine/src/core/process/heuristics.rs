// File: src/core/process/heuristics.rs
// Behavioral analysis for running processes

use super::scanner::ProcessThreatLevel;
use std::collections::HashMap;

pub struct ProcessAnalyzer {
    suspicious_names: HashMap<String, i32>,
    suspicious_patterns: Vec<(String, i32)>,
}

impl ProcessAnalyzer {
    pub fn new() -> Self {
        let mut analyzer = Self {
            suspicious_names: HashMap::new(),
            suspicious_patterns: Vec::new(),
        };
        
        analyzer.init_detection_rules();
        analyzer
    }
    
    fn init_detection_rules(&mut self) {
        // Known malicious process names
        self.suspicious_names.insert("keylogger.exe".to_string(), 90);
        self.suspicious_names.insert("cryptolocker.exe".to_string(), 95);
        self.suspicious_names.insert("ransomware.exe".to_string(), 95);
        self.suspicious_names.insert("miner.exe".to_string(), 70);
        self.suspicious_names.insert("rat.exe".to_string(), 85);
        self.suspicious_names.insert("trojan.exe".to_string(), 90);
        
        // Suspicious patterns in process names
        self.suspicious_patterns.push(("keylog".to_string(), 60));
        self.suspicious_patterns.push(("crypt".to_string(), 40));
        self.suspicious_patterns.push(("ransom".to_string(), 70));
        self.suspicious_patterns.push(("miner".to_string(), 50));
        self.suspicious_patterns.push(("stealer".to_string(), 65));
        self.suspicious_patterns.push(("backdoor".to_string(), 70));
        self.suspicious_patterns.push(("rootkit".to_string(), 80));
        self.suspicious_patterns.push(("trojan".to_string(), 70));
        self.suspicious_patterns.push(("virus".to_string(), 65));
        self.suspicious_patterns.push(("worm".to_string(), 60));
        
        // Crypto mining indicators
        self.suspicious_patterns.push(("xmrig".to_string(), 75));
        self.suspicious_patterns.push(("cpuminer".to_string(), 70));
        self.suspicious_patterns.push(("nicehash".to_string(), 45));
        
        // Script-based threats
        self.suspicious_patterns.push(("powershell.exe".to_string(), 30));
        self.suspicious_patterns.push(("cmd.exe".to_string(), 20));
        self.suspicious_patterns.push(("wscript.exe".to_string(), 35));
        self.suspicious_patterns.push(("cscript.exe".to_string(), 35));
    }
    
    /// Analyze a process and determine threat level
    pub fn analyze_process(
        &self,
        name: &str,
        _pid: u32,
        path: Option<&str>,
    ) -> (ProcessThreatLevel, Vec<String>) {
        let mut threat_score = 0;
        let mut behaviors = Vec::new();
        
        let name_lower = name.to_lowercase();
        
        // Check exact name matches
        if let Some(&score) = self.suspicious_names.get(&name_lower) {
            threat_score += score;
            behaviors.push(format!("Known malicious process: {}", name));
        }
        
        // Check pattern matches
        for (pattern, score) in &self.suspicious_patterns {
            if name_lower.contains(pattern) {
                threat_score += score;
                behaviors.push(format!("Suspicious pattern detected: {}", pattern));
            }
        }
        
        // Check for unsigned/hidden processes
        if let Some(proc_path) = path {
            if proc_path.contains("Temp") || proc_path.contains("AppData") {
                threat_score += 25;
                behaviors.push("Running from temporary directory".to_string());
            }
            
            if proc_path.contains("System32") {
                // Legitimate system process location
                threat_score = threat_score.saturating_sub(15);
            }
        }
        
        // Check for suspicious names (random characters)
        if name_lower.chars().filter(|c| c.is_numeric()).count() > 8 {
            threat_score += 30;
            behaviors.push("Obfuscated process name (many digits)".to_string());
        }
        
        // Multiple suspicious behaviors increase score
        if behaviors.len() > 2 {
            threat_score += 20;
            behaviors.push("Multiple suspicious indicators".to_string());
        }
        
        // Determine threat level from score
        let threat_level = match threat_score {
            0..=30 => ProcessThreatLevel::Safe,
            31..=60 => ProcessThreatLevel::Suspicious,
            61..=85 => ProcessThreatLevel::Malicious,
            _ => ProcessThreatLevel::Critical,
        };
        
        (threat_level, behaviors)
    }
    
    /// Check if a process is likely crypto mining
    pub fn is_crypto_miner(&self, name: &str, cpu_usage: f32) -> bool {
        let name_lower = name.to_lowercase();
        
        let miner_keywords = [
            "miner", "xmrig", "cpuminer", "nicehash", "mine", "crypto"
        ];
        
        let has_miner_keyword = miner_keywords.iter()
            .any(|keyword| name_lower.contains(keyword));
        
        // High CPU usage + suspicious name = likely miner
        has_miner_keyword || (cpu_usage > 80.0 && !self.is_known_safe_process(name))
    }
    
    /// Check if process is known safe (system processes)
    fn is_known_safe_process(&self, name: &str) -> bool {
        let safe_processes = [
            "system", "smss.exe", "csrss.exe", "wininit.exe", 
            "services.exe", "lsass.exe", "svchost.exe", "explorer.exe",
            "dwm.exe", "chrome.exe", "firefox.exe", "msedge.exe"
        ];
        
        let name_lower = name.to_lowercase();
        safe_processes.iter().any(|safe| name_lower.contains(safe))
    }
}

impl Default for ProcessAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_malicious_process_detection() {
        let analyzer = ProcessAnalyzer::new();
        
        let (level, behaviors) = analyzer.analyze_process("keylogger.exe", 1234, None);
        assert_eq!(level, ProcessThreatLevel::Critical);
        assert!(!behaviors.is_empty());
    }
    
    #[test]
    fn test_suspicious_pattern() {
        let analyzer = ProcessAnalyzer::new();
        
        let (level, behaviors) = analyzer.analyze_process("my_crypt_app.exe", 1234, None);
        assert!(level == ProcessThreatLevel::Suspicious || level == ProcessThreatLevel::Malicious);
        assert!(!behaviors.is_empty());
    }
    
    #[test]
    fn test_safe_process() {
        let analyzer = ProcessAnalyzer::new();
        
        let (level, _) = analyzer.analyze_process("explorer.exe", 1234, None);
        assert_eq!(level, ProcessThreatLevel::Safe);
    }
    
    #[test]
    fn test_crypto_miner_detection() {
        let analyzer = ProcessAnalyzer::new();
        
        assert!(analyzer.is_crypto_miner("xmrig.exe", 90.0));
        assert!(analyzer.is_crypto_miner("cpuminer.exe", 85.0));
        assert!(!analyzer.is_crypto_miner("chrome.exe", 95.0)); // Known safe despite high CPU
    }
}
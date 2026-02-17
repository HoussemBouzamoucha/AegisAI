// File: src/core/process/scanner.rs
// Real-time process monitoring and scanning

use std::collections::HashMap;
use anyhow::Result;
use serde::{Serialize, Deserialize};

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

/// Information about a running process
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub path: Option<String>,
    pub cpu_usage: f32,
    pub memory_mb: f64,
    pub threat_level: ProcessThreatLevel,
    pub suspicious_behaviors: Vec<String>,
    pub connections: Vec<NetworkConnection>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProcessThreatLevel {
    Safe,
    Suspicious,
    Malicious,
    Critical,
}

impl ProcessThreatLevel {
    pub fn as_str(&self) -> &str {
        match self {
            ProcessThreatLevel::Safe => "Safe",
            ProcessThreatLevel::Suspicious => "Suspicious",
            ProcessThreatLevel::Malicious => "Malicious",
            ProcessThreatLevel::Critical => "Critical",
        }
    }
    
    pub fn emoji(&self) -> &str {
        match self {
            ProcessThreatLevel::Safe => "✅",
            ProcessThreatLevel::Suspicious => "⚠️",
            ProcessThreatLevel::Malicious => "🚨",
            ProcessThreatLevel::Critical => "💀",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnection {
    pub local_addr: String,
    pub remote_addr: String,
    pub state: String,
    pub suspicious: bool,
}

/// Process scanner for monitoring running processes
pub struct ProcessScanner {
    analyzer: super::heuristics::ProcessAnalyzer,
}

impl ProcessScanner {
    pub fn new() -> Self {
        Self {
            analyzer: super::heuristics::ProcessAnalyzer::new(),
        }
    }
    
    /// Get list of all running processes with threat analysis
    pub fn scan_all_processes(&self) -> Result<Vec<ProcessInfo>> {
        #[cfg(target_os = "windows")]
        {
            self.scan_windows_processes()
        }
        
        #[cfg(not(target_os = "windows"))]
        {
            Ok(vec![])  // Placeholder for other platforms
        }
    }
    
    #[cfg(target_os = "windows")]
    fn scan_windows_processes(&self) -> Result<Vec<ProcessInfo>> {
        use std::process::Command;
        
        let mut processes = Vec::new();
        
        // Use tasklist to get process information
        let output = Command::new("tasklist")
            .args(&["/FO", "CSV", "/V", "/NH"])
            .creation_flags(0x08000000) // CREATE_NO_WINDOW
            .output()?;
        
        if !output.status.success() {
            return Ok(processes);
        }
        
        let output_str = String::from_utf8_lossy(&output.stdout);
        
        for line in output_str.lines() {
            if let Some(process) = self.parse_tasklist_line(line) {
                processes.push(process);
            }
        }
        
        Ok(processes)
    }
    
    fn parse_tasklist_line(&self, line: &str) -> Option<ProcessInfo> {
        // Parse CSV line from tasklist
        let parts: Vec<&str> = line.split(',')
            .map(|s| s.trim_matches('"').trim())
            .collect();
        
        if parts.len() < 5 {
            return None;
        }
        
        let name = parts[0].to_string();
        let pid = parts[1].parse::<u32>().ok()?;
        let memory_str = parts[4].replace(" K", "").replace(",", "");
        let memory_kb = memory_str.parse::<f64>().unwrap_or(0.0);
        let memory_mb = memory_kb / 1024.0;
        
        // Analyze process for threats
        let (threat_level, behaviors) = self.analyzer.analyze_process(&name, pid, None);
        
        Some(ProcessInfo {
            pid,
            name,
            path: None, // Would need additional API call
            cpu_usage: 0.0, // Would need performance counters
            memory_mb,
            threat_level,
            suspicious_behaviors: behaviors,
            connections: vec![], // Would need netstat integration
        })
    }
    
    /// Get detailed information about a specific process
    pub fn get_process_details(&self, pid: u32) -> Result<ProcessInfo> {
        let all_processes = self.scan_all_processes()?;
        
        all_processes.into_iter()
            .find(|p| p.pid == pid)
            .ok_or_else(|| anyhow::anyhow!("Process not found"))
    }
    
    /// Terminate a malicious process
    pub fn terminate_process(&self, pid: u32) -> Result<()> {
        #[cfg(target_os = "windows")]
        {
            use std::process::Command;
            
            let output = Command::new("taskkill")
                .args(&["/PID", &pid.to_string(), "/F"])
                .creation_flags(0x08000000)
                .output()?;
            
            if output.status.success() {
                Ok(())
            } else {
                Err(anyhow::anyhow!("Failed to terminate process"))
            }
        }
        
        #[cfg(not(target_os = "windows"))]
        {
            Err(anyhow::anyhow!("Process termination not supported on this platform"))
        }
    }
    
    /// Get process statistics
    pub fn get_statistics(&self, processes: &[ProcessInfo]) -> ProcessStatistics {
        let mut stats = ProcessStatistics {
            total_processes: processes.len(),
            safe_processes: 0,
            suspicious_processes: 0,
            malicious_processes: 0,
            critical_processes: 0,
            total_memory_mb: 0.0,
        };
        
        for process in processes {
            stats.total_memory_mb += process.memory_mb;
            
            match process.threat_level {
                ProcessThreatLevel::Safe => stats.safe_processes += 1,
                ProcessThreatLevel::Suspicious => stats.suspicious_processes += 1,
                ProcessThreatLevel::Malicious => stats.malicious_processes += 1,
                ProcessThreatLevel::Critical => stats.critical_processes += 1,
            }
        }
        
        stats
    }
}

impl Default for ProcessScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessStatistics {
    pub total_processes: usize,
    pub safe_processes: usize,
    pub suspicious_processes: usize,
    pub malicious_processes: usize,
    pub critical_processes: usize,
    pub total_memory_mb: f64,
}
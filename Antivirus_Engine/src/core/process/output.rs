// File: src/core/process_scanner/output.rs
// JSON output formatting for process scan results.
// CSV support can be added in a future stage if needed.

use crate::core::process::types::{ProcessInfo, ScanStatistics, ThreatLevel};
use serde_json::json;
use std::path::Path;
use anyhow::Result;

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub enum OutputFormat {
    Json,
    // Csv — reserved for future stage
}

// ─── Scan output ──────────────────────────────────────────────────────────────

#[allow(dead_code)]
pub struct ScanOutput {
    pub processes:  Vec<ProcessInfo>,
    pub statistics: ScanStatistics,
}

impl ScanOutput {
    #[allow(dead_code)]
    pub fn new(processes: Vec<ProcessInfo>, statistics: ScanStatistics) -> Self {
        Self { processes, statistics }
    }

    /// Serialize all processes to a pretty-printed JSON string.
    #[allow(dead_code)]
    pub fn to_json(&self) -> Result<String> {
        let processes: Vec<serde_json::Value> = self.processes.iter()
            .map(serialize_process)
            .collect();

        let output = json!({
            "success": true,
            "statistics": serialize_stats(&self.statistics),
            "processes": processes,
        });

        Ok(serde_json::to_string_pretty(&output)?)
    }

    /// Write JSON to a file.
    #[allow(dead_code)]
    pub fn write_json(&self, path: &Path) -> Result<()> {
        std::fs::write(path, self.to_json()?)?;
        Ok(())
    }

    /// Return only non-safe processes as JSON — used by the UI and daemon.
    #[allow(dead_code)]
    pub fn to_json_threats_only(&self) -> Result<String> {
        let threats: Vec<serde_json::Value> = self.processes.iter()
            .filter(|p| p.threat_level != ThreatLevel::Safe)
            .map(serialize_process)
            .collect();

        let output = json!({
            "success": true,
            "statistics": serialize_stats(&self.statistics),
            "processes": threats,
        });

        Ok(serde_json::to_string_pretty(&output)?)
    }

    /// Print a short summary to stderr.
    #[allow(dead_code)]
    pub fn print_summary(&self) {
        let s = &self.statistics;
        eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        eprintln!("Process Scan  |  {} ms", s.scan_duration_ms);
        eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        eprintln!("Total:        {}", s.total_processes);
        eprintln!("Safe:         {}", s.safe_processes);
        eprintln!("Suspicious:   {}", s.suspicious_processes);
        eprintln!("Malicious:    {}", s.malicious_processes);
        eprintln!("Critical:     {}", s.critical_processes);
        eprintln!("Memory:       {:.0} MB total", s.total_memory_mb);
        eprintln!("Threads:      {}", s.total_threads);
        eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    }
}

// ─── Serialization helpers ────────────────────────────────────────────────────

pub fn serialize_process(p: &ProcessInfo) -> serde_json::Value {
    let signals: Vec<serde_json::Value> = p.detection_signals.iter()
        .map(|s| json!({
            "source":      s.source,
            "description": s.description,
            "score":       s.score,
        }))
        .collect();

    json!({
        // Core metadata
        "pid":          p.pid,
        "name":         p.name,
        "parent_pid":   p.parent_pid,
        "exe_path":     p.exe_path,
        "command_line": p.command_line,
        "status":       p.status,
        "start_time":   p.start_time,
        "user":         p.user,

        // Resources
        "cpu_usage":         p.cpu_usage,
        "memory_mb":         format!("{:.2}", p.memory_mb),
        "memory_bytes":      p.memory_bytes,
        "virtual_memory_mb": format!("{:.2}", p.virtual_memory as f64 / 1024.0 / 1024.0),
        "thread_count":      p.thread_count,

        // Stage 2-4 (empty for now, populated in future stages)
        "handle_count": p.handle_count,
        "module_count": p.module_count,

        // Threat assessment + ML fields
        "threat_level":      p.threat_level.as_str(),
        "threat_score":      p.threat_score,
        "is_threat":         p.threat_level.is_threat(),
        "detection_signals": signals,
        "anomaly_flags":     p.anomaly_flags,
    })
}

#[allow(dead_code)]
fn serialize_stats(s: &ScanStatistics) -> serde_json::Value {
    json!({
        "total_processes":      s.total_processes,
        "safe_processes":       s.safe_processes,
        "suspicious_processes": s.suspicious_processes,
        "malicious_processes":  s.malicious_processes,
        "critical_processes":   s.critical_processes,
        "total_memory_mb":      format!("{:.2}", s.total_memory_mb),
        "total_threads":        s.total_threads,
        "avg_cpu_usage":        format!("{:.2}", s.avg_cpu_usage),
        "scan_duration_ms":     s.scan_duration_ms,
    })
}
// File: src/core/process/scanner.rs
// Process scanner orchestration — thin layer that wires together:
//   enumerate_processes() → ProcessHeuristics::analyze() → ScanStatistics

use crate::core::process::heuristics::ProcessHeuristics;
use crate::core::process::types::{
    enumerate_processes, ProcessInfo, ScanStatistics, ThreatLevel,
};
use std::time::Instant;

pub struct ProcessScanner {
    heuristics: ProcessHeuristics,
}

impl ProcessScanner {
    pub fn new() -> Self {
        Self {
            heuristics: ProcessHeuristics::new(),
        }
    }

    /// Enumerate all running processes, analyze each one, return results + stats.
    pub fn scan(&self) -> (Vec<ProcessInfo>, ScanStatistics) {
        let start = Instant::now();

        let mut processes = enumerate_processes();

        for process in processes.iter_mut() {
            self.heuristics.analyze(process);
        }

        // Sort: highest threat score first
        processes.sort_by(|a, b| b.threat_score.cmp(&a.threat_score));

        let duration_ms = start.elapsed().as_millis() as u64;
        let stats = ScanStatistics::from_results(&processes, duration_ms);

        (processes, stats)
    }

    /// Return only non-safe processes.
    pub fn scan_threats_only(&self) -> (Vec<ProcessInfo>, ScanStatistics) {
        let (all, stats) = self.scan();
        let threats: Vec<ProcessInfo> = all
            .into_iter()
            .filter(|p| p.threat_level != ThreatLevel::Safe)
            .collect();
        (threats, stats)
    }

    /// Scan a single process by PID.
    pub fn scan_pid(&self, target_pid: u32) -> Option<ProcessInfo> {
        let processes = enumerate_processes();
        let mut found = processes.into_iter().find(|p| p.pid == target_pid)?;
        self.heuristics.analyze(&mut found);
        Some(found)
    }

    /// Terminate a process by PID — sysinfo 0.30 API.
    pub fn terminate_process(&self, pid: u32) -> anyhow::Result<()> {
        use sysinfo::{System, Pid};

        let mut sys = System::new_all();
        sys.refresh_all();

        let sysinfo_pid = Pid::from_u32(pid);
        // Fix: renamed variable to `proc` to avoid shadowing the `process` module
        if let Some(proc) = sys.process(sysinfo_pid) {
            proc.kill();
            Ok(())
        } else {
            Err(anyhow::anyhow!("Process {} not found", pid))
        }
    }

    /// Get statistics from a list of already-scanned processes.
    pub fn get_statistics(&self, processes: &[ProcessInfo]) -> ScanStatistics {
        ScanStatistics::from_results(processes, 0)
    }

    /// Scan all processes — used by engine main.rs daemon handler.
    pub fn scan_all_processes(&self) -> anyhow::Result<Vec<ProcessInfo>> {
        let (processes, _) = self.scan();
        Ok(processes)
    }
}

impl Default for ProcessScanner {
    fn default() -> Self { Self::new() }
}
// File: src/core/process/scanner.rs
// Process scanner orchestration — thin layer that wires together:
//   enumerate_processes()
//     → Stage 1: ProcessHeuristics::analyze()
//     → Stage 2: enumerate_handles()
//     → Stage 3: enumerate_modules()
//     → ScanStatistics

use crate::core::process::heuristics::ProcessHeuristics;
use crate::core::process::types::{
    enumerate_processes, DetectionSignal, ProcessInfo, ScanStatistics, ThreatLevel,
};
use crate::core::process::handles::{
    enumerate_handles, has_cross_process_handle, has_suspicious_mutex, open_file_handle_count,
};
use crate::core::process::modules::enumerate_modules;
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

    /// Enumerate all running processes, run all analysis stages, return results + stats.
    pub fn scan(&self) -> (Vec<ProcessInfo>, ScanStatistics) {
        let start = Instant::now();

        let mut processes = enumerate_processes();

        for process in processes.iter_mut() {
            self.analyze_process(process);
        }

        // Sort: highest threat score first
        processes.sort_by(|a, b| b.threat_score.cmp(&a.threat_score));

        let duration_ms = start.elapsed().as_millis() as u64;
        let stats = ScanStatistics::from_results(&processes, duration_ms);

        (processes, stats)
    }

    /// Core per-process analysis — shared between scan() and scan_pid().
    /// Runs all three stages and finalises threat_level + is_threat.
    fn analyze_process(&self, process: &mut ProcessInfo) {
        // ── Stage 1: heuristic analysis (path, name, resource, cmdline) ──
        self.heuristics.analyze(process);

        // ── Stage 2: open handle enumeration ─────────────────────────────
        // Only meaningful on Windows — returns empty vec elsewhere.
        let handles = enumerate_handles(process.pid);
        if !handles.is_empty() {
            process.handle_count = Some(handles.len() as u32);

            // Suspicious mutex — single-instance malware marker.
            if has_suspicious_mutex(&handles) {
                process.threat_score += 20;
                process.detection_signals.push(DetectionSignal::new(
                    "handle",
                    "Suspicious named mutex detected (possible malware singleton)",
                    20,
                ));
            }

            // High open-file count — ransomware iterating the filesystem.
            let file_count = open_file_handle_count(&handles);
            if file_count > 200 {
                process.threat_score += 15;
                process.detection_signals.push(DetectionSignal::new(
                    "handle",
                    format!("Unusually high open file handle count: {}", file_count),
                    15,
                ));
            }

            // Cross-process handle — code injection / hollowing indicator.
            if has_cross_process_handle(&handles) {
                process.threat_score += 25;
                process.detection_signals.push(DetectionSignal::new(
                    "handle",
                    "Holds handle to another process object (possible injection)",
                    25,
                ));
            }
        }

        // ── Stage 3: loaded module enumeration ───────────────────────────
        // Only done on Windows — returns empty vec on other platforms.
        let modules = enumerate_modules(process.pid);
        if !modules.is_empty() {
            process.module_count = Some(modules.len() as u32);

            let suspicious_modules: Vec<_> = modules
                .iter()
                .filter(|m| m.is_suspicious)
                .collect();

            if !suspicious_modules.is_empty() {
                // Change #3: cap module-based score contribution to prevent
                // explosion from benign toolchains with many DLLs (max +50).
                let capped = suspicious_modules.len().min(5);
                process.threat_score += capped as i32 * 10;

                // Change #4: record anomaly flag for ML / graph analysis later.
                // Separates signal presence from numeric score.
                process.anomaly_flags.push("suspicious_modules".to_string());

                for m in &suspicious_modules {
                    process.detection_signals.push(DetectionSignal::new(
                        "module",
                        format!(
                            "Suspicious DLL loaded: {}",
                            m.path.as_deref().unwrap_or(&m.name)
                        ),
                        10,
                    ));
                }
            }
        }

        // ── Final: re-evaluate threat level once all stages have scored ──
        process.threat_level = threat_level_from_score(process.threat_score);
        process.is_threat = process.threat_level.is_threat();
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

    /// Scan a single process by PID — runs the full three-stage pipeline.
    pub fn scan_pid(&self, target_pid: u32) -> Option<ProcessInfo> {
        let processes = enumerate_processes();
        let mut found = processes.into_iter().find(|p| p.pid == target_pid)?;
        self.analyze_process(&mut found);
        Some(found)
    }

    /// Terminate a process by PID — sysinfo 0.30 API.
    pub fn terminate_process(&self, pid: u32) -> anyhow::Result<()> {
        use sysinfo::{Pid, System};

        let mut sys = System::new_all();
        sys.refresh_all();

        let sysinfo_pid = Pid::from_u32(pid);
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
    fn default() -> Self {
        Self::new()
    }
}

// ─── Helper ───────────────────────────────────────────────────────────────────

/// Derive a ThreatLevel from a cumulative threat score.
/// Adjust thresholds to match your ProcessHeuristics scoring if needed.
fn threat_level_from_score(score: i32) -> ThreatLevel {
    match score {
        s if s >= 80 => ThreatLevel::Critical,
        s if s >= 50 => ThreatLevel::Malicious,
        s if s >= 20 => ThreatLevel::Suspicious,
        _            => ThreatLevel::Safe,
    }
}
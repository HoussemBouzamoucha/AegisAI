// File: src/core/process/heuristics.rs
// Process Heuristic Analyzer — all scoring checks in one place.
//
// Scoring table:
//   No executable path (non-system process)          +5   (hollowing indicator)
//   No executable path (known system process name)    0   (access denied is normal on Windows)
//   Executable outside standard paths                +4
//   System process in wrong location                 +8   (svchost.exe not in system32)
//   Known malware process name                       +10
//   Suspicious name pattern                          +5
//   Zero threads                                     +6   (hollowing / zombie))
//   CPU usage > 90%                                  +3   (possible miner)
//   Memory > 1GB                                     +2
//   Suspicious command line argument                 +3   per arg, capped at +9
//
// Dev process halving:
//   Known dev tools (rust-analyzer, node, cargo…)   score /= 2
//   These legitimately load temp DLLs, dynamic modules, etc.
//
// Thresholds:
//   score >= 15  → Critical
//   score >= 10  → Malicious
//   score >= 4   → Suspicious
//   else         → Safe

use crate::core::process::types::{DetectionSignal, ProcessInfo, ThreatLevel};

const CRITICAL_THRESHOLD:   i32 = 15;
const MALICIOUS_THRESHOLD:  i32 = 10;
const SUSPICIOUS_THRESHOLD: i32 = 4;

const SAFE_PATHS: &[&str] = &[
    r"c:\windows\system32",
    r"c:\windows\syswow64",
    r"c:\windows\",
    r"c:\program files\",
    r"c:\program files (x86)\",
    // Change #6 (optional): user-directory apps are common and legitimate.
    // Safe only when combined with the dev-process halving below, which
    // prevents malware from hiding here undetected.
    r"c:\users\",
];

// Processes that MUST run from system32 — if found elsewhere that's malicious.
const SYSTEM32_ONLY: &[&str] = &[
    "svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe",
    "wininit.exe", "services.exe", "smss.exe",
    "taskhost.exe", "taskhostw.exe",
];

// Well-known Windows system/security process names whose exe paths are
// commonly unreadable even with admin rights (PPL / protected processes).
// Missing exe_path for these is NOT suspicious — it's normal Windows behaviour.
const PROTECTED_SYSTEM_NAMES: &[&str] = &[
    // Core Windows kernel/session processes
    "svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe",
    "wininit.exe", "services.exe", "smss.exe", "taskhost.exe",
    "taskhostw.exe", "lsaiso.exe", "audiodg.exe", "dwm.exe",
    "fontdrvhost.exe", "registry", "system", "secure system",
    "memory compression", "spoolsv.exe", "wuauclt.exe",
    // Windows Defender / Security Center
    "msmpeng.exe", "nissrv.exe", "mssense.exe", "securityhealthservice.exe",
    "antimalware service executable",
    // Common shell/UX system services
    "runtimebroker.exe", "sihost.exe", "ctfmon.exe", "dashost.exe",
    "searchindexer.exe", "searchhost.exe", "startmenuexperiencehost.exe",
    "shellexperiencehost.exe", "textinputhost.exe", "applicationframehost.exe",
    "systemsettings.exe", "settingssynchost.exe", "usoclient.exe",
    // Audio/display driver services that run as protected
    "rtkaudservice64.exe", "rtkauduservice64.exe",
];

const KNOWN_MALWARE_NAMES: &[&str] = &[
    "mimikatz", "meterpreter", "cobaltstrike", "cobalt_strike",
    "empire", "metasploit", "pwdump", "fgdump", "wce",
    "netcat", "ncat", "socat", "psexec", "paexec",
    "remcom", "lazagne", "procdump",
];

const SUSPICIOUS_NAME_PATTERNS: &[&str] = &[
    "svch0st", "lsaas", "csrsss", "wininit32", "winlogon32",
    "cmd32", "powershell32", "taskmgr32",
    "inject", "hook", "keylog", "stealer",
    "coinminer", "cryptminer", "ransom", "backdoor",
    "dropper", "shellcode",
];

const SUSPICIOUS_CMDLINE_ARGS: &[&str] = &[
    "-enc", "-encodedcommand", "-windowstyle hidden", "-w hidden",
    "invoke-expression", "iex(", "downloadstring", "frombase64string",
    "-noprofile -noninteractive", "bypass", "reflectiveloader",
];

pub struct ProcessHeuristics;

impl ProcessHeuristics {
    pub fn new() -> Self { Self }

    pub fn analyze(&self, process: &mut ProcessInfo) {
        let mut score:   i32 = 0;
        let mut signals: Vec<DetectionSignal> = Vec::new();

        let name_lower = process.name.to_lowercase();
        let exe_lower  = process.exe_path.as_deref().unwrap_or("").to_lowercase();

        let is_protected_name = PROTECTED_SYSTEM_NAMES.iter()
            .any(|s| name_lower == *s);
        let is_system32_name = SYSTEM32_ONLY.iter()
            .any(|s| name_lower == *s);

        // ── Check 1: No executable path ───────────────────────────────────────
        // Windows legitimately denies exe path reads for PPL/protected processes
        // even as admin. Don't penalize known system names with no readable path.
        if exe_lower.is_empty() {
            if !is_protected_name {
                score += 5;
                signals.push(DetectionSignal::new(
                    "path",
                    "No executable path — possible process hollowing or rootkit",
                    5,
                ));
            }
            // Protected name + no path = 0 score, no signal. Cannot verify but
            // won't assume malicious for known system processes.
        } else {
            // ── Check 2: Executable outside standard paths ─────────────────────
            let in_safe = SAFE_PATHS.iter().any(|s| exe_lower.starts_with(s));
            if !in_safe {
                score += 4;
                signals.push(DetectionSignal::new(
                    "path",
                    format!("Executable outside standard paths: {}", exe_lower),
                    4,
                ));
            }

            // ── Check 3: System process in wrong location ──────────────────────
            if is_system32_name {
                let in_system32 = exe_lower.contains(r"system32\")
                    || exe_lower.contains(r"syswow64\");
                if !in_system32 {
                    score += 8;
                    signals.push(DetectionSignal::new(
                        "path",
                        format!(
                            "System process '{}' running outside system32 — impersonation likely",
                            process.name
                        ),
                        8,
                    ));
                }
            }
        }

        // ── Check 4: Known malware name ───────────────────────────────────────
        if KNOWN_MALWARE_NAMES.iter().any(|m| name_lower.contains(m)) {
            score += 10;
            signals.push(DetectionSignal::new(
                "name",
                format!("Known malware process name: '{}'", process.name),
                10,
            ));
        }

        // ── Check 5: Suspicious name pattern ──────────────────────────────────
        if !KNOWN_MALWARE_NAMES.iter().any(|m| name_lower.contains(m)) {
            for pattern in SUSPICIOUS_NAME_PATTERNS {
                if name_lower.contains(pattern) {
                    let in_safe = SAFE_PATHS.iter().any(|s| exe_lower.starts_with(s));
                    if !in_safe || exe_lower.is_empty() {
                        score += 5;
                        signals.push(DetectionSignal::new(
                            "name",
                            format!("Suspicious process name pattern: '{}'", pattern),
                            5,
                        ));
                        break;
                    }
                }
            }
        }

        // ── Check 6: Zero threads ─────────────────────────────────────────────
        // Only meaningful on Linux where sysinfo actually gives thread counts.
        // On Windows we default thread_count=1 so this never fires incorrectly.
        if process.thread_count == 0 && process.pid > 4 {
            score += 6;
            signals.push(DetectionSignal::new(
                "threads",
                "Zero threads — possible process hollowing or zombie process",
                6,
            ));
        }

        // ── Check 7: Extremely high CPU ───────────────────────────────────────
        if process.cpu_usage > 90.0 {
            score += 3;
            signals.push(DetectionSignal::new(
                "resource",
                format!("Extremely high CPU: {:.1}% — possible crypto miner", process.cpu_usage),
                3,
            ));
        }

        // ── Check 8: Extremely high memory ────────────────────────────────────
        if process.memory_mb > 1024.0 {
            score += 2;
            signals.push(DetectionSignal::new(
                "resource",
                format!("High memory usage: {:.0} MB", process.memory_mb),
                2,
            ));
        }

        // ── Check 9: Suspicious command line ──────────────────────────────────
        if let Some(cmd) = process.command_line.as_ref() {
            let cmd_lower: String = cmd.to_lowercase();
            let mut cmd_score = 0i32;
            let mut cmd_hits: Vec<&str> = Vec::new();

            for arg in SUSPICIOUS_CMDLINE_ARGS {
                if cmd_lower.contains(arg) {
                    cmd_score += 3;
                    cmd_hits.push(arg);
                    if cmd_score >= 9 { break; }
                }
            }

            if cmd_score > 0 {
                score += cmd_score;
                signals.push(DetectionSignal::new(
                    "cmdline",
                    format!("Suspicious command line: {}", cmd_hits.join(", ")),
                    cmd_score,
                ));
            }
        }

        // ── Change #5: Dev process context awareness ──────────────────────────
        // Dev tools legitimately exhibit malware-like behaviour (temp DLL loading,
        // dynamic module injection, high file I/O). Halve their score to avoid
        // over-penalizing normal development workflows.
        if is_known_dev_process(&process.name) {
            score /= 2;
        }

        // ── Decision ──────────────────────────────────────────────────────────
        process.threat_score = score;
        process.threat_level = if score >= CRITICAL_THRESHOLD {
            ThreatLevel::Critical
        } else if score >= MALICIOUS_THRESHOLD {
            ThreatLevel::Malicious
        } else if score >= SUSPICIOUS_THRESHOLD {
            ThreatLevel::Suspicious
        } else {
            ThreatLevel::Safe
        };
        process.is_threat         = process.threat_level.is_threat();
        process.detection_signals = signals;
    }
}

// ── Change #5 helper ──────────────────────────────────────────────────────────

/// True for well-known development toolchain processes.
/// These are intentionally excluded from full threat scoring because they
/// dynamically load proc-macro DLLs, spawn child processes, and perform
/// heavy file I/O — all patterns that overlap with malware heuristics.
fn is_known_dev_process(name: &str) -> bool {
    let n = name.to_lowercase();
    n.contains("rust-analyzer")
        || n.contains("node")
        || n.contains("npm")
        || n.contains("python")
        || n.contains("cargo")
}

impl Default for ProcessHeuristics {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::process::types::ProcessInfo;

    fn make_process(name: &str, exe: Option<&str>, threads: u32, cpu: f32) -> ProcessInfo {
        let mut p = ProcessInfo::new(1234, name.to_string());
        p.exe_path     = exe.map(String::from);
        p.thread_count = threads;
        p.cpu_usage    = cpu;
        p.memory_mb    = 100.0;
        p
    }

    #[test]
    fn test_clean_process_is_safe() {
        let h = ProcessHeuristics::new();
        let mut p = make_process(
            "notepad.exe",
            Some(r"c:\windows\system32\notepad.exe"),
            4, 0.5,
        );
        h.analyze(&mut p);
        assert_eq!(p.threat_level, ThreatLevel::Safe,
            "notepad.exe from system32 should be Safe. Score: {} signals: {:?}",
            p.threat_score,
            p.detection_signals.iter().map(|s| &s.description).collect::<Vec<_>>());
    }

    #[test]
    fn test_svchost_no_path_is_safe() {
        let h = ProcessHeuristics::new();
        let mut p = make_process("svchost.exe", None, 1, 0.0);
        h.analyze(&mut p);
        assert_eq!(p.threat_level, ThreatLevel::Safe,
            "svchost.exe with unreadable path should be Safe (PPL). Score: {}",
            p.threat_score);
    }

    #[test]
    fn test_msmpeng_no_path_is_safe() {
        let h = ProcessHeuristics::new();
        let mut p = make_process("MsMpEng.exe", None, 1, 0.0);
        h.analyze(&mut p);
        assert_eq!(p.threat_level, ThreatLevel::Safe,
            "MsMpEng.exe with unreadable path should be Safe. Score: {}",
            p.threat_score);
    }

    #[test]
    fn test_unknown_no_path_is_suspicious() {
        let h = ProcessHeuristics::new();
        let mut p = make_process("unknown_thing.exe", None, 4, 0.5);
        h.analyze(&mut p);
        assert!(p.threat_level != ThreatLevel::Safe,
            "Unknown process with no path should not be Safe");
    }

    #[test]
    fn test_zero_threads_is_suspicious() {
        let h = ProcessHeuristics::new();
        let mut p = make_process(
            "normal.exe",
            Some(r"c:\windows\system32\normal.exe"),
            0, 0.5,
        );
        h.analyze(&mut p);
        assert!(p.threat_score >= SUSPICIOUS_THRESHOLD);
    }

    #[test]
    fn test_known_malware_is_malicious() {
        let h = ProcessHeuristics::new();
        let mut p = make_process("mimikatz.exe", Some(r"c:\temp\mimikatz.exe"), 4, 0.5);
        h.analyze(&mut p);
        assert!(
            p.threat_level == ThreatLevel::Malicious
            || p.threat_level == ThreatLevel::Critical
        );
    }

    #[test]
    fn test_svchost_wrong_path_is_malicious() {
        let h = ProcessHeuristics::new();
        let mut p = make_process(
            "svchost.exe",
            Some(r"c:\users\user\appdata\svchost.exe"),
            4, 0.5,
        );
        h.analyze(&mut p);
        assert!(p.threat_score >= MALICIOUS_THRESHOLD,
            "svchost from wrong path should be Malicious. Score: {}", p.threat_score);
    }

    #[test]
    fn test_suspicious_cmdline() {
        let h = ProcessHeuristics::new();
        let mut p = make_process(
            "powershell.exe",
            Some(r"c:\windows\system32\powershell.exe"),
            4, 0.5,
        );
        p.command_line = Some("powershell.exe -enc SQBFAFgA -windowstyle hidden".to_string());
        h.analyze(&mut p);
        assert!(p.threat_score >= SUSPICIOUS_THRESHOLD);
    }

    #[test]
    fn test_high_cpu_adds_score() {
        let h = ProcessHeuristics::new();
        let mut p = make_process(
            "worker.exe",
            Some(r"c:\windows\system32\worker.exe"),
            4, 95.0,
        );
        h.analyze(&mut p);
        assert!(p.detection_signals.iter().any(|s| s.source == "resource"));
    }

    // Change #5: dev processes should never reach Critical from normal activity.
    #[test]
    fn test_rust_analyzer_score_is_halved() {
        let h = ProcessHeuristics::new();
        // Give it a suspicious-looking path to rack up raw score, then confirm halving.
        let mut p = make_process(
            "rust-analyzer.exe",
            Some(r"c:\users\dev\.rustup\bin\rust-analyzer.exe"),
            4, 0.5,
        );
        h.analyze(&mut p);
        assert!(
            p.threat_level != ThreatLevel::Critical,
            "rust-analyzer should not be Critical after dev halving. Score: {}",
            p.threat_score
        );
    }

    #[test]
    fn test_node_score_is_halved() {
        let h = ProcessHeuristics::new();
        let mut p = make_process(
            "node.exe",
            Some(r"c:\users\dev\appdata\roaming\nvm\node.exe"),
            4, 0.5,
        );
        h.analyze(&mut p);
        assert!(
            p.threat_level != ThreatLevel::Critical,
            "node.exe should not be Critical after dev halving. Score: {}",
            p.threat_score
        );
    }
}
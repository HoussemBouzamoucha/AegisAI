// File: src/core/process/types.rs
// ProcessInfo type + sysinfo-based enumeration.

use serde::{Deserialize, Serialize};
use std::sync::{Mutex, OnceLock};
use sysinfo::{ProcessRefreshKind, RefreshKind, System, UpdateKind};

// ─── Detection signal ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionSignal {
    pub source:      String,
    pub description: String,
    pub score:       i32,
}

impl DetectionSignal {
    pub fn new(source: impl Into<String>, description: impl Into<String>, score: i32) -> Self {
        Self {
            source:      source.into(),
            description: description.into(),
            score,
        }
    }
}

// ─── Threat level ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ThreatLevel {
    Safe,
    Suspicious,
    Malicious,
    Critical,
}

impl ThreatLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            ThreatLevel::Safe       => "Safe",
            ThreatLevel::Suspicious => "Suspicious",
            ThreatLevel::Malicious  => "Malicious",
            ThreatLevel::Critical   => "Critical",
        }
    }

    pub fn is_threat(&self) -> bool {
        !matches!(self, ThreatLevel::Safe)
    }
}

// ─── Stage 2 stub: Handle info ────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandleInfo {
    pub handle_value: u64,
    pub object_type:  String,
    pub name:         Option<String>,
}

// ─── Stage 3 stub: Module info ────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleInfo {
    pub name:         String,
    pub path:         Option<String>, // None if the path could not be retrieved
    pub base_address: u64,
    pub size:         u64,
    pub is_suspicious: bool,          // Fix #2: added missing field
}

// ─── Stage 4 stub: Service info ───────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub name:         String,
    pub display_name: String,
    pub service_type: String,
    pub status:       String,
    pub pid:          Option<u32>,
}

// ─── Process info ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid:          u32,
    pub name:         String,
    pub parent_pid:   Option<u32>,
    pub exe_path:     Option<String>,
    pub command_line: Option<String>,
    pub status:       String,
    pub start_time:   Option<u64>,
    pub user:         Option<String>,

    // Resources
    pub cpu_usage:      f32,
    pub memory_mb:      f64,
    pub memory_bytes:   u64,
    pub virtual_memory: u64,
    pub thread_count:   u32,

    // Stage 2-4 placeholders
    pub handle_count: Option<u32>,
    pub module_count: Option<u32>,

    // Threat assessment
    pub threat_level:      ThreatLevel,
    pub threat_score:      i32,
    pub is_threat:         bool,
    pub detection_signals: Vec<DetectionSignal>,
    pub anomaly_flags:     Vec<String>,
}

impl ProcessInfo {
    pub fn new(pid: u32, name: String) -> Self {
        Self {
            pid,
            name,
            parent_pid:   None,
            exe_path:     None,
            command_line: None,
            status:       "Unknown".to_string(),
            start_time:   None,
            user:         None,
            cpu_usage:    0.0,
            memory_mb:    0.0,
            memory_bytes: 0,
            virtual_memory: 0,
            thread_count: 0,
            handle_count: None,
            module_count: None,
            threat_level:      ThreatLevel::Safe,
            threat_score:      0,
            is_threat:         false,
            detection_signals: Vec::new(),
            anomaly_flags:     Vec::new(),
        }
    }
}

// ─── Scan statistics ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanStatistics {
    pub total_processes:      usize,
    pub safe_processes:       usize,
    pub suspicious_processes: usize,
    pub malicious_processes:  usize,
    pub critical_processes:   usize,
    pub total_memory_mb:      f64,
    pub total_threads:        u64,
    pub avg_cpu_usage:        f64,
    pub scan_duration_ms:     u64,
}

impl ScanStatistics {
    pub fn from_results(processes: &[ProcessInfo], duration_ms: u64) -> Self {
        let total      = processes.len();
        let safe       = processes.iter().filter(|p| p.threat_level == ThreatLevel::Safe).count();
        let suspicious = processes.iter().filter(|p| p.threat_level == ThreatLevel::Suspicious).count();
        let malicious  = processes.iter().filter(|p| p.threat_level == ThreatLevel::Malicious).count();
        let critical   = processes.iter().filter(|p| p.threat_level == ThreatLevel::Critical).count();

        let total_memory_mb = processes.iter().map(|p| p.memory_mb).sum();
        let total_threads   = processes.iter().map(|p| p.thread_count as u64).sum();
        let avg_cpu = if total > 0 {
            processes.iter().map(|p| p.cpu_usage as f64).sum::<f64>() / total as f64
        } else {
            0.0
        };

        Self {
            total_processes:      total,
            safe_processes:       safe,
            suspicious_processes: suspicious,
            malicious_processes:  malicious,
            critical_processes:   critical,
            total_memory_mb,
            total_threads,
            avg_cpu_usage:    avg_cpu,
            scan_duration_ms: duration_ms,
        }
    }
}

// ─── Process enumeration ──────────────────────────────────────────────────────

/// Global warm System instance.  Initialised once (with its mandatory 200 ms
/// sleep) and then reused on every subsequent scan call — eliminating the
/// per-scan blocking sleep that previously froze the daemon thread.
static WARM_SYSTEM: OnceLock<Mutex<System>> = OnceLock::new();

pub fn enumerate_processes() -> Vec<ProcessInfo> {
    // sysinfo 0.30+: use ::nothing() / ::everything(), NOT ::new().
    let process_refresh = ProcessRefreshKind::everything()
        .with_exe(UpdateKind::Always)
        .with_cmd(UpdateKind::Always)
        .with_user(UpdateKind::Always);

    let refresh_kind = RefreshKind::nothing()
        .with_processes(process_refresh);

    // ── Two-sample CPU measurement ────────────────────────────────────────────
    // On first call: create System, sleep once, refresh — unavoidable.
    // On subsequent calls: just refresh. User-triggered scans are always
    // multiple seconds apart, so the 200 ms delta requirement is satisfied
    // without an additional sleep.
    let warm = WARM_SYSTEM.get_or_init(|| {
        let mut sys = System::new_with_specifics(refresh_kind);
        std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
        sys.refresh_processes_specifics(
            sysinfo::ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::everything()
                .with_exe(UpdateKind::Always)
                .with_cmd(UpdateKind::Always)
                .with_user(UpdateKind::Always),
        );
        Mutex::new(sys)
    });

    let mut sys = warm.lock().expect("process system mutex poisoned");

    sys.refresh_processes_specifics(
        sysinfo::ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::everything()
            .with_exe(UpdateKind::Always)
            .with_cmd(UpdateKind::Always)
            .with_user(UpdateKind::Always),
    );

    sys.processes()
        .values()
        .map(|proc| {
            let pid = proc.pid().as_u32();

            // exe_path: empty PathBuf = Windows denied access (PPL/protected).
            // Treat as None; heuristics decide what to do with missing path.
            let exe_path = proc.exe()
                .and_then(|p| if p.as_os_str().is_empty() { None } else { Some(p) })
                .map(|p| p.to_string_lossy().to_string());

            // command_line: join OsString args
            let command_line = {
                let args = proc.cmd();
                if args.is_empty() {
                    None
                } else {
                    let joined = args.iter()
                        .map(|a| a.to_string_lossy().to_string())
                        .collect::<Vec<_>>()
                        .join(" ");
                    if joined.is_empty() { None } else { Some(joined) }
                }
            };

            // thread_count:
            //   Linux  — tasks() gives the real thread list.
            //   Windows — sysinfo doesn't expose thread count; use 1 as the
            //             minimum so the zero-thread heuristic never fires on
            //             every Windows process incorrectly.
            let thread_count: u32 = {
                #[cfg(target_os = "linux")]
                { proc.tasks().map(|t| t.len() as u32).unwrap_or(1) }
                #[cfg(not(target_os = "linux"))]
                { 1u32 }
            };

            let memory_bytes = proc.memory();
            let memory_mb    = memory_bytes as f64 / 1024.0 / 1024.0;
            let virtual_mem  = proc.virtual_memory();
            let status       = format!("{:?}", proc.status());
            let parent_pid   = proc.parent().map(|p| p.as_u32());
            let start_time   = Some(proc.start_time());
            let user         = proc.user_id().map(|uid| format!("{}", **uid));

            ProcessInfo {
                pid,
                name: proc.name().to_string_lossy().to_string(),
                parent_pid,
                exe_path,
                command_line,
                status,
                start_time,
                user,
                cpu_usage:    proc.cpu_usage(),
                memory_mb,
                memory_bytes,
                virtual_memory: virtual_mem,
                thread_count,
                handle_count: None,
                module_count: None,
                threat_level:      ThreatLevel::Safe,
                threat_score:      0,
                is_threat:         false,
                detection_signals: Vec::new(),
                anomaly_flags:     Vec::new(),
            }
        })
        .collect()
}
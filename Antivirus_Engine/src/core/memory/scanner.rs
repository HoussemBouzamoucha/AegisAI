use anyhow::{anyhow, Result};
use std::ffi::c_void;
use std::mem::{size_of, MaybeUninit};
use std::sync::Arc;
use std::thread;
use std::time::Instant;
use sysinfo::{Pid, Process, ProcessRefreshKind, ProcessesToUpdate, RefreshKind, System, UpdateKind};

#[cfg(windows)]
use windows::{
    Win32::Foundation::{CloseHandle, HANDLE},
    Win32::System::Diagnostics::Debug::ReadProcessMemory,
    Win32::System::Memory::{
        MEM_COMMIT, MEM_PRIVATE, MEMORY_BASIC_INFORMATION, PAGE_PROTECTION_FLAGS,
        PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
        PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
        VirtualQueryEx,
    },
    Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ},
};

use crate::core::process::types::DetectionSignal;

#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub pid:            u32,
    pub process_name:   Arc<String>,
    pub process_path:   Arc<Option<String>>,
    pub command_line:   Arc<Option<String>>,
    pub region_start:   u64,
    pub region_size:    u64,
    pub protection:     String,
    pub is_executable:  bool,
    pub is_writable:    bool,
    pub is_readable:    bool,
    pub is_committed:   bool,
    pub is_private:     bool,
    pub content_sample: Option<String>,
    pub threat_level:   String,
    pub threat_score:   i32,
    pub is_threat:      bool,
    pub detection_signals: Vec<DetectionSignal>,
}

#[derive(Debug, Clone)]
pub struct MemoryStats {
    pub total_regions:       u64,
    pub scanned_processes:   u64,
    pub suspicious_regions:  u64,
    pub malicious_regions:   u64,
    pub total_bytes_scanned: u64,
    pub scan_duration_ms:    u64,
}

pub struct MemoryScanner;

impl MemoryScanner {
    pub fn new() -> Self {
        Self
    }

    pub fn scan_processes(&self, pid: Option<u32>) -> Result<(Vec<MemoryRegion>, MemoryStats)> {
        let start = Instant::now();
        let mut threat_regions = Vec::new();
        let mut scanned_processes = 0u64;
        let mut total_regions = 0u64;
        let mut total_bytes_scanned = 0u64;

        let process_refresh = ProcessRefreshKind::everything()
            .with_exe(UpdateKind::Always)
            .with_cmd(UpdateKind::Always);

        let refresh_kind = RefreshKind::nothing().with_processes(process_refresh);
        let mut system = System::new_with_specifics(refresh_kind);
        system.refresh_processes_specifics(ProcessesToUpdate::All, true, process_refresh);

        if let Some(pid) = pid {
            let process = system
                .process(Pid::from_u32(pid))
                .ok_or_else(|| anyhow!("Process {} not found", pid))?;
            let (regions, proc_total, proc_bytes) = self.scan_process(pid, process)?;
            if proc_total > 0 {
                scanned_processes = 1;
            }
            total_regions += proc_total;
            total_bytes_scanned += proc_bytes;
            threat_regions.extend(regions);
        } else {
            for process in system.processes().values() {
                let pid = process.pid().as_u32();
                if let Ok((regions, proc_total, proc_bytes)) = self.scan_process(pid, process) {
                    if proc_total > 0 {
                        scanned_processes += 1;
                        total_regions += proc_total;
                        total_bytes_scanned += proc_bytes;
                        threat_regions.extend(regions);
                    }
                }
            }
        }

        // Drop the System object now — no need to hold it while we compute stats.
        drop(system);

        let suspicious_regions = threat_regions
            .iter()
            .filter(|r| r.threat_level == "Suspicious")
            .count() as u64;
        let malicious_regions = threat_regions
            .iter()
            .filter(|r| r.threat_level == "Malicious")
            .count() as u64;

        let stats = MemoryStats {
            total_regions,
            scanned_processes,
            suspicious_regions,
            malicious_regions,
            total_bytes_scanned,
            scan_duration_ms: start.elapsed().as_millis() as u64,
        };

        Ok((threat_regions, stats))
    }

    // Returns (threat_only_regions, total_committed_count, total_bytes_scanned)
    fn scan_process(&self, pid: u32, process: &Process) -> Result<(Vec<MemoryRegion>, u64, u64)> {
        #[cfg(not(windows))]
        {
            return Err(anyhow!("Memory scanning is only supported on Windows."));
        }

        #[cfg(windows)]
        {
            let handle = unsafe {
                OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
            }
            .map_err(|e| anyhow!("Unable to open process {}: {}", pid, e))?;

            if handle.is_invalid() {
                return Err(anyhow!("Invalid handle for process {}", pid));
            }

            let result = self.enumerate_regions(handle, pid, process);
            unsafe { let _ = CloseHandle(handle); }
            result
        }
    }

    #[cfg(windows)]
    fn enumerate_regions(
        &self,
        handle: HANDLE,
        pid: u32,
        process: &sysinfo::Process,
    ) -> Result<(Vec<MemoryRegion>, u64, u64)> {
        let process_name = Arc::new(process.name().to_string_lossy().into_owned());

        // Defer these allocations — share process metadata across regions.
        let process_path = Arc::new(
            process
                .exe()
                .and_then(|p| p.to_str())
                .map(String::from),
        );

        let command_line = Arc::new(if process.cmd().is_empty() {
            None
        } else {
            Some(
                process
                    .cmd()
                    .iter()
                    .map(|s| s.to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join(" "),
            )
        });

        let mut threat_regions: Vec<MemoryRegion> = Vec::new();
        let mut total_committed: u64 = 0;
        let mut total_bytes: u64 = 0;
        let mut address = 0usize;
        let mut iter_count: usize = 0;

        loop {
            let mut mem_info = MaybeUninit::<MEMORY_BASIC_INFORMATION>::zeroed();
            let result = unsafe {
                VirtualQueryEx(
                    handle,
                    Some(address as *const c_void),
                    mem_info.as_mut_ptr(),
                    size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };

            if result == 0 {
                break;
            }

            let info = unsafe { mem_info.assume_init() };
            let region_start = info.BaseAddress as usize;
            let region_size = info.RegionSize as u64;

            if region_size == 0 {
                break;
            }

            let next_address = region_start.saturating_add(region_size as usize);
            let is_committed = info.State == MEM_COMMIT;

            if is_committed {
                total_committed += 1;
                total_bytes += region_size;

                let protection    = protection_to_string(info.Protect);
                let is_readable   = mem_is_readable(info.Protect);
                let is_writable   = mem_is_writable(info.Protect);
                let is_executable = mem_is_executable(info.Protect);
                let is_private    = info.Type == MEM_PRIVATE;

                let (threat_score, detection_signals) = score_region(
                    is_executable,
                    is_writable,
                    is_private,
                    region_size,
                    &protection,
                );

                // Only keep regions that are actually suspicious or malicious.
                // This avoids reporting every normal executable page loaded by the OS.
                if threat_score >= 20 {
                    let threat_level = if threat_score >= 40 {
                        "Malicious"
                    } else {
                        "Suspicious"
                    }
                    .to_string();

                    // Only read memory for regions we're actually going to report.
                    let content_sample = if is_readable {
                        read_memory_sample(handle, region_start as *const c_void, region_size)
                    } else {
                        None
                    };

                    threat_regions.push(MemoryRegion {
                        pid,
                        process_name:  process_name.clone(),
                        process_path:  process_path.clone(),
                        command_line:  command_line.clone(),
                        region_start:  region_start as u64,
                        region_size,
                        protection:    protection.clone(),
                        is_executable,
                        is_writable,
                        is_readable,
                        is_committed:  true,
                        is_private,
                        content_sample,
                        threat_level:  threat_level.clone(),
                        threat_score,
                        is_threat: true,
                        detection_signals,
                    });
                }
            }

            if next_address <= address {
                break;
            }
            address = next_address;

            // Yield every 1 000 regions so other threads get CPU time.
            iter_count += 1;
            if iter_count % 1_000 == 0 {
                thread::yield_now();
            }
        }

        Ok((threat_regions, total_committed, total_bytes))
    }
}

// ─── Protection helpers ───────────────────────────────────────────────────────

#[cfg(windows)]
fn protection_to_string(protect: PAGE_PROTECTION_FLAGS) -> String {
    match protect {
        PAGE_NOACCESS          => "NOACCESS".to_string(),
        PAGE_READONLY          => "READONLY".to_string(),
        PAGE_READWRITE         => "READWRITE".to_string(),
        PAGE_WRITECOPY         => "WRITECOPY".to_string(),
        PAGE_EXECUTE           => "EXECUTE".to_string(),
        PAGE_EXECUTE_READ      => "EXECUTE_READ".to_string(),
        PAGE_EXECUTE_READWRITE => "EXECUTE_READWRITE".to_string(),
        PAGE_EXECUTE_WRITECOPY => "EXECUTE_WRITECOPY".to_string(),
        other                  => format!("UNKNOWN_{:#X}", other.0),
    }
}

#[cfg(windows)]
fn mem_is_readable(protect: PAGE_PROTECTION_FLAGS) -> bool {
    protect != PAGE_NOACCESS
}

#[cfg(windows)]
fn mem_is_writable(protect: PAGE_PROTECTION_FLAGS) -> bool {
    matches!(
        protect,
        PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
    )
}

#[cfg(windows)]
fn mem_is_executable(protect: PAGE_PROTECTION_FLAGS) -> bool {
    matches!(
        protect,
        PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
    )
}

// ─── Memory reading ───────────────────────────────────────────────────────────

#[cfg(windows)]
fn read_memory_sample(handle: HANDLE, address: *const c_void, region_size: u64) -> Option<String> {
    let sample_len = std::cmp::min(region_size as usize, 64);
    let mut buffer = vec![0u8; sample_len];
    let mut bytes_read = 0usize;

    let success = unsafe {
        ReadProcessMemory(
            handle,
            address,
            buffer.as_mut_ptr() as *mut c_void,
            sample_len,
            Some(&mut bytes_read),
        )
        .is_ok()
    };

    if !success || bytes_read == 0 {
        return None;
    }

    let sample = &buffer[..bytes_read];
    Some(
        sample
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(" "),
    )
}

// ─── Scoring ──────────────────────────────────────────────────────────────────

#[cfg(windows)]
fn score_region(
    is_executable: bool,
    is_writable:   bool,
    is_private:    bool,
    region_size:   u64,
    protection:    &str,
) -> (i32, Vec<DetectionSignal>) {
    let mut score   = 0i32;
    let mut signals = Vec::new();

    if is_executable && is_writable {
        score += 40;
        signals.push(DetectionSignal::new("memory", "Executable writable memory region", 40));
    } else if is_executable && is_private && region_size >= 1024 * 1024 {
        score += 20;
        signals.push(DetectionSignal::new("memory", "Large private executable memory region", 20));
    }

    if is_writable && is_private {
        score += 10;
        signals.push(DetectionSignal::new("memory", "Writable private memory region", 10));
    }

    if is_writable && !is_executable {
        score += 5;
        signals.push(DetectionSignal::new("memory", "Writable region", 5));
    }

    if is_private && !is_executable {
        score += 2;
        signals.push(DetectionSignal::new("memory", "Private memory type", 2));
    }

    if region_size >= 50 * 1024 * 1024 {
        score += 10;
        signals.push(DetectionSignal::new("memory", "Large memory region", 10));
    }

    if protection.contains("NOACCESS") {
        signals.push(DetectionSignal::new("memory", "No access region", 1));
    }

    (score, signals)
}
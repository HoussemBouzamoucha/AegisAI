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

                let trusted_jit = is_trusted_jit(&process_name, process_path.as_deref());
                let system_proc = is_system_process(process_path.as_deref());

                let (mut threat_score, mut detection_signals) = score_region(
                    is_executable,
                    is_writable,
                    is_private,
                    region_size,
                    &protection,
                    trusted_jit,
                    system_proc,
                );

                // For regions that already have a base score, read a content
                // sample and run payload-indicator analysis on the raw bytes.
                // This upgrades scores for PE-in-anonymous-memory and NOP sleds
                // without reading memory for every normal region.
                let content_sample = if threat_score > 0 && is_readable {
                    let raw = read_memory_bytes(handle, region_start as *const c_void, region_size);
                    if let Some(ref bytes) = raw {
                        let (bonus, mut bonus_sigs) =
                            analyze_content(bytes, is_executable, is_private);
                        threat_score += bonus;
                        detection_signals.append(&mut bonus_sigs);
                    }
                    raw.map(|b| bytes_to_hex(&b))
                } else {
                    None
                };

                // Only keep regions that are actually suspicious or malicious.
                if threat_score >= 20 {
                    let threat_level = if threat_score >= 40 {
                        "Malicious"
                    } else {
                        "Suspicious"
                    }
                    .to_string();

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

/// Read up to `sample_len` raw bytes from the target process memory.
#[cfg(windows)]
fn read_memory_bytes(handle: HANDLE, address: *const c_void, region_size: u64) -> Option<Vec<u8>> {
    let sample_len = std::cmp::min(region_size as usize, 128);
    let mut buffer = vec![0u8; sample_len];
    let mut bytes_read = 0usize;

    let ok = unsafe {
        ReadProcessMemory(
            handle,
            address,
            buffer.as_mut_ptr() as *mut c_void,
            sample_len,
            Some(&mut bytes_read),
        )
        .is_ok()
    };

    if !ok || bytes_read == 0 {
        return None;
    }

    buffer.truncate(bytes_read);
    Some(buffer)
}

/// Format raw bytes as a space-separated hex string for display.
fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(" ")
}

// ─── Process trust classification ────────────────────────────────────────────

/// Processes that use JIT compilation and legitimately produce RWX / large
/// anonymous-executable regions as part of normal operation.
const KNOWN_JIT_PROCESSES: &[&str] = &[
    // .NET CLR / PowerShell
    "powershell.exe",
    "pwsh.exe",
    "dotnet.exe",
    // Node.js / Deno  (V8)
    "node.exe",
    "deno.exe",
    // Chromium / CEF-based apps  (V8 embedded)
    "chrome.exe",
    "msedge.exe",
    "opera.exe",
    "brave.exe",
    "firefox.exe",
    "overwolfbrowser.exe",
    "overwolf.exe",
    "overwolfbrowserhost.exe",
    // Java JVM
    "java.exe",
    "javaw.exe",
    // Electron  (V8)
    "code.exe",       // VS Code
    "discord.exe",
    "slack.exe",
    "teams.exe",
    "ms-teams.exe",
];

/// Returns true when the process is a known JIT runtime running from a
/// legitimate (non-temporary) path.  JIT engines routinely allocate RWX /
/// large anonymous-exec regions; penalising them creates massive false-positive
/// noise without catching real threats.
///
/// Safety guard: if the binary is located inside a temp directory, we do NOT
/// trust it — a JIT process spawned from %TEMP% is itself a red flag.
#[cfg(windows)]
fn is_trusted_jit(name: &str, path: Option<&str>) -> bool {
    let name_lc = name.to_lowercase();
    if !KNOWN_JIT_PROCESSES.contains(&name_lc.as_str()) {
        return false;
    }
    match path {
        Some(p) => {
            let pl = p.to_lowercase().replace('\\', "/");
            // Reject if the binary lives in a temp directory.
            !pl.contains("/temp/")
                && !pl.contains("/tmp/")
                && !pl.ends_with("/temp")
                && !pl.ends_with("/tmp")
                && !pl.contains("/appdata/local/temp")
        }
        // Unknown path → be conservative.
        None => false,
    }
}

/// Returns true when the process executable lives in a Windows system
/// directory.  OS components (svchost, lsass, services, etc.) are trusted and
/// must not be flagged for normal memory layouts.
#[cfg(windows)]
fn is_system_process(path: Option<&str>) -> bool {
    let Some(p) = path else { return false };
    let pl = p.to_lowercase().replace('\\', "/");
    pl.starts_with("c:/windows/system32/")
        || pl.starts_with("c:/windows/syswow64/")
        || pl.starts_with("c:/windows/winsxs/")
        || pl.starts_with("c:/windows/servicing/")
}

// ─── Scoring ──────────────────────────────────────────────────────────────────

/// Primary heuristic: score a memory region based on its protection flags,
/// size, and process trust level.
///
/// Trust tiers
/// ───────────
/// • Trusted JIT (known runtime from non-temp path) or system process
///   → RWX scores 5 (below reporting threshold); only escalated if content
///     analysis finds actual payload indicators (PE header, NOP sled).
///   → Large anonymous executable regions score 0 — V8/CLR heap is routine.
///
/// • Unknown / untrusted process
///   → RWX scores 25 (Suspicious).  Content analysis can push to Malicious
///     (PE header +20 → 45, NOP sled +10 → 35).
///   → Large anonymous exec scored as before.
///
/// Note: the RWX branch no longer early-returns so that content analysis
/// always runs and can escalate — or confirm — the score.
#[cfg(windows)]
fn score_region(
    is_executable: bool,
    is_writable:   bool,
    is_private:    bool,
    region_size:   u64,
    _protection:   &str,
    trusted_jit:   bool,
    system_proc:   bool,
) -> (i32, Vec<DetectionSignal>) {
    let mut score   = 0i32;
    let mut signals = Vec::new();
    let trusted     = trusted_jit || system_proc;

    // ── Tier 1: RWX ───────────────────────────────────────────────────────────
    // Execute + Write simultaneously is the canonical shellcode / reflective-DLL
    // injection signature (T1055).  However, JIT engines (.NET CLR, V8) also
    // create RWX pages legitimately.
    //
    // • Trusted process  → score 5 (silent; content analysis decides).
    // • Unknown process  → score 25 (Suspicious baseline).
    //
    // We no longer early-return here so that content analysis always runs
    // and can escalate the score when payload indicators are present.
    if is_executable && is_writable {
        if trusted {
            score += 5;
            // No UI signal added — routine JIT behaviour should not create noise.
        } else {
            score += 25;
            signals.push(DetectionSignal::new(
                "memory",
                "Executable + writable region (RWX) — shellcode / injection indicator (T1055)",
                25,
            ));
        }
    }

    // ── Tier 2: anonymous executable pages ────────────────────────────────────
    // MEM_PRIVATE + executable = no image-file backing (not MEM_IMAGE).
    // Trusted JIT and system processes skip this check: V8, CLR, and JVM
    // regularly allocate multi-MB anonymous exec regions for compiled code.
    // The `!is_writable` guard avoids double-counting with the RWX branch.
    if is_executable && is_private && !is_writable && !trusted {
        if region_size >= 8 * 1024 * 1024 {
            // ≥ 8 MB without image backing: uncommon outside injection payloads.
            score += 25;
            signals.push(DetectionSignal::new(
                "memory",
                "Large anonymous executable region (≥ 8 MB, no image backing)",
                25,
            ));
        } else if region_size >= 2 * 1024 * 1024 {
            // 2 – 8 MB: moderate indicator — could be JIT, but worth noting.
            score += 12;
            signals.push(DetectionSignal::new(
                "memory",
                "Anonymous executable region (2 – 8 MB, no image backing)",
                12,
            ));
        }
        // < 2 MB: JIT stubs / trampolines — too prevalent to be a useful signal.
    }

    (score, signals)
}

/// Content-based payload analysis for regions that already have a base score.
///
/// Only called on regions where `score_region` returned score > 0, so the
/// overhead is paid only for genuinely suspicious candidates.
fn analyze_content(
    bytes:         &[u8],
    is_executable: bool,
    is_private:    bool,
) -> (i32, Vec<DetectionSignal>) {
    let mut bonus   = 0i32;
    let mut signals = Vec::new();

    if bytes.len() < 4 {
        return (bonus, signals);
    }

    // ── PE header in anonymous executable memory ──────────────────────────────
    // "MZ" at offset 0 inside a MEM_PRIVATE executable region = PE file loaded
    // without going through the normal image loader (reflective DLL injection).
    if is_executable && is_private && bytes[0] == 0x4D && bytes[1] == 0x5A {
        bonus += 20;
        signals.push(DetectionSignal::new(
            "memory",
            "PE header (MZ) in anonymous executable memory — reflective injection",
            20,
        ));
    }

    // ── NOP sled ─────────────────────────────────────────────────────────────
    // > 40 % of the sample being 0x90 (NOP) suggests a shellcode landing pad.
    if is_executable {
        let nop_count = bytes.iter().filter(|&&b| b == 0x90).count();
        if nop_count * 100 / bytes.len() > 40 {
            bonus += 10;
            signals.push(DetectionSignal::new(
                "memory",
                "NOP sled detected (> 40 % of sample) — shellcode staging pattern",
                10,
            ));
        }
    }

    // ── INT3 / breakpoint flood ────────────────────────────────────────────────
    // > 40 % 0xCC bytes is unusual in legitimate code and can indicate injected
    // hook / patching sleds.
    if is_executable {
        let int3_count = bytes.iter().filter(|&&b| b == 0xCC).count();
        if int3_count * 100 / bytes.len() > 40 {
            bonus += 8;
            signals.push(DetectionSignal::new(
                "memory",
                "INT3 sled detected (> 40 % of sample) — possible hook / patch region",
                8,
            ));
        }
    }

    (bonus, signals)
}
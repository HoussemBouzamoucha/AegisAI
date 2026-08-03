use anyhow::{anyhow, Result};
use std::ffi::c_void;
use std::mem::{size_of, MaybeUninit};
use std::sync::Arc;
use std::thread;
use std::time::Instant;
use sysinfo::{Pid, Process, ProcessRefreshKind, ProcessesToUpdate, RefreshKind, System, UpdateKind};
use crate::core::utils::{calculate_entropy, is_pe_file};

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

                let trusted_jit    = is_trusted_jit(&process_name, process_path.as_deref());
                let system_proc    = is_system_process(process_path.as_deref(), &process_name);
                let trusted_install = is_trusted_install_path(process_path.as_deref());

                let (mut threat_score, mut detection_signals) = score_region(
                    is_executable,
                    is_writable,
                    is_private,
                    region_size,
                    &protection,
                    trusted_jit,
                    system_proc,
                    trusted_install,
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

                // Include all regions with any non-zero score so the UI list
                // is populated with noteworthy regions (executable, writable-
                // private, etc.).  Pure zero-score regions (normal mapped /
                // read-only pages) are still skipped to avoid flooding the UI.
                if threat_score > 0 {
                    let (threat_level, is_threat) = if threat_score >= 40 {
                        ("Malicious", true)
                    } else if threat_score >= 20 {
                        ("Suspicious", true)
                    } else {
                        ("Clean", false)
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
                        threat_level:  threat_level.to_string(),
                        threat_score,
                        is_threat,
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

/// Read up to `CONTENT_SAMPLE_BYTES` raw bytes from the target process memory.
///
/// 512 bytes gives the entropy and NOP-sled checks enough data to be
/// statistically meaningful while keeping the per-region overhead negligible.
const CONTENT_SAMPLE_BYTES: usize = 512;

#[cfg(windows)]
fn read_memory_bytes(handle: HANDLE, address: *const c_void, region_size: u64) -> Option<Vec<u8>> {
    let sample_len = std::cmp::min(region_size as usize, CONTENT_SAMPLE_BYTES);
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

/// Processes that use JIT compilation or dynamic code generation and
/// legitimately produce RWX / large anonymous-executable regions as part of
/// normal operation.
///
/// Rule: a process on this list is trusted only when its binary does NOT live
/// in a temporary directory (see `is_trusted_jit`).
const KNOWN_JIT_PROCESSES: &[&str] = &[
    // ── .NET CLR / PowerShell ────────────────────────────────────────────────
    "powershell.exe",
    "pwsh.exe",
    "dotnet.exe",
    "msbuild.exe",
    "csc.exe",
    "vbc.exe",

    // ── Node.js / Deno / Bun  (V8) ──────────────────────────────────────────
    "node.exe",
    "deno.exe",
    "bun.exe",

    // ── Chromium-based browsers  (V8) ────────────────────────────────────────
    "chrome.exe",
    "msedge.exe",
    "microsoftedge.exe",
    "opera.exe",
    "brave.exe",
    "vivaldi.exe",
    "chromium.exe",
    "ungoogled-chromium.exe",

    // ── Firefox  (SpiderMonkey JIT) ───────────────────────────────────────────
    "firefox.exe",
    "waterfox.exe",
    "librewolf.exe",
    "palemoon.exe",

    // ── Electron-based apps  (all embed V8) ───────────────────────────────────
    // Communication
    "discord.exe",
    "slack.exe",
    "teams.exe",
    "ms-teams.exe",
    "zoom.exe",
    "skype.exe",
    "signal.exe",
    "element.exe",
    "telegram.exe",
    "whatsapp.exe",
    "mattermost.exe",
    // Productivity / creative
    "code.exe",           // VS Code
    "cursor.exe",         // Cursor IDE
    "windsurf.exe",
    "obsidian.exe",
    "notion.exe",
    "figma.exe",
    "canva.exe",
    // Developer tools
    "postman.exe",
    "insomnia.exe",
    "gitkraken.exe",
    "github desktop.exe",
    "githubdesktop.exe",
    "lens.exe",           // Kubernetes IDE
    // Media / entertainment
    "spotify.exe",
    "twitch.exe",
    // Other popular Electron apps
    "1password.exe",
    "1password 7.exe",
    "dashlane.exe",
    "bitwarden.exe",
    "lastpass.exe",
    "termius.exe",
    "hyper.exe",
    "tabby.exe",
    "warp.exe",
    "microsoft teams.exe",

    // ── Overwolf / gaming overlay  (CEF) ─────────────────────────────────────
    "overwolf.exe",
    "overwolfbrowser.exe",
    "overwolfbrowserhost.exe",

    // ── JVM  (Java, Kotlin, Scala, Clojure) ──────────────────────────────────
    "java.exe",
    "javaw.exe",
    "javaws.exe",
    // JetBrains IDEs  (all JVM-based)
    "idea64.exe",
    "idea.exe",
    "webstorm64.exe",
    "pycharm64.exe",
    "clion64.exe",
    "rider64.exe",
    "goland64.exe",
    "datagrip64.exe",
    "phpstorm64.exe",
    "rubymine64.exe",
    "studio64.exe",       // Android Studio
    "dataspell64.exe",
    // Other JVM apps
    "minecraft.exe",
    "minecraft launcher.exe",
    "minecraftlauncher.exe",
    "eclipse.exe",
    "netbeans64.exe",

    // ── Rust toolchain  (LLVM JIT + proc-macro DLL loading) ─────────────────
    // rust-analyzer-proc-macro-srv allocates RWX regions to JIT-compile
    // proc-macro crates at build time.  rustc itself uses LLVM's JIT for
    // incremental compilation passes.  All run from known toolchain paths.
    "rust-analyzer.exe",
    "rust-analyzer-proc-macro-srv.exe",
    "rustc.exe",
    "cargo.exe",
    "clippy-driver.exe",
    "rustdoc.exe",

    // ── Python  (CPython / PyPy JIT) ─────────────────────────────────────────
    "python.exe",
    "pythonw.exe",
    "python3.exe",
    "pypy.exe",
    "pypy3.exe",

    // ── Ruby  (YARV JIT in Ruby 3+) ──────────────────────────────────────────
    "ruby.exe",

    // ── PHP  (OPcache JIT in PHP 8+) ─────────────────────────────────────────
    "php.exe",
    "php-cgi.exe",
    "php-fpm.exe",

    // ── Perl ──────────────────────────────────────────────────────────────────
    "perl.exe",

    // ── Julia  (LLVM JIT) ────────────────────────────────────────────────────
    "julia.exe",

    // ── R  (statistical computing with JIT via GNU R ≥ 4.x) ─────────────────
    "rscript.exe",
    "rgui.exe",
    "r.exe",

    // ── MATLAB  (JIT-compiled M-code) ────────────────────────────────────────
    "matlab.exe",
    "matlab_crash_handler.exe",

    // ── LuaJIT ───────────────────────────────────────────────────────────────
    "luajit.exe",

    // ── Media players  (SIMD / JIT-compiled decoders) ────────────────────────
    "vlc.exe",
    "mpv.exe",
    "mpc-hc.exe",
    "mpc-hc64.exe",
    "mpc-be.exe",
    "mpc-be64.exe",
    "potplayer.exe",
    "potplayermini64.exe",
    "wmplayer.exe",
    "groove.exe",
    "plex.exe",
    "kodi.exe",
    "kmplayer.exe",
    "daum potplayer.exe",
    "klite codec pack.exe",
    "ffmpeg.exe",

    // ── Game launchers ────────────────────────────────────────────────────────
    "steam.exe",
    "steamwebhelper.exe",
    "epicgameslauncher.exe",
    "galaxyclient.exe",       // GOG Galaxy
    "battle.net.exe",
    "battlenet.exe",
    "origin.exe",             // EA (legacy)
    "eadesktop.exe",          // EA App
    "uplay.exe",              // Ubisoft (legacy)
    "ubisoftgamelauncher.exe",
    "leagueclient.exe",
    "leagueclientuxrender.exe",
    "riotclientservices.exe",
    "valorant-win64-shipping.exe",
    "xboxapp.exe",

    // ── Game / 3-D engines  (shader JIT compilation) ──────────────────────────
    "unity.exe",
    "unityhub.exe",
    "unityeditor.exe",
    "ue4editor.exe",
    "ue4editor-win64-debug.exe",
    "unrealeditor.exe",       // UE5
    "godot.exe",
    "godot4.exe",

    // ── Database engines ──────────────────────────────────────────────────────
    "mysqld.exe",
    "mysqld-nt.exe",
    "postgres.exe",
    "mongod.exe",
    "redis-server.exe",
    "elasticsearch.exe",

    // ── Virtualisation / containers ───────────────────────────────────────────
    "vmware-vmx.exe",
    "vmware.exe",
    "vmplayer.exe",
    "virtualbox.exe",
    "vboxheadless.exe",
    "vboxsvc.exe",
    "docker.exe",
    "dockerd.exe",
    "wsl.exe",
    "wslhost.exe",
    "wslservice.exe",
    "qemu-system-x86_64.exe",

    // ── Security / sysadmin tools  (instrument processes legitimately) ─────────
    "wireshark.exe",
    "procexp64.exe",
    "procexp.exe",
    "procmon.exe",
    "procmon64.exe",
    "x64dbg.exe",
    "x32dbg.exe",
    "windbg.exe",
    "windbgx.exe",
    "ida.exe",
    "ida64.exe",
    "ollydbg.exe",
    "immunitydebugger.exe",
    "cheatengine-x86_64.exe",
    "cheatengine.exe",
    "fiddler.exe",
    "burpsuite.exe",
    "burp.exe",
];

/// Returns true when the process is a known JIT runtime running from a
/// legitimate (non-temporary) path.  JIT engines routinely allocate RWX /
/// large anonymous-exec regions; penalising them creates massive false-positive
/// noise without catching real threats.
///
/// Safety guard: if the binary is located inside a temp directory, we do NOT
/// trust it — a JIT process spawned from %TEMP% is itself a red flag.
///
/// **Path-unknown case**: if `sysinfo` cannot resolve the process path (handle
/// restrictions, race with process exit) we still apply JIT trust based on the
/// name alone.  The temp-directory guard cannot fire, but the alternative —
/// scoring every Chrome / VS Code / Node page at the "Unknown" tier — produces
/// thousands of false-positive alerts from normal browser and IDE operation.
#[cfg(windows)]
fn is_trusted_jit(name: &str, path: Option<&str>) -> bool {
    let name_lc = name.to_lowercase();
    if !KNOWN_JIT_PROCESSES.contains(&name_lc.as_str()) {
        return false;
    }
    match path {
        Some(p) => {
            let pl = p.to_lowercase().replace('\\', "/");
            // Exception: rust-analyzer-proc-macro-srv is legitimately staged by
            // cargo under %TEMP%\proc-macro-srv<N>-<N>\ at build time.  Trust it
            // even from temp — the proc-macro-srv directory name is a sufficiently
            // specific signal that a random dropper would not mimic.
            if pl.contains("proc-macro-srv") {
                return true;
            }
            // Reject if the binary lives in a temp directory.
            !pl.contains("/temp/")
                && !pl.contains("/tmp/")
                && !pl.ends_with("/temp")
                && !pl.ends_with("/tmp")
                && !pl.contains("/appdata/local/temp")
        }
        // Path unreadable — trust by name.  The RWX base score for known JIT
        // processes is only 5 so content analysis must still confirm before
        // a region is reported.
        None => true,
    }
}

/// Well-known Windows OS process names used as a fallback when the process
/// path is unreadable (restricted handle, race with process exit, etc.).
///
/// Kept intentionally short — only processes that are *always* OS components
/// and whose names cannot plausibly be spoofed by malware running at the
/// same privilege level as the scanner.
const KNOWN_SYSTEM_PROCESS_NAMES: &[&str] = &[
    "system",
    "registry",
    "memory compression",
    "secure system",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "winlogon.exe",
    "services.exe",
    "lsass.exe",
    "lsaiso.exe",
    "svchost.exe",
    "fontdrvhost.exe",
    "dwm.exe",
    "audiodg.exe",
    "werfault.exe",
    "werfaultsecure.exe",
    "conhost.exe",
    "dllhost.exe",
    "taskhostw.exe",
    "sihost.exe",
    "ctfmon.exe",
    "spoolsv.exe",
    "ntoskrnl.exe",
    "hal.dll",
];

/// Returns true when the process executable lives in a Windows system
/// directory.  OS components (svchost, lsass, services, werfault, etc.) are
/// trusted and must not be flagged for normal memory layouts.
///
/// Two-stage check:
/// 1. **Path-based** (primary) — drive-letter-agnostic fragment match so that
///    Windows installations on drives other than C: are handled correctly.
/// 2. **Name-based fallback** — for processes whose path is unreadable due to
///    handle restrictions (lsass, csrss, etc.).
#[cfg(windows)]
fn is_system_process(path: Option<&str>, name: &str) -> bool {
    if let Some(p) = path {
        let pl = p.to_lowercase().replace('\\', "/");
        // Drive-letter-agnostic: match the canonical Windows subdirectory
        // structure without assuming the OS lives on C:.
        if pl.contains("/windows/") {
            return true;
        }
    }
    // Name fallback — covers restricted-access OS processes.
    let name_lc = name.to_lowercase();
    KNOWN_SYSTEM_PROCESS_NAMES.contains(&name_lc.as_str())
}

/// Returns true when the process binary lives in a standard software
/// installation directory.  These processes receive reduced (but not zero)
/// scoring — they are orders of magnitude less likely to be malware than
/// processes running from temp directories or unknown paths, but we still
/// want content analysis to confirm before flagging them.
///
/// Temp paths are explicitly excluded so that a dropper that copies itself
/// into %ProgramFiles% is not accidentally trusted.
#[cfg(windows)]
fn is_trusted_install_path(path: Option<&str>) -> bool {
    let Some(p) = path else { return false };
    let pl = p.to_lowercase().replace('\\', "/");

    // Reject temp / staging locations regardless of other path components.
    if pl.contains("/temp/")
        || pl.contains("/tmp/")
        || pl.contains("/appdata/local/temp")
        || pl.contains("/appdata/local/microsoft/windowsapps/temp")
    {
        return false;
    }

    // Standard install roots — drive-letter-agnostic (some systems use D:\).
    pl.contains("/program files/")
        || pl.contains("/program files (x86)/")
        // Windows Store / UWP apps
        || pl.contains("/program files/windowsapps/")
        // Some legitimate software installs here (antivirus, agents, etc.)
        || pl.contains("/programdata/")
}

// ─── Scoring ──────────────────────────────────────────────────────────────────

/// Primary heuristic: score a memory region based on its protection flags,
/// size, and process trust level.
///
/// # Trust tiers
///
/// ```text
/// SystemOs       (C:\Windows\* or known OS name)  → score 0  — never flag OS components
/// JitRuntime     (known JIT, non-temp path)        → RWX: +5  — content analysis still runs
/// TrustedInstall (Program Files / PData)           → RWX: +8  — strong content needed
/// Unknown        (everything else)                 → RWX: +18 — any content indicator reports
/// ```
///
/// The reporting threshold is 20.
///
/// **Why TrustedInstall was reduced from 12 → 8**: at 12 the minimum entropy
/// bonus (+8 for entropy 6.8–7.2) was enough to reach the threshold, causing
/// DRM-protected and installer-packed binaries in Program Files to be reported
/// as Suspicious on entropy alone.  At 8 a single content signal is no longer
/// sufficient; a PE header in anonymous memory (+20 → 28) or a known shellcode
/// sequence (+20 → 28) still reports correctly.
///
/// **Unknown-tier RWX at 18**: bare RWX without any content confirmation never
/// crosses the threshold, so a one-off RWX page from a non-JIT, non-system app
/// does not generate noise by itself.
///
/// # Anonymous executable regions (MEM_PRIVATE + exec, no writable flag)
///
/// Thresholds raised from 2/8 MB to 4/16 MB after field testing showed that
/// many game engines and media decoders allocate 2–4 MB private exec regions
/// for compiled shader / filter code.  Trusted processes skip this check
/// entirely.
#[cfg(windows)]
fn score_region(
    is_executable:   bool,
    is_writable:     bool,
    is_private:      bool,
    region_size:     u64,
    _protection:     &str,
    trusted_jit:     bool,
    system_proc:     bool,
    trusted_install: bool,
) -> (i32, Vec<DetectionSignal>) {
    let mut score   = 0i32;
    let mut signals = Vec::new();

    // OS components are unconditionally clean — scoring them is noise.
    if system_proc {
        return (0, signals);
    }

    // ── RWX: Execute + Write ──────────────────────────────────────────────────
    // The canonical shellcode / reflective-DLL injection signature (T1055).
    // JIT engines (.NET CLR, V8, JVM) also create RWX pages legitimately.
    //
    // Scores are deliberately set below the 20-point reporting threshold so
    // that content analysis must confirm the suspicion before a region is
    // reported.  This eliminates the most common false-positive class: ordinary
    // installed applications that briefly use RWX pages for code patching, DRM,
    // or JIT-style optimisation.
    if is_executable && is_writable {
        if trusted_jit {
            // Known JIT runtime — score 5, no visible signal.
            // Content analysis can still escalate if actual shellcode is present.
            score += 5;
        } else if trusted_install {
            // Program Files / ProgramData — legitimately installed software.
            // Score 8 (well below threshold); strong content evidence needed.
            // Reduced from 12: at 12, the minimum entropy bonus (+8) already
            // reached the threshold, generating FPs from DRM / packed installers.
            score += 8;
            signals.push(DetectionSignal::new(
                "memory",
                "Executable + writable region (RWX) in installed application — verify with content",
                8,
            ));
        } else {
            // No trust — score 18 (still below threshold).
            // A single content indicator (PE header, high entropy, NOP sled)
            // will push this over 20 and trigger a report.
            score += 18;
            signals.push(DetectionSignal::new(
                "memory",
                "Executable + writable region (RWX) — shellcode / injection indicator (T1055)",
                18,
            ));
        }
    }

    // ── Anonymous executable pages ────────────────────────────────────────────
    // MEM_PRIVATE + executable, no writable flag = code region with no
    // image-file backing (not MEM_IMAGE).
    //
    // Trusted processes (JIT, system) skip this check entirely — V8, CLR, and
    // JVM routinely allocate multi-MB anonymous exec regions for compiled code.
    // The `!is_writable` guard avoids double-counting with the RWX branch above.
    //
    // Thresholds: 16 MB (strong indicator) / 4 MB (moderate, content needed).
    // Rationale: game shaders and media decoders commonly fall in the 2–4 MB
    // range; raising the lower bound from 2 MB to 4 MB eliminates that FP class.
    if is_executable && is_private && !is_writable && !trusted_jit {
        if region_size >= 16 * 1024 * 1024 {
            // ≥ 16 MB without image backing: very unusual outside injection payloads.
            score += 20;
            signals.push(DetectionSignal::new(
                "memory",
                "Large anonymous executable region (≥ 16 MB, no image backing) — likely injected code",
                20,
            ));
        } else if region_size >= 4 * 1024 * 1024 && !trusted_install {
            // 4 – 16 MB, untrusted path: moderate indicator.
            // Below threshold alone — content analysis decides.
            score += 10;
            signals.push(DetectionSignal::new(
                "memory",
                "Anonymous executable region (4 – 16 MB, no image backing)",
                10,
            ));
        }
        // < 4 MB: JIT stubs, trampolines, shader kernels — too prevalent.
    }

    (score, signals)
}

/// Well-known shellcode preamble byte sequences.
///
/// These are the opening bytes of common shellcode stubs used by Metasploit,
/// Cobalt Strike, and hand-crafted exploits.  Matching any of these in a
/// private executable region is a very strong indicator of injection.
const SHELLCODE_SEQUENCES: &[(&[u8], &str)] = &[
    // x86 classic: pushad; mov ebp, esp
    (&[0x60, 0x89, 0xE5], "x86 shellcode preamble (pushad; mov ebp,esp)"),
    // x64 common: cld; rex.w sub rsp (Metasploit / CS beacon alignment stub)
    (&[0xFC, 0x48, 0x83, 0xE4], "x64 shellcode alignment stub (cld; and rsp)"),
    // Metasploit x86 reverse_tcp / meterpreter stage-0
    (&[0xFC, 0xE8, 0x89, 0x00, 0x00, 0x00], "Metasploit x86 stage-0 stub"),
    // Metasploit x86 variant (shorter header)
    (&[0xFC, 0xE8, 0x82, 0x00, 0x00, 0x00], "Metasploit x86 stage-0 variant"),
    // Cobalt Strike Beacon: push ebp; mov ebp, esp; sub esp; push esi
    (&[0x55, 0x89, 0xE5, 0x83, 0xEC], "Cobalt Strike beacon function prologue"),
    // egghunter / SEH-based shellcode prefix
    (&[0x66, 0x81, 0xCA, 0xFF, 0x0F], "SEH egghunter shellcode pattern"),
];

/// Content-based payload analysis for regions that already have a base score.
///
/// Only called on regions where `score_region` returned score > 0, so the
/// overhead is paid only for genuinely suspicious candidates.
///
/// # Checks (in order)
///
/// 1. **PE header** — MZ magic in private executable memory = reflective injection.
/// 2. **Entropy** — Shannon entropy > 7.2 in private exec memory = packed shellcode.
///    Threshold raised from 6.8 to avoid flagging compressed resource sections
///    that some legitimate code generators produce.
/// 3. **NOP sled** — > 50 % 0x90 bytes (raised from 40 %; reduces FPs on
///    aligned function prologues which commonly have 1–8 NOP padding bytes).
/// 4. **INT3 flood** — > 50 % 0xCC bytes (debug-mode fill or hook patching sled).
/// 5. **Shellcode sequences** — exact byte-sequence match against known stubs.
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

    // ── 1. PE header in anonymous executable memory ───────────────────────────
    // "MZ" at offset 0 inside a MEM_PRIVATE executable region means a PE was
    // loaded without going through the normal image loader — reflective DLL
    // injection (T1055.001).
    if is_executable && is_private && is_pe_file(bytes) {
        bonus += 20;
        signals.push(DetectionSignal::new(
            "memory",
            "PE header (MZ) in anonymous executable memory — reflective DLL injection (T1055.001)",
            20,
        ));
    }

    // ── 2. Entropy — packed / encrypted shellcode ─────────────────────────────
    // Legitimate compiled code has entropy in the 5.0–6.5 range.
    // Packed or encrypted shellcode typically exceeds 7.2 (approaching the
    // theoretical maximum of 8.0 for uniformly random bytes).
    // Only checked in private executable regions to avoid FPs on compressed
    // resources in mapped image files.
    if is_executable && is_private && bytes.len() >= 64 {
        let entropy = calculate_entropy(bytes);
        if entropy > 7.2 {
            bonus += 15;
            signals.push(DetectionSignal::new(
                "memory",
                &format!(
                    "Very high entropy ({:.2}) in private executable memory — packed / encrypted shellcode",
                    entropy
                ),
                15,
            ));
        } else if entropy > 6.8 {
            bonus += 8;
            signals.push(DetectionSignal::new(
                "memory",
                &format!(
                    "High entropy ({:.2}) in private executable memory — possible packed code",
                    entropy
                ),
                8,
            ));
        }
    }

    // ── 3. NOP sled ───────────────────────────────────────────────────────────
    // A shellcode landing pad typically fills the approach region with 0x90
    // (NOP) instructions.  Threshold raised to 50 % on a 512-byte sample
    // (was 40 % on 128 bytes) to eliminate FPs from aligned function prologues,
    // which legitimately contain a handful of NOP padding bytes.
    if is_executable && bytes.len() >= 16 {
        let nop_count = bytes.iter().filter(|&&b| b == 0x90).count();
        if nop_count * 100 / bytes.len() > 50 {
            bonus += 15;
            signals.push(DetectionSignal::new(
                "memory",
                &format!(
                    "NOP sled detected ({:.0}% of sample) — shellcode staging pattern",
                    nop_count as f64 * 100.0 / bytes.len() as f64
                ),
                15,
            ));
        }
    }

    // ── 4. INT3 / breakpoint flood ────────────────────────────────────────────
    // > 50 % 0xCC bytes in executable memory is unusual: debug-mode compilers
    // fill uninitialised stack frames with 0xCC, but not in .text.  In an
    // anonymous exec region it suggests a hook patching sled or trampolines
    // planted by an in-process code injector.
    if is_executable && bytes.len() >= 16 {
        let int3_count = bytes.iter().filter(|&&b| b == 0xCC).count();
        if int3_count * 100 / bytes.len() > 50 {
            bonus += 10;
            signals.push(DetectionSignal::new(
                "memory",
                &format!(
                    "INT3 sled detected ({:.0}% of sample) — hook / patch region indicator",
                    int3_count as f64 * 100.0 / bytes.len() as f64
                ),
                10,
            ));
        }
    }

    // ── 5. Known shellcode byte sequences ─────────────────────────────────────
    // Exact match against the opening bytes of well-known shellcode stubs.
    // Only checked in private executable memory to avoid matching legitimate
    // code that happens to use the same prologue pattern in a mapped image.
    if is_executable && is_private {
        for (seq, description) in SHELLCODE_SEQUENCES {
            if bytes.starts_with(seq) {
                bonus += 20;
                signals.push(DetectionSignal::new(
                    "memory",
                    &format!("Known shellcode sequence: {}", description),
                    20,
                ));
                // One match is enough — don't double-count overlapping sequences.
                break;
            }
        }
    }

    (bonus, signals)
}
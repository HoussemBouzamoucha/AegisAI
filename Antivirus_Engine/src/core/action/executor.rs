// File: src/core/action/executor.rs
//
// Post-verdict containment actions — the layer between the graph verdict and
// the operating system.
//
// Each public function is synchronous, self-contained, and returns a typed
// result struct that `main.rs` serialises directly to JSON.  Side-effects
// (file moves, firewall rules, dump files, interface state) are all logged
// under `%PROGRAMDATA%\AegisAI\` for forensic review and rollback.
//
// Windows-specific calls are guarded by `#[cfg(windows)]`.  On other
// platforms every function returns a descriptive error so the crate still
// compiles in CI.
//
// Design principles (from actions.md):
//   • Never delete quarantined files — move and rename only.
//   • Use `netsh` for firewall / interface control (auditable, no COM).
//   • `MiniDumpWithFullMemory` for dumps — compatible with WinDbg / Volatility.
//   • Firewall rule names embed a timestamp so they are unique and rollback-safe.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

// ─── AegisAI runtime data directory ──────────────────────────────────────────

/// Root of all AegisAI on-disk runtime state.
///
/// Prefers `%PROGRAMDATA%\AegisAI`.  Falls back to `%TEMP%\AegisAI` when
/// the engine is running without elevation (e.g. during development tests).
fn aegisai_data_dir() -> PathBuf {
    let base = std::env::var("PROGRAMDATA")
        .or_else(|_| std::env::var("TEMP"))
        .unwrap_or_else(|_| "C:\\Temp".to_string());
    PathBuf::from(base).join("AegisAI")
}

/// Create `path` and all missing parent directories.
fn ensure_dir(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)
}

/// Seconds since the Unix epoch — used in timestamped filenames and metadata.
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ─── SHA-256 helper ───────────────────────────────────────────────────────────

/// Compute the hex-encoded SHA-256 of a file without buffering it entirely.
///
/// Streams in 64 KB chunks; suitable for large executables.
fn file_sha256(path: &Path) -> io::Result<String> {
    let mut hasher = Sha256::new();
    let mut file = fs::File::open(path)?;
    io::copy(&mut file, &mut hasher)?;
    Ok(hex::encode(hasher.finalize()))
}

// ─── 1. File Quarantine ───────────────────────────────────────────────────────

/// Returned by [`quarantine_file`].
pub struct QuarantineResult {
    pub success:         bool,
    /// Absolute path to the quarantined file in the AegisAI quarantine folder.
    pub quarantine_path: Option<String>,
    /// SHA-256 hex of the original file.
    pub sha256:          Option<String>,
    pub error:           Option<String>,
}

/// Move `path` into `%PROGRAMDATA%\AegisAI\quarantine\`.
///
/// Steps:
/// 1. Hash the source file with SHA-256.
/// 2. Ensure the quarantine directory exists.
/// 3. Rename to `{sha256}.quarantined` — the extension change alone prevents
///    accidental execution even if the folder is browsed.
/// 4. Write a JSON sidecar `{sha256}.meta.json` with provenance metadata
///    (original path, hash, timestamp, reason).
///
/// Cross-volume moves fall back to copy + remove; the original is never
/// left on disk.  Deletion of quarantined files requires explicit user action.
pub fn quarantine_file(path: &str) -> QuarantineResult {
    let src = Path::new(path);

    if !src.exists() {
        return QuarantineResult {
            success:         false,
            quarantine_path: None,
            sha256:          None,
            error:           Some(format!("File does not exist: {path}")),
        };
    }

    // 1. Hash the file before moving it.
    let sha256 = match file_sha256(src) {
        Ok(h)  => h,
        Err(e) => return QuarantineResult {
            success:         false,
            quarantine_path: None,
            sha256:          None,
            error:           Some(format!("Failed to hash file: {e}")),
        },
    };

    // 2. Ensure quarantine directory exists.
    let quarantine_dir = aegisai_data_dir().join("quarantine");
    if let Err(e) = ensure_dir(&quarantine_dir) {
        return QuarantineResult {
            success:         false,
            quarantine_path: None,
            sha256:          Some(sha256),
            error:           Some(format!("Cannot create quarantine dir: {e}")),
        };
    }

    let dst     = quarantine_dir.join(format!("{sha256}.quarantined"));
    let dst_str = dst.to_string_lossy().to_string();

    // 3. Move the file; fall back to copy+remove if rename crosses volumes.
    let move_result = fs::rename(src, &dst)
        .or_else(|_| fs::copy(src, &dst).and(fs::remove_file(src)));

    if let Err(e) = move_result {
        return QuarantineResult {
            success:         false,
            quarantine_path: None,
            sha256:          Some(sha256),
            error:           Some(format!("Failed to move file to quarantine: {e}")),
        };
    }

    // 4. Write sidecar metadata (non-fatal if it fails).
    let meta_path = quarantine_dir.join(format!("{sha256}.meta.json"));
    let meta = serde_json::json!({
        "original_path":  path,
        "sha256":         sha256,
        "quarantined_at": unix_now(),
        "reason":         "manual_quarantine",
    });
    let _ = fs::write(&meta_path, serde_json::to_string_pretty(&meta).unwrap_or_default());

    QuarantineResult {
        success:         true,
        quarantine_path: Some(dst_str),
        sha256:          Some(sha256),
        error:           None,
    }
}

// ─── 2. Firewall Block ────────────────────────────────────────────────────────

/// Returned by [`block_ip`].
pub struct BlockIpResult {
    pub success:   bool,
    /// The `netsh` rule name — store this to call [`remove_block_ip`] later.
    pub rule_name: Option<String>,
    pub error:     Option<String>,
}

/// Add Windows Firewall deny rule(s) for `remote_ip`.
///
/// `direction` — `"out"` blocks outbound only; `"both"` blocks in and out.
///
/// Rule names follow `AegisAI-Block-{sanitized_ip}-{unix_ts}` so each rule
/// is unique, human-readable in the Firewall GUI, and rollback-safe.
///
/// All created rule names are appended to
/// `%PROGRAMDATA%\AegisAI\firewall_rules.json` for audit and rollback.
///
/// **Why `netsh` instead of the COM firewall API:** `netsh` is available on
/// all Windows versions targeted, requires no COM interop in Rust, and the
/// commands are human-readable and auditable in shell history.
pub fn block_ip(remote_ip: &str, direction: &str) -> BlockIpResult {
    // Sanitize IP for use in the rule name (colons in IPv6 are invalid in names).
    let ip_tag    = remote_ip.replace(':', "-").replace('.', "-");
    let rule_name = format!("AegisAI-Block-{ip_tag}-{}", unix_now());

    // Determine which directions to block.
    let directions: &[&str] = if direction == "both" { &["out", "in"] } else { &["out"] };

    for dir in directions {
        let status = Command::new("netsh")
            .args([
                "advfirewall", "firewall", "add", "rule",
                &format!("name={rule_name}"),
                &format!("dir={dir}"),
                "action=block",
                &format!("remoteip={remote_ip}"),
                "enable=yes",
                "profile=any",
            ])
            .status();

        match status {
            Ok(s) if s.success() => {}
            Ok(s) => return BlockIpResult {
                success:   false,
                rule_name: None,
                error:     Some(format!("netsh exited {:?} for dir={dir}", s.code())),
            },
            Err(e) => return BlockIpResult {
                success:   false,
                rule_name: None,
                error:     Some(format!("Failed to run netsh: {e}")),
            },
        }
    }

    // Persist the rule name so it can be found and rolled back later.
    append_firewall_rule(&rule_name);

    BlockIpResult { success: true, rule_name: Some(rule_name), error: None }
}

/// Remove a previously created AegisAI firewall block rule by name.
///
/// Runs `netsh advfirewall firewall delete rule name="{rule_name}"` and
/// removes the entry from `firewall_rules.json`.
pub fn remove_block_ip(rule_name: &str) -> Result<(), String> {
    let status = Command::new("netsh")
        .args(["advfirewall", "firewall", "delete", "rule",
               &format!("name={rule_name}")])
        .status()
        .map_err(|e| format!("Failed to run netsh: {e}"))?;

    if status.success() {
        remove_firewall_rule(rule_name);
        Ok(())
    } else {
        Err(format!("netsh exited {:?}", status.code()))
    }
}

// Helpers — persist the list of active AegisAI firewall rules.

fn firewall_rules_path() -> PathBuf {
    aegisai_data_dir().join("firewall_rules.json")
}

fn load_firewall_rules() -> Vec<String> {
    fs::read_to_string(firewall_rules_path())
        .ok()
        .and_then(|s| serde_json::from_str::<Vec<String>>(&s).ok())
        .unwrap_or_default()
}

fn save_firewall_rules(rules: &[String]) {
    let _ = ensure_dir(&aegisai_data_dir());
    let _ = fs::write(
        firewall_rules_path(),
        serde_json::to_string_pretty(rules).unwrap_or_default(),
    );
}

fn append_firewall_rule(rule_name: &str) {
    let mut rules = load_firewall_rules();
    rules.push(rule_name.to_string());
    save_firewall_rules(&rules);
}

fn remove_firewall_rule(rule_name: &str) {
    let mut rules = load_firewall_rules();
    rules.retain(|r| r != rule_name);
    save_firewall_rules(&rules);
}

// ─── 3. Memory Dump ───────────────────────────────────────────────────────────

/// Returned by [`dump_memory`].
pub struct DumpResult {
    pub success:   bool,
    /// Absolute path to the `.dmp` file written to `%PROGRAMDATA%\AegisAI\dumps\`.
    pub dump_path: Option<String>,
    pub error:     Option<String>,
}

/// Write a full memory dump of process `pid` to disk.
///
/// Steps:
/// 1. Attempt to enable `SeDebugPrivilege` on the calling process token so
///    cross-process memory access succeeds even for protected processes.
/// 2. Open the target process with `PROCESS_ALL_ACCESS`.
/// 3. Create `%PROGRAMDATA%\AegisAI\dumps\{pid}_{unix_ts}.dmp`.
/// 4. Call `MiniDumpWriteDump` with `MiniDumpWithFullMemory` — the most
///    complete dump type; captures all committed memory pages and is
///    compatible with WinDbg and Volatility.
///
/// The dump file is preserved even after process termination — do not delete
/// it until the forensic investigation is closed.
///
/// **Requires** the daemon to be running as Administrator (it already is for
/// memory scanning).
#[cfg(windows)]
pub fn dump_memory(pid: u32) -> DumpResult {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::Diagnostics::Debug::{MiniDumpWithFullMemory, MiniDumpWriteDump};
    use windows::Win32::System::Threading::{
        GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_ALL_ACCESS,
    };
    use windows::Win32::Security::{
        AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES,
        SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
    };

    // ── Enable SeDebugPrivilege ───────────────────────────────────────────────
    // Required for cross-process full-memory access, especially for protected
    // or system-owned processes.  Failure is non-fatal — we still attempt the
    // dump in case the process is accessible without the privilege.
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )
        .is_ok()
        {
            let mut luid = windows::Win32::Foundation::LUID::default();
            let _ = LookupPrivilegeValueW(
                None,
                windows::core::w!("SeDebugPrivilege"),
                &mut luid,
            );
            let privs = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [LUID_AND_ATTRIBUTES {
                    Luid:       luid,
                    Attributes: SE_PRIVILEGE_ENABLED,
                }],
            };
            let _ = AdjustTokenPrivileges(token, false, Some(&privs), 0, None, None);
            if !token.is_invalid() {
                let _ = CloseHandle(token);
            }
        }
    }

    // ── Open target process ───────────────────────────────────────────────────
    let proc_handle = match unsafe { OpenProcess(PROCESS_ALL_ACCESS, false, pid) } {
        Ok(h)  => h,
        Err(e) => return DumpResult {
            success:   false,
            dump_path: None,
            error:     Some(format!("OpenProcess failed for PID {pid}: {e}")),
        },
    };

    // ── Create dump file ──────────────────────────────────────────────────────
    let dumps_dir = aegisai_data_dir().join("dumps");
    if let Err(e) = ensure_dir(&dumps_dir) {
        unsafe { let _ = CloseHandle(proc_handle); }
        return DumpResult {
            success:   false,
            dump_path: None,
            error:     Some(format!("Cannot create dumps dir: {e}")),
        };
    }

    let dump_path = dumps_dir.join(format!("{pid}_{}.dmp", unix_now()));
    let dump_file = match fs::File::create(&dump_path) {
        Ok(f)  => f,
        Err(e) => {
            unsafe { let _ = CloseHandle(proc_handle); }
            return DumpResult {
                success:   false,
                dump_path: None,
                error:     Some(format!("Cannot create dump file: {e}")),
            };
        }
    };

    // ── Write the dump ────────────────────────────────────────────────────────
    // Wrap the std::fs::File raw handle in a HANDLE without transferring
    // ownership — dump_file stays alive for the duration of the call, keeping
    // the underlying handle valid.  We do NOT CloseHandle(file_handle) because
    // dump_file's Drop impl owns the handle.
    let file_handle = HANDLE(dump_file.as_raw_handle());
    let result = unsafe {
        MiniDumpWriteDump(
            proc_handle,
            pid,
            file_handle,
            MiniDumpWithFullMemory,
            None,
            None,
            None,
        )
    };

    unsafe { let _ = CloseHandle(proc_handle); }

    match result {
        Ok(()) => DumpResult {
            success:   true,
            dump_path: Some(dump_path.to_string_lossy().to_string()),
            error:     None,
        },
        Err(e) => {
            let _ = fs::remove_file(&dump_path); // clean up empty/partial file
            DumpResult {
                success:   false,
                dump_path: None,
                error:     Some(format!("MiniDumpWriteDump failed for PID {pid}: {e}")),
            }
        }
    }
}

/// Non-Windows stub — returns an error so the crate still compiles in CI.
#[cfg(not(windows))]
pub fn dump_memory(_pid: u32) -> DumpResult {
    DumpResult {
        success:   false,
        dump_path: None,
        error:     Some("Memory dump is only supported on Windows".to_string()),
    }
}

// ─── 4. Persistence Check ────────────────────────────────────────────────────

/// A single autorun / persistence mechanism discovered on the host.
pub struct PersistenceEntry {
    /// Source category: `"registry"` | `"scheduled_task"` | `"startup_folder"`
    pub kind:       String,
    /// Human-readable identifier (registry value name, task name, filename).
    pub name:       String,
    /// Executable path referenced by this entry (may be a command line with args).
    pub path:       String,
    /// SHA-256 of the target file if it exists on disk.
    pub sha256:     Option<String>,
    /// True when `path` overlaps with a path from the current verdict.
    pub suspicious: bool,
}

/// Returned by [`check_persistence`].
pub struct PersistenceResult {
    pub success: bool,
    pub entries: Vec<PersistenceEntry>,
    pub error:   Option<String>,
}

/// Scan three persistence locations and return every entry found.
///
/// `suspicious_paths` — executable paths from the current verdict (malicious
/// file paths + exe paths of terminated PIDs).  Each found entry is cross-
/// referenced against this list; a match sets `suspicious = true`.
///
/// Sub-scans:
/// 1. **Registry** — four standard Windows autorun keys via `reg query`.
/// 2. **Scheduled tasks** — `schtasks /query /fo CSV /v` (action path field).
/// 3. **Startup folders** — `%APPDATA%` and `%PROGRAMDATA%` startup dirs.
pub fn check_persistence(suspicious_paths: &[String]) -> PersistenceResult {
    // Pre-lowercase suspicious paths for case-insensitive comparison.
    let sp_lower: Vec<String> = suspicious_paths.iter()
        .map(|p| p.to_lowercase())
        .collect();

    let mut entries: Vec<PersistenceEntry> = Vec::new();

    // ── 1. Registry run keys ──────────────────────────────────────────────────
    let run_keys = [
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
    ];

    for key in &run_keys {
        if let Ok(values) = query_registry_run_key(key) {
            for (name, path) in values {
                let sha256 = Path::new(&path).exists()
                    .then(|| file_sha256(Path::new(&path)).ok())
                    .flatten();
                let suspicious = sp_lower.iter()
                    .any(|sp| path.to_lowercase().contains(sp.as_str()));
                entries.push(PersistenceEntry { kind: "registry".into(), name, path, sha256, suspicious });
            }
        }
        // Missing keys are not errors — not all keys exist on every system.
    }

    // ── 2. Scheduled tasks ────────────────────────────────────────────────────
    if let Ok(tasks) = query_scheduled_tasks() {
        for (name, path) in tasks {
            let sha256 = Path::new(&path).exists()
                .then(|| file_sha256(Path::new(&path)).ok())
                .flatten();
            let suspicious = sp_lower.iter()
                .any(|sp| path.to_lowercase().contains(sp.as_str()));
            entries.push(PersistenceEntry {
                kind: "scheduled_task".into(), name, path, sha256, suspicious,
            });
        }
    }

    // ── 3. Startup folders ────────────────────────────────────────────────────
    let startup_dirs: Vec<PathBuf> = [
        std::env::var("APPDATA")
            .map(|d| PathBuf::from(d).join(r"Microsoft\Windows\Start Menu\Programs\Startup")),
        std::env::var("PROGRAMDATA")
            .map(|d| PathBuf::from(d).join(r"Microsoft\Windows\Start Menu\Programs\Startup")),
    ]
    .into_iter()
    .filter_map(|r| r.ok())
    .collect();

    for dir in &startup_dirs {
        if let Ok(iter) = fs::read_dir(dir) {
            for item in iter.flatten() {
                let file_path = item.path();
                let name      = file_path.file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();
                let path_str  = file_path.to_string_lossy().to_string();
                let sha256    = file_sha256(&file_path).ok();
                let suspicious = sp_lower.iter()
                    .any(|sp| path_str.to_lowercase().contains(sp.as_str()));
                entries.push(PersistenceEntry {
                    kind: "startup_folder".into(), name, path: path_str, sha256, suspicious,
                });
            }
        }
    }

    PersistenceResult { success: true, entries, error: None }
}

/// Query a Windows registry key via `reg query` and return `(value_name, data)` pairs.
///
/// Only entries whose data looks like an executable path are returned
/// (`*.exe`, contains `:\`, or is quoted).  Surrounding quotes are stripped.
///
/// Output format of `reg query`:
/// ```text
/// HKEY_CURRENT_USER\...\Run
///     OneDrive    REG_SZ    "C:\...\OneDrive.exe" /background
/// ```
fn query_registry_run_key(key: &str) -> Result<Vec<(String, String)>, String> {
    let output = Command::new("reg")
        .args(["query", key])
        .output()
        .map_err(|e| format!("reg query failed: {e}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut result = Vec::new();

    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("HKEY") { continue; }

        // Columns are separated by 4+ spaces; split at most twice so data
        // (which may itself contain spaces) is preserved intact.
        let parts: Vec<&str> = trimmed.splitn(3, "    ")
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();

        if parts.len() >= 3 {
            let name = parts[0].to_string();
            let data = parts[2].to_string();

            // Accept only entries that plausibly reference an executable.
            let data_lower = data.to_lowercase();
            if data_lower.ends_with(".exe") || data.contains(":\\") || data.starts_with('"') {
                // Take only the path portion (strip arguments after the first space
                // outside of quotes).
                let clean = data.trim_matches('"').to_string();
                let exe_path = if let Some(idx) = clean.find("\" ") {
                    clean[..idx].trim_matches('"').to_string()
                } else {
                    // No quoted trailing args — take up to first space after ".exe"
                    clean.splitn(2, ".exe ").next()
                        .map(|s| format!("{s}.exe"))
                        .unwrap_or(clean)
                };
                result.push((name, exe_path));
            }
        }
    }

    Ok(result)
}

/// Query scheduled tasks via `schtasks /query /fo CSV /v` and return
/// `(task_name, task_action_path)` pairs.
///
/// The CSV header includes "TaskName" and "Task To Run"; both columns are
/// matched case-insensitively to handle localised Windows installations.
fn query_scheduled_tasks() -> Result<Vec<(String, String)>, String> {
    let output = Command::new("schtasks")
        .args(["/query", "/fo", "CSV", "/v"])
        .output()
        .map_err(|e| format!("schtasks failed: {e}"))?;

    let stdout  = String::from_utf8_lossy(&output.stdout);
    let mut result: Vec<(String, String)> = Vec::new();
    let mut header: Vec<String> = Vec::new();
    // Track the last-seen TaskName because the CSV repeats the task name on
    // every action row but the action path is on a separate row in some versions.
    let mut last_task_name = String::new();

    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() { continue; }

        let fields = split_csv_line(line);

        if header.is_empty() {
            header = fields;
            continue;
        }

        let name_idx   = header.iter().position(|h| h.to_lowercase().contains("taskname"));
        let action_idx = header.iter().position(|h| h.to_lowercase().contains("task to run"));

        if let Some(ni) = name_idx {
            if let Some(n) = fields.get(ni) {
                if !n.is_empty() { last_task_name = n.clone(); }
            }
        }

        if let Some(ai) = action_idx {
            let action = fields.get(ai).cloned().unwrap_or_default();
            if !action.is_empty() && action.to_lowercase() != "n/a" && !last_task_name.is_empty() {
                result.push((last_task_name.clone(), action));
            }
        }
    }

    Ok(result)
}

/// Minimal CSV field parser that respects double-quoted fields.
///
/// Does not handle escaped quotes inside fields — sufficient for `schtasks`
/// output which uses simple quoting.
fn split_csv_line(line: &str) -> Vec<String> {
    let mut fields   = Vec::new();
    let mut current  = String::new();
    let mut in_quotes = false;

    for ch in line.chars() {
        match ch {
            '"'           => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                fields.push(current.trim().to_string());
                current.clear();
            }
            c => current.push(c),
        }
    }
    fields.push(current.trim().to_string());
    fields
}

// ─── 5. Host Network Isolation ───────────────────────────────────────────────

/// Returned by [`isolate_network`].
pub struct IsolationResult {
    pub success:             bool,
    /// Names of network adapters that were successfully disabled.
    pub disabled_interfaces: Vec<String>,
    pub error:               Option<String>,
}

/// Disable all currently-connected network interfaces.
///
/// Steps:
/// 1. Run `netsh interface show interface` and parse connected adapter names.
/// 2. For each: `netsh interface set interface "{name}" admin=disable`.
/// 3. Save the disabled-interface list to
///    `%PROGRAMDATA%\AegisAI\isolated_interfaces.json` for rollback.
///
/// **Requires administrator privileges.**  The daemon already runs elevated
/// for memory scanning.
///
/// **Recovery:** call [`restore_network`] to re-enable the saved adapters.
pub fn isolate_network() -> IsolationResult {
    // ── Step 1: enumerate connected adapters ──────────────────────────────────
    let output = match Command::new("netsh")
        .args(["interface", "show", "interface"])
        .output()
    {
        Ok(o)  => o,
        Err(e) => return IsolationResult {
            success:             false,
            disabled_interfaces: vec![],
            error:               Some(format!("Cannot run netsh: {e}")),
        },
    };

    let stdout    = String::from_utf8_lossy(&output.stdout);
    let mut connected: Vec<String> = Vec::new();

    // Header: "Admin State    State          Type             Interface Name"
    // Data:   "Enabled        Connected      Dedicated        Wi-Fi"
    // The interface name occupies all words at index 3+ (may contain spaces).
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 4 && parts[1].eq_ignore_ascii_case("connected") {
            connected.push(parts[3..].join(" "));
        }
    }

    if connected.is_empty() {
        return IsolationResult {
            success:             true,
            disabled_interfaces: vec![],
            error:               Some("No connected interfaces found".to_string()),
        };
    }

    // ── Step 2: disable each adapter ─────────────────────────────────────────
    let mut disabled: Vec<String> = Vec::new();
    let mut last_err: Option<String> = None;

    for name in &connected {
        match Command::new("netsh")
            .args(["interface", "set", "interface", name, "admin=disable"])
            .status()
        {
            Ok(s) if s.success() => disabled.push(name.clone()),
            Ok(s) => last_err = Some(format!("Disable '{name}' failed: exit {:?}", s.code())),
            Err(e) => last_err = Some(format!("Disable '{name}' error: {e}")),
        }
    }

    // ── Step 3: persist the list for restore ─────────────────────────────────
    let save_path = aegisai_data_dir().join("isolated_interfaces.json");
    let _ = ensure_dir(&aegisai_data_dir());
    let _ = fs::write(
        &save_path,
        serde_json::to_string_pretty(&disabled).unwrap_or_default(),
    );

    IsolationResult {
        success:             !disabled.is_empty(),
        disabled_interfaces: disabled,
        error:               last_err,
    }
}

/// Re-enable all network interfaces previously disabled by [`isolate_network`].
///
/// Reads `%PROGRAMDATA%\AegisAI\isolated_interfaces.json` and runs
/// `netsh interface set interface "{name}" admin=enable` for each entry.
/// The JSON file is removed after restore regardless of individual outcomes.
pub fn restore_network() -> Result<(), String> {
    let save_path = aegisai_data_dir().join("isolated_interfaces.json");

    let json = fs::read_to_string(&save_path)
        .map_err(|_| "No isolated_interfaces.json found — nothing to restore".to_string())?;

    let interfaces: Vec<String> = serde_json::from_str(&json)
        .map_err(|e| format!("Cannot parse isolated_interfaces.json: {e}"))?;

    let mut errors: Vec<String> = Vec::new();

    for name in &interfaces {
        match Command::new("netsh")
            .args(["interface", "set", "interface", name, "admin=enable"])
            .status()
        {
            Ok(s) if s.success() => {}
            Ok(s) => errors.push(format!("Enable '{name}' failed: exit {:?}", s.code())),
            Err(e) => errors.push(format!("Enable '{name}' error: {e}")),
        }
    }

    // Clean up saved state whether or not all enables succeeded.
    let _ = fs::remove_file(&save_path);

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

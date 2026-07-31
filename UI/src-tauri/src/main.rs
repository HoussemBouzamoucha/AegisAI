// File: UI/src-tauri/src/main.rs
// Tauri backend — spawns the antivirus engine once as a daemon.
// YARA rules compile once at startup — no per-scan delay.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod agent;

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::time::Duration;
use serde::{Deserialize, Serialize};
use tauri::Manager;

// ─── Types ────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub struct DetectionSignal {
    pub source:      String,
    pub description: String,
    pub score:       i32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub struct ScanResult {
    pub path:              String,
    pub level:             String,
    pub reason:            String,
    pub hash:              Option<String>,
    pub signature:         Option<String>,
    pub is_threat:         bool,
    pub confidence_score:  f32,
    pub detection_signals: Vec<DetectionSignal>,
    pub file_category:     String,
    pub context_flags:     Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ScanStats {
    pub total_files:      u64,
    pub clean_files:      u64,
    pub suspicious_files: u64,
    pub malicious_files:  u64,
    pub error_files:      u64,
    pub total_size_mb:    f64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ScanOutput {
    pub success:    bool,
    pub files:      Vec<ScanResult>,
    pub statistics: ScanStats,
    pub error:      Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ProcessStats {
    pub total_processes:      u64,
    pub safe_processes:       u64,
    pub suspicious_processes: u64,
    pub malicious_processes:  u64,
    pub critical_processes:   u64,
    pub total_memory_mb:      String,
    pub total_threads:        u64,
    pub avg_cpu_usage:        String,
    pub scan_duration_ms:     u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ProcessScanOutput {
    pub success:    bool,
    pub processes:  Vec<serde_json::Value>,
    pub statistics: ProcessStats,
    pub error:      Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct NetworkStats {
    pub total_connections:       u64,
    pub suspicious_connections:  u64,
    pub malicious_connections:   u64,
    pub local_listeners:         u64,
    pub established_connections: u64,
    pub scan_duration_ms:        u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct NetworkScanOutput {
    pub success:     bool,
    pub statistics:  NetworkStats,
    pub connections: Vec<serde_json::Value>,
    pub error:       Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MemoryRegion {
    pub pid:               u32,
    pub process_name:      String,
    pub process_path:      Option<String>,
    pub command_line:      Option<String>,
    pub region_start:      u64,
    pub region_size:       u64,
    pub protection:        String,
    pub is_executable:     bool,
    pub is_writable:       bool,
    pub is_readable:       bool,
    pub is_committed:      bool,
    pub is_private:        bool,
    pub content_sample:    Option<String>,
    pub threat_level:      String,
    pub threat_score:      i32,
    pub is_threat:         bool,
    pub detection_signals: Vec<DetectionSignal>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MemoryStats {
    pub total_regions:       u64,
    pub scanned_processes:   u64,
    pub suspicious_regions:  u64,
    pub malicious_regions:   u64,
    pub total_bytes_scanned: u64,
    pub scan_duration_ms:    u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MemoryScanOutput {
    pub success:    bool,
    pub statistics: MemoryStats,
    pub regions:    Vec<MemoryRegion>,
    pub error:      Option<String>,
}

// ─── Daemon state ─────────────────────────────────────────────────────────────

struct Daemon {
    stdin: ChildStdin,
}

struct AppState {
    daemon:           Mutex<Option<Daemon>>,
    child:            Mutex<Child>,
    response_rx:      Mutex<std::sync::mpsc::Receiver<String>>,
    // Prevents concurrent memory scans from stacking up and compounding
    // the RAM spike. Only one memory scan may be in-flight at a time.
    memory_scan_lock: AtomicBool,
}

static REQUEST_ID: AtomicU64 = AtomicU64::new(1);
fn next_id() -> String { REQUEST_ID.fetch_add(1, Ordering::SeqCst).to_string() }

// ─── Engine paths ─────────────────────────────────────────────────────────────

fn get_engine_path() -> PathBuf {
    PathBuf::from(
        r"C:\Users\houss\Desktop\AegisAI\Antivirus_Engine\target\x86_64-pc-windows-msvc\release\antivirus.exe"
    )
}

fn get_engine_dir() -> PathBuf {
    PathBuf::from(r"C:\Users\houss\Desktop\AegisAI\Antivirus_Engine")
}

// ─── Spawn daemon ─────────────────────────────────────────────────────────────

fn spawn_daemon() -> Result<AppState, String> {
    let engine     = get_engine_path();
    let engine_dir = get_engine_dir();

    let mut child = Command::new(&engine)
        .arg("daemon")
        .current_dir(&engine_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("Failed to spawn engine daemon: {}", e))?;

    let stdin  = child.stdin.take().ok_or("Could not get daemon stdin")?;
    let stdout = child.stdout.take().ok_or("Could not get daemon stdout")?;

    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<BufReader<std::process::ChildStdout>, String>>();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut ready_line = String::new();
        match reader.read_line(&mut ready_line) {
            Ok(0)  => { ready_tx.send(Err("Daemon exited before ready".to_string())).ok(); }
            Ok(_)  => { ready_tx.send(Ok(reader)).ok(); }
            Err(e) => { ready_tx.send(Err(format!("Ready read error: {}", e))).ok(); }
        }
    });

    let reader = match ready_rx.recv_timeout(Duration::from_secs(60)) {
        Ok(Ok(r))  => { eprintln!("DAEMON: ready signal received"); r }
        Ok(Err(e)) => return Err(e),
        Err(_)     => return Err("Daemon startup timed out after 60s".to_string()),
    };

    let (tx, rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        for line in reader.lines() {
            match line {
                Ok(l)  => { if tx.send(l).is_err() { break; } }
                Err(_) => break,
            }
        }
        eprintln!("DAEMON: stdout reader thread exited");
    });

    Ok(AppState {
        daemon:           Mutex::new(Some(Daemon { stdin })),
        child:            Mutex::new(child),
        response_rx:      Mutex::new(rx),
        memory_scan_lock: AtomicBool::new(false),
    })
}

// ─── Send request / read matching response ────────────────────────────────────

fn daemon_request(
    state: &AppState,
    request: serde_json::Value,
    timeout: Duration,
) -> Result<serde_json::Value, String> {
    let id = request["id"].as_str().unwrap_or("0").to_string();

    {
        let mut child = state.child.lock().unwrap();
        match child.try_wait() {
            Ok(Some(status)) => return Err(format!("Daemon process has exited with status: {}", status)),
            Err(e)           => return Err(format!("Could not check daemon status: {}", e)),
            Ok(None)         => {}
        }
    }

    {
        let mut lock = state.daemon.lock().unwrap();
        let daemon = lock.as_mut().ok_or("Daemon not initialized")?;
        let mut line = request.to_string();
        line.push('\n');
        daemon.stdin.write_all(line.as_bytes())
            .map_err(|e| format!("Failed to write to daemon stdin: {}", e))?;
        daemon.stdin.flush()
            .map_err(|e| format!("Failed to flush daemon stdin: {}", e))?;
    }

    let rx = state.response_rx.lock().unwrap();
    let deadline = std::time::Instant::now() + timeout;

    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err(format!("Daemon response timeout for id={}", id));
        }
        let line = match rx.recv_timeout(remaining) {
            Ok(l) => l,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) =>
                return Err(format!("Daemon response timeout for id={} (scan still running after {}s — try again or restart the app)", id, timeout.as_secs())),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) =>
                return Err(format!("Daemon process died while handling id={} — check engine stderr for crash details", id)),
        };

        let json: serde_json::Value = serde_json::from_str(&line)
            .map_err(|e| format!("Invalid JSON from daemon: {} — raw: {}", e, &line[..line.len().min(200)]))?;

        match json["id"].as_str() {
            Some(resp_id) if resp_id == id => return Ok(json),
            Some(other) => { eprintln!("WARN: skipping response id={}", other); continue; }
            None        => return Ok(json),
        }
    }
}

// ─── Helper: parse ScanResult from daemon JSON ────────────────────────────────

fn parse_scan_result(f: &serde_json::Value, fallback_path: &str) -> ScanResult {
    let level     = f["level"].as_str().unwrap_or("Clean").to_string();
    let is_threat = f["is_threat"].as_bool()
        .unwrap_or(level == "Suspicious" || level == "Malicious");

    let detection_signals = f["detection_signals"].as_array()
        .map(|arr| arr.iter().map(|s| DetectionSignal {
            source:      s["source"].as_str().unwrap_or("").to_string(),
            description: s["description"].as_str().unwrap_or("").to_string(),
            score:       s["score"].as_i64().unwrap_or(0) as i32,
        }).collect())
        .unwrap_or_default();

    let context_flags = f["context_flags"].as_array()
        .map(|arr| arr.iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect())
        .unwrap_or_default();

    ScanResult {
        path:             f["path"].as_str().unwrap_or(fallback_path).to_string(),
        level,
        reason:           f["reason"].as_str().unwrap_or("").to_string(),
        hash:             f["hash"].as_str().map(String::from),
        signature:        f["signature"].as_str().map(String::from),
        is_threat,
        confidence_score: f["confidence_score"].as_f64()
            .unwrap_or(if is_threat { 0.6 } else { 1.0 }) as f32,
        detection_signals,
        context_flags,
        file_category:    f["file_category"].as_str().unwrap_or("unknown").to_string(),
    }
}

// ─── Tauri Commands ───────────────────────────────────────────────────────────

#[tauri::command]
async fn scan_file(
    path: String,
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<ScanOutput, String> {
    let request = serde_json::json!({
        "id": next_id(), "cmd": "scan-file", "path": path,
    });
    let json = daemon_request(&state, request, Duration::from_secs(60))?;
    if let Some(err) = json["error"].as_str() { return Err(err.to_string()); }

    let file  = parse_scan_result(&json, &path);
    let level = file.level.clone();
    let stats = ScanStats {
        total_files:      1,
        clean_files:      if level == "Clean"      { 1 } else { 0 },
        suspicious_files: if level == "Suspicious" { 1 } else { 0 },
        malicious_files:  if level == "Malicious"  { 1 } else { 0 },
        error_files:      if level == "Error"      { 1 } else { 0 },
        total_size_mb:    0.0,
    };
    Ok(ScanOutput { success: true, files: vec![file], statistics: stats, error: None })
}

/// Run the GRU-Attention process model on a batch of suspicious process entries.
///
/// Each entry must have `pid` (u32) and `exe_path` (string).
/// The daemon parses the PE import table of each exe, filters it to the GRU
/// vocabulary, and runs the GRU-Attention model via `process_bridge.py`.
/// Returns a JSON array of one result per input entry.
#[tauri::command]
async fn apply_process_gru(
    entries: Vec<serde_json::Value>,
    state:   tauri::State<'_, Arc<AppState>>,
) -> Result<serde_json::Value, String> {
    let request = serde_json::json!({
        "id": next_id(), "cmd": "apply-process-gru", "entries": entries,
    });
    // PyTorch cold-start (~15 s) + 2 s/exe × N + margin; floor 60 s.
    let n = entries.len() as u64;
    let timeout_secs = (30u64 + n * 5).max(60);
    let json = daemon_request(&state, request, Duration::from_secs(timeout_secs))?;
    if let Some(err) = json["error"].as_str() { return Err(err.to_string()); }
    Ok(json["results"].clone())
}

/// Run Ember2024 ML on a batch of paths in one Python subprocess.
/// Returns a JSON array of `{ path, skipped, file_type, score, malicious }` entries
/// (one per input path, in order).  Bypasses the YARA/heuristics score gate so
/// that context-escalated Suspicious files are always analysed.
#[tauri::command]
async fn apply_ember_ml(
    paths: Vec<String>,
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<serde_json::Value, String> {
    let request = serde_json::json!({
        "id": next_id(), "cmd": "apply-ember-ml", "paths": paths,
    });
    // Dynamic timeout: 180 s warmup (Python start + 5-model LightGBM load on slow machines)
    // + 30 s per file (generous ceiling for large-file PE feature extraction).
    // Hard floor of 300 s so single-file calls are never penalised.
    // This prevents the Tauri-side timeout from firing before the daemon finishes
    // when there are many suspicious files or model loading is slow.
    let timeout_secs = (180u64 + paths.len() as u64 * 30).max(300);
    let json = daemon_request(&state, request, Duration::from_secs(timeout_secs))?;
    if let Some(err) = json["error"].as_str() { return Err(err.to_string()); }
    Ok(json["results"].clone())
}

#[tauri::command]
async fn scan_directory(
    path: String,
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<ScanOutput, String> {
    let request = serde_json::json!({
        "id": next_id(), "cmd": "scan-dir", "path": path,
    });
    let json = daemon_request(&state, request, Duration::from_secs(120))?;
    if let Some(err) = json["error"].as_str() { return Err(err.to_string()); }

    let files_arr = json["files"].as_array()
        .ok_or("No files array in daemon response")?;
    let files: Vec<ScanResult> = files_arr.iter()
        .map(|f| parse_scan_result(f, ""))
        .collect();

    let s = &json["statistics"];
    let stats = ScanStats {
        total_files:      s["total_files"].as_u64().unwrap_or(0),
        clean_files:      s["clean_files"].as_u64().unwrap_or(0),
        suspicious_files: s["suspicious_files"].as_u64().unwrap_or(0),
        malicious_files:  s["malicious_files"].as_u64().unwrap_or(0),
        error_files:      s["error_files"].as_u64().unwrap_or(0),
        total_size_mb:    s["total_size_mb"].as_f64().unwrap_or(0.0),
    };
    Ok(ScanOutput { success: true, files, statistics: stats, error: None })
}

#[tauri::command]
async fn scan_processes(
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<ProcessScanOutput, String> {
    let request = serde_json::json!({
        "id": next_id(), "cmd": "scan-processes",
    });
    let json = daemon_request(&state, request, Duration::from_secs(60))?;
    if let Some(err) = json["error"].as_str() { return Err(err.to_string()); }

    let processes = json["processes"].as_array()
        .cloned()
        .unwrap_or_default();

    let s = &json["statistics"];
    let stats = ProcessStats {
        total_processes:      s["total_processes"].as_u64().unwrap_or(0),
        safe_processes:       s["safe_processes"].as_u64().unwrap_or(0),
        suspicious_processes: s["suspicious_processes"].as_u64().unwrap_or(0),
        malicious_processes:  s["malicious_processes"].as_u64().unwrap_or(0),
        critical_processes:   s["critical_processes"].as_u64().unwrap_or(0),
        total_memory_mb:      s["total_memory_mb"].as_str().unwrap_or("0.00").to_string(),
        total_threads:        s["total_threads"].as_u64().unwrap_or(0),
        avg_cpu_usage:        s["avg_cpu_usage"].as_str().unwrap_or("0.00").to_string(),
        scan_duration_ms:     s["scan_duration_ms"].as_u64().unwrap_or(0),
    };
    Ok(ProcessScanOutput { success: true, processes, statistics: stats, error: None })
}

#[tauri::command]
async fn scan_network(
    pid: Option<u32>,
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<NetworkScanOutput, String> {
    let mut request = serde_json::Map::new();
    request.insert("id".to_string(),  serde_json::json!(next_id()));
    request.insert("cmd".to_string(), serde_json::json!("scan-network"));
    if let Some(pid) = pid {
        request.insert("pid".to_string(), serde_json::json!(pid));
    }

    let json = daemon_request(&state, serde_json::Value::Object(request), Duration::from_secs(30))?;
    if let Some(err) = json["error"].as_str() { return Err(err.to_string()); }

    let connections = json["connections"].as_array()
        .cloned()
        .unwrap_or_default();

    let s = &json["statistics"];
    let stats = NetworkStats {
        total_connections:       s["total_connections"].as_u64().unwrap_or(0),
        suspicious_connections:  s["suspicious_connections"].as_u64().unwrap_or(0),
        malicious_connections:   s["malicious_connections"].as_u64().unwrap_or(0),
        local_listeners:         s["local_listeners"].as_u64().unwrap_or(0),
        established_connections: s["established_connections"].as_u64().unwrap_or(0),
        scan_duration_ms:        s["scan_duration_ms"].as_u64().unwrap_or(0),
    };

    Ok(NetworkScanOutput { success: true, statistics: stats, connections, error: None })
}

#[tauri::command]
async fn scan_memory(
    pid: Option<u32>,
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<serde_json::Value, String> {
    // Reject concurrent memory scan requests immediately rather than
    // letting them queue up and compound the RSS spike.
    if state.memory_scan_lock.compare_exchange(
        false, true, Ordering::SeqCst, Ordering::SeqCst
    ).is_err() {
        return Err("A memory scan is already in progress. Please wait.".to_string());
    }

    let mut request = serde_json::Map::new();
    request.insert("id".to_string(),  serde_json::json!(next_id()));
    request.insert("cmd".to_string(), serde_json::json!("scan-memory"));
    if let Some(pid) = pid {
        request.insert("pid".to_string(), serde_json::json!(pid));
    }

    let result = daemon_request(
        &state,
        serde_json::Value::Object(request),
        Duration::from_secs(120),
    );

    // Always release the lock, even if the scan failed.
    state.memory_scan_lock.store(false, Ordering::SeqCst);

    let json = result?;
    if let Some(err) = json["error"].as_str() {
        return Err(err.to_string());
    }
    Ok(json)
}

#[tauri::command]
async fn kill_process(
    pid: u32,
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<serde_json::Value, String> {
    let request = serde_json::json!({
        "id": next_id(), "cmd": "kill-process", "pid": pid,
    });
    let json = daemon_request(&state, request, Duration::from_secs(10))?;
    if let Some(err) = json["error"].as_str() { return Err(err.to_string()); }
    Ok(json)
}

#[tauri::command]
async fn open_file_dialog(app: tauri::AppHandle) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;
    Ok(app.dialog().file().set_title("Select File to Scan")
        .blocking_pick_file().map(|p| p.to_string()))
}

#[tauri::command]
async fn open_dir_dialog(app: tauri::AppHandle) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;
    Ok(app.dialog().file().set_title("Select Directory to Scan")
        .blocking_pick_folder().map(|p| p.to_string()))
}

#[tauri::command]
async fn check_engine() -> bool {
    get_engine_path().exists()
}

#[tauri::command]
async fn run_ml_ids(csv_path: Option<String>) -> Result<serde_json::Value, String> {
    let script = PathBuf::from(
        r"C:\Users\houss\Desktop\AegisAI\Antivirus_Engine\src\core\network\Feature_extractor\ML_IDS\preprocessing_pipeline.py"
    );

    if !script.exists() {
        return Err(format!("ML script not found at: {}", script.display()));
    }

    let csv = csv_path.unwrap_or_else(|| {
        let home = std::env::var("USERPROFILE").unwrap_or_else(|_| "C:\\Users\\Public".to_string());
        format!("{}\\OnePace.csv", home)
    });

    // Try common Python executable names
    for py in &["python", "python3", "py"] {
        match std::process::Command::new(py)
            .args([
                script.to_str().unwrap_or(""),
                "--infer",
                "--csv", &csv,
            ])
            .output()
        {
            Ok(output) => {
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    let trimmed = stdout.trim();
                    return serde_json::from_str(trimmed)
                        .map_err(|e| format!("Invalid JSON from ML script: {} — raw: {}", e, &trimmed[..trimmed.len().min(300)]));
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    // If the script printed a JSON error to stdout, return that
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(stdout.trim()) {
                        return Ok(v);
                    }
                    return Err(format!("ML script error: {}", stderr.trim()));
                }
            }
            Err(_) => continue, // try next interpreter name
        }
    }

    Err("Python interpreter not found. Ensure Python 3 is installed and available in PATH.".to_string())
}

// ─── Action Commands ──────────────────────────────────────────────────────────
//
// Each command forwards its arguments to the daemon via JSON-RPC and returns
// the daemon's response verbatim.  No logic lives here — the daemon owns all
// containment logic so it can be tested independently of Tauri.

/// Move a file into the AegisAI quarantine folder.
///
/// The daemon hashes the file, renames it to `{sha256}.quarantined`, and
/// writes a metadata sidecar.  Returns `{ quarantine_path, sha256 }` on
/// success.
#[tauri::command]
async fn quarantine_file(
    path:  String,
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<serde_json::Value, String> {
    let request = serde_json::json!({
        "id": next_id(), "cmd": "quarantine-file", "path": path,
    });
    let json = daemon_request(&state, request, Duration::from_secs(30))?;
    if let Some(err) = json["error"].as_str() { return Err(err.to_string()); }
    Ok(json)
}

/// Add a Windows Firewall deny rule for `remote_ip`.
///
/// `direction` — `"out"` (default) or `"both"`.
/// Returns `{ rule_name }` on success; save the rule name to call
/// `remove_block_ip` for rollback.
#[tauri::command]
async fn block_ip(
    remote_ip: String,
    direction: Option<String>,
    state:     tauri::State<'_, Arc<AppState>>,
) -> Result<serde_json::Value, String> {
    let request = serde_json::json!({
        "id":        next_id(),
        "cmd":       "block-ip",
        "remote_ip": remote_ip,
        "direction": direction.unwrap_or_else(|| "out".to_string()),
    });
    let json = daemon_request(&state, request, Duration::from_secs(15))?;
    if let Some(err) = json["error"].as_str() { return Err(err.to_string()); }
    Ok(json)
}

/// Remove a previously created AegisAI firewall rule by name.
#[tauri::command]
async fn remove_block_ip(
    rule_name: String,
    state:     tauri::State<'_, Arc<AppState>>,
) -> Result<serde_json::Value, String> {
    let request = serde_json::json!({
        "id": next_id(), "cmd": "remove-block-ip", "rule_name": rule_name,
    });
    let json = daemon_request(&state, request, Duration::from_secs(15))?;
    if let Some(err) = json["error"].as_str() { return Err(err.to_string()); }
    Ok(json)
}

/// Write a full memory dump (`MiniDumpWithFullMemory`) of `pid` to disk.
///
/// The dump is saved to `%PROGRAMDATA%\AegisAI\dumps\{pid}_{ts}.dmp`.
/// Returns `{ dump_path }` on success.
#[tauri::command]
async fn dump_memory(
    pid:   u32,
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<serde_json::Value, String> {
    let request = serde_json::json!({
        "id": next_id(), "cmd": "dump-memory", "pid": pid,
    });
    // Dumping a large process can take several seconds.
    let json = daemon_request(&state, request, Duration::from_secs(120))?;
    if let Some(err) = json["error"].as_str() { return Err(err.to_string()); }
    Ok(json)
}

/// Scan registry run keys, scheduled tasks, and startup folders.
///
/// `suspicious_paths` — paths from the current verdict to cross-reference.
/// Matching entries are flagged `suspicious: true` in the response.
#[tauri::command]
async fn check_persistence(
    suspicious_paths: Option<Vec<String>>,
    state:            tauri::State<'_, Arc<AppState>>,
) -> Result<serde_json::Value, String> {
    let request = serde_json::json!({
        "id":              next_id(),
        "cmd":             "check-persistence",
        "suspicious_paths": suspicious_paths.unwrap_or_default(),
    });
    let json = daemon_request(&state, request, Duration::from_secs(60))?;
    if let Some(err) = json["error"].as_str() { return Err(err.to_string()); }
    Ok(json)
}

/// Disable all connected network interfaces to cut off C2 communications.
///
/// Returns `{ disabled_interfaces: [...] }`.
/// Call `restore_network` once the incident is resolved.
#[tauri::command]
async fn isolate_network(
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<serde_json::Value, String> {
    let request = serde_json::json!({
        "id": next_id(), "cmd": "isolate-network",
    });
    let json = daemon_request(&state, request, Duration::from_secs(30))?;
    if let Some(err) = json["error"].as_str() { return Err(err.to_string()); }
    Ok(json)
}

/// Re-enable all network interfaces that were disabled by `isolate_network`.
#[tauri::command]
async fn restore_network(
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<serde_json::Value, String> {
    let request = serde_json::json!({
        "id": next_id(), "cmd": "restore-network",
    });
    let json = daemon_request(&state, request, Duration::from_secs(30))?;
    if let Some(err) = json["error"].as_str() { return Err(err.to_string()); }
    Ok(json)
}

/// Round 1 agent analysis — take a correlate result and return a ranked action plan.
///
/// `correlate_result` is the full JSON object returned by `correlate_entities`.
/// This command is intentionally separate from `correlate_entities` so that:
///   (a) The detection pipeline is never delayed by an LLM call.
///   (b) The analyst decides when to invoke AI reasoning (not automatic).
///   (c) Round 2+ can re-call via `run_agent_reassessment` with an updated graph.
#[tauri::command]
async fn run_agent_analysis(
    correlate_result: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let verdict = agent::run_analysis(&correlate_result).await?;
    serde_json::to_value(&verdict)
        .map_err(|e| format!("Serialization error: {e}"))
}

/// Round 2+ agent re-assessment — called after the user executes an action
/// and the daemon has re-correlated to produce an updated threat graph.
///
/// Arguments:
///   `correlate_result`      — fresh correlate result from the daemon
///   `actions_taken`         — array of ExecutedAction objects (all actions so far)
///   `round`                 — current round number (2, 3, …)
///   `previous_threat_score` — sum of combined_score over Malicious/Critical
///                             entities from the *previous* round (for monotonicity)
///
/// Returns an `AgentVerdict`.  When `investigation_closed` is true the UI
/// should stop calling this command and surface the `close_reason`.
#[tauri::command]
async fn run_agent_reassessment(
    correlate_result:      serde_json::Value,
    actions_taken:         Vec<serde_json::Value>,
    round:                 u32,
    previous_threat_score: f64,
) -> Result<serde_json::Value, String> {
    let verdict = agent::run_reassessment(
        &correlate_result,
        &actions_taken,
        round,
        previous_threat_score,
    ).await?;
    serde_json::to_value(&verdict)
        .map_err(|e| format!("Serialization error: {e}"))
}

/// Export a structured incident report to disk.
///
/// `correlate_result` — the full JSON object returned by the last
/// `correlate_entities` call (attack chains, critical path, graph snapshot).
/// `actions_taken`    — list of `{ action, pid?, path?, rule_name?, at, result }`
///                      objects logged by the UI during response.
/// `output_path`      — optional absolute path; defaults to
///                      `%USERPROFILE%\Documents\AegisAI\incident_{ts}.json`.
///
/// Returns `{ report_path }` on success.
///
/// Note: this command runs entirely in the Tauri backend — no daemon call
/// needed because the data is already present in the UI's Zustand store.
#[tauri::command]
async fn export_incident_report(
    correlate_result: serde_json::Value,
    actions_taken:    Vec<serde_json::Value>,
    output_path:      Option<String>,
) -> Result<serde_json::Value, String> {
    use std::fs;
    use std::path::PathBuf;

    // Determine output file path.
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let report_path: PathBuf = match output_path {
        Some(p) => PathBuf::from(p),
        None => {
            let docs = std::env::var("USERPROFILE")
                .map(|u| PathBuf::from(u).join("Documents").join("AegisAI"))
                .unwrap_or_else(|_| PathBuf::from("C:\\AegisAI"));
            fs::create_dir_all(&docs)
                .map_err(|e| format!("Cannot create report directory: {e}"))?;
            docs.join(format!("incident_{ts}.json"))
        }
    };

    // Derive severity from the highest attack chain in the correlate result.
    let severity = correlate_result["graph"]["attack_chains"]
        .as_array()
        .and_then(|chains| chains.first())
        .and_then(|c| c["severity"].as_str())
        .unwrap_or("Unknown");

    // Build the structured report.
    let report = serde_json::json!({
        "report_id":      uuid_v4_simple(),
        "generated_at":   ts,
        "severity":       severity,
        "attack_chains":  correlate_result["graph"]["attack_chains"],
        "critical_path":  correlate_result["graph"]["critical_path"],
        "entities":       correlate_result["entities"],
        "actions_taken":  actions_taken,
        "graph_snapshot": {
            "nodes": correlate_result["graph"]["nodes"],
            "edges": correlate_result["graph"]["edges"],
        },
        "statistics":     correlate_result["statistics"],
    });

    let json_str = serde_json::to_string_pretty(&report)
        .map_err(|e| format!("Serialization error: {e}"))?;

    fs::write(&report_path, &json_str)
        .map_err(|e| format!("Cannot write report: {e}"))?;

    Ok(serde_json::json!({
        "success":     true,
        "report_path": report_path.to_string_lossy(),
    }))
}

/// List all entries in the AegisAI quarantine directory.
///
/// Returns an array of metadata objects read from `*.meta.json` sidecars.
/// Each entry includes `original_path`, `sha256`, `quarantined_at`, `reason`,
/// `quarantine_path`, and `quarantine_file_exists`.
/// Returns an empty array if the quarantine directory does not exist yet.
#[tauri::command]
async fn list_quarantine() -> Result<serde_json::Value, String> {
    use std::fs;
    use std::path::PathBuf;

    let quarantine_dir: PathBuf = {
        let base = std::env::var("PROGRAMDATA")
            .or_else(|_| std::env::var("TEMP"))
            .unwrap_or_else(|_| "C:\\Temp".to_string());
        PathBuf::from(base).join("AegisAI").join("quarantine")
    };

    if !quarantine_dir.exists() {
        return Ok(serde_json::json!([]));
    }

    let mut entries: Vec<serde_json::Value> = Vec::new();

    let read_dir = fs::read_dir(&quarantine_dir)
        .map_err(|e| format!("Cannot read quarantine directory: {e}"))?;

    for entry in read_dir.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let Ok(text) = fs::read_to_string(&path) else { continue };
        let Ok(mut meta) = serde_json::from_str::<serde_json::Value>(&text) else { continue };

        // Attach the quarantine file path and existence flag
        if let Some(sha256) = meta["sha256"].as_str() {
            let q_path = quarantine_dir.join(format!("{sha256}.quarantined"));
            meta["quarantine_path"] = serde_json::Value::String(
                q_path.to_string_lossy().to_string(),
            );
            meta["quarantine_file_exists"] = serde_json::Value::Bool(q_path.exists());
        }
        entries.push(meta);
    }

    // Newest first
    entries.sort_by(|a, b| {
        let ta = a["quarantined_at"].as_u64().unwrap_or(0);
        let tb = b["quarantined_at"].as_u64().unwrap_or(0);
        tb.cmp(&ta)
    });

    Ok(serde_json::json!(entries))
}

/// Restore a quarantined file to its original path.
///
/// `sha256` — hash of the file to restore (locates `{sha256}.quarantined`).
/// Reads `original_path` from the `.meta.json` sidecar.
/// Removes both the `.quarantined` file and the `.meta.json` on success.
/// Returns `{ success, restored_path }`.
#[tauri::command]
async fn restore_quarantine_file(sha256: String) -> Result<serde_json::Value, String> {
    use std::fs;
    use std::path::PathBuf;

    let quarantine_dir: PathBuf = {
        let base = std::env::var("PROGRAMDATA")
            .or_else(|_| std::env::var("TEMP"))
            .unwrap_or_else(|_| "C:\\Temp".to_string());
        PathBuf::from(base).join("AegisAI").join("quarantine")
    };

    let q_file    = quarantine_dir.join(format!("{sha256}.quarantined"));
    let meta_file = quarantine_dir.join(format!("{sha256}.meta.json"));

    if !q_file.exists() {
        return Err(format!("Quarantined file not found: {sha256}.quarantined"));
    }

    if !meta_file.exists() {
        return Err("Metadata file not found — cannot determine original path".to_string());
    }

    let text = fs::read_to_string(&meta_file)
        .map_err(|e| format!("Cannot read meta file: {e}"))?;
    let meta: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| format!("Cannot parse meta file: {e}"))?;
    let original_path = meta["original_path"]
        .as_str()
        .ok_or_else(|| "original_path missing from meta file".to_string())?
        .to_string();

    let dst = std::path::Path::new(&original_path);
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Cannot create restore directory: {e}"))?;
    }

    fs::rename(&q_file, dst)
        .or_else(|_| fs::copy(&q_file, dst).and(fs::remove_file(&q_file)))
        .map_err(|e| format!("Failed to restore file: {e}"))?;

    let _ = fs::remove_file(&meta_file);

    Ok(serde_json::json!({
        "success":       true,
        "restored_path": original_path,
    }))
}

/// Permanently delete a quarantined file.
///
/// Removes both the `{sha256}.quarantined` file and its `.meta.json` sidecar.
/// Use only when the file is confirmed malicious and must not be restored.
/// Returns `{ success }`.
#[tauri::command]
async fn delete_quarantine_file(sha256: String) -> Result<serde_json::Value, String> {
    use std::fs;
    use std::path::PathBuf;

    let quarantine_dir: PathBuf = {
        let base = std::env::var("PROGRAMDATA")
            .or_else(|_| std::env::var("TEMP"))
            .unwrap_or_else(|_| "C:\\Temp".to_string());
        PathBuf::from(base).join("AegisAI").join("quarantine")
    };

    let q_file    = quarantine_dir.join(format!("{sha256}.quarantined"));
    let meta_file = quarantine_dir.join(format!("{sha256}.meta.json"));

    if !q_file.exists() {
        return Err(format!("Quarantined file not found: {sha256}.quarantined"));
    }

    fs::remove_file(&q_file)
        .map_err(|e| format!("Failed to delete quarantined file: {e}"))?;
    let _ = fs::remove_file(&meta_file);

    Ok(serde_json::json!({ "success": true }))
}

/// Generate a simple UUID v4 without pulling in the `uuid` crate.
///
/// Uses `SystemTime` entropy seeded from the lower 128 bits of timestamp +
/// a counter.  Not cryptographically strong but sufficient for report IDs.
fn uuid_v4_simple() -> String {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    format!(
        "{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}",
        ts,
        (ts >> 16) & 0xffff,
        (ts >> 4)  & 0x0fff,
        ((ts >> 2) & 0x3fff) | 0x8000,
        ts as u64 * 0xdeadbeef,
    )
}

#[tauri::command]
async fn correlate_entities(
    include_memory: Option<bool>,
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<serde_json::Value, String> {
    let request = serde_json::json!({
        "id":             next_id(),
        "cmd":            "correlate",
        "include_memory": include_memory.unwrap_or(false),
    });
    // Process+network correlate can take 120-180 s on a loaded Windows system
    // (200+ processes × handle/module enumeration). Memory adds another ~120 s.
    let timeout = if include_memory.unwrap_or(false) {
        Duration::from_secs(480)  // 8 min with memory
    } else {
        Duration::from_secs(300)  // 5 min without memory
    };
    let json = daemon_request(&state, request, timeout)?;
    if let Some(err) = json["error"].as_str() {
        return Err(err.to_string());
    }
    Ok(json)
}

#[tauri::command]
async fn get_engine_status(
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<serde_json::Value, String> {
    let path  = get_engine_path();
    let alive = {
        let mut c = state.child.lock().unwrap();
        matches!(c.try_wait(), Ok(None))
    };
    Ok(serde_json::json!({
        "available":    path.exists(),
        "daemon_alive": alive,
        "path":         path.to_string_lossy(),
    }))
}

// ─── Steganography ML scan ────────────────────────────────────────────────────

/// Run the MIL steganography detector on a list of image paths.
///
/// Calls `steg_inference.py --paths <p1> <p2> ...` and returns a JSON array
/// of `{ path, stego_prob, is_stego, verdict, warning, error }` objects.
/// Supported formats: PNG (best), BMP, TIFF; JPEG works but accuracy is reduced.
#[tauri::command]
async fn scan_images_steg(paths: Vec<String>) -> Result<serde_json::Value, String> {
    if paths.is_empty() {
        return Ok(serde_json::json!([]));
    }

    let script = PathBuf::from(
        r"C:\Users\houss\Desktop\AegisAI\Antivirus_Engine\src\core\MIL_Steganography\steg_inference.py"
    );

    if !script.exists() {
        return Err(format!("Steg inference script not found: {}", script.display()));
    }

    // Dynamic timeout: 120 s model cold-start + 20 s per image, floor 180 s.
    let timeout_secs = (120u64 + paths.len() as u64 * 20).max(180);

    for py in &["python", "python3", "py"] {
        let mut cmd = std::process::Command::new(py);
        cmd.arg(script.to_str().unwrap_or(""))
           .arg("--paths");
        for p in &paths {
            cmd.arg(p);
        }

        match cmd.output() {
            Ok(output) if output.status.success() => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let trimmed = stdout.trim();
                return serde_json::from_str(trimmed)
                    .map_err(|e| format!("Invalid JSON from steg script: {} — raw: {}", e,
                                         &trimmed[..trimmed.len().min(300)]));
            }
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                let stdout = String::from_utf8_lossy(&output.stdout);
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(stdout.trim()) {
                    return Ok(v);
                }
                return Err(format!("Steg script error: {}", stderr.trim()));
            }
            Err(_) => continue,
        }
        let _ = timeout_secs; // suppress unused warning; timeout handled by OS process
    }

    Err("Python interpreter not found. Ensure Python 3 is installed and available in PATH.".to_string())
}

/// Open a file-picker dialog that accepts common image formats (multi-select).
#[tauri::command]
async fn open_images_dialog(app: tauri::AppHandle) -> Result<Option<Vec<String>>, String> {
    use tauri_plugin_dialog::DialogExt;
    let files = app.dialog()
        .file()
        .set_title("Select Images for Steganography Analysis")
        .add_filter("Images", &["png", "bmp", "tiff", "tif", "jpg", "jpeg", "webp"])
        .blocking_pick_files();
    Ok(files.map(|list| list.into_iter().map(|p| p.to_string()).collect()))
}

/// Embed random LSB payload (0.4 bpp) into a PNG using the same method as the
/// training data.  Creates a `_stego.png` copy next to the source file so the
/// original is never modified.  Returns `{ dst_path, pixels_modified, ... }`.
#[tauri::command]
async fn embed_steg_test(src_path: String) -> Result<serde_json::Value, String> {
    let script = PathBuf::from(
        r"C:\Users\houss\Desktop\AegisAI\Antivirus_Engine\src\core\MIL_Steganography\steg_inference.py"
    );
    if !script.exists() {
        return Err(format!("Steg script not found: {}", script.display()));
    }

    // Build dst path: same dir, same stem + "_stego.png"
    let src = std::path::Path::new(&src_path);
    let stem = src.file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("image");
    let dst_path = src.parent()
        .unwrap_or(std::path::Path::new("."))
        .join(format!("{}_stego.png", stem))
        .to_string_lossy()
        .to_string();

    for py in &["python", "python3", "py"] {
        match std::process::Command::new(py)
            .args([script.to_str().unwrap_or(""), "--embed", &src_path, &dst_path])
            .output()
        {
            Ok(output) if output.status.success() => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                return serde_json::from_str(stdout.trim())
                    .map_err(|e| format!("Invalid JSON from embed script: {}", e));
            }
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(format!("Embed script error: {}", stderr.trim()));
            }
            Err(_) => continue,
        }
    }
    Err("Python interpreter not found.".to_string())
}

// ─── Quick scan ───────────────────────────────────────────────────────────────

/// Quick scan — delegates to the daemon's `quick-scan` command, which uses
/// `SystemScanner::quick_roots()`: Downloads, Desktop, AppData Temp/Roaming,
/// ProgramData, Startup folder, System32\Tasks + drivers.
/// Typically completes in 1–5 minutes vs 30–120 min for a full scan.
#[tauri::command]
async fn quick_scan(
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<ScanOutput, String> {
    eprintln!("quick_scan: delegating to daemon quick-scan command");

    let request = serde_json::json!({ "id": next_id(), "cmd": "quick-scan" });

    let json = daemon_request(&state, request, Duration::from_secs(900))
        .map_err(|e| format!("quick-scan daemon error: {}", e))?;

    if let Some(err) = json["error"].as_str() {
        return Err(format!("quick-scan: {}", err));
    }

    let files: Vec<ScanResult> = json["files"]
        .as_array()
        .map(|arr| arr.iter().map(|f| parse_scan_result(f, "")).collect())
        .unwrap_or_default();

    let s = &json["statistics"];
    let statistics = ScanStats {
        total_files:      s["total_files"].as_u64().unwrap_or(0),
        clean_files:      s["clean_files"].as_u64().unwrap_or(0),
        suspicious_files: s["suspicious_files"].as_u64().unwrap_or(0),
        malicious_files:  s["malicious_files"].as_u64().unwrap_or(0),
        error_files:      s["error_files"].as_u64().unwrap_or(0),
        total_size_mb:    s["total_size_mb"].as_f64().unwrap_or(0.0),
    };

    Ok(ScanOutput { success: true, files, statistics, error: None })
}

// ─── Full system scan ─────────────────────────────────────────────────────────

/// Full-system scan delegated entirely to the daemon's `scan-all` command,
/// which runs [`SystemScanner`] internally (parallel thread pool + incremental
/// mtime cache + [`ScanPrioritizer`]).
///
/// A single long-running daemon request replaces the previous loop of four
/// sequential `scan-dir` requests, each of which timed out at 300 s on large
/// roots like `%USERPROFILE%` and `%SystemRoot%\System32`.
///
/// The daemon applies its own skip rules, size caps, and cache — no timeout
/// coordination or result merging is needed on the Tauri side.
#[tauri::command]
async fn scan_all(
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<ScanOutput, String> {
    eprintln!("scan_all: delegating to daemon scan-all command");

    let request = serde_json::json!({ "id": next_id(), "cmd": "scan-all" });

    // SystemScanner uses a thread pool and incremental cache so the wall-clock
    // time is a fraction of a serial walk.  30 minutes is a generous ceiling
    // that covers a cold (no-cache) first run over tens of thousands of files.
    let json = daemon_request(&state, request, Duration::from_secs(7200))
        .map_err(|e| format!("scan-all daemon error: {}", e))?;

    if let Some(err) = json["error"].as_str() {
        return Err(format!("scan-all: {}", err));
    }

    let files: Vec<ScanResult> = json["files"]
        .as_array()
        .map(|arr| arr.iter().map(|f| parse_scan_result(f, "")).collect())
        .unwrap_or_default();

    let s = &json["statistics"];
    let statistics = ScanStats {
        total_files:      s["total_files"].as_u64().unwrap_or(0),
        clean_files:      s["clean_files"].as_u64().unwrap_or(0),
        suspicious_files: s["suspicious_files"].as_u64().unwrap_or(0),
        malicious_files:  s["malicious_files"].as_u64().unwrap_or(0),
        error_files:      s["error_files"].as_u64().unwrap_or(0),
        total_size_mb:    s["total_size_mb"].as_f64().unwrap_or(0.0),
    };

    Ok(ScanOutput { success: true, files, statistics, error: None })
}

// ─── Main ─────────────────────────────────────────────────────────────────────

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            match spawn_daemon() {
                Ok(state) => {
                    app.manage(Arc::new(state));
                    eprintln!("Engine daemon started successfully");
                }
                Err(e) => {
                    eprintln!("FATAL: Failed to start engine daemon: {}", e);
                    std::process::exit(1);
                }
            }

            #[cfg(debug_assertions)]
            {
                let window = app.get_webview_window("main").unwrap();
                window.open_devtools();
            }

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            // ── AI agent ──────────────────────────────────────────────────
            run_agent_analysis,
            run_agent_reassessment,
            // ── Scanning ──────────────────────────────────────────────────
            scan_file,
            scan_directory,
            scan_all,
            quick_scan,
            apply_ember_ml,
            apply_process_gru,
            scan_processes,
            scan_network,
            scan_memory,
            // ── Process control ───────────────────────────────────────────
            kill_process,
            // ── File dialogs ──────────────────────────────────────────────
            open_file_dialog,
            open_dir_dialog,
            open_images_dialog,
            // ── Steganography ML ──────────────────────────────────────────
            scan_images_steg,
            embed_steg_test,
            // ── Engine status / ML ────────────────────────────────────────
            check_engine,
            get_engine_status,
            run_ml_ids,
            // ── Entity / graph pipeline ───────────────────────────────────
            correlate_entities,
            // ── Post-verdict containment actions ──────────────────────────
            quarantine_file,
            block_ip,
            remove_block_ip,
            dump_memory,
            check_persistence,
            isolate_network,
            restore_network,
            export_incident_report,
            // ── Quarantine management ─────────────────────────────────────
            list_quarantine,
            restore_quarantine_file,
            delete_quarantine_file,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
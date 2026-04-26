// File: UI/src-tauri/src/main.rs
// Tauri backend — spawns the antivirus engine once as a daemon.
// YARA rules compile once at startup — no per-scan delay.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

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
        let line = rx.recv_timeout(remaining)
            .map_err(|_| format!("Daemon response timeout for id={}", id))?;

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
            scan_file,
            scan_directory,
            scan_processes,
            scan_network,
            scan_memory,
            kill_process,
            open_file_dialog,
            open_dir_dialog,
            check_engine,
            get_engine_status,
            run_ml_ids,
            correlate_entities,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
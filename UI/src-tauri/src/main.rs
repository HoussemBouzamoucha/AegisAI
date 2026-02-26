// File: UI/src-tauri/src/main.rs
// Tauri backend — spawns the antivirus engine once as a daemon.
// YARA rules compile once at startup — no per-scan delay.
//
// Fixes applied:
//   1. Timeout on ready phase — Tauri won't freeze if daemon hangs
//   2. response_tx removed from Daemon struct — clean separation
//   3. Crash detection via child.try_wait() before each request
//   4. Request/response ID matching — safe for future concurrency

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use serde::{Deserialize, Serialize};
use tauri::Manager;

// ─── Types ────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub struct ScanResult {
    pub path: String,
    pub level: String,
    pub reason: String,
    pub hash: Option<String>,
    pub signature: Option<String>,
    pub is_threat: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ScanStats {
    pub total_files: u64,
    pub clean_files: u64,
    pub suspicious_files: u64,
    pub malicious_files: u64,
    pub error_files: u64,
    pub total_size_mb: f64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ScanOutput {
    pub success: bool,
    pub files: Vec<ScanResult>,
    pub statistics: ScanStats,
    pub error: Option<String>,
}

// ─── Fix 1+2: Daemon holds only stdin. Receiver stays on AppState. ────────────

struct Daemon {
    stdin: ChildStdin,
}

struct AppState {
    daemon: Mutex<Option<Daemon>>,
    child:  Mutex<Child>,
    // Fix 4: response channel carries (id, json_line) pairs
    response_rx: Mutex<std::sync::mpsc::Receiver<String>>,
}

// ─── Fix 4: Global atomic request ID counter ─────────────────────────────────

static REQUEST_ID: AtomicU64 = AtomicU64::new(1);

fn next_id() -> String {
    REQUEST_ID.fetch_add(1, Ordering::SeqCst).to_string()
}

// ─── Engine paths ─────────────────────────────────────────────────────────────

fn get_engine_path() -> PathBuf {
    PathBuf::from(
        r"C:\Users\houss\Desktop\AegisAI\antivirus_engine\target\release\antivirus.exe"
    )
}

fn get_engine_dir() -> PathBuf {
    PathBuf::from(r"C:\Users\houss\Desktop\AegisAI\antivirus_engine")
}

// ─── Spawn daemon ─────────────────────────────────────────────────────────────

fn spawn_daemon() -> Result<AppState, String> {
    let engine = get_engine_path();
    let engine_dir = get_engine_dir();

    let mut child = Command::new(&engine)
        .arg("daemon")
        .current_dir(&engine_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("Failed to spawn engine daemon: {}", e))?;

    let stdin = child.stdin.take()
        .ok_or("Could not get daemon stdin")?;
    let stdout = child.stdout.take()
        .ok_or("Could not get daemon stdout")?;

    // Fix 1: Timeout on ready phase using a thread + channel
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<BufReader<std::process::ChildStdout>, String>>();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut ready_line = String::new();
        match reader.read_line(&mut ready_line) {
            Ok(0) => { ready_tx.send(Err("Daemon exited before ready".to_string())).ok(); }
            Ok(_) => { ready_tx.send(Ok(reader)).ok(); }
            Err(e) => { ready_tx.send(Err(format!("Ready read error: {}", e))).ok(); }
        }
    });

    // Wait max 60 seconds for YARA to compile
    let reader = match ready_rx.recv_timeout(Duration::from_secs(60)) {
        Ok(Ok(r)) => {
            eprintln!("DAEMON: ready signal received");
            r
        }
        Ok(Err(e)) => return Err(e),
        Err(_) => return Err("Daemon startup timed out after 60s — YARA may have failed".to_string()),
    };

    // Fix 2: Spawn stdout reader thread, only passes lines to channel
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        for line in reader.lines() {
            match line {
                Ok(l) => { if tx.send(l).is_err() { break; } }
                Err(_) => break,
            }
        }
        eprintln!("DAEMON: stdout reader thread exited");
    });

    Ok(AppState {
        daemon: Mutex::new(Some(Daemon { stdin })),
        child:  Mutex::new(child),
        response_rx: Mutex::new(rx),
    })
}

// ─── Send request, read matching response ─────────────────────────────────────

fn daemon_request(state: &AppState, request: serde_json::Value) -> Result<serde_json::Value, String> {
    let id = request["id"].as_str().unwrap_or("0").to_string();

    // Fix 3: Check if daemon process is still alive before sending
    {
        let mut child = state.child.lock().unwrap();
        match child.try_wait() {
            Ok(Some(status)) => {
                return Err(format!("Daemon process has exited with status: {}", status));
            }
            Err(e) => {
                return Err(format!("Could not check daemon status: {}", e));
            }
            Ok(None) => {} // still running, proceed
        }
    }

    // Send request
    {
        let mut daemon_lock = state.daemon.lock().unwrap();
        let daemon = daemon_lock.as_mut()
            .ok_or("Daemon not initialized")?;

        let mut line = request.to_string();
        line.push('\n');
        daemon.stdin.write_all(line.as_bytes())
            .map_err(|e| format!("Failed to write to daemon stdin: {}", e))?;
        daemon.stdin.flush()
            .map_err(|e| format!("Failed to flush daemon stdin: {}", e))?;
    }

    // Fix 4: Read responses until we find one matching our request ID
    // (safe for future parallel calls — each gets its own ID)
    let rx = state.response_rx.lock().unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(120);

    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err(format!("Daemon response timeout for request id={}", id));
        }

        let line = rx.recv_timeout(remaining)
            .map_err(|_| format!("Daemon response timeout for request id={}", id))?;

        let json: serde_json::Value = serde_json::from_str(&line)
            .map_err(|e| format!("Invalid JSON from daemon: {} — raw: {}", e, &line[..line.len().min(200)]))?;

        // Fix 4: Only return if ID matches, otherwise keep waiting
        match json["id"].as_str() {
            Some(resp_id) if resp_id == id => return Ok(json),
            Some(other_id) => {
                eprintln!("WARN: Got response for id={}, waiting for id={}, skipping", other_id, id);
                continue;
            }
            None => return Ok(json), // no ID field — return as-is (e.g. error responses)
        }
    }
}

// ─── Tauri Commands ───────────────────────────────────────────────────────────

#[tauri::command]
async fn scan_file(
    path: String,
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<ScanOutput, String> {
    let request = serde_json::json!({
        "id":   next_id(),
        "cmd":  "scan-file",
        "path": path,
    });

    let json = daemon_request(&state, request)?;

    if let Some(err) = json["error"].as_str() {
        return Err(err.to_string());
    }

    let level = json["level"].as_str().unwrap_or("Error").to_string();
    let is_threat = json["is_threat"].as_bool()
        .unwrap_or(level == "Suspicious" || level == "Malicious");

    let file = ScanResult {
        path:      json["path"].as_str().unwrap_or(&path).to_string(),
        level:     level.clone(),
        reason:    json["reason"].as_str().unwrap_or("").to_string(),
        hash:      json["hash"].as_str().map(String::from),
        signature: json["signature"].as_str().map(String::from),
        is_threat,
    };

    let stats = ScanStats {
        total_files: 1,
        clean_files:      if level == "Clean"      { 1 } else { 0 },
        suspicious_files: if level == "Suspicious" { 1 } else { 0 },
        malicious_files:  if level == "Malicious"  { 1 } else { 0 },
        error_files:      if level == "Error"      { 1 } else { 0 },
        total_size_mb: 0.0,
    };

    Ok(ScanOutput { success: true, files: vec![file], statistics: stats, error: None })
}

#[tauri::command]
async fn scan_directory(
    path: String,
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<ScanOutput, String> {
    let request = serde_json::json!({
        "id":   next_id(),
        "cmd":  "scan-dir",
        "path": path,
    });

    let json = daemon_request(&state, request)?;

    if let Some(err) = json["error"].as_str() {
        return Err(err.to_string());
    }

    let files_arr = json["files"].as_array()
        .ok_or("No files array in daemon response")?;

    let files: Vec<ScanResult> = files_arr.iter().map(|f| {
        let level = f["level"].as_str().unwrap_or("Error").to_string();
        let is_threat = f["is_threat"].as_bool()
            .unwrap_or(level == "Suspicious" || level == "Malicious");
        ScanResult {
            path:      f["path"].as_str().unwrap_or("").to_string(),
            level,
            reason:    f["reason"].as_str().unwrap_or("").to_string(),
            hash:      f["hash"].as_str().map(String::from),
            signature: f["signature"].as_str().map(String::from),
            is_threat,
        }
    }).collect();

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
async fn open_file_dialog(app: tauri::AppHandle) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;
    let path = app.dialog()
        .file()
        .set_title("Select File to Scan")
        .blocking_pick_file();
    Ok(path.map(|p| p.to_string()))
}

#[tauri::command]
async fn open_dir_dialog(app: tauri::AppHandle) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;
    let path = app.dialog()
        .file()
        .set_title("Select Directory to Scan")
        .blocking_pick_folder();
    Ok(path.map(|p| p.to_string()))
}

#[tauri::command]
async fn check_engine() -> bool {
    get_engine_path().exists()
}

#[tauri::command]
async fn get_engine_status(
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<serde_json::Value, String> {
    let path = get_engine_path();

    // Fix 3: Check daemon health via try_wait
    let alive = {
        let mut child = state.child.lock().unwrap();
        matches!(child.try_wait(), Ok(None))
    };

    Ok(serde_json::json!({
        "available": path.exists(),
        "daemon_alive": alive,
        "path": path.to_string_lossy(),
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
            open_file_dialog,
            open_dir_dialog,
            check_engine,
            get_engine_status,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
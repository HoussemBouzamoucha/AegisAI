// File: UI/src-tauri/src/main.rs
// Tauri backend — bridges Scanner.tsx invoke() calls to the antivirus engine binary

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::PathBuf;
use std::process::Command;
use serde::{Deserialize, Serialize};
use tauri::Manager; 
// ─── Types (must exactly match Scanner.tsx + types.ts) ───────────────────────

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

// ─── Engine Discovery ─────────────────────────────────────────────────────────

fn get_engine_path() -> PathBuf {
    let candidates = vec![
        PathBuf::from("../../antivirus_engine/target/release/antivirus.exe"),
        PathBuf::from("../../antivirus_engine/target/release/antivirus"),
        PathBuf::from("../antivirus_engine/target/release/antivirus.exe"),
        PathBuf::from("../antivirus_engine/target/release/antivirus"),
        PathBuf::from("antivirus.exe"),
        PathBuf::from("antivirus"),
    ];

    for path in &candidates {
        if path.exists() {
            return path.clone();
        }
    }

    candidates.into_iter().next().unwrap()
}

fn call_engine(args: &[&str]) -> Result<serde_json::Value, String> {
    let engine = get_engine_path();

    let output = Command::new(&engine)
        .args(args)
        .output()
        .map_err(|e| format!(
            "Engine not found. Build it first:\n  cd antivirus_engine && cargo build --release\n\nDetail: {}",
            e
        ))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if stdout.trim().is_empty() {
        return Err(format!("Engine produced no output. stderr: {}", stderr.trim()));
    }

    serde_json::from_str(stdout.trim())
        .map_err(|e| format!("Failed to parse engine output: {}\n\nRaw output:\n{}", e, &stdout[..stdout.len().min(500)]))
}

// ─── Tauri Commands ───────────────────────────────────────────────────────────

/// Called by Scanner.tsx: scanFile(path)
#[tauri::command]
async fn scan_file(path: String) -> Result<ScanOutput, String> {
    let json = call_engine(&["scan-file", &path, "--format", "json"])?;

    // Check if the response has a "files" array or is a flat object
    if let Some(files_arr) = json["files"].as_array() {
        // Format 1: { files: [...], statistics: {...} }
        if files_arr.is_empty() {
            return Err("Engine returned empty files array".to_string());
        }

        let f = &files_arr[0];
        let level = f["level"].as_str().unwrap_or("Error").to_string();
        let is_threat = level == "Suspicious" || level == "Malicious";

        let file = ScanResult {
            path:      f["path"].as_str().unwrap_or(&path).to_string(),
            level:     level.clone(),
            reason:    f["reason"].as_str().unwrap_or("").to_string(),
            hash:      f["hash"].as_str().map(String::from),
            signature: f["signature"].as_str().map(String::from),
            is_threat,
        };

        let s = &json["statistics"];
        let stats = ScanStats {
            total_files:      s["total_files"].as_u64().unwrap_or(1),
            clean_files:      s["clean_files"].as_u64().unwrap_or(if level == "Clean" { 1 } else { 0 }),
            suspicious_files: s["suspicious_files"].as_u64().unwrap_or(if level == "Suspicious" { 1 } else { 0 }),
            malicious_files:  s["malicious_files"].as_u64().unwrap_or(if level == "Malicious" { 1 } else { 0 }),
            error_files:      s["error_files"].as_u64().unwrap_or(if level == "Error" { 1 } else { 0 }),
            total_size_mb:    s["total_size_mb"].as_f64().unwrap_or(0.0),
        };

        Ok(ScanOutput { success: true, files: vec![file], statistics: stats, error: None })

    } else {
        // Format 2: Flat object { path, level, reason, hash, signature, is_threat }
        // Read is_threat directly from engine output if present, otherwise derive from level
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
}

/// Called by Scanner.tsx: scanDirectory(path)
#[tauri::command]
async fn scan_directory(path: String) -> Result<ScanOutput, String> {
    let json = call_engine(&["scan-dir", &path, "--format", "json"])?;

    let files_arr = json["files"].as_array()
        .ok_or_else(|| "Engine returned no 'files' array".to_string())?;

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

/// Called by Scanner.tsx: invoke('open_file_dialog')
#[tauri::command]
async fn open_file_dialog(app: tauri::AppHandle) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;

    let path = app.dialog()
        .file()
        .set_title("Select File to Scan")
        .blocking_pick_file();

    Ok(path.map(|p| p.to_string()))
}

/// Called by Scanner.tsx: invoke('open_dir_dialog')
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
async fn get_engine_status() -> serde_json::Value {
    let path = get_engine_path();
    serde_json::json!({
        "available": path.exists(),
        "path": path.to_string_lossy(),
    })
}

// ─── Main ─────────────────────────────────────────────────────────────────────

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            scan_file,
            scan_directory,
            open_file_dialog,
            open_dir_dialog,
            check_engine,
            get_engine_status,
        ])
        .setup(|app| {
            #[cfg(debug_assertions)]
            {
                let window = app.get_webview_window("main").unwrap();
                window.open_devtools();
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
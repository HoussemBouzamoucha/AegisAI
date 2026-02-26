// File: src/main.rs
// JSON-Compatible Antivirus Scanner with Process Monitoring + Daemon Mode

mod core;

use core::file_system::scanner::FileSystemScanner;
use core::process::scanner::ProcessScanner;
use core::types::ThreatLevel;
use std::path::Path;
use std::env;
use std::io::{self, BufRead, Write};
use serde_json::json;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage();
        return;
    }

    let command = &args[1];

    match command.as_str() {
        // ── Daemon mode ───────────────────────────────────────────────────────
        // Spawned once by Tauri. Compiles YARA rules once, then processes
        // scan requests from stdin as newline-delimited JSON forever.
        "daemon" => {
            run_daemon();
        }

        // ── One-shot CLI commands ─────────────────────────────────────────────
        "scan" => {
            if args.len() < 3 {
                eprintln!("{{\"error\": \"Please provide a file or directory to scan\"}}");
                return;
            }
            let path = Path::new(&args[2]);
            let json_output = args.iter().any(|arg| arg == "--json");
            if json_output {
                scan_path_json(path);
            } else {
                scan_path_human(path);
            }
        }
        "scan-file" => {
            if args.len() < 3 {
                println!("{{\"error\": \"No file path provided\"}}");
                return;
            }
            scan_single_file_json(Path::new(&args[2]));
        }
        "scan-dir" => {
            if args.len() < 3 {
                println!("{{\"error\": \"No directory path provided\"}}");
                return;
            }
            scan_directory_json(Path::new(&args[2]));
        }
        "scan-processes" => {
            scan_processes_json();
        }
        "kill-process" => {
            if args.len() < 3 {
                println!("{{\"error\": \"No PID provided\"}}");
                return;
            }
            if let Ok(pid) = args[2].parse::<u32>() {
                kill_process_json(pid);
            } else {
                println!("{{\"error\": \"Invalid PID\"}}");
            }
        }
        "test" => {
            run_tests();
        }
        "help" | "--help" | "-h" => {
            print_usage();
        }
        _ => {
            eprintln!("{{\"error\": \"Unknown command: {}\"}}", command);
        }
    }
}

// ─── Daemon Mode ──────────────────────────────────────────────────────────────
// Protocol: newline-delimited JSON over stdin/stdout
//
// Request:  { "id": "...", "cmd": "scan-file"|"scan-dir"|"scan-processes"|"kill-process", "path": "..." }
// Response: { "id": "...", ...result fields... }
//
// The scanner is created ONCE here — YARA rules compile once and are reused
// for every subsequent request, eliminating the per-scan startup delay.

fn run_daemon() {
    // Signal ready to Tauri
    let ready = json!({ "status": "ready" });
    println!("{}", ready);
    io::stdout().flush().ok();

    // Create scanner once — this is where YARA compiles (the slow part)
    let scanner = FileSystemScanner::new();
    let process_scanner = ProcessScanner::new();

    eprintln!("DAEMON: scanner initialized, waiting for requests...");

    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let request: serde_json::Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(e) => {
                let err = json!({ "error": format!("Invalid JSON: {}", e) });
                println!("{}", err);
                io::stdout().flush().ok();
                continue;
            }
        };

        let id = request["id"].as_str().unwrap_or("").to_string();
        let cmd = request["cmd"].as_str().unwrap_or("");

        let response = match cmd {
            "scan-file" => {
                let path_str = request["path"].as_str().unwrap_or("");
                let path = Path::new(path_str);
                daemon_scan_file(&scanner, path, &id)
            }
            "scan-dir" => {
                let path_str = request["path"].as_str().unwrap_or("");
                let path = Path::new(path_str);
                daemon_scan_dir(&scanner, path, &id)
            }
            "scan-processes" => {
                daemon_scan_processes(&process_scanner, &id)
            }
            "kill-process" => {
                let pid = request["pid"].as_u64().unwrap_or(0) as u32;
                daemon_kill_process(&process_scanner, pid, &id)
            }
            "ping" => {
                json!({ "id": id, "status": "pong" })
            }
            _ => {
                json!({ "id": id, "error": format!("Unknown command: {}", cmd) })
            }
        };

        println!("{}", response);
        io::stdout().flush().ok();
    }

    eprintln!("DAEMON: stdin closed, exiting");
}

fn daemon_scan_file(scanner: &FileSystemScanner, path: &Path, id: &str) -> serde_json::Value {
    if !path.exists() {
        return json!({ "id": id, "error": "File does not exist" });
    }

    match scanner.scan_file(path) {
        Ok(result) => json!({
            "id": id,
            "success": true,
            "path": result.path.display().to_string(),
            "level": result.level.as_str(),
            "reason": result.reason,
            "hash": result.hash,
            "signature": result.signature,
            "is_threat": result.level.is_threat(),
        }),
        Err(e) => json!({ "id": id, "success": false, "error": e.to_string() }),
    }
}

fn daemon_scan_dir(scanner: &FileSystemScanner, path: &Path, id: &str) -> serde_json::Value {
    if !path.exists() {
        return json!({ "id": id, "error": "Directory does not exist" });
    }

    let (results, stats) = scanner.scan_directory_with_stats(path, true);

    let files: Vec<serde_json::Value> = results.iter().map(|r| json!({
        "path": r.path.display().to_string(),
        "level": r.level.as_str(),
        "reason": r.reason,
        "hash": r.hash,
        "signature": r.signature,
        "is_threat": r.level.is_threat(),
    })).collect();

    json!({
        "id": id,
        "success": true,
        "statistics": {
            "total_files": stats.total_files,
            "clean_files": stats.clean_files,
            "suspicious_files": stats.suspicious_files,
            "malicious_files": stats.malicious_files,
            "error_files": stats.error_files,
            "total_size_mb": (stats.total_size_scanned as f64) / 1024.0 / 1024.0,
        },
        "files": files,
    })
}

fn daemon_scan_processes(scanner: &ProcessScanner, id: &str) -> serde_json::Value {
    match scanner.scan_all_processes() {
        Ok(processes) => {
            let stats = scanner.get_statistics(&processes);
            let process_list: Vec<serde_json::Value> = processes.iter().map(|p| json!({
                "pid": p.pid,
                "name": p.name,
                "path": p.path,
                "memory_mb": format!("{:.2}", p.memory_mb),
                "cpu_usage": p.cpu_usage,
                "threat_level": p.threat_level.as_str(),
                "suspicious_behaviors": p.suspicious_behaviors,
                "is_threat": p.threat_level != core::process::scanner::ProcessThreatLevel::Safe,
            })).collect();

            json!({
                "id": id,
                "success": true,
                "statistics": {
                    "total_processes": stats.total_processes,
                    "safe_processes": stats.safe_processes,
                    "suspicious_processes": stats.suspicious_processes,
                    "malicious_processes": stats.malicious_processes,
                    "critical_processes": stats.critical_processes,
                    "total_memory_mb": format!("{:.2}", stats.total_memory_mb),
                },
                "processes": process_list,
            })
        }
        Err(e) => json!({ "id": id, "success": false, "error": e.to_string() }),
    }
}

fn daemon_kill_process(scanner: &ProcessScanner, pid: u32, id: &str) -> serde_json::Value {
    match scanner.terminate_process(pid) {
        Ok(()) => json!({ "id": id, "success": true, "message": format!("Process {} terminated", pid) }),
        Err(e) => json!({ "id": id, "success": false, "error": e.to_string() }),
    }
}

// ─── One-shot CLI functions (unchanged) ──────────────────────────────────────

fn scan_processes_json() {
    let scanner = ProcessScanner::new();
    match scanner.scan_all_processes() {
        Ok(processes) => {
            let stats = scanner.get_statistics(&processes);
            let process_list: Vec<_> = processes.iter().map(|p| {
                json!({
                    "pid": p.pid,
                    "name": p.name,
                    "path": p.path,
                    "memory_mb": format!("{:.2}", p.memory_mb),
                    "cpu_usage": p.cpu_usage,
                    "threat_level": p.threat_level.as_str(),
                    "suspicious_behaviors": p.suspicious_behaviors,
                    "is_threat": p.threat_level != core::process::scanner::ProcessThreatLevel::Safe,
                })
            }).collect();
            let output = json!({
                "success": true,
                "statistics": {
                    "total_processes": stats.total_processes,
                    "safe_processes": stats.safe_processes,
                    "suspicious_processes": stats.suspicious_processes,
                    "malicious_processes": stats.malicious_processes,
                    "critical_processes": stats.critical_processes,
                    "total_memory_mb": format!("{:.2}", stats.total_memory_mb),
                },
                "processes": process_list,
            });
            println!("{}", output);
        }
        Err(e) => println!("{{\"success\": false, \"error\": \"{}\"}}", e),
    }
}

fn kill_process_json(pid: u32) {
    let scanner = ProcessScanner::new();
    match scanner.terminate_process(pid) {
        Ok(()) => println!("{{\"success\": true, \"message\": \"Process {} terminated\"}}", pid),
        Err(e) => println!("{{\"success\": false, \"error\": \"{}\"}}", e),
    }
}

fn scan_single_file_json(path: &Path) {
    if !path.exists() {
        println!("{{\"error\": \"File does not exist\"}}");
        return;
    }
    let scanner = FileSystemScanner::new();
    match scanner.scan_file(path) {
        Ok(result) => {
            let output = json!({
                "success": true,
                "path": result.path.display().to_string(),
                "level": result.level.as_str(),
                "reason": result.reason,
                "hash": result.hash,
                "signature": result.signature,
                "is_threat": result.level.is_threat(),
            });
            println!("{}", output);
        }
        Err(e) => println!("{{\"success\": false, \"error\": \"{}\"}}", e.to_string()),
    }
}

fn scan_directory_json(path: &Path) {
    if !path.exists() {
        println!("{{\"error\": \"Directory does not exist\"}}");
        return;
    }
    let scanner = FileSystemScanner::new();
    let (results, stats) = scanner.scan_directory_with_stats(path, true);
    let mut files = Vec::new();
    for result in results {
        files.push(json!({
            "path": result.path.display().to_string(),
            "level": result.level.as_str(),
            "reason": result.reason,
            "hash": result.hash,
            "signature": result.signature,
            "is_threat": result.level.is_threat(),
        }));
    }
    let output = json!({
        "success": true,
        "statistics": {
            "total_files": stats.total_files,
            "clean_files": stats.clean_files,
            "suspicious_files": stats.suspicious_files,
            "malicious_files": stats.malicious_files,
            "error_files": stats.error_files,
            "total_size_mb": (stats.total_size_scanned as f64) / 1024.0 / 1024.0,
        },
        "files": files,
    });
    println!("{}", output);
}

fn scan_path_human(path: &Path) {
    println!("🛡️  Antivirus Engine v1.0.0");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    println!("🔍 Scanning: {}\n", path.display());
    if !path.exists() {
        eprintln!("❌ Error: Path does not exist");
        return;
    }
    let scanner = FileSystemScanner::new();
    if path.is_file() {
        match scanner.scan_file(path) {
            Ok(result) => print_result(&result),
            Err(e) => eprintln!("❌ Scan error: {}", e),
        }
    } else if path.is_dir() {
        let (results, stats) = scanner.scan_directory_with_stats(path, true);
        println!("📊 Scan Results:");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("Total files:      {}", stats.total_files);
        println!("Clean:            {} ✅", stats.clean_files);
        println!("Suspicious:       {} ⚠️", stats.suspicious_files);
        println!("Malicious:        {} 🚨", stats.malicious_files);
        println!("Errors:           {}", stats.error_files);
        println!("Total size:       {:.2} MB", stats.total_size_scanned as f64 / 1024.0 / 1024.0);
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
        let threats: Vec<_> = results.iter().filter(|r| r.level.is_threat()).collect();
        if !threats.is_empty() {
            println!("⚠️  {} Threat(s) detected:\n", threats.len());
            for result in threats {
                print_result(result);
            }
        } else {
            println!("✅ No threats detected! All files are clean.");
        }
    }
}

fn scan_path_json(path: &Path) {
    if !path.exists() {
        println!("{{\"error\": \"Path does not exist\"}}");
        return;
    }
    if path.is_file() {
        scan_single_file_json(path);
    } else if path.is_dir() {
        scan_directory_json(path);
    }
}

fn print_result(result: &core::types::ScanResult) {
    println!("{} {}", result.level.emoji(), result.path.display());
    println!("   Level: {}", result.level);
    println!("   Reason: {}", result.reason);
    if let Some(hash) = &result.hash {
        println!("   Hash: {}...", &hash[..std::cmp::min(16, hash.len())]);
    }
    if let Some(sig) = &result.signature {
        println!("   Signature: {}", sig);
    }
    println!();
}

fn run_tests() {
    println!("🛡️  Antivirus Engine v1.0.0");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    println!("🧪 Running self-tests...\n");
    let scanner = FileSystemScanner::new();
    let mut passed = 0;
    let mut failed = 0;
    println!("Test 1: EICAR detection");
    match test_eicar(&scanner) {
        Ok(true) => { println!("   ✅ PASSED\n"); passed += 1; }
        Ok(false) => { println!("   ❌ FAILED\n"); failed += 1; }
        Err(e) => { println!("   ⚠️  SKIPPED - {}\n", e); }
    }
    println!("Test 2: Clean file detection");
    match test_clean_file(&scanner) {
        Ok(true) => { println!("   ✅ PASSED\n"); passed += 1; }
        Ok(false) => { println!("   ❌ FAILED\n"); failed += 1; }
        Err(e) => { println!("   ❌ FAILED - {}\n", e); failed += 1; }
    }
    println!("Test 3: Ransomware note detection");
    match test_ransomware_note(&scanner) {
        Ok(true) => { println!("   ✅ PASSED\n"); passed += 1; }
        Ok(false) => { println!("   ❌ FAILED\n"); failed += 1; }
        Err(e) => { println!("   ❌ FAILED - {}\n", e); failed += 1; }
    }
    println!("Test 4: Zero-byte executable detection");
    match test_zero_byte_executable(&scanner) {
        Ok(true) => { println!("   ✅ PASSED\n"); passed += 1; }
        Ok(false) => { println!("   ❌ FAILED\n"); failed += 1; }
        Err(e) => { println!("   ❌ FAILED - {}\n", e); failed += 1; }
    }
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Test Results: {} passed, {} failed", passed, failed);
    if failed == 0 { println!("✅ All tests passed!"); } else { println!("⚠️  Some tests failed"); }
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
}

fn test_eicar(scanner: &FileSystemScanner) -> Result<bool, String> {
    let path = create_eicar_test();
    let result = scanner.scan_file(&path).map_err(|e| format!("Blocked: {}", e))?;
    std::fs::remove_file(&path).ok();
    Ok(result.level == ThreatLevel::Malicious)
}

fn test_clean_file(scanner: &FileSystemScanner) -> Result<bool, String> {
    let path = std::env::temp_dir().join("clean_test.txt");
    std::fs::write(&path, "Clean file.").map_err(|e| e.to_string())?;
    let result = scanner.scan_file(&path).map_err(|e| e.to_string())?;
    std::fs::remove_file(&path).ok();
    Ok(result.level == ThreatLevel::Clean)
}

fn test_ransomware_note(scanner: &FileSystemScanner) -> Result<bool, String> {
    let path = std::env::temp_dir().join("README_DECRYPT.txt");
    std::fs::write(&path, "All your files encrypted AES-256 pay bitcoin ransom decrypt").map_err(|e| e.to_string())?;
    let result = scanner.scan_file(&path).map_err(|e| e.to_string())?;
    std::fs::remove_file(&path).ok();
    Ok(result.level == ThreatLevel::Malicious || result.level == ThreatLevel::Suspicious)
}

fn test_zero_byte_executable(scanner: &FileSystemScanner) -> Result<bool, String> {
    let path = std::env::temp_dir().join("zero.exe");
    std::fs::write(&path, "").map_err(|e| e.to_string())?;
    let result = scanner.scan_file(&path).map_err(|e| e.to_string())?;
    std::fs::remove_file(&path).ok();
    Ok(result.level == ThreatLevel::Suspicious || result.level == ThreatLevel::Malicious)
}

fn create_eicar_test() -> std::path::PathBuf {
    let path = std::env::temp_dir().join("eicar_test.txt");
    std::fs::write(&path, "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*").unwrap();
    path
}

fn print_usage() {
    println!("🛡️  Antivirus Engine v1.0.0");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    println!("Usage:");
    println!("  antivirus daemon                Run as persistent daemon (used by Tauri)");
    println!("  antivirus scan <path>           Scan a file or directory");
    println!("  antivirus scan <path> --json    Scan with JSON output");
    println!("  antivirus scan-file <file>      Scan single file (JSON)");
    println!("  antivirus scan-dir <dir>        Scan directory (JSON)");
    println!("  antivirus scan-processes        Scan running processes (JSON)");
    println!("  antivirus kill-process <PID>    Terminate a process");
    println!("  antivirus test                  Run self-tests");
    println!("  antivirus help                  Show this help");
}
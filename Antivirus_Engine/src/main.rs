// File: antivirus_engine/src/main.rs
// JSON-Compatible Antivirus Scanner with Process Monitoring + Daemon Mode

mod core;

use core::file_system::scanner::FileSystemScanner;
use core::network::NetworkScanner;
use core::process::ProcessScanner;
use core::process::output::serialize_process;
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
        "daemon" => { run_daemon(); }
        "scan" => {
            if args.len() < 3 {
                eprintln!("{{\"error\": \"Please provide a file or directory to scan\"}}");
                return;
            }
            let path = Path::new(&args[2]);
            if args.iter().any(|a| a == "--json") {
                scan_path_json(path);
            } else {
                scan_path_human(path);
            }
        }
        "scan-file" => {
            if args.len() < 3 { println!("{{\"error\": \"No file path provided\"}}"); return; }
            scan_single_file_json(Path::new(&args[2]));
        }
        "scan-dir" => {
            if args.len() < 3 { println!("{{\"error\": \"No directory path provided\"}}"); return; }
            scan_directory_json(Path::new(&args[2]));
        }
        "scan-processes" => { scan_processes_json(); }
        "scan-network" => { scan_network_json(None); }
        "scan-network-pid" => {
            if args.len() < 3 { println!("{{\"error\": \"No PID provided\"}}"); return; }
            if let Ok(pid) = args[2].parse::<u32>() {
                scan_network_json(Some(pid));
            } else {
                println!("{{\"error\": \"Invalid PID\"}}");
            }
        }
        "kill-process" => {
            if args.len() < 3 { println!("{{\"error\": \"No PID provided\"}}"); return; }
            if let Ok(pid) = args[2].parse::<u32>() {
                kill_process_json(pid);
            } else {
                println!("{{\"error\": \"Invalid PID\"}}");
            }
        }
        "test"  => { run_tests(); }
        "help" | "--help" | "-h" => { print_usage(); }
        _ => { eprintln!("{{\"error\": \"Unknown command: {}\"}}", command); }
    }
}

// ─── Daemon ───────────────────────────────────────────────────────────────────

fn run_daemon() {
    let ready = json!({ "status": "ready" });
    println!("{}", ready);
    io::stdout().flush().ok();

    // Scanners created ONCE — YARA compiles here, reused for every request
    let scanner         = FileSystemScanner::new();
    let process_scanner = ProcessScanner::new();
    let network_scanner = NetworkScanner::new();

    eprintln!("DAEMON: scanner initialized, waiting for requests...");

    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = match line { Ok(l) => l, Err(_) => break };
        let trimmed = line.trim();
        if trimmed.is_empty() { continue; }

        let request: serde_json::Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(e) => {
                let err = json!({ "error": format!("Invalid JSON: {}", e) });
                println!("{}", err);
                io::stdout().flush().ok();
                continue;
            }
        };

        let id  = request["id"].as_str().unwrap_or("").to_string();
        let cmd = request["cmd"].as_str().unwrap_or("");

        let response = match cmd {
            "scan-file" => {
                let path = request["path"].as_str().unwrap_or("");
                daemon_scan_file(&scanner, Path::new(path), &id)
            }
            "scan-dir" => {
                let path = request["path"].as_str().unwrap_or("");
                daemon_scan_dir(&scanner, Path::new(path), &id)
            }
            "scan-processes" => daemon_scan_processes(&process_scanner, &id),
            "scan-network" => daemon_scan_network(&network_scanner, request["pid"].as_u64().map(|v| v as u32), &id),
            "kill-process"   => {
                let pid = request["pid"].as_u64().unwrap_or(0) as u32;
                daemon_kill_process(&process_scanner, pid, &id)
            }
            "ping" => json!({ "id": id, "status": "pong" }),
            _      => json!({ "id": id, "error": format!("Unknown command: {}", cmd) }),
        };

        println!("{}", response);
        io::stdout().flush().ok();
    }

    eprintln!("DAEMON: stdin closed, exiting");
}

// ─── File scan serialization ──────────────────────────────────────────────────

fn serialize_result(r: &core::types::ScanResult) -> serde_json::Value {
    let context_flags: Vec<&str> = r.context_flags.iter()
        .map(|f| f.as_str())
        .collect();

    let detection_signals: Vec<serde_json::Value> = r.detection_signals.iter()
        .map(|s| json!({
            "source":      s.source,
            "description": s.description,
            "score":       s.score,
        }))
        .collect();

    json!({
        "path":              r.path.display().to_string(),
        "level":             r.level.as_str(),
        "reason":            r.reason,
        "hash":              r.hash,
        "signature":         r.signature,
        "is_threat":         r.level.is_threat(),
        "confidence_score":  r.confidence_score,
        "detection_signals": detection_signals,
        "file_category":     r.file_category.as_str(),
        "context_flags":     context_flags,
    })
}

// ─── Daemon handlers ──────────────────────────────────────────────────────────

fn daemon_scan_file(scanner: &FileSystemScanner, path: &Path, id: &str) -> serde_json::Value {
    if !path.exists() {
        return json!({ "id": id, "error": "File does not exist" });
    }
    match scanner.scan_file(path) {
        Ok(result) => {
            let mut v = serialize_result(&result);
            v["id"]      = json!(id);
            v["success"] = json!(true);
            v
        }
        Err(e) => json!({ "id": id, "success": false, "error": e.to_string() }),
    }
}

fn daemon_scan_dir(scanner: &FileSystemScanner, path: &Path, id: &str) -> serde_json::Value {
    if !path.exists() {
        return json!({ "id": id, "error": "Directory does not exist" });
    }
    let (results, stats) = scanner.scan_directory_with_stats(path, true);
    let files: Vec<serde_json::Value> = results.iter().map(serialize_result).collect();
    json!({
        "id":      id,
        "success": true,
        "statistics": {
            "total_files":      stats.total_files,
            "clean_files":      stats.clean_files,
            "suspicious_files": stats.suspicious_files,
            "malicious_files":  stats.malicious_files,
            "error_files":      stats.error_files,
            "total_size_mb":    (stats.total_size_scanned as f64) / 1024.0 / 1024.0,
        },
        "files": files,
    })
}

fn daemon_scan_processes(scanner: &ProcessScanner, id: &str) -> serde_json::Value {
    match scanner.scan_all_processes() {
        Ok(processes) => {
            let stats = scanner.get_statistics(&processes);
            let list: Vec<serde_json::Value> = processes.iter()
                .map(serialize_process)
                .collect();
            json!({
                "id":      id,
                "success": true,
                "statistics": {
                    "total_processes":      stats.total_processes,
                    "safe_processes":       stats.safe_processes,
                    "suspicious_processes": stats.suspicious_processes,
                    "malicious_processes":  stats.malicious_processes,
                    "critical_processes":   stats.critical_processes,
                    "total_memory_mb":      format!("{:.2}", stats.total_memory_mb),
                    "total_threads":        stats.total_threads,
                    "avg_cpu_usage":        format!("{:.2}", stats.avg_cpu_usage),
                    "scan_duration_ms":     stats.scan_duration_ms,
                },
                "processes": list,
            })
        }
        Err(e) => json!({ "id": id, "success": false, "error": e.to_string() }),
    }
}

fn daemon_kill_process(scanner: &ProcessScanner, pid: u32, id: &str) -> serde_json::Value {
    match scanner.terminate_process(pid) {
        Ok(())  => json!({ "id": id, "success": true, "message": format!("Process {} terminated", pid) }),
        Err(e)  => json!({ "id": id, "success": false, "error": e.to_string() }),
    }
}

// ─── One-shot CLI ─────────────────────────────────────────────────────────────

fn scan_processes_json() {
    let scanner = ProcessScanner::new();
    match scanner.scan_all_processes() {
        Ok(processes) => {
            let stats = scanner.get_statistics(&processes);
            let list: Vec<serde_json::Value> = processes.iter()
                .map(serialize_process)
                .collect();
            println!("{}", json!({
                "success": true,
                "statistics": {
                    "total_processes":      stats.total_processes,
                    "safe_processes":       stats.safe_processes,
                    "suspicious_processes": stats.suspicious_processes,
                    "malicious_processes":  stats.malicious_processes,
                    "critical_processes":   stats.critical_processes,
                    "total_memory_mb":      format!("{:.2}", stats.total_memory_mb),
                    "total_threads":        stats.total_threads,
                    "avg_cpu_usage":        format!("{:.2}", stats.avg_cpu_usage),
                    "scan_duration_ms":     stats.scan_duration_ms,
                },
                "processes": list,
            }));
        }
        Err(e) => println!("{{\"success\": false, \"error\": \"{}\"}}", e),
    }
}

fn scan_network_json(pid: Option<u32>) {
    let scanner = NetworkScanner::new();

    let (connections, stats) = match pid {
        Some(pid) => {
            let connections = match scanner.scan_by_pid(pid) {
                Ok(connections) => connections,
                Err(e) => {
                    println!("{{\"success\": false, \"error\": \"{}\"}}", e);
                    return;
                }
            };
            let stats = scanner.get_statistics(&connections);
            (connections, stats)
        }
        None => match scanner.scan() {
            Ok((connections, stats)) => (connections, stats),
            Err(e) => {
                println!("{{\"success\": false, \"error\": \"{}\"}}", e);
                return;
            }
        },
    };

    let list: Vec<serde_json::Value> = connections.iter()
        .map(serialize_network_connection)
        .collect();

    println!("{}", json!({
        "success": true,
        "statistics": {
            "total_connections":      stats.total_connections,
            "suspicious_connections": stats.suspicious_connections,
            "malicious_connections":  stats.malicious_connections,
            "local_listeners":        stats.local_listeners,
            "established_connections": stats.established_connections,
            "scan_duration_ms":       stats.scan_duration_ms,
        },
        "connections": list,
    }));
}

fn serialize_network_connection(c: &crate::core::network::types::NetworkConnection) -> serde_json::Value {
    let signals: Vec<serde_json::Value> = c.detection_signals.iter()
        .map(|s| json!({
            "source":      s.source,
            "description": s.description,
            "score":       s.score,
        }))
        .collect();

    json!({
        "protocol":      c.protocol,
        "local_address": c.local_address,
        "remote_address": c.remote_address,
        "state":         c.state,
        "pid":           c.pid,
        "process_name":  c.process_name,
        "threat_level":  c.threat_level.as_str(),
        "threat_score":  c.threat_score,
        "is_threat":     c.is_threat,
        "detection_signals": signals,
    })
}

fn daemon_scan_network(scanner: &NetworkScanner, pid: Option<u32>, id: &str) -> serde_json::Value {
    let result = match pid {
        Some(pid) => scanner.scan_by_pid(pid).map(|connections| {
            let stats = scanner.get_statistics(&connections);
            json!({
                "id": id,
                "success": true,
                "statistics": {
                    "total_connections":      stats.total_connections,
                    "suspicious_connections": stats.suspicious_connections,
                    "malicious_connections":  stats.malicious_connections,
                    "local_listeners":        stats.local_listeners,
                    "established_connections": stats.established_connections,
                    "scan_duration_ms":       stats.scan_duration_ms,
                },
                "connections": connections.iter().map(serialize_network_connection).collect::<Vec<_>>(),
            })
        }),
        None => scanner.scan().map(|(connections, stats)| {
            json!({
                "id": id,
                "success": true,
                "statistics": {
                    "total_connections":      stats.total_connections,
                    "suspicious_connections": stats.suspicious_connections,
                    "malicious_connections":  stats.malicious_connections,
                    "local_listeners":        stats.local_listeners,
                    "established_connections": stats.established_connections,
                    "scan_duration_ms":       stats.scan_duration_ms,
                },
                "connections": connections.iter().map(serialize_network_connection).collect::<Vec<_>>(),
            })
        }),
    };

    match result {
        Ok(value) => value,
        Err(e)    => json!({ "id": id, "success": false, "error": e.to_string() }),
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
    if !path.exists() { println!("{{\"error\": \"File does not exist\"}}"); return; }
    let scanner = FileSystemScanner::new();
    match scanner.scan_file(path) {
        Ok(result) => println!("{}", serialize_result(&result)),
        Err(e)     => println!("{{\"success\": false, \"error\": \"{}\"}}", e),
    }
}

fn scan_directory_json(path: &Path) {
    if !path.exists() { println!("{{\"error\": \"Directory does not exist\"}}"); return; }
    let scanner = FileSystemScanner::new();
    let (results, stats) = scanner.scan_directory_with_stats(path, true);
    let files: Vec<serde_json::Value> = results.iter().map(serialize_result).collect();
    println!("{}", json!({
        "success": true,
        "statistics": {
            "total_files":      stats.total_files,
            "clean_files":      stats.clean_files,
            "suspicious_files": stats.suspicious_files,
            "malicious_files":  stats.malicious_files,
            "error_files":      stats.error_files,
            "total_size_mb":    (stats.total_size_scanned as f64) / 1024.0 / 1024.0,
        },
        "files": files,
    }));
}

fn scan_path_human(path: &Path) {
    println!("🛡️  Antivirus Engine v1.0.0");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    println!("🔍 Scanning: {}\n", path.display());
    if !path.exists() { eprintln!("❌ Error: Path does not exist"); return; }
    let scanner = FileSystemScanner::new();
    if path.is_file() {
        match scanner.scan_file(path) {
            Ok(r)  => print_result(&r),
            Err(e) => eprintln!("❌ Scan error: {}", e),
        }
    } else if path.is_dir() {
        let (results, stats) = scanner.scan_directory_with_stats(path, true);
        println!("📊 Scan Results:");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("Total:      {}", stats.total_files);
        println!("Clean:      {} ✅", stats.clean_files);
        println!("Suspicious: {} ⚠️",  stats.suspicious_files);
        println!("Malicious:  {} 🚨", stats.malicious_files);
        println!("Errors:     {}", stats.error_files);
        println!("Size:       {:.2} MB", stats.total_size_scanned as f64 / 1024.0 / 1024.0);
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
        let threats: Vec<_> = results.iter().filter(|r| r.level.is_threat()).collect();
        if threats.is_empty() {
            println!("✅ No threats detected!");
        } else {
            println!("⚠️  {} Threat(s) detected:\n", threats.len());
            for r in threats { print_result(r); }
        }
    }
}

fn scan_path_json(path: &Path) {
    if !path.exists() { println!("{{\"error\": \"Path does not exist\"}}"); return; }
    if path.is_file()     { scan_single_file_json(path); }
    else if path.is_dir() { scan_directory_json(path); }
}

fn print_result(r: &core::types::ScanResult) {
    println!("{} {}", r.level.emoji(), r.path.display());
    println!("   Level:  {}", r.level);
    println!("   Reason: {}", r.reason);
    if let Some(h) = &r.hash      { println!("   Hash:  {}...", &h[..h.len().min(16)]); }
    if let Some(s) = &r.signature { println!("   Sig:   {}", s); }
    if !r.context_flags.is_empty() {
        let flags: Vec<&str> = r.context_flags.iter().map(|f| f.as_str()).collect();
        println!("   Flags: {}", flags.join(", "));
    }
    println!();
}

fn run_tests() {
    println!("🛡️  Antivirus Engine v1.0.0\n🧪 Running self-tests...\n");
    let scanner = FileSystemScanner::new();
    let mut passed = 0; let mut failed = 0;

    let tests: &[(&str, Box<dyn Fn(&FileSystemScanner) -> Result<bool, String>>)] = &[
        ("EICAR detection",      Box::new(test_eicar)),
        ("Clean file detection", Box::new(test_clean_file)),
        ("Ransomware note",      Box::new(test_ransomware_note)),
        ("Zero-byte executable", Box::new(test_zero_byte_executable)),
    ];

    for (name, test_fn) in tests {
        print!("Test: {} ... ", name);
        match test_fn(&scanner) {
            Ok(true)  => { println!("✅ PASSED"); passed += 1; }
            Ok(false) => { println!("❌ FAILED"); failed += 1; }
            Err(e)    => { println!("⚠️  SKIPPED — {}", e); }
        }
    }

    println!("\nResults: {} passed, {} failed", passed, failed);
    if failed == 0 { println!("✅ All tests passed!"); }
}

fn test_eicar(scanner: &FileSystemScanner) -> Result<bool, String> {
    let path = std::env::temp_dir().join("eicar_test.txt");
    std::fs::write(&path, "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*").unwrap();
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
    std::fs::write(&path, "All your files have been encrypted. Pay bitcoin to recover your files.")
        .map_err(|e| e.to_string())?;
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

fn print_usage() {
    println!("🛡️  Antivirus Engine v1.0.0\n");
    println!("Usage:");
    println!("  antivirus daemon                Run as persistent daemon (used by Tauri)");
    println!("  antivirus scan <path>           Scan a file or directory");
    println!("  antivirus scan <path> --json    Scan with JSON output");
    println!("  antivirus scan-file <file>      Scan single file (JSON)");
    println!("  antivirus scan-dir <dir>        Scan directory (JSON)");
    println!("  antivirus scan-processes        Scan running processes (JSON)");
    println!("  antivirus scan-network          Scan system network connections (JSON)");
    println!("  antivirus scan-network-pid <PID> Scan network connections for a process (JSON)");
    println!("  antivirus kill-process <PID>    Terminate a process");
    println!("  antivirus test                  Run self-tests");
}
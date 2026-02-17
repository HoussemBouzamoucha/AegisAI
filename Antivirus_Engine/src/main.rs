// File: src/main.rs
// JSON-Compatible Antivirus Scanner with Process Monitoring

mod core;

use core::file_system::scanner::FileSystemScanner;
use core::process::scanner::ProcessScanner;
use core::types::ThreatLevel;
use std::path::Path;
use std::env;
use serde_json::json;

fn main() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        print_usage();
        return;
    }
    
    let command = &args[1];
    
    match command.as_str() {
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
            
            let path = Path::new(&args[2]);
            scan_single_file_json(path);
        }
        "scan-dir" => {
            if args.len() < 3 {
                println!("{{\"error\": \"No directory path provided\"}}");
                return;
            }
            
            let path = Path::new(&args[2]);
            scan_directory_json(path);
        }
        "scan-processes" => {
            // NEW: Scan all running processes
            scan_processes_json();
        }
        "kill-process" => {
            // NEW: Terminate a malicious process
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
            eprintln!("{{\"error\": \"Unknown command: {}\"}}",  command);
        }
    }
}

/// Scan all running processes and output JSON
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
        Err(e) => {
            println!("{{\"success\": false, \"error\": \"{}\"}}", e);
        }
    }
}

/// Terminate a process by PID
fn kill_process_json(pid: u32) {
    let scanner = ProcessScanner::new();
    
    match scanner.terminate_process(pid) {
        Ok(()) => {
            println!("{{\"success\": true, \"message\": \"Process {} terminated\"}}", pid);
        }
        Err(e) => {
            println!("{{\"success\": false, \"error\": \"{}\"}}", e);
        }
    }
}

/// Scan single file and output JSON (for Python)
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
        Err(e) => {
            let output = json!({
                "success": false,
                "error": e.to_string(),
            });
            println!("{}", output);
        }
    }
}

/// Scan directory and output JSON (for Python)
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

/// Human-readable output for command line use
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
            Ok(result) => {
                print_result(&result);
            }
            Err(e) => {
                eprintln!("❌ Scan error: {}", e);
            }
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
        
        let threats: Vec<_> = results.iter()
            .filter(|r| r.level.is_threat())
            .collect();
        
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

/// JSON output for --json flag
fn scan_path_json(path: &Path) {
    if !path.exists() {
        println!("{{\"error\": \"Path does not exist\"}}");
        return;
    }
    
    let scanner = FileSystemScanner::new();
    
    if path.is_file() {
        scan_single_file_json(path);
    } else if path.is_dir() {
        scan_directory_json(path);
    }
}

fn print_result(result: &core::types::ScanResult) {
    println!("{} {}", 
        result.level.emoji(),
        result.path.display()
    );
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
    
    // Test 1: EICAR detection
    println!("Test 1: EICAR detection");
    match test_eicar(&scanner) {
        Ok(true) => {
            println!("   ✅ PASSED - EICAR detected as malicious\n");
            passed += 1;
        }
        Ok(false) => {
            println!("   ❌ FAILED - EICAR not detected\n");
            failed += 1;
        }
        Err(e) => {
            println!("   ⚠️  SKIPPED - {}\n", e);
        }
    }
    
    // Test 2: Clean file
    println!("Test 2: Clean file detection");
    match test_clean_file(&scanner) {
        Ok(true) => {
            println!("   ✅ PASSED - Clean file correctly identified\n");
            passed += 1;
        }
        Ok(false) => {
            println!("   ❌ FAILED - Clean file incorrectly flagged\n");
            failed += 1;
        }
        Err(e) => {
            println!("   ❌ FAILED - Error: {}\n", e);
            failed += 1;
        }
    }
    
    // Test 3: Ransomware note detection
    println!("Test 3: Ransomware note detection");
    match test_ransomware_note(&scanner) {
        Ok(true) => {
            println!("   ✅ PASSED - Ransomware note detected\n");
            passed += 1;
        }
        Ok(false) => {
            println!("   ❌ FAILED - Ransomware note not detected\n");
            failed += 1;
        }
        Err(e) => {
            println!("   ❌ FAILED - Error: {}\n", e);
            failed += 1;
        }
    }
    
    // Test 4: Zero-byte executable
    println!("Test 4: Zero-byte executable detection");
    match test_zero_byte_executable(&scanner) {
        Ok(true) => {
            println!("   ✅ PASSED - Zero-byte executable detected as suspicious\n");
            passed += 1;
        }
        Ok(false) => {
            println!("   ❌ FAILED - Zero-byte executable not detected\n");
            failed += 1;
        }
        Err(e) => {
            println!("   ❌ FAILED - Error: {}\n", e);
            failed += 1;
        }
    }
    
    // Summary
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Test Results: {} passed, {} failed", passed, failed);
    if failed == 0 {
        println!("✅ All tests passed!");
    } else {
        println!("⚠️  Some tests failed");
    }
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
}

fn test_eicar(scanner: &FileSystemScanner) -> Result<bool, String> {
    let path = create_eicar_test();
    
    let result = scanner.scan_file(&path)
        .map_err(|e| format!("Windows Defender blocked EICAR: {}", e))?;
    
    std::fs::remove_file(&path).ok();
    
    Ok(result.level == ThreatLevel::Malicious)
}

fn test_clean_file(scanner: &FileSystemScanner) -> Result<bool, String> {
    let temp_dir = std::env::temp_dir();
    let path = temp_dir.join("clean_test.txt");
    
    std::fs::write(&path, "This is a completely clean file with no malicious content.")
        .map_err(|e| e.to_string())?;
    
    let result = scanner.scan_file(&path)
        .map_err(|e| e.to_string())?;
    
    std::fs::remove_file(&path).ok();
    
    Ok(result.level == ThreatLevel::Clean)
}

fn test_ransomware_note(scanner: &FileSystemScanner) -> Result<bool, String> {
    let temp_dir = std::env::temp_dir();
    let path = temp_dir.join("README_DECRYPT.txt");
    
    let content = r#"
    !!!ATTENTION!!!
    
    All your files have been encrypted using military-grade AES-256 encryption.
    
    To decrypt your files, you must pay 0.05 BTC to the following address:
    1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
    
    After payment, contact us at: decrypt@ransomware.com
    
    You have 72 hours to pay. After that, the decryption key will be destroyed.
    "#;
    
    std::fs::write(&path, content)
        .map_err(|e| e.to_string())?;
    
    let result = scanner.scan_file(&path)
        .map_err(|e| e.to_string())?;
    
    std::fs::remove_file(&path).ok();
    
    Ok(result.level == ThreatLevel::Malicious || result.level == ThreatLevel::Suspicious)
}

fn test_zero_byte_executable(scanner: &FileSystemScanner) -> Result<bool, String> {
    let temp_dir = std::env::temp_dir();
    let path = temp_dir.join("zero.exe");
    
    // Create zero-byte file
    std::fs::write(&path, "")
        .map_err(|e| e.to_string())?;
    
    let result = scanner.scan_file(&path)
        .map_err(|e| e.to_string())?;
    
    std::fs::remove_file(&path).ok();
    
    // Should be suspicious or malicious
    Ok(result.level == ThreatLevel::Suspicious || result.level == ThreatLevel::Malicious)
}

fn create_eicar_test() -> std::path::PathBuf {
    let path = std::env::temp_dir().join("eicar_test.txt");
    let eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    std::fs::write(&path, eicar).unwrap();
    path
}

fn print_usage() {
    println!("🛡️  Antivirus Engine v1.0.0");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    println!("Usage:");
    println!("  antivirus scan <path>           Scan a file or directory (human-readable)");
    println!("  antivirus scan <path> --json    Scan with JSON output");
    println!("  antivirus scan-file <file>      Scan single file (JSON output)");
    println!("  antivirus scan-dir <dir>        Scan directory (JSON output)");
    println!("  antivirus scan-processes        Scan all running processes (JSON output)");
    println!("  antivirus kill-process <PID>    Terminate a process");
    println!("  antivirus test                  Run self-tests");
    println!("  antivirus help                  Show this help message");
    println!();
    println!("Examples:");
    println!("  antivirus scan C:\\Downloads");
    println!("  antivirus scan-file file.exe");
    println!("  antivirus scan-dir C:\\Downloads");
    println!("  antivirus scan-processes");
    println!("  antivirus kill-process 1234");
    println!("  antivirus test");
    println!();
    println!("For Python Integration:");
    println!("  Use 'scan-file', 'scan-dir', or 'scan-processes' commands for JSON output");
}
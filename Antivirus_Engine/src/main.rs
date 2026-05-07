// File: antivirus_engine/src/main.rs
// JSON-Compatible Antivirus Scanner with Process Monitoring + Daemon Mode

mod core;

use core::file_system::scanner::FileSystemScanner;
use core::file_system::scan_all::SystemScanner;
use core::memory::scanner::MemoryScanner;
use core::network::NetworkScanner;
use core::process::ProcessScanner;
use core::process::output::serialize_process;
use core::types::ThreatLevel;

// Post-verdict containment actions
use core::action::{
    block_ip, check_persistence, dump_memory, isolate_network,
    quarantine_file, remove_block_ip, restore_network,
};

// Entity + graph layer
use core::entity::{
    EntityManager, EntityCorrelator, CorrelatedCluster, JoinReason, EntityNode,
};
use core::graph::{GraphAnalyzer, GraphNode, GraphEdge, AttackChain, CriticalPath, build_from_aggregated};

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
        "scan-memory" => {
            if args.len() >= 3 {
                if let Ok(pid) = args[2].parse::<u32>() {
                    scan_memory_json(Some(pid));
                } else {
                    println!("{{\"success\": false, \"error\": \"Invalid PID\"}}");
                }
            } else {
                scan_memory_json(None);
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

    let scanner         = FileSystemScanner::new();
    let system_scanner  = SystemScanner::new();
    let quick_scanner   = SystemScanner::with_config(
        core::file_system::scan_all::SystemScanConfig {
            roots:           SystemScanner::quick_roots(),
            num_threads:     4,
            // Cap walk depth at 3 — keeps Temp surface-level while still
            // reaching tasks nested under System32\Tasks\Microsoft\Windows\*
            max_depth:       Some(3),
            // After the prioritizer sorts highest-risk files first, discard
            // everything beyond 2 000 candidates.  This bounds quick-scan
            // time regardless of how many files are in %TEMP%.
            max_files:       Some(2_000),
            // SHA-256 only — no need for MD5 + SHA-512 on a quick pass.
            enable_multi_hash: false,
            ..core::file_system::scan_all::SystemScanConfig::default()
        },
    );
    let process_scanner = ProcessScanner::new();
    let network_scanner = NetworkScanner::new();
    // FIX: MemoryScanner is now created once here instead of being
    // re-created on every scan-memory request. Each new() previously
    // triggered a fresh System allocation internally when scan_processes
    // was called, compounding the RAM spike with every daemon request.
    let memory_scanner  = MemoryScanner::new();

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
            "scan-file"      => {
                let path = request["path"].as_str().unwrap_or("");
                daemon_scan_file(&scanner, Path::new(path), &id)
            }
            "scan-all"       => daemon_scan_all(&system_scanner, &id),
            "quick-scan"     => daemon_scan_all(&quick_scanner, &id),
            "scan-dir"       => {
                let path = request["path"].as_str().unwrap_or("");
                daemon_scan_dir(&scanner, Path::new(path), &id)
            }
            "scan-processes" => daemon_scan_processes(&process_scanner, &id),
            "scan-network"   => daemon_scan_network(
                &network_scanner,
                request["pid"].as_u64().map(|v| v as u32),
                &id,
            ),
            // FIX: pass &memory_scanner instead of allocating a new one per call.
            "scan-memory"    => daemon_scan_memory(
                &memory_scanner,
                request["pid"].as_u64().map(|v| v as u32),
                &id,
            ),
            "kill-process"   => {
                let pid = request["pid"].as_u64().unwrap_or(0) as u32;
                daemon_kill_process(&process_scanner, pid, &id)
            }
            // ── Post-verdict containment actions ─────────────────────────────
        "quarantine-file" => {
            let path = request["path"].as_str().unwrap_or("");
            daemon_quarantine_file(path, &id)
        }
        "block-ip" => {
            let remote_ip = request["remote_ip"].as_str().unwrap_or("");
            let direction = request["direction"].as_str().unwrap_or("out");
            daemon_block_ip(remote_ip, direction, &id)
        }
        "remove-block-ip" => {
            let rule_name = request["rule_name"].as_str().unwrap_or("");
            daemon_remove_block_ip(rule_name, &id)
        }
        "dump-memory" => {
            let pid = request["pid"].as_u64().unwrap_or(0) as u32;
            daemon_dump_memory(pid, &id)
        }
        "check-persistence" => {
            let paths: Vec<String> = request["suspicious_paths"]
                .as_array()
                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                .unwrap_or_default();
            daemon_check_persistence(&paths, &id)
        }
        "isolate-network" => daemon_isolate_network(&id),
        "restore-network" => daemon_restore_network(&id),

        "correlate" => daemon_correlate(
                &scanner,
                &process_scanner,
                &network_scanner,
                &memory_scanner,
                request["include_memory"].as_bool().unwrap_or(false),
                &id,
            ),
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

// ─── Shared memory region serializer ─────────────────────────────────────────

fn serialize_memory_region(r: &crate::core::memory::scanner::MemoryRegion) -> serde_json::Value {
    let signals: Vec<serde_json::Value> = r.detection_signals.iter()
        .map(|s| json!({
            "source":      s.source,
            "description": s.description,
            "score":       s.score,
        }))
        .collect();

    json!({
        "pid":               r.pid,
        "process_name":      r.process_name,
        "process_path":      r.process_path,
        "command_line":      r.command_line,
        "region_start":      r.region_start,
        "region_size":       r.region_size,
        "protection":        r.protection,
        "is_executable":     r.is_executable,
        "is_writable":       r.is_writable,
        "is_readable":       r.is_readable,
        "is_committed":      r.is_committed,
        "is_private":        r.is_private,
        "content_sample":    r.content_sample,
        "threat_level":      r.threat_level,
        "threat_score":      r.threat_score,
        "is_threat":         r.is_threat,
        "detection_signals": signals,
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

/// Full-system scan using [`SystemScanner`] (thread pool + incremental cache +
/// [`ScanPrioritizer`]).  Returns the same JSON shape as `daemon_scan_dir` so
/// the Tauri frontend can parse results identically.
///
/// Unlike `daemon_scan_dir`, this command:
/// - Uses multiple worker threads (no 300-second timeout risk on large roots).
/// - Applies the incremental mtime+size cache — unchanged files from the last
///   scan are served instantly without re-reading disk.
/// - Sorts the queue by risk score before dispatching, so threats surface first.
fn daemon_scan_all(scanner: &SystemScanner, id: &str) -> serde_json::Value {
    eprintln!("DAEMON scan-all: starting system scan (thread pool + cache)");
    let result = scanner.scan(None);

    let files: Vec<serde_json::Value> = result.results.iter()
        .map(serialize_result)
        .collect();

    let total_size_mb = result.stats.total_size_scanned as f64 / 1024.0 / 1024.0;

    json!({
        "id":      id,
        "success": true,
        "statistics": {
            "total_files":      result.stats.total_files,
            "clean_files":      result.stats.clean_files,
            "suspicious_files": result.stats.suspicious_files,
            "malicious_files":  result.stats.malicious_files,
            "error_files":      result.stats.error_files,
            "total_size_mb":    total_size_mb,
            "skipped_files":    result.skipped_files,
            "cached_hits":      result.cached_hits,
            "duration_secs":    result.duration_secs,
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

// FIX: now accepts &MemoryScanner instead of allocating a new one each call.
fn daemon_scan_memory(scanner: &MemoryScanner, pid: Option<u32>, id: &str) -> serde_json::Value {
    match scanner.scan_processes(pid) {
        Ok((regions, stats)) => json!({
            "id":      id,
            "success": true,
            "statistics": {
                "total_regions":       stats.total_regions,
                "scanned_processes":   stats.scanned_processes,
                "suspicious_regions":  stats.suspicious_regions,
                "malicious_regions":   stats.malicious_regions,
                "total_bytes_scanned": stats.total_bytes_scanned,
                "scan_duration_ms":    stats.scan_duration_ms,
            },
            "regions": regions.iter().map(serialize_memory_region).collect::<Vec<_>>(),
        }),
        Err(e) => json!({ "id": id, "success": false, "error": e.to_string() }),
    }
}

// ─── Action daemon handlers ───────────────────────────────────────────────────

/// Move a file into the AegisAI quarantine folder.
///
/// Calls `quarantine_file(path)` and wraps the result in a JSON response
/// suitable for returning directly to the Tauri IPC caller.
fn daemon_quarantine_file(path: &str, id: &str) -> serde_json::Value {
    let r = quarantine_file(path);
    if r.success {
        json!({
            "id":              id,
            "success":         true,
            "quarantine_path": r.quarantine_path,
            "sha256":          r.sha256,
        })
    } else {
        json!({ "id": id, "success": false, "error": r.error })
    }
}

/// Add a Windows Firewall outbound (or bidirectional) deny rule for `remote_ip`.
///
/// Returns the generated rule name so the caller can later call
/// `remove-block-ip` to roll it back.
fn daemon_block_ip(remote_ip: &str, direction: &str, id: &str) -> serde_json::Value {
    let r = block_ip(remote_ip, direction);
    if r.success {
        json!({ "id": id, "success": true, "rule_name": r.rule_name })
    } else {
        json!({ "id": id, "success": false, "error": r.error })
    }
}

/// Remove a previously created AegisAI firewall rule.
fn daemon_remove_block_ip(rule_name: &str, id: &str) -> serde_json::Value {
    match remove_block_ip(rule_name) {
        Ok(())  => json!({ "id": id, "success": true }),
        Err(e)  => json!({ "id": id, "success": false, "error": e }),
    }
}

/// Write a full `MiniDumpWithFullMemory` dump of `pid` to the AegisAI dumps dir.
///
/// Returns the absolute path to the `.dmp` file on success.
fn daemon_dump_memory(pid: u32, id: &str) -> serde_json::Value {
    let r = dump_memory(pid);
    if r.success {
        json!({ "id": id, "success": true, "dump_path": r.dump_path })
    } else {
        json!({ "id": id, "success": false, "error": r.error })
    }
}

/// Scan registry run keys, scheduled tasks, and startup folders for persistence
/// mechanisms.  `suspicious_paths` are cross-referenced against each entry.
fn daemon_check_persistence(suspicious_paths: &[String], id: &str) -> serde_json::Value {
    let r = check_persistence(suspicious_paths);
    let entries: Vec<serde_json::Value> = r.entries.iter().map(|e| json!({
        "kind":       e.kind,
        "name":       e.name,
        "path":       e.path,
        "sha256":     e.sha256,
        "suspicious": e.suspicious,
    })).collect();

    json!({ "id": id, "success": r.success, "entries": entries, "error": r.error })
}

/// Disable all connected network interfaces to cut off C2 communications.
///
/// Returns the list of disabled adapter names.  Call `restore-network` to
/// re-enable them after the incident is resolved.
fn daemon_isolate_network(id: &str) -> serde_json::Value {
    let r = isolate_network();
    json!({
        "id":                   id,
        "success":              r.success,
        "disabled_interfaces":  r.disabled_interfaces,
        "error":                r.error,
    })
}

/// Re-enable all adapters saved by the last `isolate-network` call.
fn daemon_restore_network(id: &str) -> serde_json::Value {
    match restore_network() {
        Ok(())  => json!({ "id": id, "success": true }),
        Err(e)  => json!({ "id": id, "success": false, "error": e }),
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
                Ok(c)  => c,
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
            "total_connections":       stats.total_connections,
            "suspicious_connections":  stats.suspicious_connections,
            "malicious_connections":   stats.malicious_connections,
            "local_listeners":         stats.local_listeners,
            "established_connections": stats.established_connections,
            "scan_duration_ms":        stats.scan_duration_ms,
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
        "protocol":          c.protocol,
        "local_address":     c.local_address,
        "remote_address":    c.remote_address,
        "state":             c.state,
        "pid":               c.pid,
        "process_name":      c.process_name,
        "threat_level":      c.threat_level.as_str(),
        "threat_score":      c.threat_score,
        "is_threat":         c.is_threat,
        "detection_signals": signals,
    })
}

fn daemon_scan_network(scanner: &NetworkScanner, pid: Option<u32>, id: &str) -> serde_json::Value {
    let result = match pid {
        Some(pid) => scanner.scan_by_pid(pid).map(|connections| {
            let stats = scanner.get_statistics(&connections);
            json!({
                "id":      id,
                "success": true,
                "statistics": {
                    "total_connections":       stats.total_connections,
                    "suspicious_connections":  stats.suspicious_connections,
                    "malicious_connections":   stats.malicious_connections,
                    "local_listeners":         stats.local_listeners,
                    "established_connections": stats.established_connections,
                    "scan_duration_ms":        stats.scan_duration_ms,
                },
                "connections": connections.iter().map(serialize_network_connection).collect::<Vec<_>>(),
            })
        }),
        None => scanner.scan().map(|(connections, stats)| {
            json!({
                "id":      id,
                "success": true,
                "statistics": {
                    "total_connections":       stats.total_connections,
                    "suspicious_connections":  stats.suspicious_connections,
                    "malicious_connections":   stats.malicious_connections,
                    "local_listeners":         stats.local_listeners,
                    "established_connections": stats.established_connections,
                    "scan_duration_ms":        stats.scan_duration_ms,
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

// ─── One-shot memory scan (CLI) ───────────────────────────────────────────────

fn scan_memory_json(pid: Option<u32>) {
    let scanner = MemoryScanner::new();
    match scanner.scan_processes(pid) {
        Ok((regions, stats)) => {
            let regions_json: Vec<serde_json::Value> =
                regions.iter().map(serialize_memory_region).collect();

            println!("{}", json!({
                "success": true,
                "statistics": {
                    "total_regions":       stats.total_regions,
                    "scanned_processes":   stats.scanned_processes,
                    "suspicious_regions":  stats.suspicious_regions,
                    "malicious_regions":   stats.malicious_regions,
                    "total_bytes_scanned": stats.total_bytes_scanned,
                    "scan_duration_ms":    stats.scan_duration_ms,
                },
                "regions": regions_json,
            }));
        }
        Err(e) => println!("{{\"success\": false, \"error\": \"{}\"}}", e),
    }
}

// ─── Entity / graph serialization ────────────────────────────────────────────

fn serialize_entity_node(node: &EntityNode) -> serde_json::Value {
    use core::entity::types::EntityAttributes;

    let join_keys = json!({
        "pid":         node.join_keys.pid,
        "parent_pid":  node.join_keys.parent_pid,
        "file_path":   node.join_keys.file_path,
        "file_hash":   node.join_keys.file_hash,
        "remote_ip":   node.join_keys.remote_ip,
        "remote_port": node.join_keys.remote_port,
    });

    let signals: Vec<serde_json::Value> = node.detection_signals.iter()
        .map(|s| json!({ "source": s.source, "description": s.description, "score": s.score }))
        .collect();

    // Derive display labels from type-specific attributes
    let (label, sub_label) = match &node.attributes {
        EntityAttributes::Process(p) => (
            p.name.clone(),
            p.exe_path.clone(),
        ),
        EntityAttributes::File(f) => {
            let name = std::path::Path::new(&f.path)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| f.path.clone());
            (name, Some(f.path.clone()))
        }
        EntityAttributes::Network(n) => (
            format!("{} → {}", n.protocol.to_uppercase(), n.remote_address),
            n.process_name.as_ref().map(|pn| format!("{} · {}", pn, n.state)),
        ),
        EntityAttributes::Memory(m) => (
            format!("{} @ {:#x}", m.process_name, m.region_start),
            Some(format!("{} · {} KB", m.protection, m.region_size / 1024)),
        ),
    };

    json!({
        "entity_id":         node.entity_id,
        "entity_type":       node.entity_type.as_str(),
        "threat_level":      node.threat_level.as_str(),
        "combined_score":    node.combined_score(),
        "heuristic_score":   node.heuristic_score,
        "ml_score":          node.ml_score,
        "join_keys":         join_keys,
        "detection_signals": signals,
        "label":             label,
        "sub_label":         sub_label,
    })
}

fn serialize_cluster(cluster: &CorrelatedCluster) -> serde_json::Value {
    let members: Vec<serde_json::Value> = cluster.members.iter()
        .map(serialize_entity_node)
        .collect();

    let join_reason = match &cluster.join_reason {
        JoinReason::SharedPid(pid) =>
            json!({ "type": "SharedPid", "pid": pid }),
        JoinReason::ParentChildChain { parent_pid, child_pid } =>
            json!({ "type": "ParentChildChain", "parent_pid": parent_pid, "child_pid": child_pid }),
        JoinReason::SharedRemoteIp(ip) =>
            json!({ "type": "SharedRemoteIp", "ip": ip }),
        JoinReason::SharedFileHash(hash) =>
            json!({ "type": "SharedFileHash", "hash": hash }),
    };

    json!({
        "anchor_id":       cluster.anchor_id,
        "members":         members,
        "join_reason":     join_reason,
        "cluster_score":   cluster.cluster_score,
        "has_threat":      cluster.has_threat,
        "max_threat_level": cluster.max_threat_level().as_str(),
    })
}

fn serialize_graph_node(node: &GraphNode) -> serde_json::Value {
    json!({
        "entity_id":             node.entity_id,
        "entity_type":           node.entity_type,
        "threat_level":          node.threat_level,
        "combined_score":        node.combined_score,
        "heuristic_score":       node.heuristic_score,
        "ml_score":              node.ml_score,
        "label":                 node.label,
        "sub_label":             node.sub_label,
        "process_score":         node.process_score,
        "network_score":         node.network_score,
        "memory_score":          node.memory_score,
        "file_score":            node.file_score,
        "has_malicious_network": node.has_malicious_network,
        "has_malicious_memory":  node.has_malicious_memory,
        "has_malicious_file":    node.has_malicious_file,
        "pid":                   node.pid,
        "parent_pid":            node.parent_pid,
        "graph_boost":           node.graph_boost,
        "is_vector":             node.is_vector,
        "is_lolbin":             node.is_lolbin,
    })
}

fn serialize_graph_edge(edge: &GraphEdge) -> serde_json::Value {
    json!({
        "from":      edge.from,
        "to":        edge.to,
        "edge_type": edge.edge_type.as_str(),
        "weight":    edge.weight,
    })
}

fn serialize_critical_path(cp: &CriticalPath) -> serde_json::Value {
    json!({
        "node_ids":     cp.node_ids,
        "edge_types":   cp.edge_types,
        "edge_weights": cp.edge_weights,
        "total_score":  cp.total_score,
        "narrative":    cp.narrative,
    })
}

fn serialize_attack_chain(chain: &AttackChain) -> serde_json::Value {
    json!({
        "chain_id":     chain.chain_id,
        "pattern":      chain.pattern.as_str(),
        "node_ids":     chain.node_ids,
        "chain_score":  chain.chain_score,
        "severity":     chain.severity,
        "description":  chain.description,
        "mitre_tactic": chain.mitre_tactic,
        "confidence":   chain.confidence,
    })
}

// ─── ML pipeline helper ───────────────────────────────────────────────────────

/// Locate the preprocessing_pipeline.py script relative to the engine binary.
///
/// Layout:  Antivirus_Engine/target/{profile}/antivirus.exe
///          Antivirus_Engine/src/core/network/Feature_extractor/ML_IDS/preprocessing_pipeline.py
fn find_ml_script() -> Option<std::path::PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let engine_root = exe
        .parent()?   // {profile}/
        .parent()?   // target/
        .parent()?;  // Antivirus_Engine/

    let script = engine_root
        .join("src").join("core").join("network")
        .join("Feature_extractor").join("ML_IDS")
        .join("preprocessing_pipeline.py");

    if script.exists() { Some(script) } else { None }
}

/// Run the ML IDS pipeline on the OnePace.csv written by the network scanner,
/// then patch `ml_score` into each matching network entity in the manager.
///
/// Silently no-ops if Python is unavailable or the CSV is missing — the graph
/// falls back to heuristic-only scoring in that case.
fn run_ml_and_patch_scores(manager: &EntityManager) {
    let Some(script) = find_ml_script() else { return; };

    let csv = {
        let home = std::env::var("USERPROFILE")
            .unwrap_or_else(|_| "C:\\Users\\Public".to_string());
        format!("{}\\OnePace.csv", home)
    };

    for py in &["python", "python3", "py"] {
        let output = match std::process::Command::new(py)
            .args([script.to_str().unwrap_or(""), "--infer", "--csv", &csv])
            .output()
        {
            Ok(o) if o.status.success() => o,
            _                           => continue,
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        let result: serde_json::Value = match serde_json::from_str(stdout.trim()) {
            Ok(v) => v,
            Err(_) => break,
        };

        if let Some(flows) = result["flows"].as_array() {
            for flow in flows {
                let proto  = flow["proto"].as_str().unwrap_or("").to_uppercase();
                let srcip  = flow["srcip"].as_str().unwrap_or("");
                let sport  = flow["sport"].as_u64().unwrap_or(0);
                let dstip  = flow["dstip"].as_str().unwrap_or("");
                let dsport = flow["dsport"].as_u64().unwrap_or(0);
                let prob   = flow["probability"].as_f64().unwrap_or(0.0) as f32;

                if prob < 0.01 { continue; }

                // Reconstruct the entity_id format used by manager.ingest_network:
                //   net:{proto}:{local_address}:{remote_address}
                // where local = srcip:sport, remote = dstip:dsport.
                let entity_id = format!("net:{}:{}:{}:{}:{}", proto, srcip, sport, dstip, dsport);
                manager.update_ml_score(&entity_id, prob);
            }
        }
        break; // successfully ran — no need to try other interpreters
    }
}

// ─── Daemon correlate ─────────────────────────────────────────────────────────

/// Run all background scanners, build the entity graph, run attack-chain
/// analysis, and return a comprehensive JSON payload.
///
/// `include_memory` controls whether the (slow) memory scanner is included.
/// When false the graph uses only process and network entities; when true all
/// four entity types are included.
fn daemon_correlate(
    file_scanner:    &FileSystemScanner,
    process_scanner: &ProcessScanner,
    network_scanner: &NetworkScanner,
    memory_scanner:  &MemoryScanner,
    include_memory:  bool,
    id: &str,
) -> serde_json::Value {
    let t0 = std::time::Instant::now();

    // 10-minute sliding window — matches the EntityManager default
    let manager = EntityManager::new(600);

    // ── Ingest: Process scanner ───────────────────────────────────────────────
    let mut proc_count   = 0usize;
    let mut net_count    = 0usize;
    let mut mem_count    = 0usize;

    eprintln!("CORRELATE: starting process scan...");
    let t_proc = std::time::Instant::now();
    match process_scanner.scan_all_processes() {
        Ok(processes) => {
            proc_count = processes.len();
            eprintln!("CORRELATE: process scan done in {}ms — {} processes", t_proc.elapsed().as_millis(), proc_count);

            for p in &processes {
                manager.ingest_process(p);
            }

            // Only YARA-scan the exe of *confirmed malicious/critical* processes,
            // capped at 5 to avoid spending minutes on false-positive Suspicious ones.
            // Suspicious processes are too noisy (many legit system processes score
            // there) and each file scan is a full YARA + SHA-256 + heuristics pass.
            use core::process::types::ThreatLevel as ProcThreat;
            let exe_scan_candidates: Vec<_> = processes.iter()
                .filter(|p| matches!(p.threat_level, ProcThreat::Malicious | ProcThreat::Critical))
                .filter_map(|p| p.exe_path.as_ref().map(|e| (p, e.clone())))
                .take(5)
                .collect();

            eprintln!("CORRELATE: scanning {} confirmed-malicious exe files...", exe_scan_candidates.len());
            let t_exe = std::time::Instant::now();
            for (_, exe) in &exe_scan_candidates {
                if let Ok(result) = file_scanner.scan_file(Path::new(exe.as_str())) {
                    manager.ingest_file(&result);
                }
            }
            eprintln!("CORRELATE: exe file scans done in {}ms", t_exe.elapsed().as_millis());
        }
        Err(e) => eprintln!("CORRELATE: process scan error: {}", e),
    }

    // ── Ingest: Network scanner ───────────────────────────────────────────────
    eprintln!("CORRELATE: starting network scan...");
    let t_net = std::time::Instant::now();
    match network_scanner.scan() {
        Ok((connections, _)) => {
            net_count = connections.len();
            eprintln!("CORRELATE: network scan done in {}ms — {} connections", t_net.elapsed().as_millis(), net_count);
            for conn in &connections { manager.ingest_network(conn, None); }
        }
        Err(e) => eprintln!("CORRELATE: network scan error: {}", e),
    }

    // Fix #1: Run the ML pipeline on the OnePace.csv written by the network
    // scanner above and patch ml_score into each matching network entity.
    eprintln!("CORRELATE: running ML pipeline...");
    let t_ml = std::time::Instant::now();
    run_ml_and_patch_scores(&manager);
    eprintln!("CORRELATE: ML pipeline done in {}ms", t_ml.elapsed().as_millis());

    // Fix #3: Boost child-process scores when their parent is a threat.
    manager.apply_parent_context_boost();

    // ── Ingest: Memory scanner (optional) ────────────────────────────────────
    if include_memory {
        eprintln!("CORRELATE: starting memory scan...");
        let t_mem = std::time::Instant::now();
        match memory_scanner.scan_processes(None) {
            Ok((regions, _)) => {
                // ingest_memory already filters to is_threat == true
                for region in &regions { manager.ingest_memory(region); }
                mem_count = manager.len().saturating_sub(proc_count + net_count);
                eprintln!("CORRELATE: memory scan done in {}ms — {} threat regions", t_mem.elapsed().as_millis(), mem_count);
            }
            Err(e) => eprintln!("CORRELATE: memory scan error: {}", e),
        }
    }

    // ── Backfill structural stubs for untracked PIDs ──────────────────────────
    // Memory and network signals may reference PIDs that the process scanner
    // never ingested (e.g. the process died between scans, or the process
    // scanner errored).  For each such PID, do a cheap sysinfo lookup to get
    // name + parent_pid + exe_path so the graph can draw ParentChild edges.
    {
        use std::collections::HashSet;
        use core::entity::types::EntityType;
        use core::process::types::fetch_process_metadata;

        let all_nodes = manager.get_all();

        let process_pids: HashSet<u32> = all_nodes.iter()
            .filter(|n| n.entity_type == EntityType::Process)
            .filter_map(|n| n.join_keys.pid)
            .collect();

        let orphan_pids: HashSet<u32> = all_nodes.iter()
            .filter(|n| n.entity_type != EntityType::Process)
            .filter_map(|n| n.join_keys.pid)
            .filter(|pid| !process_pids.contains(pid))
            .collect();

        for pid in orphan_pids {
            if let Some(meta) = fetch_process_metadata(pid) {
                manager.ingest_process_stub(&meta);
            }
        }
    }

    // ── Build aggregated entity graph ─────────────────────────────────────────
    eprintln!("CORRELATE: building entity graph...");
    let t_graph = std::time::Instant::now();
    let aggregated = manager.aggregate();
    let mut graph  = build_from_aggregated(&aggregated);

    let attack_chains = GraphAnalyzer::find_attack_chains_aggregated(&graph);
    graph.attack_chains = attack_chains;

    let critical_path = GraphAnalyzer::find_critical_path(&graph);
    graph.critical_path = critical_path;

    // Refinement pass: push graph findings (critical-path position, centrality,
    // vector proximity) back into node scores and flags.
    GraphAnalyzer::apply_graph_feedback(&mut graph);

    // Recompute stored GraphEdge weights from the updated node scores so that
    // the serialized edge.weight values reflect the post-feedback combined_scores.
    graph.refresh_edge_weights();

    eprintln!("CORRELATE: graph done in {}ms — {} nodes, {} edges, {} chains",
        t_graph.elapsed().as_millis(), graph.nodes.len(), graph.edges.len(), graph.attack_chains.len());

    // ── Build correlator clusters ─────────────────────────────────────────────
    let correlator = EntityCorrelator::new(&manager);
    let all_clusters    = correlator.find_all_clusters();
    let threat_clusters = all_clusters.iter().filter(|c| c.has_threat).count();

    // ── Serialize ─────────────────────────────────────────────────────────────
    let entities_json: Vec<serde_json::Value> = manager.get_all().iter()
        .map(serialize_entity_node)
        .collect();

    let clusters_json: Vec<serde_json::Value> = all_clusters.iter()
        .map(serialize_cluster)
        .collect();

    let graph_nodes_json: Vec<serde_json::Value> = graph.nodes.values()
        .map(serialize_graph_node)
        .collect();

    let graph_edges_json: Vec<serde_json::Value> = graph.edges.iter()
        .map(serialize_graph_edge)
        .collect();

    let chains_json: Vec<serde_json::Value> = graph.attack_chains.iter()
        .map(serialize_attack_chain)
        .collect();

    let duration_ms       = t0.elapsed().as_millis() as u64;
    let total_entities    = manager.len();
    let threat_entities   = manager.get_threats().len();
    let chains_detected   = graph.attack_chains.len();

    json!({
        "id":      id,
        "success": true,
        "entities": entities_json,
        "clusters": clusters_json,
        "graph": {
            "nodes":         graph_nodes_json,
            "edges":         graph_edges_json,
            "attack_chains": chains_json,
            "critical_path": graph.critical_path.as_ref().map(serialize_critical_path),
        },
        "statistics": {
            "total_entities":        total_entities,
            "threat_entities":       threat_entities,
            "process_entities":      proc_count,
            "network_entities":      net_count,
            "memory_entities":       mem_count,
            "total_clusters":        all_clusters.len(),
            "threat_clusters":       threat_clusters,
            "graph_nodes":           graph.nodes.len(),
            "graph_edges":           graph.edges.len(),
            "attack_chains_detected": chains_detected,
            "include_memory":        include_memory,
            "scan_duration_ms":      duration_ms,
        }
    })
}

// ─── Remaining CLI helpers ────────────────────────────────────────────────────

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
    println!("  antivirus daemon                  Run as persistent daemon (used by Tauri)");
    println!("  antivirus scan <path>             Scan a file or directory");
    println!("  antivirus scan <path> --json      Scan with JSON output");
    println!("  antivirus scan-file <file>        Scan single file (JSON)");
    println!("  antivirus scan-dir <dir>          Scan directory (JSON)");
    println!("  antivirus scan-processes          Scan running processes (JSON)");
    println!("  antivirus scan-network            Scan system network connections (JSON)");
    println!("  antivirus scan-network-pid <PID>  Scan network connections for a process (JSON)");
    println!("  antivirus scan-memory             Scan process memory regions (JSON)");
    println!("  antivirus kill-process <PID>      Terminate a process");
    println!("  antivirus test                    Run self-tests");
}
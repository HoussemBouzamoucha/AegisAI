// File: antivirus_engine/src/main.rs
// JSON-Compatible Antivirus Scanner with Process Monitoring + Daemon Mode

mod core;

use core::file_system::scanner::FileSystemScanner;
use core::file_system::scan_all::{SystemScanner, ScanScheduler};
use core::file_system::realtime::RealTimeWatcher;
use core::memory::scanner::MemoryScanner;
use core::network::NetworkScanner;
use core::process::ProcessScanner;
use core::process::types::ProcessInfo;
use core::process::handles::handle_count_for_pid;
use core::process::output::serialize_process;
use core::types::ThreatLevel;
use std::time::Duration;

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

    let mut scanner     = FileSystemScanner::new();
    let system_scanner  = SystemScanner::new();
    let quick_scanner   = SystemScanner::with_config(
        core::file_system::scan_all::SystemScanConfig {
            roots:           SystemScanner::quick_roots(),
            // 8 threads: quick scan roots are I/O-bound on small files; more
            // threads keep the disk pipeline full without thrashing the CPU.
            num_threads:     8,
            // Cap walk depth at 3 — keeps Temp surface-level while still
            // reaching tasks nested under System32\Tasks\Microsoft\Windows\*
            max_depth:       Some(3),
            // After the prioritizer sorts highest-risk files first, discard
            // everything beyond 10_000 candidates.  Combined with the per-file
            // caps below this keeps quick-scan wall-clock time well under
            // the 900 s daemon timeout.
            max_files:       Some(10_000),
            // SHA-256 only — no need for MD5 + SHA-512 on a quick pass.
            enable_multi_hash: false,
            // Skip hash-DB lookup entirely — heuristics catch the same threats faster.
            enable_hash_db:  false,
            // Disable YARA: each worker compiles all rules via wasmtime JIT.
            // 8 concurrent compilations race on wasmtime's global engine singleton
            // and cause a non-recoverable process abort (not catchable by
            // catch_unwind).  Heuristics alone provide sufficient detection quality
            // for a surface-level quick scan.
            enable_yara:     false,
            // Hard cap at 10 MiB — same ceiling as the YARA scanner.
            max_file_bytes:  10 * 1024 * 1024,
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

    // ── Background scheduled full-system scan (every 6 hours) ────────────────
    // Uses the builder API so all SchedulerBuilder methods are exercised.
    // The scheduler lives for the daemon's lifetime — Drop impl calls stop().
    let scheduler = ScanScheduler::builder()
        .scanner(SystemScanner::new())
        .interval(Duration::from_secs(6 * 3600))
        .on_threat(|r| {
            eprintln!("[AegisAI SCHED] {:?} — {}", r.level, r.path.display());
        })
        .build();
    scheduler.start();
    eprintln!("DAEMON: background scan scheduler started (6 h interval)");
    eprintln!("DAEMON: scanner initialized, waiting for requests...");

    // Real-time file watcher — created on first "start-realtime" command.
    let mut rt_watcher: Option<RealTimeWatcher> = None;

    // Persistent Ember ML server — started eagerly so that the five LightGBM
    // models are loaded in the background while the daemon is otherwise idle.
    // By the time the user clicks "Apply ML" the warmup is already done, so
    // the 120 s first-file timeout in analyze_batch is purely a safety net.
    // If bridge.py or Python cannot be found, this is None and analyze_batch
    // falls back to the one-shot subprocess path.
    let mut ember_server: Option<crate::core::file_system::scanner::EmberServer> =
        crate::core::file_system::scanner::EmberServer::start();
    if ember_server.is_some() {
        eprintln!("DAEMON: Ember ML server starting (models loading in background)...");
    } else {
        eprintln!("DAEMON: Ember ML server unavailable — will use fallback batch mode");
    }

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
            "apply-ember-ml" => {
                let paths: Vec<String> = request["paths"]
                    .as_array()
                    .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                    .unwrap_or_default();
                daemon_apply_ember_ml(&paths, &id, &mut ember_server)
            }
            "apply-process-gru" => {
                // entries: [{pid, exe_path}, ...]
                let entries: Vec<(u32, String)> = request["entries"]
                    .as_array()
                    .map(|arr| arr.iter().filter_map(|e| {
                        let pid      = e["pid"].as_u64()? as u32;
                        let exe_path = e["exe_path"].as_str()?.to_string();
                        Some((pid, exe_path))
                    }).collect())
                    .unwrap_or_default();
                daemon_apply_process_gru(&entries, &id)
            }
            // ── Targeted process commands ─────────────────────────────────────
            "scan-process-pid" => {
                let pid = request["pid"].as_u64().unwrap_or(0) as u32;
                daemon_scan_process_pid(&process_scanner, pid, &id)
            }
            "scan-threats-only-processes" => daemon_scan_threats_only_processes(&process_scanner, &id),

            // ── Targeted network commands ─────────────────────────────────────
            "scan-listeners"            => daemon_scan_listeners(&network_scanner, &id),
            "scan-threats-only-network" => daemon_scan_threats_only_network(&network_scanner, &id),

            // ── Scan cache management ─────────────────────────────────────────
            "clear-scan-cache" => {
                system_scanner.clear_cache();
                json!({ "id": id, "success": true, "message": "scan cache cleared" })
            }
            "score-file" => {
                let path = request["path"].as_str().unwrap_or("");
                let p    = std::path::Path::new(path);
                let meta = std::fs::metadata(p).ok();
                let size      = meta.as_ref().map(|m| m.len()).unwrap_or(0);
                let now_secs  = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
                let mtime_secs = meta.as_ref()
                    .and_then(|m| m.modified().ok())
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let score = system_scanner.prioritizer().score(p, size, mtime_secs, now_secs);
                json!({ "id": id, "success": true, "path": path, "priority_score": score })
            }

            // ── Signature database management ─────────────────────────────────
            "load-signatures" => {
                let path = request["path"].as_str().unwrap_or("");
                daemon_load_signatures(&mut scanner, path, &id)
            }
            "reload-signatures" => {
                let path = request["path"].as_str().unwrap_or("");
                daemon_reload_signatures(&mut scanner, path, &id)
            }
            "save-signatures" => {
                let path = request["path"].as_str().unwrap_or("");
                daemon_save_signatures(&scanner, path, &id)
            }
            "get-signature" => {
                let hash = request["hash"].as_str().unwrap_or("");
                daemon_get_signature(&scanner, hash, &id)
            }
            "signature-stats" => daemon_signature_stats(&scanner, &id),

            // ── YARA rule loading ─────────────────────────────────────────────
            "load-yara-rules" => {
                let dir = request["dir"].as_str().unwrap_or("");
                daemon_load_yara_rules(&mut scanner, dir, &id)
            }

            // ── Scheduler control ─────────────────────────────────────────────
            "get-scheduler-status" => {
                json!({
                    "id":         id,
                    "success":    true,
                    "running":    scheduler.is_running(),
                    "last_scan":  scheduler.last_scan_time().map(|t| {
                        t.duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs()
                    }),
                    "cache_size": scheduler.scanner().cache_size(),
                })
            }
            "trigger-scan" => {
                eprintln!("DAEMON: manual trigger of scheduled scan...");
                let result = scheduler.trigger_now(None);
                json!({
                    "id":           id,
                    "success":      true,
                    "threat_count": result.threats().count(),
                    "has_malicious":result.has_malicious(),
                    "total_files":  result.stats.total_files,
                    "duration_secs":result.duration_secs,
                    "cached_hits":  result.cached_hits,
                })
            }

            // ── Real-time file watcher ────────────────────────────────────
            "start-realtime" => {
                if rt_watcher.as_ref().map(|w| w.is_running()).unwrap_or(false) {
                    json!({ "id": id, "success": true, "already_running": true })
                } else {
                    let dirs: Vec<std::path::PathBuf> = request["dirs"]
                        .as_array()
                        .map(|arr| arr.iter()
                            .filter_map(|v| v.as_str().map(std::path::PathBuf::from))
                            .collect())
                        .unwrap_or_else(|| {
                            // Default: watch common write-heavy locations.
                            let mut dirs = vec![
                                std::path::PathBuf::from(
                                    std::env::var("USERPROFILE").unwrap_or_default()
                                ).join("Downloads"),
                                std::path::PathBuf::from(
                                    std::env::var("TEMP").unwrap_or_default()
                                ),
                            ];
                            // Test/dev directory — Defender-excluded safe drop zone.
                            let test_dir = std::path::PathBuf::from(r"C:\TestAV");
                            if test_dir.is_dir() { dirs.push(test_dir); }
                            dirs
                        });
                    let auto_q = request["auto_quarantine"].as_bool().unwrap_or(false);
                    let mut watcher = RealTimeWatcher::new(auto_q);
                    match watcher.start(dirs.clone()) {
                        Ok(()) => {
                            let dir_strs: Vec<String> = dirs.iter()
                                .map(|d| d.display().to_string())
                                .collect();
                            rt_watcher = Some(watcher);
                            json!({
                                "id":       id,
                                "success":  true,
                                "watching": dir_strs,
                                "auto_quarantine": auto_q,
                            })
                        }
                        Err(e) => json!({ "id": id, "success": false, "error": e.to_string() }),
                    }
                }
            }
            "stop-realtime" => {
                if let Some(w) = rt_watcher.take() {
                    drop(w); // Drop triggers RealTimeWatcher::stop()
                    json!({ "id": id, "success": true, "was_running": true })
                } else {
                    json!({ "id": id, "success": true, "was_running": false })
                }
            }
            "realtime-status" => {
                let running  = rt_watcher.as_ref().map(|w| w.is_running()).unwrap_or(false);
                let dirs: Vec<String> = rt_watcher.as_ref()
                    .map(|w| w.watched_dirs().iter().map(|d| d.display().to_string()).collect())
                    .unwrap_or_default();
                let threats: Vec<serde_json::Value> = rt_watcher.as_ref()
                    .map(|w| w.drain_threats().into_iter().map(|e| json!({
                        "path":           e.path.display().to_string(),
                        "level":          e.level.as_str(),
                        "reason":         e.reason,
                        "hash":           e.hash,
                        "timestamp_secs": e.timestamp_secs,
                        "quarantined":    e.quarantined,
                    })).collect())
                    .unwrap_or_default();
                json!({
                    "id":           id,
                    "success":      true,
                    "running":      running,
                    "watched_dirs": dirs,
                    "threats":      threats,
                })
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

    // Wrap in catch_unwind so a panic in the scan pipeline returns a JSON error
    // instead of killing the daemon process.  The panic message is captured and
    // forwarded to the UI, making crashes debuggable without inspecting stderr.
    let result = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| scanner.scan(None))) {
        Ok(r) => r,
        Err(e) => {
            let msg = e.downcast_ref::<&str>().map(|s| s.to_string())
                .or_else(|| e.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "unknown panic in scan engine".to_string());
            eprintln!("DAEMON scan-all PANIC: {}", msg);
            return json!({ "id": id, "success": false, "error": format!("scan engine panic: {}", msg) });
        }
    };

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

/// Run Ember2024 ML on a batch of file paths.
///
/// Uses the persistent `EmberServer` (bridge.py --server) so that LightGBM
/// models are loaded only once per daemon lifetime.  If the server has not
/// been started yet, or if it crashed, it is (re)started here before the
/// batch is processed.  Falls back to `run_ember_ml_batch` (one-shot subprocess)
/// if the server cannot be started at all.
fn daemon_apply_ember_ml(
    paths: &[String],
    id:    &str,
    server: &mut Option<crate::core::file_system::scanner::EmberServer>,
) -> serde_json::Value {
    use crate::core::file_system::scanner::{EmberServer, run_ember_ml_batch};

    let path_refs: Vec<&Path> = paths.iter().map(|s| Path::new(s.as_str())).collect();

    // (Re)start the server if it is absent or has crashed.
    if server.as_mut().map(|s| !s.is_alive()).unwrap_or(true) {
        eprintln!("EMBER SERVER: (re)starting…");
        *server = EmberServer::start();
        if server.is_none() {
            eprintln!("EMBER SERVER: could not start, falling back to batch subprocess");
        }
    }

    let results = match server.as_mut() {
        Some(s) => {
            let r = s.analyze_batch(&path_refs);
            // If the server died mid-batch, clear it so the next call restarts it.
            if !s.is_alive() { *server = None; }
            r
        }
        None => run_ember_ml_batch(&path_refs),
    };

    let entries: Vec<serde_json::Value> = results
        .into_iter()
        .map(|(path, ember)| match ember {
            Ok(e) => json!({
                "path":        path.display().to_string(),
                "skipped":     false,
                "skip_reason": null,
                "file_type":   e.file_type,
                "score":       e.score,
                "malicious":   e.malicious,
            }),
            Err(reason) => json!({
                "path":        path.display().to_string(),
                "skipped":     true,
                "skip_reason": reason,
                "file_type":   null,
                "score":       null,
                "malicious":   null,
            }),
        })
        .collect();

    json!({ "id": id, "success": true, "results": entries })
}

/// Locate `process_bridge.py` relative to the running engine binary.
///
/// Layout: Antivirus_Engine/target/{profile}/antivirus.exe
///         Antivirus_Engine/src/core/process/Sys_API/process_bridge.py
fn find_process_bridge_script() -> Option<std::path::PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let bridge_rel = ["src", "core", "process", "Sys_API", "process_bridge.py"];

    let mut candidate = exe.as_path();
    for _ in 0..5 {
        candidate = candidate.parent()?;
        let script: std::path::PathBuf = bridge_rel.iter()
            .fold(candidate.to_path_buf(), |p, s| p.join(s));
        if script.exists() {
            return Some(script);
        }
    }
    None
}

/// Run `process_bridge.py --batch` on a list of (pid, exe_path) entries.
///
/// Returns one result per input entry (in order).  Each result is a JSON
/// object with the GRU verdict or a `skipped/reason` pair on failure.
///
/// Uses a one-shot Python subprocess (batch mode) — the PyTorch model is
/// smaller than EMBER2024 so cold-start is ~5–15 s vs ~120 s for EMBER.
fn daemon_apply_process_gru(entries: &[(u32, String)], id: &str) -> serde_json::Value {
    let error_results = |reason: &str| {
        let items: Vec<serde_json::Value> = entries.iter().map(|(pid, exe)| json!({
            "pid":      pid,
            "exe_path": exe,
            "skipped":  true,
            "reason":   reason,
        })).collect();
        json!({ "id": id, "success": true, "results": items })
    };

    let script = match find_process_bridge_script() {
        Some(s) => s,
        None    => return error_results("bridge_not_found"),
    };
    let script_str = match script.to_str() {
        Some(s) => s.to_string(),
        None    => return error_results("invalid_script_path"),
    };

    // Venv-first candidate list (same logic as run_ember_ml_batch)
    let exe_bin = match std::env::current_exe() {
        Ok(e) => e,
        Err(_) => return error_results("no_current_exe"),
    };
    let engine_root = match exe_bin.parent().and_then(|p| p.parent()).and_then(|p| p.parent()) {
        Some(r) => r.to_path_buf(),
        None    => return error_results("no_engine_root"),
    };
    let venv_python = engine_root
        .parent()
        .map(|r| r.join("ai_agent").join(".venv").join("Scripts").join("python.exe"))
        .filter(|p| p.exists());

    let venv_str: Option<String> = venv_python
        .as_ref()
        .and_then(|p| p.to_str().map(|s| s.to_string()));

    let mut candidates: Vec<String> = Vec::new();
    if let Some(ref s) = venv_str { candidates.push(s.clone()); }
    candidates.extend(["python", "python3", "py"].iter().map(|s| s.to_string()));

    let exe_paths: Vec<&str> = entries.iter().map(|(_, e)| e.as_str()).collect();

    // Subprocess timeout: PyTorch cold-start (~15 s) + ~2 s/exe for PE parse + inference.
    const TIMEOUT_SECS: u64 = 120;

    for py in &candidates {
        let mut child = match std::process::Command::new(py)
            .arg(&script_str)
            .arg("--batch")
            .args(&exe_paths)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
            Ok(c) => c,
            Err(_) => continue,
        };

        // Drain stdout in a background thread (prevent pipe-buffer deadlock).
        let mut pipe = match child.stdout.take() {
            Some(s) => s,
            None => { child.kill().ok(); continue; }
        };
        let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
        std::thread::spawn(move || {
            use std::io::Read;
            let mut buf = Vec::new();
            pipe.read_to_end(&mut buf).ok();
            tx.send(buf).ok();
        });

        let start   = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(TIMEOUT_SECS);
        let mut timed_out = false;
        let success = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status.success(),
                Ok(None) if start.elapsed() >= timeout => {
                    child.kill().ok();
                    timed_out = true;
                    eprintln!(
                        "daemon_apply_process_gru: killed after {}s ({} exes)",
                        TIMEOUT_SECS, entries.len()
                    );
                    break false;
                }
                Ok(None) => std::thread::sleep(std::time::Duration::from_millis(200)),
                Err(_)   => { child.kill().ok(); break false; }
            }
        };

        if !success {
            if timed_out { break; }
            continue;
        }

        let raw = match rx.recv_timeout(std::time::Duration::from_secs(5)) {
            Ok(b)  => b,
            Err(_) => continue,
        };
        let stdout_str = match std::str::from_utf8(&raw) {
            Ok(s) => s.trim().to_string(),
            Err(_) => continue,
        };
        let arr: serde_json::Value = match serde_json::from_str(&stdout_str) {
            Ok(v)  => v,
            Err(_) => continue,
        };
        let results_arr = match arr.as_array() {
            Some(a) => a,
            None    => continue,
        };

        // Merge: attach pid back to each result (bridge only knows exe_path).
        let out: Vec<serde_json::Value> = entries.iter()
            .enumerate()
            .map(|(i, (pid, exe))| {
                let mut entry = results_arr.get(i)
                    .cloned()
                    .unwrap_or_else(|| json!({
                        "exe_path": exe,
                        "skipped":  true,
                        "reason":   "missing_result",
                    }));
                // Inject pid so Tauri/frontend can match back to ProcessInfo
                if let Some(obj) = entry.as_object_mut() {
                    obj.insert("pid".to_string(), json!(pid));
                }
                entry
            })
            .collect();

        return json!({ "id": id, "success": true, "results": out });
    }

    error_results("python_unavailable")
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

// ─── New targeted scan handlers ───────────────────────────────────────────────

/// Scan a single process by PID through the full three-stage pipeline.
///
/// On success returns the same JSON shape as `scan-processes` individual entries.
/// Also appends `live_handle_count` — a direct OS query performed after the scan.
/// On failure returns a stub built with `ProcessInfo::new` so the caller always
/// gets a well-formed object (with default/zero fields) alongside the error.
fn daemon_scan_process_pid(scanner: &ProcessScanner, pid: u32, id: &str) -> serde_json::Value {
    match scanner.scan_pid(pid) {
        Some(p) => {
            let handle_count = handle_count_for_pid(pid);
            let mut v = serialize_process(&p);
            if let Some(obj) = v.as_object_mut() {
                obj.insert("live_handle_count".to_string(), json!(handle_count));
                obj.insert("id".to_string(), json!(id));
                obj.insert("success".to_string(), json!(true));
            }
            v
        }
        None => {
            let stub = ProcessInfo::new(pid, format!("pid:{}", pid));
            json!({
                "id":      id,
                "success": false,
                "error":   format!("Process {} not found", pid),
                "pid":     stub.pid,
                "name":    stub.name,
            })
        }
    }
}

/// Return only processes whose threat level is Suspicious, Malicious, or Critical.
fn daemon_scan_threats_only_processes(scanner: &ProcessScanner, id: &str) -> serde_json::Value {
    let (threats, stats) = scanner.scan_threats_only();
    let list: Vec<serde_json::Value> = threats.iter().map(serialize_process).collect();
    json!({
        "id":      id,
        "success": true,
        "statistics": {
            "total_processes":      stats.total_processes,
            "suspicious_processes": stats.suspicious_processes,
            "malicious_processes":  stats.malicious_processes,
            "critical_processes":   stats.critical_processes,
        },
        "processes": list,
    })
}

/// Return only listening (server) sockets without scanning all connections.
fn daemon_scan_listeners(scanner: &NetworkScanner, id: &str) -> serde_json::Value {
    match scanner.scan_listeners() {
        Ok((connections, stats)) => json!({
            "id":      id,
            "success": true,
            "statistics": {
                "total_connections":  stats.total_connections,
                "local_listeners":    stats.local_listeners,
                "scan_duration_ms":   stats.scan_duration_ms,
            },
            "connections": connections.iter().map(serialize_network_connection).collect::<Vec<_>>(),
        }),
        Err(e) => json!({ "id": id, "success": false, "error": e.to_string() }),
    }
}

/// Return only connections whose threat level is Suspicious or Malicious.
fn daemon_scan_threats_only_network(scanner: &NetworkScanner, id: &str) -> serde_json::Value {
    match scanner.scan_threats_only() {
        Ok((connections, stats)) => json!({
            "id":      id,
            "success": true,
            "statistics": {
                "total_connections":       stats.total_connections,
                "suspicious_connections":  stats.suspicious_connections,
                "malicious_connections":   stats.malicious_connections,
                "scan_duration_ms":        stats.scan_duration_ms,
            },
            "connections": connections.iter().map(serialize_network_connection).collect::<Vec<_>>(),
        }),
        Err(e) => json!({ "id": id, "success": false, "error": e.to_string() }),
    }
}

// ─── YARA / signature management handlers ────────────────────────────────────

/// Load custom YARA rules from a directory and hot-swap them into the scanner.
fn daemon_load_yara_rules(scanner: &mut FileSystemScanner, dir: &str, id: &str) -> serde_json::Value {
    let path = std::path::Path::new(dir);
    match scanner.load_yara_rules(path) {
        Ok(count) => json!({ "id": id, "success": true, "rules_loaded": count }),
        Err(e)    => json!({ "id": id, "success": false, "error": e.to_string() }),
    }
}

/// Append signatures from a CSV file into the running scanner's hash database.
fn daemon_load_signatures(scanner: &mut FileSystemScanner, path: &str, id: &str) -> serde_json::Value {
    match scanner.load_signatures_from_file(std::path::Path::new(path)) {
        Ok(count) => json!({
            "id":      id,
            "success": true,
            "loaded":  count,
            "total":   scanner.signature_count(),
        }),
        Err(e) => json!({ "id": id, "success": false, "error": e.to_string() }),
    }
}

/// Clear the signature database and reload it entirely from a CSV file.
fn daemon_reload_signatures(scanner: &mut FileSystemScanner, path: &str, id: &str) -> serde_json::Value {
    match scanner.reload_signatures_from_file(std::path::Path::new(path)) {
        Ok(count) => json!({
            "id":      id,
            "success": true,
            "loaded":  count,
        }),
        Err(e) => json!({ "id": id, "success": false, "error": e.to_string() }),
    }
}

/// Persist the current in-memory signature database to a CSV file.
fn daemon_save_signatures(scanner: &FileSystemScanner, path: &str, id: &str) -> serde_json::Value {
    match scanner.save_signatures_to_file(std::path::Path::new(path)) {
        Ok(()) => json!({
            "id":      id,
            "success": true,
            "total":   scanner.signature_count(),
            "path":    path,
        }),
        Err(e) => json!({ "id": id, "success": false, "error": e.to_string() }),
    }
}

/// Look up a single hash in the signature database and return its full entry.
fn daemon_get_signature(scanner: &FileSystemScanner, hash: &str, id: &str) -> serde_json::Value {
    match scanner.lookup_signature(hash) {
        Some(entry) => json!({
            "id":          id,
            "success":     true,
            "hash":        entry.hash,
            "hash_type":   entry.hash_type.as_str(),
            "malware_name":entry.malware_name,
            "severity":    entry.severity.as_str(),
            "family":      entry.family,
            "description": entry.description,
        }),
        None => json!({ "id": id, "success": false, "error": "hash not found in database" }),
    }
}

/// Return aggregate counts grouped by hash type, severity, and malware family.
fn daemon_signature_stats(scanner: &FileSystemScanner, id: &str) -> serde_json::Value {
    let (by_type, by_sev, by_fam) = scanner.signature_stats();

    let type_map: serde_json::Map<String, serde_json::Value> =
        by_type.into_iter().map(|(k, v)| (k, json!(v))).collect();
    let sev_map: serde_json::Map<String, serde_json::Value> =
        by_sev.into_iter().map(|(k, v)| (k, json!(v))).collect();
    let fam_map: serde_json::Map<String, serde_json::Value> =
        by_fam.into_iter().map(|(k, v)| (k, json!(v))).collect();

    json!({
        "id":           id,
        "success":      true,
        "total":        scanner.signature_count(),
        "by_hash_type": type_map,
        "by_severity":  sev_map,
        "by_family":    fam_map,
    })
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
                "csv_path": scanner.csv_path().display().to_string(),
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
            // Include the PID so the UI can always show it even when exe_path is absent.
            Some(p.exe_path.as_deref()
                .map(|e| format!("PID {} — {}", p.pid, e))
                .unwrap_or_else(|| format!("PID {}", p.pid))),
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
                    // Reconstruct the entity_id that ingest_file will use so we
                    // can patch the Ember ML probability into the entity manager.
                    // Format: "file:{sha256}" if hash present, else "file:{path}".
                    let entity_id = match &result.hash {
                        Some(h) => format!("file:{}", h),
                        None    => format!("file:{}", result.path.display()),
                    };

                    // scan_file() runs Ember ML internally (Layer 4) for non-clean
                    // files and records the score in a detection signal whose
                    // description has the form:
                    //   "EMBER2024_Win64 score 0.9234 (malicious)"
                    // Extract the probability so it can be stored as ml_score.
                    let ember_score: Option<f32> = result.detection_signals.iter()
                        .find(|s| s.source == "ember_ml")
                        .and_then(|s| {
                            s.description
                                .split("score ").nth(1)
                                .and_then(|rest| rest.split_whitespace().next())
                                .and_then(|p| p.parse::<f32>().ok())
                        });

                    manager.ingest_file(&result);

                    // Patch the Ember probability into the entity's ml_score so
                    // combined_score = H×0.4 + ML×0.6 uses the file ML model.
                    if let Some(score) = ember_score {
                        manager.update_ml_score(&entity_id, score);
                        eprintln!("CORRELATE: file ML score {:.4} patched for {}", score, entity_id);
                    }
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
            "threat_node_count":     graph.threat_node_count(),
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
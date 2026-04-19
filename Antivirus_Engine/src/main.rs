// File: antivirus_engine/src/main.rs
// JSON-Compatible Antivirus Scanner with Process Monitoring + Daemon Mode

mod core;

use core::file_system::scanner::FileSystemScanner;
use core::memory::scanner::MemoryScanner;
use core::network::NetworkScanner;
use core::process::ProcessScanner;
use core::process::output::serialize_process;
use core::types::ThreatLevel;

// Entity + graph layer
use core::entity::{
    EntityManager, EntityCorrelator, CorrelatedCluster, JoinReason, EntityNode,
};
use core::graph::{GraphBuilder, GraphAnalyzer, GraphNode, GraphEdge, AttackChain, CriticalPath};

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
            "correlate" => daemon_correlate(
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
        "entity_id":       node.entity_id,
        "entity_type":     node.entity_type,
        "threat_level":    node.threat_level,
        "combined_score":  node.combined_score,
        "heuristic_score": node.heuristic_score,
        "ml_score":        node.ml_score,
        "label":           node.label,
        "sub_label":       node.sub_label,
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
    })
}

// ─── Daemon correlate ─────────────────────────────────────────────────────────

/// Run all background scanners, build the entity graph, run attack-chain
/// analysis, and return a comprehensive JSON payload.
///
/// `include_memory` controls whether the (slow) memory scanner is included.
/// When false the graph uses only process and network entities; when true all
/// four entity types are included.
fn daemon_correlate(
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

    match process_scanner.scan_all_processes() {
        Ok(processes) => {
            proc_count = processes.len();
            for p in &processes { manager.ingest_process(p); }
        }
        Err(e) => eprintln!("CORRELATE: process scan error: {}", e),
    }

    // ── Ingest: Network scanner ───────────────────────────────────────────────
    match network_scanner.scan() {
        Ok((connections, _)) => {
            net_count = connections.len();
            for conn in &connections { manager.ingest_network(conn, None); }
        }
        Err(e) => eprintln!("CORRELATE: network scan error: {}", e),
    }

    // ── Ingest: Memory scanner (optional) ────────────────────────────────────
    if include_memory {
        match memory_scanner.scan_processes(None) {
            Ok((regions, _)) => {
                // ingest_memory already filters to is_threat == true
                for region in &regions { manager.ingest_memory(region); }
                mem_count = manager.len().saturating_sub(proc_count + net_count);
            }
            Err(e) => eprintln!("CORRELATE: memory scan error: {}", e),
        }
    }

    // ── Build graph ───────────────────────────────────────────────────────────
    let builder = GraphBuilder::new(&manager);
    let mut graph = builder.build();

    let attack_chains = GraphAnalyzer::find_attack_chains(&graph);
    graph.attack_chains = attack_chains;

    let critical_path = GraphAnalyzer::find_critical_path(&graph);
    graph.critical_path = critical_path;

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
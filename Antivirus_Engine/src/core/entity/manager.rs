// File: src/core/entity/manager.rs
// EntityManager — receives raw scanner output, normalises it into EntityNodes,
// and provides correlation queries for the graph layer.
//
// Design rules:
//  - All events enter here regardless of individual score.
//    The graph decides significance, not the scanner.
//  - Network entities carry both a heuristic_score and an optional ml_score.
//    All other scanners contribute heuristic scores only.
//  - A sliding time window (window_secs) bounds the live node set.
//    Expired nodes are pruned on demand via prune_expired().

use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;

use crate::core::types::{DetectionSignal, ScanResult};
use crate::core::network::types::NetworkConnection;
use crate::core::process::types::ProcessInfo;
use crate::core::memory::scanner::MemoryRegion;

use super::types::{
    EntityAttributes, EntityNode, EntityType, FileAttributes, JoinKeys,
    MemoryAttributes, NetworkAttributes, ProcessAttributes, UnifiedThreatLevel,
};

// ─── EntityManager ────────────────────────────────────────────────────────────

pub struct EntityManager {
    nodes:       DashMap<String, EntityNode>,
    window_secs: u64,
}

impl EntityManager {
    /// Create a new manager with the given sliding window.
    /// A 10-minute window (600 s) is a reasonable default for endpoint activity.
    pub fn new(window_secs: u64) -> Self {
        Self {
            nodes: DashMap::new(),
            window_secs,
        }
    }

    // ── Ingestion ─────────────────────────────────────────────────────────────

    /// Ingest a ProcessInfo produced by the process scanner heuristics.
    /// All processes are accepted — even Safe ones — because a clean process
    /// may later correlate with a suspicious network connection or memory region.
    pub fn ingest_process(&self, process: &ProcessInfo) {
        let entity_id = format!("proc:{}:{}", process.pid, process.name);

        let threat_level = UnifiedThreatLevel::from(&process.threat_level);

        let join_keys = JoinKeys {
            pid:        Some(process.pid),
            parent_pid: process.parent_pid,
            file_path:  process.exe_path.clone(),
            ..Default::default()
        };

        let attributes = EntityAttributes::Process(ProcessAttributes {
            pid:          process.pid,
            name:         process.name.clone(),
            exe_path:     process.exe_path.clone(),
            command_line: process.command_line.clone(),
            user:         process.user.clone(),
            parent_pid:   process.parent_pid,
        });

        // process::types::DetectionSignal and core::types::DetectionSignal are
        // structurally identical but defined separately — convert explicitly.
        let signals: Vec<DetectionSignal> = process.detection_signals
            .iter()
            .map(|s| DetectionSignal {
                source:      s.source.clone(),
                description: s.description.clone(),
                score:       s.score,
            })
            .collect();

        let node = EntityNode::new(
            entity_id.clone(),
            EntityType::Process,
            process.threat_score,
            None,
            threat_level,
            signals,
            attributes,
            join_keys,
        );

        self.nodes.insert(entity_id, node);
    }

    /// Ingest a zero-score structural stub for a process that was seen in
    /// memory or network signals but was not directly scanned by the process
    /// heuristics.  The stub carries only name, parent_pid, and exe_path —
    /// enough for the graph layer to draw ParentChild edges.
    ///
    /// No-ops if a process entity for this PID is already present, so calling
    /// this after a full process scan is always safe.
    pub fn ingest_process_stub(&self, process: &ProcessInfo) {
        let entity_id = format!("proc:{}:{}", process.pid, process.name);
        if self.nodes.contains_key(&entity_id) {
            return; // full process scan already ingested this PID
        }
        self.ingest_process(process);
    }

    /// Ingest a ScanResult produced by the file scanner heuristics.
    pub fn ingest_file(&self, result: &ScanResult) {
        let path_str = result.path.to_string_lossy().to_string();
        let entity_id = match &result.hash {
            Some(h) => format!("file:{h}"),
            None    => format!("file:{path_str}"),
        };

        let threat_level = UnifiedThreatLevel::from(&result.level);

        let join_keys = JoinKeys {
            file_path: Some(path_str.clone()),
            file_hash: result.hash.clone(),
            ..Default::default()
        };

        let context_flags: Vec<String> = result.context_flags
            .iter()
            .map(|f| f.as_str().to_string())
            .collect();

        let attributes = EntityAttributes::File(FileAttributes {
            path:          path_str,
            hash:          result.hash.clone(),
            category:      result.file_category.as_str().to_string(),
            context_flags,
        });

        // confidence_score is 0.0–1.0; map to integer score for consistency
        let heuristic_score = (result.confidence_score * 40.0) as i32;

        let node = EntityNode::new(
            entity_id.clone(),
            EntityType::File,
            heuristic_score,
            None,
            threat_level,
            result.detection_signals.clone(),
            attributes,
            join_keys,
        );

        self.nodes.insert(entity_id, node);
    }

    /// Ingest a NetworkConnection.
    ///
    /// This is the only ingest method that accepts an ml_score because the
    /// network scanner is the only one backed by both heuristics and an ML
    /// model.  Pass `None` when only heuristics have run; the score can be
    /// patched later via `update_ml_score` once the ML pipeline returns.
    ///
    /// All connections are accepted regardless of heuristic_score so the graph
    /// can see clean connections that later correlate with suspicious entities
    /// through a shared PID or remote IP.
    pub fn ingest_network(&self, conn: &NetworkConnection, ml_score: Option<f32>) {
        let entity_id = format!(
            "net:{}:{}:{}",
            conn.protocol, conn.local_address, conn.remote_address
        );

        let threat_level = UnifiedThreatLevel::from(&conn.threat_level);

        let (remote_ip, remote_port) = parse_remote_address(&conn.remote_address);

        let join_keys = JoinKeys {
            pid:         conn.pid,
            remote_ip,
            remote_port,
            ..Default::default()
        };

        let attributes = EntityAttributes::Network(NetworkAttributes {
            protocol:       conn.protocol.clone(),
            local_address:  conn.local_address.clone(),
            remote_address: conn.remote_address.clone(),
            state:          conn.state.clone(),
            pid:            conn.pid,
            process_name:   conn.process_name.clone(),
        });

        let node = EntityNode::new(
            entity_id.clone(),
            EntityType::NetworkConnection,
            conn.threat_score,
            ml_score,
            threat_level,
            conn.detection_signals.clone(),
            attributes,
            join_keys,
        );

        self.nodes.insert(entity_id, node);
    }

    /// Ingest a MemoryRegion produced by the memory scanner.
    /// Only regions the memory scanner surfaced as threats (is_threat == true)
    /// are ingested — the scanner itself filters to score >= 20.
    pub fn ingest_memory(&self, region: &MemoryRegion) {
        if !region.is_threat {
            return;
        }

        let entity_id = format!(
            "mem:{}:{:#x}",
            region.pid, region.region_start
        );

        let threat_level = match region.threat_level.as_str() {
            "Malicious"  => UnifiedThreatLevel::Malicious,
            "Suspicious" => UnifiedThreatLevel::Suspicious,
            _            => UnifiedThreatLevel::Suspicious,
        };

        let join_keys = JoinKeys {
            pid: Some(region.pid),
            ..Default::default()
        };

        let attributes = EntityAttributes::Memory(MemoryAttributes {
            pid:           region.pid,
            process_name:  (*region.process_name).clone(),
            region_start:  region.region_start,
            region_size:   region.region_size,
            protection:    region.protection.clone(),
            is_executable: region.is_executable,
            is_writable:   region.is_writable,
        });

        // memory scanner uses process::types::DetectionSignal — convert
        let signals: Vec<DetectionSignal> = region.detection_signals
            .iter()
            .map(|s| DetectionSignal {
                source:      s.source.clone(),
                description: s.description.clone(),
                score:       s.score,
            })
            .collect();

        let node = EntityNode::new(
            entity_id.clone(),
            EntityType::MemoryRegion,
            region.threat_score,
            None,
            threat_level,
            signals,
            attributes,
            join_keys,
        );

        self.nodes.insert(entity_id, node);
    }

    // ── ML score update ───────────────────────────────────────────────────────

    /// Patch the ML score of a network entity once the ML pipeline returns.
    ///
    /// The entity_id must match what was produced at ingest time:
    ///   `"net:{protocol}:{local_address}:{remote_address}"`
    ///
    /// Also re-evaluates the threat level if the combined score crosses a
    /// threshold that heuristics alone did not reach.
    pub fn update_ml_score(&self, entity_id: &str, ml_score: f32) {
        if let Some(mut entry) = self.nodes.get_mut(entity_id) {
            entry.ml_score = Some(ml_score.clamp(0.0, 1.0));

            // Re-evaluate threat level using the combined score.
            let combined = entry.combined_score();
            let new_level = if combined >= 0.80 {
                UnifiedThreatLevel::Malicious
            } else if combined >= 0.55 {
                UnifiedThreatLevel::Suspicious
            } else {
                UnifiedThreatLevel::Clean
            };

            // Only escalate — never downgrade a heuristic verdict.
            if new_level > entry.threat_level {
                entry.threat_level = new_level;
            }
        }
    }

    /// Boost child-process scores when their parent is already a threat.
    ///
    /// +3 heuristic points for a Suspicious parent, +6 for Malicious/Critical.
    /// Threat level is re-evaluated using the same thresholds as the process
    /// heuristics (4 / 10 / 15).  Never downgrades an existing verdict.
    pub fn apply_parent_context_boost(&self) {
        use std::collections::HashMap;

        // Build pid → threat_level for all threat-level process entities.
        let parent_threats: HashMap<u32, UnifiedThreatLevel> = self.nodes
            .iter()
            .filter(|e| e.entity_type == EntityType::Process && e.is_threat())
            .filter_map(|e| e.join_keys.pid.map(|pid| (pid, e.threat_level.clone())))
            .collect();

        if parent_threats.is_empty() { return; }

        // Collect (entity_id, boost) for processes whose parent is a threat.
        let boosts: Vec<(String, i32)> = self.nodes
            .iter()
            .filter(|e| e.entity_type == EntityType::Process)
            .filter_map(|e| {
                let ppid = e.join_keys.parent_pid?;
                let boost = match parent_threats.get(&ppid)? {
                    UnifiedThreatLevel::Malicious | UnifiedThreatLevel::Critical => 6,
                    UnifiedThreatLevel::Suspicious => 3,
                    _ => return None,
                };
                Some((e.entity_id.clone(), boost))
            })
            .collect();

        for (id, boost) in boosts {
            if let Some(mut entry) = self.nodes.get_mut(&id) {
                entry.heuristic_score += boost;
                let new_level = if entry.heuristic_score >= 15 {
                    UnifiedThreatLevel::Critical
                } else if entry.heuristic_score >= 10 {
                    UnifiedThreatLevel::Malicious
                } else if entry.heuristic_score >= 4 {
                    UnifiedThreatLevel::Suspicious
                } else {
                    UnifiedThreatLevel::Clean
                };
                if new_level > entry.threat_level {
                    entry.threat_level = new_level;
                }
            }
        }
    }

    // ── Queries ───────────────────────────────────────────────────────────────

    /// All entities sharing a PID — links processes, network connections, and
    /// memory regions that belong to the same OS process.
    pub fn get_by_pid(&self, pid: u32) -> Vec<EntityNode> {
        self.nodes
            .iter()
            .filter(|e| e.value().join_keys.pid == Some(pid))
            .map(|e| e.value().clone())
            .collect()
    }

    /// All network entities connecting to the same remote IP — useful for
    /// detecting multiple processes communicating with the same C2 host.
    pub fn get_by_remote_ip(&self, ip: &str) -> Vec<EntityNode> {
        self.nodes
            .iter()
            .filter(|e| {
                e.value().join_keys.remote_ip.as_deref() == Some(ip)
            })
            .map(|e| e.value().clone())
            .collect()
    }

    /// All entities that reference the same file path.
    pub fn get_by_file_path(&self, path: &str) -> Vec<EntityNode> {
        let path_lower = path.to_lowercase();
        self.nodes
            .iter()
            .filter(|e| {
                e.value()
                    .join_keys
                    .file_path
                    .as_deref()
                    .map(|p| p.to_lowercase() == path_lower)
                    .unwrap_or(false)
            })
            .map(|e| e.value().clone())
            .collect()
    }

    /// All entities whose threat_level is not Clean, sorted by combined_score
    /// descending.  This is the feed into the graph layer.
    pub fn get_threats(&self) -> Vec<EntityNode> {
        let mut threats: Vec<EntityNode> = self.nodes
            .iter()
            .filter(|e| e.value().is_threat())
            .map(|e| e.value().clone())
            .collect();

        threats.sort_by(|a, b| {
            b.combined_score()
                .partial_cmp(&a.combined_score())
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        threats
    }

    /// All nodes currently live in the window (including Clean ones).
    /// Intended for the graph builder which needs the full picture.
    pub fn get_all(&self) -> Vec<EntityNode> {
        self.nodes.iter().map(|e| e.value().clone()).collect()
    }

    /// Look up a single entity by its stable ID.
    pub fn get(&self, entity_id: &str) -> Option<EntityNode> {
        self.nodes.get(entity_id).map(|e| e.value().clone())
    }

    // ── Maintenance ───────────────────────────────────────────────────────────

    /// Remove entities older than window_secs.
    /// Call this periodically (e.g., every 60 s) to bound memory usage.
    pub fn prune_expired(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let cutoff = now.saturating_sub(self.window_secs);
        self.nodes.retain(|_, node| node.timestamp >= cutoff);
    }

    /// Number of live nodes in the window.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    // ── Aggregation ───────────────────────────────────────────────────────────

    /// Aggregate flat EntityNodes into composite entities for the graph layer.
    ///
    /// One `AggregatedEntity` is produced per OS process (PID-anchored),
    /// embedding its owned network connections, memory regions, and executable
    /// file.  PID-keyed nodes whose process was never ingested (e.g. memory or
    /// network observed for a PID the process scanner skipped) are merged into a
    /// process-less `entity:{pid}` node so no signal is silently dropped.
    /// Network connections with no PID at all and standalone malicious files each
    /// become their own entity node.
    pub fn aggregate(&self) -> Vec<super::types::AggregatedEntity> {
        use std::collections::{HashMap, HashSet};
        use super::types::{AggregatedEntity, EntityAttributes, EntityType};

        let all = self.get_all();

        let mut procs:     Vec<EntityNode> = Vec::new();
        let mut nets:      Vec<EntityNode> = Vec::new();
        let mut mems:      Vec<EntityNode> = Vec::new();
        let mut files:     Vec<EntityNode> = Vec::new();

        for n in all {
            match n.entity_type {
                EntityType::Process           => procs.push(n),
                EntityType::NetworkConnection => nets.push(n),
                EntityType::MemoryRegion      => mems.push(n),
                EntityType::File              => files.push(n),
            }
        }

        // Index network and memory nodes by PID
        let mut net_by_pid: HashMap<u32, Vec<EntityNode>> = HashMap::new();
        let mut orphan_net: Vec<EntityNode>               = Vec::new();
        for n in nets {
            match n.join_keys.pid {
                Some(pid) => net_by_pid.entry(pid).or_default().push(n),
                None      => orphan_net.push(n),
            }
        }
        let mut mem_by_pid: HashMap<u32, Vec<EntityNode>> = HashMap::new();
        for n in mems {
            if let Some(pid) = n.join_keys.pid {
                mem_by_pid.entry(pid).or_default().push(n);
            }
        }

        // Index files by lowercase exe path (first match wins)
        let mut file_by_path: HashMap<String, EntityNode> = HashMap::new();
        for n in &files {
            if let Some(ref p) = n.join_keys.file_path {
                file_by_path.entry(p.to_lowercase()).or_insert_with(|| n.clone());
            }
        }

        let mut result: Vec<AggregatedEntity> = Vec::new();
        let mut used_file_ids: HashSet<String> = HashSet::new();

        // ── One entity per process ────────────────────────────────────────────
        for proc in procs {
            let Some(pid) = proc.join_keys.pid else { continue };
            let parent_pid = proc.join_keys.parent_pid;

            let owned_net  = net_by_pid.remove(&pid).unwrap_or_default();
            let owned_mem  = mem_by_pid.remove(&pid).unwrap_or_default();

            let exe_file = proc.join_keys.file_path.as_ref()
                .and_then(|p| file_by_path.get(&p.to_lowercase()))
                .cloned();
            if let Some(ref f) = exe_file {
                used_file_ids.insert(f.entity_id.clone());
            }
            let owned_files: Vec<EntityNode> = exe_file.into_iter().collect();

            let name = match &proc.attributes {
                EntityAttributes::Process(p) => strip_exe_suffix(&p.name),
                _                            => format!("proc:{}", pid),
            };

            result.push(assemble_entity(
                format!("entity:{}", pid),
                name,
                Some(proc),
                owned_net,
                owned_mem,
                owned_files,
                Some(pid),
                parent_pid,
            ));
        }

        // ── PID-keyed nodes whose process was never ingested ─────────────────
        // net_by_pid and mem_by_pid may still contain entries for PIDs that
        // had no matching process entity (e.g. the process scanner skipped them
        // or memory/network ran independently).  Merge by PID so no signal is lost.
        {
            let mut leftover_pids: std::collections::HashSet<u32> = std::collections::HashSet::new();
            leftover_pids.extend(net_by_pid.keys().copied());
            leftover_pids.extend(mem_by_pid.keys().copied());

            for pid in leftover_pids {
                let nets = net_by_pid.remove(&pid).unwrap_or_default();
                let mems = mem_by_pid.remove(&pid).unwrap_or_default();

                // Derive the best available process name from memory or network attributes.
                let name = mems.first()
                    .and_then(|m| {
                        if let EntityAttributes::Memory(ref ma) = m.attributes {
                            Some(format!("{} (pid:{})", strip_exe_suffix(&ma.process_name), pid))
                        } else { None }
                    })
                    .or_else(|| nets.first().and_then(|n| {
                        if let EntityAttributes::Network(ref na) = n.attributes {
                            na.process_name.as_ref()
                                .map(|pn| format!("{} (pid:{})", strip_exe_suffix(pn), pid))
                        } else { None }
                    }))
                    .unwrap_or_else(|| format!("pid:{}", pid));

                result.push(assemble_entity(
                    format!("entity:{}", pid),
                    name,
                    None,
                    nets,
                    mems,
                    vec![],
                    Some(pid),
                    None,
                ));
            }
        }

        // ── Orphan network connections (no PID at all) ────────────────────────
        for n in orphan_net {
            let name = match &n.attributes {
                EntityAttributes::Network(net) =>
                    format!("{} → {}", net.protocol.to_uppercase(), net.remote_address),
                _ => n.entity_id.clone(),
            };
            let eid = format!("entity-net:{}", &n.entity_id);
            result.push(assemble_entity(eid, name, None, vec![n], vec![], vec![], None, None));
        }

        // ── Standalone files (not matched to any running process) ─────────────
        for f in files {
            if used_file_ids.contains(&f.entity_id) { continue; }
            let name = f.join_keys.file_path.as_ref()
                .and_then(|p| std::path::Path::new(p.as_str()).file_name())
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| f.entity_id.clone());
            let eid = format!("entity-file:{}", &f.entity_id);
            result.push(assemble_entity(eid, name, None, vec![], vec![], vec![f], None, None));
        }

        result
    }
}

// ─── Aggregation helper ───────────────────────────────────────────────────────

fn assemble_entity(
    entity_id:  String,
    name:       String,
    process:    Option<EntityNode>,
    network:    Vec<EntityNode>,
    memory:     Vec<EntityNode>,
    files:      Vec<EntityNode>,
    pid:        Option<u32>,
    parent_pid: Option<u32>,
) -> super::types::AggregatedEntity {
    use super::types::{AggregatedEntity, UnifiedThreatLevel};
    use crate::core::types::DetectionSignal;

    const LOOPBACK: &[&str] = &["127.", "::1", "0.0.0.0", "::", "*"];

    // ── Per-domain scores ────────────────────────────────────────────────────
    let process_score = process.as_ref()
        .map(|p| (p.heuristic_score as f32 / 30.0).clamp(0.0, 1.0))
        .unwrap_or(0.0);

    let network_score = network.iter()
        .map(|n| (n.heuristic_score as f32 / 40.0).clamp(0.0, 1.0))
        .fold(0.0_f32, f32::max);

    let memory_score = memory.iter()
        .map(|n| (n.heuristic_score as f32 / 40.0).clamp(0.0, 1.0))
        .fold(0.0_f32, f32::max);

    let file_score = files.iter()
        .map(|n| n.combined_score())
        .fold(0.0_f32, f32::max);

    // ── ML score: max across owned network sub-entities ──────────────────────
    let ml_score: Option<f32> = network.iter()
        .filter_map(|n| n.ml_score)
        .reduce(f32::max);

    // ── Combined score ────────────────────────────────────────────────────────
    let heuristic_max = process_score.max(network_score).max(memory_score).max(file_score);
    let combined_score = match ml_score {
        Some(ml) => (heuristic_max * 0.4 + ml.clamp(0.0, 1.0) * 0.6).clamp(0.0, 1.0),
        None     => heuristic_max,
    };

    // ── Worst threat level across all sub-entities ────────────────────────────
    fn max_level(a: UnifiedThreatLevel, b: &UnifiedThreatLevel) -> UnifiedThreatLevel {
        if b > &a { b.clone() } else { a }
    }

    let mut threat_level = process.as_ref()
        .map(|p| p.threat_level.clone())
        .unwrap_or(UnifiedThreatLevel::Clean);
    for n in network.iter().chain(memory.iter()).chain(files.iter()) {
        threat_level = max_level(threat_level, &n.threat_level);
    }

    // ── Intra-entity threat flags ─────────────────────────────────────────────
    let has_malicious_network = network.iter().any(|n| n.is_threat());
    let has_malicious_memory  = memory.iter().any(|n| n.is_threat());
    let has_malicious_file    = files.iter().any(|n| n.is_threat());

    // ── Remote IPs (non-loopback) ────────────────────────────────────────────
    let mut seen_ips: std::collections::HashSet<String> = std::collections::HashSet::new();
    let remote_ips: Vec<String> = network.iter()
        .filter_map(|n| n.join_keys.remote_ip.clone())
        .filter(|ip| !LOOPBACK.iter().any(|pfx| ip.starts_with(pfx)))
        .filter(|ip| seen_ips.insert(ip.clone()))
        .collect();

    // ── File hashes ──────────────────────────────────────────────────────────
    let mut seen_hashes: std::collections::HashSet<String> = std::collections::HashSet::new();
    let file_hashes: Vec<String> = files.iter()
        .filter_map(|n| n.join_keys.file_hash.clone())
        .filter(|h| seen_hashes.insert(h.clone()))
        .collect();

    // ── Merge detection signals ───────────────────────────────────────────────
    let detection_signals: Vec<DetectionSignal> = process.iter()
        .flat_map(|p| p.detection_signals.iter().cloned())
        .chain(network.iter().flat_map(|n| n.detection_signals.iter().cloned()))
        .chain(memory.iter().flat_map(|m| m.detection_signals.iter().cloned()))
        .chain(files.iter().flat_map(|f| f.detection_signals.iter().cloned()))
        .collect();

    // ── Sub-label: exe path for processes ────────────────────────────────────
    let sub_label = process.as_ref().and_then(|p| {
        if let super::types::EntityAttributes::Process(ref pa) = p.attributes {
            pa.exe_path.clone()
        } else { None }
    });
    let _ = sub_label; // sub_label is stored in the GraphNode, not AggregatedEntity

    AggregatedEntity {
        entity_id,
        name,
        threat_level,
        combined_score,
        process_score,
        network_score,
        memory_score,
        file_score,
        has_malicious_network,
        has_malicious_memory,
        has_malicious_file,
        process,
        network,
        memory,
        files,
        detection_signals,
        pid,
        parent_pid,
        remote_ips,
        file_hashes,
        ml_score,
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Strip the Windows executable extension from a process name for display.
///
/// The raw name (e.g. "notepad.exe") is kept intact in entity_id so lookups
/// are unaffected; only the human-readable label is cleaned up.
fn strip_exe_suffix(name: &str) -> String {
    for ext in &[".exe", ".EXE", ".dll", ".DLL", ".sys", ".SYS"] {
        if let Some(stem) = name.strip_suffix(ext) {
            if !stem.is_empty() { return stem.to_string(); }
        }
    }
    name.to_string()
}

/// Split "192.168.1.1:4444" or "[::1]:8080" into (Some(ip), Some(port)).
/// Returns (None, None) for wildcard addresses ("*", "0.0.0.0:*", etc.).
fn parse_remote_address(addr: &str) -> (Option<String>, Option<u16>) {
    if addr == "*" || addr.ends_with(":*") || addr.is_empty() {
        return (None, None);
    }

    // IPv6: "[::1]:port"
    if addr.starts_with('[') {
        if let Some(bracket_end) = addr.find(']') {
            let ip = addr[1..bracket_end].to_string();
            let port = addr.get(bracket_end + 2..)
                .and_then(|p| p.parse::<u16>().ok());
            return (Some(ip), port);
        }
    }

    // IPv4: "x.x.x.x:port"
    if let Some(colon) = addr.rfind(':') {
        let ip   = &addr[..colon];
        let port = addr[colon + 1..].parse::<u16>().ok();
        if !ip.is_empty() {
            return (Some(ip.to_string()), port);
        }
    }

    (None, None)
}

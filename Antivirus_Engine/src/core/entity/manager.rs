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
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

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

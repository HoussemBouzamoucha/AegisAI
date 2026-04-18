// File: src/core/graph/builder.rs
// GraphBuilder — converts the EntityManager's live node set into a ThreatGraph.
//
// Complexity guarantee
// ──────────────────
// Naive edge discovery is O(n²) — for every pair of entities check all join keys.
// GraphBuilder uses pre-built HashMap indexes keyed on each join-key value so the
// total work is:
//   • O(n)  — build five index maps (pid, parent_pid, file_path, file_hash, remote_ip)
//   • O(n)  — iterate each entity once, look up peers in O(1) per map entry
// The seen-pair HashSet ensures each undirected edge is emitted exactly once
// regardless of traversal order.

use std::collections::{HashMap, HashSet};

use crate::core::entity::{EntityManager, EntityNode, EntityType};
use crate::core::entity::types::EntityAttributes;

use super::types::{EdgeType, GraphEdge, GraphNode, ThreatGraph};

// ─── GraphBuilder ─────────────────────────────────────────────────────────────

pub struct GraphBuilder<'a> {
    manager: &'a EntityManager,
}

impl<'a> GraphBuilder<'a> {
    pub fn new(manager: &'a EntityManager) -> Self {
        Self { manager }
    }

    /// Build a ThreatGraph from all entities currently in the EntityManager window.
    pub fn build(&self) -> ThreatGraph {
        let nodes = self.manager.get_all();
        let mut graph = ThreatGraph::new();

        if nodes.is_empty() {
            return graph;
        }

        // ── Fast-lookup maps for score and type ───────────────────────────────
        // Built once; O(1) per query throughout the edge phase.
        let scores: HashMap<&str, f32> = nodes.iter()
            .map(|n| (n.entity_id.as_str(), n.combined_score()))
            .collect();

        let types: HashMap<&str, EntityType> = nodes.iter()
            .map(|n| (n.entity_id.as_str(), n.entity_type.clone()))
            .collect();

        // ── Add graph nodes ───────────────────────────────────────────────────
        for entity in &nodes {
            graph.add_node(entity_to_graph_node(entity));
        }

        // ── Build join-key indexes ────────────────────────────────────────────
        let mut by_pid:       HashMap<u32, Vec<&str>>    = HashMap::new();
        let mut by_parent:    HashMap<u32, Vec<&str>>    = HashMap::new();
        let mut by_file_path: HashMap<String, Vec<&str>> = HashMap::new();
        let mut by_file_hash: HashMap<&str, Vec<&str>>   = HashMap::new();
        let mut by_remote_ip: HashMap<&str, Vec<&str>>   = HashMap::new();

        for entity in &nodes {
            let id = entity.entity_id.as_str();
            if let Some(pid)  = entity.join_keys.pid        { by_pid.entry(pid).or_default().push(id); }
            if let Some(ppid) = entity.join_keys.parent_pid { by_parent.entry(ppid).or_default().push(id); }
            if let Some(ref fp) = entity.join_keys.file_path {
                by_file_path.entry(fp.to_lowercase()).or_default().push(id);
            }
            if let Some(ref fh) = entity.join_keys.file_hash {
                by_file_hash.entry(fh.as_str()).or_default().push(id);
            }
            if let Some(ref ip) = entity.join_keys.remote_ip {
                by_remote_ip.entry(ip.as_str()).or_default().push(id);
            }
        }

        // ── Emit edges (each unordered pair emitted at most once) ─────────────
        let mut seen: HashSet<(String, String)> = HashSet::new();

        for entity in &nodes {
            let id = entity.entity_id.as_str();
            let s  = entity.combined_score();

            // ─ PID group: proc↔net, proc↔mem, net↔mem ────────────────────────
            if let Some(pid) = entity.join_keys.pid {
                for &peer in by_pid.get(&pid).into_iter().flatten() {
                    if peer == id { continue; }
                    if !seen.insert(canonical_pair(id, peer)) { continue; }
                    let et = pid_edge_type(
                        entity.entity_type.clone(),
                        types.get(peer).cloned().unwrap_or(EntityType::Process),
                    );
                    let w = max_score(s, *scores.get(peer).unwrap_or(&0.0));
                    graph.add_edge(GraphEdge {
                        from: id.to_string(), to: peer.to_string(), edge_type: et, weight: w,
                    });
                }
            }

            // ─ Process-specific ───────────────────────────────────────────────
            if entity.entity_type == EntityType::Process {
                // Parent → child chain
                if let Some(pid) = entity.join_keys.pid {
                    for &child in by_parent.get(&pid).into_iter().flatten() {
                        if child == id { continue; }
                        if !seen.insert(canonical_pair(id, child)) { continue; }
                        let w = max_score(s, *scores.get(child).unwrap_or(&0.0));
                        graph.add_edge(GraphEdge {
                            from:      id.to_string(),
                            to:        child.to_string(),
                            edge_type: EdgeType::ParentChild,
                            weight:    w,
                        });
                    }
                }

                // exe_path → file entity (file executed → process spawned)
                if let Some(ref fp) = entity.join_keys.file_path {
                    for &file_id in by_file_path.get(&fp.to_lowercase()).into_iter().flatten() {
                        if file_id == id { continue; }
                        if types.get(file_id) != Some(&EntityType::File) { continue; }
                        if !seen.insert(canonical_pair(id, file_id)) { continue; }
                        let w = max_score(s, *scores.get(file_id).unwrap_or(&0.0));
                        // Edge direction: file → process (file was executed)
                        graph.add_edge(GraphEdge {
                            from:      file_id.to_string(),
                            to:        id.to_string(),
                            edge_type: EdgeType::ProcessOpenedFile,
                            weight:    w,
                        });
                    }
                }
            }

            // ─ File: shared hash (same binary at different paths) ─────────────
            if entity.entity_type == EntityType::File {
                if let Some(ref fh) = entity.join_keys.file_hash {
                    for &peer in by_file_hash.get(fh.as_str()).into_iter().flatten() {
                        if peer == id { continue; }
                        if !seen.insert(canonical_pair(id, peer)) { continue; }
                        let w = max_score(s, *scores.get(peer).unwrap_or(&0.0));
                        graph.add_edge(GraphEdge {
                            from:      id.to_string(),
                            to:        peer.to_string(),
                            edge_type: EdgeType::SharedFileHash,
                            weight:    w,
                        });
                    }
                }
            }

            // ─ Network: shared remote IP (potential shared C2) ────────────────
            if entity.entity_type == EntityType::NetworkConnection {
                if let Some(ref ip) = entity.join_keys.remote_ip {
                    for &peer in by_remote_ip.get(ip.as_str()).into_iter().flatten() {
                        if peer == id { continue; }
                        if types.get(peer) != Some(&EntityType::NetworkConnection) { continue; }
                        if !seen.insert(canonical_pair(id, peer)) { continue; }
                        let w = max_score(s, *scores.get(peer).unwrap_or(&0.0));
                        graph.add_edge(GraphEdge {
                            from:      id.to_string(),
                            to:        peer.to_string(),
                            edge_type: EdgeType::SharedC2,
                            weight:    w,
                        });
                    }
                }
            }
        }

        graph
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Canonical (min, max) pair so A→B and B→A map to the same key.
fn canonical_pair(a: &str, b: &str) -> (String, String) {
    if a <= b { (a.to_string(), b.to_string()) }
    else      { (b.to_string(), a.to_string()) }
}

fn max_score(a: f32, b: f32) -> f32 { a.max(b) }

/// Derive the most specific edge type for two entities that share a PID.
fn pid_edge_type(a: EntityType, b: EntityType) -> EdgeType {
    use EntityType::*;
    match (&a, &b) {
        (Process, NetworkConnection) | (NetworkConnection, Process) => EdgeType::NetworkOwner,
        (Process, MemoryRegion)      | (MemoryRegion,      Process) => EdgeType::MemoryInjection,
        _ => EdgeType::SameProcess,
    }
}

/// Convert an EntityNode into the leaner GraphNode for the graph layer.
pub fn entity_to_graph_node(entity: &EntityNode) -> GraphNode {
    let (label, sub_label) = derive_labels(entity);
    GraphNode {
        entity_id:       entity.entity_id.clone(),
        entity_type:     entity.entity_type.as_str().to_string(),
        threat_level:    entity.threat_level.as_str().to_string(),
        combined_score:  entity.combined_score(),
        heuristic_score: entity.heuristic_score,
        ml_score:        entity.ml_score,
        label,
        sub_label,
    }
}

/// Derive human-readable labels from the type-specific entity attributes.
pub fn derive_labels(entity: &EntityNode) -> (String, Option<String>) {
    match &entity.attributes {
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
    }
}

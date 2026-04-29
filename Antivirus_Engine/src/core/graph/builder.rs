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

use crate::core::entity::{AggregatedEntity, EntityManager, EntityNode, EntityType};
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
                    let peer_s = *scores.get(peer).unwrap_or(&0.0);
                    let w = GraphEdge::weight_for(s, peer_s, &et);
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
                        let child_s = *scores.get(child).unwrap_or(&0.0);
                        let w = GraphEdge::weight_for(s, child_s, &EdgeType::ParentChild);
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
                        let file_s = *scores.get(file_id).unwrap_or(&0.0);
                        let w = GraphEdge::weight_for(s, file_s, &EdgeType::ProcessOpenedFile);
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
                        let peer_s = *scores.get(peer).unwrap_or(&0.0);
                        let w = GraphEdge::weight_for(s, peer_s, &EdgeType::SharedFileHash);
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
                        let peer_s = *scores.get(peer).unwrap_or(&0.0);
                        let w = GraphEdge::weight_for(s, peer_s, &EdgeType::SharedC2);
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

// ─── Aggregated-entity graph builder ─────────────────────────────────────────

/// Build a `ThreatGraph` from a slice of composite `AggregatedEntity` nodes.
///
/// Each node represents a full OS process (or orphan network/file entity)
/// with all domain evidence embedded.  Edges are drawn only *between*
/// entities:
///   `ParentChild`    — entity A's pid matches entity B's parent_pid
///   `SharedC2`       — two entities share the same non-loopback remote IP
///   `SharedFileHash` — two entities share a file SHA-256 hash
///
/// This keeps the graph readable (O(processes) nodes instead of
/// O(processes + connections + regions + files) nodes) and ensures every
/// node is a semantically complete "actor".
pub fn build_from_aggregated(entities: &[AggregatedEntity]) -> ThreatGraph {
    let mut graph = ThreatGraph::new();
    if entities.is_empty() { return graph; }

    // ── Add nodes ─────────────────────────────────────────────────────────────
    for e in entities {
        graph.add_node(aggregate_to_graph_node(e));
    }

    let scores: HashMap<&str, f32> = entities.iter()
        .map(|e| (e.entity_id.as_str(), e.combined_score))
        .collect();

    let mut seen: HashSet<(String, String)> = HashSet::new();

    // ── ParentChild edges ─────────────────────────────────────────────────────
    let pid_to_entity: HashMap<u32, &str> = entities.iter()
        .filter_map(|e| e.pid.map(|pid| (pid, e.entity_id.as_str())))
        .collect();

    for e in entities {
        if let Some(ppid) = e.parent_pid {
            if let Some(&parent_id) = pid_to_entity.get(&ppid) {
                let child_id = e.entity_id.as_str();
                if parent_id == child_id { continue; }
                if !seen.insert(canonical_pair(parent_id, child_id)) { continue; }
                let sp = *scores.get(parent_id).unwrap_or(&0.0);
                let sc = *scores.get(child_id ).unwrap_or(&0.0);
                let w  = GraphEdge::weight_for(sp, sc, &EdgeType::ParentChild);
                graph.add_edge(GraphEdge {
                    from: parent_id.to_string(), to: child_id.to_string(),
                    edge_type: EdgeType::ParentChild, weight: w,
                });
            }
        }
    }

    // ── SharedC2 edges (≥2 distinct entities share the same remote IP) ────────
    let mut ip_to_entities: HashMap<&str, Vec<&str>> = HashMap::new();
    for e in entities {
        for ip in &e.remote_ips {
            ip_to_entities.entry(ip.as_str()).or_default().push(e.entity_id.as_str());
        }
    }
    for (_, ids) in &ip_to_entities {
        if ids.len() < 2 { continue; }
        for i in 0..ids.len() {
            for j in (i + 1)..ids.len() {
                let a = ids[i]; let b = ids[j];
                if !seen.insert(canonical_pair(a, b)) { continue; }
                let sa = *scores.get(a).unwrap_or(&0.0);
                let sb = *scores.get(b).unwrap_or(&0.0);
                let w  = GraphEdge::weight_for(sa, sb, &EdgeType::SharedC2);
                graph.add_edge(GraphEdge {
                    from: a.to_string(), to: b.to_string(),
                    edge_type: EdgeType::SharedC2, weight: w,
                });
            }
        }
    }

    // ── SharedFileHash edges (≥2 distinct entities share the same hash) ───────
    let mut hash_to_entities: HashMap<&str, Vec<&str>> = HashMap::new();
    for e in entities {
        for h in &e.file_hashes {
            hash_to_entities.entry(h.as_str()).or_default().push(e.entity_id.as_str());
        }
    }
    for (_, ids) in &hash_to_entities {
        if ids.len() < 2 { continue; }
        for i in 0..ids.len() {
            for j in (i + 1)..ids.len() {
                let a = ids[i]; let b = ids[j];
                if !seen.insert(canonical_pair(a, b)) { continue; }
                let sa = *scores.get(a).unwrap_or(&0.0);
                let sb = *scores.get(b).unwrap_or(&0.0);
                let w  = GraphEdge::weight_for(sa, sb, &EdgeType::SharedFileHash);
                graph.add_edge(GraphEdge {
                    from: a.to_string(), to: b.to_string(),
                    edge_type: EdgeType::SharedFileHash, weight: w,
                });
            }
        }
    }

    graph
}

/// Convert an `AggregatedEntity` into a `GraphNode`.
pub fn aggregate_to_graph_node(e: &AggregatedEntity) -> GraphNode {
    // sub_label: exe path for process-anchored entities
    let sub_label = e.process.as_ref().and_then(|p| {
        if let EntityAttributes::Process(ref pa) = p.attributes { pa.exe_path.clone() } else { None }
    });

    let heuristic_score = e.process.as_ref()
        .map(|p| p.heuristic_score)
        .unwrap_or_else(|| {
            e.network.iter().chain(e.memory.iter()).chain(e.files.iter())
                .map(|n| n.heuristic_score)
                .max()
                .unwrap_or(0)
        });

    GraphNode {
        entity_id:             e.entity_id.clone(),
        entity_type:           "entity".to_string(),
        threat_level:          e.threat_level.as_str().to_string(),
        combined_score:        e.combined_score,
        heuristic_score,
        ml_score:              e.ml_score,
        label:                 e.name.clone(),
        sub_label,
        process_score:         e.process_score,
        network_score:         e.network_score,
        memory_score:          e.memory_score,
        file_score:            e.file_score,
        has_malicious_network: e.has_malicious_network,
        has_malicious_memory:  e.has_malicious_memory,
        has_malicious_file:    e.has_malicious_file,
        pid:                   e.pid,
        parent_pid:            e.parent_pid,
        graph_boost:           0.0,
        is_vector:             false,
        is_lolbin:             false,
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Strip Windows executable extension for display labels only.
/// Entity IDs keep the raw name so all lookups remain stable.
fn strip_exe_suffix(name: &str) -> String {
    for ext in &[".exe", ".EXE", ".dll", ".DLL", ".sys", ".SYS"] {
        if let Some(stem) = name.strip_suffix(ext) {
            if !stem.is_empty() { return stem.to_string(); }
        }
    }
    name.to_string()
}

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

/// Convert a flat EntityNode into a GraphNode (legacy / backward-compat path).
/// Sub-score fields default to zero; use `aggregate_to_graph_node` for the
/// aggregated-entity graph.
pub fn entity_to_graph_node(entity: &EntityNode) -> GraphNode {
    let (label, sub_label) = derive_labels(entity);
    GraphNode {
        entity_id:             entity.entity_id.clone(),
        entity_type:           entity.entity_type.as_str().to_string(),
        threat_level:          entity.threat_level.as_str().to_string(),
        combined_score:        entity.combined_score(),
        heuristic_score:       entity.heuristic_score,
        ml_score:              entity.ml_score,
        label,
        sub_label,
        process_score:         0.0,
        network_score:         0.0,
        memory_score:          0.0,
        file_score:            0.0,
        has_malicious_network: false,
        has_malicious_memory:  false,
        has_malicious_file:    false,
        pid:                   entity.join_keys.pid,
        parent_pid:            entity.join_keys.parent_pid,
        graph_boost:           0.0,
        is_vector:             false,
        is_lolbin:             false,
    }
}

/// Derive human-readable labels from the type-specific entity attributes.
pub fn derive_labels(entity: &EntityNode) -> (String, Option<String>) {
    match &entity.attributes {
        EntityAttributes::Process(p) => (
            strip_exe_suffix(&p.name),
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

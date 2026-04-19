// File: src/core/graph/analyzer.rs
// GraphAnalyzer — detects attack chains by pattern-matching the ThreatGraph.
//
// Each pattern is a self-contained detection method.  New patterns can be added
// without modifying existing ones.  Detection order:
//   1. ProcessInjection  — Process + malicious MemoryRegion (same PID)
//   2. C2Communication   — Process + malicious NetworkConnection (same PID)
//   3. MalwareExecution  — Malicious File → Process (file path match)
//   4. LateralMovement   — ParentChild chain → external NetworkConnection
//   5. SuspiciousSpawn   — Both parent and child are threat-level processes
//   6. MultiStageAttack  — BFS over threat nodes: components with ≥ 3 members
//
// After detection, chains are sorted by chain_score descending.

use std::collections::{HashMap, HashSet, VecDeque};

use super::types::{AttackChain, AttackPattern, CriticalPath, EdgeType, GraphEdge, ThreatGraph};

pub struct GraphAnalyzer;

impl GraphAnalyzer {
    /// Detect all attack chains in `graph` and return them sorted by score.
    pub fn find_attack_chains(graph: &ThreatGraph) -> Vec<AttackChain> {
        let mut counter: u32 = 0;
        let mut chains = Vec::new();

        chains.extend(Self::detect_process_injection(graph,  &mut counter));
        chains.extend(Self::detect_c2_communication(graph,   &mut counter));
        chains.extend(Self::detect_malware_execution(graph,  &mut counter));
        chains.extend(Self::detect_lateral_movement(graph,   &mut counter));
        chains.extend(Self::detect_suspicious_spawn(graph,   &mut counter));
        chains.extend(Self::detect_multi_stage(graph,        &mut counter));

        chains.sort_by(|a, b| {
            b.chain_score.partial_cmp(&a.chain_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        chains
    }

    // ── Critical path (Dijkstra-like max-weight path) ─────────────────────────
    //
    // Strategy:
    //  1. Build a threat sub-graph: only nodes with threat_level != Clean, plus
    //     edges where at least one endpoint is a threat node.
    //  2. Edge weight = avg(combined_score_a, combined_score_b) × type_multiplier.
    //     combined_score already incorporates ML for network entities (H×0.4+ML×0.6).
    //  3. Depth-bounded DFS (max depth 6) with a per-path visited set prevents
    //     cycles.  Starting only from threat nodes keeps the search space small
    //     (typically < 20 nodes, < 50 edges → microseconds of wall-clock time).
    //  4. The path with the highest cumulative edge-weight sum is returned.

    pub fn find_critical_path(graph: &ThreatGraph) -> Option<CriticalPath> {
        // ── Collect threat node IDs ────────────────────────────────────────────
        let threat_ids: HashSet<&str> = graph.nodes.values()
            .filter(|n| !is_clean(&n.threat_level))
            .map(|n| n.entity_id.as_str())
            .collect();

        if threat_ids.is_empty() {
            return None;
        }

        // ── Build bidirectional weighted adjacency (threat-anchored edges) ─────
        // We include any edge where at least one endpoint is a threat node so that
        // a clean pivot (e.g. a shared process) can still connect threat entities.
        let mut adj: HashMap<&str, Vec<(&str, f32, &str)>> = HashMap::new();

        for edge in &graph.edges {
            let from = edge.from.as_str();
            let to   = edge.to.as_str();

            if !threat_ids.contains(from) && !threat_ids.contains(to) {
                continue; // skip clean↔clean edges
            }

            let from_score = graph.nodes.get(from).map_or(0.0, |n| n.combined_score);
            let to_score   = graph.nodes.get(to  ).map_or(0.0, |n| n.combined_score);
            let weight     = edge_weight(from_score, to_score, &edge.edge_type);

            adj.entry(from).or_default().push((to,   weight, edge.edge_type.as_str()));
            adj.entry(to  ).or_default().push((from, weight, edge.edge_type.as_str()));
        }

        // ── DFS from every threat node ─────────────────────────────────────────
        let mut best: Option<CriticalPath> = None;

        for &start in &threat_ids {
            let mut visited: HashSet<&str>  = HashSet::new();
            let mut path_nodes: Vec<String> = vec![start.to_string()];
            let mut path_hops: Vec<(String, f32)> = Vec::new(); // (edge_type, weight)
            visited.insert(start);

            dfs_max_path(
                start,
                0.0,
                &adj,
                &mut visited,
                &mut path_nodes,
                &mut path_hops,
                &mut best,
                6, // max depth (7 nodes)
            );
        }

        best
    }

    // ── Pattern 1: ProcessInjection ───────────────────────────────────────────

    fn detect_process_injection(graph: &ThreatGraph, counter: &mut u32) -> Vec<AttackChain> {
        let mut result = Vec::new();

        for edge in graph.edges.iter().filter(|e| e.edge_type == EdgeType::MemoryInjection) {
            // The MemoryInjection edge connects process ↔ memory; determine which is which.
            let (proc_id, mem_id) = if node_type(graph, &edge.from) == "process" {
                (&edge.from, &edge.to)
            } else {
                (&edge.to, &edge.from)
            };

            let mem_node  = unwrap_or_continue!(graph.nodes.get(mem_id));
            let proc_node = unwrap_or_continue!(graph.nodes.get(proc_id));

            if is_clean(&mem_node.threat_level) { continue; }

            let score    = max_score(mem_node.combined_score, proc_node.combined_score);
            let severity = worst_level(&mem_node.threat_level, &proc_node.threat_level);

            *counter += 1;
            result.push(AttackChain {
                chain_id:     format!("chain-{counter}"),
                pattern:      AttackPattern::ProcessInjection,
                node_ids:     vec![proc_id.clone(), mem_id.clone()],
                chain_score:  score,
                severity,
                description:  format!(
                    "'{}' [{}]: {}",
                    proc_node.label,
                    extract_pid(proc_id),
                    AttackPattern::ProcessInjection.description(),
                ),
                mitre_tactic: AttackPattern::ProcessInjection.mitre_tactic().to_string(),
            });
        }
        result
    }

    // ── Pattern 2: C2Communication ────────────────────────────────────────────

    fn detect_c2_communication(graph: &ThreatGraph, counter: &mut u32) -> Vec<AttackChain> {
        let mut result = Vec::new();

        for edge in graph.edges.iter().filter(|e| e.edge_type == EdgeType::NetworkOwner) {
            let (proc_id, net_id) = if node_type(graph, &edge.from) == "process" {
                (&edge.from, &edge.to)
            } else {
                (&edge.to, &edge.from)
            };

            let net_node  = unwrap_or_continue!(graph.nodes.get(net_id));
            let proc_node = unwrap_or_continue!(graph.nodes.get(proc_id));

            if is_clean(&net_node.threat_level) { continue; }

            let score    = max_score(net_node.combined_score, proc_node.combined_score);
            let severity = worst_level(&net_node.threat_level, &proc_node.threat_level);

            *counter += 1;
            result.push(AttackChain {
                chain_id:     format!("chain-{counter}"),
                pattern:      AttackPattern::C2Communication,
                node_ids:     vec![proc_id.clone(), net_id.clone()],
                chain_score:  score,
                severity,
                description:  format!(
                    "'{}' → '{}': {}",
                    proc_node.label,
                    net_node.label,
                    AttackPattern::C2Communication.description(),
                ),
                mitre_tactic: AttackPattern::C2Communication.mitre_tactic().to_string(),
            });
        }
        result
    }

    // ── Pattern 3: MalwareExecution ───────────────────────────────────────────

    fn detect_malware_execution(graph: &ThreatGraph, counter: &mut u32) -> Vec<AttackChain> {
        let mut result = Vec::new();

        for edge in graph.edges.iter().filter(|e| e.edge_type == EdgeType::ProcessOpenedFile) {
            // By convention: from = file, to = process
            let file_node = unwrap_or_continue!(graph.nodes.get(&edge.from));
            let proc_node = unwrap_or_continue!(graph.nodes.get(&edge.to));

            if is_clean(&file_node.threat_level) { continue; }

            let score    = max_score(file_node.combined_score, proc_node.combined_score);
            let severity = worst_level(&file_node.threat_level, &proc_node.threat_level);

            *counter += 1;
            result.push(AttackChain {
                chain_id:     format!("chain-{counter}"),
                pattern:      AttackPattern::MalwareExecution,
                node_ids:     vec![edge.from.clone(), edge.to.clone()],
                chain_score:  score,
                severity,
                description:  format!(
                    "File '{}' → process '{}': {}",
                    file_node.label,
                    proc_node.label,
                    AttackPattern::MalwareExecution.description(),
                ),
                mitre_tactic: AttackPattern::MalwareExecution.mitre_tactic().to_string(),
            });
        }
        result
    }

    // ── Pattern 4: LateralMovement ────────────────────────────────────────────
    // Walk ParentChild edges → for each child, check for a NetworkOwner edge
    // where the network endpoint is a non-clean entity.

    fn detect_lateral_movement(graph: &ThreatGraph, counter: &mut u32) -> Vec<AttackChain> {
        let mut result = Vec::new();

        let parent_edges: Vec<&GraphEdge> = graph.edges.iter()
            .filter(|e| e.edge_type == EdgeType::ParentChild)
            .collect();

        for pe in parent_edges {
            let parent_id = &pe.from;
            let child_id  = &pe.to;

            // Find NetworkOwner edges from the child
            for ne in graph.edges.iter().filter(|e| e.edge_type == EdgeType::NetworkOwner) {
                let net_id = if &ne.from == child_id { &ne.to }
                             else if &ne.to == child_id { &ne.from }
                             else { continue };

                let net_node    = unwrap_or_continue!(graph.nodes.get(net_id));
                if is_clean(&net_node.threat_level) { continue; }

                let parent_node = unwrap_or_continue!(graph.nodes.get(parent_id));
                let child_node  = unwrap_or_continue!(graph.nodes.get(child_id));

                let scores = [
                    parent_node.combined_score,
                    child_node.combined_score,
                    net_node.combined_score,
                ];
                let score    = scores.iter().cloned().fold(0.0_f32, f32::max);
                let severity = {
                    let s1 = worst_level(&parent_node.threat_level, &child_node.threat_level);
                    worst_level(&s1, &net_node.threat_level)
                };

                *counter += 1;
                result.push(AttackChain {
                    chain_id:     format!("chain-{counter}"),
                    pattern:      AttackPattern::LateralMovement,
                    node_ids:     vec![parent_id.clone(), child_id.clone(), net_id.clone()],
                    chain_score:  score,
                    severity,
                    description:  format!(
                        "'{}' spawned '{}' which connected to '{}': {}",
                        parent_node.label,
                        child_node.label,
                        net_node.label,
                        AttackPattern::LateralMovement.description(),
                    ),
                    mitre_tactic: AttackPattern::LateralMovement.mitre_tactic().to_string(),
                });
            }
        }
        result
    }

    // ── Pattern 5: SuspiciousSpawn ────────────────────────────────────────────

    fn detect_suspicious_spawn(graph: &ThreatGraph, counter: &mut u32) -> Vec<AttackChain> {
        let mut result = Vec::new();

        for edge in graph.edges.iter().filter(|e| e.edge_type == EdgeType::ParentChild) {
            let parent = unwrap_or_continue!(graph.nodes.get(&edge.from));
            let child  = unwrap_or_continue!(graph.nodes.get(&edge.to));

            if is_clean(&parent.threat_level) || is_clean(&child.threat_level) { continue; }

            let score    = max_score(parent.combined_score, child.combined_score);
            let severity = worst_level(&parent.threat_level, &child.threat_level);

            *counter += 1;
            result.push(AttackChain {
                chain_id:     format!("chain-{counter}"),
                pattern:      AttackPattern::SuspiciousSpawn,
                node_ids:     vec![edge.from.clone(), edge.to.clone()],
                chain_score:  score,
                severity,
                description:  format!(
                    "'{}' → '{}': {}",
                    parent.label,
                    child.label,
                    AttackPattern::SuspiciousSpawn.description(),
                ),
                mitre_tactic: AttackPattern::SuspiciousSpawn.mitre_tactic().to_string(),
            });
        }
        result
    }

    // ── Pattern 6: MultiStageAttack ───────────────────────────────────────────
    // BFS over an undirected view of the graph, seeded from unvisited threat
    // nodes.  Only threat-level nodes propagate in the BFS; clean nodes act as
    // barriers.  Components with ≥ 3 members are emitted as MultiStageAttack.

    fn detect_multi_stage(graph: &ThreatGraph, counter: &mut u32) -> Vec<AttackChain> {
        let mut result  = Vec::new();
        let mut visited: HashSet<&str> = HashSet::new();

        // Build undirected adjacency from the directed edge list
        let mut undirected: HashMap<&str, Vec<&str>> = HashMap::new();
        for edge in &graph.edges {
            undirected.entry(edge.from.as_str()).or_default().push(edge.to.as_str());
            undirected.entry(edge.to.as_str()).or_default().push(edge.from.as_str());
        }

        let threat_ids: Vec<&str> = graph.nodes.values()
            .filter(|n| !is_clean(&n.threat_level))
            .map(|n| n.entity_id.as_str())
            .collect();

        for start in &threat_ids {
            if visited.contains(start) { continue; }

            // BFS — only traverse edges between threat-level nodes
            let mut component: Vec<&str> = Vec::new();
            let mut queue: VecDeque<&str> = VecDeque::new();

            visited.insert(start);
            queue.push_back(start);

            while let Some(cur) = queue.pop_front() {
                component.push(cur);

                for &neighbor in undirected.get(cur).into_iter().flatten() {
                    if visited.contains(neighbor) { continue; }
                    if let Some(n) = graph.nodes.get(neighbor) {
                        if !is_clean(&n.threat_level) {
                            visited.insert(neighbor);
                            queue.push_back(neighbor);
                        }
                    }
                }
            }

            if component.len() < 3 { continue; }

            let score = component.iter()
                .filter_map(|id| graph.nodes.get(*id))
                .map(|n| n.combined_score)
                .fold(0.0_f32, f32::max);

            let severity = component.iter()
                .filter_map(|id| graph.nodes.get(*id))
                .fold("Suspicious".to_string(), |acc, n| worst_level(&acc, &n.threat_level));

            let scanner_types: HashSet<&str> = component.iter()
                .filter_map(|id| graph.nodes.get(*id))
                .map(|n| n.entity_type.as_str())
                .collect();

            *counter += 1;
            result.push(AttackChain {
                chain_id:     format!("chain-{counter}"),
                pattern:      AttackPattern::MultiStageAttack,
                node_ids:     component.iter().map(|s| s.to_string()).collect(),
                chain_score:  score,
                severity,
                description:  format!(
                    "{} threat indicators across {} scanner type(s) — {}",
                    component.len(),
                    scanner_types.len(),
                    AttackPattern::MultiStageAttack.description(),
                ),
                mitre_tactic: AttackPattern::MultiStageAttack.mitre_tactic().to_string(),
            });
        }
        result
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// true when threat_level is "Clean" or "Safe".
fn is_clean(level: &str) -> bool {
    matches!(level, "Clean" | "Safe")
}

/// Max of two combined scores.
fn max_score(a: f32, b: f32) -> f32 { a.max(b) }

/// Returns the higher of two threat-level strings.
fn worst_level(a: &str, b: &str) -> String {
    fn rank(s: &str) -> u8 {
        match s { "Critical" => 3, "Malicious" => 2, "Suspicious" => 1, _ => 0 }
    }
    if rank(a) >= rank(b) { a.to_string() } else { b.to_string() }
}

/// Derive entity_type string for a node (returns "" if not found).
fn node_type<'a>(graph: &'a ThreatGraph, id: &str) -> &'a str {
    graph.nodes.get(id).map(|n| n.entity_type.as_str()).unwrap_or("")
}

/// Extract the PID segment from "proc:PID:name" entity IDs.
fn extract_pid(entity_id: &str) -> &str {
    entity_id.split(':').nth(1).unwrap_or("?")
}

/// Convenience macro: continue the loop if an Option is None.
macro_rules! unwrap_or_continue {
    ($opt:expr) => {
        match $opt { Some(v) => v, None => continue }
    };
}

use unwrap_or_continue;

// ─── Critical-path helpers ────────────────────────────────────────────────────

/// Edge weight for the critical-path search.
///
/// Formula:  avg(combined_score_a, combined_score_b) × type_multiplier
///
/// combined_score already encodes the ML signal for network entities
/// (H×0.4 + ML×0.6 when an ML score is present), so no extra term is needed.
///
/// Type multipliers reflect the relative severity of each relationship:
///   MemoryInjection   1.50  — in-memory code injection is a critical IOC
///   NetworkOwner      1.40  — process owning a C2 connection is high-severity
///   SharedC2          1.30  — shared command-and-control infrastructure
///   ProcessOpenedFile 1.20  — file-to-process execution chain
///   ParentChild       1.10  — process lineage is a meaningful escalation signal
///   SameProcess       1.00  — same-PID grouping (structural, less directional)
///   SharedFileHash    0.90  — same binary at different paths (lower severity alone)
fn edge_weight(score_a: f32, score_b: f32, edge_type: &EdgeType) -> f32 {
    let avg = (score_a + score_b) / 2.0;
    let multiplier = match edge_type {
        EdgeType::MemoryInjection   => 1.50,
        EdgeType::NetworkOwner      => 1.40,
        EdgeType::SharedC2          => 1.30,
        EdgeType::ProcessOpenedFile => 1.20,
        EdgeType::ParentChild       => 1.10,
        EdgeType::SameProcess       => 1.00,
        EdgeType::SharedFileHash    => 0.90,
    };
    avg * multiplier
}

/// Recursive depth-bounded DFS for the maximum-weight simple path.
///
/// At each step we extend the current path by one unvisited neighbour and
/// recurse.  On return we roll back the path (backtracking).  The best
/// complete path (≥2 nodes) seen so far is stored in `best`.
#[allow(clippy::too_many_arguments)]
fn dfs_max_path<'a>(
    current:    &'a str,
    running:    f32,
    adj:        &HashMap<&'a str, Vec<(&'a str, f32, &'a str)>>,
    visited:    &mut HashSet<&'a str>,
    path_nodes: &mut Vec<String>,
    path_hops:  &mut Vec<(String, f32)>,   // (edge_type, weight) per hop
    best:       &mut Option<CriticalPath>,
    depth_left: usize,
) {
    // Record best if this path has ≥2 nodes and beats the current champion.
    if path_nodes.len() >= 2 {
        let is_better = best.as_ref().map_or(true, |b| running > b.total_score);
        if is_better {
            let (edge_types, edge_weights): (Vec<String>, Vec<f32>) =
                path_hops.iter().map(|(et, w)| (et.clone(), *w)).unzip();
            *best = Some(CriticalPath {
                node_ids:     path_nodes.clone(),
                edge_types,
                edge_weights,
                total_score:  running,
            });
        }
    }

    if depth_left == 0 {
        return;
    }

    // Iterate over neighbours in descending weight order so we explore the
    // most promising branch first (makes the best-path pruning more effective).
    let mut neighbours: Vec<(&str, f32, &str)> = adj
        .get(current)
        .cloned()
        .unwrap_or_default();
    neighbours.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    for (neighbour, weight, edge_type) in neighbours {
        if visited.contains(neighbour) {
            continue;
        }

        visited.insert(neighbour);
        path_nodes.push(neighbour.to_string());
        path_hops.push((edge_type.to_string(), weight));

        dfs_max_path(
            neighbour,
            running + weight,
            adj,
            visited,
            path_nodes,
            path_hops,
            best,
            depth_left - 1,
        );

        // Backtrack
        visited.remove(neighbour);
        path_nodes.pop();
        path_hops.pop();
    }
}

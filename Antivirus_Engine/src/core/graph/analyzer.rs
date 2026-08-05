// File: src/core/graph/analyzer.rs
// GraphAnalyzer — detects attack chains by pattern-matching the ThreatGraph.
//
// LOLBin detection: when a clean process spawns a confirmed-Malicious child,
// the parent node is flagged `is_vector = true` by `apply_graph_feedback`.
// If the parent's label also appears in the LOLBINS list below, `is_lolbin`
// is set as well so the UI can display a "LOLBin" badge.

// ─── LOLBin static list ───────────────────────────────────────────────────────
//
// Common living-off-the-land binaries that attackers abuse to download,
// execute, or proxy malicious payloads while hiding behind a trusted binary.
// Source: LOLBAS project (lolbas-project.github.io).
//
// Both the bare name and the `.exe` suffix are matched; labels in aggregated
// nodes may or may not carry the extension depending on how sysinfo reports them.
const LOLBINS: &[&str] = &[
    "powershell.exe", "cmd.exe",      "wscript.exe",   "cscript.exe",
    "mshta.exe",      "regsvr32.exe", "rundll32.exe",  "certutil.exe",
    "bitsadmin.exe",  "msiexec.exe",  "wmic.exe",      "schtasks.exe",
    "regasm.exe",     "installutil.exe", "msbuild.exe", "cmstp.exe",
    "forfiles.exe",   "pcalua.exe",   "syncappvpublishingserver.exe",
    "appsyncpublishingserver.exe",    "bash.exe",      "explorer.exe",
    "expand.exe",     "extrac32.exe", "findstr.exe",   "hh.exe",
    "makecab.exe",    "mavinject.exe","microsoft.workflow.compiler.exe",
    "msdeploy.exe",   "msdt.exe",     "msiexec.exe",   "odbcconf.exe",
    "pcwrun.exe",     "presentationhost.exe", "regsvcs.exe",
    "replace.exe",    "rpcping.exe",  "runscripthelper.exe",
    "sfc.exe",        "tracker.exe",  "wab.exe",       "xwizard.exe",
];

/// Return true if `label` (the node's display name) matches a known LOLBin.
///
/// Checks both the bare stem (`cmd`) and the full name (`cmd.exe`) so that
/// labels work regardless of whether sysinfo strips the extension.
fn is_lolbin_label(label: &str) -> bool {
    let lower = label.to_lowercase();
    LOLBINS.iter().any(|&lb| {
        let stem = lb.trim_end_matches(".exe");
        lower == lb || lower == stem
    })
}
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

use super::types::{AttackChain, AttackPattern, CriticalPath, EdgeType, GraphEdge, GraphNode, ThreatGraph};
// GraphEdge::weight_for() is the canonical edge-weight formula shared with builder.rs.

pub struct GraphAnalyzer;

impl GraphAnalyzer {
    /// Detect attack chains on a graph built from **aggregated** entities.
    ///
    /// Patterns 1–3 (ProcessInjection, C2Communication, MalwareExecution) are
    /// detected from intra-entity flags on each node (no edge required).
    /// Patterns 4–6 use inter-entity edges (ParentChild, SharedC2, …).
    pub fn find_attack_chains_aggregated(graph: &ThreatGraph) -> Vec<AttackChain> {
        let mut counter: u32 = 0;
        let mut chains = Vec::new();

        chains.extend(Self::detect_process_injection_agg(graph, &mut counter));
        chains.extend(Self::detect_c2_communication_agg(graph, &mut counter));
        chains.extend(Self::detect_malware_execution_agg(graph, &mut counter));
        chains.extend(Self::detect_lateral_movement_agg(graph, &mut counter));
        chains.extend(Self::detect_suspicious_spawn_agg(graph, &mut counter));
        // Must run before MultiStage so its node pairs are in `specific_nodes`
        // for deduplication purposes.
        chains.extend(Self::detect_exploited_trusted_process_agg(graph, &mut counter));
        chains.extend(Self::detect_multi_stage(graph, &mut counter));

        // Sort by chain_score × confidence descending so that a chain with
        // high severity *and* high evidence quality ranks above one that merely
        // crossed the threshold with a marginal signal.
        chains.sort_by(|a, b| {
            let ra = a.chain_score * a.confidence;
            let rb = b.chain_score * b.confidence;
            rb.partial_cmp(&ra).unwrap_or(std::cmp::Ordering::Equal)
        });
        deduplicate_chains(chains)
    }

    fn detect_process_injection_agg(graph: &ThreatGraph, counter: &mut u32) -> Vec<AttackChain> {
        graph.nodes.values()
            .filter(|n| n.has_malicious_memory)
            .map(|n| {
                *counter += 1;
                // Confidence = how saturated the memory sub-score is.
                // RWX + PE-header shellcode will push memory_score close to 1.0;
                // a single suspicious flag will leave it much lower.
                let ml_corroboration = n.ml_score.unwrap_or(0.0) * 0.15;
                let confidence = (n.memory_score + ml_corroboration).clamp(0.0, 1.0);
                AttackChain {
                    chain_id:     format!("chain-{counter}"),
                    pattern:      AttackPattern::ProcessInjection,
                    node_ids:     vec![n.entity_id.clone()],
                    chain_score:  n.combined_score,
                    severity:     n.threat_level.clone(),
                    description:  format!("'{}': {}", n.label, AttackPattern::ProcessInjection.description()),
                    mitre_tactic: AttackPattern::ProcessInjection.mitre_tactic().to_string(),
                    confidence,
                }
            })
            .collect()
    }

    fn detect_c2_communication_agg(graph: &ThreatGraph, counter: &mut u32) -> Vec<AttackChain> {
        graph.nodes.values()
            .filter(|n| n.has_malicious_network)
            .map(|n| {
                *counter += 1;
                // Confidence = network sub-score + ML corroboration (the IDS
                // model specifically targets network C2 patterns so its signal
                // is particularly relevant here).
                let ml_corroboration = n.ml_score.unwrap_or(0.0) * 0.20;
                let confidence = (n.network_score + ml_corroboration).clamp(0.0, 1.0);
                AttackChain {
                    chain_id:     format!("chain-{counter}"),
                    pattern:      AttackPattern::C2Communication,
                    node_ids:     vec![n.entity_id.clone()],
                    chain_score:  n.combined_score,
                    severity:     n.threat_level.clone(),
                    description:  format!("'{}': {}", n.label, AttackPattern::C2Communication.description()),
                    mitre_tactic: AttackPattern::C2Communication.mitre_tactic().to_string(),
                    confidence,
                }
            })
            .collect()
    }

    fn detect_malware_execution_agg(graph: &ThreatGraph, counter: &mut u32) -> Vec<AttackChain> {
        graph.nodes.values()
            .filter(|n| n.has_malicious_file)
            .map(|n| {
                *counter += 1;
                // Confidence = file sub-score.  A YARA hit on a known-bad hash
                // will push this close to 1.0; a marginal heuristic match stays
                // much lower.
                let confidence = n.file_score.clamp(0.0, 1.0);
                AttackChain {
                    chain_id:     format!("chain-{counter}"),
                    pattern:      AttackPattern::MalwareExecution,
                    node_ids:     vec![n.entity_id.clone()],
                    chain_score:  n.combined_score,
                    severity:     n.threat_level.clone(),
                    description:  format!("'{}': {}", n.label, AttackPattern::MalwareExecution.description()),
                    mitre_tactic: AttackPattern::MalwareExecution.mitre_tactic().to_string(),
                    confidence,
                }
            })
            .collect()
    }

    fn detect_lateral_movement_agg(graph: &ThreatGraph, counter: &mut u32) -> Vec<AttackChain> {
        let mut result = Vec::new();
        for edge in graph.edges.iter().filter(|e| e.edge_type == EdgeType::ParentChild) {
            let child  = unwrap_or_continue!(graph.nodes.get(&edge.to));
            if !child.has_malicious_network { continue; }
            let parent = unwrap_or_continue!(graph.nodes.get(&edge.from));
            let score    = max_score(parent.combined_score, child.combined_score);
            let severity = worst_level(&parent.threat_level, &child.threat_level);
            // Confidence = how convincing both halves of the lateral movement are.
            // The parent→child relationship is structural; the child's actual
            // network evidence is the primary discriminator.
            let avg_score = (parent.combined_score + child.combined_score) / 2.0;
            let confidence = (avg_score * 0.50 + child.network_score * 0.50).clamp(0.0, 1.0);
            *counter += 1;
            result.push(AttackChain {
                chain_id:     format!("chain-{counter}"),
                pattern:      AttackPattern::LateralMovement,
                node_ids:     vec![edge.from.clone(), edge.to.clone()],
                chain_score:  score,
                severity,
                description:  format!(
                    "'{}' spawned '{}' which has malicious network activity: {}",
                    parent.label, child.label, AttackPattern::LateralMovement.description(),
                ),
                mitre_tactic: AttackPattern::LateralMovement.mitre_tactic().to_string(),
                confidence,
            });
        }
        result
    }

    fn detect_suspicious_spawn_agg(graph: &ThreatGraph, counter: &mut u32) -> Vec<AttackChain> {
        let mut result = Vec::new();
        for edge in graph.edges.iter().filter(|e| e.edge_type == EdgeType::ParentChild) {
            let parent = unwrap_or_continue!(graph.nodes.get(&edge.from));
            let child  = unwrap_or_continue!(graph.nodes.get(&edge.to));
            if is_clean(&parent.threat_level) || is_clean(&child.threat_level) { continue; }
            let score    = max_score(parent.combined_score, child.combined_score);
            let severity = worst_level(&parent.threat_level, &child.threat_level);
            // Confidence = the *weaker* side of the pair.  Both nodes must be
            // convincingly threatening for the propagation chain to be real;
            // using min() prevents a single strong node from masking a barely-
            // suspicious partner.  Bonus if both are confirmed Malicious/Critical
            // — that rules out benign parent processes that happen to be flagged.
            let base  = f32::min(parent.combined_score, child.combined_score);
            let both_malicious = !matches!(parent.threat_level.as_str(), "Suspicious")
                && !matches!(child.threat_level.as_str(), "Suspicious");
            let bonus = if both_malicious { 0.15 } else { 0.0 };
            let confidence = (base + bonus).clamp(0.0, 1.0);
            *counter += 1;
            result.push(AttackChain {
                chain_id:     format!("chain-{counter}"),
                pattern:      AttackPattern::SuspiciousSpawn,
                node_ids:     vec![edge.from.clone(), edge.to.clone()],
                chain_score:  score,
                severity,
                description:  format!(
                    "'{}' → '{}': {}",
                    parent.label, child.label, AttackPattern::SuspiciousSpawn.description(),
                ),
                mitre_tactic: AttackPattern::SuspiciousSpawn.mitre_tactic().to_string(),
                confidence,
            });
        }
        result
    }

    // ── Pattern 7: ExploitedTrustedProcess ───────────────────────────────────
    // A clean (trusted) process spawns a child that is Malicious — the most
    // common real-world attack delivery: phishing doc → Word.exe (clean) spawns
    // cmd.exe / powershell.exe (clean) which finally spawns the malicious payload.
    //
    // Intentionally stricter than SuspiciousSpawn:
    //   • Parent must be Clean — if the parent is already flagged, SuspiciousSpawn
    //     already covers it.
    //   • Child must be Malicious (not merely Suspicious) to avoid false positives
    //     from normal software chains (e.g. svchost spawning a suspicious helper).
    //
    // MITRE: T1059 (Command and Scripting Interpreter), T1204 (User Execution)

    fn detect_exploited_trusted_process_agg(
        graph: &ThreatGraph,
        counter: &mut u32,
    ) -> Vec<AttackChain> {
        let mut result = Vec::new();
        for edge in graph.edges.iter().filter(|e| e.edge_type == EdgeType::ParentChild) {
            let parent = unwrap_or_continue!(graph.nodes.get(&edge.from));
            let child  = unwrap_or_continue!(graph.nodes.get(&edge.to));

            // Parent must be clean; child must be confirmed Malicious.
            if !is_clean(&parent.threat_level) { continue; }
            if child.threat_level != "Malicious" { continue; }

            // Confidence = child's combined_score.  The parent is by definition
            // clean (its own signals are low), so the child's maliciousness is
            // the sole evidence quality indicator.  Because the child is already
            // confirmed Malicious (≥ threshold), confidence is always at least
            // moderate; saturated child scores push it toward 1.0.
            let confidence = child.combined_score.clamp(0.0, 1.0);
            *counter += 1;
            result.push(AttackChain {
                chain_id:     format!("chain-{counter}"),
                pattern:      AttackPattern::ExploitedTrustedProcess,
                node_ids:     vec![edge.from.clone(), edge.to.clone()],
                chain_score:  child.combined_score,
                severity:     child.threat_level.clone(),
                description:  format!(
                    "Trusted process '{}' spawned malicious child '{}' — \
                     possible exploitation or living-off-the-land delivery (T1059/T1204)",
                    parent.label, child.label,
                ),
                mitre_tactic: AttackPattern::ExploitedTrustedProcess.mitre_tactic().to_string(),
                confidence,
            });
        }
        result
    }

    /// Detect all attack chains in `graph` and return them sorted by score.
    #[allow(dead_code)]
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
            let ra = a.chain_score * a.confidence;
            let rb = b.chain_score * b.confidence;
            rb.partial_cmp(&ra).unwrap_or(std::cmp::Ordering::Equal)
        });

        deduplicate_chains(chains)
    }

    // ── Critical path (max-weight path with clean-ancestry tracing) ──────────
    //
    // Strategy:
    //  1. Collect threat nodes (non-Clean).
    //  2. Trace backwards through ParentChild edges from every threat node to
    //     find clean ancestor processes (the "delivery chain").  Real attacks
    //     almost always start clean: explorer → cmd → powershell → malware.
    //     Without this step the critical path would begin at the first malicious
    //     node and miss the full lineage.
    //  3. Build adjacency over (threat nodes ∪ clean ancestors).  Non-ancestry
    //     clean↔clean edges are still excluded to keep the search space bounded.
    //  4. Seed DFS from process-tree roots (nodes with no parent in scope) AND
    //     from every threat node (catches threat clusters not connected to a
    //     ParentChild chain).
    //  5. Edge weight = avg(score_a, score_b) × type_multiplier.  Clean nodes
    //     contribute 0 to the average, so ancestry hops add little weight by
    //     themselves; the max-path still gravitates toward the malicious tail,
    //     but the full lineage is preserved in the result.
    //  6. Depth limit raised to 10 to accommodate clean ancestors before the
    //     malicious tail (previously 6, which was fine when only threat nodes
    //     were in the graph, but too shallow once clean roots are included).
    //  7. Guard: winning path must contain at least one threat node.

    pub fn find_critical_path(graph: &ThreatGraph) -> Option<CriticalPath> {
        // ── Collect threat node IDs ────────────────────────────────────────────
        let threat_ids: HashSet<&str> = graph.nodes.values()
            .filter(|n| !is_clean(&n.threat_level))
            .map(|n| n.entity_id.as_str())
            .collect();

        if threat_ids.is_empty() {
            return None;
        }

        // ── Build parent_of map for ancestry traversal ─────────────────────────
        // child_id → parent_id, restricted to ParentChild edges.
        let parent_of: HashMap<&str, &str> = graph.edges.iter()
            .filter(|e| e.edge_type == EdgeType::ParentChild)
            .map(|e| (e.to.as_str(), e.from.as_str()))
            .collect();

        // ── Trace clean ancestors of every threat node ─────────────────────────
        // Walk ParentChild edges backwards until we hit a node that either has no
        // parent or is already a threat node.  Depth-limited to avoid traversing
        // very deep but entirely-clean process trees (e.g. system service chains).
        const MAX_ANCESTRY_DEPTH: usize = 8;

        let mut ancestry: HashSet<&str> = HashSet::new();
        let mut chain_roots: HashSet<&str> = HashSet::new();

        for &tid in &threat_ids {
            let mut cursor = tid;
            let mut depth  = 0usize;
            loop {
                if depth >= MAX_ANCESTRY_DEPTH { break; }
                match parent_of.get(cursor) {
                    Some(&parent) => {
                        ancestry.insert(parent);
                        cursor = parent;
                        depth += 1;
                    }
                    None => {
                        // cursor is the root of this process tree branch.
                        chain_roots.insert(cursor);
                        break;
                    }
                }
            }
        }

        // ── Build adjacency ────────────────────────────────────────────────────
        // Include:
        //   • Any edge where at least one endpoint is a *threat* node  (original rule).
        //   • ParentChild edges where both endpoints are in ancestry scope — these
        //     form the clean delivery chain that must be traversable.
        let ancestry_scope: HashSet<&str> = threat_ids.iter().copied()
            .chain(ancestry.iter().copied())
            .collect();

        let mut adj: HashMap<&str, Vec<(&str, f32, &str)>> = HashMap::new();

        for edge in &graph.edges {
            let from = edge.from.as_str();
            let to   = edge.to.as_str();

            let threat_anchored = threat_ids.contains(from) || threat_ids.contains(to);
            let ancestry_edge   = edge.edge_type == EdgeType::ParentChild
                                  && ancestry_scope.contains(from)
                                  && ancestry_scope.contains(to);

            if !threat_anchored && !ancestry_edge {
                continue;
            }

            let from_score = graph.nodes.get(from).map_or(0.0, |n| n.combined_score);
            let to_score   = graph.nodes.get(to  ).map_or(0.0, |n| n.combined_score);
            let weight     = GraphEdge::weight_for(from_score, to_score, &edge.edge_type);

            adj.entry(from).or_default().push((to,   weight, edge.edge_type.as_str()));
            adj.entry(to  ).or_default().push((from, weight, edge.edge_type.as_str()));
        }

        // ── DFS from chain roots + all threat nodes ────────────────────────────
        // Chain roots are the clean process-tree ancestors; starting there lets
        // the DFS discover the full delivery chain leading into the malicious tail.
        // Threat nodes are always included so isolated threat clusters are covered.
        let start_ids: HashSet<&str> = chain_roots.iter().copied()
            .chain(threat_ids.iter().copied())
            .collect();

        let mut best: Option<CriticalPath> = None;

        for &start in &start_ids {
            let mut visited: HashSet<&str>  = HashSet::new();
            let mut path_nodes: Vec<String> = vec![start.to_string()];
            let mut path_hops: Vec<(String, f32)> = Vec::new();
            visited.insert(start);

            dfs_max_path(
                start,
                0.0,
                &adj,
                &mut visited,
                &mut path_nodes,
                &mut path_hops,
                &mut best,
                10, // increased from 6: clean ancestors add hops before the malicious tail
            );
        }

        // Guard: discard any winning path that contains no threat node.
        // This prevents returning a purely clean path when the DFS seeds from roots.
        if best.as_ref().map_or(false, |p| {
            !p.node_ids.iter().any(|id| threat_ids.contains(id.as_str()))
        }) {
            best = None;
        }

        if let Some(ref mut path) = best {
            path.narrative = build_narrative(path, graph);
        }

        best
    }

    // ── Pattern 1: ProcessInjection ───────────────────────────────────────────

    #[allow(dead_code)]
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
                // Legacy flat graph: use mem node score as confidence proxy.
                confidence:   mem_node.combined_score.clamp(0.0, 1.0),
            });
        }
        result
    }

    // ── Pattern 2: C2Communication ────────────────────────────────────────────

    #[allow(dead_code)]
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
                // Legacy flat graph: use network node score as confidence proxy.
                confidence:   net_node.combined_score.clamp(0.0, 1.0),
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
                // Legacy flat graph: use file node score as confidence proxy.
                confidence:   file_node.combined_score.clamp(0.0, 1.0),
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

                let avg_score = (parent_node.combined_score + child_node.combined_score
                    + net_node.combined_score) / 3.0;
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
                    // Legacy flat: avg of three involved nodes' scores.
                    confidence:   avg_score.clamp(0.0, 1.0),
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

            let legacy_confidence = f32::min(parent.combined_score, child.combined_score)
                .clamp(0.0, 1.0);
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
                confidence:   legacy_confidence,
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

            // Confidence = avg node score × scanner-type diversity factor.
            // More distinct scanner domains (memory + network + file + process)
            // = more independent corroborating evidence → higher confidence.
            // Cap diversity at 3 unique types (diminishing returns beyond that).
            let avg_score: f32 = component.iter()
                .filter_map(|id| graph.nodes.get(*id))
                .map(|n| n.combined_score)
                .sum::<f32>() / component.len() as f32;
            let type_factor = (scanner_types.len() as f32 / 3.0).min(1.0);
            let confidence = (avg_score * type_factor).clamp(0.0, 1.0);
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
                confidence,
            });
        }
        result
    }
}

// ─── Graph feedback pass ─────────────────────────────────────────────────────

impl GraphAnalyzer {
    /// Push graph-layer findings back into node scores so that downstream
    /// consumers (serializer, UI) see scores that reflect structural importance,
    /// not just per-domain heuristics.
    ///
    /// Three refinements run in sequence, each capped to prevent runaway inflation:
    ///
    /// 1. **Critical-path boost** (max +0.15 per node) — nodes on the highest-weight
    ///    path are boosted proportionally to their edge-weight contribution.
    ///    High-weight hops → bigger boosts.
    ///
    /// 2. **Centrality boost** (max +0.10 per threat node) — nodes with many
    ///    cross-entity edges are structurally pivotal; their score is raised
    ///    proportional to degree / max_degree.
    ///
    /// 3. **Vector flag** (clean parent of Malicious child, +0.08) — a clean
    ///    trusted process that directly spawned a Malicious/Critical child is
    ///    marked `is_vector = true`.  Its score is raised to surface it in path
    ///    analysis even though its own heuristic score is low.
    ///
    /// After each boost the threat level is re-evaluated and escalated (never
    /// downgraded) if the new combined_score crosses the Suspicious (≥0.55) or
    /// Malicious (≥0.80) threshold.  Vectors always stay at their original level
    /// (usually Clean) so as not to generate false alarms.
    pub fn apply_graph_feedback(graph: &mut ThreatGraph) {
        // ── 1. Critical-path boost ────────────────────────────────────────────
        // Clone the path data first to avoid simultaneous mutable + immutable
        // borrows of `graph`.
        let cp_data: Option<(Vec<String>, Vec<f32>, f32)> = graph.critical_path
            .as_ref()
            .map(|cp| (cp.node_ids.clone(), cp.edge_weights.clone(), cp.total_score));

        if let Some((node_ids, edge_weights, total_score)) = cp_data {
            if total_score > 0.0 {
                let n = node_ids.len();
                for (i, node_id) in node_ids.iter().enumerate() {
                    // Each node's path contribution = avg of the edge weights it touches.
                    let contribution = if n == 1 {
                        total_score
                    } else if i == 0 {
                        edge_weights[0]
                    } else if i == n - 1 {
                        edge_weights[n - 2]
                    } else {
                        (edge_weights[i - 1] + edge_weights[i]) * 0.5
                    };

                    let path_importance = (contribution / total_score).clamp(0.0, 1.0);
                    let boost = 0.15 * path_importance;

                    if let Some(node) = graph.nodes.get_mut(node_id) {
                        node.graph_boost  += boost;
                        node.combined_score = (node.combined_score + boost).clamp(0.0, 1.0);
                        escalate_threat_level(node);
                    }
                }
            }
        }

        // ── 2. Centrality boost ───────────────────────────────────────────────
        // Compute undirected degree (in + out) for every node.
        let mut degree: HashMap<String, usize> = HashMap::new();
        for edge in &graph.edges {
            *degree.entry(edge.from.clone()).or_insert(0) += 1;
            *degree.entry(edge.to.clone()).or_insert(0) += 1;
        }

        let max_degree = degree.values().copied().max().unwrap_or(1).max(1);

        let centrality_boosts: Vec<(String, f32)> = degree
            .iter()
            .filter(|(id, &deg)| {
                deg >= 2 && graph.nodes.get(*id)
                    .map_or(false, |n| !is_clean(&n.threat_level))
            })
            .map(|(id, &deg)| {
                let boost = 0.10 * (deg as f32 / max_degree as f32);
                (id.clone(), boost)
            })
            .collect();

        for (id, boost) in centrality_boosts {
            if let Some(node) = graph.nodes.get_mut(&id) {
                node.graph_boost    += boost;
                node.combined_score  = (node.combined_score + boost).clamp(0.0, 1.0);
                escalate_threat_level(node);
            }
        }

        // ── 3. Vector flag ────────────────────────────────────────────────────
        // Collect qualifying (from, to) pairs before mutating the node map.
        let vector_parents: Vec<String> = graph.edges
            .iter()
            .filter(|e| e.edge_type == EdgeType::ParentChild)
            .filter(|e| {
                let parent_clean = graph.nodes.get(&e.from)
                    .map_or(false, |n| n.threat_level == "Clean");
                let child_malicious = graph.nodes.get(&e.to)
                    .map_or(false, |n| matches!(n.threat_level.as_str(), "Malicious" | "Critical"));
                parent_clean && child_malicious
            })
            .map(|e| e.from.clone())
            .collect();

        for parent_id in vector_parents {
            if let Some(node) = graph.nodes.get_mut(&parent_id) {
                node.is_vector       = true;
                node.graph_boost    += 0.08;
                node.combined_score  = (node.combined_score + 0.08).clamp(0.0, 1.0);
                // Intentionally do NOT escalate threat level — a vector stays
                // Clean; its elevated score is a positional indicator only.

                // LOLBin detection: if the vector is a known living-off-the-land
                // binary the UI displays an additional "LOLBin" badge to highlight
                // the abuse of a trusted Windows tool for payload delivery.
                node.is_lolbin = is_lolbin_label(&node.label);
            }
        }
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Escalate a node's threat_level if the new combined_score crosses a threshold.
/// Never downgrades an existing level.
fn escalate_threat_level(node: &mut GraphNode) {
    let new_level = if node.combined_score >= 0.80 {
        "Malicious"
    } else if node.combined_score >= 0.55 {
        "Suspicious"
    } else {
        return;
    };

    fn rank(s: &str) -> u8 {
        match s { "Critical" => 3, "Malicious" => 2, "Suspicious" => 1, _ => 0 }
    }
    if rank(new_level) > rank(&node.threat_level) {
        node.threat_level = new_level.to_string();
    }
}

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

// ─── Chain deduplication ─────────────────────────────────────────────────────
//
// MultiStageAttack fires on every connected threat component ≥3 nodes, which
// means it often duplicates LateralMovement / SuspiciousSpawn / C2Communication
// that already cover the same nodes with more specific descriptions.
//
// Rule: suppress MultiStageAttack chains whose node set is fully covered by the
// union of already-kept specific-pattern chains.  Specific chains are always
// kept, even when they share nodes with each other.

fn deduplicate_chains(chains: Vec<AttackChain>) -> Vec<AttackChain> {
    // Collect all nodes covered by non-MultiStageAttack chains.
    // Build an owned set so we can consume `chains` below.
    let specific_nodes: HashSet<String> = chains
        .iter()
        .filter(|c| c.pattern.as_str() != "MultiStageAttack")
        .flat_map(|c| c.node_ids.iter().cloned())
        .collect();

    chains
        .into_iter()
        .filter(|c| {
            if c.pattern.as_str() != "MultiStageAttack" {
                return true; // always keep specific chains
            }
            // Keep a MultiStageAttack only if it introduces at least one node
            // not already surfaced by a specific chain.
            c.node_ids.iter().any(|id| !specific_nodes.contains(id))
        })
        .collect()
}

// ─── Narrative builder ────────────────────────────────────────────────────────

/// Build a plain-English sentence that narrates the critical path in order.
///
/// Format:
///   "[A] [verb] [B], which [verb] [C], which [verb] [D]"
///
/// Example:
///   "malicious.docx was loaded by word.exe, which spawned powershell.exe,
///    which connected to TCP → 185.x.x.x:443"
fn build_narrative(path: &CriticalPath, graph: &ThreatGraph) -> String {
    if path.node_ids.is_empty() {
        return String::new();
    }

    let label = |id: &str| -> &str {
        graph.nodes.get(id).map(|n| n.label.as_str()).unwrap_or("?")
    };
    let etype = |id: &str| -> &str {
        graph.nodes.get(id).map(|n| n.entity_type.as_str()).unwrap_or("")
    };

    let mut sentence = label(&path.node_ids[0]).to_string();

    for i in 0..path.edge_types.len() {
        let from_id  = &path.node_ids[i];
        let to_id    = &path.node_ids[i + 1];
        let verb     = hop_verb(&path.edge_types[i], etype(from_id), etype(to_id));
        let to_label = label(to_id);

        if i == 0 {
            // First hop: "[A] [verb] [B]"
            sentence.push(' ');
        } else {
            // Subsequent hops: ", which [verb] [B]"
            sentence.push_str(", which ");
        }
        sentence.push_str(verb);
        sentence.push(' ');
        sentence.push_str(to_label);
    }

    sentence
}

/// Plain-English verb phrase for a single graph hop.
///
/// `from_type` and `to_type` are the entity_type strings
/// ("process" | "file" | "network" | "memory").
fn hop_verb(edge_type: &str, from_type: &str, _to_type: &str) -> &'static str {
    match edge_type {
        "network_owner" => match from_type {
            "process" => "connected to",
            _         => "was used by",
        },
        "process_opened_file" => match from_type {
            "file"    => "was loaded by",
            _         => "loaded",
        },
        "parent_child"      => "spawned",
        "memory_injection"  => match from_type {
            "process" => "has a suspicious memory region at",
            _         => "was injected into",
        },
        "shared_c2"         => "shares C2 infrastructure with",
        "same_process"      => "runs in the same process as",
        "shared_file_hash"  => "is the same binary as",
        _                   => "is linked to",
    }
}

// ─── Critical-path helpers ────────────────────────────────────────────────────
// Edge weights in the DFS use `GraphEdge::weight_for()` — the same canonical
// formula used by the graph builder — so stored GraphEdge.weight values and
// DFS path weights are always computed identically.

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
                narrative:    String::new(), // filled in by find_critical_path
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

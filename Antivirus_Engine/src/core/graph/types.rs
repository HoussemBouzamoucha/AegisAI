// File: src/core/graph/types.rs
// ThreatGraph — directed, weighted graph of EntityNodes.
//
// Nodes  → GraphNode (lightweight projection of EntityNode)
// Edges  → GraphEdge (relationship type + weight)
// Result → AttackChain (pattern-matched sequence of correlated threat nodes)
//
// The graph is assembled by GraphBuilder (O(n) via join-key indexes) and
// analysed by GraphAnalyzer (pattern DFS / BFS over the adjacency list).

use std::collections::HashMap;

// ─── Edge type ────────────────────────────────────────────────────────────────

/// Structural reason two entity nodes are connected.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EdgeType {
    /// Two entities (process / network / memory) share the same OS PID.
    SameProcess,
    /// A process (parent) spawned another process (child).
    ParentChild,
    /// A process's exe_path matches a scanned file entity's path.
    ProcessOpenedFile,
    /// Two file entities reference the same SHA-256 hash.
    SharedFileHash,
    /// Two network connections reach the same remote IP (shared C2 host).
    SharedC2,
    /// A process owns a suspicious / malicious network connection (PID match).
    NetworkOwner,
    /// A process is associated with a suspicious / malicious memory region (PID match).
    MemoryInjection,
}

impl EdgeType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SameProcess       => "same_process",
            Self::ParentChild       => "parent_child",
            Self::ProcessOpenedFile => "process_opened_file",
            Self::SharedFileHash    => "shared_file_hash",
            Self::SharedC2          => "shared_c2",
            Self::NetworkOwner      => "network_owner",
            Self::MemoryInjection   => "memory_injection",
        }
    }
}

// ─── Graph edge ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct GraphEdge {
    pub from:      String,
    pub to:        String,
    pub edge_type: EdgeType,
    /// avg(combined_score_from, combined_score_to) × edge-type multiplier.
    /// Both scores must be in [0, 1]; see `GraphEdge::weight_for`.
    pub weight:    f32,
}

impl GraphEdge {
    /// Canonical edge-weight formula shared by the graph builder and the
    /// critical-path DFS.
    ///
    /// `avg(score_a, score_b) × type_multiplier`
    ///
    /// Multipliers encode the relative severity of each relationship type:
    ///
    /// | EdgeType            | ×    | Rationale                              |
    /// |---------------------|------|----------------------------------------|
    /// | SharedC2            | 1.50 | shared C2 infra — strongest tie        |
    /// | MemoryInjection     | 1.35 | in-memory shellcode execution          |
    /// | NetworkOwner        | 1.25 | process owns a C2 connection           |
    /// | ParentChild         | 1.20 | process spawning chain                 |
    /// | ProcessOpenedFile   | 1.10 | file executed → process spawned        |
    /// | SameProcess         | 1.00 | structural PID grouping                |
    /// | SharedFileHash      | 0.90 | same binary, different path            |
    ///
    /// Both `score_a` and `score_b` must already be in `[0, 1]` (guaranteed
    /// after the per-domain normalization pass in entity/manager.rs).
    pub fn weight_for(score_a: f32, score_b: f32, edge_type: &EdgeType) -> f32 {
        let avg = (score_a + score_b) / 2.0;
        let multiplier = match edge_type {
            EdgeType::SharedC2          => 1.50,
            EdgeType::MemoryInjection   => 1.35,
            EdgeType::NetworkOwner      => 1.25,
            EdgeType::ParentChild       => 1.20,
            EdgeType::ProcessOpenedFile => 1.10,
            EdgeType::SameProcess       => 1.00,
            EdgeType::SharedFileHash    => 0.90,
        };
        avg * multiplier
    }
}

// ─── Graph node ───────────────────────────────────────────────────────────────

/// Lightweight projection of an entity for the graph layer.
///
/// For aggregated entity graphs `entity_type` is always `"entity"` and the
/// per-domain sub-scores + threat flags are populated.  Legacy flat-node graphs
/// (backward compat) still set `entity_type` to the domain name and leave
/// sub-scores at their zero defaults.
#[derive(Debug, Clone)]
pub struct GraphNode {
    pub entity_id:       String,
    /// "entity" (aggregated) | "process" | "file" | "network" | "memory" (legacy flat)
    pub entity_type:     String,
    /// "Clean" | "Suspicious" | "Malicious" | "Critical"
    pub threat_level:    String,
    pub combined_score:  f32,
    pub heuristic_score: i32,
    pub ml_score:        Option<f32>,
    /// Primary display string (process name, filename, "NET → IP:PORT", …).
    pub label:           String,
    pub sub_label:       Option<String>,

    // ── Aggregated-entity fields (zero/false for legacy flat nodes) ───────────
    pub process_score:         f32,
    pub network_score:         f32,
    pub memory_score:          f32,
    pub file_score:            f32,
    /// True when the entity has at least one malicious-flagged network connection.
    pub has_malicious_network: bool,
    /// True when the entity has at least one malicious-flagged memory region.
    pub has_malicious_memory:  bool,
    /// True when the entity has at least one malicious-flagged file.
    pub has_malicious_file:    bool,
    pub pid:                   Option<u32>,
    pub parent_pid:            Option<u32>,

    // ── Graph-feedback fields (set by GraphAnalyzer::apply_graph_feedback) ───
    /// Cumulative score added by the graph feedback pass (path boost + centrality
    /// boost + vector proximity).  Zero until the pass runs.
    pub graph_boost: f32,
    /// True when this node is Clean but is a direct parent of a Malicious/Critical
    /// child — marks it as an exploitation vector (living-off-the-land delivery).
    pub is_vector:   bool,
}

// ─── Attack pattern ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum AttackPattern {
    /// Process + malicious memory region sharing a PID → in-memory code injection.
    ProcessInjection,
    /// Process + malicious network connection sharing a PID → C2 beaconing.
    C2Communication,
    /// Malicious file entity linked to a running process via file path.
    MalwareExecution,
    /// Parent process chain that terminates in an external network connection.
    LateralMovement,
    /// 3+ structurally connected threat-level nodes (multi-scanner escalation).
    MultiStageAttack,
    /// A suspicious / malicious process spawned a suspicious / malicious child.
    SuspiciousSpawn,
    /// A clean (trusted) process spawned a child that is confirmed Malicious —
    /// classic delivery via living-off-the-land or exploitation of a legitimate binary.
    ExploitedTrustedProcess,
}

impl AttackPattern {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ProcessInjection         => "ProcessInjection",
            Self::C2Communication          => "C2Communication",
            Self::MalwareExecution         => "MalwareExecution",
            Self::LateralMovement          => "LateralMovement",
            Self::MultiStageAttack         => "MultiStageAttack",
            Self::SuspiciousSpawn          => "SuspiciousSpawn",
            Self::ExploitedTrustedProcess  => "ExploitedTrustedProcess",
        }
    }

    pub fn mitre_tactic(&self) -> &'static str {
        match self {
            Self::ProcessInjection         => "T1055 - Process Injection",
            Self::C2Communication          => "T1071 - Application Layer Protocol",
            Self::MalwareExecution         => "T1204 - User Execution",
            Self::LateralMovement          => "T1021 - Remote Services",
            Self::MultiStageAttack         => "TA0002 - Execution",
            Self::SuspiciousSpawn          => "T1059 - Command and Scripting Interpreter",
            Self::ExploitedTrustedProcess  => "T1059/T1204 - Execution via Trusted Process",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::ProcessInjection =>
                "Process is associated with a suspicious or malicious memory region \
                 — possible code injection or shellcode execution in-flight",
            Self::C2Communication =>
                "Process has an active connection to a suspicious or malicious remote host \
                 — possible command-and-control beaconing",
            Self::MalwareExecution =>
                "A malicious file on disk matches the executable path of a running process \
                 — possible malware execution",
            Self::LateralMovement =>
                "A process spawned a child process that subsequently opened an external network \
                 connection — possible lateral movement or dropper behaviour",
            Self::MultiStageAttack =>
                "Three or more threat indicators across different scanners are structurally \
                 linked — consistent with a multi-stage attack chain",
            Self::SuspiciousSpawn =>
                "A suspicious or malicious process spawned a child process that is also \
                 flagged as suspicious or malicious — possible propagation or privilege-escalation chain",
            Self::ExploitedTrustedProcess =>
                "A clean trusted process spawned a child that is confirmed Malicious \
                 — classic living-off-the-land delivery or exploitation of a legitimate binary",
        }
    }
}

// ─── Attack chain ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AttackChain {
    pub chain_id:     String,
    pub pattern:      AttackPattern,
    /// entity_ids in traversal order (root → leaf).
    pub node_ids:     Vec<String>,
    /// max combined_score among all member nodes.
    pub chain_score:  f32,
    /// "Suspicious" | "Malicious" | "Critical"
    pub severity:     String,
    pub description:  String,
    pub mitre_tactic: String,
}

// ─── Critical path ────────────────────────────────────────────────────────────

/// The maximum-weight simple path through the threat graph.
///
/// Computed by a depth-bounded DFS over the threat subgraph using
/// per-edge weights that incorporate both heuristic and ML scores.
/// `edge_types` and `edge_weights` have length `node_ids.len() - 1`.
#[derive(Debug, Clone)]
pub struct CriticalPath {
    /// Entity IDs in traversal order (source → sink).
    pub node_ids:     Vec<String>,
    /// Edge-type string for each hop (e.g. "network_owner", "memory_injection").
    pub edge_types:   Vec<String>,
    /// Weight of each hop (avg combined scores × edge-type severity multiplier).
    pub edge_weights: Vec<f32>,
    /// Cumulative sum of all hop weights — the "total path score".
    pub total_score:  f32,
    /// Plain-English sentence describing the full attack chain in traversal order.
    /// Example: "malicious.docx was loaded by word.exe, which spawned
    /// powershell.exe, which connected to TCP → 185.x.x.x:443"
    pub narrative:    String,
}

// ─── Threat graph ─────────────────────────────────────────────────────────────

pub struct ThreatGraph {
    pub nodes:         HashMap<String, GraphNode>,
    pub edges:         Vec<GraphEdge>,
    pub attack_chains: Vec<AttackChain>,
    /// The most malicious simple path found by the critical-path analyser.
    pub critical_path: Option<CriticalPath>,
    /// Forward adjacency list: entity_id → list of reachable entity_ids.
    pub adjacency:     HashMap<String, Vec<String>>,
}

impl ThreatGraph {
    pub fn new() -> Self {
        Self {
            nodes:         HashMap::new(),
            edges:         Vec::new(),
            attack_chains: Vec::new(),
            critical_path: None,
            adjacency:     HashMap::new(),
        }
    }

    pub fn add_node(&mut self, node: GraphNode) {
        self.adjacency.entry(node.entity_id.clone()).or_default();
        self.nodes.insert(node.entity_id.clone(), node);
    }

    pub fn add_edge(&mut self, edge: GraphEdge) {
        self.adjacency
            .entry(edge.from.clone())
            .or_default()
            .push(edge.to.clone());
        self.edges.push(edge);
    }

    /// Count of nodes whose threat_level is not Clean or Safe.
    pub fn threat_node_count(&self) -> usize {
        self.nodes.values()
            .filter(|n| !matches!(n.threat_level.as_str(), "Clean" | "Safe"))
            .count()
    }

    /// Recompute every `GraphEdge.weight` from the current `combined_score` of
    /// the two endpoint nodes.
    ///
    /// Call this after any pass that mutates node scores (e.g.
    /// `GraphAnalyzer::apply_graph_feedback`) so stored edge weights stay
    /// consistent with the scores the UI and serializer will read.
    pub fn refresh_edge_weights(&mut self) {
        // Snapshot scores first to satisfy the borrow checker
        // (self.nodes and self.edges are separate fields, but Rust doesn't know
        // that when we borrow self mutably for the edges loop).
        let scores: HashMap<String, f32> = self.nodes
            .iter()
            .map(|(id, n)| (id.clone(), n.combined_score))
            .collect();

        for edge in &mut self.edges {
            let sa = scores.get(&edge.from).copied().unwrap_or(0.0);
            let sb = scores.get(&edge.to  ).copied().unwrap_or(0.0);
            edge.weight = GraphEdge::weight_for(sa, sb, &edge.edge_type);
        }
    }
}

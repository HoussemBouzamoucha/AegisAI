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
    /// max(combined_score_from, combined_score_to) — used as path weight.
    pub weight:    f32,
}

// ─── Graph node ───────────────────────────────────────────────────────────────

/// Lightweight projection of EntityNode for the graph layer.
#[derive(Debug, Clone)]
pub struct GraphNode {
    pub entity_id:       String,
    /// "process" | "file" | "network" | "memory"
    pub entity_type:     String,
    /// "Clean" | "Suspicious" | "Malicious" | "Critical"
    pub threat_level:    String,
    pub combined_score:  f32,
    pub heuristic_score: i32,
    pub ml_score:        Option<f32>,
    /// Primary display string (process name, filename, "PROTO → IP:PORT", …).
    pub label:           String,
    pub sub_label:       Option<String>,
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
}

impl AttackPattern {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ProcessInjection => "ProcessInjection",
            Self::C2Communication  => "C2Communication",
            Self::MalwareExecution => "MalwareExecution",
            Self::LateralMovement  => "LateralMovement",
            Self::MultiStageAttack => "MultiStageAttack",
            Self::SuspiciousSpawn  => "SuspiciousSpawn",
        }
    }

    pub fn mitre_tactic(&self) -> &'static str {
        match self {
            Self::ProcessInjection => "T1055 - Process Injection",
            Self::C2Communication  => "T1071 - Application Layer Protocol",
            Self::MalwareExecution => "T1204 - User Execution",
            Self::LateralMovement  => "T1021 - Remote Services",
            Self::MultiStageAttack => "TA0002 - Execution",
            Self::SuspiciousSpawn  => "T1059 - Command and Scripting Interpreter",
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

// ─── Threat graph ─────────────────────────────────────────────────────────────

pub struct ThreatGraph {
    pub nodes:         HashMap<String, GraphNode>,
    pub edges:         Vec<GraphEdge>,
    pub attack_chains: Vec<AttackChain>,
    /// Forward adjacency list: entity_id → list of reachable entity_ids.
    pub adjacency:     HashMap<String, Vec<String>>,
}

impl ThreatGraph {
    pub fn new() -> Self {
        Self {
            nodes:         HashMap::new(),
            edges:         Vec::new(),
            attack_chains: Vec::new(),
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
}

// File: src/core/entity/types.rs
// Core entity types for the Entity Manager layer.
//
// Every scanner reduces its raw output to an EntityNode before it reaches
// the graph.  Each node carries both a heuristic score and (for network
// entities) an optional ML score so the graph can compute path-level
// significance without knowing which scanner produced the node.

use std::time::{SystemTime, UNIX_EPOCH};
use crate::core::types::DetectionSignal;

// ─── Unified threat level ─────────────────────────────────────────────────────
// Normalises the three different ThreatLevel enums used by the scanners into
// one canonical representation for the entity layer.

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UnifiedThreatLevel {
    Clean,
    Suspicious,
    Malicious,
    Critical,
}

impl UnifiedThreatLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Clean      => "Clean",
            Self::Suspicious => "Suspicious",
            Self::Malicious  => "Malicious",
            Self::Critical   => "Critical",
        }
    }

    pub fn is_threat(&self) -> bool {
        !matches!(self, Self::Clean)
    }
}

// Convert from core ThreatLevel (Clean / Suspicious / Malicious)
// Used by: network scanner, file scanner
impl From<&crate::core::types::ThreatLevel> for UnifiedThreatLevel {
    fn from(level: &crate::core::types::ThreatLevel) -> Self {
        match level {
            crate::core::types::ThreatLevel::Clean      => Self::Clean,
            crate::core::types::ThreatLevel::Suspicious => Self::Suspicious,
            crate::core::types::ThreatLevel::Malicious  => Self::Malicious,
        }
    }
}

// Convert from process ThreatLevel (Safe / Suspicious / Malicious / Critical)
// Used by: process scanner
impl From<&crate::core::process::types::ThreatLevel> for UnifiedThreatLevel {
    fn from(level: &crate::core::process::types::ThreatLevel) -> Self {
        match level {
            crate::core::process::types::ThreatLevel::Safe       => Self::Clean,
            crate::core::process::types::ThreatLevel::Suspicious => Self::Suspicious,
            crate::core::process::types::ThreatLevel::Malicious  => Self::Malicious,
            crate::core::process::types::ThreatLevel::Critical   => Self::Critical,
        }
    }
}

// ─── Entity type ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EntityType {
    Process,
    File,
    NetworkConnection,
    MemoryRegion,
}

impl EntityType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Process           => "process",
            Self::File              => "file",
            Self::NetworkConnection => "network",
            Self::MemoryRegion      => "memory",
        }
    }
}

// ─── Join keys ───────────────────────────────────────────────────────────────
// Structural keys used to correlate entities across scanner boundaries.
// The correlator groups entities that share the same join key value.
//
//   PID          → links Process ↔ NetworkConnection ↔ MemoryRegion
//   parent_pid   → links parent Process ↔ child Process
//   file_path    → links Process (exe_path) ↔ File
//   file_hash    → links File ↔ File (same binary, different paths)
//   remote_ip    → links NetworkConnection ↔ NetworkConnection (same C2)

#[derive(Debug, Clone, Default)]
pub struct JoinKeys {
    pub pid:        Option<u32>,
    pub parent_pid: Option<u32>,
    pub file_path:  Option<String>,
    pub file_hash:  Option<String>,
    pub remote_ip:  Option<String>,
    pub remote_port: Option<u16>,
}

// ─── Entity attributes ────────────────────────────────────────────────────────
// Type-specific fields preserved from the original scanner output.
// The graph layer can inspect these for richer path analysis.

#[derive(Debug, Clone)]
pub enum EntityAttributes {
    Process(ProcessAttributes),
    File(FileAttributes),
    Network(NetworkAttributes),
    Memory(MemoryAttributes),
}

#[derive(Debug, Clone)]
pub struct ProcessAttributes {
    pub pid:          u32,
    pub name:         String,
    pub exe_path:     Option<String>,
    #[allow(dead_code)]
    pub command_line: Option<String>,
    #[allow(dead_code)]
    pub user:         Option<String>,
    #[allow(dead_code)]
    pub parent_pid:   Option<u32>,
}

#[derive(Debug, Clone)]
pub struct FileAttributes {
    pub path:          String,
    #[allow(dead_code)]
    pub hash:          Option<String>,
    #[allow(dead_code)]
    pub category:      String,
    #[allow(dead_code)]
    pub context_flags: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct NetworkAttributes {
    pub protocol:       String,
    #[allow(dead_code)]
    pub local_address:  String,
    pub remote_address: String,
    pub state:          String,
    #[allow(dead_code)]
    pub pid:            Option<u32>,
    pub process_name:   Option<String>,
}

#[derive(Debug, Clone)]
pub struct MemoryAttributes {
    #[allow(dead_code)]
    pub pid:            u32,
    pub process_name:   String,
    pub region_start:   u64,
    pub region_size:    u64,
    pub protection:     String,
    #[allow(dead_code)]
    pub is_executable:  bool,
    #[allow(dead_code)]
    pub is_writable:    bool,
}

// ─── Aggregated entity ───────────────────────────────────────────────────────
// One composite entity per OS "actor" — a process plus all of its owned
// network connections, memory regions, and executable file evidence bundled
// together.  Orphan network connections (no owning process) and standalone
// malicious files each become their own entity.
//
// This is the unit the ThreatGraph operates on.  Intra-entity relationships
// (process ↔ its own network/memory/file) are embedded as sub-scores and
// threat flags; graph edges are only ever drawn *between* entities.

#[derive(Debug, Clone)]
pub struct AggregatedEntity {
    /// Stable ID: "entity:{pid}" | "entity-net:{net_id}" | "entity-file:{file_id}"
    pub entity_id:      String,
    /// Human-readable name (process name, "NET→ip:port", or filename).
    pub name:           String,
    pub threat_level:   UnifiedThreatLevel,
    /// Blended score across all domains (0.0–1.0).
    pub combined_score: f32,

    // Per-domain sub-scores [0, 1]
    pub process_score:  f32,
    pub network_score:  f32,
    pub memory_score:   f32,
    pub file_score:     f32,

    // Intra-entity threat flags (used by pattern detection without needing edges)
    pub has_malicious_network: bool,
    pub has_malicious_memory:  bool,
    pub has_malicious_file:    bool,

    // Embedded scanner evidence
    pub process:  Option<EntityNode>,
    pub network:  Vec<EntityNode>,
    pub memory:   Vec<EntityNode>,
    pub files:    Vec<EntityNode>,

    /// Merged detection signals from all sub-entities.
    #[allow(dead_code)]
    pub detection_signals: Vec<DetectionSignal>,

    // Join keys used to draw inter-entity graph edges
    pub pid:         Option<u32>,
    pub parent_pid:  Option<u32>,
    /// Unique non-loopback remote IPs across all owned network sub-entities.
    pub remote_ips:  Vec<String>,
    /// Unique SHA-256 hashes across all owned file sub-entities.
    pub file_hashes: Vec<String>,
    /// Max ML score from any owned network sub-entity.
    pub ml_score:    Option<f32>,
}

// ─── Entity node ──────────────────────────────────────────────────────────────
// The single unit that flows into the entity layer from every scanner.
//
// ml_score is only Some(_) for NetworkConnection entities — it is set either
// at ingestion time (if ML inference already ran) or later via
// EntityManager::update_ml_score().

#[derive(Debug, Clone)]
pub struct EntityNode {
    pub entity_id:         String,
    pub entity_type:       EntityType,
    #[allow(dead_code)]
    pub timestamp:         u64,
    pub heuristic_score:   i32,
    pub ml_score:          Option<f32>,
    pub threat_level:      UnifiedThreatLevel,
    pub detection_signals: Vec<DetectionSignal>,
    pub attributes:        EntityAttributes,
    pub join_keys:         JoinKeys,
}

impl EntityNode {
    pub fn new(
        entity_id:         String,
        entity_type:       EntityType,
        heuristic_score:   i32,
        ml_score:          Option<f32>,
        threat_level:      UnifiedThreatLevel,
        detection_signals: Vec<DetectionSignal>,
        attributes:        EntityAttributes,
        join_keys:         JoinKeys,
    ) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            entity_id,
            entity_type,
            timestamp,
            heuristic_score,
            ml_score,
            threat_level,
            detection_signals,
            attributes,
            join_keys,
        }
    }

    /// Normalised 0.0–1.0 score suitable for graph path weighting.
    ///
    /// Each domain has its own theoretical maximum derived from summing every
    /// rule that can simultaneously fire:
    ///   Process  → 110  (mutex 20 + handles 15 + cross-process 25 + 5 modules×10)
    ///   Memory   →  63  (RWX 25 + PE-header 20 + NOP sled 10 + INT3 sled 8)
    ///   Network  →  40  (largest single rule; stacked rules are clamped to 1.0)
    ///   File     →  40  (heuristic_score = confidence_score × 40, always in range)
    ///
    /// When an ML score is present it gets 60 % weight because the ML model
    /// operates on richer statistical features than the heuristic rules alone.
    pub fn combined_score(&self) -> f32 {
        let domain_max = match self.entity_type {
            EntityType::Process           => 110.0,
            EntityType::MemoryRegion      =>  63.0,
            EntityType::NetworkConnection =>  40.0,
            EntityType::File              =>  40.0,
        };
        let h = (self.heuristic_score as f32 / domain_max).clamp(0.0, 1.0);
        match self.ml_score {
            Some(ml) => h * 0.4 + ml.clamp(0.0, 1.0) * 0.6,
            None     => h,
        }
    }

    /// True if this entity contributed any threat signal.
    pub fn is_threat(&self) -> bool {
        self.threat_level.is_threat()
    }
}

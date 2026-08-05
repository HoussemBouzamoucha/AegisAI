// File: src/core/graph/mod.rs
// Threat graph layer — sits above the entity correlator and below the UI.
//
// Modules:
//   types    — GraphNode, GraphEdge, EdgeType, ThreatGraph, AttackChain, AttackPattern
//   builder  — GraphBuilder (O(n) construction via join-key indexes)
//   analyzer — GraphAnalyzer (attack-chain pattern detection)

pub mod analyzer;
pub mod builder;
pub mod types;

pub use analyzer::GraphAnalyzer;
pub use builder::build_from_aggregated;
pub use types::{
    AttackChain, CriticalPath, GraphEdge, GraphNode,
};

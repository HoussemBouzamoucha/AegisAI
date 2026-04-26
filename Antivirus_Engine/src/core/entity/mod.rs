// File: src/core/entity/mod.rs
// Entity Manager — normalises scanner outputs into EntityNodes and correlates
// them across scanner boundaries before the behavioural graph layer.
//
// Modules:
//   types      — EntityNode, EntityType, UnifiedThreatLevel, JoinKeys, EntityAttributes
//   manager    — EntityManager (ingestion + queries)
//   correlator — EntityCorrelator (cross-scanner cluster detection)

pub mod correlator;
pub mod manager;
pub mod types;

pub use correlator::{CorrelatedCluster, EntityCorrelator, JoinReason};
pub use manager::EntityManager;
pub use types::{
    AggregatedEntity, EntityAttributes, EntityNode, EntityType, FileAttributes, JoinKeys,
    MemoryAttributes, NetworkAttributes, ProcessAttributes, UnifiedThreatLevel,
};

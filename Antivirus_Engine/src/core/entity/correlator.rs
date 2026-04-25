// File: src/core/entity/correlator.rs
// EntityCorrelator — groups EntityNodes into clusters based on shared join keys.
//
// A cluster is a set of entities that are structurally related — same PID,
// same remote IP, same file, or a parent-child process chain.  The graph layer
// consumes these clusters as its initial node sets; edges are then drawn from
// the edge types defined in the graph module.
//
// The correlator does not modify the EntityManager — it is a read-only view.

use std::collections::HashMap;

use super::manager::EntityManager;
use super::types::{EntityNode, EntityType, UnifiedThreatLevel};

// ─── Cluster types ────────────────────────────────────────────────────────────

/// The structural reason two or more entities were grouped.
#[derive(Debug, Clone)]
pub enum JoinReason {
    /// All entities share the same OS process ID, or a File entity whose path
    /// matches the process executable path.
    /// Groups: Process ↔ File (exe) ↔ NetworkConnection ↔ MemoryRegion.
    SharedPid(u32),

    /// A process (child_pid) was spawned by another process (parent_pid).
    /// The full chain is reconstructed by the correlator.
    ParentChildChain { parent_pid: u32, child_pid: u32 },

    /// Multiple network connections to the same remote IP.
    /// Indicates possible shared C2 infrastructure.
    SharedRemoteIp(String),

    /// Multiple file entities with the same SHA-256 hash.
    /// Indicates the same binary present at different paths.
    SharedFileHash(String),
}

/// A set of related entities and the aggregate score of the cluster.
#[derive(Debug, Clone)]
pub struct CorrelatedCluster {
    /// The entity_id of the highest-scoring node in this cluster.
    pub anchor_id:    String,
    /// All entities belonging to this cluster (including the anchor).
    pub members:      Vec<EntityNode>,
    /// How the members were joined.
    pub join_reason:  JoinReason,
    /// Max combined_score across all members — used for graph prioritisation.
    pub cluster_score: f32,
    /// True if at least one member has a non-Clean threat level.
    pub has_threat:   bool,
}

impl CorrelatedCluster {
    fn build(members: Vec<EntityNode>, join_reason: JoinReason) -> Self {
        let cluster_score = members
            .iter()
            .map(|n| n.combined_score())
            .fold(0.0_f32, f32::max);

        let has_threat = members.iter().any(|n| n.is_threat());

        let anchor_id = members
            .iter()
            .max_by(|a, b| {
                a.combined_score()
                    .partial_cmp(&b.combined_score())
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|n| n.entity_id.clone())
            .unwrap_or_default();

        Self { anchor_id, members, join_reason, cluster_score, has_threat }
    }

    /// Highest unified threat level among all members.
    pub fn max_threat_level(&self) -> &UnifiedThreatLevel {
        self.members
            .iter()
            .map(|n| &n.threat_level)
            .max()
            .unwrap_or(&UnifiedThreatLevel::Clean)
    }
}

// ─── EntityCorrelator ─────────────────────────────────────────────────────────

pub struct EntityCorrelator<'a> {
    manager: &'a EntityManager,
}

impl<'a> EntityCorrelator<'a> {
    pub fn new(manager: &'a EntityManager) -> Self {
        Self { manager }
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /// Build all clusters from the current entity window.
    ///
    /// Returns one cluster per join key value.  An entity may appear in
    /// multiple clusters (e.g., a process node appears in both its PID cluster
    /// and its parent-child cluster).
    pub fn find_all_clusters(&self) -> Vec<CorrelatedCluster> {
        let nodes = self.manager.get_all();
        let mut clusters = Vec::new();

        clusters.extend(self.pid_clusters(&nodes));
        clusters.extend(self.parent_child_clusters(&nodes));
        clusters.extend(self.remote_ip_clusters(&nodes));
        clusters.extend(self.file_hash_clusters(&nodes));

        // Sort by cluster_score descending so the graph layer processes the
        // most suspicious clusters first.
        clusters.sort_by(|a, b| {
            b.cluster_score
                .partial_cmp(&a.cluster_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        clusters
    }

    /// All clusters that contain at least one threat-level entity.
    pub fn find_threat_clusters(&self) -> Vec<CorrelatedCluster> {
        self.find_all_clusters()
            .into_iter()
            .filter(|c| c.has_threat)
            .collect()
    }

    /// Cluster for a specific PID — returns None if fewer than 2 entity types
    /// are present (a lone process node has no cross-scanner correlation).
    pub fn get_pid_cluster(&self, pid: u32) -> Option<CorrelatedCluster> {
        let members = self.manager.get_by_pid(pid);
        if members.len() < 2 {
            return None;
        }
        Some(CorrelatedCluster::build(members, JoinReason::SharedPid(pid)))
    }

    /// Cluster for all entities connecting to a specific remote IP.
    pub fn get_remote_ip_cluster(&self, ip: &str) -> Option<CorrelatedCluster> {
        let members = self.manager.get_by_remote_ip(ip);
        if members.len() < 2 {
            return None;
        }
        Some(CorrelatedCluster::build(
            members,
            JoinReason::SharedRemoteIp(ip.to_string()),
        ))
    }

    // ── Private cluster builders ──────────────────────────────────────────────

    /// Group entities by pid.  Only emit a cluster when ≥2 entity *types*
    /// are present — a single process node alone is not a cross-scanner signal.
    ///
    /// File entities have no PID join key (the file scanner doesn't track which
    /// process owns a file), but a process's exe_path is stored in its
    /// join_keys.file_path.  We pull in any File entity whose file_path matches
    /// a process exe_path in the group so the cluster covers all four domains:
    /// Process ↔ File (executable) ↔ NetworkConnection ↔ MemoryRegion.
    fn pid_clusters(&self, nodes: &[EntityNode]) -> Vec<CorrelatedCluster> {
        // Build a lowercase file_path → File entity index.
        let mut file_by_path: HashMap<String, Vec<EntityNode>> = HashMap::new();
        for node in nodes {
            if node.entity_type == EntityType::File {
                if let Some(ref fp) = node.join_keys.file_path {
                    file_by_path
                        .entry(fp.to_lowercase())
                        .or_default()
                        .push(node.clone());
                }
            }
        }

        let mut by_pid: HashMap<u32, Vec<EntityNode>> = HashMap::new();
        for node in nodes {
            if let Some(pid) = node.join_keys.pid {
                by_pid.entry(pid).or_default().push(node.clone());
            }
        }

        by_pid
            .into_iter()
            .map(|(pid, mut members)| {
                // For every process in this PID group, pull in File entities
                // whose path equals the process executable path.
                let exe_paths: Vec<String> = members
                    .iter()
                    .filter(|n| n.entity_type == EntityType::Process)
                    .filter_map(|n| n.join_keys.file_path.as_deref().map(|p| p.to_lowercase()))
                    .collect();

                for exe_path in exe_paths {
                    if let Some(file_nodes) = file_by_path.get(&exe_path) {
                        for file_node in file_nodes {
                            if !members.iter().any(|m| m.entity_id == file_node.entity_id) {
                                members.push(file_node.clone());
                            }
                        }
                    }
                }

                (pid, members)
            })
            .filter(|(_, members)| has_multiple_entity_types(members))
            .map(|(pid, members)| {
                CorrelatedCluster::build(members, JoinReason::SharedPid(pid))
            })
            .collect()
    }

    /// Build parent → child process chains.
    /// For each process whose parent_pid matches another process in the window,
    /// emit a two-node cluster.  Deeper chains (grandparent → parent → child)
    /// are handled by the graph layer via iterative traversal.
    fn parent_child_clusters(&self, nodes: &[EntityNode]) -> Vec<CorrelatedCluster> {
        // Collect all PIDs of process entities present in the window
        let process_pids: std::collections::HashSet<u32> = nodes
            .iter()
            .filter(|n| n.entity_type == EntityType::Process)
            .filter_map(|n| n.join_keys.pid)
            .collect();

        let mut clusters = Vec::new();

        for node in nodes {
            if node.entity_type != EntityType::Process {
                continue;
            }
            let Some(child_pid)  = node.join_keys.pid        else { continue };
            let Some(parent_pid) = node.join_keys.parent_pid else { continue };

            // Only emit if the parent process is also in the entity window
            if !process_pids.contains(&parent_pid) {
                continue;
            }

            let parent_nodes = self.manager.get_by_pid(parent_pid)
                .into_iter()
                .filter(|n| n.entity_type == EntityType::Process)
                .collect::<Vec<_>>();

            let child_nodes = self.manager.get_by_pid(child_pid)
                .into_iter()
                .filter(|n| n.entity_type == EntityType::Process)
                .collect::<Vec<_>>();

            let mut members = parent_nodes;
            members.extend(child_nodes);

            if members.len() >= 2 {
                clusters.push(CorrelatedCluster::build(
                    members,
                    JoinReason::ParentChildChain { parent_pid, child_pid },
                ));
            }
        }

        clusters
    }

    /// Group network entities by remote_ip.
    /// Only emit when ≥2 distinct PIDs connect to the same remote IP — a
    /// single process connecting multiple times to the same host is normal.
    fn remote_ip_clusters(&self, nodes: &[EntityNode]) -> Vec<CorrelatedCluster> {
        let mut by_ip: HashMap<String, Vec<EntityNode>> = HashMap::new();
        for node in nodes {
            if node.entity_type != EntityType::NetworkConnection {
                continue;
            }
            if let Some(ip) = &node.join_keys.remote_ip {
                by_ip.entry(ip.clone()).or_default().push(node.clone());
            }
        }

        by_ip
            .into_iter()
            .filter(|(_, members)| {
                // Require ≥2 distinct PIDs to flag shared C2
                let distinct_pids: std::collections::HashSet<Option<u32>> =
                    members.iter().map(|n| n.join_keys.pid).collect();
                distinct_pids.len() >= 2
            })
            .map(|(ip, members)| {
                CorrelatedCluster::build(members, JoinReason::SharedRemoteIp(ip))
            })
            .collect()
    }

    /// Group file entities by hash — same binary at different paths.
    fn file_hash_clusters(&self, nodes: &[EntityNode]) -> Vec<CorrelatedCluster> {
        let mut by_hash: HashMap<String, Vec<EntityNode>> = HashMap::new();
        for node in nodes {
            if node.entity_type != EntityType::File {
                continue;
            }
            if let Some(hash) = &node.join_keys.file_hash {
                by_hash.entry(hash.clone()).or_default().push(node.clone());
            }
        }

        by_hash
            .into_iter()
            .filter(|(_, members)| members.len() >= 2)
            .map(|(hash, members)| {
                CorrelatedCluster::build(members, JoinReason::SharedFileHash(hash))
            })
            .collect()
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn has_multiple_entity_types(nodes: &[EntityNode]) -> bool {
    let first_type = nodes.first().map(|n| &n.entity_type);
    nodes.iter().any(|n| Some(&n.entity_type) != first_type)
}

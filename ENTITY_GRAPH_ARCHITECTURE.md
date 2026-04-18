# Entity Manager & Threat Graph Architecture

## Overview

AegisAI uses a three-tier detection architecture that sits above the four raw scanners and feeds the UI:

```
┌─────────────────────────────────────────────────────────────────┐
│                       Raw Scanners                              │
│   ProcessScanner  FileScanner  NetworkScanner  MemoryScanner    │
└───────────────────────────┬─────────────────────────────────────┘
                            │  (ingest_process / ingest_file /
                            │   ingest_network / ingest_memory)
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Entity Manager                              │
│  Normalises scanner output → EntityNode  (unified scoring,      │
│  join keys, sliding time window)                                │
│  EntityCorrelator → CorrelatedCluster (PID / ParentChild /      │
│                                        SharedIP / SharedHash)   │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Threat Graph                                │
│  GraphBuilder  → ThreatGraph  (nodes + edges, O(n) build)       │
│  GraphAnalyzer → AttackChain  (6 MITRE-mapped patterns)         │
└───────────────────────────┬─────────────────────────────────────┘
                            │  (JSON via "correlate" daemon cmd)
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                        Tauri UI                                 │
│  EntityManager.tsx  (flat view · cluster view · attack chains)  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Tier 1 — Entity Manager

### EntityNode

Every scanner reduces its output to a single `EntityNode` before anything else. This is the normalisation contract that lets the rest of the pipeline be scanner-agnostic.

| Field | Type | Description |
|---|---|---|
| `entity_id` | `String` | Stable key: `"proc:PID:name"`, `"file:SHA256"`, `"net:proto:local:remote"`, `"mem:PID:0xADDR"` |
| `entity_type` | `EntityType` | `Process \| File \| NetworkConnection \| MemoryRegion` |
| `heuristic_score` | `i32` | Raw score from the scanner's rule engine |
| `ml_score` | `Option<f32>` | 0–1, only populated for network entities (UNSW-NB15 ML model) |
| `combined_score()` | `f32` | `H×0.4 + ML×0.6` when ML is present, otherwise `H/40` clamped |
| `threat_level` | `UnifiedThreatLevel` | Normalised from scanner-specific enums to `Clean \| Suspicious \| Malicious \| Critical` |
| `join_keys` | `JoinKeys` | Structural correlation handles: `pid`, `parent_pid`, `file_path`, `file_hash`, `remote_ip` |
| `attributes` | `EntityAttributes` | Type-specific fields preserved from scanner output |

### Dual-signal Scoring

Network entities carry two independent scores:

- **Heuristic (H)**: Deterministic rule engine. Fast. Explains itself via `DetectionSignal` records.
- **ML (ML)**: UNSW-NB15 calibrated gradient-boosted model. Catches statistical anomalies the rules miss.
- **Combined (Σ)**: `H×0.4 + ML×0.6` — ML gets higher weight because it operates on richer statistical features. Both scores are normalised to 0–1 before blending.

The `update_ml_score()` method allows the ML pipeline result to be patched in asynchronously after heuristic ingestion. Threat level is only ever *escalated* by this patch — never downgraded.

### Sliding Time Window

`EntityManager` wraps a `DashMap<String, EntityNode>` with a `window_secs` bound (default: 600 s = 10 min). `prune_expired()` removes nodes older than the window. This prevents memory growth during continuous monitoring.

`DashMap` is used rather than `RwLock<HashMap>` because it shards the map into independent buckets, allowing concurrent reads and writes without a global lock. Ingest calls from multiple scanners can proceed simultaneously.

---

## Tier 1b — Entity Correlator

`EntityCorrelator` is a **read-only view** over `EntityManager`. It groups entities into `CorrelatedCluster` objects using four structural strategies:

| Strategy | Join Key | Detects |
|---|---|---|
| `SharedPid` | `pid` | Entities from different scanners belonging to the same OS process. Requires ≥2 distinct entity types. |
| `ParentChildChain` | `parent_pid → pid` | A process spawned by another process both present in the window. |
| `SharedRemoteIp` | `remote_ip` | Multiple network connections reaching the same IP from ≥2 distinct PIDs — shared C2 infrastructure. |
| `SharedFileHash` | `file_hash` | The same binary (SHA-256) present at ≥2 different filesystem paths — lateral copy or dropper. |

Each `CorrelatedCluster` carries:
- `cluster_score`: max `combined_score` across all members — used for graph prioritisation.
- `has_threat`: true if any member is non-Clean.
- `max_threat_level()`: the worst threat level among members.
- `anchor_id`: entity_id of the highest-scoring member.

---

## Tier 2 — Threat Graph

### Graph Construction (`GraphBuilder`)

`GraphBuilder` converts the live entity window into a directed, weighted `ThreatGraph`.

**Optimisation — O(n) instead of O(n²):**

Naïve edge discovery iterates all pairs: O(n²). `GraphBuilder` avoids this by building five index maps during a single O(n) pass:

```
by_pid:       HashMap<u32, Vec<entity_id>>    — PID → all entities with that PID
by_parent:    HashMap<u32, Vec<entity_id>>    — parent_pid → all children
by_file_path: HashMap<String, Vec<entity_id>> — file path (lowercase) → entities
by_file_hash: HashMap<String, Vec<entity_id>> — SHA-256 → entities
by_remote_ip: HashMap<String, Vec<entity_id>> — remote IP → network entities
```

Then for each entity, its join keys are looked up against these maps in O(1) per map. Total edge discovery is O(n · avg_cluster_size), which is O(n) in the typical case where clusters are small.

**Deduplication:** A `HashSet<(String, String)>` of canonical pairs `(min(a,b), max(a,b))` ensures each undirected edge is emitted exactly once regardless of traversal direction.

### Edge Types

| EdgeType | How it's created | What it means |
|---|---|---|
| `SameProcess` | Shared PID, no more specific type | Two non-process entities share an OS process |
| `ParentChild` | `parent_pid → pid` index | A process spawned another |
| `ProcessOpenedFile` | Process `file_path` matches a File `entity_id` | A scanned file is the executable of a running process |
| `SharedFileHash` | Same `file_hash` across two File entities | Same binary at different paths |
| `SharedC2` | Same `remote_ip` across two Network entities from different PIDs | Shared command-and-control host |
| `NetworkOwner` | Process ↔ NetworkConnection sharing PID | Process owns the connection |
| `MemoryInjection` | Process ↔ MemoryRegion sharing PID | Process is associated with suspicious memory |

Edge **weight** = `max(combined_score_from, combined_score_to)`. This lets path-scoring algorithms use the highest-risk node in the edge as the path weight without double-counting.

### Attack Chain Detection (`GraphAnalyzer`)

`GraphAnalyzer` implements six MITRE ATT&CK-mapped pattern detectors, each operating as an independent method over the built graph:

#### 1. ProcessInjection — T1055
Triggered by a `MemoryInjection` edge where the memory-region endpoint is non-Clean.

**Logic:** Scan all `MemoryInjection` edges. If the memory node is Suspicious/Malicious, emit a chain linking the process and its memory region. Indicates shellcode or injected code executing inside a legitimate process.

#### 2. C2Communication — T1071
Triggered by a `NetworkOwner` edge where the network endpoint is non-Clean.

**Logic:** Scan all `NetworkOwner` edges. If the network node is flagged, emit a chain. The ML model's 60% weight in `combined_score` makes this particularly sensitive to beaconing patterns the heuristics might miss.

#### 3. MalwareExecution — T1204
Triggered by a `ProcessOpenedFile` edge where the file endpoint is non-Clean.

**Logic:** Scan all `ProcessOpenedFile` edges. If the file (from which the process was spawned) is malicious, emit a chain. The edge direction is **file → process** to reflect execution causality.

#### 4. LateralMovement — T1021
Triggered by a `ParentChild` edge followed by a `NetworkOwner` edge from the child.

**Logic:** For each parent → child edge, look for NetworkOwner edges from the child to a non-Clean network node. Indicates a spawned process that immediately opens an outbound connection — a common dropper or lateral movement pattern.

#### 5. SuspiciousSpawn — T1059
Triggered by a `ParentChild` edge where **both** parent and child are threat-level entities.

**Logic:** Both endpoints must be non-Clean. Distinguishes from LateralMovement (which requires a downstream network connection) and focuses on the propagation chain itself.

#### 6. MultiStageAttack — TA0002
BFS over an undirected view of the graph, seeded from unvisited threat nodes.

**Logic:** Build an undirected adjacency list from all edges. BFS only traverses edges between threat-level nodes (clean nodes act as barriers). Any connected component with ≥ 3 threat nodes is emitted as a multi-stage chain. The description includes the count of distinct scanner types involved, giving an immediate sense of breadth.

**Optimisation:** Each threat node is visited at most once across all BFS runs via a shared `visited: HashSet`. Total BFS complexity is O(V + E) where V and E are the threat-node subgraph sizes.

---

## Tier 3 — Daemon Command

### `correlate` Command

The daemon exposes a `"correlate"` JSON command that orchestrates all three tiers in a single request:

```json
{ "cmd": "correlate", "include_memory": false }
```

`include_memory` controls whether the memory scanner runs (default: `false`). Memory scanning is the slowest sub-scan (can take 30–120 s on a loaded system) so it is opt-in. Process + network correlation completes in under 10 s.

**Response:**
```json
{
  "id": "...",
  "success": true,
  "entities":  [ ...EntityNode... ],
  "clusters":  [ ...CorrelatedCluster... ],
  "graph": {
    "nodes":         [ ...GraphNode... ],
    "edges":         [ ...GraphEdge... ],
    "attack_chains": [ ...AttackChain... ]
  },
  "statistics": {
    "total_entities":         42,
    "threat_entities":        7,
    "process_entities":       30,
    "network_entities":       12,
    "memory_entities":        0,
    "total_clusters":         5,
    "threat_clusters":        3,
    "graph_nodes":            42,
    "graph_edges":            18,
    "attack_chains_detected": 2,
    "include_memory":         false,
    "scan_duration_ms":       3200
  }
}
```

### Tauri Bridge

`correlate_entities(includeMemory?: boolean)` in `UI/src-tauri/src/main.rs` forwards the request to the daemon with a timeout of 60 s (no memory) or 180 s (with memory).

---

## UI Integration

### Three View Modes

| Mode | Data Source | Description |
|---|---|---|
| **Flat List** | Client-side (from Redux store) | All entity types, filter by type/threat/search, sortable by score |
| **Clusters** | Backend (after CORRELATE) or client-side fallback | Backend shows all 4 cluster types; client fallback shows PID-only clusters |
| **Attack Chains** | Backend only | Requires CORRELATE; shows chains with MITRE tagging, severity, node traversal |

### Cluster View — Backend vs. Fallback

Before `CORRELATE` is run, the cluster view shows **client-side PID clusters** (entities from the Redux store grouped by shared PID). After `CORRELATE`, it switches to **backend clusters** which include all four join strategies and the full `max_threat_level` / `cluster_score` from the Rust correlator.

The distinction is shown with a banner: `"Backend correlation active · N clusters · 4 strategies"`.

### Attack Chain Card

Each `AttackChain` renders as an expandable card showing:
- Pattern badge (colour-coded by severity)
- Chain score (0–100%)
- Full description from the analyzer
- MITRE ATT&CK technique ID
- Ordered node list with per-node type badge, label, and combined score

### CORRELATE Button

The toolbar includes a `CORRELATE` button with a spinner while in-flight. An `Include memory scan` checkbox toggles the `include_memory` flag. A `CLEAR` button resets the backend result and returns to client-side mode.

---

## Optimisations Summary

| Component | Technique | Benefit |
|---|---|---|
| `EntityManager` | `DashMap` sharded concurrent map | No global lock during multi-scanner ingestion |
| `EntityManager` | Sliding time window + `prune_expired()` | Bounded memory under continuous operation |
| `GraphBuilder` | 5 join-key index maps | O(n) edge discovery vs. O(n²) naive pairs |
| `GraphBuilder` | `HashSet<(min,max)>` deduplication | Each undirected edge emitted exactly once |
| `GraphAnalyzer` | Independent pattern methods | New patterns added without modifying existing code |
| `GraphAnalyzer` | BFS visited set shared across all seeds | Each threat node visited once total, O(V+E) |
| `WARM_SYSTEM` singleton | OnceLock+Mutex in process scanner | Avoids 200 ms sleep on every scan call |
| `memory_scan_lock` | AtomicBool CAS | Rejects concurrent memory scans before they stack up |
| ML score update | `update_ml_score()` patch after heuristic ingest | ML pipeline can run asynchronously; entity is usable immediately |

---

## File Map

```
Antivirus_Engine/src/core/
├── entity/
│   ├── mod.rs          — Re-exports
│   ├── types.rs        — EntityNode, EntityType, UnifiedThreatLevel, JoinKeys
│   ├── manager.rs      — EntityManager (ingest + queries + pruning)
│   └── correlator.rs   — EntityCorrelator (4 cluster strategies)
│
└── graph/
    ├── mod.rs          — Re-exports
    ├── types.rs        — ThreatGraph, GraphNode, GraphEdge, EdgeType, AttackChain
    ├── builder.rs      — GraphBuilder (O(n) via join-key indexes)
    └── analyzer.rs     — GraphAnalyzer (6 attack-chain patterns)

Antivirus_Engine/src/main.rs
  + serialize_entity_node()   — EntityNode → serde_json::Value
  + serialize_cluster()       — CorrelatedCluster → serde_json::Value
  + serialize_graph_node/edge/attack_chain()
  + daemon_correlate()        — Orchestrates all tiers, returns full payload
  + "correlate" daemon arm

UI/src-tauri/src/main.rs
  + correlate_entities()      — Tauri command, forwards to daemon

UI/src/types/index.ts
  + CorrelateEntityNode, CorrelateCluster, JoinReason
  + GraphNodeData, GraphEdgeData, AttackChain, CorrelateGraph
  + CorrelateResult, CorrelateStats

UI/src/store/index.ts
  + correlating, correlateResult, correlateError
  + correlateEntities(includeMemory?), clearCorrelate()

UI/src/components/EntityManager.tsx
  + BackendClusterRow   — Renders all 4 cluster types with appropriate icons
  + AttackChainCard     — Expandable card with MITRE, severity, node traversal
  + CORRELATE button    — Triggers backend correlation with spinner
  + Attack chains view  — New third view mode
  + Cluster view upgrade — Backend clusters preferred over client-side fallback
```

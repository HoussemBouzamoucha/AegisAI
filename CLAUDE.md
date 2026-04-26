# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**AegisAI** — multi-layer Windows antivirus + IDS. Three components:
- **Rust scanning engine** (`Antivirus_Engine/`) — four domain scanners + entity/graph pipeline
- **Python ML models** (`Antivirus_Engine/src/core/*/ML_models/`, `ai_agent/`) — per-domain ML
- **Tauri desktop app** (`UI/`) — React/TypeScript frontend + Rust Tauri backend

## Build & Run Commands

```bash
# Rust engine
cd Antivirus_Engine && cargo build --release
cargo test --release

# Tauri UI
cd UI && npm install
npm run tauri dev      # hot reload
npm run tauri build    # package
npx tsc                # type-check only

# Python ML (per-domain)
cd Antivirus_Engine/src/core/network/Feature_extractor/ML_IDS
python preprocessing_pipeline.py   # train + infer (network XGBoost)

cd Antivirus_Engine/src/core/process/Sys_API
python preprocessing_pipeline.py   # train GRU on API sequences

cd Antivirus_Engine/src/core/memory/ML_models/Deep_dive
python preprocessing_pipeline.py   # train memory model

# Smoke test
python diagnostic_test.py
```

## Architecture

### Data Flow
```
Tauri UI (invoke)
  → UI/src-tauri/src/main.rs  (IPC commands, daemon lifecycle)
  → antivirus daemon stdin (JSON-RPC, one-line per request/response)
  → Domain scanners → EntityNode signals
  → EntityManager (10-min sliding window, combined_score = H×0.4 + ML×0.6)
  → EntityCorrelator → CorrelatedCluster[]
  → GraphBuilder → ThreatGraph (nodes + edges)
  → GraphAnalyzer → AttackChain[] + CriticalPath
  → JSON → Tauri IPC → Zustand store → React components
```

### Daemon JSON-RPC Protocol
The daemon reads one JSON line from stdin, writes one JSON line to stdout.

**Request format:** `{ "id": "uuid", "cmd": "...", ...args }`

| cmd | extra args | notes |
|-----|-----------|-------|
| `scan-file` | `path` | |
| `scan-dir` | `path` | |
| `scan-processes` | — | |
| `scan-network` | `pid?` | |
| `scan-memory` | `pid?` | |
| `kill-process` | `pid` | |
| `correlate` | `include_memory: bool` | full entity/graph pipeline |
| `ping` | — | returns `{status:"pong"}` |

**Startup:** daemon prints `{"status":"ready"}` then blocks on stdin.

### Tauri IPC Commands (UI/src-tauri/src/main.rs)
`invoke('scan_file', {path})` · `invoke('scan_directory', {path})` · `invoke('scan_processes')` · `invoke('scan_network', {pid?})` · `invoke('scan_memory', {pid?})` · `invoke('kill_process', {pid})` · `invoke('correlate_entities', {includeMemory})` · `invoke('run_ml_ids', {csvPath?})` · `invoke('get_engine_status')`

### Four Scanner Domains (`Antivirus_Engine/src/core/<domain>/`)
- **file_system/** — YARA-X rules, SHA-256 hash DB, heuristics, ransomware context flags
- **process/** — Windows API call sequences via `API_feature_extractor.rs`; GRU inference in `Sys_API/`
- **network/** — pcap capture → `OnePace.csv` (47 UNSW-NB15 features) → XGBoost IDS
- **memory/** — VirtualQueryEx region analysis, shellcode heuristics, ML scoring

### Entity Graph Pipeline
1. **`entity/manager.rs`** — ingests all scanner outputs; `combined_score = (h/40)×0.4 + ml×0.6`; auto-prunes after 10 min; `apply_parent_context_boost()` boosts child scores when parent is threat
2. **`entity/manager.rs::aggregate()`** — groups flat `EntityNode`s into `AggregatedEntity` objects (one per process PID); embeds owned network/memory/file sub-entities; orphan network connections and standalone malicious files each become their own entity
3. **`entity/correlator.rs`** — groups nodes by shared PID / parent_pid / remote_ip / file_hash → `CorrelatedCluster` (used for the EntityManager UI view, not the graph)
4. **`graph/builder.rs::build_from_aggregated()`** — builds `ThreatGraph` from `AggregatedEntity` slice; only 3 inter-entity edge types:
   - `SharedC2` ×1.50, `ParentChild` ×1.20, `SharedFileHash` ×0.90
5. **`graph/analyzer.rs::find_attack_chains_aggregated()`** — patterns 1–3 (ProcessInjection, C2Communication, MalwareExecution) read intra-entity flags (`has_malicious_memory/network/file`) on each node; patterns 4–6 (LateralMovement, SuspiciousSpawn, MultiStageAttack) use inter-entity edges
6. **`graph/analyzer.rs::find_critical_path()`** — DFS max-weight path, unchanged

### Attack Patterns (MITRE mapped)
| Pattern | MITRE | Detection method |
|---------|-------|-----------------|
| ProcessInjection | T1055 | node.has_malicious_memory == true |
| C2Communication | T1071 | node.has_malicious_network == true |
| MalwareExecution | T1204 | node.has_malicious_file == true |
| LateralMovement | T1021 | ParentChild edge + child.has_malicious_network |
| SuspiciousSpawn | T1059 | ParentChild edge + both nodes are threats |
| MultiStageAttack | TA0002 | BFS over threat entities ≥3 nodes |

### Core Types (`Antivirus_Engine/src/core/`)
- `types.rs` — `ThreatLevel {Clean,Suspicious,Malicious}`, `ScanResult`, `DetectionSignal`, `FileCategory`, `ContextFlag`
- `entity/types.rs` — `UnifiedThreatLevel {Clean,Suspicious,Malicious,Critical}`, `EntityNode`, `EntityType`, `JoinKeys`, `EntityAttributes`, **`AggregatedEntity`** (composite entity with embedded sub-entities + per-domain sub-scores + threat flags)
- `graph/types.rs` — `ThreatGraph`, `GraphNode` (extended with `process/network/memory/file_score`, `has_malicious_*` flags, `pid`, `parent_pid`), `GraphEdge`, `EdgeType`, `AttackChain`, `CriticalPath`

### Entity ID Formats
**Flat `EntityNode` IDs** (stored in `EntityManager`, used by EntityManager UI view):
- Process: `proc:{pid}:{name}`
- Network: `net:{proto}:{local_address}:{remote_address}`
- Memory: `mem:{pid}:{region_start_hex}`
- File: `file:{sha256}` or `file:{path}`

**`AggregatedEntity` IDs** (used by ThreatGraph):
- Process-anchored: `entity:{pid}`
- Orphan network: `entity-net:{net_entity_id}`
- Standalone file: `entity-file:{file_entity_id}`

### ML Models & Files
| Domain | Model file | Location |
|--------|-----------|----------|
| Network | `ids_network_calibrated.pkl` / `ids_network_model.pkl` + `ordinal_encoder.joblib` + freq maps | `Antivirus_Engine/models/network/` |
| Process | GRU weights + `config.json` (vocab, MAX_LEN=177) | `Antivirus_Engine/src/core/process/Sys_API/` |
| Memory | trained classifier | `Antivirus_Engine/src/core/memory/ML_models/` |

Network ML flow: `NetworkScanner` writes `OnePace.csv` → `run_ml_and_patch_scores()` calls `preprocessing_pipeline.py --infer --csv PATH` → patches `ml_score` on network entities via `EntityManager::update_ml_score()`.

Process ML: API call sequences (min 5, max 177, stride 100) → GRU → malicious probability.

Memory ML: `Deep_dive/` diagnostic + inference pipeline (leakage/overfitting checks included).

### UI Structure (`UI/src/`)
- `App.tsx` — routes across 8 views: `dashboard|scanner|processes|network|memory|history|entities|graph`
- `store/index.ts` — Zustand store; all async state + scanner calls
- `types/index.ts` — all TypeScript types; `EntityKind` includes `"entity"` (aggregated); `GraphNodeData` extended with `process/network/memory/file_score`, `has_malicious_*`, `pid`, `parent_pid`
- `lib/entityUtils.ts` — `buildProcessEntities()` (client-side aggregation for EntityManager view), `buildProcessEdges()` (inter-entity edges), `orphanConnections()`, `orphanFiles()`
- `components/ThreatGraph.tsx` — fallback path uses `buildProcessEntities` to build entity nodes; legend shows only 3 inter-entity edge types; `NodeIcon` picks icon based on dominant sub-score; `SubChip` row shows PROC/NET/MEM/FILE breakdown in detail panel
- Components: `Dashboard`, `Scanner`, `ProcessMonitor`, `NetworkMonitor`, `MemoryMonitor`, `EntityManager`, `ThreatGraph`, `History`, `Sidebar`, `TitleBar`

## Key Design Decisions

- **Daemon mode**: YARA compiled once at startup; all scanner instances reused (no per-request re-init).
- **Dual scoring**: `combined_score = H×0.4 + ML×0.6`; heuristics catch model drift.
- **Aggregated entity graph**: graph nodes are composite `AggregatedEntity` objects (one per process), not flat domain nodes. Intra-entity relationships (process↔network, process↔memory) become embedded sub-scores and flags. Inter-entity edges are only `SharedC2`, `ParentChild`, `SharedFileHash`.
- **Two separate aggregation paths**: the EntityManager UI view uses client-side `buildProcessEntities()` from `entityUtils.ts`; the ThreatGraph uses backend `manager.aggregate()` via the `correlate` command. Both produce the same logical structure.
- **Pattern detection split**: single-entity patterns (ProcessInjection, C2Communication, MalwareExecution) are detected from node flags — no edge needed. Multi-entity patterns (LateralMovement, SuspiciousSpawn, MultiStageAttack) require inter-entity edges.
- **Sliding 10-min window**: EntityManager prunes stale entities to bound memory.
- **ML is optional**: `run_ml_and_patch_scores` silently no-ops if Python/CSV unavailable; graph falls back to heuristic-only.
- **correlate command**: only threat-level processes also trigger file scan of their exe_path (avoids scanning all 300+ processes).

## Important Files
| File | Purpose |
|------|---------|
| `Antivirus_Engine/src/main.rs` | CLI entry point, daemon loop, all serializers |
| `Antivirus_Engine/src/core/entity/manager.rs` | ingestion, scoring, pruning, **`aggregate()`** |
| `Antivirus_Engine/src/core/entity/types.rs` | `EntityNode`, **`AggregatedEntity`** |
| `Antivirus_Engine/src/core/entity/correlator.rs` | cluster logic (EntityManager UI view only) |
| `Antivirus_Engine/src/core/graph/builder.rs` | `GraphBuilder` (legacy flat), **`build_from_aggregated()`** |
| `Antivirus_Engine/src/core/graph/analyzer.rs` | `find_attack_chains_aggregated()` + critical path |
| `Antivirus_Engine/src/core/types.rs` | shared Rust types |
| `UI/src-tauri/src/main.rs` | Tauri IPC commands, daemon lifecycle |
| `UI/src/store/index.ts` | Zustand store (all UI state) |
| `UI/src/types/index.ts` | TypeScript types (source of truth for UI contracts) |
| `UI/src/lib/entityUtils.ts` | `buildProcessEntities`, `buildProcessEdges`, orphan helpers |
| `UI/src/components/ThreatGraph.tsx` | entity graph rendering, fallback aggregation |
| `Antivirus_Engine/src/core/network/Feature_extractor/ML_IDS/preprocessing_pipeline.py` | network XGBoost inference |
| `Antivirus_Engine/src/core/process/Sys_API/preprocessing_pipeline.py` | GRU training/inference |

## Known Pending Work
- Calibrate network model on real traffic (`CalibratedClassifierCV`)
- Retrain with mixed real-world + UNSW-NB15 data
- `ai_agent/` — `agent/reasoning.py` and `main.py` are empty stubs (not yet implemented)
- File domain: YARA + heuristics only, no dedicated ML model yet

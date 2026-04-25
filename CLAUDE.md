# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**AegisAI** is a multi-layered antivirus and intrusion detection system for Windows, combining behavioral analysis, machine learning, and threat correlation. It consists of three main components:
- **Rust scanning engine** (`Antivirus_Engine/`) — four domain-specific scanners + entity graph pipeline
- **Python ML agents** (`Antivirus_Engine/ai_agent/`, `Antivirus_Engine/src/core/*/ML_models/`) — per-domain ML models
- **Tauri desktop app** (`UI/`) — React/TypeScript frontend + Rust backend

## Build & Run Commands

### Rust Engine
```bash
cd Antivirus_Engine
cargo build --release              # Optimized binary
cargo build                        # Debug build
cargo test --release               # Run tests
```

### Frontend (Tauri desktop app)
```bash
cd UI
npm install
npm run dev                        # Vite dev server (localhost:1420)
npm run build                      # Production build
npm run tauri dev                  # Full Tauri dev mode (hot reload)
npm run tauri build                # Package desktop app
npx tsc                            # Type-check only
```

### Python ML Pipelines
```bash
cd Antivirus_Engine/ai_agent
pip install -r requirements.txt
python main.py

# Per-domain ML (e.g. network):
cd Antivirus_Engine/src/core/network/Feature_extractor/ML_IDS
python preprocessing_pipeline.py  # Feature extraction & training
python inference.py               # Run predictions
```

### Docker
```bash
docker-compose build rust_engine
docker-compose up rust_engine
```

### Verification
```bash
python diagnostic_test.py         # Smoke-test Rust binary
```

## Architecture

### Data Flow
```
User Action (Tauri UI)
  → Tauri backend (UI/src-tauri/main.rs) spawns daemon
  → Antivirus daemon (Antivirus_Engine/src/main.rs) handles JSON-RPC on stdin
  → Domain scanners produce EntityNode signals
  → EntityManager normalizes & aggregates (10-min sliding window)
  → EntityCorrelator groups into CorrelatedClusters
  → ThreatGraphBuilder constructs attack chains
  → GraphAnalyzer detects MITRE-mapped patterns
  → JSON response → Tauri IPC → Zustand store → React components
```

### Four Scanner Domains
Each scanner lives in `Antivirus_Engine/src/core/<domain>/`:
- **file_system/** — signature matching, YARA-X rules, hash comparison
- **process/** — Windows API call sequences, GRU-based sequence model
- **network/** — packet capture (pcap), 47 UNSW-NB15 features, XGBoost IDS
- **memory/** — region analysis, shellcode heuristics, ML scoring

### Entity Graph Pipeline (`Antivirus_Engine/src/core/`)
1. **entity/manager** — collects `EntityNode` from all scanners, computes `combined_score = H×0.4 + ML×0.6`
2. **entity/correlator** — groups nodes by shared PID, parent PID, remote IP, or file hash into `CorrelatedCluster`
3. **graph/** — `ThreatGraphBuilder` creates edges between entities; edge types carry semantic meaning and multipliers (MemoryInjection ×1.50, NetworkOwner ×1.40, ParentChild ×1.10)
4. **graph/analyzer** — detects 6 MITRE-mapped attack chain patterns, outputs `CriticalPath`

### ML Architecture
- **One model per scanner domain** (not per heuristic) to avoid calibration complexity
- All models output signals that combine with heuristics (ensemble, not replacement)
- Network: XGBoost trained on UNSW-NB15 (47 features, saved as `model.joblib` + `ordinal_encoder.joblib`)
- Process: GRU/LSTM on API call sequences (`Sys_API/`, `GRU_API/`)
- Memory: Separate ML model for memory region behavior
- File: YARA + heuristics only (no dedicated ML yet)

### UI Structure (`UI/src/`)
- **App.tsx** — routing across 8 views
- **store/index.ts** — Zustand store, single source of truth for all scanner state
- **types/index.ts** — TypeScript types shared across components (ScanResult, ProcessInfo, etc.)
- Views: Dashboard, Scanner, ProcessMonitor, NetworkMonitor, MemoryMonitor, EntityManager, ThreatGraph

## Key Design Decisions

- **Daemon mode**: The Rust binary receives JSON requests on stdin, enabling multiple UI clients without re-initialization. YARA rules are compiled once at startup.
- **Dual scoring**: Heuristics (weight 0.4) + ML (weight 0.6). ML is trusted more, but heuristics catch model drift.
- **Edge-centric graph**: Final threat decisions are structural (attack chain inference), not just score aggregation. Every edge is a semantic sentence: `ProcessA —[MemoryInjection]→ ProcessB`.
- **Sliding 10-min window**: EntityManager auto-prunes entities older than 10 minutes to bound memory.
- **Tauri over Electron**: Smaller binary, native Windows OS integration, Rust backend for direct syscalls.

## Known Pending Work (tofix.txt)
- Calibrate network model on real traffic (CalibratedClassifierCV)
- Retrain with mixed real-world + UNSW-NB15 data
- All encoder persistence (ordinal_encoder.joblib, frequency maps) is already implemented

## Important Files
- `Antivirus_Engine/src/main.rs` — CLI commands and daemon entry point
- `Antivirus_Engine/src/core/entity/` — scoring formula and correlation logic
- `Antivirus_Engine/src/core/graph/` — threat graph construction and pattern detection
- `UI/src-tauri/src/main.rs` — Tauri IPC commands and daemon lifecycle
- `ENTITY_GRAPH_ARCHITECTURE.md` — deep-dive on entity/graph design
- `ML_Architecture_Deep_Dive.md` — ML model details per domain
- `Process_Workflow.md` — edge-centric threat graph design rationale

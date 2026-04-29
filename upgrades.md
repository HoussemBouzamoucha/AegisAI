# AegisAI — Pending Upgrades

Identified gaps in the multi-layer detection pipeline that affect score correctness
from one layer to the next. Listed in priority order.

---

## Layer 1 → 2 · Domain Scanners → EntityManager

- [x] **Per-domain heuristic normalization** — replace the shared `h/40` divisor in
  `combined_score = (h/40)×0.4 + ml×0.6` with a per-domain theoretical maximum
  (memory max ≈ 55, network/process/file each different). The current divisor lets
  memory scores silently overflow `[0,1]`, corrupting every downstream weight.
  > **Done:** Added per-domain constants (PROC_MAX=110, MEM_MAX=63, NET_MAX=40) to
  > `assemble_entity()` in `manager.rs` and updated `EntityNode::combined_score()` in
  > `entity/types.rs` to use a per-type divisor derived from each scanner's maximum
  > achievable heuristic sum. All downstream scores now stay in `[0,1]` without clamp overflow.

- [ ] **ML model calibration on real environment data** — all three models
  (network XGBoost on UNSW-NB15, process GRU on synthetic sequences, memory
  classifier on limited dumps) are trained on data that does not represent this
  machine's normal behavior. Apply `CalibratedClassifierCV` and collect labeled
  samples from the actual environment before using ML scores as a reliable signal.
  > **Deferred:** ML models not yet trained on real environment data. Revisit once
  > labeled traffic and process traces from the target machine are collected.

- [ ] **Confidence / uncertainty propagation** — ML scores are point estimates with
  no measure of how confident the model is. A `0.7` probability from a well-covered
  region of the feature space is very different from `0.7` on an out-of-distribution
  input. Track prediction entropy or calibration confidence and weight `ml × 0.6`
  by that confidence rather than trusting the raw probability blindly.
  > **Deferred:** Depends on step 2. No point propagating uncertainty from uncalibrated
  > models. Blocked until real-environment calibration is done.

---

## Layer 2 → 3 · EntityManager → GraphBuilder

- [x] **Graph-to-entity score feedback loop** — graph analysis is currently read-only;
  its findings never update entity scores. After `build_from_aggregated()`, run a
  refinement pass that boosts scores for:
  - nodes on the critical path (proportional to their path-weight contribution)
  - high-centrality nodes (many cross-entity edges)
  - clean nodes that are direct parents of Malicious nodes ("vector" flag)
  > **Done:** Added `GraphAnalyzer::apply_graph_feedback()` in `analyzer.rs`. Three
  > passes run after `find_critical_path()`: critical-path boost (max +0.15, weighted
  > by hop contribution), centrality boost (max +0.10, degree / max_degree, threat
  > nodes only), vector flag (+0.08, `is_vector = true` for clean parents of Malicious
  > children). `GraphNode` gained `graph_boost: f32` and `is_vector: bool` fields,
  > serialized to JSON and typed in `GraphNodeData`.

- [x] **Validate edge weights are meaningful** — `edge_weight = avg(score_a, score_b) × multiplier`
  is only correct if `combined_score` is reliably in `[0,1]`. Fix heuristic
  normalization (item above) first; otherwise the critical-path DFS is ranking paths
  by inflated, uncalibrated numbers and the "most critical path" result is unreliable.
  > **Done:** Moved the canonical formula (`avg × type_multiplier`) into
  > `GraphEdge::weight_for()` in `types.rs` — single source of truth for all edge
  > weight computation. Updated `build_from_aggregated()` and the legacy `build()`
  > in `builder.rs` to use this formula (was `max_score()` with no multiplier).
  > Removed the duplicate `edge_weight()` from `analyzer.rs`; its DFS now calls the
  > shared method. Added `ThreatGraph::refresh_edge_weights()` called after
  > `apply_graph_feedback()` so stored edge weights stay in sync with post-feedback
  > node scores.

---

## Layer 3 → 4 · GraphAnalyzer → Verdict

- [x] **Per-chain confidence scoring** — attack pattern detection is currently binary
  (fires or does not fire). Every chain inherits `chain_score = node.combined_score`
  regardless of how marginal the triggering condition was. Add a confidence factor
  per pattern (e.g. ProcessInjection triggered by a barely-Suspicious node vs. a
  node with RWX + PE-header signals) so the verdict can surface high-confidence
  chains first.
  > **Done.** `confidence` measures *how convincingly* a pattern fired — distinct
  > from `chain_score` which captures *how bad* the worst node is.
  >
  > **Files changed:**
  > - `Antivirus_Engine/src/core/graph/types.rs` — added `confidence: f32` to `AttackChain` with doc-comment explaining the semantics
  > - `Antivirus_Engine/src/core/graph/analyzer.rs` — per-pattern confidence formulas (see table below); sort key changed from `chain_score` to `chain_score × confidence`
  > - `Antivirus_Engine/src/main.rs` — `serialize_attack_chain` now emits `"confidence"` in the JSON response
  > - `UI/src/types/index.ts` — `AttackChain` interface gains `confidence: number` with JSDoc
  > - `UI/src/lib/entityUtils.ts` — client-side fallback chain detection mirrors the same formulas
  > - `UI/src/components/GraphVerdict.tsx` — `ChainCard` renders a purple **CONF** bar + percentage next to the severity score bar; `ExploitedTrustedProcess` added to the humanized-sentence map (was previously missing)
  >
  > **Per-pattern confidence formulas:**
  >
  > | Pattern | Confidence formula | Rationale |
  > |---|---|---|
  > | ProcessInjection | `memory_score + ml_score×0.15` | RWX + PE-header shellcode saturates memory_score; ML adds corroboration |
  > | C2Communication | `network_score + ml_score×0.20` | IDS model is most relevant for C2 patterns; larger ML weight |
  > | MalwareExecution | `file_score` | YARA / hash hits push file_score close to 1.0; marginal heuristics stay low |
  > | LateralMovement | `avg(parent,child)×0.5 + child.network_score×0.5` | Both halves matter; child's network evidence is the primary discriminator |
  > | SuspiciousSpawn | `min(parent,child) + 0.15 if both Malicious` | Conservative: weaker side sets the floor; bonus only when both are confirmed Malicious |
  > | ExploitedTrustedProcess | `child.combined_score` | Parent is Clean by definition; child's score is the sole evidence quality indicator |
  > | MultiStageAttack | `avg_score × min(distinct_domains/3, 1.0)` | More independent scanner domains = more corroborating evidence |
  >
  > **Sort order:** `chain_score × confidence` descending — a threshold-grazing node can
  > no longer outrank a moderately-scored but strongly-evidenced chain. Legacy flat-graph
  > paths (`find_attack_chains`) use the same ranking formula.

- [ ] **Per-process behavioral baseline** — the system has no model of what each
  process normally looks like. Without a baseline, a JVM process that always
  allocates large anonymous exec regions scores non-zero in every memory scan,
  forever. Store a rolling per-process profile (memory layout, API call
  distribution, typical network peers) and score the **delta** from baseline rather
  than the absolute value — which is how most real attacks actually manifest.

---

## Missing Domain Coverage

- [ ] **File domain ML model** — the file scanner relies entirely on YARA rules,
  SHA-256 hash matching, and heuristics. Add a lightweight ML layer:
  PE section entropy profile, import table feature vector, or a byte-histogram
  model (MalConv-style). This is the only domain with zero ML signal feeding
  into `combined_score`.

---

## Summary Table

| # | Status | Gap | Layer boundary | Impact |
|---|--------|-----|---------------|--------|
| 1 | ✅ Done | Heuristic normalization (`h/40` overflow) | Scanner → Entity | Scores now reliably in `[0,1]` |
| 2 | ⏸ Deferred | ML models trained on wrong data | Scanner → Entity | `ml×0.6` term unreliable — blocked on real data |
| 3 | ⏸ Deferred | No uncertainty on ML scores | Scanner → Entity | Blocked on step 2 |
| 4 | ✅ Done | Graph findings not fed back to entity scores | Entity → Graph | Feedback pass added; scores reflect graph structure |
| 5 | ✅ Done | Edge weights depend on uncalibrated scores | Entity → Graph | `avg × multiplier` formula unified; weights refreshed post-feedback |
| 6 | ✅ Done | Binary pattern detection, no confidence | Graph → Verdict | Chains ranked by `score × confidence`; UI shows CONF bar per chain |
| 7 | 🔲 Pending | No per-process behavioral baseline | All layers | Can't detect delta (how attacks look) |
| 8 | 🔲 Pending | File domain has no ML model | Scanner → Entity | One domain fully blind to ML |

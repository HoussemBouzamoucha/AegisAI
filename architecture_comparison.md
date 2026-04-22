# Antivirus Behavioral Architecture: Original vs Improved

## Overview

This document compares two architectural approaches for a behavioral antivirus system, highlights their differences, and gives a concrete recommendation for systems trained on publicly available datasets.

---

## 1. Original Approach

### Pipeline

```
Heuristics → ML per heuristic → Aggregation → Graph → Feature Space
```

### Core Design

- Each heuristic signal is paired with its own ML classifier
- ML is used to compensate for weaknesses in individual heuristics
- Signals are aggregated into a behavioral graph
- Feature space is introduced after graph construction

### Strengths

- Uses multiple detection signals instead of binary decisions
- Introduces ML as an additional intelligence layer
- Incorporates graph-based reasoning for behavioral analysis

### Limitations

- One ML model per heuristic leads to:
  - Redundant learning across overlapping signals
  - Conflicting outputs with no arbitration mechanism
  - Calibration becomes exponentially harder as signals grow
- Feature space introduced too late: ML models receive inconsistent, unnormalized input
- Adding a new heuristic requires a new model — does not scale
- No shared representation means models cannot learn from each other's signals

---

## 2. Improved Approach

### Pipeline

```
Raw Events → Heuristics → Entity Aggregation → Shared Feature Space
    → Per-Scanner ML Models → Signals (Heuristics + ML)
    → Graph Engine → Final Decision
```

### Core Design

- Heuristics generate raw behavioral signals per scanner domain
- Signals are grouped by entity (process, file, network connection, memory region)
- A shared feature space standardizes all behavior into a consistent format before ML
- One ML model per scanner (process / network / memory / file)
- ML outputs are additional signals, not replacements
- A graph engine performs final reasoning using all signals combined

### Strengths

- Structured feature space before ML ensures consistent, comparable input across all models
- One model per scanner: easier training, tuning, and maintenance
- Clear role separation:
  - Heuristics → raw observations
  - Feature space → normalization and standardization
  - ML → scoring and generalization
  - Graph → contextual reasoning and correlation
- New heuristics integrate into the existing feature schema — no new model needed
- Graph resolves ambiguity through entity relationships (parent-child, shared C2, file-process linkage)

---

## Key Differences

| Aspect                  | Original Approach          | Improved Approach            |
|-------------------------|----------------------------|------------------------------|
| ML granularity          | Per heuristic              | Per scanner domain           |
| Feature space placement | After graph                | Before ML                    |
| Input consistency       | Unstructured               | Standardized                 |
| Signal fusion           | Implicit                   | Explicit and weighted        |
| Scalability             | Low                        | High                         |
| Graph role              | Primary reasoning          | Final reasoning layer        |
| ML role                 | Fragmented                 | Centralized per domain       |
| Calibration difficulty  | High (N models)            | Low (4 models)               |

---

## 3. Recommendation for Publicly Available Dataset Training

**Use the Improved Approach.** Here is why it is the better fit specifically when training on public datasets, and how to apply it per scanner.

### Why Public Datasets Favor the Improved Approach

Public datasets have a well-known problem: **distribution shift**. They capture network traffic, file behavior, and process activity from lab environments that do not reflect your real deployment environment. The more models you have, the more surfaces this shift can corrupt your detections. The improved approach contains this damage by:

- Limiting exposure to 4 domain-specific models (one per scanner)
- Using heuristics as a first filter — heuristics are rule-based and environment-independent
- Using the graph as a final layer — graph reasoning is structural and does not depend on the training distribution

### Dataset Recommendations Per Scanner

#### Network Scanner
**Dataset**: UNSW-NB15 *(already in use)*

- A strong baseline for network intrusion detection
- Contains 9 attack categories with labeled flows
- Supplement with **CIC-IDS-2017** for more modern attack coverage (DDoS, brute-force, infiltration)
- Known issue: class imbalance (benign traffic dominates) — use SMOTE or class-weighted training
- Calibrate the model with `CalibratedClassifierCV` after initial training (see `tofix.txt` item #4)

#### File Scanner
**Dataset**: EMBER (Endgame Malware BenchmaRk)

- 1M PE file samples (500K malicious, 300K benign, 200K unlabeled)
- Pre-extracted features: byte histograms, header fields, section info, strings
- GitHub: `elastic/ember`
- Alternative: **SOREL-20M** for a larger, more recent set
- Feature alignment: map EMBER features to your existing heuristic signals (entropy, section anomalies, import table flags)

#### Process Scanner
**Dataset**: DAPT 2020 / Microsoft Malware Classification Challenge (BIG 2015)

- DAPT 2020 covers long-dwell APT-style process behavior
- BIG 2015 has 9 malware family labels with assembly-level features
- For behavioral signals (not static): **CDMC 2022** process execution logs
- Feature space: use command-line arguments, parent-child PID chains, exe path anomalies — all already extracted by your heuristics

#### Memory Scanner
**Dataset**: CIC-MalMem-2022

- Labeled memory dumps: benign + spyware + ransomware + trojan
- Features: memory region permissions (RWX), allocation patterns, mapped file presence
- Directly maps to your existing `MemoryRegion` attributes (`is_executable`, `is_writable`, `protection`)

### Training Strategy

```
1. Train each model independently on its domain dataset
2. Normalize features to [0, 1] before training
3. Output probability scores (not hard labels) — these become ml_score in the entity layer
4. Calibrate each model with CalibratedClassifierCV(cv=5) to align probabilities with real priors
5. Threshold tuning: prefer high recall (low false negatives) at the model level
   — the graph layer will suppress false positives through structural context
6. Do not tune thresholds against the graph output — keep layers independent
```

### Handling Distribution Shift

This is the biggest risk when using public datasets on live systems:

- **Heuristics are your safety net.** When the ML model misfires due to distribution shift, the heuristic score still contributes (40% weight in the current `combined_score` formula).
- **Retrain periodically** on samples collected from your own environment (even if unlabeled — use clustering to find anomalies).
- **Monitor false positive rate** by watching how many Clean processes/connections get elevated to Suspicious after correlate runs. A rising rate signals distribution drift.
- **For network specifically**: your CLEAN_PREFIXES list in `preprocessing_pipeline.py` prevents known-good infrastructure (Google, Microsoft, Cloudflare) from polluting the training signal — keep this list updated.

---

## 4. Final Architecture Summary

```
┌─────────────────────────────────────────────────────────────────┐
│                        Raw System Events                        │
└───────────────┬─────────────────────────────────────────────────┘
                │
        ┌───────▼────────┐
        │   Heuristics   │  Rule-based, environment-independent
        │ (per scanner)  │  First filter — no ML dependency
        └───────┬────────┘
                │
        ┌───────▼────────┐
        │    Entities    │  Process / File / Network / Memory
        │  Aggregation   │  Join keys: PID, exe_path, remote_ip, hash
        └───────┬────────┘
                │
        ┌───────▼────────┐
        │ Shared Feature │  Normalized 0–1 scores
        │    Space       │  Consistent across all domains
        └───────┬────────┘
                │
   ┌────────────┼────────────┬───────────────┐
   ▼            ▼            ▼               ▼
Process ML   Network ML   Memory ML      File ML
(DAPT2020)  (UNSW-NB15)  (CIC-MalMem)   (EMBER)
   └────────────┴────────────┴───────────────┘
                │  ml_score per entity (0–1 probability)
                │
        ┌───────▼────────┐
        │  Signal Fusion │  combined_score = H×0.4 + ML×0.6
        │                │  Parent context boost applied here
        └───────┬────────┘
                │
        ┌───────▼────────┐
        │  Graph Engine  │  Edges: ParentChild, NetworkOwner,
        │                │         MemoryInjection, ProcessOpenedFile
        │                │  Patterns: LateralMovement, C2, Injection…
        └───────┬────────┘
                │
        ┌───────▼────────┐
        │ Final Decision │  Attack chain + narrative
        │  + Narrative   │  MITRE tactic mapping
        └────────────────┘
```

---

## 5. The Shared Feature Space

### What "Shared" Actually Means

The shared feature space does **not** mean all four models receive the same input vector.
The datasets for each scanner have unique, largely non-overlapping fields by design —
network traffic looks nothing like memory regions. Trying to force a single unified input
would either bloat the vector with zeros or destroy domain-specific signal.

"Shared" refers to the **output contract** and the **entity schema**, not the input:

| Shared element        | What it means in practice                                          |
|-----------------------|--------------------------------------------------------------------|
| Output format         | Every model outputs a probability score in `[0.0, 1.0]`           |
| Entity schema         | Every scanner maps its output to an `EntityNode` with the same fields |
| Scoring formula       | `combined_score = H × 0.4 + ML × 0.6` applies to all entity types |
| Threat vocabulary     | All models speak `Clean / Suspicious / Malicious / Critical`       |
| Join keys             | All entities carry `pid / parent_pid / file_path / remote_ip / file_hash` |

The entity layer is the convergence point. Each model has its own private feature space
tailored to its domain; they all plug into the same socket.

---

### Per-Domain Feature Spaces and Dataset Alignment

#### Network — UNSW-NB15 / CIC-IDS-2017

UNSW-NB15 has 49 raw fields. Not all of them are useful for inference.

**Used (43 features after preprocessing)**

| Feature group          | Fields                                                         | Why kept                                   |
|------------------------|----------------------------------------------------------------|--------------------------------------------|
| Flow volume            | `sbytes`, `dbytes`, `Spkts`, `Dpkts`, `smeansz`, `dmeansz`   | Volume asymmetry is a strong C2 signal     |
| Timing                 | `dur`, `Sintpkt`, `Dintpkt`, `Sjit`, `Djit`                   | Beaconing has a regular inter-packet time  |
| Protocol / state       | `proto`, `state`, `service` (OrdinalEncoded)                  | Unusual protocol/state combos flag attacks |
| TCP internals          | `swin`, `dwin`, `stcpb`, `dtcpb`, `tcprtt`, `synack`, `ackdat` | Handshake anomalies                       |
| Load                   | `Sload`, `Dload`                                              | Exfiltration shows asymmetric load         |
| Categorical counts     | `ct_srv_src`, `ct_srv_dst`, `ct_dst_ltm`, `ct_src_ltm`, etc. | Frequency of connections to same service   |
| IP-derived             | `src_is_private`, `src_is_global`, `src_version`, `src_freq`, `dst_freq` | Internal vs external, rare IPs |
| Port numbers           | `sport`, `dsport`                                             | C2 ports, high/ephemeral port patterns     |

**Discarded**

| Field              | Reason                                                                  |
|--------------------|-------------------------------------------------------------------------|
| `srcip`, `dstip`   | Raw IPs are environment-specific; replaced by `src_freq` / `dst_freq` and IP property flags |
| `Stime`, `Ltime`   | Absolute timestamps — meaningless at inference time on a different machine |
| `sloss`, `dloss`   | Near-zero variance in most real traffic; adds noise without signal      |
| `is_ftp_login`, `ct_ftp_cmd` | FTP-specific; rarely encountered in modern environments   |

---

#### File — EMBER

EMBER provides pre-extracted features across 8 feature groups covering the PE file format.

**Used**

| Feature group          | Fields / description                                           | Why kept                                       |
|------------------------|----------------------------------------------------------------|------------------------------------------------|
| Byte histogram         | 256-bin distribution of raw bytes                             | Encrypted/packed content has a flat histogram  |
| Byte entropy           | Shannon entropy in 2048-byte windows                          | High entropy → packed or encrypted sections    |
| PE header              | `MajorLinkerVersion`, `SizeOfCode`, `SizeOfHeaders`, timestamps, subsystem, DLL characteristics | Anomalous header fields signal tampering |
| Section info           | Per-section: name, size, entropy, virtual size ratio           | `.text` section with high entropy → packed     |
| Imports                | Hashed library/function names (count per library, total count) | Suspicious API call patterns (VirtualAlloc, WriteProcessMemory) |
| Exports                | Count and hashed names                                        | Rare in benign EXEs; common in DLLs used for injection |
| Strings                | Count, average length, paths, URLs, registry keys, MZ/PE markers | Embedded strings reveal intent                |
| General                | `VirtualSize`, `NumSections`, `HasDebug`, `HasTLS`, `HasSignature` | Structural anomalies                    |

**Discarded**

| Field                        | Reason                                                              |
|------------------------------|---------------------------------------------------------------------|
| Raw byte sequences           | Too high-dimensional; entropy/histogram captures the same signal    |
| Full import table (string list) | Replaced by hashed library-level counts — avoids vocabulary explosion |
| `TimeDateStamp` (raw value)  | Absolute timestamp; replaced by "is timestamp in future?" binary flag |
| Unlabeled samples (200K)     | EMBER marks 200K samples as unlabeled — exclude from supervised training, optionally use for semi-supervised pre-training |

---

#### Process — DAPT 2020 / BIG 2015

Process datasets are the most environment-sensitive. Raw values like PID and absolute
paths are meaningless across machines and must be normalized before use.

**Used**

| Feature group          | Fields / description                                           | Why kept                                        |
|------------------------|----------------------------------------------------------------|-------------------------------------------------|
| Name encoding          | Process name hashed or embedded (not raw string)              | Known malware names cluster in embedding space  |
| Path anomaly           | `exe_in_safe_path` (bool), `is_system32_name_outside_system32` (bool) | Impersonation detection        |
| Ancestry               | `parent_is_threat` (bool), `spawn_depth` (int)                | Malware chains show deep spawn trees            |
| Resource usage         | `cpu_percentile`, `memory_percentile` (relative, not absolute)| Miners and ransomware occupy high percentiles   |
| Thread count           | `thread_count == 0` (bool), `thread_count < 2` (bool)         | Process hollowing indicator                     |
| Command-line flags     | Binary features per suspicious argument pattern (`-enc`, `bypass`, `iex`, etc.) | Obfuscated execution patterns |
| Timing                 | `process_age_seconds` (if available)                          | Very short-lived processes are suspicious       |

**Discarded**

| Field               | Reason                                                                   |
|---------------------|--------------------------------------------------------------------------|
| Raw PID             | Assigned by OS at runtime — not comparable across machines or sessions   |
| Absolute exe path   | Replaced by normalized boolean features (in_safe_path, in_system32)     |
| Raw username / SID  | Environment-specific; replaced by `is_system_account` boolean           |
| Raw memory bytes    | Absolute value; replace with percentile rank within the current session  |
| Absolute CPU value  | Replace with percentile rank — what matters is relative to other processes |

---

#### Memory — CIC-MalMem-2022

Memory features describe the properties of virtual memory regions, not their content.

**Used**

| Feature group           | Fields / description                                          | Why kept                                          |
|-------------------------|---------------------------------------------------------------|---------------------------------------------------|
| Permission flags        | `is_executable` (bool), `is_writable` (bool), `is_executable_and_writable` (bool) | RWX regions are the strongest injection indicator |
| Allocation type         | Private vs mapped vs image (one-hot encoded)                  | Injected shellcode lives in private anonymous memory |
| Region size             | `log(region_size)` (log-scaled)                               | Shellcode tends to occupy specific size ranges    |
| Process context         | `process_is_threat` (bool from heuristics)                    | Flagged process + suspicious region = high confidence |
| Region count per process| Total suspicious regions for this PID                        | Many suspicious regions → active injection campaign |

**Discarded**

| Field                  | Reason                                                               |
|------------------------|----------------------------------------------------------------------|
| Raw virtual address    | Absolute address — meaningless across processes and sessions         |
| Raw memory content     | Too large and legally/ethically sensitive to include in a dataset    |
| `region_start` (raw)   | Replaced by alignment anomaly flag (`is_aligned_to_page` bool)      |
| Process name (raw)     | Already captured by the process scanner; avoid duplication           |

---

### How the Four Feature Spaces Converge

Each model operates in its own feature space and outputs a single float. That float
flows into the entity layer through a common interface:

```
Network model   → ml_score (0–1) → NetworkConnection entity → EntityNode.ml_score
File model      → ml_score (0–1) → File entity              → EntityNode.ml_score
Process model   → ml_score (0–1) → Process entity           → EntityNode.ml_score
Memory model    → ml_score (0–1) → MemoryRegion entity      → EntityNode.ml_score
                                          │
                                   combined_score = H×0.4 + ML×0.6
                                          │
                                     Graph engine
```

There is no cross-domain feature vector. The graph engine never sees raw features —
it sees only `combined_score`, `threat_level`, and structural join keys.
This is intentional: the graph reasons about relationships, not feature values.

---

### Feature Discarding: General Rules

Across all four domains, the same categories of features get discarded for the same reasons:

| Category                  | Examples                                  | Why discarded                                        |
|---------------------------|-------------------------------------------|------------------------------------------------------|
| Absolute identifiers      | PID, raw IP, virtual address              | Machine/session-specific; break generalization       |
| Absolute timestamps       | `Stime`, `TimeDateStamp`, process start   | Meaningless at inference time on new data            |
| High-cardinality strings  | Full process names, full paths, full URLs | Cause vocabulary explosion; use hashed/encoded form  |
| Zero-variance fields      | `sloss`, `dloss` in clean traffic         | Add noise without signal                             |
| Domain-specific edge cases | FTP login fields, IPv6-only counters     | Rare enough that they hurt more than they help       |
| Raw content               | Byte sequences, memory dumps              | Too large; statistical summaries capture the signal  |

The rule of thumb: **if the feature value changes between two identical attacks on
different machines, discard it and replace it with a normalized or boolean form.**

---

## Conceptual Model

| Layer         | Role                  | Analogy                  |
|---------------|-----------------------|--------------------------|
| Heuristics    | Sensors               | Tripwires                |
| Feature Space | Common language       | Translator               |
| ML Models     | Domain experts        | Specialists              |
| Graph Engine  | Decision system       | Investigator             |
| Narrative     | Human communication   | Incident report          |

---

## 6. How the Shared Feature Space Actually Works at Runtime

### Where It Sits in the Pipeline

The shared feature space is **before** the ML model, not after it.
It is optionally extended after ML outputs if those outputs are fed back as
additional features (e.g., using an ML confidence score as a derived feature
for a downstream ensemble). The full pipeline is:

```
Raw Events
    │
    ▼
Heuristics  (rule-based scoring per scanner domain)
    │
    ▼
Entity Aggregation  (group signals by PID / file path / remote IP / region)
    │
    ▼
Shared Feature Space  ◄── HERE: normalize raw signals into a clean input vector
    │
    ▼
Per-Scanner ML Model  (one model per domain: network / file / process / memory)
    │   [optionally: ML output re-enters feature space as a derived feature]
    ▼
Standardized Output: ml_score ∈ [0, 1]
    │
    ▼
Entity Layer  (attach ml_score to entity via join key)
    │
    ▼
Graph Engine  (combined_score + structural relationships only)
```

### What the Shared Feature Space Actually Does

Within each scanner domain, the heuristics produce raw, heterogeneous signals:
integer scores, boolean flags, raw strings, absolute values. The shared feature
space is the normalization step that converts these into a form the ML model
can learn from consistently:

| Raw heuristic output          | After shared feature space                        |
|-------------------------------|---------------------------------------------------|
| `threat_score = 18` (network) | `heuristic_score_norm = 18 / 40 = 0.45`           |
| `exe_path = C:\Windows\...`   | `in_safe_path = true` (boolean)                   |
| `port = 4444`                 | `is_known_c2_port = true` (boolean)               |
| `pid = 1234`                  | discarded — runtime-specific, not a feature       |
| `region_size = 4096`          | `log_region_size = 8.33` (log-scaled)             |
| `bytes_sent = 982344`         | `bytes_sent_log = 5.99` (log-scaled)              |
| `process_name = "svch0st.exe"`| `name_entropy = 3.1`, `is_known_lolbin = false`   |

"Shared" does not mean shared across scanners — it means shared across all
heuristics *within* a scanner. Every heuristic in the network scanner contributes
to the same feature vector that the network ML model trains on. The same applies
to each of the other three scanners independently.

### Step-by-Step Data Flow (Concrete Example)

```
Network scanner
────────────────
Raw event: TCP connection, port 443, 1.2 MB sent, beacon interval 30s

Heuristics fire:
  heuristic_score = 18  (is_known_c2_port +5, beaconing +8, large_upload +5)

Shared feature space builds:
  heuristic_score_norm   = 0.45
  is_known_c2_port       = true
  beaconing_detected     = true
  bytes_sent_log         = 6.08
  dst_port_norm          = 0.87
  protocol_tcp           = true
  (14 more normalized features...)

Network ML model (XGBoost trained on UNSW-NB15):
  input  → feature vector above
  output → ml_score = 0.91

Entity layer:
  net:TCP:192.168.1.5:52341→185.220.101.7:443
    heuristic_score = 18
    ml_score        = 0.91
    combined_score  = (18/40)×0.4 + 0.91×0.6 = 0.72

Graph engine receives: combined_score=0.72, join_key=pid:3821
```

The graph never sees the 14 feature vector fields.
It sees one number (0.72) and one structural relationship (pid 3821).

### Optional: ML Output Fed Back as a Feature

In a more advanced setup, the ML output itself can be re-injected into the
feature space as a meta-feature before a second-stage classifier:

```
Heuristics → Feature Space → ML Model A (fast, lightweight)
                                   │
                              ml_score_A
                                   │
                    Feature Space (extended with ml_score_A)
                                   │
                              ML Model B (slower, ensemble)
                                   │
                              final ml_score
```

This is useful when you want a fast rule-based pre-filter to reduce the load
on an expensive deep model. The current codebase uses a single-stage approach
(no feedback loop), which is appropriate for an endpoint agent where latency matters.

### How Each Scanner's Weight Reaches the Final Decision

Each scanner's contribution to the final verdict is not a fixed manual weight.
It is determined at graph traversal time by two factors:

```
Graph edge weight = avg(node_score_A, node_score_B) × edge_type_multiplier

Edge type multipliers:
  MemoryInjection   × 1.50   ← memory scanner's contribution amplified most
  NetworkOwner      × 1.40   ← network scanner
  SharedC2          × 1.30
  ProcessOpenedFile × 1.20   ← file scanner
  ParentChild       × 1.10   ← process scanner (structural, less directional)
  SameProcess       × 1.00
  SharedFileHash    × 0.90
```

A memory injection edge (×1.50) from a 0.90-score region outweighs a parent-child
edge (×1.10) from a 0.30-score process. The weights emerge from graph topology —
they are not manually assigned per scanner. A scanner with a weak signal on a given
entity simply contributes less path weight. It is never silenced — it just pulls less.

---

## Conclusion

The improved approach does not discard the original — it refines the order and granularity:

- Heuristics, ML, and graph reasoning are all preserved
- Proper structure and ordering eliminate redundancy and calibration nightmares
- With public datasets, the 4-model architecture is the maximum complexity you should train before adding real-environment data
- The graph layer is what makes this competitive with commercial EDR systems: it catches attack chains that no individual model would detect alone

The current codebase already implements this architecture. The remaining work is training the 3 missing models (process, memory, file) on the datasets listed above, calibrating all 4, and wiring their outputs into the entity layer the same way the network ML model is wired today.

---

## 7. Training the Models on the Feature Vectors: How to Actually Do It

### The Core Question

> "My datasets don't overlap or intersect in their fields — so what exactly gets trained on what?"

Each ML model is trained entirely within its own domain. The datasets don't need to
overlap because the models never share an input. There is no cross-domain training.

```
UNSW-NB15     → network feature vector  → Network ML model
EMBER         → file feature vector     → File ML model
DAPT 2020     → process feature vector  → Process ML model
CIC-MalMem    → memory feature vector   → Memory ML model
```

Each dataset feeds exactly one model. Non-overlapping datasets is not a problem —
it is by design. The feature vectors are the bridge between "what the dataset provides"
and "what the live scanner produces."

---

### The Key Insight: The Feature Vector Is the Contract


The feature vector you define for each scanner has to serve two masters:

1. **Training time**: dataset rows get transformed into this vector and fed to the model
2. **Inference time**: live scanner events get transformed into the same vector and fed to the same model

If both transformations produce the same vector schema, the model works in production.
If they diverge, it doesn't — regardless of how well it scored on the dataset.

This is the only hard requirement. The datasets don't need to share any fields with
each other. They just need to be transformable into their own domain's canonical vector.

---

### Step-by-Step: How to Train Each Model

#### Step 1 — Define the canonical feature vector schema

Before touching any dataset, write down the feature vector for each scanner.
This is the list of normalized fields the model will see, in a fixed order.
You already have this from Section 5 of this document.

Example for the network scanner (abridged):

```python
NETWORK_FEATURES = [
    "heuristic_score_norm",   # float, 0–1
    "is_known_c2_port",       # bool → int (0/1)
    "beaconing_score",        # float, 0–1
    "bytes_sent_log",         # log10(bytes_sent + 1)
    "bytes_recv_log",         # log10(bytes_recv + 1)
    "dst_port_norm",          # port / 65535
    "duration_log",           # log10(duration_s + 1)
    "proto_tcp",              # one-hot
    "proto_udp",              # one-hot
    # ... etc
]
```

This list is the single source of truth. Both the dataset preprocessor and the
runtime extractor must produce columns in this exact order.

#### Step 2 — Write a dataset preprocessor

The preprocessor reads the raw dataset CSV and outputs a DataFrame with exactly
the columns in `NETWORK_FEATURES` plus a `label` column (0 = benign, 1 = malicious).

```python
# preprocess_unsw_nb15.py
import pandas as pd, numpy as np

df = pd.read_csv("UNSW-NB15.csv")

# Map dataset columns → canonical feature vector
out = pd.DataFrame()
out["heuristic_score_norm"] = 0.0           # no heuristics at training time, fill 0
out["is_known_c2_port"]     = df["dport"].isin(C2_PORTS).astype(int)
out["beaconing_score"]      = compute_beaconing(df)  # derived from inter-arrival times
out["bytes_sent_log"]       = np.log10(df["sbytes"] + 1)
out["bytes_recv_log"]       = np.log10(df["dbytes"] + 1)
out["dst_port_norm"]        = df["dport"] / 65535
out["duration_log"]         = np.log10(df["dur"] + 1)
out["proto_tcp"]            = (df["proto"] == "tcp").astype(int)
out["proto_udp"]            = (df["proto"] == "udp").astype(int)
# ... map remaining fields
out["label"]                = df["label"]   # 0 or 1, already in UNSW-NB15

out.to_csv("network_features.csv", index=False)
```

Fields in the dataset that have no runtime equivalent are either derived into a
normalized form or dropped. Fields in the feature vector that have no dataset
equivalent (like `heuristic_score_norm`) are filled with a constant (0.0) at
training time — the model learns to treat them as uninformative. At inference
time they carry real values.

#### Step 3 — Train the model on the preprocessed CSV

```python
# train_network_model.py
import pandas as pd
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.calibration import CalibratedClassifierCV
import joblib

df    = pd.read_csv("network_features.csv")
X     = df[NETWORK_FEATURES]
y     = df["label"]

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, stratify=y)

model = XGBClassifier(n_estimators=300, max_depth=6, learning_rate=0.05,
                      scale_pos_weight=(y==0).sum() / (y==1).sum())  # class imbalance
model.fit(X_train, y_train)

# Calibrate so output is a true probability, not a raw score
calibrated = CalibratedClassifierCV(model, method="isotonic", cv="prefit")
calibrated.fit(X_test, y_test)

joblib.dump(calibrated, "network_model.pkl")
```

The calibration step (`CalibratedClassifierCV`) is critical. Without it,
`predict_proba` returns a score, not a probability — a 0.7 from an uncalibrated
XGBoost does not mean "70% chance of malicious." After calibration it does,
which is what the `combined_score = H×0.4 + ML×0.6` formula depends on.

#### Step 4 — Write a runtime feature extractor

The runtime extractor takes a live `NetworkConnection` struct and builds the same
vector the dataset preprocessor produced:

```python
# runtime_extractor.py  (called from preprocessing_pipeline.py --infer)
def extract_network_features(conn: dict, heuristic_score: float) -> list:
    return [
        heuristic_score / 40.0,                          # heuristic_score_norm
        int(conn["dport"] in C2_PORTS),                  # is_known_c2_port
        conn.get("beaconing_score", 0.0),                # beaconing_score
        math.log10(conn["sbytes"] + 1),                  # bytes_sent_log
        math.log10(conn["dbytes"] + 1),                  # bytes_recv_log
        conn["dport"] / 65535,                           # dst_port_norm
        math.log10(conn.get("dur", 0) + 1),              # duration_log
        int(conn["proto"].lower() == "tcp"),              # proto_tcp
        int(conn["proto"].lower() == "udp"),              # proto_udp
        # ... same order as NETWORK_FEATURES
    ]
```

The model sees the same schema at inference time as it saw during training.
That is all it takes for the model to generalize.

---

### Why Non-Overlapping Datasets Are Not a Problem

The confusion usually comes from imagining a single model that takes all 4 scanners'
data at once. That model would need a unified input with columns from all 4 datasets,
and those datasets don't share fields — so it would fail.

But that is not the architecture here. There are 4 separate models:

| Model    | Trains on       | Input at inference         | Output     |
|----------|-----------------|----------------------------|------------|
| Network  | UNSW-NB15       | live network conn features | ml_score   |
| File     | EMBER           | live PE/file features      | ml_score   |
| Process  | DAPT 2020       | live process features      | ml_score   |
| Memory   | CIC-MalMem-2022 | live memory region features| ml_score   |

Each model trains and infers in its own column space. The 4 outputs are dimensionally
identical (a float in [0,1]) and that is the only point where they meet — at the
entity layer, where they become `ml_score` on 4 different `EntityNode` types.

---

### The Dataset-to-Runtime Field Mapping Table

For each scanner, the critical work is mapping dataset column names to runtime
struct field names. Do this once per scanner, in writing, before coding anything.

**Network scanner: UNSW-NB15 → NetworkConnection**

| Dataset column | Runtime field         | Transform                        |
|----------------|-----------------------|----------------------------------|
| `sbytes`       | `bytes_sent`          | `log10(x + 1)`                   |
| `dbytes`       | `bytes_recv`          | `log10(x + 1)`                   |
| `dur`          | `duration_s`          | `log10(x + 1)`                   |
| `dport`        | `remote_port`         | `port / 65535`, `in C2_PORTS`    |
| `proto`        | `protocol`            | one-hot encode                   |
| `sttl`         | not in runtime        | drop — OS-specific, not portable |
| `ct_srv_src`   | derived at runtime    | compute from connection history  |

**File scanner: EMBER → ScanResult**

| Dataset column        | Runtime field        | Transform                         |
|-----------------------|----------------------|-----------------------------------|
| `has_debug`           | context_flags        | map flag → bool                   |
| `exports` (count)     | n/a                  | derive from PE header inspection  |
| `entry_point`         | n/a                  | extract from PE parser            |
| `label`               | threat_level         | 0=benign, 1=malicious, -1=unknown |

**Process scanner: DAPT 2020 → ProcessInfo**

| Dataset column    | Runtime field      | Transform                              |
|-------------------|--------------------|----------------------------------------|
| `cpu_percent`     | resource data      | percentile rank within session         |
| `parent_pid`      | `parent_pid`       | bool: `parent_is_known_threat`         |
| `cmdline`         | `command_line`     | binary flags: `-enc`, `bypass`, `iex`  |
| `username`        | `user`             | bool: `is_system_account`              |

**Memory scanner: CIC-MalMem-2022 → MemoryRegion**

| Dataset column       | Runtime field       | Transform                           |
|----------------------|---------------------|-------------------------------------|
| `Type`               | alloc type          | one-hot: private/mapped/image        |
| `Size`               | `region_size`       | `log10(x + 1)`                      |
| `Protection`         | `protection`        | extract rwx booleans                |
| `AllocationType`     | n/a                 | derive from `protection` flags      |

---

### What to Build, In Order

1. **Write `NETWORK_FEATURES`, `FILE_FEATURES`, `PROCESS_FEATURES`, `MEMORY_FEATURES`**
   as Python lists. These are your contracts. Do not change them after training.

2. **Write one `preprocess_<dataset>.py` per scanner** that maps the raw dataset
   CSV into the canonical feature vector CSV.

3. **Train each model** on its preprocessed CSV. Calibrate all 4 with
   `CalibratedClassifierCV`. Save with `joblib.dump`.

4. **Write one `extract_<scanner>_features(live_data)` function per scanner**
   that mirrors the preprocessing logic on live runtime data.
   Test that `extract_network_features(fake_conn)` produces the exact same
   column order and scaling as `preprocess_unsw_nb15.py` does on a matching row.

5. **Wire each model into the engine** the same way `preprocessing_pipeline.py`
   already wires the network model:
   - Rust scanner writes features to a temp file or pipe
   - Python script loads model, runs inference, returns JSON with `ml_score`
   - Rust calls `manager.update_ml_score(entity_id, score)`

The network scanner already completes steps 1–5. Repeat for the remaining three.

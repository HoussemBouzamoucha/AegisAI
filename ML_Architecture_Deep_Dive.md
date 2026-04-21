# AegisAI — ML Architecture Deep Dive

> A rigorous technical argument for every design decision, from raw event to final verdict.

---

## Table of Contents

1. [The Two Architectures: A Critical Argument](#1-the-two-architectures-a-critical-argument)
2. [Why the Shared Feature Space Is the Backbone](#2-why-the-shared-feature-space-is-the-backbone)
3. [The Feature Vector Contracts](#3-the-feature-vector-contracts)
4. [How Data Is Generated for Training](#4-how-data-is-generated-for-training)
5. [Why Non-Intersecting Datasets Are Not a Problem](#5-why-non-intersecting-datasets-are-not-a-problem)
6. [How Each Model Trains on Its Feature Vector](#6-how-each-model-trains-on-its-feature-vector)
7. [How the Four Models Interact at Runtime](#7-how-the-four-models-interact-at-runtime)
8. [The Entity Layer: Where All Outputs Converge](#8-the-entity-layer-where-all-outputs-converge)
9. [The Graph Engine: Why Four Numbers Beat Four Verdicts](#9-the-graph-engine-why-four-numbers-beat-four-verdicts)
10. [Distribution Shift: The Real Risk and How to Contain It](#10-distribution-shift-the-real-risk-and-how-to-contain-it)

---

## 1. The Two Architectures: A Critical Argument

### 1.1 Original Approach — What It Gets Right and Where It Breaks

The original pipeline reads:

```
Heuristics → ML per heuristic → Aggregation → Graph → Feature Space
```

The intent is sound: pair each heuristic signal with a dedicated ML classifier to compensate
for that heuristic's blind spots. If the "beaconing detection" heuristic fires on port 443
traffic it cannot distinguish from legitimate HTTPS, a small binary classifier trained on
labeled beacon traffic should resolve the ambiguity. The graph then aggregates everything
into a behavioral picture.

**Where it is right:**
- Using multiple detection signals instead of a single binary decision is fundamentally correct.
  No single heuristic has 100% precision; combining N independent signals exponentially
  reduces the joint false positive rate if those signals are conditionally independent.
- Introducing ML as a second-pass filter on top of rules is standard EDR practice.
  CrowdStrike, SentinelOne, and Carbon Black all use this pattern at their core.
- Graph-based reasoning is the correct final layer. Individual signals on isolated
  entities miss multi-stage attack chains that only become visible as a connected subgraph.

**Where it breaks:**

| Failure Mode | Root Cause | Consequence |
|---|---|---|
| N ML models for N heuristics | No shared representation | Model A and Model B learn overlapping features; their outputs conflict with no arbitration mechanism |
| Feature space introduced after graph | ML receives raw, unnormalized signals | XGBoost trained on `threat_score = 18` cannot generalize to `threat_score = 22` without understanding the scale |
| Adding a new heuristic requires a new model | Architecture is not composable | At 20 heuristics you have 20 models to train, calibrate, monitor, and update when the threat landscape shifts |
| Calibration is impossible at scale | Each model was trained on a different slice of data | Model A outputs 0.85 meaning "very likely malicious"; Model B outputs 0.85 meaning "slightly above average risk" — the aggregation step adds noise instead of reducing it |

The core failure is a **missing abstraction layer**. The original design goes directly from
raw heuristic output to ML inference, then tries to reconcile the outputs at the graph level.
The graph was never designed to arbitrate between conflicting ML scores — it was designed to
reason about entity relationships.

---

### 1.2 Improved Approach — Why This Order Is the Only Order That Works

The improved pipeline reads:

```
Raw Events → Heuristics → Entity Aggregation → Shared Feature Space
    → Per-Scanner ML Models → Signals → Graph Engine → Final Decision
```

The key insight is that **the feature space is not a pre-processing step — it is an
architectural boundary**. Everything to the left of it is rule-based and
environment-independent. Everything to the right of it operates on normalized, comparable
numbers. The boundary enforces a clean contract: any heuristic can contribute to the
feature space without touching any model; any model can consume the feature space without
knowing which heuristics fired.

This is equivalent to the separation between a REST API and its database. The API schema
is the contract. The database can be re-indexed, migrated, or replaced without changing
the API. The consumers of the API never see the storage details.

**Why one model per scanner (not per heuristic):**

A scanner domain is a natural unit of training data. UNSW-NB15 captures network flows.
EMBER captures PE file properties. DAPT 2020 captures process execution chains. These
datasets are collected with consistent methodology within their domain. Training one model
per dataset means the training distribution and the inference distribution are aligned by
construction. Training one model per heuristic means slicing each dataset into N subsets,
each of which is smaller, noisier, and harder to calibrate.

**Why ML outputs are signals, not replacements:**

A heuristic that fires on port 4444 is always right that port 4444 is used for Metasploit.
It may be wrong that this particular connection is Metasploit. The ML model provides
the probabilistic qualification: given the full feature context, how likely is this
specific connection to be malicious? The heuristic score and the ML score each carry
information the other lacks. Discarding either one loses signal. The formula
`combined_score = H × 0.4 + ML × 0.6` is not arbitrary — it assigns higher weight to
the ML score because it has access to more context, while ensuring the heuristic
still contributes as a safety net when ML misfires due to distribution shift.

---

### 1.3 Side-by-Side Decision Table

| Design Question | Original Answer | Improved Answer | Why Improved Wins |
|---|---|---|---|
| How many ML models? | One per heuristic (N models) | One per scanner domain (4 models) | 4 models can be trained, calibrated, and retrained in a single sprint; N models cannot |
| When is the feature space applied? | After the graph | Before ML inference | ML requires consistent input format; the graph requires structured output — not the same requirement |
| What does the graph receive? | Raw ML scores of variable meaning | Normalized combined_scores with consistent semantics | The graph can reason about 0.72 vs 0.31; it cannot reason about "XGBoost model #7 thinks this is suspicious" |
| What happens when a new heuristic is added? | A new model must be trained | The new heuristic contributes fields to the existing feature vector | No retraining required; the existing model adapts via its feature weights at next calibration |
| What is the ML model's role? | Primary detection mechanism | One voice among many in a weighted ensemble | Prevents over-reliance on any single component; heuristics catch what ML misses and vice versa |

---

## 2. Why the Shared Feature Space Is the Backbone

### 2.1 The Problem It Solves

Consider what happens without a feature space. The network heuristics produce:

```
- threat_score: int (0–40, sum of heuristic weights that fired)
- is_known_c2_port: bool
- beaconing_interval_ms: float (milliseconds between packets)
- bytes_sent: int (raw byte count, can be 0 to 10^9)
- remote_port: int (0–65535)
- protocol: str ("tcp", "udp", "icmp")
```

These six fields have nothing in common: different scales, different types, different
distributions. XGBoost will learn to use them, but only if the training data and inference
data have matching distributions. If the training data was captured on a gigabit LAN where
`bytes_sent` typically reaches 10^7, and the inference machine is on a 10Mbps endpoint
where `bytes_sent` rarely exceeds 10^5, the model will systematically underestimate
risk for large-transfer attacks and the `threat_score` field will be misweighted.

The feature space is the normalization contract that makes the model **portable** across
environments. It converts heterogeneous raw signals into a homogeneous numerical vector
with predictable range and semantics.

### 2.2 What "Shared" Means and Does Not Mean

There is a common misreading: "shared feature space" implies a single unified feature vector
that all four models consume. This is wrong and would not work — network flow features
and memory region features have no structural overlap.

"Shared" refers to **three specific things**:

**1. Shared output contract:** Every model, regardless of input domain, outputs a single
float `ml_score ∈ [0.0, 1.0]` that represents a calibrated probability of malicious
behavior. This is the only point where all four models interact.

**2. Shared entity schema:** Every scanner maps its output to an `EntityNode` with
identical fields (`heuristic_score`, `ml_score`, `combined_score`, `threat_level`,
`pid`, `parent_pid`, `file_path`, `remote_ip`, `file_hash`). The graph engine only
ever sees `EntityNode` objects — it does not know which scanner produced them.

**3. Shared normalization rules:** Within each domain, the same categories of transformation
are applied:
- Log-scale all volume/size features (`log10(x + 1)`)
- Normalize counts to `[0, 1]` by dividing by their theoretical maximum
- Convert categorical variables to one-hot or ordinal encoding
- Replace absolute identifiers (PID, IP address, raw path) with derived boolean features

Each scanner has its **own private** feature vector. "Shared" is the architecture of
convergence at the output, not the architecture of the input.

### 2.3 The Feature Space Is a Runtime Artifact, Not Just a Training Artifact

This is the most important property and the one most often misunderstood. The feature
space must be constructed identically at both training time (from dataset rows) and
inference time (from live scanner events). If these two constructions diverge — even
in a single field's scaling — the model produces garbage at inference time regardless
of its training performance.

The feature space is therefore a **specification**, not a script. It must be:
- Written down as a canonical ordered list (`NETWORK_FEATURES`, etc.) before any training begins
- Implemented twice: once in the dataset preprocessor, once in the runtime feature extractor
- Tested for equivalence: the same real-world event, preprocessed from the dataset and
  extracted at runtime, must produce bit-identical vectors

This is the contract. Breaking it after training invalidates all trained models.

---

## 3. The Feature Vector Contracts

### 3.1 Network Feature Vector (`NETWORK_FEATURES`)

**Training dataset:** UNSW-NB15 (primary), CIC-IDS-2017 (supplement)
**Raw fields in UNSW-NB15:** 49
**Features after preprocessing:** ~43

```python
NETWORK_FEATURES = [
    # ── Heuristic output (filled with 0.0 at training time) ──────────────
    "heuristic_score_norm",       # float  [0,1]  = raw_score / MAX_NETWORK_SCORE

    # ── Port / protocol ──────────────────────────────────────────────────
    "is_known_c2_port",           # bool→int  1 if dport in C2_PORT_LIST
    "dst_port_norm",              # float  [0,1]  = dport / 65535
    "proto_tcp",                  # one-hot: 1 if proto == "tcp"
    "proto_udp",                  # one-hot: 1 if proto == "udp"
    "proto_icmp",                 # one-hot: 1 if proto == "icmp"
    "state_FIN",                  # one-hot: connection state
    "state_CON",
    "state_REQ",
    "state_INT",

    # ── Volume ───────────────────────────────────────────────────────────
    "bytes_sent_log",             # float  log10(sbytes + 1)
    "bytes_recv_log",             # float  log10(dbytes + 1)
    "pkts_sent_log",              # float  log10(Spkts + 1)
    "pkts_recv_log",              # float  log10(Dpkts + 1)
    "mean_pkt_size_src_log",      # float  log10(smeansz + 1)
    "mean_pkt_size_dst_log",      # float  log10(dmeansz + 1)
    "load_src_log",               # float  log10(Sload + 1)
    "load_dst_log",               # float  log10(Dload + 1)

    # ── Timing / beaconing ───────────────────────────────────────────────
    "duration_log",               # float  log10(dur + 1)
    "inter_pkt_src_log",          # float  log10(Sintpkt + 1)
    "inter_pkt_dst_log",          # float  log10(Dintpkt + 1)
    "jitter_src_log",             # float  log10(Sjit + 1)
    "jitter_dst_log",             # float  log10(Djit + 1)
    "beaconing_score",            # float  [0,1]  derived: regularity of inter-packet interval

    # ── TCP internals ────────────────────────────────────────────────────
    "tcp_win_src_norm",           # float  swin / 65535
    "tcp_win_dst_norm",           # float  dwin / 65535
    "tcp_rtt_log",                # float  log10(tcprtt + 1)
    "synack_time_log",            # float  log10(synack + 1)
    "ackdat_time_log",            # float  log10(ackdat + 1)

    # ── IP metadata ──────────────────────────────────────────────────────
    "src_is_private",             # bool→int
    "src_is_global",              # bool→int
    "dst_is_private",             # bool→int
    "dst_is_global",              # bool→int
    "src_freq_log",               # float  log10(frequency of this src IP in session + 1)
    "dst_freq_log",               # float  log10(frequency of this dst IP in session + 1)

    # ── Connection frequency counters ────────────────────────────────────
    "ct_srv_src_log",             # float  log10(ct_srv_src + 1)
    "ct_srv_dst_log",             # float  log10(ct_srv_dst + 1)
    "ct_dst_ltm_log",             # float  log10(ct_dst_ltm + 1)
    "ct_src_ltm_log",             # float  log10(ct_src_ltm + 1)
    "ct_src_dport_ltm_log",       # float  log10(ct_src_dport_ltm + 1)
    "ct_dst_sport_ltm_log",       # float  log10(ct_dst_sport_ltm + 1)
    "ct_dst_src_ltm_log",         # float  log10(ct_dst_src_ltm + 1)
]
```

**Fields discarded from UNSW-NB15 and why:**

| Discarded field | Reason |
|---|---|
| `srcip`, `dstip` | Raw IPs are machine-specific. Replaced by `src_freq_log`, `dst_freq_log`, and IP-class booleans |
| `Stime`, `Ltime` | Absolute UNIX timestamps. Meaningless on a different machine at a different time |
| `sloss`, `dloss` | Near-zero variance in real traffic — the field adds noise without signal |
| `is_ftp_login`, `ct_ftp_cmd` | FTP-specific. Vanishingly rare in modern environments; hurts the model by creating a feature that is almost always 0 |
| `sttl`, `dttl` | TTL values are router-hop-count-dependent. Not portable across network topologies |

---

### 3.2 File Feature Vector (`FILE_FEATURES`)

**Training dataset:** EMBER (primary), SOREL-20M (supplement)

```python
FILE_FEATURES = [
    # ── Heuristic output ─────────────────────────────────────────────────
    "heuristic_score_norm",       # float  [0,1]

    # ── Byte-level statistics ────────────────────────────────────────────
    # 256-bin byte histogram (normalized so bins sum to 1.0)
    *[f"byte_hist_{i}" for i in range(256)],
    # Entropy in 2048-byte windows (EMBER provides this as a series)
    "byte_entropy_mean",          # float  mean Shannon entropy across windows
    "byte_entropy_max",           # float  max entropy window (packed section indicator)
    "byte_entropy_std",           # float  stddev — high std → heterogeneous sections

    # ── PE header ────────────────────────────────────────────────────────
    "linker_version_norm",        # float  MajorLinkerVersion / 14.0
    "size_of_code_log",           # float  log10(SizeOfCode + 1)
    "size_of_headers_log",        # float  log10(SizeOfHeaders + 1)
    "subsystem_norm",             # float  subsystem enum / 16
    "timestamp_is_future",        # bool→int  1 if TimeDateStamp > current_time (tampered)
    "timestamp_is_zero",          # bool→int  1 if TimeDateStamp == 0 (stripped)
    "has_debug",                  # bool→int
    "has_tls",                    # bool→int
    "has_signature",              # bool→int
    "is_dll",                     # bool→int
    "dll_characteristics_nx",     # bool→int  NX-compatible flag
    "dll_characteristics_aslr",   # bool→int  ASLR flag

    # ── Section analysis ─────────────────────────────────────────────────
    "num_sections_norm",          # float  num_sections / 20
    "section_max_entropy",        # float  entropy of most-entropic section
    "section_mean_entropy",       # float
    "frac_sections_high_entropy", # float  fraction of sections with entropy > 7.0
    "text_section_entropy",       # float  entropy of .text specifically
    "rwx_section_present",        # bool→int  any section with RWX flags
    "virtual_vs_raw_ratio_max",   # float  max(virtual_size / raw_size) across sections

    # ── Imports ──────────────────────────────────────────────────────────
    "num_import_libs_log",        # float  log10(len(imports) + 1)
    "num_import_funcs_log",       # float  log10(total_import_count + 1)
    "has_virtualalloc",           # bool→int
    "has_writeprocessmemory",     # bool→int
    "has_createremotethread",     # bool→int
    "has_loadlibrary",            # bool→int

    # ── Exports ──────────────────────────────────────────────────────────
    "num_exports_log",            # float  log10(num_exports + 1)
    "has_exports",                # bool→int  unusual for EXEs; common in injection DLLs

    # ── Strings ──────────────────────────────────────────────────────────
    "num_strings_log",            # float  log10(num_strings + 1)
    "mean_string_length_norm",    # float  mean_len / 100
    "num_paths_log",              # float  log10(count_of_path_strings + 1)
    "num_urls_log",               # float  log10(count_of_url_strings + 1)
    "num_registry_keys_log",      # float  log10(count_of_registry_strings + 1)
    "has_mz_in_strings",          # bool→int  MZ header embedded in strings (dropper)
]
```

---

### 3.3 Process Feature Vector (`PROCESS_FEATURES`)

**Training dataset:** DAPT 2020 (primary), BIG 2015 (secondary), CDMC 2022 (behavioral)

```python
PROCESS_FEATURES = [
    # ── Heuristic output ─────────────────────────────────────────────────
    "heuristic_score_norm",       # float  [0,1]

    # ── Path / identity ──────────────────────────────────────────────────
    "exe_in_safe_path",           # bool→int  1 if path starts with known-safe prefix
    "exe_in_temp",                # bool→int  1 if path contains \Temp\ or /tmp/
    "exe_in_appdata",             # bool→int
    "is_system32_name_outside",   # bool→int  svchost.exe NOT in System32
    "name_entropy_norm",          # float  Shannon entropy of process name / 5.0
    "is_known_lolbin",            # bool→int  Living-off-the-land binary (powershell, wscript, etc.)

    # ── Ancestry ─────────────────────────────────────────────────────────
    "parent_is_threat",           # bool→int  parent entity has threat_level >= Suspicious
    "spawn_depth_norm",           # float  depth_in_process_tree / 10
    "is_orphan",                  # bool→int  parent PID == 0 or parent no longer exists
    "spawned_by_lolbin",          # bool→int  direct parent is a known lolbin

    # ── Resource usage ───────────────────────────────────────────────────
    "cpu_percentile",             # float  [0,1]  percentile rank in current session
    "memory_percentile",          # float  [0,1]  percentile rank in current session
    "handle_count_log",           # float  log10(handle_count + 1)

    # ── Thread / integrity ───────────────────────────────────────────────
    "thread_count_is_zero",       # bool→int  hollowed process indicator
    "thread_count_lt_2",          # bool→int
    "integrity_is_system",        # bool→int
    "integrity_is_high",          # bool→int

    # ── Command line ─────────────────────────────────────────────────────
    "cmdline_has_encoded",        # bool→int  -enc or -EncodedCommand
    "cmdline_has_bypass",         # bool→int  -ExecutionPolicy Bypass
    "cmdline_has_iex",            # bool→int  Invoke-Expression / iex
    "cmdline_has_download",       # bool→int  DownloadString / DownloadFile / wget / curl
    "cmdline_has_hidden",         # bool→int  -WindowStyle Hidden
    "cmdline_has_noprofile",      # bool→int  -NoProfile (evading PSReadline history)
    "cmdline_length_norm",        # float  min(len(cmdline), 1000) / 1000

    # ── Timing ───────────────────────────────────────────────────────────
    "process_age_log",            # float  log10(age_seconds + 1); very short-lived → suspicious
    "started_at_odd_hour",        # bool→int  started between 00:00 and 06:00 local time

    # ── Module / injection indicators ────────────────────────────────────
    "has_unsigned_module",        # bool→int  loaded DLL without a valid signature
    "has_module_outside_safe_path",# bool→int
]
```

---

### 3.4 Memory Feature Vector (`MEMORY_FEATURES`)

**Training dataset:** CIC-MalMem-2022

```python
MEMORY_FEATURES = [
    # ── Heuristic output ─────────────────────────────────────────────────
    "heuristic_score_norm",       # float  [0,1]

    # ── Permission flags (strongest signals) ─────────────────────────────
    "is_executable",              # bool→int
    "is_writable",                # bool→int
    "is_rwx",                     # bool→int  RWX combined — primary injection indicator
    "is_copy_on_write",           # bool→int

    # ── Allocation type ──────────────────────────────────────────────────
    "alloc_private",              # one-hot  shellcode lives in private anonymous regions
    "alloc_mapped",               # one-hot
    "alloc_image",                # one-hot  normal loaded modules

    # ── Region size ──────────────────────────────────────────────────────
    "region_size_log",            # float  log10(region_size + 1)
    "is_shellcode_size_range",    # bool→int  region_size between 4KB and 1MB

    # ── Alignment ────────────────────────────────────────────────────────
    "is_page_aligned",            # bool→int  not page-aligned → unusual
    "has_pe_header",              # bool→int  MZ signature found in region content

    # ── Process context ──────────────────────────────────────────────────
    "process_is_threat",          # bool→int  owning process entity is flagged
    "process_has_network",        # bool→int  owning process has network connections

    # ── Session-level aggregates ─────────────────────────────────────────
    "rwx_region_count_log",       # float  log10(count of RWX regions in this PID + 1)
    "suspicious_region_ratio",    # float  suspicious_regions / total_regions for this PID
]
```

---

## 4. How Data Is Generated for Training

### 4.1 The Central Principle

Training data is generated through a **transform pipeline**, not a direct mapping.
The raw dataset provides labelled observations in its own format. The transform
pipeline converts those observations into the canonical feature vector defined in
Section 3. The output of the pipeline — not the raw dataset — is what the model
trains on.

This pipeline must be deterministic, reproducible, and versioned alongside the model.
If the pipeline changes, all models that depend on it must be retrained.

### 4.2 Network — UNSW-NB15 Transform

```
UNSW-NB15.csv  (2,540,044 rows × 49 columns, labelled 0/1)
      │
      ▼  preprocess_unsw_nb15.py
      ├── Drop: srcip, dstip, Stime, Ltime, sloss, dloss, sttl, dttl,
      │         is_ftp_login, ct_ftp_cmd
      ├── Log-scale: sbytes, dbytes, Spkts, Dpkts, smeansz, dmeansz,
      │              Sload, Dload, dur, Sintpkt, Dintpkt, Sjit, Djit,
      │              ct_srv_src, ct_srv_dst, ct_dst_ltm, ct_src_ltm,
      │              ct_src_dport_ltm, ct_dst_sport_ltm, ct_dst_src_ltm
      ├── Normalize: dport / 65535, swin / 65535, dwin / 65535
      ├── One-hot: proto → (tcp, udp, icmp), state → (FIN, CON, REQ, INT)
      ├── Derive: src_is_private (RFC1918), src_is_global, is_known_c2_port
      ├── Derive: src_freq_log, dst_freq_log (from IP frequency table in dataset)
      ├── Derive: beaconing_score (stddev(inter_arrival) / mean(inter_arrival) — inverted)
      ├── Fill: heuristic_score_norm = 0.0 (not available at training time)
      └── Output: network_features.csv (same columns as NETWORK_FEATURES + "label")
```

Key detail: `heuristic_score_norm` is **always zero in the training data**.
The model therefore learns the feature as "when this is 0, it provides no information;
weight the other features accordingly." At inference time, when it carries a real value
like 0.45, it becomes an additional positive signal on top of the raw features. The model
does not need to be retrained to use it — it was trained to be compatible with it.

### 4.3 File — EMBER Transform

```
EMBER jsonl files (1M samples, pre-extracted feature groups)
      │
      ▼  preprocess_ember.py
      ├── Skip: unlabeled samples (label == -1)
      ├── Byte histogram: normalize 256-bin counts to sum to 1.0
      ├── Byte entropy: extract mean, max, std from entropy series
      ├── PE header: extract and normalize each field per EMBER schema
      ├── Section analysis: per-section entropy, compute aggregates
      ├── Imports: hash library names → presence/absence of critical APIs
      ├── Strings: count by category (paths, URLs, registry, MZ markers)
      ├── Fill: heuristic_score_norm = 0.0
      └── Output: file_features.csv (same columns as FILE_FEATURES + "label")
```

EMBER already provides pre-extracted features — the transform only normalizes and
reorders them into the canonical schema. No raw PE file parsing is required at
training time. At inference time, the runtime scanner parses the live PE file using
a Rust PE library and extracts the same fields.

### 4.4 Process — DAPT 2020 Transform

```
DAPT 2020 logs (APT-style process execution events, labelled by attack stage)
      │
      ▼  preprocess_dapt2020.py
      ├── Extract: process name, path, parent path, command line, PID, PPID
      ├── Derive: exe_in_safe_path, exe_in_temp, exe_in_appdata (boolean from path)
      ├── Derive: is_system32_name_outside (name match without path match)
      ├── Derive: name_entropy (Shannon entropy of filename)
      ├── Derive: is_known_lolbin (lookup table)
      ├── Derive: spawn_depth (traverse parent chain, count depth)
      ├── Derive: cpu_percentile, memory_percentile (rank within dataset session)
      ├── Derive: cmdline_* flags (regex matches on command line string)
      ├── Fill: heuristic_score_norm = 0.0, parent_is_threat = 0 (no entity layer at training)
      └── Output: process_features.csv (same columns as PROCESS_FEATURES + "label")
```

Raw PIDs, absolute CPU values, and absolute memory bytes are all **discarded** and
replaced with derived features. This is mandatory: a PID of 1234 on the training machine
is meaningless on the inference machine. The percentile rank of CPU usage within the
current session is meaningful on both.

### 4.5 Memory — CIC-MalMem-2022 Transform

```
CIC-MalMem-2022 (memory region dumps, labelled: Benign / Spyware / Ransomware / Trojan)
      │
      ▼  preprocess_cicmalmem.py
      ├── Map label: Benign → 0, {Spyware, Ransomware, Trojan} → 1
      ├── Extract: Type (private/mapped/image), Size, Protection flags
      ├── Derive: is_executable, is_writable, is_rwx from Protection bitmask
      ├── Derive: alloc_private/mapped/image one-hot from Type
      ├── Derive: region_size_log, is_shellcode_size_range
      ├── Derive: is_page_aligned (from base address alignment)
      ├── Derive: has_pe_header (MZ signature present in first bytes of region)
      ├── Aggregate: rwx_region_count_log, suspicious_region_ratio (per PID)
      ├── Fill: heuristic_score_norm = 0.0, process_is_threat = 0
      └── Output: memory_features.csv (same columns as MEMORY_FEATURES + "label")
```

---

## 5. Why Non-Intersecting Datasets Are Not a Problem

### 5.1 The Misconception

The most common confusion about this architecture is: "If the four datasets have nothing
in common, how can the models work together? How can the entity layer combine their outputs?"

This question assumes the models share an input. They do not.

### 5.2 The Correct Mental Model

Think of four specialists in a hospital:

- A **radiologist** reads X-rays. Their input is a greyscale image. Their output is
  a report with a probability estimate for each finding.
- A **cardiologist** reads ECG traces. Their input is a time-series voltage signal.
  Their output is a report with a probability estimate for each arrhythmia.
- A **neurologist** reads MRI scans. Their input is a 3D volumetric scan.
  Their output is a report with a probability estimate for each lesion.
- A **pathologist** reads tissue biopsies. Their input is a microscope slide.
  Their output is a report with a probability estimate for each cell abnormality.

The inputs of these four specialists have **nothing in common**. An X-ray and an MRI
are not the same data. A cardiologist cannot read a biopsy.

Yet the **outputs** converge at the attending physician, who combines them into a
unified diagnosis. The attending does not need to understand X-ray physics or
electrophysiology — they read four probability estimates and reason about the
combination.

The entity layer is the attending physician. The four ML models are the specialists.
The graph engine is the clinical reasoning that catches patterns no single specialist
would see alone (e.g., a cascade of findings that together indicate sepsis, which
none of the individual reports flagged).

### 5.3 Why the Outputs Are Comparable Even Though the Inputs Are Not

The outputs are comparable because of **calibration**. Without calibration,
`ml_score = 0.85` from the network model and `ml_score = 0.85` from the file model
mean completely different things — the network model might have learned to output
high scores conservatively, while the file model might output high scores aggressively.

`CalibratedClassifierCV` with isotonic regression maps each model's raw output to
a **true probability** — the fraction of training samples with that score that were
actually malicious. After calibration, `ml_score = 0.85` means "of the events this
model assigned a score of approximately 0.85, 85% were actually malicious" for all
four models. The scores are now on the same probability scale and can be meaningfully
combined via `combined_score`.

### 5.4 The Data Flow Through the Non-Intersecting Domains

```
UNSW-NB15 ──► Network Feature Vector ──► Network ML ──► ml_score=0.91
                                                              │
                                                              ▼
EMBER ────► File Feature Vector ──────► File ML ────► ml_score=0.43  ──► Entity Layer
                                                              ▲              │
DAPT 2020 ► Process Feature Vector ──► Process ML ──► ml_score=0.67         │
                                                              │         combined_score
CIC-MalMem ► Memory Feature Vector ──► Memory ML ──► ml_score=0.88          │
                                                                             ▼
                                                                       Graph Engine
```

At no point do network features touch the file model or vice versa. The datasets
do not need to intersect because the models never share an input. They share only
an output interface: a calibrated probability score attached to an entity.

---

## 6. How Each Model Trains on Its Feature Vector

### 6.1 Training Architecture

All four models use the same algorithm class: **XGBoost** (`XGBClassifier`).
This is not arbitrary. XGBoost is chosen because:

1. **It handles mixed-type features well.** The feature vectors contain floats, booleans
   cast to integers, log-scaled values, and one-hot columns. XGBoost's tree splits
   handle these natively without requiring standardization.

2. **It is robust to irrelevant features.** When `heuristic_score_norm = 0.0` in all
   training rows, XGBoost will learn to assign that feature near-zero weight.
   It will not overfit to a constant.

3. **It produces well-behaved probability estimates after calibration.** Raw XGBoost
   probabilities are not calibrated, but they are monotone and bounded, making
   isotonic regression calibration reliable.

4. **It is fast at inference time.** An endpoint agent must classify thousands of
   events per second without degrading system performance. XGBoost inference on
   a 40-feature vector takes microseconds.

### 6.2 Step-by-Step Training Protocol

**Step 1: Load the preprocessed CSV**
```python
df = pd.read_csv("network_features.csv")
X  = df[NETWORK_FEATURES]   # ordered list from Section 3
y  = df["label"]             # 0 or 1
```

**Step 2: Handle class imbalance**
```python
# Benign traffic dominates in every dataset (10:1 to 100:1 ratio)
neg_count = (y == 0).sum()
pos_count = (y == 1).sum()
scale_pos_weight = neg_count / pos_count   # passed to XGBoost
```

Without this adjustment, the model learns to classify everything as benign (majority class)
and achieves 99% accuracy on a useless classifier. `scale_pos_weight` makes misclassifying
a malicious sample `neg/pos` times more costly than misclassifying a benign sample.

**Step 3: Train**
```python
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42
)

model = XGBClassifier(
    n_estimators=300,
    max_depth=6,
    learning_rate=0.05,
    subsample=0.8,
    colsample_bytree=0.8,
    scale_pos_weight=scale_pos_weight,
    eval_metric="aucpr",           # area under precision-recall curve (better than AUC-ROC for imbalanced data)
    early_stopping_rounds=20,
)
model.fit(X_train, y_train, eval_set=[(X_test, y_test)])
```

`eval_metric="aucpr"` is deliberately chosen over `"auc"` for imbalanced security
datasets. AUC-ROC is misleading when the negative class is 100× larger than the
positive class — a model that correctly classifies 99.9% of benign traffic while
missing half of all attacks still scores 0.99 AUC-ROC. AUC-PR measures precision
at each recall level and is honest about the false positive / false negative tradeoff.

**Step 4: Calibrate**
```python
calibrated = CalibratedClassifierCV(
    estimator=model,
    method="isotonic",    # non-parametric; better than "sigmoid" for XGBoost
    cv="prefit",          # model is already trained; use X_test as calibration set
)
calibrated.fit(X_test, y_test)
```

This step transforms the raw XGBoost score into a true probability. The `cv="prefit"`
option uses the held-out test set for calibration, which prevents information leakage
from the training set into the calibration mapping.

**Step 5: Threshold tuning**
```python
probs = calibrated.predict_proba(X_test)[:, 1]
precision, recall, thresholds = precision_recall_curve(y_test, probs)

# Target: recall >= 0.95 (catch 95% of malicious events)
# Accept: whatever precision that buys
target_idx = np.argmax(recall >= 0.95)
optimal_threshold = thresholds[target_idx]
```

The threshold is tuned for **high recall at the model level**. False positives are
acceptable here because the graph engine will suppress them through structural context.
A process that triggers the process model but has no suspicious network connections,
no memory injection, and no file drops will score low in the graph and will not be
elevated to Malicious even if its individual `combined_score` is above threshold.

**Step 6: Save**
```python
import joblib
joblib.dump({"model": calibrated, "threshold": optimal_threshold,
             "features": NETWORK_FEATURES}, "network_model.pkl")
```

The feature list is saved with the model to catch version drift: if `NETWORK_FEATURES`
changes between training runs, the saved list will not match the new runtime extractor,
and the mismatch will be caught before inference.

---

## 7. How the Four Models Interact at Runtime

### 7.1 They Do Not Interact — They Converge

The four models never call each other. They never share state during inference.
They run in parallel, each consuming events from their respective scanner,
and produce output that flows into the entity layer independently.

The interaction is **structural**, not computational. The entity layer provides the
join point: when the network model scores a connection owned by PID 3821, and the
process model scores the process with PID 3821, the entity layer joins them on the
shared `pid` key. The graph engine then draws an edge between these two entities
and uses both scores to compute the edge weight.

### 7.2 Runtime Data Flow (Concrete Example)

```
[Rust scanner thread: Process]
  ProcessScanner scans PID 3821
  Heuristics fire: exe_in_temp=true, parent_is_lolbin=true → heuristic_score=22
  feature_extractor builds PROCESS_FEATURES vector
  → writes to /tmp/process_features_3821.json
  → calls: python infer.py --model process --input /tmp/process_features_3821.json
  ← receives: {"ml_score": 0.67, "entity_id": "proc:3821"}
  → manager.update_entity("proc:3821", heuristic_score=22, ml_score=0.67)
  → combined_score = (22/40)×0.4 + 0.67×0.6 = 0.622

[Rust scanner thread: Network]
  NetworkScanner scans connection pid=3821 → 185.220.101.7:4444
  Heuristics fire: known_c2_port=true, beaconing=true → heuristic_score=31
  feature_extractor builds NETWORK_FEATURES vector
  → calls: python infer.py --model network --input /tmp/network_features_3821_c2.json
  ← receives: {"ml_score": 0.91, "entity_id": "net:3821:185.220.101.7:4444"}
  → manager.update_entity("net:3821:...", heuristic_score=31, ml_score=0.91)
  → combined_score = (31/40)×0.4 + 0.91×0.6 = 0.856

[Graph builder]
  EntityNode proc:3821        combined_score=0.622
  EntityNode net:3821:...     combined_score=0.856
  Edge: NetworkOwner (proc:3821 → net:3821:...) × 1.40
  Edge weight = avg(0.622, 0.856) × 1.40 = 1.037

[Graph analyzer]
  Path score for proc:3821 receives boost from high-scoring network edge
  Adjusted threat level: Malicious
  Pattern matched: C2_BEACON_FROM_TEMP_PROCESS
  MITRE: T1071.001 (Application Layer Protocol: Web Protocols)
```

### 7.3 What Happens When a Scanner Is Not Available

If the memory scanner has not yet been trained, `ml_score` for memory entities
defaults to `0.0`, and `combined_score = heuristic_score × 0.4`. The entity
still participates in the graph. Its contribution is lower, but it is not absent.
The architecture degrades gracefully.

---

## 8. The Entity Layer: Where All Outputs Converge

### 8.1 EntityNode Structure

Every scanner produces data that maps to a common `EntityNode` schema:

```
EntityNode {
    id:               String        (unique: "proc:PID", "net:PID:IP:PORT", "file:HASH", "mem:PID:ADDR")
    entity_type:      ProcessInfo | NetworkConnection | FileInfo | MemoryRegion
    heuristic_score:  f32           (raw sum of heuristic weights that fired)
    ml_score:         f32           (calibrated probability from domain ML model)
    combined_score:   f32           (H×0.4 + ML×0.6, computed once and cached)
    threat_level:     Clean | Suspicious | Malicious | Critical
    pid:              Option<u32>   (join key for process ↔ network ↔ memory)
    parent_pid:       Option<u32>
    file_path:        Option<String>
    remote_ip:        Option<String>
    file_hash:        Option<String>
    signals:          Vec<Signal>   (list of all heuristic signals that fired)
}
```

### 8.2 The Join Keys

The entity layer maintains four indexes, one per join key type:

| Index | Key | Joins |
|---|---|---|
| PID index | `pid` | Process ↔ Network ↔ Memory |
| Parent index | `parent_pid` | Process ↔ Process (ancestry chain) |
| File hash index | `file_hash` | File ↔ Process (process loaded this file) |
| Remote IP index | `remote_ip` | Network ↔ Network (multiple connections to same C2) |

When any entity is updated, the correlator checks all four indexes for existing entities
that share a key. Each match produces a potential graph edge.

### 8.3 Threat Level Thresholds

```
combined_score ∈ [0.00, 0.30)  →  Clean
combined_score ∈ [0.30, 0.55)  →  Suspicious
combined_score ∈ [0.55, 0.75)  →  Malicious
combined_score ∈ [0.75, 1.00]  →  Critical
```

These thresholds are tuned after calibration. The graph engine can elevate an entity's
threat level above its individual `combined_score` threshold if it is strongly connected
to other high-scoring entities. It can also suppress an entity if its connections are
all low-scoring (isolated high scorer → false positive suppression).

---

## 9. The Graph Engine: Why Four Numbers Beat Four Verdicts

### 9.1 The Problem With Verdict-Based Aggregation

A naive alternative to the graph approach: each model outputs a verdict (Clean /
Suspicious / Malicious), and the system raises an alert if more than two models
agree. This fails for several reasons:

- **Multi-stage attacks are sequential, not simultaneous.** In a typical APT intrusion,
  the initial payload is a legitimate-looking executable that only becomes suspicious
  after it downloads a second stage. At T=0, no scanner flags it. At T=5m, the network
  scanner sees beaconing. At T=30m, the memory scanner sees shellcode injection.
  Verdict voting at any single point in time would not catch this.

- **Verdicts lose magnitude.** A network `combined_score` of 0.99 and a network
  `combined_score` of 0.56 are both "Malicious" in a verdict system. The graph treats
  them very differently — the 0.99 entity pulls all its connected entities up; the 0.56
  entity has a much weaker gravitational effect.

- **Verdicts lose structure.** Knowing that "process A is Malicious AND network connection
  B is Malicious" tells you less than knowing "process A owns network connection B through
  a NetworkOwner edge, and both are high-scoring." The edge type encodes the relationship;
  the graph captures the attack chain topology.

### 9.2 Edge Weight Calculation

```
edge_weight = avg(score_A, score_B) × edge_type_multiplier

Multipliers:
  MemoryInjection   × 1.50  ← RWX region in a flagged process = extremely strong signal
  NetworkOwner      × 1.40  ← C2 connection owned by flagged process
  SharedC2          × 1.30  ← multiple processes connecting to the same flagged IP
  ProcessOpenedFile × 1.20  ← flagged process opened a flagged file (loader / dropper)
  ParentChild       × 1.10  ← flagged process spawned another process (propagation)
  SameProcess       × 1.00  ← two entities both owned by same process
  SharedFileHash    × 0.90  ← two processes loaded the same file (spread indicator, weaker)
```

The multipliers encode domain knowledge about which behavioral relationships are most
diagnostic of real attacks. A memory injection edge from a 0.90-score region outweighs
a parent-child edge from a 0.30-score process. The graph does not silence weak signals —
they still contribute — but they carry proportionally less weight in the traversal.

### 9.3 Attack Pattern Detection

The graph analyzer runs several pattern detectors over the scored graph:

```
LateralMovement:    process → network(to internal IP) → process(on remote host)
C2Beacon:           process → network(to external IP, regular interval, small packets)
ProcessHollowing:   process(zero threads) ← memoryinjection ← process(flagged)
DropperChain:       file(high entropy) ← processopened ← process ← child process
PrivilegeEscalation: process(user) → parentchild → process(system integrity)
```

Each pattern generates a structured narrative with the entities involved, the edge
path through the graph, the combined score along the path, and the MITRE ATT&CK
tactic and technique that best matches.

---

## 10. Distribution Shift: The Real Risk and How to Contain It

### 10.1 What Distribution Shift Means in This Context

Every public dataset was collected in a specific lab environment at a specific point in
time. UNSW-NB15 was collected at the UNSW Canberra cyber range in 2015. CIC-IDS-2017
was collected at the University of New Brunswick in 2017. These environments have:

- Different baseline traffic profiles than a modern enterprise network
- Different OS versions, patch levels, and application software
- Simulated attacks that may not reflect current threat actor TTPs

When these models run on a 2025 enterprise endpoint, the features they were trained on
may have shifted: packet sizes are different, inter-arrival times are different, process
ancestry patterns are different. A model that learned "beaconing looks like this" from
2015 traffic may not recognize 2025 beaconing that uses HTTP/2 multiplexing over CDN
infrastructure.

### 10.2 How the Architecture Contains This Risk

**Layer 1: Heuristics as a safety net (40% weight)**

The `combined_score` formula ensures that even when `ml_score` drops to zero due to
distribution shift, the heuristic score still contributes 40% of the final score. A
rule that fires on port 4444 with a Metasploit pattern will fire regardless of which
year the traffic was generated. Heuristics are environment-independent by construction.

**Layer 2: The graph as a structural filter**

The graph engine reasons about entity relationships, not feature values. A
parent-child edge between a process and its child exists independently of what year
the training data came from. If a process spawns a child that opens a network
connection to an external IP, that structural relationship is suspicious regardless
of the specific feature values involved. The graph catches attack chains that survive
feature distribution shift because chain topology does not shift as fast as raw features.

**Layer 3: Four small models instead of one large model**

Distribution shift in network traffic does not affect the file model or the process
model. By isolating each model to its own domain, the blast radius of any single
model's degradation is limited to that domain. The other three models continue to
function correctly, and the graph can compensate for the degraded model's weaker signal.

**Layer 4: Monitoring false positive rate**

The most reliable early warning for distribution shift is a rising false positive rate
in production. If the process model begins flagging legitimate `svchost.exe` instances
as suspicious at an increasing rate, the training distribution has diverged from the
deployment distribution. This is detected by tracking the rate at which `Clean`
entities are elevated to `Suspicious` after a correlate run.

**Layer 5: CLEAN_PREFIXES (network-specific)**

Known-good infrastructure (Cloudflare, Google, Microsoft, Akamai) is excluded from
the training signal via a `CLEAN_PREFIXES` IP block list. This prevents the model
from learning that traffic to `8.8.8.8` is benign, then misfiring when a real C2
uses a Cloudflare fronting domain. The clean prefix list must be updated as
infrastructure providers change.

### 10.3 Retraining Strategy

```
Phase 1 (current): Train all four models on public datasets with CLEAN_PREFIXES filtering.
                   Calibrate all four. Deploy. Monitor false positive rate per model.

Phase 2 (after 4 weeks): Collect unlabeled samples from the deployment environment.
                          Run the current model on them to generate pseudo-labels.
                          Identify high-confidence pseudo-labeled malicious samples
                          and add them to the training set. Retrain with updated data.
                          Do NOT change NETWORK_FEATURES — the contract must not change.

Phase 3 (ongoing):        Use clustering (DBSCAN or Isolation Forest) on the feature
                          vectors of entities that scored in the 0.30–0.55 range
                          ("ambiguous zone"). Clusters that grow over time represent
                          new behavioral patterns. Manually label a sample from each
                          new cluster. Retrain quarterly.
```

---

## Conclusion

The architecture described here is not a collection of independent components bolted
together — it is a layered inference system where each layer has a precisely defined
role and a clean interface to the next.

| Layer | Role | Survives distribution shift? |
|---|---|---|
| Heuristics | Rule-based first filter | Yes — rules do not depend on training data |
| Feature space | Normalization contract | Yes — it is a specification, not a model |
| ML models | Domain-specific probability estimators | Partially — degrades gracefully; safety nets compensate |
| Entity layer | Signal convergence and join point | Yes — join keys are structural |
| Graph engine | Attack chain reasoning | Yes — topology does not shift as fast as raw features |
| Narrative | Human-readable output | N/A |

The four models do not need shared datasets, shared features, or shared training
because they are not trying to solve the same problem. They are each solving one
subproblem (is this network connection suspicious? is this process suspicious?)
and handing a single calibrated number to a higher layer that reasons about all
four numbers simultaneously. The complexity of multi-domain threat detection is
not concentrated in any single model — it is distributed across layers that each
do one thing well and compose cleanly.

The remaining work is to train the three missing models (file, process, memory)
using the protocol in Section 6, calibrate them, and wire their outputs into
`manager.update_ml_score()` the same way the network model is wired today.
The architecture is already in place. The models just need to be built.

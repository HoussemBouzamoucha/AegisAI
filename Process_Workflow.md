# AegisAI — Threat Graph Process Workflow
## Edge-Centric Architecture with LSTM + Heuristics + ML Fusion

---

## 1. Core Design Philosophy

### Edges Carry the Value, Not the Nodes

A node (process, file, IP address) is an entity. It does not inherently carry threat — it carries identity. The threat is expressed through **what it does**, and what it does is the edge.

Every edge is a semantic sentence:

```
ProcessA  —[MemoryInjection]→  ProcessB
ProcessA  —[NetworkOwner]→     IP:192.168.1.1
ProcessA  —[ProcessOpenedFile]→ File:loader.dll
```

The edge type is the verb. The nodes are the actors. The edge weight is how confident we are that this action was malicious, scaled by how dangerous that class of action is.

---

## 2. Edge Weight Formula

```
edge_weight = edge_type_multiplier × (heuristic_score × 0.4 + ML_score × 0.6)
```

Where:
- `edge_type_multiplier` — static domain knowledge about how dangerous this class of action is
- `heuristic_score` — rule-based evaluation of whether this specific action matches known-bad patterns
- `ML_score` — learned signal derived from the actor's behavioral profile (see Stage 1 + Stage 2 below)

### Edge Type Multipliers

| Edge Type         | Multiplier | Rationale                                                       |
|-------------------|------------|----------------------------------------------------------------|
| MemoryInjection   | ×1.50      | RWX region in a flagged process — extremely strong signal      |
| NetworkOwner      | ×1.40      | C2 connection owned by a flagged process                       |
| SharedC2          | ×1.30      | Multiple processes connecting to the same flagged IP           |
| ProcessOpenedFile | ×1.20      | Flagged process opened a flagged file (loader/dropper pattern) |
| ParentChild       | ×1.10      | Flagged process spawned another process (propagation)          |
| SameProcess       | ×1.00      | Two entities both owned by the same process                    |
| SharedFileHash    | ×0.90      | Two processes loaded the same file (spread indicator, weaker)  |

The multiplier is the **last amplifier** — it scales the final fused signal, not the raw input.

---

## 3. Two-Layer Edge Model

Each edge has two distinct layers:

### Layer 1 — Structural Default (Static)
The edge type defines the baseline danger of this class of action. This is baked-in domain knowledge. It never changes regardless of context. A spawn relationship carries ×1.10 inherent weight in a flagged context, always.

### Layer 2 — Observed Signal (Dynamic)
ML and heuristics evaluate the specific instance of this action. Was this particular spawn anomalous? Does it match a known injection pattern? This changes per event and per process pair.

The final edge value is the product of both layers: the structural weight of the action type, scaled by how suspicious this specific instance of that action was.

---

## 4. Signal Pipeline — Three-Stage Architecture

### Stage 1 — Entity ML Classifiers (Existing Models)

**Purpose:** Determine whether each entity (process) is malicious.

**Input:** Process behavior features — syscalls, memory patterns, PE characteristics, etc.

**Output:** Node-level threat score `[0.0 – 1.0]`

**Role in edge weight:** Provides the actor's risk profile. A highly-flagged process performing any action makes that action more suspicious. This is not the edge signal — it informs the edge signal via the actor's identity.

**Limitation:** Entity-level only. Does not know about relationships, targets, or inter-process interactions.

---

### Stage 2 — LSTM Behavioral Encoder (MalBehavD-V1)

**Purpose:** Recognize sequential API call patterns associated with specific malicious behaviors.

**Dataset:** MalBehavD-V1 — dynamic analysis traces containing per-process API call sequences from malware samples.

**Model:** LSTM trained on API call sequences to learn temporal patterns that precede or constitute malicious actions (injection sequences, C2 communication rhythms, dropper patterns, etc.).

**Input:** Sequence of API call names observed for a process.

**Output:** 
- Behavioral maliciousness score (richer than binary classification)
- Behavioral class encoding — what type of malicious behavior does this sequence resemble (injection-like, network-like, dropper-like)

**Role in edge weight:** Upgrades the node-level signal. Instead of "this process is malicious," it says "this process is performing injection-like behavior with confidence X." That behavioral class becomes part of the ML score fed into the edge weight formula.

**Limitation:** Still single-process focused. Sees what APIs were called — not what they were called on. Cannot identify the target of the action. Cannot construct the edge endpoint by itself.

---

### Stage 3 — Heuristics (API Parameter + Handle Tracking)

**Purpose:** Cover everything the LSTM cannot. Define the edge type, identify the target, and produce the relationship-level suspicion score.

**The LSTM vs Heuristics distinction:**

| Signal   | Sees                            | Cannot See                  |
|----------|---------------------------------|-----------------------------|
| LSTM     | Which APIs were called (sequence) | What those APIs were called on |
| Heuristics | API parameters and targets    | Learned/statistical patterns |

Target identity lives in API **parameters**, not API names. Parameters are not in MalBehavD-V1. This is the structural gap heuristics fill.

---

#### Handle Tracking

Most inter-process relationships are mediated through handles. A process cannot inject into, spawn, or manipulate another process without first acquiring a handle via `OpenProcess`. Heuristics track the handle chain across calls:

```
OpenProcess(PID=1234)         → handle acquired to ProcessB
VirtualAllocEx(handle→PID1234) → memory allocated in ProcessB
WriteProcessMemory(handle→PID1234) → payload written to ProcessB
CreateRemoteThread(handle→PID1234) → thread spawned in ProcessB
```

The heuristic follows this handle across all four calls and binds the entire sequence to both endpoints — creating a `MemoryInjection` edge from ProcessA to ProcessB.

---

#### API Combinations That Define Each Edge Type

**MemoryInjection**
- API pattern: `OpenProcess` → `VirtualAllocEx` → `WriteProcessMemory` → thread hijack API
- Target: the process referenced by the shared handle
- Suspicion amplifiers: `PAGE_EXECUTE_READWRITE` flag in `VirtualAllocEx`, `CreateRemoteThread` vs quieter hijack techniques

**ParentChild**
- API pattern: `CreateProcess` / `NtCreateProcess` / `ShellExecute` / WMI process creation
- Target: child PID returned in the process information structure
- Suspicion amplifiers: child spawned from a temp or unusual path, child name mismatches parent context

**ProcessOpenedFile**
- API pattern: `CreateFile` / `NtCreateFile`
- Target: path parameter — resolved to a file entity in the graph
- Suspicion amplifiers: file opened with write + execute access, file in a temp or user-writable location

**NetworkOwner**
- API pattern: `connect` / `WSAConnect` / `WSASend`
- Target: destination IP and port from the address parameter
- Suspicion amplifiers: destination on threat intelligence blocklist, non-standard port, connection immediately after injection

**SharedC2**
- Not detectable per-process. Constructed at graph level by comparing `NetworkOwner` edges across all processes and finding shared destination IPs.
- Created during graph assembly, not during per-process analysis.

---

## 5. Aggregation Layer

Sits on top of all three stages. Takes as input:

- `entity_ML_score` — Stage 1 binary/probability classifier output
- `lstm_behavioral_score` — Stage 2 LSTM confidence + behavioral class encoding
- `heuristic_edge_score` — Stage 3 rule-based suspicion score for this specific action
- `edge_type` — identified by Stage 3 heuristics, used to look up the multiplier

Produces:

```
ML_score      = weighted_combine(entity_ML_score, lstm_behavioral_score)
edge_value    = edge_type_multiplier × (heuristic_score × 0.4 + ML_score × 0.6)
```

The aggregation layer is lightweight — it is not re-learning. It is fusing signals from three systems that each answer a different question.

---

## 6. Division of Responsibility (Summary)

| Question                                           | Answered By               |
|----------------------------------------------------|---------------------------|
| Is this process malicious?                         | Stage 1 — Entity ML       |
| What class of malicious behavior is it exhibiting? | Stage 2 — LSTM            |
| Which specific action was taken?                   | Stage 3 — Heuristics      |
| Who was the target of that action?                 | Stage 3 — Heuristics (API parameters) |
| What edge type exists between which two nodes?     | Stage 3 — Heuristics      |
| How dangerous is this class of action inherently?  | Edge type multiplier       |
| What is the final edge threat score?               | Aggregation layer          |

---

## 7. Data Flow

```
Process Execution
      │
      ▼
API Call Trace Captured
      │
      ├──────────────────────────────────────┐
      │                                      │
      ▼                                      ▼
Stage 1: Entity ML Classifier         Stage 2: LSTM Encoder
(process features → malicious score)  (API sequence → behavioral score + class)
      │                                      │
      └──────────────┬───────────────────────┘
                     │
                     ▼
              ML_score (fused)
                     │
      ┌──────────────┴──────────────────────┐
      │                                     │
      ▼                                     ▼
Stage 3: Heuristics                  Heuristics output:
- API parameter extraction           - edge type identified
- Handle tracking                    - target node identified
- Known-bad pattern matching         - heuristic_edge_score
      │                                     │
      └──────────────┬───────────────────────┘
                     │
                     ▼
           Aggregation Layer
   edge_weight = multiplier × (heuristics×0.4 + ML×0.6)
                     │
                     ▼
            Edge Created in Threat Graph
         (typed, weighted, both endpoints defined)
```

---

## 8. What Each Stage Cannot Do Alone

| Stage              | Cannot Do                                                      |
|--------------------|----------------------------------------------------------------|
| Entity ML          | See relationships, targets, or inter-process interactions      |
| LSTM               | Identify the target of an action (parameters not in dataset)   |
| Heuristics         | Detect novel patterns not covered by existing rules            |
| Any single stage   | Produce a complete, typed, weighted edge on its own            |

All three are necessary. None is sufficient alone.

---

## 9. Future Extension

When labeled inter-process event data becomes available (e.g., ETW traces, Sysmon logs with cross-process correlation), a dedicated **edge-level ML model** can be introduced as a fourth stage. This model would:

- Take features describing the relationship itself (timing, frequency, sequence of inter-process events)
- Output a true edge-level anomaly score independent of node scores
- Reduce dependency on heuristics for edge type definition over time

Until that data exists, heuristics cover the relational gap that LSTM and entity ML cannot reach.

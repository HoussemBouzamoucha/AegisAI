# Agent Workflow

## Where the agent sits in the pipeline

The graph is the **detection layer**. The agent is the **reasoning layer**.
They are sequential: the graph must finish before the agent starts, but the
agent can loop back and trigger new scans, which rebuild the graph, which the
agent re-analyzes.

```
Scanners ──► EntityManager ──► AggregatedEntities ──► ThreatGraph
                                                            │
                                                    AttackChains[]
                                                    CriticalPath
                                                    GraphNodes + Edges
                                                            │
                                                            ▼
                                              ┌─────────────────────────┐
                                              │        AI Agent          │
                                              │                          │
                                              │  in:  structured verdict │
                                              │  out: explanation        │
                                              │       confidence         │
                                              │       pivot suggestions  │
                                              └────────────┬────────────┘
                                                           │
                                          pivot needed?    │
                                               ┌───────────▼───────────┐
                                               │  targeted scan runs   │
                                               │  (scan-file,          │
                                               │   scan-memory,        │
                                               │   correlate, …)       │
                                               └───────────┬───────────┘
                                                           │
                                               new entities ingested
                                               graph rebuilds
                                               agent re-analyzes
                                                           │
                                                    repeat until
                                                    investigation closes
```

---

## Why the agent cannot run before the graph

The agent would be reasoning over raw scanner output: hundreds of processes,
thousands of network connections, memory regions. That is noise.

The graph's job is to collapse that noise into a small number of structured,
MITRE-mapped, scored findings. By the time the agent sees the output it is not
looking at 300 processes — it is looking at 3 attack chains with entity IDs,
scores, and tactics. That is a tractable reasoning problem.

---

## What the agent receives

The graph already produces exactly what a reasoning model needs:

```json
{
  "attack_chains": [
    {
      "pattern": "C2Communication",
      "mitre_tactic": "T1071 - Application Layer Protocol",
      "chain_score": 0.91,
      "severity": "Malicious",
      "node_ids": ["entity:4821"],
      "description": "'chrome': active connection to a suspicious remote host"
    },
    {
      "pattern": "SuspiciousSpawn",
      "mitre_tactic": "T1059 - Command and Scripting Interpreter",
      "chain_score": 0.74,
      "severity": "Malicious",
      "node_ids": ["entity:4821", "entity:6032"],
      "description": "'chrome' spawned 'cmd' — both flagged as threats"
    }
  ],
  "critical_path": {
    "node_ids": ["entity:4821", "entity:6032"],
    "edge_types": ["parent_child"],
    "edge_weights": [0.82],
    "total_score": 0.82,
    "narrative": "chrome connected to 185.x.x.x:8080 and spawned cmd"
  },
  "graph": {
    "nodes": [ ... ],
    "edges": [ ... ]
  }
}
```

The narrative, MITRE tactics, entity scores, and inter-entity edges are handed
directly to the agent prompt. The agent does not re-derive any of this.

---

## The hunt loop — round by round

### Round 1 — initial graph verdict

```
Graph output:
  C2Communication  on entity:4821 (chrome, score 0.91)
  SuspiciousSpawn  entity:4821 → entity:6032 (cmd, score 0.74)
  CriticalPath:    chrome → cmd  (edge weight 0.82)

Agent reasoning:
  "Browser spawned cmd after C2 contact.
   Consistent with drive-by exploit → dropper execution (T1071 + T1059).
   Confidence: high — two corroborating patterns, both domains flagged.

  Next pivots:
   1. Scan %TEMP% and %APPDATA% for binaries written after chrome started.
   2. Check if cmd wrote any child processes (re-correlate with include_memory).
   3. Look for persistence: scheduled tasks, registry run keys."
```

### Round 2 — targeted file scan on pivot paths

```
New scan: scan-dir %TEMP%

New entity ingested:
  entity-file:file:{sha256}  payload.exe  Malicious (score 0.95)
  SharedFileHash edge → entity:6032

Graph output (updated):
  MalwareExecution on entity:6032 — malicious file matches cmd's path
  CriticalPath now: chrome → cmd → payload.exe  (total score 1.23)

Agent reasoning:
  "Dropper confirmed. Payload binary identified.
   Hash lookup: matches known trojan family (if IOC feed wired).

  Next pivots:
   1. Re-correlate with include_memory=true — cmd may have injected.
   2. Check process tree for children of entity:6032.
   3. Check autorun locations for persistence."
```

### Round 3 — full correlate with memory included

```
New scan: correlate (include_memory: true)

New entities:
  entity:8901  (schtasks, spawned by cmd, score 0.68)
  entity:9012  (reg, spawned by cmd, score 0.61)
  ProcessInjection on entity:6032 — malicious memory region detected

Graph output (updated):
  SuspiciousSpawn: cmd → schtasks, cmd → reg
  ProcessInjection on cmd
  MultiStageAttack: chrome → cmd → schtasks (3 nodes, TA0002)

Agent reasoning:
  "Persistence confirmed via scheduled task and registry modification.
   Process injection into cmd confirms in-memory execution.
   Investigation complete — full kill chain mapped.

  Recommended actions:
   1. Terminate PIDs 4821, 6032, 8901, 9012.
   2. Quarantine %TEMP%\payload.exe.
   3. Review scheduled tasks and HKCU\Software\Microsoft\Windows\CurrentVersion\Run.
   4. Isolate host from network pending forensic review."
```

---

## Key design properties of the loop

**The agent never runs a full scan unprompted.**
Each pivot is specific: a path, a PID, a flag (`include_memory`). This keeps
each round fast and the total investigation bounded.

**The graph rebuilds from scratch each round.**
All four scanners re-run (or a subset). The EntityManager starts fresh. This
ensures the graph reflects current system state, not a stale snapshot.

**The agent closes the loop or escalates.**
If after N rounds no new evidence surfaces, the agent closes the investigation
with a confidence statement. If evidence is severe enough (critical_path score
above threshold, confirmed IOC match), it escalates to an alert.

---

## Prerequisites before the loop works

The following must be in place before the reasoning loop is implementable:

| Prerequisite | Why it is needed |
|---|---|
| Agent can invoke daemon commands | The loop requires the agent to emit `scan-file`, `scan-memory`, `correlate` JSON-RPC calls and receive their responses |
| Persistence layer (SQLite) | Without history, the agent cannot ask "when did this entity first appear?" or "has its score changed?" |
| Continuous monitoring mode | Rounds 2 and 3 need the daemon running — not a one-shot CLI call |
| IOC feed integration | Hash and IP lookups give the agent external confirmation of findings |
| Behavioral baseline | Required before the agent can say "this is anomalous for this process" |

---

## What the agent does NOT do

- **Re-run heuristics or ML models** — those belong to the scanners and graph
- **Replace the graph** — the graph is still the detection source of truth
- **Run a full system scan on every round** — only targeted, agent-directed scans
- **Make blocking decisions autonomously** — it produces recommendations;
  termination and quarantine require user confirmation (or an explicit
  autonomous mode the user opts into)

---

## Action prioritization — from 20+ options to a ranked plan

### The problem

The graph pipeline produces rich context: attack patterns (MITRE-mapped), scores,
LOLBin flags, entity relationships. The 20+ possible containment actions are a
**menu**, not a plan. The agent's job is to pick 3–5 ordered, justified actions
from that menu.

### How the agent reasons

The agent receives one structured input — the `correlate` result — and outputs a
ranked action plan. The reasoning has three layers:

**1. Severity gating** — actions have minimum score thresholds. Network isolation
should never fire below 0.85. Killing a process might fire at 0.65.

**2. Pattern → action mapping** — each attack chain pattern has a natural response set:

| Pattern | Primary actions | Skip unless critical |
|---------|----------------|---------------------|
| `ProcessInjection` | `dump_memory`, `kill_process` | `isolate_network` |
| `C2Communication` | `block_ip`, `check_persistence` | `isolate_network` |
| `MalwareExecution` | `quarantine_file`, `kill_process` | `dump_memory` |
| `LateralMovement` | `isolate_network`, `check_persistence` | — |
| `MultiStageAttack` | all, sequenced | — |

**3. Risk ranking** — actions ordered by reversibility. Reversible actions
(`block_ip`) before destructive ones (`kill_process`), which always come before
disruptive ones (`isolate_network`).

### Architecture

```
GraphVerdict (attack chains + scores)
  → AI Agent (Claude API call with structured prompt)
      input: { chains[], critical_path, top entities, scores }
      output: { ranked_actions[], rationale, risk_level }
  → UI shows: "3 recommended actions" + collapsible "19 others considered"
```

The agent prompt is structured like a security analyst briefing — concise context,
then the reasoning question. The model returns JSON with the top actions, sequence,
and a one-line justification for each.

### Example UI output

Instead of showing 20 checkboxes, the UI surfaces:

```
AI recommends (confidence 91%):
  1. quarantine_file  — chrome_update.exe (hash match, score 0.94)
  2. block_ip         — 185.220.101.x outbound (C2 pattern confirmed)
  3. check_persistence — suspicious_paths from chain

  [See 17 other considered actions ▼]
```

### What the agent does NOT do in this context

- It does not fire actions automatically unless `autonomousMode` is enabled
- It does not override the score thresholds — those are hard gates, not suggestions
- It does not recommend irreversible actions without a `confirm: true` in the
  response that forces a UI confirmation prompt before execution

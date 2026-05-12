# AegisAI Agent — Rounds Reference

This document describes what each reasoning round does, what it produces,
and whether a further round is needed.

---

## Round 1 — Initial verdict  *(implemented)*

### What triggers it

The user clicks **"Analyse with AI"** after running `correlate_entities`.
Tauri invokes `run_agent_analysis(correlate_result)`.

### What it receives

The full `correlate` output from the Rust daemon:

```json
{
  "graph": {
    "attack_chains": [ ... ],
    "critical_path": { ... },
    "nodes":         [ ... ],
    "edges":         [ ... ]
  },
  "statistics": { ... }
}
```

### What it does (two sub-layers)

```
correlate_result
  │
  ▼ analyst.py::analyze()
  build_prompt_context()         ← extract chains / critical path / malicious entities
  PROMPT (ChatPromptTemplate)    ← format compact system + human message
  LLM (OpenRouter)               ← temperature=0, JSON mode
  _parse_verdict()               ← strip fences, Pydantic validate
  │
  ▼ reasoning.py::refine()       ← micro-loop (Level 1)
  validate()                     ← 8 deterministic rules, no LLM
    R1  score thresholds per action type
    R2  reversibility ordering (block_ip < quarantine < dump < kill < isolate)
    R3  confirm_required integrity (kill_process / isolate_network only)
    R4  coverage — every Malicious/Critical entity has at least one action
    R5  hallucination guard — entity_ids exist in the graph
    R6  LOLBin + vector → check_persistence must be present
    R7  risk_level cannot understate highest chain severity
    R8  1–5 actions when chains are present
  if violations: _correct() → corrected verdict → validate() again
  repeat until: 0 violations | converged | 3 iterations reached
  returns best verdict (fewest violations)
```

### What it produces — `AgentVerdict`

| Field | Type | Example |
|---|---|---|
| `ranked_actions` | list, 3–5 items | `[{action:"block_ip", target:"185.x.x.x", …}]` |
| `rationale` | string | `"powershell.exe is beaconing to a known C2 IP…"` |
| `risk_level` | `Low\|Medium\|High\|Critical` | `"Critical"` |
| `confidence` | float 0–1 | `0.91` |
| `pivot_suggestions` | list, 0–3 items | `["Scan TEMP for dropped payloads"]` |
| `warnings` | list (empty on clean exit) | `["R3: …"]` if micro-loop hit cap |
| `investigation_closed` | bool | `false` (always on Round 1) |
| `close_reason` | string\|null | `null` |
| `round_num` | int | `1` |

### Is another round needed?

Yes — when the user executes one of the recommended actions.
Executing an action changes system state; the graph from Round 1 is now stale.
Round 2 is how the agent sees the updated state and adapts.

---

## Round 2+ — Re-assessment after action  *(implemented)*

### What triggers it

After the user executes an action (quarantine file, block IP, kill process, …)
the UI:
1. Calls the Rust executor (quarantine, block_ip, etc.)
2. Calls `correlate_entities` again to get the post-action graph
3. Calls `run_agent_reassessment(correlate_result, actions_taken, round, previous_threat_score)`

`previous_threat_score` = sum of `combined_score` for all Malicious/Critical entities
from the *previous* verdict's graph. The UI must compute and track this across calls.

### What it receives — the envelope

```json
{
  "correlate_result":      { ... },     // fresh re-correlate (post-action state)
  "actions_taken":         [            // every action executed so far
    {
      "action":      "block_ip",
      "target":      "185.220.101.47",
      "entity_id":   "entity:7891",
      "executed_at": "2026-05-12T14:30:22Z",
      "result":      "success",
      "pid":         null
    }
  ],
  "round":                 2,
  "previous_threat_score": 0.91
}
```

### Three guards — checked before any LLM call

| Guard | Condition | Result |
|---|---|---|
| **Resolved** | No Malicious/Critical entities in the new graph | `investigation_closed=true`, `close_reason="resolved"` |
| **No improvement** | Threat score did not decrease (score ≥ previous) | `investigation_closed=true`, `close_reason="no_improvement"` |
| **Max rounds** | `round_num ≥ 5` | `investigation_closed=true`, `close_reason="max_rounds_reached"` |

Guards are checked in order: Resolved → No improvement → Max rounds.
If any fires, the function returns immediately — no LLM call, no API cost.

### What it does when no guard fires

```
correlate_result + actions_taken
  │
  ▼ analyst.py::reassess()
  build_reassess_context()       ← same graph extraction + actions_taken block
  REASSESS_PROMPT                ← system: "do not repeat completed actions"
                                    human:  "ACTIONS TAKEN: … / CURRENT STATE: …"
  LLM (OpenRouter)
  _parse_verdict()
  │
  ▼ reasoning.py::refine_reassess() continuation
  validate()                     ← same 8 rules
  if violations: _correct() → repeat (capped at MAX_ITERATIONS = 3)
  returns best verdict
```

### What it produces

Same `AgentVerdict` schema as Round 1 with:
- `round_num` = 2, 3, … (stamped by the Python layer, not the model)
- `investigation_closed` = true when any guard fires
- `ranked_actions` = `[]` when closed
- Model will not re-recommend already-executed actions (enforced via prompt)

### Loop break conditions (all in Python, no UI logic needed)

| Condition | `investigation_closed` | `close_reason` |
|---|---|---|
| No threats remain in graph | `true` | `"resolved"` |
| Score unchanged after action | `true` | `"no_improvement"` |
| Round ≥ 5 | `true` | `"max_rounds_reached"` |
| Analyst closes manually (UI) | n/a — UI-side decision | — |

When `investigation_closed = true`, the UI should:
- Stop calling `run_agent_reassessment`
- Surface the `close_reason` to the user
- Offer to export the incident report (`export_incident_report`)

---

## Round 3 — Is it needed?

**Not as a separate code layer.** Round 2 is a loop — the same
`run_agent_reassessment` call handles rounds 2, 3, 4, … with an incrementing
`round` counter.  Each call:

1. Receives the graph state *after the most recent action*
2. Receives the full `actions_taken` history
3. Checks all three guards
4. If still open: re-prompts the LLM with the updated context

So "Round 3" is just `run_agent_reassessment(..., round=3, ...)`.
The Python code handles all rounds identically; only the `round_num` stamp
and the accumulated `actions_taken` list differ.

What would require a separate third layer is **Level 3 — the learning loop**
(cross-session memory). That is out of scope for this implementation.

---

## Level 3 — Cross-session learning  *(not yet implemented)*

After the investigation closes, store the tuple:

```
(correlate_input, final_verdict, actions_taken, outcome)
```

where `outcome` ∈ `{resolved, overridden, false_positive}` based on analyst
feedback.  High-quality past verdicts (analyst accepted, no override) become
few-shot examples injected into future Round 1 system prompts.  This lets
the model improve on this specific environment without retraining.

**Why not yet**: requires a local SQLite store, a feedback signal from the
analyst (was the verdict accepted or overridden?), and a few-shot injection
mechanism in `prompt.py`.  The data schema is designed (see `data-persistence.md`)
but the write/read paths are not wired.

---

## Call sequence summary

```
User: "Analyse"
  → invoke('run_agent_analysis', {correlate_result})
      Python: refine(correlate_result) → AgentVerdict {round_num:1}
  UI shows: 3–5 ranked actions

User: executes action[0] (e.g. block_ip)
  → invoke('block_ip', {remote_ip, direction})        // execute
  → invoke('correlate_entities', {includeMemory})     // re-scan
  → invoke('run_agent_reassessment', {               // re-assess
        correlate_result: <new graph>,
        actions_taken:    [{action:"block_ip", …}],
        round:            2,
        previous_threat_score: <sum from round 1>
    })
      Python: refine_reassess(…) → AgentVerdict {round_num:2}
  UI shows: updated action list or investigation_closed message

repeat until investigation_closed = true
  → invoke('export_incident_report', {…})
```

---

## New Tauri commands added in this round

| Command | Arguments | Purpose |
|---|---|---|
| `run_agent_analysis` | `correlate_result` | Round 1 — existing |
| `run_agent_reassessment` | `correlate_result`, `actions_taken`, `round`, `previous_threat_score` | Round 2+ — new |

## New Python functions

| File | Function | Purpose |
|---|---|---|
| `schema.py` | `ExecutedAction` | Records one user-executed action |
| `schema.py` | `AgentVerdict` fields | `investigation_closed`, `close_reason`, `round_num` |
| `prompt.py` | `REASSESS_PROMPT` | Re-assessment prompt template |
| `prompt.py` | `build_reassess_context()` | Graph extraction + actions_taken block |
| `analyst.py` | `reassess()` | LLM call using REASSESS_PROMPT |
| `analyst.py` | `build_reassess_chain()` | REASSESS_PROMPT \| LLM |
| `reasoning.py` | `_compute_threat_score()` | Monotonicity check helper |
| `reasoning.py` | `refine_reassess()` | Guards + LLM + micro-loop |
| `main.py` | dual-format routing | Round 1 vs Round 2+ protocol detection |

# Agent Round 1 — Wiring the AI to the Graph Output

## What this document covers

This document is the complete design and implementation spec for **Round 1** of
the AI agent loop: taking the `correlate` result that the engine already
produces and turning it into a ranked, justified action plan via a single
Claude API call.

No persistence layer, no continuous monitoring, no multi-round loops. Just:

```
correlate result  →  structured prompt  →  Claude API  →  ranked actions  →  UI
```

Everything needed to make this work already exists. The graph produces exactly
the right signal. The Tauri IPC layer already wires the frontend to the daemon.
The only missing piece is the Claude API call and the UI component that shows its
output.

---

## Why Round 1 works without persistence

The `correlate` command returns a self-contained snapshot:

- `attack_chains[]` — MITRE-mapped patterns, scores, confidence, descriptions
- `critical_path` — the highest-weight chain across all entities, with a
  plain-English narrative already written by the engine
- `graph.nodes[]` — every entity with combined/per-domain scores, threat flags,
  `is_vector`, `is_lolbin`
- `graph.edges[]` — typed, weighted relationships between entities

This is not raw scanner output. The graph has already collapsed hundreds of
processes, thousands of connections, and memory regions into 3–5 structured
attack chains. The agent receives a tractable reasoning problem, not noise.

The only thing persistence would add is cross-session history
("was this entity's score different 24h ago?"). That question is not asked in
Round 1. Round 1 only asks: **given what the graph says right now, what are the
3–5 most important actions to take?**

---

## Architecture: where Round 1 sits

```
Tauri UI
  invoke('correlate_entities', { includeMemory })
        │
        ▼
  UI/src-tauri/src/main.rs  →  daemon stdin JSON-RPC
        │
        ▼  (existing, unchanged)
  Antivirus_Engine daemon
    ProcessScanner + NetworkScanner + MemoryScanner + FileSystemScanner
    EntityManager  →  AggregatedEntities
    GraphBuilder   →  ThreatGraph
    GraphAnalyzer  →  AttackChains + CriticalPath + LOLBin flags
        │
        ▼  correlate result JSON (already returned to UI today)
  ════════════════════════════════════════════════════  ← NEW BOUNDARY
        │
        ▼  (NEW — added in this document)
  invoke('run_agent_analysis', { correlateResult })
        │
  UI/src-tauri/src/main.rs  →  agent.rs
        │
  build_analyst_prompt(correlate_result)
        │
  Claude API  claude-sonnet-4-6
        │
  parse_agent_response(raw_json)
        │
        ▼
  AgentVerdict {
    ranked_actions[],
    rationale,
    risk_level,
    confidence,
    pivot_suggestions[],
  }
        │
        ▼
  Zustand store  →  React  GraphVerdict component
```

The `correlate_entities` Tauri command is **not changed**. The agent runs as a
second, independent Tauri command that receives the correlate result as its
input. This keeps the two concerns cleanly separated: the detection pipeline
never touches the AI layer.

---

## The correlate result — exact JSON shape

This is what the engine already returns (defined in `main.rs:1060`). The agent
receives this verbatim. Understanding its structure is essential before writing
the prompt.

```json
{
  "id": "uuid",
  "success": true,

  "graph": {
    "attack_chains": [
      {
        "chain_id":    "uuid",
        "pattern":     "C2Communication",
        "mitre_tactic":"T1071 - Application Layer Protocol",
        "chain_score": 0.91,
        "confidence":  0.87,
        "severity":    "Malicious",
        "description": "'chrome.exe': active connection to a suspicious remote host",
        "node_ids":    ["entity:4821"]
      },
      {
        "chain_id":    "uuid",
        "pattern":     "SuspiciousSpawn",
        "mitre_tactic":"T1059 - Command and Scripting Interpreter",
        "chain_score": 0.74,
        "confidence":  0.71,
        "severity":    "Malicious",
        "description": "'chrome.exe' spawned 'cmd.exe' — both flagged as threats",
        "node_ids":    ["entity:4821", "entity:6032"]
      }
    ],
    "critical_path": {
      "node_ids":     ["entity:4821", "entity:6032"],
      "edge_types":   ["parent_child"],
      "edge_weights": [0.82],
      "total_score":  0.82,
      "narrative":    "chrome.exe connected to 185.x.x.x:8080 and spawned cmd.exe"
    },
    "nodes": [
      {
        "entity_id":             "entity:4821",
        "entity_type":           "entity",
        "label":                 "chrome.exe",
        "threat_level":          "Malicious",
        "combined_score":        0.91,
        "heuristic_score":       28,
        "ml_score":              0.89,
        "process_score":         0.45,
        "network_score":         0.91,
        "memory_score":          0.12,
        "file_score":            0.05,
        "has_malicious_network": true,
        "has_malicious_memory":  false,
        "has_malicious_file":    false,
        "pid":                   4821,
        "parent_pid":            1234,
        "graph_boost":           0.09,
        "is_vector":             false,
        "is_lolbin":             false
      }
    ],
    "edges": [
      {
        "from":      "entity:4821",
        "to":        "entity:6032",
        "edge_type": "parent_child",
        "weight":    0.82
      }
    ]
  },

  "statistics": {
    "total_entities":          47,
    "threat_entities":          3,
    "attack_chains_detected":   2,
    "scan_duration_ms":      4821
  }
}
```

Key observations:
- `attack_chains` are already sorted by `chain_score` descending (highest threat first).
- `critical_path.narrative` is a complete English sentence — paste it directly into the prompt.
- `graph_boost` and `is_lolbin` are post-feedback fields set by `GraphAnalyzer::apply_graph_feedback`.
  A non-zero `graph_boost` means the analyzer already identified this node as
  high-centrality or on the critical path. `is_lolbin` = true means the attack
  was delivered via a known living-off-the-land binary.
- Per-domain sub-scores (`process_score`, `network_score`, `memory_score`,
  `file_score`) tell the agent *which scanner* flagged the entity and *how
  strongly*, without requiring it to re-run any analysis.

---

## Prompt design — what the agent receives

The prompt is structured as a **security analyst briefing**. It has four
sections:

1. **System role** — sets the agent's identity and output contract.
2. **Graph context** — the structured threat picture (attack chains + critical path + top entities).
3. **Action menu** — the full list of available containment actions with their score thresholds.
4. **Reasoning instruction** — explicit rules for ranking and a required JSON output schema.

### 1. System role

```
You are AegisAI's threat analysis engine. You receive structured graph output
from a multi-layer Windows security scanner and produce a prioritised, justified
action plan for a human analyst.

Your output MUST be valid JSON matching the schema at the end of this prompt.
Do not explain your reasoning in prose — put it in the "rationale" field.
Do not add fields not in the schema. Do not omit required fields.
```

Why this wording:
- "structured graph output" frames the task correctly — the model is not being
  asked to detect threats from raw data, which it cannot do reliably. It is
  being asked to reason over pre-classified, pre-structured findings.
- "for a human analyst" ensures the model never produces actions that execute
  automatically. Its role is advisory.
- Strict JSON schema enforcement is critical: the Tauri backend parses the
  response directly. A prose response breaks the pipeline.

### 2. Graph context (built from correlate result)

```
## Threat Graph Summary

Attack chains detected: {chains.len()}
Highest severity: {max_severity}
Critical path score: {critical_path.total_score:.2}
Critical path narrative: {critical_path.narrative}

## Attack Chains (sorted by confidence descending)

{for each chain:}
  [{i}] {chain.pattern} — {chain.mitre_tactic}
       Score: {chain.chain_score:.2}  Confidence: {chain.confidence:.2}  Severity: {chain.severity}
       Description: {chain.description}
       Entities involved: {chain.node_ids joined by " → "}

## Top Threat Entities

{for each node where threat_level != "Clean" and threat_level != "Suspicious" (only Malicious/Critical):}
  Entity:  {node.label}  (PID {node.pid})
  Scores:  combined={node.combined_score:.2}  proc={node.process_score:.2}  net={node.network_score:.2}  mem={node.memory_score:.2}  file={node.file_score:.2}
  Flags:   {flags: join non-false flags from has_malicious_network, has_malicious_memory, has_malicious_file, is_vector, is_lolbin}
  Boost:   {node.graph_boost:.2} (centrality/path amplification added by graph feedback)
```

This section is deliberately **compact**. We do not dump the full node list.
Only malicious/critical entities are included. The model should not be asked
to filter noise — that is the graph's job.

### 3. Action menu

```
## Available Actions

Each action has a minimum combined_score threshold. Never recommend an action
for an entity whose combined_score is below its threshold.

| Action             | Min Score | Reversible | Notes                                      |
|--------------------|-----------|------------|--------------------------------------------|
| kill_process       | 0.65      | No         | Terminates the process immediately         |
| quarantine_file    | 0.70      | Yes        | Moves file to quarantine; restorable       |
| block_ip           | 0.60      | Yes        | Adds outbound firewall deny rule           |
| dump_memory        | 0.75      | Yes        | Writes minidump; process continues         |
| check_persistence  | 0.50      | Yes (read) | Scans registry + scheduled tasks; no write |
| isolate_network    | 0.85      | Yes        | Disables all network adapters; disruptive  |
| remove_block_ip    | n/a       | Yes        | Rollback only — only recommend if a prior  |
|                    |           |            | block_ip was taken this session            |

Pattern → primary action mapping (use as a starting point, not a hard rule):

  ProcessInjection   → dump_memory, kill_process
  C2Communication    → block_ip, check_persistence
  MalwareExecution   → quarantine_file, kill_process
  LateralMovement    → isolate_network, check_persistence
  SuspiciousSpawn    → kill_process (child first), check_persistence
  MultiStageAttack   → all actions, sequenced by reversibility
  ExploitedTrustedProcess → kill_process (child), check_persistence

Ordering rule: always sequence reversible actions before irreversible ones.
  block_ip < quarantine_file < dump_memory < kill_process < isolate_network
```

The thresholds and ordering rules are hard constraints, not style preferences.
They are the same rules described in `agent-workflow.md`. Embedding them
directly in the prompt removes the need for post-processing validation logic —
the model enforces them during generation.

### 4. Output schema

```
## Required Output

Return exactly this JSON structure. No markdown, no explanation outside JSON.

{
  "ranked_actions": [
    {
      "action":      "<action name from the table above>",
      "target":      "<entity label or IP or path — the specific target>",
      "entity_id":   "<entity_id from the graph>",
      "pid":         <integer or null>,
      "justification": "<one sentence: which chain/pattern drove this recommendation>",
      "reversible":  <true|false>,
      "min_score_met": <true|false>,
      "confirm_required": <true|false>   // true for kill_process and isolate_network
    }
  ],
  "rationale": "<2–4 sentences: overall threat assessment, why these actions in this order>",
  "risk_level": "<Low|Medium|High|Critical>",
  "confidence": <0.0–1.0, derived from the highest-confidence attack chain>,
  "pivot_suggestions": [
    "<one-sentence suggestion for a targeted follow-up scan if evidence is incomplete>"
  ]
}

Rules:
- ranked_actions: 3–5 items, ordered from most reversible to least reversible.
- If no chains were detected (empty attack_chains array), return ranked_actions: []
  and risk_level: "Low".
- pivot_suggestions: 0–3 items. Only include if the chains leave unanswered
  questions. Examples: "scan %TEMP% for binaries written in the last 10 minutes",
  "re-run correlate with include_memory=true to check for injection into cmd.exe".
- confirm_required: must be true for kill_process and isolate_network. The UI
  will block execution of these actions until the analyst explicitly confirms.
```

---

## Implementation

### New files

```
UI/src-tauri/src/agent.rs          ← Rust: prompt builder + Claude API call + response parser
UI/src/components/AgentVerdict.tsx ← React: renders ranked_actions + rationale + pivots
```

### Modified files

```
UI/src-tauri/src/main.rs           ← register run_agent_analysis Tauri command + add agent.rs mod
UI/src-tauri/Cargo.toml            ← add reqwest dependency (if not already present)
UI/src/store/index.ts              ← add agentVerdict state + runAgentAnalysis() action
UI/src/types/index.ts              ← add AgentVerdict + RankedAction TypeScript types
UI/src/components/ThreatGraph.tsx  ← add "Analyze with AI" button + embed AgentVerdict panel
```

---

### `UI/src-tauri/Cargo.toml` — dependency

```toml
[dependencies]
# existing ...
reqwest = { version = "0.12", features = ["json", "rustls-tls"], default-features = false }
```

`rustls-tls` is required on Windows because OpenSSL is not bundled. The
`default-features = false` strips the native-tls dependency that would fail
to link.

---

### `UI/src-tauri/src/agent.rs` — full implementation

```rust
//! Agent Round 1 — single-shot analyst reasoning over a correlate result.
//!
//! Entry point: `run_analysis(correlate_result) -> AgentVerdict`
//!
//! This module:
//!   1. Extracts the threat-relevant slice from the correlate result JSON.
//!   2. Builds a structured security-analyst briefing prompt.
//!   3. Calls the Claude API (claude-sonnet-4-6) with that prompt.
//!   4. Parses and validates the response into an `AgentVerdict`.
//!
//! The Claude API key is read from the ANTHROPIC_API_KEY environment variable
//! at call time.  It is never stored in AppState or written to disk.

use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;

// ─── Output types ─────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RankedAction {
    pub action:           String,
    pub target:           String,
    pub entity_id:        String,
    pub pid:              Option<u32>,
    pub justification:    String,
    pub reversible:       bool,
    pub min_score_met:    bool,
    pub confirm_required: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AgentVerdict {
    pub ranked_actions:    Vec<RankedAction>,
    pub rationale:         String,
    pub risk_level:        String,
    pub confidence:        f32,
    pub pivot_suggestions: Vec<String>,
}

// ─── Prompt builder ───────────────────────────────────────────────────────────

/// Build the analyst briefing prompt from a correlate result.
///
/// The prompt has four sections (see agent-round1.md for the design rationale):
///   1. System role
///   2. Graph context  (chains + critical path + top malicious entities)
///   3. Action menu    (available actions, thresholds, pattern→action mapping)
///   4. Output schema  (strict JSON contract)
pub fn build_analyst_prompt(result: &Value) -> String {
    let empty_vec = vec![];
    let chains = result["graph"]["attack_chains"]
        .as_array()
        .unwrap_or(&empty_vec);

    let nodes_arr = result["graph"]["nodes"]
        .as_array()
        .unwrap_or(&empty_vec);

    let critical_path = &result["graph"]["critical_path"];

    // ── Section 2a: summary line ──────────────────────────────────────────────
    let max_severity = chains
        .iter()
        .map(|c| c["severity"].as_str().unwrap_or("Unknown"))
        .max_by_key(|s| match *s {
            "Critical"   => 3,
            "Malicious"  => 2,
            "Suspicious" => 1,
            _            => 0,
        })
        .unwrap_or("None");

    let cp_score = critical_path["total_score"]
        .as_f64()
        .unwrap_or(0.0);
    let cp_narrative = critical_path["narrative"]
        .as_str()
        .unwrap_or("No critical path found.");

    // ── Section 2b: attack chains ─────────────────────────────────────────────
    let mut chains_text = String::new();
    // Sort by confidence descending for the prompt
    let mut sorted_chains: Vec<&Value> = chains.iter().collect();
    sorted_chains.sort_by(|a, b| {
        let ca = a["confidence"].as_f64().unwrap_or(0.0);
        let cb = b["confidence"].as_f64().unwrap_or(0.0);
        cb.partial_cmp(&ca).unwrap_or(std::cmp::Ordering::Equal)
    });

    for (i, chain) in sorted_chains.iter().enumerate() {
        let node_ids = chain["node_ids"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .collect::<Vec<_>>()
                    .join(" → ")
            })
            .unwrap_or_default();

        chains_text.push_str(&format!(
            "  [{}] {} — {}\n       Score: {:.2}  Confidence: {:.2}  Severity: {}\n       Description: {}\n       Entities: {}\n\n",
            i + 1,
            chain["pattern"].as_str().unwrap_or("Unknown"),
            chain["mitre_tactic"].as_str().unwrap_or(""),
            chain["chain_score"].as_f64().unwrap_or(0.0),
            chain["confidence"].as_f64().unwrap_or(0.0),
            chain["severity"].as_str().unwrap_or("Unknown"),
            chain["description"].as_str().unwrap_or(""),
            node_ids,
        ));
    }

    if chains_text.is_empty() {
        chains_text = "  No attack chains detected.\n".to_string();
    }

    // ── Section 2c: top malicious entities ───────────────────────────────────
    let mut entities_text = String::new();
    let threat_nodes: Vec<&Value> = nodes_arr
        .iter()
        .filter(|n| {
            matches!(
                n["threat_level"].as_str().unwrap_or(""),
                "Malicious" | "Critical"
            )
        })
        .collect();

    for node in &threat_nodes {
        let mut flags: Vec<&str> = Vec::new();
        if node["has_malicious_network"].as_bool().unwrap_or(false) { flags.push("malicious_network"); }
        if node["has_malicious_memory"].as_bool().unwrap_or(false)  { flags.push("malicious_memory"); }
        if node["has_malicious_file"].as_bool().unwrap_or(false)    { flags.push("malicious_file"); }
        if node["is_vector"].as_bool().unwrap_or(false)             { flags.push("is_vector"); }
        if node["is_lolbin"].as_bool().unwrap_or(false)             { flags.push("is_lolbin"); }

        let flags_str = if flags.is_empty() {
            "none".to_string()
        } else {
            flags.join(", ")
        };

        let pid_str = node["pid"]
            .as_u64()
            .map(|p| p.to_string())
            .unwrap_or_else(|| "n/a".to_string());

        entities_text.push_str(&format!(
            "  Entity:  {} (PID {})\n  ID:      {}\n  Scores:  combined={:.2}  proc={:.2}  net={:.2}  mem={:.2}  file={:.2}\n  Flags:   {}\n  Boost:   {:.2}\n\n",
            node["label"].as_str().unwrap_or("unknown"),
            pid_str,
            node["entity_id"].as_str().unwrap_or(""),
            node["combined_score"].as_f64().unwrap_or(0.0),
            node["process_score"].as_f64().unwrap_or(0.0),
            node["network_score"].as_f64().unwrap_or(0.0),
            node["memory_score"].as_f64().unwrap_or(0.0),
            node["file_score"].as_f64().unwrap_or(0.0),
            flags_str,
            node["graph_boost"].as_f64().unwrap_or(0.0),
        ));
    }

    if entities_text.is_empty() {
        entities_text = "  No malicious entities detected.\n".to_string();
    }

    // ── Assemble full prompt ──────────────────────────────────────────────────
    format!(
r#"You are AegisAI's threat analysis engine. You receive structured graph output
from a multi-layer Windows security scanner and produce a prioritised, justified
action plan for a human analyst.

Your output MUST be valid JSON matching the schema at the end of this prompt.
Do not explain your reasoning in prose outside the JSON. Do not add fields not
in the schema. Do not omit required fields.

────────────────────────────────────────────────────────────────────────────────
## Threat Graph Summary

Attack chains detected: {}
Highest severity: {}
Critical path score: {:.2}
Critical path narrative: {}

## Attack Chains (sorted by confidence descending)

{}
## Top Malicious Entities

{}
────────────────────────────────────────────────────────────────────────────────
## Available Actions

Each action has a minimum combined_score threshold. Never recommend an action
for an entity whose combined_score is below its threshold.

Action             | Min Score | Reversible | Notes
-------------------|-----------|------------|---------------------------------------
kill_process       | 0.65      | No         | Terminates the process immediately
quarantine_file    | 0.70      | Yes        | Moves file to quarantine; restorable
block_ip           | 0.60      | Yes        | Adds outbound firewall deny rule
dump_memory        | 0.75      | Yes        | Writes minidump; process continues
check_persistence  | 0.50      | Yes (read) | Scans registry + scheduled tasks
isolate_network    | 0.85      | Yes        | Disables ALL network adapters; disruptive

Pattern → primary action mapping:
  ProcessInjection        → dump_memory, kill_process
  C2Communication         → block_ip, check_persistence
  MalwareExecution        → quarantine_file, kill_process
  LateralMovement         → isolate_network, check_persistence
  SuspiciousSpawn         → kill_process (child first), check_persistence
  MultiStageAttack        → all actions, sequenced by reversibility
  ExploitedTrustedProcess → kill_process (child), check_persistence

Ordering rule: sequence reversible actions before irreversible ones:
  block_ip < quarantine_file < dump_memory < kill_process < isolate_network

────────────────────────────────────────────────────────────────────────────────
## Required Output

Return exactly this JSON. No markdown fences, no text before or after the JSON.

{{
  "ranked_actions": [
    {{
      "action":           "<action name from the table above>",
      "target":           "<entity label, IP, or file path — the specific target>",
      "entity_id":        "<entity_id from the graph>",
      "pid":              <integer or null>,
      "justification":    "<one sentence: which chain/pattern drove this>",
      "reversible":       <true|false>,
      "min_score_met":    <true|false>,
      "confirm_required": <true|false>
    }}
  ],
  "rationale":         "<2–4 sentences: overall threat assessment and action order justification>",
  "risk_level":        "<Low|Medium|High|Critical>",
  "confidence":        <0.0–1.0, derived from highest-confidence attack chain>,
  "pivot_suggestions": [
    "<one-sentence suggestion for a targeted follow-up scan if evidence is incomplete>"
  ]
}}

Rules:
- ranked_actions: 3–5 items ordered from most reversible to least reversible.
- If attack_chains is empty: return ranked_actions: [] and risk_level: "Low".
- confirm_required: MUST be true for kill_process and isolate_network.
- pivot_suggestions: 0–3 items. Only include if chains leave unanswered questions.
"#,
        chains.len(),
        max_severity,
        cp_score,
        cp_narrative,
        chains_text,
        entities_text,
    )
}

// ─── Claude API call ──────────────────────────────────────────────────────────

/// Call the Claude API with the analyst prompt.
///
/// The API key is read from the `ANTHROPIC_API_KEY` environment variable.
/// Returns an error string if the key is missing or the call fails.
///
/// Model: claude-sonnet-4-6 (latest Sonnet; good reasoning, low latency)
/// Max tokens: 1024  (the output schema is compact; 1024 is generous)
/// Temperature: 0    (deterministic — same graph should always produce the same plan)
pub async fn call_claude(prompt: &str) -> Result<String, String> {
    let api_key = std::env::var("ANTHROPIC_API_KEY")
        .map_err(|_| "ANTHROPIC_API_KEY environment variable not set".to_string())?;

    let client = Client::new();

    let body = serde_json::json!({
        "model":      "claude-sonnet-4-6",
        "max_tokens": 1024,
        "temperature": 0,
        "system": "You are a security analyst assistant. Return only valid JSON.",
        "messages": [
            {
                "role":    "user",
                "content": prompt
            }
        ]
    });

    let resp = client
        .post("https://api.anthropic.com/v1/messages")
        .header("x-api-key",         &api_key)
        .header("anthropic-version", "2023-06-01")
        .header("content-type",      "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("Claude API request failed: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(format!("Claude API error {status}: {text}"));
    }

    let resp_json: Value = resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse Claude API response: {e}"))?;

    // The API returns: { "content": [{ "type": "text", "text": "..." }] }
    let text = resp_json["content"]
        .as_array()
        .and_then(|arr| arr.first())
        .and_then(|block| block["text"].as_str())
        .ok_or_else(|| "Unexpected Claude API response shape".to_string())?;

    Ok(text.to_string())
}

// ─── Response parser ──────────────────────────────────────────────────────────

/// Parse the raw Claude response text into an `AgentVerdict`.
///
/// The model is instructed to return raw JSON. However, models occasionally
/// wrap JSON in markdown fences (```json ... ```) despite instructions.
/// This function strips fences if present before parsing.
pub fn parse_agent_response(raw: &str) -> Result<AgentVerdict, String> {
    // Strip markdown fences if present
    let stripped = raw
        .trim()
        .trim_start_matches("```json")
        .trim_start_matches("```")
        .trim_end_matches("```")
        .trim();

    serde_json::from_str::<AgentVerdict>(stripped)
        .map_err(|e| format!("Failed to parse agent response as AgentVerdict: {e}\nRaw: {raw}"))
}

// ─── Entry point ──────────────────────────────────────────────────────────────

/// Full Round 1 pipeline: correlate_result → AgentVerdict.
///
/// Called by the `run_agent_analysis` Tauri command.
pub async fn run_analysis(correlate_result: &Value) -> Result<AgentVerdict, String> {
    let prompt  = build_analyst_prompt(correlate_result);
    let raw     = call_claude(&prompt).await?;
    let verdict = parse_agent_response(&raw)?;
    Ok(verdict)
}
```

---

### `UI/src-tauri/src/main.rs` — wiring in the new command

Add the module declaration near the top:

```rust
mod agent;
```

Add the Tauri command (place it alongside `correlate_entities`):

```rust
/// Round 1 agent analysis: take a correlate result and return a ranked action plan.
///
/// The correlate_result is the full JSON object returned by `correlate_entities`.
/// The ANTHROPIC_API_KEY environment variable must be set; an error is returned
/// if it is missing.
///
/// This command is intentionally separate from correlate_entities so that:
///   (a) The detection pipeline is never delayed by a Claude API call.
///   (b) The user can choose when to invoke the AI (it is not automatic).
///   (c) Future rounds can re-call this command with an updated correlate result.
#[tauri::command]
async fn run_agent_analysis(
    correlate_result: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let verdict = agent::run_analysis(&correlate_result).await?;
    serde_json::to_value(&verdict)
        .map_err(|e| format!("Serialization error: {e}"))
}
```

Register it in the `invoke_handler`:

```rust
.invoke_handler(tauri::generate_handler![
    // ... existing commands ...
    run_agent_analysis,
])
```

---

### `UI/src/types/index.ts` — TypeScript types

```typescript
// ─── Agent types ──────────────────────────────────────────────────────────────

export interface RankedAction {
  action:           string;
  target:           string;
  entity_id:        string;
  pid:              number | null;
  justification:    string;
  reversible:       boolean;
  min_score_met:    boolean;
  confirm_required: boolean;
}

export interface AgentVerdict {
  ranked_actions:    RankedAction[];
  rationale:         string;
  risk_level:        'Low' | 'Medium' | 'High' | 'Critical';
  confidence:        number;
  pivot_suggestions: string[];
}
```

---

### `UI/src/store/index.ts` — Zustand state + action

Add to the store state interface:

```typescript
agentVerdict:       AgentVerdict | null;
agentLoading:       boolean;
agentError:         string | null;
```

Add to initial state:

```typescript
agentVerdict:  null,
agentLoading:  false,
agentError:    null,
```

Add the action:

```typescript
runAgentAnalysis: async () => {
  const { correlateResult } = get();
  if (!correlateResult) {
    set({ agentError: 'No correlate result available. Run correlation first.' });
    return;
  }
  set({ agentLoading: true, agentError: null, agentVerdict: null });
  try {
    const verdict = await invoke<AgentVerdict>('run_agent_analysis', {
      correlateResult,
    });
    set({ agentVerdict: verdict, agentLoading: false });
  } catch (err) {
    set({ agentError: String(err), agentLoading: false });
  }
},
```

Note: `correlateResult` is the raw JSON returned by `correlate_entities`. It
is already stored in the Zustand store as the graph data. The agent command
receives it as its sole input.

---

### `UI/src/components/AgentVerdict.tsx` — React component

```tsx
import { useStore } from '../store';
import type { RankedAction } from '../types';

// Risk level → colour mapping (tailwind classes)
const riskColor: Record<string, string> = {
  Low:      'text-green-400',
  Medium:   'text-yellow-400',
  High:     'text-orange-400',
  Critical: 'text-red-500',
};

// Action → icon mapping (text emoji fallback — no extra dependency)
const actionIcon: Record<string, string> = {
  kill_process:       '⚡',
  quarantine_file:    '🔒',
  block_ip:           '🛡',
  dump_memory:        '💾',
  check_persistence:  '🔍',
  isolate_network:    '🔌',
  remove_block_ip:    '↩',
};

function ActionCard({ action, index }: { action: RankedAction; index: number }) {
  const icon = actionIcon[action.action] ?? '•';
  return (
    <div className="bg-surface border border-border rounded p-3 flex flex-col gap-1">
      <div className="flex items-center gap-2">
        <span className="text-lg">{icon}</span>
        <span className="font-mono font-semibold text-sm">{action.action}</span>
        <span className="ml-auto text-xs text-muted">#{index + 1}</span>
      </div>
      <div className="text-sm text-foreground">
        Target: <span className="font-mono">{action.target}</span>
        {action.pid != null && (
          <span className="text-muted ml-2">(PID {action.pid})</span>
        )}
      </div>
      <div className="text-xs text-muted">{action.justification}</div>
      <div className="flex gap-2 mt-1 text-xs">
        {action.reversible ? (
          <span className="text-green-400">reversible</span>
        ) : (
          <span className="text-red-400">irreversible</span>
        )}
        {action.confirm_required && (
          <span className="text-yellow-400">requires confirmation</span>
        )}
      </div>
    </div>
  );
}

export function AgentVerdictPanel() {
  const { agentVerdict, agentLoading, agentError, runAgentAnalysis, correlateResult } =
    useStore();

  if (!correlateResult) return null;  // no graph yet

  return (
    <div className="flex flex-col gap-4 p-4">
      {/* Trigger button */}
      {!agentVerdict && !agentLoading && (
        <button
          onClick={runAgentAnalysis}
          className="btn btn-primary w-full"
        >
          Analyze with AI
        </button>
      )}

      {/* Loading state */}
      {agentLoading && (
        <div className="text-center text-muted py-6">
          Consulting threat analysis engine…
        </div>
      )}

      {/* Error state */}
      {agentError && (
        <div className="text-red-400 text-sm p-3 bg-red-900/20 rounded">
          {agentError}
        </div>
      )}

      {/* Verdict */}
      {agentVerdict && (
        <>
          {/* Header */}
          <div className="flex items-baseline gap-3">
            <span className={`text-2xl font-bold ${riskColor[agentVerdict.risk_level]}`}>
              {agentVerdict.risk_level}
            </span>
            <span className="text-muted text-sm">
              {Math.round(agentVerdict.confidence * 100)}% confidence
            </span>
            <button
              onClick={runAgentAnalysis}
              className="ml-auto text-xs text-muted hover:text-foreground"
            >
              Re-analyze
            </button>
          </div>

          {/* Rationale */}
          <p className="text-sm text-foreground">{agentVerdict.rationale}</p>

          {/* Ranked actions */}
          {agentVerdict.ranked_actions.length > 0 ? (
            <div className="flex flex-col gap-2">
              <div className="text-xs text-muted uppercase tracking-wide">
                Recommended actions ({agentVerdict.ranked_actions.length})
              </div>
              {agentVerdict.ranked_actions.map((a, i) => (
                <ActionCard key={i} action={a} index={i} />
              ))}
            </div>
          ) : (
            <div className="text-sm text-muted">No actions recommended — system appears clean.</div>
          )}

          {/* Pivot suggestions */}
          {agentVerdict.pivot_suggestions.length > 0 && (
            <div className="flex flex-col gap-1">
              <div className="text-xs text-muted uppercase tracking-wide">
                Suggested follow-up scans
              </div>
              {agentVerdict.pivot_suggestions.map((s, i) => (
                <div key={i} className="text-xs text-muted bg-surface rounded p-2">
                  → {s}
                </div>
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
}
```

---

### `UI/src/components/ThreatGraph.tsx` — embed the panel

Find the detail panel section in `ThreatGraph.tsx` (the right-side panel that
shows node details when a node is selected). Add the `AgentVerdictPanel`
below the graph statistics summary, so it appears when the user is looking at
the full graph picture:

```tsx
import { AgentVerdictPanel } from './AgentVerdict';

// Inside the right panel JSX, below the statistics block:
<AgentVerdictPanel />
```

---

## Environment variable setup

The Claude API key is read at runtime from `ANTHROPIC_API_KEY`. There are two
ways to set it for development:

**Option A — shell export (recommended for dev)**

```bash
export ANTHROPIC_API_KEY=sk-ant-...
npm run tauri dev
```

**Option B — `.env` file loaded by Tauri**

Create `UI/.env` (never commit this file):

```
ANTHROPIC_API_KEY=sk-ant-...
```

Add to `UI/.gitignore`:

```
.env
.env.local
```

Then in `UI/src-tauri/src/main.rs` at startup (before `tauri::Builder`):

```rust
// Load .env for development convenience
#[cfg(debug_assertions)]
if let Ok(env_path) = std::env::current_dir().map(|d| d.join("..").join(".env")) {
    if env_path.exists() {
        for line in std::fs::read_to_string(env_path).unwrap_or_default().lines() {
            if let Some((k, v)) = line.split_once('=') {
                if !k.starts_with('#') {
                    std::env::set_var(k.trim(), v.trim());
                }
            }
        }
    }
}
```

For production builds, the API key must be set as a system environment variable
or injected via a CI/CD secret. It is never bundled into the binary.

---

## Data flow — step by step

```
1.  User opens ThreatGraph view.
    The view renders the graph from the Zustand store's correlateResult.
    The AgentVerdictPanel is visible with an "Analyze with AI" button.

2.  User clicks "Analyze with AI".
    runAgentAnalysis() is called.
    agentLoading = true is set; the button is replaced by a spinner.

3.  invoke('run_agent_analysis', { correlateResult }) is called from the store.
    The full correlate result JSON (attack_chains, critical_path, nodes, edges)
    travels via Tauri IPC to the Rust backend.

4.  run_agent_analysis Tauri command calls agent::run_analysis(&correlate_result).

5.  agent::build_analyst_prompt() extracts:
    - attack chains (sorted by confidence)
    - top malicious entities only
    - critical path narrative
    These are formatted into the 4-section briefing prompt.

6.  agent::call_claude() sends the prompt to api.anthropic.com/v1/messages
    with model=claude-sonnet-4-6, temperature=0, max_tokens=1024.
    The API key comes from ANTHROPIC_API_KEY env var.

7.  Claude returns a JSON object matching the AgentVerdict schema.

8.  agent::parse_agent_response() deserializes the JSON into AgentVerdict.
    Markdown fences are stripped if present.

9.  The AgentVerdict is serialized back to JSON by serde_json::to_value()
    and returned to the Tauri IPC layer.

10. The Zustand store sets agentVerdict = verdict, agentLoading = false.

11. AgentVerdictPanel re-renders:
    - Risk level badge (colour-coded)
    - Confidence percentage
    - Rationale paragraph
    - Ranked action cards (3–5 items)
    - Pivot suggestion list (0–3 items)

12. User reads the recommendations.
    Actions marked confirm_required show a confirmation gate before execution.
    (The actual execution of actions is wired separately via existing
     quarantine_file, block_ip, kill_process, etc. Tauri commands.)
```

---

## What is not done yet — and why

### Action execution

The `AgentVerdictPanel` shows the ranked actions but does not execute them.
Execution is wired to the existing Tauri commands (`kill_process`, `block_ip`,
`quarantine_file`, etc.) which the `GraphVerdict.tsx` component already calls.
Connecting the agent's recommendations to those buttons is a UI wiring task
that is separate from Round 1.

Round 1's job is: **given the graph, what should happen?** Execution wiring is
a separate concern that does not depend on AI.

### Multi-round hunt loop (Rounds 2–3)

Round 1 produces `pivot_suggestions` — these are plain-English suggestions for
follow-up scans. The user can read them and manually invoke a new scan.

Automating the loop (the agent emits a `scan-file` JSON-RPC call, waits for a
new correlate result, and reasons again) requires:

- A way for the Tauri backend to issue daemon commands on behalf of the agent
  (the plumbing exists, but the agent command needs access to `AppState`).
- A persistent session ID so the UI can distinguish Round 1 vs Round 2 graph states.
- A loop termination condition (N rounds with no new evidence, or investigation closed).

These are straightforward extensions of what is built here. The prompt schema
already includes `pivot_suggestions`, so the data contract between Rounds 1 and
2 is already defined.

### Streaming

The `call_claude()` function uses the standard messages endpoint, which returns
the full response at once. For a 1024-token response this means a 2–4 second
wait before anything is shown in the UI.

Streaming (`anthropic-streaming: true`) can be added later to show tokens as
they arrive. The parser would need to be updated to accumulate SSE chunks and
parse the final assembled JSON. This is a UX improvement, not a correctness
requirement.

### Error recovery

If the model returns malformed JSON (rare but possible), `parse_agent_response`
returns an error and `agentError` is set in the store. The user can click
"Re-analyze" to retry. A retry counter with exponential backoff can be added
later.

---

## Testing the integration without a real ANTHROPIC_API_KEY

For development without burning API credits, add a mock mode:

```rust
// In agent.rs, replace call_claude with a mock in test/debug builds:
#[cfg(test)]
pub async fn call_claude(_prompt: &str) -> Result<String, String> {
    Ok(r#"{
      "ranked_actions": [
        {
          "action": "block_ip",
          "target": "185.220.101.x",
          "entity_id": "entity:4821",
          "pid": 4821,
          "justification": "C2Communication pattern detected with confidence 0.87",
          "reversible": true,
          "min_score_met": true,
          "confirm_required": false
        }
      ],
      "rationale": "Mock response for testing.",
      "risk_level": "High",
      "confidence": 0.87,
      "pivot_suggestions": ["Scan %TEMP% for recently written binaries"]
    }"#.to_string())
}
```

You can also test the prompt builder independently by calling
`build_analyst_prompt` with a hardcoded correlate result JSON and printing the
output — no API call needed.

---

## Summary: what gets built in Round 1

| Component | File | Purpose |
|---|---|---|
| `agent.rs` | `UI/src-tauri/src/agent.rs` | Prompt builder + Claude API call + response parser |
| `run_agent_analysis` command | `UI/src-tauri/src/main.rs` | Tauri IPC entry point |
| `AgentVerdict` + `RankedAction` types | `UI/src/types/index.ts` | TypeScript contracts |
| `agentVerdict` state + `runAgentAnalysis` action | `UI/src/store/index.ts` | Zustand state management |
| `AgentVerdictPanel` component | `UI/src/components/AgentVerdict.tsx` | UI rendering |
| Embed in ThreatGraph | `UI/src/components/ThreatGraph.tsx` | Surface in the right panel |
| `reqwest` dependency | `UI/src-tauri/Cargo.toml` | HTTP client for API call |

After this is built, the user can:
1. Run a `correlate`.
2. See the graph and attack chains.
3. Click "Analyze with AI".
4. Receive a ranked, justified 3–5 action plan in 2–4 seconds.
5. Read the pivot suggestions for what to investigate next.

That is Round 1 complete. Rounds 2 and 3 build on the same infrastructure
without changing any of the above.

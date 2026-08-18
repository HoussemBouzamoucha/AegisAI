# File: ai_agent/agent/prompt.py
#
# Two prompt templates:
#   PROMPT         — Round 1 initial analysis (first look at the graph)
#   REASSESS_PROMPT — Round 2+ re-assessment (graph updated after user actions)
#
# Token budget: each template stays under ~2 000 tokens so the model has
# room to write the JSON response within its context window.

from langchain_core.prompts import ChatPromptTemplate


# ─── System message ───────────────────────────────────────────────────────────

SYSTEM_MESSAGE = """\
You are a Windows threat analyst. Given a security graph, output ONLY a JSON object — no prose, no markdown, no headers.
Start your response with {{ and end with }}.

Action thresholds (never recommend below these combined_score values):
  block_ip=0.60  quarantine_file=0.70  dump_memory=0.75  kill_process=0.65  check_persistence=0.50  isolate_network=0.85

Ordering: reversible before irreversible → block_ip < quarantine_file < dump_memory < kill_process < isolate_network
confirm_required=true for kill_process and isolate_network only.

technical_suggestions: 3–5 MITRE-mapped steps for the SOC analyst (human-in-the-loop; NOT automated commands).
Each entry must include:
  "keyword"   — short technical label using DFIR/SOC vocabulary (include MITRE ID inline if known),
                e.g. "T1055 – Reflective DLL Injection", "T1003.001 – LSASS Credential Dump",
                     "ETW Telemetry Gap – Kernel Callback Suppression"
  "mitre_id"  — MITRE ATT&CK ID string or null
  "reasoning" — one sentence: what specifically to investigate, which tool to use, and why it applies here
  "priority"  — "critical" | "high" | "medium"
Only emit technical_suggestions when there is real threat evidence (attack chains or Malicious entities).
Empty list if risk_level is Low.\
"""

# ─── Human message ────────────────────────────────────────────────────────────

HUMAN_TEMPLATE = """\
ATTACK CHAINS ({chain_count} detected, highest severity: {max_severity}):
{chains_text}
CRITICAL PATH (score {cp_score:.2f}): {cp_narrative}

MALICIOUS ENTITIES:
{entities_text}

IMPORTANT: If MALICIOUS ENTITIES is "none" and ATTACK CHAINS is 0, you MUST set ranked_actions=[], technical_suggestions=[], and risk_level="Low". A high critical-path score from clean/suspicious-only nodes does NOT justify any action.
Otherwise respond with 1-5 ranked_actions (most reversible first) targeting only entities listed above, plus 3-5 technical_suggestions for the SOC analyst.
{{"ranked_actions":[{{"action":"...","target":"...","entity_id":"...","pid":null,"justification":"...","reversible":true,"min_score_met":true,"confirm_required":false}}],"rationale":"...","risk_level":"Low|Medium|High|Critical","confidence":0.0,"pivot_suggestions":["..."],"technical_suggestions":[{{"keyword":"T1055 – Process Injection","mitre_id":"T1055","reasoning":"...","priority":"high"}}]}}\
"""

PROMPT = ChatPromptTemplate.from_messages([
    ("system", SYSTEM_MESSAGE),
    ("human",  HUMAN_TEMPLATE),
])


# ─── Round 2+ re-assessment prompt ───────────────────────────────────────────

REASSESS_SYSTEM_MESSAGE = """\
You are a Windows threat analyst conducting a follow-up investigation.
The user has already executed some containment actions. The graph has been re-scanned.
Output ONLY a JSON object — no prose, no markdown, no headers.
Start your response with {{ and end with }}.

Do NOT recommend any action already listed in ACTIONS TAKEN.
If ranked_actions is empty, set investigation_closed=true with the appropriate close_reason.

Action thresholds (never recommend below these combined_score values):
  block_ip=0.60  quarantine_file=0.70  dump_memory=0.75  kill_process=0.65  check_persistence=0.50  isolate_network=0.85

Ordering: reversible before irreversible → block_ip < quarantine_file < dump_memory < check_persistence < kill_process < isolate_network
confirm_required=true for kill_process and isolate_network only.

technical_suggestions: Update these based on remaining threats. 3–5 MITRE-mapped steps for the SOC analyst.
Each entry must include:
  "keyword"   — short technical label (include MITRE ID inline), e.g. "T1021.002 – SMB Lateral Movement"
  "mitre_id"  — MITRE ATT&CK ID or null
  "reasoning" — one sentence: what specifically to investigate post-action, referencing what has changed
  "priority"  — "critical" | "high" | "medium"
Empty list if investigation_closed=true.\
"""

REASSESS_HUMAN_TEMPLATE = """\
ROUND {round_num} RE-ASSESSMENT

ACTIONS ALREADY TAKEN (do NOT recommend these again):
{actions_taken_text}

CURRENT THREAT STATE after those actions:
ATTACK CHAINS ({chain_count} remaining, highest severity: {max_severity}):
{chains_text}
CRITICAL PATH (score {cp_score:.2f}): {cp_narrative}

REMAINING MALICIOUS ENTITIES:
{entities_text}

IMPORTANT: If REMAINING MALICIOUS ENTITIES is "none" and ATTACK CHAINS is 0, you MUST set ranked_actions=[], technical_suggestions=[], risk_level="Low", and investigation_closed=true.
Otherwise respond with 1-5 ranked_actions (most reversible first) targeting only entities listed above, plus updated technical_suggestions:
{{"ranked_actions":[{{"action":"...","target":"...","entity_id":"...","pid":null,"justification":"...","reversible":true,"min_score_met":true,"confirm_required":false}}],"rationale":"...","risk_level":"Low|Medium|High|Critical","confidence":0.0,"pivot_suggestions":["..."],"technical_suggestions":[{{"keyword":"T1055 – Process Injection","mitre_id":"T1055","reasoning":"...","priority":"high"}}],"investigation_closed":false,"close_reason":null,"round_num":{round_num}}}\
"""

REASSESS_PROMPT = ChatPromptTemplate.from_messages([
    ("system", REASSESS_SYSTEM_MESSAGE),
    ("human",  REASSESS_HUMAN_TEMPLATE),
])


# ─── Context builder ──────────────────────────────────────────────────────────

def build_prompt_context(result: dict) -> dict:
    chains    = result.get("graph", {}).get("attack_chains", [])
    nodes     = result.get("graph", {}).get("nodes", [])
    crit_path = result.get("graph", {}).get("critical_path") or {}

    # Max severity
    severity_rank = {"Critical": 3, "Malicious": 2, "Suspicious": 1}
    max_severity = max(
        (c.get("severity", "") for c in chains),
        key=lambda s: severity_rank.get(s, 0),
        default="None",
    )

    # Critical path
    cp_score     = float(crit_path.get("total_score", 0.0))
    cp_narrative = crit_path.get("narrative") or "none"

    # Chains — compact one-liner each, sorted by confidence desc
    sorted_chains = sorted(chains, key=lambda c: c.get("confidence", 0.0), reverse=True)
    chains_lines = []
    for c in sorted_chains:
        ids = ",".join(c.get("node_ids", []))
        chains_lines.append(
            f"  {c.get('pattern')} score={c.get('chain_score',0):.2f} "
            f"conf={c.get('confidence',0):.2f} sev={c.get('severity')} "
            f"mitre={c.get('mitre_tactic','')} entities=[{ids}] "
            f"desc={c.get('description','')}"
        )
    chains_text = "\n".join(chains_lines) if chains_lines else "  none"

    # Entities — only Malicious/Critical, one-liner each
    threat_nodes = [n for n in nodes if n.get("threat_level") in ("Malicious", "Critical")]
    entities_lines = []
    for n in threat_nodes:
        flags = [
            f for f, v in {
                "mal_net": n.get("has_malicious_network"),
                "mal_mem": n.get("has_malicious_memory"),
                "mal_file": n.get("has_malicious_file"),
                "lolbin": n.get("is_lolbin"),
            }.items() if v
        ]
        entities_lines.append(
            f"  {n.get('entity_id')} label={n.get('label')} pid={n.get('pid')} "
            f"score={n.get('combined_score',0):.2f} flags={','.join(flags) or 'none'}"
        )
    entities_text = "\n".join(entities_lines) if entities_lines else "  none"

    return {
        "chain_count":   len(chains),
        "max_severity":  max_severity,
        "cp_score":      cp_score,
        "cp_narrative":  cp_narrative,
        "chains_text":   chains_text,
        "entities_text": entities_text,
    }


def build_reassess_context(result: dict, actions_taken: list[dict], round_num: int) -> dict:
    """
    Build the variable dict for REASSESS_PROMPT.

    Same graph extraction as build_prompt_context(), plus a compact
    'ACTIONS ALREADY TAKEN' block so the model knows what not to repeat.
    """
    # Reuse the same graph extraction
    base = build_prompt_context(result)

    # Format executed actions — one line each
    action_lines = []
    for a in actions_taken:
        status = a.get("result", "success")
        ts     = a.get("executed_at", "")
        ts_str = f" at {ts}" if ts else ""
        action_lines.append(
            f"  [{status.upper()}] {a.get('action')} → target={a.get('target')} "
            f"entity={a.get('entity_id')}{ts_str}"
        )
    actions_taken_text = "\n".join(action_lines) if action_lines else "  (none yet)"

    return {
        **base,
        "actions_taken_text": actions_taken_text,
        "round_num":          round_num,
    }

# File: ai_agent/agent/prompt.py
#
# Compact prompt — keeps total token count under ~2000 so the model has
# enough room in its context window to finish the JSON response.

from langchain_core.prompts import ChatPromptTemplate


# ─── System message ───────────────────────────────────────────────────────────

SYSTEM_MESSAGE = """\
You are a Windows threat analyst. Given a security graph, output ONLY a JSON object — no prose, no markdown, no headers.
Start your response with {{ and end with }}.

Action thresholds (never recommend below these combined_score values):
  block_ip=0.60  quarantine_file=0.70  dump_memory=0.75  kill_process=0.65  check_persistence=0.50  isolate_network=0.85

Ordering: reversible before irreversible → block_ip < quarantine_file < dump_memory < kill_process < isolate_network
confirm_required=true for kill_process and isolate_network only.\
"""

# ─── Human message ────────────────────────────────────────────────────────────

HUMAN_TEMPLATE = """\
ATTACK CHAINS ({chain_count} detected, highest severity: {max_severity}):
{chains_text}
CRITICAL PATH (score {cp_score:.2f}): {cp_narrative}

MALICIOUS ENTITIES:
{entities_text}
Respond with this JSON (3-5 ranked_actions, most reversible first):
{{"ranked_actions":[{{"action":"...","target":"...","entity_id":"...","pid":null,"justification":"...","reversible":true,"min_score_met":true,"confirm_required":false}}],"rationale":"...","risk_level":"Low|Medium|High|Critical","confidence":0.0,"pivot_suggestions":["..."]}}\
"""

PROMPT = ChatPromptTemplate.from_messages([
    ("system", SYSTEM_MESSAGE),
    ("human",  HUMAN_TEMPLATE),
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

# File: ai_agent/agent/reasoning.py
#
# Self-correcting feedback loop for the AI threat analyst.
#
# Flow:
#   1. analyst.py  → Round 1 verdict (initial generation)
#   2. validate()  → deterministic rule checks (R1–R8), returns violations[]
#   3. if violations: build targeted correction prompt → LLM → corrected verdict
#   4. repeat until: zero violations | converged | MAX_ITERATIONS reached
#   5. return best verdict (fewest violations seen across all iterations)
#
# See agent_reasoning.txt for the full design rationale.

import json
import sys
from dataclasses import dataclass

from langchain_core.prompts import ChatPromptTemplate

from .analyst import analyze, reassess, build_llm, _extract_text, _parse_verdict
from .schema import AgentVerdict

# ─── Constants ────────────────────────────────────────────────────────────────

MAX_ITERATIONS = 3

# Minimum combined_score an entity must have for each action type (R1).
_SCORE_THRESHOLDS: dict[str, float] = {
    "block_ip":          0.60,
    "quarantine_file":   0.70,
    "dump_memory":       0.75,
    "kill_process":      0.65,
    "check_persistence": 0.50,
    "isolate_network":   0.85,
    "remove_block_ip":   0.0,   # rollback action — no score gate
}

# Actions sorted most-reversible → least-reversible (R2).
# Any pair (i, j) where rank[i] > rank[j] is an ordering violation.
_REVERSIBILITY_RANK: dict[str, int] = {
    "block_ip":          0,
    "remove_block_ip":   0,
    "quarantine_file":   1,
    "dump_memory":       2,
    "check_persistence": 3,
    "kill_process":      4,
    "isolate_network":   5,
}

# ─── Clean-graph gate ─────────────────────────────────────────────────────────

def _is_clean_graph(correlate_result: dict) -> bool:
    """
    Return True when the graph has no evidence worth acting on.

    A graph is considered clean when ALL of the following hold:
      1. Zero attack chains detected.
      2. Zero Malicious or Critical entities.
      3. No Suspicious entity carries an active malicious domain flag
         (has_malicious_network / has_malicious_memory / has_malicious_file).

    NOTE: A high critical-path score alone is NOT a reliable threat signal.
    A long chain of clean parent-child relationships (e.g. IDE → spawned
    processes) can accumulate a high numeric score with zero threat indicators.
    We therefore base the decision on threat labels and domain flags, not score.
    """
    nodes  = _node_map(correlate_result)
    chains = _chains(correlate_result)

    # Any attack chain is a potential threat signal — do not short-circuit.
    if chains:
        return False

    for n in nodes.values():
        level = n.get("threat_level", "Clean")
        # Malicious / Critical always warrants a response.
        if level in ("Malicious", "Critical"):
            return False
        # Suspicious + active domain flag is actionable; Suspicious alone is not.
        if level == "Suspicious" and (
            n.get("has_malicious_network")
            or n.get("has_malicious_memory")
            or n.get("has_malicious_file")
        ):
            return False

    return True


# ─── Violation ────────────────────────────────────────────────────────────────

@dataclass
class Violation:
    rule:    str   # "R1" … "R8"
    message: str   # what is wrong
    fix:     str   # exact instruction for the model

    def __str__(self) -> str:
        return f"{self.rule}: {self.message} → FIX: {self.fix}"


# ─── Graph helpers ────────────────────────────────────────────────────────────

def _node_map(correlate_result: dict) -> dict[str, dict]:
    """Return entity_id → node dict from the correlate result."""
    nodes = correlate_result.get("graph", {}).get("nodes", [])
    if isinstance(nodes, list):
        return {n["entity_id"]: n for n in nodes if "entity_id" in n}
    if isinstance(nodes, dict):
        return dict(nodes)
    return {}


def _chains(correlate_result: dict) -> list[dict]:
    return correlate_result.get("graph", {}).get("attack_chains", [])


# ─── Validator ───────────────────────────────────────────────────────────────

def validate(verdict: AgentVerdict, correlate_result: dict) -> list[Violation]:
    """
    Run all 8 deterministic validation rules against `verdict`.

    No LLM is involved — every check is pure Python against the Pydantic
    schema and the correlate graph.

    Returns a (possibly empty) list of Violation objects.
    Empty = verdict is structurally correct.
    """
    violations: list[Violation] = []
    nodes      = _node_map(correlate_result)
    chains     = _chains(correlate_result)
    actions    = verdict.ranked_actions

    # ── R1: Score thresholds ──────────────────────────────────────────────────
    for i, action in enumerate(actions):
        threshold = _SCORE_THRESHOLDS.get(action.action, 0.0)
        if threshold == 0.0:
            continue
        node  = nodes.get(action.entity_id)
        score = float(node.get("combined_score", 0.0)) if node else 0.0
        if score < threshold:
            violations.append(Violation(
                rule="R1",
                message=(
                    f"action[{i}] '{action.action}' targets '{action.entity_id}' "
                    f"(score={score:.2f}) but minimum threshold is {threshold:.2f}"
                ),
                fix=(
                    f"Remove action[{i}] '{action.action}' — entity score {score:.2f} "
                    f"is below the required minimum {threshold:.2f}."
                ),
            ))

    # ── R2: Reversibility ordering ────────────────────────────────────────────
    for i in range(len(actions) - 1):
        rank_cur  = _REVERSIBILITY_RANK.get(actions[i].action,     99)
        rank_next = _REVERSIBILITY_RANK.get(actions[i + 1].action, 99)
        if rank_cur > rank_next:
            violations.append(Violation(
                rule="R2",
                message=(
                    f"action[{i}] '{actions[i].action}' (rank={rank_cur}) comes before "
                    f"action[{i+1}] '{actions[i+1].action}' (rank={rank_next}) — "
                    "more-reversible actions must come first"
                ),
                fix=(
                    f"Reorder so '{actions[i+1].action}' appears before "
                    f"'{actions[i].action}'. "
                    "Required order: block_ip / remove_block_ip → quarantine_file → "
                    "dump_memory → check_persistence → kill_process → isolate_network."
                ),
            ))

    # ── R3: confirm_required integrity ────────────────────────────────────────
    for i, action in enumerate(actions):
        if action.action in ("kill_process", "isolate_network"):
            if not action.confirm_required:
                violations.append(Violation(
                    rule="R3",
                    message=(
                        f"action[{i}] '{action.action}' has confirm_required=false "
                        "— must be true"
                    ),
                    fix=f"Set confirm_required=true on action[{i}] '{action.action}'.",
                ))
        else:
            if action.confirm_required:
                violations.append(Violation(
                    rule="R3",
                    message=(
                        f"action[{i}] '{action.action}' has confirm_required=true "
                        "— must be false for this action type"
                    ),
                    fix=f"Set confirm_required=false on action[{i}] '{action.action}'.",
                ))

    # ── R4: Coverage — no missed Malicious/Critical entities ──────────────────
    malicious_ids = {
        eid for eid, n in nodes.items()
        if n.get("threat_level") in ("Malicious", "Critical")
    }
    covered_ids = {a.entity_id for a in actions}
    for eid in malicious_ids:
        if eid not in covered_ids:
            node  = nodes[eid]
            label = node.get("label", eid)
            score = float(node.get("combined_score", 0.0))
            violations.append(Violation(
                rule="R4",
                message=(
                    f"Malicious entity '{eid}' (label='{label}', score={score:.2f}) "
                    "has no corresponding action"
                ),
                fix=(
                    f"Add at least one action targeting entity_id='{eid}' "
                    f"(label='{label}', score={score:.2f}). "
                    "Use dump_memory or kill_process for a process; "
                    "quarantine_file for a file."
                ),
            ))

    # ── R5: Hallucination guard — no invented entity IDs ─────────────────────
    valid_ids = set(nodes.keys())
    for i, action in enumerate(actions):
        eid = action.entity_id or ""
        # Null/empty entity_id is only allowed for system-wide check_persistence
        if not eid or eid.lower() in ("null", "none"):
            if action.action != "check_persistence":
                violations.append(Violation(
                    rule="R5",
                    message=f"action[{i}] '{action.action}' has no entity_id",
                    fix=(
                        f"Set entity_id to a valid entity_id from the graph "
                        f"on action[{i}] '{action.action}'. "
                        f"Valid IDs: {_fmt_ids(valid_ids)}."
                    ),
                ))
            continue
        # "system" is an accepted sentinel for system-wide check_persistence
        if eid == "system" and action.action == "check_persistence":
            continue
        if eid not in valid_ids:
            violations.append(Violation(
                rule="R5",
                message=(
                    f"action[{i}] '{action.action}' uses entity_id='{eid}' "
                    "which does not exist in the graph"
                ),
                fix=(
                    f"Replace entity_id='{eid}' on action[{i}] with a real entity_id. "
                    f"Valid IDs: {_fmt_ids(valid_ids)}."
                ),
            ))

    # ── R6: LOLBin coverage ───────────────────────────────────────────────────
    lolbin_vectors = {
        eid for eid, n in nodes.items()
        if n.get("is_lolbin") and n.get("is_vector")
    }
    check_targets = {
        a.entity_id for a in actions if a.action == "check_persistence"
    }
    for eid in lolbin_vectors:
        # Covered if the action targets this entity directly OR targets "system"
        if eid not in check_targets and "system" not in check_targets:
            label = nodes[eid].get("label", eid)
            violations.append(Violation(
                rule="R6",
                message=(
                    f"LOLBin vector '{eid}' ({label}) has no check_persistence action — "
                    "LOLBin vectors are strong persistence indicators and must be checked"
                ),
                fix=(
                    f"Add a check_persistence action with entity_id='{eid}' "
                    f"(label='{label}') to scan for registry/startup persistence."
                ),
            ))

    # ── R7: risk_level consistency ────────────────────────────────────────────
    _sev_rank  = {"Critical": 3, "Malicious": 2, "Suspicious": 1}
    _risk_rank = {"Critical": 3, "High": 2, "Medium": 1, "Low": 0}

    max_chain_sev = max(
        (_sev_rank.get(c.get("severity", ""), 0) for c in chains),
        default=0,
    )
    current_risk = _risk_rank.get(verdict.risk_level, 0)

    if max_chain_sev >= 2 and current_risk < 2:
        violations.append(Violation(
            rule="R7",
            message=(
                f"risk_level='{verdict.risk_level}' understates severity — "
                "a Malicious or Critical attack chain is present"
            ),
            fix="Change risk_level to 'High' or 'Critical'.",
        ))
    elif max_chain_sev == 1 and current_risk < 1:
        violations.append(Violation(
            rule="R7",
            message=(
                f"risk_level='{verdict.risk_level}' understates severity — "
                "a Suspicious attack chain is present"
            ),
            fix="Change risk_level to at least 'Medium'.",
        ))

    # ── R8: Action count ──────────────────────────────────────────────────────
    if chains:
        if len(actions) == 0:
            violations.append(Violation(
                rule="R8",
                message="ranked_actions is empty but attack chains are present",
                fix="Add 1–5 ranked_actions covering the detected threat entities.",
            ))
        elif len(actions) > 5:
            excess = len(actions) - 5
            violations.append(Violation(
                rule="R8",
                message=f"ranked_actions has {len(actions)} actions — maximum is 5",
                fix=(
                    f"Remove the {excess} lowest-priority action(s) so that "
                    "ranked_actions contains at most 5 entries."
                ),
            ))

    # ── R9: No actions without confirmed threat evidence ──────────────────────
    # Actions must NOT be recommended when the graph contains no Malicious/Critical
    # entities AND no attack chains — even if a Suspicious entity passes the numeric
    # score threshold for some action.
    #
    # Rationale: the critical-path score can be high purely from graph topology
    # (many parent-child edges between clean processes).  A Suspicious-only graph
    # with no domain flags and no attack chains does not warrant containment.
    # The only always-permitted action regardless of threat state is remove_block_ip
    # (rollback).
    has_malicious_entities = any(
        n.get("threat_level") in ("Malicious", "Critical")
        for n in nodes.values()
    )
    if not chains and not has_malicious_entities:
        for i, action in enumerate(actions):
            if action.action == "remove_block_ip":
                continue  # rollback is always allowed
            violations.append(Violation(
                rule="R9",
                message=(
                    f"action[{i}] '{action.action}' has no supporting threat evidence — "
                    "graph contains no Malicious/Critical entities and no attack chains. "
                    "A high critical-path score from clean/suspicious-only nodes does not "
                    "justify containment actions."
                ),
                fix=(
                    f"Remove action[{i}] '{action.action}'. "
                    "Set ranked_actions=[] and risk_level='Low' — no confirmed threats present."
                ),
            ))

    return violations


# ─── Correction prompt ────────────────────────────────────────────────────────

_CORRECTION_SYSTEM = """\
You are a JSON correction engine for a security verdict.
Fix ONLY the listed violations. Change nothing else.
Output ONLY a valid JSON object — no prose, no markdown, no explanation.
Start your response with {{ and end with }}.\
"""

_CORRECTION_HUMAN = """\
CURRENT VERDICT:
{verdict_json}

VIOLATIONS TO FIX ({count}):
{violations_text}

Output the corrected JSON verdict with ONLY the listed violations fixed.\
"""

_CORRECTION_PROMPT = ChatPromptTemplate.from_messages([
    ("system", _CORRECTION_SYSTEM),
    ("human",  _CORRECTION_HUMAN),
])


# ─── Correction call ──────────────────────────────────────────────────────────

def _correct(
    verdict:    AgentVerdict,
    violations: list[Violation],
    llm,
) -> AgentVerdict:
    """Send a targeted correction prompt and parse the result."""
    verdict_json    = json.dumps(verdict.model_dump(), indent=2)
    violations_text = "\n".join(f"{i+1}. {v}" for i, v in enumerate(violations))

    response = (_CORRECTION_PROMPT | llm).invoke({
        "verdict_json":    verdict_json,
        "violations_text": violations_text,
        "count":           len(violations),
    })

    print(f"[reasoning] correction raw: {str(response.content)[:300]}", file=sys.stderr)
    text = _extract_text(response)
    return _parse_verdict(text)


# ─── Convergence check ────────────────────────────────────────────────────────

def _verdicts_equal(a: AgentVerdict, b: AgentVerdict) -> bool:
    """True if two verdicts are semantically identical (field-by-field)."""
    a_dump = a.model_dump(exclude={"warnings"})
    b_dump = b.model_dump(exclude={"warnings"})
    return a_dump == b_dump


# ─── ID formatter ────────────────────────────────────────────────────────────

def _fmt_ids(ids: set[str], limit: int = 5) -> str:
    """Format a set of entity IDs for inclusion in a violation message."""
    sample = sorted(ids)[:limit]
    suffix = "..." if len(ids) > limit else ""
    return "[" + ", ".join(f"'{i}'" for i in sample) + suffix + "]"


# ─── Main entry point ─────────────────────────────────────────────────────────

def refine(correlate_result: dict) -> AgentVerdict:
    """
    Round 1 generation + self-correction feedback loop.

    Calls analyst.analyze() for Round 1, then iterates:
      validate → correct → check convergence → repeat

    Break conditions (first hit wins):
      1. Zero violations after validate()        → clean exit
      2. Corrected verdict identical to previous → converged, no progress
      3. MAX_ITERATIONS (3) reached              → return best-so-far

    Returns:
        AgentVerdict.  If the loop exits with unresolved violations,
        the verdict's `warnings` field lists the outstanding rule violations
        so the UI can surface a caution indicator.
    """
    # ── Pre-LLM clean-graph gate ──────────────────────────────────────────────
    # Skip the LLM entirely when there is no actionable threat evidence.
    # Sending a clean graph to the model wastes a round-trip and risks the model
    # hallucinating actions based on the critical-path narrative alone.
    if _is_clean_graph(correlate_result):
        print(
            "[reasoning] Clean-graph gate: no Malicious/Critical entities and no "
            "attack chains — returning Low-risk verdict without calling the LLM.",
            file=sys.stderr,
        )
        return AgentVerdict(
            ranked_actions=[],
            rationale=(
                "No malicious or critical entities detected. All observed processes "
                "are within normal operating parameters. The critical path reflects "
                "normal parent-child process topology, not an attack chain."
            ),
            risk_level="Low",
            confidence=1.0,
            pivot_suggestions=[],
        )

    # ── Round 1 ───────────────────────────────────────────────────────────────
    print("[reasoning] Round 1 — generating initial verdict...", file=sys.stderr)
    verdict = analyze(correlate_result)

    violations = validate(verdict, correlate_result)
    print(
        f"[reasoning] Round 1 complete — {len(violations)} violation(s): "
        f"{[v.rule for v in violations]}",
        file=sys.stderr,
    )

    if not violations:
        print("[reasoning] No violations — returning immediately.", file=sys.stderr)
        return verdict

    # ── Shared LLM instance for all correction calls ──────────────────────────
    llm = build_llm()

    # Track the best verdict seen (fewest violations).
    best_verdict    = verdict
    best_violations = violations

    prev_verdict = verdict

    # ── Correction loop ───────────────────────────────────────────────────────
    for iteration in range(1, MAX_ITERATIONS + 1):
        print(
            f"[reasoning] Iteration {iteration}/{MAX_ITERATIONS} — "
            f"correcting {len(best_violations)} violation(s): "
            f"{[v.rule for v in best_violations]}",
            file=sys.stderr,
        )

        try:
            corrected = _correct(prev_verdict, best_violations, llm)
        except Exception as exc:
            print(f"[reasoning] Correction call failed: {exc}", file=sys.stderr)
            break

        # ── Convergence check ─────────────────────────────────────────────────
        if _verdicts_equal(corrected, prev_verdict):
            print(
                "[reasoning] Converged — correction produced no change. "
                "Exiting loop.",
                file=sys.stderr,
            )
            break

        new_violations = validate(corrected, correlate_result)
        print(
            f"[reasoning] Iteration {iteration} → {len(new_violations)} violation(s): "
            f"{[v.rule for v in new_violations]}",
            file=sys.stderr,
        )

        # Keep the best verdict seen across all iterations.
        if len(new_violations) < len(best_violations):
            best_verdict    = corrected
            best_violations = new_violations

        prev_verdict = corrected

        if not new_violations:
            print(
                "[reasoning] All violations resolved — exiting loop.",
                file=sys.stderr,
            )
            return best_verdict

    # ── Loop ended without full resolution ────────────────────────────────────
    if best_violations:
        warning_strs = [str(v) for v in best_violations]
        print(
            f"[reasoning] Exiting with {len(best_violations)} unresolved "
            f"violation(s). Returning best verdict with warnings.",
            file=sys.stderr,
        )
        # Attach warnings — AgentVerdict.warnings is already defined in schema.py
        best_verdict = best_verdict.model_copy(
            update={"warnings": warning_strs}
        )

    return best_verdict


# ─── Level 2: Action-Response loop ────────────────────────────────────────────

MAX_ROUNDS = 5  # hard cap on re-assessment cycles


def _compute_threat_score(correlate_result: dict) -> float:
    """
    Sum of combined_score for all Malicious/Critical entities in the graph.

    Used for monotonicity checking: if this value did not decrease after an
    action, the action had no measurable effect on the threat state.
    """
    nodes = correlate_result.get("graph", {}).get("nodes", [])
    return sum(
        float(n.get("combined_score", 0.0))
        for n in nodes
        if n.get("threat_level") in ("Malicious", "Critical")
    )


def refine_reassess(
    correlate_result:       dict,
    actions_taken:          list[dict],
    round_num:              int,
    previous_threat_score:  float = 0.0,
) -> AgentVerdict:
    """
    Level 2 — action-response loop entry point.

    Called after the user executes an action and the Rust daemon has
    re-correlated.  Performs three checks before invoking the LLM:

    1. **No-improvement guard**: if the overall threat score did not decrease
       after the action, stop recommending further actions and flag the
       investigation for manual review.

    2. **Resolved guard**: if no Malicious/Critical entities remain, close
       the investigation immediately without an LLM call.

    3. **Max-rounds guard**: if we have already cycled MAX_ROUNDS times, close
       the investigation and require human escalation.

    If none of the guards fire, the function calls analyst.reassess() then
    runs the same validate → correct micro-loop from refine() to ensure the
    new verdict is structurally sound.

    Args:
        correlate_result:      Fresh daemon correlate result (post-action state).
        actions_taken:         List of ExecutedAction dicts, newest last.
        round_num:             Current round (caller increments: 1 → 2 → …).
        previous_threat_score: Sum of combined_scores from the *previous* round.
                               0.0 on the very first re-assessment means the check
                               is skipped (no baseline to compare against).

    Returns:
        AgentVerdict with investigation_closed=True when the loop should stop.
    """
    current_score = _compute_threat_score(correlate_result)

    # ── Guard 1: monotonicity ─────────────────────────────────────────────────
    # Only check if we have a real baseline (previous_score > 0) and there were
    # actually actions taken.  A score of exactly 0 after actions means resolved.
    if (
        actions_taken
        and previous_threat_score > 0.0
        and current_score >= previous_threat_score
        and current_score > 0.0
    ):
        msg = (
            f"Overall threat score did not decrease after the last action "
            f"({previous_threat_score:.2f} → {current_score:.2f}). "
            "The action may have had no measurable effect. Manual investigation required."
        )
        print(f"[reasoning] Round {round_num}: monotonicity guard fired — {msg}", file=sys.stderr)
        return AgentVerdict(
            ranked_actions=[],
            rationale=msg,
            risk_level="High",
            confidence=0.0,
            pivot_suggestions=[
                "Re-examine whether the executed action targeted the correct entity.",
                "Check if the threat actor spawned a new process after the action.",
            ],
            investigation_closed=True,
            close_reason="no_improvement",
            round_num=round_num,
        )

    # ── Guard 2: resolved ─────────────────────────────────────────────────────
    if current_score == 0.0 or not any(
        n.get("threat_level") in ("Malicious", "Critical")
        for n in correlate_result.get("graph", {}).get("nodes", [])
    ):
        msg = "All confirmed threat entities have been removed. Investigation complete."
        print(f"[reasoning] Round {round_num}: resolved — {msg}", file=sys.stderr)
        return AgentVerdict(
            ranked_actions=[],
            rationale=msg,
            risk_level="Low",
            confidence=1.0,
            pivot_suggestions=[],
            investigation_closed=True,
            close_reason="resolved",
            round_num=round_num,
        )

    # ── Guard 3: max rounds ───────────────────────────────────────────────────
    if round_num >= MAX_ROUNDS:
        msg = (
            f"Maximum re-assessment rounds ({MAX_ROUNDS}) reached with threats still "
            "present. Escalating to manual review."
        )
        print(f"[reasoning] {msg}", file=sys.stderr)
        return AgentVerdict(
            ranked_actions=[],
            rationale=msg,
            risk_level="Critical",
            confidence=0.0,
            pivot_suggestions=["Perform manual forensic analysis — automated loop exhausted."],
            investigation_closed=True,
            close_reason="max_rounds_reached",
            round_num=round_num,
        )

    # ── LLM re-assessment + micro-loop ───────────────────────────────────────
    print(
        f"[reasoning] Round {round_num}: re-assessing — score {previous_threat_score:.2f} → "
        f"{current_score:.2f}, {len(actions_taken)} action(s) taken so far.",
        file=sys.stderr,
    )

    verdict    = reassess(correlate_result, actions_taken, round_num)
    violations = validate(verdict, correlate_result)

    print(
        f"[reasoning] Round {round_num} initial verdict — {len(violations)} violation(s): "
        f"{[v.rule for v in violations]}",
        file=sys.stderr,
    )

    if not violations:
        return verdict

    # Correction sub-loop (same as in refine(), capped at MAX_ITERATIONS).
    llm             = build_llm()
    best_verdict    = verdict
    best_violations = violations
    prev_verdict    = verdict

    for iteration in range(1, MAX_ITERATIONS + 1):
        try:
            corrected = _correct(prev_verdict, best_violations, llm)
        except Exception as exc:
            print(f"[reasoning] Round {round_num} correction failed: {exc}", file=sys.stderr)
            break

        if _verdicts_equal(corrected, prev_verdict):
            print(f"[reasoning] Round {round_num}: converged.", file=sys.stderr)
            break

        new_violations = validate(corrected, correlate_result)
        if len(new_violations) < len(best_violations):
            best_verdict    = corrected
            best_violations = new_violations

        prev_verdict = corrected

        if not new_violations:
            print(f"[reasoning] Round {round_num}: all violations resolved.", file=sys.stderr)
            return best_verdict

    if best_violations:
        best_verdict = best_verdict.model_copy(
            update={"warnings": [str(v) for v in best_violations]}
        )

    return best_verdict

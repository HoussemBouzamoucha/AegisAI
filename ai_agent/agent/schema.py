# File: ai_agent/agent/schema.py
#
# Pydantic models for the agent output contract.
#
# RankedAction uses a model_validator to fill in fields the model sometimes
# omits (reversible, min_score_met, justification) from the action name,
# so validation never hard-fails on missing optional metadata.
#
# ExecutedAction records what the user has already done — passed back in
# on round 2+ so the model never re-recommends completed actions.

from typing import Literal, Optional
from pydantic import BaseModel, Field, model_validator

# ─── Technical suggestion (SOC analyst layer) ─────────────────────────────────

class TechnicalSuggestion(BaseModel):
    """
    A MITRE-mapped, human-action recommendation for a SOC analyst.

    Distinct from RankedAction (automation layer): these are investigative /
    forensic steps that require a human analyst — threat hunting, log queries,
    tooling suggestions, detection engineering.
    """
    keyword: str = Field(
        description=(
            "Short technical label using SOC/DFIR vocabulary, "
            "e.g. 'T1055 – Reflective DLL Injection via VirtualAllocEx'"
        )
    )
    mitre_id: Optional[str] = Field(
        default=None,
        description="MITRE ATT&CK ID, e.g. 'T1055' or 'T1547.001'"
    )
    reasoning: str = Field(
        description=(
            "One sentence for a SOC analyst: what to look for, "
            "which tool or technique to apply, and why it matters here"
        )
    )
    priority: Literal["critical", "high", "medium"] = Field(
        default="medium",
        description="Analyst priority: critical | high | medium"
    )


# ─── Hardcoded action metadata ────────────────────────────────────────────────

# These are facts about each action, not model output — derive them here
# rather than trusting the model to fill them in correctly every time.
_ACTION_REVERSIBLE: dict[str, bool] = {
    "kill_process":      False,
    "quarantine_file":   True,
    "block_ip":          True,
    "dump_memory":       True,
    "check_persistence": True,
    "isolate_network":   True,   # re-enable via restore_network
    "remove_block_ip":   True,
}

_ACTION_CONFIRM: dict[str, bool] = {
    "kill_process":      True,
    "isolate_network":   True,
    "quarantine_file":   False,
    "block_ip":          False,
    "dump_memory":       False,
    "check_persistence": False,
    "remove_block_ip":   False,
}


class ExecutedAction(BaseModel):
    """Records one action the user already executed — passed back on round 2+."""
    action:      str                                     = Field(description="Action name, same vocabulary as RankedAction.action")
    target:      str                                     = Field(description="Human-readable target (IP, label, path)")
    entity_id:   str                                     = Field(description="entity_id from the graph at the time the action was taken")
    executed_at: Optional[str]                           = Field(default=None, description="ISO-8601 timestamp, or null")
    result:      Literal["success", "failed", "skipped"] = Field(default="success", description="Outcome reported by the Rust executor")
    pid:         Optional[int]                           = Field(default=None, description="PID if the action targeted a running process")


class RankedAction(BaseModel):
    action: str = Field(
        description=(
            "Action name: kill_process | quarantine_file | block_ip | "
            "dump_memory | check_persistence | isolate_network | remove_block_ip"
        )
    )
    target: str = Field(
        description="Human-readable target: process label, IP address, or file path"
    )
    entity_id: str = Field(
        description="entity_id from the correlate graph, e.g. 'entity:4821'"
    )
    pid: Optional[int] = Field(
        default=None,
        description="Process ID if the action targets a running process, else null"
    )
    justification: Optional[str] = Field(
        default=None,
        description="One sentence: which attack chain or pattern drove this recommendation"
    )
    # These two are derived from action name if the model omits them
    reversible: Optional[bool] = Field(
        default=None,
        description="True if the action can be undone"
    )
    min_score_met: Optional[bool] = Field(
        default=None,
        description="True if the entity's score meets the action's minimum threshold"
    )
    confirm_required: Optional[bool] = Field(
        default=None,
        description="MUST be True for kill_process and isolate_network"
    )

    @model_validator(mode="after")
    def fill_derived_fields(self) -> "RankedAction":
        """
        Always derive reversible and confirm_required from the action name —
        these are facts, not model output, so we never trust what the model sends.
        Fill justification and min_score_met only when omitted.
        """
        self.reversible       = _ACTION_REVERSIBLE.get(self.action, True)
        self.confirm_required = _ACTION_CONFIRM.get(self.action, False)
        if self.min_score_met is None:
            self.min_score_met = True
        if not self.justification:
            self.justification = f"{self.action} recommended based on graph analysis"
        return self


class AgentVerdict(BaseModel):
    ranked_actions: list[RankedAction] = Field(
        default_factory=list,
        description=(
            "3–5 containment actions ordered from most reversible to least reversible. "
            "Empty list if no attack chains were detected."
        )
    )
    rationale: str = Field(
        default="",
        description="2–4 sentences: overall threat assessment and action justification"
    )
    risk_level: Literal["Low", "Medium", "High", "Critical"] = Field(
        default="Low",
        description="Overall risk level derived from the highest-severity attack chain"
    )
    confidence: float = Field(
        default=0.0,
        ge=0.0, le=1.0,
        description="Confidence score [0, 1] derived from the highest-confidence attack chain"
    )
    pivot_suggestions: list[str] = Field(
        default_factory=list,
        description="0–3 one-sentence suggestions for targeted follow-up scans"
    )
    technical_suggestions: list[TechnicalSuggestion] = Field(
        default_factory=list,
        description=(
            "3–5 MITRE-mapped, SOC-analyst-level technical action suggestions. "
            "Each entry names a specific investigative technique (with ATT&CK ID), "
            "explains why it applies to this incident in one sentence, "
            "and is prioritised critical|high|medium. "
            "These are human-analyst steps (forensics, threat hunting, detection "
            "engineering) — not automated commands."
        )
    )
    warnings: list[str] = Field(
        default_factory=list,
        description=(
            "Non-empty only when the reasoning loop hit the iteration cap without "
            "resolving all violations. Each entry names a rule that is still violated "
            "so the UI can surface a caution indicator."
        )
    )
    # ── Level 2 fields ────────────────────────────────────────────────────────
    investigation_closed: bool = Field(
        default=False,
        description=(
            "True when the agent determines the investigation is complete: "
            "no threats remain, no improvement was detected, or max rounds hit."
        )
    )
    close_reason: Optional[str] = Field(
        default=None,
        description=(
            "Why the investigation closed. One of: 'resolved' | 'no_improvement' | "
            "'max_rounds_reached' | null (still open)."
        )
    )
    round_num: int = Field(
        default=1,
        description="Which reasoning round produced this verdict (1 = initial, 2+ = re-assessment)."
    )

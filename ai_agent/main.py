# File: ai_agent/main.py
#
# Entry point for the AI agent process.
#
# Protocol — identical to the antivirus daemon's JSON-RPC convention:
#   stdin  → one JSON line: the correlate result produced by `correlate_entities`
#   stdout → one JSON line: the AgentVerdict (or an error object)
#   stderr → diagnostic logs (never read by the Rust caller)
#
# The Rust backend (agent.rs) spawns this script as a subprocess, writes the
# correlate result JSON to its stdin, and reads the verdict from stdout.
#
# Usage:
#   python main.py                      # reads one JSON line from stdin
#   python main.py --test               # runs with a synthetic correlate result
#
# Environment:
#   OPENROUTER_API_KEY — loaded from ai_agent/.env if present, else from shell.

import json
import sys
import os

# Ensure ai_agent/ is on the import path when run as a script
sys.path.insert(0, os.path.dirname(__file__))

# Load .env from the ai_agent/ directory before importing agent modules
# so OPENROUTER_API_KEY is available when analyst.py calls os.environ.get()
try:
    from dotenv import load_dotenv
    _env_path = os.path.join(os.path.dirname(__file__), ".env")
    load_dotenv(_env_path)
except ImportError:
    pass  # python-dotenv not installed; key must be set in the shell

from agent.reasoning import refine, refine_reassess
from agent.schema import AgentVerdict


# ─── Protocol ─────────────────────────────────────────────────────────────────
#
# Round 1 (initial analysis) — input is the raw correlate result dict:
#   { "graph": { "attack_chains": [...], "nodes": [...], ... }, "statistics": {...} }
#
# Round 2+ (re-assessment after user actions) — input is a wrapper object:
#   {
#     "correlate_result":      { ... },   ← fresh re-correlate result
#     "actions_taken":         [ ... ],   ← list of ExecutedAction dicts
#     "round":                 2,         ← current round number
#     "previous_threat_score": 0.91       ← score from the previous round
#   }
#
# Distinguishing rule: if the JSON object has a "correlate_result" key it is
# the wrapper format; otherwise it is a raw Round 1 correlate result.


def run_stdin() -> None:
    """Read one JSON line from stdin, route to the correct analysis path."""
    raw = sys.stdin.readline()
    if not raw.strip():
        _write_error("Empty input — expected a JSON correlate result on stdin.")
        return

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as e:
        _write_error(f"JSON parse error: {e}")
        return

    if "correlate_result" in payload:
        # Round 2+ wrapper format
        correlate_result       = payload["correlate_result"]
        actions_taken          = payload.get("actions_taken", [])
        round_num              = int(payload.get("round", 2))
        previous_threat_score  = float(payload.get("previous_threat_score", 0.0))
        _run_and_write_reassess(correlate_result, actions_taken, round_num, previous_threat_score)
    else:
        # Round 1: raw correlate result
        _run_and_write(payload)


def _run_and_write(correlate_result: dict) -> None:
    """Round 1 — initial analysis."""
    try:
        verdict: AgentVerdict = refine(correlate_result)
        print(json.dumps(verdict.model_dump()), flush=True)
    except EnvironmentError as e:
        _write_error(str(e))
    except Exception as e:
        _write_error(f"Agent error: {e}")


def _run_and_write_reassess(
    correlate_result:      dict,
    actions_taken:         list,
    round_num:             int,
    previous_threat_score: float,
) -> None:
    """Round 2+ — re-assessment after user-executed actions."""
    try:
        verdict: AgentVerdict = refine_reassess(
            correlate_result,
            actions_taken,
            round_num,
            previous_threat_score,
        )
        print(json.dumps(verdict.model_dump()), flush=True)
    except EnvironmentError as e:
        _write_error(str(e))
    except Exception as e:
        _write_error(f"Agent reassess error: {e}")


def _write_error(message: str) -> None:
    print(json.dumps({"error": message}), flush=True)
    print(f"[agent] ERROR: {message}", file=sys.stderr)


# ─── Test mode ────────────────────────────────────────────────────────────────

SYNTHETIC_CORRELATE = {
    "graph": {
        "attack_chains": [
            {
                "chain_id":    "test-chain-1",
                "pattern":     "C2Communication",
                "mitre_tactic":"T1071 - Application Layer Protocol",
                "chain_score": 0.91,
                "confidence":  0.87,
                "severity":    "Malicious",
                "description": "'chrome.exe': active connection to a suspicious remote host",
                "node_ids":    ["entity:4821"],
            },
            {
                "chain_id":    "test-chain-2",
                "pattern":     "SuspiciousSpawn",
                "mitre_tactic":"T1059 - Command and Scripting Interpreter",
                "chain_score": 0.74,
                "confidence":  0.71,
                "severity":    "Malicious",
                "description": "'chrome.exe' spawned 'cmd.exe' — both flagged as threats",
                "node_ids":    ["entity:4821", "entity:6032"],
            },
        ],
        "critical_path": {
            "node_ids":     ["entity:4821", "entity:6032"],
            "edge_types":   ["parent_child"],
            "edge_weights": [0.82],
            "total_score":  0.82,
            "narrative":    "chrome.exe connected to 185.x.x.x:8080 and spawned cmd.exe",
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
                "has_malicious_network": True,
                "has_malicious_memory":  False,
                "has_malicious_file":    False,
                "pid":                   4821,
                "parent_pid":            1234,
                "graph_boost":           0.09,
                "is_vector":             False,
                "is_lolbin":             False,
            },
            {
                "entity_id":             "entity:6032",
                "entity_type":           "entity",
                "label":                 "cmd.exe",
                "threat_level":          "Malicious",
                "combined_score":        0.74,
                "heuristic_score":       22,
                "ml_score":              0.71,
                "process_score":         0.74,
                "network_score":         0.0,
                "memory_score":          0.0,
                "file_score":            0.0,
                "has_malicious_network": False,
                "has_malicious_memory":  False,
                "has_malicious_file":    False,
                "pid":                   6032,
                "parent_pid":            4821,
                "graph_boost":           0.04,
                "is_vector":             False,
                "is_lolbin":             True,
            },
        ],
        "edges": [
            {
                "from":      "entity:4821",
                "to":        "entity:6032",
                "edge_type": "parent_child",
                "weight":    0.82,
            }
        ],
    },
    "statistics": {
        "total_entities":         47,
        "threat_entities":         2,
        "attack_chains_detected":  2,
        "scan_duration_ms":     4821,
    },
}


SYNTHETIC_ACTIONS_TAKEN = [
    {
        "action":      "block_ip",
        "target":      "185.x.x.x:8080",
        "entity_id":   "entity:4821",
        "executed_at": "2026-05-12T14:30:22Z",
        "result":      "success",
        "pid":         None,
    }
]

# Synthetic round-2 correlate: chrome.exe still present but network score dropped
# (beaconing severed by block_ip), cmd.exe still suspicious.
SYNTHETIC_CORRELATE_R2 = {
    "graph": {
        "attack_chains": [
            {
                "chain_id":    "test-chain-2",
                "pattern":     "SuspiciousSpawn",
                "mitre_tactic":"T1059 - Command and Scripting Interpreter",
                "chain_score": 0.74,
                "confidence":  0.71,
                "severity":    "Malicious",
                "description": "'chrome.exe' spawned 'cmd.exe' — both flagged as threats",
                "node_ids":    ["entity:4821", "entity:6032"],
            },
        ],
        "critical_path": {
            "node_ids":     ["entity:4821", "entity:6032"],
            "edge_types":   ["parent_child"],
            "edge_weights": [0.72],
            "total_score":  0.72,
            "narrative":    "chrome.exe spawned cmd.exe — C2 beaconing severed, spawn chain remains",
        },
        "nodes": [
            {
                "entity_id":             "entity:4821",
                "entity_type":           "entity",
                "label":                 "chrome.exe",
                "threat_level":          "Suspicious",
                "combined_score":        0.52,
                "heuristic_score":       18,
                "ml_score":              0.55,
                "process_score":         0.45,
                "network_score":         0.10,   # dropped: beaconing severed
                "memory_score":          0.12,
                "file_score":            0.05,
                "has_malicious_network": False,
                "has_malicious_memory":  False,
                "has_malicious_file":    False,
                "pid":                   4821,
                "parent_pid":            1234,
                "graph_boost":           0.04,
                "is_vector":             False,
                "is_lolbin":             False,
            },
            {
                "entity_id":             "entity:6032",
                "entity_type":           "entity",
                "label":                 "cmd.exe",
                "threat_level":          "Malicious",
                "combined_score":        0.74,
                "heuristic_score":       22,
                "ml_score":              0.71,
                "process_score":         0.74,
                "network_score":         0.0,
                "memory_score":          0.0,
                "file_score":            0.0,
                "has_malicious_network": False,
                "has_malicious_memory":  False,
                "has_malicious_file":    False,
                "pid":                   6032,
                "parent_pid":            4821,
                "graph_boost":           0.04,
                "is_vector":             False,
                "is_lolbin":             True,
            },
        ],
        "edges": [
            {
                "from":      "entity:4821",
                "to":        "entity:6032",
                "edge_type": "parent_child",
                "weight":    0.72,
            }
        ],
    },
    "statistics": {
        "total_entities":         47,
        "threat_entities":         2,
        "attack_chains_detected":  1,
        "scan_duration_ms":     3210,
    },
}


if __name__ == "__main__":
    if "--test" in sys.argv:
        print("[agent] Running Round 1 with synthetic correlate result...", file=sys.stderr)
        _run_and_write(SYNTHETIC_CORRELATE)
    elif "--test-r2" in sys.argv:
        print("[agent] Running Round 2 re-assessment with synthetic data...", file=sys.stderr)
        _run_and_write_reassess(
            SYNTHETIC_CORRELATE_R2,
            SYNTHETIC_ACTIONS_TAKEN,
            round_num=2,
            previous_threat_score=1.65,  # 0.91 + 0.74 from Round 1
        )
    else:
        run_stdin()

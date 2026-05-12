// File: UI/src-tauri/src/agent.rs
//
// Rust side of the AI agent bridge.
//
// Responsibility: spawn the Python LangChain agent as a subprocess, feed it
// the correlate result via stdin, and read the AgentVerdict from stdout.
//
// The actual reasoning logic lives in:
//   ai_agent/main.py          ← entry point (stdin/stdout JSON-RPC)
//   ai_agent/agent/analyst.py ← LangChain chain
//   ai_agent/agent/prompt.py  ← prompt builder
//   ai_agent/agent/schema.py  ← Pydantic output schema
//
// Protocol (same as the antivirus daemon):
//   stdin  → one JSON line: the correlate result
//   stdout → one JSON line: AgentVerdict | { "error": "..." }
//   stderr → diagnostic logs (printed to Tauri stderr, never parsed)
//
// The ANTHROPIC_API_KEY env var is forwarded to the child process automatically
// because `std::process::Command` inherits the parent's environment by default.

use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

// ─── Output types (mirrors ai_agent/agent/schema.py) ─────────────────────────

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

/// Records one action the user already executed — sent back on round 2+ so
/// the model never re-recommends completed actions.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ExecutedAction {
    pub action:      String,
    pub target:      String,
    pub entity_id:   String,
    pub executed_at: Option<String>,
    pub result:      String, // "success" | "failed" | "skipped"
    pub pid:         Option<u32>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AgentVerdict {
    pub ranked_actions:       Vec<RankedAction>,
    pub rationale:            String,
    pub risk_level:           String,
    pub confidence:           f32,
    pub pivot_suggestions:    Vec<String>,
    #[serde(default)]
    pub warnings:             Vec<String>,
    // Level 2 fields
    #[serde(default)]
    pub investigation_closed: bool,
    pub close_reason:         Option<String>,
    #[serde(default = "default_round")]
    pub round_num:            u32,
}

fn default_round() -> u32 { 1 }

// ─── Python script locator ────────────────────────────────────────────────────

/// Resolve the absolute path to ai_agent/main.py.
///
/// Expected layout (relative to the Tauri project root UI/):
///   UI/src-tauri/src/agent.rs   ← this file
///   ai_agent/main.py            ← two levels up from UI/
///
/// At runtime the binary lives at UI/src-tauri/target/{profile}/aegisai-ui.exe.
/// Walking up: target/{profile}/ → target/ → src-tauri/ → UI/ → project root.
fn find_agent_script() -> Option<PathBuf> {
    // Collect every candidate root directory we might be running from.
    // In Tauri dev mode current_exe() can point to a temp runner, so we
    // try multiple strategies and return the first path where the file exists.

    let mut roots: Vec<PathBuf> = Vec::new();

    // Strategy 1: walk up from the executable (release / normal dev builds)
    // exe = .../UI/src-tauri/target/{profile}/aegisai-ui.exe
    //   → 4× parent = UI/  → 1× parent = AegisAI/
    if let Ok(exe) = std::env::current_exe() {
        let mut p = exe.as_path();
        for _ in 0..5 {
            if let Some(parent) = p.parent() {
                roots.push(parent.to_path_buf());
                p = parent;
            }
        }
    }

    // Strategy 2: walk up from the current working directory
    // In `tauri dev` the cwd is UI/, so one level up = AegisAI/
    if let Ok(cwd) = std::env::current_dir() {
        let mut p = cwd.clone();
        for _ in 0..5 {
            roots.push(p.clone());
            if let Some(parent) = p.parent() {
                p = parent.to_path_buf();
            }
        }
    }

    // Return the first root where ai_agent/main.py actually exists
    for root in &roots {
        let candidate = root.join("ai_agent").join("main.py");
        if candidate.exists() {
            return Some(candidate);
        }
    }

    None
}

/// Resolve the venv Python inside ai_agent/.venv/.
///
/// Prefers the isolated venv (no global-env conflicts) over any system Python.
/// Falls back to the system interpreter if the venv doesn't exist yet.
fn find_python(project_root: &std::path::Path) -> Option<PathBuf> {
    // venv Python locations
    let candidates = [
        project_root.join("ai_agent").join(".venv").join("Scripts").join("python.exe"), // Windows
        project_root.join("ai_agent").join(".venv").join("bin").join("python"),          // Unix
        project_root.join("ai_agent").join(".venv").join("bin").join("python3"),
    ];
    for path in &candidates {
        if path.exists() {
            return Some(path.clone());
        }
    }
    // Fall back to system Python
    for py in &["python", "python3", "py"] {
        if Command::new(py).arg("--version").output().is_ok() {
            return Some(PathBuf::from(py));
        }
    }
    None
}

// ─── Entry point ──────────────────────────────────────────────────────────────

// ─── Shared subprocess helper ─────────────────────────────────────────────────

/// Spawn the Python agent, write `input_json` to stdin, collect stdout.
///
/// Returns the raw JSON string from the agent's stdout line.
fn call_agent(input_json: &str) -> Result<String, String> {
    let script = find_agent_script()
        .ok_or_else(|| {
            let cwd = std::env::current_dir()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "<unknown>".into());
            let exe = std::env::current_exe()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "<unknown>".into());
            format!(
                "Cannot find ai_agent/main.py.\ncwd = {cwd}\nexe = {exe}\n\
                 Make sure ai_agent/ exists at the AegisAI project root."
            )
        })?;

    let project_root = script
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));

    let python = find_python(&project_root).ok_or_else(|| {
        "Python interpreter not found. \
         Run: python -m venv ai_agent/.venv && \
         ai_agent/.venv/Scripts/pip install -r ai_agent/requirements.txt"
            .to_string()
    })?;

    let mut child = Command::new(python)
        .arg(script.to_str().unwrap_or("ai_agent/main.py"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("Failed to spawn Python agent: {e}"))?;

    if let Some(stdin) = child.stdin.as_mut() {
        stdin.write_all(input_json.as_bytes())
            .map_err(|e| format!("Failed to write to agent stdin: {e}"))?;
        stdin.write_all(b"\n")
            .map_err(|e| format!("Failed to write newline to agent stdin: {e}"))?;
    }

    let output = child
        .wait_with_output()
        .map_err(|e| format!("Agent process error: {e}"))?;

    if !output.status.success() {
        return Err(format!("Python agent exited with status {}", output.status));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stdout = stdout.trim().to_string();

    if stdout.is_empty() {
        return Err("Python agent produced no output.".to_string());
    }

    Ok(stdout)
}

fn parse_verdict(stdout: &str) -> Result<AgentVerdict, String> {
    let raw: serde_json::Value = serde_json::from_str(stdout)
        .map_err(|e| format!("Failed to parse agent output as JSON: {e}\nOutput: {stdout}"))?;

    if let Some(err) = raw["error"].as_str() {
        return Err(format!("Agent returned an error: {err}"));
    }

    serde_json::from_value::<AgentVerdict>(raw)
        .map_err(|e| format!("Failed to deserialise AgentVerdict: {e}\nOutput: {stdout}"))
}


// ─── Entry points ─────────────────────────────────────────────────────────────

/// Full Round 1 pipeline: correlate_result → AgentVerdict.
///
/// Spawns `python ai_agent/main.py`, writes the correlate result JSON to its
/// stdin, reads the verdict JSON from stdout, deserialises into AgentVerdict.
pub async fn run_analysis(correlate_result: &serde_json::Value) -> Result<AgentVerdict, String> {
    // Round 1: pass the raw correlate result directly (no wrapper).
    // Python's main.py recognises it by the absence of a "correlate_result" key.
    let input_json = serde_json::to_string(correlate_result)
        .map_err(|e| format!("Failed to serialise correlate result: {e}"))?;

    let stdout = call_agent(&input_json)?;
    parse_verdict(&stdout)
}

/// Round 2+ pipeline: re-assess after user-executed containment actions.
///
/// Wraps `correlate_result` + `actions_taken` + metadata into the protocol
/// envelope that `main.py` recognises as a re-assessment request.
///
/// `previous_threat_score` is the sum of `combined_score` over all
/// Malicious/Critical entities from the *previous* round — used by the
/// Python monotonicity guard.
pub async fn run_reassessment(
    correlate_result:      &serde_json::Value,
    actions_taken:         &[serde_json::Value],
    round_num:             u32,
    previous_threat_score: f64,
) -> Result<AgentVerdict, String> {
    let envelope = serde_json::json!({
        "correlate_result":      correlate_result,
        "actions_taken":         actions_taken,
        "round":                 round_num,
        "previous_threat_score": previous_threat_score,
    });

    let input_json = serde_json::to_string(&envelope)
        .map_err(|e| format!("Failed to serialise reassessment envelope: {e}"))?;

    let stdout = call_agent(&input_json)?;
    parse_verdict(&stdout)
}

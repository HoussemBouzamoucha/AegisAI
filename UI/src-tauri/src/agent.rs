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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AgentVerdict {
    pub ranked_actions:    Vec<RankedAction>,
    pub rationale:         String,
    pub risk_level:        String,
    pub confidence:        f32,
    pub pivot_suggestions: Vec<String>,
}

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

/// Full Round 1 pipeline: correlate_result → AgentVerdict.
///
/// Spawns `python ai_agent/main.py`, writes the correlate result JSON to its
/// stdin, reads the verdict JSON from stdout, deserialises into AgentVerdict.
pub async fn run_analysis(correlate_result: &serde_json::Value) -> Result<AgentVerdict, String> {
    let script = find_agent_script()
        .ok_or_else(|| {
            let cwd = std::env::current_dir()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "<unknown>".into());
            let exe = std::env::current_exe()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "<unknown>".into());
            format!(
                "Cannot find ai_agent/main.py.\n\
                 cwd = {cwd}\n\
                 exe = {exe}\n\
                 Make sure ai_agent/ exists at the AegisAI project root."
            )
        })?;

    // project_root is the parent of ai_agent/
    let project_root = script
        .parent() // ai_agent/
        .and_then(|p| p.parent()) // AegisAI/
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));

    let python = find_python(&project_root)
        .ok_or_else(|| {
            "Python interpreter not found. \
             Run: python -m venv ai_agent/.venv && ai_agent/.venv/Scripts/pip install -r ai_agent/requirements.txt".to_string()
        })?;

    // The Python agent loads OPENROUTER_API_KEY from ai_agent/.env via python-dotenv,
    // so we only hard-fail here if neither the shell env nor the .env file provides it.
    // The Python process will emit a clear error on stdout if the key is missing.

    // Serialise the correlate result to a single JSON line
    let input_json = serde_json::to_string(correlate_result)
        .map_err(|e| format!("Failed to serialise correlate result: {e}"))?;

    // Spawn the Python agent
    let mut child = Command::new(python)
        .arg(script.to_str().unwrap_or("ai_agent/main.py"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit()) // let Python logs appear in Tauri stderr
        .spawn()
        .map_err(|e| format!("Failed to spawn Python agent: {e}"))?;

    // Write correlate result to stdin
    if let Some(stdin) = child.stdin.as_mut() {
        stdin
            .write_all(input_json.as_bytes())
            .map_err(|e| format!("Failed to write to agent stdin: {e}"))?;
        stdin
            .write_all(b"\n")
            .map_err(|e| format!("Failed to write newline to agent stdin: {e}"))?;
    }

    // Wait for the process and collect stdout
    let output = child
        .wait_with_output()
        .map_err(|e| format!("Agent process error: {e}"))?;

    if !output.status.success() {
        return Err(format!(
            "Python agent exited with status {}",
            output.status
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stdout = stdout.trim();

    if stdout.is_empty() {
        return Err("Python agent produced no output.".to_string());
    }

    // Check for error response from the Python side
    let raw: serde_json::Value = serde_json::from_str(stdout)
        .map_err(|e| format!("Failed to parse agent output as JSON: {e}\nOutput: {stdout}"))?;

    if let Some(err) = raw["error"].as_str() {
        return Err(format!("Agent returned an error: {err}"));
    }

    // Deserialise into AgentVerdict
    serde_json::from_value::<AgentVerdict>(raw)
        .map_err(|e| format!("Failed to deserialise AgentVerdict: {e}\nOutput: {stdout}"))
}

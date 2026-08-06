// File: src/core/process/API_feature_extractor.rs
//
// Bridges live Windows API call telemetry → ML features → graph edge signals.
//
// Pipeline:
//   1. Ingest ApiCall events from an ETW consumer or usermode hook.
//   2. Maintain a per-process ring buffer (latest BUFFER_CAPACITY calls).
//   3. On demand, extract:
//        a) API name sequence  →  GRU-Attention model (Python subprocess)
//        b) Edge signals       →  injection / C2 / spawn / file patterns
//        c) Category histogram →  auxiliary feature vector
//   4. Return ApiFeatures which carries both the ML score (ml_score feeds
//      into GraphNode::ml_score) and the detected edge types with multipliers.
//
// NOTE: This extractor requires a live ETW (Event Tracing for Windows) provider
// to supply `ApiCall` events.  That provider is not yet integrated into the
// daemon.  Suppress dead-code warnings until the ETW consumer lands.
#![allow(dead_code)]

use std::collections::{HashMap, VecDeque};
use std::io::Write;
use std::process::{Command, Stdio};

use super::api_parameters::{
    ApiCall, ApiCategory, ApiKnowledgeBase, EdgeSignal, ParsedTarget,
};

// ─── Constants ────────────────────────────────────────────────────────────────

/// Maximum API calls kept per process in the ring buffer.
/// Covers the GRU sliding-window (MAX_LEN=177, STRIDE=100) across ~5 chunks.
const BUFFER_CAPACITY: usize = 512;

// ─── Output types ─────────────────────────────────────────────────────────────

/// One detected graph-edge signal, ready to be applied as an edge multiplier
/// on the `GraphEdge` connecting the calling process to its target entity.
#[derive(Debug, Clone)]
pub struct DetectedEdgeSignal {
    /// The graph edge relationship this observation implies.
    pub edge_type: EdgeSignal,
    /// Weight multiplier to apply to the edge (from EdgeSignal::multiplier()).
    pub multiplier: f32,
    /// API calls that triggered this signal (names only, for reporting).
    pub trigger_apis: Vec<String>,
    /// Resolved target — the entity on the other end of the edge.
    pub target: ParsedTarget,
}

/// Result returned by the Python GRU-Attention model.
#[derive(Debug, Clone)]
pub struct GruPrediction {
    /// Sigmoid malware probability in [0, 1].
    pub probability: f32,
    /// Binary label at the configured threshold (1 = malware, 0 = benign).
    pub label: u8,
    /// Human-readable verdict from the model.
    pub verdict: String,
    /// Top-10 (api_name, attention_weight) pairs explaining the decision.
    pub top_apis: Vec<(String, f32)>,
    /// Which sliding-window chunk scored highest (for long sequences).
    pub trigger_chunk: Option<u32>,
}

/// Full feature set extracted for one process.
///
/// Consumers:
///   - `GraphNode::ml_score`   ← `gru.as_ref().map(|g| g.probability)`
///   - `GraphEdge::weight`     ← multiplied by `detected_edges[i].multiplier`
///   - ML pipeline extras      ← `category_counts`, `heuristic_injection_score`
#[derive(Debug, Clone)]
pub struct ApiFeatures {
    pub pid: u32,
    /// Ordered API names — the exact sequence fed to the GRU model.
    pub sequence: Vec<String>,
    /// GRU model output (None if inference failed or sequence too short).
    pub gru: Option<GruPrediction>,
    /// Edge signals detected from API call patterns.
    pub detected_edges: Vec<DetectedEdgeSignal>,
    /// Count of calls per semantic category.
    pub category_counts: HashMap<ApiCategory, u32>,
    /// Classic 4-step injection pattern detected in the buffer.
    /// (OpenProcess → VirtualAllocEx → WriteProcessMemory → CreateRemoteThread)
    pub injection_sequence_detected: bool,
    /// C2 communication tri-pattern detected.
    /// (connect → send → recv)
    pub c2_sequence_detected: bool,
    /// Aggregate heuristic injection score: sum of threat_weight over all
    /// cross-process memory/thread API calls, clamped to [0, 1].
    pub heuristic_injection_score: f32,
}

// ─── Extractor ────────────────────────────────────────────────────────────────

/// Configuration for the Python GRU inference subprocess.
#[derive(Debug, Clone)]
pub struct GruConfig {
    /// Python executable to invoke ("python", "python3", "py", …).
    pub python_exec: String,
    /// Directory that contains `inference.py` (and the `GRU_API/` subfolder).
    pub inference_dir: String,
}

impl Default for GruConfig {
    fn default() -> Self {
        Self {
            python_exec:   "python".to_string(),
            inference_dir: "./Sys_API".to_string(),
        }
    }
}

/// Main feature extractor.
///
/// Create one instance per engine session.
/// Call `ingest_call()` from your ETW consumer / hook callback.
/// Call `extract_features(pid)` whenever you need an updated assessment.
pub struct ApiFeatureExtractor {
    kb:      ApiKnowledgeBase,
    buffers: HashMap<u32, VecDeque<ApiCall>>,
    gru_cfg: GruConfig,
}

impl ApiFeatureExtractor {
    pub fn new(gru_cfg: GruConfig) -> Self {
        Self {
            kb:      ApiKnowledgeBase::new(),
            buffers: HashMap::new(),
            gru_cfg,
        }
    }

    // ── Ingestion ──────────────────────────────────────────────────────────────

    /// Add one observed API call to the process's ring buffer.
    ///
    /// Call this from your ETW provider callback or hook dispatcher.
    /// Thread-safe usage requires external locking (e.g. `Mutex<ApiFeatureExtractor>`).
    pub fn ingest_call(&mut self, call: ApiCall) {
        let buf = self.buffers
            .entry(call.pid)
            .or_insert_with(|| VecDeque::with_capacity(BUFFER_CAPACITY));

        if buf.len() == BUFFER_CAPACITY {
            buf.pop_front();
        }
        buf.push_back(call);
    }

    /// Remove all buffered data for a process (call on process exit).
    pub fn evict(&mut self, pid: u32) {
        self.buffers.remove(&pid);
    }

    // ── Sequence builder ───────────────────────────────────────────────────────

    /// Ordered list of API names for a PID — direct input to `predict_process()`.
    pub fn build_sequence(&self, pid: u32) -> Vec<String> {
        self.buffers
            .get(&pid)
            .map(|buf| buf.iter().map(|c| c.name.clone()).collect())
            .unwrap_or_default()
    }

    // ── Feature extraction ─────────────────────────────────────────────────────

    /// Full feature extraction for one process.
    ///
    /// Returns `None` only if no API calls have been ingested for this PID yet.
    pub fn extract_features(&mut self, pid: u32) -> Option<ApiFeatures> {
        let calls: Vec<ApiCall> = self.buffers.get(&pid)?.iter().cloned().collect();
        if calls.is_empty() {
            return None;
        }

        let sequence                    = calls.iter().map(|c| c.name.clone()).collect::<Vec<_>>();
        let category_counts             = self.build_category_counts(&calls);
        let heuristic_injection_score   = self.compute_injection_score(&calls);
        let injection_sequence_detected = self.detect_injection_sequence(&calls);
        let c2_sequence_detected        = self.detect_c2_sequence(&calls);
        let detected_edges              = self.classify_edge_signals(&calls);
        let gru                         = self.run_gru_inference(&sequence);

        Some(ApiFeatures {
            pid,
            sequence,
            gru,
            detected_edges,
            category_counts,
            injection_sequence_detected,
            c2_sequence_detected,
            heuristic_injection_score,
        })
    }

    // ── Category histogram ─────────────────────────────────────────────────────

    fn build_category_counts(&self, calls: &[ApiCall]) -> HashMap<ApiCategory, u32> {
        let mut counts: HashMap<ApiCategory, u32> = HashMap::new();
        for call in calls {
            let cat = self.kb.get(&call.name)
                .map(|s| s.category.clone())
                .unwrap_or(ApiCategory::Unknown);
            *counts.entry(cat).or_insert(0) += 1;
        }
        counts
    }

    // ── Heuristic injection score ──────────────────────────────────────────────

    fn compute_injection_score(&self, calls: &[ApiCall]) -> f32 {
        let raw: f32 = calls.iter()
            .filter(|c| matches!(self.kb.edge_signal_for(&c.name), EdgeSignal::MemoryInjection))
            .map(|c| self.kb.threat_weight_for(&c.name))
            .sum();
        raw.min(1.0)
    }

    // ── Pattern detection ──────────────────────────────────────────────────────

    /// Classic 4-step process-injection chain (must all appear, in buffer order):
    ///   Step 1 — process handle acquisition:
    ///              OpenProcess | NtOpenProcess
    ///   Step 2 — remote memory allocation:
    ///              VirtualAllocEx | NtAllocateVirtualMemory
    ///   Step 3 — payload write:
    ///              WriteProcessMemory | NtWriteVirtualMemory
    ///   Step 4 — remote execution trigger:
    ///              CreateRemoteThread | NtCreateThreadEx |
    ///              RtlCreateUserThread | NtQueueApcThread | SetThreadContext
    pub fn detect_injection_sequence(&self, calls: &[ApiCall]) -> bool {
        let names: Vec<&str> = calls.iter().map(|c| c.name.as_str()).collect();

        let step1 = names.iter().any(|n| matches!(*n,
            "OpenProcess" | "NtOpenProcess"));
        let step2 = names.iter().any(|n| matches!(*n,
            "VirtualAllocEx" | "NtAllocateVirtualMemory"));
        let step3 = names.iter().any(|n| matches!(*n,
            "WriteProcessMemory" | "NtWriteVirtualMemory"));
        let step4 = names.iter().any(|n| matches!(*n,
            "CreateRemoteThread" | "NtCreateThreadEx" |
            "RtlCreateUserThread" | "NtQueueApcThread" | "SetThreadContext"));

        step1 && step2 && step3 && step4
    }

    /// C2 communication tri-pattern:
    ///   Phase 1 — connection setup:
    ///              connect | WSAConnect | InternetConnectA | InternetConnectW
    ///   Phase 2 — data exfiltration / beaconing:
    ///              send | WSASend | HttpSendRequestA | HttpSendRequestW
    ///   Phase 3 — command receive:
    ///              recv | WSARecv
    pub fn detect_c2_sequence(&self, calls: &[ApiCall]) -> bool {
        let names: Vec<&str> = calls.iter().map(|c| c.name.as_str()).collect();

        let phase1 = names.iter().any(|n| matches!(*n,
            "connect" | "WSAConnect" | "InternetConnectA" | "InternetConnectW"));
        let phase2 = names.iter().any(|n| matches!(*n,
            "send" | "WSASend" | "HttpSendRequestA" | "HttpSendRequestW"));
        let phase3 = names.iter().any(|n| matches!(*n, "recv" | "WSARecv"));

        phase1 && phase2 && phase3
    }

    // ── Edge signal classification ─────────────────────────────────────────────

    /// Map the call buffer to a deduplicated list of `DetectedEdgeSignal` values.
    ///
    /// Groups calls by (EdgeSignal, resolved-target) so each unique relationship
    /// is emitted once, carrying all the API names that contributed to it.
    ///
    /// Downstream: `GraphBuilder` multiplies `GraphEdge::weight` by
    /// `DetectedEdgeSignal::multiplier` when it finds the matching edge.
    pub fn classify_edge_signals(&self, calls: &[ApiCall]) -> Vec<DetectedEdgeSignal> {
        // key = (edge_signal_str, target_entity_key)
        let mut groups:     HashMap<(String, String), Vec<String>>  = HashMap::new();
        let mut target_map: HashMap<(String, String), ParsedTarget> = HashMap::new();

        for call in calls {
            let signal = self.kb.edge_signal_for(&call.name);
            if signal == EdgeSignal::None {
                continue;
            }
            let target  = self.kb.resolve_target(call);
            let sig_key = signal.to_str().to_string();
            let tgt_key = match &target {
                ParsedTarget::ProcessId(pid)               => format!("pid:{}", pid),
                ParsedTarget::FilePath(p)                  => format!("file:{}", p),
                ParsedTarget::NetworkEndpoint { ip, port } => format!("net:{}:{}", ip, port),
                ParsedTarget::MemoryAddress(a)             => format!("addr:{:#x}", a),
                ParsedTarget::None                         => "unknown".to_string(),
            };
            let key = (sig_key, tgt_key);
            groups.entry(key.clone()).or_default().push(call.name.clone());
            target_map.entry(key).or_insert(target);
        }

        groups.into_iter().map(|(key, trigger_apis)| {
            let edge_type  = signal_from_str(&key.0);
            let multiplier = edge_type.multiplier();
            let target     = target_map.remove(&key).unwrap_or(ParsedTarget::None);
            DetectedEdgeSignal { edge_type, multiplier, trigger_apis, target }
        }).collect()
    }

    // ── GRU inference ──────────────────────────────────────────────────────────

    /// Invoke the Python GRU-Attention model as a subprocess.
    ///
    /// Serialises `sequence` to JSON on stdin; reads the JSON prediction from
    /// stdout.  Returns `None` on any failure so callers fall back gracefully
    /// to the heuristic score.
    ///
    /// The Python command executed:
    /// ```text
    /// python -c "
    ///   import json, sys
    ///   sys.path.insert(0, '<inference_dir>')
    ///   from inference import predict_process
    ///   calls = json.loads(sys.stdin.read())
    ///   r = predict_process(calls)
    ///   r['top_api_calls'] = [(a, float(w)) for a, w in r.get('top_api_calls', [])]
    ///   print(json.dumps(r))
    /// "
    /// ```
    pub fn run_gru_inference(&self, sequence: &[String]) -> Option<GruPrediction> {
        let inline = format!(
            "import json, sys; \
             sys.path.insert(0, '{dir}'); \
             from inference import predict_process; \
             calls = json.loads(sys.stdin.read()); \
             r = predict_process(calls); \
             r['top_api_calls'] = [(a, float(w)) for a, w in r.get('top_api_calls', [])]; \
             print(json.dumps(r))",
            dir = self.gru_cfg.inference_dir.replace('\\', "/"),
        );

        let input_json = serde_json::to_string(sequence).ok()?;

        let mut child = Command::new(&self.gru_cfg.python_exec)
            .args(["-c", &inline])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;

        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(input_json.as_bytes());
        }

        let output = child.wait_with_output().ok()?;
        if !output.status.success() {
            return None;
        }

        let stdout = std::str::from_utf8(&output.stdout).ok()?.trim();
        let v: serde_json::Value = serde_json::from_str(stdout).ok()?;

        let probability   = v["probability"].as_f64()? as f32;
        let label         = v["label"].as_u64()? as u8;
        let verdict       = v["verdict"].as_str().unwrap_or("UNKNOWN").to_string();
        let trigger_chunk = v["trigger_chunk"].as_u64().map(|c| c as u32);

        let top_apis: Vec<(String, f32)> = v["top_api_calls"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|e| {
                let arr  = e.as_array()?;
                let name = arr.first()?.as_str()?.to_string();
                let w    = arr.get(1)?.as_f64()? as f32;
                Some((name, w))
            })
            .collect();

        Some(GruPrediction { probability, label, verdict, top_apis, trigger_chunk })
    }

    // ── Combined score helper ──────────────────────────────────────────────────

    /// Compute the final combined score to store in `GraphNode::ml_score`.
    ///
    /// Mirrors the entity-layer formula:
    ///   combined = 0.40 × (heuristic_score / 40.0) + 0.60 × gru_probability
    ///
    /// Falls back to heuristic-only when GRU is unavailable.
    pub fn combined_score(features: &ApiFeatures, heuristic_score: i32) -> f32 {
        let h = (heuristic_score as f32 / 40.0).clamp(0.0, 1.0);
        match &features.gru {
            Some(g) => 0.40 * h + 0.60 * g.probability,
            None    => h,
        }
    }
}

// ─── Internal helper ──────────────────────────────────────────────────────────

fn signal_from_str(s: &str) -> EdgeSignal {
    match s {
        "memory_injection"    => EdgeSignal::MemoryInjection,
        "network_owner"       => EdgeSignal::NetworkOwner,
        "shared_c2"           => EdgeSignal::SharedC2,
        "process_opened_file" => EdgeSignal::ProcessOpenedFile,
        "parent_child"        => EdgeSignal::ParentChild,
        "same_process"        => EdgeSignal::SameProcess,
        "shared_file_hash"    => EdgeSignal::SharedFileHash,
        _                     => EdgeSignal::None,
    }
}

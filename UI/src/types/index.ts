// src/types/index.ts

// ─────────────────────────────────────────────────────────────────────────────
// Core Threat Types
// ─────────────────────────────────────────────────────────────────────────────

export type ThreatLevel = 'Clean' | 'Suspicious' | 'Malicious';
export type ProcessThreat = 'Safe' | 'Suspicious' | 'Malicious' | 'Critical';
export type View = 'dashboard' | 'scanner' | 'processes' | 'network' | 'memory' | 'history' | 'entities' | 'graph' | 'verdict' | 'quarantine';

// ─────────────────────────────────────────────────────────────────────────────
// File Classification
// ─────────────────────────────────────────────────────────────────────────────

export type FileCategory =
  | 'executable'
  | 'script'
  | 'document'
  | 'archive'
  | 'macro_enabled'
  | 'unknown';

// ─────────────────────────────────────────────────────────────────────────────
// Context Flags (Ransomware Intelligence)
// ─────────────────────────────────────────────────────────────────────────────

export type ContextFlag =
  | 'ransom_note_nearby'
  | 'multiple_ransom_notes'
  | 'ransomware_extension'
  | 'mass_modification_detected'
  | 'encrypted_copy_detected'
  | 'yara_ransomware_correlated'
  | 'yara_filename_correlated'
  | 'high_ransomware_extension_ratio';

// ─────────────────────────────────────────────────────────────────────────────
// Shared Detection Signal
// ─────────────────────────────────────────────────────────────────────────────

export interface DetectionSignal {
  source: string;       // "path" | "name" | "cmdline" | "resource" | "handle" | "module"
  description: string;
  score: number;
}

// ─────────────────────────────────────────────────────────────────────────────
// File Scan Types
// ─────────────────────────────────────────────────────────────────────────────

export interface ScanResult {
  path: string;
  level: ThreatLevel;
  reason: string;
  hash?: string;
  signature?: string;
  is_threat: boolean;
  success: boolean;
  confidence_score: number;
  detection_signals: DetectionSignal[];
  file_category: FileCategory;
  context_flags: ContextFlag[];
}

export interface ScanStats {
  total_files: number;
  clean_files: number;
  suspicious_files: number;
  malicious_files: number;
  error_files: number;
  total_size_mb: number;
}

export interface ScanOutput {
  success: boolean;
  files: ScanResult[];
  statistics: ScanStats;
  error?: string;
}

export interface DirectoryScanResult {
  success: boolean;
  statistics: ScanStats;
  files: ScanResult[];
  error?: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// Process Scan Types (UPDATED)
// ─────────────────────────────────────────────────────────────────────────────

export interface ProcessInfo {
  // Core metadata
  pid: number;
  name: string;
  parent_pid: number | null;
  exe_path: string | null;
  command_line: string | null;
  status: string;

  // Resources
  cpu_usage: number;
  memory_mb: string;          // formatted string from backend
  memory_bytes: number;
  virtual_memory_mb: string;
  thread_count: number;
  start_time: number | null;
  user: string | null;

  // Windows / advanced inspection
  handle_count: number | null;
  module_count: number | null;

  // Threat scoring
  threat_level: ProcessThreat;
  threat_score: number;
  is_threat: boolean;
  detection_signals: DetectionSignal[];

  // Heuristic flags (VERY IMPORTANT for UI badges)
  anomaly_flags: string[]; // ["hollow", "packed", "temp_dir", ...]
}

export interface ProcessStats {
  total_processes: number;
  safe_processes: number;
  suspicious_processes: number;
  malicious_processes: number;
  critical_processes: number;
  total_memory_mb: string;
  total_threads: number;
  avg_cpu_usage: string;
  scan_duration_ms: number;
}

export interface ProcessScanResult {
  success: boolean;
  statistics: ProcessStats;
  processes: ProcessInfo[];
  error?: string;
}

export interface NetworkConnection {
  protocol: string;
  local_address: string;
  remote_address: string;
  state: string;
  pid: number | null;
  process_name: string | null;
  threat_level: ThreatLevel;
  threat_score: number;
  is_threat: boolean;
  detection_signals: DetectionSignal[];
}

export interface NetworkStats {
  total_connections: number;
  suspicious_connections: number;
  malicious_connections: number;
  local_listeners: number;
  established_connections: number;
  scan_duration_ms: number;
}

export interface NetworkScanResult {
  success: boolean;
  statistics: NetworkStats;
  connections: NetworkConnection[];
  error?: string;
}

export interface MemoryRegion {
  pid: number;
  process_name: string;
  process_path: string | null;
  command_line: string | null;
  region_start: number;
  region_size: number;
  protection: string;
  is_executable: boolean;
  is_writable: boolean;
  is_readable: boolean;
  is_committed: boolean;
  is_private: boolean;
  content_sample?: string | null;
  threat_level: ThreatLevel;
  threat_score: number;
  is_threat: boolean;
  detection_signals: DetectionSignal[];
}

export interface MemoryStats {
  total_regions: number;
  scanned_processes: number;
  suspicious_regions: number;
  malicious_regions: number;
  total_bytes_scanned: number;
  scan_duration_ms: number;
}

export interface MemoryScanResult {
  success: boolean;
  statistics: MemoryStats;
  regions: MemoryRegion[];
  error?: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// History
// ─────────────────────────────────────────────────────────────────────────────

export interface ScanHistoryEntry {
  id: string;
  timestamp: Date;
  path: string;
  type: 'file' | 'directory' | 'full-scan' | 'quick-scan';
  stats: {
    total: number;
    clean: number;
    suspicious: number;
    malicious: number;
  };
  durationMs: number;
}

// ─────────────────────────────────────────────────────────────────────────────
// ML IDS Types
// ─────────────────────────────────────────────────────────────────────────────

export interface MlFlowResult {
  srcip: string;
  dstip: string;
  sport: number;
  dsport: number;
  proto: string;
  is_ipv6: boolean;
  prediction: 'Clean' | 'Suspicious' | 'Malicious';
  probability: number;
  reasons: string[];
  src_host?: string;
  dst_host?: string;
  src_service?: string;
  dst_service?: string;
}

export interface MlIdsSummary {
  total_flows: number;
  clean_flows: number;
  suspicious_flows: number;
  malicious_flows: number;
  malicious_rate: number;
}

export interface MlIdsResult {
  success: boolean;
  summary: MlIdsSummary;
  flows: MlFlowResult[];
  error?: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// Entity / Graph / Correlate Types  (Step 3 — backend entity pipeline)
// ─────────────────────────────────────────────────────────────────────────────

export type UnifiedThreat = 'Clean' | 'Suspicious' | 'Malicious' | 'Critical';
/** "entity" = aggregated composite node; legacy flat values kept for backward compat */
export type EntityKind    = 'entity' | 'process' | 'file' | 'network' | 'memory';
/** Inter-entity edges (aggregated graph): parent_child | shared_c2 | shared_file_hash.
 *  Legacy intra-entity edges still accepted for backward compat. */
export type EdgeKind =
  | 'parent_child' | 'shared_c2' | 'shared_file_hash'
  | 'same_process' | 'process_opened_file' | 'network_owner' | 'memory_injection'
  | 'cross_injection';

// ─────────────────────────────────────────────────────────────────────────────
// Unified Process Entity  (one atom per process — all owned evidence embedded)
// ─────────────────────────────────────────────────────────────────────────────

export interface ProcessEntity {
  entity_id:     string;            // "proc:{pid}"
  pid:           number;
  name:          string;
  exe_path:      string | null;
  command_line:  string | null;
  parent_pid:    number | null;
  user:          string | null;

  threat_level:   UnifiedThreat;
  combined_score: number;           // max(sub-scores) blended with ML when available

  // Per-domain sub-scores (each in [0,1])
  process_score:  number;           // process heuristic / 30
  network_score:  number;           // max network heuristic / 40
  memory_score:   number;           // max memory heuristic / 40
  file_score:     number;           // max file confidence_score

  // Owned sub-entities (by PID or exe_path match)
  network:        NetworkConnection[];
  memory:         MemoryRegion[];
  files:          ScanResult[];

  // Merged from all sub-entities
  detection_signals: DetectionSignal[];
  anomaly_flags:     string[];

  ml_score?:      number;           // max GRU probability from owned connections
  raw:            ProcessInfo;      // original process record
}

export type AttackPatternName =
  | 'ProcessInjection' | 'C2Communication' | 'MalwareExecution'
  | 'LateralMovement'  | 'MultiStageAttack' | 'SuspiciousSpawn'
  | 'ExploitedTrustedProcess';

export interface EntityJoinKeys {
  pid?:        number;
  parent_pid?: number;
  file_path?:  string;
  file_hash?:  string;
  remote_ip?:  string;
  remote_port?: number;
}

export interface CorrelateEntityNode {
  entity_id:         string;
  entity_type:       EntityKind;
  threat_level:      UnifiedThreat;
  combined_score:    number;
  heuristic_score:   number;
  ml_score?:         number;
  join_keys:         EntityJoinKeys;
  detection_signals: DetectionSignal[];
  label:             string;
  sub_label?:        string;
}

export interface JoinReason {
  type:        'SharedPid' | 'ParentChildChain' | 'SharedRemoteIp' | 'SharedFileHash';
  pid?:        number;
  parent_pid?: number;
  child_pid?:  number;
  ip?:         string;
  hash?:       string;
}

export interface CorrelateCluster {
  anchor_id:       string;
  members:         CorrelateEntityNode[];
  join_reason:     JoinReason;
  cluster_score:   number;
  has_threat:      boolean;
  max_threat_level: UnifiedThreat;
}

export interface GraphNodeData {
  entity_id:       string;
  /** "entity" for aggregated nodes; legacy: "process" | "network" | "memory" | "file" */
  entity_type:     EntityKind;
  threat_level:    UnifiedThreat;
  combined_score:  number;
  heuristic_score: number;
  ml_score?:       number;
  label:           string;
  sub_label?:      string;
  // Sub-scores (present for aggregated "entity" nodes, 0 for legacy flat nodes)
  process_score?:         number;
  network_score?:         number;
  memory_score?:          number;
  file_score?:            number;
  // Intra-entity threat flags (present for aggregated nodes)
  has_malicious_network?: boolean;
  has_malicious_memory?:  boolean;
  has_malicious_file?:    boolean;
  pid?:                   number;
  parent_pid?:            number;
  // Graph-feedback fields (set after apply_graph_feedback pass)
  /** Score added by graph analysis (path position + centrality + vector proximity). */
  graph_boost?: number;
  /** True when this Clean node directly spawned a Malicious/Critical child. */
  is_vector?:   boolean;
  /** True when this vector node's label matches a known living-off-the-land binary. */
  is_lolbin?:   boolean;
}

export interface GraphEdgeData {
  from:      string;
  to:        string;
  edge_type: EdgeKind;
  weight:    number;
}

export interface AttackChain {
  chain_id:     string;
  pattern:      AttackPatternName;
  node_ids:     string[];
  chain_score:  number;
  severity:     UnifiedThreat;
  description:  string;
  mitre_tactic: string;
  /** How convincingly this pattern fired — [0, 1].
   *  High chain_score + low confidence = threshold barely crossed.
   *  High chain_score + high confidence = multiple saturated domain signals. */
  confidence:   number;
}

export interface CriticalPath {
  /** Entity IDs in traversal order (source → sink). */
  node_ids:     string[];
  /** Edge-type string for each hop, length = node_ids.length - 1. */
  edge_types:   string[];
  /** Weight for each hop (avg combined scores × type multiplier). */
  edge_weights: number[];
  /** Sum of all hop weights — the total path score. */
  total_score:  number;
  /** Plain-English sentence describing the full attack chain in traversal order. */
  narrative:    string;
}

export interface CorrelateGraph {
  nodes:         GraphNodeData[];
  edges:         GraphEdgeData[];
  attack_chains: AttackChain[];
  critical_path?: CriticalPath | null;
}

export interface CorrelateStats {
  total_entities:         number;
  threat_entities:        number;
  process_entities:       number;
  network_entities:       number;
  memory_entities:        number;
  total_clusters:         number;
  threat_clusters:        number;
  graph_nodes:            number;
  graph_edges:            number;
  attack_chains_detected: number;
  include_memory:         boolean;
  scan_duration_ms:       number;
}

export interface CorrelateResult {
  success:    boolean;
  entities:   CorrelateEntityNode[];
  clusters:   CorrelateCluster[];
  graph:      CorrelateGraph;
  statistics: CorrelateStats;
  error?:     string;
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────
// Quarantine
// ─────────────────────────────────────────────────────────────────────────────

export interface QuarantineEntry {
  original_path:          string;
  sha256:                 string;
  quarantined_at:         number;   // Unix timestamp (seconds)
  reason:                 string;
  quarantine_path:        string;
  quarantine_file_exists: boolean;
}

export const CONTEXT_FLAG_LABEL: Record<ContextFlag, string> = {
  ransom_note_nearby: 'Ransom note in directory',
  multiple_ransom_notes: 'Multiple ransom notes detected',
  ransomware_extension: 'Ransomware file extension',
  mass_modification_detected: 'Mass file modification detected',
  encrypted_copy_detected: 'Encrypted copy exists',
  yara_ransomware_correlated: 'YARA + ransom note correlated',
  yara_filename_correlated: 'YARA + filename correlated',
  high_ransomware_extension_ratio: 'High ransomware extension ratio',
};

// ─────────────────────────────────────────────────────────────────────────────
// Agent — AI analysis output types (Round 1 + Round 2+)
// ─────────────────────────────────────────────────────────────────────────────

export interface RankedAction {
  /** Action name matching the available-actions table in agent.rs */
  action:           string;
  /** Human-readable target: process label, IP address, or file path */
  target:           string;
  /** entity_id from the correlate graph (e.g. "entity:4821") */
  entity_id:        string;
  pid:              number | null;
  /** One sentence explaining which chain/pattern drove this recommendation */
  justification:    string;
  /** Whether the action can be undone */
  reversible:       boolean;
  /** Whether the entity's combined_score met the action's minimum threshold */
  min_score_met:    boolean;
  /** True for kill_process and isolate_network — UI must show a confirm gate */
  confirm_required: boolean;
}

/**
 * One action auto-executed by autonomous mode, with rollback state.
 */
export interface AutoExecutedAction {
  id:           string;
  action:       string;   // 'quarantine_file' | 'block_ip' | 'dump_memory'
  target:       string;   // file path | IP | process label
  entity_id:    string;
  executedAt:   string;   // ISO-8601
  result:       'pending' | 'success' | 'failed';
  error?:       string;
  reversible:   boolean;
  // Rollback params stored at execution time
  sha256?:      string;   // quarantine_file rollback
  ruleName?:    string;   // block_ip rollback
  rolledBack:   boolean;
  rollbackError?: string;
}

/**
 * Records one action the user already executed — accumulated across rounds
 * and sent back to the agent on re-assessment so it never repeats itself.
 */
export interface ExecutedAction {
  action:      string;
  target:      string;
  entity_id:   string;
  executed_at: string | null;  // ISO-8601
  result:      'success' | 'failed' | 'skipped';
  pid:         number | null;
}

export interface AgentVerdict {
  /** 0–5 actions ordered from most reversible to least reversible */
  ranked_actions:    RankedAction[];
  /** 2–4 sentence overall threat assessment and action justification */
  rationale:         string;
  risk_level:        'Low' | 'Medium' | 'High' | 'Critical';
  /** Derived from the highest-confidence attack chain [0, 1] */
  confidence:        number;
  /** 0–3 suggested follow-up targeted scans */
  pivot_suggestions: string[];
  /** Non-empty when the micro-loop hit its cap without resolving all rule violations */
  warnings:          string[];
  // ── Level 2 fields ──────────────────────────────────────────────────────────
  /** True when the agent determines no further action is needed */
  investigation_closed: boolean;
  /** 'resolved' | 'no_improvement' | 'max_rounds_reached' | null */
  close_reason:         string | null;
  /** Which reasoning round produced this verdict (1 = initial, 2+ = re-assessment) */
  round_num:            number;
}

export const CONTEXT_FLAG_SEVERITY: Record<
  ContextFlag,
  'critical' | 'high' | 'medium'
> = {
  multiple_ransom_notes: 'critical',
  yara_ransomware_correlated: 'critical',
  mass_modification_detected: 'critical',
  ransomware_extension: 'high',
  encrypted_copy_detected: 'high',
  yara_filename_correlated: 'high',
  high_ransomware_extension_ratio: 'high',
  ransom_note_nearby: 'medium',
};
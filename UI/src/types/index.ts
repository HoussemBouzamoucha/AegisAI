// src/types/index.ts

// ─────────────────────────────────────────────────────────────────────────────
// Core Threat Types
// ─────────────────────────────────────────────────────────────────────────────

export type ThreatLevel = 'Clean' | 'Suspicious' | 'Malicious';
export type ProcessThreat = 'Safe' | 'Suspicious' | 'Malicious' | 'Critical';
export type View = 'dashboard' | 'scanner' | 'processes' | 'network' | 'memory' | 'history' | 'entities' | 'graph' | 'verdict';

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
  type: 'file' | 'directory';
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
  | 'LateralMovement'  | 'MultiStageAttack' | 'SuspiciousSpawn';

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
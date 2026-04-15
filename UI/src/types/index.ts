// src/types/index.ts

// ─────────────────────────────────────────────────────────────────────────────
// Core Threat Types
// ─────────────────────────────────────────────────────────────────────────────

export type ThreatLevel = 'Clean' | 'Suspicious' | 'Malicious';
export type ProcessThreat = 'Safe' | 'Suspicious' | 'Malicious' | 'Critical';
export type View = 'dashboard' | 'scanner' | 'processes' | 'network' | 'memory' | 'history';

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
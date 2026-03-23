// src/types/index.ts

export type ThreatLevel = 'Clean' | 'Suspicious' | 'Malicious';
export type ProcessThreat = 'Safe' | 'Suspicious' | 'Malicious' | 'Critical';
export type View = 'dashboard' | 'scanner' | 'processes' | 'history';

export type FileCategory =
  | 'executable'
  | 'script'
  | 'document'
  | 'archive'
  | 'macro_enabled'
  | 'unknown';

export type ContextFlag =
  | 'ransom_note_nearby'
  | 'multiple_ransom_notes'
  | 'ransomware_extension'
  | 'mass_modification_detected'
  | 'encrypted_copy_detected'
  | 'yara_ransomware_correlated'
  | 'yara_filename_correlated'
  | 'high_ransomware_extension_ratio';

// ─── Shared detection signal (used by both file and process scanner) ──────────

export interface DetectionSignal {
  source:      string;
  description: string;
  score:       number;
}

// ─── File scan types ──────────────────────────────────────────────────────────

export interface ScanResult {
  path:             string;
  level:            ThreatLevel;
  reason:           string;
  hash?:            string;
  signature?:       string;
  is_threat:        boolean;
  success:          boolean;
  confidence_score: number;
  detection_signals: DetectionSignal[];
  file_category:    FileCategory;
  context_flags:    ContextFlag[];
}

export interface ScanStats {
  total_files:      number;
  clean_files:      number;
  suspicious_files: number;
  malicious_files:  number;
  error_files:      number;
  total_size_mb:    number;
}

export interface ScanOutput {
  success:    boolean;
  files:      ScanResult[];
  statistics: ScanStats;
  error?:     string;
}

export interface DirectoryScanResult {
  success:    boolean;
  statistics: ScanStats;
  files:      ScanResult[];
  error?:     string;
}

// ─── Process scan types ───────────────────────────────────────────────────────

export interface ProcessInfo {
  // Core metadata
  pid:          number;
  name:         string;
  parent_pid:   number | null;
  exe_path:     string | null;
  command_line: string | null;
  status:       string;

  // Resources
  cpu_usage:         number;
  memory_mb:         string;   // "xx.xx" formatted string from engine
  memory_bytes:      number;
  virtual_memory_mb: string;
  thread_count:      number;
  start_time:        number | null;
  user:              string | null;

  // Stage 2-4 placeholders
  handle_count: number | null;
  module_count: number | null;

  // Threat assessment + ML fields
  threat_level:      ProcessThreat;
  threat_score:      number;
  is_threat:         boolean;
  detection_signals: DetectionSignal[];
  anomaly_flags:     string[];
}

export interface ProcessStats {
  total_processes:      number;
  safe_processes:       number;
  suspicious_processes: number;
  malicious_processes:  number;
  critical_processes:   number;
  total_memory_mb:      string;
  total_threads:        number;
  avg_cpu_usage:        string;
  scan_duration_ms:     number;
}

export interface ProcessScanResult {
  success:    boolean;
  statistics: ProcessStats;
  processes:  ProcessInfo[];
  error?:     string;
}

// ─── History ──────────────────────────────────────────────────────────────────

export interface ScanHistoryEntry {
  id:        string;
  timestamp: Date;
  path:      string;
  type:      'file' | 'directory';
  stats:     { total: number; clean: number; suspicious: number; malicious: number };
  durationMs: number;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

export const CONTEXT_FLAG_LABEL: Record<ContextFlag, string> = {
  ransom_note_nearby:             'Ransom note in directory',
  multiple_ransom_notes:          'Multiple ransom notes detected',
  ransomware_extension:           'Ransomware file extension',
  mass_modification_detected:     'Mass file modification detected',
  encrypted_copy_detected:        'Encrypted copy exists',
  yara_ransomware_correlated:     'YARA + ransom note correlated',
  yara_filename_correlated:       'YARA + filename correlated',
  high_ransomware_extension_ratio:'High ransomware extension ratio',
};

export const CONTEXT_FLAG_SEVERITY: Record<ContextFlag, 'critical' | 'high' | 'medium'> = {
  multiple_ransom_notes:          'critical',
  yara_ransomware_correlated:     'critical',
  mass_modification_detected:     'critical',
  ransomware_extension:           'high',
  encrypted_copy_detected:        'high',
  yara_filename_correlated:       'high',
  high_ransomware_extension_ratio:'high',
  ransom_note_nearby:             'medium',
};
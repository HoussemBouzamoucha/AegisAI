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

export interface DetectionSignal {
  /** Short identifier: "yara", "hash", "entropy", "keyword", "filename", "context" */
  source: string;
  /** Human-readable description of what triggered */
  description: string;
  /** Score contribution from this signal */
  score: number;
}

export interface ScanResult {
  // ── Core verdict ────────────────────────────────────────────────────────
  path: string;
  level: ThreatLevel;
  reason: string;
  hash?: string;
  signature?: string;
  is_threat: boolean;
  success: boolean;

  // ── ML classification fields ─────────────────────────────────────────────
  /** 0.0 (uncertain) → 1.0 (definitive). Hash match = 1.0, clean = 1.0 */
  confidence_score: number;
  /** Individual signals that contributed to the verdict */
  detection_signals: DetectionSignal[];
  /** File type category derived from extension */
  file_category: FileCategory;
  /** Directory-level context flags set after full directory scan */
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

export interface ProcessInfo {
  pid: number;
  name: string;
  path?: string;
  memory_mb: string;
  cpu_usage: number;
  threat_level: ProcessThreat;
  suspicious_behaviors: string[];
  is_threat: boolean;
}

export interface ProcessStats {
  total_processes: number;
  safe_processes: number;
  suspicious_processes: number;
  malicious_processes: number;
  critical_processes: number;
  total_memory_mb: string;
}

export interface ProcessScanResult {
  success: boolean;
  statistics: ProcessStats;
  processes: ProcessInfo[];
  error?: string;
}

export interface ScanHistoryEntry {
  id: string;
  timestamp: Date;
  path: string;
  type: 'file' | 'directory';
  stats: { total: number; clean: number; suspicious: number; malicious: number };
  durationMs: number;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

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
export type ThreatLevel = 'Clean' | 'Suspicious' | 'Malicious';
export type ProcessThreat = 'Safe' | 'Suspicious' | 'Malicious' | 'Critical';
export type View = 'dashboard' | 'scanner' | 'processes' | 'history';

export interface ScanResult {
  path: string;
  level: ThreatLevel;
  reason: string;
  hash?: string;
  signature?: string;
  is_threat: boolean;
  success: boolean;
}

export interface ScanStats {
  total_files: number;
  clean_files: number;
  suspicious_files: number;
  malicious_files: number;
  error_files: number;
  total_size_mb: number;
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
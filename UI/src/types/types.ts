// File: UI/src/types.ts
// Must match Rust structs in src-tauri/src/main.rs exactly

export interface ScanResult {
  path: string;
  level: 'Clean' | 'Suspicious' | 'Malicious' | 'Error';
  reason: string;
  hash?: string;
  signature?: string;
  is_threat: boolean;
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

export interface EngineStatus {
  available: boolean;
  path: string;
}
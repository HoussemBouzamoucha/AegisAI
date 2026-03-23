// src/store/index.ts
import { create } from 'zustand';
import { invoke } from '@tauri-apps/api/core';
import type {
  View, ScanResult, ScanOutput, DirectoryScanResult,
  ProcessInfo, ProcessScanResult, ScanHistoryEntry,
} from '../types';

interface AppState {
  view: View;
  setView: (v: View) => void;

  engineReady: boolean;
  checkEngine: () => Promise<void>;

  scanning: boolean;
  scanResults: ScanResult[];
  scanStats: DirectoryScanResult['statistics'] | null;
  scanError: string | null;
  scanFile: (path: string) => Promise<void>;
  scanDirectory: (path: string) => Promise<void>;
  clearScan: () => void;

  processScanning: boolean;
  processes: ProcessInfo[];
  processStats: ProcessScanResult['statistics'] | null;
  processError: string | null;
  scanProcesses: () => Promise<void>;
  killProcess: (pid: number) => Promise<void>;

  history: ScanHistoryEntry[];
  addHistory: (entry: ScanHistoryEntry) => void;
}

// ─── Normalizers ──────────────────────────────────────────────────────────────

function normalizeScanResult(f: any): ScanResult {
  return {
    path:              f.path      ?? '',
    level:             f.level     ?? 'Clean',
    reason:            f.reason    ?? '',
    hash:              f.hash,
    signature:         f.signature,
    is_threat:         f.is_threat ?? (f.level === 'Suspicious' || f.level === 'Malicious'),
    success:           f.success   ?? true,
    confidence_score:  f.confidence_score  ?? (f.level === 'Clean' ? 1.0 : 0.6),
    detection_signals: f.detection_signals ?? [],
    file_category:     f.file_category     ?? 'unknown',
    context_flags:     f.context_flags     ?? [],
  };
}

function normalizeProcess(p: any): ProcessInfo {
  return {
    pid:               p.pid           ?? 0,
    name:              p.name          ?? '',
    parent_pid:        p.parent_pid    ?? null,
    exe_path:          p.exe_path      ?? null,
    command_line:      p.command_line  ?? null,
    status:            p.status        ?? 'Unknown',
    cpu_usage:         p.cpu_usage     ?? 0,
    memory_mb:         p.memory_mb     ?? '0.00',
    memory_bytes:      p.memory_bytes  ?? 0,
    virtual_memory_mb: p.virtual_memory_mb ?? '0.00',
    thread_count:      p.thread_count  ?? 0,
    start_time:        p.start_time    ?? null,
    user:              p.user          ?? null,
    handle_count:      p.handle_count  ?? null,
    module_count:      p.module_count  ?? null,
    threat_level:      p.threat_level  ?? 'Safe',
    threat_score:      p.threat_score  ?? 0,
    is_threat:         p.is_threat     ?? false,
    detection_signals: p.detection_signals ?? [],
    anomaly_flags:     p.anomaly_flags ?? [],
  };
}

// ─── Store ────────────────────────────────────────────────────────────────────

export const useStore = create<AppState>((set, get) => ({
  view: 'dashboard',
  setView: (view) => set({ view }),

  engineReady: false,
  checkEngine: async () => {
    try {
      const status = await invoke<{ ready: boolean }>('engine_status');
      set({ engineReady: status.ready });
    } catch {
      set({ engineReady: false });
    }
  },

  scanning: false,
  scanResults: [],
  scanStats: null,
  scanError: null,

  scanFile: async (path) => {
    set({ scanning: true, scanResults: [], scanStats: null, scanError: null });
    const t0 = Date.now();
    try {
      const result = await invoke<ScanOutput>('scan_file', { path });
      if (!result.success) throw new Error(result.error ?? 'Scan failed');
      const files = (result.files ?? []).map(normalizeScanResult);
      set({ scanResults: files, scanStats: result.statistics });
      const s = result.statistics;
      get().addHistory({
        id: crypto.randomUUID(),
        timestamp: new Date(),
        path,
        type: 'file',
        stats: {
          total:      s.total_files,
          clean:      s.clean_files,
          suspicious: s.suspicious_files,
          malicious:  s.malicious_files,
        },
        durationMs: Date.now() - t0,
      });
    } catch (e: any) {
      set({ scanError: String(e) });
    } finally {
      set({ scanning: false });
    }
  },

  scanDirectory: async (path) => {
    set({ scanning: true, scanResults: [], scanStats: null, scanError: null });
    const t0 = Date.now();
    try {
      const result = await invoke<DirectoryScanResult>('scan_directory', { path });
      if (!result.success) throw new Error(result.error ?? 'Scan failed');
      const files = (result.files ?? []).map(normalizeScanResult);
      set({ scanResults: files, scanStats: result.statistics });
      const s = result.statistics;
      get().addHistory({
        id: crypto.randomUUID(),
        timestamp: new Date(),
        path,
        type: 'directory',
        stats: {
          total:      s.total_files,
          clean:      s.clean_files,
          suspicious: s.suspicious_files,
          malicious:  s.malicious_files,
        },
        durationMs: Date.now() - t0,
      });
    } catch (e: any) {
      set({ scanError: String(e) });
    } finally {
      set({ scanning: false });
    }
  },

  clearScan: () => set({ scanResults: [], scanStats: null, scanError: null }),

  processScanning: false,
  processes: [],
  processStats: null,
  processError: null,

  scanProcesses: async () => {
    set({ processScanning: true, processError: null });
    try {
      const result = await invoke<ProcessScanResult>('scan_processes');
      if (!result.success) throw new Error(result.error ?? 'Process scan failed');
      const processes = (result.processes ?? []).map(normalizeProcess);
      set({ processes, processStats: result.statistics });
    } catch (e: any) {
      set({ processError: String(e) });
    } finally {
      set({ processScanning: false });
    }
  },

  killProcess: async (pid) => {
    try {
      await invoke('kill_process', { pid });
      await get().scanProcesses();
    } catch (e: any) {
      set({ processError: String(e) });
    }
  },

  history: [],
  addHistory: (entry) =>
    set((s) => ({ history: [entry, ...s.history].slice(0, 50) })),
}));
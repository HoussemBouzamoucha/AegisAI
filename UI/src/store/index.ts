import { create } from 'zustand';
import { invoke } from '@tauri-apps/api/core';
import type {
  View, ScanResult, ScanOutput, DirectoryScanResult,
  ProcessScanResult, ScanHistoryEntry
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
  processes: ProcessScanResult['processes'];
  processStats: ProcessScanResult['statistics'] | null;
  processError: string | null;
  scanProcesses: () => Promise<void>;
  killProcess: (pid: number) => Promise<void>;

  history: ScanHistoryEntry[];
  addHistory: (entry: ScanHistoryEntry) => void;
}

export const useStore = create<AppState>((set, get) => ({
  view: 'dashboard',
  setView: (view) => set({ view }),

  engineReady: false,
  checkEngine: async () => {
    try {
      const status = await invoke<{ ready: boolean }>('engine_status');
      set({ engineReady: status.ready });
    } catch { set({ engineReady: false }); }
  },

  scanning: false,
  scanResults: [],
  scanStats: null,
  scanError: null,

  scanFile: async (path) => {
    set({ scanning: true, scanResults: [], scanStats: null, scanError: null });
    const t0 = Date.now();
    try {
      const result = await invoke<ScanOutput>('scan_file', { path }); // ← ScanOutput, not ScanResult
      if (!result.success) throw new Error(result.error ?? 'Scan failed');

      set({ scanResults: result.files, scanStats: result.statistics });
      const s = result.statistics;
      get().addHistory({
        id: crypto.randomUUID(),
        timestamp: new Date(),
        path,
        type: 'file',
        stats: { total: s.total_files, clean: s.clean_files, suspicious: s.suspicious_files, malicious: s.malicious_files },
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
      set({ scanResults: result.files, scanStats: result.statistics });
      const s = result.statistics;
      get().addHistory({
        id: crypto.randomUUID(),
        timestamp: new Date(),
        path,
        type: 'directory',
        stats: { total: s.total_files, clean: s.clean_files, suspicious: s.suspicious_files, malicious: s.malicious_files },
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
      set({ processes: result.processes, processStats: result.statistics });
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
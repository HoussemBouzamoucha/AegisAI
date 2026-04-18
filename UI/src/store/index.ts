// src/store/index.ts
import { create } from 'zustand';
import { invoke } from '@tauri-apps/api/core';
import type {
  View, ScanResult, ScanOutput, DirectoryScanResult,
  ProcessInfo, ProcessScanResult, ScanHistoryEntry,
  NetworkConnection, NetworkStats, NetworkScanResult,
  MemoryRegion, MemoryStats, MemoryScanResult as MemoryScanResultType,
  MlIdsResult, CorrelateResult,
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

  networkScanning: boolean;
  networkConnections: NetworkConnection[];
  networkStats: NetworkStats | null;
  networkError: string | null;
  scanNetwork: (pid?: number) => Promise<void>;

  mlIdsRunning: boolean;
  mlIdsResult: MlIdsResult | null;
  mlIdsError: string | null;
  runMlIds: (csvPath?: string) => Promise<void>;

  memoryScanning: boolean;
  memoryRegions: MemoryRegion[];
  memoryStats: MemoryStats | null;
  memoryError: string | null;
  scanMemory: (pid?: number) => Promise<void>;

  correlating:      boolean;
  correlateResult:  CorrelateResult | null;
  correlateError:   string | null;
  correlateEntities: (includeMemory?: boolean) => Promise<void>;
  clearCorrelate:   () => void;

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

function normalizeNetwork(connection: any): NetworkConnection {
  return {
    protocol:          connection.protocol      ?? 'tcp',
    local_address:     connection.local_address  ?? '',
    remote_address:    connection.remote_address ?? '',
    state:             connection.state          ?? '',
    pid:               connection.pid ?? null,
    process_name:      connection.process_name ?? null,
    threat_level:      connection.threat_level  ?? 'Clean',
    threat_score:      connection.threat_score  ?? 0,
    is_threat:         connection.is_threat     ?? false,
    detection_signals: connection.detection_signals ?? [],
  };
}
function normalizeMemoryRegion(region: any): MemoryRegion {
  return {
    pid:               region.pid ?? 0,
    process_name:      region.process_name ?? '',
    process_path:      region.process_path ?? null,
    command_line:      region.command_line ?? null,
    region_start:      region.region_start ?? 0,
    region_size:       region.region_size ?? 0,
    protection:        region.protection ?? '',
    is_executable:      region.is_executable ?? false,
    is_writable:        region.is_writable ?? false,
    is_readable:        region.is_readable ?? false,
    is_committed:       region.is_committed ?? false,
    is_private:         region.is_private ?? false,
    content_sample:     region.content_sample ?? null,
    threat_level:       region.threat_level ?? 'Clean',
    threat_score:       region.threat_score ?? 0,
    is_threat:          region.is_threat ?? false,
    detection_signals:  region.detection_signals ?? [],
  };
}
// ─── Store ────────────────────────────────────────────────────────────────────

export const useStore = create<AppState>((set, get) => ({
  view: 'dashboard',
  setView: (view) => set({ view }),

  engineReady: false,
  checkEngine: async () => {
    try {
      const status = await invoke<{ available: boolean; daemon_alive: boolean }>('get_engine_status');
      set({ engineReady: status.available && status.daemon_alive });
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

  networkScanning: false,
  networkConnections: [],
  networkStats: null,
  networkError: null,

  mlIdsRunning: false,
  mlIdsResult: null,
  mlIdsError: null,
  runMlIds: async (csvPath) => {
    set({ mlIdsRunning: true, mlIdsError: null, mlIdsResult: null });
    try {
      const args: Record<string, unknown> = {};
      if (csvPath !== undefined) { args.csvPath = csvPath; }
      const result = await invoke<MlIdsResult>('run_ml_ids', args);
      if (!result.success) throw new Error(result.error ?? 'ML IDS failed');
      set({ mlIdsResult: result });
    } catch (e: any) {
      set({ mlIdsError: String(e) });
    } finally {
      set({ mlIdsRunning: false });
    }
  },

  scanNetwork: async (pid) => {
    set({ networkScanning: true, networkError: null });
    try {
      const args: Record<string, unknown> = {};
      if (pid !== undefined) { args.pid = pid; }
      const result = await invoke<NetworkScanResult>('scan_network', args);
      if (!result.success) throw new Error(result.error ?? 'Network scan failed');
      const connections = (result.connections ?? []).map(normalizeNetwork);
      set({ networkConnections: connections, networkStats: result.statistics });
    } catch (e: any) {
      set({ networkError: String(e) });
    } finally {
      set({ networkScanning: false });
    }
  },

  memoryScanning: false,
  memoryRegions: [],
  memoryStats: null,
  memoryError: null,
  scanMemory: async (pid) => {
    set({ memoryScanning: true, memoryError: null });
    try {
      const args: Record<string, unknown> = {};
      if (pid !== undefined) { args.pid = pid; }
      const result = await invoke<MemoryScanResultType>('scan_memory', args);
      if (!result.success) throw new Error(result.error ?? 'Memory scan failed');
      const regions = (result.regions ?? []).map(normalizeMemoryRegion);
      set({ memoryRegions: regions, memoryStats: result.statistics });
    } catch (e: any) {
      set({ memoryError: String(e) });
    } finally {
      set({ memoryScanning: false });
    }
  },

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

  correlating:     false,
  correlateResult: null,
  correlateError:  null,

  correlateEntities: async (includeMemory = false) => {
    set({ correlating: true, correlateError: null });
    try {
      const args: Record<string, unknown> = { includeMemory };
      const result = await invoke<CorrelateResult>('correlate_entities', args);
      if (!result.success) throw new Error(result.error ?? 'Correlation failed');
      set({ correlateResult: result });
    } catch (e: any) {
      set({ correlateError: String(e) });
    } finally {
      set({ correlating: false });
    }
  },

  clearCorrelate: () => set({ correlateResult: null, correlateError: null }),

  history: [],
  addHistory: (entry) =>
    set((s) => ({ history: [entry, ...s.history].slice(0, 50) })),
}));
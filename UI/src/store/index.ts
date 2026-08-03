// src/store/index.ts
import { create } from 'zustand';
import { invoke } from '@tauri-apps/api/core';
import { buildCorrelateResultFromStore } from '../lib/entityUtils';
import type {
  View, ScanResult, ScanOutput, DirectoryScanResult,
  ProcessInfo, ProcessScanResult, ScanHistoryEntry,
  NetworkConnection, NetworkStats, NetworkScanResult,
  MemoryRegion, MemoryStats, MemoryScanResult as MemoryScanResultType,
  MlIdsResult, CorrelateResult, AgentVerdict, ExecutedAction,
  AutoExecutedAction,
} from '../types';

// ─── Steganography scan result ───────────────────────────────────────────────

export interface StegScanResult {
  path:          string;
  fileName:      string;
  stegProb:      number | null;   // 0.0–1.0 probability of being stego
  isStego:       boolean | null;
  verdict:       'stego' | 'clean' | 'error';
  lsbOnesRatio:  number | null;   // fraction of pixels with LSB==1; stego → ~0.50
  warning:       string | null;   // e.g. JPEG warning or LSB distribution note
  error:         string | null;
}

// ─── Ember ML per-process result ─────────────────────────────────────────────

export interface ProcessEmberResult {
  pid:          number;
  name:         string;
  exe_path:     string;
  mlModel:      string | null;   // 'GRU' (process bridge)
  mlScore:      number | null;   // 0.0–1.0 sigmoid probability; null when skipped
  mlVerdict:    'malicious' | 'clean' | null;
  escalated:    boolean;         // Suspicious → Malicious
  skipped:      boolean;
  skipReason:   string | null;
}

// ─── Ember ML per-file comparison record ─────────────────────────────────────

export interface EmberMlFileResult {
  path: string;
  fileName: string;                            // basename for display
  initialLevel: 'Suspicious';                  // always — we only run on Suspicious files
  finalLevel: 'Suspicious' | 'Malicious' | 'Clean';
  mlModel: string | null;                      // 'Win32' | 'Win64' | 'DotNet' | 'PDF' | 'All'
  mlScore: number | null;                      // 0.0–1.0; null when skipped
  mlVerdict: 'malicious' | 'clean' | null;     // null when skipped
  escalated: boolean;                          // Suspicious → Malicious
  skipped: boolean;                            // bridge could not analyse this file
  skipReason: string | null;                   // "file_unavailable" | "prediction_error" | …
}

// ── Raw entry returned by the apply-ember-ml daemon command ──────────────────
interface EmberBatchEntry {
  path: string;
  skipped: boolean;
  /** Populated when skipped=true: "file_unavailable" | "prediction_error" | "batch_error" | … */
  skip_reason: string | null;
  file_type: string | null;
  score: number | null;
  malicious: boolean | null;
}

interface AppState {
  view: View;
  setView: (v: View) => void;

  engineReady: boolean;
  checkEngine: () => Promise<void>;

  scanning: boolean;
  scanResults: ScanResult[];
  scanStats: DirectoryScanResult['statistics'] | null;
  scanError: string | null;
  lastScanDurationMs: number | null;
  scanFile: (path: string) => Promise<void>;
  scanDirectory: (path: string) => Promise<void>;
  scanAll: () => Promise<void>;
  quickScan: () => Promise<void>;
  clearScan: () => void;

  emberMlRunning: boolean;
  emberMlProgress: { done: number; total: number } | null;
  emberMlError: string | null;
  emberMlResults: EmberMlFileResult[] | null;
  applyEmberMl: () => Promise<void>;

  processEmberRunning: boolean;
  processEmberError: string | null;
  processEmberResults: ProcessEmberResult[] | null;
  applyProcessMl: () => Promise<void>;

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
  correlateFromStore: () => void;
  clearCorrelate:   () => void;
  abortCorrelate:   () => void;

  // ── Agent Round 1 ──────────────────────────────────────────────────────────
  agentVerdict:      AgentVerdict | null;
  agentLoading:      boolean;
  agentError:        string | null;
  runAgentAnalysis:  () => Promise<void>;
  clearAgentVerdict: () => void;

  // ── Agent Round 2+ ─────────────────────────────────────────────────────────
  actionsTaken:         ExecutedAction[];
  previousThreatScore:  number;
  currentRound:         number;
  agentReassessing:     boolean;
  agentReassessError:   string | null;
  recordExecutedAction: (action: ExecutedAction) => void;
  runAgentReassessment: () => Promise<void>;
  resetInvestigation:   () => void;

  // ── Network isolation ──────────────────────────────────────────────────────
  networkIsolated:      boolean;
  networkIsolating:     boolean;
  networkIsolateError:  string | null;
  isolateNetworkAction: () => Promise<void>;
  restoreNetworkAction: () => Promise<void>;

  // ── Autonomous mode ────────────────────────────────────────────────────────
  autonomousMode:         boolean;
  setAutonomousMode:      (v: boolean) => void;
  autoRunning:            boolean;
  autoActionLog:          AutoExecutedAction[];
  rollbackAutoAction:     (id: string) => Promise<void>;
  rollbackAllAutoActions: () => Promise<void>;
  clearAutoLog:           () => void;
  _runAutonomousActions:  (result: CorrelateResult) => Promise<void>;

  // ── Steganography ML ───────────────────────────────────────────────────────
  stegScanRunning:  boolean;
  stegScanError:    string | null;
  stegScanResults:  StegScanResult[] | null;
  scanImagesSteg:   (paths: string[]) => Promise<void>;
  clearStegScan:    () => void;
  embedStegTest:    (srcPath: string) => Promise<string | null>;

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
// ─── Correlate abort token ────────────────────────────────────────────────────
// Incremented every time a new correlate starts or the user cancels.
// Each correlate invocation captures its own snapshot; on completion it checks
// the current token before touching state — stale results are silently dropped.
let correlateToken = 0;

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
  lastScanDurationMs: null,

  scanFile: async (path) => {
    set({ scanning: true, scanResults: [], scanStats: null, scanError: null, lastScanDurationMs: null });
    const t0 = Date.now();
    try {
      const result = await invoke<ScanOutput>('scan_file', { path });
      if (!result.success) throw new Error(result.error ?? 'Scan failed');
      const files = (result.files ?? []).map(normalizeScanResult);
      const durationMs = Date.now() - t0;
      set({ scanResults: files, scanStats: result.statistics, lastScanDurationMs: durationMs });
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
        durationMs,
      });
    } catch (e: any) {
      set({ scanError: String(e) });
    } finally {
      set({ scanning: false });
    }
  },

  scanDirectory: async (path) => {
    set({ scanning: true, scanResults: [], scanStats: null, scanError: null, lastScanDurationMs: null });
    const t0 = Date.now();
    try {
      const result = await invoke<DirectoryScanResult>('scan_directory', { path });
      if (!result.success) throw new Error(result.error ?? 'Scan failed');
      const files = (result.files ?? []).map(normalizeScanResult);
      const durationMs = Date.now() - t0;
      set({ scanResults: files, scanStats: result.statistics, lastScanDurationMs: durationMs });
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
        durationMs,
      });
    } catch (e: any) {
      set({ scanError: String(e) });
    } finally {
      set({ scanning: false });
    }
  },

  scanAll: async () => {
    set({ scanning: true, scanResults: [], scanStats: null, scanError: null, lastScanDurationMs: null });
    const t0 = Date.now();
    try {
      const result = await invoke<ScanOutput>('scan_all');
      if (!result.success) throw new Error(result.error ?? 'Full scan failed');
      const files = (result.files ?? []).map(normalizeScanResult);
      const durationMs = Date.now() - t0;
      set({ scanResults: files, scanStats: result.statistics, lastScanDurationMs: durationMs });
      const s = result.statistics;
      get().addHistory({
        id: crypto.randomUUID(),
        timestamp: new Date(),
        path: '[FULL SYSTEM SCAN]',
        type: 'directory',
        stats: {
          total:      s.total_files,
          clean:      s.clean_files,
          suspicious: s.suspicious_files,
          malicious:  s.malicious_files,
        },
        durationMs,
      });
    } catch (e: any) {
      set({ scanError: String(e) });
    } finally {
      set({ scanning: false });
    }
  },

  quickScan: async () => {
    set({ scanning: true, scanResults: [], scanStats: null, scanError: null, lastScanDurationMs: null });
    const t0 = Date.now();
    try {
      const result = await invoke<ScanOutput>('quick_scan');
      if (!result.success) throw new Error(result.error ?? 'Quick scan failed');
      const files = (result.files ?? []).map(normalizeScanResult);
      const durationMs = Date.now() - t0;
      set({ scanResults: files, scanStats: result.statistics, lastScanDurationMs: durationMs });
      const s = result.statistics;
      get().addHistory({
        id: crypto.randomUUID(),
        timestamp: new Date(),
        path: '[QUICK SCAN]',
        type: 'quick-scan',
        stats: {
          total:      s.total_files,
          clean:      s.clean_files,
          suspicious: s.suspicious_files,
          malicious:  s.malicious_files,
        },
        durationMs,
      });
    } catch (e: any) {
      set({ scanError: String(e) });
    } finally {
      set({ scanning: false });
    }
  },

  clearScan: () => set({
    scanResults: [], scanStats: null, scanError: null, lastScanDurationMs: null,
    emberMlRunning: false, emberMlProgress: null, emberMlError: null, emberMlResults: null,
  }),

  emberMlRunning: false,
  emberMlProgress: null,
  emberMlError: null,
  emberMlResults: null,

  applyEmberMl: async () => {
    const suspicious = get().scanResults.filter(r => r.level === 'Suspicious');
    if (suspicious.length === 0) return;

    // Reset results so a re-run starts fresh
    set({
      emberMlRunning: true,
      emberMlError: null,
      emberMlProgress: { done: 0, total: suspicious.length },
      emberMlResults: [],
    });

    try {
      // The daemon's persistent EmberServer (bridge.py --server) loads all
      // LightGBM models once at first call and keeps them in memory.
      // Subsequent calls bypass model loading entirely — inference only.
      const batchRaw = await invoke<EmberBatchEntry[]>('apply_ember_ml', {
        paths: suspicious.map(r => r.path),
      });

      const mlResults: EmberMlFileResult[] = suspicious.map((file, i) => {
        const entry     = batchRaw[i];
        const fileName  = file.path.split(/[\\/]/).pop() ?? file.path;
        const skipped   = !entry || entry.skipped;
        const mlModel   = entry?.file_type ?? null;
        const mlScore   = entry?.score ?? null;
        const mlVerdict: EmberMlFileResult['mlVerdict'] =
          entry?.malicious === true  ? 'malicious' :
          entry?.malicious === false ? 'clean'     : null;
        const escalated  = !skipped && entry?.malicious === true;
        const finalLevel: EmberMlFileResult['finalLevel'] = escalated
          ? 'Malicious'
          : (file.level as EmberMlFileResult['finalLevel']);
        const skipReason = skipped ? (entry?.skip_reason ?? 'skipped') : null;
        return { path: file.path, fileName, initialLevel: 'Suspicious',
                 finalLevel, mlModel, mlScore, mlVerdict, escalated, skipped, skipReason };
      });

      const escalatedPaths = new Set(mlResults.filter(r => r.escalated).map(r => r.path));

      set(s => ({
        emberMlResults: mlResults,
        emberMlProgress: { done: suspicious.length, total: suspicious.length },
        ...(escalatedPaths.size > 0 && {
          scanResults: s.scanResults.map(r =>
            escalatedPaths.has(r.path)
              ? { ...r, level: 'Malicious' as const, is_threat: true }
              : r
          ),
        }),
      }));
    } catch (e: any) {
      set({ emberMlError: String(e) });
    }

    // Recompute stats from the updated results
    const final = get().scanResults;
    const prev  = get().scanStats;
    set({
      scanStats: prev ? {
        ...prev,
        suspicious_files: final.filter(r => r.level === 'Suspicious').length,
        malicious_files:  final.filter(r => r.level === 'Malicious').length,
        clean_files:      final.filter(r => r.level === 'Clean').length,
      } : prev,
      emberMlRunning:  false,
      emberMlProgress: null,
    });
  },

  processEmberRunning: false,
  processEmberError:   null,
  processEmberResults: null,

  applyProcessMl: async () => {
    const suspicious = get().processes.filter(
      p => p.threat_level === 'Suspicious' && p.exe_path,
    );
    if (suspicious.length === 0) return;

    set({ processEmberRunning: true, processEmberError: null, processEmberResults: null });

    try {
      // Build entries for the GRU daemon command
      const entries = suspicious.map(p => ({ pid: p.pid, exe_path: p.exe_path as string }));

      // Raw result from daemon: array of {pid, exe_path, probability, verdict, label,
      //   top_api_calls, trigger_chunk, api_count, source, skipped, reason}
      const batchRaw = await invoke<any[]>('apply_process_gru', { entries });

      const results: ProcessEmberResult[] = suspicious.map((proc, i) => {
        const entry   = batchRaw[i];
        const skipped = !entry || entry.skipped;
        // GRU returns "MALWARE" | "BENIGN" — map to our verdict type
        const mlVerdict: ProcessEmberResult['mlVerdict'] =
          entry?.verdict === 'MALWARE' ? 'malicious' :
          entry?.verdict === 'BENIGN'  ? 'clean'     : null;
        const escalated = !skipped && entry?.verdict === 'MALWARE';
        return {
          pid:        proc.pid,
          name:       proc.name,
          exe_path:   proc.exe_path as string,
          mlModel:    'GRU',
          mlScore:    entry?.probability ?? null,
          mlVerdict,
          escalated,
          skipped,
          skipReason: skipped ? (entry?.reason ?? 'skipped') : null,
        };
      });

      // Escalate Suspicious → Malicious when GRU concurs
      const escalatedPids = new Set(results.filter(r => r.escalated).map(r => r.pid));
      set(s => ({
        processEmberResults: results,
        ...(escalatedPids.size > 0 && {
          processes: s.processes.map(p =>
            escalatedPids.has(p.pid)
              ? { ...p, threat_level: 'Malicious' as const, is_threat: true }
              : p
          ),
        }),
      }));
    } catch (e: any) {
      set({ processEmberError: String(e) });
    } finally {
      set({ processEmberRunning: false });
    }
  },

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
    const myToken = ++correlateToken;
    set({ correlating: true, correlateError: null });
    try {
      const TIMEOUT_MS = 360_000; // 6 minutes (Rust-side timeout is 5 min; extra buffer)
      const timeout = new Promise<never>((_, reject) =>
        setTimeout(
          () => reject(new Error(
            'Correlation timed out after 6 minutes. ' +
            'The engine may still be running in the background — try again shortly.'
          )),
          TIMEOUT_MS,
        )
      );

      const result = await Promise.race([
        invoke<CorrelateResult>('correlate_entities', { includeMemory }),
        timeout,
      ]);

      if (correlateToken !== myToken) return; // cancelled while in flight
      if (!result.success) throw new Error(result.error ?? 'Correlation failed');
      set({ correlateResult: result });

      // Autonomous mode: auto-run agent + execute safe actions when threats found
      if (get().autonomousMode) {
        const hasThreat = (result.graph?.nodes ?? []).some(
          n => n.threat_level === 'Malicious' || n.threat_level === 'Critical',
        );
        if (hasThreat) get()._runAutonomousActions(result);
      }
    } catch (e: any) {
      if (correlateToken !== myToken) return;
      set({ correlateError: String(e) });
    } finally {
      if (correlateToken === myToken) set({ correlating: false });
    }
  },

  correlateFromStore: () => {
    const { processes, networkConnections, memoryRegions, scanResults, mlIdsResult } = get();
    const mlFlows = mlIdsResult?.flows ?? [];
    try {
      const result = buildCorrelateResultFromStore(
        processes, networkConnections, memoryRegions, scanResults, mlFlows,
      );
      set({ correlateResult: result, correlateError: null });
    } catch (e: any) {
      set({ correlateError: String(e) });
    }
  },

  clearCorrelate: () => set({ correlateResult: null, correlateError: null }),

  // Immediately resets the loading state without waiting for the invoke.
  // The daemon call may still complete in the background; when it does the
  // token mismatch ensures the stale result is silently discarded.
  abortCorrelate: () => {
    correlateToken++; // invalidate the in-flight invocation
    set({ correlating: false, correlateError: null });
  },

  // ── Agent Round 1 ──────────────────────────────────────────────────────────
  agentVerdict:  null,
  agentLoading:  false,
  agentError:    null,

  runAgentAnalysis: async () => {
    const { correlateResult } = get();
    if (!correlateResult) {
      set({ agentError: 'No correlate result available. Run Correlate first.' });
      return;
    }
    set({
      agentLoading: true, agentError: null, agentVerdict: null,
      // Reset investigation on fresh Round 1
      actionsTaken: [], currentRound: 1, previousThreatScore: 0,
      agentReassessError: null,
    });
    try {
      const verdict = await invoke<AgentVerdict>('run_agent_analysis', {
        correlateResult,
      });
      set({ agentVerdict: verdict, agentLoading: false });
    } catch (e: any) {
      set({ agentError: String(e), agentLoading: false });
    }
  },

  clearAgentVerdict: () => set({
    agentVerdict: null, agentError: null,
    actionsTaken: [], currentRound: 1, previousThreatScore: 0,
    agentReassessError: null,
  }),

  // ── Agent Round 2+ ─────────────────────────────────────────────────────────
  actionsTaken:        [],
  previousThreatScore: 0,
  currentRound:        1,
  agentReassessing:    false,
  agentReassessError:  null,

  recordExecutedAction: (action: ExecutedAction) => {
    set(s => ({ actionsTaken: [...s.actionsTaken, action] }));
  },

  runAgentReassessment: async () => {
    const { correlateResult, actionsTaken, currentRound } = get();

    // Compute threat score from the current graph before re-correlating
    const prevScore = (correlateResult?.graph?.nodes ?? [])
      .filter(n => n.threat_level === 'Malicious' || n.threat_level === 'Critical')
      .reduce((sum, n) => sum + ((n as any).combined_score ?? 0), 0);

    set({ agentReassessing: true, agentReassessError: null });

    // Re-correlate to get the post-action graph
    await get().correlateEntities(false);

    const freshResult = get().correlateResult;
    if (!freshResult) {
      set({ agentReassessing: false, agentReassessError: 'Re-correlation failed — no fresh graph available.' });
      return;
    }

    const nextRound = currentRound + 1;
    try {
      const verdict = await invoke<AgentVerdict>('run_agent_reassessment', {
        correlateResult:     freshResult,
        actionsTaken:        actionsTaken,
        round:               nextRound,
        previousThreatScore: prevScore,
      });
      set({
        agentVerdict:        verdict,
        currentRound:        nextRound,
        previousThreatScore: prevScore,
      });
    } catch (e: any) {
      set({ agentReassessError: String(e) });
    } finally {
      set({ agentReassessing: false });
    }
  },

  resetInvestigation: () => set({
    agentVerdict:        null,
    agentError:          null,
    actionsTaken:        [],
    currentRound:        1,
    previousThreatScore: 0,
    agentReassessing:    false,
    agentReassessError:  null,
  }),

  // ── Autonomous mode ────────────────────────────────────────────────────────
  autonomousMode:  false,
  autoRunning:     false,
  autoActionLog:   [],

  setAutonomousMode: (v) => set({ autonomousMode: v }),

  clearAutoLog: () => set({ autoActionLog: [] }),

  rollbackAutoAction: async (id) => {
    const entry = get().autoActionLog.find(e => e.id === id);
    if (!entry || entry.rolledBack || !entry.reversible || entry.result !== 'success') return;
    try {
      if (entry.action === 'quarantine_file' && entry.sha256) {
        await invoke('restore_quarantine_file', { sha256: entry.sha256 });
      } else if (entry.action === 'block_ip' && entry.ruleName) {
        await invoke('remove_block_ip', { ruleName: entry.ruleName });
      }
      set(s => ({
        autoActionLog: s.autoActionLog.map(e =>
          e.id === id ? { ...e, rolledBack: true, rollbackError: undefined } : e,
        ),
      }));
    } catch (e: any) {
      set(s => ({
        autoActionLog: s.autoActionLog.map(e =>
          e.id === id ? { ...e, rollbackError: String(e) } : e,
        ),
      }));
    }
  },

  rollbackAllAutoActions: async () => {
    const reversible = get().autoActionLog.filter(
      e => e.reversible && !e.rolledBack && e.result === 'success',
    );
    for (const entry of reversible) {
      await get().rollbackAutoAction(entry.id);
    }
  },

  _runAutonomousActions: async (result) => {
    // Step 1 — run agent analysis to get ranked actions
    set({
      agentLoading: true, agentError: null, agentVerdict: null,
      actionsTaken: [], currentRound: 1, previousThreatScore: 0, agentReassessError: null,
    });
    let verdict: AgentVerdict;
    try {
      verdict = await invoke<AgentVerdict>('run_agent_analysis', { correlateResult: result });
      set({ agentVerdict: verdict, agentLoading: false });
    } catch (e: any) {
      set({ agentError: String(e), agentLoading: false });
      return;
    }

    // Step 2 — execute only safe reversible actions (skip kill_process / isolate_network)
    const safeActions = verdict.ranked_actions.filter(
      a => a.reversible && !a.confirm_required,
    );
    if (safeActions.length === 0) return;

    set({ autoRunning: true });

    for (const action of safeActions) {
      const logEntry: AutoExecutedAction = {
        id:          crypto.randomUUID(),
        action:      action.action,
        target:      action.target,
        entity_id:   action.entity_id,
        executedAt:  new Date().toISOString(),
        result:      'pending',
        reversible:  action.reversible,
        rolledBack:  false,
      };
      set(s => ({ autoActionLog: [...s.autoActionLog, logEntry] }));

      const patch = (fields: Partial<AutoExecutedAction>) =>
        set(s => ({
          autoActionLog: s.autoActionLog.map(e =>
            e.id === logEntry.id ? { ...e, ...fields } : e,
          ),
        }));

      try {
        if (action.action === 'quarantine_file') {
          const r = await invoke<{ success: boolean; sha256?: string; error?: string }>(
            'quarantine_file', { path: action.target },
          );
          patch({ result: r.success ? 'success' : 'failed', sha256: r.sha256, error: r.error });
          if (r.success) get().recordExecutedAction({ action: action.action, target: action.target, entity_id: action.entity_id, executed_at: logEntry.executedAt, result: 'success', pid: action.pid });
        } else if (action.action === 'block_ip') {
          const r = await invoke<{ success: boolean; rule_name?: string; error?: string }>(
            'block_ip', { remoteIp: action.target, direction: 'out' },
          );
          patch({ result: r.success ? 'success' : 'failed', ruleName: r.rule_name, error: r.error });
          if (r.success) get().recordExecutedAction({ action: action.action, target: action.target, entity_id: action.entity_id, executed_at: logEntry.executedAt, result: 'success', pid: action.pid });
        } else if (action.action === 'dump_memory' && action.pid != null) {
          const r = await invoke<{ success: boolean; error?: string }>(
            'dump_memory', { pid: action.pid },
          );
          patch({ result: r.success ? 'success' : 'failed', error: r.error });
          if (r.success) get().recordExecutedAction({ action: action.action, target: action.target, entity_id: action.entity_id, executed_at: logEntry.executedAt, result: 'success', pid: action.pid });
        } else {
          patch({ result: 'failed', error: 'Unsupported action in autonomous mode' });
        }
      } catch (e: any) {
        patch({ result: 'failed', error: String(e) });
      }
    }

    set({ autoRunning: false });
  },

  // ── Network isolation ──────────────────────────────────────────────────────
  networkIsolated:     false,
  networkIsolating:    false,
  networkIsolateError: null,

  isolateNetworkAction: async () => {
    set({ networkIsolating: true, networkIsolateError: null });
    try {
      await invoke('isolate_network');
      set({ networkIsolated: true });
    } catch (e: any) {
      set({ networkIsolateError: String(e) });
    } finally {
      set({ networkIsolating: false });
    }
  },

  restoreNetworkAction: async () => {
    set({ networkIsolating: true, networkIsolateError: null });
    try {
      await invoke('restore_network');
      set({ networkIsolated: false });
    } catch (e: any) {
      set({ networkIsolateError: String(e) });
    } finally {
      set({ networkIsolating: false });
    }
  },

  // ── Steganography ML ───────────────────────────────────────────────────────
  stegScanRunning: false,
  stegScanError:   null,
  stegScanResults: null,

  scanImagesSteg: async (paths) => {
    if (paths.length === 0) return;
    set({ stegScanRunning: true, stegScanError: null, stegScanResults: null });
    try {
      const raw = await invoke<Array<{
        path: string; stego_prob: number | null; is_stego: boolean | null;
        verdict: string; lsb_ones_ratio: number | null;
        warning: string | null; error: string | null;
      }>>('scan_images_steg', { paths });

      const results: StegScanResult[] = raw.map(r => ({
        path:         r.path,
        fileName:     r.path.split(/[\\/]/).pop() ?? r.path,
        stegProb:     r.stego_prob,
        isStego:      r.is_stego,
        verdict:      (r.verdict === 'stego' || r.verdict === 'clean' || r.verdict === 'error')
                        ? r.verdict as StegScanResult['verdict']
                        : 'error',
        lsbOnesRatio: r.lsb_ones_ratio ?? null,
        warning:      r.warning,
        error:        r.error,
      }));
      set({ stegScanResults: results });
    } catch (e: any) {
      set({ stegScanError: String(e) });
    } finally {
      set({ stegScanRunning: false });
    }
  },

  clearStegScan: () => set({ stegScanRunning: false, stegScanError: null, stegScanResults: null }),

  embedStegTest: async (srcPath) => {
    try {
      const result = await invoke<{ success: boolean; dst_path?: string; error?: string }>(
        'embed_steg_test', { srcPath }
      );
      if (!result.success) throw new Error(result.error ?? 'Embed failed');
      return result.dst_path ?? null;
    } catch (e: any) {
      set({ stegScanError: String(e) });
      return null;
    }
  },

  history: [],
  addHistory: (entry) =>
    set((s) => ({ history: [entry, ...s.history].slice(0, 50) })),
}));
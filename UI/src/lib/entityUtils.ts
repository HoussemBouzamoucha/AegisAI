// src/lib/entityUtils.ts
//
// Builds unified ProcessEntity objects from raw scanner data.
// One entity per OS process — all owned network connections, memory regions,
// and matching files are embedded rather than standing as separate graph nodes.

import type {
  ProcessInfo, NetworkConnection, MemoryRegion, ScanResult,
  MlFlowResult, ProcessEntity, UnifiedThreat, GraphEdgeData, DetectionSignal,
} from '../types';

// ─── Internal helpers ─────────────────────────────────────────────────────────

const LEVEL_ORDER: Record<string, number> = {
  Critical: 4, Malicious: 3, Suspicious: 2, Clean: 1,
};

function maxThreat(levels: string[]): UnifiedThreat {
  let max = 0;
  let result: UnifiedThreat = 'Clean';
  for (const l of levels) {
    const o = LEVEL_ORDER[l] ?? 0;
    if (o > max) { max = o; result = l as UnifiedThreat; }
  }
  return result;
}

function unifyThreat(level: string): UnifiedThreat {
  if (level === 'Critical')   return 'Critical';
  if (level === 'Malicious')  return 'Malicious';
  if (level === 'Suspicious') return 'Suspicious';
  return 'Clean';
}

function parseRemoteIp(addr: string): { ip: string; port: number } | null {
  if (!addr || addr === '*') return null;
  const last = addr.lastIndexOf(':');
  if (last < 0) return null;
  return { ip: addr.slice(0, last), port: parseInt(addr.slice(last + 1)) };
}

function matchMlScore(remoteAddr: string, flows: MlFlowResult[]): number | undefined {
  const parsed = parseRemoteIp(remoteAddr);
  if (!parsed) return undefined;
  const flow = flows.find(
    (f) => (f.dstip === parsed.ip || f.srcip === parsed.ip) &&
           (f.dsport === parsed.port || f.sport === parsed.port),
  );
  return flow?.probability;
}

// ─── Primary builder ──────────────────────────────────────────────────────────

/**
 * Merge processes, connections, regions, and files into one ProcessEntity per PID.
 *
 * Ownership rules:
 *   • NetworkConnection  → owned by process if connection.pid === process.pid
 *   • MemoryRegion       → owned by process if region.pid === process.pid
 *   • ScanResult         → owned by process if file.path matches process.exe_path
 *     (case-insensitive). Only threat files are embedded.
 */
export function buildProcessEntities(
  processes:          ProcessInfo[],
  networkConnections: NetworkConnection[],
  memoryRegions:      MemoryRegion[],
  scanResults:        ScanResult[],
  mlFlows:            MlFlowResult[],
): ProcessEntity[] {
  // ── Index connections and regions by pid ──────────────────────────────────
  const netByPid = new Map<number, NetworkConnection[]>();
  const memByPid = new Map<number, MemoryRegion[]>();

  networkConnections.forEach((c) => {
    if (c.pid != null) {
      const arr = netByPid.get(c.pid) ?? [];
      arr.push(c);
      netByPid.set(c.pid, arr);
    }
  });

  memoryRegions.forEach((r) => {
    const arr = memByPid.get(r.pid) ?? [];
    arr.push(r);
    memByPid.set(r.pid, arr);
  });

  // ── Index threat files by lowercase path ──────────────────────────────────
  const fileByPath = new Map<string, ScanResult>();
  scanResults.forEach((f) => {
    if (f.level !== 'Clean') fileByPath.set(f.path.toLowerCase(), f);
  });

  // ── Build one ProcessEntity per process ───────────────────────────────────
  return processes.map((p): ProcessEntity => {
    const ownedNet   = netByPid.get(p.pid) ?? [];
    const ownedMem   = memByPid.get(p.pid) ?? [];
    const ownedFiles: ScanResult[] = p.exe_path
      ? (() => {
          const f = fileByPath.get(p.exe_path.toLowerCase());
          return f ? [f] : [];
        })()
      : [];

    // ── Per-domain scores (normalised to [0, 1]) ───────────────────────────
    const processScore = Math.min(p.threat_score / 30, 1);
    const networkScore = ownedNet.length
      ? Math.max(...ownedNet.map((c) => Math.min(c.threat_score / 40, 1)))
      : 0;
    const memoryScore = ownedMem.length
      ? Math.max(...ownedMem.map((r) => Math.min(r.threat_score / 40, 1)))
      : 0;
    const fileScore = ownedFiles.length
      ? Math.max(...ownedFiles.map((f) => f.confidence_score))
      : 0;

    // ── ML score: best probability across owned connections ────────────────
    let mlScore: number | undefined;
    if (ownedNet.length && mlFlows.length) {
      for (const c of ownedNet) {
        const s = matchMlScore(c.remote_address, mlFlows);
        if (s !== undefined) {
          mlScore = mlScore === undefined ? s : Math.max(mlScore, s);
        }
      }
    }

    // ── Combined score: heuristic max, blended with ML when available ──────
    const heuristicMax = Math.max(processScore, networkScore, memoryScore, fileScore);
    const combined = mlScore !== undefined
      ? Math.min(heuristicMax * 0.4 + mlScore * 0.6, 1)
      : heuristicMax;

    // ── Threat level: worst across all sub-entities ────────────────────────
    const threat = maxThreat([
      unifyThreat(p.threat_level),
      ...ownedNet.map((c) => unifyThreat(c.threat_level)),
      ...ownedMem.map((r) => r.is_threat ? unifyThreat(r.threat_level) : 'Clean'),
      ...ownedFiles.map((f) => unifyThreat(f.level)),
    ]);

    // ── Merge all detection signals ────────────────────────────────────────
    const signals: DetectionSignal[] = [
      ...p.detection_signals,
      ...ownedNet.flatMap((c) => c.detection_signals),
      ...ownedMem.flatMap((r) => r.detection_signals),
      ...ownedFiles.flatMap((f) => f.detection_signals),
    ];

    return {
      entity_id:        `proc:${p.pid}`,
      pid:              p.pid,
      name:             p.name,
      exe_path:         p.exe_path,
      command_line:     p.command_line,
      parent_pid:       p.parent_pid,
      user:             p.user,
      threat_level:     threat,
      combined_score:   combined,
      process_score:    processScore,
      network_score:    networkScore,
      memory_score:     memoryScore,
      file_score:       fileScore,
      network:          ownedNet,
      memory:           ownedMem,
      files:            ownedFiles,
      detection_signals: signals,
      anomaly_flags:    p.anomaly_flags,
      ml_score:         mlScore,
      raw:              p,
    };
  });
}

// ─── Edge builder ─────────────────────────────────────────────────────────────

/**
 * Build cross-process edges from a list of ProcessEntity objects.
 * Only edges that connect TWO DIFFERENT processes are emitted — all
 * intra-process relationships (network_owner, same_process, etc.) are
 * now embedded evidence inside the entity and not drawn as graph edges.
 *
 * Emitted edge kinds:
 *   parent_child    — process A has parent_pid = B's pid
 *   shared_c2       — two processes both connect to the same external IP
 *   shared_file_hash — two processes whose embedded files share a SHA-256 hash
 */
export function buildProcessEdges(entities: ProcessEntity[]): GraphEdgeData[] {
  const edges: GraphEdgeData[] = [];
  const byPid = new Map<number, ProcessEntity>(entities.map((e) => [e.pid, e]));

  // ── parent_child ──────────────────────────────────────────────────────────
  entities.forEach((e) => {
    if (e.parent_pid != null && byPid.has(e.parent_pid)) {
      edges.push({
        from:      `proc:${e.parent_pid}`,
        to:        `proc:${e.pid}`,
        edge_type: 'parent_child',
        weight:    1,
      });
    }
  });

  // ── shared_c2: multiple processes connected to the same external IP ───────
  const ipToProcs = new Map<string, Set<string>>();
  const LOOPBACK_RE = /^(127\.|::1$|0\.0\.0\.0$|::$)/;

  entities.forEach((e) => {
    e.network.forEach((c) => {
      const parsed = parseRemoteIp(c.remote_address);
      if (!parsed || LOOPBACK_RE.test(parsed.ip) || parsed.ip === '*') return;
      const set = ipToProcs.get(parsed.ip) ?? new Set<string>();
      set.add(e.entity_id);
      ipToProcs.set(parsed.ip, set);
    });
  });
  ipToProcs.forEach((procIds) => {
    const ids = [...procIds];
    if (ids.length < 2) return;
    for (let i = 0; i < ids.length - 1; i++)
      edges.push({ from: ids[i], to: ids[i + 1], edge_type: 'shared_c2', weight: 1 });
  });

  // ── shared_file_hash: two processes that loaded the same binary ───────────
  const hashToProcs = new Map<string, string[]>();
  entities.forEach((e) => {
    e.files.forEach((f) => {
      if (f.hash) {
        const arr = hashToProcs.get(f.hash) ?? [];
        arr.push(e.entity_id);
        hashToProcs.set(f.hash, arr);
      }
    });
  });
  hashToProcs.forEach((procIds) => {
    if (procIds.length < 2) return;
    for (let i = 0; i < procIds.length - 1; i++)
      edges.push({ from: procIds[i], to: procIds[i + 1], edge_type: 'shared_file_hash', weight: 1 });
  });

  return edges;
}

// ─── Orphan helpers ───────────────────────────────────────────────────────────

/** Network connections that have no matching process in the process list. */
export function orphanConnections(
  networkConnections: NetworkConnection[],
  processes:          ProcessInfo[],
): NetworkConnection[] {
  const pids = new Set(processes.map((p) => p.pid));
  return networkConnections.filter((c) => c.pid == null || !pids.has(c.pid));
}

/** Scan results that are not the exe of any known running process. */
export function orphanFiles(
  scanResults: ScanResult[],
  processes:   ProcessInfo[],
): ScanResult[] {
  const exePaths = new Set(
    processes.map((p) => p.exe_path?.toLowerCase()).filter(Boolean) as string[],
  );
  return scanResults.filter(
    (f) => f.level !== 'Clean' && !exePaths.has(f.path.toLowerCase()),
  );
}

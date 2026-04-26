// src/lib/entityUtils.ts
//
// Builds unified ProcessEntity objects from raw scanner data.
// One entity per OS process — all owned network connections, memory regions,
// and matching files are embedded rather than standing as separate graph nodes.

import type {
  ProcessInfo, NetworkConnection, MemoryRegion, ScanResult,
  MlFlowResult, ProcessEntity, UnifiedThreat, GraphEdgeData, GraphNodeData,
  DetectionSignal, AttackChain, AttackPatternName, CriticalPath,
  CorrelateResult, CorrelateEntityNode, EdgeKind, EntityKind,
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

// ─── Client-side correlation engine ──────────────────────────────────────────
// Mirrors the Rust entity/graph pipeline but runs purely in TypeScript using
// data already present in the Zustand store. No daemon call required.

const LEVEL_RANK: Record<string, number> = { Clean: 0, Suspicious: 1, Malicious: 2, Critical: 3 };

function maxThreatLevel(levels: (UnifiedThreat | string)[]): UnifiedThreat {
  return levels.reduce<UnifiedThreat>((best, l) =>
    (LEVEL_RANK[l] ?? 0) > (LEVEL_RANK[best] ?? 0) ? l as UnifiedThreat : best,
    'Clean',
  );
}

function isThreat(n: GraphNodeData) { return n.threat_level !== 'Clean'; }

/** Strip .exe / .dll / .sys suffixes (mirrors Rust strip_exe_suffix). */
function stripExe(name: string): string {
  for (const ext of ['.exe', '.EXE', '.dll', '.DLL', '.sys', '.SYS']) {
    if (name.endsWith(ext)) { const s = name.slice(0, -ext.length); if (s) return s; }
  }
  return name;
}

/** Convert an aggregated ProcessEntity → GraphNodeData. */
function entityToNode(e: ProcessEntity): GraphNodeData {
  const heuristic = Math.max(e.process_score, e.network_score, e.memory_score, e.file_score);
  return {
    entity_id:      e.entity_id,
    entity_type:    'entity' as EntityKind,
    threat_level:   e.threat_level,
    combined_score: e.combined_score,
    heuristic_score: heuristic,
    ml_score:       e.ml_score,
    label:          stripExe(e.name),
    sub_label:      e.exe_path ?? undefined,
    process_score:  e.process_score,
    network_score:  e.network_score,
    memory_score:   e.memory_score,
    file_score:     e.file_score,
    // Mirrors builder.rs: flag set only when sub-entity is Malicious (not just Suspicious)
    has_malicious_network: e.network.some((c) => c.threat_level === 'Malicious'),
    has_malicious_memory:  e.memory.some((r) => r.threat_level === 'Malicious'),
    has_malicious_file:    e.files.some((f) => f.level === 'Malicious'),
    pid:            e.pid,
    parent_pid:     e.parent_pid ?? undefined,
  };
}

/** Compute edge weight = avg(combined_scores) × type multiplier (mirrors builder.rs). */
function calcEdgeWeight(a: GraphNodeData, b: GraphNodeData, edgeType: EdgeKind): number {
  const avg = (a.combined_score + b.combined_score) / 2;
  const multipliers: Partial<Record<EdgeKind, number>> = {
    shared_c2:        1.50,
    parent_child:     1.20,
    shared_file_hash: 0.90,
  };
  return avg * (multipliers[edgeType] ?? 1.0);
}

/** Detect all six attack patterns (mirrors graph/analyzer.rs find_attack_chains_aggregated). */
function detectAttackChains(
  nodes: GraphNodeData[],
  edges: GraphEdgeData[],
  nodeMap: Record<string, GraphNodeData>,
): AttackChain[] {
  const chains: AttackChain[] = [];
  let idx = 0;
  const id = () => `local-chain-${++idx}`;

  const parentEdges = edges.filter((e) => e.edge_type === 'parent_child');

  // ── Patterns 1-3: single-node, detected from node flags ───────────────────
  nodes.forEach((n) => {
    if (n.has_malicious_memory) {
      chains.push({
        chain_id: id(), pattern: 'ProcessInjection' as AttackPatternName,
        node_ids: [n.entity_id], chain_score: n.combined_score,
        severity: n.threat_level, mitre_tactic: 'T1055',
        description: `"${n.label}" has malicious memory regions — possible shellcode injection`,
      });
    }
    if (n.has_malicious_network) {
      chains.push({
        chain_id: id(), pattern: 'C2Communication' as AttackPatternName,
        node_ids: [n.entity_id], chain_score: n.combined_score,
        severity: n.threat_level, mitre_tactic: 'T1071',
        description: `"${n.label}" has active connections matching C2 indicators`,
      });
    }
    if (n.has_malicious_file) {
      chains.push({
        chain_id: id(), pattern: 'MalwareExecution' as AttackPatternName,
        node_ids: [n.entity_id], chain_score: n.combined_score,
        severity: n.threat_level, mitre_tactic: 'T1204',
        description: `"${n.label}" is executing a known malicious file`,
      });
    }
  });

  // ── Pattern 4: LateralMovement — ParentChild + child has malicious network ─
  parentEdges.forEach((e) => {
    const parent = nodeMap[e.from], child = nodeMap[e.to];
    if (!parent || !child || !child.has_malicious_network) return;
    chains.push({
      chain_id: id(), pattern: 'LateralMovement' as AttackPatternName,
      node_ids: [e.from, e.to],
      chain_score: Math.max(parent.combined_score, child.combined_score),
      severity: maxThreatLevel([parent.threat_level, child.threat_level]),
      mitre_tactic: 'T1021',
      description: `"${parent.label}" spawned "${child.label}" which opened C2 connections`,
    });
  });

  // ── Pattern 5: SuspiciousSpawn — ParentChild + both are threats ───────────
  parentEdges.forEach((e) => {
    const parent = nodeMap[e.from], child = nodeMap[e.to];
    if (!parent || !child || !isThreat(parent) || !isThreat(child)) return;
    chains.push({
      chain_id: id(), pattern: 'SuspiciousSpawn' as AttackPatternName,
      node_ids: [e.from, e.to],
      chain_score: Math.max(parent.combined_score, child.combined_score),
      severity: maxThreatLevel([parent.threat_level, child.threat_level]),
      mitre_tactic: 'T1059',
      description: `"${parent.label}" (threat) spawned "${child.label}" (threat)`,
    });
  });

  // ── Pattern 6: MultiStageAttack — BFS, ≥3 connected threat nodes ─────────
  const adj = new Map<string, string[]>();
  edges.forEach((e) => {
    const a = adj.get(e.from) ?? []; a.push(e.to); adj.set(e.from, a);
    const b = adj.get(e.to)  ?? []; b.push(e.from); adj.set(e.to, b);
  });

  const threatIds = new Set(nodes.filter(isThreat).map((n) => n.entity_id));
  const bfsVisited = new Set<string>();

  threatIds.forEach((startId) => {
    if (bfsVisited.has(startId)) return;
    const component: string[] = [];
    const queue = [startId];
    while (queue.length > 0) {
      const cur = queue.shift()!;
      if (bfsVisited.has(cur)) continue;
      bfsVisited.add(cur);
      if (threatIds.has(cur)) component.push(cur);
      (adj.get(cur) ?? []).forEach((nb) => {
        if (!bfsVisited.has(nb) && threatIds.has(nb)) queue.push(nb);
      });
    }
    if (component.length >= 3) {
      const scores = component.map((id2) => nodeMap[id2]?.combined_score ?? 0);
      const avg = scores.reduce((a, b) => a + b, 0) / scores.length;
      chains.push({
        chain_id: id(), pattern: 'MultiStageAttack' as AttackPatternName,
        node_ids: component, chain_score: avg,
        severity: maxThreatLevel(component.map((id2) => nodeMap[id2]?.threat_level ?? 'Clean')),
        mitre_tactic: 'TA0002',
        description: `${component.length} threat entities linked in a multi-stage attack`,
      });
    }
  });

  return chains;
}

/** DFS max-weight path (mirrors graph/analyzer.rs find_critical_path). */
function findCriticalPath(
  nodes: GraphNodeData[],
  edges: GraphEdgeData[],
  nodeMap: Record<string, GraphNodeData>,
): CriticalPath | null {
  if (nodes.length < 2 || edges.length === 0) return null;

  // Build weighted adjacency (bidirectional)
  type AdjEntry = { to: string; edgeType: EdgeKind; weight: number };
  const adj = new Map<string, AdjEntry[]>();
  edges.forEach((e) => {
    const fn2 = nodeMap[e.from], tn = nodeMap[e.to];
    if (!fn2 || !tn) return;
    const w = calcEdgeWeight(fn2, tn, e.edge_type as EdgeKind);
    const a = adj.get(e.from) ?? []; a.push({ to: e.to,   edgeType: e.edge_type as EdgeKind, weight: w }); adj.set(e.from, a);
    const b = adj.get(e.to)  ?? []; b.push({ to: e.from, edgeType: e.edge_type as EdgeKind, weight: w }); adj.set(e.to, b);
  });

  let bestIds: string[] = [], bestTypes: string[] = [], bestWeights: number[] = [], bestScore = 0;

  // Only start DFS from threat nodes to keep it fast
  const startNodes = nodes.filter(isThreat);

  const dfs = (
    cur: string, visited: Set<string>,
    pathIds: string[], pathTypes: string[], pathWts: number[], total: number,
  ) => {
    if (total > bestScore && pathIds.length >= 2) {
      bestScore = total; bestIds = [...pathIds]; bestTypes = [...pathTypes]; bestWeights = [...pathWts];
    }
    (adj.get(cur) ?? []).forEach(({ to, edgeType, weight }) => {
      if (!visited.has(to)) {
        visited.add(to);
        dfs(to, visited, [...pathIds, to], [...pathTypes, edgeType], [...pathWts, weight], total + weight);
        visited.delete(to);
      }
    });
  };

  startNodes.forEach((n) => {
    const vis = new Set([n.entity_id]);
    dfs(n.entity_id, vis, [n.entity_id], [], [], 0);
  });

  if (bestIds.length < 2) return null;

  const narrative = bestIds.map((id2) => nodeMap[id2]?.label ?? id2).join(' → ');
  return { node_ids: bestIds, edge_types: bestTypes, edge_weights: bestWeights, total_score: bestScore, narrative };
}

/**
 * Build a full CorrelateResult from the data already in the Zustand store —
 * no daemon call, no re-scanning. Runs in milliseconds.
 *
 * For ML enrichment on network connections, pass `mlFlows` from
 * `mlIdsResult.flows` (empty array if ML IDS has not been run).
 */
export function buildCorrelateResultFromStore(
  processes:          ProcessInfo[],
  networkConnections: NetworkConnection[],
  memoryRegions:      MemoryRegion[],
  scanResults:        ScanResult[],
  mlFlows:            MlFlowResult[],
): CorrelateResult {
  const t0 = performance.now();

  // Only include threat memory regions (mirrors Rust ingest_memory filter)
  const threatMemory = memoryRegions.filter((r) => r.is_threat);

  // ── Build aggregated entities ──────────────────────────────────────────────
  const entities = buildProcessEntities(
    processes, networkConnections, threatMemory, scanResults, mlFlows,
  );

  // ── Convert to graph nodes ─────────────────────────────────────────────────
  const graphNodes: GraphNodeData[] = entities.map(entityToNode);

  // Add orphan threat network connections as standalone entity nodes
  orphanConnections(networkConnections, processes)
    .filter((c) => c.is_threat)
    .forEach((c) => {
      graphNodes.push({
        entity_id:      `entity-net:net:${c.protocol}:${c.local_address}:${c.remote_address}`,
        entity_type:    'network' as EntityKind,
        threat_level:   c.threat_level as UnifiedThreat,
        combined_score: Math.min(c.threat_score / 40, 1),
        heuristic_score: Math.min(c.threat_score / 40, 1),
        label:          `${c.protocol.toUpperCase()} → ${c.remote_address}`,
        sub_label:      c.process_name ?? undefined,
        has_malicious_network: c.threat_level === 'Malicious',
      });
    });

  // Add orphan malicious standalone files
  orphanFiles(scanResults, processes).forEach((f) => {
    const fileName = f.path.split(/[\\/]/).pop() ?? f.path;
    graphNodes.push({
      entity_id:      `entity-file:file:${f.hash ?? f.path}`,
      entity_type:    'file' as EntityKind,
      threat_level:   f.level as UnifiedThreat,
      combined_score: f.confidence_score,
      heuristic_score: f.confidence_score,
      label:          fileName,
      sub_label:      f.path,
      has_malicious_file: f.level === 'Malicious',
    });
  });

  const nodeMap: Record<string, GraphNodeData> =
    Object.fromEntries(graphNodes.map((n) => [n.entity_id, n]));

  // ── Build edges with weights ───────────────────────────────────────────────
  const graphEdges: GraphEdgeData[] = buildProcessEdges(entities).map((e) => ({
    ...e,
    weight: calcEdgeWeight(
      nodeMap[e.from] ?? { combined_score: 0 } as GraphNodeData,
      nodeMap[e.to]   ?? { combined_score: 0 } as GraphNodeData,
      e.edge_type as EdgeKind,
    ),
  }));

  // ── Attack chains + critical path ─────────────────────────────────────────
  const attackChains  = detectAttackChains(graphNodes, graphEdges, nodeMap);
  const criticalPath  = findCriticalPath(graphNodes, graphEdges, nodeMap);

  // ── Build CorrelateEntityNode list (used by EntityManager view) ───────────
  const entityNodes: CorrelateEntityNode[] = entities.map((e) => ({
    entity_id:         e.entity_id,
    entity_type:       'entity' as EntityKind,
    threat_level:      e.threat_level,
    combined_score:    e.combined_score,
    heuristic_score:   Math.max(e.process_score, e.network_score, e.memory_score, e.file_score),
    ml_score:          e.ml_score,
    join_keys:         { pid: e.pid, parent_pid: e.parent_pid ?? undefined, file_path: e.exe_path ?? undefined },
    detection_signals: e.detection_signals,
    label:             stripExe(e.name),
    sub_label:         e.exe_path ?? undefined,
  }));

  const durationMs = Math.round(performance.now() - t0);

  return {
    success: true,
    entities: entityNodes,
    clusters: [],          // EntityManager cluster view is not rebuilt client-side
    graph: {
      nodes:         graphNodes,
      edges:         graphEdges,
      attack_chains: attackChains,
      critical_path: criticalPath,
    },
    statistics: {
      total_entities:          entities.length,
      threat_entities:         entities.filter((e) => e.threat_level !== 'Clean').length,
      process_entities:        processes.length,
      network_entities:        networkConnections.length,
      memory_entities:         threatMemory.length,
      total_clusters:          0,
      threat_clusters:         0,
      graph_nodes:             graphNodes.length,
      graph_edges:             graphEdges.length,
      attack_chains_detected:  attackChains.length,
      include_memory:          threatMemory.length > 0,
      scan_duration_ms:        durationMs,
    },
  };
}

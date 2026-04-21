// File: UI/src/components/ThreatGraph.tsx
// Static radial graph — top 5 threat nodes, fixed positions, animated edges.
// Critical path (max-weight Dijkstra-like path from backend) is overlaid in gold.

import { useState, useMemo } from 'react';
import {
  Cpu, Wifi, HardDrive, FolderOpen,
  GitMerge, ShieldAlert, ShieldCheck, Loader, Network,
  TrendingUp,
} from 'lucide-react';
import { useStore } from '../store';
import type { GraphNodeData, GraphEdgeData, UnifiedThreat, CriticalPath } from '../types';

// ─── Layout constants ─────────────────────────────────────────────────────────

const NODE_R = 36;

// Gold colour for the critical path
const CRITICAL_COLOR = '#f59e0b';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function threatColor(level: UnifiedThreat | string): string {
  if (level === 'Critical' || level === 'Malicious') return '#ff3355';
  if (level === 'Suspicious') return '#ffb300';
  return '#00ff88';
}

function edgeColor(kind: string): string {
  if (kind === 'memory_injection' || kind === 'network_owner') return '#ff3355';
  if (kind === 'shared_c2'        || kind === 'process_opened_file') return '#ffb300';
  return '#00d4ff';
}

const EDGE_LABEL: Record<string, string> = {
  same_process:        'SAME PID',
  parent_child:        'SPAWNED',
  process_opened_file: 'OPENED FILE',
  shared_file_hash:    'SAME HASH',
  shared_c2:           'SHARED C2',
  network_owner:       'OWNS CONN',
  memory_injection:    'INJECTION',
};

// Edge weight multipliers (mirrors backend logic — used for display only)
const EDGE_MULTIPLIER: Record<string, number> = {
  memory_injection:    1.50,
  network_owner:       1.40,
  shared_c2:           1.30,
  process_opened_file: 1.20,
  parent_child:        1.10,
  same_process:        1.00,
  shared_file_hash:    0.90,
};

interface PlacedNode {
  id: string; x: number; y: number;
  data: GraphNodeData;
}

interface Layout {
  placed: PlacedNode[];
  vW: number;
  vH: number;
}

function computeLayout(nodes: GraphNodeData[]): Layout {
  const n   = nodes.length;
  const vW  = n > 25 ? 1300 : n > 12 ? 1050 : 800;
  const vH  = n > 25 ? 900  : n > 12 ? 700  : 520;
  if (n === 0) return { placed: [], vW, vH };

  const cx = vW / 2, cy = vH / 2;
  if (n === 1) return { placed: [{ id: nodes[0].entity_id, x: cx, y: cy, data: nodes[0] }], vW, vH };

  const minDim = Math.min(vW, vH);
  // Concentric rings — capacity and fractional radius of minDim
  const rings =
    n <= 8  ? [{ cap: n,      r: minDim * 0.32 }]
    : n <= 16 ? [{ cap: 7,   r: minDim * 0.22 }, { cap: n - 7,  r: minDim * 0.40 }]
              : [{ cap: 7,   r: minDim * 0.18 }, { cap: 13, r: minDim * 0.32 }, { cap: n - 20, r: minDim * 0.44 }];

  const placed: PlacedNode[] = [];
  let idx = 0;
  rings.forEach((ring, ri) => {
    const count = Math.min(ring.cap, n - idx);
    for (let i = 0; i < count && idx < n; i++, idx++) {
      const angle = (i / count) * Math.PI * 2 - Math.PI / 2 + ri * 0.18;
      placed.push({ id: nodes[idx].entity_id, x: cx + Math.cos(angle) * ring.r, y: cy + Math.sin(angle) * ring.r, data: nodes[idx] });
    }
  });
  return { placed, vW, vH };
}

// Mid-point offset so edges don't overlap when bidirectional
function edgePath(ax: number, ay: number, bx: number, by: number, idx: number): string {
  const mx = (ax + bx) / 2;
  const my = (ay + by) / 2;
  const dx = bx - ax, dy = by - ay;
  const len = Math.sqrt(dx * dx + dy * dy) || 1;
  const curve = 40 + idx * 10;
  const cx2 = mx - (dy / len) * curve;
  const cy2 = my + (dx / len) * curve;
  return `M${ax},${ay} Q${cx2},${cy2} ${bx},${by}`;
}

// Quadratic bezier midpoint for label placement
function bezierMid(ax: number, ay: number, bx: number, by: number, idx: number): [number, number] {
  const mx = (ax + bx) / 2;
  const my = (ay + by) / 2;
  const dx = bx - ax, dy = by - ay;
  const len = Math.sqrt(dx * dx + dy * dy) || 1;
  const curve = 40 + idx * 10;
  const cpx = mx - (dy / len) * curve;
  const cpy = my + (dx / len) * curve;
  const t = 0.5;
  const qx = (1-t)*(1-t)*ax + 2*(1-t)*t*cpx + t*t*bx;
  const qy = (1-t)*(1-t)*ay + 2*(1-t)*t*cpy + t*t*by;
  return [qx, qy];
}

// ─── Main component ───────────────────────────────────────────────────────────

export default function ThreatGraph() {
  const {
    correlating, correlateResult, correlateError,
    correlateEntities, clearCorrelate,
    processes, networkConnections, memoryRegions, scanResults,
  } = useStore();

  const [selected,      setSelected]      = useState<PlacedNode | null>(null);
  const [includeMemory, setIncludeMemory] = useState(false);

  // ── Build all visible nodes + edges + critical path ───────────────────────
  const { visNodes, visEdges, criticalPath } = useMemo(() => {
    let allNodes: GraphNodeData[] = [];
    let allEdges: GraphEdgeData[] = [];
    let criticalPath: CriticalPath | null = null;

    if (correlateResult?.graph?.nodes?.length) {
      // ── Backend correlate result ───────────────────────────────────────────
      allNodes     = correlateResult.graph.nodes;
      allEdges     = correlateResult.graph.edges ?? [];
      criticalPath = correlateResult.graph.critical_path ?? null;
    } else {
      // ── Fallback: build from raw scanner data ──────────────────────────────
      // Use consistent entity_id scheme: proc:{pid}, net:{local}:{remote}, mem:{pid}:{hex}, file:{hash|path}
      processes.forEach((p) => allNodes.push({
        entity_id: `proc:${p.pid}`, entity_type: 'process',
        threat_level: (p.threat_level === 'Safe' ? 'Clean' : p.threat_level) as UnifiedThreat,
        combined_score: Math.min(p.threat_score / 30, 1),
        heuristic_score: p.threat_score, label: p.name, sub_label: p.exe_path ?? undefined,
      }));
      networkConnections.forEach((c) => allNodes.push({
        entity_id: `net:${c.local_address}:${c.remote_address}`, entity_type: 'network',
        threat_level: c.threat_level as UnifiedThreat,
        combined_score: Math.min(c.threat_score / 40, 1),
        heuristic_score: c.threat_score,
        label: `${c.protocol.toUpperCase()} → ${c.remote_address}`,
        sub_label: c.process_name ?? undefined,
      }));
      memoryRegions.forEach((r) => allNodes.push({
        entity_id: `mem:${r.pid}:${r.region_start.toString(16)}`, entity_type: 'memory',
        threat_level: r.threat_level as UnifiedThreat,
        combined_score: Math.min(r.threat_score / 40, 1),
        heuristic_score: r.threat_score,
        label: `${r.process_name} @0x${r.region_start.toString(16).toUpperCase()}`,
      }));
      scanResults.forEach((f) => allNodes.push({
        entity_id: `file:${f.hash ?? f.path}`, entity_type: 'file',
        threat_level: f.level as UnifiedThreat,
        combined_score: f.confidence_score,
        heuristic_score: Math.round(f.confidence_score * 20),
        label: f.path.split(/[/\\]/).pop() ?? f.path, sub_label: f.path,
      }));

      // Build synthetic edges from known relationships
      const procIds = new Set(processes.map((p) => p.pid));
      // parent → child
      processes.forEach((p) => {
        if (p.parent_pid != null && procIds.has(p.parent_pid))
          allEdges.push({ from: `proc:${p.parent_pid}`, to: `proc:${p.pid}`, edge_type: 'parent_child', weight: 1 });
      });
      // process → its network connections (by pid)
      networkConnections.forEach((c) => {
        if (c.pid != null && procIds.has(c.pid))
          allEdges.push({ from: `proc:${c.pid}`, to: `net:${c.local_address}:${c.remote_address}`, edge_type: 'network_owner', weight: 1 });
      });
      // process → its memory regions (by pid)
      memoryRegions.forEach((r) => {
        if (procIds.has(r.pid))
          allEdges.push({ from: `proc:${r.pid}`, to: `mem:${r.pid}:${r.region_start.toString(16)}`, edge_type: 'memory_injection', weight: 1 });
      });
      // shared file hash edges
      const byHash = new Map<string, string[]>();
      scanResults.forEach((f) => {
        if (f.hash) {
          const id = `file:${f.hash}`;
          byHash.set(f.hash, [...(byHash.get(f.hash) ?? []), id]);
        }
      });
      byHash.forEach((ids) => {
        for (let i = 0; i < ids.length - 1; i++)
          allEdges.push({ from: ids[i], to: ids[i + 1], edge_type: 'shared_file_hash', weight: 1 });
      });
    }

    const order: Record<string, number> = { Critical: 4, Malicious: 3, Suspicious: 2, Clean: 1 };
    // Deduplicate by entity_id — keep highest-scoring entry
    const deduped = [...allNodes
      .sort((a, b) => b.combined_score - a.combined_score)
      .reduce((map, n) => { if (!map.has(n.entity_id)) map.set(n.entity_id, n); return map; }, new Map<string, typeof allNodes[0]>())
      .values()]
      .sort((a, b) => (order[b.threat_level] ?? 0) - (order[a.threat_level] ?? 0) || b.combined_score - a.combined_score);

    // Always include critical path nodes; fill remaining slots with highest-threat nodes
    const cpNodeIds = new Set(criticalPath?.node_ids ?? []);
    const cpNodes   = deduped.filter((n) => cpNodeIds.has(n.entity_id));
    const rest      = deduped.filter((n) => !cpNodeIds.has(n.entity_id)).slice(0, 60 - cpNodes.length);
    const visNodes  = [...cpNodes, ...rest];

    const ids      = new Set(visNodes.map((n) => n.entity_id));
    const visEdges = allEdges.filter((e) => ids.has(e.from) && ids.has(e.to));

    return { visNodes, visEdges, criticalPath };
  }, [correlateResult, processes, networkConnections, memoryRegions, scanResults]);

  const { placed, vW, vH } = useMemo(() => computeLayout(visNodes), [visNodes.map((n) => n.entity_id).join(',')]);
  const nodeMap             = useMemo(() => new Map(placed.map((n) => [n.id, n])), [placed]);

  // Build a set of edge pairs that are on the critical path (for highlighted rendering)
  const criticalEdgeSet = useMemo((): Set<string> => {
    if (!criticalPath || criticalPath.node_ids.length < 2) return new Set();
    const s = new Set<string>();
    for (let i = 0; i < criticalPath.node_ids.length - 1; i++) {
      const a = criticalPath.node_ids[i];
      const b = criticalPath.node_ids[i + 1];
      s.add(`${a}|||${b}`);
      s.add(`${b}|||${a}`);
    }
    return s;
  }, [criticalPath]);

  const criticalNodeSet = useMemo((): Set<string> => {
    if (!criticalPath) return new Set();
    return new Set(criticalPath.node_ids);
  }, [criticalPath]);

  const noData     = visNodes.length === 0;
  const hasBackend = !!correlateResult;

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', padding: 28, gap: 18, overflow: 'hidden' }}>

      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexShrink: 0 }}>
        <div>
          <div style={{ fontFamily: 'var(--font-hud)', fontSize: 20, fontWeight: 700, color: 'var(--text-bright)', letterSpacing: '0.05em' }}>
            THREAT GRAPH
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)', marginTop: 4 }}>
            {visNodes.length} node{visNodes.length !== 1 ? 's' : ''} · {visEdges.length} edge{visEdges.length !== 1 ? 's' : ''}
            {hasBackend && ` · ${correlateResult!.statistics.graph_nodes} total entities`}
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)', cursor: 'pointer' }}>
            <input type="checkbox" checked={includeMemory} onChange={(e) => setIncludeMemory(e.target.checked)}
              style={{ accentColor: 'var(--amber)' }} />
            Include memory
          </label>
          {hasBackend && (
            <button onClick={clearCorrelate} style={{
              padding: '6px 12px', borderRadius: 5, fontSize: 9, fontFamily: 'var(--font-hud)',
              background: 'transparent', border: '1px solid var(--border)', color: 'var(--text-dim)', cursor: 'pointer',
            }}>CLEAR</button>
          )}
          <button onClick={() => correlateEntities(includeMemory)} disabled={correlating} style={{
            display: 'flex', alignItems: 'center', gap: 7,
            padding: '7px 16px', borderRadius: 6, fontSize: 10, fontFamily: 'var(--font-hud)',
            background: correlating ? 'var(--elevated)' : 'rgba(16,185,129,0.12)',
            border: `1px solid ${correlating ? 'var(--border)' : 'var(--green)'}`,
            color: correlating ? 'var(--text-dim)' : 'var(--green)',
            cursor: correlating ? 'not-allowed' : 'pointer', letterSpacing: '0.06em',
          }}>
            {correlating
              ? <><Loader size={11} style={{ animation: 'spin 1s linear infinite' }} /> CORRELATING…</>
              : <><GitMerge size={11} /> CORRELATE</>}
          </button>
        </div>
      </div>

      {correlateError && (
        <div style={{
          padding: '8px 14px', borderRadius: 6, flexShrink: 0,
          background: 'rgba(255,51,85,0.08)', border: '1px solid rgba(255,51,85,0.25)',
          fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--red)',
        }}>{correlateError}</div>
      )}

      {/* Critical path banner */}
      {criticalPath && criticalPath.node_ids.length >= 2 && (
        <div style={{
          display: 'flex', alignItems: 'flex-start', gap: 14,
          padding: '12px 16px', borderRadius: 8, flexShrink: 0,
          background: 'rgba(245,158,11,0.07)',
          border: `1px solid ${CRITICAL_COLOR}40`,
        }}>
          <TrendingUp size={14} color={CRITICAL_COLOR} style={{ flexShrink: 0, marginTop: 3 }} />
          <div style={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column', gap: 8 }}>
            {/* Narrative — primary headline */}
            {criticalPath.narrative && (
              <div style={{
                fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-bright)',
                lineHeight: 1.7, fontWeight: 500,
              }}>
                {criticalPath.narrative}
              </div>
            )}
            <div style={{ fontFamily: 'var(--font-hud)', fontSize: 9, color: `${CRITICAL_COLOR}90`, letterSpacing: '0.08em' }}>
              CRITICAL PATH · SCORE {criticalPath.total_score.toFixed(3)} · {criticalPath.node_ids.length} NODES
            </div>
            {/* Path node chain */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 4, flexWrap: 'wrap' }}>
              {criticalPath.node_ids.map((nid, i) => {
                const node = correlateResult?.graph?.nodes?.find((n) => n.entity_id === nid);
                const label = node?.label ?? nid.split(':').slice(0, 2).join(':');
                const isLast = i === criticalPath.node_ids.length - 1;
                return (
                  <div key={nid} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                    <span style={{
                      fontFamily: 'var(--font-mono)', fontSize: 9,
                      color: CRITICAL_COLOR,
                      padding: '1px 6px', borderRadius: 3,
                      background: `${CRITICAL_COLOR}15`,
                      border: `1px solid ${CRITICAL_COLOR}30`,
                      maxWidth: 130, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                    }} title={label}>
                      {label}
                    </span>
                    {!isLast && (
                      <div style={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 8, color: `${CRITICAL_COLOR}80` }}>
                          {criticalPath.edge_types[i] ? `[${criticalPath.edge_weights[i].toFixed(2)}]` : ''}
                        </span>
                        <span style={{ color: CRITICAL_COLOR, fontSize: 10 }}>→</span>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
          {/* Per-hop weights breakdown */}
          <div style={{ display: 'flex', gap: 6, flexShrink: 0, flexWrap: 'wrap', maxWidth: 200 }}>
            {criticalPath.edge_types.map((et, i) => (
              <span key={i} style={{
                display: 'inline-flex', alignItems: 'center', gap: 3,
                padding: '1px 6px', borderRadius: 3,
                background: `${CRITICAL_COLOR}12`,
                fontFamily: 'var(--font-hud)', fontSize: 7,
                color: CRITICAL_COLOR, letterSpacing: '0.06em',
                border: `1px solid ${CRITICAL_COLOR}25`,
              }}>
                {(EDGE_MULTIPLIER[et] ?? 1.0).toFixed(1)}× · {criticalPath.edge_weights[i].toFixed(2)}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Canvas + detail */}
      <div style={{ flex: 1, display: 'flex', gap: 20, overflow: 'hidden', minHeight: 0 }}>

        {/* SVG */}
        <div style={{
          flex: 1, position: 'relative',
          background: 'var(--surface)', border: '1px solid var(--border)',
          borderRadius: 12, overflow: 'hidden', minWidth: 0,
        }}>
          {noData ? (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%', gap: 14 }}>
              <Network size={40} color="var(--text-dim)" style={{ opacity: 0.3 }} />
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-dim)' }}>No entity data</div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)', opacity: 0.6, textAlign: 'center', maxWidth: 280 }}>
                Run any scan, then click CORRELATE to build the graph
              </div>
            </div>
          ) : (
            <svg viewBox={`0 0 ${vW} ${vH}`} style={{ width: '100%', height: '100%' }}>
              <defs>
                {(['Clean','Suspicious','Malicious','Critical'] as UnifiedThreat[]).map((lvl) => (
                  <filter key={lvl} id={`gf-${lvl}`} x="-60%" y="-60%" width="220%" height="220%">
                    <feGaussianBlur stdDeviation={lvl === 'Clean' ? 5 : 10} result="blur" />
                    <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
                  </filter>
                ))}
                {/* Gold glow filter for critical path */}
                <filter id="gf-critical" x="-80%" y="-80%" width="260%" height="260%">
                  <feGaussianBlur stdDeviation={14} result="blur" />
                  <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
                </filter>
                <marker id="arr" markerWidth="7" markerHeight="7" refX="5" refY="3.5" orient="auto">
                  <path d="M0,0 L7,3.5 L0,7 Z" fill="rgba(200,230,212,0.35)" />
                </marker>
                <marker id="arr-critical" markerWidth="8" markerHeight="8" refX="6" refY="4" orient="auto">
                  <path d="M0,0 L8,4 L0,8 Z" fill={CRITICAL_COLOR} />
                </marker>
                <style>{`
                  @keyframes dashFlow     { to { stroke-dashoffset: -48; } }
                  @keyframes ringFade     { 0%,100%{opacity:.35} 50%{opacity:0} }
                  @keyframes criticalFlow { to { stroke-dashoffset: -32; } }
                  .edge-anim     { animation: dashFlow     2s linear infinite; }
                  .ring-anim     { animation: ringFade     2.2s ease-out infinite; }
                  .critical-anim { animation: criticalFlow 1.4s linear infinite; }
                `}</style>
              </defs>

              {/* Faint radial guides */}
              <circle cx={vW/2} cy={vH/2} r={Math.min(vW,vH)*0.20}
                fill="none" stroke="rgba(0,255,136,0.03)" strokeWidth={1} strokeDasharray="4 8" />
              <circle cx={vW/2} cy={vH/2} r={Math.min(vW,vH)*0.35}
                fill="none" stroke="rgba(0,255,136,0.02)" strokeWidth={1} strokeDasharray="4 8" />
              <circle cx={vW/2} cy={vH/2} r={Math.min(vW,vH)*0.46}
                fill="none" stroke="rgba(0,255,136,0.015)" strokeWidth={1} strokeDasharray="4 8" />

              {/* ── NORMAL edges (drawn first, underneath) ─────────────────── */}
              {visEdges.map((edge, i) => {
                const a = nodeMap.get(edge.from);
                const b = nodeMap.get(edge.to);
                if (!a || !b) return null;

                const key = `${edge.from}|||${edge.to}`;
                if (criticalEdgeSet.has(key)) return null; // drawn separately below

                const col  = edgeColor(edge.edge_type);
                const path = edgePath(a.x, a.y, b.x, b.y, i);
                const [qx, qy] = bezierMid(a.x, a.y, b.x, b.y, i);
                return (
                  <g key={i}>
                    <path d={path} fill="none" stroke={`${col}20`} strokeWidth={4} />
                    <path d={path} fill="none" stroke={`${col}55`} strokeWidth={2} markerEnd="url(#arr)" />
                    <path d={path} fill="none" stroke={col} strokeWidth={1.5}
                      strokeDasharray="10 14" className="edge-anim"
                      style={{ animationDelay: `${i * 0.35}s` }} opacity={0.85} />
                    <rect x={qx - 28} y={qy - 8} width={56} height={14}
                      rx={4} fill="var(--base)" stroke={`${col}40`} strokeWidth={1} />
                    <text x={qx} y={qy + 3.5} textAnchor="middle"
                      fontFamily="'IBM Plex Mono', monospace" fontSize={7.5} fill={col}
                      style={{ pointerEvents: 'none' }}>
                      {EDGE_LABEL[edge.edge_type] ?? edge.edge_type}
                    </text>
                  </g>
                );
              })}

              {/* ── CRITICAL PATH edges (drawn on top) ────────────────────── */}
              {criticalPath && criticalPath.node_ids.length >= 2 &&
                criticalPath.node_ids.slice(0, -1).map((fromId, i) => {
                  const toId = criticalPath.node_ids[i + 1];
                  const a = nodeMap.get(fromId);
                  const b = nodeMap.get(toId);
                  if (!a || !b) return null;

                  const et     = criticalPath.edge_types[i] ?? '';
                  const weight = criticalPath.edge_weights[i] ?? 0;
                  const path   = edgePath(a.x, a.y, b.x, b.y, i + visEdges.length); // offset so curves don't overlap
                  const [qx, qy] = bezierMid(a.x, a.y, b.x, b.y, i + visEdges.length);

                  return (
                    <g key={`cp-${i}`}>
                      {/* Outer gold glow */}
                      <path d={path} fill="none"
                        stroke={CRITICAL_COLOR} strokeWidth={10}
                        opacity={0.08} />
                      {/* Thick base */}
                      <path d={path} fill="none"
                        stroke={CRITICAL_COLOR} strokeWidth={3.5}
                        opacity={0.4} markerEnd="url(#arr-critical)" />
                      {/* Moving dashes */}
                      <path d={path} fill="none"
                        stroke={CRITICAL_COLOR} strokeWidth={2}
                        strokeDasharray="8 10" className="critical-anim"
                        style={{ animationDelay: `${i * 0.22}s` }}
                        opacity={0.95} />
                      {/* Weight label pill */}
                      <rect x={qx - 30} y={qy - 9} width={60} height={16}
                        rx={5} fill="#1a1200" stroke={`${CRITICAL_COLOR}60`} strokeWidth={1.5} />
                      <text x={qx} y={qy + 3} textAnchor="middle"
                        fontFamily="'IBM Plex Mono', monospace" fontSize={8} fill={CRITICAL_COLOR}
                        fontWeight="bold" style={{ pointerEvents: 'none' }}>
                        {EDGE_LABEL[et] ?? et} · {weight.toFixed(2)}
                      </text>
                    </g>
                  );
                })
              }

              {/* ── Nodes ──────────────────────────────────────────────────── */}
              {placed.map((node) => {
                const col       = threatColor(node.data.threat_level);
                const isThreat  = node.data.threat_level !== 'Clean';
                const isSel     = selected?.id === node.id;
                const isOnPath  = criticalNodeSet.has(node.id);
                const label     = node.data.label.length > 15 ? node.data.label.slice(0, 14) + '…' : node.data.label;

                // Score arc
                const arcR  = NODE_R - 5;
                const pct   = Math.min(node.data.combined_score, 0.9999);
                const angle = pct * 2 * Math.PI - Math.PI / 2;
                const arcX  = arcR * Math.cos(angle);
                const arcY  = arcR * Math.sin(angle);
                const large = pct > 0.5 ? 1 : 0;

                return (
                  <g key={node.id} transform={`translate(${node.x},${node.y})`}
                    style={{ cursor: 'pointer' }}
                    onClick={() => setSelected(isSel ? null : node)}>

                    {/* Critical path gold halo */}
                    {isOnPath && (
                      <circle r={NODE_R + 18} fill={`${CRITICAL_COLOR}10`}
                        stroke={CRITICAL_COLOR} strokeWidth={2}
                        strokeDasharray="6 4" opacity={0.7}
                        filter="url(#gf-critical)" />
                    )}

                    {/* Pulsing threat ring */}
                    {isThreat && (
                      <circle r={NODE_R + 6} fill="none" stroke={col}
                        strokeWidth={1.5} className="ring-anim"
                        style={{ animationDelay: `${placed.indexOf(node) * 0.45}s` }} />
                    )}

                    {/* Selection ring */}
                    {isSel && (
                      <circle r={NODE_R + 12} fill="none" stroke={col}
                        strokeWidth={2} strokeDasharray="5 4" opacity={0.8} />
                    )}

                    {/* Glow fill */}
                    <circle r={NODE_R} fill={`${col}12`}
                      filter={`url(#gf-${node.data.threat_level})`} />

                    {/* Main circle */}
                    <circle r={NODE_R}
                      fill={isSel ? `${col}22` : '#0f1830'}
                      stroke={isOnPath ? CRITICAL_COLOR : col}
                      strokeWidth={isOnPath ? 3 : (isSel ? 2.5 : 1.8)} />

                    {/* Score arc */}
                    {pct > 0.01 && (
                      <path d={`M0,${-arcR} A${arcR},${arcR} 0 ${large},1 ${arcX},${arcY}`}
                        fill="none" stroke={isOnPath ? CRITICAL_COLOR : col} strokeWidth={3.5}
                        strokeLinecap="round" opacity={0.9}
                        style={{ pointerEvents: 'none' }} />
                    )}

                    {/* Score % */}
                    <text y={-7} textAnchor="middle"
                      fontFamily="'Orbitron', monospace" fontSize={11} fontWeight={700}
                      fill={isOnPath ? CRITICAL_COLOR : col} style={{ pointerEvents: 'none' }}>
                      {(node.data.combined_score * 100).toFixed(0)}%
                    </text>

                    {/* Type tag */}
                    <text y={8} textAnchor="middle"
                      fontFamily="'IBM Plex Mono', monospace" fontSize={8}
                      fill={`${isOnPath ? CRITICAL_COLOR : col}99`} style={{ pointerEvents: 'none' }}>
                      {node.data.entity_type.slice(0, 4).toUpperCase()}
                    </text>

                    {/* Name label */}
                    <text y={NODE_R + 16} textAnchor="middle"
                      fontFamily="'IBM Plex Mono', monospace" fontSize={10}
                      fill={isOnPath ? CRITICAL_COLOR : (isThreat ? col : 'var(--text)')}
                      style={{ pointerEvents: 'none' }}>
                      {label}
                    </text>

                    {/* Threat level */}
                    {isThreat && (
                      <text y={NODE_R + 29} textAnchor="middle"
                        fontFamily="'Orbitron', monospace" fontSize={7.5}
                        fill={isOnPath ? CRITICAL_COLOR : col} style={{ pointerEvents: 'none' }}>
                        ● {node.data.threat_level.toUpperCase()}
                      </text>
                    )}

                    {/* Critical path rank badge */}
                    {isOnPath && (() => {
                      const idx = criticalPath!.node_ids.indexOf(node.id);
                      return (
                        <g transform={`translate(${NODE_R - 6}, ${-NODE_R + 6})`}>
                          <circle r={9} fill={CRITICAL_COLOR} />
                          <text textAnchor="middle" dy="0.35em"
                            fontFamily="'Orbitron', monospace" fontSize={8} fontWeight={700}
                            fill="#000" style={{ pointerEvents: 'none' }}>
                            {idx + 1}
                          </text>
                        </g>
                      );
                    })()}
                  </g>
                );
              })}
            </svg>
          )}

          {/* Bottom hint */}
          {!noData && (
            <div style={{
              position: 'absolute', bottom: 10, left: 14,
              fontFamily: 'var(--font-mono)', fontSize: 8, color: 'var(--text-dim)', opacity: 0.4,
            }}>
              click node to inspect · {visNodes.length} nodes · {visEdges.length} edges
              {criticalPath && ` · critical path: ${criticalPath.node_ids.length} nodes`}
            </div>
          )}
        </div>

        {/* Detail / legend panel */}
        <div style={{ width: 270, flexShrink: 0, display: 'flex', flexDirection: 'column', gap: 12, overflowY: 'auto' }}>
          {selected
            ? <DetailPanel node={selected} edges={visEdges} nodeMap={nodeMap} onClose={() => setSelected(null)} criticalPath={criticalPath} />
            : <LegendPanel hasBackend={hasBackend} nodeCount={visNodes.length} correlateResult={correlateResult} criticalPath={criticalPath} />}
        </div>
      </div>
    </div>
  );
}

// ─── Activity helpers ─────────────────────────────────────────────────────────

interface ActivityItem {
  direction: 'out' | 'in';
  edgeType:  string;
  verb:      string;        // past-tense action
  preposition: string;      // "to" | "from" | "with" | "into"
  targetLabel: string;
  targetType:  string;
  targetThreat: string;
  targetScore:  number;
  accentColor:  string;
  icon:         string;     // emoji glyph used as inline icon
}

function buildActivity(nodeId: string, edges: GraphEdgeData[], nodeMap: Map<string, PlacedNode>): ActivityItem[] {
  const items: ActivityItem[] = [];

  edges.forEach((e) => {
    const isOut  = e.from === nodeId;
    const isIn   = e.to   === nodeId;
    if (!isOut && !isIn) return;

    const otherId     = isOut ? e.to : e.from;
    const other       = nodeMap.get(otherId);
    const targetLabel = other?.data.label ?? otherId.split(':').slice(0, 2).join(':');
    const targetType  = other?.data.entity_type ?? otherId.split(':')[0] ?? 'unknown';
    const targetThreat = other?.data.threat_level ?? 'Clean';
    const targetScore  = other?.data.combined_score ?? 0;

    type Config = { verb: string; prep: string; color: string; icon: string };
    const OUT: Record<string, Config> = {
      parent_child:        { verb: 'Spawned',           prep: 'child process',        color: '#00d4ff', icon: '▶' },
      network_owner:       { verb: 'Connected',         prep: 'to',                   color: '#ffb300', icon: '⇢' },
      memory_injection:    { verb: 'Injected code',     prep: 'into',                 color: '#ff3355', icon: '⚡' },
      process_opened_file: { verb: 'Opened file',       prep: '',                     color: '#a78bfa', icon: '📄' },
      shared_file_hash:    { verb: 'Same binary as',    prep: '',                     color: '#6ee7b7', icon: '=' },
      shared_c2:           { verb: 'Shares C2 with',    prep: '',                     color: '#ff3355', icon: '⚠' },
      same_process:        { verb: 'Co-process with',   prep: '',                     color: '#00ff88', icon: '○' },
    };
    const IN: Record<string, Config> = {
      parent_child:        { verb: 'Spawned by',        prep: 'parent',               color: '#00d4ff', icon: '◀' },
      network_owner:       { verb: 'Owned by',          prep: 'process',              color: '#ffb300', icon: '⇠' },
      memory_injection:    { verb: 'Injected by',       prep: '',                     color: '#ff3355', icon: '⚡' },
      process_opened_file: { verb: 'Accessed by',       prep: 'process',              color: '#a78bfa', icon: '📄' },
      shared_file_hash:    { verb: 'Same binary as',    prep: '',                     color: '#6ee7b7', icon: '=' },
      shared_c2:           { verb: 'Shares C2 with',    prep: '',                     color: '#ff3355', icon: '⚠' },
      same_process:        { verb: 'Co-process with',   prep: '',                     color: '#00ff88', icon: '○' },
    };

    const cfg = (isOut ? OUT : IN)[e.edge_type];
    if (!cfg) return;

    items.push({
      direction:    isOut ? 'out' : 'in',
      edgeType:     e.edge_type,
      verb:         cfg.verb,
      preposition:  cfg.prep,
      targetLabel, targetType, targetThreat, targetScore,
      accentColor:  cfg.color,
      icon:         cfg.icon,
    });
  });

  return items;
}

function buildSummary(activity: ActivityItem[]): string {
  const out = (et: string) => activity.filter((a) => a.direction === 'out' && a.edgeType === et);
  const inn = (et: string) => activity.filter((a) => a.direction === 'in'  && a.edgeType === et);

  const spawned     = out('parent_child');
  const spawnedBy   = inn('parent_child');
  const conns       = out('network_owner');
  const ownedBy     = inn('network_owner');
  const injected    = out('memory_injection');
  const injectedBy  = inn('memory_injection');
  const filesOpened = out('process_opened_file');
  const sharedC2    = activity.filter((a) => a.edgeType === 'shared_c2');
  const sharedHash  = activity.filter((a) => a.edgeType === 'shared_file_hash');

  const parts: string[] = [];

  if (spawnedBy.length)   parts.push(`launched by ${spawnedBy[0].targetLabel}`);
  if (spawned.length)     parts.push(`spawned ${spawned.length} child process${spawned.length > 1 ? 'es' : ''} (${spawned.map(a => a.targetLabel).join(', ')})`);
  if (conns.length)       parts.push(`opened ${conns.length} network connection${conns.length > 1 ? 's' : ''}`);
  if (ownedBy.length)     parts.push(`connection owned by ${ownedBy[0].targetLabel}`);
  if (injected.length)    parts.push(`injected code into ${injected.length} memory region${injected.length > 1 ? 's' : ''}`);
  if (injectedBy.length)  parts.push(`code injected by ${injectedBy[0].targetLabel}`);
  if (filesOpened.length) parts.push(`accessed ${filesOpened.length} file${filesOpened.length > 1 ? 's' : ''}`);
  if (sharedC2.length)    parts.push(`shares C2 infrastructure with ${sharedC2.length} other entit${sharedC2.length > 1 ? 'ies' : 'y'}`);
  if (sharedHash.length)  parts.push(`same binary detected in ${sharedHash.length} other location${sharedHash.length > 1 ? 's' : ''}`);

  if (!parts.length) return 'No relationships detected for this entity.';
  const [first, ...rest] = parts;
  return (first.charAt(0).toUpperCase() + first.slice(1))
    + (rest.length ? ', ' + rest.join(', ') : '') + '.';
}

// ─── Detail Panel ─────────────────────────────────────────────────────────────

function DetailPanel({ node, edges, nodeMap, onClose, criticalPath }: {
  node: PlacedNode; edges: GraphEdgeData[];
  nodeMap: Map<string, PlacedNode>; onClose: () => void;
  criticalPath: CriticalPath | null;
}) {
  const col      = threatColor(node.data.threat_level);
  const pathIdx  = criticalPath?.node_ids.indexOf(node.id) ?? -1;
  const isOnPath = pathIdx !== -1;
  const accent   = isOnPath ? CRITICAL_COLOR : col;

  const activity   = buildActivity(node.id, edges, nodeMap);
  const summary    = buildSummary(activity);
  const outActions = activity.filter((a) => a.direction === 'out');
  const inActions  = activity.filter((a) => a.direction === 'in');

  return (
    <>
      {/* ── Identity card ─────────────────────────────────────────────── */}
      <div style={{
        background: 'var(--surface)',
        border: `1px solid ${accent}40`,
        borderRadius: 10, padding: 16, display: 'flex', flexDirection: 'column', gap: 12,
      }}>
        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{
            width: 36, height: 36, borderRadius: 8, flexShrink: 0,
            background: `${accent}18`, border: `1px solid ${accent}40`,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>
            <NodeIcon type={node.data.entity_type} color={accent} size={16} />
          </div>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: accent, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={node.data.label}>
              {node.data.label}
            </div>
            <div style={{ fontFamily: 'var(--font-hud)', fontSize: 8, color: 'var(--text-dim)', marginTop: 2, letterSpacing: '0.08em' }}>
              {node.data.entity_type.toUpperCase()}
              {isOnPath && <span style={{ color: CRITICAL_COLOR, marginLeft: 8 }}>PATH NODE #{pathIdx + 1}</span>}
            </div>
          </div>
          <button onClick={onClose} style={{ background: 'transparent', border: 'none', color: 'var(--text-dim)', cursor: 'pointer', fontSize: 14, flexShrink: 0 }}>✕</button>
        </div>

        {/* Scores */}
        <div style={{ display: 'flex', gap: 8 }}>
          <Chip label="COMBINED"  value={`${(node.data.combined_score * 100).toFixed(1)}%`} color={accent} />
          <Chip label="HEURISTIC" value={String(node.data.heuristic_score)} color="var(--cyan)" />
          {node.data.ml_score !== undefined && (
            <Chip label="ML" value={`${(node.data.ml_score * 100).toFixed(1)}%`} color="#a78bfa" />
          )}
        </div>

        {/* Threat badge */}
        <div style={{
          display: 'flex', alignItems: 'center', gap: 8, padding: '7px 12px', borderRadius: 6,
          background: `${accent}10`, border: `1px solid ${accent}25`,
        }}>
          {node.data.threat_level === 'Clean'
            ? <ShieldCheck size={13} color={col} />
            : <ShieldAlert size={13} color={accent} />}
          <span style={{ fontFamily: 'var(--font-hud)', fontSize: 11, color: accent, letterSpacing: '0.08em' }}>
            {node.data.threat_level.toUpperCase()}
          </span>
          {isOnPath && pathIdx < (criticalPath?.edge_weights.length ?? 0) && (
            <span style={{ marginLeft: 'auto', fontFamily: 'var(--font-mono)', fontSize: 8, color: CRITICAL_COLOR }}>
              next hop ×{criticalPath!.edge_weights[pathIdx].toFixed(2)}
            </span>
          )}
        </div>

        {/* Sub-label (path / address) */}
        {node.data.sub_label && (
          <div style={{
            fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)',
            padding: '5px 8px', background: 'var(--base)', borderRadius: 5,
            wordBreak: 'break-all', lineHeight: 1.5,
          }}>
            {node.data.sub_label}
          </div>
        )}
      </div>

      {/* ── Behaviour summary ─────────────────────────────────────────── */}
      <div style={{
        background: 'var(--surface)', border: '1px solid var(--border)',
        borderRadius: 10, padding: 14, display: 'flex', flexDirection: 'column', gap: 6,
      }}>
        <div style={{ fontFamily: 'var(--font-hud)', fontSize: 9, color: 'var(--text-dim)', letterSpacing: '0.1em', marginBottom: 2 }}>
          BEHAVIOUR SUMMARY
        </div>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text)', lineHeight: 1.7 }}>
          {summary}
        </div>
      </div>

      {/* ── Actions this node performed ───────────────────────────────── */}
      {outActions.length > 0 && (
        <ActivitySection title="ACTIONS PERFORMED" items={outActions} />
      )}

      {/* ── Events received ───────────────────────────────────────────── */}
      {inActions.length > 0 && (
        <ActivitySection title="RECEIVED FROM" items={inActions} />
      )}

      {activity.length === 0 && (
        <div style={{
          background: 'var(--surface)', border: '1px solid var(--border)',
          borderRadius: 10, padding: 14,
          fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)', textAlign: 'center',
        }}>
          No edges for this entity
        </div>
      )}
    </>
  );
}

function ActivitySection({ title, items }: {
  title: string; items: ActivityItem[];
}) {
  return (
    <div style={{
      background: 'var(--surface)', border: '1px solid var(--border)',
      borderRadius: 10, padding: 14, display: 'flex', flexDirection: 'column', gap: 8,
    }}>
      <div style={{ fontFamily: 'var(--font-hud)', fontSize: 9, color: 'var(--text-dim)', letterSpacing: '0.1em', marginBottom: 2 }}>
        {title} ({items.length})
      </div>
      {items.map((a, i) => {
        const tc = threatColor(a.targetThreat);
        return (
          <div key={i} style={{
            borderLeft: `3px solid ${a.accentColor}60`,
            paddingLeft: 10,
            display: 'flex', flexDirection: 'column', gap: 4,
          }}>
            {/* Verb row */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <span style={{ fontSize: 11, lineHeight: 1, flexShrink: 0 }}>{a.icon}</span>
              <span style={{
                fontFamily: 'var(--font-hud)', fontSize: 10, fontWeight: 700,
                color: a.accentColor, letterSpacing: '0.04em',
              }}>
                {a.verb}
              </span>
              {a.preposition && (
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)' }}>
                  {a.preposition}
                </span>
              )}
            </div>
            {/* Target chip */}
            <div style={{
              display: 'flex', alignItems: 'center', gap: 6,
              padding: '4px 8px', borderRadius: 5,
              background: `${tc}10`, border: `1px solid ${tc}25`,
            }}>
              <NodeIcon type={a.targetType} color={tc} size={11} />
              <span style={{
                flex: 1, fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text)',
                overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
              }} title={a.targetLabel}>
                {a.targetLabel}
              </span>
              <span style={{
                fontFamily: 'var(--font-hud)', fontSize: 9, fontWeight: 700,
                color: tc, flexShrink: 0,
              }}>
                {(a.targetScore * 100).toFixed(0)}%
              </span>
              <span style={{
                fontFamily: 'var(--font-hud)', fontSize: 7,
                color: tc, opacity: 0.8, flexShrink: 0,
              }}>
                {a.targetThreat.toUpperCase()}
              </span>
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ─── Legend Panel ─────────────────────────────────────────────────────────────

function LegendPanel({ hasBackend, nodeCount, correlateResult, criticalPath }: {
  hasBackend: boolean; nodeCount: number; correlateResult: any;
  criticalPath: CriticalPath | null;
}) {
  return (
    <>
      {/* Critical path summary card */}
      {criticalPath && criticalPath.node_ids.length >= 2 && (
        <div style={{
          background: `${CRITICAL_COLOR}06`, border: `1px solid ${CRITICAL_COLOR}35`,
          borderRadius: 10, padding: 14, display: 'flex', flexDirection: 'column', gap: 8,
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <TrendingUp size={12} color={CRITICAL_COLOR} />
            <div style={{ fontFamily: 'var(--font-hud)', fontSize: 9, color: CRITICAL_COLOR, letterSpacing: '0.1em' }}>
              CRITICAL PATH
            </div>
          </div>
          {[
            { label: 'Path Length',  value: `${criticalPath.node_ids.length} nodes` },
            { label: 'Total Score',  value: criticalPath.total_score.toFixed(3) },
            { label: 'Hops',         value: criticalPath.edge_types.length },
            { label: 'Max Hop Wt',   value: Math.max(...criticalPath.edge_weights).toFixed(3) },
          ].map(({ label, value }) => (
            <div key={label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)' }}>{label}</span>
              <span style={{ fontFamily: 'var(--font-hud)', fontSize: 12, fontWeight: 700, color: CRITICAL_COLOR }}>{value}</span>
            </div>
          ))}
          {/* Narrative */}
          {criticalPath.narrative && (
            <>
              <div style={{ height: 1, background: `${CRITICAL_COLOR}25`, margin: '2px 0' }} />
              <div style={{ fontFamily: 'var(--font-hud)', fontSize: 8, color: `${CRITICAL_COLOR}80`, letterSpacing: '0.08em' }}>
                CHAIN NARRATIVE
              </div>
              <div style={{
                fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text)',
                lineHeight: 1.7, padding: '6px 8px', borderRadius: 5,
                background: `${CRITICAL_COLOR}08`, border: `1px solid ${CRITICAL_COLOR}20`,
              }}>
                {criticalPath.narrative}
              </div>
            </>
          )}
          {/* Multiplier breakdown */}
          <div style={{ height: 1, background: `${CRITICAL_COLOR}25`, margin: '2px 0' }} />
          <div style={{ fontFamily: 'var(--font-hud)', fontSize: 8, color: `${CRITICAL_COLOR}80`, letterSpacing: '0.08em' }}>
            EDGE TYPE MULTIPLIERS
          </div>
          {criticalPath.edge_types.map((et, i) => (
            <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 8, color: CRITICAL_COLOR, opacity: 0.8 }}>
                {EDGE_LABEL[et] ?? et}
              </span>
              <span style={{ fontFamily: 'var(--font-hud)', fontSize: 9, color: CRITICAL_COLOR }}>
                ×{(EDGE_MULTIPLIER[et] ?? 1).toFixed(2)} → {criticalPath.edge_weights[i].toFixed(3)}
              </span>
            </div>
          ))}
        </div>
      )}

      {hasBackend && (
        <div style={{
          background: 'var(--surface)', border: '1px solid var(--border)',
          borderRadius: 10, padding: 14, display: 'flex', flexDirection: 'column', gap: 10,
        }}>
          <div style={{ fontFamily: 'var(--font-hud)', fontSize: 9, color: 'var(--text-dim)', letterSpacing: '0.1em' }}>GRAPH STATS</div>
          {[
            { label: 'Total Nodes',   value: correlateResult?.statistics?.graph_nodes ?? 0 },
            { label: 'Total Edges',   value: correlateResult?.statistics?.graph_edges ?? 0 },
            { label: 'Threat Nodes',  value: correlateResult?.statistics?.threat_entities ?? 0 },
            { label: 'Attack Chains', value: correlateResult?.graph?.attack_chains?.length ?? 0 },
          ].map(({ label, value }) => (
            <div key={label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)' }}>{label}</span>
              <span style={{ fontFamily: 'var(--font-hud)', fontSize: 13, fontWeight: 700, color: 'var(--text-bright)' }}>{value}</span>
            </div>
          ))}
        </div>
      )}

      <div style={{
        background: 'var(--surface)', border: '1px solid var(--border)',
        borderRadius: 10, padding: 14, display: 'flex', flexDirection: 'column', gap: 10,
      }}>
        <div style={{ fontFamily: 'var(--font-hud)', fontSize: 9, color: 'var(--text-dim)', letterSpacing: '0.1em' }}>LEGEND</div>
        {[
          { color: '#ff3355',    label: 'Critical / Malicious' },
          { color: '#ffb300',    label: 'Suspicious' },
          { color: '#00ff88',    label: 'Clean' },
          { color: CRITICAL_COLOR, label: 'Critical path node' },
        ].map(({ color, label }) => (
          <div key={label} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{ width: 10, height: 10, borderRadius: '50%', background: color, boxShadow: `0 0 6px ${color}`, flexShrink: 0 }} />
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)' }}>{label}</span>
          </div>
        ))}
        <div style={{ height: 1, background: 'var(--border)', margin: '2px 0' }} />
        {[
          { color: '#ff3355',    label: 'Memory injection / C2 (×1.5/1.4)' },
          { color: '#ffb300',    label: 'Shared C2 / File open (×1.3/1.2)' },
          { color: '#00d4ff',    label: 'Same PID / spawned (×1.0/1.1)' },
          { color: CRITICAL_COLOR, label: 'Critical path edge' },
        ].map(({ color, label }) => (
          <div key={label} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <svg width={24} height={8}><line x1={0} y1={4} x2={24} y2={4} stroke={color} strokeWidth={2} strokeDasharray="5 3" /></svg>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)' }}>{label}</span>
          </div>
        ))}
        <div style={{ height: 1, background: 'var(--border)', margin: '2px 0' }} />
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)' }}>
          Showing {nodeCount} nodes (up to 60)
        </div>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)', opacity: 0.7 }}>
          Arc = combined score · Badge = path order
        </div>
      </div>

      {!hasBackend && (
        <div style={{
          padding: '10px 12px', borderRadius: 8,
          background: 'rgba(0,212,255,0.06)', border: '1px solid rgba(0,212,255,0.2)',
          fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--cyan)', lineHeight: 1.6,
        }}>
          Click <strong>CORRELATE</strong> to build real edges and compute the critical path.
        </div>
      )}
    </>
  );
}

// ─── Shared helpers ───────────────────────────────────────────────────────────

function Chip({ label, value, color }: { label: string; value: string; color: string }) {
  return (
    <div style={{
      flex: 1, display: 'flex', flexDirection: 'column', gap: 3,
      padding: '6px 8px', borderRadius: 6,
      background: 'var(--elevated)', border: `1px solid ${color}20`,
    }}>
      <span style={{ fontFamily: 'var(--font-hud)', fontSize: 7, color: 'var(--text-dim)', letterSpacing: '0.08em' }}>{label}</span>
      <span style={{ fontFamily: 'var(--font-hud)', fontSize: 13, fontWeight: 700, color }}>{value}</span>
    </div>
  );
}

function NodeIcon({ type, color, size = 14 }: { type: string; color: string; size?: number }) {
  const t = (type ?? '').toLowerCase();
  if (t === 'process') return <Cpu       size={size} color={color} />;
  if (t === 'network') return <Wifi      size={size} color={color} />;
  if (t === 'memory')  return <HardDrive size={size} color={color} />;
  return <FolderOpen size={size} color={color} />;
}

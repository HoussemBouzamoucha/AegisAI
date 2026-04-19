// File: UI/src/components/ThreatGraph.tsx
// Static radial graph — top 5 threat nodes, fixed positions, animated edges only.

import { useState, useMemo } from 'react';
import {
  Cpu, Wifi, HardDrive, FolderOpen,
  GitMerge, ShieldAlert, ShieldCheck, Loader, Network,
} from 'lucide-react';
import { useStore } from '../store';
import type { GraphNodeData, GraphEdgeData, UnifiedThreat } from '../types';

// ─── Layout constants ─────────────────────────────────────────────────────────

const W = 760;
const H = 480;
const NODE_R = 36;

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

interface PlacedNode {
  id: string; x: number; y: number;
  data: GraphNodeData;
}

function placeNodes(nodes: GraphNodeData[]): PlacedNode[] {
  if (nodes.length === 0) return [];
  if (nodes.length === 1)
    return [{ id: nodes[0].entity_id, x: W / 2, y: H / 2, data: nodes[0] }];

  const cx = W / 2, cy = H / 2;
  const r  = Math.min(W, H) * 0.30;
  return nodes.map((n, i) => {
    const angle = (i / nodes.length) * Math.PI * 2 - Math.PI / 2;
    return { id: n.entity_id, x: cx + Math.cos(angle) * r, y: cy + Math.sin(angle) * r, data: n };
  });
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

// ─── Main component ───────────────────────────────────────────────────────────

export default function ThreatGraph() {
  const {
    correlating, correlateResult, correlateError,
    correlateEntities, clearCorrelate,
    processes, networkConnections, memoryRegions, scanResults,
  } = useStore();

  const [selected,      setSelected]      = useState<PlacedNode | null>(null);
  const [includeMemory, setIncludeMemory] = useState(false);

  // ── Build top-5 nodes + edges ──────────────────────────────────────────────
  const { top5, edges5 } = useMemo(() => {
    let allNodes: GraphNodeData[] = [];
    let allEdges: GraphEdgeData[] = [];

    if (correlateResult?.graph?.nodes?.length) {
      allNodes = correlateResult.graph.nodes;
      allEdges = correlateResult.graph.edges ?? [];
    } else {
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
        entity_id: `mem:${r.pid}:${r.region_start}`, entity_type: 'memory',
        threat_level: r.threat_level as UnifiedThreat,
        combined_score: Math.min(r.threat_score / 40, 1),
        heuristic_score: r.threat_score,
        label: `${r.process_name} @0x${r.region_start.toString(16).toUpperCase()}`,
      }));
      scanResults.filter((f) => f.level !== 'Clean').forEach((f) => allNodes.push({
        entity_id: `file:${f.hash ?? f.path}`, entity_type: 'file',
        threat_level: f.level as UnifiedThreat,
        combined_score: f.confidence_score,
        heuristic_score: Math.round(f.confidence_score * 20),
        label: f.path.split(/[/\\]/).pop() ?? f.path, sub_label: f.path,
      }));
    }

    const order: Record<string, number> = { Critical: 4, Malicious: 3, Suspicious: 2, Clean: 1 };
    const top5 = [...allNodes]
      .sort((a, b) => (order[b.threat_level] ?? 0) - (order[a.threat_level] ?? 0) || b.combined_score - a.combined_score)
      .slice(0, 5);

    const ids = new Set(top5.map((n) => n.entity_id));
    const edges5 = allEdges.filter((e) => ids.has(e.from) && ids.has(e.to));

    return { top5, edges5 };
  }, [correlateResult, processes, networkConnections, memoryRegions, scanResults]);

  const placed   = useMemo(() => placeNodes(top5), [top5.map((n) => n.entity_id).join(',')]);
  const nodeMap  = useMemo(() => new Map(placed.map((n) => [n.id, n])), [placed]);
  const noData   = top5.length === 0;
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
            Top 5 threat nodes · {edges5.length} edge{edges5.length !== 1 ? 's' : ''}
            {hasBackend && ` · ${correlateResult!.statistics.graph_nodes} total · ${correlateResult!.statistics.graph_edges} total edges`}
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
            <svg viewBox={`0 0 ${W} ${H}`} style={{ width: '100%', height: '100%' }}>
              <defs>
                {(['Clean','Suspicious','Malicious','Critical'] as UnifiedThreat[]).map((lvl) => (
                  <filter key={lvl} id={`gf-${lvl}`} x="-60%" y="-60%" width="220%" height="220%">
                    <feGaussianBlur stdDeviation={lvl === 'Clean' ? 5 : 10} result="blur" />
                    <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
                  </filter>
                ))}
                <marker id="arr" markerWidth="7" markerHeight="7" refX="5" refY="3.5" orient="auto">
                  <path d="M0,0 L7,3.5 L0,7 Z" fill="rgba(200,230,212,0.35)" />
                </marker>
                <style>{`
                  @keyframes dashFlow  { to { stroke-dashoffset: -48; } }
                  @keyframes ringFade  { 0%,100%{opacity:.35;r:${NODE_R + 6}px} 50%{opacity:0;r:${NODE_R + 20}px} }
                  .edge-anim { animation: dashFlow 2s linear infinite; }
                  .ring-anim { animation: ringFade 2.2s ease-out infinite; }
                `}</style>
              </defs>

              {/* Faint radial guide */}
              <circle cx={W/2} cy={H/2} r={Math.min(W,H)*0.30}
                fill="none" stroke="rgba(0,255,136,0.04)" strokeWidth={1} strokeDasharray="4 8" />

              {/* Edges — drawn before nodes so nodes sit on top */}
              {edges5.map((edge, i) => {
                const a = nodeMap.get(edge.from);
                const b = nodeMap.get(edge.to);
                if (!a || !b) return null;
                const col  = edgeColor(edge.edge_type);
                const path = edgePath(a.x, a.y, b.x, b.y, i);
                // Label position: roughly midpoint of the quadratic
                const t    = 0.5;
                const qx   = (1-t)*(1-t)*a.x + 2*(1-t)*t*((a.x+b.x)/2 - (b.y-a.y)/(Math.sqrt((b.x-a.x)**2+(b.y-a.y)**2)||1)*(40+i*10)) + t*t*b.x;
                const qy   = (1-t)*(1-t)*a.y + 2*(1-t)*t*((a.y+b.y)/2 + (b.x-a.x)/(Math.sqrt((b.x-a.x)**2+(b.y-a.y)**2)||1)*(40+i*10)) + t*t*b.y;
                return (
                  <g key={i}>
                    {/* Thick ghost line */}
                    <path d={path} fill="none" stroke={`${col}20`} strokeWidth={4} />
                    {/* Solid base */}
                    <path d={path} fill="none" stroke={`${col}55`} strokeWidth={2} markerEnd="url(#arr)" />
                    {/* Moving dashes */}
                    <path d={path} fill="none" stroke={col} strokeWidth={1.5}
                      strokeDasharray="10 14" className="edge-anim"
                      style={{ animationDelay: `${i * 0.35}s` }} opacity={0.85} />
                    {/* Label pill */}
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

              {/* Nodes */}
              {placed.map((node) => {
                const col       = threatColor(node.data.threat_level);
                const isThreat  = node.data.threat_level !== 'Clean';
                const isSel     = selected?.id === node.id;
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
                      stroke={col} strokeWidth={isSel ? 2.5 : 1.8} />

                    {/* Score arc */}
                    {pct > 0.01 && (
                      <path d={`M0,${-arcR} A${arcR},${arcR} 0 ${large},1 ${arcX},${arcY}`}
                        fill="none" stroke={col} strokeWidth={3.5}
                        strokeLinecap="round" opacity={0.9}
                        style={{ pointerEvents: 'none' }} />
                    )}

                    {/* Score % */}
                    <text y={-7} textAnchor="middle"
                      fontFamily="'Orbitron', monospace" fontSize={11} fontWeight={700}
                      fill={col} style={{ pointerEvents: 'none' }}>
                      {(node.data.combined_score * 100).toFixed(0)}%
                    </text>

                    {/* Type tag */}
                    <text y={8} textAnchor="middle"
                      fontFamily="'IBM Plex Mono', monospace" fontSize={8}
                      fill={`${col}99`} style={{ pointerEvents: 'none' }}>
                      {node.data.entity_type.slice(0, 4).toUpperCase()}
                    </text>

                    {/* Name label */}
                    <text y={NODE_R + 16} textAnchor="middle"
                      fontFamily="'IBM Plex Mono', monospace" fontSize={10}
                      fill={isThreat ? col : 'var(--text)'}
                      style={{ pointerEvents: 'none' }}>
                      {label}
                    </text>

                    {/* Threat level */}
                    {isThreat && (
                      <text y={NODE_R + 29} textAnchor="middle"
                        fontFamily="'Orbitron', monospace" fontSize={7.5}
                        fill={col} style={{ pointerEvents: 'none' }}>
                        ● {node.data.threat_level.toUpperCase()}
                      </text>
                    )}
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
              click node to inspect · {top5.length} nodes · {edges5.length} edges
            </div>
          )}
        </div>

        {/* Detail / legend panel */}
        <div style={{ width: 270, flexShrink: 0, display: 'flex', flexDirection: 'column', gap: 12, overflowY: 'auto' }}>
          {selected
            ? <DetailPanel node={selected} edges={edges5} nodeMap={nodeMap} onClose={() => setSelected(null)} />
            : <LegendPanel hasBackend={hasBackend} nodeCount={top5.length} correlateResult={correlateResult} />}
        </div>
      </div>
    </div>
  );
}

// ─── Detail Panel ─────────────────────────────────────────────────────────────

function DetailPanel({ node, edges, nodeMap, onClose }: {
  node: PlacedNode; edges: GraphEdgeData[];
  nodeMap: Map<string, PlacedNode>; onClose: () => void;
}) {
  const col       = threatColor(node.data.threat_level);
  const connected = edges.filter((e) => e.from === node.id || e.to === node.id);

  return (
    <>
      <div style={{
        background: 'var(--surface)', border: `1px solid ${col}40`,
        borderRadius: 10, padding: 16, display: 'flex', flexDirection: 'column', gap: 12,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{
            width: 36, height: 36, borderRadius: 8, flexShrink: 0,
            background: `${col}18`, border: `1px solid ${col}40`,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>
            <NodeIcon type={node.data.entity_type} color={col} size={16} />
          </div>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: col, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {node.data.label}
            </div>
            <div style={{ fontFamily: 'var(--font-hud)', fontSize: 8, color: 'var(--text-dim)', marginTop: 2, letterSpacing: '0.08em' }}>
              {node.data.entity_type.toUpperCase()}
            </div>
          </div>
          <button onClick={onClose} style={{ background: 'transparent', border: 'none', color: 'var(--text-dim)', cursor: 'pointer', fontSize: 14 }}>✕</button>
        </div>

        <div style={{ display: 'flex', gap: 8 }}>
          <Chip label="COMBINED"  value={`${(node.data.combined_score * 100).toFixed(1)}%`} color={col} />
          <Chip label="HEURISTIC" value={String(node.data.heuristic_score)} color="var(--cyan)" />
          {node.data.ml_score !== undefined && (
            <Chip label="ML" value={`${(node.data.ml_score * 100).toFixed(1)}%`} color="#a78bfa" />
          )}
        </div>

        <div style={{
          display: 'flex', alignItems: 'center', gap: 8, padding: '8px 12px', borderRadius: 6,
          background: `${col}10`, border: `1px solid ${col}25`,
        }}>
          {node.data.threat_level === 'Clean'
            ? <ShieldCheck size={13} color={col} />
            : <ShieldAlert size={13} color={col} />}
          <span style={{ fontFamily: 'var(--font-hud)', fontSize: 11, color: col, letterSpacing: '0.08em' }}>
            {node.data.threat_level.toUpperCase()}
          </span>
        </div>

        {node.data.sub_label && (
          <div style={{
            fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)',
            padding: '6px 8px', background: 'var(--base)', borderRadius: 5, wordBreak: 'break-all',
          }}>
            {node.data.sub_label}
          </div>
        )}
      </div>

      {connected.length > 0 && (
        <div style={{
          background: 'var(--surface)', border: '1px solid var(--border)',
          borderRadius: 10, padding: 14, display: 'flex', flexDirection: 'column', gap: 8,
        }}>
          <div style={{ fontFamily: 'var(--font-hud)', fontSize: 9, color: 'var(--text-dim)', letterSpacing: '0.1em', marginBottom: 2 }}>
            EDGES ({connected.length})
          </div>
          {connected.map((e, i) => {
            const otherId = e.from === node.id ? e.to : e.from;
            const other   = nodeMap.get(otherId);
            const col2    = edgeColor(e.edge_type);
            const dir     = e.from === node.id ? '→' : '←';
            return (
              <div key={i} style={{
                display: 'flex', alignItems: 'center', gap: 8,
                padding: '6px 10px', borderRadius: 6,
                background: 'var(--elevated)', border: `1px solid ${col2}25`,
              }}>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)' }}>{dir}</span>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {other?.data.label ?? otherId.slice(0, 18)}
                  </div>
                  <div style={{ fontFamily: 'var(--font-hud)', fontSize: 7, color: col2, marginTop: 1, letterSpacing: '0.06em' }}>
                    {EDGE_LABEL[e.edge_type] ?? e.edge_type}
                  </div>
                </div>
                <span style={{ fontFamily: 'var(--font-hud)', fontSize: 9, color: threatColor(other?.data.threat_level ?? 'Clean'), fontWeight: 700, flexShrink: 0 }}>
                  {other ? `${(other.data.combined_score * 100).toFixed(0)}%` : '?'}
                </span>
              </div>
            );
          })}
        </div>
      )}
    </>
  );
}

// ─── Legend Panel ─────────────────────────────────────────────────────────────

function LegendPanel({ hasBackend, nodeCount, correlateResult }: {
  hasBackend: boolean; nodeCount: number; correlateResult: any;
}) {
  return (
    <>
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
          { color: '#ff3355', label: 'Critical / Malicious' },
          { color: '#ffb300', label: 'Suspicious' },
          { color: '#00ff88', label: 'Clean' },
        ].map(({ color, label }) => (
          <div key={label} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{ width: 10, height: 10, borderRadius: '50%', background: color, boxShadow: `0 0 6px ${color}`, flexShrink: 0 }} />
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)' }}>{label}</span>
          </div>
        ))}
        <div style={{ height: 1, background: 'var(--border)', margin: '2px 0' }} />
        {[
          { color: '#ff3355', label: 'Memory injection / C2' },
          { color: '#ffb300', label: 'Shared C2 / File open' },
          { color: '#00d4ff', label: 'Same PID / spawned' },
        ].map(({ color, label }) => (
          <div key={label} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <svg width={24} height={8}><line x1={0} y1={4} x2={24} y2={4} stroke={color} strokeWidth={2} strokeDasharray="5 3" /></svg>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)' }}>{label}</span>
          </div>
        ))}
        <div style={{ height: 1, background: 'var(--border)', margin: '2px 0' }} />
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)' }}>
          Showing {nodeCount} / 5 highest-threat nodes
        </div>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)', opacity: 0.7 }}>
          Arc = combined threat score
        </div>
      </div>

      {!hasBackend && (
        <div style={{
          padding: '10px 12px', borderRadius: 8,
          background: 'rgba(0,212,255,0.06)', border: '1px solid rgba(0,212,255,0.2)',
          fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--cyan)', lineHeight: 1.6,
        }}>
          Click <strong>CORRELATE</strong> to build real edges between entities across scanners.
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

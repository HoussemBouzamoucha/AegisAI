// File: UI/src/components/GraphVerdict.tsx
// Graph Verdict — humanized synthesis of the graph's attack-chain output.
//
// Layout:
//   Left panel  — verdict card + attack chains + critical path narrative
//   Right panel — sub-graph showing only verdict-relevant entities and edges
//
// ML placeholder policy:
//   If ml_score is undefined/null for a node, the display shows "N/A" and
//   notes that ML scoring was not available for that domain.  The combined
//   score shown is the heuristic-only value from the backend.  No fake score
//   is injected — the verdict text calls this out explicitly.

import { useMemo, useState, useEffect, useRef } from 'react';
import { AlertTriangle, CheckCircle, Zap, GitMerge, ChevronDown, ChevronRight, Info, Clock } from 'lucide-react';
import { useStore } from '../store';
import type {
  AttackChain, CriticalPath, GraphNodeData, GraphEdgeData, UnifiedThreat,
} from '../types';

// ─── Colour tokens (mirror ThreatGraph) ──────────────────────────────────────

function threatColor(level: UnifiedThreat | string): string {
  if (level === 'Critical')   return '#ff3355';
  if (level === 'Malicious')  return '#ff3355';
  if (level === 'Suspicious') return '#ffb300';
  return '#00ff88';
}

const EDGE_COLORS: Record<string, string> = {
  shared_c2:        '#facc15',
  parent_child:     '#00d4ff',
  shared_file_hash: '#34d399',
};

// ─── Verdict generation ───────────────────────────────────────────────────────

type Severity = 'Clean' | 'Suspicious' | 'Malicious' | 'Critical';

const SEVERITY_ORDER: Record<Severity, number> = {
  Clean: 0, Suspicious: 1, Malicious: 2, Critical: 3,
};

function worstSeverity(chains: AttackChain[]): Severity {
  return chains.reduce<Severity>((worst, c) => {
    const s = c.severity as Severity;
    return SEVERITY_ORDER[s] > SEVERITY_ORDER[worst] ? s : worst;
  }, 'Clean');
}

interface PatternSentence {
  pattern: string;
  sentence: string;
  mitre: string;
}

function humanizePattern(chain: AttackChain, nodes: Record<string, GraphNodeData>): PatternSentence {
  const labels = chain.node_ids
    .map(id => nodes[id]?.label ?? id)
    .filter(Boolean);

  const actor = labels[0] ?? 'Unknown process';
  const target = labels[1] ?? null;

  const sentences: Record<string, string> = {
    ProcessInjection:
      `"${actor}" has a suspicious or malicious memory region — possible shellcode injected into its address space.`,
    C2Communication:
      `"${actor}" is actively connecting to a remote host that matches command-and-control indicators.`,
    MalwareExecution:
      `A malicious file on disk matches the executable path of "${actor}" — this process is running known malware.`,
    LateralMovement:
      target
        ? `"${actor}" spawned "${target}", which subsequently opened an external network connection — consistent with dropper or lateral-movement behaviour.`
        : `A process spawned a child that opened an external network connection — consistent with lateral-movement behaviour.`,
    SuspiciousSpawn:
      target
        ? `"${actor}" (already flagged as a threat) spawned "${target}", which is also flagged — possible propagation or privilege-escalation chain.`
        : `A threat-level process spawned another threat-level child — possible propagation chain.`,
    MultiStageAttack:
      `Three or more threat indicators across different scanners are structurally linked through ${actor}${target ? ` → ${target}` : ''} — consistent with a coordinated, multi-stage attack.`,
  };

  return {
    pattern: chain.pattern,
    sentence: sentences[chain.pattern] ?? chain.description,
    mitre: chain.mitre_tactic,
  };
}

function mlCoverage(nodes: GraphNodeData[]): string {
  const total = nodes.length;
  const withMl = nodes.filter(n => n.ml_score != null).length;
  if (withMl === 0) return 'ML scoring was not available for any entity in this verdict — scores reflect heuristic analysis only.';
  if (withMl < total) return `ML scoring available for ${withMl} of ${total} entities. Remaining scores are heuristic-only.`;
  return '';
}

function overallSummary(
  severity: Severity,
  chains: AttackChain[],
  cp: CriticalPath | null | undefined,
  nodesInVerdict: GraphNodeData[],
): string {
  if (chains.length === 0) {
    return 'The graph found no attack patterns and no critical path. The system appears clean based on current scan data.';
  }

  const patternNames = [...new Set(chains.map(c => c.pattern))];
  const patternList = patternNames.length === 1
    ? patternNames[0]
    : patternNames.slice(0, -1).join(', ') + ' and ' + patternNames[patternNames.length - 1];

  const entityCount = nodesInVerdict.length;
  const entityWord = entityCount === 1 ? 'entity' : 'entities';

  let base = `The graph identified ${chains.length} attack chain${chains.length > 1 ? 's' : ''} `
    + `(${patternList}) across ${entityCount} ${entityWord}. `;

  if (severity === 'Critical') {
    base += 'Threat level is CRITICAL — immediate action is required.';
  } else if (severity === 'Malicious') {
    base += 'Threat level is MALICIOUS — confirmed malicious activity detected.';
  } else if (severity === 'Suspicious') {
    base += 'Threat level is SUSPICIOUS — further investigation is warranted.';
  }

  if (cp && cp.node_ids.length > 1) {
    base += ` The highest-weight path through the graph is: ${cp.narrative}`;
  }

  return base;
}

// ─── Sub-graph layout ─────────────────────────────────────────────────────────

interface PlacedNode { id: string; x: number; y: number; data: GraphNodeData; }

function layoutSubgraph(nodes: GraphNodeData[], vW: number, vH: number): PlacedNode[] {
  const n = nodes.length;
  if (n === 0) return [];
  const cx = vW / 2, cy = vH / 2;
  if (n === 1) return [{ id: nodes[0].entity_id, x: cx, y: cy, data: nodes[0] }];

  // Simple ring layout
  return nodes.map((node, i) => {
    const angle = (i / n) * Math.PI * 2 - Math.PI / 2;
    const r = Math.min(vW, vH) * 0.33;
    return { id: node.entity_id, x: cx + Math.cos(angle) * r, y: cy + Math.sin(angle) * r, data: node };
  });
}

// ─── Sub-graph component ──────────────────────────────────────────────────────

const NODE_R = 30;

function VerdictSubgraph({
  nodes, edges, criticalNodeIds,
}: {
  nodes: GraphNodeData[];
  edges: GraphEdgeData[];
  criticalNodeIds: Set<string>;
}) {
  const [hovered, setHovered] = useState<string | null>(null);

  const vW = 560, vH = 320;
  const placed = useMemo(() => layoutSubgraph(nodes, vW, vH), [nodes]);
  const posMap = useMemo(() =>
    Object.fromEntries(placed.map(p => [p.id, { x: p.x, y: p.y }])),
    [placed],
  );

  if (nodes.length === 0) {
    return (
      <div style={{
        display: 'flex', flexDirection: 'column', alignItems: 'center',
        justifyContent: 'center', height: 220,
        border: '1px dashed var(--border)', borderRadius: 8,
        color: 'var(--text-dim)', fontFamily: 'var(--font-mono)', fontSize: 12, gap: 10,
      }}>
        <Info size={24} style={{ opacity: 0.4 }} />
        <span>No entities are connected to any detected attack chain.</span>
        <span style={{ fontSize: 10, opacity: 0.6 }}>
          Run a correlation scan to populate the entity graph.
        </span>
      </div>
    );
  }

  return (
    <svg width="100%" viewBox={`0 0 ${vW} ${vH}`} style={{ overflow: 'visible' }}>
      <defs>
        <filter id="glow-v">
          <feGaussianBlur stdDeviation="3" result="blur" />
          <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
        </filter>
      </defs>

      {/* Edges */}
      {edges.map((e, i) => {
        const a = posMap[e.from], b = posMap[e.to];
        if (!a || !b) return null;
        const color = EDGE_COLORS[e.edge_type] ?? '#00d4ff';
        const mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2;
        const dx = b.x - a.x, dy = b.y - a.y;
        const len = Math.sqrt(dx * dx + dy * dy) || 1;
        const curve = 30;
        const cpx = mx - (dy / len) * curve, cpy = my + (dx / len) * curve;
        const d = `M${a.x},${a.y} Q${cpx},${cpy} ${b.x},${b.y}`;

        const label = e.edge_type.replace(/_/g, ' ').toUpperCase();
        const t = 0.5;
        const lx = (1-t)*(1-t)*a.x + 2*(1-t)*t*cpx + t*t*b.x;
        const ly = (1-t)*(1-t)*a.y + 2*(1-t)*t*cpy + t*t*b.y;

        return (
          <g key={`${e.from}-${e.to}-${i}`}>
            <path d={d} fill="none" stroke={color} strokeWidth={1.5} strokeOpacity={0.5} />
            <text x={lx} y={ly - 6} textAnchor="middle"
              fill={color} fontSize={8} fontFamily="var(--font-mono)" opacity={0.8}>
              {label}
            </text>
          </g>
        );
      })}

      {/* Nodes */}
      {placed.map(p => {
        const isHovered = hovered === p.id;
        const isCritical = criticalNodeIds.has(p.id);
        const color = threatColor(p.data.threat_level);
        const mlAvailable = p.data.ml_score != null;

        return (
          <g key={p.id} transform={`translate(${p.x},${p.y})`}
            onMouseEnter={() => setHovered(p.id)}
            onMouseLeave={() => setHovered(null)}
            style={{ cursor: 'default' }}>

            {/* Critical path ring */}
            {isCritical && (
              <circle r={NODE_R + 6} fill="none"
                stroke="#f59e0b" strokeWidth={2} strokeDasharray="4 3" opacity={0.7} />
            )}

            {/* Node circle */}
            <circle r={NODE_R}
              fill={`${color}18`}
              stroke={color}
              strokeWidth={isHovered ? 2.5 : 1.5}
              filter={isHovered ? 'url(#glow-v)' : undefined}
            />

            {/* Score arc */}
            <circle r={NODE_R} fill="none"
              stroke={color} strokeWidth={3} strokeOpacity={0.35}
              strokeDasharray={`${p.data.combined_score * 2 * Math.PI * NODE_R} ${2 * Math.PI * NODE_R}`}
              transform="rotate(-90)"
            />

            {/* Label */}
            <text textAnchor="middle" dy={-6}
              fill={color} fontSize={10} fontFamily="var(--font-mono)" fontWeight={700}>
              {p.data.label.length > 12 ? p.data.label.slice(0, 11) + '…' : p.data.label}
            </text>

            {/* Score */}
            <text textAnchor="middle" dy={8}
              fill="var(--text-dim)" fontSize={8} fontFamily="var(--font-mono)">
              {(p.data.combined_score * 100).toFixed(0)}%
            </text>

            {/* ML indicator */}
            <text textAnchor="middle" dy={19}
              fill={mlAvailable ? '#818cf8' : 'var(--text-dim)'}
              fontSize={7} fontFamily="var(--font-mono)" opacity={0.8}>
              {mlAvailable ? `ML:${(p.data.ml_score! * 100).toFixed(0)}%` : 'ML:N/A'}
            </text>

            {/* Hover tooltip */}
            {isHovered && (
              <g>
                <rect x={NODE_R + 6} y={-36} width={130} height={72}
                  rx={4} fill="var(--elevated)" stroke="var(--border)" strokeWidth={1} />
                <text x={NODE_R + 12} y={-20} fill="var(--text)"
                  fontSize={9} fontFamily="var(--font-mono)" fontWeight={700}>
                  {p.data.label}
                </text>
                <text x={NODE_R + 12} y={-8} fill={color}
                  fontSize={8} fontFamily="var(--font-mono)">
                  {p.data.threat_level} · {(p.data.combined_score * 100).toFixed(0)}%
                </text>
                {p.data.process_score !== undefined && (
                  <text x={NODE_R + 12} y={4} fill="var(--text-dim)"
                    fontSize={7} fontFamily="var(--font-mono)">
                    PROC:{(p.data.process_score! * 100).toFixed(0)}
                    {' '}NET:{(p.data.network_score! * 100).toFixed(0)}
                    {' '}MEM:{(p.data.memory_score! * 100).toFixed(0)}
                  </text>
                )}
                <text x={NODE_R + 12} y={16} fill="var(--text-dim)"
                  fontSize={7} fontFamily="var(--font-mono)">
                  {p.data.sub_label
                    ? (p.data.sub_label.length > 20
                        ? '…' + p.data.sub_label.slice(-18)
                        : p.data.sub_label)
                    : p.data.entity_id}
                </text>
                <text x={NODE_R + 12} y={28} fill="#818cf8"
                  fontSize={7} fontFamily="var(--font-mono)">
                  {p.data.ml_score != null
                    ? `ML score: ${(p.data.ml_score * 100).toFixed(1)}%`
                    : 'ML score: not available'}
                </text>
              </g>
            )}
          </g>
        );
      })}
    </svg>
  );
}

// ─── Chain card ───────────────────────────────────────────────────────────────

function ChainCard({
  chain, sentence, nodeMap,
}: {
  chain: AttackChain;
  sentence: PatternSentence;
  nodeMap: Record<string, GraphNodeData>;
}) {
  const [open, setOpen] = useState(false);
  const color = threatColor(chain.severity);

  return (
    <div style={{
      border: `1px solid ${color}40`,
      borderRadius: 8,
      background: `${color}08`,
      overflow: 'hidden',
      marginBottom: 8,
    }}>
      {/* Header row */}
      <button onClick={() => setOpen(v => !v)} style={{
        display: 'flex', alignItems: 'center', gap: 10,
        width: '100%', padding: '10px 14px',
        background: 'transparent', border: 'none', cursor: 'pointer',
        textAlign: 'left',
      }}>
        <span style={{
          fontFamily: 'var(--font-mono)', fontSize: 9, fontWeight: 700,
          color, letterSpacing: '0.1em',
          background: `${color}20`, padding: '2px 6px', borderRadius: 3,
          flexShrink: 0,
        }}>
          {chain.severity.toUpperCase()}
        </span>
        <span style={{
          fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text)',
          fontWeight: 600, flex: 1,
        }}>
          {chain.pattern}
        </span>
        {/* Score bar */}
        <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <div style={{
            width: 60, height: 4, background: 'var(--border)', borderRadius: 2, overflow: 'hidden',
          }}>
            <div style={{
              width: `${chain.chain_score * 100}%`, height: '100%',
              background: color, borderRadius: 2,
            }} />
          </div>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)' }}>
            {(chain.chain_score * 100).toFixed(0)}%
          </span>
        </span>
        <span style={{ color: 'var(--text-dim)', marginLeft: 6 }}>
          {open ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
        </span>
      </button>

      {open && (
        <div style={{ padding: '0 14px 12px', display: 'flex', flexDirection: 'column', gap: 8 }}>
          {/* Humanized sentence */}
          <p style={{
            fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text)',
            lineHeight: 1.7, margin: 0,
          }}>
            {sentence.sentence}
          </p>

          {/* MITRE tag */}
          <div style={{
            fontFamily: 'var(--font-mono)', fontSize: 9, color: '#818cf8',
            background: 'rgba(129,140,248,0.1)', padding: '3px 8px', borderRadius: 3,
            alignSelf: 'flex-start',
          }}>
            {sentence.mitre}
          </div>

          {/* Involved entities */}
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 2 }}>
            {chain.node_ids.map(id => {
              const node = nodeMap[id];
              if (!node) return null;
              const nc = threatColor(node.threat_level);
              return (
                <span key={id} style={{
                  fontFamily: 'var(--font-mono)', fontSize: 9,
                  color: nc, background: `${nc}15`,
                  border: `1px solid ${nc}40`,
                  padding: '2px 7px', borderRadius: 3,
                }}>
                  {node.label}
                  {node.ml_score == null && (
                    <span style={{ color: 'var(--text-dim)', marginLeft: 4 }}>[ML:N/A]</span>
                  )}
                </span>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────

export default function GraphVerdict() {
  const {
    correlateResult, correlating, correlateError,
    correlateEntities, correlateFromStore, abortCorrelate,
    processes, networkConnections, memoryRegions, scanResults, mlIdsResult,
  } = useStore();

  // Whether there is enough store data to correlate without re-scanning
  const hasStoreData = processes.length > 0 || networkConnections.length > 0;

  // ── Derive verdict data ────────────────────────────────────────────────────
  const verdict = useMemo(() => {
    if (!correlateResult?.graph) return null;

    const { nodes: rawNodes, edges: rawEdges, attack_chains, critical_path } = correlateResult.graph;
    const nodeMap: Record<string, GraphNodeData> =
      Object.fromEntries(rawNodes.map(n => [n.entity_id, n]));

    // Collect all entity IDs referenced by any chain or the critical path
    const verdictIds = new Set<string>();
    attack_chains.forEach(c => c.node_ids.forEach(id => verdictIds.add(id)));
    if (critical_path) critical_path.node_ids.forEach(id => verdictIds.add(id));

    const criticalPathIds = new Set<string>(critical_path?.node_ids ?? []);

    // Filter nodes and edges to verdict participants only
    const verdictNodes = rawNodes.filter(n => verdictIds.has(n.entity_id));
    const verdictEdges = rawEdges.filter(
      e => verdictIds.has(e.from) && verdictIds.has(e.to),
    );

    const severity = worstSeverity(attack_chains);
    const sentences = attack_chains.map(c => humanizePattern(c, nodeMap));
    const summary   = overallSummary(severity, attack_chains, critical_path, verdictNodes);
    const mlNote    = mlCoverage(verdictNodes);

    return {
      severity, summary, mlNote,
      chains: attack_chains, sentences,
      criticalPath: critical_path ?? null,
      verdictNodes, verdictEdges,
      nodeMap, criticalPathIds,
      hasThreats: attack_chains.length > 0,
    };
  }, [correlateResult]);

  // ── Elapsed timer (resets when correlating starts) ────────────────────────
  const elapsedRef = useRef(0);
  const [elapsed, setElapsed] = useState(0);
  useEffect(() => {
    if (!correlating) { elapsedRef.current = 0; setElapsed(0); return; }
    const start = Date.now();
    const interval = setInterval(() => {
      const s = Math.floor((Date.now() - start) / 1000);
      elapsedRef.current = s;
      setElapsed(s);
    }, 500);
    return () => clearInterval(interval);
  }, [correlating]);

  // ── Loading ────────────────────────────────────────────────────────────────
  if (correlating) {
    // Approximate stage windows (seconds). Process enum + exe scan is now fast
    // (only confirmed-malicious exes are file-scanned, capped at 5).
    // Network scan (pcap + threat scoring) is the new dominant step.
    const STEPS: { label: string; start: number; end: number; detail: string }[] = [
      { label: 'Process scan',    start: 0,   end: 30,  detail: 'Enumerating all running processes, handles, modules…' },
      { label: 'Exe file scan',   start: 5,   end: 60,  detail: 'YARA-scanning confirmed-malicious process executables (max 5)…' },
      { label: 'Network scan',    start: 15,  end: 180, detail: 'Capturing live connections, scoring, running ML IDS pipeline…' },
      { label: 'Entity pipeline', start: 60,  end: 270, detail: 'Aggregating entities, scoring, backfilling orphan PIDs…' },
      { label: 'Graph analysis',  start: 240, end: 300, detail: 'Building graph, detecting attack chains, critical path…' },
    ];

    function stepStatus(s: { start: number; end: number }) {
      if (elapsed > s.end) return 'done';
      if (elapsed >= s.start) return 'running';
      return 'pending';
    }

    const statusColor = { done: '#00ff88', running: '#ffb300', pending: 'var(--text-dim)' } as const;
    const statusLabel = { done: '✓', running: '▶', pending: '○' } as const;

    return (
      <div style={{
        height: '100%', display: 'flex', flexDirection: 'column',
        alignItems: 'center', justifyContent: 'center',
        fontFamily: 'var(--font-mono)', color: 'var(--text-dim)', gap: 20,
      }}>
        <GitMerge size={36} style={{ opacity: 0.5 }} />

        {/* Elapsed clock */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, color: 'var(--text)' }}>
          <Clock size={14} style={{ opacity: 0.7 }} />
          <span>Correlating entities…</span>
          <span style={{
            fontFamily: 'var(--font-mono)', fontSize: 14, color: '#ffb300',
            minWidth: 42, textAlign: 'right',
          }}>
            {elapsed}s
          </span>
        </div>

        {/* Step tracker */}
        <div style={{
          background: 'var(--base)',
          border: '1px solid var(--border)',
          borderRadius: 8, padding: '14px 20px',
          display: 'flex', flexDirection: 'column', gap: 12,
          minWidth: 380,
        }}>
          {STEPS.map(step => {
            const st = stepStatus(step);
            const col = statusColor[st];
            return (
              <div key={step.label} style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  {/* Status icon */}
                  <span style={{
                    width: 16, textAlign: 'center',
                    color: col, fontSize: 11, fontWeight: 700,
                  }}>
                    {statusLabel[st]}
                  </span>
                  {/* Step label */}
                  <span style={{
                    fontSize: 11, color: st === 'pending' ? 'var(--text-dim)' : 'var(--text)',
                    fontWeight: st === 'running' ? 700 : 400,
                    flex: 1,
                  }}>
                    {step.label}
                  </span>
                  {/* Time badge */}
                  <span style={{
                    fontSize: 9, color: col,
                    background: `${col}18`,
                    padding: '1px 6px', borderRadius: 3,
                  }}>
                    {st === 'done'    ? `~${step.end}s`
                    : st === 'running' ? `${elapsed}s / ~${step.end}s`
                    : `~${step.start}s`}
                  </span>
                </div>
                {/* Detail line when running */}
                {st === 'running' && (
                  <div style={{
                    marginLeft: 26, fontSize: 9, color: '#ffb300', opacity: 0.7, lineHeight: 1.5,
                  }}>
                    {step.detail}
                  </div>
                )}
              </div>
            );
          })}

          {/* Warning if taking longer than expected */}
          {elapsed > 300 && (
            <div style={{
              marginTop: 4, padding: '8px 10px',
              background: 'rgba(255,179,0,0.07)',
              border: '1px solid rgba(255,179,0,0.25)',
              borderRadius: 5, fontSize: 9,
              color: '#ffb300', lineHeight: 1.6,
            }}>
              ⚠ Taking longer than expected. Check the daemon stderr for per-step timings.
              Network scan (pcap) or ML pipeline may be the bottleneck.
              Timeout is 5 minutes.
            </div>
          )}
        </div>

        <button
          onClick={abortCorrelate}
          style={{
            padding: '6px 18px',
            background: 'transparent', color: 'var(--text-dim)',
            border: '1px solid var(--border)', borderRadius: 5,
            fontFamily: 'var(--font-mono)', fontSize: 10, cursor: 'pointer',
          }}>
          CANCEL
        </button>
      </div>
    );
  }

  // ── Error state ────────────────────────────────────────────────────────────
  if (correlateError) {
    return (
      <div style={{
        height: '100%', display: 'flex', flexDirection: 'column',
        alignItems: 'center', justifyContent: 'center',
        fontFamily: 'var(--font-mono)', color: 'var(--text-dim)', gap: 14,
      }}>
        <AlertTriangle size={36} color="#ff3355" style={{ opacity: 0.8 }} />
        <div style={{ fontSize: 13, color: '#ff3355' }}>Correlation failed</div>
        <div style={{
          fontSize: 10, color: 'var(--text-dim)', maxWidth: 420, textAlign: 'center',
          background: 'rgba(255,51,85,0.07)', border: '1px solid rgba(255,51,85,0.2)',
          borderRadius: 6, padding: '10px 16px', lineHeight: 1.7,
        }}>
          {correlateError}
        </div>
        <div style={{ display: 'flex', gap: 10 }}>
          {hasStoreData && (
            <button onClick={correlateFromStore}
              style={{
                padding: '8px 20px',
                background: 'var(--green)', color: 'var(--void)',
                border: 'none', borderRadius: 5,
                fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 700,
                cursor: 'pointer',
              }}>
              ⚡ USE EXISTING DATA
            </button>
          )}
          <button onClick={() => correlateEntities(false)}
            style={{
              padding: '8px 20px',
              background: 'transparent', color: 'var(--text)',
              border: '1px solid var(--border)', borderRadius: 5,
              fontFamily: 'var(--font-mono)', fontSize: 11,
              cursor: 'pointer',
            }}>
            FULL RESCAN
          </button>
        </div>
      </div>
    );
  }

  // ── No result yet ──────────────────────────────────────────────────────────
  if (!correlateResult) {
    return (
      <div style={{
        height: '100%', display: 'flex', flexDirection: 'column',
        alignItems: 'center', justifyContent: 'center',
        fontFamily: 'var(--font-mono)', color: 'var(--text-dim)', gap: 20,
      }}>
        <GitMerge size={40} style={{ opacity: 0.3 }} />
        <div style={{ fontSize: 13, color: 'var(--text)' }}>No correlation data available</div>

        {/* Available store data summary */}
        <div style={{
          display: 'flex', gap: 10, flexWrap: 'wrap', justifyContent: 'center',
          fontSize: 10,
        }}>
          {[
            { label: 'Processes',   count: processes.length,          color: processes.length > 0 ? 'var(--green)' : 'var(--text-dim)' },
            { label: 'Connections', count: networkConnections.length,  color: networkConnections.length > 0 ? '#00d4ff' : 'var(--text-dim)' },
            { label: 'Memory',      count: memoryRegions.length,       color: memoryRegions.length > 0 ? '#ffb300' : 'var(--text-dim)' },
            { label: 'Files',       count: scanResults.length,         color: scanResults.length > 0 ? '#34d399' : 'var(--text-dim)' },
            { label: 'ML flows',    count: mlIdsResult?.flows.length ?? 0, color: mlIdsResult ? '#818cf8' : 'var(--text-dim)' },
          ].map(({ label, count, color }) => (
            <span key={label} style={{
              padding: '3px 10px', borderRadius: 4,
              border: `1px solid ${count > 0 ? color + '60' : 'var(--border)'}`,
              color,
            }}>
              {count > 0 ? `${count}` : '—'} {label}
            </span>
          ))}
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 10, marginTop: 4 }}>
          {/* Fast path: use existing store data */}
          <button
            onClick={correlateFromStore}
            disabled={!hasStoreData}
            style={{
              padding: '9px 24px',
              background: hasStoreData ? 'var(--green)' : 'var(--border)',
              color: hasStoreData ? 'var(--void)' : 'var(--text-dim)',
              border: 'none', borderRadius: 5,
              fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 700,
              cursor: hasStoreData ? 'pointer' : 'not-allowed',
              opacity: hasStoreData ? 1 : 0.5,
            }}>
            ⚡ USE EXISTING SCAN DATA
          </button>
          <div style={{ fontSize: 9, color: 'var(--text-dim)' }}>
            {hasStoreData
              ? 'Builds the graph instantly from already-scanned data (with ML if run)'
              : 'Run the Process or Network scanner first'}
          </div>

          {/* Slow path: full re-scan via daemon */}
          <button
            onClick={() => correlateEntities(false)}
            style={{
              marginTop: 4, padding: '7px 20px',
              background: 'transparent', color: 'var(--text-dim)',
              border: '1px solid var(--border)', borderRadius: 5,
              fontFamily: 'var(--font-mono)', fontSize: 10,
              cursor: 'pointer',
            }}>
            FULL RESCAN (slow — runs all scanners)
          </button>
        </div>
      </div>
    );
  }

  // ── Result exists but graph payload is missing ─────────────────────────────
  if (!verdict) {
    return (
      <div style={{
        height: '100%', display: 'flex', flexDirection: 'column',
        alignItems: 'center', justifyContent: 'center',
        fontFamily: 'var(--font-mono)', color: 'var(--text-dim)', gap: 14,
      }}>
        <Info size={32} style={{ opacity: 0.4 }} />
        <div style={{ fontSize: 13, color: 'var(--text)' }}>Graph data unavailable</div>
        <div style={{ fontSize: 10, maxWidth: 360, textAlign: 'center', lineHeight: 1.7 }}>
          The correlation completed but returned no graph payload.
          This usually means the engine daemon is not running or
          the correlate response was malformed.
        </div>
        <button onClick={() => correlateEntities(false)}
          style={{
            marginTop: 4, padding: '8px 20px',
            background: 'transparent', color: 'var(--text)',
            border: '1px solid var(--border)', borderRadius: 5,
            fontFamily: 'var(--font-mono)', fontSize: 11, cursor: 'pointer',
          }}>
          RETRY
        </button>
      </div>
    );
  }

  const severityColor = threatColor(verdict.severity);
  const SeverityIcon = verdict.severity === 'Clean'
    ? CheckCircle
    : verdict.severity === 'Suspicious'
      ? AlertTriangle
      : Zap;

  return (
    <div style={{
      height: '100%', display: 'flex', overflow: 'hidden',
      fontFamily: 'var(--font-mono)',
      background: 'var(--void)',
    }}>

      {/* ── Left panel: verdict text ────────────────────────────────────────── */}
      <div style={{
        width: 480, flexShrink: 0,
        borderRight: '1px solid var(--border)',
        display: 'flex', flexDirection: 'column',
        overflow: 'hidden',
      }}>
        {/* Header */}
        <div style={{
          padding: '18px 20px 14px',
          borderBottom: '1px solid var(--border)',
          background: 'var(--base)',
          flexShrink: 0,
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
            <SeverityIcon size={18} color={severityColor} />
            <span style={{ fontSize: 13, fontWeight: 700, color: severityColor, letterSpacing: '0.08em' }}>
              GRAPH VERDICT — {verdict.severity.toUpperCase()}
            </span>
          </div>
          <div style={{ fontSize: 10, color: 'var(--text-dim)' }}>
            {verdict.chains.length} attack chain{verdict.chains.length !== 1 ? 's' : ''} detected
            &nbsp;·&nbsp;
            {verdict.verdictNodes.length} entit{verdict.verdictNodes.length !== 1 ? 'ies' : 'y'} involved
          </div>
        </div>

        <div style={{ flex: 1, overflowY: 'auto', padding: '16px 20px', display: 'flex', flexDirection: 'column', gap: 18 }}>

          {/* Overall summary */}
          <section>
            <div style={{ fontSize: 9, letterSpacing: '0.12em', color: 'var(--text-dim)', marginBottom: 8 }}>
              SUMMARY
            </div>
            <p style={{
              margin: 0, fontSize: 12, color: 'var(--text)', lineHeight: 1.75,
              borderLeft: `2px solid ${severityColor}`,
              paddingLeft: 12,
            }}>
              {verdict.summary}
            </p>
          </section>

          {/* ML note */}
          {verdict.mlNote && (
            <div style={{
              display: 'flex', gap: 8, alignItems: 'flex-start',
              background: 'rgba(129,140,248,0.07)',
              border: '1px solid rgba(129,140,248,0.2)',
              borderRadius: 6, padding: '8px 12px',
            }}>
              <Info size={13} color="#818cf8" style={{ flexShrink: 0, marginTop: 1 }} />
              <span style={{ fontSize: 10, color: '#818cf8', lineHeight: 1.6 }}>
                {verdict.mlNote}
              </span>
            </div>
          )}

          {/* Attack chains */}
          {verdict.hasThreats && (
            <section>
              <div style={{ fontSize: 9, letterSpacing: '0.12em', color: 'var(--text-dim)', marginBottom: 10 }}>
                DETECTED ATTACK CHAINS
              </div>
              {verdict.chains.map((chain, i) => (
                <ChainCard
                  key={chain.chain_id}
                  chain={chain}
                  sentence={verdict.sentences[i]}
                  nodeMap={verdict.nodeMap}
                />
              ))}
            </section>
          )}

          {/* No threats */}
          {!verdict.hasThreats && (
            <div style={{
              display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 10,
              padding: '24px 0', color: '#00ff88',
            }}>
              <CheckCircle size={28} />
              <span style={{ fontSize: 12 }}>No attack patterns detected.</span>
              <span style={{ fontSize: 10, color: 'var(--text-dim)', textAlign: 'center' }}>
                The graph found no structural relationships between threat signals.<br />
                All entities are either clean or isolated.
              </span>
            </div>
          )}

          {/* Critical path */}
          {verdict.criticalPath && verdict.criticalPath.node_ids.length > 0 && (
            <section>
              <div style={{ fontSize: 9, letterSpacing: '0.12em', color: 'var(--text-dim)', marginBottom: 8 }}>
                CRITICAL PATH
              </div>
              <div style={{
                border: '1px solid rgba(245,158,11,0.3)',
                borderRadius: 8, padding: '12px 14px',
                background: 'rgba(245,158,11,0.05)',
              }}>
                {/* Path hops */}
                <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 4, marginBottom: 10 }}>
                  {verdict.criticalPath.node_ids.map((id, i) => {
                    const node = verdict.nodeMap[id];
                    const label = node?.label ?? id;
                    const isLast = i === verdict.criticalPath!.node_ids.length - 1;
                    return (
                      <span key={id} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                        <span style={{
                          fontFamily: 'var(--font-mono)', fontSize: 10,
                          color: '#f59e0b', fontWeight: 600,
                          background: 'rgba(245,158,11,0.12)',
                          padding: '2px 7px', borderRadius: 3,
                        }}>
                          {label}
                        </span>
                        {!isLast && (
                          <span style={{ color: 'var(--text-dim)', fontSize: 11 }}>→</span>
                        )}
                      </span>
                    );
                  })}
                </div>

                {/* Narrative */}
                <p style={{
                  margin: 0, fontSize: 11, color: 'var(--text)', lineHeight: 1.7,
                  fontStyle: 'italic',
                }}>
                  "{verdict.criticalPath.narrative}"
                </p>

                {/* Total score */}
                <div style={{ marginTop: 8, fontSize: 9, color: 'var(--text-dim)' }}>
                  Path score: {verdict.criticalPath.total_score.toFixed(3)}
                </div>
              </div>
            </section>
          )}

          {/* Spacer */}
          <div style={{ height: 8 }} />
        </div>
      </div>

      {/* ── Right panel: sub-graph ──────────────────────────────────────────── */}
      <div style={{
        flex: 1, display: 'flex', flexDirection: 'column',
        overflow: 'hidden', padding: '18px 20px',
      }}>
        <div style={{
          fontSize: 9, letterSpacing: '0.12em', color: 'var(--text-dim)', marginBottom: 14,
        }}>
          INVOLVED ENTITIES
          {verdict.verdictNodes.length > 0 && (
            <span style={{ marginLeft: 8, color: 'var(--text-dim)', fontWeight: 400 }}>
              — showing only entities linked to detected attack chains
            </span>
          )}
        </div>

        {/* The sub-graph */}
        <div style={{
          flex: 1, background: 'var(--base)',
          border: '1px solid var(--border)', borderRadius: 8,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          overflow: 'hidden', position: 'relative', minHeight: 260,
        }}>
          <VerdictSubgraph
            nodes={verdict.verdictNodes}
            edges={verdict.verdictEdges}
            criticalNodeIds={verdict.criticalPathIds}
          />
        </div>

        {/* Legend */}
        {verdict.verdictNodes.length > 0 && (
          <div style={{
            display: 'flex', gap: 16, marginTop: 12, flexWrap: 'wrap',
            fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)',
          }}>
            <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
              <span style={{ width: 16, height: 2, background: '#f59e0b', display: 'inline-block', borderRadius: 1 }} />
              Critical path
            </span>
            <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
              <span style={{ width: 16, height: 2, background: '#00d4ff', display: 'inline-block', borderRadius: 1 }} />
              Parent → child
            </span>
            <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
              <span style={{ width: 16, height: 2, background: '#facc15', display: 'inline-block', borderRadius: 1 }} />
              Shared C2
            </span>
            <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
              <span style={{ width: 16, height: 2, background: '#34d399', display: 'inline-block', borderRadius: 1 }} />
              Shared hash
            </span>
            <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
              <span style={{ color: '#818cf8' }}>ML:N/A</span>
              = ML model not run for this entity
            </span>
          </div>
        )}
      </div>
    </div>
  );
}

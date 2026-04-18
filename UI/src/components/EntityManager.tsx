import { useMemo, useState } from 'react';
import {
  Search, ChevronDown, ChevronRight,
  Cpu, Wifi, HardDrive, FolderOpen,
  GitMerge, ShieldAlert, ShieldCheck, AlertTriangle,
  Info, BrainCircuit, Link2, GitBranch, Globe, FileStack,
  Zap, Network, Loader,
} from 'lucide-react';
import { useStore } from '../store';
import type {
  DetectionSignal, MlFlowResult,
  CorrelateEntityNode, CorrelateCluster, AttackChain,
  UnifiedThreat, EntityKind, AttackPatternName,
} from '../types';

// ─── Local entity types (client-side view) ────────────────────────────────────

type EntityType = 'Process' | 'File' | 'Network' | 'Memory';

interface JoinKeys {
  pid?:        number;
  parent_pid?: number;
  file_path?:  string;
  file_hash?:  string;
  remote_ip?:  string;
  remote_port?: number;
}

interface EntityNode {
  entity_id:         string;
  entity_type:       EntityType;
  heuristic_score:   number;
  heuristic_max:     number;
  ml_score?:         number;
  combined_score:    number;
  threat_level:      UnifiedThreat;
  detection_signals: DetectionSignal[];
  join_keys:         JoinKeys;
  label:             string;
  sub_label?:        string;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function combined(heuristic: number, max: number, ml?: number): number {
  const h = Math.min(heuristic / max, 1);
  return ml !== undefined ? h * 0.4 + ml * 0.6 : h;
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

function unifyThreat(level: string): UnifiedThreat {
  if (level === 'Critical')   return 'Critical';
  if (level === 'Malicious')  return 'Malicious';
  if (level === 'Suspicious') return 'Suspicious';
  return 'Clean';
}

function threatColor(level: UnifiedThreat): string {
  if (level === 'Critical' || level === 'Malicious') return 'var(--red)';
  if (level === 'Suspicious') return 'var(--amber)';
  return 'var(--green)';
}

function scoreColor(score: number): string {
  if (score >= 0.8)  return 'var(--red)';
  if (score >= 0.55) return 'var(--amber)';
  if (score >= 0.25) return 'var(--cyan)';
  return 'var(--green)';
}

const PATTERN_META: Record<AttackPatternName, { label: string; color: string; Icon: any }> = {
  ProcessInjection: { label: 'PROCESS INJECTION',  color: 'var(--red)',   Icon: HardDrive   },
  C2Communication:  { label: 'C2 COMMUNICATION',   color: 'var(--red)',   Icon: Globe       },
  MalwareExecution: { label: 'MALWARE EXECUTION',  color: 'var(--red)',   Icon: Zap         },
  LateralMovement:  { label: 'LATERAL MOVEMENT',   color: 'var(--amber)', Icon: Network     },
  MultiStageAttack: { label: 'MULTI-STAGE ATTACK', color: 'var(--red)',   Icon: GitBranch   },
  SuspiciousSpawn:  { label: 'SUSPICIOUS SPAWN',   color: 'var(--amber)', Icon: GitMerge    },
};

// ─── Sub-components ───────────────────────────────────────────────────────────

function StatCard({ label, value, color, sub }: {
  label: string; value: string | number; color: string; sub?: string;
}) {
  return (
    <div style={{
      background: 'var(--surface)', border: '1px solid var(--border)',
      borderRadius: 8, padding: '16px 20px',
      display: 'flex', flexDirection: 'column', gap: 8,
    }}>
      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)', letterSpacing: '0.1em' }}>
        {label}
      </span>
      <span style={{ fontFamily: 'var(--font-hud)', fontSize: 26, fontWeight: 700, color }}>{value}</span>
      {sub && <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)' }}>{sub}</span>}
    </div>
  );
}

function TypeIcon({ type, size = 12 }: { type: EntityType | EntityKind; size?: number }) {
  const t = typeof type === 'string' ? type.toLowerCase() : type;
  if (t === 'process') return <Cpu       size={size} color="var(--cyan)"     />;
  if (t === 'network') return <Wifi      size={size} color="var(--green)"    />;
  if (t === 'memory')  return <HardDrive size={size} color="var(--amber)"    />;
  return <FolderOpen size={size} color="var(--text-dim)" />;
}

function TypeBadge({ type }: { type: EntityType | EntityKind }) {
  const t = String(type).toLowerCase();
  const bg:   Record<string, string> = { process: 'rgba(6,182,212,0.12)',   network: 'rgba(16,185,129,0.12)', memory: 'rgba(245,158,11,0.12)', file: 'rgba(148,163,184,0.1)' };
  const fg:   Record<string, string> = { process: 'var(--cyan)',             network: 'var(--green)',          memory: 'var(--amber)',          file: 'var(--text-dim)'       };
  const label: Record<string, string> = { process: 'PROCESS', network: 'NETWORK', memory: 'MEMORY', file: 'FILE' };
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 5,
      padding: '2px 8px', borderRadius: 4, background: bg[t] ?? 'var(--elevated)',
      fontFamily: 'var(--font-hud)', fontSize: 9, color: fg[t] ?? 'var(--text-dim)', letterSpacing: '0.08em',
    }}>
      <TypeIcon type={type} size={9} />
      {label[t] ?? t.toUpperCase()}
    </span>
  );
}

function ThreatBadge({ level }: { level: UnifiedThreat }) {
  if (level === 'Clean') return null;
  const color = threatColor(level);
  const Icon = level === 'Malicious' || level === 'Critical' ? ShieldAlert : AlertTriangle;
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 5,
      padding: '2px 8px', borderRadius: 4, background: `${color}18`,
      fontFamily: 'var(--font-hud)', fontSize: 9, color, letterSpacing: '0.08em',
    }}>
      <Icon size={9} />
      {level.toUpperCase()}
    </span>
  );
}

function ScoreBar({ entity }: { entity: EntityNode }) {
  const h = Math.min(entity.heuristic_score / entity.heuristic_max, 1);
  const c = entity.combined_score;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 4, minWidth: 100 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 8, color: 'var(--text-dim)', width: 14, textAlign: 'right' }}>H</span>
        <div style={{ flex: 1, height: 3, background: 'var(--elevated)', borderRadius: 2, overflow: 'hidden' }}>
          <div style={{ width: `${h * 100}%`, height: '100%', background: scoreColor(h), borderRadius: 2 }} />
        </div>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 8, color: scoreColor(h), width: 24 }}>
          {entity.heuristic_score}
        </span>
      </div>
      {entity.ml_score !== undefined && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 8, color: '#a78bfa', width: 14, textAlign: 'right' }}>ML</span>
          <div style={{ flex: 1, height: 3, background: 'var(--elevated)', borderRadius: 2, overflow: 'hidden' }}>
            <div style={{ width: `${(entity.ml_score) * 100}%`, height: '100%', background: '#a78bfa', borderRadius: 2 }} />
          </div>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 8, color: '#a78bfa', width: 24 }}>
            {((entity.ml_score) * 100).toFixed(0)}%
          </span>
        </div>
      )}
      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 8, color: scoreColor(c), width: 14, textAlign: 'right' }}>Σ</span>
        <div style={{ flex: 1, height: 4, background: 'var(--elevated)', borderRadius: 2, overflow: 'hidden' }}>
          <div style={{ width: `${c * 100}%`, height: '100%', background: scoreColor(c), borderRadius: 2, opacity: 0.9 }} />
        </div>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: scoreColor(c), width: 24, fontWeight: 700 }}>
          {(c * 100).toFixed(0)}%
        </span>
      </div>
    </div>
  );
}

function JoinKeyChip({ icon, label, value }: { icon: React.ReactNode; label: string; value: string | number }) {
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 4,
      padding: '2px 7px', borderRadius: 4, background: 'var(--elevated)',
      fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)',
      border: '1px solid var(--border)',
    }}>
      {icon}
      <span style={{ marginRight: 2 }}>{label}:</span>
      <span style={{ color: 'var(--text)' }}>{value}</span>
    </span>
  );
}

// ─── Flat entity row ──────────────────────────────────────────────────────────

function EntityRow({ entity, expanded, onToggle, indent = false }: {
  entity: EntityNode; expanded: boolean; onToggle: () => void; indent?: boolean;
}) {
  const color = threatColor(entity.threat_level);
  const isClean = entity.threat_level === 'Clean';
  return (
    <div style={{ borderBottom: '1px solid var(--border)' }}>
      <div
        onClick={() => !isClean && onToggle()}
        style={{
          display: 'grid', gridTemplateColumns: '26px 110px 1fr 160px 140px 26px',
          gap: 12, alignItems: 'center',
          padding: `10px ${indent ? 12 : 16}px`,
          background: !isClean ? `${color}07` : 'transparent',
          cursor: !isClean ? 'pointer' : 'default',
        }}
      >
        <span style={{ color: 'var(--text-dim)', justifySelf: 'center' }}>
          {!isClean && (expanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />)}
        </span>
        <TypeBadge type={entity.entity_type} />
        <div style={{ display: 'flex', flexDirection: 'column', gap: 2, minWidth: 0 }}>
          <span style={{
            fontFamily: 'var(--font-mono)', fontSize: 10,
            color: !isClean ? color : 'var(--text)',
            overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
          }}>{entity.label}</span>
          {entity.sub_label && (
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {entity.sub_label}
            </span>
          )}
          <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginTop: 2 }}>
            {entity.join_keys.pid !== undefined && (
              <JoinKeyChip icon={<Cpu size={8} />} label="PID" value={entity.join_keys.pid} />
            )}
            {entity.join_keys.remote_ip && (
              <JoinKeyChip icon={<Wifi size={8} />} label="IP" value={entity.join_keys.remote_ip} />
            )}
            {entity.join_keys.file_hash && (
              <JoinKeyChip icon={<Link2 size={8} />} label="SHA256" value={`${entity.join_keys.file_hash.slice(0, 10)}…`} />
            )}
          </div>
        </div>
        <ScoreBar entity={entity} />
        <div style={{ display: 'flex', justifyContent: 'flex-start' }}>
          {!isClean
            ? <ThreatBadge level={entity.threat_level} />
            : <span style={{ display: 'flex', alignItems: 'center', gap: 5, fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--green)' }}>
                <ShieldCheck size={10} /> CLEAN
              </span>}
        </div>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)', textAlign: 'right' }}>
          {!isClean && entity.detection_signals.length > 0 && `${entity.detection_signals.length}sig`}
        </span>
      </div>
      {expanded && !isClean && (
        <div style={{
          padding: '12px 16px 14px 52px', background: 'var(--base)',
          borderTop: `1px solid ${color}22`,
          display: 'flex', flexDirection: 'column', gap: 10,
        }}>
          {entity.ml_score !== undefined && (
            <div style={{
              padding: '8px 12px', background: 'rgba(167,139,250,0.06)',
              border: '1px solid rgba(167,139,250,0.2)', borderRadius: 6,
              display: 'flex', gap: 20,
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontFamily: 'var(--font-mono)', fontSize: 9 }}>
                <span style={{ color: 'var(--text-dim)' }}>HEURISTIC</span>
                <span style={{ color: scoreColor(entity.heuristic_score / entity.heuristic_max) }}>
                  {entity.heuristic_score} / {entity.heuristic_max}
                </span>
                <span style={{ color: 'var(--text-dim)' }}>× 0.4</span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontFamily: 'var(--font-mono)', fontSize: 9 }}>
                <BrainCircuit size={9} color="#a78bfa" />
                <span style={{ color: 'var(--text-dim)' }}>ML MODEL</span>
                <span style={{ color: '#a78bfa' }}>{((entity.ml_score) * 100).toFixed(1)}%</span>
                <span style={{ color: 'var(--text-dim)' }}>× 0.6</span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontFamily: 'var(--font-mono)', fontSize: 9 }}>
                <span style={{ color: 'var(--text-dim)' }}>COMBINED Σ</span>
                <span style={{ color: scoreColor(entity.combined_score), fontWeight: 700 }}>
                  {(entity.combined_score * 100).toFixed(1)}%
                </span>
              </div>
            </div>
          )}
          {entity.detection_signals.length > 0 ? (
            <>
              <div style={{ fontFamily: 'var(--font-hud)', fontSize: 9, color: 'var(--text-dim)', letterSpacing: '0.1em' }}>
                DETECTION SIGNALS
              </div>
              {entity.detection_signals.map((sig, i) => (
                <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
                  <Info size={10} color={color} style={{ flexShrink: 0, marginTop: 1 }} />
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text)', flex: 1 }}>
                    {sig.description}
                  </span>
                  <span style={{ flexShrink: 0, fontFamily: 'var(--font-hud)', fontSize: 9, padding: '1px 6px', borderRadius: 3, background: `${color}18`, color }}>
                    +{sig.score}
                  </span>
                  <span style={{ flexShrink: 0, fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)' }}>
                    [{sig.source}]
                  </span>
                </div>
              ))}
            </>
          ) : (
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)' }}>
              No detection signals recorded.
            </span>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Client-side PID cluster row ──────────────────────────────────────────────

function PidClusterRow({ pid, entities, expandedIds }: {
  pid: number; entities: EntityNode[]; expandedIds: Set<string>;
}) {
  const [open, setOpen] = useState(false);
  const maxThreat = entities.reduce<UnifiedThreat>((best, e) => {
    const order: UnifiedThreat[] = ['Clean', 'Suspicious', 'Malicious', 'Critical'];
    return order.indexOf(e.threat_level) > order.indexOf(best) ? e.threat_level : best;
  }, 'Clean');
  const maxScore = Math.max(...entities.map((e) => e.combined_score));
  const types    = [...new Set(entities.map((e) => e.entity_type))];
  const color    = threatColor(maxThreat);
  const hasML    = entities.some((e) => e.ml_score !== undefined);

  return (
    <div style={{ borderBottom: '1px solid var(--border)' }}>
      <div
        onClick={() => setOpen((p) => !p)}
        style={{
          display: 'flex', alignItems: 'center', gap: 14, padding: '10px 16px',
          background: maxThreat !== 'Clean' ? `${color}08` : 'transparent',
          cursor: 'pointer',
        }}
      >
        <span style={{ color: 'var(--text-dim)' }}>
          {open ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
        </span>
        <GitMerge size={13} color={maxThreat !== 'Clean' ? color : 'var(--text-dim)'} />
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text)', flex: 1 }}>
          PID <span style={{ color: 'var(--cyan)', fontWeight: 700 }}>{pid}</span>
          <span style={{ color: 'var(--text-dim)', marginLeft: 6 }}>— {entities.length} entit{entities.length === 1 ? 'y' : 'ies'}</span>
        </span>
        <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
          {types.map((t) => <TypeBadge key={t} type={t} />)}
          {hasML && (
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, padding: '2px 6px', borderRadius: 4, background: 'rgba(167,139,250,0.12)', fontFamily: 'var(--font-hud)', fontSize: 8, color: '#a78bfa' }}>
              <BrainCircuit size={8} /> ML
            </span>
          )}
        </div>
        <span style={{ fontFamily: 'var(--font-hud)', fontSize: 11, color: scoreColor(maxScore), fontWeight: 700, minWidth: 40, textAlign: 'right' }}>
          {(maxScore * 100).toFixed(0)}%
        </span>
        {maxThreat !== 'Clean' && <ThreatBadge level={maxThreat} />}
      </div>
      {open && (
        <div style={{ paddingLeft: 32, borderTop: `1px solid ${color}20` }}>
          {entities.map((e) => (
            <EntityRow key={e.entity_id} entity={e} expanded={expandedIds.has(e.entity_id)} onToggle={() => {}} indent />
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Backend cluster row (all 4 join-reason types) ────────────────────────────

const JOIN_REASON_META = {
  SharedPid:       { icon: <GitMerge  size={13} />, label: (r: any) => `PID ${r.pid}`,          desc: 'cross-scanner correlation' },
  ParentChildChain:{ icon: <GitBranch size={13} />, label: (r: any) => `${r.parent_pid} → ${r.child_pid}`, desc: 'parent-child chain' },
  SharedRemoteIp:  { icon: <Globe     size={13} />, label: (r: any) => r.ip,                     desc: 'shared C2 host' },
  SharedFileHash:  { icon: <FileStack size={13} />, label: (r: any) => r.hash?.slice(0, 12) + '…', desc: 'same binary' },
};

function BackendClusterRow({ cluster }: { cluster: CorrelateCluster }) {
  const [open, setOpen] = useState(false);
  const meta    = JOIN_REASON_META[cluster.join_reason.type];
  const color   = threatColor(cluster.max_threat_level);
  const score   = cluster.cluster_score;
  const types   = [...new Set(cluster.members.map((m) => m.entity_type))];

  return (
    <div style={{ borderBottom: '1px solid var(--border)' }}>
      <div
        onClick={() => setOpen((p) => !p)}
        style={{
          display: 'flex', alignItems: 'center', gap: 14, padding: '10px 16px',
          background: cluster.has_threat ? `${color}08` : 'transparent',
          cursor: 'pointer',
        }}
      >
        <span style={{ color: 'var(--text-dim)' }}>
          {open ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
        </span>
        <span style={{ color: cluster.has_threat ? color : 'var(--text-dim)' }}>
          {meta?.icon}
        </span>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text)', flex: 1 }}>
          <span style={{ color: 'var(--cyan)', fontWeight: 700 }}>{meta?.label(cluster.join_reason)}</span>
          <span style={{ color: 'var(--text-dim)', marginLeft: 6 }}>— {meta?.desc} · {cluster.members.length} entit{cluster.members.length === 1 ? 'y' : 'ies'}</span>
        </span>
        <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
          {types.map((t) => <TypeBadge key={t} type={t} />)}
          <span style={{
            fontFamily: 'var(--font-hud)', fontSize: 8, padding: '2px 6px', borderRadius: 4,
            background: 'rgba(99,102,241,0.12)', color: '#818cf8',
          }}>
            {cluster.join_reason.type}
          </span>
        </div>
        <span style={{ fontFamily: 'var(--font-hud)', fontSize: 11, color: scoreColor(score), fontWeight: 700, minWidth: 40, textAlign: 'right' }}>
          {(score * 100).toFixed(0)}%
        </span>
        {cluster.has_threat && <ThreatBadge level={cluster.max_threat_level} />}
      </div>
      {open && (
        <div style={{ paddingLeft: 32, borderTop: `1px solid ${color}20` }}>
          {cluster.members.map((m) => (
            <div key={m.entity_id} style={{
              display: 'flex', alignItems: 'center', gap: 12,
              padding: '8px 16px', borderBottom: '1px solid var(--border)',
              background: m.threat_level !== 'Clean' ? `${threatColor(m.threat_level)}06` : 'transparent',
            }}>
              <TypeBadge type={m.entity_type} />
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{
                  fontFamily: 'var(--font-mono)', fontSize: 10,
                  color: m.threat_level !== 'Clean' ? threatColor(m.threat_level) : 'var(--text)',
                  overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                }}>{m.label}</div>
                {m.sub_label && (
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {m.sub_label}
                  </div>
                )}
              </div>
              <span style={{ fontFamily: 'var(--font-hud)', fontSize: 10, color: scoreColor(m.combined_score), fontWeight: 700 }}>
                {(m.combined_score * 100).toFixed(0)}%
              </span>
              <ThreatBadge level={m.threat_level} />
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Attack chain card ────────────────────────────────────────────────────────

function AttackChainCard({ chain, nodeMap }: {
  chain: AttackChain;
  nodeMap: Map<string, CorrelateEntityNode>;
}) {
  const [open, setOpen] = useState(false);
  const meta  = PATTERN_META[chain.pattern];
  const color = meta?.color ?? 'var(--red)';
  const Icon  = meta?.Icon ?? ShieldAlert;

  return (
    <div style={{
      border: `1px solid ${color}30`, borderRadius: 8,
      background: `${color}06`, overflow: 'hidden',
    }}>
      {/* Header */}
      <div
        onClick={() => setOpen((p) => !p)}
        style={{
          display: 'flex', alignItems: 'center', gap: 12,
          padding: '12px 16px', cursor: 'pointer',
        }}
      >
        <Icon size={14} color={color} style={{ flexShrink: 0 }} />
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 2 }}>
            <span style={{ fontFamily: 'var(--font-hud)', fontSize: 10, color, letterSpacing: '0.08em' }}>
              {meta?.label ?? chain.pattern}
            </span>
            <span style={{
              fontFamily: 'var(--font-hud)', fontSize: 8,
              padding: '1px 6px', borderRadius: 3,
              background: `${color}20`, color,
            }}>
              {chain.severity.toUpperCase()}
            </span>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 8, color: 'var(--text-dim)' }}>
              {chain.chain_id}
            </span>
          </div>
          <div style={{
            fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)',
            overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
          }}>
            {chain.description}
          </div>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 4, flexShrink: 0 }}>
          <span style={{ fontFamily: 'var(--font-hud)', fontSize: 13, color, fontWeight: 700 }}>
            {(chain.chain_score * 100).toFixed(0)}%
          </span>
          <span style={{ color: 'var(--text-dim)' }}>
            {open ? <ChevronDown size={11} /> : <ChevronRight size={11} />}
          </span>
        </div>
      </div>

      {/* Expanded */}
      {open && (
        <div style={{ borderTop: `1px solid ${color}20`, padding: '12px 16px', display: 'flex', flexDirection: 'column', gap: 10 }}>
          {/* MITRE */}
          <div style={{
            display: 'inline-flex', alignItems: 'center', gap: 6,
            padding: '4px 10px', borderRadius: 4,
            background: 'rgba(139,92,246,0.1)', border: '1px solid rgba(139,92,246,0.25)',
            fontFamily: 'var(--font-mono)', fontSize: 9, color: '#a78bfa',
          }}>
            <ShieldAlert size={9} />
            MITRE ATT&CK: {chain.mitre_tactic}
          </div>

          {/* Chain nodes */}
          <div style={{ fontFamily: 'var(--font-hud)', fontSize: 9, color: 'var(--text-dim)', letterSpacing: '0.1em', marginTop: 4 }}>
            CHAIN MEMBERS ({chain.node_ids.length})
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            {chain.node_ids.map((nid, i) => {
              const node = nodeMap.get(nid);
              if (!node) return (
                <div key={nid} style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)', padding: '4px 8px' }}>
                  {nid}
                </div>
              );
              const nc = threatColor(node.threat_level);
              return (
                <div key={nid} style={{
                  display: 'flex', alignItems: 'center', gap: 8,
                  padding: '6px 10px', borderRadius: 4,
                  background: 'var(--elevated)', border: `1px solid ${nc}18`,
                }}>
                  {i > 0 && (
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)', minWidth: 12 }}>→</span>
                  )}
                  <TypeBadge type={node.entity_type} />
                  <span style={{
                    fontFamily: 'var(--font-mono)', fontSize: 9, color: nc,
                    flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                  }}>{node.label}</span>
                  <span style={{ fontFamily: 'var(--font-hud)', fontSize: 9, color: scoreColor(node.combined_score), fontWeight: 700 }}>
                    {(node.combined_score * 100).toFixed(0)}%
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────

type TypeFilter   = 'all' | EntityType;
type ThreatFilter = 'all' | 'threats';
type ViewMode     = 'flat' | 'clusters' | 'attack_chains';

export default function EntityManager() {
  const {
    processes, networkConnections, memoryRegions, scanResults, mlIdsResult,
    correlating, correlateResult, correlateError,
    correlateEntities, clearCorrelate,
  } = useStore();

  const [typeFilter,    setTypeFilter]   = useState<TypeFilter>('all');
  const [threatFilter,  setThreatFilter] = useState<ThreatFilter>('all');
  const [viewMode,      setViewMode]     = useState<ViewMode>('flat');
  const [search,        setSearch]       = useState('');
  const [expandedIds,   setExpandedIds]  = useState<Set<string>>(new Set());
  const [includeMemory, setIncludeMemory] = useState(false);

  // ── Build client-side entity nodes from store ──────────────────────────────
  const entities = useMemo<EntityNode[]>(() => {
    const nodes: EntityNode[] = [];
    const mlFlows = mlIdsResult?.flows ?? [];

    processes.forEach((p) => {
      const threat = unifyThreat(p.threat_level);
      nodes.push({
        entity_id: `proc:${p.pid}:${p.name}`, entity_type: 'Process',
        heuristic_score: p.threat_score, heuristic_max: 30,
        combined_score: combined(p.threat_score, 30), threat_level: threat,
        detection_signals: p.detection_signals,
        join_keys: { pid: p.pid, parent_pid: p.parent_pid ?? undefined, file_path: p.exe_path ?? undefined },
        label: p.name, sub_label: p.exe_path ?? undefined,
      });
    });

    networkConnections.forEach((conn) => {
      const ml    = mlFlows.length > 0 ? matchMlScore(conn.remote_address, mlFlows) : undefined;
      const threat = unifyThreat(conn.threat_level);
      const parsed = parseRemoteIp(conn.remote_address);
      nodes.push({
        entity_id: `net:${conn.protocol}:${conn.local_address}:${conn.remote_address}`, entity_type: 'Network',
        heuristic_score: conn.threat_score, heuristic_max: 40, ml_score: ml,
        combined_score: combined(conn.threat_score, 40, ml), threat_level: threat,
        detection_signals: conn.detection_signals,
        join_keys: { pid: conn.pid ?? undefined, remote_ip: parsed?.ip, remote_port: parsed?.port },
        label: `${conn.protocol.toUpperCase()} → ${conn.remote_address}`,
        sub_label: conn.process_name ? `${conn.process_name} · ${conn.state}` : conn.state,
      });
    });

    memoryRegions.forEach((r) => {
      const threat = r.threat_level === 'Malicious' ? 'Malicious' : 'Suspicious' as UnifiedThreat;
      nodes.push({
        entity_id: `mem:${r.pid}:${r.region_start.toString(16)}`, entity_type: 'Memory',
        heuristic_score: r.threat_score, heuristic_max: 40,
        combined_score: combined(r.threat_score, 40), threat_level: threat,
        detection_signals: r.detection_signals,
        join_keys: { pid: r.pid },
        label: `${r.process_name} @ 0x${r.region_start.toString(16).toUpperCase()}`,
        sub_label: `${r.protection} · size: ${(r.region_size / 1024).toFixed(1)} KB`,
      });
    });

    scanResults.filter((f) => f.level !== 'Clean').forEach((f) => {
      const threat = f.level === 'Malicious' ? 'Malicious' : 'Suspicious' as UnifiedThreat;
      const fileName = f.path.split(/[/\\]/).pop() ?? f.path;
      nodes.push({
        entity_id: `file:${f.hash ?? f.path}`, entity_type: 'File',
        heuristic_score: Math.round(f.confidence_score * 20), heuristic_max: 20,
        combined_score: combined(Math.round(f.confidence_score * 20), 20), threat_level: threat,
        detection_signals: f.detection_signals,
        join_keys: { file_path: f.path, file_hash: f.hash ?? undefined },
        label: fileName, sub_label: f.path,
      });
    });

    return nodes;
  }, [processes, networkConnections, memoryRegions, scanResults, mlIdsResult]);

  // ── Stats ──────────────────────────────────────────────────────────────────
  const stats = useMemo(() => {
    const cr = correlateResult;
    return {
      total:   entities.length,
      process: entities.filter((e) => e.entity_type === 'Process').length,
      network: entities.filter((e) => e.entity_type === 'Network').length,
      memory:  entities.filter((e) => e.entity_type === 'Memory').length,
      file:    entities.filter((e) => e.entity_type === 'File').length,
      threats: entities.filter((e) => e.threat_level !== 'Clean').length,
      withML:  entities.filter((e) => e.ml_score !== undefined).length,
      chains:  cr?.graph?.attack_chains?.length ?? 0,
      backendClusters: cr?.clusters?.length ?? 0,
    };
  }, [entities, correlateResult]);

  // ── Filter + sort ──────────────────────────────────────────────────────────
  const filtered = useMemo(() => {
    return entities
      .filter((e) => {
        if (typeFilter !== 'all' && e.entity_type !== typeFilter) return false;
        if (threatFilter === 'threats' && e.threat_level === 'Clean') return false;
        if (search) {
          const q = search.toLowerCase();
          return (
            e.label.toLowerCase().includes(q) ||
            (e.sub_label ?? '').toLowerCase().includes(q) ||
            e.entity_id.toLowerCase().includes(q) ||
            (e.join_keys.pid !== undefined && String(e.join_keys.pid).includes(q)) ||
            (e.join_keys.remote_ip ?? '').includes(q)
          );
        }
        return true;
      })
      .sort((a, b) => b.combined_score - a.combined_score);
  }, [entities, typeFilter, threatFilter, search]);

  // ── Client-side PID clusters (fallback when no backend data) ──────────────
  const clientClusters = useMemo(() => {
    const byPid = new Map<number, EntityNode[]>();
    filtered.forEach((e) => {
      if (e.join_keys.pid !== undefined) {
        const arr = byPid.get(e.join_keys.pid) ?? [];
        arr.push(e);
        byPid.set(e.join_keys.pid, arr);
      }
    });
    return [...byPid.entries()]
      .filter(([, nodes]) => new Set(nodes.map((n) => n.entity_type)).size > 1)
      .sort(([, a], [, b]) => {
        const maxA = Math.max(...a.map((n) => n.combined_score));
        const maxB = Math.max(...b.map((n) => n.combined_score));
        return maxB - maxA;
      });
  }, [filtered]);

  // ── Backend cluster list (when correlate result is available) ──────────────
  const backendClusters = useMemo<CorrelateCluster[]>(() => {
    if (!correlateResult) return [];
    return [...correlateResult.clusters].sort((a, b) => b.cluster_score - a.cluster_score);
  }, [correlateResult]);

  // ── Attack chains + node lookup ────────────────────────────────────────────
  const attackChains = correlateResult?.graph?.attack_chains ?? [];
  const nodeMap = useMemo(() => {
    const m = new Map<string, CorrelateEntityNode>();
    correlateResult?.entities?.forEach((e) => m.set(e.entity_id, e));
    return m;
  }, [correlateResult]);

  const toggleExpand = (id: string) => {
    setExpandedIds((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };

  const noData     = entities.length === 0;
  const hasBackend = !!correlateResult;

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', padding: 32, gap: 24, overflow: 'hidden' }}>

      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexShrink: 0 }}>
        <div>
          <div style={{ fontFamily: 'var(--font-hud)', fontSize: 22, fontWeight: 700, color: 'var(--text-bright)', letterSpacing: '0.05em' }}>
            ENTITY MANAGER
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-dim)', marginTop: 4 }}>
            Cross-scanner entity correlation · graph-based attack chain detection · dual-signal scoring
          </div>
        </div>
        {/* Correlate controls */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)', cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={includeMemory}
              onChange={(e) => setIncludeMemory(e.target.checked)}
              style={{ accentColor: 'var(--amber)', cursor: 'pointer' }}
            />
            Include memory scan
          </label>
          {hasBackend && (
            <button onClick={clearCorrelate} style={{
              padding: '6px 12px', borderRadius: 5, fontSize: 9, fontFamily: 'var(--font-hud)',
              background: 'transparent', border: '1px solid var(--border)',
              color: 'var(--text-dim)', cursor: 'pointer',
            }}>
              CLEAR
            </button>
          )}
          <button
            onClick={() => correlateEntities(includeMemory)}
            disabled={correlating}
            style={{
              display: 'flex', alignItems: 'center', gap: 7,
              padding: '7px 16px', borderRadius: 6, fontSize: 10, fontFamily: 'var(--font-hud)',
              background: correlating ? 'var(--elevated)' : 'rgba(16,185,129,0.12)',
              border: `1px solid ${correlating ? 'var(--border)' : 'var(--green)'}`,
              color: correlating ? 'var(--text-dim)' : 'var(--green)',
              cursor: correlating ? 'not-allowed' : 'pointer', letterSpacing: '0.06em',
            }}
          >
            {correlating
              ? <><Loader size={11} style={{ animation: 'spin 1s linear infinite' }} /> CORRELATING…</>
              : <><GitMerge size={11} /> CORRELATE</>}
          </button>
        </div>
      </div>

      {/* Error banner */}
      {correlateError && (
        <div style={{
          padding: '10px 14px', borderRadius: 6, flexShrink: 0,
          background: 'rgba(255,51,85,0.08)', border: '1px solid rgba(255,51,85,0.25)',
          fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--red)',
        }}>
          Correlation error: {correlateError}
        </div>
      )}

      {/* Stats */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(8, 1fr)', gap: 10, flexShrink: 0 }}>
        <StatCard label="TOTAL ENTITIES" value={stats.total}   color="var(--text-bright)" />
        <StatCard label="PROCESS"        value={stats.process} color="var(--cyan)"    sub="heuristics" />
        <StatCard label="NETWORK"        value={stats.network} color="var(--green)"   sub="heuristics" />
        <StatCard label="MEMORY"         value={stats.memory}  color="var(--amber)"   sub="heuristics" />
        <StatCard label="FILE"           value={stats.file}    color="var(--text-dim)" sub="heuristics" />
        <StatCard label="THREATS"        value={stats.threats} color={stats.threats > 0 ? 'var(--red)' : 'var(--green)'} sub="non-clean" />
        <StatCard label="ML SCORED"      value={stats.withML}  color="#a78bfa"         sub="network+ML" />
        <StatCard label="ATTACK CHAINS"  value={stats.chains}  color={stats.chains > 0 ? 'var(--red)' : 'var(--text-dim)'} sub="from graph" />
      </div>

      {/* Toolbar */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 10,
        padding: '10px 14px', background: 'var(--surface)',
        border: '1px solid var(--border)', borderRadius: 8, flexShrink: 0,
      }}>
        {/* View mode */}
        <div style={{ display: 'flex', gap: 3 }}>
          {([
            { key: 'flat',         label: 'FLAT LIST' },
            { key: 'clusters',     label: hasBackend ? `CLUSTERS (${stats.backendClusters})` : `CLUSTERS (${clientClusters.length})` },
            { key: 'attack_chains', label: `ATTACK CHAINS (${stats.chains})` },
          ] as const).map(({ key, label }) => (
            <button key={key} onClick={() => setViewMode(key)} style={{
              padding: '5px 11px', borderRadius: 5, fontSize: 9, fontFamily: 'var(--font-hud)',
              border: `1px solid ${viewMode === key ? 'var(--border-md)' : 'transparent'}`,
              background: viewMode === key ? (key === 'attack_chains' ? 'rgba(255,51,85,0.08)' : 'var(--green-glow)') : 'transparent',
              color: viewMode === key ? (key === 'attack_chains' ? 'var(--red)' : 'var(--green)') : 'var(--text-dim)',
              cursor: 'pointer',
            }}>{label}</button>
          ))}
        </div>

        <div style={{ width: 1, height: 16, background: 'var(--border)' }} />

        {/* Type filter (only for flat list) */}
        {viewMode === 'flat' && (
          <>
            <div style={{ display: 'flex', gap: 3 }}>
              {(['all', 'Process', 'Network', 'Memory', 'File'] as const).map((t) => (
                <button key={t} onClick={() => setTypeFilter(t)} style={{
                  padding: '5px 10px', borderRadius: 5, fontSize: 9, fontFamily: 'var(--font-hud)',
                  border: `1px solid ${typeFilter === t ? 'var(--border-md)' : 'transparent'}`,
                  background: typeFilter === t ? 'var(--elevated)' : 'transparent',
                  color: typeFilter === t ? 'var(--text)' : 'var(--text-dim)', cursor: 'pointer',
                }}>
                  {t === 'all'
                    ? `ALL (${stats.total})`
                    : `${t.toUpperCase()} (${stats[t.toLowerCase() as 'process' | 'network' | 'memory' | 'file']})`}
                </button>
              ))}
            </div>
            <div style={{ width: 1, height: 16, background: 'var(--border)' }} />
            {(['all', 'threats'] as const).map((t) => (
              <button key={t} onClick={() => setThreatFilter(t)} style={{
                padding: '5px 10px', borderRadius: 5, fontSize: 9, fontFamily: 'var(--font-hud)',
                border: `1px solid ${threatFilter === t ? 'var(--border-md)' : 'transparent'}`,
                background: threatFilter === t ? (t === 'threats' ? 'rgba(255,51,85,0.08)' : 'transparent') : 'transparent',
                color: threatFilter === t ? (t === 'threats' ? 'var(--red)' : 'var(--text)') : 'var(--text-dim)',
                cursor: 'pointer',
              }}>
                {t === 'all' ? 'ALL' : `THREATS ONLY (${stats.threats})`}
              </button>
            ))}
          </>
        )}

        {/* Search */}
        <div style={{
          display: 'flex', alignItems: 'center', gap: 8, marginLeft: 'auto', width: 260,
          background: 'var(--base)', border: '1px solid var(--border)', borderRadius: 6, padding: '5px 10px',
        }}>
          <Search size={12} color="var(--text-dim)" />
          <input
            value={search} onChange={(e) => setSearch(e.target.value)}
            placeholder="PID, name, IP, path…"
            style={{
              background: 'transparent', border: 'none', outline: 'none',
              color: 'var(--text)', fontFamily: 'var(--font-mono)', fontSize: 10, width: '100%',
            }}
          />
        </div>
      </div>

      {/* Table header (flat only) */}
      {viewMode === 'flat' && filtered.length > 0 && (
        <div style={{
          display: 'grid', gridTemplateColumns: '26px 110px 1fr 160px 140px 26px',
          gap: 12, padding: '6px 16px',
          fontFamily: 'var(--font-hud)', fontSize: 9, color: 'var(--text-dim)', letterSpacing: '0.1em',
          background: 'var(--base)', border: '1px solid var(--border)', borderRadius: '8px 8px 0 0',
          flexShrink: 0,
        }}>
          {['', 'TYPE', 'ENTITY / ATTRIBUTES', 'SCORE  (H · ML · Σ)', 'VERDICT', ''].map((h) => (
            <span key={h}>{h}</span>
          ))}
        </div>
      )}

      {/* Main content */}
      <div style={{
        flex: 1, overflowY: 'auto',
        background: 'var(--surface)', border: '1px solid var(--border)',
        borderRadius: viewMode === 'flat' && filtered.length > 0 ? '0 0 8px 8px' : 8,
        marginTop: viewMode === 'flat' && filtered.length > 0 ? -1 : 0,
      }}>

        {/* ── No data placeholder ──────────────────────────────────────────── */}
        {noData && viewMode !== 'attack_chains' && (
          <div style={{
            display: 'flex', flexDirection: 'column', alignItems: 'center',
            justifyContent: 'center', height: '100%', gap: 12,
          }}>
            <GitMerge size={32} color="var(--text-dim)" style={{ opacity: 0.4 }} />
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-dim)' }}>No entity data yet</div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)', opacity: 0.6 }}>
              Run a scan from Processes, Network, Memory, or Scanner
            </div>
          </div>
        )}

        {/* ── Flat list ────────────────────────────────────────────────────── */}
        {!noData && viewMode === 'flat' && (
          filtered.length === 0 ? (
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: 120, fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-dim)' }}>
              No entities match the current filter
            </div>
          ) : (
            filtered.map((entity) => (
              <EntityRow
                key={entity.entity_id} entity={entity}
                expanded={expandedIds.has(entity.entity_id)}
                onToggle={() => toggleExpand(entity.entity_id)}
              />
            ))
          )
        )}

        {/* ── Cluster view ─────────────────────────────────────────────────── */}
        {viewMode === 'clusters' && !noData && (
          hasBackend ? (
            backendClusters.length === 0 ? (
              <div style={{
                display: 'flex', flexDirection: 'column', alignItems: 'center',
                justifyContent: 'center', height: 180, gap: 8,
              }}>
                <GitMerge size={24} color="var(--text-dim)" style={{ opacity: 0.4 }} />
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-dim)' }}>
                  No correlated clusters found
                </div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)', opacity: 0.6 }}>
                  Run CORRELATE to analyse cross-scanner relationships
                </div>
              </div>
            ) : (
              <>
                <div style={{
                  display: 'flex', alignItems: 'center', gap: 8,
                  padding: '8px 16px', borderBottom: '1px solid var(--border)',
                  background: 'rgba(99,102,241,0.06)',
                }}>
                  <GitMerge size={11} color="#818cf8" />
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: '#818cf8' }}>
                    Backend correlation active · {backendClusters.length} clusters · 4 strategies (PID, ParentChild, SharedIP, FileHash)
                  </span>
                  <span style={{ marginLeft: 'auto', fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)' }}>
                    {correlateResult?.statistics.scan_duration_ms}ms
                  </span>
                </div>
                {backendClusters.map((c) => (
                  <BackendClusterRow key={c.anchor_id} cluster={c} />
                ))}
              </>
            )
          ) : (
            // Fallback: client-side PID clusters
            clientClusters.length === 0 ? (
              <div style={{
                display: 'flex', flexDirection: 'column', alignItems: 'center',
                justifyContent: 'center', height: 180, gap: 8,
              }}>
                <GitMerge size={24} color="var(--text-dim)" style={{ opacity: 0.4 }} />
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-dim)' }}>
                  No multi-scanner clusters found
                </div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)', opacity: 0.6 }}>
                  Click CORRELATE for full cross-scanner analysis (PID + ParentChild + SharedIP + FileHash)
                </div>
              </div>
            ) : (
              clientClusters.map(([pid, nodes]) => (
                <PidClusterRow key={pid} pid={pid} entities={nodes} expandedIds={expandedIds} />
              ))
            )
          )
        )}

        {/* ── Attack chains ─────────────────────────────────────────────────── */}
        {viewMode === 'attack_chains' && (
          !hasBackend ? (
            <div style={{
              display: 'flex', flexDirection: 'column', alignItems: 'center',
              justifyContent: 'center', height: '100%', gap: 12,
            }}>
              <ShieldAlert size={32} color="var(--text-dim)" style={{ opacity: 0.4 }} />
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-dim)' }}>
                Attack chain analysis requires backend correlation
              </div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)', opacity: 0.6 }}>
                Click CORRELATE to run the graph analyser
              </div>
            </div>
          ) : attackChains.length === 0 ? (
            <div style={{
              display: 'flex', flexDirection: 'column', alignItems: 'center',
              justifyContent: 'center', height: '100%', gap: 12,
            }}>
              <ShieldCheck size={32} color="var(--green)" style={{ opacity: 0.6 }} />
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-dim)' }}>
                No attack chains detected
              </div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)', opacity: 0.6 }}>
                {correlateResult?.statistics.total_entities ?? 0} entities analysed ·{' '}
                {correlateResult?.statistics.graph_edges ?? 0} edges in graph
              </div>
            </div>
          ) : (
            <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 12 }}>
              {/* Graph stats banner */}
              <div style={{
                display: 'flex', gap: 24, padding: '10px 14px',
                background: 'var(--elevated)', borderRadius: 6,
                border: '1px solid var(--border)',
              }}>
                {[
                  { label: 'GRAPH NODES',   value: correlateResult?.statistics.graph_nodes },
                  { label: 'GRAPH EDGES',   value: correlateResult?.statistics.graph_edges },
                  { label: 'THREAT NODES',  value: correlateResult?.statistics.threat_entities },
                  { label: 'CHAINS',        value: attackChains.length },
                  { label: 'SCAN DURATION', value: `${correlateResult?.statistics.scan_duration_ms}ms` },
                ].map(({ label, value }) => (
                  <div key={label} style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                    <span style={{ fontFamily: 'var(--font-hud)', fontSize: 8, color: 'var(--text-dim)', letterSpacing: '0.1em' }}>{label}</span>
                    <span style={{ fontFamily: 'var(--font-hud)', fontSize: 16, fontWeight: 700, color: 'var(--text-bright)' }}>{value}</span>
                  </div>
                ))}
              </div>
              {attackChains.map((chain) => (
                <AttackChainCard key={chain.chain_id} chain={chain} nodeMap={nodeMap} />
              ))}
            </div>
          )
        )}
      </div>

      {/* Footer */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 20,
        fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)', flexShrink: 0,
      }}>
        <span>H = heuristic score</span>
        <span style={{ color: '#a78bfa' }}>ML = model probability</span>
        <span>Σ = combined score (H×0.4 + ML×0.6 when ML available)</span>
        {hasBackend && (
          <span style={{ color: '#818cf8' }}>
            · Backend: {correlateResult?.statistics.total_entities} entities · {correlateResult?.statistics.threat_clusters} threat clusters
          </span>
        )}
        <span style={{ marginLeft: 'auto' }}>{filtered.length} / {entities.length} entities shown</span>
      </div>
    </div>
  );
}

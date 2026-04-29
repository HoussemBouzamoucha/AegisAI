import { useMemo, useState } from 'react';
import {
  Search, ChevronDown, ChevronRight, X,
  Cpu, Wifi, HardDrive, FolderOpen,
  GitMerge, ShieldAlert, ShieldCheck, AlertTriangle,
  Info, BrainCircuit, Link2, GitBranch, Globe, FileStack,
  Zap, Network, Loader, Terminal, Hash,
  Activity, Clock, User, Server, Shield, Lock,
  Tag, Fingerprint, Flag,
} from 'lucide-react';
import { useStore } from '../store';
import type {
  DetectionSignal, MlFlowResult,
  CorrelateEntityNode, CorrelateCluster, AttackChain,
  UnifiedThreat, EntityKind, AttackPatternName,
  ProcessInfo, NetworkConnection, MemoryRegion, ScanResult,
  ProcessEntity,
} from '../types';
import {
  buildProcessEntities, orphanConnections, orphanFiles,
} from '../lib/entityUtils';

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
  // Raw source data for detail panel
  rawProcess?:        ProcessInfo;
  rawNetwork?:        NetworkConnection;
  rawMemory?:         MemoryRegion;
  rawFile?:           ScanResult;
  // Unified process entity (present for EntityType === 'Process')
  rawProcessEntity?:  ProcessEntity;
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
  SuspiciousSpawn:         { label: 'SUSPICIOUS SPAWN',          color: 'var(--amber)', Icon: GitMerge  },
  ExploitedTrustedProcess: { label: 'EXPLOITED TRUSTED PROCESS', color: 'var(--red)',   Icon: GitMerge  },
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
  const bg:    Record<string, string> = { process: 'rgba(6,182,212,0.12)',   network: 'rgba(16,185,129,0.12)', memory: 'rgba(245,158,11,0.12)', file: 'rgba(148,163,184,0.1)' };
  const fg:    Record<string, string> = { process: 'var(--cyan)',             network: 'var(--green)',          memory: 'var(--amber)',          file: 'var(--text-dim)'       };
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

// ─── Detail Field Row ─────────────────────────────────────────────────────────

function DetailField({ icon, label, value, mono = true, color, copyable = false }: {
  icon?: React.ReactNode;
  label: string;
  value: string | number | null | undefined;
  mono?: boolean;
  color?: string;
  copyable?: boolean;
}) {
  if (value === null || value === undefined || value === '') return null;
  const valStr = String(value);
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 5, fontFamily: 'var(--font-hud)', fontSize: 8, color: 'var(--text-dim)', letterSpacing: '0.08em' }}>
        {icon}
        {label}
      </div>
      <div
        title={copyable ? 'Click to copy' : undefined}
        onClick={copyable ? () => navigator.clipboard.writeText(valStr) : undefined}
        style={{
          fontFamily: mono ? 'var(--font-mono)' : 'inherit',
          fontSize: 10, color: color ?? 'var(--text)',
          wordBreak: 'break-all', lineHeight: 1.5,
          cursor: copyable ? 'pointer' : 'default',
          padding: '4px 8px', borderRadius: 4,
          background: 'var(--base)', border: '1px solid var(--border)',
        }}
      >
        {valStr}
      </div>
    </div>
  );
}

function DetailSection({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      <div style={{ fontFamily: 'var(--font-hud)', fontSize: 9, color: 'var(--text-dim)', letterSpacing: '0.12em', borderBottom: '1px solid var(--border)', paddingBottom: 5 }}>
        {title}
      </div>
      {children}
    </div>
  );
}

function FlagChip({ label, color }: { label: string; color: string }) {
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 4,
      padding: '2px 8px', borderRadius: 4,
      background: `${color}15`, border: `1px solid ${color}35`,
      fontFamily: 'var(--font-hud)', fontSize: 8, color, letterSpacing: '0.06em',
    }}>
      {label}
    </span>
  );
}

// ─── Entity Detail Panel ──────────────────────────────────────────────────────

function EntityDetailPanel({ entity, onClose }: { entity: EntityNode; onClose: () => void }) {
  const color   = threatColor(entity.threat_level);
  const isClean = entity.threat_level === 'Clean';
  const h       = Math.min(entity.heuristic_score / entity.heuristic_max, 1);

  return (
    <div style={{
      width: 340, flexShrink: 0, display: 'flex', flexDirection: 'column',
      background: 'var(--surface)', border: '1px solid var(--border)',
      borderRadius: 10, overflow: 'hidden',
    }}>
      {/* Panel header */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 10,
        padding: '12px 14px', borderBottom: `1px solid ${color}30`,
        background: `${color}06`, flexShrink: 0,
      }}>
        <div style={{
          width: 32, height: 32, borderRadius: 7, flexShrink: 0,
          background: `${color}18`, border: `1px solid ${color}40`,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
        }}>
          <TypeIcon type={entity.entity_type} size={14} />
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{
            fontFamily: 'var(--font-mono)', fontSize: 11,
            color: isClean ? 'var(--text)' : color,
            overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
          }}>{entity.label}</div>
          <div style={{ display: 'flex', gap: 6, marginTop: 4, flexWrap: 'wrap' }}>
            <TypeBadge type={entity.entity_type} />
            {isClean
              ? <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, fontFamily: 'var(--font-hud)', fontSize: 8, color: 'var(--green)' }}><ShieldCheck size={8} /> CLEAN</span>
              : <ThreatBadge level={entity.threat_level} />}
          </div>
        </div>
        <button
          onClick={onClose}
          style={{ background: 'transparent', border: 'none', color: 'var(--text-dim)', cursor: 'pointer', padding: 4, borderRadius: 4, flexShrink: 0 }}
        >
          <X size={14} />
        </button>
      </div>

      {/* Scrollable body */}
      <div style={{ flex: 1, overflowY: 'auto', padding: 14, display: 'flex', flexDirection: 'column', gap: 16 }}>

        {/* ── Score Breakdown ─────────────────────────────────────────────── */}
        <DetailSection title="THREAT SCORES">
          {/* Visual score bars */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6, padding: '10px 12px', background: 'var(--base)', borderRadius: 6, border: '1px solid var(--border)' }}>
            {/* Heuristic */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 8, color: 'var(--text-dim)', width: 70, flexShrink: 0 }}>HEURISTIC</span>
              <div style={{ flex: 1, height: 5, background: 'var(--elevated)', borderRadius: 3, overflow: 'hidden' }}>
                <div style={{ width: `${h * 100}%`, height: '100%', background: scoreColor(h), borderRadius: 3 }} />
              </div>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: scoreColor(h), width: 46, textAlign: 'right', flexShrink: 0 }}>
                {entity.heuristic_score} / {entity.heuristic_max}
              </span>
            </div>
            {/* ML */}
            {entity.ml_score !== undefined && (
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 8, color: '#a78bfa', width: 70, flexShrink: 0, display: 'flex', alignItems: 'center', gap: 4 }}>
                  <BrainCircuit size={8} /> ML MODEL
                </span>
                <div style={{ flex: 1, height: 5, background: 'var(--elevated)', borderRadius: 3, overflow: 'hidden' }}>
                  <div style={{ width: `${entity.ml_score * 100}%`, height: '100%', background: '#a78bfa', borderRadius: 3 }} />
                </div>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: '#a78bfa', width: 46, textAlign: 'right', flexShrink: 0 }}>
                  {(entity.ml_score * 100).toFixed(1)}%
                </span>
              </div>
            )}
            {/* Combined */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 2 }}>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 8, color: scoreColor(entity.combined_score), width: 70, flexShrink: 0 }}>COMBINED Σ</span>
              <div style={{ flex: 1, height: 7, background: 'var(--elevated)', borderRadius: 3, overflow: 'hidden' }}>
                <div style={{ width: `${entity.combined_score * 100}%`, height: '100%', background: scoreColor(entity.combined_score), borderRadius: 3 }} />
              </div>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: scoreColor(entity.combined_score), width: 46, textAlign: 'right', flexShrink: 0, fontWeight: 700 }}>
                {(entity.combined_score * 100).toFixed(1)}%
              </span>
            </div>
          </div>
          {entity.ml_score !== undefined && (
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 8, color: 'var(--text-dim)', opacity: 0.7 }}>
              Formula: H×{(0.4).toFixed(1)} + ML×{(0.6).toFixed(1)} when ML available
            </div>
          )}
        </DetailSection>

        {/* ── Identity ────────────────────────────────────────────────────── */}
        <DetailSection title="IDENTITY">
          <DetailField icon={<Fingerprint size={8} />} label="ENTITY ID" value={entity.entity_id} copyable />
          {entity.sub_label && (
            <DetailField icon={<Tag size={8} />} label="SUB LABEL" value={entity.sub_label} />
          )}
        </DetailSection>

        {/* ── Join Keys ───────────────────────────────────────────────────── */}
        {(entity.join_keys.pid !== undefined ||
          entity.join_keys.parent_pid !== undefined ||
          entity.join_keys.remote_ip ||
          entity.join_keys.remote_port !== undefined ||
          entity.join_keys.file_path ||
          entity.join_keys.file_hash) && (
          <DetailSection title="JOIN KEYS">
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {entity.join_keys.pid !== undefined && (
                <DetailField icon={<Cpu size={8} />} label="PID" value={entity.join_keys.pid} />
              )}
              {entity.join_keys.parent_pid !== undefined && (
                <DetailField icon={<GitBranch size={8} />} label="PARENT PID" value={entity.join_keys.parent_pid} />
              )}
              {entity.join_keys.remote_ip && (
                <DetailField icon={<Globe size={8} />} label="REMOTE IP" value={entity.join_keys.remote_ip} copyable />
              )}
              {entity.join_keys.remote_port !== undefined && (
                <DetailField icon={<Server size={8} />} label="REMOTE PORT" value={entity.join_keys.remote_port} />
              )}
              {entity.join_keys.file_path && (
                <DetailField icon={<FolderOpen size={8} />} label="FILE PATH" value={entity.join_keys.file_path} copyable />
              )}
              {entity.join_keys.file_hash && (
                <DetailField icon={<Hash size={8} />} label="FILE HASH (SHA256)" value={entity.join_keys.file_hash} copyable />
              )}
            </div>
          </DetailSection>
        )}

        {/* ── Per-domain evidence breakdown (unified entities only) ────────── */}
        {entity.rawProcessEntity && (() => {
          const pe = entity.rawProcessEntity!;
          type DomainRow = { label: string; score: number; count: number; unit: string; color: string };
          const rows: DomainRow[] = [
            { label: 'PROCESS',  score: pe.process_score, count: 1,               unit: 'heuristic',   color: 'var(--cyan)' },
            { label: 'NETWORK',  score: pe.network_score, count: pe.network.length, unit: 'connections', color: 'var(--green)' },
            { label: 'MEMORY',   score: pe.memory_score,  count: pe.memory.length,  unit: 'regions',     color: 'var(--amber)' },
            { label: 'FILES',    score: pe.file_score,    count: pe.files.length,   unit: 'threat files', color: 'var(--text-dim)' },
          ];
          return (
            <DetailSection title="EVIDENCE BREAKDOWN">
              <div style={{ display: 'flex', flexDirection: 'column', gap: 5, padding: '10px 12px', background: 'var(--base)', borderRadius: 6, border: '1px solid var(--border)' }}>
                {rows.map(({ label, score, count, unit, color }) => (
                  <div key={label} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 8, color, width: 52, flexShrink: 0 }}>{label}</span>
                    <div style={{ flex: 1, height: 4, background: 'var(--elevated)', borderRadius: 2, overflow: 'hidden' }}>
                      <div style={{ width: `${score * 100}%`, height: '100%', background: color, borderRadius: 2, opacity: score > 0 ? 1 : 0.2 }} />
                    </div>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 8, color: scoreColor(score), width: 32, textAlign: 'right', flexShrink: 0 }}>
                      {(score * 100).toFixed(0)}%
                    </span>
                    <span style={{ fontFamily: 'var(--font-hud)', fontSize: 7, color: 'var(--text-dim)', width: 60, flexShrink: 0 }}>
                      {count} {unit}
                    </span>
                  </div>
                ))}
              </div>
            </DetailSection>
          );
        })()}

        {/* ── Process-specific fields ─────────────────────────────────────── */}
        {entity.rawProcess && (
          <>
            <DetailSection title="PROCESS ATTRIBUTES">
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                <DetailField icon={<Cpu size={8} />}      label="NAME"       value={entity.rawProcess.name} />
                <DetailField icon={<FolderOpen size={8} />} label="EXE PATH" value={entity.rawProcess.exe_path} copyable />
                <DetailField icon={<Terminal size={8} />} label="COMMAND LINE" value={entity.rawProcess.command_line} copyable />
                <DetailField icon={<Activity size={8} />} label="STATUS"     value={entity.rawProcess.status} />
                <DetailField icon={<User size={8} />}     label="USER"       value={entity.rawProcess.user} />
              </div>
            </DetailSection>

            <DetailSection title="RESOURCE USAGE">
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6 }}>
                {[
                  { label: 'CPU', value: `${entity.rawProcess.cpu_usage.toFixed(2)}%`, color: entity.rawProcess.cpu_usage > 50 ? 'var(--amber)' : 'var(--text)' },
                  { label: 'MEMORY', value: `${entity.rawProcess.memory_mb} MB` },
                  { label: 'VIRTUAL MEM', value: `${entity.rawProcess.virtual_memory_mb} MB` },
                  { label: 'THREADS', value: entity.rawProcess.thread_count },
                  { label: 'HANDLES', value: entity.rawProcess.handle_count ?? 'N/A' },
                  { label: 'MODULES', value: entity.rawProcess.module_count ?? 'N/A' },
                ].map(({ label, value, color }) => (
                  <div key={label} style={{ padding: '6px 8px', background: 'var(--base)', borderRadius: 5, border: '1px solid var(--border)' }}>
                    <div style={{ fontFamily: 'var(--font-hud)', fontSize: 7, color: 'var(--text-dim)', letterSpacing: '0.08em', marginBottom: 3 }}>{label}</div>
                    <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: color ?? 'var(--text)', fontWeight: 600 }}>{String(value)}</div>
                  </div>
                ))}
              </div>
            </DetailSection>

            {entity.rawProcess.anomaly_flags.length > 0 && (
              <DetailSection title="ANOMALY FLAGS">
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                  {entity.rawProcess.anomaly_flags.map((flag) => {
                    const flagColor =
                      flag === 'hollow' || flag === 'packed' ? 'var(--red)'
                      : flag === 'temp_dir' || flag === 'no_path' ? 'var(--amber)'
                      : 'var(--cyan)';
                    return <FlagChip key={flag} label={flag.toUpperCase()} color={flagColor} />;
                  })}
                </div>
              </DetailSection>
            )}

            {entity.rawProcess.start_time !== null && entity.rawProcess.start_time !== undefined && (
              <DetailSection title="TIMING">
                <DetailField
                  icon={<Clock size={8} />}
                  label="STARTED"
                  value={new Date(entity.rawProcess.start_time * 1000).toLocaleString()}
                />
              </DetailSection>
            )}
          </>
        )}

        {/* ── Embedded network connections (unified entity) ───────────────── */}
        {entity.rawProcessEntity && entity.rawProcessEntity.network.length > 0 && (
          <DetailSection title={`OWNED CONNECTIONS (${entity.rawProcessEntity.network.length})`}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
              {entity.rawProcessEntity.network.map((conn, i) => {
                const cc = conn.is_threat ? (conn.threat_level === 'Malicious' ? 'var(--red)' : 'var(--amber)') : 'var(--text-dim)';
                return (
                  <div key={i} style={{
                    display: 'flex', alignItems: 'center', gap: 8,
                    padding: '5px 8px', borderRadius: 4,
                    background: conn.is_threat ? `${cc}06` : 'var(--elevated)',
                    border: `1px solid ${conn.is_threat ? `${cc}25` : 'var(--border)'}`,
                  }}>
                    <Wifi size={9} color={cc} style={{ flexShrink: 0 }} />
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: cc, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {conn.protocol.toUpperCase()} → {conn.remote_address}
                      </div>
                      <div style={{ fontFamily: 'var(--font-hud)', fontSize: 7, color: 'var(--text-dim)', marginTop: 1 }}>
                        {conn.state}
                      </div>
                    </div>
                    {conn.is_threat && (
                      <span style={{ fontFamily: 'var(--font-hud)', fontSize: 7, color: cc, padding: '1px 5px', borderRadius: 3, background: `${cc}18`, flexShrink: 0 }}>
                        {conn.threat_level.toUpperCase()}
                      </span>
                    )}
                  </div>
                );
              })}
            </div>
          </DetailSection>
        )}

        {/* ── Embedded memory regions (unified entity) ───────────────────── */}
        {entity.rawProcessEntity && entity.rawProcessEntity.memory.length > 0 && (
          <DetailSection title={`MEMORY REGIONS (${entity.rawProcessEntity.memory.length})`}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
              {entity.rawProcessEntity.memory.map((r, i) => {
                const mc = r.is_threat ? (r.threat_level === 'Malicious' ? 'var(--red)' : 'var(--amber)') : 'var(--text-dim)';
                return (
                  <div key={i} style={{
                    display: 'flex', alignItems: 'center', gap: 8,
                    padding: '5px 8px', borderRadius: 4,
                    background: r.is_threat ? `${mc}06` : 'var(--elevated)',
                    border: `1px solid ${r.is_threat ? `${mc}25` : 'var(--border)'}`,
                  }}>
                    <HardDrive size={9} color={mc} style={{ flexShrink: 0 }} />
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: mc }}>
                        0x{r.region_start.toString(16).toUpperCase()} · {(r.region_size / 1024).toFixed(1)} KB
                      </div>
                      <div style={{ fontFamily: 'var(--font-hud)', fontSize: 7, color: 'var(--text-dim)', marginTop: 1 }}>
                        {r.protection}{r.is_executable ? ' · EXEC' : ''}{r.is_writable ? ' · WRITE' : ''}
                      </div>
                    </div>
                    {r.is_threat && (
                      <span style={{ fontFamily: 'var(--font-hud)', fontSize: 7, color: mc, padding: '1px 5px', borderRadius: 3, background: `${mc}18`, flexShrink: 0 }}>
                        {r.threat_level.toUpperCase()}
                      </span>
                    )}
                  </div>
                );
              })}
            </div>
          </DetailSection>
        )}

        {/* ── Embedded files (unified entity) ────────────────────────────── */}
        {entity.rawProcessEntity && entity.rawProcessEntity.files.length > 0 && (
          <DetailSection title={`ASSOCIATED FILES (${entity.rawProcessEntity.files.length})`}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
              {entity.rawProcessEntity.files.map((f, i) => {
                const fc = f.level === 'Malicious' ? 'var(--red)' : 'var(--amber)';
                const fname = f.path.split(/[/\\]/).pop() ?? f.path;
                return (
                  <div key={i} style={{
                    display: 'flex', alignItems: 'center', gap: 8,
                    padding: '5px 8px', borderRadius: 4,
                    background: `${fc}06`, border: `1px solid ${fc}25`,
                  }}>
                    <FolderOpen size={9} color={fc} style={{ flexShrink: 0 }} />
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: fc, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={f.path}>
                        {fname}
                      </div>
                      <div style={{ fontFamily: 'var(--font-hud)', fontSize: 7, color: 'var(--text-dim)', marginTop: 1 }}>
                        {f.file_category} · {(f.confidence_score * 100).toFixed(0)}% confidence
                      </div>
                    </div>
                    <span style={{ fontFamily: 'var(--font-hud)', fontSize: 7, color: fc, padding: '1px 5px', borderRadius: 3, background: `${fc}18`, flexShrink: 0 }}>
                      {f.level.toUpperCase()}
                    </span>
                  </div>
                );
              })}
            </div>
          </DetailSection>
        )}

        {/* ── Network-specific fields ─────────────────────────────────────── */}
        {entity.rawNetwork && (
          <DetailSection title="NETWORK ATTRIBUTES">
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6 }}>
                {[
                  { label: 'PROTOCOL',   value: entity.rawNetwork.protocol.toUpperCase() },
                  { label: 'STATE',      value: entity.rawNetwork.state },
                  { label: 'PROCESS',    value: entity.rawNetwork.process_name ?? 'N/A' },
                  { label: 'OWNER PID',  value: entity.rawNetwork.pid ?? 'N/A' },
                ].map(({ label, value }) => (
                  <div key={label} style={{ padding: '6px 8px', background: 'var(--base)', borderRadius: 5, border: '1px solid var(--border)' }}>
                    <div style={{ fontFamily: 'var(--font-hud)', fontSize: 7, color: 'var(--text-dim)', letterSpacing: '0.08em', marginBottom: 3 }}>{label}</div>
                    <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text)', fontWeight: 600 }}>{String(value)}</div>
                  </div>
                ))}
              </div>
              <DetailField icon={<Server size={8} />} label="LOCAL ADDRESS"  value={entity.rawNetwork.local_address} copyable />
              <DetailField icon={<Globe size={8} />}  label="REMOTE ADDRESS" value={entity.rawNetwork.remote_address} copyable />
            </div>
          </DetailSection>
        )}

        {/* ── Memory-specific fields ──────────────────────────────────────── */}
        {entity.rawMemory && (
          <>
            <DetailSection title="MEMORY REGION ATTRIBUTES">
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6 }}>
                  {[
                    { label: 'REGION START', value: `0x${entity.rawMemory.region_start.toString(16).toUpperCase()}` },
                    { label: 'SIZE',         value: `${(entity.rawMemory.region_size / 1024).toFixed(1)} KB` },
                    { label: 'PROTECTION',   value: entity.rawMemory.protection },
                    { label: 'PROCESS',      value: entity.rawMemory.process_name },
                    { label: 'PID',          value: entity.rawMemory.pid },
                  ].map(({ label, value }) => (
                    <div key={label} style={{ padding: '6px 8px', background: 'var(--base)', borderRadius: 5, border: '1px solid var(--border)' }}>
                      <div style={{ fontFamily: 'var(--font-hud)', fontSize: 7, color: 'var(--text-dim)', letterSpacing: '0.08em', marginBottom: 3 }}>{label}</div>
                      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text)', fontWeight: 600 }}>{String(value)}</div>
                    </div>
                  ))}
                </div>
                {entity.rawMemory.process_path && (
                  <DetailField icon={<FolderOpen size={8} />} label="PROCESS PATH" value={entity.rawMemory.process_path} copyable />
                )}
                {entity.rawMemory.command_line && (
                  <DetailField icon={<Terminal size={8} />} label="COMMAND LINE" value={entity.rawMemory.command_line} copyable />
                )}
              </div>
            </DetailSection>

            <DetailSection title="MEMORY FLAGS">
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                {[
                  { label: 'EXEC',      active: entity.rawMemory.is_executable, color: 'var(--red)' },
                  { label: 'WRITE',     active: entity.rawMemory.is_writable,   color: 'var(--amber)' },
                  { label: 'READ',      active: entity.rawMemory.is_readable,   color: 'var(--cyan)' },
                  { label: 'COMMITTED', active: entity.rawMemory.is_committed,  color: 'var(--green)' },
                  { label: 'PRIVATE',   active: entity.rawMemory.is_private,    color: 'var(--cyan)' },
                ].map(({ label, active, color }) => (
                  <span key={label} style={{
                    display: 'inline-flex', alignItems: 'center', gap: 4,
                    padding: '2px 8px', borderRadius: 4,
                    background: active ? `${color}15` : 'var(--elevated)',
                    border: `1px solid ${active ? `${color}35` : 'var(--border)'}`,
                    fontFamily: 'var(--font-hud)', fontSize: 8,
                    color: active ? color : 'var(--text-dim)',
                  }}>
                    <Lock size={7} />
                    {label}
                  </span>
                ))}
              </div>
            </DetailSection>

            {entity.rawMemory.content_sample && (
              <DetailSection title="CONTENT SAMPLE">
                <div style={{
                  fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--amber)',
                  padding: '8px 10px', background: 'rgba(245,158,11,0.06)',
                  border: '1px solid rgba(245,158,11,0.2)', borderRadius: 6,
                  wordBreak: 'break-all', lineHeight: 1.6, maxHeight: 80, overflowY: 'auto',
                }}>
                  {entity.rawMemory.content_sample}
                </div>
              </DetailSection>
            )}
          </>
        )}

        {/* ── File-specific fields ────────────────────────────────────────── */}
        {entity.rawFile && (
          <>
            <DetailSection title="FILE ATTRIBUTES">
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                <DetailField icon={<FolderOpen size={8} />} label="PATH"      value={entity.rawFile.path} copyable />
                <DetailField icon={<Hash size={8} />}       label="SHA256"    value={entity.rawFile.hash} copyable />
                <DetailField icon={<Shield size={8} />}     label="SIGNATURE" value={entity.rawFile.signature} />
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6 }}>
                  {[
                    { label: 'CATEGORY',   value: entity.rawFile.file_category.replace('_', ' ').toUpperCase() },
                    { label: 'CONFIDENCE', value: `${(entity.rawFile.confidence_score * 100).toFixed(1)}%` },
                  ].map(({ label, value }) => (
                    <div key={label} style={{ padding: '6px 8px', background: 'var(--base)', borderRadius: 5, border: '1px solid var(--border)' }}>
                      <div style={{ fontFamily: 'var(--font-hud)', fontSize: 7, color: 'var(--text-dim)', letterSpacing: '0.08em', marginBottom: 3 }}>{label}</div>
                      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text)', fontWeight: 600 }}>{value}</div>
                    </div>
                  ))}
                </div>
                {entity.rawFile.reason && (
                  <div style={{
                    padding: '7px 10px', background: 'var(--base)', borderRadius: 5,
                    border: '1px solid var(--border)',
                    fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text)',
                    lineHeight: 1.5,
                  }}>
                    <div style={{ fontFamily: 'var(--font-hud)', fontSize: 7, color: 'var(--text-dim)', letterSpacing: '0.08em', marginBottom: 4 }}>REASON</div>
                    {entity.rawFile.reason}
                  </div>
                )}
              </div>
            </DetailSection>

            {entity.rawFile.context_flags.length > 0 && (
              <DetailSection title="CONTEXT FLAGS">
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                  {entity.rawFile.context_flags.map((flag) => (
                    <FlagChip key={flag} label={flag.replace(/_/g, ' ').toUpperCase()} color="var(--amber)" />
                  ))}
                </div>
              </DetailSection>
            )}
          </>
        )}

        {/* ── Detection Signals ───────────────────────────────────────────── */}
        {entity.detection_signals.length > 0 && (
          <DetailSection title={`DETECTION SIGNALS (${entity.detection_signals.length})`}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {entity.detection_signals.map((sig, i) => {
                const sigColor = sig.score >= 8 ? 'var(--red)' : sig.score >= 5 ? 'var(--amber)' : 'var(--cyan)';
                return (
                  <div key={i} style={{
                    padding: '7px 10px', borderRadius: 6,
                    background: `${sigColor}06`, border: `1px solid ${sigColor}25`,
                    display: 'flex', flexDirection: 'column', gap: 4,
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <Info size={9} color={sigColor} style={{ flexShrink: 0 }} />
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text)', flex: 1, lineHeight: 1.5 }}>
                        {sig.description}
                      </span>
                    </div>
                    <div style={{ display: 'flex', gap: 8, paddingLeft: 17 }}>
                      <span style={{ fontFamily: 'var(--font-hud)', fontSize: 8, padding: '1px 6px', borderRadius: 3, background: `${sigColor}20`, color: sigColor }}>
                        +{sig.score}
                      </span>
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 8, color: 'var(--text-dim)' }}>
                        source: {sig.source}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          </DetailSection>
        )}

        {entity.detection_signals.length === 0 && entity.threat_level === 'Clean' && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '10px 12px', borderRadius: 6, background: 'rgba(16,185,129,0.06)', border: '1px solid rgba(16,185,129,0.2)' }}>
            <ShieldCheck size={12} color="var(--green)" />
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--green)' }}>No threats detected for this entity</span>
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Flat entity row ──────────────────────────────────────────────────────────

function EntityRow({ entity, selected, onSelect, indent = false }: {
  entity: EntityNode; selected: boolean; onSelect: () => void; indent?: boolean;
}) {
  const color   = threatColor(entity.threat_level);
  const isClean = entity.threat_level === 'Clean';
  return (
    <div
      onClick={onSelect}
      style={{
        display: 'grid', gridTemplateColumns: '110px 1fr 160px 140px 26px',
        gap: 12, alignItems: 'center',
        padding: `10px ${indent ? 12 : 16}px`,
        background: selected
          ? `${color}14`
          : !isClean ? `${color}07` : 'transparent',
        cursor: 'pointer',
        borderBottom: '1px solid var(--border)',
        borderLeft: selected ? `3px solid ${color}` : '3px solid transparent',
        transition: 'background 0.12s',
      }}
    >
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
          {entity.rawProcess?.anomaly_flags?.map((f) => (
            <span key={f} style={{ display: 'inline-flex', alignItems: 'center', gap: 3, padding: '1px 5px', borderRadius: 3, background: 'rgba(255,51,85,0.12)', fontFamily: 'var(--font-hud)', fontSize: 7, color: 'var(--red)' }}>
              <Flag size={7} />{f}
            </span>
          ))}
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
        {entity.detection_signals.length > 0 && `${entity.detection_signals.length}sig`}
      </span>
    </div>
  );
}

// ─── Client-side PID cluster row ──────────────────────────────────────────────

function PidClusterRow({ pid, entities, selectedId, onSelect }: {
  pid: number; entities: EntityNode[]; selectedId: string | null; onSelect: (e: EntityNode) => void;
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
            <EntityRow key={e.entity_id} entity={e} selected={selectedId === e.entity_id} onSelect={() => onSelect(e)} indent />
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
          {cluster.members.map((m) => {
            const nc = threatColor(m.threat_level);
            return (
              <div key={m.entity_id} style={{
                display: 'flex', alignItems: 'center', gap: 12,
                padding: '8px 16px', borderBottom: '1px solid var(--border)',
                background: m.threat_level !== 'Clean' ? `${nc}06` : 'transparent',
              }}>
                <TypeBadge type={m.entity_type} />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{
                    fontFamily: 'var(--font-mono)', fontSize: 10,
                    color: m.threat_level !== 'Clean' ? nc : 'var(--text)',
                    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                  }}>{m.label}</div>
                  {m.sub_label && (
                    <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {m.sub_label}
                    </div>
                  )}
                  {/* Inline join keys for backend members */}
                  <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginTop: 3 }}>
                    {m.join_keys.pid !== undefined && (
                      <JoinKeyChip icon={<Cpu size={7} />} label="PID" value={m.join_keys.pid} />
                    )}
                    {m.join_keys.remote_ip && (
                      <JoinKeyChip icon={<Globe size={7} />} label="IP" value={m.join_keys.remote_ip} />
                    )}
                    {m.join_keys.file_hash && (
                      <JoinKeyChip icon={<Hash size={7} />} label="SHA256" value={`${m.join_keys.file_hash.slice(0, 8)}…`} />
                    )}
                  </div>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 4 }}>
                  {/* Mini score bars */}
                  <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 7, color: 'var(--text-dim)' }}>H</span>
                    <div style={{ width: 50, height: 3, background: 'var(--elevated)', borderRadius: 2 }}>
                      <div style={{ width: `${Math.min(m.heuristic_score / 40, 1) * 100}%`, height: '100%', background: scoreColor(m.heuristic_score / 40), borderRadius: 2 }} />
                    </div>
                    {m.ml_score !== undefined && (
                      <>
                        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 7, color: '#a78bfa' }}>ML</span>
                        <div style={{ width: 50, height: 3, background: 'var(--elevated)', borderRadius: 2 }}>
                          <div style={{ width: `${m.ml_score * 100}%`, height: '100%', background: '#a78bfa', borderRadius: 2 }} />
                        </div>
                      </>
                    )}
                  </div>
                  <span style={{ fontFamily: 'var(--font-hud)', fontSize: 11, color: scoreColor(m.combined_score), fontWeight: 700 }}>
                    {(m.combined_score * 100).toFixed(0)}%
                  </span>
                  <ThreatBadge level={m.threat_level} />
                </div>
              </div>
            );
          })}
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
  const [selectedEntity, setSelectedEntity] = useState<EntityNode | null>(null);
  const [includeMemory, setIncludeMemory] = useState(false);

  // ── Build client-side entity nodes from store ──────────────────────────────
  // Each process becomes ONE unified entity with all owned network/memory/files
  // embedded inside it. Orphan connections (no matching process) and orphan
  // files (not a running exe) are kept as standalone entities.
  const entities = useMemo<EntityNode[]>(() => {
    const nodes: EntityNode[] = [];
    const mlFlows = mlIdsResult?.flows ?? [];

    // ── Process entities (unified) ─────────────────────────────────────────
    const processEntities = buildProcessEntities(
      processes, networkConnections, memoryRegions, scanResults, mlFlows,
    );
    processEntities.forEach((pe) => {
      nodes.push({
        entity_id:         pe.entity_id,
        entity_type:       'Process',
        heuristic_score:   pe.raw.threat_score,
        heuristic_max:     30,
        ml_score:          pe.ml_score,
        combined_score:    pe.combined_score,
        threat_level:      pe.threat_level,
        detection_signals: pe.detection_signals,
        join_keys:         { pid: pe.pid, parent_pid: pe.parent_pid ?? undefined, file_path: pe.exe_path ?? undefined },
        label:             pe.name,
        sub_label:         pe.exe_path ?? undefined,
        rawProcess:        pe.raw,
        rawProcessEntity:  pe,
      });
    });

    // ── Orphan network connections (pid not in process list) ───────────────
    orphanConnections(networkConnections, processes).forEach((conn) => {
      const ml     = mlFlows.length > 0 ? matchMlScore(conn.remote_address, mlFlows) : undefined;
      const threat = unifyThreat(conn.threat_level);
      const parsed = parseRemoteIp(conn.remote_address);
      nodes.push({
        entity_id:         `net:${conn.protocol}:${conn.local_address}:${conn.remote_address}`,
        entity_type:       'Network',
        heuristic_score:   conn.threat_score, heuristic_max: 40, ml_score: ml,
        combined_score:    combined(conn.threat_score, 40, ml), threat_level: threat,
        detection_signals: conn.detection_signals,
        join_keys:         { pid: conn.pid ?? undefined, remote_ip: parsed?.ip, remote_port: parsed?.port },
        label:             `${conn.protocol.toUpperCase()} → ${conn.remote_address}`,
        sub_label:         conn.process_name ? `${conn.process_name} · ${conn.state}` : conn.state,
        rawNetwork:        conn,
      });
    });

    // ── Orphan files (not the exe of any running process) ─────────────────
    orphanFiles(scanResults, processes).forEach((f) => {
      const threat    = f.level === 'Malicious' ? 'Malicious' : 'Suspicious' as UnifiedThreat;
      const fileName  = f.path.split(/[/\\]/).pop() ?? f.path;
      nodes.push({
        entity_id:         `file:${f.hash ?? f.path}`,
        entity_type:       'File',
        heuristic_score:   Math.round(f.confidence_score * 20), heuristic_max: 20,
        combined_score:    combined(Math.round(f.confidence_score * 20), 20), threat_level: threat,
        detection_signals: f.detection_signals,
        join_keys:         { file_path: f.path, file_hash: f.hash ?? undefined },
        label:             fileName, sub_label: f.path,
        rawFile:           f,
      });
    });

    // Deduplicate by entity_id — keep highest combined_score entry
    const seen = new Map<string, EntityNode>();
    for (const node of nodes) {
      const prev = seen.get(node.entity_id);
      if (!prev || node.combined_score > prev.combined_score) {
        seen.set(node.entity_id, node);
      }
    }
    return Array.from(seen.values());
  }, [processes, networkConnections, memoryRegions, scanResults, mlIdsResult]);

  // ── Stats ──────────────────────────────────────────────────────────────────
  const stats = useMemo(() => {
    const cr = correlateResult;
    return {
      total:   entities.length,
      process: entities.filter((e) => e.entity_type === 'Process').length,
      // Raw counts — connections/regions/files may be embedded in process entities
      network: networkConnections.length,
      memory:  memoryRegions.length,
      file:    scanResults.filter((f) => f.level !== 'Clean').length,
      threats: entities.filter((e) => e.threat_level !== 'Clean').length,
      withML:  entities.filter((e) => e.ml_score !== undefined).length,
      chains:  cr?.graph?.attack_chains?.length ?? 0,
      backendClusters: cr?.clusters?.length ?? 0,
    };
  }, [entities, correlateResult, networkConnections, memoryRegions, scanResults]);

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

  const noData     = entities.length === 0;
  const hasBackend = !!correlateResult;

  // Deselect when view changes
  const handleViewMode = (mode: ViewMode) => {
    setViewMode(mode);
    setSelectedEntity(null);
  };

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
        <StatCard label="PROCESSES"      value={stats.process} color="var(--cyan)"    sub="unified entities" />
        <StatCard label="CONNECTIONS"    value={stats.network} color="var(--green)"   sub="embedded in proc" />
        <StatCard label="MEM REGIONS"    value={stats.memory}  color="var(--amber)"   sub="embedded in proc" />
        <StatCard label="THREAT FILES"   value={stats.file}    color="var(--text-dim)" sub="embedded / orphan" />
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
            <button key={key} onClick={() => handleViewMode(key)} style={{
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
              {(['all', 'Process', 'Network', 'File'] as const).map((t) => {
                // entity counts for filter badges
                const count = t === 'all'
                  ? stats.total
                  : entities.filter((e) => e.entity_type === t).length;
                return (
                  <button key={t} onClick={() => setTypeFilter(t as TypeFilter)} style={{
                    padding: '5px 10px', borderRadius: 5, fontSize: 9, fontFamily: 'var(--font-hud)',
                    border: `1px solid ${typeFilter === t ? 'var(--border-md)' : 'transparent'}`,
                    background: typeFilter === t ? 'var(--elevated)' : 'transparent',
                    color: typeFilter === t ? 'var(--text)' : 'var(--text-dim)', cursor: 'pointer',
                  }}>
                    {t === 'all' ? `ALL (${count})` : `${t.toUpperCase()} (${count})`}
                  </button>
                );
              })}
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
      {viewMode === 'flat' && filtered.length > 0 && !selectedEntity && (
        <div style={{
          display: 'grid', gridTemplateColumns: '110px 1fr 160px 140px 26px',
          gap: 12, padding: '6px 16px',
          fontFamily: 'var(--font-hud)', fontSize: 9, color: 'var(--text-dim)', letterSpacing: '0.1em',
          background: 'var(--base)', border: '1px solid var(--border)', borderRadius: '8px 8px 0 0',
          flexShrink: 0,
        }}>
          {['TYPE', 'ENTITY / ATTRIBUTES', 'SCORE  (H · ML · Σ)', 'VERDICT', ''].map((h) => (
            <span key={h}>{h}</span>
          ))}
        </div>
      )}
      {viewMode === 'flat' && filtered.length > 0 && selectedEntity && (
        <div style={{
          display: 'grid', gridTemplateColumns: '110px 1fr 160px 140px 26px',
          gap: 12, padding: '6px 16px',
          fontFamily: 'var(--font-hud)', fontSize: 9, color: 'var(--text-dim)', letterSpacing: '0.1em',
          background: 'var(--base)', border: '1px solid var(--border)', borderRadius: '8px 8px 0 0',
          flexShrink: 0,
        }}>
          {['TYPE', 'ENTITY / ATTRIBUTES', 'SCORE  (H · ML · Σ)', 'VERDICT', ''].map((h) => (
            <span key={h}>{h}</span>
          ))}
        </div>
      )}

      {/* Main content: list + optional detail panel */}
      <div style={{ flex: 1, display: 'flex', gap: 12, overflow: 'hidden', minHeight: 0 }}>

        {/* List column */}
        <div style={{
          flex: 1, overflowY: 'auto',
          background: 'var(--surface)', border: '1px solid var(--border)',
          borderRadius: viewMode === 'flat' && filtered.length > 0 ? '0 0 8px 8px' : 8,
          marginTop: viewMode === 'flat' && filtered.length > 0 ? -1 : 0,
          minWidth: 0,
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
                  key={entity.entity_id}
                  entity={entity}
                  selected={selectedEntity?.entity_id === entity.entity_id}
                  onSelect={() => setSelectedEntity(
                    selectedEntity?.entity_id === entity.entity_id ? null : entity
                  )}
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
                  <PidClusterRow
                    key={pid} pid={pid} entities={nodes}
                    selectedId={selectedEntity?.entity_id ?? null}
                    onSelect={setSelectedEntity}
                  />
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

        {/* Detail panel — shown when an entity is selected */}
        {selectedEntity && (
          <EntityDetailPanel
            entity={selectedEntity}
            onClose={() => setSelectedEntity(null)}
          />
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
        <span style={{ marginLeft: 'auto' }}>
          {selectedEntity ? (
            <span style={{ color: 'var(--cyan)' }}>
              1 entity selected · click to dismiss
            </span>
          ) : (
            `${filtered.length} / ${entities.length} entities shown · click a row to inspect`
          )}
        </span>
      </div>
    </div>
  );
}

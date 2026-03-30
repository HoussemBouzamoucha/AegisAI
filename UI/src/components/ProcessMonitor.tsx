// src/components/ProcessMonitor.tsx
import { useState } from 'react';
import { useStore } from '../store';
import {
  RefreshCw, Cpu, Trash2, AlertTriangle, CheckCircle,
  Loader, Search, ChevronDown, ChevronRight, Shield, Zap,
  Package, Hash,
} from 'lucide-react';
import type { ProcessInfo } from '../types';

// ─── Constants ────────────────────────────────────────────────────────────────

const THREAT_COLOR: Record<string, string> = {
  Safe:      'var(--green)',
  Suspicious:'var(--amber)',
  Malicious: 'var(--red)',
  Critical:  '#e040fb',
};

// All six sources the Rust engine emits
const SIGNAL_SOURCE_COLOR: Record<string, string> = {
  path:     'var(--amber)',
  name:     'var(--red)',
  threads:  'var(--cyan)',
  resource: 'var(--amber)',
  cmdline:  'var(--red)',
  handle:   '#e040fb',   // purple — cross-process / mutex signals
  module:   'var(--cyan)', // cyan  — suspicious DLL signals
};

// ─── Small helpers ────────────────────────────────────────────────────────────

function InfoRow({ label, value, color }: { label: string; value: React.ReactNode; color?: string }) {
  return (
    <div style={{ display: 'flex', gap: 4 }}>
      <span style={{ color: 'var(--text-dim)', minWidth: 90 }}>{label}</span>
      <span style={{ color: color ?? 'var(--text)', wordBreak: 'break-all', flex: 1 }}>{value}</span>
    </div>
  );
}

// ─── Expandable Process Row ───────────────────────────────────────────────────

function ProcessRow({ proc, onKill }: { proc: ProcessInfo; onKill: (pid: number) => void }) {
  const [expanded, setExpanded] = useState(false);
  const color    = THREAT_COLOR[proc.threat_level] ?? 'var(--text-dim)';
  const isThreat = proc.is_threat;

  // Null-safe arrays
  const detectionSignals = Array.isArray(proc.detection_signals) ? proc.detection_signals : [];
  const anomalyFlags     = Array.isArray(proc.anomaly_flags)     ? proc.anomaly_flags     : [];

  return (
    <div style={{
      borderBottom: '1px solid var(--border)',
      borderLeft: isThreat ? `2px solid ${color}` : '2px solid transparent',
    }}>
      {/* ── Row header ─────────────────────────────────────────────────────── */}
      <div
        onClick={() => isThreat && setExpanded(e => !e)}
        style={{
          display: 'grid',
          gridTemplateColumns: '60px 1fr 80px 80px 100px 90px',
          alignItems: 'center',
          gap: 12,
          padding: '9px 16px',
          background: isThreat ? `${color}06` : 'transparent',
          cursor: isThreat ? 'pointer' : 'default',
          transition: 'background 0.1s',
        }}
        onMouseEnter={e => {
          (e.currentTarget as HTMLDivElement).style.background =
            isThreat ? `${color}12` : 'var(--elevated)';
        }}
        onMouseLeave={e => {
          (e.currentTarget as HTMLDivElement).style.background =
            isThreat ? `${color}06` : 'transparent';
        }}
      >
        {/* PID */}
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)' }}>
          {proc.pid}
        </span>

        {/* Name + path */}
        <div style={{ overflow: 'hidden' }}>
          <div style={{
            fontFamily: 'var(--font-mono)', fontSize: 11,
            color: isThreat ? color : 'var(--text)',
            display: 'flex', alignItems: 'center', gap: 6,
          }}>
            {isThreat && <AlertTriangle size={11} color={color} />}
            <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {proc.name}
            </span>
          </div>
          {proc.exe_path && (
            <div style={{
              fontFamily: 'var(--font-mono)', fontSize: 9,
              color: 'var(--text-dim)', marginTop: 1,
              overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
            }}>
              {proc.exe_path}
            </div>
          )}
        </div>

        {/* Memory */}
        <span style={{
          fontFamily: 'var(--font-mono)', fontSize: 10,
          color: 'var(--text-dim)', textAlign: 'right',
        }}>
          {Number.isFinite(Number(proc.memory_mb))
            ? Number(proc.memory_mb).toFixed(1)
            : String(proc.memory_mb)} MB
        </span>

        {/* CPU */}
        <span style={{
          fontFamily: 'var(--font-mono)', fontSize: 10,
          color: proc.cpu_usage > 50 ? 'var(--amber)' : 'var(--text-dim)',
          textAlign: 'right',
        }}>
          {typeof proc.cpu_usage === 'number' ? proc.cpu_usage.toFixed(1) : proc.cpu_usage}%
        </span>

        {/* Threat level badge */}
        <span style={{
          fontFamily: 'var(--font-hud)', fontSize: 10,
          color, letterSpacing: '0.06em', textAlign: 'center',
          padding: '2px 8px',
          background: `${color}15`,
          borderRadius: 4,
          border: `1px solid ${color}30`,
        }}>
          {proc.threat_level.toUpperCase()}
        </span>

        {/* Action */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6 }}>
          {isThreat ? (
            <>
              <span style={{ color: 'var(--text-dim)' }}>
                {expanded ? <ChevronDown size={11} /> : <ChevronRight size={11} />}
              </span>
              <button
                onClick={e => { e.stopPropagation(); onKill(proc.pid); }}
                style={{
                  display: 'flex', alignItems: 'center', gap: 4,
                  padding: '3px 8px',
                  background: 'rgba(255,51,85,0.1)',
                  border: '1px solid rgba(255,51,85,0.3)',
                  borderRadius: 4,
                  color: 'var(--red)',
                  fontFamily: 'var(--font-hud)', fontSize: 9,
                  letterSpacing: '0.08em', cursor: 'pointer',
                  transition: 'all 0.15s',
                }}
                onMouseEnter={e => {
                  const el = e.currentTarget as HTMLButtonElement;
                  el.style.background = 'rgba(255,51,85,0.25)';
                  el.style.borderColor = 'var(--red)';
                }}
                onMouseLeave={e => {
                  const el = e.currentTarget as HTMLButtonElement;
                  el.style.background = 'rgba(255,51,85,0.1)';
                  el.style.borderColor = 'rgba(255,51,85,0.3)';
                }}
              >
                <Trash2 size={10} /> KILL
              </button>
            </>
          ) : (
            <CheckCircle size={12} color="var(--text-dim)" style={{ opacity: 0.3 }} />
          )}
        </div>
      </div>

      {/* ── Expanded detail panel ───────────────────────────────────────────── */}
      {expanded && isThreat && (
        <div style={{
          padding: '0 16px 14px 76px',
          display: 'flex', flexDirection: 'column', gap: 12,
        }}>

          {/* ── Basic process info ─────────────────────────────────────────── */}
          <div style={{
            fontFamily: 'var(--font-mono)', fontSize: 10,
            display: 'flex', flexDirection: 'column', gap: 3,
          }}>
            {proc.parent_pid != null && (
              <InfoRow label="PARENT PID:" value={proc.parent_pid} color="var(--cyan)" />
            )}
            {proc.user && (
              <InfoRow label="USER:" value={proc.user} />
            )}
            <InfoRow
              label="SCORE:"
              value={
                <span>
                  <span style={{ color }}>{proc.threat_score}</span>
                  <span style={{ color: 'var(--text-dim)', margin: '0 12px' }}>
                    THREADS: {proc.thread_count}
                  </span>
                  <span style={{ color: 'var(--text-dim)' }}>STATUS: </span>
                  <span style={{ color: 'var(--text)' }}>{proc.status}</span>
                </span>
              }
            />
            {proc.command_line && (
              <InfoRow label="CMD:" value={proc.command_line} color={color} />
            )}
          </div>

          {/* ── Handle / Module counts ─────────────────────────────────────── */}
          {(proc.handle_count != null || proc.module_count != null) && (
            <div style={{
              display: 'flex', gap: 20,
              fontFamily: 'var(--font-mono)', fontSize: 10,
            }}>
              {proc.handle_count != null && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <Hash size={10} color="var(--text-dim)" />
                  <span style={{ color: 'var(--text-dim)' }}>HANDLES:</span>
                  <span style={{
                    color: proc.handle_count > 500 ? 'var(--amber)' : 'var(--text)',
                  }}>
                    {proc.handle_count}
                  </span>
                </div>
              )}
              {proc.module_count != null && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <Package size={10} color="var(--text-dim)" />
                  <span style={{ color: 'var(--text-dim)' }}>MODULES:</span>
                  <span style={{ color: 'var(--text)' }}>{proc.module_count}</span>
                </div>
              )}
            </div>
          )}

          {/* ── Detection signals ──────────────────────────────────────────── */}
          {detectionSignals.length > 0 && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              <div style={{
                fontFamily: 'var(--font-hud)', fontSize: 8,
                color: 'var(--text-dim)', letterSpacing: '0.08em',
                display: 'flex', alignItems: 'center', gap: 4,
              }}>
                <Zap size={9} /> DETECTION SIGNALS ({detectionSignals.length})
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                {detectionSignals.map((s, i) => (
                  <div key={i} style={{
                    display: 'flex', alignItems: 'flex-start', gap: 6,
                    padding: '4px 8px',
                    background: 'var(--bg)',
                    border: '1px solid var(--border)',
                    borderRadius: 4,
                  }}>
                    <span style={{
                      fontFamily: 'var(--font-hud)', fontSize: 8,
                      color: SIGNAL_SOURCE_COLOR[s.source] ?? 'var(--text-dim)',
                      letterSpacing: '0.08em', minWidth: 60, paddingTop: 1,
                    }}>
                      [{s.source.toUpperCase()}]
                    </span>
                    <span style={{
                      fontFamily: 'var(--font-mono)', fontSize: 9,
                      color: 'var(--text)', flex: 1, lineHeight: 1.4,
                    }}>
                      {s.description}
                    </span>
                    {s.score > 0 && (
                      <span style={{
                        fontFamily: 'var(--font-hud)', fontSize: 8,
                        color: 'var(--text-dim)', paddingTop: 1,
                        whiteSpace: 'nowrap',
                      }}>
                        +{s.score}
                      </span>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* ── Anomaly flags ──────────────────────────────────────────────── */}
          {anomalyFlags.length > 0 && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              <div style={{
                fontFamily: 'var(--font-hud)', fontSize: 8,
                color: 'var(--text-dim)', letterSpacing: '0.08em',
                display: 'flex', alignItems: 'center', gap: 4,
              }}>
                <Shield size={9} /> ANOMALY FLAGS
              </div>
              <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                {anomalyFlags.map((f, i) => (
                  <span key={i} style={{
                    padding: '2px 8px',
                    background: 'rgba(255,51,85,0.1)',
                    border: '1px solid rgba(255,51,85,0.3)',
                    borderRadius: 3,
                    fontFamily: 'var(--font-hud)', fontSize: 8,
                    color: 'var(--red)', letterSpacing: '0.06em',
                  }}>
                    {f.toUpperCase()}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Stats card ───────────────────────────────────────────────────────────────

function StatCard({ label, value, color, sub }: {
  label: string; value: React.ReactNode; color: string; sub?: string;
}) {
  return (
    <div style={{
      background: 'var(--surface)', border: '1px solid var(--border)',
      borderRadius: 8, padding: '14px 16px',
      borderTop: `2px solid ${color}`,
    }}>
      <div style={{
        fontFamily: 'var(--font-hud)', fontSize: 24, fontWeight: 700, color,
      }}>
        {value}
      </div>
      <div style={{
        fontFamily: 'var(--font-mono)', fontSize: 9,
        color: 'var(--text-dim)', marginTop: 4, letterSpacing: '0.08em',
      }}>
        {label}
      </div>
      {sub && (
        <div style={{
          fontFamily: 'var(--font-mono)', fontSize: 8,
          color: 'var(--text-dim)', marginTop: 2, opacity: 0.7,
        }}>
          {sub}
        </div>
      )}
    </div>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────

export default function ProcessMonitor() {
  const {
    processes, processStats, processScanning,
    processError, scanProcesses, killProcess,
  } = useStore();

  const [search, setSearch] = useState('');
  const [filter, setFilter] = useState<'all' | 'threats'>('all');

  const filtered = processes.filter(p => {
    if (filter === 'threats' && !p.is_threat) return false;
    if (search) {
      const q = search.toLowerCase();
      if (
        !p.name.toLowerCase().includes(q) &&
        !String(p.pid).includes(q) &&
        !(p.exe_path?.toLowerCase().includes(q)) &&
        !(p.user?.toLowerCase().includes(q))
      ) return false;
    }
    return true;
  });

  const threatCount = processes.filter(p => p.is_threat).length;

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', padding: 32, gap: 24 }}>

      {/* ── Header ──────────────────────────────────────────────────────────── */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <div style={{
            fontFamily: 'var(--font-hud)', fontSize: 22, fontWeight: 700,
            color: 'var(--text-bright)', letterSpacing: '0.05em',
          }}>
            PROCESS MONITOR
          </div>
          <div style={{
            fontFamily: 'var(--font-mono)', fontSize: 11,
            color: 'var(--text-dim)', marginTop: 4,
          }}>
            Real-time process analysis · path · name · resource · cmdline · handles · modules
          </div>
        </div>
        <button
          onClick={scanProcesses}
          disabled={processScanning}
          style={{
            display: 'flex', alignItems: 'center', gap: 8,
            padding: '10px 20px',
            background: 'var(--green-glow)',
            border: '1px solid var(--border-md)',
            borderRadius: 6,
            color: 'var(--green)',
            fontFamily: 'var(--font-hud)', fontSize: 11,
            letterSpacing: '0.1em',
            cursor: processScanning ? 'not-allowed' : 'pointer',
            opacity: processScanning ? 0.6 : 1,
          }}
        >
          <RefreshCw size={14} style={{ animation: processScanning ? 'spin 1s linear infinite' : 'none' }} />
          {processScanning ? 'SCANNING...' : 'REFRESH'}
        </button>
      </div>

      {/* ── Stats row ───────────────────────────────────────────────────────── */}
      {processStats && (
        <>
          {/* Threat counts */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 12 }}>
            <StatCard label="TOTAL"      value={processStats.total_processes}      color="var(--cyan)" />
            <StatCard label="SAFE"       value={processStats.safe_processes}       color="var(--green)" />
            <StatCard label="SUSPICIOUS" value={processStats.suspicious_processes} color="var(--amber)" />
            <StatCard label="MALICIOUS"  value={processStats.malicious_processes}  color="var(--red)" />
            <StatCard label="CRITICAL"   value={processStats.critical_processes}   color="#e040fb" />
          </div>
          {/* System metrics */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
            <StatCard
              label="MEMORY USED"
              value={`${parseFloat(processStats.total_memory_mb).toFixed(0)} MB`}
              color="var(--cyan)"
            />
            <StatCard
              label="TOTAL THREADS"
              value={processStats.total_threads}
              color="var(--text-dim)"
            />
            <StatCard
              label="AVG CPU"
              value={`${parseFloat(processStats.avg_cpu_usage).toFixed(1)}%`}
              color={parseFloat(processStats.avg_cpu_usage) > 50 ? 'var(--amber)' : 'var(--text-dim)'}
            />
            <StatCard
              label="SCAN TIME"
              value={`${processStats.scan_duration_ms} ms`}
              color="var(--text-dim)"
            />
          </div>
        </>
      )}

      {/* ── Process list ────────────────────────────────────────────────────── */}
      <div style={{
        flex: 1, display: 'flex', flexDirection: 'column',
        background: 'var(--surface)', border: '1px solid var(--border)',
        borderRadius: 8, overflow: 'hidden', minHeight: 0,
      }}>
        {/* Toolbar */}
        <div style={{
          display: 'flex', alignItems: 'center', gap: 12,
          padding: '10px 16px', borderBottom: '1px solid var(--border)',
          background: 'var(--elevated)',
        }}>
          <div style={{ display: 'flex', gap: 4 }}>
            {(['all', 'threats'] as const).map(f => (
              <button key={f} onClick={() => setFilter(f)} style={{
                padding: '4px 12px',
                background: filter === f ? 'var(--green-glow)' : 'transparent',
                border: `1px solid ${filter === f ? 'var(--border-md)' : 'transparent'}`,
                borderRadius: 4,
                color: filter === f ? 'var(--green)' : 'var(--text-dim)',
                fontFamily: 'var(--font-hud)', fontSize: 10,
                letterSpacing: '0.08em', cursor: 'pointer',
              }}>
                {f === 'all' ? `ALL (${processes.length})` : `THREATS (${threatCount})`}
              </button>
            ))}
          </div>

          <div style={{
            display: 'flex', alignItems: 'center', gap: 8,
            background: 'var(--surface)', border: '1px solid var(--border)',
            borderRadius: 4, padding: '4px 10px', marginLeft: 'auto',
          }}>
            <Search size={12} color="var(--text-dim)" />
            <input
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Search by name, PID, path or user..."
              style={{
                background: 'transparent', border: 'none', outline: 'none',
                color: 'var(--text)', fontFamily: 'var(--font-mono)', fontSize: 11,
                width: 240,
              }}
            />
          </div>
        </div>

        {/* Column headers */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: '60px 1fr 80px 80px 100px 90px',
          gap: 12, padding: '6px 16px',
          borderBottom: '1px solid var(--border)',
          background: 'var(--base)',
        }}>
          {['PID', 'PROCESS / PATH', 'MEMORY', 'CPU', 'STATUS', 'ACTION'].map((h, i) => (
            <span key={h} style={{
              fontFamily: 'var(--font-hud)', fontSize: 9,
              color: 'var(--text-dim)', letterSpacing: '0.1em',
              textAlign: i >= 2 ? 'center' : 'left',
            }}>
              {h}
            </span>
          ))}
        </div>

        {/* Rows */}
        <div style={{ flex: 1, overflowY: 'auto' }}>
          {processScanning ? (
            <div style={{
              display: 'flex', flexDirection: 'column',
              alignItems: 'center', justifyContent: 'center',
              height: '100%', gap: 16,
            }}>
              <Loader size={28} color="var(--green)" style={{ animation: 'spin 1s linear infinite' }} />
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--green)' }}>
                SCANNING PROCESSES...
              </div>
            </div>
          ) : processError ? (
            <div style={{
              display: 'flex', flexDirection: 'column',
              alignItems: 'center', justifyContent: 'center',
              height: '100%', gap: 8,
            }}>
              <AlertTriangle size={28} color="var(--red)" />
              <div style={{
                fontFamily: 'var(--font-mono)', fontSize: 11,
                color: 'var(--red)', maxWidth: 400, textAlign: 'center',
              }}>
                {processError}
              </div>
            </div>
          ) : processes.length === 0 ? (
            <div style={{
              display: 'flex', flexDirection: 'column',
              alignItems: 'center', justifyContent: 'center',
              height: '100%', gap: 12, opacity: 0.5,
            }}>
              <Cpu size={40} color="var(--text-dim)" />
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-dim)' }}>
                Click REFRESH to scan running processes
              </div>
            </div>
          ) : filtered.length === 0 ? (
            <div style={{
              display: 'flex', alignItems: 'center',
              justifyContent: 'center', height: '100%', opacity: 0.5,
            }}>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-dim)' }}>
                No processes match filter
              </div>
            </div>
          ) : (
            filtered.map(p => (
              <ProcessRow key={p.pid} proc={p} onKill={killProcess} />
            ))
          )}
        </div>
      </div>
    </div>
  );
}
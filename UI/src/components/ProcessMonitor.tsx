import { useState } from 'react';
import { useStore } from '../store/store';
import { RefreshCw, Cpu, Trash2, AlertTriangle, CheckCircle, Loader, Search } from 'lucide-react';
import type { ProcessInfo } from '../types';

const THREAT_COLOR: Record<string, string> = {
  Safe:      'var(--green)',
  Suspicious:'var(--amber)',
  Malicious: 'var(--red)',
  Critical:  '#e040fb',
};

function ProcessRow({ proc, onKill }: { proc: ProcessInfo; onKill: (pid: number) => void }) {
  const color = THREAT_COLOR[proc.threat_level] ?? 'var(--text-dim)';

  return (
    <div style={{
      display: 'grid',
      gridTemplateColumns: '60px 1fr 90px 100px 90px',
      alignItems: 'center',
      gap: 12,
      padding: '9px 16px',
      borderBottom: '1px solid var(--border)',
      background: proc.is_threat ? `${color}06` : 'transparent',
      transition: 'background 0.1s',
    }}
      onMouseEnter={e => { (e.currentTarget as HTMLDivElement).style.background = proc.is_threat ? `${color}12` : 'var(--elevated)'; }}
      onMouseLeave={e => { (e.currentTarget as HTMLDivElement).style.background = proc.is_threat ? `${color}06` : 'transparent'; }}
    >
      {/* PID */}
      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)' }}>
        {proc.pid}
      </span>

      {/* Name + behaviors */}
      <div>
        <div style={{
          fontFamily: 'var(--font-mono)', fontSize: 11,
          color: proc.is_threat ? color : 'var(--text)',
          display: 'flex', alignItems: 'center', gap: 6,
        }}>
          {proc.is_threat && <AlertTriangle size={11} color={color} />}
          {proc.name}
        </div>
        {proc.suspicious_behaviors.length > 0 && (
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: color, opacity: 0.7, marginTop: 2 }}>
            {proc.suspicious_behaviors[0]}
            {proc.suspicious_behaviors.length > 1 && ` +${proc.suspicious_behaviors.length - 1} more`}
          </div>
        )}
      </div>

      {/* Memory */}
      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)', textAlign: 'right' }}>
        {proc.memory_mb} MB
      </span>

      {/* Threat level */}
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

      {/* Kill button */}
      <div style={{ display: 'flex', justifyContent: 'center' }}>
        {proc.is_threat ? (
          <button onClick={() => onKill(proc.pid)} style={{
            display: 'flex', alignItems: 'center', gap: 4,
            padding: '4px 10px',
            background: 'rgba(255,51,85,0.1)',
            border: '1px solid rgba(255,51,85,0.3)',
            borderRadius: 4,
            color: 'var(--red)',
            fontFamily: 'var(--font-hud)', fontSize: 9,
            letterSpacing: '0.08em', cursor: 'pointer',
            transition: 'all 0.15s',
          }}
            onMouseEnter={e => { const el = e.currentTarget as HTMLButtonElement; el.style.background = 'rgba(255,51,85,0.25)'; el.style.borderColor = 'var(--red)'; }}
            onMouseLeave={e => { const el = e.currentTarget as HTMLButtonElement; el.style.background = 'rgba(255,51,85,0.1)'; el.style.borderColor = 'rgba(255,51,85,0.3)'; }}
          >
            <Trash2 size={10} /> KILL
          </button>
        ) : (
          <CheckCircle size={12} color="var(--text-dim)" style={{ opacity: 0.3 }} />
        )}
      </div>
    </div>
  );
}

export default function ProcessMonitor() {
  const { processes, processStats, processScanning, processError, scanProcesses, killProcess } = useStore();
  const [search, setSearch] = useState('');
  const [filter, setFilter] = useState<'all' | 'threats'>('all');

  const filtered = processes.filter(p => {
    if (filter === 'threats' && !p.is_threat) return false;
    if (search && !p.name.toLowerCase().includes(search.toLowerCase()) && !String(p.pid).includes(search)) return false;
    return true;
  });

  const threatCount = processes.filter(p => p.is_threat).length;

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', padding: 32, gap: 24 }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <div style={{ fontFamily: 'var(--font-hud)', fontSize: 22, fontWeight: 700, color: 'var(--text-bright)', letterSpacing: '0.05em' }}>
            PROCESS MONITOR
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-dim)', marginTop: 4 }}>
            Real-time monitoring of running system processes
          </div>
        </div>
        <button onClick={scanProcesses} disabled={processScanning} style={{
          display: 'flex', alignItems: 'center', gap: 8,
          padding: '10px 20px',
          background: 'var(--green-glow)',
          border: '1px solid var(--border-md)',
          borderRadius: 6,
          color: 'var(--green)',
          fontFamily: 'var(--font-hud)', fontSize: 11,
          letterSpacing: '0.1em', cursor: processScanning ? 'not-allowed' : 'pointer',
          opacity: processScanning ? 0.6 : 1,
        }}>
          <RefreshCw size={14} style={{ animation: processScanning ? 'spin 1s linear infinite' : 'none' }} />
          {processScanning ? 'SCANNING...' : 'REFRESH'}
        </button>
      </div>

      {/* Stats */}
      {processStats && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 12 }}>
          {[
            { label: 'TOTAL',      value: processStats.total_processes,     color: 'var(--cyan)' },
            { label: 'SAFE',       value: processStats.safe_processes,      color: 'var(--green)' },
            { label: 'SUSPICIOUS', value: processStats.suspicious_processes, color: 'var(--amber)' },
            { label: 'MALICIOUS',  value: processStats.malicious_processes, color: 'var(--red)' },
            { label: 'CRITICAL',   value: processStats.critical_processes,  color: '#e040fb' },
          ].map(s => (
            <div key={s.label} style={{
              background: 'var(--surface)', border: '1px solid var(--border)',
              borderRadius: 8, padding: '14px 16px',
              borderTop: `2px solid ${s.color}`,
            }}>
              <div style={{ fontFamily: 'var(--font-hud)', fontSize: 24, fontWeight: 700, color: s.color }}>{s.value}</div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)', marginTop: 4, letterSpacing: '0.08em' }}>{s.label}</div>
            </div>
          ))}
        </div>
      )}

      {/* Process list */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, overflow: 'hidden', minHeight: 0 }}>
        {/* Toolbar */}
        <div style={{
          display: 'flex', alignItems: 'center', gap: 12,
          padding: '10px 16px', borderBottom: '1px solid var(--border)',
          background: 'var(--elevated)',
        }}>
          {/* Filter tabs */}
          <div style={{ display: 'flex', gap: 4 }}>
            {(['all', 'threats'] as const).map(f => (
              <button key={f} onClick={() => setFilter(f)} style={{
                padding: '4px 12px',
                background: filter === f ? 'var(--green-glow)' : 'transparent',
                border: `1px solid ${filter === f ? 'var(--border-md)' : 'transparent'}`,
                borderRadius: 4,
                color: filter === f ? 'var(--green)' : 'var(--text-dim)',
                fontFamily: 'var(--font-hud)', fontSize: 10, letterSpacing: '0.08em', cursor: 'pointer',
              }}>
                {f === 'all' ? `ALL (${processes.length})` : `THREATS (${threatCount})`}
              </button>
            ))}
          </div>

          {/* Search */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 4, padding: '4px 10px', marginLeft: 'auto' }}>
            <Search size={12} color="var(--text-dim)" />
            <input
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Search by name or PID..."
              style={{
                background: 'transparent', border: 'none', outline: 'none',
                color: 'var(--text)', fontFamily: 'var(--font-mono)', fontSize: 11,
                width: 200,
              }}
            />
          </div>
        </div>

        {/* Column headers */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: '60px 1fr 90px 100px 90px',
          gap: 12, padding: '6px 16px',
          borderBottom: '1px solid var(--border)',
          background: 'var(--base)',
        }}>
          {['PID', 'PROCESS', 'MEMORY', 'STATUS', 'ACTION'].map((h, i) => (
            <span key={h} style={{
              fontFamily: 'var(--font-hud)', fontSize: 9,
              color: 'var(--text-dim)', letterSpacing: '0.1em',
              textAlign: i >= 2 ? 'center' : 'left',
            }}>{h}</span>
          ))}
        </div>

        {/* Rows */}
        <div style={{ flex: 1, overflowY: 'auto' }}>
          {processScanning ? (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%', gap: 16 }}>
              <Loader size={28} color="var(--green)" style={{ animation: 'spin 1s linear infinite' }} />
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--green)' }}>SCANNING PROCESSES...</div>
            </div>
          ) : processError ? (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%', gap: 8 }}>
              <AlertTriangle size={28} color="var(--red)" />
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--red)', maxWidth: 400, textAlign: 'center' }}>{processError}</div>
            </div>
          ) : processes.length === 0 ? (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%', gap: 12, opacity: 0.5 }}>
              <Cpu size={40} color="var(--text-dim)" />
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-dim)' }}>Click REFRESH to scan running processes</div>
            </div>
          ) : filtered.length === 0 ? (
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', opacity: 0.5 }}>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-dim)' }}>No processes match filter</div>
            </div>
          ) : (
            filtered.map(p => <ProcessRow key={p.pid} proc={p} onKill={killProcess} />)
          )}
        </div>
      </div>
    </div>
  );
}
import { useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { useStore } from './store/index';
import type { RealTimeThreat } from './types';
import TitleBar from './components/TitleBar';
import Sidebar from './components/Sidebar';
import Dashboard from './components/Dashboard';
import Scanner from './components/Scanner';
import ProcessMonitor from './components/ProcessMonitor';
import NetworkMonitor from './components/NetworkMonitor';
import MemoryMonitor from './components/MemoryMonitor';
import History from './components/History';
import EntityManager from './components/EntityManager';
import ThreatGraph from './components/ThreatGraph';
import GraphVerdict from './components/GraphVerdict';
import QuarantineManager from './components/QuarantineManager';
import Settings from './components/Settings';

function DetailRow({ label, value, mono, break: wordBreak }: {
  label: string; value: string; mono?: boolean; break?: boolean;
}) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
      <span style={{
        fontFamily: 'var(--font-hud)', fontSize: 8,
        letterSpacing: '0.12em', color: 'var(--text-dim)',
      }}>
        {label}
      </span>
      <span style={{
        fontFamily: mono ? 'var(--font-mono)' : 'var(--font-body)',
        fontSize: mono ? 10 : 11,
        color: 'var(--text)',
        wordBreak: wordBreak ? 'break-all' : 'normal',
        lineHeight: 1.5,
      }}>
        {value}
      </span>
    </div>
  );
}

export default function App() {
  const { view, checkEngine, addRealtimeThreat, realtimeRunning } = useStore();
  const [toasts, setToasts] = useState<Array<RealTimeThreat & { id: string }>>([]);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const toggleExpand = (id: string) =>
    setExpanded(prev => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });

  const dismiss = (id: string) => {
    setToasts(prev => prev.filter(t => t.id !== id));
    setExpanded(prev => { const n = new Set(prev); n.delete(id); return n; });
  };

  useEffect(() => { checkEngine(); }, []);

  // ── Real-time threat poll (2 s interval while watcher is on) ───────────────
  // The daemon queues ThreatEvents internally; get_realtime_status drains them.
  // There is no push event from the backend — we must poll.
  useEffect(() => {
    if (!realtimeRunning) return;

    const poll = async () => {
      try {
        const status = await invoke<{ running: boolean; threats: RealTimeThreat[] }>(
          'get_realtime_status',
        );
        const incoming = status.threats ?? [];
        if (incoming.length === 0) return;

        // Deduplicate within the batch itself (same file can fire ADDED + MODIFIED)
        const batchUnique = incoming.filter((t, i, arr) =>
          arr.findIndex(x => x.path === t.path) === i,
        );

        for (const threat of batchUnique) addRealtimeThreat(threat);

        // Single setState so `prev` is consistent across all new threats
        setToasts(prev => {
          const activePaths = new Set(prev.map(t => t.path));
          const toAdd = batchUnique.filter(t => !activePaths.has(t.path));
          if (toAdd.length === 0) return prev;
          const next = toAdd.map(threat => {
            const id = crypto.randomUUID();
            setTimeout(() => setToasts(p => p.filter(t => t.id !== id)), 6000);
            return { ...threat, id };
          });
          return [...prev, ...next];
        });
      } catch { /* daemon not ready yet — ignore */ }
    };

    const interval = setInterval(poll, 2000);
    return () => clearInterval(interval);
  }, [realtimeRunning]);

  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      width: '100vw',
      height: '100vh',
      background: 'var(--void)',
      overflow: 'hidden',
    }}>
      <TitleBar />
      <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>
        <Sidebar />
        <main style={{ flex: 1, overflow: 'hidden', position: 'relative' }}>
          {view === 'dashboard'  && <Dashboard />}
          {view === 'scanner'   && <Scanner />}
          {view === 'processes' && <ProcessMonitor />}
          {view === 'network'   && <NetworkMonitor />}
          {view === 'memory'    && <MemoryMonitor />}
          {view === 'history'   && <History />}
          {view === 'entities'  && <EntityManager />}
          {view === 'graph'     && <ThreatGraph />}
          {view === 'verdict'   && <GraphVerdict />}
          {view === 'quarantine' && <QuarantineManager />}
          {view === 'settings'  && <Settings />}
        </main>
      </div>

      {/* ── Real-time threat toast overlay ─────────────────────────────────── */}
      <style>{`
        @keyframes aegis-pulse {
          0%, 100% { box-shadow: 0 0 0 0 rgba(255,51,85,0.0), 0 8px 32px rgba(0,0,0,0.7); }
          50%       { box-shadow: 0 0 0 4px rgba(255,51,85,0.18), 0 8px 32px rgba(0,0,0,0.7); }
        }
      `}</style>
      {toasts.length > 0 && (
        <div style={{
          position: 'fixed', bottom: 24, right: 24,
          display: 'flex', flexDirection: 'column', gap: 10,
          zIndex: 9999, maxHeight: 'calc(100vh - 48px)',
          overflowY: 'auto', overflowX: 'hidden',
        }}>
          {toasts.map(toast => {
            const isExpanded = expanded.has(toast.id);
            const isMalicious = toast.level === 'Malicious';
            const accentColor = isMalicious ? 'var(--red)' : 'var(--amber)';
            const accentRgb   = isMalicious ? '255,51,85' : '255,136,0';
            const filename    = toast.path.split(/[\\/]/).pop() ?? toast.path;
            const ts          = new Date(toast.timestamp_secs * 1000).toLocaleTimeString();

            return (
              <div key={toast.id} style={{
                position: 'relative',
                background: 'var(--base)',
                border: `1px solid rgba(${accentRgb},0.55)`,
                borderLeft: `4px solid ${accentColor}`,
                borderRadius: 8,
                minWidth: 360, maxWidth: 460,
                overflow: 'hidden',
                animation: 'aegis-pulse 2s ease-in-out 3',
              }}>

                {/* ── Top colour bar ── */}
                <div style={{
                  height: 3,
                  background: `linear-gradient(90deg, ${accentColor}, transparent)`,
                  opacity: 0.6,
                }} />

                {/* ── Header ── */}
                <div style={{
                  display: 'flex', alignItems: 'center', gap: 10,
                  padding: '12px 14px 10px',
                  borderBottom: `1px solid rgba(${accentRgb},0.18)`,
                }}>
                  {/* Pulsing dot */}
                  <div style={{
                    width: 9, height: 9, borderRadius: '50%', flexShrink: 0,
                    background: accentColor,
                    boxShadow: `0 0 8px ${accentColor}`,
                    animation: 'aegis-pulse 1.2s ease-in-out infinite',
                  }} />
                  <span style={{
                    fontFamily: 'var(--font-hud)', fontSize: 11,
                    letterSpacing: '0.16em', color: accentColor, flex: 1,
                  }}>
                    {isMalicious ? '⚠ MALICIOUS FILE DETECTED' : '⚠ SUSPICIOUS FILE DETECTED'}
                  </span>
                  <span style={{
                    fontFamily: 'var(--font-mono)', fontSize: 9,
                    color: 'var(--text-dim)',
                  }}>
                    {ts}
                  </span>
                  <button
                    onClick={() => dismiss(toast.id)}
                    style={{
                      background: 'none', border: 'none', cursor: 'pointer',
                      color: 'var(--text-dim)', fontSize: 16, lineHeight: 1,
                      padding: '0 2px', marginLeft: 4,
                    }}
                  >×</button>
                </div>

                {/* ── Body ── */}
                <div style={{ padding: '12px 14px' }}>

                  {/* Filename — large + prominent */}
                  <div style={{
                    fontFamily: 'var(--font-mono)', fontSize: 14, fontWeight: 700,
                    color: 'var(--text-bright)', wordBreak: 'break-all',
                    marginBottom: 6,
                  }}>
                    {filename}
                  </div>

                  {/* Reason — the why */}
                  <div style={{
                    fontFamily: 'var(--font-body)', fontSize: 12,
                    color: 'var(--text)', lineHeight: 1.6,
                    marginBottom: 10,
                  }}>
                    {toast.reason || 'Threat detected by scan engine.'}
                  </div>

                  {/* Status badges */}
                  <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 10 }}>
                    <span style={{
                      fontFamily: 'var(--font-mono)', fontSize: 9, fontWeight: 700,
                      color: accentColor,
                      background: `rgba(${accentRgb},0.1)`,
                      border: `1px solid rgba(${accentRgb},0.35)`,
                      borderRadius: 4, padding: '3px 8px', letterSpacing: '0.06em',
                    }}>
                      {toast.level.toUpperCase()}
                    </span>
                    {toast.quarantined && (
                      <span style={{
                        fontFamily: 'var(--font-mono)', fontSize: 9,
                        color: 'var(--green)',
                        background: 'rgba(0,255,136,0.08)',
                        border: '1px solid rgba(0,255,136,0.3)',
                        borderRadius: 4, padding: '3px 8px',
                      }}>
                        ✓ AUTO-QUARANTINED
                      </span>
                    )}
                  </div>

                  {/* INSPECT panel */}
                  {isExpanded && (
                    <div style={{
                      marginBottom: 10,
                      padding: '10px 12px',
                      background: 'var(--elevated)',
                      border: `1px solid rgba(${accentRgb},0.2)`,
                      borderRadius: 6,
                      display: 'flex', flexDirection: 'column', gap: 7,
                    }}>
                      <DetailRow label="FULL PATH"  value={toast.path} mono break />
                      {toast.hash && <DetailRow label="SHA-256" value={toast.hash} mono break />}
                      <DetailRow label="LEVEL"     value={toast.level} />
                      <DetailRow label="DETECTED"  value={new Date(toast.timestamp_secs * 1000).toLocaleString()} />
                      <DetailRow label="QUARANTINE" value={toast.quarantined ? 'Yes — moved to AegisAI quarantine store' : 'No'} />
                    </div>
                  )}

                  {/* Action row */}
                  <div style={{ display: 'flex', gap: 8 }}>
                    <button
                      onClick={() => toggleExpand(toast.id)}
                      style={{
                        flex: 1, padding: '6px 0',
                        background: `rgba(${accentRgb},0.08)`,
                        border: `1px solid rgba(${accentRgb},0.3)`,
                        borderRadius: 5, cursor: 'pointer',
                        fontFamily: 'var(--font-hud)', fontSize: 9,
                        letterSpacing: '0.1em', color: accentColor,
                      }}
                    >
                      {isExpanded ? '▲ COLLAPSE' : '▼ INSPECT'}
                    </button>
                    <button
                      onClick={() => dismiss(toast.id)}
                      style={{
                        flex: 1, padding: '6px 0',
                        background: 'var(--elevated)',
                        border: '1px solid var(--border)',
                        borderRadius: 5, cursor: 'pointer',
                        fontFamily: 'var(--font-hud)', fontSize: 9,
                        letterSpacing: '0.1em', color: 'var(--text-dim)',
                      }}
                    >
                      DISMISS
                    </button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
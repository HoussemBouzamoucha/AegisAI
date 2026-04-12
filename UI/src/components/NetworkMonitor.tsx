import { useMemo, useState } from 'react';
import { useStore } from '../store';
import { RefreshCw, Search, ChevronDown, ChevronRight, Link, BrainCircuit, ShieldAlert, ShieldCheck, X } from 'lucide-react';
import type { MlFlowResult } from '../types';

function StatCard({ label, value, color, sub }: { label: string; value: string | number; color: string; sub?: string }) {
  return (
    <div style={{
      background: 'var(--surface)',
      border: '1px solid var(--border)',
      borderRadius: 8,
      padding: '18px 22px',
      display: 'flex',
      flexDirection: 'column',
      gap: 10,
    }}>
      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)', letterSpacing: '0.1em' }}>
        {label}
      </span>
      <span style={{ fontFamily: 'var(--font-hud)', fontSize: 28, fontWeight: 700, color }}>{value}</span>
      {sub && <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)' }}>{sub}</span>}
    </div>
  );
}

function MlResultsPanel({ flows, summary, onClose }: {
  flows: MlFlowResult[];
  summary: { total_flows: number; clean_flows: number; malicious_flows: number; malicious_rate: number };
  onClose: () => void;
}) {
  const maliciousFlows = flows.filter(f => f.prediction === 'Malicious');
  const [showAll, setShowAll] = useState(false);
  const displayed = showAll ? flows : maliciousFlows.slice(0, 50);

  return (
    <div style={{
      background: 'var(--surface)',
      border: '1px solid rgba(139, 92, 246, 0.3)',
      borderRadius: 8,
      overflow: 'hidden',
    }}>
      {/* Header */}
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '12px 16px',
        background: 'rgba(139, 92, 246, 0.06)',
        borderBottom: '1px solid rgba(139, 92, 246, 0.2)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <BrainCircuit size={14} color="#a78bfa" />
          <span style={{ fontFamily: 'var(--font-hud)', fontSize: 11, color: '#a78bfa', letterSpacing: '0.1em' }}>
            ML IDS RESULTS
          </span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
          <div style={{ display: 'flex', gap: 20 }}>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)' }}>
              Flows: <span style={{ color: 'var(--text)' }}>{summary.total_flows}</span>
            </span>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)' }}>
              Clean: <span style={{ color: 'var(--green)' }}>{summary.clean_flows}</span>
            </span>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)' }}>
              Malicious: <span style={{ color: 'var(--red)' }}>{summary.malicious_flows}</span>
            </span>
            {summary.total_flows > 0 && (
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)' }}>
                Rate: <span style={{ color: summary.malicious_rate > 0.1 ? 'var(--red)' : 'var(--amber)' }}>
                  {(summary.malicious_rate * 100).toFixed(1)}%
                </span>
              </span>
            )}
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-dim)', display: 'flex' }}>
            <X size={14} />
          </button>
        </div>
      </div>

      {/* Toggle */}
      <div style={{ padding: '8px 16px', borderBottom: '1px solid var(--border)', display: 'flex', gap: 8 }}>
        <button
          onClick={() => setShowAll(false)}
          style={{
            padding: '4px 10px', borderRadius: 4, fontSize: 10, fontFamily: 'var(--font-hud)',
            border: `1px solid ${!showAll ? 'var(--border-md)' : 'transparent'}`,
            background: !showAll ? 'rgba(255,51,85,0.08)' : 'transparent',
            color: !showAll ? 'var(--red)' : 'var(--text-dim)', cursor: 'pointer',
          }}
        >
          MALICIOUS ({maliciousFlows.length})
        </button>
        <button
          onClick={() => setShowAll(true)}
          style={{
            padding: '4px 10px', borderRadius: 4, fontSize: 10, fontFamily: 'var(--font-hud)',
            border: `1px solid ${showAll ? 'var(--border-md)' : 'transparent'}`,
            background: showAll ? 'var(--green-glow)' : 'transparent',
            color: showAll ? 'var(--green)' : 'var(--text-dim)', cursor: 'pointer',
          }}
        >
          ALL FLOWS ({flows.length})
        </button>
      </div>

      {/* Table */}
      {displayed.length === 0 ? (
        <div style={{ padding: '20px', display: 'flex', alignItems: 'center', gap: 10, color: 'var(--green)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>
          <ShieldCheck size={16} />
          No malicious flows detected in captured data.
        </div>
      ) : (
        <div style={{ maxHeight: 220, overflowY: 'auto' }}>
          {/* Column headers */}
          <div style={{
            display: 'grid', gridTemplateColumns: '1.2fr 1.2fr 80px 80px 70px 100px 90px',
            gap: 8, padding: '6px 16px',
            fontFamily: 'var(--font-hud)', fontSize: 9, color: 'var(--text-dim)', letterSpacing: '0.1em',
            background: 'var(--base)', borderBottom: '1px solid var(--border)',
          }}>
            {['SRC IP', 'DST IP', 'SPORT', 'DSPORT', 'PROTO', 'VERDICT', 'CONFIDENCE'].map(h => (
              <span key={h}>{h}</span>
            ))}
          </div>
          {displayed.map((flow, i) => {
            const isMal = flow.prediction === 'Malicious';
            const pct   = (flow.probability * 100).toFixed(1);
            return (
              <div key={i} style={{
                display: 'grid', gridTemplateColumns: '1.2fr 1.2fr 80px 80px 70px 100px 90px',
                gap: 8, padding: '8px 16px',
                borderBottom: '1px solid var(--border)',
                background: isMal ? 'rgba(255,51,85,0.04)' : 'transparent',
                alignItems: 'center',
              }}>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: isMal ? 'var(--red)' : 'var(--text)' }}>
                  {flow.srcip}
                </span>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: isMal ? 'var(--red)' : 'var(--text)' }}>
                  {flow.dstip}
                </span>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)' }}>{flow.sport}</span>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)' }}>{flow.dsport}</span>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)' }}>
                  {flow.proto.toUpperCase()}
                </span>
                <span style={{ display: 'flex', alignItems: 'center', gap: 5, fontFamily: 'var(--font-mono)', fontSize: 10, color: isMal ? 'var(--red)' : 'var(--green)' }}>
                  {isMal ? <ShieldAlert size={11} /> : <ShieldCheck size={11} />}
                  {flow.prediction.toUpperCase()}
                </span>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: isMal ? 'var(--red)' : 'var(--text-dim)' }}>
                  {pct}%
                </span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

export default function NetworkMonitor() {
  const {
    networkConnections,
    networkStats,
    networkScanning,
    networkError,
    scanNetwork,
    mlIdsRunning,
    mlIdsResult,
    mlIdsError,
    runMlIds,
  } = useStore();

  const [search, setSearch] = useState('');
  const [filter, setFilter] = useState<'all' | 'threats'>('all');
  const [expandedRows, setExpandedRows] = useState<Set<number>>(new Set());

  const filtered = useMemo(() => {
    return networkConnections.filter((connection) => {
      if (filter === 'threats' && !connection.is_threat) return false;
      if (!search) return true;
      const q = search.toLowerCase();
      return (
        connection.protocol.toLowerCase().includes(q) ||
        connection.local_address.toLowerCase().includes(q) ||
        connection.remote_address.toLowerCase().includes(q) ||
        connection.state.toLowerCase().includes(q) ||
        connection.process_name?.toLowerCase().includes(q) ||
        String(connection.pid).includes(q)
      );
    });
  }, [filter, search, networkConnections]);

  const threatCount = networkConnections.filter((c) => c.is_threat).length;

  const toggleRow = (index: number) => {
    setExpandedRows((prev) => {
      const next = new Set(prev);
      if (next.has(index)) {
        next.delete(index);
      } else {
        next.add(index);
      }
      return next;
    });
  };

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', padding: 32, gap: 24 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <div style={{ fontFamily: 'var(--font-hud)', fontSize: 22, fontWeight: 700, color: 'var(--text-bright)', letterSpacing: '0.05em' }}>
            NETWORK MONITOR
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-dim)', marginTop: 4 }}>
            Live connection telemetry · process mapping · suspicious hosts · listener detection
          </div>
        </div>
        <div style={{ display: 'flex', gap: 10 }}>
          <button
            onClick={() => runMlIds()}
            disabled={mlIdsRunning}
            style={{
              display: 'flex', alignItems: 'center', gap: 8,
              padding: '10px 20px',
              background: 'rgba(139, 92, 246, 0.08)',
              border: '1px solid rgba(139, 92, 246, 0.35)',
              borderRadius: 6,
              color: '#a78bfa',
              fontFamily: 'var(--font-hud)',
              fontSize: 11,
              letterSpacing: '0.1em',
              cursor: mlIdsRunning ? 'not-allowed' : 'pointer',
              opacity: mlIdsRunning ? 0.6 : 1,
            }}
          >
            <BrainCircuit size={14} style={{ animation: mlIdsRunning ? 'spin 1s linear infinite' : 'none' }} />
            {mlIdsRunning ? 'ANALYZING...' : 'APPLY ML MODEL'}
          </button>
          <button
            onClick={() => scanNetwork()}
            disabled={networkScanning}
            style={{
              display: 'flex', alignItems: 'center', gap: 8,
              padding: '10px 20px',
              background: 'var(--green-glow)',
              border: '1px solid var(--border-md)',
              borderRadius: 6,
              color: 'var(--green)',
              fontFamily: 'var(--font-hud)',
              fontSize: 11,
              letterSpacing: '0.1em',
              cursor: networkScanning ? 'not-allowed' : 'pointer',
              opacity: networkScanning ? 0.6 : 1,
            }}
          >
            <RefreshCw size={14} style={{ animation: networkScanning ? 'spin 1s linear infinite' : 'none' }} />
            {networkScanning ? 'REFRESHING...' : 'REFRESH'}
          </button>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 12 }}>
        <StatCard label="TOTAL CONNECTIONS" value={networkStats?.total_connections ?? '—'} color="var(--cyan)" sub="Live endpoints" />
        <StatCard label="SUSPICIOUS" value={networkStats?.suspicious_connections ?? '—'} color="var(--amber)" sub="Potentially risky" />
        <StatCard label="MALICIOUS" value={networkStats?.malicious_connections ?? '—'} color="var(--red)" sub="High-risk traffic" />
        <StatCard label="LISTENERS" value={networkStats?.local_listeners ?? '—'} color="var(--green)" sub="Open services" />
        <StatCard label="ESTABLISHED" value={networkStats?.established_connections ?? '—'} color="var(--text-dim)" sub="Active flows" />
      </div>

      {/* ML IDS error */}
      {mlIdsError && (
        <div style={{ padding: '12px 16px', background: 'rgba(255,51,85,0.08)', border: '1px solid rgba(255,51,85,0.3)', borderRadius: 8, color: 'var(--red)', fontFamily: 'var(--font-mono)', fontSize: 11, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span>ML IDS: {mlIdsError}</span>
          <button onClick={() => useStore.setState({ mlIdsError: null })} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--red)' }}>
            <X size={12} />
          </button>
        </div>
      )}

      {/* ML IDS results panel */}
      {mlIdsResult && mlIdsResult.success && (
        <MlResultsPanel
          flows={mlIdsResult.flows}
          summary={mlIdsResult.summary}
          onClose={() => useStore.setState({ mlIdsResult: null })}
        />
      )}

      <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '12px 16px', background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8 }}>
        <div style={{ display: 'flex', gap: 4 }}>
          {(['all', 'threats'] as const).map((option) => (
            <button
              key={option}
              onClick={() => setFilter(option)}
              style={{
                padding: '6px 12px',
                borderRadius: 6,
                border: `1px solid ${filter === option ? 'var(--border-md)' : 'transparent'}`,
                background: filter === option ? 'var(--green-glow)' : 'transparent',
                color: filter === option ? 'var(--green)' : 'var(--text-dim)',
                fontFamily: 'var(--font-hud)',
                fontSize: 10,
                cursor: 'pointer',
              }}
            >
              {option === 'all' ? `ALL (${networkConnections.length})` : `THREATS (${threatCount})`}
            </button>
          ))}
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginLeft: 'auto', width: 360, background: 'var(--base)', border: '1px solid var(--border)', borderRadius: 6, padding: '6px 10px' }}>
          <Search size={14} color="var(--text-dim)" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search protocol, host, process..."
            style={{
              background: 'transparent', border: 'none', outline: 'none',
              color: 'var(--text)', fontFamily: 'var(--font-mono)', fontSize: 11,
              width: '100%',
            }}
          />
        </div>
      </div>

      {networkError && (
        <div style={{ padding: '12px 16px', background: 'rgba(255,51,85,0.08)', border: '1px solid rgba(255,51,85,0.3)', borderRadius: 8, color: 'var(--red)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>
          {networkError}
        </div>
      )}

      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, overflow: 'hidden' }}>
        <div style={{ display: 'grid', gridTemplateColumns: '90px 1.4fr 1.4fr 110px 100px 100px 100px', gap: 12, padding: '10px 16px', borderBottom: '1px solid var(--border)', background: 'var(--base)' }}>
          {['PROTO', 'LOCAL', 'REMOTE', 'STATE', 'PID', 'PROCESS', 'THREAT'].map((h) => (
            <span key={h} style={{ fontFamily: 'var(--font-hud)', fontSize: 9, color: 'var(--text-dim)', letterSpacing: '0.1em' }}>{h}</span>
          ))}
        </div>
        <div style={{ flex: 1, overflowY: 'auto' }}>
          {networkScanning ? (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%', gap: 12 }}>
              <RefreshCw size={28} color="var(--green)" style={{ animation: 'spin 1s linear infinite' }} />
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--green)' }}>Refreshing network connections...</div>
            </div>
          ) : filtered.length === 0 ? (
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', opacity: 0.6 }}>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-dim)' }}>
                {networkConnections.length === 0 ? 'Refresh to discover network connections' : 'No network connections match filter'}
              </div>
            </div>
          ) : (
            filtered.map((connection, index) => {
              const expanded = expandedRows.has(index);
              const color = connection.threat_level === 'Malicious' ? 'var(--red)' : connection.threat_level === 'Suspicious' ? 'var(--amber)' : 'var(--text-dim)';

              return (
                <div key={`${connection.protocol}-${connection.local_address}-${index}`}>
                  <div
                    onClick={() => toggleRow(index)}
                    style={{
                      display: 'grid',
                      gridTemplateColumns: '90px 1.4fr 1.4fr 110px 100px 100px 100px 24px',
                      gap: 12,
                      alignItems: 'center',
                      padding: '12px 16px',
                      borderBottom: '1px solid var(--border)',
                      background: connection.is_threat ? `${color}0f` : 'transparent',
                      cursor: 'pointer',
                    }}
                  >
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color }}>{connection.protocol.toUpperCase()}</span>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text)' }}>{connection.local_address}</span>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: connection.is_threat ? color : 'var(--text)' }}>{connection.remote_address}</span>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)' }}>{connection.state}</span>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text)' }}>{connection.pid ?? '-'}</span>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text)' }}>{connection.process_name ?? '-'}</span>
                    <span style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, fontFamily: 'var(--font-mono)', fontSize: 10, color }}>{connection.threat_level}</span>
                    <span style={{ justifySelf: 'end', color: 'var(--text-dim)' }}>
                      {expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                    </span>
                  </div>
                  {expanded && (
                    <div style={{ padding: '0 16px 16px 106px', display: 'flex', flexDirection: 'column', gap: 10, background: 'var(--surface)' }}>
                      {connection.detection_signals.length > 0 ? (
                        <div style={{ display: 'grid', gap: 8 }}>
                          {connection.detection_signals.map((signal, signalIndex) => (
                            <div key={signalIndex} style={{ display: 'flex', gap: 10, alignItems: 'center', padding: '10px 12px', background: 'var(--base)', borderRadius: 8, border: '1px solid var(--border)' }}>
                              <span style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', width: 24, height: 24, borderRadius: '50%', background: 'var(--border)', color: 'var(--text-dim)' }}>
                                <Link size={14} />
                              </span>
                              <div style={{ flex: 1 }}>
                                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text)' }}>{signal.description}</div>
                                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)', marginTop: 3 }}>Source: {signal.source.toUpperCase()} · Score: {signal.score}</div>
                              </div>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)' }}>
                          No detection signals for this connection.
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
}

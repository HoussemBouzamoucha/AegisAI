import { useMemo, useState } from 'react';
import { useStore } from '../store';
import { RefreshCw, Search, ChevronDown, ChevronRight, BrainCircuit, ShieldAlert, ShieldCheck, AlertTriangle, X, Info, Cpu, Globe } from 'lucide-react';
import type { MlFlowResult, MlIdsSummary } from '../types';

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

function VerdictIcon({ prediction }: { prediction: MlFlowResult['prediction'] }) {
  if (prediction === 'Malicious')  return <ShieldAlert   size={11} color="var(--red)"   />;
  if (prediction === 'Suspicious') return <AlertTriangle size={11} color="var(--amber)" />;
  return <ShieldCheck size={11} color="var(--green)" />;
}

function verdictColor(prediction: MlFlowResult['prediction']) {
  if (prediction === 'Malicious')  return 'var(--red)';
  if (prediction === 'Suspicious') return 'var(--amber)';
  return 'var(--green)';
}

function verdictBg(prediction: MlFlowResult['prediction']) {
  if (prediction === 'Malicious')  return 'rgba(255,51,85,0.05)';
  if (prediction === 'Suspicious') return 'rgba(245,158,11,0.05)';
  return 'transparent';
}

type FlowFilter = 'malicious' | 'suspicious' | 'all';

function MlResultsPanel({ flows, summary, onClose }: {
  flows: MlFlowResult[];
  summary: MlIdsSummary;
  onClose: () => void;
}) {
  const maliciousFlows  = flows.filter(f => f.prediction === 'Malicious');
  const suspiciousFlows = flows.filter(f => f.prediction === 'Suspicious');

  const [tab, setTab]               = useState<FlowFilter>('malicious');
  const [expandedFlows, setExpanded] = useState<Set<number>>(new Set());

  const displayed = tab === 'malicious' ? maliciousFlows
                  : tab === 'suspicious' ? suspiciousFlows
                  : flows;

  const toggleFlow = (i: number) =>
    setExpanded(prev => { const n = new Set(prev); n.has(i) ? n.delete(i) : n.add(i); return n; });

  const COLS = '1.1fr 1.1fr 65px 65px 55px 115px 72px 20px';

  return (
    <div style={{
      background: 'var(--surface)',
      border: '1px solid rgba(139, 92, 246, 0.3)',
      borderRadius: 8,
      overflow: 'hidden',
    }}>
      {/* ── Header ─────────────────────────────────────────────────────── */}
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
        <div style={{ display: 'flex', alignItems: 'center', gap: 20 }}>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)' }}>
            Flows: <span style={{ color: 'var(--text)' }}>{summary.total_flows}</span>
          </span>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)' }}>
            Clean: <span style={{ color: 'var(--green)' }}>{summary.clean_flows}</span>
          </span>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)' }}>
            Suspicious: <span style={{ color: 'var(--amber)' }}>{summary.suspicious_flows}</span>
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
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-dim)', display: 'flex' }}>
            <X size={14} />
          </button>
        </div>
      </div>

      {/* ── Filter tabs ─────────────────────────────────────────────────── */}
      <div style={{ padding: '8px 16px', borderBottom: '1px solid var(--border)', display: 'flex', gap: 6 }}>
        {([
          { key: 'malicious',  label: `MALICIOUS (${maliciousFlows.length})`,  activeColor: 'var(--red)',   activeBg: 'rgba(255,51,85,0.08)'   },
          { key: 'suspicious', label: `SUSPICIOUS (${suspiciousFlows.length})`, activeColor: 'var(--amber)', activeBg: 'rgba(245,158,11,0.08)'  },
          { key: 'all',        label: `ALL FLOWS (${flows.length})`,            activeColor: 'var(--green)', activeBg: 'var(--green-glow)'      },
        ] as const).map(({ key, label, activeColor, activeBg }) => (
          <button key={key} onClick={() => setTab(key)} style={{
            padding: '4px 10px', borderRadius: 4, fontSize: 10, fontFamily: 'var(--font-hud)',
            border:     `1px solid ${tab === key ? 'var(--border-md)' : 'transparent'}`,
            background: tab === key ? activeBg : 'transparent',
            color:      tab === key ? activeColor : 'var(--text-dim)',
            cursor: 'pointer',
          }}>
            {label}
          </button>
        ))}
        <span style={{ marginLeft: 'auto', fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)', alignSelf: 'center' }}>
          Click a row to inspect reasons
        </span>
      </div>

      {/* ── Table ───────────────────────────────────────────────────────── */}
      {displayed.length === 0 ? (
        <div style={{ padding: '20px', display: 'flex', alignItems: 'center', gap: 10, color: 'var(--green)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>
          <ShieldCheck size={16} />
          {tab === 'malicious' ? 'No malicious flows detected.' : tab === 'suspicious' ? 'No suspicious flows detected.' : 'No flows to display.'}
        </div>
      ) : (
        <div style={{ maxHeight: 320, overflowY: 'auto' }}>
          {/* Column headers */}
          <div style={{
            display: 'grid', gridTemplateColumns: COLS,
            gap: 8, padding: '6px 16px',
            fontFamily: 'var(--font-hud)', fontSize: 9, color: 'var(--text-dim)', letterSpacing: '0.1em',
            background: 'var(--base)', borderBottom: '1px solid var(--border)',
            position: 'sticky', top: 0,
          }}>
            {['SRC IP', 'DST IP', 'SPORT', 'DPORT', 'PROTO', 'VERDICT', 'CONF', ''].map(h => (
              <span key={h}>{h}</span>
            ))}
          </div>

          {displayed.map((flow, i) => {
            const color    = verdictColor(flow.prediction);
            const expanded = expandedFlows.has(i);
            const pct      = (flow.probability * 100).toFixed(1);
            const flagged  = flow.prediction !== 'Clean';

            return (
              <div key={i} style={{ borderBottom: '1px solid var(--border)' }}>
                {/* Flow row */}
                <div
                  onClick={() => flagged && toggleFlow(i)}
                  style={{
                    display: 'grid', gridTemplateColumns: COLS,
                    gap: 8, padding: '8px 16px',
                    background: expanded ? `${verdictBg(flow.prediction).replace('0.05', '0.09')}` : verdictBg(flow.prediction),
                    alignItems: 'center',
                    cursor: flagged ? 'pointer' : 'default',
                  }}
                >
                  {/* SRC IP + hostname + IPv6 badge */}
                  <span style={{ display: 'flex', flexDirection: 'column', minWidth: 0, gap: 1 }}>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color, display: 'flex', alignItems: 'center', gap: 4, minWidth: 0 }}>
                      <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {flow.src_host && flow.src_host !== flow.srcip ? flow.src_host : flow.srcip}
                      </span>
                      {flow.is_ipv6 && (
                        <span style={{ flexShrink: 0, fontSize: 8, padding: '1px 4px', borderRadius: 3, background: 'rgba(139,92,246,0.15)', color: '#a78bfa', fontFamily: 'var(--font-hud)', letterSpacing: '0.05em' }}>
                          IPv6
                        </span>
                      )}
                    </span>
                    {flow.src_host && flow.src_host !== flow.srcip && (
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {flow.srcip}
                      </span>
                    )}
                  </span>
                  {/* DST IP + hostname */}
                  <span style={{ display: 'flex', flexDirection: 'column', minWidth: 0, gap: 1 }}>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {flow.dst_host && flow.dst_host !== flow.dstip ? flow.dst_host : flow.dstip}
                    </span>
                    {flow.dst_host && flow.dst_host !== flow.dstip && (
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {flow.dstip}
                      </span>
                    )}
                  </span>
                  {/* SRC port + service name */}
                  <span style={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)' }}>
                      {flow.src_service && flow.src_service !== String(flow.sport) ? flow.src_service : flow.sport}
                    </span>
                  </span>
                  {/* DST port + service name */}
                  <span style={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)' }}>
                      {flow.dst_service && flow.dst_service !== String(flow.dsport) ? flow.dst_service : flow.dsport}
                    </span>
                  </span>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)' }}>
                    {flow.proto.toUpperCase()}
                  </span>
                  <span style={{ display: 'flex', alignItems: 'center', gap: 5, fontFamily: 'var(--font-mono)', fontSize: 10, color }}>
                    <VerdictIcon prediction={flow.prediction} />
                    {flow.prediction.toUpperCase()}
                  </span>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color }}>{pct}%</span>
                  <span style={{ color: 'var(--text-dim)', display: 'flex', justifyContent: 'flex-end' }}>
                    {flagged && (expanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />)}
                  </span>
                </div>

                {/* Reasons panel */}
                {expanded && flagged && flow.reasons.length > 0 && (
                  <div style={{
                    padding: '10px 16px 12px 32px',
                    background: 'var(--base)',
                    borderTop: `1px solid ${color}22`,
                    display: 'flex', flexDirection: 'column', gap: 6,
                  }}>
                    <span style={{ fontFamily: 'var(--font-hud)', fontSize: 9, color: 'var(--text-dim)', letterSpacing: '0.1em', marginBottom: 2 }}>
                      DETECTION REASONS
                    </span>
                    {flow.reasons.map((reason, ri) => (
                      <div key={ri} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <Info size={10} color={color} style={{ flexShrink: 0 }} />
                        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text)' }}>{reason}</span>
                      </div>
                    ))}
                  </div>
                )}
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
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)', whiteSpace: 'nowrap' }}>
          Click flagged rows to see heuristic signals
        </span>
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
                    onClick={() => connection.is_threat && toggleRow(index)}
                    style={{
                      display: 'grid',
                      gridTemplateColumns: '90px 1.4fr 1.4fr 110px 100px 100px 100px 24px',
                      gap: 12,
                      alignItems: 'center',
                      padding: '12px 16px',
                      borderBottom: '1px solid var(--border)',
                      background: connection.is_threat ? `${color}0f` : 'transparent',
                      cursor: connection.is_threat ? 'pointer' : 'default',
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
                      {connection.is_threat && (expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />)}
                    </span>
                  </div>
                  {expanded && connection.is_threat && (
                    <div style={{
                      padding: '10px 16px 14px 106px',
                      background: 'var(--base)',
                      borderTop: `1px solid ${color}22`,
                      display: 'flex', flexDirection: 'column', gap: 7,
                    }}>
                      {/* Header row */}
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
                        <span style={{ fontFamily: 'var(--font-hud)', fontSize: 9, color: 'var(--text-dim)', letterSpacing: '0.1em' }}>
                          HEURISTIC SIGNALS
                        </span>
                        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)' }}>
                          total score: <span style={{ color }}>{connection.threat_score}</span>
                        </span>
                      </div>

                      {connection.detection_signals.length > 0 ? connection.detection_signals.map((signal, si) => {
                        const srcIcon = signal.source === 'process'
                          ? <Cpu size={10} color={color} style={{ flexShrink: 0 }} />
                          : <Globe size={10} color={color} style={{ flexShrink: 0 }} />;
                        return (
                          <div key={si} style={{ display: 'flex', alignItems: 'flex-start', gap: 8 }}>
                            <span style={{ marginTop: 1 }}>{srcIcon}</span>
                            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text)', flex: 1 }}>
                              {signal.description}
                            </span>
                            <span style={{
                              flexShrink: 0,
                              fontFamily: 'var(--font-hud)', fontSize: 9,
                              padding: '1px 6px', borderRadius: 3,
                              background: `${color}18`, color,
                              letterSpacing: '0.05em',
                            }}>
                              +{signal.score}
                            </span>
                          </div>
                        );
                      }) : (
                        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)' }}>
                          No heuristic signals recorded.
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

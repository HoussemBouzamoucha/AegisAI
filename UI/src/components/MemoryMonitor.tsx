import { useMemo, useState } from 'react';
import { useStore } from '../store';
import { RefreshCw, Search, ChevronDown, ChevronRight, Link } from 'lucide-react';
import type { MemoryRegion } from '../types';

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

function formatSize(bytes: number): string {
  if (bytes >= 1_000_000_000) return `${(bytes / 1_000_000_000).toFixed(2)} GB`;
  if (bytes >= 1_000_000) return `${(bytes / 1_000_000).toFixed(2)} MB`;
  if (bytes >= 1_000) return `${(bytes / 1_000).toFixed(2)} KB`;
  return `${bytes} B`;
}

function formatAddress(address: number): string {
  return `0x${address.toString(16).toUpperCase().padStart(8, '0')}`;
}

export default function MemoryMonitor() {
  const {
    memoryRegions,
    memoryStats,
    memoryScanning,
    memoryError,
    scanMemory,
  } = useStore();

  const [search, setSearch] = useState('');
  const [filter, setFilter] = useState<'all' | 'threats'>('all');
  const [expandedRows, setExpandedRows] = useState<Set<number>>(new Set());

  const filtered = useMemo<MemoryRegion[]>(() => {
    return memoryRegions.filter((region: MemoryRegion) => {
      if (filter === 'threats' && !region.is_threat) return false;
      if (!search) return true;
      const q = search.toLowerCase();
      return (
        region.process_name.toLowerCase().includes(q) ||
        region.protection.toLowerCase().includes(q) ||
        region.command_line?.toLowerCase().includes(q) ||
        formatAddress(region.region_start).toLowerCase().includes(q) ||
        String(region.pid).includes(q)
      );
    });
  }, [filter, search, memoryRegions]);

  const threatCount = memoryRegions.filter((region) => region.is_threat).length;

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
            MEMORY SCANNER
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-dim)', marginTop: 4 }}>
            Live region analysis · executable page detection · content fingerprinting
          </div>
        </div>
        <button
          onClick={() => scanMemory()}
          disabled={memoryScanning}
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
            cursor: memoryScanning ? 'not-allowed' : 'pointer',
            opacity: memoryScanning ? 0.6 : 1,
          }}
        >
          <RefreshCw size={14} style={{ animation: memoryScanning ? 'spin 1s linear infinite' : 'none' }} />
          {memoryScanning ? 'SCANNING...' : 'SCAN MEMORY'}
        </button>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 12 }}>
        <StatCard label="REGIONS" value={memoryStats?.total_regions ?? '—'} color="var(--cyan)" sub="Memory blocks analyzed" />
        <StatCard label="PROCESSES" value={memoryStats?.scanned_processes ?? '—'} color="var(--green)" sub="Processes scanned" />
        <StatCard label="SUSPICIOUS" value={memoryStats?.suspicious_regions ?? '—'} color="var(--amber)" sub="Risky regions" />
        <StatCard label="MALICIOUS" value={memoryStats?.malicious_regions ?? '—'} color="var(--red)" sub="High risk" />
        <StatCard label="MEMORY" value={memoryStats ? formatSize(memoryStats.total_bytes_scanned) : '—'} color="var(--text-dim)" sub="Bytes examined" />
      </div>

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
              {option === 'all' ? `ALL (${memoryRegions.length})` : `THREATS (${threatCount})`}
            </button>
          ))}
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginLeft: 'auto', width: 360, background: 'var(--base)', border: '1px solid var(--border)', borderRadius: 6, padding: '6px 10px' }}>
          <Search size={14} color="var(--text-dim)" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search process, protection, address..."
            style={{
              background: 'transparent', border: 'none', outline: 'none',
              color: 'var(--text)', fontFamily: 'var(--font-mono)', fontSize: 11,
              width: '100%',
            }}
          />
        </div>
      </div>

      {memoryError && (
        <div style={{ padding: '12px 16px', background: 'rgba(255,51,85,0.08)', border: '1px solid rgba(255,51,85,0.3)', borderRadius: 8, color: 'var(--red)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>
          {memoryError}
        </div>
      )}

      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, overflow: 'hidden' }}>
        <div style={{ display: 'grid', gridTemplateColumns: '60px 240px 160px 120px 120px 90px 90px 24px', gap: 12, padding: '10px 16px', borderBottom: '1px solid var(--border)', background: 'var(--base)' }}>
          {['PID', 'PROCESS', 'START', 'SIZE', 'PROTECTION', 'FLAGS', 'THREAT', ''].map((h) => (
            <span key={h} style={{ fontFamily: 'var(--font-hud)', fontSize: 9, color: 'var(--text-dim)', letterSpacing: '0.1em' }}>{h}</span>
          ))}
        </div>
        <div style={{ flex: 1, overflowY: 'auto' }}>
          {memoryScanning ? (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%', gap: 12 }}>
              <RefreshCw size={28} color="var(--green)" style={{ animation: 'spin 1s linear infinite' }} />
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--green)' }}>Scanning memory regions...</div>
            </div>
          ) : filtered.length === 0 ? (
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', opacity: 0.6 }}>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-dim)' }}>
                {memoryRegions.length === 0 ? 'Run a memory scan to populate regions.' : 'No memory regions match the filter.'}
              </div>
            </div>
          ) : (
            filtered.map((region: MemoryRegion, index: number) => {
              const expanded = expandedRows.has(index);
              const color = region.threat_level === 'Malicious' ? 'var(--red)' : region.threat_level === 'Suspicious' ? 'var(--amber)' : 'var(--text-dim)';

              return (
                <div key={`${region.pid}-${region.region_start}-${index}`}>
                  <div
                    onClick={() => toggleRow(index)}
                    style={{
                      display: 'grid',
                      gridTemplateColumns: '60px 240px 160px 120px 120px 90px 90px 24px',
                      gap: 12,
                      alignItems: 'center',
                      padding: '12px 16px',
                      borderBottom: '1px solid var(--border)',
                      background: region.is_threat ? `${color}0f` : 'transparent',
                      cursor: 'pointer',
                    }}
                  >
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text)' }}>{region.pid}</span>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text)' }}>{region.process_name}</span>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)' }}>{formatAddress(region.region_start)}</span>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text)' }}>{formatSize(region.region_size)}</span>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text)' }}>{region.protection}</span>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: region.is_executable ? 'var(--green)' : 'var(--text-dim)' }}>
                      {region.is_executable ? 'EXEC' : region.is_writable ? 'WR' : 'RW'}
                    </span>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color }}>{region.threat_level}</span>
                    <span style={{ justifySelf: 'end', color: 'var(--text-dim)' }}>
                      {expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                    </span>
                  </div>
                  {expanded && (
                    <div style={{ padding: '0 16px 16px 76px', display: 'flex', flexDirection: 'column', gap: 10, background: 'var(--surface)' }}>
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)' }}>
                          <div><strong>COMMAND LINE</strong></div>
                          <div style={{ color: 'var(--text)' }}>{region.command_line ?? 'None'}</div>
                        </div>
                        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)' }}>
                          <div><strong>PATH</strong></div>
                          <div style={{ color: 'var(--text)' }}>{region.process_path ?? 'Unknown'}</div>
                        </div>
                      </div>
                      {region.content_sample ? (
                        <div style={{ background: 'var(--base)', border: '1px solid var(--border)', borderRadius: 6, padding: 12, fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text)' }}>
                          <div style={{ marginBottom: 6, color: 'var(--text-dim)' }}>CONTENT SNAPSHOT</div>
                          <div>{region.content_sample}</div>
                        </div>
                      ) : null}
                      {region.detection_signals.length > 0 ? (
                        <div style={{ display: 'grid', gap: 8 }}>
                          {region.detection_signals.map((signal: any, signalIndex: number) => (
                            <div key={signalIndex} style={{ display: 'flex', gap: 10, alignItems: 'center', padding: '10px 12px', background: 'var(--base)', borderRadius: 8, border: '1px solid var(--border)' }}>
                              <span style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', width: 24, height: 24, borderRadius: '50%', background: 'var(--border)', color: 'var(--text-dim)' }}>
                                <Link size={14} />
                              </span>
                              <div style={{ flex: 1 }}>
                                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text)' }}>{signal.description}</div>
                                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)', marginTop: 3 }}>
                                  Source: {signal.source.toUpperCase()} · Score: {signal.score}
                                </div>
                              </div>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)' }}>
                          No detection signals were generated for this region.
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

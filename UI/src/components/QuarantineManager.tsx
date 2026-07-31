// File: UI/src/components/QuarantineManager.tsx
//
// Quarantine Manager — view and manage files moved to %PROGRAMDATA%\AegisAI\quarantine\.
//
// Panels:
//   Top    — network isolation status banner + restore_network button (emergency rollback)
//   Middle — quarantine file list with restore / permanent-delete per entry
//   Bottom — export incident report section

import { useState, useEffect, useCallback } from 'react';
import {
  Archive, RefreshCw, RotateCcw, Trash2, FileText, Shield,
  ShieldOff, AlertTriangle, CheckCircle, WifiOff, Wifi,
} from 'lucide-react';
import { invoke } from '@tauri-apps/api/core';
import { useStore } from '../store';
import type { QuarantineEntry } from '../types';

// ─── Helpers ─────────────────────────────────────────────────────────────────

function fmtTimestamp(unix: number): string {
  if (!unix) return '—';
  return new Date(unix * 1000).toLocaleString();
}

function fmtPath(p: string): string {
  // Show last 2 path segments so long paths don't overflow
  const parts = p.replace(/\\/g, '/').split('/').filter(Boolean);
  if (parts.length <= 2) return p;
  return '…\\' + parts.slice(-2).join('\\');
}

// ─── Network Isolation Banner ────────────────────────────────────────────────

function NetworkIsolationBanner() {
  const {
    networkIsolated, networkIsolating, networkIsolateError,
    restoreNetworkAction,
  } = useStore();

  if (!networkIsolated && !networkIsolateError) return null;

  return (
    <div style={{
      padding: '12px 18px',
      background: networkIsolated
        ? 'rgba(255,51,85,0.08)'
        : 'rgba(255,179,0,0.06)',
      border: `1px solid ${networkIsolated ? 'rgba(255,51,85,0.35)' : 'rgba(255,179,0,0.3)'}`,
      borderRadius: 8,
      display: 'flex', alignItems: 'center', gap: 14,
      flexShrink: 0,
    }}>
      <WifiOff size={18} color={networkIsolated ? '#ff3355' : '#ffb300'} />
      <div style={{ flex: 1 }}>
        <div style={{
          fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 700,
          color: networkIsolated ? '#ff3355' : '#ffb300',
          letterSpacing: '0.06em',
        }}>
          {networkIsolated ? 'NETWORK ISOLATED' : 'ISOLATION ERROR'}
        </div>
        {networkIsolated && (
          <div style={{
            fontFamily: 'var(--font-mono)', fontSize: 9,
            color: 'var(--text-dim)', marginTop: 3,
          }}>
            All network adapters are disabled. Re-enable only after the threat is contained.
          </div>
        )}
        {networkIsolateError && (
          <div style={{
            fontFamily: 'var(--font-mono)', fontSize: 9, color: '#ffb300', marginTop: 3,
          }}>
            {networkIsolateError}
          </div>
        )}
      </div>
      {networkIsolated && (
        <button
          onClick={restoreNetworkAction}
          disabled={networkIsolating}
          style={{
            display: 'flex', alignItems: 'center', gap: 6,
            padding: '7px 14px',
            background: 'rgba(0,255,136,0.1)',
            border: '1px solid rgba(0,255,136,0.4)',
            borderRadius: 5,
            color: '#00ff88',
            fontFamily: 'var(--font-mono)', fontSize: 10, fontWeight: 700,
            cursor: networkIsolating ? 'not-allowed' : 'pointer',
            opacity: networkIsolating ? 0.5 : 1,
            flexShrink: 0,
          }}>
          <Wifi size={12} />
          {networkIsolating ? 'Restoring…' : 'Restore Network'}
        </button>
      )}
    </div>
  );
}

// ─── Single quarantine entry row ─────────────────────────────────────────────

type EntryOp = 'idle' | 'restoring' | 'deleting' | 'restored' | 'deleted' | 'error';

function QuarantineRow({
  entry,
  onRefresh,
}: {
  entry:     QuarantineEntry;
  onRefresh: () => void;
}) {
  const [op,     setOp]     = useState<EntryOp>('idle');
  const [errMsg, setErrMsg] = useState<string | null>(null);
  const [showDel, setShowDel] = useState(false);

  const handleRestore = useCallback(async () => {
    setOp('restoring'); setErrMsg(null);
    try {
      await invoke('restore_quarantine_file', { sha256: entry.sha256 });
      setOp('restored');
      setTimeout(onRefresh, 800);
    } catch (e: any) {
      setErrMsg(String(e)); setOp('error');
    }
  }, [entry.sha256, onRefresh]);

  const handleDelete = useCallback(async () => {
    setOp('deleting'); setErrMsg(null); setShowDel(false);
    try {
      await invoke('delete_quarantine_file', { sha256: entry.sha256 });
      setOp('deleted');
      setTimeout(onRefresh, 600);
    } catch (e: any) {
      setErrMsg(String(e)); setOp('error');
    }
  }, [entry.sha256, onRefresh]);

  const busy = op === 'restoring' || op === 'deleting';
  const done = op === 'restored'  || op === 'deleted';

  return (
    <div style={{
      padding: '12px 16px',
      background: done   ? 'rgba(0,255,136,0.04)'
                : op === 'error' ? 'rgba(255,51,85,0.05)'
                : 'var(--elevated)',
      border: `1px solid ${
        done         ? 'rgba(0,255,136,0.2)'
        : op === 'error' ? 'rgba(255,51,85,0.2)'
        : 'var(--border)'
      }`,
      borderRadius: 7,
      display: 'flex', flexDirection: 'column', gap: 6,
      opacity: done ? 0.55 : 1,
      transition: 'opacity 0.4s',
    }}>

      {/* Top row: filename + status badges */}
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
        <Archive size={14} color="#ffb300" style={{ flexShrink: 0, marginTop: 1 }} />
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{
            fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 700,
            color: 'var(--text)', wordBreak: 'break-all',
          }}>
            {entry.original_path.replace(/\\/g, '/').split('/').pop() ?? entry.sha256}
          </div>
          <div style={{
            fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)',
            marginTop: 2, wordBreak: 'break-all',
          }}
            title={entry.original_path}
          >
            {fmtPath(entry.original_path)}
          </div>
        </div>
        {!entry.quarantine_file_exists && (
          <span style={{
            fontFamily: 'var(--font-mono)', fontSize: 8, color: '#ff3355',
            background: 'rgba(255,51,85,0.1)', padding: '2px 6px', borderRadius: 3,
            flexShrink: 0,
          }}>
            FILE MISSING
          </span>
        )}
      </div>

      {/* Meta row */}
      <div style={{
        display: 'flex', gap: 16, flexWrap: 'wrap',
        fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)',
      }}>
        <span>quarantined {fmtTimestamp(entry.quarantined_at)}</span>
        <span title={entry.sha256}>SHA-256 {entry.sha256.slice(0, 12)}…</span>
        <span style={{ color: '#ffb300' }}>{entry.reason}</span>
      </div>

      {/* Error message */}
      {op === 'error' && errMsg && (
        <div style={{
          fontFamily: 'var(--font-mono)', fontSize: 9, color: '#ff3355',
          background: 'rgba(255,51,85,0.07)', padding: '4px 8px',
          borderRadius: 3, lineHeight: 1.5,
        }}>
          {errMsg}
        </div>
      )}

      {/* Status label when resolved */}
      {done && (
        <div style={{
          fontFamily: 'var(--font-mono)', fontSize: 9,
          color: '#00ff88', display: 'flex', alignItems: 'center', gap: 5,
        }}>
          <CheckCircle size={11} />
          {op === 'restored' ? 'File restored to original location.' : 'File permanently deleted.'}
        </div>
      )}

      {/* Delete confirmation */}
      {showDel && (
        <div style={{
          padding: '8px 10px',
          background: 'rgba(255,51,85,0.08)',
          border: '1px solid rgba(255,51,85,0.3)',
          borderRadius: 5,
          fontFamily: 'var(--font-mono)', fontSize: 10,
          display: 'flex', flexDirection: 'column', gap: 8,
        }}>
          <div style={{ color: '#ff3355', fontWeight: 700 }}>
            Permanently delete this file? This cannot be undone.
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button onClick={handleDelete} style={{
              padding: '4px 12px',
              background: '#ff3355', color: '#fff',
              border: 'none', borderRadius: 4,
              fontFamily: 'var(--font-mono)', fontSize: 10, fontWeight: 700,
              cursor: 'pointer',
            }}>
              Delete permanently
            </button>
            <button onClick={() => setShowDel(false)} style={{
              padding: '4px 12px',
              background: 'transparent', color: 'var(--text-dim)',
              border: '1px solid var(--border)', borderRadius: 4,
              fontFamily: 'var(--font-mono)', fontSize: 10, cursor: 'pointer',
            }}>
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* Action buttons */}
      {!done && !showDel && (
        <div style={{ display: 'flex', gap: 8, marginTop: 2 }}>
          <button
            onClick={handleRestore}
            disabled={busy || !entry.quarantine_file_exists}
            title={!entry.quarantine_file_exists ? 'Quarantined file is missing on disk' : undefined}
            style={{
              display: 'flex', alignItems: 'center', gap: 5,
              padding: '5px 12px',
              background: 'rgba(0,255,136,0.08)',
              border: '1px solid rgba(0,255,136,0.3)',
              borderRadius: 4, color: '#00ff88',
              fontFamily: 'var(--font-mono)', fontSize: 10, fontWeight: 600,
              cursor: busy || !entry.quarantine_file_exists ? 'not-allowed' : 'pointer',
              opacity: busy || !entry.quarantine_file_exists ? 0.4 : 1,
            }}>
            <RotateCcw size={10} />
            {op === 'restoring' ? 'Restoring…' : 'Restore'}
          </button>
          <button
            onClick={() => setShowDel(true)}
            disabled={busy}
            style={{
              display: 'flex', alignItems: 'center', gap: 5,
              padding: '5px 12px',
              background: 'transparent',
              border: '1px solid rgba(255,51,85,0.3)',
              borderRadius: 4, color: '#ff3355',
              fontFamily: 'var(--font-mono)', fontSize: 10,
              cursor: busy ? 'not-allowed' : 'pointer',
              opacity: busy ? 0.4 : 1,
            }}>
            <Trash2 size={10} />
            Delete
          </button>
        </div>
      )}
    </div>
  );
}

// ─── Export incident report section ──────────────────────────────────────────

function ExportReportSection() {
  const { correlateResult, actionsTaken } = useStore();
  const [exporting, setExporting]         = useState(false);
  const [reportPath, setReportPath]       = useState<string | null>(null);
  const [exportError, setExportError]     = useState<string | null>(null);

  const handleExport = useCallback(async () => {
    if (!correlateResult) return;
    setExporting(true); setReportPath(null); setExportError(null);
    try {
      const res = await invoke<{ success: boolean; report_path: string }>(
        'export_incident_report',
        {
          correlateResult,
          actionsTaken:  actionsTaken.map(a => ({ ...a })),
          outputPath:    undefined,
        },
      );
      setReportPath(res.report_path);
    } catch (e: any) {
      setExportError(String(e));
    } finally {
      setExporting(false);
    }
  }, [correlateResult, actionsTaken]);

  return (
    <div style={{
      padding: '16px 18px',
      border: '1px solid var(--border)',
      borderRadius: 8,
      background: 'var(--elevated)',
      display: 'flex', flexDirection: 'column', gap: 10,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 9 }}>
        <FileText size={14} color="#818cf8" />
        <span style={{
          fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 700,
          color: 'var(--text)', letterSpacing: '0.06em',
        }}>
          INCIDENT REPORT
        </span>
      </div>

      <div style={{
        fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)',
        lineHeight: 1.6,
      }}>
        Exports a structured JSON report containing the graph snapshot, all detected
        attack chains, the critical path, and every action taken during this investigation.
        Saved to <code style={{ color: '#818cf8' }}>%USERPROFILE%\Documents\AegisAI\</code>.
      </div>

      {!correlateResult && (
        <div style={{
          fontFamily: 'var(--font-mono)', fontSize: 9, color: '#ffb300',
          background: 'rgba(255,179,0,0.07)', padding: '6px 10px', borderRadius: 4,
        }}>
          Run a correlation scan first to populate the graph data.
        </div>
      )}

      {actionsTaken.length > 0 && (
        <div style={{
          fontFamily: 'var(--font-mono)', fontSize: 9,
          color: 'var(--text-dim)',
        }}>
          {actionsTaken.length} action{actionsTaken.length !== 1 ? 's' : ''} recorded in this investigation.
        </div>
      )}

      {reportPath && (
        <div style={{
          fontFamily: 'var(--font-mono)', fontSize: 9, color: '#00ff88',
          background: 'rgba(0,255,136,0.06)', padding: '6px 10px', borderRadius: 4,
          display: 'flex', alignItems: 'center', gap: 6,
          wordBreak: 'break-all',
        }}>
          <CheckCircle size={11} />
          Saved to: {reportPath}
        </div>
      )}

      {exportError && (
        <div style={{
          fontFamily: 'var(--font-mono)', fontSize: 9, color: '#ff3355',
          background: 'rgba(255,51,85,0.07)', padding: '6px 10px', borderRadius: 4,
        }}>
          {exportError}
        </div>
      )}

      <button
        onClick={handleExport}
        disabled={exporting || !correlateResult}
        style={{
          display: 'flex', alignItems: 'center', gap: 7,
          padding: '8px 16px', alignSelf: 'flex-start',
          background: correlateResult ? 'rgba(129,140,248,0.1)' : 'var(--border)',
          border: `1px solid ${correlateResult ? 'rgba(129,140,248,0.4)' : 'transparent'}`,
          borderRadius: 5, color: correlateResult ? '#818cf8' : 'var(--text-dim)',
          fontFamily: 'var(--font-mono)', fontSize: 10, fontWeight: 700,
          cursor: exporting || !correlateResult ? 'not-allowed' : 'pointer',
          opacity: exporting || !correlateResult ? 0.5 : 1,
        }}>
        <FileText size={12} />
        {exporting ? 'Exporting…' : 'Export Incident Report'}
      </button>
    </div>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────

export default function QuarantineManager() {
  const [entries,  setEntries]  = useState<QuarantineEntry[]>([]);
  const [loading,  setLoading]  = useState(false);
  const [loadErr,  setLoadErr]  = useState<string | null>(null);

  const loadEntries = useCallback(async () => {
    setLoading(true); setLoadErr(null);
    try {
      const raw = await invoke<QuarantineEntry[]>('list_quarantine');
      setEntries(raw);
    } catch (e: any) {
      setLoadErr(String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  // Load on mount
  useEffect(() => { loadEntries(); }, [loadEntries]);

  return (
    <div style={{
      height: '100%', display: 'flex', flexDirection: 'column',
      fontFamily: 'var(--font-mono)',
      background: 'var(--void)',
    }}>

      {/* ── Header ─────────────────────────────────────────────────────────── */}
      <div style={{
        padding: '18px 24px 14px',
        borderBottom: '1px solid var(--border)',
        background: 'var(--base)',
        flexShrink: 0,
        display: 'flex', alignItems: 'center', gap: 12,
      }}>
        <Shield size={18} color="#ffb300" />
        <div style={{ flex: 1 }}>
          <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text)', letterSpacing: '0.08em' }}>
            QUARANTINE MANAGER
          </div>
          <div style={{ fontSize: 9, color: 'var(--text-dim)', marginTop: 2 }}>
            {entries.length} file{entries.length !== 1 ? 's' : ''} in quarantine
            &nbsp;·&nbsp;
            <code style={{ color: 'var(--text-dim)' }}>%PROGRAMDATA%\AegisAI\quarantine\</code>
          </div>
        </div>
        <button
          onClick={loadEntries}
          disabled={loading}
          style={{
            display: 'flex', alignItems: 'center', gap: 5,
            padding: '6px 12px',
            background: 'transparent', border: '1px solid var(--border)',
            borderRadius: 5, color: 'var(--text-dim)',
            fontSize: 10, cursor: loading ? 'wait' : 'pointer',
          }}>
          <RefreshCw size={11} style={{ animation: loading ? 'spin 1s linear infinite' : 'none' }} />
          Refresh
        </button>
      </div>

      {/* ── Body ───────────────────────────────────────────────────────────── */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '20px 24px', display: 'flex', flexDirection: 'column', gap: 18 }}>

        {/* Network isolation emergency banner */}
        <NetworkIsolationBanner />

        {/* Load error */}
        {loadErr && (
          <div style={{
            display: 'flex', alignItems: 'center', gap: 8,
            padding: '10px 14px',
            background: 'rgba(255,51,85,0.07)',
            border: '1px solid rgba(255,51,85,0.2)',
            borderRadius: 7,
            color: '#ff3355', fontSize: 10,
          }}>
            <AlertTriangle size={14} />
            {loadErr}
          </div>
        )}

        {/* Quarantine list */}
        <section>
          <div style={{
            fontSize: 9, letterSpacing: '0.12em', color: 'var(--text-dim)',
            marginBottom: 12,
          }}>
            QUARANTINED FILES
          </div>

          {loading && entries.length === 0 && (
            <div style={{ fontSize: 10, color: 'var(--text-dim)', padding: '20px 0' }}>
              Loading…
            </div>
          )}

          {!loading && entries.length === 0 && !loadErr && (
            <div style={{
              display: 'flex', flexDirection: 'column', alignItems: 'center',
              padding: '40px 0', gap: 10, color: 'var(--text-dim)',
            }}>
              <ShieldOff size={30} style={{ opacity: 0.3 }} />
              <span style={{ fontSize: 12 }}>No quarantined files.</span>
              <span style={{ fontSize: 9, textAlign: 'center', maxWidth: 300, lineHeight: 1.6 }}>
                Files quarantined via the Graph Verdict action panel will appear here.
                You can restore them or permanently delete them.
              </span>
            </div>
          )}

          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {entries.map(entry => (
              <QuarantineRow
                key={entry.sha256}
                entry={entry}
                onRefresh={loadEntries}
              />
            ))}
          </div>
        </section>

        {/* Export report */}
        <section>
          <div style={{
            fontSize: 9, letterSpacing: '0.12em', color: 'var(--text-dim)',
            marginBottom: 12,
          }}>
            INCIDENT REPORT
          </div>
          <ExportReportSection />
        </section>

        {/* Spacer */}
        <div style={{ height: 20 }} />
      </div>
    </div>
  );
}

// src/components/Scanner.tsx
import { useState, useEffect, useRef } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { useStore } from '../store';
import type { EmberMlFileResult } from '../store';
import {
  FolderOpen, FileSearch, X, AlertTriangle,
  CheckCircle, Loader, ChevronDown, ChevronRight,
  Shield, Zap, Tag, HardDrive, Clock, BrainCircuit,
} from 'lucide-react';
import type { ScanResult, ContextFlag, DetectionSignal } from '../types';
import { CONTEXT_FLAG_LABEL, CONTEXT_FLAG_SEVERITY } from '../types';

// ─── Helpers ──────────────────────────────────────────────────────────────────

/** Format a millisecond duration as a human-readable string. */
function formatDuration(ms: number): string {
  const totalSecs = ms / 1000;
  if (totalSecs < 60) return `${totalSecs.toFixed(1)}s`;
  const mins = Math.floor(totalSecs / 60);
  const secs = Math.floor(totalSecs % 60);
  if (mins < 60) return `${mins}m ${secs}s`;
  const hours = Math.floor(mins / 60);
  return `${hours}h ${mins % 60}m ${secs}s`;
}

/** Format elapsed whole seconds (for the live timer). */
function formatElapsed(secs: number): string {
  if (secs < 60) return `${secs}s`;
  const m = Math.floor(secs / 60);
  const s = secs % 60;
  return `${m}m ${s < 10 ? '0' : ''}${s}s`;
}

// ─── Constants ────────────────────────────────────────────────────────────────

const LEVEL_COLOR: Record<string, string> = {
  Clean:      'var(--green)',
  Suspicious: 'var(--amber)',
  Malicious:  'var(--red)',
};

const SIGNAL_SOURCE_COLOR: Record<string, string> = {
  hash:        'var(--red)',
  yara:        'var(--amber)',
  entropy:     'var(--cyan)',
  keyword:     'var(--amber)',
  content:     'var(--amber)',
  filename:    'var(--cyan)',
  extension:   'var(--cyan)',
  structure:   'var(--cyan)',
  metadata:    'var(--text-dim)',
  obfuscation: 'var(--red)',
  timestamp:   'var(--text-dim)',
  context:     'var(--red)',
  ember_ml:    '#a855f7',   // violet — Ember2024 ML signal
};

const FLAG_COLOR: Record<'critical' | 'high' | 'medium', string> = {
  critical: 'var(--red)',
  high:     'var(--amber)',
  medium:   'var(--cyan)',
};

// ─── Sub-components ───────────────────────────────────────────────────────────

function ConfidenceBar({ score, color }: { score: number; color: string }) {
  const pct = Math.round(score * 100);
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      <div style={{
        flex: 1, height: 4, background: 'var(--border)', borderRadius: 2, overflow: 'hidden',
      }}>
        <div style={{
          height: '100%',
          width: `${pct}%`,
          background: color,
          borderRadius: 2,
          transition: 'width 0.3s ease',
        }} />
      </div>
      <span style={{
        fontFamily: 'var(--font-mono)', fontSize: 9,
        color: 'var(--text-dim)', minWidth: 28, textAlign: 'right',
      }}>
        {pct}%
      </span>
    </div>
  );
}

function SignalTag({ signal }: { signal: DetectionSignal }) {
  const color = SIGNAL_SOURCE_COLOR[signal.source] ?? 'var(--text-dim)';
  return (
    <div style={{
      display: 'flex', alignItems: 'flex-start', gap: 6,
      padding: '4px 8px',
      background: 'var(--bg)',
      border: `1px solid var(--border)`,
      borderRadius: 4,
    }}>
      <span style={{
        fontFamily: 'var(--font-hud)', fontSize: 8,
        color, letterSpacing: '0.08em',
        minWidth: 60, paddingTop: 1,
      }}>
        [{signal.source.toUpperCase()}]
      </span>
      <span style={{
        fontFamily: 'var(--font-mono)', fontSize: 9,
        color: 'var(--text)', flex: 1, lineHeight: 1.4,
      }}>
        {signal.description}
      </span>
      {signal.score > 0 && (
        <span style={{
          fontFamily: 'var(--font-hud)', fontSize: 8,
          color: 'var(--text-dim)', paddingTop: 1,
        }}>
          +{signal.score}
        </span>
      )}
    </div>
  );
}

function ContextFlagBadge({ flag }: { flag: ContextFlag }) {
  const severity = CONTEXT_FLAG_SEVERITY[flag];
  const color = FLAG_COLOR[severity];
  const label = CONTEXT_FLAG_LABEL[flag];
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 4,
      padding: '2px 8px',
      background: `${color}18`,
      border: `1px solid ${color}60`,
      borderRadius: 3,
      fontFamily: 'var(--font-hud)', fontSize: 8,
      color, letterSpacing: '0.06em',
    }}>
      {severity === 'critical' ? '🚨' : severity === 'high' ? '⚠️' : 'ℹ️'}
      {label.toUpperCase()}
    </span>
  );
}

// ─── Result row ───────────────────────────────────────────────────────────────

function ResultRow({ result, index }: { result: ScanResult; index: number }) {
  const [expanded, setExpanded] = useState(false);
  const color = LEVEL_COLOR[result.level] ?? 'var(--text-dim)';
  const hasCriticalFlag = result.context_flags.some(
    f => CONTEXT_FLAG_SEVERITY[f] === 'critical'
  );

  return (
    <div style={{
      borderBottom: '1px solid var(--border)',
      animation: `fadeUp 0.2s ease ${Math.min(index * 0.02, 0.3)}s both`,
      // Subtle left border for critical context
      borderLeft: hasCriticalFlag ? '2px solid var(--red)' : '2px solid transparent',
    }}>
      {/* ── Row header ─────────────────────────────────────────────────── */}
      <button
        onClick={() => result.is_threat && setExpanded(e => !e)}
        style={{
          width: '100%', background: 'transparent', border: 'none',
          display: 'grid',
          gridTemplateColumns: '20px 1fr auto 90px 28px',
          alignItems: 'center', gap: 12, padding: '10px 16px',
          cursor: result.is_threat ? 'pointer' : 'default',
          transition: 'background 0.1s',
        }}
        onMouseEnter={e => {
          if (result.is_threat)
            (e.currentTarget as HTMLButtonElement).style.background = 'var(--elevated)';
        }}
        onMouseLeave={e => {
          (e.currentTarget as HTMLButtonElement).style.background = 'transparent';
        }}
      >
        {/* Icon */}
        <span>
          {result.level === 'Malicious'
            ? <AlertTriangle size={14} color="var(--red)" />
            : result.level === 'Suspicious'
            ? <AlertTriangle size={14} color="var(--amber)" />
            : <CheckCircle size={14} color="var(--green)" />}
        </span>

        {/* Path */}
        <span style={{
          fontFamily: 'var(--font-mono)', fontSize: 11,
          color: result.is_threat ? color : 'var(--text-dim)',
          overflow: 'hidden', textOverflow: 'ellipsis',
          whiteSpace: 'nowrap', textAlign: 'left',
        }}>
          {result.path}
        </span>

        {/* Context flags — show inline badges for critical/high */}
        <span style={{ display: 'flex', gap: 4, flexWrap: 'nowrap' }}>
          {result.context_flags
            .filter(f => CONTEXT_FLAG_SEVERITY[f] !== 'medium')
            .slice(0, 2)
            .map(f => (
              <ContextFlagBadge key={f} flag={f} />
            ))}
        </span>

        {/* Level */}
        <span style={{
          fontFamily: 'var(--font-hud)', fontSize: 10,
          color, letterSpacing: '0.08em', textAlign: 'right',
        }}>
          {result.level.toUpperCase()}
        </span>

        {/* Chevron */}
        <span style={{ color: 'var(--text-dim)', opacity: result.is_threat ? 1 : 0 }}>
          {expanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
        </span>
      </button>

      {/* ── Expanded detail panel ───────────────────────────────────────── */}
      {expanded && result.is_threat && (
        <div style={{
          padding: '0 16px 14px 48px',
          display: 'flex', flexDirection: 'column', gap: 10,
        }}>
          {/* Reason + hash + sig */}
          <div style={{
            fontFamily: 'var(--font-mono)', fontSize: 10,
            display: 'flex', flexDirection: 'column', gap: 4,
          }}>
            <div>
              <span style={{ color: 'var(--text-dim)' }}>REASON: </span>
              <span style={{ color }}>{result.reason}</span>
            </div>
            {result.hash && (
              <div>
                <span style={{ color: 'var(--text-dim)' }}>HASH: </span>
                <span style={{ color: 'var(--cyan)' }}>{result.hash}</span>
              </div>
            )}
            {result.signature && (
              <div>
                <span style={{ color: 'var(--text-dim)' }}>SIG: </span>
                <span style={{ color: 'var(--red)' }}>{result.signature}</span>
              </div>
            )}
          </div>

          {/* Confidence bar */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            <div style={{
              fontFamily: 'var(--font-hud)', fontSize: 8,
              color: 'var(--text-dim)', letterSpacing: '0.08em',
              display: 'flex', alignItems: 'center', gap: 4,
            }}>
              <Shield size={9} /> CONFIDENCE
            </div>
            <ConfidenceBar score={result.confidence_score} color={color} />
          </div>

          {/* Detection signals */}
          {result.detection_signals.length > 0 && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              <div style={{
                fontFamily: 'var(--font-hud)', fontSize: 8,
                color: 'var(--text-dim)', letterSpacing: '0.08em',
                display: 'flex', alignItems: 'center', gap: 4,
              }}>
                <Zap size={9} /> DETECTION SIGNALS ({result.detection_signals.length})
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                {result.detection_signals.map((s, i) => (
                  <SignalTag key={i} signal={s} />
                ))}
              </div>
            </div>
          )}

          {/* Context flags — full list */}
          {result.context_flags.length > 0 && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              <div style={{
                fontFamily: 'var(--font-hud)', fontSize: 8,
                color: 'var(--text-dim)', letterSpacing: '0.08em',
                display: 'flex', alignItems: 'center', gap: 4,
              }}>
                <Tag size={9} /> CONTEXT FLAGS
              </div>
              <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                {result.context_flags.map(f => (
                  <ContextFlagBadge key={f} flag={f} />
                ))}
              </div>
            </div>
          )}

          {/* File category badge */}
          <div style={{
            fontFamily: 'var(--font-mono)', fontSize: 9,
            color: 'var(--text-dim)',
          }}>
            CATEGORY: <span style={{ color: 'var(--cyan)' }}>
              {result.file_category.toUpperCase()}
            </span>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Ember ML comparison row ──────────────────────────────────────────────────

function EmberMlRow({ record, index }: { record: EmberMlFileResult; index: number }) {
  const verdictColor = record.mlVerdict === 'malicious'
    ? 'var(--red)'
    : record.mlVerdict === 'clean'
    ? 'var(--green)'
    : 'var(--text-dim)';

  const finalColor = record.finalLevel === 'Malicious'
    ? 'var(--red)'
    : record.finalLevel === 'Suspicious'
    ? 'var(--amber)'
    : 'var(--green)';

  const scorePct = record.mlScore !== null ? Math.round(record.mlScore * 100) : null;

  return (
    <div style={{
      display: 'grid',
      gridTemplateColumns: '1fr 100px 28px 60px 120px 28px 100px',
      alignItems: 'center',
      gap: 10,
      padding: '9px 16px',
      borderBottom: '1px solid var(--border)',
      animation: `fadeUp 0.2s ease ${Math.min(index * 0.04, 0.4)}s both`,
    }}>

      {/* File name */}
      <span style={{
        fontFamily: 'var(--font-mono)', fontSize: 11,
        color: 'var(--text)',
        overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
      }} title={record.path}>
        {record.fileName}
      </span>

      {/* Initial verdict — always Suspicious */}
      <span style={{
        display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
        padding: '2px 8px',
        background: 'rgba(255,180,0,0.12)',
        border: '1px solid rgba(255,180,0,0.4)',
        borderRadius: 3,
        fontFamily: 'var(--font-hud)', fontSize: 8,
        color: 'var(--amber)', letterSpacing: '0.06em',
      }}>
        SUSPICIOUS
      </span>

      {/* Arrow */}
      <span style={{ color: 'var(--text-dim)', fontFamily: 'var(--font-mono)', fontSize: 12, textAlign: 'center' }}>→</span>

      {/* Model chip — All model gets a distinct muted colour */}
      {record.mlModel ? (
        <span style={{
          display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
          padding: '2px 7px',
          background: record.mlModel === 'All'
            ? 'rgba(100,116,139,0.15)'
            : 'rgba(168,85,247,0.12)',
          border: `1px solid ${record.mlModel === 'All'
            ? 'rgba(100,116,139,0.4)'
            : 'rgba(168,85,247,0.35)'}`,
          borderRadius: 3,
          fontFamily: 'var(--font-hud)', fontSize: 8,
          color: record.mlModel === 'All' ? '#94a3b8' : '#a855f7',
          letterSpacing: '0.06em',
          whiteSpace: 'nowrap',
        }}
        title={record.mlModel === 'All' ? 'Catch-all model — byte-level features (no PE/PDF header)' : undefined}
        >
          {record.mlModel}
        </span>
      ) : (
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)' }}>
          —
        </span>
      )}

      {/* Score bar + number */}
      {scorePct !== null ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
          <div style={{
            height: 3, background: 'var(--border)', borderRadius: 2, overflow: 'hidden',
          }}>
            <div style={{
              height: '100%',
              width: `${scorePct}%`,
              background: scorePct >= 80 ? 'var(--red)' : scorePct >= 50 ? 'var(--amber)' : 'var(--green)',
              borderRadius: 2,
              transition: 'width 0.4s ease',
            }} />
          </div>
          <span style={{
            fontFamily: 'var(--font-mono)', fontSize: 9,
            color: verdictColor, textAlign: 'right',
          }}>
            {record.mlScore!.toFixed(4)}
          </span>
        </div>
      ) : (
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)' }}>
          skipped
        </span>
      )}

      {/* Arrow 2 */}
      <span style={{ color: 'var(--text-dim)', fontFamily: 'var(--font-mono)', fontSize: 12, textAlign: 'center' }}>→</span>

      {/* ML verdict / final verdict */}
      {record.skipped ? (
        <span style={{
          fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)',
        }}>
          unsupported
        </span>
      ) : (
        <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
          <span style={{
            display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
            padding: '2px 8px',
            background: record.finalLevel === 'Malicious'
              ? 'rgba(255,50,50,0.12)'
              : record.finalLevel === 'Clean'
              ? 'rgba(0,200,80,0.10)'
              : 'rgba(255,180,0,0.10)',
            border: `1px solid ${finalColor}60`,
            borderRadius: 3,
            fontFamily: 'var(--font-hud)', fontSize: 8,
            color: finalColor, letterSpacing: '0.06em',
          }}>
            {record.finalLevel.toUpperCase()}
          </span>
          {record.escalated && (
            <span style={{
              fontFamily: 'var(--font-hud)', fontSize: 8,
              color: 'var(--red)', letterSpacing: '0.04em',
            }} title="Escalated from Suspicious to Malicious by Ember ML">
              ▲
            </span>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Ember ML comparison panel ─────────────────────────────────────────────────

function EmberMlPanel({
  results,
  running,
  progress,
}: {
  results: EmberMlFileResult[];
  running: boolean;
  progress: { done: number; total: number } | null;
}) {
  const escalated = results.filter(r => r.escalated).length;
  const confirmed = results.filter(r => !r.escalated && r.mlVerdict === 'malicious').length;
  const clean     = results.filter(r => r.mlVerdict === 'clean').length;
  const skipped   = results.filter(r => r.skipped).length;

  return (
    <div style={{
      background: 'var(--surface)',
      border: '1px solid rgba(168,85,247,0.3)',
      borderRadius: 8,
      overflow: 'hidden',
    }}>
      {/* Panel header */}
      <div style={{
        padding: '10px 16px',
        background: 'rgba(168,85,247,0.06)',
        borderBottom: '1px solid rgba(168,85,247,0.2)',
        display: 'flex', alignItems: 'center', gap: 12,
      }}>
        <BrainCircuit size={14} color="#a855f7" />
        <span style={{
          fontFamily: 'var(--font-hud)', fontSize: 11, fontWeight: 700,
          color: '#a855f7', letterSpacing: '0.08em', flex: 1,
        }}>
          EMBER2024 ML ANALYSIS
          {running && progress && (
            <span style={{ fontWeight: 400, marginLeft: 8, color: 'var(--text-dim)' }}>
              — {progress.done}/{progress.total} files
            </span>
          )}
          {!running && results.length > 0 && (
            <span style={{ fontWeight: 400, marginLeft: 8, color: 'var(--text-dim)' }}>
              — {results.length} file{results.length !== 1 ? 's' : ''} processed
            </span>
          )}
        </span>

        {/* Summary chips — shown once at least one result is in */}
        {results.length > 0 && (
          <div style={{ display: 'flex', gap: 6 }}>
            {escalated > 0 && (
              <span style={{
                padding: '2px 8px',
                background: 'rgba(255,50,50,0.12)', border: '1px solid rgba(255,50,50,0.4)',
                borderRadius: 3, fontFamily: 'var(--font-hud)', fontSize: 8,
                color: 'var(--red)', letterSpacing: '0.05em',
              }}>
                ▲ {escalated} ESCALATED
              </span>
            )}
            {confirmed > 0 && (
              <span style={{
                padding: '2px 8px',
                background: 'rgba(255,100,50,0.10)', border: '1px solid rgba(255,100,50,0.35)',
                borderRadius: 3, fontFamily: 'var(--font-hud)', fontSize: 8,
                color: 'var(--amber)', letterSpacing: '0.05em',
              }}>
                {confirmed} CONFIRMED MALICIOUS
              </span>
            )}
            {clean > 0 && (
              <span style={{
                padding: '2px 8px',
                background: 'rgba(0,200,80,0.08)', border: '1px solid rgba(0,200,80,0.35)',
                borderRadius: 3, fontFamily: 'var(--font-hud)', fontSize: 8,
                color: 'var(--green)', letterSpacing: '0.05em',
              }}>
                {clean} CLEAN
              </span>
            )}
            {skipped > 0 && (
              <span style={{
                padding: '2px 8px',
                background: 'var(--elevated)', border: '1px solid var(--border)',
                borderRadius: 3, fontFamily: 'var(--font-hud)', fontSize: 8,
                color: 'var(--text-dim)', letterSpacing: '0.05em',
              }}>
                {skipped} SKIPPED
              </span>
            )}
          </div>
        )}
      </div>

      {/* Column headings */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: '1fr 100px 28px 60px 120px 28px 100px',
        gap: 10,
        padding: '6px 16px',
        borderBottom: '1px solid var(--border)',
        background: 'var(--elevated)',
      }}>
        {['FILE', 'INITIAL', '', 'MODEL', 'ML SCORE', '', 'VERDICT'].map((h, i) => (
          <span key={i} style={{
            fontFamily: 'var(--font-hud)', fontSize: 8,
            color: 'var(--text-dim)', letterSpacing: '0.08em',
            textAlign: i === 2 || i === 5 ? 'center' : 'left',
          }}>
            {h}
          </span>
        ))}
      </div>

      {/* Rows — scrollable, header + column labels stay pinned */}
      <div style={{ maxHeight: 260, overflowY: 'auto' }}>
        {results.length === 0 && running && (
          <div style={{
            padding: '20px 16px', textAlign: 'center',
            fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-dim)',
          }}>
            Waiting for first result...
          </div>
        )}
        {results.map((r, i) => (
          <EmberMlRow key={r.path} record={r} index={i} />
        ))}
      </div>
    </div>
  );
}

// ─── Main Scanner component ───────────────────────────────────────────────────

export default function Scanner() {
  const {
    scanning, scanResults, scanStats, scanError,
    lastScanDurationMs,
    scanFile, scanDirectory, scanAll, quickScan, clearScan,
    emberMlRunning, emberMlProgress, emberMlError, emberMlResults, applyEmberMl,
  } = useStore();

  const [tab, setTab] = useState<'threats' | 'all'>('threats');
  const [pathInput, setPathInput] = useState('');
  // Track which kind of scan is running so the spinner label is accurate.
  const [scanMode, setScanMode] = useState<'file' | 'directory' | 'all' | 'quick' | null>(null);

  // ── Live elapsed timer ───────────────────────────────────────────────────────
  const [elapsedSecs, setElapsedSecs] = useState(0);
  const scanStartRef = useRef<number>(0);

  useEffect(() => {
    if (!scanning) {
      setElapsedSecs(0);
      return;
    }
    scanStartRef.current = Date.now();
    setElapsedSecs(0);
    const id = setInterval(() => {
      setElapsedSecs(Math.floor((Date.now() - scanStartRef.current) / 1000));
    }, 1000);
    return () => clearInterval(id);
  }, [scanning]);

  // ── Handlers ─────────────────────────────────────────────────────────────────

  const handleScanFile = () => {
    if (!pathInput.trim()) return;
    setScanMode('file');
    clearScan();
    scanFile(pathInput.trim());
  };

  const handleScanDir = () => {
    if (!pathInput.trim()) return;
    setScanMode('directory');
    clearScan();
    scanDirectory(pathInput.trim());
  };

  const handleScanAll = () => {
    setScanMode('all');
    clearScan();
    scanAll();
  };

  const handleQuickScan = () => {
    setScanMode('quick');
    clearScan();
    quickScan();
  };

  const handleBrowse = async () => {
    try {
      const path = await invoke<string | null>('open_file_dialog');
      if (path) setPathInput(path);
    } catch {}
  };

  const handleBrowseDir = async () => {
    try {
      const path = await invoke<string | null>('open_dir_dialog');
      if (path) setPathInput(path);
    } catch {}
  };

  const threats = scanResults.filter(r => r.is_threat);
  const displayed = tab === 'threats' ? threats : scanResults;

  // Suspicious files eligible for Ember2024 ML analysis
  const suspiciousFiles = scanResults.filter(r => r.level === 'Suspicious');

  // Count critical context flags across all results for summary
  const criticalContextCount = scanResults.filter(r =>
    r.context_flags.some(f => CONTEXT_FLAG_SEVERITY[f] === 'critical')
  ).length;

  return (
    <div style={{
      height: '100%', display: 'flex', flexDirection: 'column',
      padding: 32, gap: 24,
    }}>
      {/* ── Header ────────────────────────────────────────────────────────── */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
        <div>
          <div style={{
            fontFamily: 'var(--font-hud)', fontSize: 22, fontWeight: 700,
            color: 'var(--text-bright)', letterSpacing: '0.05em',
          }}>
            FILE SCANNER
          </div>
          <div style={{
            fontFamily: 'var(--font-mono)', fontSize: 11,
            color: 'var(--text-dim)', marginTop: 4,
          }}>
            Multi-layer threat analysis — Hash · YARA · Heuristics · Directory Context
          </div>
        </div>

        {/* Duration badge — shown after any scan completes */}
        {lastScanDurationMs !== null && !scanning && (
          <div style={{
            display: 'flex', alignItems: 'center', gap: 6,
            padding: '6px 12px',
            background: 'var(--surface)',
            border: '1px solid var(--border)',
            borderRadius: 6,
            flexShrink: 0,
          }}>
            <Clock size={12} color="var(--text-dim)" />
            <span style={{
              fontFamily: 'var(--font-hud)', fontSize: 10,
              color: 'var(--text-dim)', letterSpacing: '0.08em',
            }}>
              COMPLETED IN
            </span>
            <span style={{
              fontFamily: 'var(--font-mono)', fontSize: 12,
              color: 'var(--cyan)', fontWeight: 600,
            }}>
              {formatDuration(lastScanDurationMs)}
            </span>
          </div>
        )}
      </div>

      {/* ── Path input + buttons ───────────────────────────────────────────── */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        <div style={{ display: 'flex', gap: 8 }}>
          <input
            value={pathInput}
            onChange={e => setPathInput(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleScanFile()}
            placeholder="Enter file or directory path... e.g. C:\Users\Downloads"
            style={{
              flex: 1, background: 'var(--surface)',
              border: '1px solid var(--border)', borderRadius: 6,
              padding: '10px 14px', color: 'var(--text)',
              fontFamily: 'var(--font-mono)', fontSize: 12,
              outline: 'none', transition: 'border-color 0.15s',
            }}
            onFocus={e => (e.target as HTMLInputElement).style.borderColor = 'var(--border-hi)'}
            onBlur={e => (e.target as HTMLInputElement).style.borderColor = 'var(--border)'}
          />
        </div>

        {/* ── File / dir buttons row ─────────────────────────────────────── */}
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          {[
            { icon: <FileSearch size={15} />, label: 'SCAN FILE',      action: handleScanFile,  primary: true  },
            { icon: <FolderOpen size={15} />, label: 'SCAN DIRECTORY', action: handleScanDir,   primary: false },
            { icon: <FileSearch size={15} />, label: 'BROWSE FILE',    action: handleBrowse,    primary: false },
            { icon: <FolderOpen size={15} />, label: 'BROWSE DIR',     action: handleBrowseDir, primary: false },
            ...(scanResults.length > 0
              ? [{ icon: <X size={13} />, label: 'CLEAR', action: clearScan, primary: false }]
              : []),
          ].map((btn, i) => (
            <button
              key={i}
              onClick={btn.action}
              disabled={scanning}
              style={{
                display: 'flex', alignItems: 'center', gap: 7,
                padding: '9px 16px',
                background: btn.primary ? 'var(--green-glow)' : 'var(--surface)',
                border: `1px solid ${btn.primary ? 'var(--border-md)' : 'var(--border)'}`,
                borderRadius: 6,
                color: btn.primary ? 'var(--green)' : 'var(--text-dim)',
                fontFamily: 'var(--font-hud)', fontSize: 10,
                letterSpacing: '0.1em',
                cursor: scanning ? 'not-allowed' : 'pointer',
                opacity: scanning ? 0.5 : 1,
                transition: 'all 0.15s',
              }}
              onMouseEnter={e => {
                if (!scanning) {
                  const el = e.currentTarget as HTMLButtonElement;
                  el.style.borderColor = 'var(--border-hi)';
                  el.style.color = 'var(--green)';
                }
              }}
              onMouseLeave={e => {
                const el = e.currentTarget as HTMLButtonElement;
                el.style.borderColor = btn.primary ? 'var(--border-md)' : 'var(--border)';
                el.style.color = btn.primary ? 'var(--green)' : 'var(--text-dim)';
              }}
            >
              {btn.icon} {btn.label}
            </button>
          ))}
        </div>

        {/* ── QUICK SCAN + SCAN ALL row ──────────────────────────────────── */}
        <div style={{ display: 'flex', gap: 8 }}>

          {/* Quick Scan */}
          <div style={{
            flex: 1, display: 'flex', alignItems: 'center', gap: 12,
            padding: '10px 14px',
            background: scanning && scanMode === 'quick'
              ? 'rgba(255,180,0,0.05)'
              : 'var(--surface)',
            border: `1px solid ${scanning && scanMode === 'quick' ? 'var(--amber)' : 'var(--border)'}`,
            borderRadius: 6,
            transition: 'border-color 0.2s, background 0.2s',
          }}>
            <button
              onClick={handleQuickScan}
              disabled={scanning}
              style={{
                display: 'flex', alignItems: 'center', gap: 8,
                padding: '8px 18px',
                background: 'rgba(255,180,0,0.1)',
                border: '1px solid var(--amber)',
                borderRadius: 6,
                color: 'var(--amber)',
                fontFamily: 'var(--font-hud)', fontSize: 11,
                letterSpacing: '0.12em', fontWeight: 700,
                cursor: scanning ? 'not-allowed' : 'pointer',
                opacity: scanning ? 0.5 : 1,
                transition: 'all 0.15s',
                flexShrink: 0,
              }}
              onMouseEnter={e => {
                if (!scanning) {
                  const el = e.currentTarget as HTMLButtonElement;
                  el.style.background = 'rgba(255,180,0,0.18)';
                  el.style.boxShadow = '0 0 12px rgba(255,180,0,0.2)';
                }
              }}
              onMouseLeave={e => {
                const el = e.currentTarget as HTMLButtonElement;
                el.style.background = 'rgba(255,180,0,0.1)';
                el.style.boxShadow = 'none';
              }}
            >
              <Zap size={15} />
              QUICK SCAN
            </button>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 2, flex: 1 }}>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)' }}>
                Downloads · Desktop · AppData · Temp · Tasks · Drivers
              </span>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)', opacity: 0.6 }}>
                High-risk locations only — typically 1–5 minutes
              </span>
            </div>
            {scanning && scanMode === 'quick' && (
              <div style={{
                display: 'flex', alignItems: 'center', gap: 6,
                padding: '4px 10px',
                background: 'rgba(255,180,0,0.08)',
                border: '1px solid rgba(255,180,0,0.3)',
                borderRadius: 4, flexShrink: 0,
              }}>
                <div style={{
                  width: 6, height: 6, borderRadius: '50%',
                  background: 'var(--amber)',
                  animation: 'pulse 1s ease-in-out infinite',
                }} />
                <span style={{
                  fontFamily: 'var(--font-mono)', fontSize: 13,
                  color: 'var(--amber)', fontWeight: 600, minWidth: 52,
                }}>
                  {formatElapsed(elapsedSecs)}
                </span>
              </div>
            )}
          </div>

          {/* Full Scan All */}
          <div style={{
            flex: 1, display: 'flex', alignItems: 'center', gap: 12,
            padding: '10px 14px',
            background: scanning && scanMode === 'all'
              ? 'rgba(0,200,255,0.05)'
              : 'var(--surface)',
            border: `1px solid ${scanning && scanMode === 'all' ? 'var(--cyan)' : 'var(--border)'}`,
            borderRadius: 6,
            transition: 'border-color 0.2s, background 0.2s',
          }}>
            <button
              onClick={handleScanAll}
              disabled={scanning}
              style={{
                display: 'flex', alignItems: 'center', gap: 8,
                padding: '8px 18px',
                background: 'rgba(0,200,255,0.1)',
                border: '1px solid var(--cyan)',
                borderRadius: 6,
                color: 'var(--cyan)',
                fontFamily: 'var(--font-hud)', fontSize: 11,
                letterSpacing: '0.12em', fontWeight: 700,
                cursor: scanning ? 'not-allowed' : 'pointer',
                opacity: scanning ? 0.5 : 1,
                transition: 'all 0.15s',
                flexShrink: 0,
              }}
              onMouseEnter={e => {
                if (!scanning) {
                  const el = e.currentTarget as HTMLButtonElement;
                  el.style.background = 'rgba(0,200,255,0.18)';
                  el.style.boxShadow = '0 0 12px rgba(0,200,255,0.2)';
                }
              }}
              onMouseLeave={e => {
                const el = e.currentTarget as HTMLButtonElement;
                el.style.background = 'rgba(0,200,255,0.1)';
                el.style.boxShadow = 'none';
              }}
            >
              <HardDrive size={15} />
              SCAN ALL
            </button>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 2, flex: 1 }}>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)' }}>
                Full system — Users · Windows · Program Files · ProgramData
              </span>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)', opacity: 0.6 }}>
                Complete coverage — up to 2 hours on first run
              </span>
            </div>
            {scanning && scanMode === 'all' && (
              <div style={{
                display: 'flex', alignItems: 'center', gap: 6,
                padding: '4px 10px',
                background: 'rgba(0,200,255,0.08)',
                border: '1px solid rgba(0,200,255,0.3)',
                borderRadius: 4, flexShrink: 0,
              }}>
                <div style={{
                  width: 6, height: 6, borderRadius: '50%',
                  background: 'var(--cyan)',
                  animation: 'pulse 1s ease-in-out infinite',
                }} />
                <span style={{
                  fontFamily: 'var(--font-mono)', fontSize: 13,
                  color: 'var(--cyan)', fontWeight: 600, minWidth: 52,
                }}>
                  {formatElapsed(elapsedSecs)}
                </span>
              </div>
            )}
          </div>

        </div>
      </div>

      {/* ── Stats bar ──────────────────────────────────────────────────────── */}
      {scanStats && (
        <div style={{
          display: 'grid',
          gridTemplateColumns: criticalContextCount > 0
            ? 'repeat(5, 1fr) 1fr'
            : 'repeat(5, 1fr)',
          gap: 1, background: 'var(--border)',
          borderRadius: 6, overflow: 'hidden',
        }}>
          {[
            { label: 'TOTAL',      value: scanStats.total_files,     color: 'var(--cyan)'     },
            { label: 'CLEAN',      value: scanStats.clean_files,      color: 'var(--green)'    },
            { label: 'SUSPICIOUS', value: scanStats.suspicious_files, color: 'var(--amber)'    },
            { label: 'MALICIOUS',  value: scanStats.malicious_files,  color: 'var(--red)'      },
            { label: 'ERRORS',     value: scanStats.error_files,      color: 'var(--text-dim)' },
            ...(criticalContextCount > 0
              ? [{ label: '🚨 CRITICAL CTX', value: criticalContextCount, color: 'var(--red)' }]
              : []),
          ].map(s => (
            <div key={s.label} style={{
              background: 'var(--surface)', padding: '12px 16px',
              display: 'flex', flexDirection: 'column', gap: 4,
            }}>
              <div style={{
                fontFamily: 'var(--font-hud)', fontSize: 20,
                fontWeight: 700, color: s.color,
              }}>
                {s.value}
              </div>
              <div style={{
                fontFamily: 'var(--font-mono)', fontSize: 9,
                color: 'var(--text-dim)', letterSpacing: '0.08em',
              }}>
                {s.label}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* ── Ember2024 ML banner ───────────────────────────────────────────── */}
      {/* Shown when there are suspicious files waiting for ML analysis,      */}
      {/* or while the ML scan is in progress.                                */}
      {(suspiciousFiles.length > 0 || emberMlRunning || emberMlError) && !scanning && (
        <div style={{
          padding: '10px 16px',
          background: emberMlRunning
            ? 'rgba(168,85,247,0.08)'
            : 'rgba(168,85,247,0.05)',
          border: `1px solid ${emberMlRunning ? 'rgba(168,85,247,0.5)' : 'rgba(168,85,247,0.25)'}`,
          borderRadius: 6,
          display: 'flex', alignItems: 'center', gap: 12,
          transition: 'all 0.2s',
        }}>
          {/* Icon */}
          {emberMlRunning
            ? <Loader size={15} color="#a855f7" style={{ animation: 'spin 1s linear infinite', flexShrink: 0 }} />
            : <BrainCircuit size={15} color="#a855f7" style={{ flexShrink: 0 }} />
          }

          {/* Label */}
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 2 }}>
            {emberMlRunning && emberMlProgress ? (
              <>
                <span style={{
                  fontFamily: 'var(--font-hud)', fontSize: 10,
                  color: '#a855f7', letterSpacing: '0.08em',
                }}>
                  EMBER2024 ML — ANALYZING {emberMlProgress.done}/{emberMlProgress.total} FILES
                </span>
                {/* Progress bar */}
                <div style={{
                  height: 3, background: 'rgba(168,85,247,0.2)',
                  borderRadius: 2, overflow: 'hidden', maxWidth: 240,
                }}>
                  <div style={{
                    height: '100%',
                    width: `${Math.round((emberMlProgress.done / emberMlProgress.total) * 100)}%`,
                    background: '#a855f7',
                    borderRadius: 2,
                    transition: 'width 0.3s ease',
                  }} />
                </div>
              </>
            ) : emberMlError ? (
              <span style={{
                fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--red)',
              }}>
                ML error: {emberMlError}
              </span>
            ) : (
              <>
                <span style={{
                  fontFamily: 'var(--font-hud)', fontSize: 10,
                  color: '#a855f7', letterSpacing: '0.08em',
                }}>
                  EMBER2024 ML READY
                </span>
                <span style={{
                  fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)',
                }}>
                  {suspiciousFiles.length} suspicious file{suspiciousFiles.length !== 1 ? 's' : ''} — run EMBER2024 Win32 / Win64 / .NET / PDF models to confirm or escalate
                </span>
              </>
            )}
          </div>

          {/* Apply ML button */}
          <button
            onClick={applyEmberMl}
            disabled={emberMlRunning || suspiciousFiles.length === 0}
            style={{
              display: 'flex', alignItems: 'center', gap: 7,
              padding: '8px 16px',
              background: emberMlRunning ? 'rgba(168,85,247,0.05)' : 'rgba(168,85,247,0.12)',
              border: '1px solid rgba(168,85,247,0.5)',
              borderRadius: 6,
              color: '#a855f7',
              fontFamily: 'var(--font-hud)', fontSize: 10,
              letterSpacing: '0.1em', fontWeight: 700,
              cursor: (emberMlRunning || suspiciousFiles.length === 0) ? 'not-allowed' : 'pointer',
              opacity: (emberMlRunning || suspiciousFiles.length === 0) ? 0.5 : 1,
              transition: 'all 0.15s',
              flexShrink: 0,
            }}
            onMouseEnter={e => {
              if (!emberMlRunning && suspiciousFiles.length > 0) {
                const el = e.currentTarget as HTMLButtonElement;
                el.style.background = 'rgba(168,85,247,0.22)';
                el.style.boxShadow = '0 0 12px rgba(168,85,247,0.25)';
              }
            }}
            onMouseLeave={e => {
              const el = e.currentTarget as HTMLButtonElement;
              el.style.background = emberMlRunning ? 'rgba(168,85,247,0.05)' : 'rgba(168,85,247,0.12)';
              el.style.boxShadow = 'none';
            }}
          >
            <BrainCircuit size={13} />
            APPLY ML
          </button>
        </div>
      )}

      {/* ── Ember ML comparison panel ─────────────────────────────────────── */}
      {/* Visible while ML is running OR after it completes with results.     */}
      {(emberMlRunning || (emberMlResults !== null && emberMlResults.length > 0)) && !scanning && (
        <EmberMlPanel
          results={emberMlResults ?? []}
          running={emberMlRunning}
          progress={emberMlProgress}
        />
      )}

      {/* ── Critical context alert banner ─────────────────────────────────── */}
      {criticalContextCount > 0 && (
        <div style={{
          padding: '10px 16px',
          background: 'rgba(255,50,50,0.08)',
          border: '1px solid rgba(255,50,50,0.3)',
          borderRadius: 6,
          display: 'flex', alignItems: 'center', gap: 10,
        }}>
          <AlertTriangle size={16} color="var(--red)" />
          <span style={{
            fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--red)',
          }}>
            🚨 Active ransomware indicators detected in this directory —
            {' '}{criticalContextCount} file{criticalContextCount !== 1 ? 's' : ''} with critical context flags.
            Isolate immediately.
          </span>
        </div>
      )}

      {/* ── Results panel ──────────────────────────────────────────────────── */}
      <div style={{
        flex: 1, display: 'flex', flexDirection: 'column',
        background: 'var(--surface)', border: '1px solid var(--border)',
        borderRadius: 8, overflow: 'hidden', minHeight: 0,
      }}>
        {/* Tab bar */}
        {scanResults.length > 0 && (
          <div style={{
            display: 'flex', alignItems: 'center',
            justifyContent: 'space-between',
            padding: '10px 16px',
            borderBottom: '1px solid var(--border)',
            background: 'var(--elevated)',
          }}>
            <div style={{ display: 'flex', gap: 4 }}>
              {(['threats', 'all'] as const).map(t => (
                <button
                  key={t}
                  onClick={() => setTab(t)}
                  style={{
                    padding: '4px 12px',
                    background: tab === t ? 'var(--green-glow)' : 'transparent',
                    border: `1px solid ${tab === t ? 'var(--border-md)' : 'transparent'}`,
                    borderRadius: 4,
                    color: tab === t ? 'var(--green)' : 'var(--text-dim)',
                    fontFamily: 'var(--font-hud)', fontSize: 10,
                    letterSpacing: '0.08em', cursor: 'pointer',
                  }}
                >
                  {t === 'threats'
                    ? `THREATS (${threats.length})`
                    : `ALL (${scanResults.length})`}
                </button>
              ))}
            </div>
            <div style={{
              fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)',
            }}>
              {displayed.length} result{displayed.length !== 1 ? 's' : ''}
            </div>
          </div>
        )}

        {/* Content */}
        {scanning ? (
          <div style={{
            flex: 1, display: 'flex', flexDirection: 'column',
            alignItems: 'center', justifyContent: 'center', gap: 16,
          }}>
            <div style={{ animation: 'spin 1s linear infinite' }}>
              <Loader size={28} color={
                scanMode === 'all' ? 'var(--cyan)' :
                scanMode === 'quick' ? 'var(--amber)' :
                'var(--green)'
              } />
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 8 }}>
              <div style={{
                fontFamily: 'var(--font-mono)', fontSize: 12,
                color: scanMode === 'all' ? 'var(--cyan)' : scanMode === 'quick' ? 'var(--amber)' : 'var(--green)',
              }}>
                {scanMode === 'all' ? 'SCANNING ALL...' : scanMode === 'quick' ? 'QUICK SCAN...' : 'SCANNING...'}
              </div>
              {/* Elapsed timer — visible for all scan modes */}
              <div style={{
                display: 'flex', alignItems: 'center', gap: 6,
                padding: '4px 12px',
                background: 'var(--elevated)',
                border: '1px solid var(--border)',
                borderRadius: 4,
              }}>
                <Clock size={11} color="var(--text-dim)" />
                <span style={{
                  fontFamily: 'var(--font-mono)', fontSize: 13,
                  color: scanMode === 'all' ? 'var(--cyan)' : 'var(--green)',
                  fontWeight: 600, minWidth: 48, textAlign: 'center',
                }}>
                  {formatElapsed(elapsedSecs)}
                </span>
              </div>
              {(scanMode === 'all' || scanMode === 'quick') && (
                <div style={{
                  fontFamily: 'var(--font-mono)', fontSize: 10,
                  color: 'var(--text-dim)', maxWidth: 360, textAlign: 'center',
                }}>
                  {scanMode === 'quick'
                    ? 'Scanning Downloads · Desktop · AppData · Temp · Tasks · Drivers'
                    : 'Scanning Users · Windows · Program Files · ProgramData'}
                </div>
              )}
            </div>
          </div>
        ) : scanError ? (
          <div style={{
            flex: 1, display: 'flex', flexDirection: 'column',
            alignItems: 'center', justifyContent: 'center', gap: 8,
          }}>
            <AlertTriangle size={28} color="var(--red)" />
            <div style={{
              fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--red)',
              maxWidth: 400, textAlign: 'center',
            }}>
              {scanError}
            </div>
          </div>
        ) : scanResults.length === 0 ? (
          <div style={{
            flex: 1, display: 'flex', flexDirection: 'column',
            alignItems: 'center', justifyContent: 'center', gap: 12, opacity: 0.5,
          }}>
            <FileSearch size={40} color="var(--text-dim)" />
            <div style={{
              fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-dim)',
            }}>
              Type a path above or use Browse — then click Scan
            </div>
          </div>
        ) : displayed.length === 0 ? (
          <div style={{
            flex: 1, display: 'flex', flexDirection: 'column',
            alignItems: 'center', justifyContent: 'center', gap: 12,
          }}>
            <CheckCircle size={40} color="var(--green)" />
            <div style={{
              fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--green)',
            }}>
              No threats detected — all files are clean
            </div>
          </div>
        ) : (
          <div style={{ flex: 1, overflowY: 'auto' }}>
            {displayed.map((r, i) => (
              <ResultRow key={r.path + i} result={r} index={i} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
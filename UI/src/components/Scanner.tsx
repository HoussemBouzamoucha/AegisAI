// src/components/Scanner.tsx
import { useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { useStore } from '../store';
import {
  FolderOpen, FileSearch, X, AlertTriangle,
  CheckCircle, Loader, ChevronDown, ChevronRight,
  Shield, Zap, Tag,
} from 'lucide-react';
import type { ScanResult, ContextFlag, DetectionSignal } from '../types';
import { CONTEXT_FLAG_LABEL, CONTEXT_FLAG_SEVERITY } from '../types';

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

// ─── Main Scanner component ───────────────────────────────────────────────────

export default function Scanner() {
  const {
    scanning, scanResults, scanStats, scanError,
    scanFile, scanDirectory, clearScan,
  } = useStore();

  const [tab, setTab] = useState<'threats' | 'all'>('threats');
  const [pathInput, setPathInput] = useState('');

  const handleScanFile = () => {
    if (!pathInput.trim()) return;
    clearScan();
    scanFile(pathInput.trim());
  };

  const handleScanDir = () => {
    if (!pathInput.trim()) return;
    clearScan();
    scanDirectory(pathInput.trim());
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

        <div style={{ display: 'flex', gap: 8 }}>
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
              <Loader size={28} color="var(--green)" />
            </div>
            <div style={{
              fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--green)',
            }}>
              SCANNING...
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
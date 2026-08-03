// UI/src/components/AutonomousLog.tsx
// Displays auto-executed actions from autonomous mode with per-action and bulk rollback.

import { useStore } from '../store';

const ACTION_LABEL: Record<string, string> = {
  quarantine_file: 'QUARANTINE FILE',
  block_ip:        'BLOCK IP',
  dump_memory:     'DUMP MEMORY',
};

const ACTION_COLOR: Record<string, string> = {
  quarantine_file: '#e879f9',
  block_ip:        '#f97316',
  dump_memory:     '#a78bfa',
};

export default function AutonomousLog() {
  const {
    autoActionLog, autoRunning,
    rollbackAutoAction, rollbackAllAutoActions, clearAutoLog,
  } = useStore();

  if (autoActionLog.length === 0 && !autoRunning) return null;

  const successCount  = autoActionLog.filter(a => a.result === 'success').length;
  const rollbackCount = autoActionLog.filter(a => a.rolledBack).length;
  const hasRollbackable = autoActionLog.some(
    a => a.reversible && !a.rolledBack && a.result === 'success',
  );

  return (
    <div style={{
      background: 'rgba(255,51,85,0.05)',
      border: '1px solid rgba(255,51,85,0.3)',
      borderRadius: 10, padding: 14,
      display: 'flex', flexDirection: 'column', gap: 10,
    }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <div style={{
          width: 6, height: 6, borderRadius: '50%',
          background: autoRunning ? '#ffb300' : '#ff3355',
          animation: autoRunning ? 'pulse 1s infinite' : 'none',
          flexShrink: 0,
        }} />
        <div style={{
          fontFamily: 'var(--font-hud)', fontSize: 9, letterSpacing: '0.1em',
          color: '#ff3355', flex: 1,
        }}>
          AUTO MODE {autoRunning ? '— EXECUTING…' : `— ${successCount} ACTION${successCount !== 1 ? 'S' : ''} TAKEN`}
        </div>
        <button
          onClick={clearAutoLog}
          style={{
            background: 'transparent', border: 'none',
            color: 'var(--text-dim)', cursor: 'pointer', fontSize: 11, flexShrink: 0,
          }}
          title="Clear log"
        >✕</button>
      </div>

      {/* Bulk rollback */}
      {hasRollbackable && (
        <button
          onClick={rollbackAllAutoActions}
          style={{
            padding: '6px 10px', borderRadius: 5,
            background: 'rgba(0,255,136,0.08)', border: '1px solid rgba(0,255,136,0.3)',
            color: 'var(--green)', fontFamily: 'var(--font-hud)', fontSize: 8,
            letterSpacing: '0.1em', cursor: 'pointer', textAlign: 'center',
          }}
        >
          ↩ ROLLBACK ALL REVERSIBLE
        </button>
      )}

      {rollbackCount > 0 && rollbackCount === successCount && (
        <div style={{
          padding: '5px 8px', borderRadius: 4,
          background: 'rgba(0,255,136,0.07)', border: '1px solid rgba(0,255,136,0.2)',
          fontFamily: 'var(--font-mono)', fontSize: 8, color: 'var(--green)',
          textAlign: 'center',
        }}>
          All actions rolled back
        </div>
      )}

      {/* Action list */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        {autoActionLog.map((entry) => {
          const col = ACTION_COLOR[entry.action] ?? '#00d4ff';
          const label = ACTION_LABEL[entry.action] ?? entry.action.toUpperCase();
          const canRollback = entry.reversible && !entry.rolledBack && entry.result === 'success';

          return (
            <div key={entry.id} style={{
              borderLeft: `3px solid ${col}60`,
              paddingLeft: 10,
              display: 'flex', flexDirection: 'column', gap: 4,
              opacity: entry.rolledBack ? 0.5 : 1,
            }}>
              {/* Action type + status */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <span style={{
                  fontFamily: 'var(--font-hud)', fontSize: 8, fontWeight: 700,
                  color: col, letterSpacing: '0.08em',
                }}>
                  {label}
                </span>
                <StatusBadge result={entry.result} rolledBack={entry.rolledBack} />
              </div>

              {/* Target */}
              <div style={{
                fontFamily: 'var(--font-mono)', fontSize: 8, color: 'var(--text-dim)',
                overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
              }} title={entry.target}>
                {entry.target}
              </div>

              {/* Error */}
              {entry.error && (
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 7, color: '#ff3355' }}>
                  {entry.error}
                </div>
              )}

              {/* Rollback error */}
              {entry.rollbackError && (
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 7, color: '#ff3355' }}>
                  Rollback failed: {entry.rollbackError}
                </div>
              )}

              {/* Rollback button */}
              {canRollback && (
                <button
                  onClick={() => rollbackAutoAction(entry.id)}
                  style={{
                    alignSelf: 'flex-start',
                    padding: '3px 8px', borderRadius: 3,
                    background: 'rgba(0,255,136,0.07)', border: '1px solid rgba(0,255,136,0.25)',
                    color: 'var(--green)', fontFamily: 'var(--font-mono)', fontSize: 7,
                    cursor: 'pointer',
                  }}
                >
                  ↩ rollback
                </button>
              )}
            </div>
          );
        })}
      </div>

      {/* Footer note */}
      <div style={{
        fontFamily: 'var(--font-mono)', fontSize: 7, color: 'var(--text-dim)',
        borderTop: '1px solid var(--border)', paddingTop: 8, lineHeight: 1.5,
      }}>
        Only reversible actions (quarantine, block IP) are auto-executed.
        Kill process and network isolation require manual approval.
      </div>
    </div>
  );
}

function StatusBadge({ result, rolledBack }: { result: string; rolledBack: boolean }) {
  if (rolledBack) {
    return (
      <span style={{
        padding: '1px 5px', borderRadius: 2,
        background: 'rgba(0,255,136,0.1)', border: '1px solid rgba(0,255,136,0.25)',
        fontFamily: 'var(--font-hud)', fontSize: 7, color: 'var(--green)',
      }}>ROLLED BACK</span>
    );
  }
  if (result === 'success') {
    return (
      <span style={{
        padding: '1px 5px', borderRadius: 2,
        background: 'rgba(0,212,255,0.1)', border: '1px solid rgba(0,212,255,0.25)',
        fontFamily: 'var(--font-hud)', fontSize: 7, color: 'var(--cyan)',
      }}>DONE</span>
    );
  }
  if (result === 'failed') {
    return (
      <span style={{
        padding: '1px 5px', borderRadius: 2,
        background: 'rgba(255,51,85,0.1)', border: '1px solid rgba(255,51,85,0.25)',
        fontFamily: 'var(--font-hud)', fontSize: 7, color: '#ff3355',
      }}>FAILED</span>
    );
  }
  return (
    <span style={{
      padding: '1px 5px', borderRadius: 2,
      background: 'rgba(255,179,0,0.1)', border: '1px solid rgba(255,179,0,0.25)',
      fontFamily: 'var(--font-hud)', fontSize: 7, color: 'var(--amber)',
    }}>PENDING</span>
  );
}

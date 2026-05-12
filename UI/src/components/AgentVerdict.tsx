// File: UI/src/components/AgentVerdict.tsx
//
// Agent verdict panel — shows the AI's ranked action plan (Round 1+).
// Round 2+ adds: execute buttons, investigation-closed banner, round badge,
// warnings display, and a Re-assess button.

import { useState, useCallback } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { useStore } from '../store';
import type { RankedAction, ExecutedAction } from '../types';

// ─── Colour maps ──────────────────────────────────────────────────────────────

const RISK_COLOR: Record<string, string> = {
  Low:      '#00ff88',
  Medium:   '#ffb300',
  High:     '#ff7b00',
  Critical: '#ff3355',
};

const ACTION_COLOR: Record<string, string> = {
  kill_process:      '#ff3355',
  quarantine_file:   '#ffb300',
  block_ip:          '#00d4ff',
  dump_memory:       '#a78bfa',
  check_persistence: '#34d399',
  isolate_network:   '#ff3355',
  remove_block_ip:   '#00d4ff',
};

const ACTION_ICON: Record<string, string> = {
  kill_process:      '⚡',
  quarantine_file:   '🔒',
  block_ip:          '🛡',
  dump_memory:       '💾',
  check_persistence: '🔍',
  isolate_network:   '🔌',
  remove_block_ip:   '↩',
};

const CLOSE_REASON_LABEL: Record<string, string> = {
  resolved:            'All threats resolved — investigation closed.',
  no_improvement:      'Threat score did not decrease — further actions may not help.',
  max_rounds_reached:  'Maximum reassessment rounds reached.',
};

// ─── Action → Tauri command + args mapping ────────────────────────────────────

function buildTauriArgs(action: RankedAction): { cmd: string; args: Record<string, unknown> } {
  switch (action.action) {
    case 'kill_process':
      return { cmd: 'kill_process', args: { pid: action.pid } };
    case 'quarantine_file':
      return { cmd: 'quarantine_file', args: { path: action.target } };
    case 'block_ip':
      return { cmd: 'block_ip', args: { remote_ip: action.target, direction: 'out' } };
    case 'dump_memory':
      return { cmd: 'dump_memory', args: { pid: action.pid } };
    case 'check_persistence':
      return { cmd: 'check_persistence', args: { suspicious_paths: [action.target] } };
    case 'isolate_network':
      return { cmd: 'isolate_network', args: {} };
    case 'remove_block_ip':
      return { cmd: 'remove_block_ip', args: { rule_name: action.target } };
    default:
      return { cmd: action.action, args: { target: action.target } };
  }
}

// ─── Sub-components ───────────────────────────────────────────────────────────

type ExecStatus = 'idle' | 'running' | 'done' | 'error';

function ActionCard({
  action,
  index,
  onExecuted,
}: {
  action:     RankedAction;
  index:      number;
  onExecuted: (executed: ExecutedAction) => void;
}) {
  const accentColor = ACTION_COLOR[action.action] ?? '#00d4ff';
  const icon        = ACTION_ICON[action.action]  ?? '•';
  const [status, setStatus] = useState<ExecStatus>('idle');
  const [result, setResult] = useState<string | null>(null);

  const handleExecute = useCallback(async () => {
    setStatus('running');
    setResult(null);
    const { cmd, args } = buildTauriArgs(action);
    const executedAt = new Date().toISOString();
    try {
      const res = await invoke(cmd, args);
      const text = typeof res === 'string' ? res : JSON.stringify(res, null, 2);
      setResult(text);
      setStatus('done');
      onExecuted({
        action:      action.action,
        target:      action.target,
        entity_id:   action.entity_id,
        executed_at: executedAt,
        result:      'success',
        pid:         action.pid ?? null,
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setResult(msg);
      setStatus('error');
      onExecuted({
        action:      action.action,
        target:      action.target,
        entity_id:   action.entity_id,
        executed_at: executedAt,
        result:      'failed',
        pid:         action.pid ?? null,
      });
    }
  }, [action, onExecuted]);

  return (
    <div style={{
      background: status === 'done'  ? 'rgba(0,255,136,0.04)'
                : status === 'error' ? 'rgba(255,51,85,0.05)'
                : 'var(--elevated)',
      border: `1px solid ${
        status === 'done'  ? 'rgba(0,255,136,0.25)'
        : status === 'error' ? 'rgba(255,51,85,0.25)'
        : `${accentColor}30`}`,
      borderLeft: `3px solid ${accentColor}`,
      borderRadius: 6,
      padding: '8px 10px',
      display: 'flex',
      flexDirection: 'column',
      gap: 4,
    }}>
      {/* Header row */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
        <span style={{ fontSize: 11 }}>{icon}</span>
        <span style={{
          fontFamily: 'var(--font-mono)',
          fontSize: 10,
          fontWeight: 700,
          color: accentColor,
          flex: 1,
        }}>
          {action.action}
        </span>
        <span style={{
          fontFamily: 'var(--font-hud)',
          fontSize: 8,
          color: 'var(--text-dim)',
          background: 'var(--surface)',
          borderRadius: 3,
          padding: '1px 4px',
        }}>
          #{index + 1}
        </span>
      </div>

      {/* Target */}
      <div style={{
        fontFamily: 'var(--font-mono)',
        fontSize: 9,
        color: 'var(--text-bright)',
        overflow: 'hidden',
        textOverflow: 'ellipsis',
        whiteSpace: 'nowrap',
      }}>
        {action.target}
        {action.pid != null && (
          <span style={{ color: 'var(--text-dim)', marginLeft: 4 }}>
            pid {action.pid}
          </span>
        )}
      </div>

      {/* Justification */}
      <div style={{
        fontFamily: 'var(--font-mono)',
        fontSize: 8.5,
        color: 'var(--text-dim)',
        lineHeight: 1.4,
      }}>
        {action.justification}
      </div>

      {/* Tag row */}
      <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap', marginTop: 2 }}>
        {action.reversible ? (
          <span style={{ fontFamily: 'var(--font-hud)', fontSize: 7.5, color: '#00ff88',
            background: 'rgba(0,255,136,0.1)', borderRadius: 3, padding: '1px 5px' }}>
            reversible
          </span>
        ) : (
          <span style={{ fontFamily: 'var(--font-hud)', fontSize: 7.5, color: '#ff3355',
            background: 'rgba(255,51,85,0.1)', borderRadius: 3, padding: '1px 5px' }}>
            irreversible
          </span>
        )}
        {action.confirm_required && (
          <span style={{ fontFamily: 'var(--font-hud)', fontSize: 7.5, color: '#ffb300',
            background: 'rgba(255,179,0,0.1)', borderRadius: 3, padding: '1px 5px' }}>
            confirm required
          </span>
        )}
        {status === 'done' && (
          <span style={{ fontFamily: 'var(--font-hud)', fontSize: 7.5, color: '#00ff88',
            background: 'rgba(0,255,136,0.12)', borderRadius: 3, padding: '1px 5px' }}>
            executed
          </span>
        )}
        {status === 'error' && (
          <span style={{ fontFamily: 'var(--font-hud)', fontSize: 7.5, color: '#ff3355',
            background: 'rgba(255,51,85,0.12)', borderRadius: 3, padding: '1px 5px' }}>
            failed
          </span>
        )}
      </div>

      {/* Result text */}
      {result && (
        <div style={{
          fontFamily: 'var(--font-mono)',
          fontSize: 8,
          color: status === 'error' ? '#ff3355' : '#00ff88',
          background: status === 'error' ? 'rgba(255,51,85,0.07)' : 'rgba(0,255,136,0.06)',
          borderRadius: 3,
          padding: '4px 6px',
          whiteSpace: 'pre-wrap',
          wordBreak: 'break-all',
          maxHeight: 80,
          overflowY: 'auto',
        }}>
          {result}
        </div>
      )}

      {/* Execute button — hidden once done */}
      {status !== 'done' && (
        <button
          onClick={handleExecute}
          disabled={status === 'running'}
          style={{
            marginTop: 4,
            alignSelf: 'flex-start',
            padding: '4px 12px',
            background: status === 'running' ? 'rgba(0,212,255,0.12)' : accentColor,
            color: status === 'running' ? accentColor : '#000',
            border: `1px solid ${accentColor}`,
            borderRadius: 4,
            fontFamily: 'var(--font-mono)',
            fontSize: 9,
            fontWeight: 700,
            cursor: status === 'running' ? 'not-allowed' : 'pointer',
            letterSpacing: '0.06em',
          }}
        >
          {status === 'running' ? 'executing…' : status === 'error' ? 'RETRY' : 'EXECUTE'}
        </button>
      )}
    </div>
  );
}

// ─── Main panel ───────────────────────────────────────────────────────────────

export function AgentVerdictPanel() {
  const {
    agentVerdict,
    agentLoading,
    agentError,
    runAgentAnalysis,
    clearAgentVerdict,
    correlateResult,
    // Round 2+
    actionsTaken,
    currentRound,
    agentReassessing,
    agentReassessError,
    recordExecutedAction,
    runAgentReassessment,
  } = useStore();

  // Don't render at all until there's a graph to analyze
  if (!correlateResult) return null;

  const riskColor = agentVerdict
    ? (RISK_COLOR[agentVerdict.risk_level] ?? '#00d4ff')
    : '#00d4ff';

  const hasNewActions = actionsTaken.length > 0;

  return (
    <div style={{
      background: 'var(--surface)',
      border: '1px solid var(--border)',
      borderRadius: 10,
      padding: 14,
      display: 'flex',
      flexDirection: 'column',
      gap: 10,
    }}>
      {/* Section header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <span style={{
          fontFamily: 'var(--font-hud)',
          fontSize: 9,
          color: 'var(--text-dim)',
          letterSpacing: '0.1em',
          flex: 1,
        }}>
          AI ANALYSIS
        </span>
        {/* Round badge */}
        {agentVerdict && currentRound > 1 && (
          <span style={{
            fontFamily: 'var(--font-hud)',
            fontSize: 7.5,
            color: '#a78bfa',
            background: 'rgba(167,139,250,0.12)',
            border: '1px solid rgba(167,139,250,0.3)',
            borderRadius: 3,
            padding: '1px 6px',
          }}>
            ROUND {currentRound}
          </span>
        )}
      </div>

      {/* Idle — show trigger button */}
      {!agentVerdict && !agentLoading && !agentError && (
        <button
          onClick={runAgentAnalysis}
          style={{
            width: '100%',
            padding: '8px 0',
            background: 'rgba(0,212,255,0.08)',
            border: '1px solid rgba(0,212,255,0.35)',
            borderRadius: 6,
            color: '#00d4ff',
            fontFamily: 'var(--font-hud)',
            fontSize: 10,
            letterSpacing: '0.08em',
            cursor: 'pointer',
          }}
        >
          ANALYZE WITH AI
        </button>
      )}

      {/* Loading (Round 1) */}
      {agentLoading && (
        <div style={{
          textAlign: 'center',
          fontFamily: 'var(--font-mono)',
          fontSize: 9,
          color: 'var(--text-dim)',
          padding: '10px 0',
        }}>
          Consulting threat analysis engine…
        </div>
      )}

      {/* Reassessing (Round 2+) */}
      {agentReassessing && (
        <div style={{
          display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 6,
          padding: '10px 0',
        }}>
          <div style={{
            fontFamily: 'var(--font-mono)',
            fontSize: 9,
            color: '#a78bfa',
          }}>
            Re-correlating and reassessing…
          </div>
          <div style={{
            fontFamily: 'var(--font-hud)',
            fontSize: 7.5,
            color: 'var(--text-dim)',
          }}>
            ROUND {currentRound + 1}
          </div>
        </div>
      )}

      {/* Error (Round 1) */}
      {agentError && !agentLoading && (
        <>
          <div style={{
            fontFamily: 'var(--font-mono)',
            fontSize: 8.5,
            color: '#ff3355',
            background: 'rgba(255,51,85,0.08)',
            border: '1px solid rgba(255,51,85,0.25)',
            borderRadius: 6,
            padding: '8px 10px',
            lineHeight: 1.5,
          }}>
            {agentError}
          </div>
          <button
            onClick={runAgentAnalysis}
            style={{
              padding: '6px 0',
              background: 'transparent',
              border: '1px solid var(--border)',
              borderRadius: 6,
              color: 'var(--text-dim)',
              fontFamily: 'var(--font-hud)',
              fontSize: 9,
              cursor: 'pointer',
            }}
          >
            RETRY
          </button>
        </>
      )}

      {/* Reassess error */}
      {agentReassessError && !agentReassessing && (
        <div style={{
          fontFamily: 'var(--font-mono)',
          fontSize: 8.5,
          color: '#ff3355',
          background: 'rgba(255,51,85,0.07)',
          border: '1px solid rgba(255,51,85,0.2)',
          borderRadius: 5,
          padding: '6px 8px',
          lineHeight: 1.5,
        }}>
          Re-assess error: {agentReassessError}
        </div>
      )}

      {/* Verdict */}
      {agentVerdict && !agentLoading && !agentReassessing && (
        <>
          {/* Investigation closed banner */}
          {agentVerdict.investigation_closed && (
            <div style={{
              background: agentVerdict.close_reason === 'resolved'
                ? 'rgba(0,255,136,0.08)' : 'rgba(255,179,0,0.07)',
              border: `1px solid ${agentVerdict.close_reason === 'resolved'
                ? 'rgba(0,255,136,0.3)' : 'rgba(255,179,0,0.3)'}`,
              borderRadius: 6,
              padding: '8px 10px',
              fontFamily: 'var(--font-mono)',
              fontSize: 8.5,
              color: agentVerdict.close_reason === 'resolved' ? '#00ff88' : '#ffb300',
              lineHeight: 1.5,
            }}>
              {CLOSE_REASON_LABEL[agentVerdict.close_reason ?? '']
                ?? `Investigation closed: ${agentVerdict.close_reason}`}
            </div>
          )}

          {/* Warnings */}
          {agentVerdict.warnings.length > 0 && (
            <div style={{
              background: 'rgba(255,179,0,0.05)',
              border: '1px solid rgba(255,179,0,0.2)',
              borderRadius: 5,
              padding: '6px 8px',
              display: 'flex',
              flexDirection: 'column',
              gap: 3,
            }}>
              <div style={{ fontFamily: 'var(--font-hud)', fontSize: 7.5, color: '#ffb300', letterSpacing: '0.07em' }}>
                VALIDATION WARNINGS
              </div>
              {agentVerdict.warnings.map((w, i) => (
                <div key={i} style={{ fontFamily: 'var(--font-mono)', fontSize: 7.5, color: '#ffb300', opacity: 0.8 }}>
                  {w}
                </div>
              ))}
            </div>
          )}

          {/* Risk badge + confidence */}
          <div style={{ display: 'flex', alignItems: 'baseline', gap: 8 }}>
            <span style={{
              fontFamily: 'var(--font-hud)',
              fontSize: 16,
              fontWeight: 700,
              color: riskColor,
              textShadow: `0 0 12px ${riskColor}80`,
            }}>
              {agentVerdict.risk_level.toUpperCase()}
            </span>
            <span style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 9,
              color: 'var(--text-dim)',
            }}>
              {Math.round(agentVerdict.confidence * 100)}% confidence
            </span>
            <button
              onClick={clearAgentVerdict}
              style={{
                marginLeft: 'auto',
                background: 'transparent',
                border: 'none',
                color: 'var(--text-dim)',
                fontFamily: 'var(--font-mono)',
                fontSize: 9,
                cursor: 'pointer',
                padding: 0,
              }}
              title="Clear verdict and reset investigation"
            >
              ✕
            </button>
          </div>

          {/* Rationale */}
          <div style={{
            fontFamily: 'var(--font-mono)',
            fontSize: 8.5,
            color: 'var(--text-dim)',
            lineHeight: 1.55,
          }}>
            {agentVerdict.rationale}
          </div>

          {/* Ranked actions */}
          {agentVerdict.ranked_actions.length > 0 ? (
            <>
              <div style={{
                fontFamily: 'var(--font-hud)',
                fontSize: 8,
                color: 'var(--text-dim)',
                letterSpacing: '0.08em',
                marginTop: 2,
              }}>
                RECOMMENDED ACTIONS ({agentVerdict.ranked_actions.length})
              </div>
              {agentVerdict.ranked_actions.map((a, i) => (
                <ActionCard
                  key={i}
                  action={a}
                  index={i}
                  onExecuted={recordExecutedAction}
                />
              ))}
            </>
          ) : (
            <div style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 8.5,
              color: 'var(--text-dim)',
            }}>
              {agentVerdict.investigation_closed
                ? 'No further actions recommended.'
                : 'No containment actions recommended.'}
            </div>
          )}

          {/* Re-assess button — shown after any action executed and investigation not closed */}
          {hasNewActions && !agentVerdict.investigation_closed && (
            <button
              onClick={runAgentReassessment}
              disabled={agentReassessing}
              style={{
                marginTop: 4,
                padding: '7px 0',
                background: 'rgba(167,139,250,0.1)',
                border: '1px solid rgba(167,139,250,0.4)',
                borderRadius: 6,
                color: '#a78bfa',
                fontFamily: 'var(--font-hud)',
                fontSize: 9,
                letterSpacing: '0.08em',
                cursor: agentReassessing ? 'not-allowed' : 'pointer',
              }}
            >
              RE-ASSESS WITH AI ({actionsTaken.length} action{actionsTaken.length !== 1 ? 's' : ''} taken)
            </button>
          )}

          {/* Pivot suggestions */}
          {agentVerdict.pivot_suggestions.length > 0 && (
            <>
              <div style={{ height: 1, background: 'var(--border)', margin: '2px 0' }} />
              <div style={{
                fontFamily: 'var(--font-hud)',
                fontSize: 8,
                color: 'var(--text-dim)',
                letterSpacing: '0.08em',
              }}>
                SUGGESTED FOLLOW-UPS
              </div>
              {agentVerdict.pivot_suggestions.map((s, i) => (
                <div key={i} style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: 8.5,
                  color: 'var(--text-dim)',
                  background: 'var(--elevated)',
                  borderRadius: 5,
                  padding: '6px 8px',
                  lineHeight: 1.5,
                }}>
                  → {s}
                </div>
              ))}
            </>
          )}

          {/* Actions taken summary */}
          {actionsTaken.length > 0 && (
            <>
              <div style={{ height: 1, background: 'var(--border)', margin: '2px 0' }} />
              <div style={{
                fontFamily: 'var(--font-hud)',
                fontSize: 8,
                color: 'var(--text-dim)',
                letterSpacing: '0.08em',
              }}>
                ACTIONS TAKEN ({actionsTaken.length})
              </div>
              {actionsTaken.map((a, i) => (
                <div key={i} style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: 7.5,
                  color: a.result === 'success' ? '#00ff88' : '#ff3355',
                  background: 'var(--elevated)',
                  borderRadius: 4,
                  padding: '4px 7px',
                  display: 'flex',
                  gap: 6,
                }}>
                  <span style={{ opacity: 0.7 }}>#{i + 1}</span>
                  <span style={{ fontWeight: 700 }}>{a.action}</span>
                  <span style={{ color: 'var(--text-dim)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {a.target}
                  </span>
                  <span style={{ flexShrink: 0 }}>{a.result}</span>
                </div>
              ))}
            </>
          )}

          {/* Re-analyze / Reset buttons */}
          <div style={{ display: 'flex', gap: 6, marginTop: 2 }}>
            {!agentVerdict.investigation_closed && (
              <button
                onClick={runAgentAnalysis}
                style={{
                  flex: 1,
                  padding: '5px 0',
                  background: 'transparent',
                  border: '1px solid var(--border)',
                  borderRadius: 6,
                  color: 'var(--text-dim)',
                  fontFamily: 'var(--font-hud)',
                  fontSize: 8.5,
                  letterSpacing: '0.06em',
                  cursor: 'pointer',
                }}
              >
                RE-ANALYZE
              </button>
            )}
            {actionsTaken.length > 0 && (
              <button
                onClick={() => useStore.getState().resetInvestigation()}
                style={{
                  flex: 1,
                  padding: '5px 0',
                  background: 'transparent',
                  border: '1px solid var(--border)',
                  borderRadius: 6,
                  color: 'var(--text-dim)',
                  fontFamily: 'var(--font-hud)',
                  fontSize: 8.5,
                  letterSpacing: '0.06em',
                  cursor: 'pointer',
                }}
              >
                RESET
              </button>
            )}
          </div>
        </>
      )}
    </div>
  );
}

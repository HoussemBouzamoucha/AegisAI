// File: UI/src/components/AgentVerdict.tsx
//
// Agent Round 1 verdict panel — shows the AI's ranked action plan.
// Rendered inside the ThreatGraph right-side panel (LegendPanel).
//
// Uses the same inline-style design system as ThreatGraph.tsx:
//   CSS variables: --surface, --border, --text-dim, --text-bright,
//                  --font-mono, --font-hud, --elevated
//   Accent colours from the existing palette.

import { useStore } from '../store';
import type { RankedAction } from '../types';

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

// ─── Sub-components ───────────────────────────────────────────────────────────

function ActionCard({ action, index }: { action: RankedAction; index: number }) {
  const accentColor = ACTION_COLOR[action.action] ?? '#00d4ff';
  const icon        = ACTION_ICON[action.action]  ?? '•';

  return (
    <div style={{
      background: 'var(--elevated)',
      border: `1px solid ${accentColor}30`,
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
      </div>
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
  } = useStore();

  // Don't render at all until there's a graph to analyze
  if (!correlateResult) return null;

  const riskColor = agentVerdict
    ? (RISK_COLOR[agentVerdict.risk_level] ?? '#00d4ff')
    : '#00d4ff';

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
      <div style={{
        fontFamily: 'var(--font-hud)',
        fontSize: 9,
        color: 'var(--text-dim)',
        letterSpacing: '0.1em',
      }}>
        AI ANALYSIS
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

      {/* Loading */}
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

      {/* Error */}
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

      {/* Verdict */}
      {agentVerdict && !agentLoading && (
        <>
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
              title="Clear and re-analyze"
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
                <ActionCard key={i} action={a} index={i} />
              ))}
            </>
          ) : (
            <div style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 8.5,
              color: 'var(--text-dim)',
            }}>
              No containment actions recommended.
            </div>
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

          {/* Re-analyze button */}
          <button
            onClick={runAgentAnalysis}
            style={{
              marginTop: 2,
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
        </>
      )}
    </div>
  );
}

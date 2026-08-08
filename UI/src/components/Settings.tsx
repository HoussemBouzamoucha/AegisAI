import { useState } from 'react';
import { Zap, Brain, ScanLine, Shield, Eye, ChevronDown, ChevronUp } from 'lucide-react';
import { useStore } from '../store';
import type { AutoAllowedActions } from '../types';

// ─── Toggle ───────────────────────────────────────────────────────────────────

function Toggle({ checked, onChange }: { checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <button
      onClick={() => onChange(!checked)}
      style={{
        width: 40, height: 20, borderRadius: 10, border: 'none', padding: 0,
        background: checked ? 'var(--green)' : 'rgba(255,255,255,0.08)',
        cursor: 'pointer', position: 'relative', flexShrink: 0,
        transition: 'background 0.25s',
        boxShadow: checked ? '0 0 10px rgba(0,255,136,0.4)' : 'none',
      }}
    >
      <div style={{
        position: 'absolute', top: 4,
        left: checked ? 24 : 4,
        width: 12, height: 12, borderRadius: '50%',
        background: checked ? '#000' : 'var(--text-dim)',
        transition: 'left 0.25s',
      }} />
    </button>
  );
}

// ─── Card ─────────────────────────────────────────────────────────────────────

function Card({ icon, title, accentColor = 'var(--green)', children }: {
  icon: React.ReactNode;
  title: string;
  accentColor?: string;
  children: React.ReactNode;
}) {
  return (
    <div style={{
      background: 'var(--surface)',
      border: '1px solid var(--border)',
      borderRadius: 10,
      overflow: 'hidden',
      position: 'relative',
    }}>
      {/* Left accent bar */}
      <div style={{
        position: 'absolute', top: 0, left: 0,
        width: 3, height: '100%',
        background: accentColor,
        boxShadow: `0 0 14px ${accentColor}`,
      }} />

      {/* Header */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 10,
        padding: '16px 20px 16px 24px',
        borderBottom: '1px solid var(--border)',
      }}>
        <span style={{ color: accentColor }}>{icon}</span>
        <span style={{
          fontFamily: 'var(--font-hud)', fontSize: 11,
          letterSpacing: '0.14em', color: 'var(--text-bright)',
        }}>
          {title}
        </span>
      </div>

      <div style={{ padding: '20px 20px 20px 24px', display: 'flex', flexDirection: 'column', gap: 18 }}>
        {children}
      </div>
    </div>
  );
}

// ─── Setting row ──────────────────────────────────────────────────────────────

function SettingRow({ label, description, children }: {
  label: string;
  description?: string;
  children: React.ReactNode;
}) {
  return (
    <div style={{ display: 'flex', alignItems: 'flex-start', gap: 16 }}>
      <div style={{ flex: 1 }}>
        <div style={{
          fontFamily: 'var(--font-body)', fontSize: 13, fontWeight: 500,
          color: 'var(--text-bright)', marginBottom: description ? 4 : 0,
        }}>
          {label}
        </div>
        {description && (
          <div style={{
            fontFamily: 'var(--font-body)', fontSize: 12,
            color: 'var(--text-dim)', lineHeight: 1.6,
          }}>
            {description}
          </div>
        )}
      </div>
      <div style={{ paddingTop: 2, flexShrink: 0 }}>{children}</div>
    </div>
  );
}

function Divider() {
  return <div style={{ borderTop: '1px solid var(--border)' }} />;
}

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <div style={{
      fontFamily: 'var(--font-hud)', fontSize: 9,
      letterSpacing: '0.14em', color: 'var(--text-dim)',
      marginBottom: -4,
    }}>
      {children}
    </div>
  );
}

function InfoBox({ children }: { children: React.ReactNode }) {
  return (
    <div style={{
      padding: '10px 14px',
      background: 'var(--elevated)',
      border: '1px solid var(--border)',
      borderRadius: 6,
      fontFamily: 'var(--font-body)', fontSize: 12,
      color: 'var(--text-dim)', lineHeight: 1.6,
    }}>
      {children}
    </div>
  );
}

function ModelBadge({ k, label, note }: { k: string; label: string; note: string }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
      <span style={{
        fontFamily: 'var(--font-mono)', fontSize: 9,
        color: 'var(--green)', background: 'rgba(0,255,136,0.08)',
        border: '1px solid rgba(0,255,136,0.2)',
        borderRadius: 4, padding: '2px 7px', flexShrink: 0,
        letterSpacing: '0.04em',
      }}>
        {k}
      </span>
      <span style={{ fontFamily: 'var(--font-body)', fontSize: 12, color: 'var(--text)', flex: 1 }}>{label}</span>
      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)', flexShrink: 0 }}>{note}</span>
    </div>
  );
}

function StatusDot({ ok, label, value }: { ok: boolean; label: string; value: string }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
      <div style={{
        width: 6, height: 6, borderRadius: '50%', flexShrink: 0,
        background: ok ? 'var(--green)' : 'var(--text-dim)',
        boxShadow: ok ? '0 0 6px var(--green)' : 'none',
      }} />
      <span style={{ fontFamily: 'var(--font-body)', fontSize: 13, color: 'var(--text)', flex: 1 }}>{label}</span>
      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: ok ? 'var(--green)' : 'var(--text-dim)' }}>{value}</span>
    </div>
  );
}

// ─── Main ─────────────────────────────────────────────────────────────────────

export default function Settings() {
  const {
    autonomousMode, setAutonomousMode,
    autoAllowedActions, setAutoAllowedActions,
    emberMlEnabled, setEmberMlEnabled,
    realtimeRunning, realtimeThreats, realtimeError,
    startRealtime, stopRealtime,
  } = useStore();

  const [expandedThreat, setExpandedThreat] = useState<number | null>(null);

  function toggleAction(key: keyof AutoAllowedActions) {
    setAutoAllowedActions({ ...autoAllowedActions, [key]: !autoAllowedActions[key] });
  }

  return (
    <div style={{
      height: '100%', overflow: 'auto',
      padding: '36px 32px',
      background: 'var(--void)',
    }}>
      <div style={{ maxWidth: 900, margin: '0 auto' }}>

        {/* ── Page header ─────────────────────────────────────────────────── */}
        <div style={{ marginBottom: 36 }}>
          <div style={{
            fontFamily: 'var(--font-hud)', fontSize: 22,
            letterSpacing: '0.18em', color: 'var(--text-bright)',
            marginBottom: 8,
            textShadow: '0 0 20px rgba(0,255,136,0.3)',
          }}>
            SETTINGS
          </div>
          <div style={{ fontFamily: 'var(--font-body)', fontSize: 13, color: 'var(--text-dim)' }}>
            Configure autonomous behaviour, scan engine, and AI agent
          </div>
        </div>

        {/* ── Two-column grid ─────────────────────────────────────────────── */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }}>

          {/* Left column */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>

            {/* Autonomous Mode */}
            <Card icon={<Zap size={14} />} title="AUTONOMOUS MODE" accentColor="var(--red)">
              <SettingRow
                label="Enable Autonomous Mode"
                description="After each threat correlation, automatically run the AI agent and execute the safe reversible actions selected below."
              >
                <Toggle checked={autonomousMode} onChange={setAutonomousMode} />
              </SettingRow>

              <Divider />
              <SectionLabel>ALLOWED ACTIONS</SectionLabel>

              <SettingRow
                label="Quarantine File"
                description="Move malicious file to quarantine. Reversible."
              >
                <Toggle checked={autoAllowedActions.quarantine_file} onChange={() => toggleAction('quarantine_file')} />
              </SettingRow>

              <SettingRow
                label="Block IP"
                description="Add outbound firewall deny rule for C2 IP. Reversible."
              >
                <Toggle checked={autoAllowedActions.block_ip} onChange={() => toggleAction('block_ip')} />
              </SettingRow>

              <SettingRow
                label="Memory Dump"
                description="Write full MiniDump of malicious process to disk."
              >
                <Toggle checked={autoAllowedActions.dump_memory} onChange={() => toggleAction('dump_memory')} />
              </SettingRow>

              <InfoBox>
                Kill process and network isolation always require manual confirmation and are never executed automatically.
              </InfoBox>
            </Card>

            {/* Real-Time Protection */}
            <Card icon={<Eye size={14} />} title="REAL-TIME PROTECTION" accentColor="var(--cyan)">
              <SettingRow
                label="On-Access File Watcher"
                description="Watches Downloads, Desktop, Temp, and AppData for new or modified files. Each file is scanned through the full pipeline; Malicious files are auto-quarantined."
              >
                <Toggle
                  checked={realtimeRunning}
                  onChange={v => v ? startRealtime() : stopRealtime()}
                />
              </SettingRow>

              {realtimeError && (
                <div style={{
                  fontFamily: 'var(--font-mono)', fontSize: 10,
                  color: 'var(--red)', lineHeight: 1.5,
                }}>
                  {realtimeError}
                </div>
              )}

              {realtimeThreats.length > 0 && (
                <>
                  <Divider />
                  <SectionLabel>
                    SESSION THREATS — {realtimeThreats.length} CAUGHT
                  </SectionLabel>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                    {realtimeThreats.map((threat, i) => {
                      const isMalicious = threat.level === 'Malicious';
                      const accentColor = isMalicious ? 'var(--red)' : 'var(--amber)';
                      const accentRgb   = isMalicious ? '255,51,85' : '255,136,0';
                      const filename    = threat.path.split(/[\\/]/).pop() ?? threat.path;
                      const ts          = new Date(threat.timestamp_secs * 1000).toLocaleTimeString();
                      const isOpen      = expandedThreat === i;

                      return (
                        <div key={i} style={{
                          border: `1px solid rgba(${accentRgb},${isOpen ? '0.35' : '0.2'})`,
                          borderLeft: `3px solid ${accentColor}`,
                          borderRadius: 6,
                          overflow: 'hidden',
                          background: isOpen ? `rgba(${accentRgb},0.04)` : 'transparent',
                          transition: 'background 0.15s',
                        }}>
                          {/* Row header — always visible */}
                          <button
                            onClick={() => setExpandedThreat(isOpen ? null : i)}
                            style={{
                              width: '100%', display: 'flex', alignItems: 'center', gap: 8,
                              padding: '8px 10px',
                              background: 'none', border: 'none', cursor: 'pointer',
                              textAlign: 'left',
                            }}
                          >
                            {/* Level dot */}
                            <div style={{
                              width: 6, height: 6, borderRadius: '50%', flexShrink: 0,
                              background: accentColor,
                              boxShadow: `0 0 5px ${accentColor}`,
                            }} />

                            {/* Filename */}
                            <span style={{
                              fontFamily: 'var(--font-mono)', fontSize: 11,
                              color: 'var(--text-bright)', flex: 1,
                              overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                            }}>
                              {filename}
                            </span>

                            {/* Level badge */}
                            <span style={{
                              fontFamily: 'var(--font-mono)', fontSize: 8,
                              color: accentColor,
                              background: `rgba(${accentRgb},0.1)`,
                              border: `1px solid rgba(${accentRgb},0.3)`,
                              borderRadius: 3, padding: '1px 5px', flexShrink: 0,
                            }}>
                              {threat.level.toUpperCase()}
                            </span>

                            {/* Time */}
                            <span style={{
                              fontFamily: 'var(--font-mono)', fontSize: 9,
                              color: 'var(--text-dim)', flexShrink: 0,
                            }}>
                              {ts}
                            </span>

                            {/* Chevron */}
                            <span style={{ color: 'var(--text-dim)', flexShrink: 0 }}>
                              {isOpen ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
                            </span>
                          </button>

                          {/* Expanded detail panel */}
                          {isOpen && (
                            <div style={{
                              padding: '0 10px 10px 24px',
                              display: 'flex', flexDirection: 'column', gap: 8,
                              borderTop: `1px solid rgba(${accentRgb},0.15)`,
                              paddingTop: 10,
                            }}>
                              {/* Reason */}
                              <div>
                                <div style={{
                                  fontFamily: 'var(--font-hud)', fontSize: 8,
                                  letterSpacing: '0.12em', color: 'var(--text-dim)',
                                  marginBottom: 3,
                                }}>
                                  DETECTION REASON
                                </div>
                                <div style={{
                                  fontFamily: 'var(--font-body)', fontSize: 12,
                                  color: 'var(--text)', lineHeight: 1.6,
                                }}>
                                  {threat.reason || '—'}
                                </div>
                              </div>

                              {/* Full path */}
                              <div>
                                <div style={{
                                  fontFamily: 'var(--font-hud)', fontSize: 8,
                                  letterSpacing: '0.12em', color: 'var(--text-dim)',
                                  marginBottom: 3,
                                }}>
                                  FULL PATH
                                </div>
                                <div style={{
                                  fontFamily: 'var(--font-mono)', fontSize: 10,
                                  color: 'var(--text)', wordBreak: 'break-all', lineHeight: 1.5,
                                }}>
                                  {threat.path}
                                </div>
                              </div>

                              {/* Hash */}
                              {threat.hash && (
                                <div>
                                  <div style={{
                                    fontFamily: 'var(--font-hud)', fontSize: 8,
                                    letterSpacing: '0.12em', color: 'var(--text-dim)',
                                    marginBottom: 3,
                                  }}>
                                    SHA-256
                                  </div>
                                  <div style={{
                                    fontFamily: 'var(--font-mono)', fontSize: 9,
                                    color: 'var(--text)', wordBreak: 'break-all',
                                  }}>
                                    {threat.hash}
                                  </div>
                                </div>
                              )}

                              {/* Quarantine status */}
                              <div style={{ display: 'flex', gap: 6 }}>
                                {threat.quarantined && (
                                  <span style={{
                                    fontFamily: 'var(--font-mono)', fontSize: 8,
                                    color: 'var(--green)',
                                    background: 'rgba(0,255,136,0.08)',
                                    border: '1px solid rgba(0,255,136,0.25)',
                                    borderRadius: 3, padding: '2px 7px',
                                  }}>
                                    ✓ AUTO-QUARANTINED
                                  </span>
                                )}
                                <span style={{
                                  fontFamily: 'var(--font-mono)', fontSize: 8,
                                  color: 'var(--text-dim)',
                                  background: 'var(--elevated)',
                                  border: '1px solid var(--border)',
                                  borderRadius: 3, padding: '2px 7px',
                                }}>
                                  {new Date(threat.timestamp_secs * 1000).toLocaleString()}
                                </span>
                              </div>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </>
              )}

              <InfoBox>
                Race window: ~milliseconds between file write and scan (userspace). For zero-gap protection a kernel minifilter driver would be required.
              </InfoBox>
            </Card>

            {/* AI Agent */}
            <Card icon={<Brain size={14} />} title="AI AGENT">
              <SettingRow label="Analysis model" description="Self-correcting reasoning loop, Round 1 + re-assessment.">
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--green)' }}>
                  laguna-xs.2:free
                </span>
              </SettingRow>

              <SettingRow label="Report model" description="Human-readable Markdown incident report generation.">
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--green)' }}>
                  gpt-4o-mini
                </span>
              </SettingRow>

              <Divider />

              <SettingRow label="Analysis API key" description="OPENROUTER_API_KEY in ai_agent/.env">
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--green)' }}>● configured</span>
              </SettingRow>

              <SettingRow label="Report API key" description="OPENROUTER_REPORT_API_KEY in ai_agent/.env">
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--green)' }}>● configured</span>
              </SettingRow>

              <InfoBox>
                To update API keys edit <span style={{ color: 'var(--text)' }}>ai_agent/.env</span> and restart.
              </InfoBox>
            </Card>

          </div>

          {/* Right column */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>

            {/* Scan Engine */}
            <Card icon={<ScanLine size={14} />} title="SCAN ENGINE" accentColor="var(--cyan)">
              <SettingRow
                label="EMBER2024 ML"
                description="Run 14 LightGBM file-type models on suspicious files. Adds ~2–10 s per file on cold start. Significantly improves file threat scoring."
              >
                <Toggle checked={emberMlEnabled} onChange={setEmberMlEnabled} />
              </SettingRow>

              <Divider />
              <SectionLabel>MODEL ROUTING — 14 MODELS</SectionLabel>

              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                <ModelBadge k="Win32"         label="Windows PE 32-bit"    note="single" />
                <ModelBadge k="Win64"         label="Windows PE 64-bit"    note="single" />
                <ModelBadge k="DotNet"        label=".NET assembly"         note="single" />
                <ModelBadge k="packer"        label="Packed / crypted PE"   note="32 folds" />
                <ModelBadge k="behavior"      label="Scripts / behaviour"   note="92 folds" />
                <ModelBadge k="exploit"       label="Office exploit docs"   note="46 folds" />
                <ModelBadge k="group"         label="LNK / shortcut"        note="14 folds" />
                <ModelBadge k="file_property" label="Archives"              note="20 folds" />
                <ModelBadge k="PDF"           label="PDF documents"         note="single" />
                <ModelBadge k="ELF"           label="ELF binaries"          note="single" />
                <ModelBadge k="APK"           label="Android APK"           note="single" />
                <ModelBadge k="family"        label="Installer packages"    note="single" />
                <ModelBadge k="PE"            label="Generic PE fallback"   note="single" />
                <ModelBadge k="All"           label="Catch-all"             note="single" />
              </div>
            </Card>

            {/* Protection Status */}
            <Card icon={<Shield size={14} />} title="PROTECTION STATUS" accentColor="var(--amber)">
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                <StatusDot ok label="YARA Engine"           value="483 rules" />
                <StatusDot ok label="Hash Signature DB"     value="5 816+ entries" />
                <StatusDot ok label="Heuristics"            value="active" />
                <StatusDot ok={emberMlEnabled} label="EMBER2024 File ML" value={emberMlEnabled ? '14 models' : 'disabled'} />
                <StatusDot ok label="Network IDS (XGBoost)" value="active" />
                <StatusDot ok label="Process GRU"           value="active" />
                <StatusDot ok label="Memory Scanner"        value="active" />
                <StatusDot ok={realtimeRunning} label="Real-Time Watcher" value={realtimeRunning ? 'active' : 'off'} />
                <StatusDot ok label="AI Agent"              value="connected" />
              </div>
            </Card>

          </div>
        </div>
      </div>
    </div>
  );
}

import { useStore } from '../store';
import { Shield, AlertTriangle, CheckCircle, Cpu, FolderSearch, Clock, Wifi } from 'lucide-react';
import { RadialBarChart, RadialBar, ResponsiveContainer, PolarAngleAxis } from 'recharts';

function StatCard({ label, value, color, sub }: { label: string; value: string | number; color: string; sub?: string }) {
  return (
    <div style={{
      background: 'var(--surface)',
      border: '1px solid var(--border)',
      borderRadius: 8,
      padding: '20px 24px',
      position: 'relative',
      overflow: 'hidden',
    }}>
      <div style={{
        position: 'absolute', top: 0, left: 0,
        width: 3, height: '100%',
        background: color,
        boxShadow: `0 0 12px ${color}`,
      }} />
      <div style={{
        fontFamily: 'var(--font-mono)',
        fontSize: 10,
        color: 'var(--text-dim)',
        letterSpacing: '0.1em',
        marginBottom: 8,
      }}>{label}</div>
      <div style={{
        fontFamily: 'var(--font-hud)',
        fontSize: 32,
        fontWeight: 700,
        color,
        lineHeight: 1,
      }}>{value}</div>
      {sub && <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)', marginTop: 6 }}>{sub}</div>}
    </div>
  );
}

function QuickAction({ icon, label, onClick }: { icon: React.ReactNode; label: string; onClick: () => void }) {
  return (
    <button onClick={onClick} style={{
      display: 'flex', alignItems: 'center', gap: 12,
      padding: '14px 20px',
      background: 'var(--surface)',
      border: '1px solid var(--border)',
      borderRadius: 8,
      color: 'var(--text)',
      fontFamily: 'var(--font-body)',
      fontSize: 13,
      fontWeight: 500,
      cursor: 'pointer',
      transition: 'all 0.2s',
      width: '100%',
      textAlign: 'left',
    }}
      onMouseEnter={e => {
        const el = e.currentTarget as HTMLButtonElement;
        el.style.background = 'var(--elevated)';
        el.style.borderColor = 'var(--border-md)';
        el.style.color = 'var(--green)';
      }}
      onMouseLeave={e => {
        const el = e.currentTarget as HTMLButtonElement;
        el.style.background = 'var(--surface)';
        el.style.borderColor = 'var(--border)';
        el.style.color = 'var(--text)';
      }}>
      {icon}
      {label}
    </button>
  );
}

export default function Dashboard() {
  const { setView, scanStats, processStats, history } = useStore();

  const totalThreats = (scanStats?.malicious_files ?? 0) + (scanStats?.suspicious_files ?? 0);
  const secureScore = scanStats
    ? Math.round((scanStats.clean_files / Math.max(scanStats.total_files, 1)) * 100)
    : 100;

  const gaugeData = [{ value: secureScore, fill: secureScore > 80 ? 'var(--green)' : secureScore > 50 ? 'var(--amber)' : 'var(--red)' }];

  return (
    <div style={{
      height: '100%',
      overflowY: 'auto',
      padding: 32,
      display: 'flex',
      flexDirection: 'column',
      gap: 28,
    }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <div style={{ fontFamily: 'var(--font-hud)', fontSize: 22, fontWeight: 700, color: 'var(--text-bright)', letterSpacing: '0.05em' }}>
            THREAT OVERVIEW
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-dim)', marginTop: 4 }}>
            {new Date().toLocaleString()} — SYSTEM STATUS: {totalThreats > 0 ? <span style={{ color: 'var(--red)' }}>AT RISK</span> : <span style={{ color: 'var(--green)' }}>SECURED</span>}
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <Shield size={18} color={totalThreats > 0 ? 'var(--red)' : 'var(--green)'} />
          <span style={{
            fontFamily: 'var(--font-hud)',
            fontSize: 12,
            color: totalThreats > 0 ? 'var(--red)' : 'var(--green)',
            letterSpacing: '0.1em',
          }}>
            {totalThreats > 0 ? 'ACTION REQUIRED' : 'ALL CLEAR'}
          </span>
        </div>
      </div>

      {/* Main grid */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 240px', gap: 16 }}>
        <StatCard
          label="FILES SCANNED"
          value={scanStats?.total_files ?? '—'}
          color="var(--cyan)"
          sub={scanStats ? `${(scanStats.total_size_mb).toFixed(1)} MB analyzed` : 'No scan run yet'}
        />
        <StatCard
          label="THREATS DETECTED"
          value={totalThreats || '—'}
          color={totalThreats > 0 ? 'var(--red)' : 'var(--green)'}
          sub={scanStats ? `${scanStats.malicious_files} malicious · ${scanStats.suspicious_files} suspicious` : ''}
        />
        <StatCard
          label="PROCESSES MONITORED"
          value={processStats?.total_processes ?? '—'}
          color="var(--amber)"
          sub={processStats ? `${processStats.malicious_processes + processStats.critical_processes} suspicious` : 'Not scanned'}
        />

        {/* Security score gauge */}
        <div style={{
          background: 'var(--surface)',
          border: '1px solid var(--border)',
          borderRadius: 8,
          padding: '16px',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
        }}>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)', marginBottom: 8, letterSpacing: '0.1em' }}>
            SECURITY SCORE
          </div>
          <div style={{ width: 120, height: 80, position: 'relative' }}>
            <ResponsiveContainer width="100%" height="100%">
              <RadialBarChart cx="50%" cy="100%" innerRadius="60%" outerRadius="100%" startAngle={180} endAngle={0} data={gaugeData}>
                <PolarAngleAxis type="number" domain={[0, 100]} angleAxisId={0} tick={false} />
                <RadialBar background={{ fill: 'var(--elevated)' }} dataKey="value" cornerRadius={4} />
              </RadialBarChart>
            </ResponsiveContainer>
            <div style={{
              position: 'absolute',
              bottom: 0, left: '50%',
              transform: 'translateX(-50%)',
              fontFamily: 'var(--font-hud)',
              fontSize: 24,
              fontWeight: 900,
              color: gaugeData[0].fill,
              lineHeight: 1,
            }}>{secureScore}</div>
          </div>
        </div>
      </div>

      {/* Bottom row */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        {/* Quick actions */}
        <div style={{
          background: 'var(--surface)',
          border: '1px solid var(--border)',
          borderRadius: 8,
          padding: '20px 24px',
        }}>
          <div style={{ fontFamily: 'var(--font-hud)', fontSize: 12, color: 'var(--text-dim)', letterSpacing: '0.1em', marginBottom: 16 }}>
            QUICK ACTIONS
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            <QuickAction icon={<FolderSearch size={16} />} label="Scan Files or Directory" onClick={() => setView('scanner')} />
            <QuickAction icon={<Cpu size={16} />} label="Monitor Running Processes" onClick={() => setView('processes')} />
            <QuickAction icon={<Wifi size={16} />} label="Inspect Network Traffic" onClick={() => setView('network')} />
            <QuickAction icon={<Clock size={16} />} label="View Scan History" onClick={() => setView('history')} />
          </div>
        </div>

        {/* Recent activity */}
        <div style={{
          background: 'var(--surface)',
          border: '1px solid var(--border)',
          borderRadius: 8,
          padding: '20px 24px',
          overflow: 'hidden',
        }}>
          <div style={{ fontFamily: 'var(--font-hud)', fontSize: 12, color: 'var(--text-dim)', letterSpacing: '0.1em', marginBottom: 16 }}>
            RECENT ACTIVITY
          </div>
          {history.length === 0 ? (
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-dim)', textAlign: 'center', paddingTop: 24 }}>
              No scans run yet
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {history.slice(0, 5).map(entry => (
                <div key={entry.id} style={{
                  display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                  padding: '8px 12px',
                  background: 'var(--elevated)',
                  borderRadius: 6,
                  fontFamily: 'var(--font-mono)',
                  fontSize: 10,
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    {entry.stats.malicious > 0
                      ? <AlertTriangle size={12} color="var(--red)" />
                      : <CheckCircle size={12} color="var(--green)" />
                    }
                    <span style={{ color: 'var(--text)', maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {entry.path.split(/[\\/]/).pop()}
                    </span>
                  </div>
                  <span style={{ color: 'var(--text-dim)', flexShrink: 0 }}>
                    {entry.stats.malicious > 0
                      ? <span style={{ color: 'var(--red)' }}>{entry.stats.malicious} threat{entry.stats.malicious > 1 ? 's' : ''}</span>
                      : <span style={{ color: 'var(--green)' }}>clean</span>
                    }
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
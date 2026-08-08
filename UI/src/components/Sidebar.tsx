import { LayoutDashboard, FolderSearch, Cpu, ClockIcon, Wifi, Activity, Share2, Layers, FileText, Archive, WifiOff, Zap, Settings, Eye } from 'lucide-react';
import { useStore } from '../store';
import type { View } from '../types';


const NAV: { id: View; label: string; icon: React.ReactNode; }[] = [
  { id: 'dashboard',  label: 'OVERVIEW',  icon: <LayoutDashboard size={18} /> },
  { id: 'scanner',   label: 'SCANNER',   icon: <FolderSearch size={18} /> },
  { id: 'processes', label: 'PROCESSES', icon: <Cpu size={18} /> },
  { id: 'network',   label: 'NETWORK',   icon: <Wifi size={18} /> },
  { id: 'memory',    label: 'MEMORY',    icon: <Activity size={18} /> },
  { id: 'history',   label: 'HISTORY',   icon: <ClockIcon size={18} /> },
  { id: 'entities',  label: 'ENTITIES',     icon: <Layers size={18} /> },
  { id: 'graph',     label: 'THREAT GRAPH',   icon: <Share2   size={18} /> },
  { id: 'verdict',   label: 'GRAPH VERDICT',  icon: <FileText size={18} /> },
  { id: 'quarantine', label: 'QUARANTINE',   icon: <Archive  size={18} /> },
  { id: 'settings',   label: 'SETTINGS',     icon: <Settings size={18} /> },
];

export default function Sidebar() {
  const {
    view, setView, scanStats, processStats,
    scanning, processScanning, networkScanning, memoryScanning,
    networkIsolated, networkIsolating, restoreNetworkAction,
    autonomousMode, autoRunning, autoActionLog,
    realtimeRunning, realtimeThreats,
  } = useStore();

  return (
    <nav style={{
      width: 200,
      background: 'var(--base)',
      borderRight: '1px solid var(--border)',
      display: 'flex',
      flexDirection: 'column',
      padding: '24px 0',
      gap: 2,
      flexShrink: 0,
    }}>
      {/* Threat summary badge */}
      {scanStats && (scanStats.malicious_files > 0 || scanStats.suspicious_files > 0) && (
        <div style={{
          margin: '0 12px 20px',
          padding: '10px 12px',
          background: 'var(--red-glow)',
          border: '1px solid rgba(255,51,85,0.3)',
          borderRadius: 6,
          fontFamily: 'var(--font-mono)',
          fontSize: 10,
        }}>
          <div style={{ color: 'var(--red)', fontWeight: 600, marginBottom: 4 }}>⚠ THREATS FOUND</div>
          <div style={{ color: 'var(--text-dim)' }}>
            {scanStats.malicious_files > 0 && <div style={{ color: 'var(--red)' }}>{scanStats.malicious_files} Malicious</div>}
            {scanStats.suspicious_files > 0 && <div style={{ color: 'var(--amber)' }}>{scanStats.suspicious_files} Suspicious</div>}
          </div>
        </div>
      )}

      {NAV.map(item => {
        const active = view === item.id;
        const isBusy = (item.id === 'scanner' && scanning) || (item.id === 'processes' && processScanning) || (item.id === 'network' && networkScanning) || (item.id === 'memory' && memoryScanning);

        return (
          <button key={item.id} onClick={() => setView(item.id)} style={{
            display: 'flex', alignItems: 'center', gap: 12,
            padding: '12px 20px',
            background: active ? 'var(--elevated)' : 'transparent',
            border: 'none',
            borderLeft: active ? '2px solid var(--green)' : '2px solid transparent',
            color: active ? 'var(--green)' : 'var(--text-dim)',
            fontFamily: 'var(--font-hud)',
            fontSize: 11,
            fontWeight: active ? 700 : 400,
            letterSpacing: '0.12em',
            cursor: 'pointer',
            transition: 'all 0.15s',
            textAlign: 'left',
            width: '100%',
          }}
            onMouseEnter={e => { if (!active) (e.currentTarget as HTMLButtonElement).style.color = 'var(--text)'; }}
            onMouseLeave={e => { if (!active) (e.currentTarget as HTMLButtonElement).style.color = 'var(--text-dim)'; }}
          >
            <span style={{ opacity: active ? 1 : 0.6, transition: 'opacity 0.15s' }}>
              {item.icon}
            </span>
            <span style={{ flex: 1 }}>{item.label}</span>
            {isBusy && (
              <div style={{
                width: 6, height: 6, borderRadius: '50%',
                background: 'var(--amber)',
                animation: 'pulse 1s infinite',
              }} />
            )}
          </button>
        );
      })}

      {/* Bottom - process threat count */}
      {processStats && processStats.malicious_processes + processStats.critical_processes > 0 && (
        <div style={{
          margin: '20px 12px 0',
          padding: '8px 12px',
          background: 'rgba(255,51,85,0.08)',
          border: '1px solid rgba(255,51,85,0.25)',
          borderRadius: 6,
          fontFamily: 'var(--font-mono)',
          fontSize: 10,
          color: 'var(--red)',
        }}>
          ⚠ {processStats.malicious_processes + processStats.critical_processes} malicious process{processStats.malicious_processes + processStats.critical_processes > 1 ? 'es' : ''} detected
        </div>
      )}

      <div style={{ flex: 1 }} />

      {/* Network isolation emergency banner */}
      {networkIsolated && (
        <div style={{
          margin: '0 12px 10px',
          padding: '10px 12px',
          background: 'rgba(255,51,85,0.09)',
          border: '1px solid rgba(255,51,85,0.35)',
          borderRadius: 6,
          fontFamily: 'var(--font-mono)',
          fontSize: 9,
        }}>
          <div style={{
            display: 'flex', alignItems: 'center', gap: 6,
            color: '#ff3355', fontWeight: 700, marginBottom: 6,
          }}>
            <WifiOff size={11} /> NETWORK ISOLATED
          </div>
          <button
            onClick={restoreNetworkAction}
            disabled={networkIsolating}
            style={{
              width: '100%', padding: '5px 0',
              background: 'rgba(0,255,136,0.1)',
              border: '1px solid rgba(0,255,136,0.35)',
              borderRadius: 4, color: '#00ff88',
              fontFamily: 'var(--font-mono)', fontSize: 9, fontWeight: 700,
              cursor: networkIsolating ? 'not-allowed' : 'pointer',
              opacity: networkIsolating ? 0.5 : 1,
            }}>
            {networkIsolating ? 'Restoring…' : 'Restore Network'}
          </button>
        </div>
      )}

      {/* Real-time watcher status / threat count */}
      <button
        onClick={() => setView('settings')}
        style={{
          margin: '0 12px 8px', padding: '8px 12px',
          background: realtimeThreats.length > 0
            ? 'rgba(255,136,0,0.07)'
            : realtimeRunning
              ? 'rgba(0,255,255,0.05)'
              : 'var(--elevated)',
          border: `1px solid ${realtimeThreats.length > 0
            ? 'rgba(255,136,0,0.35)'
            : realtimeRunning
              ? 'rgba(0,255,255,0.25)'
              : 'var(--border)'}`,
          borderRadius: 6, cursor: 'pointer', textAlign: 'left', width: 'calc(100% - 24px)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
          <Eye size={10} color={realtimeRunning ? 'var(--cyan)' : 'var(--text-dim)'} />
          <span style={{
            fontFamily: 'var(--font-hud)', fontSize: 9, letterSpacing: '0.1em',
            color: realtimeRunning ? 'var(--cyan)' : 'var(--text-dim)', flex: 1,
          }}>
            REALTIME
          </span>
          <span style={{
            fontFamily: 'var(--font-mono)', fontSize: 8,
            color: realtimeRunning ? 'var(--cyan)' : 'var(--text-dim)',
          }}>
            {realtimeRunning ? 'ON' : 'OFF'}
          </span>
        </div>
        {realtimeThreats.length > 0 && (
          <div style={{
            fontFamily: 'var(--font-mono)', fontSize: 8,
            color: 'var(--amber)', marginTop: 3,
          }}>
            ⚠ {realtimeThreats.length} threat{realtimeThreats.length !== 1 ? 's' : ''} caught
          </div>
        )}
      </button>

      {/* Autonomous mode status pill — click to open Settings */}
      <button
        onClick={() => setView('settings')}
        style={{
          margin: '0 12px 8px', padding: '8px 12px',
          background: autonomousMode ? 'rgba(255,51,85,0.07)' : 'var(--elevated)',
          border: `1px solid ${autonomousMode ? 'rgba(255,51,85,0.35)' : 'var(--border)'}`,
          borderRadius: 6, cursor: 'pointer', textAlign: 'left', width: 'calc(100% - 24px)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
          <Zap size={10} color={autonomousMode ? '#ff3355' : 'var(--text-dim)'} />
          <span style={{
            fontFamily: 'var(--font-hud)', fontSize: 9, letterSpacing: '0.1em',
            color: autonomousMode ? '#ff3355' : 'var(--text-dim)', flex: 1,
          }}>
            AUTO MODE
          </span>
          <span style={{
            fontFamily: 'var(--font-mono)', fontSize: 8,
            color: autonomousMode ? '#ff3355' : 'var(--text-dim)',
          }}>
            {autoRunning ? '⚡ running' : autonomousMode ? 'ON' : 'OFF'}
          </span>
        </div>
        {autonomousMode && autoActionLog.length > 0 && (
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 8, color: 'rgba(255,51,85,0.6)', marginTop: 3 }}>
            {autoActionLog.filter(a => a.result === 'success').length} action(s) taken
          </div>
        )}
      </button>

      {/* Status footer */}
      <div style={{
        margin: '0 16px',
        padding: '12px 0',
        borderTop: '1px solid var(--border)',
        fontFamily: 'var(--font-mono)',
        fontSize: 9,
        color: 'var(--text-dim)',
        lineHeight: 1.8,
      }}>
        <div>SYS: {new Date().toLocaleDateString()}</div>
        <div style={{ color: 'var(--green)', opacity: 0.7 }}>● PROTECTION ACTIVE</div>
      </div>
    </nav>
  );
}
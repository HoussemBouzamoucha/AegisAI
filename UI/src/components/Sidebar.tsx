import { LayoutDashboard, FolderSearch, Cpu, ClockIcon, Wifi } from 'lucide-react';
import { useStore } from '../store';
import type { View } from '../types';


const NAV: { id: View; label: string; icon: React.ReactNode; }[] = [
  { id: 'dashboard',  label: 'OVERVIEW',  icon: <LayoutDashboard size={18} /> },
  { id: 'scanner',   label: 'SCANNER',   icon: <FolderSearch size={18} /> },
  { id: 'processes', label: 'PROCESSES', icon: <Cpu size={18} /> },
  { id: 'network',   label: 'NETWORK',   icon: <Wifi size={18} /> },
  { id: 'history',   label: 'HISTORY',   icon: <ClockIcon size={18} /> },
];

export default function Sidebar() {
  const { view, setView, scanStats, processStats, scanning, processScanning, networkScanning } = useStore();

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
        const isBusy = (item.id === 'scanner' && scanning) || (item.id === 'processes' && processScanning) || (item.id === 'network' && networkScanning);

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
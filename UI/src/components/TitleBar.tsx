import { getCurrentWindow } from '@tauri-apps/api/window';
import { Minus, Square, X, Shield } from 'lucide-react';
import { useStore } from '../store';

export default function TitleBar() {
  const engineReady = useStore(s => s.engineReady);
  const win = getCurrentWindow();

  return (
    <div data-tauri-drag-region style={{
      height: 40,
      background: 'var(--base)',
      borderBottom: '1px solid var(--border)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      padding: '0 16px 0 20px',
      flexShrink: 0,
      zIndex: 100,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <Shield size={16} color="var(--green)" />
        <span style={{
          fontFamily: 'var(--font-hud)',
          fontSize: 13,
          fontWeight: 700,
          color: 'var(--green)',
          letterSpacing: '0.15em',
        }}>AEGIS<span style={{ color: 'var(--text-dim)' }}>AI</span></span>
        <span style={{
          fontSize: 10,
          fontFamily: 'var(--font-mono)',
          color: 'var(--text-dim)',
          marginLeft: 8,
          paddingLeft: 8,
          borderLeft: '1px solid var(--border)',
        }}>v1.0.0</span>
      </div>

      <div style={{
        display: 'flex', alignItems: 'center', gap: 6,
        fontFamily: 'var(--font-mono)', fontSize: 10,
        color: engineReady ? 'var(--green)' : 'var(--red)',
      }}>
        <div style={{
          width: 6, height: 6, borderRadius: '50%',
          background: engineReady ? 'var(--green)' : 'var(--red)',
          animation: engineReady ? 'pulse 2s infinite' : 'none',
        }} />
        {engineReady ? 'ENGINE ONLINE' : 'ENGINE OFFLINE'}
      </div>

      <div style={{ display: 'flex', gap: 2 }}>
        {[
          { icon: <Minus size={12} />, action: () => win.minimize(), hoverBg: 'var(--hover)' },
          { icon: <Square size={10} />, action: () => win.toggleMaximize(), hoverBg: 'var(--hover)' },
          { icon: <X size={12} />,     action: () => win.close(),           hoverBg: 'var(--red)' },
        ].map((btn, i) => (
          <button key={i} onClick={btn.action} style={{
            width: 32, height: 28,
            background: 'transparent',
            border: 'none',
            color: 'var(--text-dim)',
            cursor: 'pointer',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            borderRadius: 4,
            transition: 'all 0.15s',
          }}
            onMouseEnter={e => {
              (e.currentTarget as HTMLButtonElement).style.background = btn.hoverBg;
              (e.currentTarget as HTMLButtonElement).style.color = '#fff';
            }}
            onMouseLeave={e => {
              (e.currentTarget as HTMLButtonElement).style.background = 'transparent';
              (e.currentTarget as HTMLButtonElement).style.color = 'var(--text-dim)';
            }}>
            {btn.icon}
          </button>
        ))}
      </div>
    </div>
  );
}
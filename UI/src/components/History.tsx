import { useStore } from '../store';
import { Clock, FolderOpen, FileText, CheckCircle, AlertTriangle } from 'lucide-react';

export default function History() {
  const { history } = useStore();

  if (history.length === 0) {
    return (
      <div style={{ height: '100%', display: 'flex', flexDirection: 'column', padding: 32, gap: 24 }}>
        <div>
          <div style={{ fontFamily: 'var(--font-hud)', fontSize: 22, fontWeight: 700, color: 'var(--text-bright)', letterSpacing: '0.05em' }}>SCAN HISTORY</div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-dim)', marginTop: 4 }}>Past scan records for this session</div>
        </div>
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 16, opacity: 0.5 }}>
          <Clock size={48} color="var(--text-dim)" />
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 13, color: 'var(--text-dim)' }}>No scan history yet</div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-dim)' }}>Run a scan to see results here</div>
        </div>
      </div>
    );
  }

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', padding: 32, gap: 24 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <div style={{ fontFamily: 'var(--font-hud)', fontSize: 22, fontWeight: 700, color: 'var(--text-bright)', letterSpacing: '0.05em' }}>SCAN HISTORY</div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-dim)', marginTop: 4 }}>{history.length} scan{history.length !== 1 ? 's' : ''} this session</div>
        </div>
      </div>

      <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 8 }}>
        {history.map((entry, i) => {
          const hasThreats = entry.stats.malicious > 0 || entry.stats.suspicious > 0;
          return (
            <div key={entry.id} className="anim-fade" style={{
              background: 'var(--surface)',
              border: `1px solid ${hasThreats ? 'rgba(255,51,85,0.2)' : 'var(--border)'}`,
              borderRadius: 8,
              padding: '16px 20px',
              display: 'grid',
              gridTemplateColumns: '36px 1fr auto',
              gap: 16,
              alignItems: 'center',
              animationDelay: `${i * 0.04}s`,
            }}>
              {/* Icon */}
              <div style={{
                width: 36, height: 36, borderRadius: 8,
                background: hasThreats ? 'var(--red-glow)' : 'var(--green-glow)',
                border: `1px solid ${hasThreats ? 'rgba(255,51,85,0.3)' : 'var(--border-md)'}`,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
              }}>
                {entry.type === 'directory'
                  ? <FolderOpen size={16} color={hasThreats ? 'var(--red)' : 'var(--green)'} />
                  : <FileText size={16} color={hasThreats ? 'var(--red)' : 'var(--green)'} />
                }
              </div>

              {/* Details */}
              <div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text)', marginBottom: 4, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {entry.path}
                </div>
                <div style={{ display: 'flex', gap: 16, fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)' }}>
                  <span><Clock size={9} style={{ display: 'inline', verticalAlign: 'middle', marginRight: 4 }} />{entry.timestamp.toLocaleTimeString()}</span>
                  <span>{entry.stats.total} file{entry.stats.total !== 1 ? 's' : ''}</span>
                  <span style={{ color: 'var(--green)' }}>{entry.stats.clean} clean</span>
                  {entry.stats.suspicious > 0 && <span style={{ color: 'var(--amber)' }}>{entry.stats.suspicious} suspicious</span>}
                  {entry.stats.malicious > 0 && <span style={{ color: 'var(--red)' }}>{entry.stats.malicious} malicious</span>}
                  <span>{(entry.durationMs / 1000).toFixed(1)}s</span>
                </div>
              </div>

              {/* Status */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                {hasThreats
                  ? <AlertTriangle size={16} color="var(--red)" />
                  : <CheckCircle size={16} color="var(--green)" />
                }
                <span style={{
                  fontFamily: 'var(--font-hud)', fontSize: 10,
                  color: hasThreats ? 'var(--red)' : 'var(--green)',
                  letterSpacing: '0.08em',
                }}>
                  {hasThreats ? 'THREATS FOUND' : 'CLEAN'}
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
import { useEffect } from 'react';
import { useStore } from './store/index';
import TitleBar from './components/TitleBar';
import Sidebar from './components/Sidebar';
import Dashboard from './components/Dashboard';
import Scanner from './components/Scanner';
import ProcessMonitor from './components/ProcessMonitor';
import History from './components/History';

export default function App() {
  const { view, checkEngine } = useStore();

  useEffect(() => { checkEngine(); }, []);

  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      width: '100vw',
      height: '100vh',
      background: 'var(--void)',
      overflow: 'hidden',
    }}>
      <TitleBar />
      <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>
        <Sidebar />
        <main style={{ flex: 1, overflow: 'hidden', position: 'relative' }}>
          {view === 'dashboard'  && <Dashboard />}
          {view === 'scanner'   && <Scanner />}
          {view === 'processes' && <ProcessMonitor />}
          {view === 'history'   && <History />}
        </main>
      </div>
    </div>
  );
}
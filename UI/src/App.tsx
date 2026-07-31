import { useEffect } from 'react';
import { useStore } from './store/index';
import TitleBar from './components/TitleBar';
import Sidebar from './components/Sidebar';
import Dashboard from './components/Dashboard';
import Scanner from './components/Scanner';
import ProcessMonitor from './components/ProcessMonitor';
import NetworkMonitor from './components/NetworkMonitor';
import MemoryMonitor from './components/MemoryMonitor';
import History from './components/History';
import EntityManager from './components/EntityManager';
import ThreatGraph from './components/ThreatGraph';
import GraphVerdict from './components/GraphVerdict';
import QuarantineManager from './components/QuarantineManager';

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
          {view === 'network'   && <NetworkMonitor />}
          {view === 'memory'    && <MemoryMonitor />}
          {view === 'history'   && <History />}
          {view === 'entities'  && <EntityManager />}
          {view === 'graph'     && <ThreatGraph />}
          {view === 'verdict'   && <GraphVerdict />}
          {view === 'quarantine' && <QuarantineManager />}
        </main>
      </div>
    </div>
  );
}
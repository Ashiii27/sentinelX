/**
 * App — layout shell: sidebar navigation, routed pages, and a live
 * status footer (WebSocket state + backend health).
 */
import React, { useEffect, useState } from 'react';
import { BrowserRouter, Routes, Route, NavLink, Navigate } from 'react-router-dom';
import Dashboard from './pages/Dashboard.jsx';
import Alerts from './pages/Alerts.jsx';
import Settings from './pages/Settings.jsx';
import api from './services/api.js';
import { useWebSocket } from './hooks/useWebSocket.js';

const NAV = [
  { to: '/', label: 'Overview', icon: '◉', end: true },
  { to: '/alerts', label: 'Alerts', icon: '⚠' },
  { to: '/settings', label: 'Settings', icon: '⚙' },
];

function StatusBar() {
  const { status: wsStatus } = useWebSocket();
  const [health, setHealth] = useState(null);

  useEffect(() => {
    let live = true;
    const tick = async () => {
      try {
        const h = await api.health();
        if (live) setHealth(h);
      } catch {
        if (live) setHealth(null);
      }
    };
    tick();
    const id = setInterval(tick, 10000);
    return () => { live = false; clearInterval(id); };
  }, []);

  const wsDot = wsStatus === 'open' ? 'ok' : wsStatus === 'reconnecting' ? 'warn' : 'warn';
  const engineOk = !!(health && health.engine && health.engine.connected);
  const dbOk = !!(health && health.db === 'mongodb');

  return (
    <div className="statusbar">
      <div className="status-row">
        <span><span className={`dot ${wsDot}`} />stream: {wsStatus}</span>
        <span className="mono">v1.0.0</span>
      </div>
      <div className="status-row">
        <span>
          <span className={`dot ${engineOk ? 'ok' : 'crit'}`} />
          engine {engineOk ? 'up' : 'down'}
        </span>
        <span>
          <span className={`dot ${dbOk ? 'ok' : 'warn'}`} />
          {health ? health.db : 'api down'}
        </span>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <div className="app">
        <aside className="sidebar">
          <div className="brand">
            <h1>Sentinel<span className="x">X</span></h1>
            <p className="sub">NIDS · SOC console</p>
          </div>
          <nav className="nav">
            {NAV.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                className={({ isActive }) => (isActive ? 'active' : '')}
              >
                <span className="ico">{item.icon}</span>
                {item.label}
              </NavLink>
            ))}
          </nav>
          <StatusBar />
        </aside>
        <main className="main">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/alerts" element={<Alerts />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}

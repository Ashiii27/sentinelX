/**
 * Dashboard — the SOC overview: stat cards, live alert feed, charts,
 * threat map, kill chain, MITRE matrix.
 */
import React, { useEffect, useMemo, useState } from 'react';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  AreaChart, Area, CartesianGrid, Cell,
} from 'recharts';
import api, { apiError } from '../services/api.js';
import { useAlerts } from '../hooks/useAlerts.js';
import AlertFeed from '../components/AlertFeed/index.jsx';
import ThreatMap from '../components/ThreatMap/index.jsx';
import KillChain from '../components/KillChain/index.jsx';
import MITREMatrix from '../components/MITREMatrix/index.jsx';
import { Panel, SEVERITY_COLORS } from '../components/common.jsx';

const AXIS = { stroke: '#6e7681', fontSize: 10 };
const TOOLTIP_STYLE = {
  backgroundColor: '#161b22',
  border: '1px solid #21262d',
  borderRadius: 6,
  fontSize: 12,
};

export default function Dashboard() {
  const params = useMemo(() => ({}), []);
  const { alerts, total, error, wsStatus } = useAlerts(params);

  const [summary, setSummary] = useState(null);
  const [sumError, setSumError] = useState(null);

  // Poll the summary (charts) — live alerts come over WebSocket.
  useEffect(() => {
    let live = true;
    const tick = async () => {
      try {
        const s = await api.summary();
        if (live) { setSummary(s); setSumError(null); }
      } catch (err) {
        if (live) setSumError(apiError(err));
      }
    };
    tick();
    const id = setInterval(tick, 15000);
    return () => { live = false; clearInterval(id); };
  }, []);

  const sevData = useMemo(() => {
    const s = summary && summary.by_severity;
    if (!s) return [];
    return ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].map((k) => ({
      name: k,
      count: s[k] || 0,
      fill: SEVERITY_COLORS[k],
    }));
  }, [summary]);

  const typeData = useMemo(() => {
    const t = summary && summary.by_type;
    if (!t) return [];
    return Object.entries(t)
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 8);
  }, [summary]);

  const hourlyData = useMemo(() => {
    const buckets = new Map();
    const now = new Date();
    for (let i = 23; i >= 0; i--) {
      const d = new Date(now.getTime() - i * 3600 * 1000);
      d.setMinutes(0, 0, 0);
      buckets.set(d.toISOString(), { label: `${String(d.getHours()).padStart(2, '0')}:00`, count: 0 });
    }
    for (const row of (summary && summary.hourly_24h) || []) {
      const d = new Date(row.hour);
      d.setMinutes(0, 0, 0);
      const key = d.toISOString();
      if (buckets.has(key)) buckets.get(key).count += row.count;
    }
    return [...buckets.values()];
  }, [summary]);

  const engine = (summary && summary.engine) || null;

  return (
    <div>
      <div className="page-title">
        <h1>Overview</h1>
        <span className="hint">
          {wsStatus === 'open' ? '● live' : wsStatus === 'reconnecting' ? '◌ reconnecting' : '◌ connecting'}
          {' · '}total alerts: {summary ? summary.total : total}
        </span>
      </div>

      {(error || sumError) && (
        <div className="msg err">{error || sumError}</div>
      )}

      <div className="stat-cards">
        <div className="stat-card">
          <div className="label">Total alerts</div>
          <div className="value">{summary ? summary.total : '—'}</div>
          <div className="foot">{summary && summary.db_mode === 'in-memory' ? 'in-memory store' : 'mongodb'}</div>
        </div>
        <div className="stat-card">
          <div className="label">Critical</div>
          <div className="value crit">{summary ? summary.by_severity.CRITICAL : '—'}</div>
          <div className="foot">severity = CRITICAL</div>
        </div>
        <div className="stat-card">
          <div className="label">High</div>
          <div className="value high">{summary ? summary.by_severity.HIGH : '—'}</div>
          <div className="foot">severity = HIGH</div>
        </div>
        <div className="stat-card">
          <div className="label">Engine</div>
          <div className={`value ${engine && engine.connected ? 'ok' : ''}`}>
            {engine ? (engine.connected ? 'UP' : 'DOWN') : '—'}
          </div>
          <div className="foot">
            {engine
              ? `${engine.alerts} ingested · ${engine.duplicates} dup · ${engine.malformed} bad`
              : 'no stats'}
          </div>
        </div>
        <div className="stat-card">
          <div className="label">WebSocket clients</div>
          <div className="value">{summary && summary.ws ? summary.ws.clients : '—'}</div>
          <div className="foot">dashboard viewers</div>
        </div>
      </div>

      <div className="grid-2">
        <Panel title="Live alert feed" subtitle="newest first — WebSocket" className="span-none">
          <AlertFeed alerts={alerts} limit={12} />
        </Panel>
        <Panel title="Threat map" subtitle="geo-IP source locations">
          <ThreatMap
            alerts={alerts}
            topSrcIps={(summary && summary.top_src_ips) || []}
            geoEnabled={!!(summary && summary.geoip && summary.geoip.enabled)}
          />
        </Panel>
      </div>

      <div className="grid-2">
        <Panel title="Alerts by severity">
          <div className="chart-box">
            <ResponsiveContainer>
              <BarChart data={sevData}>
                <CartesianGrid stroke="#21262d" vertical={false} />
                <XAxis dataKey="name" tick={AXIS} axisLine={false} tickLine={false} />
                <YAxis tick={AXIS} axisLine={false} tickLine={false} allowDecimals={false} />
                <Tooltip contentStyle={TOOLTIP_STYLE} cursor={{ fill: 'rgba(88,166,255,0.06)' }} />
                <Bar dataKey="count" radius={[3, 3, 0, 0]}>
                  {sevData.map((d) => (
                    <Cell key={d.name} fill={d.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Panel>
        <Panel title="Alerts by type">
          <div className="chart-box">
            <ResponsiveContainer>
              <BarChart data={typeData} layout="vertical" margin={{ left: 30 }}>
                <CartesianGrid stroke="#21262d" horizontal={false} />
                <XAxis type="number" tick={AXIS} axisLine={false} tickLine={false} allowDecimals={false} />
                <YAxis type="category" dataKey="name" tick={{ ...AXIS, fill: '#c9d1d9' }} width={110} axisLine={false} tickLine={false} />
                <Tooltip contentStyle={TOOLTIP_STYLE} cursor={{ fill: 'rgba(88,166,255,0.06)' }} />
                <Bar dataKey="count" fill="#58a6ff" radius={[0, 3, 3, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Panel>
      </div>

      <Panel title="Alert volume — last 24 h">
        <div className="chart-box">
          <ResponsiveContainer>
            <AreaChart data={hourlyData}>
              <defs>
                <linearGradient id="vol" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#58a6ff" stopOpacity={0.5} />
                  <stop offset="100%" stopColor="#58a6ff" stopOpacity={0.02} />
                </linearGradient>
              </defs>
              <CartesianGrid stroke="#21262d" vertical={false} />
              <XAxis dataKey="label" tick={AXIS} axisLine={false} tickLine={false} />
              <YAxis tick={AXIS} axisLine={false} tickLine={false} allowDecimals={false} />
              <Tooltip contentStyle={TOOLTIP_STYLE} />
              <Area type="monotone" dataKey="count" stroke="#58a6ff" fill="url(#vol)" strokeWidth={2} />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </Panel>

      <Panel title="Cyber kill chain" subtitle="alerts grouped by kill chain phase">
        <KillChain byKillChain={(summary && summary.by_kill_chain) || {}} />
      </Panel>

      <Panel title="MITRE ATT&CK" subtitle="tactics flagged by detections">
        <MITREMatrix alerts={alerts} byMitre={(summary && summary.by_mitre) || []} />
      </Panel>
    </div>
  );
}

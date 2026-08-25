/**
 * Settings — system status + YARA rule management.
 *
 * Shows live backend health (engine bridge, database mode, geo-IP
 * enrichment, uptime) polled every 5 s, and hosts the rule manager
 * component.
 */
import React, { useEffect, useState } from 'react';
import api, { apiError } from '../services/api.js';
import YARARules from '../components/YARARules/index.jsx';
import { Panel } from '../components/common.jsx';

export default function Settings() {
  const [health, setHealth] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    let live = true;
    const tick = async () => {
      try {
        const h = await api.health();
        if (live) { setHealth(h); setError(null); }
      } catch (err) {
        if (live) setError(apiError(err));
      }
    };
    tick();
    const id = setInterval(tick, 5000);
    return () => { live = false; clearInterval(id); };
  }, []);

  const engine = health && health.engine;

  return (
    <div>
      <div className="page-title">
        <h1>Settings &amp; System</h1>
        <span className="hint">health poll: 5 s</span>
      </div>

      {error && <div className="msg err">{error} — is the backend running?</div>}

      <Panel title="Backend health" subtitle={health ? `v${health.version} · ${health.service}` : ''}>
        <table className="data">
          <tbody>
            <tr>
              <td>Service</td>
              <td>
                <span className={`dot ${health ? 'ok' : 'crit'}`} />
                {health ? 'healthy' : 'unreachable'}
              </td>
            </tr>
            <tr>
              <td>Database</td>
              <td>
                <span className={`dot ${health && health.db === 'mongodb' ? 'ok' : 'warn'}`} />
                {health
                  ? health.db === 'mongodb'
                    ? 'MongoDB (persistent)'
                    : 'in-memory fallback (alerts lost on restart — set MONGO_URI)'
                  : '—'}
              </td>
            </tr>
            <tr>
              <td>Engine bridge</td>
              <td>
                <span className={`dot ${engine && engine.connected ? 'ok' : 'crit'}`} />
                {engine
                  ? `${engine.connected ? 'connected' : 'disconnected'} · ${engine.connections} lifetime connection(s)`
                  : 'ingestion disabled'}
              </td>
            </tr>
            <tr>
              <td>Ingested alerts</td>
              <td className="mono">{engine ? engine.alerts : '—'}</td>
            </tr>
            <tr>
              <td>Duplicates suppressed</td>
              <td className="mono">{engine ? engine.duplicates : '—'}</td>
            </tr>
            <tr>
              <td>Malformed frames</td>
              <td className="mono">{engine ? engine.malformed : '—'}</td>
            </tr>
            <tr>
              <td>Last alert</td>
              <td className="mono">{engine && engine.last_alert_at ? new Date(engine.last_alert_at).toLocaleString() : '—'}</td>
            </tr>
            <tr>
              <td>Geo-IP enrichment</td>
              <td>
                <span className={`dot ${health && health.geoip && health.geoip.enabled ? 'ok' : 'warn'}`} />
                {health && health.geoip && health.geoip.enabled
                  ? 'enabled (GeoLite2)'
                  : 'disabled — set GEOIP_MMDB to enable Threat Map locations'}
              </td>
            </tr>
            <tr>
              <td>Uptime</td>
              <td className="mono">{health ? `${health.uptime_seconds} s` : '—'}</td>
            </tr>
          </tbody>
        </table>
      </Panel>

      <Panel title="YARA rules" subtitle="engine rules directory — files are the single source of truth">
        <YARARules />
      </Panel>
    </div>
  );
}

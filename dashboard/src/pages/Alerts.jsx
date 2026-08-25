/**
 * Alerts — full alert browser: filters, pagination, triage actions
 * (mark false-positive / reviewed), delete.
 *
 * Live WebSocket alerts are spliced into the current page as they
 * arrive; changing filters re-queries the backend.
 */
import React, { useEffect, useMemo, useState } from 'react';
import api, { apiError } from '../services/api.js';
import { useAlerts } from '../hooks/useAlerts.js';
import {
  SeverityBadge, formatDateTime, flowText,
} from '../components/common.jsx';

const PAGE_SIZE = 25;

const TIME_RANGES = {
  all: null,
  '1h': { from: new Date(Date.now() - 3600e3).toISOString() },
  '24h': { from: new Date(Date.now() - 24 * 3600e3).toISOString() },
  '7d': { from: new Date(Date.now() - 7 * 24 * 3600e3).toISOString() },
};

export default function Alerts() {
  const [severity, setSeverity] = useState('');
  const [type, setType] = useState('');
  const [srcIp, setSrcIp] = useState('');
  const [range, setRange] = useState('all');
  const [page, setPage] = useState(1);

  // Only send filter params that are set — the backend treats empty
  // values as "no filter" too, but keep the URL clean in dev tools.
  const params = useMemo(() => {
    const p = { page, limit: PAGE_SIZE, ...TIME_RANGES[range] };
    if (severity) p.severity = severity;
    if (type) p.type = type;
    if (srcIp.trim()) p.src_ip = srcIp.trim();
    return p;
  }, [severity, type, srcIp, range, page]);

  const { alerts, total, loading, error, wsStatus, lastUpdated, refresh } =
    useAlerts(params, { cap: 100 });

  // New page whenever filters change.
  useEffect(() => { setPage(1); }, [severity, type, srcIp, range]);

  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  const types = useMemo(() => {
    const set = new Set(alerts.map((a) => a.type));
    return [...set].sort();
  }, [alerts]);

  async function triage(alert, patch) {
    try {
      const updated = await api.updateTriage(alert.alert_id, patch);
      refresh(); // re-sync row state from the store
      return updated;
    } catch (err) {
      window.alert(apiError(err));
      return null;
    }
  }

  async function remove(alert) {
    if (!window.confirm(`Delete alert ${alert.alert_id}?`)) return;
    try {
      await api.deleteAlert(alert.alert_id);
      refresh();
    } catch (err) {
      window.alert(apiError(err));
    }
  }

  return (
    <div>
      <div className="page-title">
        <h1>Alerts</h1>
        <span className="hint">
          {total} matching · updated {lastUpdated ? lastUpdated.toLocaleTimeString() : '—'}
          {' · '}{wsStatus === 'open' ? 'live' : wsStatus}
        </span>
      </div>

      {error && <div className="msg err">{error}</div>}

      <div className="controls">
        <div>
          <label>Severity</label>
          <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
            <option value="">All</option>
            <option>LOW</option>
            <option>MEDIUM</option>
            <option>HIGH</option>
            <option>CRITICAL</option>
          </select>
        </div>
        <div>
          <label>Type</label>
          <select value={type} onChange={(e) => setType(e.target.value)}>
            <option value="">All</option>
            {types.map((t) => <option key={t}>{t}</option>)}
          </select>
        </div>
        <div>
          <label>Source IP</label>
          <input
            type="text"
            value={srcIp}
            onChange={(e) => setSrcIp(e.target.value)}
            placeholder="203.0.113.9"
            style={{ width: 140 }}
          />
        </div>
        <div>
          <label>Window</label>
          <select value={range} onChange={(e) => setRange(e.target.value)}>
            <option value="all">All time</option>
            <option value="1h">Last hour</option>
            <option value="24h">Last 24 h</option>
            <option value="7d">Last 7 days</option>
          </select>
        </div>
        <div style={{ flex: 1 }} />
        <button className="btn" onClick={refresh} disabled={loading}>
          {loading ? <span className="spin" /> : '↻'} Refresh
        </button>
      </div>

      {loading && !alerts.length ? (
        <div className="empty"><span className="spin" /> Loading…</div>
      ) : !alerts.length ? (
        <div className="empty">No alerts match the current filters.</div>
      ) : (
        <div className="panel">
          <div className="panel-body" style={{ overflowX: 'auto', padding: 0 }}>
            <table className="data">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Severity</th>
                  <th>Type</th>
                  <th>Flow</th>
                  <th>MITRE</th>
                  <th>Triage</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((a) => (
                  <tr key={a.alert_id}>
                    <td className="mono">{formatDateTime(a.timestamp)}</td>
                    <td><SeverityBadge severity={a.severity} /></td>
                    <td style={{ fontWeight: 600 }}>{a.type}</td>
                    <td className="mono" title={flowText(a)}>{flowText(a)}</td>
                    <td className="mono">
                      {a.mitre && a.mitre.technique_id
                        ? <span title={a.mitre.tactic || ''}>{a.mitre.technique_id}</span>
                        : '—'}
                    </td>
                    <td>
                      <div style={{ display: 'flex', gap: 6 }}>
                        <button
                          className={`btn ${a.false_positive ? 'primary' : ''}`}
                          style={{ padding: '3px 8px', fontSize: 11 }}
                          title={a.false_positive ? 'Marked false positive — click to clear' : 'Mark as false positive'}
                          onClick={() => triage(a, { false_positive: !a.false_positive })}
                        >
                          FP
                        </button>
                        <button
                          className={`btn ${a.reviewed ? 'primary' : ''}`}
                          style={{ padding: '3px 8px', fontSize: 11 }}
                          title={a.reviewed ? 'Reviewed — click to unmark' : 'Mark as reviewed'}
                          onClick={() => triage(a, { reviewed: !a.reviewed })}
                        >
                          ✓
                        </button>
                      </div>
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      <button
                        className="btn danger"
                        style={{ padding: '3px 8px', fontSize: 11 }}
                        onClick={() => remove(a)}
                        title="Delete alert"
                      >
                        ✕
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="pagination" style={{ padding: '10px 16px' }}>
            <button className="btn" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>← Prev</button>
            <span>page {page} / {pages}</span>
            <button className="btn" disabled={page >= pages} onClick={() => setPage((p) => p + 1)}>Next →</button>
          </div>
        </div>
      )}
    </div>
  );
}

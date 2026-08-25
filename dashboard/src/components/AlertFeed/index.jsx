/**
 * AlertFeed — live scrolling list of alerts, newest first.
 *
 * Items that arrived over the WebSocket (less than ~3s old) get a
 * flash animation. Capped at `limit` to keep the DOM small during
 * floods; the Alerts page is where you paginate deeper.
 */
import React, { useMemo } from 'react';
import { SeverityBadge, formatTime, flowText } from '../common.jsx';

export default function AlertFeed({ alerts = [], limit = 30, emptyText = 'No alerts yet — the engine is watching.' }) {
  const visible = alerts.slice(0, limit);

  // Alerts newer than a few seconds are "fresh" (arrived via WS).
  const now = useMemo(() => Date.now(), [alerts]);
  const freshUntil = now - 3000;

  if (!visible.length) {
    return <div className="empty">{emptyText}</div>;
  }

  return (
    <div className="alert-feed">
      {visible.map((a) => {
        const t = new Date(a.timestamp).getTime();
        const isNew = !Number.isNaN(t) && t >= freshUntil;
        const sev = String(a.severity || 'LOW').toUpperCase();
        return (
          <div key={a.alert_id} className={`alert-row sev-${sev}${isNew ? ' is-new' : ''}`}>
            <span className="t">{formatTime(a.timestamp)}</span>
            <span><SeverityBadge severity={sev} /></span>
            <span className="type">{a.type}</span>
            <span className="flow" title={flowText(a)}>{flowText(a)}</span>
            {a.description && <span className="desc">{a.description}</span>}
          </div>
        );
      })}
    </div>
  );
}

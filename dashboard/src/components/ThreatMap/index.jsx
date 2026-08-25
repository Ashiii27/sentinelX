/**
 * ThreatMap — geo-IP world map of observed source IPs.
 *
 * The basemap is the Natural Earth 110m land outline (world-atlas
 * TopoJSON, bundled — no runtime network calls). Markers are plotted
 * from the `geo` object the backend attaches to alerts when a
 * GeoLite2 .mmdb is configured (GEOIP_MMDB). Without geo enrichment
 * the map renders dimmed and the panel falls back to a ranked list of
 * top source IPs — the dashboard is still useful, it just can't place
 * the dots.
 */
import React, { useMemo } from 'react';
import { feature } from 'topojson-client';
import land110 from 'world-atlas/land-110m.json';
import { SEVERITY_COLORS, SeverityBadge } from '../common.jsx';

const W = 720;
const H = 360;
const SEV_RANK = { CRITICAL: 3, HIGH: 2, MEDIUM: 1, LOW: 0 };

/** Equirectangular projection: lon/lat → SVG x/y. */
const px = (lon) => ((lon + 180) / 360) * W;
const py = (lat) => ((90 - lat) / 180) * H;

function landPaths() {
  const fc = feature(land110, land110.objects.land);
  return fc.features
    .map((f) =>
      (f.geometry.coordinates || [])
        .map((ring) =>
          ring
            .map(([lon, lat], i) =>
              `${i === 0 ? 'M' : 'L'}${px(lon).toFixed(1)} ${py(lat).toFixed(1)}`
            )
            .join(' ') + ' Z'
        )
        .join(' ')
    )
    .join(' ');
}

const LAND = landPaths();

export default function ThreatMap({ alerts = [], topSrcIps = [], geoEnabled = false }) {
  const markers = useMemo(() => {
    const byIp = new Map();
    for (const a of alerts) {
      const geo = a.geo;
      if (!geo || geo.lat === null || geo.lon === null) continue;
      const sev = String(a.severity || 'LOW').toUpperCase();
      const cur = byIp.get(a.src_ip);
      if (!cur) {
        byIp.set(a.src_ip, {
          ip: a.src_ip,
          lat: geo.lat,
          lon: geo.lon,
          count: 1,
          worst: sev,
          country: geo.country || null,
          city: geo.city || null,
          last: new Date(a.timestamp).getTime() || 0,
        });
      } else {
        cur.count += 1;
        if ((SEV_RANK[sev] || 0) > (SEV_RANK[cur.worst] || 0)) cur.worst = sev;
        const t = new Date(a.timestamp).getTime() || 0;
        if (t > cur.last) cur.last = t;
      }
    }
    return [...byIp.values()].sort((a, b) => b.count - a.count).slice(0, 40);
  }, [alerts]);

  const maxCount = markers.length ? Math.max(...markers.map((m) => m.count)) : 1;
  const now = Date.now();
  const withGeo = markers.length > 0;

  return (
    <div>
      <div className="map-box">
        <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="xMidYMid meet">
          {/* graticule */}
          {[-60, 0, 60].map((lat) => (
            <line key={`g${lat}`} className="map-grid" x1="0" y1={py(lat)} x2={W} y2={py(lat)} />
          ))}
          {[-120, -60, 0, 60, 120].map((lon) => (
            <line key={`v${lon}`} className="map-grid" x1={px(lon)} y1="0" x2={px(lon)} y2={H} />
          ))}
          <path d={LAND} className="map-land" opacity={withGeo ? 1 : 0.45} />
          {markers.map((m) => {
            const x = px(m.lon);
            const y = py(m.lat);
            const r = 3.5 + 4 * (m.count / maxCount);
            const color = SEVERITY_COLORS[m.worst] || SEVERITY_COLORS.LOW;
            const pulsing = now - m.last < 10 * 60 * 1000;
            return (
              <g key={m.ip} className="map-marker">
                {pulsing && (
                  <circle cx={x} cy={y} r={r} fill="none" stroke={color} strokeWidth="1" className="map-marker-pulse" />
                )}
                <circle cx={x} cy={y} r={r} fill={color} fillOpacity="0.85" stroke="#0d1117" strokeWidth="0.8">
                  <title>
                    {m.ip} — {m.count} alert(s), worst: {m.worst}
                    {m.country ? ` (${m.country}${m.city ? ', ' + m.city : ''})` : ''}
                  </title>
                </circle>
              </g>
            );
          })}
        </svg>
      </div>

      <div style={{ display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: 10, marginTop: 8 }}>
        <div className="legend">
          {Object.entries(SEVERITY_COLORS).map(([sev, color]) => (
            <span key={sev}>
              <span className="swatch" style={{ background: color }} />
              {sev}
            </span>
          ))}
          <span>marker size = alert count</span>
        </div>
        {!geoEnabled && (
          <span className="muted" style={{ fontSize: 11 }}>
            Geo-IP enrichment disabled — set GEOIP_MMDB on the backend to plot locations
          </span>
        )}
      </div>

      {!withGeo && topSrcIps.length > 0 && (
        <div style={{ marginTop: 12 }}>
          <div className="panel-sub" style={{ marginBottom: 6 }}>
            Top observed source IPs
          </div>
          {topSrcIps.slice(0, 8).map(({ ip, count }) => {
            const max = topSrcIps[0] ? topSrcIps[0].count : 1;
            return (
              <div key={ip} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 5 }}>
                <span className="mono" style={{ width: 130, fontSize: 11 }}>{ip}</span>
                <div style={{ flex: 1, height: 6, background: '#1c2330', borderRadius: 3, overflow: 'hidden' }}>
                  <div style={{ width: `${(count / max) * 100}%`, height: '100%', background: 'var(--accent)' }} />
                </div>
                <span className="muted mono" style={{ fontSize: 11 }}>{count}</span>
              </div>
            );
          })}
        </div>
      )}

      {!withGeo && topSrcIps.length === 0 && (
        <div className="empty">No source IPs observed yet.</div>
      )}

      {withGeo && (
        <div style={{ marginTop: 10, maxHeight: 120, overflowY: 'auto' }}>
          <table className="data">
            <thead>
              <tr><th>Source</th><th>Location</th><th>Worst</th><th>Alerts</th></tr>
            </thead>
            <tbody>
              {markers.slice(0, 10).map((m) => (
                <tr key={m.ip}>
                  <td className="mono">{m.ip}</td>
                  <td>{m.country ? `${m.country}${m.city ? ' · ' + m.city : ''}` : '—'}</td>
                  <td><SeverityBadge severity={m.worst} /></td>
                  <td className="mono">{m.count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

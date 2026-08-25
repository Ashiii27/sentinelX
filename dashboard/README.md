# SentinelX — React Dashboard

SOC console for SentinelX: live alert feed, threat map, kill-chain and
MITRE ATT&CK views, full alert browser with triage, and YARA rule
management.

## Stack

- **React 18 + Vite** — SPA, dark theme, no CSS framework
- **react-router-dom** — `Overview` / `Alerts` / `Settings`
- **recharts** — severity, type, and 24 h volume charts
- **axios** — REST client (`src/services/api.js`)
- **topojson-client + world-atlas** — bundled Natural Earth basemap for
  the Threat Map (no runtime CDN calls)
- **WebSocket** — live alerts via `src/services/socket.js`
  (auto-reconnect with backoff, one shared socket per page)

## Running

```bash
cd dashboard
npm install
npm run dev          # http://localhost:5173 (proxies /api + /ws → :4000)
```

The backend must be running (default port 4000). The Vite dev server
proxies `/api/*` and `/ws` to `SENTINELX_BACKEND` (default
`http://127.0.0.1:4000`), so all browser calls are same-origin — the
same setup works in production behind `deployment/nginx.conf`.

```bash
npm run build        # static bundle in dist/
npm run preview      # serve the bundle locally (port 4173, same proxy)
```

### Configuration

| Env var | Default | Purpose |
|---|---|---|
| `VITE_API_URL` | `/api` | API base URL override (only if the API is cross-origin) |
| `SENTINELX_BACKEND` | `http://127.0.0.1:4000` | dev/preview proxy target |

## Data flow

```
engine ──(NDJSON over Unix socket)──▶ backend ──▶ MongoDB / memory
                                              │
                       REST /api/* ◀──────────┤   WebSocket /ws
                                              ▼
                       React (axios + LiveSocket)
```

- `useAlerts` = REST page + WebSocket splice (deduped by `alert_id`,
  newest first, capped in memory)
- `useWebSocket` = connection status + live alert / history callbacks
- Charts poll `GET /api/stats/summary` every 15 s; health every 10 s

## Threat Map & Geo-IP

The map basemap is bundled (`world-atlas` 110 m land). Markers are
plotted from the `geo` object the backend attaches to each alert **only
when** `GEOIP_MMDB` (MaxMind GeoLite2-City) is configured — see
`backend/.env.example`. Without geo-IP the map renders dimmed and the
panel falls back to a ranked top-source-IP list, so the dashboard stays
useful either way.

## Pages

| Route | Contents |
|---|---|
| `/` | stat cards, live feed, threat map, severity/type/volume charts, kill chain, MITRE matrix |
| `/alerts` | filters (severity, type, source IP, time window), pagination, FP/reviewed triage, delete |
| `/settings` | backend health (engine bridge, DB mode, geo-IP, uptime), YARA rule manager (create / delete / hot-reload) |

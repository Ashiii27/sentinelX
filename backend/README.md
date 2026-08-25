# SentinelX — Backend (Node.js)

Alert ingestion, persistence, and API layer. Sits between the C++
detection engine and the React dashboard:

```
C++ engine ──(Unix socket, NDJSON)──▶ EngineIngestion
                                              │
                                     AlertStore ──▶ MongoDB (Mongoose)
                                              │         (in-memory fallback)
                       ┌──────────────────────┴─────────────────────┐
                       │                                            │
                REST API (Express)                          WebSocket (ws)
                /api/alerts /api/stats                      /ws — live broadcast
                /api/rules                                    + history on connect
                       │                                            │
                       └────────────────────▶  React dashboard  ◀──┘
```

## Running

```bash
cp .env.example .env        # edit MONGO_URI / ENGINE_SOCKET
npm install
npm start                   # REST on :4000, WS on ws://:4000/ws
npm run dev                 # auto-restart on change
```

The engine must point at the same socket path:

```bash
sudo ./engine/build/sentinelx --output socket \
     --socket /run/sentinelx/alerts.sock
```

### Database

* **MongoDB** (default): persistent storage, full query API, 30-day TTL
  index on alerts.
* **In-memory fallback**: if Mongo is unreachable at startup the backend
  logs a warning and runs with a bounded in-memory ring buffer (default
  20k alerts). Every endpoint and the live stream keep working; only
  persistence across restarts is lost. The mode is visible in
  `GET /api/health` (`"db": "mongodb" | "in-memory"`).

## REST API

| Method | Path | Description |
|---|---|---|
| GET | `/api/health` | Service, db mode, engine + WS stats |
| GET | `/api/alerts` | List alerts. Filters: `severity, type, src_ip, dst_ip, technique, reviewed, false_positive, from, to, page, limit (≤500), sort=oldest` |
| GET | `/api/alerts/:id` | One alert |
| PUT | `/api/alerts/:id` | Triage: `{ "false_positive": bool, "reviewed": bool }` |
| DELETE | `/api/alerts/:id` | Remove an alert |
| GET | `/api/stats/summary` | Totals by severity/type/MITRE, 24h hourly series, top source IPs, engine + WS status |
| GET | `/api/rules` | All YARA rules (parsed: name, meta, file, line) |
| GET | `/api/rules/:name` | One rule file + parsed rules |
| POST | `/api/rules` | Create rule file `{ filename, content }` |
| PUT | `/api/rules/:name` | Replace rule file content |
| DELETE | `/api/rules/:name` | Delete rule file |
| POST | `/api/rules/reload` | Hot-reload: SIGUSR1 to the engine (needs `ENGINE_PID_FILE`) |

Rule files are written atomically (tmp + rename) — the engine can never
read a half-written rule.

## WebSocket protocol (`/ws`)

Server → client, JSON per frame:

```jsonc
{ "type": "hello",   "data": { "clients": 2, "time": "..." } }
{ "type": "history", "data": [ /* ≤50 most recent alerts */ ] }
{ "type": "alert",   "data": { /* engine alert JSON, verbatim */ } }
{ "type": "stats",   "data": { "clients": 3 } }   // on connect/disconnect
```

Clients get the last N alerts on connect (configurable via
`WS_HISTORY_COUNT`) so a refreshed dashboard tab doesn't lose the last
few minutes. 30 s ping/pong keepalive prunes dead clients.

## Configuration (`.env`)

| Var | Default | Purpose |
|---|---|---|
| `PORT` | `4000` | REST + WS port |
| `CORS_ORIGIN` | `*` | Comma list or `*` |
| `MONGO_URI` | `mongodb://127.0.0.1:27017/sentinelx` | Database |
| `ENGINE_SOCKET` | `/run/sentinelx/alerts.sock` | Engine bridge path |
| `RULES_DIR` | `<repo>/engine/rules` | YARA rule files |
| `ENGINE_PID_FILE` | `/run/sentinelx/sentinelx.pid` | For hot reload |
| `MEMORY_ALERT_CAP` | `20000` | In-memory buffer size |
| `WS_HISTORY_COUNT` | `50` | History replay length |

## Tests

```bash
npm test
```

`node:test` suites (no extra dependencies):

* `alert_store.test.js` — store semantics: dedupe, filters, pagination,
  time ranges, triage, eviction, summary aggregation
* `ingestion.test.js` — real Unix socket: NDJSON framing, split frames,
  malformed lines, duplicate suppression, engine restart
* `api.test.js` — end-to-end: fake engine → socket → store → REST +
  live WebSocket broadcast, rules CRUD over a temp directory

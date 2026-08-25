# SentinelX — API Reference

REST API (Express, `:4000`) + WebSocket stream (`/ws`). All request
and response bodies are JSON. In production both are served
same-origin through nginx (`deployment/nginx.conf`); in dev the Vite
proxy forwards them.

Base path: **`/api`** (all paths below are relative to it).

---

## Contents

- [Health](#health)
- [Alerts](#alerts)
  - [List alerts](#list-alerts)
  - [Get alert](#get-alert)
  - [Triage alert](#triage-alert)
  - [Delete alert](#delete-alert)
- [Stats](#stats)
- [Rules](#rules)
  - [List rules](#list-rules)
  - [Get rule file](#get-rule-file)
  - [Create rule file](#create-rule-file)
  - [Update rule file](#update-rule-file)
  - [Delete rule file](#delete-rule-file)
  - [Hot-reload engine](#hot-reload-engine)
- [WebSocket stream](#websocket-stream)
- [Alert object](#alert-object)
- [Errors](#errors)

---

## Health

### `GET /health`

Liveness + component status.

```jsonc
{
  "status": "ok",
  "service": "sentinelx-backend",
  "version": "1.0.0",
  "db": "in-memory",            // "mongodb" | "in-memory"
  "engine": {                   // null if ingestion is disabled
    "connected": true,          // engine socket client currently attached
    "connections": 1,           // lifetime engine connections
    "alerts": 42,               // new alerts ingested
    "duplicates": 2,            // suppressed duplicate alert_ids
    "malformed": 0,             // malformed NDJSON lines skipped
    "last_alert_at": "2026-08-25T04:27:46.342Z"
  },
  "geoip": { "enabled": false },
  "ws": { "clients": 1, "attached": true },
  "uptime_seconds": 1834
}
```

---

## Alerts

### List alerts

`GET /alerts?page=1&limit=50&sort=latest&severity=HIGH&type=PORT_SCAN&src_ip=203.0.113.9&dst_ip=192.168.1.100&technique=T1046&from=2026-08-25T00:00:00Z&to=2026-08-25T23:59:59Z&reviewed=true&false_positive=false`

| Param | Default | Notes |
|---|---|---|
| `page` | 1 | 1-based |
| `limit` | 50 | max 500 |
| `sort` | `latest` | `latest` \| `oldest` (by `timestamp`) |
| `severity` | — | `LOW`\|`MEDIUM`\|`HIGH`\|`CRITICAL` (case-insensitive) |
| `type` | — | `PORT_SCAN`\|`SYN_FLOOD`\|`HTTP_ANOMALY`\|`HONEYPOT_HIT`\|`YARA_MATCH` |
| `src_ip` / `dst_ip` | — | exact match |
| `technique` | — | `mitre.technique_id`, e.g. `T1046` |
| `from` / `to` | — | ISO 8601, inclusive bounds on `timestamp` |
| `reviewed` | — | `true`\|`false` |
| `false_positive` | — | `true`\|`false` |

**200**

```jsonc
{
  "items": [ /* Alert objects, see [Alert object](#alert-object) */ ],
  "total": 128,
  "page": 1,
  "limit": 50
}
```

### Get alert

`GET /alerts/:id` — `id` is the `alert_id`.

**200** → `Alert` · **404** → `{"error":"alert not found","id":"…"}`

### Triage alert

`PUT /alerts/:id`

```json
{ "false_positive": true, "reviewed": true }
```

Either field (or both) may be sent. Sets the boolean as given.

**200** → updated `Alert` · **400** → `{"error":"nothing to update…"}` · **404**

### Delete alert

`DELETE /alerts/:id`

**200** → `{"deleted":true}` · **404** → `{"error":"alert not found"}`

---

## Stats

### `GET /stats/summary`

Dashboard aggregation (no filters).

```jsonc
{
  "total": 128,
  "by_severity": { "LOW": 0, "MEDIUM": 3, "HIGH": 96, "CRITICAL": 29 },
  "by_type": { "PORT_SCAN": 40, "SYN_FLOOD": 12, "HTTP_ANOMALY": 51, "HONEYPOT_HIT": 20, "YARA_MATCH": 5 },
  "by_kill_chain": { "Reconnaissance": 60, "Exploitation": 51, "Actions on Objectives": 17 },
  "by_mitre": [
    { "technique_id": "T1046", "count": 60 },
    { "technique_id": "T1190", "count": 51 }
  ],
  "hourly_24h": [
    { "hour": "2026-08-24T05:00:00.000Z", "count": 4 }
  ],
  "top_src_ips": [
    { "ip": "203.0.113.9", "count": 33 }
  ],
  "engine": { /* same object as /health */ },
  "ws": { "clients": 1, "attached": true },
  "db_mode": "in-memory",
  "uptime_seconds": 1834
}
```

- `by_mitre` — top 10 techniques by count.
- `hourly_24h` — only non-empty hours in the last 24 h (dashboard fills gaps).
- `top_src_ips` — top 10 source IPs by alert count.

---

## Rules

Rules are **files** in the engine rules directory (`RULES_DIR`,
default `engine/rules`). CRUD here edits those files directly
(atomic tmp+rename); the engine picks changes up on next load or
via the hot-reload endpoint.

File names must match `^[a-z0-9][a-z0-9_-]*\.(yar|yara)$`. Max size
1 MB.

### List rules

`GET /rules`

**200** — flat list, one entry per rule parsed from every file:

```jsonc
{
  "directory": "/home/user/sentinelX/engine/rules",
  "rules": [
    {
      "name": "shellcode_nop_sled",
      "file": "shellcode_patterns.yar",
      "meta": { "severity": "HIGH", "mitre": "T1059", "mitre_name": "Command and Scripting Interpreter", "description": "NOP sled — at least 10 consecutive 0x90 bytes" },
      "string_count": 3,
      "line": 12
    }
  ]
}
```

### Get rule file

`GET /rules/:name` — `:name` is the file name (with or without
extension).

**200**

```jsonc
{
  "name": "shellcode_patterns.yar",
  "content": "rule shellcode_nop_sled { … }",
  "rules": [ /* parsed rules for this file */ ]
}
```

**404** if the file doesn't exist · **400** for path traversal attempts.

### Create rule file

`POST /rules`

```json
{ "filename": "my_rules.yar", "content": "rule … { … }" }
```

**201** → `{"filename":"my_rules.yar","rules":[…],"note":"saved — POST /api/rules/reload to load it into the running engine"}`
· **400** bad filename/empty content/too large · **409** already exists

### Update rule file

`PUT /rules/:name` — body `{"content": "…"}`.

**200** → same shape as create · **400** · **404**

### Delete rule file

`DELETE /rules/:name`

**200** → `{"deleted":true,"filename":"…"}` · **404**

### Hot-reload engine

`POST /rules/reload`

Sends **SIGUSR1** to the engine PID read from `ENGINE_PID_FILE`
(default `/run/sentinelx/sentinelx.pid`). The engine re-reads
`RULES_DIR` and rebuilds its YARA rule sets in place.

**200** → `{"reloaded":true}` or
`{"reloaded":false,"detail":"no engine pid file at /run/sentinelx/sentinelx.pid — restart the engine to pick up rule changes"}`

---

## WebSocket stream

Connect: **`ws://<host>/ws`** (same origin as the API in production).

Server → client frames (all JSON):

| `type` | `data` | When |
|---|---|---|
| `hello` | `{ "service": "sentinelx-backend", "clients": n, "time": ISO }` | immediately on connect |
| `history` | `Alert[]` (newest-first, up to `WS_HISTORY_COUNT`, default 50) | right after `hello` |
| `alert` | `{ "alert": Alert, "clients": n }` | every new alert ingested |
| `clients` | `{ "clients": n }` | on client join/leave |

Client → server: no messages required. The server sends ping
keepalives; the client just needs a conforming WS implementation
(browsers answer pong automatically).

Reconnect behavior is a client concern — the dashboard's `LiveSocket`
retries with exponential backoff (1 s → 15 s cap) and re-fetches
history on each connect, so a dropped connection self-heals.

---

## Alert object

The single schema shared by engine → socket → store → REST → WS →
dashboard (see `docs/architecture.md` §6 for the contract):

```jsonc
{
  "alert_id": "1787632066339_eb44cad9",
  "timestamp": "2026-08-25T04:27:46Z",
  "severity": "HIGH",
  "type": "PORT_SCAN",
  "src_ip": "203.0.113.9",
  "dst_ip": "192.168.1.100",
  "src_port": 40001,
  "dst_port": 22,
  "protocol": "TCP",
  "tcp_flags": 2,
  "mitre": {
    "technique_id": "T1046",
    "technique_name": "Network Service Discovery",
    "tactic": "Discovery",
    "kill_chain_phase": "Reconnaissance",
    "reference_url": "https://attack.mitre.org/techniques/T1046/"
  },
  "evidence": {
    "packet_count": 10,
    "ports_contacted": [21, 22, 23, 25, 80, 110, 135, 139, 443, 1433],
    "scan_type": "SYN",
    "window_seconds": 5,
    "extra": { "first_seen_ms": 1700000000000, "last_seen_ms": 1700000000540 }
  },
  "yara_match": null,
  "raw_payload_hash": null,
  "description": "Port scan detected: 203.0.113.9 probed 10 distinct ports on 192.168.1.100 within 5s (type: SYN)",
  "geo": null,
  "false_positive": false,
  "reviewed": false
}
```

Field notes:

- `alert_id` — unique per emission (ms-epoch + random suffix); the
  dedupe key everywhere.
- `evidence` — detector-specific: `PORT_SCAN` (ports, scan type),
  `SYN_FLOOD` (ratios, top source), `HTTP_ANOMALY` (method, path,
  kind), `HONEYPOT_HIT` (port, mimicked service), `YARA_MATCH`
  (rule, file, strings).
- `yara_match` — non-null only for `YARA_MATCH` alerts.
- `geo` — added by the backend when `GEOIP_MMDB` is configured;
  otherwise `null`.
- `false_positive` / `reviewed` — triage, mutated only via
  `PUT /alerts/:id`.

---

## Errors

Errors are JSON: `{"error": "message", …}`.

| Status | Meaning |
|---|---|
| 400 | bad input (filename, body, parameters) |
| 404 | unknown alert / rule file / API path |
| 409 | rule file already exists |
| 500 | unexpected server error (stack logged server-side only) |

Unknown `/api/*` paths return `404 {"error":"not found","path":"…"}`
(never an HTML page).

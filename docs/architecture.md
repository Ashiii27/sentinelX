# SentinelX — System Architecture

A deep dive into how SentinelX is designed: the capture → detect → alert
→ store → visualize pipeline, the contracts between components, and the
failure modes the system is built to survive.

---

## 1. Design goals

1. **Real Blue-Team shape.** The pipeline mirrors how production NIDS
   tooling is layered: a fast, stateful detection core in C++; a
   durable, queryable API layer in Node.js; a visualization layer in
   React. Each layer can be rebuilt, replaced, or scaled without
   touching the others.
2. **The alert is the contract.** Every component speaks the same
   JSON alert schema (`engine/include/Alert.h` → NDJSON → Mongoose
   model → REST → WebSocket → dashboard). If you can read one alert
   object, you can read every layer.
3. **Graceful degradation.** Missing MongoDB → in-memory ring buffer.
   Missing GeoLite2 → geo-IP off, alerts unchanged. Engine down →
   backend keeps serving history, WS keeps working, dashboard shows
   "engine down". No single missing piece takes down the console.
4. **Zero false-positive by construction** where possible — e.g. the
   honeypot detector only fires on ports that legitimately never serve
   anything.

---

## 2. Topology

```
                    ┌────────────────────────────────────────────────┐
   NIC (promisc)    │                C++ ENGINE (root)               │
   ┌───────────┐    │  ┌──────────┐   ┌───────────────────────────┐  │
   │  packets  │    │  │ libpcap  │──▶│  Parser chain             │  │
   └───────────┘    │  │ capture/ │   │  IP → TCP → HTTP          │  │
        │           │  └──────────┘   └────────────┬──────────────┘  │
        │           │                              ▼                 │
        │           │  ┌──────────────────────────────────────────┐  │
        │           │  │ Detectors (per-packet, stateful)         │  │
        │           │  │  PortScan · SYNFlood · HTTPAnomaly ·     │  │
        │           │  │  Honeypot · YARA scanner                 │  │
        │           │  └────────────┬─────────────────────────────┘  │
        │           │               ▼                                │
        │           │  ┌──────────────────────────┐                  │
        │           │  │ AlertEmitter (NDJSON)    │                  │
        │           │  │  stdout | Unix socket    │                  │
        │           │  └────────────┬─────────────┘                  │
        │           └───────────────┼────────────────────────────────┘
        │                           │ NDJSON, one alert per line
        │                           ▼
        │           ┌────────────────────────────────────────────────┐
        │           │             NODE.JS BACKEND (:4000)            │
        │           │  ┌─────────────────┐     ┌──────────────────┐  │
        │           │  │ EngineIngestion │────▶│ AlertStore       │  │
        │           │  │ (listens on the │     │  Mongo ⇄ memory  │  │
        │           │  │  engine socket) │     └────────┬─────────┘  │
        │           │  └─────────────────┘              │            │
        │           │        │              ┌───────────┴─────────┐  │
        │           │        ▼              ▼                     ▼  │
        │           │  ┌─────────────┐  REST /api/alerts…   /stats   │
        │           │  │ AlertStream │  /api/health           /rules │
        │           │  │ (ws /ws)    │                            ▲  │
        │           │  └──────┬──────┘                            │  │
        │           └─────────┼────────────────────────────────────┼──┘
        │                     │ WebSocket JSON frames              │
        │                     ▼                                    │
        │           ┌─────────────────────┐      ┌─────────────────┴──┐
        │           │      DASHBOARD      │─────▶│  (axios REST for   │
        │           │  React + Vite       │      │   initial load &   │
        │           │  feed/map/matrix    │      │   charts)          │
        │           └─────────────────────┘      └────────────────────┘
```

### Process model

| Process | Runs as | Owns | Lifecycle |
|---|---|---|---|
| `sentinelx` (engine) | root (raw sockets) | NIC capture, detector state, YARA VMs, Unix socket **client** | systemd `sentinelx.service` / compose `engine` |
| `node src/app.js` (backend) | root (socket dir) | REST+WS server, alert store, socket **listener**, rules CRUD | systemd `sentinelx-backend.service` / compose `backend` |
| browser (dashboard) | — | REST + WS clients, local render state | static build behind nginx / Vite dev |

The engine connects **to** the backend's Unix socket (client of the
listener). That directionality is deliberate: the backend is the
stable endpoint, the engine may start after it, crash, or be
restarted with new rules — each reconnect is just a new client.

---

## 3. The engine

### 3.1 Packet path

```
libpcap live loop (or pcap replayer)
   │  (raw bytes, capture timestamp)
   ▼
IPParser      — validation, IPv4/IPv6, ICMP handled, payload slice
   ▼
TCPParser     — flags, sequence, connection direction, scan-type
                classification (SYN / NULL / FIN / XMAS / UDP)
   ▼
HTTPParser    — method, path, headers (bounded), body presence
   ▼
Detector pipeline  (each detector sees every packet; returns 0..n alerts)
   ▼
YARA scanner       (payload bytes scanned per rule file, deduped by
                    matched rule + payload hash)
   ▼
AlertEmitter      — Alert struct → JSON → stdout | socket (NDJSON)
```

Parsers are pure functions over `const uint8_t*` + length; they never
allocate except for the small number of HTTP header strings they must
extract. Detectors hold **sliding-window state** keyed by
`(src_ip, dst_ip)` or destination IP and must bound that state
(`max_tracked_*` caps + periodic `tick()` purges from the main loop)
— this is what keeps the engine O(traffic), not O(history).

### 3.2 Time

All window math is done on **packet timestamps in ms**, not the wall
clock. That makes replay deterministic (a 2-hour capture replays with
its original windowing) and makes unit tests fast (inject synthetic
timings). The main loop still calls `tick(now_ms)` periodically so
window state is purged even when traffic goes quiet.

### 3.3 Output modes

- `--output stdout` — one JSON object per line, for demos/pipe.
- `--output socket` (default) — the engine connects to
  `--socket <path>` (default `/run/sentinelx/alerts.sock`) and sends
  NDJSON. Reconnects with backoff if the backend is briefly down;
  emits a startup banner and periodic stats to stderr.

### 3.4 YARA integration

Rule files (`engine/rules/*.yar`) are compiled **per file** into
separate YARA rule sets. The scanner runs every payload through each
compiled set. Match results attach to an alert as:

```json
"yara_match": {
  "rule_name": "shellcode_nop_sled",
  "rule_file": "shellcode_patterns.yar",
  "matched_strings": ["$nop10"],
  "payload_hash": "sha256:…"
}
```

Rule `meta:` fields (`severity`, `mitre`, `kill_chain_phase`,
`description`) drive the alert's severity and MITRE mapping — the
detection data is data, not code.

---

## 4. The backend

### 4.1 EngineIngestion

Listens on the configured Unix socket. Per connection it:

1. accepts exactly one engine at a time (a second connection replaces
   the first — that *is* the engine-restart path),
2. accumulates bytes and splits on `\n` (NDJSON framing), tolerating
   frames that arrive split across reads (buffered reassembly) and
   counting malformed lines instead of wedging,
3. optionally enriches each alert with GeoLite2 (`geo` object) when
   `GEOIP_MMDB` is configured,
4. hands the alert to the store (dedupe on `alert_id`) and, if new,
   broadcasts it over the WS stream.

A 1 MB cap on the unflushed buffer bounds memory on protocol
violations (e.g. binary garbage with no newlines).

### 4.2 AlertStore (the "is Mongo up?" firewall)

One interface, two backends:

| Operation | MongoDB | In-memory |
|---|---|---|
| add | `updateOne($setOnInsert)` upsert on `alert_id` | Map insert, `alert_id` dedupe, ring-buffer eviction at `cap` |
| list | filter + sort + skip/limit | same filter semantics in JS |
| summary | `$group` aggregations | equivalent JS passes |
| triage | `findOneAndUpdate` | in-place patch |

Consequences of the design:

- **Dedupe is idempotent and first-wins** in both backends — engine
  replays of the same capture never double-count.
- The memory fallback is a **ring buffer** (`MEMORY_ALERT_CAP`,
  default 20 000) — oldest evicted first, so a flood can't OOM the
  backend.
- 30-day TTL index on Mongo alerts (SOC retention, not a database
  policy).

### 4.3 AlertStream (WebSocket)

Attached to the same HTTP server (path `/ws`). On connect the client
receives, in order:

```
{ "type": "hello",   "data": { "service": "sentinelx-backend", "clients": n, "time": … } }
{ "type": "history", "data": [ …last N alerts, oldest→newest… ] }   // N = WS_HISTORY_COUNT
{ "type": "alert",   "data": { "alert": {…}, "clients": n } }       // live
{ "type": "clients", "data": { "clients": n } }                     // on join/leave
```

Ping/pong keepalive from the server; dead clients are pruned, and the
broadcast never throws into the store path (a broken client can't
affect ingestion).

### 4.4 Rules management

Rules are **files on disk** — the engine loads exactly what is in
`RULES_DIR`. The backend provides CRUD over those files (atomic
write-tmp-then-rename, filename validation, 1 MB cap) plus
`POST /api/rules/reload`, which sends **SIGUSR1** to the PID in
`ENGINE_PID_FILE` (the engine rebuilds its YARA rule sets in place).
If the engine isn't running (no pid file) the endpoint reports it
instead of failing silently.

---

## 5. The dashboard

- **Initial state** comes from REST (`GET /alerts`, `GET
  /api/stats/summary`); **ongoing state** comes from the WebSocket
  (live alerts spliced in, deduped, capped at 500 per page in the
  browser).
- One shared `LiveSocket` per page (auto-reconnect, exponential
  backoff capped at 15 s).
- Charts poll `summary` every 15 s; health every 10 s; the status bar
  shows stream state, engine state, and DB mode at a glance.
- The Threat Map basemap is **bundled** (Natural Earth 110 m via
  `world-atlas`); marker positions come from backend geo-IP
  enrichment. Without `GEOIP_MMDB` the panel degrades to a
  top-source-IP ranking — the UI never shows fake locations.
- Built with Vite; served by nginx (`deployment/nginx.conf`) with
  SPA history-mode fallback, `/api` and `/ws` proxied to the backend
  so the browser only ever speaks to one origin.

---

## 6. Contracts

### 6.1 Alert schema (the one schema)

```jsonc
{
  "alert_id": "1787632066339_eb44cad9",        // ms-epoch + 8 hex, unique per emission
  "timestamp": "2026-08-25T04:27:46Z",         // ISO 8601 (packet time in replay)
  "severity": "HIGH",                           // LOW|MEDIUM|HIGH|CRITICAL
  "type": "PORT_SCAN",                          // detector id
  "src_ip": "203.0.113.9",
  "dst_ip": "192.168.1.100",
  "src_port": 40001,
  "dst_port": 22,
  "protocol": "TCP",                            // TCP|UDP|ICMP|HTTP
  "tcp_flags": 2,                               // raw flag byte (0 for non-TCP)
  "mitre": {
    "technique_id": "T1046",
    "technique_name": "Network Service Discovery",
    "tactic": "Discovery",
    "kill_chain_phase": "Reconnaissance",
    "reference_url": "https://attack.mitre.org/techniques/T1046/"
  },
  "evidence": { /* detector-specific: ports, ratios, HTTP fields… */ },
  "yara_match": null,                            // see §3.4
  "raw_payload_hash": null,                      // sha256:… when payload captured
  "description": "human-readable one-liner",
  "geo": null,                                   // backend-added when GEOIP_MMDB set
  "false_positive": false,                       // triage (backend-mutated)
  "reviewed": false                              // triage (backend-mutated)
}
```

### 6.2 NDJSON wire format

One alert per line, UTF-8, `\n`-terminated. The engine never sends
partial lines atomically across packets — but *TCP segments can split
mid-line*, which is why ingestion reassembles on newlines (both
sides tolerate framing splits).

### 6.3 Systemd signal contract

| Signal | Target | Meaning |
|---|---|---|
| SIGTERM | engine / backend | graceful shutdown (flush, unlink socket) |
| SIGUSR1 | engine | hot-reload YARA rules (sent by `POST /api/rules/reload`) |

---

## 7. Failure modes & behavior

| Failure | Behavior |
|---|---|
| MongoDB down at boot | backend starts **in-memory**; `db` in `/api/health` says `in-memory`; every alert still flows. |
| MongoDB dies mid-run | current mode is sticky (the store was built at boot); next boot re-detects. (No live switchover by design — partial writes across backends would corrupt dedupe.) |
| Engine down | ingestion stats show `connected: false`; WS keeps streaming history; dashboard status bar shows engine down. Engine reconnect on restart; new `alert_id`s flow, duplicates suppressed. |
| Engine restart (rule reload via SIGUSR1) | no reconnect needed — the socket connection persists; rule sets rebuilt in place. A full process restart = new client, old one dropped. |
| Malformed engine line | counted in `malformed`, skipped; ingestion continues. |
| GeoLite2 missing/broken | enricher disabled at boot (or per-lookup failure returns null); alerts unaffected. |
| Dashboard WS drops | client reconnects with backoff; on reconnect the server replays recent history, so the feed self-heals. |
| Alert flood | engine windows are capped; store caps memory; WS broadcast is O(clients); dashboard caps its local list. |
| Half-written rule file | impossible from the API (atomic tmp+rename); the engine only ever sees complete files. |

---

## 8. Security notes

- The engine runs as root (raw sockets) and nothing else does, except
  the backend when it needs to create `/run/sentinelx`.
- The backend binds REST+WS to `127.0.0.1`/localhost by default
  intent — production puts nginx in front (`deployment/nginx.conf`)
  and should restrict access to the API port at the firewall level.
- CORS is `*` by default (SOC consoles are usually same-origin via
  nginx); set `CORS_ORIGIN` to lock it down for cross-origin setups.
- Rule files are trusted code — the rules API writes to disk and the
  engine compiles them. Protect the API (nginx auth / VPN) if the
  dashboard is reachable beyond the SOC.
- Alerts can contain attacker-controlled strings (URLs, user agents).
  The dashboard renders them as text (React escaping) — never as
  HTML.

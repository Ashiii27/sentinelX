# SentinelX — Detection Engine

C++17 network intrusion detection engine. Captures live traffic with
libpcap (or replays pcap files offline), runs it through a pipeline of
detectors + YARA signature scanning, and emits JSON alerts (NDJSON) on
stdout or over a Unix socket to the SentinelX backend.

```
raw packet ──▶ IP parser ──▶ TCP/HTTP parsers
                          │
                          ▼
   ┌────────────┬──────────────┬───────────────┬────────────┐
   │ Honeypot   │ Port Scan    │ SYN Flood     │ HTTP       │   detectors
   │ Detector   │ Detector     │ Detector      │ Anomaly    │   (fixed order)
   └────────────┴──────────────┴───────────────┴────────────┘
                          │
                          ▼
              YARA signature scan (every TCP/UDP payload)
                          │
                          ▼
           Alert JSON (NDJSON) ──▶ stdout | Unix socket
```

## Building

Dependencies:

| Component  | Purpose                    | Install                          |
|------------|----------------------------|----------------------------------|
| CMake ≥ 3.16 | build system             | your package manager             |
| GCC/Clang (C++17) | compiler            | your package manager             |
| libpcap-dev  | live capture + pcap API    | `sudo apt install libpcap-dev`   |
| libyara-dev  | signature scanning         | `sudo apt install libyara-dev`   |

`nlohmann/json` is vendored in `third_party/` — nothing to install.

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

Optional CMake flags (both auto-detected; pass explicit paths when the
libraries live in a non-standard prefix):

```bash
cmake -S . -B build \
  -DPCAP_INCLUDE_DIR=/path/to/include \
  -DPCAP_LIBRARY=/path/to/libpcap.so \
  -DYARA_INCLUDE_DIR=/path/to/include \
  -DYARA_LIBRARY=/path/to/libyara.so
```

### Minimal build (no libpcap / no YARA)

The engine degrades gracefully and still compiles:

* **No libpcap** — live capture is unavailable; `PacketCapture` throws a
  clear error at startup. Offline replay (`--replay`) works fully: the
  replayer, parsers, detectors, and YARA (if present) never touch
  libpcap. `--list-interfaces` reports that it needs a libpcap build.
* **No YARA** — signature detection is disabled with a startup warning;
  all behavioral detectors keep working.

## Running

```
sentinelx [options]
```

### Live capture (requires root / CAP_NET_RAW)

```bash
sudo ./build/sentinelx -i eth0 -f "tcp or udp"
```

### Offline replay (no root required)

```bash
./build/sentinelx --replay capture.pcap --output stdout
./build/sentinelx --replay capture.pcap --loop        # demo mode
```

Replay supports classic (usec) and nanosecond pcaps, little- and
big-endian, Ethernet link type only. The file is replayed at native
timing — detector windows follow the *packet* timestamps, not wall
clock, so timing semantics are identical to live capture.

### Alert output

| Mode     | Where alerts go                                    |
|----------|----------------------------------------------------|
| `socket` (default) | Unix socket `/run/sentinelx/alerts.sock` (create the parent dir; the backend connects to this path) |
| `stdout`     | NDJSON on stdout (one JSON object per line)        |

One-line triage logs for HIGH/CRITICAL alerts also go to stderr, and a
stats/summary line is printed at shutdown.

### Key options

```
-i, --interface <name>     capture interface (default eth0)
-f, --bpf <expr>           BPF filter (default "tcp or udp")
--snaplen <n>              snap length (default 65535)
--no-promisc               disable promiscuous mode
--replay <file.pcap>       offline replay instead of live capture
--loop                     replay repeatedly until SIGINT (demo)
--output <mode>            stdout | socket (default socket)
--socket <path>            Unix socket path (default /run/sentinelx/alerts.sock)
--rules <dir>              YARA rules directory (default ./rules)
--honeypot <list>          e.g. "2222:SSH,8888:HTTP" (default 2222:SSH,8888:HTTP)
--scan-ports <n>           distinct ports triggering scan alert (default 10)
--syn-threshold <n>        SYNs/window triggering flood alert (default 100)
--stats-interval <s>       stats log interval (default 30)
--list-interfaces          list capture interfaces and exit
-V, --version / -h, --help
```

### Signals

| Signal        | Effect                              |
|---------------|-------------------------------------|
| SIGINT/SIGTERM | graceful shutdown + final summary |
| SIGUSR1        | hot-reload YARA rules from `--rules` dir |
| SIGPIPE        | ignored (backend restarts can't kill the engine) |

## YARA rules

Rules live in `engine/rules/` (three files, nine rules). Every rule
carries `meta` that drives the alert:

```yara
rule shellcode_nop_sled {
    meta:
        severity   = "HIGH"
        mitre      = "T1059"
        mitre_name = "Command and Scripting Interpreter"
        description = "NOP sled — at least 10 consecutive 0x90 bytes"
        author     = "SentinelX"
        reference  = "https://..."
    strings:
        $nop10 = { 90 * }
    condition:
        $nop10
}
```

* `severity` → alert severity (LOW/MEDIUM/HIGH/CRITICAL; unknown → HIGH)
* `mitre` / `mitre_name` / `reference` → ATT&CK mapping in the alert JSON
* `description` → human-readable match description

Load semantics: **each file is compiled in its own YARA compiler**, so a
single broken file is skipped with an error message while the rest of
the ruleset still loads (an analyst pushing one bad rule must not take
down the engine). Scans run with a 100 ms timeout so a pathological
rule can never wedge the packet pipeline.

Note on YARA 4.2.x distro builds: some ship the `YR_CONFIG_*` global
limits zero-initialized (`max_strings_per_rule = 0` makes every rule
fail to compile with "too many strings (limit: 0)"; `stack_size = 0`
makes every scan fail with `ERROR_EXEC_STACK_OVERFLOW`).
`YARAScanner::loadRules()` detects and restores the upstream defaults
once at first load.

## Detection capabilities

| Detector | What it catches | MITRE | Severity |
|----------|-----------------|-------|----------|
| Honeypot | Any TCP/UDP traffic to decoy ports (`--honeypot`) | T1046 | CRITICAL |
| Port scan | ≥ N distinct ports per source in a sliding 5 s window (SYN/NULL/FIN/XMAS/UDP) | T1046 | external HIGH, internal MEDIUM; +1 for stealth (NULL/FIN/XMAS) |
| SYN flood | ≥ N SYNs to one destination per window with no SYN-ACK responses | T1498.001 | HIGH; one CRITICAL escalation at 4× threshold |
| HTTP anomaly | Path traversal (raw + encoded), SQLi (raw + URL-decoded), null-byte WAF bypass, oversized headers, scanner User-Agents, unusual verbs (TRACE/TRACK/CONNECT), malformed HTTP | T1190 (T1595.002 for scanner UAs) | per-kind |
| YARA | Signature matches on every TCP/UDP payload ≤ 8 KB | per-rule meta | per-rule meta |

Cooldowns dedupe bursts: one alert per (source, kind) per cooldown
window per detector — a flood of matching packets produces one alert,
not one per packet.

## Alert JSON (NDJSON)

One JSON object per line:

```json
{
  "alert_id": "1787607694116_1065fe60",
  "timestamp": "2026-08-24T21:41:34Z",
  "severity": "HIGH",
  "type": "PORT_SCAN",
  "src_ip": "203.0.113.9", "dst_ip": "192.168.1.100",
  "src_port": 0, "dst_port": 1433, "protocol": "TCP", "tcp_flags": 0,
  "mitre": {
    "technique_id": "T1046",
    "technique_name": "Network Service Discovery",
    "tactic": "Discovery",
    "kill_chain_phase": "Reconnaissance",
    "reference_url": "https://attack.mitre.org/techniques/T1046/"
  },
  "evidence": {
    "scan_type": "SYN",
    "ports_contacted": [21, 22, 23],
    "window_seconds": 5,
    "packet_count": 10
  },
  "description": "Port scan detected: ...",
  "yara_match": null,
  "raw_payload_hash": null,
  "false_positive": false,
  "reviewed": false
}
```

Conventions:

* Network fields are **flattened** to the top level (not nested).
* `tcp_flags` is present only for TCP alerts.
* `evidence` includes only populated fields.
* `yara_match` and `raw_payload_hash` are **explicit `null`** when absent.
* `false_positive` / `reviewed` default to `false` and are flipped by
  the backend during triage.

## Testing

Eight standalone test suites (each an executable with its own `main`):

```bash
cmake -S . -B build -DSENTINELX_BUILD_TESTS=ON
cmake --build build -j
ctest --test-dir build --output-on-failure
```

| Suite | Covers |
|-------|--------|
| `test_parsers` | IP/TCP/HTTP parsers, edge cases, IP utility predicates |
| `test_port_scan` | window/threshold/cooldown, scan-type classification, severity by source |
| `test_syn_flood` | threshold crossing, ratio suppression, CRITICAL escalation, cadence |
| `test_http_anomaly` | every anomaly kind incl. URL-encoded and doubly-encoded payloads, cooldowns |
| `test_honeypot` | port registry, TCP+UDP, cooldown, service labels |
| `test_alert_json` | full JSON schema, escaping, Unix-socket round-trip, dead-socket clean-fail |
| `test_pcap_replayer` | LE/BE, usec/nsec, multi-packet, rewind, corrupt-file rejection |
| `test_yara` | rule loading, per-file fault isolation, matches, meta mapping, hot reload |

Detector tests use synthetic packets (zero-checksum, hand-built frames)
and injected millisecond timestamps, asserting exact alert counts.

## Source layout

```
engine/
├── CMakeLists.txt
├── README.md
├── rules/                    # YARA rules (9 rules, 3 files)
├── src/
│   ├── main.cpp              # CLI, pipeline, signal handling
│   ├── capture/              # PacketCapture (libpcap), PcapReplayer
│   ├── parsers/              # IP, TCP, HTTP parsers
│   ├── detectors/            # BaseDetector + 4 detectors
│   ├── yara/                 # YARAScanner (per-file rulesets)
│   ├── alerts/               # Alert model + JSON emitter (stdout/socket)
│   └── util/                 # SHA256 (manual, no OpenSSL dependency)
├── tests/                    # 8 suites + packet_builder helper
└── third_party/              # nlohmann/json (vendored)
```

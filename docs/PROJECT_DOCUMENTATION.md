# SentinelX — Complete Technical Specification & Documentation

> **A High-Performance, Host-Deployable Network Intrusion Detection System (NIDS)**  
> **Core Stack:** C++17 Engine (`libpcap`, `libyara`) · Node.js REST & WebSocket API · React SOC Console · MongoDB & In-Memory Fallback · MITRE ATT&CK Mapped

---

## Table of Contents

1. [Executive Summary & System Overview](#1-executive-summary--system-overview)
2. [End-to-End Architectural Pipeline](#2-end-to-end-architectural-pipeline)
3. [Component 1: The C++ Detection Engine (`engine/`)](#3-component-1-the-c-detection-engine-engine)
   - [3.1 Build System & Toolchain](#31-build-system--toolchain)
   - [3.2 Packet Capture & Ingestion Subsystem](#32-packet-capture--ingestion-subsystem)
   - [3.3 Zero-Copy Protocol Parsers](#33-zero-copy-protocol-parsers)
   - [3.4 Detection Modules Deep Dive](#34-detection-modules-deep-dive)
   - [3.5 Signature Inspection (YARA Engine)](#35-signature-inspection-yara-engine)
   - [3.6 Alert Formatting & IPC Emitter](#36-alert-formatting--ipc-emitter)
4. [Component 2: Node.js Ingestion & API Layer (`backend/`)](#4-component-2-nodejs-ingestion--api-layer-backend)
   - [4.1 Unix Domain Socket Listener & Stream Framing](#41-unix-domain-socket-listener--stream-framing)
   - [4.2 Schema Validation & Geo-IP Enrichment](#42-schema-validation--geo-ip-enrichment)
   - [4.3 Dual-Mode Persistence Architecture (MongoDB + Memory Ring Buffer)](#43-dual-mode-persistence-architecture-mongodb--memory-ring-buffer)
   - [4.4 REST API Specification](#44-rest-api-specification)
   - [4.5 Real-Time WebSocket Broadcasting Engine](#45-real-time-websocket-broadcasting-engine)
5. [Component 3: React SOC Dashboard (`dashboard/`)](#5-component-3-react-soc-dashboard-dashboard)
   - [5.1 UI Architecture & Component Topology](#51-ui-architecture--component-topology)
   - [5.2 Real-Time Alert Feed & Deep Inspection Drawer](#52-real-time-alert-feed--deep-inspection-drawer)
   - [5.3 Interactive Threat Map (Geo-IP)](#53-interactive-threat-map-geo-ip)
   - [5.4 MITRE ATT&CK Matrix & Kill Chain Navigator](#54-mitre-attck-matrix--kill-chain-navigator)
   - [5.5 YARA Rules Management & Engine Hot-Reloading](#55-yara-rules-management--engine-hot-reloading)
6. [Data Schema & System Contracts](#6-data-schema--system-contracts)
7. [Threat Modeling & MITRE ATT&CK Mapping](#7-threat-modeling--mitre-attck-mapping)
8. [Deployment, Infrastructure & Operations](#8-deployment-infrastructure--operations)
   - [8.1 Containerized Stack (`docker-compose.yml`)](#81-containerized-stack-docker-composeyml)
   - [8.2 Automated Bare-Metal Deployment (`install.sh`)](#82-automated-bare-metal-deployment-installsh)
   - [8.3 Reverse Proxy & Production Nginx Architecture](#83-reverse-proxy--production-nginx-architecture)
   - [8.4 CI/CD Pipeline (`.github/workflows/ci.yml`)](#84-cicd-pipeline-githubworkflowsciyml)
9. [Operational Guide & Testing Runbook](#9-operational-guide--testing-runbook)

---

## 1. Executive Summary & System Overview

**SentinelX** is a host-deployable Network Intrusion Detection System engineered to bring enterprise-grade Blue Team threat visibility to security analysts, DevOps engineers, and SOC teams.

Modern threat landscapes require detection systems that combine:
1. **Raw throughput and minimal latency** during deep packet inspection.
2. **Behavioral and signature-based correlation** across network layers (L3/L4/L7).
3. **Structured threat intelligence alignment** using the MITRE ATT&CK and Lockheed Martin Cyber Kill Chain frameworks.
4. **Resilient ergonomics**, ensuring that failure of any secondary subsystem (e.g., database network downtime or MaxMind database absence) degrades gracefully without blindfolding the security analyst or stopping packet capture.

SentinelX achieves these objectives by cleanly separating responsibilities into three isolated yet cohesive tiers:
- **Detection Core (`engine/`):** Written in modern C++17, utilizing Linux raw promiscuous sockets via `libpcap` or deterministic offline `.pcap` replays, executing high-speed protocol decoding, rate-based heuristic evaluation, and `libyara` payload inspection.
- **Service & Ingestion Layer (`backend/`):** An asynchronous Node.js engine consuming newline-delimited JSON (NDJSON) over local Unix domain sockets, performing GeoLite2 enrichment, schema validation, deduplication, and multi-tenant persistence.
- **Analyst Visualization Console (`dashboard/`):** A responsive React single-page application built on Vite, providing streaming alert feeds via WebSockets, interactive geospatial origin projection, MITRE ATT&CK matrix heatmaps, and in-browser rule compilation triggers.

---

## 2. End-to-End Architectural Pipeline

The following diagram illustrates the flow of a packet from the network interface controller through all parsing and detection stages, IPC transmission, persistence, and live SOC delivery:

```
                  ┌──────────────────────────────────────────────┐
                  │           PHYSICAL / VIRTUAL NIC             │
                  │        (Promiscuous Mode / Mirror Port)      │
                  └───────────────────────┬──────────────────────┘
                                          │ Raw Ethernet Frames
                                          ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           SENTINELX C++ ENGINE CORE                             │
│                                                                                 │
│   ┌───────────────────────────┐           ┌───────────────────────────────┐     │
│   │   PacketCapture (libpcap) │           │    PcapReplayer (Offline)     │     │
│   └─────────────┬─────────────┘           └──────────────┬────────────────┘     │
│                 │                                        │                      │
│                 └───────────────────┬────────────────────┘                      │
│                                     │ RawPacket (bytes, len, ts)                │
│                                     ▼                                           │
│                 ┌───────────────────────────────────────┐                       │
│                 │               IPParser                │                       │
│                 │   (IPv4 validation, checksum, split)  │                       │
│                 └───────────┬───────────────────────────┘                       │
│                             │                                                   │
│              ┌──────────────┴──────────────┐                                    │
│              ▼                             ▼                                    │
│      ┌───────────────┐             ┌───────────────┐                            │
│      │   TCPParser   │             │   UDPParser   │                            │
│      └───────┬───────┘             └───────┬───────┘                            │
│              │                             │                                    │
│              ▼                             │                                    │
│      ┌───────────────┐                     │                                    │
│      │  HTTPParser   │                     │                                    │
│      │  (L7 decode)  │                     │                                    │
│      └───────┬───────┘                     │                                    │
│              │                             │                                    │
│              └──────────────┬──────────────┘                                    │
│                             │ Parsed Context (5-Tuple + Payload)                │
│                             ▼                                                   │
│   ┌─────────────────────────────────────────────────────────────────────────┐   │
│   │                 STATEFUL & HEURISTIC DETECTOR PIPELINE                  │   │
│   │                                                                         │   │
│   │  [1] HoneypotDetector     --> Fast decoy port hit check (CRITICAL)       │   │
│   │  [2] PortScanDetector     --> Sliding 5s time-window per IP pair (HIGH) │   │
│   │  [3] SYNFloodDetector     --> SYN rate & SYN:SYN-ACK ratio check (HIGH) │   │
│   │  [4] HTTPAnomalyDetector  --> Path traversal, SQLi, scanner UA (HIGH)   │   │
│   │  [5] YARAScanner          --> libyara regex/binary rule match (DYNAMIC) │   │
│   └─────────────────────────────────────┬───────────────────────────────────┘   │
│                                         │ Emitted C++ Alert structs             │
│                                         ▼                                       │
│   ┌─────────────────────────────────────────────────────────────────────────┐   │
│   │                       AlertEmitter (NDJSON)                             │   │
│   │             Writes to /run/sentinelx/alerts.sock or stdout              │   │
│   └─────────────────────────────────────┬───────────────────────────────────┘   │
└─────────────────────────────────────────┼───────────────────────────────────────┘
                                          │ NDJSON Stream over Unix Socket
                                          ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                       NODE.JS INGESTION & BACKEND (:4000)                       │
│                                                                                 │
│  ┌──────────────────────────────┐          ┌─────────────────────────────────┐  │
│  │   EngineIngestion Service    │─────────▶│    GeoLite2 City Enrichment     │  │
│  │ (Unix Socket Stream Framer)  │          │   (lat, lon, country, city)     │  │
│  └──────────────┬───────────────┘          └────────────────┬────────────────┘  │
│                 │                                           │                   │
│                 └─────────────────────┬─────────────────────┘                   │
│                                       │ Enriched Alert JSON                     │
│                                       ▼                                         │
│  ┌───────────────────────────────────────────────────────────────────────────┐  │
│  │                         AlertStore Service                                │  │
│  │          ┌─────────────────────────────────────────────────────┐          │  │
│  │          │  MongoDB Active?                                    │          │  │
│  │          │    ├─ YES ──▶ Persist to Mongoose Collection        │          │  │
│  │          │    └─ NO  ──▶ Append to Ring-Buffer (10,000 Alerts) │          │  │
│  └──────────┴─────────────────────────┬───────────────────────────┴──────────┘  │
│                                       │                                         │
│                 ┌─────────────────────┴─────────────────────┐                   │
│                 ▼                                           ▼                   │
│  ┌──────────────────────────────┐          ┌─────────────────────────────────┐  │
│  │      REST API Controller     │          │    WebSocket AlertStream (/ws)  │  │
│  │  (/api/alerts, /stats, etc.) │          │   (Broadcasts live alert frame) │  │
│  └──────────────┬───────────────┘          └────────────────┬────────────────┘  │
└─────────────────┼───────────────────────────────────────────┼───────────────────┘
                  │ HTTP Requests                             │ WebSocket Frames
                  ▼                                           ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           REACT SOC DASHBOARD (SPA)                             │
│                                                                                 │
│   ┌───────────────────────┐   ┌───────────────────────┐   ┌─────────────────┐   │
│   │ Live Alert Feed Card  │   │ Leaflet Threat Map    │   │ MITRE Matrix    │   │
│   │ (Filter/Triage/Drawer)│   │ (Geo-located arcs)    │   │ (Tactics Grid)  │   │
│   └───────────────────────┘   └───────────────────────┘   └─────────────────┘   │
│   ┌───────────────────────┐   ┌───────────────────────┐   ┌─────────────────┐   │
│   │ Kill Chain Timeline   │   │ Traffic & Alert Stats │   │ YARA Rule CRUD  │   │
│   │ (Recon -> Action)     │   │ (Severity breakdowns) │   │ & Hot-Reload    │   │
│   └───────────────────────┘   └───────────────────────┘   └─────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Component 1: The C++ Detection Engine (`engine/`)

The detection core sits in `engine/` and is built as a modular static library (`sentinelx_core`) linked into the primary binary (`sentinelx`).

### 3.1 Build System & Toolchain
- **Language Standard:** C++17 (`-std=c++17`, strictly avoiding non-portable extensions).
- **Build Generator:** CMake 3.16+.
- **Compiler Support:** GCC 9+ or Clang 10+ on POSIX/Linux platforms.
- **Build Configurations:**
  - `Release`: `-O3 -DNDEBUG` with full optimization.
  - `Debug`: `-g -O0 -DSENTINELX_DEBUG` with debugging assertions.
- **Conditional Compilation Switches:**
  - `SENTINELX_BUILD_CAPTURE`: Toggles live libpcap capture (default: `ON`).
  - `SENTINELX_BUILD_YARA`: Toggles `libyara` integration (default: `ON`).
  - `SENTINELX_FORCE_MINIMAL`: Disables both live capture and YARA; enables fully self-contained offline replay builds without external shared libraries.
- **External Dependencies:**
  - `libpcap` (v1.10+): Raw packet capture and kernel BPF filtering.
  - `libyara` (v4.0+): Signature scanning VM.
  - `nlohmann/json` (v3.11+): Header-only vendored JSON serialization under `engine/third_party/nlohmann/json.hpp`.

### 3.2 Packet Capture & Ingestion Subsystem

The engine supports two swappable packet ingestion drivers conforming to a unified pipeline:

1. **`PacketCapture` (`engine/src/capture/PacketCapture.cpp`):**
   - Initializes a live capture session on a specified network interface (e.g., `eth0`).
   - Configures promiscuous mode (`promisc = 1`), enabling packet sniffing across the shared broadcast or mirror port.
   - Sets snapshot length to 65,535 bytes (`snaplen`) to capture complete L7 payloads without packet truncation.
   - Compiles and loads a Berkeley Packet Filter (BPF) string (e.g., `"tcp or udp"`) directly into the Linux kernel socket filter via `pcap_compile()` and `pcap_setfilter()`, discarding irrelevant frames before copying them into user space.
   - Dispatches packets using an event loop via `pcap_loop()` or `pcap_dispatch()`.

2. **`PcapReplayer` (`engine/src/capture/PcapReplayer.cpp`):**
   - Opens pre-recorded offline capture files (`.pcap` / `.pcapng`) using `pcap_open_offline()`.
   - Iterates through packets while preserving original frame capture timestamps or playing back at accelerated rates.
   - Provides deterministic replay capabilities for integration testing, malware sandbox analysis, and CI regression suites.

### 3.3 Zero-Copy Protocol Parsers

Incoming frames are converted to `RawPacket` structures and passed sequentially down the protocol stack without unnecessary data copies:

- **`IPParser` (`engine/src/parsers/IPParser.cpp`):**
  - Extracts Ethernet headers; checks EtherType for IPv4 (`0x0800`).
  - Validates IP version, header length (IHL ≥ 5), total packet length, and IP checksum.
  - Extracts 5-tuple parameters: Source IP, Destination IP, Protocol (TCP: `6`, UDP: `17`, ICMP: `1`).
  - Extracts Time-To-Live (TTL) and identification fields.
- **`TCPParser` (`engine/src/parsers/TCPParser.cpp`):**
  - Decodes TCP source and destination ports, sequence numbers, acknowledgment numbers, and data offset.
  - Decodes bitwise TCP control flags: `SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG`, `ECE`, `CWR`.
  - Computes TCP payload boundary by slicing the packet buffer past `(data_offset * 4)` bytes.
- **`UDPParser` (`engine/src/parsers/UDPParser.cpp`):**
  - Decodes UDP source/destination ports and length headers.
- **`HTTPParser` (`engine/src/parsers/HTTPParser.cpp`):**
  - Inspects payloads on well-known or identified HTTP ports (e.g., 80, 8080, 8000, 8888).
  - Performs streaming zero-copy tokenization of HTTP methods (`GET`, `POST`, `PUT`, `DELETE`, `HEAD`, `OPTIONS`, `CONNECT`, `TRACE`, `PATCH`).
  - Parses target URI, query string parameters, HTTP protocol version, and request headers (`Host`, `User-Agent`, `Referer`, `Content-Length`, `Cookie`).

### 3.4 Detection Modules Deep Dive

Detection logic runs in a deterministic sequence to maximize efficiency (stateless cheap checks execute before expensive stateful memory allocations):

```
Packet Arrival
   │
   ├─▶ [1] HoneypotDetector: Check dst_port against static decoy list
   │     └─ Hit? Emit HONEYPOT_HIT (CRITICAL), proceed
   │
   ├─▶ [2] PortScanDetector: Update sliding window for (src_ip, dst_ip)
   │     └─ Distinct ports > threshold? Emit PORT_SCAN (HIGH) & enter cooldown
   │
   ├─▶ [3] SYNFloodDetector: Track SYN vs SYN-ACK counters per destination
   │     └─ SYN rate & ratio breached? Emit SYN_FLOOD (HIGH) & enter cooldown
   │
   ├─▶ [4] HTTPAnomalyDetector: Scan URI & headers for attack signatures
   │     └─ Match? Emit HTTP_ANOMALY (HIGH)
   │
   └─▶ [5] YARAScanner: Scan raw L7 payload (<= 64 KB) with compiled YARA rules
         └─ Signature hit? Emit YARA_MATCH (Dynamic severity)
```

#### 1. `HoneypotDetector` (`engine/src/detectors/HoneypotDetector.cpp`)
- **Principle:** True zero-false-positive detection based on destination ports that host no legitimate services on the system.
- **Monitored Ports:** Decoy ports such as 21 (FTP), 23 (Telnet), 2222 (Alternative SSH), 3389 (RDP), 5900 (VNC).
- **Execution:** When any incoming TCP SYN or UDP datagram touches a configured honeypot port, it immediately flags a tripwire alert.
- **Severity:** `CRITICAL`.
- **MITRE Mapping:** `T1046` (Network Service Discovery).

#### 2. `PortScanDetector` (`engine/src/detectors/PortScanDetector.cpp`)
- **Principle:** Detects reconnaissance and network discovery activities (e.g., `nmap`, `masscan`, `zmap`).
- **State Tracking:** Maintains a per-`(src_ip, dst_ip)` pair sliding time window (default: 5.0 seconds).
- **Window Eviction:** Outdated probe records older than the sliding window are purged on each insertion.
- **Thresholds:**
  - TCP Threshold: 10 distinct ports contacted within 5 seconds (tunable via `--scan-ports`).
  - UDP Threshold: 20 distinct ports contacted within 5 seconds.
- **Scan Classification:** Analyzes observed TCP flag combinations to classify the scan technique:
  - `SYN`: Stealth SYN scan (`nmap -sS`).
  - `NULL`: All flags cleared (`nmap -sN`).
  - `FIN`: Only FIN flag set (`nmap -sF`).
  - `XMAS`: FIN, PSH, and URG flags set (`nmap -sX`).
  - `UDP`: UDP service probe (`nmap -sU`).
- **Alert Suppression (Cooldown):** After raising an alert for a source-target pair, an alert cooldown is armed (default: 60 seconds). This prevents flooding the SOC with 10,000 alerts during a comprehensive 65,535-port scan.

#### 3. `SYNFloodDetector` (`engine/src/detectors/SYNFloodDetector.cpp`)
- **Principle:** Detects Denial of Service attempts aiming to exhaust OS TCP connection state tables (`backlog queue`).
- **Tracking Structure:** Maintains per-destination IP metrics over a sliding 5-second interval:
  - Count of incoming `SYN` packets without `ACK`.
  - Count of complementary `SYN-ACK` responses.
- **Detection Criteria:** Triggers when:
  1. `SYN` count ≥ 100 within the 5-second window; **and**
  2. Ratio of `SYN` to `SYN-ACK` exceeds 5:1 (or zero `SYN-ACK` packets are observed).
- **Severity:** `HIGH`.
- **MITRE Mapping:** `T1498.001` (Direct Network Flood).

#### 4. `HTTPAnomalyDetector` (`engine/src/detectors/HTTPAnomalyDetector.cpp`)
- **Principle:** Inspects decoded HTTP application-layer traffic for web attack vectors and exploitation payloads:
  - **Directory Traversal:** Checks URI paths for patterns like `../`, `..%2f`, `%2e%2e%2f`, `/etc/passwd`, `/etc/shadow`, `boot.ini`.
  - **SQL Injection:** Checks for unescaped SQL fragments in query parameters (`UNION SELECT`, `' OR 1=1--`, `SLEEP(`, `BENCHMARK(`).
  - **Null-Byte Injection:** Detects `%00` or raw `0x00` in URIs designed to truncate file extension checks in vulnerable backends.
  - **Scanner Fingerprints:** Detects automated vulnerability scanners via `User-Agent` headers (`sqlmap`, `nikto`, `acunetix`, `nmap`, `gobuster`, `dirbuster`, `wpscan`).
  - **Abnormal HTTP Verbs:** Detects unexpected or dangerous methods (`DEBUG`, `TRACK`, `PROPFIND`).
- **MITRE Split:**
  - Active Exploit attempts (`SQL_INJECTION`, `PATH_TRAVERSAL`, `NULL_BYTE`): Mapped to `T1190` (Exploit Public-Facing Application).
  - Scanner probing (`SCANNER_USER_AGENT`): Mapped to `T1595.002` (Vulnerability Scanning).

### 3.5 Signature Inspection (YARA Engine)

The signature scanning subsystem (`engine/src/yara/YARAScanner.cpp`) embeds the native `libyara` engine:
- **Scope:** Every TCP and UDP packet payload with length between 1 byte and 64 KB (`YARA_SCAN_MAX_PAYLOAD`).
- **Rule Compilation:** On startup, all `.yar` files located in the rules directory (default: `/etc/sentinelx/rules` or `engine/rules/`) are compiled into a single in-memory YARA ruleset.
- **Rule Categories Included:**
  1. `shellcode_patterns.yar`: Detects NOP sleds (`0x90` sequences), Metasploit payload stagers, Alpha2 alphanumeric shellcode, and common architecture-specific execve sequences.
  2. `http_exploits.yar`: Complex regular expressions for Log4Shell (`${jndi:ldap://}`), Spring4Shell, and PHP deserialization payloads.
  3. `malware_generic.yar`: Command and Control (C2) beacon signatures (Cobalt Strike, Sliver, Empire HTTP headers).
- **Metadata Extraction:** YARA rules provide rich contextual metadata mapped directly into the alert schema:
  ```yara
  rule WebShell_PHP_Generic {
      meta:
          description = "Generic PHP webshell execution parameter"
          mitre_technique = "T1505.003"
          mitre_tactic = "Persistence"
          mitre_phase = "Installation"
          severity = "HIGH"
      strings:
          $a = "system($_GET[" ascii wide nocase
          $b = "passthru($_POST[" ascii wide nocase
          $c = "eval(base64_decode(" ascii wide nocase
      condition:
          any of them
  }
  ```
- **Hot-Reloading Mechanism:** When the engine process receives a `SIGUSR1` signal, it pauses packet scanning, destroys the current YARA compiler context, recompiles all rules from disk, and resumes packet processing without dropping the capture socket.

### 3.6 Alert Formatting & IPC Emitter

When a detector identifies an anomaly, it constructs a standardized C++ `Alert` object (`engine/src/alerts/Alert.h`).
- **Alert Serialization:** Uses `nlohmann::json` to serialize the alert into a single-line JSON string without internal newlines (NDJSON format).
- **Emission Targets (`AlertEmitter.cpp`):**
  - `UNIX_SOCKET` (Default): Connects to the local Unix domain socket listener at `/run/sentinelx/alerts.sock`. Features automatic non-blocking retry with reconnect backoff if the backend is restarting.
  - `STDOUT`: Emits one JSON line per alert to standard output, enabling Unix pipeline composition (`./sentinelx | jq .`).

---

## 4. Component 2: Node.js Ingestion & API Layer (`backend/`)

The backend layer is written in Node.js (Express) and provides durable persistence, enrichment, REST endpoints, and WebSocket broadcasting.

### 4.1 Unix Domain Socket Listener & Stream Framing
- **Listener Implementation (`backend/src/services/EngineIngestion.js`):**
  - Creates a Unix Domain Socket server (`net.createServer()`) listening at `/run/sentinelx/alerts.sock`.
  - Cleans up stale socket files on startup via `fs.unlinkSync()`.
  - Enforces proper filesystem permissions (`0o660`) so both engine and backend user groups can read/write.
- **NDJSON Stream Chunking:**
  - Network sockets deliver stream fragments that may break arbitrary JSON lines across buffer boundaries.
  - `EngineIngestion` maintains an internal string buffer per client socket connection, splitting incoming chunks on newline characters (`\n`).
  - Completed lines are passed to the JSON parser; partial fragments remain in the buffer until the subsequent chunk arrives.

### 4.2 Schema Validation & Geo-IP Enrichment
- **Validation:** Every parsed JSON line is verified against mandatory keys (`alert_id`, `timestamp`, `severity`, `type`, `src_ip`, `dst_ip`).
- **Deduplication:** A bounded LRU cache records recent `alert_id` values, discarding duplicates caused by socket retransmissions.
- **Geo-IP Enrichment (`backend/src/services/geoip.js`):**
  - Integrated with MaxMind GeoLite2 City databases via `maxmind` (`.mmdb` binary reader).
  - Inspects `src_ip`. If it is a public IP, resolves:
    - Country name and ISO country code (e.g., `"US"`, `"DE"`, `"CN"`).
    - City name (e.g., `"Frankfurt"`, `"San Jose"`).
    - Geographic coordinates (`latitude`, `longitude`).
  - Graceful Fallback: If `GEOIP_MMDB` is unconfigured or private IP addresses (RFC 1918) are encountered, the engine assigns `geoip: null` and continues processing without throwing exceptions.

### 4.3 Dual-Mode Persistence Architecture (MongoDB + Memory Ring Buffer)

The persistence layer (`backend/src/services/AlertStore.js`) implements a zero-dependency fallback pattern:

```
                  Incoming Enriched Alert
                             │
                             ▼
                 ┌───────────────────────┐
                 │ MongoDB Connected?    │
                 └───────────┬───────────┘
                             │
             ┌───────────────┴───────────────┐
             ▼                               ▼
       [YES: Active]                   [NO: Down/Null]
  Save to Mongoose Model           Push to In-Memory Circular
  Collection: `alerts`             Ring Buffer (Cap: 10,000)
  Indexed queries & aggregates     Fast in-memory slice/filter
```

- **Mongoose Schema (`backend/src/models/Alert.js`):**
  - Compound indexes on `{ timestamp: -1, severity: 1 }`, `{ src_ip: 1 }`, `{ "mitre.technique_id": 1 }`.
  - Supports analytical queries: top talkers, targeted ports, timeline bucketing.
- **In-Memory Ring Buffer:**
  - Maintains a circular array of the most recent 10,000 alerts.
  - Implements the exact same interface methods as the Mongo store (`insert()`, `find()`, `count()`, `stats()`).
  - Enables zero-configuration developer boot (`npm start` works immediately without running a local MongoDB daemon).

### 4.4 REST API Specification

Base Route: `/api`

| Endpoint | Method | Description | Parameters / Payload |
|---|---|---|---|
| `/health` | `GET` | Service health, engine connection status, and ingestion metrics. | None |
| `/alerts` | `GET` | Paginated and filtered alert listing. | `limit`, `offset`, `severity`, `type`, `src_ip`, `tactic` |
| `/alerts/:id` | `GET` | Retrieve detailed alert record by ID. | `id` (string) |
| `/alerts/:id/triage` | `PATCH` | Update alert triage status. | `{ "false_positive": boolean, "reviewed": boolean }` |
| `/alerts/:id` | `DELETE` | Remove alert from store. | `id` (string) |
| `/stats` | `GET` | Aggregated threat statistics (severity counts, top attacker IPs, targeted ports, timeline histogram). | `window` (e.g., `24h`, `1h`) |
| `/rules` | `GET` | List all available YARA rule files and parsed rule metadata. | None |
| `/rules/:filename` | `GET` | Read raw content of a YARA rule file. | `filename` |
| `/rules/:filename` | `PUT` | Create or update a YARA rule file. | `{ "content": "rule ..." }` |
| `/rules/:filename` | `DELETE` | Delete a YARA rule file. | `filename` |
| `/rules/reload` | `POST` | Trigger engine hot-reload by sending `SIGUSR1` to the engine PID. | None |

### 4.5 Real-Time WebSocket Broadcasting Engine

Implemented in `backend/src/websocket/AlertStream.js`:
- Uses the `ws` library attached to the shared HTTP server under `/ws`.
- **Client Handshake:** Upon connection, new clients immediately receive a replay of the most recent 50 alerts (`wsHistoryCount`) to populate the dashboard without waiting for an active attack.
- **Live Push:** When the `EngineIngestion` service ingests and enriches a new alert, it emits an internal event (`alert`), prompting `AlertStream` to broadcast the alert JSON frame to all active clients.
- **Heartbeat & Keepalive:** Transmits periodic ping/pong frames every 30 seconds to detect dead browser tabs and purge zombie connections.

---

## 5. Component 3: React SOC Dashboard (`dashboard/`)

The analyst dashboard is an enterprise-grade Single-Page Application (SPA) located in `dashboard/`, engineered with React 18 and Vite.

### 5.1 UI Architecture & Component Topology

```
App.jsx (Layout Shell)
 ├── Sidebar (Branding, Navigation Links)
 ├── StatusBar (Live WS indicator, Engine health dot, DB connectivity status)
 └── Main Content Region
      ├── Page 1: Dashboard.jsx (Overview)
      │    ├── MetricCards (Total Alerts, Criticals, Active Attackers, Engine Status)
      │    ├── AlertFeed (Live scrolling table with severity tags)
      │    ├── ThreatMap (Geospatial attack origin visualization)
      │    ├── MITREMatrix (Heatmap of observed tactics & techniques)
      │    └── KillChain (Lockheed Martin progression diagram)
      ├── Page 2: Alerts.jsx (Dedicated Investigation)
      │    ├── FilterBar (Severity, Type, Search query, Date range)
      │    ├── FullAlertTable (Batch selection, pagination, sorting)
      │    └── AlertDrawer (Deep inspector: hex dump, headers, MITRE links)
      └── Page 3: Settings.jsx (Rule Management)
           ├── RuleFileList (List active .yar files)
           ├── RuleEditor (Syntax-aware textarea editor)
           └── ReloadTrigger (Button calling /api/rules/reload)
```

### 5.2 Real-Time Alert Feed & Deep Inspection Drawer
- **Reactive Stream Hook (`useWebSocket.js`):** Connects to the backend WebSocket stream, buffering incoming alerts in state while maintaining UI responsiveness.
- **Severity Color Coding:**
  - `CRITICAL`: Bright Crimson (`#FF3B30`).
  - `HIGH`: Amber Orange (`#FF9500`).
  - `MEDIUM`: Electric Yellow (`#FFCC00`).
  - `LOW`: Cyan Blue (`#007AFF`).
- **Inspection Drawer:** Clicking any alert opens a sliding drawer displaying the full alert schema, raw payload SHA256 hash, decoded packet headers, and a direct hyperlink to the official MITRE ATT&CK technique reference.

### 5.3 Interactive Threat Map (Geo-IP)
- Built on top of Leaflet / React-Leaflet with a custom dark-mode tile layer.
- Renders attack origin markers based on `src_ip` latitude and longitude coordinates.
- Plots animated curved arcs connecting the external attacker origin to the protected host location.
- Markers are cluster-aware and scale in size based on alert volume.

### 5.4 MITRE ATT&CK Matrix & Kill Chain Navigator
- **Matrix View:** Displays the 14 MITRE Enterprise Tactics (Reconnaissance, Resource Development, Initial Access, Execution, Persistence, etc.).
- **Dynamic Heatmap:** Cells light up proportionally to the number of detected techniques matching that column, enabling SOC leads to immediately gauge adversary posture.
- **Kill Chain Visualization:** Displays the linear progression of detected threats from *Reconnaissance* → *Weaponization* → *Delivery* → *Exploitation* → *Installation* → *C2* → *Actions on Objectives*.

### 5.5 YARA Rules Management & Engine Hot-Reloading
- **In-Browser Editor:** Security analysts can create, edit, or delete `.yar` rule files directly from the dashboard.
- **Validation & Safe Deployment:** The backend validates file syntax before writing to disk.
- **One-Click Hot Reload:** Clicking "Reload Rules" in the UI sends a `POST /api/rules/reload` request, prompting the backend to look up the engine PID from `/run/sentinelx/sentinelx.pid` and dispatch `kill -SIGUSR1 <pid>`.

---

## 6. Data Schema & System Contracts

The unified alert schema is formalized in `docs/alert-schema.json`. Every alert emitted by the engine and stored by the backend strictly adheres to this structure:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "SentinelX Alert",
  "type": "object",
  "required": [
    "alert_id",
    "timestamp",
    "severity",
    "type",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "mitre",
    "evidence",
    "yara_match",
    "raw_payload_hash",
    "description",
    "false_positive",
    "reviewed"
  ],
  "properties": {
    "alert_id": { "type": "string" },
    "timestamp": { "type": "string", "format": "date-time" },
    "severity": { "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"] },
    "type": { "enum": ["PORT_SCAN", "SYN_FLOOD", "HTTP_ANOMALY", "YARA_MATCH", "HONEYPOT_HIT"] },
    "src_ip": { "type": "string" },
    "dst_ip": { "type": "string" },
    "src_port": { "type": "integer", "minimum": 0, "maximum": 65535 },
    "dst_port": { "type": "integer", "minimum": 0, "maximum": 65535 },
    "protocol": { "enum": ["TCP", "UDP", "ICMP", "HTTP", "HTTPS", "UNKNOWN"] },
    "tcp_flags": { "type": "integer" },
    "mitre": {
      "type": "object",
      "required": ["technique_id", "technique_name", "tactic", "kill_chain_phase"],
      "properties": {
        "technique_id": { "type": "string" },
        "technique_name": { "type": "string" },
        "tactic": { "type": "string" },
        "kill_chain_phase": { "type": "string" },
        "reference_url": { "type": "string" }
      }
    },
    "evidence": { "type": "object" },
    "yara_match": {
      "type": ["object", "null"],
      "properties": {
        "rule_name": { "type": "string" },
        "rule_file": { "type": "string" },
        "matched_strings": { "type": "array", "items": { "type": "string" } },
        "payload_hash": { "type": "string" }
      }
    },
    "raw_payload_hash": { "type": ["string", "null"] },
    "description": { "type": "string" },
    "false_positive": { "type": "boolean" },
    "reviewed": { "type": "boolean" },
    "geoip": {
      "type": ["object", "null"],
      "properties": {
        "country": { "type": "string" },
        "country_code": { "type": "string" },
        "city": { "type": "string" },
        "latitude": { "type": "number" },
        "longitude": { "type": "number" }
      }
    }
  }
}
```

---

## 7. Threat Modeling & MITRE ATT&CK Mapping

SentinelX directly bridges network telemetry with adversary tactics documented in the MITRE ATT&CK Enterprise Matrix:

| Alert Type | Trigger Condition | MITRE Technique ID | Technique Name | Tactic | Kill Chain Phase | Rationale |
|---|---|---|---|---|---|---|
| `PORT_SCAN` | Distinct ports ≥ 10 in 5s | **T1046** | Network Service Discovery | Discovery | Reconnaissance | Systematic probing of distinct destination ports is the canonical footprint of adversary network enumeration. |
| `SYN_FLOOD` | SYNs ≥ 100/5s and SYN:ACK ≥ 5:1 | **T1498.001** | Direct Network Flood | Impact | Actions on Objectives | High-volume connection exhaustion directly degrades target host service availability. |
| `HTTP_ANOMALY` | SQLi, Path Traversal, Null-Byte | **T1190** | Exploit Public-Facing Application | Initial Access | Exploitation | Injecting exploit payloads into HTTP parameters represents an attempt to penetrate the external perimeter. |
| `HTTP_ANOMALY` | Scanner User-Agent | **T1595.002** | Vulnerability Scanning | Reconnaissance | Reconnaissance | Scanner fingerprints (e.g., Nikto, SQLmap) identify automated target profiling prior to manual exploitation. |
| `HONEYPOT_HIT` | Connection to decoy port | **T1046** | Network Service Discovery | Discovery | Reconnaissance | Touching an unadvertised, unlinked service indicates blind or automated port sweeps. |
| `YARA_MATCH` | Payload signature match | Author-defined (Default: **T1059**) | Command and Scripting Interpreter | Execution | Exploitation | Matches malicious executable byte sequences, shellcode stagers, or webshell scripts. |

---

## 8. Deployment, Infrastructure & Operations

### 8.1 Containerized Stack (`docker-compose.yml`)

SentinelX provides a production-grade multi-container deployment:

```yaml
services:
  mongo:
    image: mongo:7
    restart: unless-stopped
    volumes:
      - mongo-data:/data/db
    healthcheck:
      test: ["CMD", "mongosh", "--quiet", "--eval", "db.adminCommand('ping').ok"]
      interval: 10s
      timeout: 5s
      retries: 5

  backend:
    build:
      context: .
      dockerfile: deployment/Dockerfile.backend
    restart: unless-stopped
    depends_on:
      mongo:
        condition: service_healthy
    environment:
      MONGO_URI: mongodb://mongo:27017/sentinelx
      ENGINE_SOCKET: /run/sentinelx/alerts.sock
      ENGINE_PID_FILE: /run/sentinelx/sentinelx.pid
      RULES_DIR: /etc/sentinelx/rules
    volumes:
      - sx-ipc:/run/sentinelx
      - sx-rules:/etc/sentinelx/rules
    ports:
      - "4000:4000"

  engine:
    build:
      context: .
      dockerfile: deployment/Dockerfile.engine
    restart: unless-stopped
    depends_on:
      - backend
    network_mode: host
    privileged: true
    environment:
      SENTINELX_INTERFACE: ${SENTINELX_INTERFACE:-eth0}
    command:
      - "-i"
      - ${SENTINELX_INTERFACE:-eth0}
      - "--socket"
      - /run/sentinelx/alerts.sock
      - "--pid-file"
      - /run/sentinelx/sentinelx.pid
      - "--rules"
      - /etc/sentinelx/rules
      - "--output"
      - socket
    volumes:
      - sx-ipc:/run/sentinelx
      - sx-rules:/etc/sentinelx/rules

  dashboard:
    build:
      context: .
      dockerfile: deployment/Dockerfile.dashboard
    restart: unless-stopped
    depends_on:
      - backend
    ports:
      - "8080:80"

volumes:
  mongo-data:
  sx-ipc:
  sx-rules:
```

> **Key Architectural Detail:** The `engine` container uses `network_mode: host` and `privileged: true` to bind directly to the host's physical network adapters in promiscuous mode. It communicates with the `backend` container via the shared Unix Domain Socket volume `sx-ipc`.

### 8.2 Automated Bare-Metal Deployment (`install.sh`)

For dedicated SOC appliances or bare-metal Linux servers (Debian, Ubuntu, Kali), the repository includes `deployment/install.sh`:
1. Installs build tools: `gcc`, `g++`, `cmake`, `pkg-config`, `libpcap-dev`, `libyara-dev`, `nginx`, `nodejs 20.x`.
2. Clones the repository to `/opt/sentinelx`.
3. Compiles the C++ engine in Release mode (`cmake -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build`).
4. Installs Node.js backend packages and executes Vite production build for the dashboard.
5. Deploys systemd service definitions:
   - `sentinelx-backend.service`: Runs Node.js API with automated restart.
   - `sentinelx.service`: Runs the C++ packet capture engine after the backend socket is created.
6. Sets Linux capabilities: `setcap cap_net_raw,cap_net_admin=eip /opt/sentinelx/engine/build/sentinelx`, enabling the engine to capture raw packets without running as the `root` superuser.

### 8.3 Reverse Proxy & Production Nginx Architecture

The production web server configuration (`deployment/nginx.conf`) handles reverse proxying and WebSocket upgrading:
```nginx
server {
    listen 80;
    server_name _;

    root /var/www/sentinelx;
    index index.html;

    # SPA Router Fallback
    location / {
        try_files $uri $uri/ /index.html;
    }

    # REST API Proxy
    location /api/ {
        proxy_pass http://127.0.0.1:4000/api/;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    # WebSocket Stream Proxy
    location /ws {
        proxy_pass http://127.0.0.1:4000/ws;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host $host;
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
    }
}
```

### 8.4 CI/CD Pipeline (`.github/workflows/ci.yml`)

The repository enforces automated continuous integration on every commit and pull request:
- **Matrix Builds:** Compiles C++ on Ubuntu 22.04 using GCC and Clang.
- **Engine Tests:** Runs CTest suite verifying `IPParser`, `TCPParser`, `HTTPParser`, and detector sliding-window math against mock PCAP replays.
- **Backend Tests:** Executes Mocha/Chai tests against ephemeral in-memory stores and mock Unix socket emitters.
- **Frontend Verification:** Runs ESLint and validates Vite production bundling.

---

## 9. Operational Guide & Testing Runbook

### Starting the System Locally (Development Mode)

```bash
# 1. Start MongoDB (or let backend fallback to in-memory mode)
mongod --dbpath ./data/db &

# 2. Start the Backend API & Socket Listener
cd backend
npm install
npm start
# -> Listening on HTTP port 4000
# -> Listening on Unix socket /run/sentinelx/alerts.sock

# 3. Compile and Start the C++ Engine (Offline Replay or Live Sniffing)
cd ../engine
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build .

# Option A: Run live packet capture on eth0
sudo ./sentinelx -i eth0 --socket /run/sentinelx/alerts.sock

# Option B: Run deterministic offline PCAP replay
./sentinelx -r ../tests/pcaps/syn_flood.pcap --socket /run/sentinelx/alerts.sock --loop

# 4. Start the React SOC Dashboard
cd ../../dashboard
npm install
npm run dev
# -> Console accessible at http://localhost:5173
```

### Simulating Attacks for Testing

1. **Trigger Port Scan Alert (`T1046`):**
   ```bash
   nmap -sS -p 1-100 <TARGET_IP>
   ```
2. **Trigger SYN Flood Alert (`T1498.001`):**
   ```bash
   hping3 -S -p 80 --flood --rand-source <TARGET_IP>
   ```
3. **Trigger HTTP Anomaly / Directory Traversal (`T1190`):**
   ```bash
   curl -A "sqlmap/1.5" "http://<TARGET_IP>/index.php?id=1%20UNION%20SELECT%20null,null"
   curl "http://<TARGET_IP>/../../../../etc/passwd"
   ```
4. **Trigger Honeypot Tripwire (`T1046`):**
   ```bash
   nc -zv <TARGET_IP> 2222
   ```

---

## 10. Summary & Architecture Strengths

SentinelX delivers a battle-ready blueprint for modern network intrusion detection:
- **Speed & Safety:** Zero-copy C++17 packet pipeline ensures microsecond packet inspection.
- **Zero Single-Point-of-Failure:** Decoupled processes, non-blocking Unix socket IPC, and automatic in-memory storage fallbacks guarantee continuous operation.
- **Actionable Intelligence:** Every detection ties directly into MITRE ATT&CK techniques, providing SOC analysts with immediate operational clarity.
- **Extensibility:** Adding new detection heuristics or YARA rules requires zero modifications to the UI or ingestion database layer.

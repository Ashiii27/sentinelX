<div align="center">

```
███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     ██╗  ██╗
██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     ╚██╗██╔╝
███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║      ╚███╔╝ 
╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║      ██╔██╗ 
███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗██╔╝ ██╗
╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝╚═╝  ╚═╝
```

**A full-stack Network Intrusion Detection System built for real threat visibility.**  
*C++ packet engine · Node.js API · React dashboard · MITRE ATT&CK mapped*

---

![C++](https://img.shields.io/badge/Engine-C++17-00599C?style=flat-square&logo=cplusplus)
![Node.js](https://img.shields.io/badge/Backend-Node.js-339933?style=flat-square&logo=nodedotjs)
![React](https://img.shields.io/badge/Dashboard-React-61DAFB?style=flat-square&logo=react)
![MongoDB](https://img.shields.io/badge/Database-MongoDB-47A248?style=flat-square&logo=mongodb)
![libpcap](https://img.shields.io/badge/Capture-libpcap-FF6B35?style=flat-square)
![YARA](https://img.shields.io/badge/Detection-YARA-CC0000?style=flat-square)
![MITRE](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-FF0000?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Linux-FCC624?style=flat-square&logo=linux)

</div>

---

## What is SentinelX?

SentinelX is a **host-deployable Network Intrusion Detection System** that captures raw network packets, analyzes them in real time using a high-performance C++ engine, and streams structured threat alerts to a React-based SOC dashboard.

It is not a toy project. Every component — the packet capture pipeline, the detection logic, the alert schema, the WebSocket stream, the dashboard — is designed to reflect how **real Blue Team tooling** is architected.

The project covers the full threat detection lifecycle:

```
Raw Packets → Capture → Parse → Detect → Alert → Store → Visualize
```

SentinelX detects:
- **Port scans** (TCP SYN, NULL, FIN, XMAS variants)
- **SYN flood / DoS attacks** (rate-based thresholding)
- **HTTP anomalies** (malformed headers, unusual verb sequences, path traversal)
- **YARA rule matches** (signature-based payload inspection)
- **Honeypot probes** (custom decoy service triggers)

All detections are **mapped to MITRE ATT&CK techniques**, kill chain phase annotated, and surfaced through a live dashboard with geo-IP threat mapping.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        SENTINELX SYSTEM                         │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                   C++ ENGINE  (engine/)                  │   │
│  │                                                          │   │
│  │  ┌─────────────┐   ┌──────────────┐   ┌───────────────┐  │   │
│  │  │  libpcap    │   │  Packet      │   │  Detectors    │  │   │
│  │  │  Capture    │──▶│  Parser      │──▶│  ┌─────────┐ │  │   │
│  │  │  Layer      │   │  (IP/TCP/    │   │  │PortScan │  │  │   │
│  │  └─────────────┘   │  UDP/HTTP)   │   │  │SYNFlood │  │  │   │
│  │                    └──────────────┘   │  │HTTP Anom│  │  │   │
│  │  ┌─────────────┐                      │  │YARAMatch│  │  │   │
│  │  │  libyara    │◀─────────────────────│  └─────────┘  │  │   │
│  │  │  Rule Engine│                      └───────────────┘  │   │
│  │  └─────────────┘                              │          │   │
│  │                                               ▼          │   │
│  │                                    ┌─────────────────┐   │   │
│  │                                    │  Alert Emitter  │   │   │
│  │                                    │  (JSON → stdout     │   │
│  │                                    │   / Unix socket)│   │   │
│  │                                    └────────┬────────┘   │   │
│  └─────────────────────────────────────────────│─────────────┘  │
│                                                │                │
│  ┌─────────────────────────────────────────────▼─────────────┐  │
│  │                NODE.JS BACKEND  (backend/)                │   │
│  │                                                           │   │
│  │  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐   │   │
│  │  │  Alert       │   │  REST API    │   │  WebSocket   │   │   │
│  │  │  Ingestion   │──▶│  (Express)   │   │  Server     │   │   │
│  │  │  Service     │   │              │   │  (live push) │   │   │
│  │  └──────────────┘   └──────┬───────┘   └──────┬───────┘   │   │
│  │                            │                   │          │   │
│  │                    ┌───────▼───────────────────▼───────┐  │   │
│  │                    │         MongoDB (Mongoose)        │  │   │
│  │                    │  alerts / sessions / rules / stats │ │   │
│  │                    └───────────────────────────────────┘  │   │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │               REACT DASHBOARD  (dashboard/)               │   │
│  │                                                           │   │
│  │   Live Alert Feed  │  Threat Map  │  Kill Chain View      │   │
│  │   MITRE Matrix     │  YARA Rules  │  Stats & Graphs       │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

---

## Repository Structure

```
SentinelX/
│
├── engine/                        # C++ packet analysis core
│   ├── src/
│   │   ├── capture/               # libpcap interface, raw packet loop
│   │   │   ├── PacketCapture.cpp
│   │   │   └── PacketCapture.h
│   │   ├── detectors/             # modular detection logic
│   │   │   ├── PortScanDetector.cpp
│   │   │   ├── SYNFloodDetector.cpp
│   │   │   ├── HTTPAnomalyDetector.cpp
│   │   │   └── BaseDetector.h     # abstract base class
│   │   ├── yara/                  # libyara integration
│   │   │   ├── YARAScanner.cpp
│   │   │   └── YARAScanner.h
│   │   ├── alerts/                # alert structure + output
│   │   │   ├── Alert.h            # Alert struct definition
│   │   │   └── AlertEmitter.cpp   # JSON serialization + IPC
│   │   ├── parsers/               # protocol parsers
│   │   │   ├── IPParser.cpp
│   │   │   ├── TCPParser.cpp
│   │   │   └── HTTPParser.cpp
│   │   └── main.cpp
│   ├── include/                   # shared headers
│   ├── rules/                     # YARA detection rules
│   │   ├── malware_generic.yar
│   │   ├── shellcode_patterns.yar
│   │   └── http_exploits.yar
│   ├── tests/
│   │   ├── test_port_scan.cpp
│   │   └── test_syn_flood.cpp
│   └── CMakeLists.txt
│
├── backend/                       # Node.js API + WebSocket server
│   ├── src/
│   │   ├── routes/
│   │   │   ├── alerts.js          # GET /alerts, GET /alerts/:id
│   │   │   ├── stats.js           # GET /stats/summary
│   │   │   └── rules.js           # CRUD for YARA rules
│   │   ├── controllers/
│   │   ├── models/
│   │   │   ├── Alert.js           # Mongoose schema
│   │   │   └── Session.js
│   │   ├── services/
│   │   │   └── EngineIngestion.js # reads alerts from C++ engine
│   │   ├── websocket/
│   │   │   └── AlertStream.js     # broadcasts live alerts
│   │   └── app.js
│   ├── .env.example
│   └── package.json
│
├── dashboard/                     # React frontend
│   ├── src/
│   │   ├── components/
│   │   │   ├── AlertFeed/         # live scrolling alert list
│   │   │   ├── ThreatMap/         # geo-IP world map
│   │   │   ├── KillChain/         # MITRE ATT&CK kill chain view
│   │   │   ├── MITREMatrix/       # ATT&CK matrix heatmap
│   │   │   └── YARARules/         # rule manager UI
│   │   ├── pages/
│   │   │   ├── Dashboard.jsx
│   │   │   ├── Alerts.jsx
│   │   │   └── Settings.jsx
│   │   ├── hooks/
│   │   │   ├── useWebSocket.js    # live alert subscription
│   │   │   └── useAlerts.js
│   │   └── services/
│   │       ├── api.js             # axios REST client
│   │       └── socket.js          # WebSocket client
│   └── package.json
│
├── deployment/                    # Linux deployment
│   ├── install.sh                 # automated setup script
│   ├── sentinelx.service          # systemd unit file
│   └── nginx.conf                 # reverse proxy config
│
├── docs/
│   ├── architecture.md            # deep-dive system design
│   ├── threat-model.md            # what SentinelX detects and how
│   ├── mitre-mapping.md           # ATT&CK technique → detector mapping
│   └── api-reference.md           # REST + WebSocket API docs
│
├── .github/
│   └── workflows/
│       └── ci.yml                 # build + test on push
│
├── .gitignore
├── docker-compose.yml
└── README.md
```

---

## Detection Capabilities

### 1. Port Scan Detection
**MITRE ATT&CK:** `T1046 — Network Service Discovery`  
**Kill Chain Phase:** Reconnaissance

SentinelX tracks per-source connection attempts across a sliding time window. When a single source IP contacts more than **N distinct destination ports** within the threshold window, it raises a `PORT_SCAN` alert.

Detected variants:
| Scan Type | Detection Method |
|-----------|-----------------|
| TCP SYN Scan | SYN-only packets, no ACK response |
| NULL Scan | TCP flags = 0x00 |
| FIN Scan | FIN set, no established session |
| XMAS Scan | FIN + PSH + URG flags set |
| UDP Scan | High-rate UDP to varied ports |

---

### 2. SYN Flood Detection
**MITRE ATT&CK:** `T1498.001 — Network Denial of Service: Direct Network Flood`  
**Kill Chain Phase:** Impact

Monitors the ratio of SYN packets to SYN-ACK responses per destination. A high SYN:SYN-ACK ratio sustained over a configurable window indicates a flood in progress.

---

### 3. HTTP Anomaly Detection
**MITRE ATT&CK:** `T1190 — Exploit Public-Facing Application`  
**Kill Chain Phase:** Initial Access

Reconstructs HTTP sessions from TCP streams and flags:
- Path traversal patterns (`../../etc/passwd`)
- Oversized headers (potential buffer overflow probes)
- Unusual HTTP verb sequences
- Known scanner User-Agent strings
- SQL injection signatures in query strings

---

### 4. YARA Rule Matching
**MITRE ATT&CK:** Multiple (rule-dependent)  
**Kill Chain Phase:** Multiple

Raw packet payloads are scanned against a configurable YARA ruleset. Rules are hot-reloadable — no engine restart required. Ships with starter rules for:
- Generic shellcode patterns
- Common malware beacon signatures
- HTTP exploit payloads

---

### 5. Honeypot Feed Integration
**MITRE ATT&CK:** `T1040 — Network Sniffing`, `T1046`  
**Kill Chain Phase:** Reconnaissance

Connections to configured honeypot ports (e.g., fake SSH on 2222, fake HTTP on 8888) are immediately flagged as high-confidence threat indicators regardless of payload content.

---

## MITRE ATT&CK Coverage Map

| Technique ID | Name | Detector |
|---|---|---|
| T1046 | Network Service Discovery | PortScanDetector |
| T1498.001 | Direct Network Flood | SYNFloodDetector |
| T1190 | Exploit Public-Facing Application | HTTPAnomalyDetector |
| T1059 | Command and Scripting Interpreter | YARAScanner (shellcode rules) |
| T1071.001 | Web Protocols (C2) | HTTPAnomalyDetector + YARA |
| T1040 | Network Sniffing | HoneypotDetector |

---

## Alert Schema

Every detection produces a structured JSON alert:

```json
{
  "alert_id": "a1b2c3d4-...",
  "timestamp": "2026-03-19T14:32:01.482Z",
  "severity": "HIGH",
  "type": "PORT_SCAN",
  "src_ip": "192.168.1.105",
  "dst_ip": "10.0.0.1",
  "src_port": 54231,
  "dst_port": 22,
  "protocol": "TCP",
  "mitre": {
    "technique_id": "T1046",
    "technique_name": "Network Service Discovery",
    "tactic": "Discovery",
    "kill_chain_phase": "Reconnaissance"
  },
  "evidence": {
    "ports_contacted": [22, 80, 443, 3306, 5432, 8080],
    "window_seconds": 5,
    "packet_count": 6
  },
  "yara_match": null,
  "raw_payload_hash": "sha256:9f86d081..."
}
```

---

## Tech Stack

| Layer | Technology | Purpose |
|---|---|---|
| Packet Capture | libpcap | Raw socket access, promiscuous mode |
| Payload Scanning | libyara | Signature-based rule matching |
| Serialization | nlohmann/json | C++ JSON output |
| IPC | Unix Domain Socket | Engine → Backend bridge |
| API Server | Express.js | REST endpoints |
| Real-time | WebSocket (ws) | Live alert streaming |
| Database | MongoDB + Mongoose | Alert persistence |
| Frontend | React + Recharts | Dashboard UI |
| Geo-IP | MaxMind GeoLite2 | Threat map IP geolocation |
| Build System | CMake | C++ build |
| Deployment | systemd + nginx | Linux service management |
| Containers | Docker + Compose | Optional containerized stack |

---

## Quick Start

### Prerequisites

```bash
# Debian/Ubuntu/Kali
sudo apt install -y \
  build-essential cmake \
  libpcap-dev \
  libyara-dev \
  nodejs npm \
  mongodb
```

### 1. Clone the repo

```bash
git clone https://github.com/<your-username>/SentinelX.git
cd SentinelX
```

### 2. Build the C++ engine

```bash
cd engine
mkdir build && cd build
cmake ..
make -j$(nproc)
```

### 3. Start the backend

```bash
cd ../../backend
cp .env.example .env
# edit .env with your MongoDB URI and socket path
npm install
npm start
```

### 4. Start the dashboard

```bash
cd ../dashboard
npm install
npm run dev
```

### 5. Run the engine (requires root for raw socket access)

```bash
cd ../engine/build
sudo ./sentinelx --interface eth0 --rules ../../rules/
```

Dashboard will be live at `http://localhost:5173`

---

### Docker (One-Command Setup)

```bash
docker-compose up --build
```

> **Note:** The C++ engine requires `--privileged` mode and host network access for raw packet capture. See `docker-compose.yml` for configuration.

---

## Project Status

| Component | Status |
|---|---|
| C++ Engine — Packet Capture | 🔧 In Progress |
| C++ Engine — Port Scan Detector | 🔧 In Progress |
| C++ Engine — SYN Flood Detector | 📋 Planned |
| C++ Engine — HTTP Anomaly Detector | 📋 Planned |
| C++ Engine — YARA Integration | 📋 Planned |
| Node.js Backend — REST API | 📋 Planned |
| Node.js Backend — WebSocket Stream | 📋 Planned |
| React Dashboard — Alert Feed | 📋 Planned |
| React Dashboard — Threat Map | 📋 Planned |
| React Dashboard — MITRE Matrix | 📋 Planned |
| Deployment Scripts | 📋 Planned |
| Docker Compose | 📋 Planned |

---

## Author

**Ash**  
B.Tech Computer Science Engineering  


Focused on Blue Team security, SOC operations, and network forensics.

[![TryHackMe](https://img.shields.io/badge/TryHackMe-Top%203%25-red?style=flat-square&logo=tryhackme)](https://tryhackme.com)
[![GitHub](https://img.shields.io/badge/GitHub-Profile-181717?style=flat-square&logo=github)](https://github.com/<your-username>)

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---


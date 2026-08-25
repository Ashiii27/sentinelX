# SentinelX Implementation Plan

## 1. Purpose and base-version definition

SentinelX will be delivered incrementally as a working, testable network intrusion detection system. The first release is intentionally narrower than the full vision in `Readme.md`.

### Base version (v0.1) outcome

A user must be able to:

1. Build the C++ engine on a supported Linux environment.
2. Run deterministic offline packet/replay tests without libpcap or root privileges.
3. Capture IPv4 TCP/UDP traffic through libpcap when the optional capture dependency is installed.
4. Detect TCP SYN, NULL, FIN, and XMAS port scans with configurable threshold/window behavior.
5. Emit a documented, valid JSON alert contract.
6. Ingest alerts into the Node.js backend, persist them in MongoDB, and expose them through REST.
7. Receive new alerts over WebSocket and view them in a minimal dashboard alert feed.
8. Start the complete stack locally with documented commands, with Docker Compose as a follow-up packaging path.

The base version does **not** require every detector advertised in the README. SYN flood, HTTP anomaly, YARA, honeypot, geo-IP, advanced analytics, and full deployment automation are later phases built on the same contracts.

## 2. Current repository baseline

### Implemented or partially implemented

- C++17 CMake project under `engine/`.
- Dependency-light `PortScanDetector` with configurable distinct-port threshold and time window.
- `PacketEvent`, TCP flag classification, alert types, severity, network context, evidence, and MITRE mapping in `engine/src/`.
- IPv4, TCP, and single-packet HTTP parser scaffolding, including recent bounds-validation work.
- Optional libpcap capture target in `engine/CMakeLists.txt`.
- A standalone port-scan test executable in `engine/tests/test_port_scan.cpp`.
- README-level architecture, alert schema, detector goals, and quick-start documentation.

### Known gaps

- `engine/main.cpp` and the complete capture-to-parse-to-detect pipeline are not wired.
- Alert emission/serialization is not implemented as a dedicated component; the current alert helper is not a complete backend transport contract.
- `SYNFloodDetector.cpp`, `HTTPAnomalyDetector.cpp`, `YARAScanner.cpp`, and related tests are empty.
- Backend service, model, routes, WebSocket stream, package metadata, and environment template are empty placeholders.
- Dashboard services, hooks, pages, and components are empty placeholders.
- Architecture/API/threat-model/MITRE documentation files are empty.
- Docker Compose and deployment files are not yet a verified runnable stack.
- The current working tree contains uncommitted engine changes; future work must preserve or deliberately review those changes rather than resetting them.

## 3. Delivery principles

- **Vertical slices over isolated scaffolding:** complete one end-to-end flow before adding feature breadth.
- **Offline-first tests:** detector and parser tests must not require root privileges, live traffic, MongoDB, or libpcap.
- **Stable contracts:** define alert JSON and packet-event semantics before connecting components.
- **Safe parsing:** every parser validates captured length, wire length, header length, fragmentation, and truncation before reading bytes.
- **Explicit capability boundaries:** IPv4 and single-packet HTTP are v0.1 scope; IPv6, TCP reassembly, and encrypted payload inspection are later work.
- **Operational visibility:** errors, dropped packets, malformed packets, and ingestion failures must be measurable.
- **Least privilege:** live capture and deployment instructions must document required privileges and avoid unnecessary container privileges.

## 4. Phased implementation roadmap

### Phase 0 — Contracts, build hygiene, and test harness

**Goal:** Establish the interfaces that every later phase can depend on.

### Work items

- Confirm the supported toolchain: C++17/CMake, Node.js version, MongoDB version, and Linux runtime assumptions.
- Make the engine build cleanly with capture disabled: `SENTINELX_BUILD_CAPTURE=OFF`.
- Add a common test configuration and portable test helpers for raw packet fixtures.
- Finalize `PacketEvent` timestamp semantics and parser failure behavior.
- Define the canonical alert JSON schema, including required fields, optional evidence, versioning, and newline-delimited transport framing.
- Decide whether the engine-to-backend bridge is a Unix domain socket, TCP loopback socket, or stdin/stdout for v0.1. Prefer a simple newline-delimited JSON stream with reconnect/error behavior documented.
- Add repository-level CI jobs for engine build/tests and backend/dashboard checks.

### Exit criteria

- A clean checkout can configure and run dependency-light C++ tests.
- A checked-in schema/example alert can be validated independently of the live engine.
- CI reports failures for compilation, unit tests, lint, and malformed alert contract cases.

### Phase 1 — Parser and offline packet pipeline

**Goal:** Convert raw Ethernet/IPv4/TCP/UDP bytes into safe, deterministic packet events.

### Work items

- Finish and test `IPParser` for null/truncated buffers, invalid Ethernet type, invalid IPv4 version/IHL/length, fragmentation, and capture-vs-wire length mismatches.
- Finish and test `TCPParser` for protocol mismatch, short headers, invalid data offsets, IP-length underflow, TCP options, and payload bounds.
- Add UDP parsing sufficient for future scan detection, even if UDP detection is not yet enabled in v0.1.
- Add reusable packet fixture builders and a small PCAP/replay abstraction that can feed the same pipeline as live capture.
- Ensure timestamps are monotonic for detector windows or explicitly handle out-of-order packets.
- Define counters for packets seen, parsed, rejected, fragmented, truncated, and detector-processed.

### Exit criteria

- Unit tests cover valid and malformed packets without undefined reads or crashes.
- A replay fixture produces a deterministic sequence of `PacketEvent` values.
- Parser behavior is documented for unsupported IPv6, non-first fragments, and truncated payloads.

### Phase 2 — Port-scan detector hardening

**Goal:** Make the existing detector a production-quality first detection module.

### Work items

- Preserve the current threshold/window/cooldown behavior and add tests for duplicate ports, multiple destinations, multiple sources, out-of-order timestamps, boundary timestamps, and state reset.
- Decide and document whether threshold means “at least N” or “more than N”; keep implementation and README consistent.
- Validate scan classification precedence for overlapping flags, especially XMAS versus FIN.
- Add severity policy for internal versus external sources only if the required network context is available; otherwise keep severity deterministic.
- Add alert evidence fields for source, destination set, port set, packet count, scan type, and observation window.
- Add detector statistics and a bounded state-retention strategy to prevent unbounded memory growth.

### Exit criteria

- All port-scan unit tests pass offline.
- Replaying a known scan fixture produces exactly one alert per configured active window.
- Normal SYN/ACK, ACK, RST, and ordinary application traffic do not produce port-scan alerts.

### Phase 3 — Engine runtime and alert emitter

**Goal:** Run the detector pipeline from either live capture or replay and emit contract-compliant alerts.

### Work items

- Implement `engine/main.cpp` with configuration for interface, BPF filter, thresholds, window, output endpoint, and replay mode.
- Create a pipeline coordinator: capture/replay → parser chain → `PacketEvent` → detector registry → alert sink.
- Implement `AlertEmitter` with one JSON object per line, complete evidence serialization, JSON escaping, flush/error handling, and output to stdout plus the selected IPC sink.
- Add startup validation and useful shutdown behavior, including capture statistics and detector counters.
- Keep libpcap isolated behind the capture interface so offline builds remain available.
- Add integration tests using generated packet fixtures and an in-memory/file alert sink.

### Exit criteria

- The engine can replay a fixture and produce valid newline-delimited JSON alerts.
- The same detector logic is used for replay and live capture.
- Capture-unavailable systems can still build and run all offline tests.

### Phase 4 — Backend ingestion, persistence, and REST API

**Goal:** Turn emitted alerts into a usable backend service.

### Work items

- Initialize `backend/package.json` with pinned runtime/development dependencies and scripts.
- Implement configuration loading from `.env.example` without committing secrets.
- Implement the Mongoose `Alert` model that matches the engine schema, with indexes for timestamp, type, severity, source IP, and MITRE technique.
- Implement `EngineIngestion` for newline-delimited JSON, validation, malformed-line handling, reconnect/backoff, and duplicate alert-id protection.
- Implement REST endpoints:
  - `GET /health`
  - `GET /alerts` with pagination, sorting, and filters
  - `GET /alerts/:id`
  - `GET /stats/summary`
- Add consistent error responses, request validation, structured logging, and graceful shutdown.
- Add unit tests with mocked MongoDB and ingestion streams; add an optional MongoDB integration test.

### Exit criteria

- A valid engine alert is persisted once and is retrievable through REST.
- Invalid alerts are rejected without crashing ingestion.
- Pagination and filtering are deterministic and covered by tests.

### Phase 5 — WebSocket stream and minimal dashboard

**Goal:** Provide immediate analyst visibility for the base alert flow.

### Work items

- Implement `AlertStream` using the backend’s WebSocket library and broadcast only successfully persisted/accepted alerts.
- Define connection lifecycle, initial snapshot behavior, heartbeat, reconnect, and server-side error messages.
- Implement dashboard API and WebSocket clients with configurable backend URL.
- Build the minimum dashboard: alert feed, severity/type styling, timestamp, source/destination, description, MITRE technique, loading state, empty state, and connection/error state.
- Add an alerts page with basic filters and pagination using the REST API.
- Add frontend tests for rendering, filtering, WebSocket updates, reconnect, and failure states.

### Exit criteria

- Opening the dashboard shows stored alerts.
- A newly ingested alert appears in connected clients without a page refresh.
- Backend or WebSocket failure is visible and recoverable from the UI.

### Phase 6 — End-to-end validation and local packaging

**Goal:** Make the base version reproducible for another developer.

### Work items

- Add a documented local run path for engine replay, backend, MongoDB, and dashboard.
- Add Docker Compose for backend, MongoDB, dashboard, and an optional replay engine profile. Keep live capture explicitly opt-in because it needs host networking/privileges.
- Verify Linux deployment assumptions and update `deployment/` only after the local stack is stable.
- Add an end-to-end smoke test: replay scan fixture → engine JSON → backend ingestion → REST record → WebSocket event.
- Fill `docs/architecture.md`, `docs/api-reference.md`, `docs/threat-model.md`, and `docs/mitre-mapping.md` with the implemented v0.1 behavior, not future claims.
- Update the README status table and quick-start instructions to match reality.

### Exit criteria

- A clean checkout can follow the documentation and see a port-scan alert end to end.
- CI runs all dependency-available checks and clearly marks optional live-capture/MongoDB checks.
- The v0.1 release checklist is complete and reproducible.

### Phase 7 — Post-base detection expansion

These features begin only after Phases 0–6 are complete and the contracts are stable.

### 7.1 SYN flood detector

- Track SYN and SYN-ACK counts per destination/source over a bounded window.
- Define ratio and minimum-volume thresholds to avoid low-volume false positives.
- Add tests for normal handshakes, asymmetric traffic, spoofed sources, expiry, and alert cooldown.
- Map to `T1498.001` and document limitations.

### 7.2 HTTP anomaly detector

- Use the current single-segment parser; do not imply TCP stream reassembly.
- Detect path traversal, SQL injection indicators, scanner user agents, unusual verbs, oversized headers, and encoded/null-byte evasions.
- Add normalization, maximum inspection lengths, reason codes, and false-positive tests.
- Map findings to `T1190`/other documented techniques as appropriate.

### 7.3 YARA integration

- Add optional libyara discovery and a ruleset loader with compile diagnostics.
- Define payload-size limits, rule reload behavior, match evidence, and resource/time limits.
- Test rule matches and malformed/unavailable rulesets without making YARA mandatory for detector-only builds.

### 7.4 Honeypot and UDP detection

- Add configurable decoy ports and service labels.
- Add UDP scan behavior only after UDP parsing and rate/state limits are proven.
- Define severity and deduplication rules for repeated honeypot hits.

### 7.5 Analyst workflow and enrichment

- Add reviewed/false-positive update APIs with authorization and audit fields.
- Add optional GeoLite2 enrichment with privacy and offline-failure behavior.
- Add MITRE matrix, threat map, statistics, and rule-management UI after the alert feed is stable.

## 5. Cross-cutting quality gates

Every phase must satisfy the following applicable gates:

- **Build:** no new compiler warnings in changed C++ code; reproducible Node/frontend install and build.
- **Tests:** unit tests for normal, malformed, boundary, and repeated-event behavior; integration tests for changed contracts.
- **Security:** validate untrusted packet and JSON input; cap sizes; avoid shell execution from network data; redact secrets from logs.
- **Performance:** measure parser/detector throughput and state growth using repeatable fixtures; do not optimize before counters identify a bottleneck.
- **Observability:** expose startup errors, malformed input counts, dropped packets, queue backpressure, ingestion failures, and WebSocket client counts.
- **Documentation:** update the relevant API/schema/runbook documentation in the same phase as the implementation.

## 6. Recommended execution order

1. Phase 0: contracts and CI.
2. Phase 1: parser/replay correctness.
3. Phase 2: port-scan detector hardening.
4. Phase 3: engine runtime and emitter.
5. Phase 4: backend ingestion/API.
6. Phase 5: WebSocket and minimal dashboard.
7. Phase 6: end-to-end packaging and release validation.
8. Phase 7: additional detectors and advanced dashboard capabilities.

Do not start Phase 7 detector work by copying the README placeholders. Each detector must first have a defined input event, bounded state model, alert evidence contract, MITRE mapping, test fixtures, and operational limits.

## 7. Base-version release checklist

- [ ] Engine configures and builds with capture disabled.
- [ ] Parser malformed-input tests pass.
- [ ] Port-scan detector tests pass, including expiry and false-positive cases.
- [ ] Replay mode emits schema-valid newline-delimited JSON.
- [ ] Live capture path is isolated, documented, and tested where libpcap is available.
- [ ] Backend validates, deduplicates, persists, and queries alerts.
- [ ] WebSocket broadcasts accepted alerts.
- [ ] Dashboard displays stored and live alerts.
- [ ] End-to-end smoke test passes.
- [ ] Docker/local setup is documented.
- [ ] Architecture, API, threat model, MITRE mapping, and README status are current.
- [ ] No secrets, generated builds, or machine-specific paths are committed.

## 8. Definition of done for SentinelX v0.1

SentinelX v0.1 is complete when a new developer can use the documented setup to replay a supplied scan fixture, observe a correctly MITRE-mapped `PORT_SCAN` alert in the dashboard, query the same alert through REST, and run the automated tests without requiring live traffic capture. Live libpcap capture is a supported optional capability, not a prerequisite for validating the base release.

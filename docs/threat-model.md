# SentinelX — Threat Model

What SentinelX detects, the signal each detector relies on, how
tunable it is, and where its false-positive (FP) risk lives. Read
`mitre-mapping.md` for the ATT&CK correspondence.

---

## Detection surface

| # | Detector | Alert type | Signal class | Default threshold | Severity |
|---|---|---|---|---|---|
| 1 | PortScanDetector | `PORT_SCAN` | behavioral (rate) | 10 distinct TCP ports / 5 s (20 UDP) | HIGH |
| 2 | SYNFloodDetector | `SYN_FLOOD` | behavioral (rate + ratio) | ≥100 SYNs / 5 s **and** SYN:SYN-ACK ≥ 5 (or 0 ACKs) | HIGH |
| 3 | HTTPAnomalyDetector | `HTTP_ANOMALY` | signature (in-request) | any signature hit | HIGH |
| 4 | HoneypotDetector | `HONEYPOT_HIT` | destination (decoy port) | any connection to a decoy port | CRITICAL |
| 5 | YARA scanner | `YARA_MATCH` | signature (payload) | any rule match | from rule `meta` |

Severity order: `LOW < MEDIUM < HIGH < CRITICAL`.

---

## 1. Port scan detection — `PORT_SCAN`

**Behavior being detected.** A single source probing many distinct
destination ports on one target within a short time — classic service
discovery (nmap-style), whether stealthy (SYN only) or raw (NULL/FIN/
XMAS).

**Mechanism.** Per `(src_ip, dst_ip)` pair, a sliding 5-second window
records each probe's destination port. When the count of *distinct*
ports in the window crosses `--scan-ports` (default 10 TCP / 20 UDP),
one alert is raised — and the detector then **arms a cooldown for that
pair**, so a 490-probe scan yields exactly one alert, not 490.

The window also records each probe's TCP flag pattern; the alert
evidence reports the **majority scan type**: `SYN`, `NULL`, `FIN`,
`XMAS`, or `UDP`. Mixed scans report the dominant pattern plus the
per-type breakdown in `evidence.extra`.

**Evidence.** `ports_contacted` (the distinct ports seen),
`packet_count`, `scan_type`, `first_seen_ms` / `last_seen_ms`.

**Tuning.** `--scan-ports <n>` (TCP). Raise to 20–50 on busy networks
where normal clients legitimately touch many ports (e.g. a cloud
metadata + telemetry fan-out). The UDP threshold is fixed at 2× TCP.

**FP risk.** Medium-low. Legitimate mass-connectors (load-test
harnesses, buggy clients retrying across ports) can trip it. The
cooldown prevents alert storms; triage (`false_positive: true`) keeps
known-good sources quiet in reporting.

**ATT&CK.** `T1046 Network Service Discovery` (Discovery /
Reconnaissance).

---

## 2. SYN flood detection — `SYN_FLOOD`

**Behavior being detected.** Connection-attempt exhaustion: many SYNs
arriving faster than the target can answer, starving legitimate
clients.

**Mechanism.** Per destination IP, a 5-second window counts SYNs and
SYN-ACKs (SYN-ACKs of *incoming* flows). A flood is confirmed when
both hold:

1. `syn_count ≥ --syn-threshold` (default 100) — absolute rate gate,
   and
2. `synack_count == 0` **or** `syn_count / synack_count ≥ 5.0` —
   ratio gate.

The dual gate is what separates a flood from a merely busy service:
a healthy 200-SYN/s web server answers most of them, so the ratio
stays near 1 and no alert fires. A flood answers little, so the ratio
blows up.

**Evidence.** `syn_count`, `syn_ack_count`, `syn_ack_ratio`,
`packet_count`, `top_src_ip` + `top_src_count` (floods are often
botnet-distributed; the top contributor is named when identifiable),
window bounds.

**Tuning.** `--syn-threshold <n>`. On high-traffic edge boxes raise to
1000–10000 (documented in the header) to avoid FP on popular
endpoints.

**FP risk.** Low. Reflected amplification (SYN from many victims) is
still caught by the ratio gate. Brief connection storms from a single
buggy client below 100 SYNs/5 s never alert.

**ATT&CK.** `T1498.001 Direct Network Flood` (Impact / Actions on
Objectives).

---

## 3. HTTP anomaly detection — `HTTP_ANOMALY`

**Behavior being detected.** Exploit attempts and scanner activity in
plain HTTP requests.

**Mechanism.** Every parsed HTTP request runs a signature battery.
Current anomaly kinds:

| Kind | Trigger | Example |
|---|---|---|
| `SQL_INJECTION` | SQLi signatures in method/path | `?id=1' OR 1=1--` |
| `PATH_TRAVERSAL` | `../`, encoded traversal, absolute paths | `/../../etc/passwd` |
| `NULL_BYTE` | `%00` in request target/headers | `/file%00.jpg` |
| `OVERSIZED_HEADER` | header beyond a sane bound (8 KB) | slowloris-style probing |
| `SCANNER_USER_AGENT` | known scanner UAs (nikto, sqlmap, masscan, nmap…) | `User-Agent: Nikto/2.1.6` |
| `UNUSUAL_VERB` | non-standard methods (TRACE, custom) | `TRACE /` |

Each hit produces one alert carrying the kind plus request context
(method, path, headers of interest) in `evidence`. The detector is
stateless per request — no cross-request memory, so no state-bloat
class of bugs.

**MITRE nuance.** Exploit-attempt kinds map to `T1190 Exploit
Public-Facing Application` (Initial Access / Exploitation); scanner
traffic maps to `T1595.002 Vulnerability Scanning` (Reconnaissance) —
the same UA that scans your whole estate is one alert, the payload
that tries to break in is another, and they're distinguishable in
reporting.

**FP risk.** Low-moderate. `UNUSUAL_VERB` and `OVERSIZED_HEADER` can
fire on legitimate integration traffic; `SCANNER_USER_AGENT` is a
hard signal (real browsers don't identify as Nikto). Signatures are
conservative (well-known payload fragments, not fuzzy heuristics).

---

## 4. Honeypot detection — `HONEYPOT_HIT`

**Behavior being detected.** Anything touching a service that exists
only to be attacked.

**Mechanism.** Destination-port membership: the engine is configured
with decoy ports (`--honeypot 2222:SSH,8888:HTTP`, the defaults). A
SYN to a decoy port raises a **CRITICAL** alert naming the mimicked
service. A 60-second per-(src, port) cooldown keeps retrying scanners
from flooding the feed while still flagging every fresh probe.

This detector has the **best precision in SentinelX**: if the port is
genuinely decoy-only, a connection is by definition hostile. No
behavioral analysis, no thresholds, no FP class — which is exactly why
a SOC deploys honeypots.

**Evidence.** `honeypot_port`, `service_mimicked`, protocol.

**Tuning.** Configure decoys for every service you *would* expose
(SSH, HTTP, RDP, SMB) on non-standard ports; every port added is a
higher-precision sensor.

**ATT&CK.** `T1046 Network Service Discovery` (Reconnaissance) — a
probe finding a service that shouldn't exist is discovery behavior.

---

## 5. YARA payload scanning — `YARA_MATCH`

**Behavior being detected.** Known-malicious byte patterns in packet
payloads — shellcode structures, exploit fragments, malware artifacts.

**Mechanism.** TCP/UDP payloads are scanned against every compiled
rule file (`engine/rules/*.yar`). A match raises an alert of the
rule's `meta: severity` (default HIGH) with:

```json
"yara_match": {
  "rule_name": "shellcode_nop_sled",
  "rule_file": "shellcode_patterns.yar",
  "matched_strings": ["$nop10", "$nop_gap"],
  "payload_hash": "sha256:…"
}
```

**Bundled rules.**

| Rule file | Rules | Targets |
|---|---|---|
| `shellcode_patterns.yar` | `shellcode_nop_sled`, `shellcode_int3_sled`, `shellcode_jmp_call_pop_pivot` | raw shellcode staging (NOP/INT3 sleds, pivot idioms) |
| `http_exploits.yar` | `web_sqli_payload`, `web_command_injection_payload`, `shellshock_probe` | web exploit payloads (SQLi, RCE, Shellshock) |
| `malware_generic.yar` | `ransomware_encryption_note`, `maldoc_autostart_macro`, `c2_beacon_endpoint` | ransomware artifacts, malicious macros, C2 beacons |

The MITRE mapping for a YARA alert comes from the rule's
`meta: mitre` + `meta: kill_chain_phase` — **the mapping is data you
control**, so adding a rule means declaring its ATT&CK semantics too
(see `mitre-mapping.md` and the rule-manager UI under Settings).

**FP risk.** Per-rule; a NOP-sled signature is aggressive by nature
(`shellcode_nop_sled` is MEDIUM/HIGH precisely because ≥10 `0x90`
bytes can appear in benign binaries' padding). Review each new rule's
expected FP class before promoting it; the triage workflow exists for
the rest.

---

## What SentinelX does *not* detect

Honest scope limits — important for a Blue-Team tool:

- **Encrypted traffic.** TLS payloads are opaque to YARA and the HTTP
  parser. Detection works on metadata (ports, rates, flags, handshakes)
  — that's exactly what the rate-based detectors are for, but content
  inside a tunnel is out of scope.
- **Low-and-slow.** Windows are 5 s by default; a scan stretched over
  minutes with long per-probe delays is below the signal. (Tune the
  window for that profile, at cost of sensitivity.)
- **Lateral movement post-compromise.** SentinelX is a network sensor
  on one host's NIC; cross-host attack chains are a SIEM job.
- **ICMP content.** Parsed for protocol completeness, no signatures.
- **DNS exfiltration / tunneling.** No DNS record parsing.

Each of these is a deliberate boundary, not an accident: the detectors
above are tuned to be *precise* on their surface; growing the surface
without the same precision bar is how NIDS become noise machines.

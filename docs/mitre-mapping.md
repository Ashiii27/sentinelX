# SentinelX — MITRE ATT&CK Mapping

Every alert SentinelX emits carries a `mitre` block. This document
maps each detector (and each bundled YARA rule) to the ATT&CK
technique it represents, the tactic, and the kill-chain phase the
engine assigns.

```jsonc
"mitre": {
  "technique_id": "T1046",
  "technique_name": "Network Service Discovery",
  "tactic": "Discovery",
  "kill_chain_phase": "Reconnaissance",
  "reference_url": "https://attack.mitre.org/techniques/T1046/"
}
```

---

## Detector → ATT&CK

| Detector / alert type | Technique ID | Technique | Tactic | Kill-chain phase | Rationale |
|---|---|---|---|---|---|
| `PORT_SCAN` | **T1046** | Network Service Discovery | Discovery | Reconnaissance | Many distinct destination ports from one source in a short window is the network signature of service discovery. |
| `SYN_FLOOD` | **T1498.001** | Network DoS: Direct Network Flood | Impact | Actions on Objectives | Connection-attempt exhaustion directly degrades service availability — a DoS impact action. |
| `HTTP_ANOMALY` (exploit kinds) | **T1190** | Exploit Public-Facing Application | Initial Access | Exploitation | SQLi / traversal / RCE payloads in requests are attempts to break into an internet-facing service. |
| `HTTP_ANOMALY` (scanner kind) | **T1595.002** | Active Scanning: Vulnerability Scanning | Reconnaissance | Reconnaissance | Scanner user-agents and version-probing traffic are pre-compromise reconnaissance, not exploitation. |
| `HONEYPOT_HIT` | **T1046** | Network Service Discovery | Discovery | Reconnaissance | Contacting a decoy service means the attacker is enumerating what exists — discovery by definition, with the honeypot as the tripwire. |
| `YARA_MATCH` | *per rule meta* | *per rule* | *per rule* | *per rule* | The rule author declares the mapping in `meta:` — see the table below. |

### Notes on the two HTTP anomaly mappings

`HTTP_ANOMALY` is the one detector that **splits** its mapping:

- A request carrying `SQL_INJECTION`, `PATH_TRAVERSAL`, `NULL_BYTE`,
  or `UNUSUAL_VERB` payloads is an *attempted exploit* → **T1190**.
- A request identified by `SCANNER_USER_AGENT` (or oversized-header
  probing) is *vulnerability scanning* → **T1595.002**.

This matters operationally: a SOC can alert on "someone is scanning
us" (T1595.002, reconnaissance posture, maybe watch) separately from
"someone is actively trying to break in" (T1190, immediate response).

### T1498.001 vs T1595

The engine emits `T1498.001` for floods, per the Readme's documented
mapping. MITRE's newer matrix also references the DoS family under
`T1595.x` in some contexts; `T1498.001 Direct Network Flood` remains
the canonical technique ID for direct floods and is what SentinelX
uses consistently.

---

## Bundled YARA rules → ATT&CK

YARA alerts start from a **factory default** — `T1059 Command and
Scripting Interpreter` (Execution / Exploitation), severity HIGH —
and the rule author overrides what they know in the rule's `meta:`:

```yara
meta:
    severity   = "HIGH"                  // overrides default severity
    mitre      = "T1190"                 // overrides default technique id
    mitre_name = "Exploit Public-Facing Application"
    description = "one line shown in the alert"
```

**What rule meta controls:** `severity`, `technique_id`,
`technique_name` (and the generated reference URL).
**What it does not (yet) control:** `tactic` and `kill_chain_phase` —
those stay at the factory defaults (`Execution` / `Exploitation`) for
all YARA alerts. The mapping below shows the technique each rule
declares; the canonical ATT&CK tactic/phase for that technique is the
third/fourth column (what the technique *should* map to), while every
alert's emitted `tactic`/`kill_chain_phase` fields remain the factory
defaults.

| Rule | File | Severity | Declared technique | Canonical tactic / phase |
|---|---|---|---|---|
| `shellcode_nop_sled` | shellcode_patterns.yar | HIGH | T1059 | Execution / Exploitation |
| `shellcode_int3_sled` | shellcode_patterns.yar | MEDIUM | T1059 | Execution / Exploitation |
| `shellcode_jmp_call_pop_pivot` | shellcode_patterns.yar | HIGH | T1059 | Execution / Exploitation |
| `web_sqli_payload` | http_exploits.yar | HIGH | T1190 | Initial Access / Exploitation |
| `web_command_injection_payload` | http_exploits.yar | HIGH | T1190 | Initial Access / Exploitation |
| `shellshock_probe` | http_exploits.yar | CRITICAL | T1190 | Initial Access / Exploitation |
| `ransomware_encryption_note` | malware_generic.yar | CRITICAL | T1486 | Impact / Actions on Objectives |
| `maldoc_autostart_macro` | malware_generic.yar | MEDIUM | T1204.002 | Execution / Exploitation |
| `c2_beacon_endpoint` | malware_generic.yar | MEDIUM | T1071.001 | Command and Control / Command & Control |

> Exact per-rule values are read from the rule files at runtime — use
> `GET /api/rules` (or the Settings → YARA rules page) for the
> authoritative current mapping after you add or edit rules.

### Technique reference (as used by SentinelX)

| ID | Name | Tactic |
|---|---|---|
| T1046 | Network Service Discovery | Discovery |
| T1059 | Command and Scripting Interpreter | Execution |
| T1071.001 | Application Layer Protocol: Web Protocols | Command and Control |
| T1190 | Exploit Public-Facing Application | Initial Access |
| T1204.002 | User Execution: Malicious File | Execution |
| T1486 | Data Encrypted for Impact | Impact |
| T1498.001 | Network DoS: Direct Network Flood | Impact |
| T1595.002 | Active Scanning: Vulnerability Scanning | Reconnaissance |

---

## How the mapping reaches the dashboard

1. Engine detectors hardcode the technique for their alert type (the
   two `HTTP_ANOMALY` variants choose per anomaly kind).
2. YARA rules carry the mapping in `meta:`; the engine reads it at
   rule-compile time.
3. The backend persists the `mitre` block verbatim.
4. The dashboard:
   - **Kill Chain** view — counts alerts by `mitre.kill_chain_phase`
     (backend `by_kill_chain` aggregation).
   - **MITRE Matrix** — groups alerts by `mitre.tactic`, listing the
     observed `technique_id`s as chips.

So a single alert feeds three views (feed, kill chain, matrix) from
one consistent block — change the mapping once (detector or rule
meta) and every view updates.

### Extending the mapping

To add a detector: use an alert factory in `Alert.h` (or set `mitre`
in the alert construction, see `makeSYNFloodAlert` for the pattern).
To add a rule:

```yara
rule my_custom_detection
{
    meta:
        severity   = "HIGH"
        mitre      = "T1190"
        mitre_name = "Exploit Public-Facing Application"
        description = "what this catches, in one line"
    strings:
        $a = "…"
    condition:
        any of them
}
```

The API validates the file exists and is parseable; YARA itself
validates syntax when the engine (re)loads — the Settings page's
**Hot-reload** button is the loop-closer.

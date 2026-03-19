/**
 * @file    Alert.h
 * @brief   Core alert data structures for the SentinelX detection engine.
 *
 * This header defines every type that represents a detection event in
 * SentinelX. All detectors produce an Alert. The AlertEmitter serializes
 * Alerts to JSON and forwards them to the Node.js backend over a Unix
 * domain socket.
 *
 * Design principles:
 *  - POD-friendly: Alert is a plain struct, not a class. No hidden state.
 *  - Self-describing: severity, type, protocol, and MITRE context are all
 *    carried inline — the consumer never needs to look anything up.
 *  - Extensible: the `evidence` field (free-form key-value map) lets new
 *    detectors attach arbitrary metadata without touching the core struct.
 *  - No dynamic memory in hot path: strings are std::string (SSO handles
 *    short ones), vectors are used only for multi-value evidence fields.
 *
 * Dependencies:
 *  - C++17 or later (std::optional, structured bindings)
 *  - No external libraries — this header is intentionally self-contained.
 *    JSON serialization lives in AlertEmitter, not here.
 *
 * @author  Ash
 * @project SentinelX
 */

#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <optional>
#include <cstdint>
#include <chrono>
#include <sstream>
#include <iomanip>


// ============================================================================
//  SECTION 1 — ENUMERATIONS
//  All enums are scoped (enum class) to avoid name collisions and force
//  explicit qualification (e.g. Severity::HIGH, not just HIGH).
// ============================================================================

/**
 * @enum Severity
 * @brief Threat severity level of an alert.
 *
 * Maps loosely to CVSS base score ranges and common SOC triage levels:
 *
 *  LOW      → Informational / low-confidence anomaly. Log it, don't page.
 *             Example: single port probe from an internal IP.
 *
 *  MEDIUM   → Suspicious activity worth investigation.
 *             Example: slow port scan over 60s from external IP.
 *
 *  HIGH     → Strong indicator of malicious intent. Requires triage.
 *             Example: SYN flood, YARA rule match on known shellcode.
 *
 *  CRITICAL → Active exploitation or confirmed IOC. Immediate response.
 *             Example: honeypot hit + YARA match on same source IP.
 */
enum class Severity : uint8_t {
    LOW      = 0,
    MEDIUM   = 1,
    HIGH     = 2,
    CRITICAL = 3
};

/**
 * @enum AlertType
 * @brief The category of detection that produced this alert.
 *
 * Each value corresponds to exactly one detector class:
 *  PORT_SCAN       → PortScanDetector
 *  SYN_FLOOD       → SYNFloodDetector
 *  HTTP_ANOMALY    → HTTPAnomalyDetector
 *  YARA_MATCH      → YARAScanner
 *  HONEYPOT_HIT    → HoneypotDetector
 *  UNKNOWN         → Fallback / unclassified (should not appear in prod)
 */
enum class AlertType : uint8_t {
    UNKNOWN         = 0,
    PORT_SCAN       = 1,
    SYN_FLOOD       = 2,
    HTTP_ANOMALY    = 3,
    YARA_MATCH      = 4,
    HONEYPOT_HIT    = 5
};

/**
 * @enum Protocol
 * @brief Layer-4 protocol of the packet(s) that triggered the alert.
 */
enum class Protocol : uint8_t {
    UNKNOWN = 0,
    TCP     = 6,    // matches IANA protocol number
    UDP     = 17,   // matches IANA protocol number
    ICMP    = 1,
    HTTP    = 80,   // application-layer convenience value (over TCP)
    HTTPS   = 443
};

/**
 * @enum KillChainPhase
 * @brief Lockheed Martin Cyber Kill Chain phase of the detected activity.
 *
 * Used alongside MITRE ATT&CK to give analysts positional context —
 * where in the attack lifecycle this event likely sits.
 *
 *  RECONNAISSANCE   → Attacker is gathering info (scanning, probing)
 *  WEAPONIZATION    → Crafting payload (rarely directly observable on wire)
 *  DELIVERY         → Payload delivery (phishing, exploit attempt)
 *  EXPLOITATION     → Active exploitation of a vulnerability
 *  INSTALLATION     → Establishing persistence / dropping implant
 *  C2               → Command & Control communication
 *  ACTIONS          → Final objective (exfil, destruction, lateral movement)
 */
enum class KillChainPhase : uint8_t {
    UNKNOWN        = 0,
    RECONNAISSANCE = 1,
    WEAPONIZATION  = 2,
    DELIVERY       = 3,
    EXPLOITATION   = 4,
    INSTALLATION   = 5,
    C2             = 6,
    ACTIONS        = 7
};


// ============================================================================
//  SECTION 2 — HELPER: STRING CONVERSION
//  Free functions to convert enums to their string representations.
//  Used by AlertEmitter during JSON serialization. Defined inline here
//  to keep this header self-contained (no separate .cpp needed).
// ============================================================================

/**
 * @brief Convert Severity enum to uppercase string.
 * @example severityToString(Severity::HIGH) → "HIGH"
 */
inline std::string severityToString(Severity s) {
    switch (s) {
        case Severity::LOW:      return "LOW";
        case Severity::MEDIUM:   return "MEDIUM";
        case Severity::HIGH:     return "HIGH";
        case Severity::CRITICAL: return "CRITICAL";
        default:                 return "UNKNOWN";
    }
}

/**
 * @brief Convert AlertType enum to uppercase snake_case string.
 * @example alertTypeToString(AlertType::PORT_SCAN) → "PORT_SCAN"
 */
inline std::string alertTypeToString(AlertType t) {
    switch (t) {
        case AlertType::PORT_SCAN:    return "PORT_SCAN";
        case AlertType::SYN_FLOOD:    return "SYN_FLOOD";
        case AlertType::HTTP_ANOMALY: return "HTTP_ANOMALY";
        case AlertType::YARA_MATCH:   return "YARA_MATCH";
        case AlertType::HONEYPOT_HIT: return "HONEYPOT_HIT";
        default:                      return "UNKNOWN";
    }
}

/**
 * @brief Convert Protocol enum to string.
 * @example protocolToString(Protocol::TCP) → "TCP"
 */
inline std::string protocolToString(Protocol p) {
    switch (p) {
        case Protocol::TCP:   return "TCP";
        case Protocol::UDP:   return "UDP";
        case Protocol::ICMP:  return "ICMP";
        case Protocol::HTTP:  return "HTTP";
        case Protocol::HTTPS: return "HTTPS";
        default:              return "UNKNOWN";
    }
}

/**
 * @brief Convert KillChainPhase enum to string.
 */
inline std::string killChainPhaseToString(KillChainPhase p) {
    switch (p) {
        case KillChainPhase::RECONNAISSANCE: return "Reconnaissance";
        case KillChainPhase::WEAPONIZATION:  return "Weaponization";
        case KillChainPhase::DELIVERY:       return "Delivery";
        case KillChainPhase::EXPLOITATION:   return "Exploitation";
        case KillChainPhase::INSTALLATION:   return "Installation";
        case KillChainPhase::C2:             return "Command & Control";
        case KillChainPhase::ACTIONS:        return "Actions on Objectives";
        default:                             return "Unknown";
    }
}


// ============================================================================
//  SECTION 3 — SUB-STRUCTS
//  Composable building blocks that are embedded inside Alert.
// ============================================================================

/**
 * @struct MitreInfo
 * @brief MITRE ATT&CK context for a detection.
 *
 * Every detector must supply a MitreInfo. This forces developers to think
 * about ATT&CK mapping at the point of detection — not as an afterthought.
 *
 * Fields:
 *  technique_id    → ATT&CK technique ID, e.g. "T1046"
 *                    For sub-techniques: "T1046.001"
 *  technique_name  → Human-readable name, e.g. "Network Service Discovery"
 *  tactic          → ATT&CK tactic, e.g. "Discovery"
 *  kill_chain_phase→ Corresponding Lockheed Martin kill chain phase
 *  reference_url   → Direct link to the ATT&CK technique page (optional)
 *
 * Reference: https://attack.mitre.org/techniques/
 */
struct MitreInfo {
    std::string    technique_id;       // e.g. "T1046"
    std::string    technique_name;     // e.g. "Network Service Discovery"
    std::string    tactic;             // e.g. "Discovery"
    KillChainPhase kill_chain_phase;   // e.g. KillChainPhase::RECONNAISSANCE
    std::string    reference_url;      // e.g. "https://attack.mitre.org/techniques/T1046/"

    MitreInfo() : kill_chain_phase(KillChainPhase::UNKNOWN) {}

    MitreInfo(std::string tid,
              std::string tname,
              std::string tactic_,
              KillChainPhase phase,
              std::string ref = "")
        : technique_id(std::move(tid))
        , technique_name(std::move(tname))
        , tactic(std::move(tactic_))
        , kill_chain_phase(phase)
        , reference_url(std::move(ref))
    {}
};

/**
 * @struct NetworkContext
 * @brief Layer-3/4 network context of the packet(s) that triggered the alert.
 *
 * All IP addresses are stored as dotted-decimal strings (e.g. "192.168.1.1").
 * We avoid uint32_t here because:
 *  1. IPv6 support is easier to add later with strings
 *  2. JSON serialization is trivial — no conversion needed
 *  3. Human readability in logs without extra formatting
 *
 * Ports are uint16_t (0–65535), matching the TCP/UDP spec.
 * 0 means "not applicable" (e.g. ICMP has no ports).
 *
 * Fields:
 *  src_ip          → Source IP address
 *  dst_ip          → Destination IP address
 *  src_port        → Source port (0 if N/A)
 *  dst_port        → Destination port (0 if N/A)
 *  protocol        → Layer-4 protocol
 *  tcp_flags       → Raw TCP flags byte (SYN=0x02, ACK=0x10, etc.)
 *                    Only meaningful when protocol == TCP
 *  ttl             → IP Time-To-Live value
 *  packet_length   → Total packet length in bytes
 */
struct NetworkContext {
    std::string src_ip;
    std::string dst_ip;
    uint16_t    src_port      = 0;
    uint16_t    dst_port      = 0;
    Protocol    protocol      = Protocol::UNKNOWN;
    uint8_t     tcp_flags     = 0;
    uint8_t     ttl           = 0;
    uint32_t    packet_length = 0;

    NetworkContext() = default;

    NetworkContext(std::string sip, std::string dip,
                   uint16_t sport, uint16_t dport,
                   Protocol proto)
        : src_ip(std::move(sip))
        , dst_ip(std::move(dip))
        , src_port(sport)
        , dst_port(dport)
        , protocol(proto)
    {}
};

/**
 * @struct YaraMatch
 * @brief Details of a YARA rule match, populated only for YARA_MATCH alerts.
 *
 * Fields:
 *  rule_name       → Name of the matched YARA rule, e.g. "shellcode_nop_sled"
 *  rule_file       → File the rule was loaded from, e.g. "shellcode_patterns.yar"
 *  matched_strings → List of specific YARA string identifiers that matched
 *                    e.g. { "$nop_sled", "$int3_breakpoint" }
 *  payload_hash    → SHA-256 hash of the raw packet payload (hex string)
 *                    Useful for pivoting to threat intel databases
 */
struct YaraMatch {
    std::string              rule_name;
    std::string              rule_file;
    std::vector<std::string> matched_strings;
    std::string              payload_hash;     // SHA-256 hex string
};

/**
 * @struct Evidence
 * @brief Detector-specific supporting data for the alert.
 *
 * This struct is intentionally open-ended. Each detector populates only
 * the fields relevant to it. Unused fields are left at their zero/empty
 * defaults and are omitted from JSON output by the AlertEmitter.
 *
 * Port Scan evidence:
 *  ports_contacted, window_seconds, packet_count, scan_type
 *
 * SYN Flood evidence:
 *  syn_count, syn_ack_ratio, window_seconds, packet_count
 *
 * HTTP Anomaly evidence:
 *  http_method, http_path, http_user_agent, anomaly_reason
 *
 * YARA Match evidence:
 *  yara_match (see YaraMatch struct)
 *
 * Honeypot evidence:
 *  honeypot_port, service_mimicked
 *
 * Generic:
 *  extra — arbitrary key-value pairs for anything that doesn't fit above.
 *  Use sparingly; prefer named fields for common patterns.
 */
struct Evidence {
    // ── Port Scan ────────────────────────────────────────────────────────
    std::vector<uint16_t> ports_contacted;   // distinct dst ports seen
    std::string           scan_type;         // "SYN", "NULL", "FIN", "XMAS"

    // ── SYN Flood ────────────────────────────────────────────────────────
    uint32_t syn_count     = 0;
    float    syn_ack_ratio = 0.0f;           // SYN count / SYN-ACK count

    // ── HTTP Anomaly ─────────────────────────────────────────────────────
    std::string http_method;                 // "GET", "POST", etc.
    std::string http_path;                   // request path
    std::string http_user_agent;
    std::string anomaly_reason;              // human-readable explanation

    // ── Shared: timing ───────────────────────────────────────────────────
    uint32_t window_seconds = 0;             // observation window
    uint32_t packet_count   = 0;             // packets in the window

    // ── YARA ─────────────────────────────────────────────────────────────
    std::optional<YaraMatch> yara_match;

    // ── Honeypot ─────────────────────────────────────────────────────────
    uint16_t    honeypot_port    = 0;
    std::string service_mimicked;            // e.g. "SSH", "HTTP"

    // ── Generic overflow ─────────────────────────────────────────────────
    std::unordered_map<std::string, std::string> extra;
};


// ============================================================================
//  SECTION 4 — CORE ALERT STRUCT
// ============================================================================

/**
 * @struct Alert
 * @brief The central unit of detection output in SentinelX.
 *
 * An Alert is produced by a detector and consumed by the AlertEmitter,
 * which serializes it to JSON and pushes it over a Unix socket to the
 * Node.js backend.
 *
 * Lifecycle:
 *  1. Detector constructs an Alert and fills all relevant fields.
 *  2. Detector returns the Alert (or pushes to a queue).
 *  3. AlertEmitter calls alert.toJson() and writes the result to the socket.
 *  4. Node.js backend parses the JSON, stores it in MongoDB, and broadcasts
 *     it over WebSocket to connected dashboard clients.
 *
 * ID generation:
 *  alert_id is a pseudo-UUID generated at construction time using
 *  timestamp + random suffix. It is NOT a cryptographic UUID — it's a
 *  collision-resistant identifier sufficient for a single-node NIDS.
 *  If you need true UUID v4, replace generateId() with a proper library.
 *
 * Timestamp format:
 *  ISO 8601 UTC: "2026-03-19T14:32:01.482Z"
 *  Generated at construction via std::chrono::system_clock.
 *
 * Fields:
 *  alert_id        → Unique identifier for this alert instance
 *  timestamp       → ISO 8601 UTC timestamp of detection
 *  severity        → Threat severity (LOW / MEDIUM / HIGH / CRITICAL)
 *  type            → Detection category (PORT_SCAN, SYN_FLOOD, etc.)
 *  network         → Layer-3/4 context (IPs, ports, protocol, flags)
 *  mitre           → ATT&CK technique + kill chain mapping
 *  evidence        → Detector-specific supporting data
 *  description     → One-line human-readable summary of the alert
 *                    e.g. "Port scan detected: 192.168.1.5 probed 12 ports
 *                          on 10.0.0.1 within 5 seconds"
 *  false_positive  → Flag set by analyst during triage (default: false)
 *  reviewed        → Flag set when alert has been reviewed (default: false)
 */
struct Alert {

    // ── Identity ─────────────────────────────────────────────────────────
    std::string alert_id;
    std::string timestamp;

    // ── Classification ───────────────────────────────────────────────────
    Severity    severity = Severity::LOW;
    AlertType   type     = AlertType::UNKNOWN;

    // ── Context ──────────────────────────────────────────────────────────
    NetworkContext network;
    MitreInfo      mitre;
    Evidence       evidence;

    // ── Human-readable summary ───────────────────────────────────────────
    std::string description;

    // ── Analyst flags (set post-detection, not by engine) ────────────────
    bool false_positive = false;
    bool reviewed       = false;


    // ────────────────────────────────────────────────────────────────────
    //  CONSTRUCTORS
    // ────────────────────────────────────────────────────────────────────

    /**
     * @brief Default constructor.
     * Automatically generates alert_id and timestamp on construction.
     */
    Alert() {
        alert_id  = generateId();
        timestamp = generateTimestamp();
    }

    /**
     * @brief Convenience constructor for the most common fields.
     *
     * @param t         AlertType (PORT_SCAN, SYN_FLOOD, etc.)
     * @param s         Severity level
     * @param net       Network context (src/dst IPs, ports, protocol)
     * @param mit       MITRE ATT&CK mapping
     * @param desc      One-line human-readable description
     */
    Alert(AlertType t,
          Severity s,
          NetworkContext net,
          MitreInfo mit,
          std::string desc)
        : severity(s)
        , type(t)
        , network(std::move(net))
        , mitre(std::move(mit))
        , description(std::move(desc))
    {
        alert_id  = generateId();
        timestamp = generateTimestamp();
    }


    // ────────────────────────────────────────────────────────────────────
    //  JSON SERIALIZATION
    //  Minimal hand-rolled JSON to avoid pulling in nlohmann/json at the
    //  header level. AlertEmitter will use nlohmann/json for full output;
    //  this toJson() is a lightweight debug/logging utility.
    // ────────────────────────────────────────────────────────────────────

    /**
     * @brief Serialize the alert to a compact JSON string.
     *
     * Produces a single-line JSON object — no pretty printing.
     * Intended for IPC (Unix socket write) and debug logging.
     *
     * Note: Does NOT include evidence sub-fields — those are serialized
     * by AlertEmitter using nlohmann/json for full fidelity.
     *
     * @return std::string containing the JSON representation.
     *
     * Example output:
     * @code
     * {
     *   "alert_id":    "a1b2c3d4e5f6",
     *   "timestamp":   "2026-03-19T14:32:01Z",
     *   "severity":    "HIGH",
     *   "type":        "PORT_SCAN",
     *   "src_ip":      "192.168.1.105",
     *   "dst_ip":      "10.0.0.1",
     *   "src_port":    54231,
     *   "dst_port":    22,
     *   "protocol":    "TCP",
     *   "description": "Port scan detected...",
     *   "mitre": {
     *     "technique_id":   "T1046",
     *     "technique_name": "Network Service Discovery",
     *     "tactic":         "Discovery",
     *     "kill_chain":     "Reconnaissance"
     *   }
     * }
     * @endcode
     */
    std::string toJson() const {
        std::ostringstream oss;
        oss << "{"
            << "\"alert_id\":\""    << alert_id                                  << "\","
            << "\"timestamp\":\""   << timestamp                                 << "\","
            << "\"severity\":\""    << severityToString(severity)                << "\","
            << "\"type\":\""        << alertTypeToString(type)                   << "\","
            << "\"src_ip\":\""      << network.src_ip                            << "\","
            << "\"dst_ip\":\""      << network.dst_ip                            << "\","
            << "\"src_port\":"      << network.src_port                          << ","
            << "\"dst_port\":"      << network.dst_port                          << ","
            << "\"protocol\":\""    << protocolToString(network.protocol)        << "\","
            << "\"description\":\"" << escapeJson(description)                   << "\","
            << "\"false_positive\":" << (false_positive ? "true" : "false")      << ","
            << "\"reviewed\":"      << (reviewed ? "true" : "false")             << ","
            << "\"mitre\":{"
                << "\"technique_id\":\""   << mitre.technique_id                 << "\","
                << "\"technique_name\":\"" << mitre.technique_name               << "\","
                << "\"tactic\":\""         << mitre.tactic                       << "\","
                << "\"kill_chain\":\""     << killChainPhaseToString(mitre.kill_chain_phase) << "\","
                << "\"reference_url\":\"" << mitre.reference_url                << "\""
            << "}"
            << "}";
        return oss.str();
    }


private:
    // ────────────────────────────────────────────────────────────────────
    //  PRIVATE HELPERS
    // ────────────────────────────────────────────────────────────────────

    /**
     * @brief Generate a pseudo-unique alert ID.
     *
     * Format: <unix_timestamp_ms>_<random_hex_suffix>
     * Example: "1742390321482_a3f9"
     *
     * Not a UUID v4 — collision probability is negligible for a
     * single-node NIDS processing thousands of alerts/sec.
     * For multi-node deployments, replace with uuid_generate() or
     * boost::uuids::random_generator.
     */
    static std::string generateId() {
        using namespace std::chrono;

        auto now_ms = duration_cast<milliseconds>(
            system_clock::now().time_since_epoch()
        ).count();

        // simple pseudo-random suffix — not cryptographic
        uint16_t suffix = static_cast<uint16_t>(now_ms ^ (now_ms >> 16));

        std::ostringstream oss;
        oss << now_ms << "_"
            << std::hex << std::setw(4) << std::setfill('0') << suffix;
        return oss.str();
    }

    /**
     * @brief Generate an ISO 8601 UTC timestamp string.
     *
     * Format: "2026-03-19T14:32:01Z"
     * Resolution: seconds (sufficient for alert correlation).
     *
     * Uses std::chrono::system_clock → std::time_t → std::gmtime.
     * gmtime is not thread-safe on all platforms; for a multi-threaded
     * engine, replace with gmtime_r (POSIX) or gmtime_s (Windows/MSVC).
     */
    static std::string generateTimestamp() {
        using namespace std::chrono;

        auto now        = system_clock::now();
        std::time_t t   = system_clock::to_time_t(now);
        std::tm* utc_tm = std::gmtime(&t);  // use gmtime_r in MT context

        std::ostringstream oss;
        oss << std::put_time(utc_tm, "%Y-%m-%dT%H:%M:%SZ");
        return oss.str();
    }

    /**
     * @brief Escape special JSON characters in a string.
     *
     * Handles: backslash, double-quote, newline, carriage return, tab.
     * Required to safely embed description strings in JSON output.
     *
     * @param s Input string
     * @return  JSON-safe escaped string
     */
    static std::string escapeJson(const std::string& s) {
        std::ostringstream oss;
        for (char c : s) {
            switch (c) {
                case '\\': oss << "\\\\"; break;
                case '"':  oss << "\\\""; break;
                case '\n': oss << "\\n";  break;
                case '\r': oss << "\\r";  break;
                case '\t': oss << "\\t";  break;
                default:   oss << c;      break;
            }
        }
        return oss.str();
    }
};


// ============================================================================
//  SECTION 5 — CONVENIENCE FACTORY FUNCTIONS
//  Pre-filled Alert constructors for each detector type.
//  Detectors call these instead of manually filling every field —
//  reduces boilerplate and keeps MITRE mappings in one place.
// ============================================================================

/**
 * @brief Create a PORT_SCAN alert with pre-filled MITRE context.
 *
 * ATT&CK: T1046 — Network Service Discovery
 * Tactic: Discovery
 * Kill Chain: Reconnaissance
 *
 * @param net       Network context from the triggering packet
 * @param severity  Severity (typically MEDIUM for slow scan, HIGH for fast)
 * @param desc      Human-readable description
 */
inline Alert makePortScanAlert(NetworkContext net,
                                Severity severity,
                                std::string desc) {
    MitreInfo mitre(
        "T1046",
        "Network Service Discovery",
        "Discovery",
        KillChainPhase::RECONNAISSANCE,
        "https://attack.mitre.org/techniques/T1046/"
    );
    return Alert(AlertType::PORT_SCAN, severity, std::move(net),
                 std::move(mitre), std::move(desc));
}

/**
 * @brief Create a SYN_FLOOD alert with pre-filled MITRE context.
 *
 * ATT&CK: T1498.001 — Network Denial of Service: Direct Network Flood
 * Tactic: Impact
 * Kill Chain: Actions on Objectives
 */
inline Alert makeSYNFloodAlert(NetworkContext net,
                                Severity severity,
                                std::string desc) {
    MitreInfo mitre(
        "T1498.001",
        "Network Denial of Service: Direct Network Flood",
        "Impact",
        KillChainPhase::ACTIONS,
        "https://attack.mitre.org/techniques/T1498/001/"
    );
    return Alert(AlertType::SYN_FLOOD, severity, std::move(net),
                 std::move(mitre), std::move(desc));
}

/**
 * @brief Create an HTTP_ANOMALY alert with pre-filled MITRE context.
 *
 * ATT&CK: T1190 — Exploit Public-Facing Application
 * Tactic: Initial Access
 * Kill Chain: Exploitation
 */
inline Alert makeHTTPAnomalyAlert(NetworkContext net,
                                   Severity severity,
                                   std::string desc) {
    MitreInfo mitre(
        "T1190",
        "Exploit Public-Facing Application",
        "Initial Access",
        KillChainPhase::EXPLOITATION,
        "https://attack.mitre.org/techniques/T1190/"
    );
    return Alert(AlertType::HTTP_ANOMALY, severity, std::move(net),
                 std::move(mitre), std::move(desc));
}

/**
 * @brief Create a YARA_MATCH alert with pre-filled MITRE context.
 *
 * ATT&CK: T1059 — Command and Scripting Interpreter (generic shellcode)
 * Tactic: Execution
 * Kill Chain: Exploitation
 *
 * Note: YARA alerts may map to different techniques depending on the
 * matched rule. Override mitre after construction if needed.
 */
inline Alert makeYARAMatchAlert(NetworkContext net,
                                 Severity severity,
                                 std::string desc) {
    MitreInfo mitre(
        "T1059",
        "Command and Scripting Interpreter",
        "Execution",
        KillChainPhase::EXPLOITATION,
        "https://attack.mitre.org/techniques/T1059/"
    );
    return Alert(AlertType::YARA_MATCH, severity, std::move(net),
                 std::move(mitre), std::move(desc));
}

/**
 * @brief Create a HONEYPOT_HIT alert with pre-filled MITRE context.
 *
 * ATT&CK: T1046 — Network Service Discovery
 * Tactic: Discovery
 * Kill Chain: Reconnaissance
 */
inline Alert makeHoneypotAlert(NetworkContext net,
                                Severity severity,
                                std::string desc) {
    MitreInfo mitre(
        "T1046",
        "Network Service Discovery",
        "Discovery",
        KillChainPhase::RECONNAISSANCE,
        "https://attack.mitre.org/techniques/T1046/"
    );
    return Alert(AlertType::HONEYPOT_HIT, severity, std::move(net),
                 std::move(mitre), std::move(desc));
}
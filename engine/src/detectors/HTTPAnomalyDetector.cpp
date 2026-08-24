/**
 * @file    HTTPAnomalyDetector.cpp
 * @brief   Implementation of the HTTP anomaly checks.
 *
 * @author  Ash
 * @project SentinelX
 */

#include "HTTPAnomalyDetector.h"

#include <algorithm>


// ============================================================================
//  KNOWN HTTP METHODS (for malformed-request heuristics)
// ============================================================================

static const char* const HTTP_METHODS[] = {
    "GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "CONNECT ", "OPTIONS ",
    "TRACE ", "PATCH ", "PROPFIND ", "PROPPATCH ", "MKCOL ", "COPY ",
    "MOVE ", "LOCK ", "UNLOCK ",
    nullptr
};

/**
 * @brief Find the first CRLF in a byte buffer (portable memmem replacement
 *        for the two-byte search — memmem is not in the C++ standard).
 * @return pointer to the CRLF, or nullptr if not found
 */
static const char* findCRLF(const char* data, size_t len) {
    if (len < 2) {
        return nullptr;
    }
    const char* end = data + len - 1;
    for (const char* p = data; p < end; ++p) {
        if (p[0] == '\r' && p[1] == '\n') {
            return p;
        }
    }
    return nullptr;
}


// ============================================================================
//  CONSTRUCTION
// ============================================================================

HTTPAnomalyDetector::HTTPAnomalyDetector(HTTPAnomalyConfig config)
    : m_config(std::move(config)) {}


// ============================================================================
//  BASE DETECTOR INTERFACE
// ============================================================================

std::string HTTPAnomalyDetector::name() const {
    return "HTTPAnomalyDetector";
}


std::vector<Alert> HTTPAnomalyDetector::process(const RawPacket& raw,
                                                const IPPacket& ip,
                                                const TCPPacket* tcp,
                                                const HTTPPacket* http,
                                                int64_t ts_ms) {
    std::vector<Alert> out;

    if (!tcp) {
        return out;  // UDP/ICMP — nothing HTTP here
    }

    // ── Case A: payload parsed as a valid HTTP message ───────────────────

    if (http) {
        m_requests_inspected++;

        if (http->message_type != HTTPMessageType::REQUEST) {
            return out;  // responses can't be the injected anomaly
        }

        const std::string& path    = http->path;
        const std::string& query   = http->query_string;
        const std::string& ua      = http->user_agent;
        const std::string& method  = http->method;

        // 1. Path traversal (raw or URL-encoded)
        if (HTTPParser::hasPathTraversal(path) ||
            (!query.empty() && HTTPParser::hasPathTraversal(query))) {
            recordAnomaly(out, ip, tcp, http, "PATH_TRAVERSAL",
                          "Path traversal pattern in URL",
                          "URL: " + path +
                              (query.empty() ? std::string()
                                             : "?" + query),
                          Severity::HIGH, ts_ms);
        }

        // 2. SQL injection in query string or request body preview
        if ((!query.empty() && HTTPParser::hasSQLInjection(query)) ||
            (!http->body_preview.empty() &&
             HTTPParser::hasSQLInjection(http->body_preview))) {
            recordAnomaly(out, ip, tcp, http, "SQL_INJECTION",
                          "SQL injection signature in request",
                          "URL: " + path +
                              (query.empty() ? std::string()
                                             : "?" + query),
                          Severity::HIGH, ts_ms);
        }

        // 3. Null bytes in path/query — WAF / IDS bypass attempt.
        //    NOTE: use the char overload find('\0') — find("\x00") is a
        //    const char* overload that sees an EMPTY string and would
        //    match every single path.
        const bool null_in_path =
            path.find("%00") != std::string::npos ||
            path.find('\0') != std::string::npos;
        const bool null_in_query =
            !query.empty() &&
            (query.find("%00") != std::string::npos ||
             query.find('\0') != std::string::npos);
        if (null_in_path || null_in_query) {
            recordAnomaly(out, ip, tcp, http, "NULL_BYTE",
                          "Null byte in URL — WAF bypass attempt",
                          "URL: " + path,
                          Severity::HIGH, ts_ms);
        }

        // 4. Oversized header value — buffer overflow probe
        for (const auto& [key, value] : http->headers) {
            if (value.size() > m_config.header_value_limit) {
                recordAnomaly(out, ip, tcp, http, "OVERSIZED_HEADER",
                              "Header value exceeds " +
                                  std::to_string(m_config.header_value_limit) +
                                  " bytes",
                              "Header: " + key + " (" +
                                  std::to_string(value.size()) + " bytes)",
                              Severity::HIGH, ts_ms);
                break;  // one oversized-header alert per request is enough
            }
        }

        // 5. Known scanner User-Agent
        if (!ua.empty() && HTTPParser::isScannerUserAgent(ua)) {
            recordAnomaly(out, ip, tcp, http, "SCANNER_USER_AGENT",
                          "Known scanner User-Agent string",
                          "User-Agent: " + ua,
                          Severity::MEDIUM, ts_ms);
        }

        // 6. Unusual verb — TRACE/TRACK never legitimate on a public
        //    server; CONNECT indicates proxy abuse or tunneling.
        if (method == "TRACE" || method == "TRACK" || method == "CONNECT") {
            recordAnomaly(out, ip, tcp, http, "UNUSUAL_VERB",
                          "Unusual HTTP verb: " + method,
                          "URL: " + method + " " + path,
                          Severity::MEDIUM, ts_ms);
        }
    }
    // ── Case B: non-empty payload on an HTTP port that does NOT parse ───
    //
    // A well-formed mid-stream body fragment usually does not contain a
    // CRLF within its first bytes. If it does, something is claiming to
    // be an HTTP message — and failing to be one. That's a malformed
    // request (protocol fuzzing, malformed-header attack, or an attempt
    // to confuse the upstream server).

    else if (tcp->payload_length > 0 &&
             HTTPParser::isHTTPPort(tcp->dst_port)) {

        const char* payload =
            reinterpret_cast<const char*>(raw.data + tcp->payload_offset);
        size_t      avail   = tcp->payload_length;

        const char* crlf = findCRLF(payload, avail);

        if (crlf && (crlf - payload) < 256) {
            std::string first_line(payload, crlf - payload);

            bool looks_like_request = false;
            for (int i = 0; HTTP_METHODS[i] != nullptr; ++i) {
                if (first_line.rfind(HTTP_METHODS[i], 0) == 0) {
                    looks_like_request = true;
                    break;
                }
            }
            // "HTTP/" start = someone sent a response where a request
            // belongs — also malformed for our purposes.
            const bool looks_like_response =
                first_line.rfind("HTTP/", 0) == 0;

            if (!looks_like_request && !looks_like_response) {
                // Keep the first 120 chars for the evidence (sanitize
                // control chars so the alert JSON stays clean).
                std::string snippet = first_line.substr(0, 120);
                for (char& c : snippet) {
                    if (static_cast<unsigned char>(c) < 0x20) c = ' ';
                }
                recordAnomaly(out, ip, tcp, nullptr, "MALFORMED_HTTP",
                              "Malformed HTTP request on port " +
                                  std::to_string(tcp->dst_port),
                              "First line: " + snippet,
                              Severity::MEDIUM, ts_ms);
            }
        }
    }

    return out;
}


void HTTPAnomalyDetector::tick(int64_t now_ms) {
    // Drop cooldown entries that have expired.
    for (auto it = m_last_alert.begin(); it != m_last_alert.end(); ) {
        if (now_ms - it->second > static_cast<int64_t>(m_config.cooldown_ms * 2)) {
            it = m_last_alert.erase(it);
        } else {
            ++it;
        }
    }
}


void HTTPAnomalyDetector::reset() {
    m_last_alert.clear();
    m_requests_inspected = 0;
    m_anomalies_found    = 0;
}


// ============================================================================
//  PRIVATE HELPERS
// ============================================================================

Alert* HTTPAnomalyDetector::recordAnomaly(std::vector<Alert>& out,
                                          const IPPacket& ip,
                                          const TCPPacket* tcp,
                                          const HTTPPacket* http,
                                          const std::string& kind,
                                          const std::string& reason,
                                          const std::string& details,
                                          Severity severity,
                                          int64_t ts_ms) {
    m_anomalies_found++;

    // ── Dedup: one alert per (src_ip, kind) per cooldown window ──────────
    const std::string dedup_key = ip.src_ip + "|" + kind;
    auto              it        = m_last_alert.find(dedup_key);
    if (it != m_last_alert.end() &&
        ts_ms - it->second < static_cast<int64_t>(m_config.cooldown_ms)) {
        return nullptr;  // already alerted for this source+kind recently
    }
    m_last_alert[dedup_key] = ts_ms;

    // ── Build the alert ──────────────────────────────────────────────────
    NetworkContext net;
    net.src_ip     = ip.src_ip;
    net.dst_ip     = ip.dst_ip;
    net.protocol   = HTTPParser::isHTTPPort(tcp->dst_port)
                         ? Protocol::HTTP
                         : Protocol::TCP;

    if (tcp) {
        net.src_port = tcp->src_port;
        net.dst_port = tcp->dst_port;
    }

    std::string desc = kind + " detected from " + ip.src_ip + " → " +
                       ip.dst_ip + ":" + std::to_string(net.dst_port) +
                       " — " + reason;

    Alert alert = makeHTTPAnomalyAlert(net, severity, std::move(desc));
    alert.mitre = mitreFor(kind);

    if (http) {
        alert.evidence.http_method      = http->method;
        alert.evidence.http_path        = http->path;
        alert.evidence.http_user_agent  = http->user_agent;
    }
    alert.evidence.anomaly_reason = reason;
    alert.evidence.extra["anomaly_kind"] = kind;
    alert.evidence.extra["details"]      = details;

    out.push_back(std::move(alert));
    return &out.back();
}


MitreInfo HTTPAnomalyDetector::mitreFor(const std::string& kind) const {
    // Exploitation attempts map to T1190 (the factory's default).
    // Scanner-tool traffic maps to T1595.002 — Vulnerability Scanning —
    // which is a Reconnaissance tactic, not exploitation.
    if (kind == "SCANNER_USER_AGENT") {
        return MitreInfo(
            "T1595.002",
            "Vulnerability Scanning",
            "Reconnaissance",
            KillChainPhase::RECONNAISSANCE,
            "https://attack.mitre.org/techniques/T1595/002/"
        );
    }
    return MitreInfo(
        "T1190",
        "Exploit Public-Facing Application",
        "Initial Access",
        KillChainPhase::EXPLOITATION,
        "https://attack.mitre.org/techniques/T1190/"
    );
}

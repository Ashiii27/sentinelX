/**
 * @file    HTTPAnomalyDetector.h
 * @brief   Detects malicious / anomalous HTTP requests
 *          (T1190 — Exploit Public-Facing Application).
 *
 * ── What Gets Flagged ────────────────────────────────────────────────────
 *
 * For every parsed HTTP REQUEST (responses are ignored — they can't be
 * injected by an attacker with the same fidelity), the detector runs a
 * battery of independent checks. Each check that fires produces its own
 * alert, so a single request containing three anomalies yields three
 * alerts (an analyst wants the full picture of a malicious request, not
 * just the first match):
 *
 *  1. PATH_TRAVERSAL     → path or query contains ../, ..\, %2e%2e/, etc.
 *                           MITRE T1190 · HIGH
 *  2. SQL_INJECTION      → query string or body preview matches SQLi
 *                           signatures (' OR 1=1, UNION SELECT, ...)
 *                           MITRE T1190 · HIGH
 *  3. NULL_BYTE          → %00 or literal NUL in path/query — WAF/IDS
 *                           bypass attempt.  MITRE T1190 · HIGH
 *  4. OVERSIZED_HEADER   → a single header value > header_value_limit
 *                           (8KB default) — buffer overflow probe.
 *                           MITRE T1190 · HIGH
 *  5. SCANNER_USER_AGENT → User-Agent matches a known scanner signature
 *                           (nmap, nikto, sqlmap, nuclei, ...).
 *                           MITRE T1595.002 · MEDIUM
 *  6. UNUSUAL_VERB       → TRACE / TRACK (never legitimate on a public
 *                           server) or CONNECT (proxy abuse / tunneling).
 *                           MITRE T1190 · MEDIUM
 *  7. MALFORMED_HTTP     → payload on a well-known HTTP port that does
 *                           not parse as a valid HTTP request line
 *                           (malformed-header attack / protocol fuzzing).
 *                           MITRE T1190 · MEDIUM
 *
 * ── Deduplication ────────────────────────────────────────────────────────
 *
 * Scanners spray the same anomaly at many URLs. To keep the alert feed
 * usable, each (src_ip, anomaly_kind) pair alerts at most once per
 * `cooldown_ms` (default 10s). The first alert in the burst carries the
 * full evidence; subsequent hits are counted in the dashboard's stats
 * instead of re-alerting.
 *
 * @author  Ash
 * @project SentinelX
 */

#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>

#include "BaseDetector.h"


// ============================================================================
//  CONFIGURATION
// ============================================================================

/**
 * @struct HTTPAnomalyConfig
 * @brief Tunables for HTTPAnomalyDetector.
 */
struct HTTPAnomalyConfig {
    size_t   header_value_limit = 8192;  ///< max bytes in one header value
    uint32_t cooldown_ms        = 10000; ///< per-(src, anomaly) alert cooldown
};


// ============================================================================
//  DETECTOR
// ============================================================================

/**
 * @class HTTPAnomalyDetector
 * @brief Signature + heuristic checks on parsed HTTP requests.
 *
 * Usage:
 * @code
 *   HTTPAnomalyDetector http_anom;
 *   auto alerts = http_anom.process(raw, ip, tcp, http.get(), ts_ms);
 * @endcode
 */
class HTTPAnomalyDetector : public BaseDetector {
public:

    explicit HTTPAnomalyDetector(HTTPAnomalyConfig config =
                                    HTTPAnomalyConfig{});

    // ── BaseDetector interface ──────────────────────────────────────────
    std::string name() const override;

    std::vector<Alert> process(const RawPacket& raw,
                               const IPPacket& ip,
                               const TCPPacket* tcp,
                               const HTTPPacket* http,
                               int64_t ts_ms) override;

    void tick(int64_t now_ms) override;
    void reset() override;

    // ── Diagnostics ─────────────────────────────────────────────────────
    uint64_t requestsInspected() const { return m_requests_inspected; }
    uint64_t anomaliesFound()    const { return m_anomalies_found; }

private:

    /**
     * @brief Record one anomaly (dedup check + alert construction).
     *
     * @return the alert if it passes the cooldown, nullptr otherwise
     */
    Alert* recordAnomaly(std::vector<Alert>& out,
                         const IPPacket& ip,
                         const TCPPacket* tcp,
                         const HTTPPacket* http,
                         const std::string& kind,
                         const std::string& reason,
                         const std::string& details,
                         Severity severity,
                         int64_t ts_ms);

    /// Build the MITRE context for an anomaly kind (T1595.002 for
    /// scanner UAs, T1190 for everything else).
    MitreInfo mitreFor(const std::string& kind) const;

    HTTPAnomalyConfig                    m_config;
    std::unordered_map<std::string, int64_t> m_last_alert;  // key: src|kind
    uint64_t m_requests_inspected = 0;
    uint64_t m_anomalies_found    = 0;
};

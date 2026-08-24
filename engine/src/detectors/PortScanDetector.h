/**
 * @file    PortScanDetector.h
 * @brief   Detects port scanning activity (T1046 — Network Service Discovery).
 *
 * ── Detection Algorithm ──────────────────────────────────────────────────
 *
 * For every (src_ip, dst_ip) pair the detector keeps a sliding time window
 * of observed connection probes. A "probe" is:
 *
 *   TCP  → SYN-only packets, plus NULL/FIN/XMAS-flagged packets
 *          (established traffic — SYN+ACK, pure ACK, PSH data — is ignored,
 *           it is not scanning)
 *   UDP  → every UDP datagram (UDP "scans" can't be half-open; a high
 *          volume of distinct-port UDP from one source IS the scan)
 *
 * When the number of DISTINCT destination ports probed by one source
 * against one target exceeds `min_ports` within `window_seconds`, a
 * PORT_SCAN alert is emitted.
 *
 * ── Alert Deduplication (Cooldown) ───────────────────────────────────────
 *
 * A sustained scan produces one alert per `cooldown_ms` (default 30s) per
 * (src, dst) pair — not one per probe. Without this, a 500-port scan would
 * generate 490 alerts after the threshold was crossed.
 *
 * ── Scan Type Classification ─────────────────────────────────────────────
 *
 * The scan_type in the evidence is the classification of the MAJORITY of
 * probes in the window (TCPParser::classifyScanType per probe). Mixed
 * traffic resolves to "SYN" (the common denominator) — an attacker who
 * mixes flags is still scanning.
 *
 * ── Severity Model ───────────────────────────────────────────────────────
 *
 *  Internal source (RFC 1918 / loopback)  → MEDIUM
 *      Rationale: internal scans are often admin tooling or a compromised
 *      host. Worth investigating, not a page.
 *  External source                        → HIGH
 *      Rationale: nobody legitimate is scanning in from the internet.
 *
 *  The scan type escalates one level when aggressive / stealthy flag
 *  combinations are used (NULL, FIN, XMAS) — these are deliberate
 *  fingerprinting techniques that normal clients never produce.
 *
 * ── Memory Bounding ──────────────────────────────────────────────────────
 *
 * The detector caps the number of tracked (src,dst) pairs at
 * `max_tracked_pairs` (default 100k). When the cap is reached and no
 * expired pair can be purged, NEW pairs are not tracked (the probe is
 * dropped silently). This bounds worst-case memory at roughly:
 *   100k pairs × ~200 bytes average state ≈ 20 MB.
 * A SYN-flood-style probe of distinct (src,dst) pairs will therefore
 * never OOM the engine — it just gets less scan tracking, while the
 * SYNFloodDetector (per-dst, not per-pair) still catches the flood.
 *
 * @author  Ash
 * @project SentinelX
 */

#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <deque>
#include <cstdint>

#include "BaseDetector.h"


// ============================================================================
//  CONFIGURATION
// ============================================================================

/**
 * @struct PortScanConfig
 * @brief Tunable thresholds for PortScanDetector.
 *
 * Defaults reflect a typical small office / home segment. Tune per
 * environment — a busy datacenter LAN will need higher values.
 */
struct PortScanConfig {
    uint16_t min_ports_tcp   = 10;    ///< distinct TCP ports → alert (5s window)
    uint32_t window_ms_tcp   = 5000;  ///< sliding window for TCP probes
    uint16_t min_ports_udp   = 20;    ///< distinct UDP ports → alert (5s window)
    uint32_t window_ms_udp   = 5000;  ///< sliding window for UDP probes
    uint32_t cooldown_ms     = 30000; ///< min time between alerts for same (src,dst)
    size_t   max_tracked_pairs = 100000; ///< cap on (src,dst) state entries
};


// ============================================================================
//  DETECTOR
// ============================================================================

/**
 * @class PortScanDetector
 * @brief Sliding-window, per-(src,dst) port scan detector.
 *
 * Usage:
 * @code
 *   PortScanConfig cfg;
 *   cfg.min_ports_tcp = 10;
 *   PortScanDetector scan(cfg);
 *
 *   std::vector<Alert> alerts = scan.process(raw, ip, tcp, nullptr, ts_ms);
 *   for (auto& a : alerts) emitter.emit(a);
 * @endcode
 */
class PortScanDetector : public BaseDetector {
public:

    explicit PortScanDetector(PortScanConfig config = PortScanConfig{});

    // ── BaseDetector interface ──────────────────────────────────────────
    std::string name() const override;

    std::vector<Alert> process(const RawPacket& raw,
                               const IPPacket& ip,
                               const TCPPacket* tcp,
                               const HTTPPacket* http,
                               int64_t ts_ms) override;

    void tick(int64_t now_ms) override;
    void reset() override;

    // ── Diagnostics (used by tests and the stats logger) ────────────────

    /// Number of (src,dst) pairs currently being tracked.
    size_t trackedPairs() const { return m_states.size(); }

    /// Total probes observed since construction / last reset.
    uint64_t probesObserved() const { return m_probes_observed; }

    /// Total alerts emitted since construction / last reset.
    uint64_t alertsEmitted() const { return m_alerts_emitted; }

private:

    // ────────────────────────────────────────────────────────────────────
    //  INTERNAL STATE STRUCTURES
    // ────────────────────────────────────────────────────────────────────

    /**
     * @struct Probe
     * @brief A single observed probe in the sliding window.
     */
    struct Probe {
        int64_t   ts_ms;      // packet timestamp (Unix ms)
        uint16_t  dst_port;   // destination port probed
        uint8_t   tcp_flags;  // raw flags (0 for UDP probes)
        bool      is_udp;     // true for UDP probes
    };

    /**
     * @struct PairState
     * @brief Sliding-window state for one (src_ip, dst_ip) pair.
     */
    struct PairState {
        std::deque<Probe> probes;        // chronological, oldest first
        int64_t           last_alert_ms  = 0;  // cooldown anchor
        std::string       src_ip;        // cached for alert construction
        std::string       dst_ip;
        uint32_t          raw_src_ip     = 0; // for key construction in alerts
        uint32_t          raw_dst_ip     = 0;
    };

    // ────────────────────────────────────────────────────────────────────
    //  PRIVATE HELPERS
    // ────────────────────────────────────────────────────────────────────

    /// Build the map key from two 32-bit IPs (network byte order).
    static uint64_t pairKey(uint32_t src, uint32_t dst);

    /// Remove probes older than the appropriate window for this pair.
    void purgeExpired(PairState& st, int64_t now_ms) const;

    /// Count distinct ports currently in a pair's window (protocol-aware).
    size_t distinctPorts(const PairState& st) const;

    /// Majority scan type across the window: "SYN", "NULL", "FIN", "XMAS", "UDP"
    std::string majorityScanType(const PairState& st) const;

    /// Choose severity: internal vs external source, aggressive flags.
    Severity severityFor(const PairState& st, const std::string& scan_type) const;

    /// Build and return the PORT_SCAN alert for this pair's state.
    Alert buildAlert(const PairState& st,
                     const std::string& scan_type,
                     int64_t now_ms) const;

    /// True if a TCP packet is a "probe" (scan candidate) rather than
    /// normal conversation traffic.
    static bool isTcpProbe(const TCPPacket& tcp);

    // ────────────────────────────────────────────────────────────────────
    //  MEMBERS
    // ────────────────────────────────────────────────────────────────────

    PortScanConfig              m_config;
    std::unordered_map<uint64_t, PairState> m_states;
    uint64_t                    m_probes_observed = 0;
    uint64_t                    m_alerts_emitted  = 0;
};

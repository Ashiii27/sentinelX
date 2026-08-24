/**
 * @file    SYNFloodDetector.h
 * @brief   Detects TCP SYN flood / DoS attacks
 *          (T1498.001 — Direct Network Flood).
 *
 * ── Detection Algorithm ──────────────────────────────────────────────────
 *
 * A SYN flood saturates a target with half-open connections: the attacker
 * sends SYNs (often with spoofed source IPs) and never completes the
 * handshake, exhausting the target's connection backlog.
 *
 * On the wire this looks like:
 *   - A very high rate of SYN-only packets TO a destination
 *   - Few or no SYN+ACK responses coming back (the target is either
 *     not answering because it's busy, or its replies are visible to us
 *     and we can compute the ratio)
 *
 * For each destination IP the detector tracks, inside a sliding window
 * (`window_ms`, default 5s):
 *
 *   syn_count    → SYN-only packets received for this destination
 *   synack_count → SYN+ACK packets sent by this destination (any source)
 *
 * An alert fires when BOTH conditions hold:
 *
 *   1. syn_count >= syn_threshold          (absolute rate check)
 *   2. synack_count == 0  OR  (syn_count / synack_count) >= ratio_threshold
 *
 * Condition 2 distinguishes a FLOOD from a busy-but-healthy server: a
 * healthy web server may see 500 SYNs in 5s under normal load — but it
 * will answer each one with SYN+ACK, so the ratio stays near 1.0. A
 * flooded server's ratio explodes (spoofed SYNs get no response) or its
 * responses stop entirely (backlog exhausted).
 *
 * ── Severity Model ───────────────────────────────────────────────────────
 *
 *  syn_count >= 4 × syn_threshold  → CRITICAL  (sustained, high-rate flood)
 *  otherwise                       → HIGH
 *
 * ── Attribution ──────────────────────────────────────────────────────────
 *
 * The evidence records the top source IP by SYN count (top_src_ip,
 * top_src_count). For spoofed floods this will show one IP with a
 * count far below syn_count — a useful forensic signal.
 *
 * ── Alert Cadence ────────────────────────────────────────────────────────
 *
 * One alert per destination per window (a flood in progress produces a
 * steady stream of one alert every `window_ms` until it stops — the
 * dashboard shows this as an ongoing incident, not an alert storm).
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
 * @struct SYNFloodConfig
 * @brief Tunable thresholds for SYNFloodDetector.
 *
 * Defaults catch moderate floods on a small network. High-traffic
 * environments should raise syn_threshold (e.g. 1000–10000) to avoid
 * false positives on legitimately popular services.
 */
struct SYNFloodConfig {
    uint32_t window_ms            = 5000;   ///< sliding observation window
    uint32_t syn_threshold        = 100;    ///< SYNs per window → candidate
    float    ratio_threshold      = 5.0f;   ///< SYN:SYNACK ratio → confirmed
    size_t   max_tracked_dsts     = 10000;  ///< cap on per-destination state
};


// ============================================================================
//  DETECTOR
// ============================================================================

/**
 * @class SYNFloodDetector
 * @brief Per-destination SYN-rate flood detector.
 *
 * Usage:
 * @code
 *   SYNFloodDetector flood;
 *   auto alerts = flood.process(raw, ip, tcp, nullptr, ts_ms);
 * @endcode
 */
class SYNFloodDetector : public BaseDetector {
public:

    explicit SYNFloodDetector(SYNFloodConfig config = SYNFloodConfig{});

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

    size_t  trackedDestinations() const { return m_states.size(); }
    uint64_t synsObserved()       const { return m_syns_observed; }
    uint64_t alertsEmitted()      const { return m_alerts_emitted; }

private:

    /**
     * @struct DstState
     * @brief Sliding-window SYN/SYNACK counters for one destination IP.
     */
    struct DstState {
        std::string              dst_ip;
        std::deque<int64_t>      syn_times;      // timestamps of SYNs
        std::deque<int64_t>      synack_times;   // timestamps of SYN+ACKs
        std::unordered_map<std::string, uint32_t> syn_by_src;  // attribution
        int64_t                  last_alert_ms = 0;
        bool                     escalated     = false;  // CRITICAL sent this
                                                         // alert window
    };

    void purge(DstState& st, int64_t now_ms);

    /// Build the SYN_FLOOD alert from current window state.
    Alert buildAlert(const DstState& st,
                     uint32_t syn_count,
                     uint32_t synack_count,
                     int64_t now_ms) const;

    SYNFloodConfig m_config;
    std::unordered_map<std::string, DstState> m_states;  // keyed by dst_ip
    uint64_t m_syns_observed = 0;
    uint64_t m_alerts_emitted = 0;
};

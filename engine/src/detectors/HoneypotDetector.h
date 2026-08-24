/**
 * @file    HoneypotDetector.h
 * @brief   Flags any connection to configured honeypot (decoy) ports.
 *
 * ── Concept ──────────────────────────────────────────────────────────────
 *
 * A honeypot is a service that exists ONLY to be attacked. It mimics a
 * real service (SSH, HTTP, RDP) but runs no legitimate workload. Any
 * client that connects to it is, by definition, either:
 *
 *   - scanning / enumerating the network (they found a "service" that
 *     doesn't normally exist), or
 *   - actively probing an exposed decoy.
 *
 * Either way: a connection to a honeypot port is a HIGH-CONFIDENCE threat
 * indicator. There is no legitimate traffic to these ports, so no
 * behavioral analysis is needed — the destination alone is the signal.
 *
 * This makes HoneypotDetector the simplest detector in the engine:
 * destination-port membership test. It also has the best precision of
 * any detector in SentinelX — effectively zero false positives if the
 * configured ports are genuinely decoy-only.
 *
 * ── MITRE Mapping ────────────────────────────────────────────────────────
 *
 *  T1046 — Network Service Discovery (Reconnaissance)
 *  A probe of a non-standard port is service discovery behavior.
 *
 * ── Severity ─────────────────────────────────────────────────────────────
 *
 *  Always CRITICAL on first contact. The cooldown (default 60s per
 *  src+port) prevents alert storms from automated scanners that retry,
 *  while keeping every fresh probe visible.
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
 * @struct HoneypotPort
 * @brief One configured decoy service.
 *
 *  port    → TCP/UDP port the decoy listens on (e.g. 2222)
 *  service → human-readable service name for alerts (e.g. "SSH")
 */
struct HoneypotPort {
    uint16_t    port    = 0;
    std::string service = "UNKNOWN";
};


/**
 * @struct HoneypotConfig
 * @brief Configuration for HoneypotDetector.
 */
struct HoneypotConfig {
    std::vector<HoneypotPort> ports;
    uint32_t cooldown_ms = 60000;  ///< per-(src,port) alert cooldown

    /**
     * @brief Default honeypot set: fake SSH on 2222, fake HTTP on 8888.
     */
    static HoneypotConfig defaults() {
        HoneypotConfig c;
        c.ports = {{2222, "SSH"}, {8888, "HTTP"}};
        return c;
    }
};


// ============================================================================
//  DETECTOR
// ============================================================================

/**
 * @class HoneypotDetector
 * @brief Destination-port membership detector for decoy services.
 *
 * Usage:
 * @code
 *   HoneypotDetector hp;                    // default ports 2222, 8888
 *   auto alerts = hp.process(raw, ip, tcp, nullptr, ts_ms);
 * @endcode
 */
class HoneypotDetector : public BaseDetector {
public:

    explicit HoneypotDetector(HoneypotConfig config = HoneypotConfig::defaults());

    // ── BaseDetector interface ──────────────────────────────────────────
    std::string name() const override;

    std::vector<Alert> process(const RawPacket& raw,
                               const IPPacket& ip,
                               const TCPPacket* tcp,
                               const HTTPPacket* http,
                               int64_t ts_ms) override;

    void tick(int64_t now_ms) override;
    void reset() override;

    /// The configured honeypot ports (for the dashboard / Settings page).
    const std::vector<HoneypotPort>& ports() const { return m_config.ports; }

    uint64_t hits() const { return m_hits; }

private:

    /// Look up the honeypot service for a port; nullptr if not configured.
    const HoneypotPort* findPort(uint16_t port) const;

    HoneypotConfig                    m_config;
    std::unordered_map<std::string, int64_t> m_last_alert;  // src|port → ts
    uint64_t m_hits = 0;
};

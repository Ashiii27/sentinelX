/**
 * @file    HoneypotDetector.cpp
 * @brief   Implementation of the honeypot port detector.
 *
 * @author  Ash
 * @project SentinelX
 */

#include "HoneypotDetector.h"


// ============================================================================
//  CONSTRUCTION
// ============================================================================

HoneypotDetector::HoneypotDetector(HoneypotConfig config)
    : m_config(std::move(config)) {}


// ============================================================================
//  BASE DETECTOR INTERFACE
// ============================================================================

std::string HoneypotDetector::name() const {
    return "HoneypotDetector";
}


std::vector<Alert> HoneypotDetector::process(const RawPacket& raw,
                                             const IPPacket& ip,
                                             const TCPPacket* tcp,
                                             const HTTPPacket* http,
                                             int64_t ts_ms) {
    (void)raw;
    (void)http;

    if (m_config.ports.empty()) {
        return {};  // no honeypots configured
    }

    // Determine the destination port. TCP carries it in the TCP header;
    // UDP has the same 2-byte src/dst port layout at the transport offset.
    uint16_t dport = 0;
    Protocol proto = Protocol::UNKNOWN;

    if (tcp) {
        dport = tcp->dst_port;
        proto = Protocol::TCP;
    } else if (ip.protocol == IPPROTO_UDP_NUM) {
        if (ip.transport_offset + 4 <= raw.capture_length) {
            const uint8_t* udp_hdr = raw.data + ip.transport_offset;
            dport = static_cast<uint16_t>(
                (static_cast<uint16_t>(udp_hdr[2]) << 8) | udp_hdr[3]);
        }
        proto = Protocol::UDP;
    }

    if (dport == 0) {
        return {};
    }

    const HoneypotPort* hp = findPort(dport);
    if (!hp) {
        return {};  // not a configured honeypot
    }

    // ── It's a honeypot hit ──────────────────────────────────────────────
    m_hits++;

    // Cooldown: one alert per (src, port) per cooldown window.
    const std::string dedup_key = ip.src_ip + "|" + std::to_string(dport);
    auto              it        = m_last_alert.find(dedup_key);
    if (it != m_last_alert.end() &&
        ts_ms - it->second < static_cast<int64_t>(m_config.cooldown_ms)) {
        return {};
    }
    m_last_alert[dedup_key] = ts_ms;

    NetworkContext net;
    net.src_ip     = ip.src_ip;
    net.dst_ip     = ip.dst_ip;
    net.protocol   = proto;
    net.dst_port   = dport;
    if (tcp) {
        net.src_port = tcp->src_port;
    }

    std::string desc = "Honeypot hit: " + ip.src_ip + " connected to decoy " +
                       hp->service + " service on port " +
                       std::to_string(dport) + " at " + ip.dst_ip;

    Alert alert = makeHoneypotAlert(net, Severity::CRITICAL, std::move(desc));

    // Evidence
    alert.evidence.honeypot_port    = dport;
    alert.evidence.service_mimicked = hp->service;
    alert.evidence.extra["protocol"] = protocolToString(proto);

    return {std::move(alert)};
}


void HoneypotDetector::tick(int64_t now_ms) {
    for (auto it = m_last_alert.begin(); it != m_last_alert.end(); ) {
        if (now_ms - it->second >
            static_cast<int64_t>(m_config.cooldown_ms * 2)) {
            it = m_last_alert.erase(it);
        } else {
            ++it;
        }
    }
}


void HoneypotDetector::reset() {
    m_last_alert.clear();
    m_hits = 0;
}


// ============================================================================
//  PRIVATE HELPERS
// ============================================================================

const HoneypotPort* HoneypotDetector::findPort(uint16_t port) const {
    for (const auto& hp : m_config.ports) {
        if (hp.port == port) {
            return &hp;
        }
    }
    return nullptr;
}

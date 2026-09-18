/**
 * @file    PortScanDetector.cpp
 * @brief   Implementation of the sliding-window port scan detector.
 *
 * @author  Ash
 * @project SentinelX
 */

#include "PortScanDetector.h"
#include "../parsers/UDPParser.h"

#include <algorithm>
#include <unordered_set>


// ============================================================================
//  CONSTRUCTION
// ============================================================================

PortScanDetector::PortScanDetector(PortScanConfig config)
    : m_config(std::move(config)) {}


// ============================================================================
//  BASE DETECTOR INTERFACE
// ============================================================================

std::string PortScanDetector::name() const {
    return "PortScanDetector";
}


std::vector<Alert> PortScanDetector::process(const RawPacket& raw,
                                             const IPPacket& ip,
                                             const TCPPacket* tcp,
                                             const HTTPPacket* /*http*/,
                                             int64_t ts_ms) {
    (void)raw;

    m_probes_observed++;

    // ── Is this packet a "probe" at all? ────────────────────────────────
    //
    // TCP: only SYN-only and stealth-flag (NULL/FIN/XMAS) packets count.
    //      ACK/PSH/SYN+ACK/RST are conversation traffic, not scanning.
    // UDP: every datagram is a candidate — UDP has no handshake, so a
    //      stream of distinct-port UDP from one source is the scan itself.

    bool      probe = false;
    uint16_t  dport = 0;
    uint8_t   flags = 0;
    bool      is_udp = false;

    if (tcp) {
        dport = tcp->dst_port;
        flags = tcp->flags;
        probe = isTcpProbe(*tcp);
    } else if (ip.protocol == IPPROTO_UDP_NUM) {
        // Do not count malformed/truncated UDP headers as scans. The
        // dedicated parser also validates the UDP length against IP length.
        auto udp = UDPParser::parse(raw, ip);
        if (!udp) return {};
        dport = udp->dst_port;
        is_udp = true;
        probe  = true;
    }

    if (!probe) {
        return {};
    }

    // ── Update sliding window for this (src, dst) pair ──────────────────

    const uint64_t key = pairKey(ip.raw_src_ip, ip.raw_dst_ip);

    // Memory cap: if we're at the limit and this is a NEW pair, drop it.
    // (Existing pairs keep tracking — an in-progress scan must not be lost
    //  just because other pairs filled the map.)
    auto it = m_states.find(key);
    if (it == m_states.end()) {
        if (m_states.size() >= m_config.max_tracked_pairs) {
            return {};
        }
        PairState st;
        st.src_ip     = ip.src_ip;
        st.dst_ip     = ip.dst_ip;
        st.raw_src_ip = ip.raw_src_ip;
        st.raw_dst_ip = ip.raw_dst_ip;
        it = m_states.emplace(key, std::move(st)).first;
    }

    PairState& st = it->second;

    Probe probe_event{ts_ms, dport, flags, is_udp};
    // Replay files and queued capture workers can deliver packets slightly
    // out of order. Keep the deque timestamp-ordered so expiry and evidence
    // remain deterministic instead of letting one old packet pin state.
    auto insert_at = std::upper_bound(
        st.probes.begin(), st.probes.end(), ts_ms,
        [](int64_t ts, const Probe& p) { return ts < p.ts_ms; });
    st.probes.insert(insert_at, probe_event);
    purgeExpired(st, ts_ms);

    // ── Threshold check ─────────────────────────────────────────────────

    const uint16_t min_ports = is_udp ? m_config.min_ports_udp
                                      : m_config.min_ports_tcp;

    if (distinctPorts(st, ts_ms) < min_ports) {
        return {};
    }

    // Cooldown: one alert per pair per cooldown_ms
    if (st.has_alert &&
        ts_ms - st.last_alert_ms < static_cast<int64_t>(m_config.cooldown_ms)) {
        return {};
    }
    st.last_alert_ms = ts_ms;
    st.has_alert = true;

    const std::string scan_type = majorityScanType(st, ts_ms);
    Alert alert = buildAlert(st, scan_type, ts_ms);
    m_alerts_emitted++;

    return {std::move(alert)};
}


void PortScanDetector::tick(int64_t now_ms) {
    // Purge expired probes from every tracked pair; drop pairs left empty.
    for (auto it = m_states.begin(); it != m_states.end(); ) {
        purgeExpired(it->second, now_ms);
        if (it->second.probes.empty()) {
            it = m_states.erase(it);
        } else {
            ++it;
        }
    }
}


void PortScanDetector::reset() {
    m_states.clear();
    m_probes_observed = 0;
    m_alerts_emitted  = 0;
}


// ============================================================================
//  PRIVATE HELPERS
// ============================================================================

uint64_t PortScanDetector::pairKey(uint32_t src, uint32_t dst) {
    // Fold two 32-bit values into one 64-bit key. Both halves are used,
    // so (A→B) and (B→A) produce different keys — direction matters
    // for scanning.
    return (static_cast<uint64_t>(src) << 32) | static_cast<uint64_t>(dst);
}


void PortScanDetector::purgeExpired(PairState& st, int64_t now_ms) const {
    // TCP and UDP probes may coexist in one pair's window (mixed scan).
    // Each protocol keeps its own window length, so a probe is expired
    // when it is older than ITS protocol's window.
    for (auto it = st.probes.begin(); it != st.probes.end(); ) {
        const uint32_t window = it->is_udp ? m_config.window_ms_udp
                                          : m_config.window_ms_tcp;
        if (now_ms >= it->ts_ms &&
            now_ms - it->ts_ms > static_cast<int64_t>(window)) {
            it = st.probes.erase(it);
        } else {
            ++it;
        }
    }
}


size_t PortScanDetector::distinctPorts(const PairState& st,
                                       int64_t now_ms) const {
    std::unordered_set<uint16_t> ports;
    for (const Probe& p : st.probes) {
        if (p.ts_ms <= now_ms) ports.insert(p.dst_port);
    }
    return ports.size();
}


std::string PortScanDetector::majorityScanType(const PairState& st,
                                               int64_t now_ms) const {
    // Tally classifyScanType() across the window. UDP pairs report "UDP".
    // Ties resolve to "SYN" — the default Nmap scan and the least
    // surprising label for mixed traffic.

    std::unordered_map<std::string, int> tally;
    bool has_udp = false;

    // Evidence labels use the SHORT names (SYN/NULL/FIN/XMAS/UDP) per the
    // Readme spec; classifyScanType() speaks the long *_SCAN forms.
    auto shortName = [](const std::string& t) -> std::string {
        if (t == "SYN_SCAN")  return "SYN";
        if (t == "NULL_SCAN") return "NULL";
        if (t == "FIN_SCAN")  return "FIN";
        if (t == "XMAS_SCAN") return "XMAS";
        return t;
    };

    for (const Probe& p : st.probes) {
        if (p.ts_ms > now_ms) continue;
        if (p.is_udp) {
            has_udp = true;
            continue;
        }
        TCPPacket tmp;   // classifyScanType only needs the flags
        tmp.flags = p.tcp_flags;
        tally[shortName(TCPParser::classifyScanType(tmp))]++;
    }

    if (has_udp && tally.empty()) {
        return "UDP";
    }

    int      best_count = -1;
    std::string best_type = "SYN";
    for (const auto& [type, count] : tally) {
        // "NORMAL" never wins — if everything looks normal we wouldn't be
        // over the port threshold in the first place, but guard anyway.
        if (type == "NORMAL") continue;
        if (count > best_count) {
            best_count = count;
            best_type  = type;
        }
    }
    if (best_count < 0 && has_udp) {
        return "UDP";
    }
    return best_type;
}


Severity PortScanDetector::severityFor(const PairState& st,
                                       const std::string& scan_type) const {
    // Base: internal source MEDIUM, external source HIGH.
    Severity sev = IPParser::isPrivateIP(st.src_ip) || IPParser::isLoopback(st.src_ip)
                       ? Severity::MEDIUM
                       : Severity::HIGH;

    // Escalate for stealthy / deliberate flag combinations. These are
    // never produced by normal clients — they exist to evade firewalls.
    if (scan_type == "NULL" || scan_type == "FIN" || scan_type == "XMAS") {
        if (sev < Severity::CRITICAL) {
            sev = static_cast<Severity>(static_cast<uint8_t>(sev) + 1);
        }
    }
    return sev;
}


Alert PortScanDetector::buildAlert(const PairState& st,
                                   const std::string& scan_type,
                                   int64_t now_ms) const {
    const uint32_t window_s = (scan_type == "UDP"
        ? m_config.window_ms_udp
        : m_config.window_ms_tcp) / 1000;

    // Collect the distinct ports probed (sorted, capped) for the evidence.
    std::vector<uint16_t> ports;
    {
        std::unordered_set<uint16_t> seen;
        for (const Probe& p : st.probes) {
            if (p.ts_ms <= now_ms) seen.insert(p.dst_port);
        }
        ports.assign(seen.begin(), seen.end());
        std::sort(ports.begin(), ports.end());
        if (ports.size() > 64) {
            ports.resize(64);
        }
    }

    NetworkContext net;
    net.src_ip     = st.src_ip;
    net.dst_ip     = st.dst_ip;
    net.protocol   = (scan_type == "UDP") ? Protocol::UDP : Protocol::TCP;
    net.dst_port   = st.probes.empty() ? 0 : st.probes.back().dst_port;
    net.src_port   = 0;  // not tracked per-probe for the alert (one alert
                          // summarizes the whole scan)

    std::string desc = "Port scan detected: " + st.src_ip + " probed " +
                       std::to_string(ports.size()) + " distinct ports on " +
                       st.dst_ip + " within " + std::to_string(window_s) +
                       "s (type: " + scan_type + ")";

    Alert alert = makePortScanAlert(net, severityFor(st, scan_type),
                                    std::move(desc));

    // Evidence
    alert.evidence.ports_contacted = std::move(ports);
    alert.evidence.scan_type       = scan_type;
    alert.evidence.window_seconds  = window_s;
    const auto packet_count = static_cast<uint32_t>(std::count_if(
        st.probes.begin(), st.probes.end(),
        [now_ms](const Probe& p) { return p.ts_ms <= now_ms; }));
    alert.evidence.packet_count = packet_count;
    alert.evidence.extra["first_seen_ms"] =
        std::to_string(st.probes.front().ts_ms);
    alert.evidence.extra["last_seen_ms"]  = std::to_string(now_ms);

    return alert;
}


bool PortScanDetector::isTcpProbe(const TCPPacket& tcp) {
    // Scan probes: SYN-only, NULL, FIN, XMAS.
    // Excluded: SYN+ACK (handshake reply), ACK/PSH (data), RST (reset),
    // FIN+ACK (teardown of an established session).
    if (tcp.is_syn_only()) {
        return true;
    }
    if (tcp.is_null_scan() || tcp.is_xmas_scan() || tcp.is_fin_scan()) {
        return true;
    }
    return false;
}

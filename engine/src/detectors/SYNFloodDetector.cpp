/**
 * @file    SYNFloodDetector.cpp
 * @brief   Implementation of the per-destination SYN flood detector.
 *
 * @author  Ash
 * @project SentinelX
 */

#include "SYNFloodDetector.h"

#include <algorithm>


// ============================================================================
//  CONSTRUCTION
// ============================================================================

SYNFloodDetector::SYNFloodDetector(SYNFloodConfig config)
    : m_config(std::move(config)) {}


// ============================================================================
//  BASE DETECTOR INTERFACE
// ============================================================================

std::string SYNFloodDetector::name() const {
    return "SYNFloodDetector";
}


std::vector<Alert> SYNFloodDetector::process(const RawPacket& raw,
                                             const IPPacket& ip,
                                             const TCPPacket* tcp,
                                             const HTTPPacket* http,
                                             int64_t ts_ms) {
    (void)raw;
    (void)http;

    // Only TCP with a parsed header is relevant.
    if (!tcp) {
        return {};
    }

    const bool is_syn     = tcp->is_syn_only();          // SYN, no ACK
    const bool is_synack  = tcp->is_syn() && tcp->is_ack();  // SYN + ACK

    if (!is_syn && !is_synack) {
        return {};  // data packets, RST, FIN — not flood-relevant
    }

    // Which destination does this packet belong to?
    //   SYN     → the target is the packet's DESTINATION
    //   SYN+ACK → the target is the packet's SOURCE (it's the reply leg)
    const std::string& dst_ip = is_syn ? ip.dst_ip : ip.src_ip;

    auto it = m_states.find(dst_ip);
    if (it == m_states.end()) {
        if (m_states.size() >= m_config.max_tracked_dsts) {
            return {};  // memory cap reached — skip this destination
        }
        DstState st;
        st.dst_ip = dst_ip;
        it = m_states.emplace(dst_ip, std::move(st)).first;
    }
    DstState& st = it->second;

    if (is_syn) {
        SynEvent event{ts_ms, ip.src_ip};
        auto insert_at = std::upper_bound(
            st.syn_events.begin(), st.syn_events.end(), ts_ms,
            [](int64_t ts, const SynEvent& e) { return ts < e.ts_ms; });
        st.syn_events.insert(insert_at, event);
        st.syn_by_src[ip.src_ip]++;
        m_syns_observed++;
    } else {  // is_synack
        auto insert_at = std::upper_bound(
            st.synack_times.begin(), st.synack_times.end(), ts_ms);
        st.synack_times.insert(insert_at, ts_ms);
    }

    // Window maintenance — drop timestamps that fell out of the window.
    purge(st, ts_ms);

    // ── Threshold check ─────────────────────────────────────────────────

    const uint32_t syn_count = static_cast<uint32_t>(std::count_if(
        st.syn_events.begin(), st.syn_events.end(),
        [ts_ms](const SynEvent& e) { return e.ts_ms <= ts_ms; }));
    const uint32_t synack_count = static_cast<uint32_t>(std::count_if(
        st.synack_times.begin(), st.synack_times.end(),
        [ts_ms](int64_t t) { return t <= ts_ms; }));

    if (syn_count < m_config.syn_threshold) {
        return {};
    }

    // Condition 2: the target is NOT keeping up with the SYNs.
    //   - no SYN+ACK responses at all, OR
    //   - SYN:SYNACK ratio above the threshold
    bool flood_confirmed;
    if (synack_count == 0) {
        flood_confirmed = true;
    } else {
        flood_confirmed = (static_cast<float>(syn_count) / synack_count)
                          >= m_config.ratio_threshold;
    }

    if (!flood_confirmed) {
        return {};  // busy but healthy — the server is answering
    }

    // A new alert window has begun (previous window fully elapsed) —
    // reset the escalation flag.
    if (!st.has_alert ||
        ts_ms - st.last_alert_ms >= static_cast<int64_t>(m_config.window_ms)) {
        st.escalated = false;
    }

    // Escalation: the first alert fires at threshold crossing (severity
    // reflects the count AT CROSSING — usually HIGH). A sustained flood
    // keeps growing; once the count reaches 4× threshold we emit ONE
    // escalation alert (CRITICAL) for the window, bypassing the cadence.
    // This gives the dashboard the "flood confirmed heavy" signal without
    // alert storms.
    if (static_cast<uint64_t>(syn_count) >=
            4ULL * m_config.syn_threshold && !st.escalated) {
        st.escalated     = true;
        st.has_alert     = true;
        st.last_alert_ms = ts_ms;
        Alert alert = buildAlert(st, syn_count, synack_count, ts_ms);
        m_alerts_emitted++;
        return {std::move(alert)};
    }

    // Cadence: one alert per destination per window.
    if (st.has_alert &&
        ts_ms - st.last_alert_ms < static_cast<int64_t>(m_config.window_ms)) {
        return {};
    }
    st.has_alert = true;
    st.last_alert_ms = ts_ms;

    Alert alert = buildAlert(st, syn_count, synack_count, ts_ms);
    m_alerts_emitted++;
    return {std::move(alert)};
}


void SYNFloodDetector::tick(int64_t now_ms) {
    for (auto it = m_states.begin(); it != m_states.end(); ) {
        purge(it->second, now_ms);
        if (it->second.syn_events.empty() &&
            it->second.synack_times.empty()) {
            it = m_states.erase(it);
        } else {
            ++it;
        }
    }
}


void SYNFloodDetector::reset() {
    m_states.clear();
    m_syns_observed = 0;
    m_alerts_emitted = 0;
}


// ============================================================================
//  PRIVATE HELPERS
// ============================================================================

void SYNFloodDetector::purge(DstState& st, int64_t now_ms) {
    const int64_t window = static_cast<int64_t>(m_config.window_ms);

    for (auto it = st.syn_events.begin(); it != st.syn_events.end(); ) {
        if (now_ms >= it->ts_ms && now_ms - it->ts_ms > window) {
            auto src = st.syn_by_src.find(it->src_ip);
            if (src != st.syn_by_src.end()) {
                if (src->second <= 1) st.syn_by_src.erase(src);
                else --src->second;
            }
            it = st.syn_events.erase(it);
        } else {
            ++it;
        }
    }
    for (auto it = st.synack_times.begin(); it != st.synack_times.end(); ) {
        if (now_ms >= *it && now_ms - *it > window) {
            it = st.synack_times.erase(it);
        } else {
            ++it;
        }
    }

    // Keep attribution bounded for spoofed-source floods. The counters are
    // still exact for the retained event window; this cap only limits the
    // amount of metadata used to build an alert.
    if (st.syn_by_src.size() > 4096) {
        std::vector<std::pair<std::string, uint32_t>> entries(
            st.syn_by_src.begin(), st.syn_by_src.end());
        std::sort(entries.begin(), entries.end(),
                  [](const auto& a, const auto& b) {
                      return a.second < b.second;
                  });
        size_t drop = entries.size() / 2;
        for (size_t i = 0; i < drop; ++i) {
            st.syn_by_src.erase(entries[i].first);
        }
    }
}


Alert SYNFloodDetector::buildAlert(const DstState& st,
                                   uint32_t syn_count,
                                   uint32_t synack_count,
                                   int64_t now_ms) const {
    const uint32_t window_s = m_config.window_ms / 1000;

    // Ratio for evidence. When the target sends no SYN+ACK at all the
    // ratio is undefined — report it as the raw SYN count (effectively
    // "infinite") so the dashboard can render a strong signal.
    float ratio = (synack_count == 0)
                      ? static_cast<float>(syn_count)
                      : static_cast<float>(syn_count) / synack_count;

    // Top source attribution (spoofed floods will show one IP far below
    // the total syn_count).
    std::string top_src;
    uint32_t    top_src_count = 0;
    for (const auto& [src, count] : st.syn_by_src) {
        if (count > top_src_count) {
            top_src_count = count;
            top_src       = src;
        }
    }

    // Severity: a sustained, high-rate flood is CRITICAL.
    const bool high_rate = (syn_count >= 4 * m_config.syn_threshold);
    const Severity sev   = high_rate ? Severity::CRITICAL : Severity::HIGH;

    NetworkContext net;
    net.src_ip     = top_src;              // best-known attacker (may be spoofed)
    net.dst_ip     = st.dst_ip;
    net.protocol   = Protocol::TCP;
    net.src_port   = 0;
    net.dst_port   = 0;                    // floods usually target one port,
                                            // but we report the destination

    std::string desc = "SYN flood detected: " +
                       std::to_string(syn_count) + " SYNs to " + st.dst_ip +
                       " in " + std::to_string(window_s) + "s, " +
                       std::to_string(synack_count) +
                       " SYN-ACK responses (ratio " +
                       (synack_count == 0 ? "∞" : std::to_string(
                           static_cast<int>(ratio))) + ")";

    Alert alert = makeSYNFloodAlert(net, sev, std::move(desc));

    // Evidence
    alert.evidence.syn_count     = syn_count;
    alert.evidence.syn_ack_ratio = ratio;
    alert.evidence.window_seconds = window_s;
    alert.evidence.packet_count   = syn_count + synack_count;
    alert.evidence.extra["top_src_ip"]     = top_src;
    alert.evidence.extra["top_src_count"]  = std::to_string(top_src_count);
    alert.evidence.extra["syn_ack_count"]  = std::to_string(synack_count);
    alert.evidence.extra["window_end_ms"]  = std::to_string(now_ms);

    return alert;
}

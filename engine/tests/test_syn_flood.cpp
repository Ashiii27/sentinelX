/**
 * @file    test_syn_flood.cpp
 * @brief   Unit tests for SYNFloodDetector.
 *
 * @author  Ash
 * @project SentinelX
 */

#include "test_framework.h"
#include "packet_builder.h"

#include "../src/detectors/SYNFloodDetector.h"


namespace {

constexpr const char* DST = "10.0.0.1";

using namespace pktbuild;

/// Send n SYN-only packets from distinct sources → dst.
std::vector<Alert> fireSYNs(SYNFloodDetector& det, int n, int64_t base_ts,
                            int step_ms = 10) {
    std::vector<Alert> alerts;
    for (int i = 0; i < n; ++i) {
        // Spoofed-style: 100 distinct sources
        std::string src = "198.51." + std::to_string((i / 256) % 100) + "." +
                          std::to_string(i % 256);
        auto frame = makeTCP(src, DST, 40000 + (i % 1000), 80, 0x02);
        auto raw   = asRaw(frame, base_ts + i * step_ms);
        auto ip    = IPParser::parse(raw);
        if (!ip) return alerts;
        auto tcp = TCPParser::parse(raw, *ip);
        if (!tcp) return alerts;
        auto out = det.process(raw, *ip, &(*tcp), nullptr,
                               base_ts + i * step_ms);
        for (auto& a : out) alerts.push_back(std::move(a));
    }
    return alerts;
}

/// Send n SYN+ACK responses from dst → random sources.
void fireSYNACKs(SYNFloodDetector& det, int n, int64_t base_ts) {
    for (int i = 0; i < n; ++i) {
        auto frame = makeTCP(DST, "198.51.100." + std::to_string(i % 256),
                             80, 40000 + i, 0x12 /*SYN|ACK*/);
        auto raw   = asRaw(frame, base_ts + i * 10);
        auto ip    = IPParser::parse(raw);
        if (!ip) return;
        auto tcp = TCPParser::parse(raw, *ip);
        if (!tcp) return;
        det.process(raw, *ip, &(*tcp), nullptr, base_ts + i * 10);
    }
}

}  // namespace


// ============================================================================
//  TESTS
// ============================================================================

static void test_flood_detected_no_responses() {
    SYNFloodConfig cfg;
    cfg.window_ms     = 5000;
    cfg.syn_threshold = 100;
    cfg.ratio_threshold = 5.0f;
    SYNFloodDetector det(cfg);

    // 150 SYNs in ~1.5s, zero SYN+ACK responses.
    // The alert fires AT THRESHOLD CROSSING (100th SYN) — so the
    // evidence reflects 100 SYNs, and with zero responses the ratio
    // is reported as the raw SYN count (the "infinite" sentinel).
    auto alerts = fireSYNs(det, 150, T0);

    CHECK_EQ(alerts.size(), static_cast<size_t>(1));
    if (alerts.empty()) return;

    const Alert& a = alerts[0];
    CHECK(a.type == AlertType::SYN_FLOOD);
    CHECK_EQ(a.severity, Severity::HIGH);  // 100 < 4×100
    CHECK_EQ(a.network.dst_ip, std::string(DST));
    CHECK_EQ(a.mitre.technique_id, std::string("T1498.001"));
    CHECK_EQ(a.evidence.syn_count, static_cast<uint32_t>(100));
    CHECK_EQ(a.evidence.syn_ack_ratio, 100.0f);  // 0 responses → = syn_count
    CHECK_CONTAINS(a.evidence.extra.at("syn_ack_count"), "0");
}

static void test_sustained_flood_escalates_critical() {
    SYNFloodConfig cfg;
    cfg.syn_threshold = 100;
    SYNFloodDetector det(cfg);

    // 500 SYNs in ~5s: alert #1 (HIGH) at the 100th SYN, then ONE
    // escalation alert (CRITICAL) when the count reaches 4× threshold.
    auto alerts = fireSYNs(det, 500, T0);
    CHECK_EQ(alerts.size(), static_cast<size_t>(2));
    if (alerts.size() < 2) return;
    CHECK_EQ(alerts[0].severity, Severity::HIGH);
    CHECK_EQ(alerts[1].severity, Severity::CRITICAL);
    CHECK(alerts[1].evidence.syn_count >= 400);
}

static void test_healthy_server_no_alert() {
    SYNFloodConfig cfg;
    cfg.syn_threshold = 100;
    SYNFloodDetector det(cfg);

    // 150 SYNs answered 1:1 with SYN+ACK (ratio 1.0) — busy, not flooded.
    // The responses must arrive INTERLEAVED: the ratio is evaluated when
    // the count crosses the threshold, so a real handshake pattern is a
    // SYN,SYNACK,SYN,SYNACK,... stream.
    std::vector<Alert> alerts;
    for (int i = 0; i < 150; ++i) {
        auto sy = fireSYNs(det, 1, T0 + i * 10);
        for (auto& a : sy) alerts.push_back(std::move(a));
        fireSYNACKs(det, 1, T0 + i * 10 + 3);  // returns void
    }
    CHECK_EQ(alerts.size(), static_cast<size_t>(0));
}

static void test_high_ratio_confirms_flood() {
    SYNFloodConfig cfg;
    cfg.syn_threshold = 100;
    cfg.ratio_threshold = 5.0f;
    SYNFloodDetector det(cfg);

    // 150 SYNs + 10 responses → ratio 15 ≥ 5 → flood
    auto alerts = fireSYNs(det, 150, T0);
    fireSYNACKs(det, 10, T0 + 100);
    CHECK_EQ(alerts.size(), static_cast<size_t>(1));
    if (alerts.empty()) return;
    CHECK(alerts[0].evidence.syn_ack_ratio > 10.0f);
}

static void test_attribution_top_source() {
    SYNFloodConfig cfg;
    cfg.syn_threshold = 50;
    SYNFloodDetector det(cfg);

    // One source (198.51.100.66) sends the first 80 of 120 SYNs.
    // The alert fires at the 50th SYN (threshold) — all 50 so far are
    // from the dominant source, so it must appear as the top source.
    std::vector<Alert> alerts;
    for (int i = 0; i < 120; ++i) {
        const std::string src = (i < 80) ? "198.51.100.66"
                                         : "198.51." + std::to_string(i % 90) +
                                               "." + std::to_string(i);
        auto frame = makeTCP(src, DST, 40000 + i, 443, 0x02);
        auto raw   = asRaw(frame, T0 + i * 5);
        auto ip    = IPParser::parse(raw);
        if (!ip) return;
        auto tcp = TCPParser::parse(raw, *ip);
        if (!tcp) return;
        auto out = det.process(raw, *ip, &(*tcp), nullptr, T0 + i * 5);
        for (auto& a : out) alerts.push_back(std::move(a));
    }

    CHECK_GE(alerts.size(), static_cast<size_t>(1));
    if (alerts.empty()) return;
    CHECK_EQ(alerts[0].evidence.extra["top_src_ip"],
             std::string("198.51.100.66"));
    CHECK_EQ(alerts[0].evidence.extra["top_src_count"], std::string("50"));
    CHECK_EQ(alerts[0].evidence.syn_count, static_cast<uint32_t>(50));
}

static void test_below_threshold_no_alert() {
    SYNFloodConfig cfg;
    cfg.syn_threshold = 100;
    SYNFloodDetector det(cfg);

    CHECK_EQ(fireSYNs(det, 50, T0).size(), static_cast<size_t>(0));
}

static void test_cadence_one_per_window() {
    SYNFloodConfig cfg;
    cfg.window_ms     = 5000;
    cfg.syn_threshold = 20;
    SYNFloodDetector det(cfg);

    // 40 SYNs → 1 alert at threshold; more SYNs in the same window → no
    // additional alerts (cadence).
    auto alerts = fireSYNs(det, 40, T0);
    CHECK_EQ(alerts.size(), static_cast<size_t>(1));

    // Next window: another burst → another alert
    auto alerts2 = fireSYNs(det, 30, T0 + 6000);
    CHECK_EQ(alerts2.size(), static_cast<size_t>(1));
}

static void test_tick_purges() {
    SYNFloodConfig cfg;
    cfg.window_ms     = 5000;
    cfg.syn_threshold = 100;
    SYNFloodDetector det(cfg);

    fireSYNs(det, 150, T0);
    CHECK_EQ(det.trackedDestinations(), static_cast<size_t>(1));

    det.tick(T0 + 10000);
    CHECK_EQ(det.trackedDestinations(), static_cast<size_t>(0));
}


int main() {
    test_flood_detected_no_responses();
    test_sustained_flood_escalates_critical();
    test_healthy_server_no_alert();
    test_high_ratio_confirms_flood();
    test_attribution_top_source();
    test_below_threshold_no_alert();
    test_cadence_one_per_window();
    test_tick_purges();
    return testfw::summary("test_syn_flood");
}

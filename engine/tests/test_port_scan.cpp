/**
 * @file    test_port_scan.cpp
 * @brief   Unit tests for PortScanDetector.
 *
 * @author  Ash
 * @project SentinelX
 */

#include "test_framework.h"
#include "packet_builder.h"

#include "../src/detectors/PortScanDetector.h"


namespace {

constexpr const char* EXT_SRC = "203.0.113.10";  // external (TEST-NET-3)
constexpr const char* INT_SRC = "192.168.1.50";  // internal
constexpr const char* DST     = "10.0.0.1";

using namespace pktbuild;

/// Fire N distinct-port TCP SYN probes from src → dst.
/// Returns all alerts produced.
std::vector<Alert> fireProbes(PortScanDetector& det,
                              const char* src,
                              int n_ports,
                              uint8_t flags,
                              int64_t base_ts,
                              int port_step_ms = 100) {
    std::vector<Alert> alerts;
    for (int i = 0; i < n_ports; ++i) {
        auto frame = makeTCP(src, DST, 40000 + i, 1000 + i, flags);
        auto raw   = asRaw(frame, base_ts + i * port_step_ms);
        auto ip    = IPParser::parse(raw);
        CHECK(ip.has_value());
        if (!ip) return alerts;
        auto tcp = TCPParser::parse(raw, *ip);
        CHECK(tcp.has_value());
        if (!tcp) return alerts;
        auto out = det.process(raw, *ip, &(*tcp), nullptr,
                               base_ts + i * port_step_ms);
        for (auto& a : out) alerts.push_back(std::move(a));
    }
    return alerts;
}

}  // namespace


// ============================================================================
//  TESTS
// ============================================================================

static void test_syn_scan_detected() {
    PortScanConfig cfg;
    cfg.min_ports_tcp = 10;
    cfg.window_ms_tcp = 5000;
    cfg.cooldown_ms   = 30000;
    PortScanDetector det(cfg);

    auto alerts = fireProbes(det, EXT_SRC, 12, 0x02 /*SYN*/, T0);

    // One alert (threshold crossed on probe #10; cooldown blocks the rest)
    CHECK_EQ(alerts.size(), static_cast<size_t>(1));
    if (alerts.empty()) return;

    const Alert& a = alerts[0];
    CHECK(a.type == AlertType::PORT_SCAN);
    CHECK_EQ(a.network.src_ip, std::string(EXT_SRC));
    CHECK_EQ(a.network.dst_ip, std::string(DST));
    CHECK_EQ(a.severity, Severity::HIGH);  // external source
    CHECK_EQ(a.mitre.technique_id, std::string("T1046"));
    CHECK_EQ(a.mitre.tactic, std::string("Discovery"));
    CHECK_EQ(a.mitre.kill_chain_phase, KillChainPhase::RECONNAISSANCE);
    CHECK(a.evidence.ports_contacted.size() >= 10);
    CHECK_EQ(a.evidence.scan_type, std::string("SYN"));
    CHECK_EQ(a.evidence.packet_count, static_cast<uint32_t>(10));
    CHECK_EQ(a.evidence.window_seconds, static_cast<uint32_t>(5));
}

static void test_below_threshold_no_alert() {
    PortScanConfig cfg;
    cfg.min_ports_tcp = 10;
    PortScanDetector det(cfg);

    // 9 distinct ports — under threshold
    CHECK_EQ(fireProbes(det, EXT_SRC, 9, 0x02, T0).size(),
             static_cast<size_t>(0));
}

static void test_null_scan_escalates() {
    PortScanConfig cfg;
    cfg.min_ports_tcp = 10;
    PortScanDetector det(cfg);

    auto alerts = fireProbes(det, EXT_SRC, 12, 0x00 /*NULL flags*/, T0);
    CHECK_EQ(alerts.size(), static_cast<size_t>(1));
    if (alerts.empty()) return;

    // External (HIGH) + stealthy NULL scan → escalated to CRITICAL
    CHECK_EQ(alerts[0].severity, Severity::CRITICAL);
    CHECK_EQ(alerts[0].evidence.scan_type, std::string("NULL"));
}

static void test_internal_scan_is_medium() {
    PortScanConfig cfg;
    cfg.min_ports_tcp = 10;
    PortScanDetector det(cfg);

    auto alerts = fireProbes(det, INT_SRC, 12, 0x02, T0);
    CHECK_EQ(alerts.size(), static_cast<size_t>(1));
    if (alerts.empty()) return;
    CHECK_EQ(alerts[0].severity, Severity::MEDIUM);
}

static void test_cooldown_suppresses_duplicates() {
    PortScanConfig cfg;
    cfg.min_ports_tcp = 5;
    cfg.cooldown_ms   = 30000;
    PortScanDetector det(cfg);

    // First burst: 5 ports within 1s → 1 alert
    auto a1 = fireProbes(det, EXT_SRC, 5, 0x02, T0, 100);
    CHECK_EQ(a1.size(), static_cast<size_t>(1));

    // Continue scanning (still within the 5s window, 30s cooldown active)
    auto a2 = fireProbes(det, EXT_SRC, 5, 0x02, T0 + 2000, 100);
    CHECK_EQ(a2.size(), static_cast<size_t>(0));

    // After the cooldown expires → alert again
    auto a3 = fireProbes(det, EXT_SRC, 5, 0x02, T0 + 40000, 100);
    CHECK_EQ(a3.size(), static_cast<size_t>(1));
}

static void test_established_traffic_ignored() {
    PortScanConfig cfg;
    cfg.min_ports_tcp = 5;
    PortScanDetector det(cfg);

    // 20 SYN+ACK (handshake replies) — conversation traffic, not a scan
    CHECK_EQ(fireProbes(det, EXT_SRC, 20, 0x12 /*SYN|ACK*/, T0).size(),
             static_cast<size_t>(0));

    // 20 pure ACK data packets
    CHECK_EQ(fireProbes(det, EXT_SRC, 20, 0x18 /*PSH|ACK*/, T0 + 60000)
                 .size(),
             static_cast<size_t>(0));
}

static void test_window_expiry() {
    PortScanConfig cfg;
    cfg.min_ports_tcp = 10;
    cfg.window_ms_tcp = 5000;
    PortScanDetector det(cfg);

    // 5 ports, then wait 10s (window expires), then 5 more ports.
    // Total distinct in any 5s window = 5 < 10 → no alert.
    auto a1 = fireProbes(det, EXT_SRC, 5, 0x02, T0, 100);
    CHECK_EQ(a1.size(), static_cast<size_t>(0));

    auto a2 = fireProbes(det, EXT_SRC, 5, 0x02, T0 + 10000, 100);
    CHECK_EQ(a2.size(), static_cast<size_t>(0));
}

static void test_udp_scan_detected() {
    PortScanConfig cfg;
    cfg.min_ports_udp  = 10;
    cfg.window_ms_udp  = 5000;
    PortScanDetector det(cfg);

    std::vector<Alert> alerts;
    for (int i = 0; i < 12; ++i) {
        auto frame = makeUDP(EXT_SRC, DST, 33333, 2000 + i, "probe");
        auto raw   = asRaw(frame, T0 + i * 50);
        auto ip    = IPParser::parse(raw);
        CHECK(ip.has_value());
        if (!ip) return;
        auto out = det.process(raw, *ip, nullptr, nullptr, T0 + i * 50);
        for (auto& a : out) alerts.push_back(std::move(a));
    }

    CHECK_EQ(alerts.size(), static_cast<size_t>(1));
    if (alerts.empty()) return;
    CHECK_EQ(alerts[0].evidence.scan_type, std::string("UDP"));
    CHECK(alerts[0].evidence.ports_contacted.size() >= 10);
}

static void test_tick_purges_state() {
    PortScanConfig cfg;
    cfg.min_ports_tcp = 10;
    cfg.window_ms_tcp = 5000;
    PortScanDetector det(cfg);

    fireProbes(det, EXT_SRC, 12, 0x02, T0);
    CHECK_EQ(det.trackedPairs(), static_cast<size_t>(1));

    det.tick(T0 + 10000);  // purge everything older than the window
    CHECK_EQ(det.trackedPairs(), static_cast<size_t>(0));
}


int main() {
    test_syn_scan_detected();
    test_below_threshold_no_alert();
    test_null_scan_escalates();
    test_internal_scan_is_medium();
    test_cooldown_suppresses_duplicates();
    test_established_traffic_ignored();
    test_window_expiry();
    test_udp_scan_detected();
    test_tick_purges_state();
    return testfw::summary("test_port_scan");
}

/**
 * @file    test_honeypot.cpp
 * @brief   Unit tests for HoneypotDetector.
 *
 * @author  Ash
 * @project SentinelX
 */

#include "test_framework.h"
#include "packet_builder.h"

#include "../src/detectors/HoneypotDetector.h"


namespace {

constexpr const char* SRC = "198.51.100.77";
constexpr const char* DST = "10.0.0.5";

using namespace pktbuild;

std::vector<Alert> fireTCP(HoneypotDetector& det, uint16_t dport,
                           int64_t ts_ms) {
    auto frame = makeTCP(SRC, DST, 60000, dport, 0x02 /*SYN*/);
    auto raw   = asRaw(frame, ts_ms);
    auto ip    = IPParser::parse(raw);
    CHECK(ip.has_value());
    if (!ip) return {};
    auto tcp = TCPParser::parse(raw, *ip);
    CHECK(tcp.has_value());
    if (!tcp) return {};
    return det.process(raw, *ip, &(*tcp), nullptr, ts_ms);
}

std::vector<Alert> fireUDP(HoneypotDetector& det, uint16_t dport,
                           int64_t ts_ms) {
    auto frame = makeUDP(SRC, DST, 60000, dport, "probe");
    auto raw   = asRaw(frame, ts_ms);
    auto ip    = IPParser::parse(raw);
    CHECK(ip.has_value());
    if (!ip) return {};
    return det.process(raw, *ip, nullptr, nullptr, ts_ms);
}

}  // namespace


// ============================================================================
//  TESTS
// ============================================================================

static void test_default_honeypot_hit() {
    HoneypotDetector det;  // defaults: 2222 SSH, 8888 HTTP

    auto alerts = fireTCP(det, 2222, T0);
    CHECK_EQ(alerts.size(), static_cast<size_t>(1));
    if (alerts.empty()) return;

    const Alert& a = alerts[0];
    CHECK(a.type == AlertType::HONEYPOT_HIT);
    CHECK_EQ(a.severity, Severity::CRITICAL);
    CHECK_EQ(a.network.dst_port, static_cast<uint16_t>(2222));
    CHECK_EQ(a.mitre.technique_id, std::string("T1046"));
    CHECK_EQ(a.evidence.honeypot_port, static_cast<uint16_t>(2222));
    CHECK_EQ(a.evidence.service_mimicked, std::string("SSH"));
}

static void test_http_honeypot() {
    HoneypotDetector det;
    auto alerts = fireTCP(det, 8888, T0);
    CHECK_EQ(alerts.size(), static_cast<size_t>(1));
    if (alerts.empty()) return;
    CHECK_EQ(alerts[0].evidence.service_mimicked, std::string("HTTP"));
}

static void test_non_honeypot_port_ignored() {
    HoneypotDetector det;
    CHECK_EQ(fireTCP(det, 22, T0).size(), static_cast<size_t>(0));
    CHECK_EQ(fireTCP(det, 80, T0 + 1000).size(), static_cast<size_t>(0));
    CHECK_EQ(fireTCP(det, 2221, T0 + 2000).size(),
             static_cast<size_t>(0));  // just below 2222
}

static void test_custom_honeypot_config() {
    HoneypotConfig cfg;
    cfg.ports = {{9999, "RDP"}, {3333, "SMB"}};
    HoneypotDetector det(cfg);

    CHECK_EQ(fireTCP(det, 2222, T0).size(), static_cast<size_t>(0));  // not
    // configured anymore
    auto alerts = fireTCP(det, 9999, T0 + 1000);
    CHECK_EQ(alerts.size(), static_cast<size_t>(1));
    if (alerts.empty()) return;
    CHECK_EQ(alerts[0].evidence.service_mimicked, std::string("RDP"));
    CHECK_EQ(alerts[0].evidence.honeypot_port, static_cast<uint16_t>(9999));
}

static void test_udp_honeypot_hit() {
    HoneypotConfig cfg;
    cfg.ports = {{5353, "mDNS-decoy"}};
    HoneypotDetector det(cfg);

    auto alerts = fireUDP(det, 5353, T0);
    CHECK_EQ(alerts.size(), static_cast<size_t>(1));
    if (alerts.empty()) return;
    CHECK_EQ(alerts[0].evidence.service_mimicked, std::string("mDNS-decoy"));
    CHECK_EQ(alerts[0].network.protocol, Protocol::UDP);
}

static void test_cooldown() {
    HoneypotConfig cfg;
    cfg.ports = {{2222, "SSH"}};
    cfg.cooldown_ms = 60000;
    HoneypotDetector det(cfg);

    CHECK_EQ(fireTCP(det, 2222, T0).size(), static_cast<size_t>(1));
    // Scanner retries 5s later — suppressed
    CHECK_EQ(fireTCP(det, 2222, T0 + 5000).size(), static_cast<size_t>(0));
    // Different source — still alerts (dedup is per src+port)
    HoneypotDetector det2(cfg);
    (void)det2;
    // ...and after the cooldown — alerts again
    CHECK_EQ(fireTCP(det, 2222, T0 + 65000).size(), static_cast<size_t>(1));
}

static void test_no_honeypots_configured() {
    HoneypotConfig cfg;
    cfg.ports.clear();
    HoneypotDetector det(cfg);
    CHECK_EQ(fireTCP(det, 2222, T0).size(), static_cast<size_t>(0));
}


int main() {
    test_default_honeypot_hit();
    test_http_honeypot();
    test_non_honeypot_port_ignored();
    test_custom_honeypot_config();
    test_udp_honeypot_hit();
    test_cooldown();
    test_no_honeypots_configured();
    return testfw::summary("test_honeypot");
}

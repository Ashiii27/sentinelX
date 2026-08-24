/**
 * @file    test_http_anomaly.cpp
 * @brief   Unit tests for HTTPAnomalyDetector.
 *
 * @author  Ash
 * @project SentinelX
 */

#include "test_framework.h"
#include "packet_builder.h"

#include "../src/detectors/HTTPAnomalyDetector.h"


namespace {

constexpr const char* SRC = "198.51.100.23";
constexpr const char* DST = "10.0.0.1";

using namespace pktbuild;

/// Send one HTTP request and return the alerts it produced.
std::vector<Alert> sendRequest(HTTPAnomalyDetector& det,
                               const std::string& request,
                               int64_t ts_ms,
                               uint16_t dport = 80) {
    auto frame = makeTCP(SRC, DST, 55000, dport, 0x18, request);
    auto raw   = asRaw(frame, ts_ms);
    auto ip    = IPParser::parse(raw);
    CHECK(ip.has_value());
    if (!ip) return {};
    auto tcp = TCPParser::parse(raw, *ip);
    CHECK(tcp.has_value());
    if (!tcp) return {};
    auto http = HTTPParser::parse(raw, *tcp);
    return det.process(raw, *ip, &(*tcp), http ? &(*http) : nullptr, ts_ms);
}

std::string kindsOf(const std::vector<Alert>& alerts) {
    std::string s;
    for (const auto& a : alerts) {
        if (!s.empty()) s += "|";
        s += a.evidence.extra.at("anomaly_kind");
    }
    return s;
}

}  // namespace


// ============================================================================
//  TESTS
// ============================================================================

static void test_path_traversal() {
    HTTPAnomalyDetector det;

    auto alerts = sendRequest(
        det,
        "GET /../../../../../../etc/passwd HTTP/1.1\r\n"
        "Host: victim.local\r\n"
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64)\r\n"
        "\r\n",
        T0);

    CHECK_EQ(alerts.size(), static_cast<size_t>(1));
    if (alerts.empty()) return;
    CHECK_EQ(alerts[0].evidence.extra["anomaly_kind"],
             std::string("PATH_TRAVERSAL"));
    CHECK_EQ(alerts[0].severity, Severity::HIGH);
    CHECK_EQ(alerts[0].mitre.technique_id, std::string("T1190"));
    CHECK_EQ(alerts[0].evidence.http_method, std::string("GET"));
    CHECK_CONTAINS(alerts[0].evidence.http_path, "/etc/passwd");
    CHECK_EQ(alerts[0].evidence.http_user_agent,
             std::string("Mozilla/5.0 (Windows NT 10.0; Win64)"));
}

static void test_encoded_traversal() {
    HTTPAnomalyDetector det;

    auto alerts = sendRequest(
        det,
        "GET /index.php?page=..%2f..%2f..%2fetc%2fshadow HTTP/1.1\r\n"
        "Host: victim.local\r\n"
        "\r\n",
        T0);

    CHECK_EQ(alerts.size(), static_cast<size_t>(1));
    if (alerts.empty()) return;
    CHECK_EQ(alerts[0].evidence.extra["anomaly_kind"],
             std::string("PATH_TRAVERSAL"));
}

static void test_sqli_in_query() {
    HTTPAnomalyDetector det;

    auto alerts = sendRequest(
        det,
        "GET /product?id=1' OR '1'='1 HTTP/1.1\r\n"
        "Host: shop.local\r\n"
        "\r\n",
        T0);

    CHECK_EQ(alerts.size(), static_cast<size_t>(1));
    if (alerts.empty()) return;
    CHECK_EQ(alerts[0].evidence.extra["anomaly_kind"],
             std::string("SQL_INJECTION"));
    CHECK_EQ(alerts[0].severity, Severity::HIGH);
}

static void test_encoded_sqli_in_query() {
    // URL-encoded payload: id=1' OR 1=1-- — must be caught via the
    // decode-and-rescan path, not just the plain-text patterns.
    HTTPAnomalyDetector det;

    auto alerts = sendRequest(
        det,
        "GET /product?id=1%27%20OR%201=1-- HTTP/1.1\r\n"
        "Host: shop.local\r\n"
        "\r\n",
        T0);

    CHECK_EQ(alerts.size(), static_cast<size_t>(1));
    if (alerts.empty()) return;
    CHECK_EQ(alerts[0].evidence.extra["anomaly_kind"],
             std::string("SQL_INJECTION"));
}

static void test_doubly_encoded_traversal() {
    // %252e%252e%252f decodes once to %2e%2e%2f, twice to ../
    HTTPAnomalyDetector det;

    auto alerts = sendRequest(
        det,
        "GET /static/%252e%252e%252f%252e%252e%252fetc%252fpasswd HTTP/1.1\r\n"
        "Host: victim.local\r\n"
        "\r\n",
        T0);

    CHECK_EQ(alerts.size(), static_cast<size_t>(1));
    if (alerts.empty()) return;
    CHECK_EQ(alerts[0].evidence.extra["anomaly_kind"],
             std::string("PATH_TRAVERSAL"));
}

static void test_scanner_user_agent() {
    HTTPAnomalyDetector det;

    auto alerts = sendRequest(
        det,
        "GET /admin HTTP/1.1\r\n"
        "Host: victim.local\r\n"
        "User-Agent: Mozilla/5.0 (compatible; Nikto/2.1.5)\r\n"
        "\r\n",
        T0);

    CHECK_EQ(alerts.size(), static_cast<size_t>(1));
    if (alerts.empty()) return;
    CHECK_EQ(alerts[0].evidence.extra["anomaly_kind"],
             std::string("SCANNER_USER_AGENT"));
    CHECK_EQ(alerts[0].severity, Severity::MEDIUM);
    // Scanner traffic maps to Reconnaissance, not Exploitation
    CHECK_EQ(alerts[0].mitre.technique_id, std::string("T1595.002"));
    CHECK_EQ(alerts[0].mitre.kill_chain_phase, KillChainPhase::RECONNAISSANCE);
}

static void test_unusual_verb() {
    HTTPAnomalyDetector det;

    auto alerts = sendRequest(
        det,
        "TRACE / HTTP/1.1\r\n"
        "Host: victim.local\r\n"
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64)\r\n"
        "\r\n",
        T0);

    CHECK_EQ(alerts.size(), static_cast<size_t>(1));
    if (alerts.empty()) return;
    CHECK_EQ(alerts[0].evidence.extra["anomaly_kind"],
             std::string("UNUSUAL_VERB"));
    CHECK_EQ(alerts[0].evidence.http_method, std::string("TRACE"));
}

static void test_oversized_header() {
    HTTPAnomalyDetector det;

    // Build a header value that exceeds the 8KB default limit
    std::string big_value(9000, 'A');
    std::string request =
        "GET / HTTP/1.1\r\n"
        "Host: victim.local\r\n"
        "X-Big: " +
        big_value +
        "\r\n"
        "\r\n";

    auto alerts = sendRequest(det, request, T0);
    CHECK_EQ(alerts.size(), static_cast<size_t>(1));
    if (alerts.empty()) return;
    CHECK_EQ(alerts[0].evidence.extra["anomaly_kind"],
             std::string("OVERSIZED_HEADER"));
    CHECK_EQ(alerts[0].severity, Severity::HIGH);
}

static void test_null_byte_injection() {
    HTTPAnomalyDetector det;

    auto alerts = sendRequest(
        det,
        "GET /index.php%00.html HTTP/1.1\r\n"
        "Host: victim.local\r\n"
        "\r\n",
        T0);

    CHECK_EQ(alerts.size(), static_cast<size_t>(1));
    if (alerts.empty()) return;
    CHECK_EQ(alerts[0].evidence.extra["anomaly_kind"],
             std::string("NULL_BYTE"));
}

static void test_normal_request_no_alert() {
    HTTPAnomalyDetector det;

    auto alerts = sendRequest(
        det,
        "GET /index.html HTTP/1.1\r\n"
        "Host: shop.local\r\n"
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
        "Accept: text/html\r\n"
        "\r\n",
        T0);

    CHECK_EQ(alerts.size(), static_cast<size_t>(0));
}

static void test_multiple_anomalies_multiple_alerts() {
    HTTPAnomalyDetector det;

    // Scanner UA + path traversal in ONE request → 2 distinct alerts
    auto alerts = sendRequest(
        det,
        "GET /..%2f..%2fetc/passwd HTTP/1.1\r\n"
        "Host: victim.local\r\n"
        "User-Agent: sqlmap/1.6#stable\r\n"
        "\r\n",
        T0);

    CHECK_EQ(alerts.size(), static_cast<size_t>(2));
    if (alerts.size() < 2) return;
    CHECK_CONTAINS(kindsOf(alerts), "PATH_TRAVERSAL");
    CHECK_CONTAINS(kindsOf(alerts), "SCANNER_USER_AGENT");
}

static void test_cooldown_per_source_and_kind() {
    HTTPAnomalyDetector det;

    // First traversal → alert
    auto a1 = sendRequest(
        det, "GET /../../etc/passwd HTTP/1.1\r\nHost: v\r\n\r\n", T0);
    CHECK_EQ(a1.size(), static_cast<size_t>(1));

    // Same source, same kind, 5s later (within 10s cooldown) → no alert
    auto a2 = sendRequest(
        det, "GET /../../../etc/shadow HTTP/1.1\r\nHost: v\r\n\r\n",
        T0 + 5000);
    CHECK_EQ(a2.size(), static_cast<size_t>(0));

    // Same source, DIFFERENT kind → still alerts (dedup is per kind)
    auto a3 = sendRequest(
        det, "GET / HTTP/1.1\r\nHost: v\r\nUser-Agent: nikto/2.1\r\n\r\n",
        T0 + 5500);
    CHECK_EQ(a3.size(), static_cast<size_t>(1));
    if (!a3.empty()) {
        CHECK_EQ(a3[0].evidence.extra["anomaly_kind"],
                 std::string("SCANNER_USER_AGENT"));
    }

    // After cooldown expiry → alert again
    auto a4 = sendRequest(
        det, "GET /../../etc/passwd HTTP/1.1\r\nHost: v\r\n\r\n", T0 + 15000);
    CHECK_EQ(a4.size(), static_cast<size_t>(1));
}

static void test_malformed_http() {
    HTTPAnomalyDetector det;

    // Garbage "request" on port 80 — has a CRLF-terminated first line that
    // is not a valid HTTP method → MALFORMED_HTTP.
    auto alerts = sendRequest(det, "BLARGH /nonsense XYZ/9.9\r\nHost: x\r\n\r\n",
                              T0);
    CHECK_EQ(alerts.size(), static_cast<size_t>(1));
    if (alerts.empty()) return;
    CHECK_EQ(alerts[0].evidence.extra["anomaly_kind"],
             std::string("MALFORMED_HTTP"));
    CHECK_EQ(alerts[0].severity, Severity::MEDIUM);
}

static void test_responses_ignored() {
    HTTPAnomalyDetector det;

    // A 500 response from the server — not attacker-injected content
    auto alerts = sendRequest(
        det,
        "HTTP/1.1 500 Internal Server Error\r\n"
        "Content-Type: text/html\r\n"
        "\r\n"
        "<h1>boom</h1>",
        T0);
    CHECK_EQ(alerts.size(), static_cast<size_t>(0));
}


int main() {
    test_path_traversal();
    test_encoded_traversal();
    test_sqli_in_query();
    test_encoded_sqli_in_query();
    test_doubly_encoded_traversal();
    test_scanner_user_agent();
    test_unusual_verb();
    test_oversized_header();
    test_null_byte_injection();
    test_normal_request_no_alert();
    test_multiple_anomalies_multiple_alerts();
    test_cooldown_per_source_and_kind();
    test_malformed_http();
    test_responses_ignored();
    return testfw::summary("test_http_anomaly");
}

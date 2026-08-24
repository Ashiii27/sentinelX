/**
 * @file    test_parsers.cpp
 * @brief   Unit tests for IPParser, TCPParser, HTTPParser.
 *
 * @author  Ash
 * @project SentinelX
 */

#include "test_framework.h"
#include "packet_builder.h"

#include "../src/parsers/IPParser.h"
#include "../src/parsers/TCPParser.h"
#include "../src/parsers/HTTPParser.h"


// ============================================================================
//  IPParser
// ============================================================================

static void test_ip_parser() {
    auto frame = pktbuild::makeTCP("192.168.1.5", "10.0.0.1", 44123, 80,
                                   0x02 /*SYN*/);
    auto raw = pktbuild::asRaw(frame, pktbuild::T0);

    auto ip = IPParser::parse(raw);
    CHECK(ip.has_value());
    if (ip) {
        CHECK_EQ(ip->src_ip, std::string("192.168.1.5"));
        CHECK_EQ(ip->dst_ip, std::string("10.0.0.1"));
        CHECK_EQ(ip->protocol, static_cast<uint8_t>(6));
        CHECK_EQ(ip->ttl, static_cast<uint8_t>(64));
        CHECK_EQ(ip->ip_header_len, static_cast<uint8_t>(20));
        CHECK_EQ(ip->total_length,
                 static_cast<uint16_t>(20 + 20));  // IP hdr + TCP hdr
        CHECK_EQ(ip->transport_offset,
                 static_cast<uint32_t>(14 + 20));  // eth + ip hdr
        CHECK(!ip->is_fragmented);
        CHECK_EQ(ip->raw_src_ip,
                 static_cast<uint32_t>(0xC0A80105));  // 192.168.1.5 net order
        CHECK_EQ(ip->raw_dst_ip,
                 static_cast<uint32_t>(0x0A000001));  // 10.0.0.1 net order
    }
}

static void test_ip_parser_non_ipv4() {
    // ARP frame must be rejected
    auto frame = pktbuild::makeARP();
    auto raw = pktbuild::asRaw(frame, pktbuild::T0);
    CHECK(!IPParser::parse(raw).has_value());

    // Truncated frame (smaller than eth + ip header)
    std::vector<uint8_t> tiny(20, 0);
    tiny[12] = 0x08;
    tiny[13] = 0x00;
    auto raw2 = pktbuild::asRaw(tiny, pktbuild::T0);
    CHECK(!IPParser::parse(raw2).has_value());
}

static void test_ip_utils() {
    CHECK(IPParser::isPrivateIP("10.1.2.3"));
    CHECK(IPParser::isPrivateIP("192.168.0.1"));
    CHECK(IPParser::isPrivateIP("172.16.5.5"));
    CHECK(IPParser::isPrivateIP("172.31.255.255"));
    CHECK(!IPParser::isPrivateIP("172.32.0.1"));  // just outside /12
    CHECK(!IPParser::isPrivateIP("8.8.8.8"));
    CHECK(IPParser::isLoopback("127.0.0.1"));
    CHECK(IPParser::isLoopback("127.1.2.3"));     // all of 127.0.0.0/8
    CHECK(!IPParser::isLoopback("126.255.255.255"));
    CHECK(!IPParser::isLoopback("10.0.0.1"));
}


// ============================================================================
//  TCPParser
// ============================================================================

static void test_tcp_parser() {
    auto frame = pktbuild::makeTCP("192.168.1.5", "10.0.0.1", 44123, 8080,
                                   0x12 /*SYN|ACK*/, "GET / HTTP/1.1");
    auto raw = pktbuild::asRaw(frame, pktbuild::T0);

    auto ip = IPParser::parse(raw);
    CHECK(ip.has_value());
    if (!ip) return;

    auto tcp = TCPParser::parse(raw, *ip);
    CHECK(tcp.has_value());
    if (!tcp) return;

    CHECK_EQ(tcp->src_port, static_cast<uint16_t>(44123));
    CHECK_EQ(tcp->dst_port, static_cast<uint16_t>(8080));
    CHECK(tcp->is_syn());
    CHECK(tcp->is_ack());
    CHECK(!tcp->is_fin());
    CHECK(!tcp->is_syn_only());
    CHECK_EQ(tcp->header_length, static_cast<uint8_t>(20));
    CHECK_EQ(tcp->payload_offset,
             static_cast<uint32_t>(14 + 20 + 20));
    CHECK_EQ(tcp->payload_length,
             static_cast<uint32_t>(14));  // len("GET / HTTP/1.1")
}

static void test_tcp_scan_classification() {
    // Build single packets per flag pattern and classify.
    auto classify = [](uint8_t flags) {
        auto frame = pktbuild::makeTCP("1.2.3.4", "5.6.7.8", 1000, 80,
                                       flags);
        auto raw = pktbuild::asRaw(frame, pktbuild::T0);
        auto ip  = IPParser::parse(raw);
        CHECK(ip.has_value());
        if (!ip) return std::string("?");
        auto tcp = TCPParser::parse(raw, *ip);
        CHECK(tcp.has_value());
        if (!tcp) return std::string("?");
        return TCPParser::classifyScanType(*tcp);
    };

    CHECK_EQ(classify(0x02), std::string("SYN_SCAN"));
    CHECK_EQ(classify(0x00), std::string("NULL_SCAN"));
    CHECK_EQ(classify(0x01), std::string("FIN_SCAN"));
    CHECK_EQ(classify(0x29), std::string("XMAS_SCAN"));
    CHECK_EQ(classify(0x12), std::string("NORMAL"));  // SYN+ACK
    CHECK_EQ(classify(0x10), std::string("NORMAL"));  // ACK
    CHECK_EQ(classify(0x18), std::string("NORMAL"));  // PSH+ACK (data)

    // flagsToString sanity
    CHECK_CONTAINS(TCPParser::flagsToString(0x12), "SYN");
    CHECK_CONTAINS(TCPParser::flagsToString(0x12), "ACK");
}

static void test_tcp_non_tcp_packet() {
    // UDP packet — TCPParser must return nullopt
    auto frame = pktbuild::makeUDP("1.2.3.4", "5.6.7.8", 1000, 53, "dns");
    auto raw   = pktbuild::asRaw(frame, pktbuild::T0);
    auto ip    = IPParser::parse(raw);
    CHECK(ip.has_value());
    if (!ip) return;
    CHECK(!TCPParser::parse(raw, *ip).has_value());
}


// ============================================================================
//  HTTPParser
// ============================================================================

static void test_http_request_parse() {
    const std::string request =
        "GET /admin/login?user=ash HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "User-Agent: Mozilla/5.0 (X11; Linux)\r\n"
        "Accept: text/html\r\n"
        "\r\n";

    auto frame = pktbuild::makeTCP("192.168.1.5", "10.0.0.1", 44123, 80,
                                   0x18 /*PSH|ACK*/, request);
    auto raw = pktbuild::asRaw(frame, pktbuild::T0);

    auto ip = IPParser::parse(raw);
    CHECK(ip.has_value());
    if (!ip) return;
    auto tcp = TCPParser::parse(raw, *ip);
    CHECK(tcp.has_value());
    if (!tcp) return;

    auto http = HTTPParser::parse(raw, *tcp);
    CHECK(http.has_value());
    if (!http) return;

    CHECK(http->message_type == HTTPMessageType::REQUEST);
    CHECK_EQ(http->method, std::string("GET"));
    CHECK_EQ(http->path, std::string("/admin/login"));
    CHECK_EQ(http->query_string, std::string("user=ash"));
    CHECK_EQ(http->http_version, std::string("HTTP/1.1"));
    CHECK_EQ(http->host, std::string("example.com"));
    CHECK_CONTAINS(http->user_agent, "Mozilla");
    CHECK(http->headers.count("accept") == 1);
    CHECK_EQ(http->content_length, -1);  // no Content-Length header
}

static void test_http_response_parse() {
    const std::string response =
        "HTTP/1.1 404 Not Found\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 12\r\n"
        "\r\n"
        "<html>404</html>";

    auto frame = pktbuild::makeTCP("10.0.0.1", "192.168.1.5", 80, 44123,
                                   0x18, response);
    auto raw = pktbuild::asRaw(frame, pktbuild::T0);

    auto ip = IPParser::parse(raw);
    CHECK(ip.has_value());
    if (!ip) return;
    auto tcp = TCPParser::parse(raw, *ip);
    CHECK(tcp.has_value());
    if (!tcp) return;

    auto http = HTTPParser::parse(raw, *tcp);
    CHECK(http.has_value());
    if (!http) return;

    CHECK(http->message_type == HTTPMessageType::RESPONSE);
    CHECK_EQ(http->status_code, 404);
    CHECK_CONTAINS(http->status_message, "Not Found");
    CHECK_EQ(http->content_length, 12);
    CHECK_CONTAINS(http->content_type, "text/html");
}

static void test_http_signature_helpers() {
    // Scanner user agents
    CHECK(HTTPParser::isScannerUserAgent("Nikto/2.1.5"));
    CHECK(HTTPParser::isScannerUserAgent(
        "Mozilla/5.0 (compatible; sqlmap/1.6)"));
    CHECK(HTTPParser::isScannerUserAgent(
        "masscan/1.3 (https://github.com/robertdavidgrace)"));
    CHECK(!HTTPParser::isScannerUserAgent("Mozilla/5.0 (Windows NT 10.0)"));
    CHECK(!HTTPParser::isScannerUserAgent(""));

    // Path traversal
    CHECK(HTTPParser::hasPathTraversal("/../../../../etc/passwd"));
    CHECK(HTTPParser::hasPathTraversal("/..%2f..%2fboot.ini"));
    CHECK(HTTPParser::hasPathTraversal("%2e%2e%2f%2e%2e%2fetc%2fshadow"));
    CHECK(!HTTPParser::hasPathTraversal("/admin/login"));
    CHECK(!HTTPParser::hasPathTraversal("/index.html"));

    // SQL injection
    CHECK(HTTPParser::hasSQLInjection("id=1' OR '1'='1"));
    CHECK(HTTPParser::hasSQLInjection("id=1 UNION SELECT username,pass"));
    CHECK(HTTPParser::hasSQLInjection("id=1; DROP TABLE users"));
    CHECK(!HTTPParser::hasSQLInjection("q=hello+world"));

    // HTTP ports
    CHECK(HTTPParser::isHTTPPort(80));
    CHECK(HTTPParser::isHTTPPort(8080));
    CHECK(!HTTPParser::isHTTPPort(22));
    CHECK(!HTTPParser::isHTTPPort(443));  // HTTPS — not parseable as HTTP
}


int main() {
    test_ip_parser();
    test_ip_parser_non_ipv4();
    test_ip_utils();
    test_tcp_parser();
    test_tcp_scan_classification();
    test_tcp_non_tcp_packet();
    test_http_request_parse();
    test_http_response_parse();
    test_http_signature_helpers();
    return testfw::summary("test_parsers");
}

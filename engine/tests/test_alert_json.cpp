/**
 * @file    test_alert_json.cpp
 * @brief   Tests AlertEmitter JSON schema + Unix-socket delivery.
 *
 * @author  Ash
 * @project SentinelX
 */

#include "test_framework.h"

#include <chrono>
#include <cstring>
#include <nlohmann/json.hpp>
#include <stdexcept>

#include "../src/alerts/Alert.h"
#include "../src/alerts/AlertEmitter.h"

#ifdef __unix__
#include <sys/socket.h>
#include <sys/un.h>
#include <thread>
#include <unistd.h>
#endif


using json = nlohmann::json;


/// Parse JSON, converting a throw into a failed CHECK (cleaner CTest
/// output than an uncaught std::exception).
static bool parseJson(const std::string& s, json& out) {
    try {
        out = json::parse(s);
        return true;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "JSON parse failed: %s\ninput: %.200s\n",
                     e.what(), s.c_str());
        testfw::checks()++;
        testfw::failures()++;
        return false;
    }
}


// ============================================================================
//  SCHEMA TESTS (toJson)
// ============================================================================

static void test_port_scan_json_schema() {
    NetworkContext net;
    net.src_ip   = "192.168.1.105";
    net.dst_ip   = "10.0.0.1";
    net.src_port = 54231;
    net.dst_port = 22;
    net.protocol = Protocol::TCP;

    Alert a = makePortScanAlert(net, Severity::HIGH,
                                "Port scan detected: 12 ports in 5s");
    a.evidence.ports_contacted = {22, 80, 443, 3306};
    a.evidence.scan_type       = "SYN";
    a.evidence.window_seconds  = 5;
    a.evidence.packet_count    = 12;

    const std::string line = AlertEmitter::toJson(a);
    json j;
    if (!parseJson(line, j)) return;

    CHECK_EQ(j["alert_id"].get<std::string>().empty(), false);
    CHECK_CONTAINS(j["timestamp"].get<std::string>(), "T");
    CHECK_EQ(j["severity"].get<std::string>(), std::string("HIGH"));
    CHECK_EQ(j["type"].get<std::string>(), std::string("PORT_SCAN"));
    CHECK_EQ(j["src_ip"].get<std::string>(), std::string("192.168.1.105"));
    CHECK_EQ(j["dst_ip"].get<std::string>(), std::string("10.0.0.1"));
    CHECK_EQ(j["src_port"].get<int>(), 54231);
    CHECK_EQ(j["dst_port"].get<int>(), 22);
    CHECK_EQ(j["protocol"].get<std::string>(), std::string("TCP"));

    CHECK_EQ(j["mitre"]["technique_id"].get<std::string>(),
             std::string("T1046"));
    CHECK_EQ(j["mitre"]["tactic"].get<std::string>(),
             std::string("Discovery"));
    CHECK_EQ(j["mitre"]["kill_chain_phase"].get<std::string>(),
             std::string("Reconnaissance"));

    CHECK_EQ(j["evidence"]["ports_contacted"].size(),
             static_cast<size_t>(4));
    CHECK_EQ(j["evidence"]["scan_type"].get<std::string>(),
             std::string("SYN"));
    CHECK_EQ(j["evidence"]["window_seconds"].get<int>(), 5);
    CHECK_EQ(j["evidence"]["packet_count"].get<int>(), 12);

    // Empty evidence fields must be omitted
    CHECK(j["evidence"].contains("syn_count") == false);
    CHECK(j["evidence"].contains("http_method") == false);
    CHECK(j["evidence"].contains("honeypot_port") == false);

    // No YARA match → explicit null per schema
    CHECK(j["yara_match"].is_null());
    CHECK(j["raw_payload_hash"].is_null());

    CHECK_EQ(j["false_positive"].get<bool>(), false);
    CHECK_EQ(j["reviewed"].get<bool>(), false);
    CHECK_CONTAINS(j["description"].get<std::string>(), "Port scan");
}

static void test_yara_match_json_schema() {
    NetworkContext net;
    net.src_ip   = "8.9.10.11";
    net.dst_ip   = "10.0.0.2";
    net.protocol = Protocol::TCP;
    net.dst_port = 443;

    Alert a = makeYARAMatchAlert(net, Severity::CRITICAL,
                                 "YARA rule match: shellcode_nop_sled");
    a.evidence.yara_match = YaraMatch{
        "shellcode_nop_sled",
        "shellcode_patterns.yar",
        {"$nop10"},
        "sha256:" + std::string(64, 'a'),
    };

    json j;
    if (!parseJson(AlertEmitter::toJson(a), j)) return;

    CHECK(j["yara_match"].is_object());
    CHECK_EQ(j["yara_match"]["rule_name"].get<std::string>(),
             std::string("shellcode_nop_sled"));
    CHECK_EQ(j["yara_match"]["rule_file"].get<std::string>(),
             std::string("shellcode_patterns.yar"));
    CHECK_EQ(j["yara_match"]["matched_strings"].size(),
             static_cast<size_t>(1));
    CHECK_CONTAINS(j["yara_match"]["payload_hash"].get<std::string>(),
                   "sha256:");
    CHECK_CONTAINS(j["raw_payload_hash"].get<std::string>(), "sha256:");
    CHECK_EQ(j["type"].get<std::string>(), std::string("YARA_MATCH"));
}

static void test_json_string_escaping() {
    NetworkContext net;
    net.src_ip   = "1.1.1.1";
    net.dst_ip   = "2.2.2.2";
    net.protocol = Protocol::TCP;

    // Description with quotes, backslashes and newlines — must survive
    // the round-trip through JSON.
    Alert a = makePortScanAlert(net, Severity::MEDIUM,
                                "desc with \"quotes\", \\slash\\ and\nnewline");

    json j = json::parse(AlertEmitter::toJson(a));
    CHECK_EQ(j["description"].get<std::string>(),
             std::string("desc with \"quotes\", \\slash\\ and\nnewline"));
}


// ============================================================================
//  UNIX SOCKET DELIVERY TEST
// ============================================================================

#ifdef __unix__
static void test_socket_delivery() {
    // Server side: bind + listen on a temp socket path
    const std::string sock_path = "/tmp/sentinelx_test_alerts.sock";
    ::unlink(sock_path.c_str());

    int server = ::socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(server >= 0);
    if (server < 0) return;

    struct sockaddr_un addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, sock_path.c_str(), sizeof(addr.sun_path) - 1);

    CHECK(::bind(server, reinterpret_cast<struct sockaddr*>(&addr),
                 sizeof(addr)) == 0);
    CHECK(::listen(server, 1) == 0);

    // Accept in a background thread, read two NDJSON lines.
    // select() bounds the wait so a broken emitter can never hang the
    // suite — the count checks below will simply fail.
    std::vector<std::string> received;
    std::thread acceptor([server, sock_path, &received]() {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(server, &fds);
        struct timeval tv;
        tv.tv_sec  = 10;
        tv.tv_usec = 0;
        if (::select(server + 1, &fds, nullptr, nullptr, &tv) <= 0) {
            ::close(server);
            return;  // timeout — no connection ever arrived
        }
        int conn = ::accept(server, nullptr, nullptr);
        if (conn < 0) {
            ::close(server);
            return;
        }
        std::string buf;
        char tmp[4096];
        // Read until we have 2 newline-terminated lines
        while (received.size() < 2) {
            ssize_t n = ::recv(conn, tmp, sizeof(tmp), 0);
            if (n <= 0) break;
            buf.append(tmp, static_cast<size_t>(n));
            size_t pos;
            while ((pos = buf.find('\n')) != std::string::npos) {
                received.push_back(buf.substr(0, pos));
                buf.erase(0, pos + 1);
            }
        }
        ::close(conn);
        ::close(server);
        ::unlink(sock_path.c_str());
    });

    // Give the server a moment to be ready, then emit from the emitter.
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    AlertEmitter emitter(AlertEmitter::Mode::UNIX_SOCKET, sock_path);

    NetworkContext net;
    net.src_ip   = "3.3.3.3";
    net.dst_ip   = "4.4.4.4";
    net.protocol = Protocol::TCP;
    net.dst_port = 2222;

    Alert a1 = makeHoneypotAlert(net, Severity::CRITICAL, "hit one");
    Alert a2 = makeHoneypotAlert(net, Severity::CRITICAL, "hit two");

    CHECK(emitter.emit(a1));
    CHECK(emitter.emit(a2));
    CHECK(emitter.connected());
    CHECK_EQ(emitter.emittedCount(), static_cast<uint64_t>(2));
    CHECK_EQ(emitter.failedCount(), static_cast<uint64_t>(0));

    acceptor.join();

    CHECK_EQ(received.size(), static_cast<size_t>(2));
    if (received.size() == 2) {
        json j1, j2;
        if (!parseJson(received[0], j1) || !parseJson(received[1], j2)) return;
        CHECK_EQ(j1["type"].get<std::string>(), std::string("HONEYPOT_HIT"));
        CHECK_EQ(j1["description"].get<std::string>(), std::string("hit one"));
        CHECK_EQ(j2["description"].get<std::string>(), std::string("hit two"));
        CHECK(j1["alert_id"].get<std::string>() !=
              j2["alert_id"].get<std::string>());
    }
}

static void test_socket_reconnect_after_backend_down() {
    // Emit to a path with no listener → fails cleanly (no crash, counted)
    const std::string dead = "/tmp/sentinelx_test_dead.sock";
    ::unlink(dead.c_str());

    AlertEmitter emitter(AlertEmitter::Mode::UNIX_SOCKET, dead);

    NetworkContext net;
    net.src_ip   = "5.5.5.5";
    net.dst_ip   = "6.6.6.6";
    net.protocol = Protocol::TCP;

    Alert a = makeHoneypotAlert(net, Severity::HIGH, "x");
    CHECK(!emitter.emit(a));  // connect fails — no listener
    CHECK_EQ(emitter.failedCount(), static_cast<uint64_t>(1));
}
#endif  // __unix__


// ============================================================================
//  STDOUT EMITTER COUNTS
// ============================================================================

static void test_emitter_counts() {
    AlertEmitter emitter(AlertEmitter::Mode::STDOUT);
    CHECK(emitter.connected());

    NetworkContext net;
    net.src_ip   = "7.7.7.7";
    net.dst_ip   = "8.8.8.8";
    net.protocol = Protocol::TCP;
    Alert a = makeSYNFloodAlert(net, Severity::HIGH, "flood");
    CHECK(emitter.emit(a));
    CHECK_EQ(emitter.emittedCount(), static_cast<uint64_t>(1));
}


int main() {
    test_port_scan_json_schema();
    test_yara_match_json_schema();
    test_json_string_escaping();
#ifdef __unix__
    test_socket_delivery();
    test_socket_reconnect_after_backend_down();
#endif
    test_emitter_counts();
    return testfw::summary("test_alert_json");
}

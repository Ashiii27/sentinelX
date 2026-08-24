/**
 * @file    AlertEmitter.cpp
 * @brief   JSON serialization and delivery for SentinelX alerts.
 *
 * @author  Ash
 * @project SentinelX
 */

#include "AlertEmitter.h"

#include <cstdio>
#include <cstring>
#include <fstream>

#include <nlohmann/json.hpp>

#ifdef __unix__
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#endif


using json = nlohmann::json;


// ============================================================================
//  CONSTRUCTION / DESTRUCTION
// ============================================================================

AlertEmitter::AlertEmitter(Mode mode, std::string target)
    : m_mode(mode)
    , m_target(std::move(target)) {}


AlertEmitter::~AlertEmitter() {
    closeSocket();
}


// ============================================================================
//  JSON SERIALIZATION
// ============================================================================

std::string AlertEmitter::toJson(const Alert& alert) {
    json j;

    // ── Identity & classification ────────────────────────────────────────
    j["alert_id"]   = alert.alert_id;
    j["timestamp"]  = alert.timestamp;
    j["severity"]   = severityToString(alert.severity);
    j["type"]       = alertTypeToString(alert.type);

    // ── Network context (flattened per the README schema) ───────────────
    j["src_ip"]     = alert.network.src_ip;
    j["dst_ip"]     = alert.network.dst_ip;
    j["src_port"]   = alert.network.src_port;
    j["dst_port"]   = alert.network.dst_port;
    j["protocol"]   = protocolToString(alert.network.protocol);
    if (alert.network.protocol == Protocol::TCP) {
        j["tcp_flags"] = alert.network.tcp_flags;
    }

    // ── MITRE ATT&CK context ─────────────────────────────────────────────
    j["mitre"] = {
        {"technique_id",    alert.mitre.technique_id},
        {"technique_name",  alert.mitre.technique_name},
        {"tactic",          alert.mitre.tactic},
        {"kill_chain_phase", killChainPhaseToString(alert.mitre.kill_chain_phase)},
    };
    if (!alert.mitre.reference_url.empty()) {
        j["mitre"]["reference_url"] = alert.mitre.reference_url;
    }

    // ── Evidence: include only populated fields ─────────────────────────
    json ev;
    const Evidence& e = alert.evidence;

    if (!e.ports_contacted.empty()) {
        ev["ports_contacted"] = e.ports_contacted;
    }
    if (!e.scan_type.empty()) {
        ev["scan_type"] = e.scan_type;
    }
    if (e.syn_count > 0) {
        ev["syn_count"] = e.syn_count;
    }
    if (e.syn_ack_ratio > 0.0f) {
        ev["syn_ack_ratio"] = e.syn_ack_ratio;
    }
    if (!e.http_method.empty()) {
        ev["http_method"] = e.http_method;
    }
    if (!e.http_path.empty()) {
        ev["http_path"] = e.http_path;
    }
    if (!e.http_user_agent.empty()) {
        ev["http_user_agent"] = e.http_user_agent;
    }
    if (!e.anomaly_reason.empty()) {
        ev["anomaly_reason"] = e.anomaly_reason;
    }
    if (e.window_seconds > 0) {
        ev["window_seconds"] = e.window_seconds;
    }
    if (e.packet_count > 0) {
        ev["packet_count"] = e.packet_count;
    }
    if (e.honeypot_port > 0) {
        ev["honeypot_port"] = e.honeypot_port;
    }
    if (!e.service_mimicked.empty()) {
        ev["service_mimicked"] = e.service_mimicked;
    }
    if (!e.extra.empty()) {
        ev["extra"] = e.extra;
    }

    // yara_match lives at the top level in the schema.
    if (e.yara_match) {
        j["yara_match"] = {
            {"rule_name",       e.yara_match->rule_name},
            {"rule_file",       e.yara_match->rule_file},
            {"matched_strings", e.yara_match->matched_strings},
            {"payload_hash",    e.yara_match->payload_hash},
        };
    } else {
        j["yara_match"] = nullptr;
    }

    j["evidence"] = ev;

    // ── Raw payload hash (top-level per schema; empty when unknown) ─────
    if (alert.evidence.yara_match) {
        j["raw_payload_hash"] = alert.evidence.yara_match->payload_hash;
    } else {
        j["raw_payload_hash"] = nullptr;
    }

    // ── Summary & triage flags ───────────────────────────────────────────
    j["description"]    = alert.description;
    j["false_positive"] = alert.false_positive;
    j["reviewed"]       = alert.reviewed;

    return j.dump();
}


// ============================================================================
//  DELIVERY
// ============================================================================

bool AlertEmitter::emit(const Alert& alert) {
    const std::string line = toJson(alert) + "\n";

#ifdef __unix__
    if (m_mode == Mode::UNIX_SOCKET) {
        if (m_sock < 0 && !connectSocket()) {
            m_failed++;
            return false;
        }
        size_t off = 0;
        while (off < line.size()) {
            ssize_t n = ::send(m_sock, line.data() + off,
                               line.size() - off, MSG_NOSIGNAL);
            if (n <= 0) {
                closeSocket();
                m_failed++;
                return false;
            }
            off += static_cast<size_t>(n);
        }
        m_emitted++;
        return true;
    }
#endif

    // STDOUT mode
    std::fwrite(line.data(), 1, line.size(), stdout);
    if (std::fflush(stdout) != 0) {
        m_failed++;
        return false;
    }
    m_emitted++;
    return true;
}


bool AlertEmitter::connected() const {
#ifdef __unix__
    if (m_mode == Mode::UNIX_SOCKET) {
        return m_sock >= 0;
    }
#endif
    return m_mode == Mode::STDOUT;
}


#ifdef __unix__
bool AlertEmitter::connectSocket() {
    // NOTE: the emitter is the CLIENT — it must NOT unlink the socket
    // file: that file belongs to the backend (the server), and removing
    // it here would make every connect() fail with ENOENT. A stale file
    // left by a crashed backend simply yields ECONNREFUSED here, which
    // is exactly the "backend down" case we retry on the next emit().

    int sock = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        std::fprintf(stderr, "[emitter] socket() failed: %s\n",
                     std::strerror(errno));
        return false;
    }

    struct sockaddr_un addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (m_target.size() >= sizeof(addr.sun_path)) {
        std::fprintf(stderr, "[emitter] socket path too long: %s\n",
                     m_target.c_str());
        ::close(sock);
        return false;
    }
    std::strncpy(addr.sun_path, m_target.c_str(), sizeof(addr.sun_path) - 1);

    if (::connect(sock, reinterpret_cast<struct sockaddr*>(&addr),
                  sizeof(addr)) < 0) {
        // Backend not up yet — that's fine in startup ordering. The next
        // emit() retries. Keep the error quiet unless it's structural.
        if (errno != ECONNREFUSED) {
            std::fprintf(stderr, "[emitter] connect(%s) failed: %s\n",
                         m_target.c_str(), std::strerror(errno));
        }
        ::close(sock);
        return false;
    }

    m_sock = sock;
    return true;
}


void AlertEmitter::closeSocket() {
    if (m_sock >= 0) {
        ::close(m_sock);
        m_sock = -1;
    }
}
#endif  // __unix__

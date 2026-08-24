/**
 * @file    main.cpp
 * @brief   SentinelX engine entry point: CLI, pipeline, capture/replay loop.
 *
 * ── The Pipeline ─────────────────────────────────────────────────────────
 *
 *   RawPacket
 *      │
 *      ▼
 *   IPParser ──────────────┐
 *      │                   │ (non-IPv4 → drop)
 *      ▼                   │
 *   TCPParser (TCP only)   │
 *      │                   │
 *      ▼                   │
 *   HTTPParser (HTTP ports │
 *    with payload)         │
 *      │                   │
 *      ├───────────────────┤
 *      ▼                   ▼
 *   ┌─────────────────────────────────────────────┐
 *   │  Detectors (in fixed order):                │
 *   │   1. HoneypotDetector   — instant hits      │
 *   │   2. PortScanDetector   — sliding window    │
 *   │   3. SYNFloodDetector   — per-destination   │
 *   │   4. HTTPAnomalyDetector— signature/heur.   │
 *   └─────────────────────────────────────────────┘
 *      │  (alerts)
 *      ▼
 *   YARAScanner (every TCP/UDP payload ≤ 64 KB)
 *      │  (alerts)
 *      ▼
 *   AlertEmitter → stdout | unix socket → backend
 *
 * Order matters: honeypot runs first because it is stateless and
 * unconditional — a honeypot port should alert even if the same packet
 * is mid-scan. Window detectors follow; HTTP anomaly last (most
 * expensive: it inspects parsed headers).
 *
 * ── Input Sources ────────────────────────────────────────────────────────
 *
 *   live     → PacketCapture (libpcap) on the configured interface
 *   replay   → PcapReplayer on a saved .pcap file (offline, no root)
 *
 * Both feed the identical pipeline.
 *
 * ── Signals ──────────────────────────────────────────────────────────────
 *
 *   SIGINT / SIGTERM → graceful shutdown (stop capture, flush, print
 *                      final stats)
 *   SIGUSR1          → hot-reload YARA rules from the rules directory
 *
 * @author  Ash
 * @project SentinelX
 */

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include <nlohmann/json.hpp>

#include "capture/PacketCapture.h"
#include "capture/PcapReplayer.h"
#include "parsers/IPParser.h"
#include "parsers/TCPParser.h"
#include "parsers/HTTPParser.h"
#include "detectors/HoneypotDetector.h"
#include "detectors/PortScanDetector.h"
#include "detectors/SYNFloodDetector.h"
#include "detectors/HTTPAnomalyDetector.h"
#include "yara/YARAScanner.h"
#include "alerts/Alert.h"
#include "alerts/AlertEmitter.h"
#include "util/SHA256.h"


// ============================================================================
//  VERSION
// ============================================================================

namespace {

constexpr const char* SENTINELX_VERSION = "1.0.0";
constexpr size_t      YARA_SCAN_MAX_PAYLOAD = 64 * 1024;  // 64 KB


// ============================================================================
//  CONFIGURATION
// ============================================================================

struct EngineConfig {
    // Live capture
    std::string interface  = "eth0";
    std::string bpf_filter = "tcp or udp";
    int         snaplen    = 65535;
    bool        promisc    = true;

    // Replay
    bool        replay     = false;
    std::string replay_file;
    bool        loop       = false;

    // Output
    AlertEmitter::Mode output      = AlertEmitter::Mode::UNIX_SOCKET;
    std::string        socket_path = "/run/sentinelx/alerts.sock";

    // Rules
    std::string rules_dir = "rules";
    bool        rules_dir_given = false;

    // Detectors
    PortScanConfig    scan;
    SYNFloodConfig    flood;
    HTTPAnomalyConfig http_anom;
    HoneypotConfig    honeypot = HoneypotConfig::defaults();

    // Diagnostics
    uint32_t stats_interval_s = 30;

    bool help    = false;
    bool version = false;
    bool list_if = false;
};


// ============================================================================
//  GLOBAL SHUTDOWN STATE (signal-handler-friendly)
// ============================================================================

std::atomic<bool> g_running{true};
std::atomic<bool> g_reload_rules{false};

void onShutdown(int) {
    g_running = false;
}

void onReloadRules(int) {
    g_reload_rules = true;
}


// ============================================================================
//  PIPELINE
// ============================================================================

struct PipelineStats {
    uint64_t packets          = 0;
    uint64_t ipv4_packets     = 0;
    uint64_t tcp_packets      = 0;
    uint64_t http_requests    = 0;
    std::unordered_map<std::string, uint64_t> alerts_by_type;
    uint64_t yara_scans       = 0;
    uint64_t yara_matches     = 0;
};


class Pipeline {
public:
    Pipeline(const EngineConfig& cfg)
        : m_cfg(cfg)
        , m_emitter(cfg.output, cfg.socket_path)
        , m_honeypot(cfg.honeypot)
        , m_port_scan(cfg.scan)
        , m_syn_flood(cfg.flood)
        , m_http_anom(cfg.http_anom)
        , m_detectors{&m_honeypot, &m_port_scan, &m_syn_flood, &m_http_anom} {

        if (!cfg.rules_dir.empty()) {
            m_yara.loadRules(cfg.rules_dir);
        }
    }

    ~Pipeline() {
        logSummary("shutdown");
    }

    /// Process one raw packet through parsers + detectors + YARA.
    void handlePacket(const RawPacket& raw) {
        m_stats.packets++;

        const int64_t ts_ms =
            static_cast<int64_t>(raw.timestamp_sec) * 1000 +
            raw.timestamp_usec / 1000;

        // ── IP layer ────────────────────────────────────────────────────
        auto ip = IPParser::parse(raw);
        if (!ip) {
            return;  // ARP / IPv6 / malformed — out of scope for v1
        }
        m_stats.ipv4_packets++;

        // ── TCP layer (only for TCP protocol) ───────────────────────────
        TCPPacket  tcp_tmp;
        const TCPPacket* tcp = nullptr;
        if (ip->protocol == IPPROTO_TCP_NUM) {
            if (auto t = TCPParser::parse(raw, *ip)) {
                tcp_tmp = std::move(*t);
                tcp     = &tcp_tmp;
                m_stats.tcp_packets++;
            }
        }

        // ── HTTP layer (TCP with payload on a well-known HTTP port) ─────
        HTTPPacket  http_tmp;
        const HTTPPacket* http = nullptr;
        if (tcp && tcp->payload_length > 0 &&
            (HTTPParser::isHTTPPort(tcp->dst_port) ||
             HTTPParser::isHTTPPort(tcp->src_port))) {
            if (auto h = HTTPParser::parse(raw, *tcp)) {
                http_tmp = std::move(*h);
                http     = &http_tmp;
                if (http->message_type == HTTPMessageType::REQUEST) {
                    m_stats.http_requests++;
                }
            }
        }

        // ── Detectors ───────────────────────────────────────────────────
        for (BaseDetector* d : m_detectors) {
            std::vector<Alert> alerts =
                d->process(raw, *ip, tcp, http, ts_ms);
            for (auto& a : alerts) {
                emitAlert(std::move(a));
            }
        }

        // ── YARA signature scan (every TCP/UDP payload) ─────────────────
        if (m_yara.ruleCount() > 0) {
            const uint8_t* payload = nullptr;
            size_t         plen    = 0;

            if (tcp && tcp->payload_length > 0 &&
                tcp->payload_length <= YARA_SCAN_MAX_PAYLOAD) {
                payload = raw.data + tcp->payload_offset;
                plen    = tcp->payload_length;
            } else if (ip->protocol == IPPROTO_UDP_NUM &&
                       ip->transport_offset + 8 <= raw.capture_length) {
                const uint8_t* udp_hdr = raw.data + ip->transport_offset;
                const uint16_t udp_hdr_len =
                    (static_cast<uint16_t>(udp_hdr[6]) << 8) | udp_hdr[7];
                size_t udp_payload_off = ip->transport_offset + udp_hdr_len;
                if (udp_payload_off < raw.capture_length) {
                    payload = raw.data + udp_payload_off;
                    plen    = raw.capture_length - udp_payload_off;
                    if (plen > YARA_SCAN_MAX_PAYLOAD) {
                        plen = YARA_SCAN_MAX_PAYLOAD;
                    }
                }
            }

            if (payload && plen > 0) {
                m_stats.yara_scans++;
                for (const auto& m : m_yara.scan(payload, plen)) {
                    emitYaraAlert(*ip, tcp, m, payload, plen, ts_ms);
                    m_stats.yara_matches++;
                }
            }
        }
    }

    /// Periodic maintenance (call ~1x/second).
    void tick(int64_t now_ms) {
        for (BaseDetector* d : m_detectors) {
            d->tick(now_ms);
        }
    }

    /// Hot-reload YARA rules (SIGUSR1 / backend rules API).
    bool reloadRules() {
        return m_yara.loadRules(m_cfg.rules_dir);
    }

    // ── Diagnostics ─────────────────────────────────────────────────────

    void logStatsLine() const {
        std::fprintf(stderr,
                     "[stats] packets=%llu ipv4=%llu tcp=%llu http_req=%llu "
                     "alerts=%llu yara_scans=%llu yara_rules=%zu\n",
                     (unsigned long long)m_stats.packets,
                     (unsigned long long)m_stats.ipv4_packets,
                     (unsigned long long)m_stats.tcp_packets,
                     (unsigned long long)m_stats.http_requests,
                     (unsigned long long)totalAlerts(),
                     (unsigned long long)m_stats.yara_scans,
                     m_yara.ruleCount());
        for (const auto& [type, count] : m_stats.alerts_by_type) {
            std::fprintf(stderr, "[stats]   %s: %llu\n", type.c_str(),
                         (unsigned long long)count);
        }
    }

    void logSummary(const char* reason) const {
        auto elapsed_s = std::chrono::duration_cast<std::chrono::seconds>(
                             std::chrono::steady_clock::now() - m_started)
                             .count();
        std::fprintf(stderr,
                     "[engine] === summary (%s, ran %llds) ===\n"
                     "[engine]   packets:      %llu\n"
                     "[engine]   alerts:       %llu (emitted %llu, failed %llu)\n"
                     "[engine]   yara matches: %llu\n",
                     reason, (long long)elapsed_s,
                     (unsigned long long)m_stats.packets,
                     (unsigned long long)totalAlerts(),
                     (unsigned long long)m_emitter.emittedCount(),
                     (unsigned long long)m_emitter.failedCount(),
                     (unsigned long long)m_stats.yara_matches);
    }

    AlertEmitter& emitter() { return m_emitter; }

    size_t yaraRuleCount() const { return m_yara.ruleCount(); }

private:

    uint64_t totalAlerts() const {
        uint64_t total = 0;
        for (const auto& [t, c] : m_stats.alerts_by_type) {
            total += c;
        }
        return total;
    }

    void emitAlert(Alert a) {
        const std::string type = alertTypeToString(a.type);
        m_stats.alerts_by_type[type]++;

        // One-line triage log for HIGH/CRITICAL — the full JSON is on the
        // wire; this keeps `journalctl`/console useful at a glance.
        if (a.severity >= Severity::HIGH) {
            std::fprintf(stderr,
                         "[%s] %s: %s\n",
                         severityToString(a.severity).c_str(),
                         type.c_str(),
                         a.description.c_str());
        }
        m_emitter.emit(a);
    }

    void emitYaraAlert(const IPPacket& ip,
                       const TCPPacket* tcp,
                       const YaraScanMatch& m,
                       const uint8_t* payload,
                       size_t plen,
                       int64_t ts_ms) {
        (void)ts_ms;

        NetworkContext net;
        net.src_ip   = ip.src_ip;
        net.dst_ip   = ip.dst_ip;
        net.protocol = tcp ? Protocol::TCP
                           : (ip.protocol == IPPROTO_UDP_NUM
                                  ? Protocol::UDP : Protocol::UNKNOWN);
        if (tcp) {
            net.src_port = tcp->src_port;
            net.dst_port = tcp->dst_port;
        }

        std::string desc = "YARA rule match: " + m.rule_name +
                           " (file: " + (m.rule_file.empty() ? std::string("?")
                                                             : m.rule_file) +
                           ") on " + ip.src_ip + " → " + ip.dst_ip +
                           (tcp ? (":" + std::to_string(tcp->dst_port))
                                : std::string());
        if (!m.description.empty()) {
            desc += " — " + m.description;
        }

        Alert a = makeYARAMatchAlert(net, m.severity, std::move(desc));

        // Rule-author-provided MITRE mapping (optional in the rule meta).
        if (!m.mitre_id.empty()) {
            a.mitre.technique_id   = m.mitre_id;
            a.mitre.technique_name = m.mitre_name.empty() ? m.mitre_id
                                                          : m.mitre_name;
            a.mitre.reference_url  = "https://attack.mitre.org/techniques/" +
                                     mitreUrlPath(m.mitre_id) + "/";
        }

        a.evidence.yara_match = YaraMatch{
            m.rule_name,
            m.rule_file,
            m.matched_strings,
            "sha256:" + SHA256::hash(payload, plen),
        };

        emitAlert(std::move(a));
    }

    /// "T1046" → "T1046", "T1498.001" → "T1498/001" (ATT&CK URL layout)
    static std::string mitreUrlPath(const std::string& id) {
        auto dot = id.find('.');
        if (dot == std::string::npos) {
            return id;
        }
        return id.substr(0, dot) + "/" + id.substr(dot + 1);
    }

    const EngineConfig& m_cfg;
    AlertEmitter        m_emitter;

    // Detectors (fixed pipeline order — see file header)
    HoneypotDetector    m_honeypot;
    PortScanDetector    m_port_scan;
    SYNFloodDetector    m_syn_flood;
    HTTPAnomalyDetector m_http_anom;
    std::vector<BaseDetector*> m_detectors;

    YARAScanner         m_yara;
    PipelineStats       m_stats;
    std::chrono::steady_clock::time_point m_started =
        std::chrono::steady_clock::now();
};


// ============================================================================
//  CLI
// ============================================================================

void printHelp() {
    std::printf(
        "SentinelX %s — Network Intrusion Detection Engine\n"
        "\n"
        "USAGE\n"
        "  sentinelx [options]\n"
        "\n"
        "CAPTURE (live)\n"
        "  -i, --interface <name>    Interface to capture on (default: eth0)\n"
        "  -f, --bpf <expr>          BPF filter (default: \"tcp or udp\")\n"
        "      --snaplen <n>         Snap length in bytes (default: 65535)\n"
        "      --no-promisc          Disable promiscuous mode\n"
        "\n"
        "REPLAY (offline, no root required)\n"
        "      --replay <file.pcap>  Replay a captured pcap file instead of\n"
        "                            live capture\n"
        "      --loop                Replay the file repeatedly (demo mode)\n"
        "\n"
        "OUTPUT\n"
        "      --output <mode stdout | socket (default: socket)\n"
        "      --socket <path>       Unix socket path for the backend\n"
        "                            (default: /run/sentinelx/alerts.sock)\n"
        "\n"
        "DETECTION\n"
        "      --rules <dir>         YARA rules directory (default: ./rules)\n"
        "      --honeypot <list>     Comma list port:SERVICE, e.g.\n"
        "                            \"2222:SSH,8888:HTTP\" (default: 2222:SSH,\n"
        "                            8888:HTTP)\n"
        "      --scan-ports <n>      Distinct ports triggering scan alert\n"
        "                            (default: 10)\n"
        "      --syn-threshold <n>   SYNs/window triggering flood alert\n"
        "                            (default: 100)\n"
        "\n"
        "DIAGNOSTICS\n"
        "      --stats-interval <s>  Stats log interval in seconds (default 30)\n"
        "      --list-interfaces     List capture interfaces and exit\n"
        "  -V, --version             Print version and exit\n"
        "  -h, --help                This help\n"
        "\n"
        "SIGNALS\n"
        "  SIGINT/SIGTERM  graceful shutdown\n"
        "  SIGUSR1         hot-reload YARA rules\n",
        SENTINELX_VERSION);
}


bool parseArgs(int argc, char** argv, EngineConfig& cfg, std::string& err) {
    auto need_value = [&](int& i) -> const char* {
        if (i + 1 >= argc) {
            err = std::string(argv[i]) + " requires a value";
            return nullptr;
        }
        return argv[++i];
    };

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        const char* v;

        if (arg == "-i" || arg == "--interface") {
            if (!(v = need_value(i))) return false;
            cfg.interface = v;
        } else if (arg == "-f" || arg == "--bpf") {
            if (!(v = need_value(i))) return false;
            cfg.bpf_filter = v;
        } else if (arg == "--snaplen") {
            if (!(v = need_value(i))) return false;
            cfg.snaplen = std::atoi(v);
        } else if (arg == "--no-promisc") {
            cfg.promisc = false;
        } else if (arg == "--replay") {
            if (!(v = need_value(i))) return false;
            cfg.replay      = true;
            cfg.replay_file = v;
        } else if (arg == "--loop") {
            cfg.loop = true;
        } else if (arg == "--output") {
            if (!(v = need_value(i))) return false;
            if (std::strcmp(v, "stdout") == 0) {
                cfg.output = AlertEmitter::Mode::STDOUT;
            } else if (std::strcmp(v, "socket") == 0) {
                cfg.output = AlertEmitter::Mode::UNIX_SOCKET;
            } else {
                err = "invalid --output: " + std::string(v) +
                      " (use stdout or socket)";
                return false;
            }
        } else if (arg == "--socket") {
            if (!(v = need_value(i))) return false;
            cfg.socket_path = v;
        } else if (arg == "--rules") {
            if (!(v = need_value(i))) return false;
            cfg.rules_dir       = v;
            cfg.rules_dir_given = true;
        } else if (arg == "--honeypot") {
            if (!(v = need_value(i))) return false;
            cfg.honeypot.ports.clear();
            std::string list = v;
            size_t start = 0;
            while (start <= list.size()) {
                size_t comma = list.find(',', start);
                std::string item = list.substr(
                    start, comma == std::string::npos
                                 ? std::string::npos
                                 : comma - start);
                if (!item.empty()) {
                    auto colon = item.find(':');
                    HoneypotPort hp;
                    if (colon == std::string::npos) {
                        hp.port    = static_cast<uint16_t>(std::atoi(item.c_str()));
                        hp.service = "SERVICE";
                    } else {
                        hp.port    = static_cast<uint16_t>(
                            std::atoi(item.substr(0, colon).c_str()));
                        hp.service = item.substr(colon + 1);
                    }
                    cfg.honeypot.ports.push_back(hp);
                }
                if (comma == std::string::npos) break;
                start = comma + 1;
            }
        } else if (arg == "--scan-ports") {
            if (!(v = need_value(i))) return false;
            cfg.scan.min_ports_tcp = static_cast<uint16_t>(std::atoi(v));
        } else if (arg == "--syn-threshold") {
            if (!(v = need_value(i))) return false;
            cfg.flood.syn_threshold = static_cast<uint32_t>(std::atoi(v));
        } else if (arg == "--stats-interval") {
            if (!(v = need_value(i))) return false;
            cfg.stats_interval_s = static_cast<uint32_t>(std::atoi(v));
        } else if (arg == "--list-interfaces") {
            cfg.list_if = true;
        } else if (arg == "-V" || arg == "--version") {
            cfg.version = true;
        } else if (arg == "-h" || arg == "--help") {
            cfg.help = true;
        } else {
            err = "unknown option: " + arg;
            return false;
        }
    }
    return true;
}

}  // namespace


// ============================================================================
//  MAIN
// ============================================================================

int main(int argc, char** argv) {
    EngineConfig cfg;
    std::string  err;

    if (!parseArgs(argc, argv, cfg, err)) {
        std::fprintf(stderr, "error: %s\n\n", err.c_str());
        printHelp();
        return 2;
    }

    if (cfg.help) {
        printHelp();
        return 0;
    }
    if (cfg.version) {
        std::printf("sentinelx %s (libpcap: %s, yara: %s)\n",
                    SENTINELX_VERSION,
#ifdef SENTINELX_WITH_LIBPCAP
                    "yes"
#else
                    "no — replay mode only"
#endif
                    , YARAScanner::supported() ? "yes" : "no");
        return 0;
    }

#ifdef SENTINELX_WITH_LIBPCAP
    if (cfg.list_if) {
        std::printf("Available interfaces:\n");
        for (const auto& name : PacketCapture::listInterfaces()) {
            std::printf("  %s\n", name.c_str());
        }
        return 0;
    }
#else
    if (cfg.list_if) {
        std::fprintf(stderr,
                     "interface listing requires a libpcap build\n");
        return 1;
    }
#endif

    if (cfg.replay && cfg.replay_file.empty()) {
        std::fprintf(stderr, "error: --replay requires a file argument\n");
        return 2;
    }

    // ── Signal handling ──────────────────────────────────────────────────
    std::signal(SIGINT, onShutdown);
    std::signal(SIGTERM, onShutdown);
    std::signal(SIGUSR1, onReloadRules);
    std::signal(SIGPIPE, SIG_IGN);  // backend restarting must not kill us

    // ── Build the pipeline ───────────────────────────────────────────────
    Pipeline pipeline(cfg);

    std::fprintf(stderr,
                 "[engine] sentinelx %s starting (mode: %s)\n",
                 SENTINELX_VERSION,
                 cfg.replay ? ("replay " + cfg.replay_file).c_str()
                            : ("live " + cfg.interface).c_str());
    std::fprintf(stderr, "[engine] yara: %s (%zu rules loaded)\n",
                 YARAScanner::supported() ? "enabled" : "disabled",
                 pipeline.yaraRuleCount());
    std::fprintf(stderr, "[engine] output: %s\n",
                 cfg.output == AlertEmitter::Mode::STDOUT
                     ? "stdout (NDJSON)"
                     : (std::string("unix socket ") + cfg.socket_path).c_str());

    // =====================================================================
    //  REPLAY MODE
    // =====================================================================
    if (cfg.replay) {
        PcapReplayer player;
        std::string  perr;
        if (!player.open(cfg.replay_file, perr)) {
            std::fprintf(stderr, "[engine] replay open failed: %s\n",
                         perr.c_str());
            return 1;
        }
        std::fprintf(stderr,
                     "[engine] replaying %s (%llu packets)\n",
                     cfg.replay_file.c_str(),
                     (unsigned long long)player.packetCount());

        // Single pass: process the whole file, then stop (unless --loop).
        // The while exits naturally when next() returns false, so the
        // entire file is consumed in one pass.
        RawPacket raw;
        while (g_running && player.next(raw)) {
            pipeline.handlePacket(raw);
            const int64_t ts =
                static_cast<int64_t>(raw.timestamp_sec) * 1000 +
                raw.timestamp_usec / 1000;
            pipeline.tick(ts);

            if (g_reload_rules.exchange(false)) {
                std::fprintf(stderr, "[engine] reloading YARA rules...\n");
                pipeline.reloadRules();
            }
        }

        if (cfg.loop && g_running) {
            // Demo mode: replay forever until SIGINT/SIGTERM.
            do {
                player.rewind();
                while (g_running && player.next(raw)) {
                    pipeline.handlePacket(raw);
                    const int64_t ts =
                        static_cast<int64_t>(raw.timestamp_sec) * 1000 +
                        raw.timestamp_usec / 1000;
                    pipeline.tick(ts);
                }
                if (g_running && g_reload_rules.exchange(false)) {
                    pipeline.reloadRules();
                }
                // Brief pause between loops so the dashboard can render.
                std::this_thread::sleep_for(std::chrono::seconds(2));
            } while (g_running);
        }
    }
    // =====================================================================
    //  LIVE CAPTURE MODE
    // =====================================================================
    else {
#ifdef SENTINELX_WITH_LIBPCAP
        CaptureConfig cc;
        cc.interface   = cfg.interface;
        cc.bpf_filter  = cfg.bpf_filter;
        cc.snaplen     = cfg.snaplen;
        cc.promiscuous = cfg.promisc;

        PacketCapture capture(cc);
        std::fprintf(stderr,
                     "[engine] capturing on %s (bpf: %s, promisc: %s)\n",
                     cfg.interface.c_str(), cfg.bpf_filter.c_str(),
                     cfg.promisc ? "on" : "off");

        auto last_stats = std::chrono::steady_clock::now();
        int64_t next_tick_ms = 0;
        {
            using namespace std::chrono;
            next_tick_ms = duration_cast<milliseconds>(
                               system_clock::now().time_since_epoch())
                               .count() +
                           1000;
        }

        capture.start([&](const RawPacket& raw) {
            pipeline.handlePacket(raw);

            // Periodic window maintenance (once per second, anchored to
            // packet timestamps).
            const int64_t ts_ms =
                static_cast<int64_t>(raw.timestamp_sec) * 1000 +
                raw.timestamp_usec / 1000;
            if (ts_ms >= next_tick_ms) {
                pipeline.tick(ts_ms);
                next_tick_ms = ts_ms + 1000;
            }

            // Periodic stats — wall-clock so quiet interfaces still log.
            const auto wall = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::seconds>(
                    wall - last_stats)
                    .count() >= static_cast<long long>(cfg.stats_interval_s)) {
                pipeline.logStatsLine();
                last_stats = wall;
            }
        });

        while (g_running) {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            if (g_reload_rules.exchange(false)) {
                std::fprintf(stderr, "[engine] reloading YARA rules...\n");
                pipeline.reloadRules();
            }
        }

        capture.stop();
        std::fprintf(stderr, "[engine] capture stopped\n");

        // Final capture stats (drops etc.) — handle still open until
        // capture goes out of scope below.
        try {
            const auto cs = capture.getStats();
            std::fprintf(stderr,
                         "[engine] capture stats: received=%llu dropped=%llu "
                         "if_dropped=%llu\n",
                         (unsigned long long)cs.packets_received,
                         (unsigned long long)cs.packets_dropped,
                         (unsigned long long)cs.packets_if_dropped);
        } catch (const std::exception& e) {
            std::fprintf(stderr, "[engine] capture stats unavailable: %s\n",
                         e.what());
        }
#else
        std::fprintf(stderr,
                     "[engine] ERROR: live capture requires a build with "
                     "libpcap. Use --replay for offline analysis, or "
                     "rebuild with libpcap-dev installed.\n");
        return 1;
#endif
    }

    pipeline.logSummary(cfg.replay ? "replay" : "live");
    return 0;
}

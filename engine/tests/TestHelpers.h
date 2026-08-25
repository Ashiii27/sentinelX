/**
 * @file    TestHelpers.h
 * @brief   Portable test helpers and raw packet fixture builders for SentinelX.
 *
 * This header provides utilities for creating deterministic packet fixtures
 * without requiring libpcap, live capture, or root privileges.
 *
 * Used by:
 *  - PortScanDetector tests
 *  - IPParser / TCPParser unit tests
 *  - HTTPParser unit tests
 *  - AlertEmitter schema validation tests
 *
 * Design:
 *  - All functions are static or inline — no runtime initialization
 *  - Fixtures produce raw Ethernet + IP + TCP/UDP byte sequences
 *  - Timestamps are deterministic; no system clock calls in tests
 *  - Byte order is handled correctly (network byte order in packets)
 *
 * @author  Ash
 * @project SentinelX
 */

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <cstring>
#include <arpa/inet.h>      // htons, htonl (available in POSIX)

/**
 * @class PacketFixtureBuilder
 * @brief Builder for constructing raw Ethernet/IP/TCP/UDP packets.
 *
 * Usage example:
 * @code
 *   auto pkt = PacketFixtureBuilder()
 *       .setEtherType(ETHERTYPE_IPV4)
 *       .setSrcIP("192.168.1.50")
 *       .setDstIP("10.0.0.1")
 *       .setSrcPort(40000)
 *       .setDstPort(22)
 *       .setTCPFlags(TCP_FLAG_SYN)
 *       .build();
 *   assert(pkt.data.size() == 54);  // 14 (Ethernet) + 20 (IP) + 20 (TCP)
 * @endcode
 */
class PacketFixtureBuilder {
public:
    // ────────────────────────────────────────────────────────────────────
    // BUILDERS
    // ────────────────────────────────────────────────────────────────────

    PacketFixtureBuilder& setEtherType(uint16_t type) {
        m_ether_type = type;
        return *this;
    }

    PacketFixtureBuilder& setSrcIP(const std::string& ip) {
        m_src_ip = ip;
        return *this;
    }

    PacketFixtureBuilder& setDstIP(const std::string& ip) {
        m_dst_ip = ip;
        return *this;
    }

    PacketFixtureBuilder& setTTL(uint8_t ttl) {
        m_ttl = ttl;
        return *this;
    }

    PacketFixtureBuilder& setProtocol(uint8_t proto) {
        m_protocol = proto;
        return *this;
    }

    PacketFixtureBuilder& setSrcPort(uint16_t port) {
        m_src_port = port;
        return *this;
    }

    PacketFixtureBuilder& setDstPort(uint16_t port) {
        m_dst_port = port;
        return *this;
    }

    PacketFixtureBuilder& setTCPFlags(uint8_t flags) {
        m_tcp_flags = flags;
        return *this;
    }

    PacketFixtureBuilder& setUDPPayload(const std::string& payload) {
        m_udp_payload = payload;
        return *this;
    }

    PacketFixtureBuilder& setTCPPayload(const std::string& payload) {
        m_tcp_payload = payload;
        return *this;
    }

    // ────────────────────────────────────────────────────────────────────
    // BUILD
    // ────────────────────────────────────────────────────────────────────

    /**
     * @brief Build the raw packet bytes.
     * @return std::vector<uint8_t> containing Ethernet + IP + transport headers
     */
    std::vector<uint8_t> build() const {
        std::vector<uint8_t> packet;

        // Ethernet header (14 bytes)
        appendEthernetHeader(packet);

        // IP header (20 bytes minimum)
        appendIPHeader(packet);

        // Transport layer (TCP or UDP)
        if (m_protocol == 6) {  // TCP
            appendTCPHeader(packet);
            packet.insert(packet.end(), m_tcp_payload.begin(),
                         m_tcp_payload.end());
        } else if (m_protocol == 17) {  // UDP
            appendUDPHeader(packet);
            packet.insert(packet.end(), m_udp_payload.begin(),
                         m_udp_payload.end());
        }

        // Update IP Total Length field (after transport layer is appended)
        uint16_t ip_total_len = packet.size() - 14;  // subtract Ethernet header
        uint8_t* ip_total_len_ptr = &packet[16];      // offset 16 in packet
        *reinterpret_cast<uint16_t*>(ip_total_len_ptr) = htons(ip_total_len);

        return packet;
    }

private:
    uint16_t    m_ether_type = 0x0800;  // IPv4
    std::string m_src_ip = "192.168.1.50";
    std::string m_dst_ip = "10.0.0.1";
    uint8_t     m_ttl = 64;
    uint8_t     m_protocol = 6;  // TCP
    uint16_t    m_src_port = 40000;
    uint16_t    m_dst_port = 22;
    uint8_t     m_tcp_flags = 0x02;  // SYN
    std::string m_udp_payload;
    std::string m_tcp_payload;

    void appendEthernetHeader(std::vector<uint8_t>& pkt) const {
        // Destination MAC (6 bytes) — not significant for NIDS
        pkt.insert(pkt.end(), {0x00, 0x00, 0x00, 0x00, 0x00, 0x00});

        // Source MAC (6 bytes)
        pkt.insert(pkt.end(), {0x00, 0x00, 0x00, 0x00, 0x00, 0x01});

        // EtherType (2 bytes, network byte order)
        uint16_t type_net = htons(m_ether_type);
        pkt.push_back((type_net >> 8) & 0xFF);
        pkt.push_back(type_net & 0xFF);
    }

    void appendIPHeader(std::vector<uint8_t>& pkt) const {
        size_t ip_start = pkt.size();

        // Version (4 bits) + IHL (4 bits)
        // Version = 4 (0x4), IHL = 5 (0x5) → 0x45
        pkt.push_back(0x45);

        // DSCP (6 bits) + ECN (2 bits)
        pkt.push_back(0x00);

        // Total Length (2 bytes) — will be filled in by build()
        pkt.push_back(0x00);
        pkt.push_back(0x00);

        // Identification (2 bytes)
        pkt.push_back(0x12);
        pkt.push_back(0x34);

        // Flags (3 bits) + Fragment Offset (13 bits)
        // Flags = 0 (no flags), Offset = 0 → 0x0000
        pkt.push_back(0x00);
        pkt.push_back(0x00);

        // TTL (1 byte)
        pkt.push_back(m_ttl);

        // Protocol (1 byte)
        pkt.push_back(m_protocol);

        // Header Checksum (2 bytes) — will be calculated
        uint16_t checksum_offset = pkt.size();
        pkt.push_back(0x00);
        pkt.push_back(0x00);

        // Source IP (4 bytes)
        appendIPAddress(pkt, m_src_ip);

        // Destination IP (4 bytes)
        appendIPAddress(pkt, m_dst_ip);

        // Calculate and set checksum
        uint16_t checksum = calculateIPChecksum(&pkt[ip_start], 20);
        pkt[checksum_offset] = (checksum >> 8) & 0xFF;
        pkt[checksum_offset + 1] = checksum & 0xFF;
    }

    void appendTCPHeader(std::vector<uint8_t>& pkt) const {
        // Source Port (2 bytes)
        uint16_t sport = htons(m_src_port);
        pkt.push_back((sport >> 8) & 0xFF);
        pkt.push_back(sport & 0xFF);

        // Destination Port (2 bytes)
        uint16_t dport = htons(m_dst_port);
        pkt.push_back((dport >> 8) & 0xFF);
        pkt.push_back(dport & 0xFF);

        // Sequence Number (4 bytes)
        pkt.insert(pkt.end(), {0x00, 0x00, 0x00, 0x01});

        // Acknowledgment Number (4 bytes)
        pkt.insert(pkt.end(), {0x00, 0x00, 0x00, 0x00});

        // Data Offset (4 bits) + Reserved (4 bits)
        // Data Offset = 5 (20 bytes) → 0x50
        pkt.push_back(0x50);

        // Flags (1 byte)
        pkt.push_back(m_tcp_flags);

        // Window Size (2 bytes)
        pkt.insert(pkt.end(), {0x20, 0x00});

        // Checksum (2 bytes) — simplified: zeros for test fixtures
        pkt.insert(pkt.end(), {0x00, 0x00});

        // Urgent Pointer (2 bytes)
        pkt.insert(pkt.end(), {0x00, 0x00});
    }

    void appendUDPHeader(std::vector<uint8_t>& pkt) const {
        // Source Port (2 bytes)
        uint16_t sport = htons(m_src_port);
        pkt.push_back((sport >> 8) & 0xFF);
        pkt.push_back(sport & 0xFF);

        // Destination Port (2 bytes)
        uint16_t dport = htons(m_dst_port);
        pkt.push_back((dport >> 8) & 0xFF);
        pkt.push_back(dport & 0xFF);

        // Length (2 bytes) = UDP header (8) + payload
        uint16_t length = htons(8 + m_udp_payload.size());
        pkt.push_back((length >> 8) & 0xFF);
        pkt.push_back(length & 0xFF);

        // Checksum (2 bytes) — simplified: zeros for test fixtures
        pkt.insert(pkt.end(), {0x00, 0x00});
    }

    static void appendIPAddress(std::vector<uint8_t>& pkt,
                                const std::string& ip_str) {
        in_addr_t addr = inet_aton(ip_str.c_str(), nullptr);
        // Note: inet_aton is deprecated; use inet_pton in production
        // For test helpers, we'll use a simple parser
        uint32_t a, b, c, d;
        if (std::sscanf(ip_str.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
            pkt.push_back(static_cast<uint8_t>(a));
            pkt.push_back(static_cast<uint8_t>(b));
            pkt.push_back(static_cast<uint8_t>(c));
            pkt.push_back(static_cast<uint8_t>(d));
        }
    }

    static uint16_t calculateIPChecksum(const uint8_t* header, size_t len) {
        uint32_t sum = 0;
        for (size_t i = 0; i < len; i += 2) {
            uint16_t word = (static_cast<uint16_t>(header[i]) << 8) |
                           header[i + 1];
            sum += word;
        }
        while (sum >> 16) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        return ~static_cast<uint16_t>(sum);
    }
};

// ============================================================================
//  CONVENIENCE FACTORIES
// ============================================================================

/**
 * @brief Create a simple SYN scan probe packet.
 * @param src_ip Source IP
 * @param dst_ip Destination IP
 * @param dst_port Destination port
 * @param timestamp_usec Timestamp in microseconds (not in packet, for test context)
 * @return Raw packet bytes suitable for IPParser input
 */
inline std::vector<uint8_t> makeSYNProbe(const std::string& src_ip,
                                         const std::string& dst_ip,
                                         uint16_t dst_port,
                                         uint64_t timestamp_usec = 0) {
    (void)timestamp_usec;  // Suppress unused warning
    return PacketFixtureBuilder()
        .setSrcIP(src_ip)
        .setDstIP(dst_ip)
        .setDstPort(dst_port)
        .setTCPFlags(0x02)  // SYN
        .build();
}

/**
 * @brief Create a NULL scan probe packet.
 */
inline std::vector<uint8_t> makeNULLProbe(const std::string& src_ip,
                                          const std::string& dst_ip,
                                          uint16_t dst_port) {
    return PacketFixtureBuilder()
        .setSrcIP(src_ip)
        .setDstIP(dst_ip)
        .setDstPort(dst_port)
        .setTCPFlags(0x00)  // NULL
        .build();
}

/**
 * @brief Create a FIN scan probe packet.
 */
inline std::vector<uint8_t> makeFINProbe(const std::string& src_ip,
                                         const std::string& dst_ip,
                                         uint16_t dst_port) {
    return PacketFixtureBuilder()
        .setSrcIP(src_ip)
        .setDstIP(dst_ip)
        .setDstPort(dst_port)
        .setTCPFlags(0x01)  // FIN
        .build();
}

/**
 * @brief Create an XMAS scan probe packet.
 */
inline std::vector<uint8_t> makeXMASProbe(const std::string& src_ip,
                                          const std::string& dst_ip,
                                          uint16_t dst_port) {
    return PacketFixtureBuilder()
        .setSrcIP(src_ip)
        .setDstIP(dst_ip)
        .setDstPort(dst_port)
        .setTCPFlags(0x29)  // FIN + PSH + URG
        .build();
}

/**
 * @brief Create a normal SYN+ACK response packet.
 */
inline std::vector<uint8_t> makeSYNACK(const std::string& src_ip,
                                       const std::string& dst_ip,
                                       uint16_t src_port,
                                       uint16_t dst_port) {
    return PacketFixtureBuilder()
        .setSrcIP(src_ip)
        .setDstIP(dst_ip)
        .setSrcPort(src_port)
        .setDstPort(dst_port)
        .setTCPFlags(0x12)  // SYN + ACK
        .build();
}

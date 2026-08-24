/**
 * @file    packet_builder.h
 * @brief   Synthetic packet construction for SentinelX engine tests.
 *
 * Builds valid Ethernet/IPv4/TCP/UDP frames in memory so detectors can
 * be exercised with controlled traffic — no network access, no root,
 * fully deterministic timestamps.
 *
 * Checksums are left zero: the parsers (like real NIDS front-ends) do
 * not validate checksums, and fabricating them would only add noise.
 *
 * @author  Ash
 * @project SentinelX
 */

#pragma once

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "../src/capture/PacketCapture.h"   // RawPacket


namespace pktbuild {

// ── Fixed test addresses ─────────────────────────────────────────────────
inline constexpr uint32_t SRC_EXT = 0x0B0A0908;  // 8.9.10.11  (network byte
                                                 // order as written bytes)
inline constexpr uint32_t DST_INT = 0x01000A08;  // 8.10.0.1

// Convert a dotted string to 4 raw bytes (big-endian, network order).
inline std::vector<uint8_t> ipBytes(const std::string& ip) {
    std::vector<uint8_t> out(4, 0);
    std::sscanf(ip.c_str(), "%hhu.%hhu.%hhu.%hhu", &out[0], &out[1], &out[2],
                &out[3]);
    return out;
}


/**
 * @brief Append a standard Ethernet II header (IPv4).
 */
inline void appendEthernet(std::vector<uint8_t>& buf) {
    // dst mac 6 + src mac 6 + ethertype 0x0800
    static const uint8_t eth[14] = {
        0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01,          // dst
        0x00, 0x00, 0x00, 0x00, 0x00, 0x02,          // src
        0x08, 0x00                                    // IPv4
    };
    buf.insert(buf.end(), eth, eth + 14);
}


/**
 * @brief Append an IPv4 header (20 bytes, no options).
 * @param proto  IANA protocol number (6 TCP, 17 UDP, 1 ICMP)
 * @param total  Total length (header + payload) — filled in by caller
 */
inline void appendIPv4(std::vector<uint8_t>& buf,
                       const std::string& src_ip,
                       const std::string& dst_ip,
                       uint8_t proto,
                       uint16_t total_len,
                       uint8_t ttl = 64) {
    std::vector<uint8_t> ip(20, 0);
    ip[0] = 0x45;                    // IPv4, IHL=5
    // ip[1] = DSCP/ECN = 0
    ip[2] = static_cast<uint8_t>(total_len >> 8);
    ip[3] = static_cast<uint8_t>(total_len & 0xFF);
    ip[4] = 0x00;                     // id
    ip[5] = 0x00;
    ip[6] = 0x00;                     // flags
    ip[7] = 0x00;                     // fragment offset
    ip[8] = ttl;
    ip[9] = proto;
    // ip[10..11] checksum = 0 (parsers don't validate)
    auto s = ipBytes(src_ip);
    auto d = ipBytes(dst_ip);
    std::copy(s.begin(), s.end(), ip.begin() + 12);
    std::copy(d.begin(), d.end(), ip.begin() + 16);
    buf.insert(buf.end(), ip.begin(), ip.end());
}


/**
 * @brief Append a TCP header (20 bytes, no options).
 */
inline void appendTCP(std::vector<uint8_t>& buf, uint16_t sport,
                      uint16_t dport, uint8_t flags, uint16_t window = 8192) {
    std::vector<uint8_t> tcp(20, 0);
    tcp[0] = static_cast<uint8_t>(sport >> 8);
    tcp[1] = static_cast<uint8_t>(sport & 0xFF);
    tcp[2] = static_cast<uint8_t>(dport >> 8);
    tcp[3] = static_cast<uint8_t>(dport & 0xFF);
    // seq/ack = 0
    tcp[12] = 0x50;                   // data offset = 5 words (20 bytes)
    tcp[13] = flags;
    tcp[14] = static_cast<uint8_t>(window >> 8);
    tcp[15] = static_cast<uint8_t>(window & 0xFF);
    // checksum, urgent = 0
    buf.insert(buf.end(), tcp.begin(), tcp.end());
}


/**
 * @brief Append a UDP header (8 bytes).
 */
inline void appendUDP(std::vector<uint8_t>& buf, uint16_t sport,
                      uint16_t dport, uint16_t total_len) {
    std::vector<uint8_t> udp(8, 0);
    udp[0] = static_cast<uint8_t>(sport >> 8);
    udp[1] = static_cast<uint8_t>(sport & 0xFF);
    udp[2] = static_cast<uint8_t>(dport >> 8);
    udp[3] = static_cast<uint8_t>(dport & 0xFF);
    udp[4] = static_cast<uint8_t>(total_len >> 8);
    udp[5] = static_cast<uint8_t>(total_len & 0xFF);
    // checksum = 0 (optional for UDP over IPv4)
    buf.insert(buf.end(), udp.begin(), udp.end());
}


// ── Composite builders ───────────────────────────────────────────────────

/**
 * @brief Build a complete Ethernet/IPv4/TCP frame.
 */
inline std::vector<uint8_t> makeTCP(const std::string& src_ip,
                                    const std::string& dst_ip,
                                    uint16_t sport, uint16_t dport,
                                    uint8_t flags,
                                    const std::string& payload = "") {
    std::vector<uint8_t> buf;
    appendEthernet(buf);
    const uint16_t ip_total = 20 + 20 + static_cast<uint16_t>(payload.size());
    appendIPv4(buf, src_ip, dst_ip, 6, ip_total);
    appendTCP(buf, sport, dport, flags);
    buf.insert(buf.end(), payload.begin(), payload.end());
    return buf;
}


/**
 * @brief Build a complete Ethernet/IPv4/UDP frame.
 */
inline std::vector<uint8_t> makeUDP(const std::string& src_ip,
                                    const std::string& dst_ip,
                                    uint16_t sport, uint16_t dport,
                                    const std::string& payload = "") {
    std::vector<uint8_t> buf;
    appendEthernet(buf);
    const uint16_t udp_total = 8 + static_cast<uint16_t>(payload.size());
    const uint16_t ip_total  = 20 + udp_total;
    appendIPv4(buf, src_ip, dst_ip, 17, ip_total);
    appendUDP(buf, sport, dport, udp_total);
    buf.insert(buf.end(), payload.begin(), payload.end());
    return buf;
}


/**
 * @brief Build an ARP frame (must be REJECTED by IPParser).
 */
inline std::vector<uint8_t> makeARP() {
    std::vector<uint8_t> buf(28, 0);
    static const uint8_t eth[14] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x08, 0x06                                       // ARP ethertype
    };
    std::copy(eth, eth + 14, buf.begin());
    return buf;
}


/**
 * @brief Wrap bytes as a RawPacket with a given timestamp.
 *
 * @param ts_ms  Unix milliseconds — split into sec/usec like libpcap
 */
inline RawPacket asRaw(const std::vector<uint8_t>& data, int64_t ts_ms) {
    RawPacket raw;
    raw.data           = data.data();
    raw.capture_length = static_cast<uint32_t>(data.size());
    raw.wire_length    = raw.capture_length;
    raw.timestamp_sec  = static_cast<uint32_t>(ts_ms / 1000);
    raw.timestamp_usec = static_cast<uint32_t>((ts_ms % 1000) * 1000);
    return raw;
}


/// Convenient fixed base timestamp (2026-01-01T00:00:00Z in ms).
inline constexpr int64_t T0 = 1767225600000LL;

}  // namespace pktbuild

/**
 * @file    IPParser.cpp
 * @brief   Implementation of IPParser — Ethernet + IPv4 header parsing.
 *
 * @author  Ash
 * @project SentinelX
 */

#include "IPParser.h"

#include <sstream>
#include <cstring>
#include <arpa/inet.h>      // ntohs(), ntohl()


// ============================================================================
//  INTERNAL: RAW IP HEADER LAYOUT
//  We map this struct directly over the raw bytes using reinterpret_cast.
//  __attribute__((packed)) prevents the compiler from adding alignment
//  padding between fields — critical when mapping structs to raw wire data.
// ============================================================================

/**
 * @struct RawIPHeader
 * @brief Memory-mapped IPv4 header structure.
 *
 * Fields are in network byte order. Use ntohs()/ntohl() before using
 * multi-byte fields on little-endian systems (x86/x64).
 *
 * ver_ihl:
 *   Upper 4 bits = IP version (should be 4)
 *   Lower 4 bits = IHL (header length in 32-bit words)
 *   Extract: version = (ver_ihl >> 4), ihl = (ver_ihl & 0x0F)
 *
 * frag_off:
 *   Bits 15-13 = flags (Reserved, DF, MF)
 *   Bits 12-0  = fragment offset
 *   MF flag (More Fragments) = bit 13 of the 16-bit field
 *   Fragmented if: MF set, OR fragment offset != 0
 */
#pragma pack(push, 1)
struct RawIPHeader {
    uint8_t  ver_ihl;       // version (4 bits) + IHL (4 bits)
    uint8_t  tos;           // type of service (DSCP + ECN)
    uint16_t total_len;     // total packet length (network byte order)
    uint16_t id;            // identification (fragmentation)
    uint16_t frag_off;      // flags (3 bits) + fragment offset (13 bits)
    uint8_t  ttl;           // time to live
    uint8_t  protocol;      // next protocol (6=TCP, 17=UDP, 1=ICMP)
    uint16_t checksum;      // header checksum
    uint32_t src_ip;        // source IP (network byte order)
    uint32_t dst_ip;        // destination IP (network byte order)
    // Options follow if IHL > 5 — not mapped here
};
#pragma pack(pop)

// Sanity check: RawIPHeader must be exactly 20 bytes
static_assert(sizeof(RawIPHeader) == 20,
    "RawIPHeader size mismatch — check packing");


// ============================================================================
//  IPParser::parse
// ============================================================================

std::optional<IPPacket> IPParser::parse(const RawPacket& pkt) {

    // ── Minimum length check ─────────────────────────────────────────────
    // Need at least: Ethernet header (14) + IP header min (20) = 34 bytes
    if (pkt.capture_length < ETHERNET_HEADER_LEN + sizeof(RawIPHeader)) {
        return std::nullopt;    // packet too short to contain an IP header
    }

    const uint8_t* data = pkt.data;

    // ── EtherType check ──────────────────────────────────────────────────
    // Bytes 12-13 of the Ethernet header contain the EtherType.
    // Read as big-endian uint16_t using ntohs().
    uint16_t ethertype = ntohs(
        *reinterpret_cast<const uint16_t*>(data + 12)
    );

    if (ethertype != ETHERTYPE_IPV4) {
        // ARP, IPv6, 802.1Q VLAN tags, etc. — not our concern in v1
        return std::nullopt;
    }

    // ── Map IP header over bytes ──────────────────────────────────────────
    // The IP header starts immediately after the 14-byte Ethernet header.
    // We reinterpret_cast the raw bytes to our packed struct — valid because
    // the struct has no padding and the alignment is handled by pragma pack.
    const RawIPHeader* iph = reinterpret_cast<const RawIPHeader*>(
        data + ETHERNET_HEADER_LEN
    );

    // ── Version check ────────────────────────────────────────────────────
    uint8_t version = (iph->ver_ihl >> 4);
    if (version != 4) {
        return std::nullopt;    // not IPv4 (shouldn't reach here given EtherType check)
    }

    // ── IHL validation ───────────────────────────────────────────────────
    // IHL = lower 4 bits of ver_ihl, in 32-bit words. Min = 5 (20 bytes).
    uint8_t ihl_words  = (iph->ver_ihl & 0x0F);
    uint8_t ihl_bytes  = ihl_words * 4;

    if (ihl_words < 5) {
        // Malformed packet — IHL below minimum. Could be a fuzzing probe.
        return std::nullopt;
    }

    // Check that the captured data is long enough to contain the full IP header
    if (pkt.capture_length < ETHERNET_HEADER_LEN + ihl_bytes) {
        return std::nullopt;    // truncated — IHL claims more bytes than we have
    }

    // ── Fragmentation check ───────────────────────────────────────────────
    // frag_off field (network byte order):
    //   Bit 15: Reserved (must be 0)
    //   Bit 14: Don't Fragment (DF)
    //   Bit 13: More Fragments (MF) — set on all fragments except the last
    //   Bits 12-0: Fragment offset in 8-byte units
    //
    // A packet is a non-first fragment if:
    //   MF is set AND fragment offset != 0 → middle fragment
    //   MF is clear AND fragment offset != 0 → last fragment
    // A first fragment has offset == 0 (but MF may be set)
    uint16_t frag_field   = ntohs(iph->frag_off);
    bool     mf_set       = (frag_field & 0x2000) != 0;    // bit 13
    uint16_t frag_offset  = (frag_field & 0x1FFF);          // bits 12-0

    bool is_fragmented = (frag_offset != 0) || mf_set;
    // Note: first fragments (offset=0, MF=1) pass through — they have headers.
    // Non-first fragments (offset!=0) lack TCP headers — can't fully parse them.

    // ── Build result ──────────────────────────────────────────────────────
    IPPacket result;

    // Canonical form: the dotted-quad interpreted as a big-endian uint32
    // (e.g. 192.168.1.5 → 0xC0A80105) on ANY host endianness — this is
    // what the dashboard expects to see / round-trip.
    result.raw_src_ip      = ntohl(iph->src_ip);
    result.raw_dst_ip      = ntohl(iph->dst_ip);
    result.src_ip          = ipToString(reinterpret_cast<const uint8_t*>(&iph->src_ip));
    result.dst_ip          = ipToString(reinterpret_cast<const uint8_t*>(&iph->dst_ip));
    result.protocol        = iph->protocol;
    result.ttl             = iph->ttl;
    result.total_length    = ntohs(iph->total_len);
    result.ip_header_len   = ihl_bytes;
    result.is_fragmented   = is_fragmented;
    result.transport_offset = ETHERNET_HEADER_LEN + ihl_bytes;

    return result;
}


// ============================================================================
//  IPParser::ipToString
// ============================================================================

/**
 * Converts 4 raw bytes (network byte order) to dotted-decimal string.
 *
 * We read each byte individually — no endianness issues since we're
 * treating the 4 bytes as separate octets, not as a uint32_t.
 *
 * Example:
 *   bytes = { 0xC0, 0xA8, 0x01, 0x01 }
 *   → "192.168.1.1"
 */
std::string IPParser::ipToString(const uint8_t* ip_bytes) {
    std::ostringstream oss;
    oss << static_cast<int>(ip_bytes[0]) << "."
        << static_cast<int>(ip_bytes[1]) << "."
        << static_cast<int>(ip_bytes[2]) << "."
        << static_cast<int>(ip_bytes[3]);
    return oss.str();
}


// ============================================================================
//  IPParser::isPrivateIP
// ============================================================================

/**
 * Checks RFC 1918 private address ranges:
 *   10.0.0.0/8       → first octet == 10
 *   172.16.0.0/12    → first octet == 172, second octet 16–31
 *   192.168.0.0/16   → first two octets == 192.168
 *
 * We parse the string manually rather than using inet_aton() to avoid
 * a dependency on the specific format of the input string.
 */
bool IPParser::isPrivateIP(const std::string& ip) {
    // Use sscanf to extract octets
    int a, b, c, d;
    if (sscanf(ip.c_str(), "%d.%d.%d.%d", &a, &b, &c, &d) != 4) {
        return false;   // malformed IP string
    }

    if (a == 10) return true;                           // 10.0.0.0/8
    if (a == 172 && b >= 16 && b <= 31) return true;   // 172.16.0.0/12
    if (a == 192 && b == 168) return true;              // 192.168.0.0/16

    return false;
}


// ============================================================================
//  IPParser::isLoopback
// ============================================================================

bool IPParser::isLoopback(const std::string& ip) {
    // Loopback range: 127.0.0.0/8
    int a, b, c, d;
    if (sscanf(ip.c_str(), "%d.%d.%d.%d", &a, &b, &c, &d) != 4) {
        return false;
    }
    return a == 127;
}
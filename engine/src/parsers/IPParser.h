/**
 * @file    IPParser.h
 * @brief   Ethernet frame and IP header parser for SentinelX.
 *
 * IPParser is the first parser in the chain. It receives a RawPacket
 * (raw bytes from libpcap) and extracts the Ethernet + IP layer fields.
 *
 * ── Packet Layout ───────────────────────────────────────────────────────
 *
 * A standard captured Ethernet/IP packet looks like this in memory:
 *
 *  Offset  Size   Field
 *  ──────────────────────────────────────────────────────────────────────
 *  [ ETHERNET HEADER — 14 bytes ]
 *   0       6      Destination MAC address
 *   6       6      Source MAC address
 *   12      2      EtherType (0x0800 = IPv4, 0x0806 = ARP, 0x86DD = IPv6)
 *  ──────────────────────────────────────────────────────────────────────
 *  [ IP HEADER — 20 bytes minimum, up to 60 bytes with options ]
 *   14      1      Version (upper 4 bits) + IHL (lower 4 bits)
 *                  Version: 4 for IPv4
 *                  IHL: IP Header Length in 32-bit words (min 5 = 20 bytes)
 *   15      1      DSCP + ECN (formerly TOS — mostly ignored by NIDS)
 *   16      2      Total Length (IP header + payload, in bytes)
 *   18      2      Identification (fragmentation)
 *   20      2      Flags (3 bits) + Fragment Offset (13 bits)
 *   22      1      TTL (Time To Live)
 *   23      1      Protocol (6=TCP, 17=UDP, 1=ICMP)
 *   24      2      Header Checksum
 *   26      4      Source IP address
 *   30      4      Destination IP address
 *   34+     var    IP Options (if IHL > 5)
 *  ──────────────────────────────────────────────────────────────────────
 *  [ TRANSPORT LAYER — starts at byte 14 + (IHL * 4) ]
 *   ...    ...     TCP / UDP / ICMP header
 *  ──────────────────────────────────────────────────────────────────────
 *
 * ── EtherType ────────────────────────────────────────────────────────────
 * We only process IPv4 packets (EtherType 0x0800). ARP, IPv6, and other
 * EtherTypes are skipped — SentinelX is IPv4-focused for now.
 *
 * ── IP Header Length (IHL) ───────────────────────────────────────────────
 * The IHL field tells us where the transport layer starts. The minimum is
 * 5 (= 20 bytes). If options are present, IHL can be up to 15 (= 60 bytes).
 * Always use IHL to find the transport layer — never hardcode offset 34.
 *
 * ── Big-Endian / Network Byte Order ──────────────────────────────────────
 * Multi-byte fields in IP headers are in network byte order (big-endian).
 * x86/x64 CPUs are little-endian. We use ntohs() (network-to-host short)
 * and ntohl() (network-to-host long) to convert correctly.
 * Forgetting this is one of the most common bugs in packet parsers.
 *
 * @author  Ash
 * @project SentinelX
 */

#pragma once

#include <string>
#include <cstdint>
#include <optional>

#include "../capture/PacketCapture.h"   // RawPacket


// ============================================================================
//  ETHERNET CONSTANTS
// ============================================================================

constexpr uint16_t ETHERTYPE_IPV4 = 0x0800;   ///< EtherType for IPv4
constexpr uint16_t ETHERTYPE_ARP  = 0x0806;   ///< EtherType for ARP
constexpr uint16_t ETHERTYPE_IPV6 = 0x86DD;   ///< EtherType for IPv6
constexpr uint32_t ETHERNET_HEADER_LEN = 14;  ///< Fixed Ethernet header size


// ============================================================================
//  IP PROTOCOL NUMBERS (IANA)
// ============================================================================

constexpr uint8_t IPPROTO_ICMP_NUM = 1;    ///< ICMP
constexpr uint8_t IPPROTO_TCP_NUM  = 6;    ///< TCP
constexpr uint8_t IPPROTO_UDP_NUM  = 17;   ///< UDP


// ============================================================================
//  PARSED IP RESULT
// ============================================================================

/**
 * @struct IPPacket
 * @brief Parsed result from the IP (and Ethernet) layer.
 *
 * Produced by IPParser::parse(). Consumed by TCPParser, UDPParser,
 * and directly by detectors that only need IP-layer information.
 *
 * Fields:
 *  src_ip          → Source IP as dotted-decimal string, e.g. "192.168.1.5"
 *  dst_ip          → Destination IP as dotted-decimal string
 *  protocol        → IANA protocol number (6=TCP, 17=UDP, 1=ICMP)
 *  ttl             → Time To Live — decremented at each hop.
 *                    Low TTL (< 5) may indicate OS fingerprinting or
 *                    a distant attacker trying to hide traceroute hops.
 *  total_length    → Total IP packet length (header + payload) in bytes
 *  ip_header_len   → IP header length in bytes (= IHL field * 4)
 *                    Minimum: 20. Maximum: 60.
 *  is_fragmented   → True if the packet is a non-first IP fragment.
 *                    Fragmented packets cannot be fully parsed by TCP/HTTP
 *                    parsers without reassembly. SentinelX logs them but
 *                    does not attempt reassembly (out of scope for v1).
 *  transport_offset→ Byte offset in the original RawPacket::data where
 *                    the transport layer (TCP/UDP) header begins.
 *                    = ETHERNET_HEADER_LEN + ip_header_len
 *                    Pass this to TCPParser so it knows where to start.
 *  raw_src_ip      → Source IP as uint32_t (network byte order).
 *                    Useful for fast hash-map lookups in detectors
 *                    (avoids string hashing overhead in hot paths).
 *  raw_dst_ip      → Destination IP as uint32_t (network byte order).
 */
struct IPPacket {
    std::string src_ip;
    std::string dst_ip;
    uint8_t     protocol        = 0;
    uint8_t     ttl             = 0;
    uint16_t    total_length    = 0;
    uint8_t     ip_header_len   = 0;    // in bytes
    bool        is_fragmented   = false;
    uint32_t    transport_offset = 0;   // byte offset into RawPacket::data

    // Raw 32-bit IPs for fast comparisons in detectors
    uint32_t    raw_src_ip      = 0;    // network byte order
    uint32_t    raw_dst_ip      = 0;    // network byte order
};


// ============================================================================
//  IP PARSER
// ============================================================================

/**
 * @class IPParser
 * @brief Parses Ethernet frames and IPv4 headers from raw packet bytes.
 *
 * Stateless — all methods are static. No instance needed.
 * Call IPParser::parse(pkt) and check the returned std::optional.
 *
 * Why std::optional?
 *  Many packets arrive that we don't care about: ARP, IPv6, IGMP, etc.
 *  Rather than throwing exceptions (expensive) or returning a bool + output
 *  parameter (ugly), we return std::optional<IPPacket>. If parsing fails
 *  or the packet is not IPv4, the optional is empty — the caller checks
 *  with if (auto ip = IPParser::parse(pkt)) { ... }
 *
 * Usage:
 * @code
 *   auto ip = IPParser::parse(raw_pkt);
 *   if (!ip) return;  // not IPv4, skip
 *
 *   std::cout << ip->src_ip << " → " << ip->dst_ip << "\n";
 *
 *   if (ip->protocol == IPPROTO_TCP_NUM) {
 *       auto tcp = TCPParser::parse(raw_pkt, *ip);
 *       // ...
 *   }
 * @endcode
 */
class IPParser {
public:

    /**
     * @brief Parse an Ethernet frame and IPv4 header from a raw packet.
     *
     * Validates:
     *  - Minimum packet length (must be at least 14 + 20 = 34 bytes)
     *  - EtherType == 0x0800 (IPv4 only — ARP/IPv6 return empty)
     *  - IP version == 4
     *  - IHL >= 5 (header is at least 20 bytes)
     *  - Packet is long enough to contain the full IP header
     *
     * @param pkt   Raw packet from libpcap
     * @return      Populated IPPacket if valid IPv4, std::nullopt otherwise
     */
    static std::optional<IPPacket> parse(const RawPacket& pkt);

    /**
     * @brief Convert a raw 4-byte IP address to dotted-decimal string.
     *
     * @param ip_bytes  Pointer to 4 bytes in network byte order
     * @return          String like "192.168.1.1"
     *
     * Example:
     * @code
     *   const uint8_t* ip_field = data + 26;  // src IP field in IP header
     *   std::string src = IPParser::ipToString(ip_field);
     * @endcode
     */
    static std::string ipToString(const uint8_t* ip_bytes);

    /**
     * @brief Check if an IP address string is in a private RFC 1918 range.
     *
     * Private ranges:
     *  10.0.0.0/8       → 10.x.x.x
     *  172.16.0.0/12    → 172.16.x.x – 172.31.x.x
     *  192.168.0.0/16   → 192.168.x.x
     *
     * Useful for detectors to distinguish internal vs external traffic:
     * an external IP scanning your internal hosts is higher severity than
     * an internal IP doing the same thing.
     *
     * @param ip    Dotted-decimal IP string
     * @return      true if the IP is in a private range
     */
    static bool isPrivateIP(const std::string& ip);

    /**
     * @brief Check if an IP is a loopback address (127.0.0.0/8).
     * @param ip    Dotted-decimal IP string
     * @return      true if loopback
     */
    static bool isLoopback(const std::string& ip);
};
/**
 * @file    TCPParser.h
 * @brief   TCP header parser for SentinelX.
 *
 * TCPParser receives a RawPacket and the already-parsed IPPacket (to know
 * where the TCP header starts), then extracts TCP layer fields.
 *
 * ── TCP Header Layout ───────────────────────────────────────────────────
 *
 *  Offset  Size   Field
 *  ──────────────────────────────────────────────────────────────────────
 *  0       2      Source Port
 *  2       2      Destination Port
 *  4       4      Sequence Number
 *  8       4      Acknowledgment Number
 *  12      1      Data Offset (upper 4 bits) + Reserved (lower 4 bits)
 *                 Data Offset: TCP header length in 32-bit words (min 5 = 20)
 *  13      1      Flags byte:
 *                   Bit 7: CWR (Congestion Window Reduced)
 *                   Bit 6: ECE (ECN-Echo)
 *                   Bit 5: URG (Urgent Pointer valid)
 *                   Bit 4: ACK (Acknowledgment valid)
 *                   Bit 3: PSH (Push — deliver data immediately)
 *                   Bit 2: RST (Reset connection)
 *                   Bit 1: SYN (Synchronize sequence numbers)
 *                   Bit 0: FIN (No more data from sender)
 *  14      2      Window Size
 *  16      2      Checksum
 *  18      2      Urgent Pointer (only valid if URG flag set)
 *  20+     var    TCP Options (if Data Offset > 5)
 *  ──────────────────────────────────────────────────────────────────────
 *  Payload starts at: transport_offset + (data_offset * 4)
 *
 * ── TCP Flags in Security Context ───────────────────────────────────────
 * TCP flags are what make scan detection possible:
 *
 *  SYN only (0x02)        → TCP SYN scan — most common Nmap default
 *  FIN only (0x01)        → FIN scan — bypasses some stateless firewalls
 *  No flags (0x00)        → NULL scan — RFC-violating, some IDSes miss it
 *  FIN+PSH+URG (0x29)     → XMAS scan — named for the "lit up" flag bits
 *  SYN+ACK (0x12)         → Normal handshake response (not a scan)
 *  RST (0x04)             → Reset — closed port response or connection abort
 *
 * ── Data Offset ─────────────────────────────────────────────────────────
 * Like IP's IHL, the TCP Data Offset tells us where the payload starts.
 * Min = 5 (20 bytes). Max = 15 (60 bytes, with options).
 * ALWAYS use data_offset to find the payload — never hardcode offset 20.
 *
 * @author  Ash
 * @project SentinelX
 */

#pragma once

#include <cstdint>
#include <optional>

#include "../capture/PacketCapture.h"   // RawPacket
#include "IPParser.h"                   // IPPacket, transport_offset


// ============================================================================
//  TCP FLAG BIT MASKS
//  Use these to test individual flags: (flags & TCP_FLAG_SYN) != 0
// ============================================================================

constexpr uint8_t TCP_FLAG_FIN = 0x01;   ///< FIN — no more data
constexpr uint8_t TCP_FLAG_SYN = 0x02;   ///< SYN — initiate connection
constexpr uint8_t TCP_FLAG_RST = 0x04;   ///< RST — reset connection
constexpr uint8_t TCP_FLAG_PSH = 0x08;   ///< PSH — push data immediately
constexpr uint8_t TCP_FLAG_ACK = 0x10;   ///< ACK — acknowledgment valid
constexpr uint8_t TCP_FLAG_URG = 0x20;   ///< URG — urgent pointer valid
constexpr uint8_t TCP_FLAG_ECE = 0x40;   ///< ECE — ECN echo
constexpr uint8_t TCP_FLAG_CWR = 0x80;   ///< CWR — congestion window reduced

/// Scan type flag combinations
constexpr uint8_t TCP_FLAGS_XMAS = TCP_FLAG_FIN | TCP_FLAG_PSH | TCP_FLAG_URG;  ///< 0x29
constexpr uint8_t TCP_FLAGS_NULL = 0x00;   ///< No flags set


// ============================================================================
//  PARSED TCP RESULT
// ============================================================================

/**
 * @struct TCPPacket
 * @brief Parsed result from the TCP header layer.
 *
 * Produced by TCPParser::parse(). Consumed by:
 *  - PortScanDetector (src_port, dst_port, flags)
 *  - SYNFloodDetector (flags, specifically SYN vs SYN+ACK)
 *  - HTTPParser (payload_offset, payload_length)
 *
 * Fields:
 *  src_port        → Source port number (0–65535)
 *  dst_port        → Destination port number
 *  seq_num         → Sequence number (used for session tracking)
 *  ack_num         → Acknowledgment number
 *  flags           → Raw flags byte — test with TCP_FLAG_* constants
 *  window_size     → TCP receive window size in bytes
 *  header_length   → TCP header length in bytes (= data_offset * 4)
 *  payload_offset  → Byte offset into RawPacket::data where TCP payload starts
 *                    = IPPacket::transport_offset + header_length
 *  payload_length  → Length of TCP payload in bytes
 *                    = IPPacket::total_length - IPPacket::ip_header_len - header_length
 *                    May be 0 for pure ACK/SYN packets with no data.
 *
 * Convenience flag accessors (computed from flags byte):
 *  is_syn, is_ack, is_fin, is_rst, is_psh, is_urg
 *
 * Scan type helpers:
 *  is_syn_only     → SYN set, ACK clear (SYN scan)
 *  is_null_scan    → No flags set (NULL scan)
 *  is_xmas_scan    → FIN+PSH+URG set (XMAS scan)
 *  is_fin_scan     → FIN set, SYN/ACK/RST clear
 */
struct TCPPacket {
    uint16_t src_port       = 0;
    uint16_t dst_port       = 0;
    uint32_t seq_num        = 0;
    uint32_t ack_num        = 0;
    uint8_t  flags          = 0;
    uint16_t window_size    = 0;
    uint8_t  header_length  = 0;    // in bytes
    uint32_t payload_offset = 0;    // byte offset into RawPacket::data
    uint32_t payload_length = 0;    // bytes of actual payload

    // ── Flag convenience accessors ───────────────────────────────────────
    bool is_syn() const { return (flags & TCP_FLAG_SYN) != 0; }
    bool is_ack() const { return (flags & TCP_FLAG_ACK) != 0; }
    bool is_fin() const { return (flags & TCP_FLAG_FIN) != 0; }
    bool is_rst() const { return (flags & TCP_FLAG_RST) != 0; }
    bool is_psh() const { return (flags & TCP_FLAG_PSH) != 0; }
    bool is_urg() const { return (flags & TCP_FLAG_URG) != 0; }

    // ── Scan type detection helpers ──────────────────────────────────────

    /// SYN scan: SYN set, ACK NOT set
    /// Nmap default scan (-sS). Half-open — never completes handshake.
    bool is_syn_only() const {
        return is_syn() && !is_ack();
    }

    /// NULL scan: no flags set at all
    /// RFC-violating. Some stateless firewalls pass these through.
    bool is_null_scan() const {
        return flags == TCP_FLAGS_NULL;
    }

    /// XMAS scan: FIN + PSH + URG all set
    /// Named because the packet looks "lit up like a Christmas tree".
    bool is_xmas_scan() const {
        return (flags & TCP_FLAGS_XMAS) == TCP_FLAGS_XMAS;
    }

    /// FIN scan: FIN set, no SYN/ACK/RST
    /// Closed ports respond with RST; open ports silently drop it.
    bool is_fin_scan() const {
        return is_fin() && !is_syn() && !is_ack() && !is_rst();
    }
};


// ============================================================================
//  TCP PARSER
// ============================================================================

/**
 * @class TCPParser
 * @brief Parses TCP headers from raw packet bytes.
 *
 * Stateless — all methods are static.
 *
 * Requires the IPPacket result from IPParser::parse() to locate
 * the TCP header (via transport_offset).
 *
 * Only processes packets where IPPacket::protocol == IPPROTO_TCP_NUM (6).
 * Returns std::nullopt for non-TCP packets or malformed TCP headers.
 *
 * Usage:
 * @code
 *   auto ip = IPParser::parse(raw_pkt);
 *   if (!ip || ip->protocol != IPPROTO_TCP_NUM) return;
 *
 *   auto tcp = TCPParser::parse(raw_pkt, *ip);
 *   if (!tcp) return;
 *
 *   if (tcp->is_syn_only()) {
 *       // potential SYN scan probe
 *   }
 * @endcode
 */
class TCPParser {
public:

    /**
     * @brief Parse the TCP header from a raw packet.
     *
     * Validates:
     *  - Packet is long enough to hold the TCP header at transport_offset
     *  - Data offset >= 5 (header is at least 20 bytes)
     *  - Packet is long enough to hold the full TCP header (with options)
     *
     * @param pkt   Raw packet from libpcap
     * @param ip    Parsed IP result (provides transport_offset and total_length)
     * @return      Populated TCPPacket, or std::nullopt if invalid/non-TCP
     */
    static std::optional<TCPPacket> parse(const RawPacket& pkt,
                                          const IPPacket& ip);

    /**
     * @brief Get a human-readable string describing the TCP flags.
     *
     * Useful for logging and alert descriptions.
     *
     * @param flags  Raw TCP flags byte
     * @return       String like "SYN", "SYN|ACK", "FIN|PSH|URG"
     *
     * Example:
     * @code
     *   TCPParser::flagsToString(0x02) → "SYN"
     *   TCPParser::flagsToString(0x12) → "SYN|ACK"
     *   TCPParser::flagsToString(0x29) → "FIN|PSH|URG"
     *   TCPParser::flagsToString(0x00) → "NULL"
     * @endcode
     */
    static std::string flagsToString(uint8_t flags);

    /**
     * @brief Classify a packet's scan type based on flags.
     *
     * Returns a string identifying the scan type, or "NORMAL" if the
     * flags look like legitimate traffic.
     *
     * @param tcp   Parsed TCPPacket
     * @return      "SYN_SCAN", "NULL_SCAN", "XMAS_SCAN", "FIN_SCAN", or "NORMAL"
     */
    static std::string classifyScanType(const TCPPacket& tcp);
};
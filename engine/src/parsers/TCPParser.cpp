/**
 * @file    TCPParser.cpp
 * @brief   Implementation of TCPParser — TCP header parsing.
 *
 * @author  Ash
 * @project SentinelX
 */

#include "TCPParser.h"

#include <sstream>
#include <cstring>
#include <arpa/inet.h>      // ntohs(), ntohl()


// ============================================================================
//  INTERNAL: RAW TCP HEADER LAYOUT
// ============================================================================

/**
 * @struct RawTCPHeader
 * @brief Memory-mapped TCP header structure (20 bytes minimum).
 *
 * data_off_reserved:
 *   Upper 4 bits = Data Offset (TCP header length in 32-bit words)
 *   Lower 4 bits = Reserved (must be 0, but we don't validate this)
 *   Extract data offset: (data_off_reserved >> 4)
 */
#pragma pack(push, 1)
struct RawTCPHeader {
    uint16_t src_port;          // source port
    uint16_t dst_port;          // destination port
    uint32_t seq_num;           // sequence number
    uint32_t ack_num;           // acknowledgment number
    uint8_t  data_off_reserved; // data offset (4 bits) + reserved (4 bits)
    uint8_t  flags;             // control flags (CWR,ECE,URG,ACK,PSH,RST,SYN,FIN)
    uint16_t window;            // receive window size
    uint16_t checksum;          // checksum
    uint16_t urg_ptr;           // urgent pointer
    // TCP options follow if data_offset > 5 — not mapped here
};
#pragma pack(pop)

static_assert(sizeof(RawTCPHeader) == 20,
    "RawTCPHeader size mismatch — check packing");


// ============================================================================
//  TCPParser::parse
// ============================================================================

std::optional<TCPPacket> TCPParser::parse(const RawPacket& pkt,
                                           const IPPacket& ip) {

    // ── Protocol check ───────────────────────────────────────────────────
    if (ip.protocol != IPPROTO_TCP_NUM) {
        return std::nullopt;    // not TCP
    }

    // ── Minimum length check ─────────────────────────────────────────────
    // Need at least transport_offset + 20 bytes for the minimum TCP header
    if (pkt.capture_length < ip.transport_offset + sizeof(RawTCPHeader)) {
        return std::nullopt;    // truncated
    }

    // ── Map TCP header over bytes ─────────────────────────────────────────
    const RawTCPHeader* tcph = reinterpret_cast<const RawTCPHeader*>(
        pkt.data + ip.transport_offset
    );

    // ── Data offset validation ────────────────────────────────────────────
    // Upper 4 bits of data_off_reserved = TCP header length in 32-bit words
    uint8_t data_offset_words = (tcph->data_off_reserved >> 4);
    uint8_t tcp_header_bytes  = data_offset_words * 4;

    if (data_offset_words < 5) {
        // TCP header can't be smaller than 20 bytes — malformed packet
        return std::nullopt;
    }

    // Check captured data is long enough for the full TCP header (with options)
    if (pkt.capture_length < ip.transport_offset + tcp_header_bytes) {
        return std::nullopt;    // truncated — options cut off
    }

    // ── Payload size calculation ──────────────────────────────────────────
    // TCP payload length = IP total length - IP header length - TCP header length
    // We use the IP total_length (from the IP header) rather than capture_length
    // because capture_length may be less than wire_length (truncated packet).
    // If total_length < ip_header_len + tcp_header_bytes, payload is 0.
    uint32_t payload_offset = ip.transport_offset + tcp_header_bytes;
    int32_t  payload_len    = static_cast<int32_t>(ip.total_length)
                            - static_cast<int32_t>(ip.ip_header_len)
                            - static_cast<int32_t>(tcp_header_bytes);

    if (payload_len < 0) payload_len = 0;   // guard against malformed total_length

    // Clamp to actually captured bytes
    // (payload_offset + payload_len might exceed capture_length for truncated packets)
    uint32_t actual_payload_len = static_cast<uint32_t>(payload_len);
    if (payload_offset + actual_payload_len > pkt.capture_length) {
        actual_payload_len = (payload_offset <= pkt.capture_length)
                           ? (pkt.capture_length - payload_offset)
                           : 0;
    }

    // ── Build result ──────────────────────────────────────────────────────
    TCPPacket result;
    result.src_port       = ntohs(tcph->src_port);
    result.dst_port       = ntohs(tcph->dst_port);
    result.seq_num        = ntohl(tcph->seq_num);
    result.ack_num        = ntohl(tcph->ack_num);
    result.flags          = tcph->flags;
    result.window_size    = ntohs(tcph->window);
    result.header_length  = tcp_header_bytes;
    result.payload_offset = payload_offset;
    result.payload_length = actual_payload_len;

    return result;
}


// ============================================================================
//  TCPParser::flagsToString
// ============================================================================

/**
 * Iterates through all 8 flag bits and builds a pipe-separated string.
 * Returns "NULL" for 0x00 (no flags) since "NULL" is its security name.
 */
std::string TCPParser::flagsToString(uint8_t flags) {
    if (flags == 0x00) return "NULL";

    std::ostringstream oss;
    bool first = true;

    auto append = [&](const char* name) {
        if (!first) oss << "|";
        oss << name;
        first = false;
    };

    if (flags & TCP_FLAG_CWR) append("CWR");
    if (flags & TCP_FLAG_ECE) append("ECE");
    if (flags & TCP_FLAG_URG) append("URG");
    if (flags & TCP_FLAG_ACK) append("ACK");
    if (flags & TCP_FLAG_PSH) append("PSH");
    if (flags & TCP_FLAG_RST) append("RST");
    if (flags & TCP_FLAG_SYN) append("SYN");
    if (flags & TCP_FLAG_FIN) append("FIN");

    return oss.str();
}


// ============================================================================
//  TCPParser::classifyScanType
// ============================================================================

std::string TCPParser::classifyScanType(const TCPPacket& tcp) {
    if (tcp.is_syn_only())  return "SYN_SCAN";
    if (tcp.is_null_scan()) return "NULL_SCAN";
    if (tcp.is_xmas_scan()) return "XMAS_SCAN";
    if (tcp.is_fin_scan())  return "FIN_SCAN";
    return "NORMAL";
}
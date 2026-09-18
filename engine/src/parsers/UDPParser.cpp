/**
 * @file UDPParser.cpp
 * @brief Bounds-checked UDP parser.
 */
#include "UDPParser.h"

#include <algorithm>
#include <cstring>

std::optional<UDPPacket> UDPParser::parse(const RawPacket& pkt,
                                          const IPPacket& ip) {
    if (pkt.data == nullptr || ip.protocol != IPPROTO_UDP_NUM ||
        ip.is_fragmented || ip.transport_offset < ETHERNET_HEADER_LEN ||
        ip.total_length < ip.ip_header_len) {
        return std::nullopt;
    }

    constexpr uint32_t UDP_HEADER_LEN = 8;
    const uint64_t ip_end = static_cast<uint64_t>(ETHERNET_HEADER_LEN) +
                            ip.total_length;
    const uint64_t header_end = static_cast<uint64_t>(ip.transport_offset) +
                                UDP_HEADER_LEN;
    if (header_end > pkt.capture_length || header_end > ip_end) {
        return std::nullopt;
    }

    const uint8_t* h = pkt.data + ip.transport_offset;
    const uint16_t src_port = static_cast<uint16_t>(h[0] << 8 | h[1]);
    const uint16_t dst_port = static_cast<uint16_t>(h[2] << 8 | h[3]);
    const uint16_t udp_len = static_cast<uint16_t>(h[4] << 8 | h[5]);
    const uint16_t checksum = static_cast<uint16_t>(h[6] << 8 | h[7]);

    if (udp_len < UDP_HEADER_LEN ||
        static_cast<uint64_t>(ip.ip_header_len) + udp_len > ip.total_length) {
        return std::nullopt;
    }

    const uint32_t payload_offset = ip.transport_offset + UDP_HEADER_LEN;
    const uint64_t payload_end = std::min<uint64_t>(
        static_cast<uint64_t>(ip.transport_offset) + udp_len,
        pkt.capture_length);

    UDPPacket result;
    result.src_port = src_port;
    result.dst_port = dst_port;
    result.length = udp_len;
    result.checksum = checksum;
    result.payload_offset = payload_offset;
    result.payload_length = payload_end > payload_offset
        ? static_cast<uint32_t>(payload_end - payload_offset)
        : 0;
    return result;
}

/**
 * @file UDPParser.h
 * @brief Bounds-checked IPv4/UDP datagram parser.
 *
 * UDP is intentionally kept separate from TCP: the engine only needs the
 * ports and payload for scan/honeypot/YARA detection, and does not attempt
 * stream reassembly.
 */
#pragma once

#include <cstdint>
#include <optional>

#include "../capture/RawPacket.h"
#include "IPParser.h"

struct UDPPacket {
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint16_t length = 0;            // UDP header + payload from the wire
    uint16_t checksum = 0;
    uint32_t payload_offset = 0;    // offset into RawPacket::data
    uint32_t payload_length = 0;    // captured payload bytes
};

class UDPParser {
public:
    /**
     * Parse a complete UDP header and a possibly snaplen-truncated payload.
     * Invalid UDP lengths, fragments, and truncated headers return nullopt.
     */
    static std::optional<UDPPacket> parse(const RawPacket& pkt,
                                          const IPPacket& ip);
};

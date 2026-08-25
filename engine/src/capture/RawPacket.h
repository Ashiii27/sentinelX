#pragma once

#include <cstdint>

/** A non-owning view of one captured packet. */
struct RawPacket {
    const uint8_t* data           = nullptr;
    uint32_t       capture_length = 0;
    uint32_t       wire_length    = 0;
    uint32_t       timestamp_sec  = 0;
    uint32_t       timestamp_usec = 0;
};
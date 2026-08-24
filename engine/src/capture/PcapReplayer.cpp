/**
 * @file    PcapReplayer.cpp
 * @brief   Implementation of the offline classic-pcap reader.
 *
 * @author  Ash
 * @project SentinelX
 */

#include "PcapReplayer.h"

#include <cstring>


// ============================================================================
//  PCAP FORMAT CONSTANTS  (see pcap(5))
// ============================================================================

namespace {

constexpr uint32_t PCAP_MAGIC_USEC_LE  = 0xA1B2C3D4;  ///< classic, usec, LE
constexpr uint32_t PCAP_MAGIC_USEC_BE  = 0xD4C3B2A1;  ///< classic, usec, BE
constexpr uint32_t PCAP_MAGIC_NSEC_LE  = 0xA1B23C4D;  ///< classic, nsec, LE
constexpr uint32_t PCAP_MAGIC_NSEC_BE  = 0x4D3CB2A1;  ///< classic, nsec, BE

// NOTE: named PCAPF_* (pcap FORMAT) to avoid colliding with the
// PCAP_VERSION_MAJOR / DLT_EN10MB #defines in <pcap/pcap.h>, which this
// translation unit sees transitively through PacketCapture.h.
constexpr uint16_t PCAPF_VERSION_MAJOR = 2;
constexpr uint16_t PCAPF_VERSION_MINOR = 4;
constexpr uint32_t PCAPF_DLT_EN10MB    = 1;  ///< Ethernet

constexpr size_t GLOBAL_HEADER_SIZE   = 24;
constexpr size_t RECORD_HEADER_SIZE   = 16;

}  // namespace


// ============================================================================
//  CONSTRUCTION / DESTRUCTION / MOVEMENT
// ============================================================================

PcapReplayer::~PcapReplayer() {
    close();
}


PcapReplayer::PcapReplayer(PcapReplayer&& other) noexcept
    : m_file(other.m_file)
    , m_path(std::move(other.m_path))
    , m_little_endian(other.m_little_endian)
    , m_ns_precision(other.m_ns_precision)
    , m_packet_count(other.m_packet_count)
    , m_snaplen(other.m_snaplen)
    , m_record_buf(std::move(other.m_record_buf)) {
    other.m_file = nullptr;
}


PcapReplayer& PcapReplayer::operator=(PcapReplayer&& other) noexcept {
    if (this != &other) {
        close();
        m_file          = other.m_file;
        m_path          = std::move(other.m_path);
        m_little_endian = other.m_little_endian;
        m_ns_precision  = other.m_ns_precision;
        m_packet_count  = other.m_packet_count;
        m_snaplen       = other.m_snaplen;
        m_record_buf    = std::move(other.m_record_buf);
        other.m_file = nullptr;
    }
    return *this;
}


// ============================================================================
//  OPEN / CLOSE
// ============================================================================

bool PcapReplayer::open(const std::string& path, std::string& err) {
    close();

    m_file = std::fopen(path.c_str(), "rb");
    if (!m_file) {
        err = "cannot open file: " + path;
        return false;
    }

    uint8_t gh[GLOBAL_HEADER_SIZE];
    if (!readBytes(gh, sizeof(gh))) {
        err = "file too small to contain a pcap global header";
        close();
        return false;
    }

    // ── Magic + byte order ───────────────────────────────────────────────
    uint32_t magic;
    std::memcpy(&magic, gh, 4);

    if (magic == PCAP_MAGIC_USEC_LE) {
        m_little_endian = true;
        m_ns_precision  = false;
    } else if (magic == PCAP_MAGIC_USEC_BE) {
        m_little_endian = false;
        m_ns_precision  = false;
    } else if (magic == PCAP_MAGIC_NSEC_LE) {
        m_little_endian = true;
        m_ns_precision  = true;
    } else if (magic == PCAP_MAGIC_NSEC_BE) {
        m_little_endian = false;
        m_ns_precision  = true;
    } else {
        char mb[16];
        std::snprintf(mb, sizeof(mb), "%08X", magic);
        err = "not a classic pcap file (bad magic 0x" + std::string(mb) + ")";
        close();
        return false;
    }

    // ── Version ──────────────────────────────────────────────────────────
    const uint16_t ver_major = readU16Host(*reinterpret_cast<uint16_t*>(gh + 4));
    const uint16_t ver_minor = readU16Host(*reinterpret_cast<uint16_t*>(gh + 6));
    if (ver_major != PCAPF_VERSION_MAJOR || ver_minor != PCAPF_VERSION_MINOR) {
        err = "unsupported pcap version " + std::to_string(ver_major) + "." +
              std::to_string(ver_minor);
        close();
        return false;
    }

    // ── Link type ────────────────────────────────────────────────────────
    const uint32_t snaplen = readU32Host(*reinterpret_cast<uint32_t*>(gh + 16));
    const uint32_t network = readU32Host(*reinterpret_cast<uint32_t*>(gh + 20));
    m_snaplen = snaplen;

    if (network != PCAPF_DLT_EN10MB) {
        err = "unsupported link type " + std::to_string(network) +
              " (only Ethernet / DLT_EN10MB is supported)";
        close();
        return false;
    }

    // ── Count packets (fast forward pass) ────────────────────────────────
    // Needed for --loop progress reporting; cheap (just skips records).
    m_packet_count = 0;
    long pos_now = std::ftell(m_file);
    RawPacket dummy;
    while (next(dummy)) {
        m_packet_count++;
    }
    std::fseek(m_file, pos_now, SEEK_SET);

    m_path = path;
    return true;
}


void PcapReplayer::close() {
    if (m_file) {
        std::fclose(m_file);
        m_file = nullptr;
    }
    m_path.clear();
    m_packet_count = 0;
    m_record_buf.clear();
}


// ============================================================================
//  READING
// ============================================================================

bool PcapReplayer::next(RawPacket& out) {
    if (!m_file) {
        return false;
    }

    uint8_t rh[RECORD_HEADER_SIZE];
    if (!readBytes(rh, sizeof(rh))) {
        return false;  // clean EOF
    }

    const uint32_t ts_sec    = readU32Host(*reinterpret_cast<uint32_t*>(rh + 0));
    const uint32_t ts_frac   = readU32Host(*reinterpret_cast<uint32_t*>(rh + 4));
    const uint32_t incl_len  = readU32Host(*reinterpret_cast<uint32_t*>(rh + 8));
    const uint32_t orig_len  = readU32Host(*reinterpret_cast<uint32_t*>(rh + 12));

    // Guard against corrupt headers claiming absurd lengths.
    if (incl_len > 0x800000) {  // > 8 MB per packet is not a real capture
        return false;
    }

    if (m_record_buf.size() < incl_len) {
        m_record_buf.resize(incl_len);
    }
    if (incl_len > 0 && !readBytes(m_record_buf.data(), incl_len)) {
        return false;  // truncated record — treat as EOF
    }

    out.data           = m_record_buf.data();
    out.capture_length = incl_len;
    out.wire_length    = orig_len;
    out.timestamp_sec  = ts_sec;
    // Normalize to microseconds regardless of file precision.
    out.timestamp_usec = m_ns_precision ? ts_frac / 1000 : ts_frac;
    return true;
}


bool PcapReplayer::rewind() {
    if (!m_file) {
        return false;
    }
    return std::fseek(m_file, static_cast<long>(GLOBAL_HEADER_SIZE),
                      SEEK_SET) == 0;
}


// ============================================================================
//  LOW-LEVEL HELPERS
// ============================================================================

bool PcapReplayer::readBytes(void* buf, size_t n) {
    if (n == 0) {
        return true;
    }
    return std::fread(buf, 1, n, m_file) == n;
}


uint32_t PcapReplayer::readU32Host(const uint32_t raw_le) const {
    if (m_little_endian) {
        return raw_le;
    }
    return ((raw_le & 0x000000FFu) << 24) |
           ((raw_le & 0x0000FF00u) << 8)  |
           ((raw_le & 0x00FF0000u) >> 8)  |
           ((raw_le & 0xFF000000u) >> 24);
}


uint16_t PcapReplayer::readU16Host(const uint16_t raw_le) const {
    if (m_little_endian) {
        return raw_le;
    }
    return static_cast<uint16_t>((raw_le << 8) | (raw_le >> 8));
}

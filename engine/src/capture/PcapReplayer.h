/**
 * @file    PcapReplayer.h
 * @brief   Offline reader for classic libpcap files (.pcap).
 *
 * WHY THIS EXISTS
 * ---------------
 * A NIDS that can only analyze live traffic is hard to develop, test, and
 * demo. Real capture requires root + a network interface. The PCAP
 * replayer gives the engine a second input source: a captured file.
 *
 *   sentinelx --replay incident.pcap
 *
 * The replayer produces the exact same RawPacket values as live capture,
 * so the entire downstream pipeline (parsers → detectors → YARA → alerts)
 * runs identically. This is how the unit test suite exercises detection
 * logic without any network access, and how an operator can re-analyze a
 * saved incident later.
 *
 * IMPL NOTES
 * ----------
 * Reads the classic pcap file format directly (pcap(5)):
 *   - 24-byte global header (magic, version, snaplen, link type)
 *   - per-record: 16-byte record header + incl_len payload bytes
 *
 * Both byte orders are supported (little-endian magic 0xa1b2c3d4 and
 * big-endian 0xd4c3b2a1), and both microsecond and nanosecond
 * timestamp-precision variants.
 *
 * Only Ethernet (link type 1) capture files are fully supported — that
 * is what PacketCapture produces on Linux. Other link types (e.g.
 * DLT_RAW) are rejected with a clear error.
 *
 * No libpcap dependency: the format is simple enough to read directly,
 * and this keeps the replayer usable in minimal test environments.
 *
 * @author  Ash
 * @project SentinelX
 */

#pragma once

#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <string>
#include <vector>

#include "PacketCapture.h"   // RawPacket


// ============================================================================
//  PLAYER
// ============================================================================

/**
 * @class PcapReplayer
 * @brief Iterates the packets of a classic pcap file.
 *
 * Usage:
 * @code
 *   PcapReplayer player;
 *   std::string err;
 *   if (!player.open("incident.pcap", err)) {
 *       // log err, abort
 *   }
 *   RawPacket pkt;
 *   while (player.next(pkt)) {
 *       pipeline.process(pkt);
 *   }
 * @endcode
 *
 * Lifetime: the bytes pointed to by RawPacket::data are owned by the
 * replayer and remain valid until the next next() call or close().
 *
 * Non-copyable (owns a FILE*), movable.
 */
class PcapReplayer {
public:

    PcapReplayer() = default;
    ~PcapReplayer();

    PcapReplayer(const PcapReplayer&)            = delete;
    PcapReplayer& operator=(const PcapReplayer&) = delete;

    PcapReplayer(PcapReplayer&& other) noexcept;
    PcapReplayer& operator=(PcapReplayer&& other) noexcept;

    /**
     * @brief Open a pcap file for replay.
     *
     * Validates the global header: magic (any byte order, usec or nsec
     * precision), version 2.4, and link type == Ethernet (1).
     *
     * @param path   Path to the .pcap file
     * @param err    [out] Human-readable error on failure
     * @return       true on success
     */
    bool open(const std::string& path, std::string& err);

    /**
     * @brief Read the next packet.
     *
     * @param out   RawPacket to fill (data points into internal buffer)
     * @return      true if a packet was read, false at EOF or on read
     *              error
     */
    bool next(RawPacket& out);

    /// Seek back to the first packet (for --loop mode).
    bool rewind();

    /// Number of packets in the file (known after open()).
    uint64_t packetCount() const { return m_packet_count; }

    /// Path of the open file ("" if not open).
    const std::string& path() const { return m_path; }

    /// Is a file currently open?
    bool isOpen() const { return m_file != nullptr; }

    /**
     * @brief Close the file (safe to call multiple times).
     */
    void close();

private:

    /// Read exactly n bytes from m_file into buf. false on error/EOF.
    bool readBytes(void* buf, size_t n);

    /// Decode one 32-bit field with endianness correction.
    uint32_t readU32Host(const uint32_t raw_le) const;

    /// Decode one 16-bit field with endianness correction.
    uint16_t readU16Host(const uint16_t raw_le) const;

    std::FILE*      m_file         = nullptr;
    std::string     m_path;
    bool            m_little_endian = true;   // file byte order
    bool            m_ns_precision  = false;  // true = nanosecond ts
    uint64_t        m_packet_count  = 0;
    uint32_t        m_snaplen       = 0;

    // Internal record buffer — RawPacket::data points here. Grown as
    // needed; never shrunk (avoids realloc churn in the loop).
    std::vector<uint8_t> m_record_buf;
};

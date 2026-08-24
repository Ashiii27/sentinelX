/**
 * @file    test_pcap_replayer.cpp
 * @brief   Tests the offline pcap replayer with synthetic capture files.
 *
 * @author  Ash
 * @project SentinelX
 */

#include "test_framework.h"
#include "packet_builder.h"

#include <cstdio>
#include <cstring>
#include <fstream>

#include "../src/capture/PcapReplayer.h"
#include "../src/parsers/IPParser.h"


namespace {

// ── Tiny pcap writer (classic format, little-endian) ─────────────────────

void putU16(std::vector<uint8_t>& b, uint16_t v) {
    b.push_back(v & 0xFF);
    b.push_back((v >> 8) & 0xFF);
}
void putU32(std::vector<uint8_t>& b, uint32_t v) {
    b.push_back(v & 0xFF);
    b.push_back((v >> 8) & 0xFF);
    b.push_back((v >> 16) & 0xFF);
    b.push_back((v >> 24) & 0xFF);
}

/// Write a classic pcap file: global header + records.
std::string writePcap(const std::string& path,
                      const std::vector<std::pair<std::vector<uint8_t>,
                                                  std::pair<uint32_t, uint32_t>>>&
                          records,  // (bytes, (ts_sec, ts_usec))
                      bool big_endian = false,
                      bool nanoseconds = false) {
    std::vector<uint8_t> f;

    // Global header
    // The canonical magic VALUE is 0xA1B2C3D4 (usec) / 0xA1B23C4D (nsec);
    // it is stored in the FILE's byte order, so an LE reader sees
    // 0xA1B2C3D4 for LE files and 0xD4C3B2A1 for BE files.
    const uint32_t magic = nanoseconds ? 0xA1B23C4D : 0xA1B2C3D4;

    auto put16 = [&](uint16_t v) {
        if (big_endian) {
            f.push_back((v >> 8) & 0xFF);
            f.push_back(v & 0xFF);
        } else {
            putU16(f, v);
        }
    };
    auto put32 = [&](uint32_t v) {
        if (big_endian) {
            f.push_back((v >> 24) & 0xFF);
            f.push_back((v >> 16) & 0xFF);
            f.push_back((v >> 8) & 0xFF);
            f.push_back(v & 0xFF);
        } else {
            putU32(f, v);
        }
    };

    put32(magic);  // magic (in the file's byte order)
    put16(2);   // version major
    put16(4);   // version minor
    put32(0);   // thiszone
    put32(0);   // sigfigs
    put32(65535);  // snaplen
    put32(1);   // link type: Ethernet

    // Records
    for (const auto& [bytes, ts] : records) {
        put32(ts.first);
        put32(ts.second);
        put32(static_cast<uint32_t>(bytes.size()));  // incl_len
        put32(static_cast<uint32_t>(bytes.size()));  // orig_len
        f.insert(f.end(), bytes.begin(), bytes.end());
    }

    std::ofstream out(path, std::ios::binary);
    out.write(reinterpret_cast<const char*>(f.data()),
              static_cast<std::streamsize>(f.size()));
    return path;
}

}  // namespace


// ============================================================================
//  TESTS
// ============================================================================

static void test_replay_basic() {
    // Three packets: TCP SYN, UDP, ARP (all valid pcap records)
    auto p1 = pktbuild::makeTCP("1.2.3.4", "5.6.7.8", 1111, 80, 0x02);
    auto p2 = pktbuild::makeUDP("1.2.3.4", "5.6.7.8", 2222, 53, "dns");
    auto p3 = pktbuild::makeARP();

    const std::string path = "/tmp/sentinelx_test_replay.pcap";
    writePcap(path, {{p1, {1700000000u, 123000u}},
                     {p2, {1700000001u, 456000u}},
                     {p3, {1700000002u, 789000u}}});

    PcapReplayer player;
    std::string err;
    CHECK(player.open(path, err));
    CHECK_EQ(player.packetCount(), static_cast<uint64_t>(3));
    CHECK(player.isOpen());
    CHECK_EQ(player.path(), path);

    RawPacket raw;
    CHECK(player.next(raw));
    CHECK_EQ(raw.timestamp_sec, static_cast<uint32_t>(1700000000u));
    CHECK_EQ(raw.timestamp_usec, static_cast<uint32_t>(123000u));
    CHECK_EQ(raw.capture_length, static_cast<uint32_t>(p1.size()));
    CHECK_EQ(raw.wire_length, static_cast<uint32_t>(p1.size()));
    CHECK(std::memcmp(raw.data, p1.data(), p1.size()) == 0);

    // The parsed IP layer must match the original packet
    auto ip = IPParser::parse(raw);
    CHECK(ip.has_value());
    if (ip) {
        CHECK_EQ(ip->src_ip, std::string("1.2.3.4"));
        CHECK_EQ(ip->dst_ip, std::string("5.6.7.8"));
    }

    CHECK(player.next(raw));
    CHECK_EQ(raw.timestamp_sec, static_cast<uint32_t>(1700000001u));
    CHECK_EQ(raw.capture_length, static_cast<uint32_t>(p2.size()));

    CHECK(player.next(raw));
    CHECK_EQ(raw.capture_length, static_cast<uint32_t>(p3.size()));

    CHECK(!player.next(raw));  // EOF
    player.close();
    CHECK(!player.isOpen());
    std::remove(path.c_str());
}

static void test_replay_big_endian() {
    auto p1 = pktbuild::makeTCP("9.9.9.9", "8.8.8.8", 3333, 443, 0x02);

    const std::string path = "/tmp/sentinelx_test_replay_be.pcap";
    writePcap(path, {{p1, {1700000100u, 1u}}}, /*big_endian=*/true);

    PcapReplayer player;
    std::string err;
    CHECK(player.open(path, err));
    CHECK_EQ(player.packetCount(), static_cast<uint64_t>(1));

    RawPacket raw;
    CHECK(player.next(raw));
    CHECK_EQ(raw.timestamp_sec, static_cast<uint32_t>(1700000100u));
    CHECK_EQ(raw.capture_length, static_cast<uint32_t>(p1.size()));
    auto ip = IPParser::parse(raw);
    CHECK(ip.has_value());
    if (ip) {
        CHECK_EQ(ip->src_ip, std::string("9.9.9.9"));
    }
    player.close();
    std::remove(path.c_str());
}

static void test_replay_nanoseconds() {
    auto p1 = pktbuild::makeTCP("9.9.9.9", "8.8.8.8", 3333, 443, 0x02);

    const std::string path = "/tmp/sentinelx_test_replay_ns.pcap";
    // 1 second + 500ms expressed in nanoseconds (500000000)
    writePcap(path, {{p1, {1700000200u, 500000000u}}}, false,
              /*nanoseconds=*/true);

    PcapReplayer player;
    std::string err;
    CHECK(player.open(path, err));

    RawPacket raw;
    CHECK(player.next(raw));
    CHECK_EQ(raw.timestamp_usec, static_cast<uint32_t>(500000u));  // ns→us
    player.close();
    std::remove(path.c_str());
}

static void test_replay_rewind() {
    auto p1 = pktbuild::makeTCP("1.1.1.1", "2.2.2.2", 1, 80, 0x02);
    auto p2 = pktbuild::makeTCP("1.1.1.1", "2.2.2.2", 1, 81, 0x02);

    const std::string path = "/tmp/sentinelx_test_replay_rw.pcap";
    writePcap(path, {{p1, {100u, 0u}}, {p2, {101u, 0u}}});

    PcapReplayer player;
    std::string err;
    CHECK(player.open(path, err));

    RawPacket raw;
    CHECK(player.next(raw));
    CHECK(player.next(raw));
    CHECK(!player.next(raw));  // EOF

    CHECK(player.rewind());
    CHECK(player.next(raw));
    CHECK_EQ(raw.timestamp_sec, static_cast<uint32_t>(100u));  // back to #1
    CHECK(player.next(raw));
    CHECK_EQ(raw.timestamp_sec, static_cast<uint32_t>(101u));
    player.close();
    std::remove(path.c_str());
}

static void test_replay_bad_magic() {
    const std::string path = "/tmp/sentinelx_test_replay_bad.pcap";
    {
        std::ofstream out(path, std::ios::binary);
        const std::string junk(40, 'X');  // not a pcap magic
        out.write(junk.data(), junk.size());
    }

    PcapReplayer player;
    std::string err;
    CHECK(!player.open(path, err));
    CHECK(!err.empty());
    std::remove(path.c_str());
}

static void test_replay_missing_file() {
    PcapReplayer player;
    std::string err;
    CHECK(!player.open("/tmp/definitely_not_here_12345.pcap", err));
    CHECK(!err.empty());
}


int main() {
    test_replay_basic();
    test_replay_big_endian();
    test_replay_nanoseconds();
    test_replay_rewind();
    test_replay_bad_magic();
    test_replay_missing_file();
    return testfw::summary("test_pcap_replayer");
}

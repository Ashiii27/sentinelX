/**
 * @file    SHA256.h
 * @brief   Minimal, dependency-free SHA-256 implementation.
 *
 * Self-contained public-domain-style implementation of SHA-256
 * (FIPS 180-4). SentinelX uses it for two things:
 *
 *   1. Alert evidence — raw_payload_hash in YARA match alerts, so an
 *      analyst can pivot from an alert to the exact payload in a PCAP.
 *   2. Dedup keys — hashing normalized probe tuples is cheaper than
 *      string concatenation at high packet rates.
 *
 * Why not OpenSSL?
 *   Pulling in OpenSSL (or nlohmann alternatives for hashing) just for
 *   one hash function bloats the dependency chain for a binary that
 *   otherwise only needs libpcap + libyara. SHA-256 is small and stable;
 *   inlining it keeps the engine's runtime dependencies minimal. This
 *   implementation is NOT constant-time — it is for hashing network
 *   evidence, not for secret-key cryptography.
 *
 * Usage:
 * @code
 *   std::string hex = SHA256::hash(payload.data(), payload.size());
 *   // → "9f86d081...64 hex chars"
 * @endcode
 *
 * @author  Ash
 * @project SentinelX
 */

#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <array>


// ============================================================================
//  SHA-256
// ============================================================================

/**
 * @class SHA256
 * @brief Streaming and one-shot SHA-256.
 *
 * For one-shot hashing (the common case in this codebase) use the static
 * hash(). For streaming, construct an instance, call update() in chunks,
 * then final().
 */
class SHA256 {
public:

    /**
     * @brief One-shot convenience: hash a memory block.
     * @param data  Pointer to data
     * @param len   Length in bytes
     * @return      64-character lowercase hex string
     */
    static std::string hash(const uint8_t* data, size_t len) {
        SHA256 ctx;
        ctx.update(data, len);
        return ctx.final();
    }

    /**
     * @brief One-shot convenience overload for std::string.
     */
    static std::string hash(const std::string& s) {
        return hash(reinterpret_cast<const uint8_t*>(s.data()), s.size());
    }

    SHA256() { init(); }

    /**
     * @brief Feed a chunk of data into the running hash.
     */
    void update(const uint8_t* data, size_t len) {
        while (len > 0) {
            size_t space = 64 - m_buf_len;
            size_t take  = (len < space) ? len : space;
            std::copy(data, data + take, m_buffer.begin() + m_buf_len);
            m_buf_len += take;
            data      += take;
            len       -= take;

            if (m_buf_len == 64) {
                m_total_len += 64;
                transform(m_buffer.data());
                m_buf_len = 0;
            }
        }
    }

    /**
     * @brief Finalize and return the 64-char hex digest.
     * Resets the context — it may be reused for another hash.
     */
    std::string final() {
        // FIPS 180-4 padding: 0x80, then zeros, then the 64-bit
        // big-endian bit length of the ORIGINAL message (captured before
        // any padding bytes are added — padding must not count toward it).
        const uint64_t bit_len = m_total_len * 8;

        m_buffer[m_buf_len++] = 0x80;
        if (m_buf_len > 56) {
            // No room for the length field in the current block —
            // fill to the block boundary, transform, then continue
            // padding in a fresh block.
            while (m_buf_len < 64) {
                m_buffer[m_buf_len++] = 0x00;
            }
            transform(m_buffer.data());
            m_buf_len = 0;
        }
        while (m_buf_len < 56) {
            m_buffer[m_buf_len++] = 0x00;
        }
        for (int i = 0; i < 8; ++i) {
            m_buffer[56 + i] = static_cast<uint8_t>(bit_len >> (56 - i * 8));
        }
        m_buf_len = 64;
        transform(m_buffer.data());

        std::string out;
        out.reserve(64);
        static const char* hexd = "0123456789abcdef";
        for (uint32_t w : m_state) {
            for (int i = 24; i >= 0; i -= 8) {
                out.push_back(hexd[(w >> i) & 0xF]);
                out.push_back(hexd[(w >> (i - 4)) & 0xF]);
            }
        }

        init();  // reset for reuse
        return out;
    }

private:

    std::array<uint32_t, 8> m_state{};
    std::array<uint8_t, 64> m_buffer{};
    size_t   m_buf_len   = 0;
    uint64_t m_total_len = 0;

    static constexpr uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    static inline uint32_t rotr(uint32_t x, uint32_t n) {
        return (x >> n) | (x << (32 - n));
    }

    void init() {
        m_state = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                   0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
        m_buffer.fill(0);
        m_buf_len   = 0;
        m_total_len = 0;
    }

    void transform(const uint8_t* chunk) {
        uint32_t w[64];
        for (int i = 0; i < 16; ++i) {
            w[i] = (static_cast<uint32_t>(chunk[i * 4]) << 24) |
                   (static_cast<uint32_t>(chunk[i * 4 + 1]) << 16) |
                   (static_cast<uint32_t>(chunk[i * 4 + 2]) << 8) |
                   (static_cast<uint32_t>(chunk[i * 4 + 3]));
        }
        for (int i = 16; i < 64; ++i) {
            const uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^
                                (w[i - 15] >> 3);
            const uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^
                                (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        uint32_t a = m_state[0], b = m_state[1], c = m_state[2],
                 d = m_state[3], e = m_state[4], f = m_state[5],
                 g = m_state[6], h = m_state[7];

        for (int i = 0; i < 64; ++i) {
            const uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            const uint32_t ch = (e & f) ^ (~e & g);
            const uint32_t t1 = h + S1 + ch + K[i] + w[i];
            const uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            const uint32_t t2 = S0 + maj;

            h = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }

        m_state[0] += a; m_state[1] += b; m_state[2] += c; m_state[3] += d;
        m_state[4] += e; m_state[5] += f; m_state[6] += g; m_state[7] += h;
    }
};

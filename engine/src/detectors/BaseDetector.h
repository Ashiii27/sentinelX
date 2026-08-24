/**
 * @file    BaseDetector.h
 * @brief   Abstract base class for all SentinelX detectors.
 *
 * Every detector in SentinelX (PortScan, SYNFlood, HTTPAnomaly, Honeypot)
 * derives from BaseDetector and implements `process()`. The main pipeline
 * treats detectors as a list of BaseDetector* — adding a new detector type
 * requires no changes to the pipeline code.
 *
 * ── Design Decisions ─────────────────────────────────────────────────────
 *
 * 1. Pull-based processing, not push:
 *    The pipeline calls detector->process(packet) for every packet, in a
 *    fixed order. Detectors decide for themselves whether the packet is
 *    relevant. This keeps the pipeline trivially simple and makes each
 *    detector independently testable with synthetic packets.
 *
 * 2. Return alerts, don't emit them:
 *    Detectors RETURN the alerts they produce (by value, small vector).
 *    They do NOT talk to the AlertEmitter or the network. This separation
 *    is what makes unit testing cheap: a test calls process() with a
 *    synthetic packet and inspects the returned vector — no sockets, no
 *    stdout, no external state.
 *
 * 3. State is owned by the detector:
 *    A detector that needs to track state across packets (port scan window,
 *    SYN counters) keeps it in its own members. The pipeline never inspects
 *    detector internals. This is why detectors are non-copyable — copying
 *    would duplicate the tracking state and double-count alerts.
 *
 * 4. tick() for time-based maintenance:
 *    Sliding-window detectors must purge expired state. Rather than doing
 *    this work on every single packet (wasteful when the packet rate is
 *    high and the window is 5s), the pipeline calls tick() at a low,
 *    fixed frequency (once per second). Detectors that need more granular
 *    timing can still purge lazily inside process().
 *
 * 5. Timestamps are injected, not read internally:
 *    process() and tick() receive the packet timestamp / current time as
 *    parameters instead of calling std::chrono::system_clock() internally.
 *    This lets unit tests replay traffic with controlled timestamps — the
 *    difference between "a 5-second window" and "a 5-hour window" is
 *    testable in milliseconds.
 *
 * @author  Ash
 * @project SentinelX
 */

#pragma once

#include <string>
#include <vector>
#include <chrono>
#include <cstdint>

#include "../capture/PacketCapture.h"   // RawPacket
#include "../parsers/IPParser.h"        // IPPacket
#include "../parsers/TCPParser.h"       // TCPPacket
#include "../parsers/HTTPParser.h"      // HTTPPacket
#include "../alerts/Alert.h"            // Alert


// ============================================================================
//  BASE DETECTOR
// ============================================================================

/**
 * @class BaseDetector
 * @brief Abstract interface that all SentinelX detectors implement.
 *
 * Inheritance contract:
 *  - name()      → stable, log-friendly identifier (e.g. "PortScanDetector")
 *  - process()   → called for every parsed packet; returns 0..N alerts
 *  - tick()      → called ~1x/second; purge expired state, reset rates
 *  - reset()     → clear all tracked state (used on engine restart / config reload)
 *
 * Threading:
 *  A detector instance is owned by a single pipeline thread. process() and
 *  tick() must NOT be called concurrently. If you run multiple pipeline
 *  threads, give each one its own detector instances (or synchronize).
 */
class BaseDetector {
public:

    BaseDetector() = default;
    virtual ~BaseDetector() = default;

    /**
     * @brief Human-readable name of this detector (for logs / stats).
     * @return e.g. "PortScanDetector"
     */
    virtual std::string name() const = 0;

    /**
     * @brief Process one parsed packet and return any alerts it triggered.
     *
     * The pipeline guarantees the arguments are consistent:
     *  - ip          is always valid (the packet parsed as IPv4)
     *  - tcp         is valid ONLY when ip.protocol == IPPROTO_TCP_NUM;
     *                otherwise nullptr
     *  - http        is valid ONLY when the packet carried an HTTP
     *                request/response on a well-known HTTP port;
     *                otherwise nullptr
     *
     * A detector should check `tcp != nullptr` before using it.
     *
     * @param raw     Raw packet bytes (valid for the duration of the call)
     * @param ip      Parsed IP layer (always present)
     * @param tcp     Parsed TCP layer (may be nullptr)
     * @param http    Parsed HTTP layer (may be nullptr)
     * @param ts_ms   Packet timestamp in Unix milliseconds (UTC)
     * @return        Alerts triggered by this packet (empty vector = none)
     */
    virtual std::vector<Alert> process(const RawPacket& raw,
                                       const IPPacket& ip,
                                       const TCPPacket* tcp,
                                       const HTTPPacket* http,
                                       int64_t ts_ms) = 0;

    /**
     * @brief Periodic maintenance — purge expired sliding-window state.
     *
     * Called by the pipeline roughly once per second. Detectors without
     * time-based state may ignore this (default implementation is a no-op).
     *
     * @param now_ms  Current time in Unix milliseconds (UTC)
     */
    virtual void tick(int64_t now_ms) { (void)now_ms; }

    /**
     * @brief Clear all tracked state.
     *
     * Called when the engine restarts its pipeline (e.g. after a capture
     * stop/start cycle) so stale window state from the previous session
     * cannot produce false alerts.
     */
    virtual void reset() {}

    // Non-copyable — detectors own state that must not be duplicated
    BaseDetector(const BaseDetector&)            = delete;
    BaseDetector& operator=(const BaseDetector&) = delete;

    // Movable (default)
    BaseDetector(BaseDetector&&)            = default;
    BaseDetector& operator=(BaseDetector&&) = default;
};

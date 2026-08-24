/**
 * @file    AlertEmitter.h
 * @brief   Serializes Alerts to JSON and delivers them to the backend.
 *
 * The AlertEmitter is the single output point of the engine. Every
 * detector's alert flows through here before reaching the Node.js
 * backend, which stores it in MongoDB and broadcasts it over WebSocket.
 *
 * ── Output Modes ─────────────────────────────────────────────────────────
 *
 *  STDOUT       → newline-delimited JSON (NDJSON) on stdout.
 *                 Used in development and by the `--replay` demo mode.
 *                 Pipe into the backend:  sentinelx | backend-ingest
 *
 *  UNIX_SOCKET  → a persistent stream connection to the backend's
 *                 EngineIngestion service (default
 *                 /run/sentinelx/alerts.sock). Connection is lazy
 *                 (first emit) and auto-reconnects on the next emit after
 *                 a failure — if the backend restarts, the engine keeps
 *                 running and resumes delivery without a restart of its
 *                 own.
 *
 * ── Wire Format ──────────────────────────────────────────────────────────
 *
 * One JSON object per line (NDJSON). The emitter owns the serialization:
 *   - evidence fields that are empty/zero are OMITTED (the schema is
 *     self-describing; a PORT_SCAN alert doesn't carry http_* fields)
 *   - yara_match, when present, appears at the TOP LEVEL (per the alert
 *     schema in the README)
 *
 * The full JSON for an alert is produced by toJson(), which is also
 * exposed publicly so tests can validate the schema without a socket.
 *
 * @author  Ash
 * @project SentinelX
 */

#pragma once

#include <string>
#include <cstdint>

#include "Alert.h"


// ============================================================================
//  EMITTER
// ============================================================================

/**
 * @class AlertEmitter
 * @brief JSON serialization + delivery of alerts to the backend.
 *
 * Usage:
 * @code
 *   AlertEmitter emitter(AlertEmitter::Mode::UNIX_SOCKET,
 *                        "/run/sentinelx/alerts.sock");
 *
 *   for (auto& alert : detector.process(...)) {
 *       if (!emitter.emit(alert)) {
 *           // delivery failed — it will retry on the next emit
 *       }
 *   }
 * @endcode
 *
 * Threading: one emitter per pipeline thread. Not thread-safe.
 */
class AlertEmitter {
public:

    /// Where alerts are delivered.
    enum class Mode {
        STDOUT,      ///< NDJSON on stdout
        UNIX_SOCKET  ///< stream connection to the backend
    };

    /**
     * @brief Construct an emitter.
     * @param mode    Output mode
     * @param target  For UNIX_SOCKET: the socket path. Ignored for STDOUT.
     */
    AlertEmitter(Mode mode = Mode::STDOUT,
                 std::string target = "/run/sentinelx/alerts.sock");

    ~AlertEmitter();

    AlertEmitter(const AlertEmitter&)            = delete;
    AlertEmitter& operator=(const AlertEmitter&) = delete;

    /**
     * @brief Serialize and deliver one alert.
     *
     * In UNIX_SOCKET mode the connection is established lazily on first
     * use and re-established automatically after a failure (on the next
     * emit call).
     *
     * @param alert   The alert to deliver
     * @return        true if the alert was written to the output,
     *                false if delivery failed (will retry next call)
     */
    bool emit(const Alert& alert);

    // ── Diagnostics ─────────────────────────────────────────────────────

    uint64_t emittedCount() const { return m_emitted; }
    uint64_t failedCount()  const { return m_failed; }

    /// UNIX_SOCKET mode: true if currently connected.
    bool connected() const;

    const std::string& target() const { return m_target; }
    Mode mode() const { return m_mode; }

    // ── Serialization (public for testing) ──────────────────────────────

    /**
     * @brief Full JSON serialization of an alert (one line, no trailing
     *        newline).
     *
     * Omits empty evidence fields. Includes top-level yara_match when
     * present.
     */
    static std::string toJson(const Alert& alert);

private:

    /// Connect (or reconnect) the Unix socket. false on failure.
    bool connectSocket();

    /// Close the socket if open.
    void closeSocket();

    Mode        m_mode;
    std::string m_target;
    int         m_sock   = -1;
    uint64_t    m_emitted = 0;
    uint64_t    m_failed  = 0;
};

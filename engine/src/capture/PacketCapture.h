/**
 * @file    PacketCapture.h
 * @brief   Network packet capture interface using libpcap.
 *
 * PacketCapture is the entry point of all raw network data in SentinelX.
 * It opens a network interface in promiscuous mode, applies an optional
 * BPF (Berkeley Packet Filter) expression, and runs a capture loop that
 * dispatches raw packets to a user-supplied callback.
 *
 * All detectors, parsers, and alert logic are downstream of this module.
 * Nothing in the engine runs until PacketCapture delivers a packet.
 *
 * ── Promiscuous Mode ────────────────────────────────────────────────────
 * In normal mode, a NIC discards packets not addressed to it.
 * In promiscuous mode, it accepts ALL packets on the wire — including
 * traffic between other hosts on the same network segment. This is
 * required for a NIDS to see attacks targeting other machines.
 * Requires root privileges (CAP_NET_RAW on Linux).
 *
 * ── BPF Filters ─────────────────────────────────────────────────────────
 * Berkeley Packet Filter expressions are compiled into bytecode and run
 * in the kernel — packets that don't match are dropped before they ever
 * reach userspace. This dramatically reduces CPU load.
 * Example filters:
 *   "tcp"                   → only TCP packets
 *   "tcp or udp"            → TCP and UDP
 *   "not port 22"           → exclude SSH (avoid capturing your own session)
 *   "host 10.0.0.1"         → only packets to/from a specific host
 *   "tcp and port 80"       → only HTTP traffic
 *
 * ── Threading Model ─────────────────────────────────────────────────────
 * PacketCapture runs its capture loop on a dedicated background thread
 * (std::thread). The callback is invoked from that thread — if your
 * callback touches shared state, you are responsible for synchronization.
 * The main thread calls start() to launch the loop and stop() to
 * terminate it cleanly.
 *
 * ── Callback Design ─────────────────────────────────────────────────────
 * Rather than hardcoding what happens to each packet, PacketCapture
 * accepts a std::function callback (PacketHandler). This decouples
 * capture from processing — the engine can swap in different handlers
 * for live capture, PCAP file replay, or unit testing without changing
 * this class.
 *
 * ── libpcap Dependency ──────────────────────────────────────────────────
 * Requires libpcap-dev:
 *   sudo apt install libpcap-dev
 * Link with: -lpcap
 * Header: <pcap/pcap.h>
 *
 * @author  Ash
 * @project SentinelX
 */

#pragma once

#include <string>
#include <functional>
#include <thread>
#include <atomic>
#include <stdexcept>
#include <cstdint>

// libpcap — raw packet capture.
// Live capture requires libpcap-dev:  sudo apt install libpcap-dev
//
// The engine can also be built WITHOUT libpcap (SENTINELX_WITH_LIBPCAP
// undefined, see CMakeLists.txt). In that mode PacketCapture degrades to
// a stub that throws at construction — offline replay (PcapReplayer) and
// every other subsystem keep working.
#ifdef SENTINELX_WITH_LIBPCAP
#include <pcap/pcap.h>
using pcap_handle_t = pcap_t;
#else
struct pcap;        // opaque forward declaration — no libpcap needed
struct pcap_pkthdr; // (only referenced in the private static callback)
using pcap_handle_t = pcap;
#endif


// ============================================================================
//  RAW PACKET STRUCTURE
//  Wraps a single captured packet with its metadata.
//  Passed by const-ref to the PacketHandler callback.
// ============================================================================

/**
 * @struct RawPacket
 * @brief A single captured packet with metadata from libpcap.
 *
 * This is the raw, uninterpreted packet — just bytes and metadata.
 * Parsers (IPParser, TCPParser, HTTPParser) consume RawPacket and
 * produce structured protocol data from it.
 *
 * Fields:
 *  data            → Pointer to raw packet bytes.
 *                    Points into libpcap's internal buffer — valid ONLY
 *                    for the duration of the callback. If you need the
 *                    data after the callback returns, copy it:
 *                      std::vector<uint8_t> copy(pkt.data, pkt.data + pkt.capture_length);
 *
 *  capture_length  → Number of bytes actually captured (may be < wire_length
 *                    if the packet was truncated by the snaplen setting).
 *
 *  wire_length     → Actual length of the packet on the wire in bytes.
 *                    If capture_length < wire_length, the packet was truncated.
 *
 *  timestamp_sec   → Capture timestamp — seconds since Unix epoch (UTC).
 *
 *  timestamp_usec  → Microsecond component of the capture timestamp.
 *                    Full timestamp = timestamp_sec + timestamp_usec / 1e6
 *
 * Note on truncation:
 *  libpcap captures up to `snaplen` bytes per packet (default: 65535).
 *  For most protocols this is sufficient. If wire_length > capture_length,
 *  parsers must handle partial data gracefully — never assume full payload.
 */
struct RawPacket {
    const uint8_t* data           = nullptr;
    uint32_t       capture_length = 0;
    uint32_t       wire_length    = 0;
    uint32_t       timestamp_sec  = 0;
    uint32_t       timestamp_usec = 0;
};

/**
 * @typedef PacketHandler
 * @brief Callback type invoked for each captured packet.
 *
 * Signature: void handler(const RawPacket& packet)
 *
 * The handler is called from the capture thread — one invocation per packet.
 * Keep the handler fast: heavy processing should be pushed to a work queue.
 * Do NOT store the RawPacket::data pointer — it is invalidated after return.
 */
using PacketHandler = std::function<void(const RawPacket&)>;


// ============================================================================
//  CAPTURE CONFIGURATION
// ============================================================================

/**
 * @struct CaptureConfig
 * @brief Configuration parameters for PacketCapture.
 *
 * Pass to PacketCapture constructor. Immutable after construction.
 *
 * Fields:
 *  interface       → Network interface name to capture on.
 *                    Examples: "eth0", "wlan0", "ens33", "any"
 *                    Use "any" to capture on all interfaces (Linux only).
 *                    Use pcap_findalldevs() to enumerate available interfaces.
 *
 *  bpf_filter      → BPF filter expression string (empty = capture all).
 *                    Compiled to kernel bytecode — filtering happens before
 *                    packets reach userspace, so this is very efficient.
 *                    Example: "tcp or udp"
 *
 *  snaplen         → Maximum bytes captured per packet.
 *                    65535 captures full packets for all practical purposes.
 *                    Lower values reduce memory usage but may truncate payloads.
 *                    Default: 65535
 *
 *  promiscuous     → Enable promiscuous mode (capture all traffic, not just
 *                    traffic addressed to this host).
 *                    Requires root / CAP_NET_RAW.
 *                    Default: true (required for a NIDS)
 *
 *  timeout_ms      → Read timeout in milliseconds.
 *                    libpcap buffers packets and delivers them in batches.
 *                    This controls how long pcap_dispatch blocks before
 *                    returning even if no packets arrived.
 *                    1000ms is a good default — short enough for responsive
 *                    shutdown, long enough to avoid busy-waiting.
 *                    Default: 1000
 */
struct CaptureConfig {
    std::string interface    = "eth0";
    std::string bpf_filter   = "tcp or udp";
    int         snaplen      = 65535;
    bool        promiscuous  = true;
    int         timeout_ms   = 1000;
};


// ============================================================================
//  CAPTURE STATISTICS
// ============================================================================

/**
 * @struct CaptureStats
 * @brief Runtime statistics from the capture session.
 *
 * Retrieved via PacketCapture::getStats().
 * All counters are uint64_t to handle long-running captures without overflow.
 *
 * Fields:
 *  packets_received  → Total packets received by libpcap from the interface.
 *  packets_dropped   → Packets dropped by the kernel because the libpcap
 *                      buffer was full. Non-zero means the engine is falling
 *                      behind — reduce processing time or increase buffer size.
 *  packets_if_dropped→ Packets dropped by the network interface driver
 *                      before they reached libpcap. Hardware-level drops.
 *  packets_processed → Packets actually delivered to our PacketHandler.
 *                      Should equal packets_received - packets_dropped.
 */
struct CaptureStats {
    uint64_t packets_received   = 0;
    uint64_t packets_dropped    = 0;
    uint64_t packets_if_dropped = 0;
    uint64_t packets_processed  = 0;
};


// ============================================================================
//  PACKETCAPTURE CLASS
// ============================================================================

/**
 * @class PacketCapture
 * @brief Manages a libpcap capture session on a network interface.
 *
 * Usage:
 * @code
 *   CaptureConfig config;
 *   config.interface  = "eth0";
 *   config.bpf_filter = "tcp or udp";
 *
 *   PacketCapture capture(config);
 *
 *   capture.start([](const RawPacket& pkt) {
 *       // process packet — runs on capture thread
 *       std::cout << "Captured " << pkt.capture_length << " bytes\n";
 *   });
 *
 *   // ... main thread does other work ...
 *
 *   capture.stop();  // signals capture thread to exit cleanly
 * @endcode
 *
 * Error handling:
 *   Constructor throws std::runtime_error if the interface cannot be opened.
 *   This is intentional — a NIDS that can't open its capture interface
 *   should fail loudly at startup, not silently do nothing.
 *
 * Ownership:
 *   PacketCapture owns the pcap_t handle and the capture thread.
 *   Non-copyable (copy would duplicate the handle — undefined behavior).
 *   Movable (transfer ownership to another instance).
 */
class PacketCapture {
public:

    // ────────────────────────────────────────────────────────────────────
    //  CONSTRUCTION / DESTRUCTION
    // ────────────────────────────────────────────────────────────────────

    /**
     * @brief Construct and initialize a PacketCapture instance.
     *
     * Opens the network interface, sets promiscuous mode, activates the
     * capture handle, and compiles + applies the BPF filter.
     *
     * Does NOT start the capture loop — call start() for that.
     *
     * @param config    CaptureConfig specifying interface, filter, etc.
     * @throws std::runtime_error if:
     *   - The interface does not exist
     *   - Permission denied (not running as root)
     *   - BPF filter expression is invalid
     *   - libpcap handle activation fails for any reason
     */
    explicit PacketCapture(const CaptureConfig& config);

    /**
     * @brief Destructor. Stops the capture loop and releases resources.
     *
     * Calls stop() if the loop is running, then closes the pcap handle.
     * Safe to call even if start() was never called.
     */
    ~PacketCapture();

    // Non-copyable — pcap_t handles cannot be duplicated
    PacketCapture(const PacketCapture&)            = delete;
    PacketCapture& operator=(const PacketCapture&) = delete;

    // Movable
    PacketCapture(PacketCapture&&)            = default;
    PacketCapture& operator=(PacketCapture&&) = default;


    // ────────────────────────────────────────────────────────────────────
    //  CAPTURE CONTROL
    // ────────────────────────────────────────────────────────────────────

    /**
     * @brief Start the capture loop on a background thread.
     *
     * Launches a std::thread that runs pcap_dispatch in a loop.
     * The provided handler is called once per captured packet.
     *
     * Returns immediately — the capture runs in the background.
     * Call stop() to terminate the loop and join the thread.
     *
     * @param handler   Callback invoked for each captured packet.
     *                  Called from the capture thread — synchronize shared
     *                  state if needed.
     * @throws std::runtime_error if start() has already been called
     *         without a subsequent stop().
     */
    void start(PacketHandler handler);

    /**
     * @brief Stop the capture loop and join the background thread.
     *
     * Sets the running flag to false, which causes the capture loop
     * to exit on its next iteration (within timeout_ms milliseconds).
     * Blocks until the capture thread has fully exited.
     *
     * Safe to call multiple times — subsequent calls are no-ops.
     */
    void stop();

    /**
     * @brief Check whether the capture loop is currently running.
     * @return true if the loop is active, false otherwise.
     */
    bool isRunning() const;


    // ────────────────────────────────────────────────────────────────────
    //  DIAGNOSTICS
    // ────────────────────────────────────────────────────────────────────

    /**
     * @brief Retrieve current capture statistics from libpcap.
     *
     * Queries pcap_stats() and returns a CaptureStats struct.
     * Check packets_dropped — if non-zero, the engine is falling behind
     * and you may be missing attacks.
     *
     * @return CaptureStats with current counters.
     * @throws std::runtime_error if called before start() or after stop().
     */
    CaptureStats getStats() const;

    /**
     * @brief Get the network interface name this instance is capturing on.
     * @return Interface name string, e.g. "eth0"
     */
    const std::string& getInterface() const;

    /**
     * @brief Get the active BPF filter expression.
     * @return BPF filter string, or empty string if none was set.
     */
    const std::string& getFilter() const;

    /**
     * @brief List all available network interfaces on this system.
     *
     * Static utility — can be called without constructing a PacketCapture.
     * Useful for startup validation or CLI interface selection.
     *
     * @return Vector of interface name strings.
     * @throws std::runtime_error if pcap_findalldevs() fails.
     */
    static std::vector<std::string> listInterfaces();


private:
    // ────────────────────────────────────────────────────────────────────
    //  PRIVATE MEMBERS
    // ────────────────────────────────────────────────────────────────────

    CaptureConfig        m_config;          // immutable capture configuration
    pcap_handle_t*       m_handle;          // libpcap session handle
    std::thread          m_thread;          // background capture thread
    std::atomic<bool>    m_running;         // loop control flag (thread-safe)
    PacketHandler        m_handler;         // user-supplied packet callback
    uint64_t             m_packets_processed; // local counter

    // ────────────────────────────────────────────────────────────────────
    //  PRIVATE METHODS
    // ────────────────────────────────────────────────────────────────────

    /**
     * @brief The capture loop body — runs on the background thread.
     *
     * Calls pcap_dispatch() in a loop until m_running is false.
     * pcap_dispatch blocks for up to timeout_ms, then returns even if
     * no packets arrived — this is what makes stop() responsive.
     */
    void captureLoop();

    /**
     * @brief Static libpcap callback — bridge between C API and C++ method.
     *
     * libpcap's pcap_dispatch requires a C-style function pointer callback.
     * We pass `this` as the user data pointer and dispatch to the member
     * handler from here.
     *
     * @param user      User data pointer — cast to PacketCapture*
     * @param header    libpcap packet header (timestamp, lengths)
     * @param data      Raw packet bytes
     */
    static void pcapCallback(uint8_t* user,
                             const struct pcap_pkthdr* header,
                             const uint8_t* data);

    /**
     * @brief Open and activate the pcap handle for the configured interface.
     *
     * Called from constructor. Uses the modern pcap_create/pcap_activate
     * API (preferred over the legacy pcap_open_live for better error
     * reporting and configuration control).
     *
     * @throws std::runtime_error on any failure.
     */
    void openInterface();

    /**
     * @brief Compile and apply the BPF filter expression.
     *
     * Called from constructor after openInterface() succeeds.
     * No-op if m_config.bpf_filter is empty.
     *
     * @throws std::runtime_error if the filter expression is invalid.
     */
    void applyFilter();
};

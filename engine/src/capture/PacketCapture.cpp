/**
 * @file    PacketCapture.cpp
 * @brief   Implementation of the PacketCapture class.
 *
 * See PacketCapture.h for full documentation of the public interface.
 *
 * Key implementation notes:
 *
 * ── pcap_create vs pcap_open_live ───────────────────────────────────────
 * We use the modern pcap_create() + pcap_set_*() + pcap_activate() API
 * instead of the legacy pcap_open_live(). The modern API gives us:
 *   - Separate error reporting for each configuration step
 *   - Ability to set buffer size (pcap_set_buffer_size)
 *   - Immediate mode support (pcap_set_immediate_mode) — delivers packets
 *     to userspace immediately without waiting to fill a buffer.
 *     Useful for low-latency detection.
 *
 * ── pcap_dispatch vs pcap_loop ──────────────────────────────────────────
 * We use pcap_dispatch() instead of pcap_loop() because:
 *   - pcap_dispatch() returns after processing a batch (or after timeout)
 *     even if no packets arrived. This lets our loop check m_running and
 *     exit cleanly when stop() is called.
 *   - pcap_loop() only returns when pcap_breakloop() is called. While
 *     that works too, pcap_dispatch in a loop is more idiomatic and gives
 *     finer control over batching behavior.
 *
 * ── The C callback bridge ───────────────────────────────────────────────
 * libpcap's pcap_dispatch requires a C-style function pointer:
 *   typedef void (*pcap_handler)(u_char*, const struct pcap_pkthdr*, const u_char*)
 * C++ member functions can't be used directly because they have an implicit
 * `this` parameter. The standard pattern is:
 *   1. Pass `this` as the `user` (u_char*) argument to pcap_dispatch.
 *   2. In the static callback, cast user back to PacketCapture* and call
 *      the member handler.
 * This is safe as long as the PacketCapture instance outlives the callback.
 *
 * @author  Ash
 * @project SentinelX
 */

#include "PacketCapture.h"

#include <iostream>
#include <sstream>
#include <stdexcept>
#include <vector>
#include <cstring>

#ifdef SENTINELX_WITH_LIBPCAP
// libpcap
#include <pcap/pcap.h>
#endif


#ifdef SENTINELX_WITH_LIBPCAP

// ============================================================================
//  CONSTRUCTOR
// ============================================================================

/**
 * Initializes the capture handle but does NOT start the capture loop.
 *
 * Steps:
 *  1. Store config
 *  2. Open the interface (pcap_create + configure + activate)
 *  3. Apply BPF filter if specified
 *  4. Initialize counters
 */
PacketCapture::PacketCapture(const CaptureConfig& config)
    : m_config(config)
    , m_handle(nullptr)
    , m_running(false)
    , m_packets_processed(0)
{
    openInterface();
    applyFilter();

    std::cout << "[PacketCapture] Initialized on interface: "
              << m_config.interface << "\n";

    if (!m_config.bpf_filter.empty()) {
        std::cout << "[PacketCapture] BPF filter: \""
                  << m_config.bpf_filter << "\"\n";
    } else {
        std::cout << "[PacketCapture] No BPF filter — capturing all traffic\n";
    }

    std::cout << "[PacketCapture] Promiscuous mode: "
              << (m_config.promiscuous ? "ON" : "OFF") << "\n";
    std::cout << "[PacketCapture] Snaplen: " << m_config.snaplen << " bytes\n";
}


// ============================================================================
//  DESTRUCTOR
// ============================================================================

/**
 * Stops the capture loop if running and closes the pcap handle.
 *
 * Explicit cleanup is important here — pcap_close() must be called
 * or the interface may remain in promiscuous mode until the OS cleans up.
 */
PacketCapture::~PacketCapture() {
    stop();  // stops loop and joins thread (safe if not running)

    if (m_handle != nullptr) {
        pcap_close(m_handle);
        m_handle = nullptr;
        std::cout << "[PacketCapture] Handle closed for interface: "
                  << m_config.interface << "\n";
    }
}


// ============================================================================
//  PUBLIC: START
// ============================================================================

/**
 * Launches the capture loop on a background std::thread.
 *
 * The handler lambda is stored in m_handler and invoked from the
 * capture thread via pcapCallback → captureLoop.
 *
 * We store the handler before setting m_running = true to avoid
 * a race where the thread starts and tries to call an empty handler.
 */
void PacketCapture::start(PacketHandler handler) {
    if (m_running.load()) {
        throw std::runtime_error(
            "[PacketCapture] start() called while already running. "
            "Call stop() first."
        );
    }

    if (!handler) {
        throw std::runtime_error(
            "[PacketCapture] start() called with null handler."
        );
    }

    m_handler = std::move(handler);
    m_running.store(true);

    // Launch background capture thread
    // std::thread takes a callable — we pass a lambda that calls captureLoop()
    // on this instance. The thread runs until m_running is set to false.
    m_thread = std::thread([this]() {
        captureLoop();
    });

    std::cout << "[PacketCapture] Capture started on interface: "
              << m_config.interface << "\n";
}


// ============================================================================
//  PUBLIC: STOP
// ============================================================================

/**
 * Signals the capture loop to exit and waits for the thread to finish.
 *
 * m_running is std::atomic<bool> — the write here is visible to the
 * capture thread without explicit memory fences (sequential consistency
 * is the default for atomic operations in C++).
 *
 * After setting m_running = false, the loop will exit within timeout_ms
 * milliseconds (the maximum time pcap_dispatch blocks before returning).
 */
void PacketCapture::stop() {
    if (!m_running.load()) {
        return;  // already stopped — no-op
    }

    m_running.store(false);

    // pcap_breakloop() causes pcap_dispatch to return PCAP_ERROR_BREAK
    // on its next call even if the timeout hasn't expired.
    // This makes shutdown faster than waiting for the full timeout_ms.
    if (m_handle != nullptr) {
        pcap_breakloop(m_handle);
    }

    // Wait for the capture thread to finish
    if (m_thread.joinable()) {
        m_thread.join();
    }

    std::cout << "[PacketCapture] Capture stopped. Packets processed: "
              << m_packets_processed << "\n";
}


// ============================================================================
//  PUBLIC: STATUS / DIAGNOSTICS
// ============================================================================

bool PacketCapture::isRunning() const {
    return m_running.load();
}

const std::string& PacketCapture::getInterface() const {
    return m_config.interface;
}

const std::string& PacketCapture::getFilter() const {
    return m_config.bpf_filter;
}

/**
 * Queries libpcap for kernel-level capture statistics.
 *
 * pcap_stats() fills a struct pcap_stat with:
 *  ps_recv   — packets received by the kernel filter
 *  ps_drop   — packets dropped because libpcap's buffer was full
 *  ps_ifdrop — packets dropped by the network interface driver
 *
 * These are cumulative since the session was opened.
 */
CaptureStats PacketCapture::getStats() const {
    if (m_handle == nullptr) {
        throw std::runtime_error(
            "[PacketCapture] getStats() called with no active handle."
        );
    }

    struct pcap_stat ps;
    if (pcap_stats(m_handle, &ps) != 0) {
        throw std::runtime_error(
            std::string("[PacketCapture] pcap_stats() failed: ")
            + pcap_geterr(m_handle)
        );
    }

    CaptureStats stats;
    stats.packets_received   = ps.ps_recv;
    stats.packets_dropped    = ps.ps_drop;
    stats.packets_if_dropped = ps.ps_ifdrop;
    stats.packets_processed  = m_packets_processed;
    return stats;
}

/**
 * Enumerates all available network interfaces using pcap_findalldevs().
 *
 * Returns a vector of interface name strings.
 * On Linux, typical interfaces: "eth0", "wlan0", "lo", "any"
 * On Kali in VirtualBox: often "eth0" or "ens33"
 */
std::vector<std::string> PacketCapture::listInterfaces() {
    pcap_if_t* devs     = nullptr;
    char       errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&devs, errbuf) != 0) {
        throw std::runtime_error(
            std::string("[PacketCapture] pcap_findalldevs() failed: ")
            + errbuf
        );
    }

    std::vector<std::string> interfaces;
    for (pcap_if_t* d = devs; d != nullptr; d = d->next) {
        if (d->name != nullptr) {
            interfaces.emplace_back(d->name);
        }
    }

    pcap_freealldevs(devs);
    return interfaces;
}


// ============================================================================
//  PRIVATE: OPEN INTERFACE
// ============================================================================

/**
 * Opens the network interface using the modern pcap_create/activate API.
 *
 * Step by step:
 *  1. pcap_create()          → allocates handle, does NOT open the interface
 *  2. pcap_set_snaplen()     → max bytes per packet
 *  3. pcap_set_promisc()     → promiscuous mode on/off
 *  4. pcap_set_timeout()     → read timeout in ms
 *  5. pcap_set_immediate_mode() → deliver packets immediately (low latency)
 *  6. pcap_activate()        → actually opens the interface
 *                              returns 0 on success, negative on error,
 *                              positive on warning (still works but degraded)
 *
 * Error buffer (errbuf):
 *  pcap_create fills errbuf on failure.
 *  pcap_activate returns a numeric code; use pcap_statustostr() for message.
 *
 * Warnings from pcap_activate (positive return values):
 *  PCAP_WARNING_PROMISC_NOTSUP → interface doesn't support promiscuous mode
 *  PCAP_WARNING               → generic warning
 *  We log these but don't throw — the session is still usable.
 */
void PacketCapture::openInterface() {
    char errbuf[PCAP_ERRBUF_SIZE];
    errbuf[0] = '\0';

    // Step 1: Create handle (does not open the interface yet)
    m_handle = pcap_create(m_config.interface.c_str(), errbuf);
    if (m_handle == nullptr) {
        throw std::runtime_error(
            "[PacketCapture] pcap_create() failed for interface '"
            + m_config.interface + "': " + errbuf
        );
    }

    // Step 2: Set snaplen — max bytes captured per packet
    // 65535 is sufficient to capture full packets for all practical MTUs.
    // Jumbo frames (9000 bytes) and standard Ethernet (1500 bytes) both fit.
    if (pcap_set_snaplen(m_handle, m_config.snaplen) != 0) {
        pcap_close(m_handle);
        throw std::runtime_error(
            "[PacketCapture] pcap_set_snaplen() failed: "
            + std::string(pcap_geterr(m_handle))
        );
    }

    // Step 3: Promiscuous mode
    // 1 = enable, 0 = disable
    if (pcap_set_promisc(m_handle, m_config.promiscuous ? 1 : 0) != 0) {
        pcap_close(m_handle);
        throw std::runtime_error(
            "[PacketCapture] pcap_set_promisc() failed: "
            + std::string(pcap_geterr(m_handle))
        );
    }

    // Step 4: Read timeout
    // Controls how long pcap_dispatch blocks when no packets arrive.
    // Shorter = more responsive shutdown, higher CPU polling overhead.
    // 1000ms is a good balance for a NIDS.
    if (pcap_set_timeout(m_handle, m_config.timeout_ms) != 0) {
        pcap_close(m_handle);
        throw std::runtime_error(
            "[PacketCapture] pcap_set_timeout() failed: "
            + std::string(pcap_geterr(m_handle))
        );
    }

    // Step 5: Immediate mode — deliver packets to userspace without buffering
    // Without this, libpcap may hold packets in kernel buffer until the
    // timeout expires even if we have data ready. For a NIDS, we want
    // packets delivered as fast as possible for low-latency detection.
    if (pcap_set_immediate_mode(m_handle, 1) != 0) {
        // Not a fatal error — some older libpcap versions don't support this.
        // Log and continue.
        std::cerr << "[PacketCapture] WARNING: pcap_set_immediate_mode() "
                     "failed — falling back to buffered mode\n";
    }

    // Step 6: Activate the handle — actually opens the interface
    int activate_result = pcap_activate(m_handle);

    if (activate_result < 0) {
        // Negative return = error, session is unusable
        std::string errmsg = pcap_statustostr(activate_result);
        pcap_close(m_handle);
        m_handle = nullptr;
        throw std::runtime_error(
            "[PacketCapture] pcap_activate() failed on interface '"
            + m_config.interface + "': " + errmsg
            + "\n  Hint: Are you running as root? (sudo ./sentinelx)"
        );
    } else if (activate_result > 0) {
        // Positive return = warning, session may be degraded but still works
        std::cerr << "[PacketCapture] WARNING from pcap_activate(): "
                  << pcap_statustostr(activate_result) << "\n";
    }

    // Verify link-layer type
    // DLT_EN10MB = standard Ethernet (most common)
    // DLT_LINUX_SLL = Linux cooked sockets (used by "any" interface)
    int datalink = pcap_datalink(m_handle);
    std::cout << "[PacketCapture] Link-layer type: "
              << pcap_datalink_val_to_name(datalink)
              << " (" << datalink << ")\n";

    // Warn if not Ethernet — parsers currently assume Ethernet frames
    if (datalink != DLT_EN10MB && datalink != DLT_LINUX_SLL) {
        std::cerr << "[PacketCapture] WARNING: Unexpected link-layer type. "
                     "Parsers are optimized for Ethernet (DLT_EN10MB). "
                     "Non-Ethernet traffic may be parsed incorrectly.\n";
    }
}


// ============================================================================
//  PRIVATE: APPLY BPF FILTER
// ============================================================================

/**
 * Compiles and installs a BPF filter on the capture handle.
 *
 * BPF filter compilation:
 *  pcap_compile() takes the human-readable filter string (e.g. "tcp or udp")
 *  and compiles it into a bpf_program (kernel bytecode). The optimize flag
 *  (1) enables the BPF optimizer — always use it in production.
 *
 *  The netmask parameter to pcap_compile() is used only for filters with
 *  the 'broadcast' keyword. PCAP_NETMASK_UNKNOWN is safe for all other filters.
 *
 * pcap_setfilter() installs the compiled program into the kernel.
 * pcap_freecode() frees the compiled bytecode after installation
 * (the kernel has its own copy).
 */
void PacketCapture::applyFilter() {
    // No filter specified — capture everything
    if (m_config.bpf_filter.empty()) {
        return;
    }

    struct bpf_program fp;

    // Compile the filter expression to BPF bytecode
    // Arguments:
    //   m_handle                → the active pcap session
    //   &fp                     → output: compiled BPF program
    //   bpf_filter.c_str()      → the filter expression string
    //   1                       → optimize = true (always enable)
    //   PCAP_NETMASK_UNKNOWN    → netmask (only needed for 'broadcast' filters)
    if (pcap_compile(m_handle,
                     &fp,
                     m_config.bpf_filter.c_str(),
                     1,                       // optimize
                     PCAP_NETMASK_UNKNOWN) != 0)
    {
        throw std::runtime_error(
            "[PacketCapture] BPF filter compile failed for expression \""
            + m_config.bpf_filter + "\": "
            + pcap_geterr(m_handle)
        );
    }

    // Install the compiled filter
    if (pcap_setfilter(m_handle, &fp) != 0) {
        pcap_freecode(&fp);
        throw std::runtime_error(
            "[PacketCapture] pcap_setfilter() failed: "
            + std::string(pcap_geterr(m_handle))
        );
    }

    // Free the compiled bytecode — kernel has its own copy now
    pcap_freecode(&fp);

    std::cout << "[PacketCapture] BPF filter applied: \""
              << m_config.bpf_filter << "\"\n";
}


// ============================================================================
//  PRIVATE: CAPTURE LOOP
// ============================================================================

/**
 * The main capture loop — runs on the background thread.
 *
 * Uses pcap_dispatch() in a while loop:
 *
 *   pcap_dispatch(handle, count, callback, user)
 *     handle   → the active pcap session
 *     count    → max packets to process per call (-1 = process all in buffer)
 *               We use -1 to drain the buffer completely each iteration.
 *     callback → our static pcapCallback function
 *     user     → arbitrary pointer passed to callback — we pass `this`
 *
 *   Return values:
 *     > 0              → number of packets processed
 *     0                → timeout expired, no packets
 *     PCAP_ERROR_BREAK → pcap_breakloop() was called (stop() triggered)
 *     PCAP_ERROR       → fatal error
 *
 * The loop exits when:
 *   1. m_running is set to false by stop()
 *   2. pcap_dispatch returns PCAP_ERROR_BREAK
 *   3. pcap_dispatch returns PCAP_ERROR (fatal — logged and exits)
 */
void PacketCapture::captureLoop() {
    std::cout << "[PacketCapture] Capture loop started (thread id: "
              << std::this_thread::get_id() << ")\n";

    while (m_running.load()) {

        // Process up to INT_MAX packets from the current buffer
        // Passes `this` as user data so pcapCallback can reach our handler
        int result = pcap_dispatch(
            m_handle,
            -1,                                         // drain buffer
            PacketCapture::pcapCallback,                // static C callback
            reinterpret_cast<uint8_t*>(this)            // user data = this
        );

        if (result == PCAP_ERROR_BREAK) {
            // pcap_breakloop() was called from stop() — clean exit
            std::cout << "[PacketCapture] pcap_breakloop() received — "
                         "exiting capture loop\n";
            break;
        }

        if (result == PCAP_ERROR) {
            // Fatal error from libpcap
            std::cerr << "[PacketCapture] FATAL: pcap_dispatch() error: "
                      << pcap_geterr(m_handle) << "\n";
            m_running.store(false);
            break;
        }

        // result == 0: timeout, no packets. Loop continues.
        // result > 0:  packets processed. Loop continues.
        // (packet count already incremented in pcapCallback)
    }

    std::cout << "[PacketCapture] Capture loop exited\n";
}


// ============================================================================
//  PRIVATE: PCAP CALLBACK (C API BRIDGE)
// ============================================================================

/**
 * Static callback — the bridge between libpcap's C API and our C++ handler.
 *
 * libpcap calls this function for every captured packet, passing:
 *   user   → the u_char* we passed to pcap_dispatch as user data.
 *             We cast this back to PacketCapture* to reach our instance.
 *   header → struct pcap_pkthdr with timestamp and length info.
 *   data   → raw packet bytes (valid only for the duration of this call).
 *
 * IMPORTANT: data is only valid during this callback invocation.
 * If the handler needs to retain the packet, it must copy the bytes.
 * We document this clearly in RawPacket::data.
 *
 * We build a RawPacket from the libpcap header + data pointer and
 * call the user-supplied handler. The handler is std::function, so it
 * can be a lambda, member function, or free function.
 */
void PacketCapture::pcapCallback(uint8_t* user,
                                  const struct pcap_pkthdr* header,
                                  const uint8_t* data)
{
    // Cast user data back to our instance
    PacketCapture* self = reinterpret_cast<PacketCapture*>(user);

    if (self == nullptr || !self->m_running.load()) {
        return;
    }

    // Build a RawPacket view over the libpcap buffer
    RawPacket pkt;
    pkt.data           = data;
    pkt.capture_length = header->caplen;
    pkt.wire_length    = header->len;
    pkt.timestamp_sec  = static_cast<uint32_t>(header->ts.tv_sec);
    pkt.timestamp_usec = static_cast<uint32_t>(header->ts.tv_usec);

    // Increment our local packet counter
    ++self->m_packets_processed;

    // Invoke the user-supplied handler
    // Any exception thrown by the handler is caught here to prevent
    // crashing the capture thread — we log it and continue.
    try {
        self->m_handler(pkt);
    } catch (const std::exception& e) {
        std::cerr << "[PacketCapture] Exception in packet handler: "
                  << e.what() << "\n";
    } catch (...) {
        std::cerr << "[PacketCapture] Unknown exception in packet handler\n";
    }
}

#else  // !SENTINELX_WITH_LIBPCAP — minimal build without libpcap

// ============================================================================
//  NO-LIBPCAP STUBS
//  Live capture is unavailable in this build. The constructors throw so the
//  engine fails loudly at startup (a NIDS that can't capture must not
//  pretend to). Offline replay (PcapReplayer) is unaffected and fully
//  functional — it never touches PacketCapture.
// ============================================================================

PacketCapture::PacketCapture(const CaptureConfig& config)
    : m_config(config)
    , m_handle(nullptr)
    , m_running(false)
    , m_packets_processed(0) {
    throw std::runtime_error(
        "[PacketCapture] This SentinelX build has no libpcap support — "
        "live capture is unavailable. Use --replay <file.pcap> for offline "
        "analysis, or rebuild with libpcap-dev installed "
        "(see engine/CMakeLists.txt).");
}

PacketCapture::~PacketCapture() {
    // Nothing to close — no handle was ever created.
}

void PacketCapture::start(PacketHandler handler) {
    (void)handler;
    throw std::runtime_error(
        "[PacketCapture] start() called but this build has no libpcap "
        "support.");
}

void PacketCapture::stop() {
    // No loop was ever started.
}

bool PacketCapture::isRunning() const {
    return false;
}

CaptureStats PacketCapture::getStats() const {
    throw std::runtime_error(
        "[PacketCapture] getStats() unavailable — no libpcap build.");
}

const std::string& PacketCapture::getInterface() const {
    return m_config.interface;
}

const std::string& PacketCapture::getFilter() const {
    return m_config.bpf_filter;
}

std::vector<std::string> PacketCapture::listInterfaces() {
    return {};
}

void PacketCapture::openInterface() {}

void PacketCapture::applyFilter() {}

void PacketCapture::captureLoop() {}

void PacketCapture::pcapCallback(uint8_t* user,
                                 const struct pcap_pkthdr* header,
                                 const uint8_t* data) {
    (void)user;
    (void)header;
    (void)data;
}

#endif  // SENTINELX_WITH_LIBPCAP

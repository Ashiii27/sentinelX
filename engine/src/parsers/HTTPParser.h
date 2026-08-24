/**
 * @file    HTTPParser.h
 * @brief   HTTP/1.x request and response parser for SentinelX.
 *
 * HTTPParser operates on the TCP payload — the raw bytes that start after
 * the TCP header. It reconstructs HTTP requests and responses from those
 * bytes and extracts fields useful for anomaly detection.
 *
 * ── Scope ────────────────────────────────────────────────────────────────
 * SentinelX's HTTP parser is a *single-packet* parser — it processes
 * whatever HTTP data fits in one TCP segment. It does NOT do TCP stream
 * reassembly (that would require maintaining per-session state across
 * thousands of concurrent connections, which is v2 territory).
 *
 * In practice, HTTP requests almost always fit in a single TCP segment
 * (request line + headers = typically < 1500 bytes = 1 MTU). Large
 * responses with bodies may be split, but we only need headers for
 * anomaly detection anyway.
 *
 * ── What We're Looking For ───────────────────────────────────────────────
 * HTTPAnomalyDetector uses the parsed result to flag:
 *
 *  1. Path traversal:     path contains "../../", "%2e%2e/", etc.
 *  2. Scanner User-Agent: known strings like "nmap", "nikto", "sqlmap",
 *                         "masscan", "zgrab", "nuclei"
 *  3. Unusual HTTP verbs: CONNECT, TRACE, TRACK outside expected contexts
 *  4. Oversized headers:  single header value > 8KB (buffer overflow probe)
 *  5. SQLi in path/query: ' OR 1=1, UNION SELECT, etc.
 *  6. Null bytes in path: %00 or literal null — WAF/IDS evasion attempt
 *
 * ── HTTP/1.x Request Format ──────────────────────────────────────────────
 *
 *   GET /index.html HTTP/1.1\r\n         ← Request line
 *   Host: example.com\r\n                ← Headers
 *   User-Agent: Mozilla/5.0\r\n
 *   Accept: text/html\r\n
 *   \r\n                                 ← Empty line = end of headers
 *   [optional body]
 *
 * ── HTTP/1.x Response Format ─────────────────────────────────────────────
 *
 *   HTTP/1.1 200 OK\r\n                  ← Status line
 *   Content-Type: text/html\r\n          ← Headers
 *   Content-Length: 1234\r\n
 *   \r\n                                 ← End of headers
 *   [body]
 *
 * @author  Ash
 * @project SentinelX
 */

#pragma once

#include <string>
#include <unordered_map>
#include <optional>
#include <cstdint>

#include "../capture/PacketCapture.h"   // RawPacket
#include "IPParser.h"                   // IPPacket
#include "TCPParser.h"                  // TCPPacket


// ============================================================================
//  WELL-KNOWN HTTP PORTS
// ============================================================================

constexpr uint16_t HTTP_PORT  = 80;
constexpr uint16_t HTTP_ALT   = 8080;
constexpr uint16_t HTTP_ALT2  = 8000;
constexpr uint16_t HTTPS_PORT = 443;


// ============================================================================
//  PARSED HTTP RESULT
// ============================================================================

/**
 * @enum HTTPMessageType
 * @brief Whether this is an HTTP request or response.
 */
enum class HTTPMessageType {
    UNKNOWN  = 0,
    REQUEST  = 1,
    RESPONSE = 2
};

/**
 * @struct HTTPPacket
 * @brief Parsed result from HTTP payload bytes.
 *
 * Produced by HTTPParser::parse(). Consumed by HTTPAnomalyDetector.
 *
 * For requests:
 *  method, path, query_string, http_version, headers, user_agent,
 *  host, content_type, content_length, body_preview
 *
 * For responses:
 *  status_code, status_message, http_version, headers,
 *  content_type, content_length, body_preview
 *
 * Fields present in both:
 *  message_type, headers (full header map), raw_first_line,
 *  is_truncated
 *
 * Fields:
 *  method          → HTTP verb: "GET", "POST", "HEAD", etc.
 *                    Empty for responses.
 *  path            → Request path without query string: "/admin/login"
 *  query_string    → Everything after '?' in the URL: "id=1' OR '1'='1"
 *  http_version    → "HTTP/1.0" or "HTTP/1.1"
 *  status_code     → Response status: 200, 404, 500, etc. (0 for requests)
 *  status_message  → Response reason phrase: "OK", "Not Found", etc.
 *  headers         → All headers as key→value map (lowercase keys)
 *  user_agent      → Shortcut to headers["user-agent"]
 *  host            → Shortcut to headers["host"]
 *  content_type    → Shortcut to headers["content-type"]
 *  content_length  → Parsed value of Content-Length header (-1 if absent)
 *  body_preview    → First 256 bytes of body (for YARA matching)
 *  raw_first_line  → Unparsed first line (for logging/fallback)
 *  is_truncated    → True if the packet appears to be a mid-stream fragment
 *                    (doesn't start with a valid HTTP method or "HTTP/")
 */
struct HTTPPacket {
    HTTPMessageType message_type    = HTTPMessageType::UNKNOWN;

    // Request fields
    std::string method;
    std::string path;
    std::string query_string;

    // Shared
    std::string http_version;
    std::unordered_map<std::string, std::string> headers;

    // Response fields
    int         status_code         = 0;
    std::string status_message;

    // Convenience shortcuts (populated from headers map)
    std::string user_agent;
    std::string host;
    std::string content_type;
    int64_t     content_length      = -1;

    // Payload
    std::string body_preview;       // first 256 bytes of body

    // Metadata
    std::string raw_first_line;     // unparsed first line
    bool        is_truncated        = false;
};


// ============================================================================
//  HTTP PARSER
// ============================================================================

/**
 * @class HTTPParser
 * @brief Parses HTTP/1.x requests and responses from TCP payload bytes.
 *
 * Stateless — all methods are static. No TCP reassembly.
 *
 * Usage:
 * @code
 *   auto ip  = IPParser::parse(raw_pkt);
 *   if (!ip) return;
 *
 *   auto tcp = TCPParser::parse(raw_pkt, *ip);
 *   if (!tcp || tcp->payload_length == 0) return;
 *
 *   auto http = HTTPParser::parse(raw_pkt, *tcp);
 *   if (!http) return;
 *
 *   if (http->message_type == HTTPMessageType::REQUEST) {
 *       std::cout << http->method << " " << http->path << "\n";
 *       std::cout << "User-Agent: " << http->user_agent << "\n";
 *   }
 * @endcode
 */
class HTTPParser {
public:

    /**
     * @brief Parse HTTP payload from a TCP segment.
     *
     * Attempts to parse the TCP payload as HTTP/1.x.
     * Returns std::nullopt if:
     *  - TCP payload is empty
     *  - Payload doesn't start with a recognized HTTP method or "HTTP/"
     *    (i.e., it's not the first segment of an HTTP message)
     *
     * @param pkt   Raw packet from libpcap
     * @param tcp   Parsed TCP result (provides payload_offset, payload_length)
     * @return      Populated HTTPPacket, or std::nullopt if not HTTP
     */
    static std::optional<HTTPPacket> parse(const RawPacket& pkt,
                                           const TCPPacket& tcp);

    /**
     * @brief Check if a port number is a well-known HTTP port.
     *
     * Detectors use this to decide whether to attempt HTTP parsing.
     * Avoids trying to parse SSH or SMTP traffic as HTTP.
     *
     * @param port  Port number to check
     * @return      true if port is 80, 8080, or 8000
     */
    static bool isHTTPPort(uint16_t port);

    /**
     * @brief Check if a User-Agent string matches known scanner signatures.
     *
     * Case-insensitive substring search against a hardcoded list of
     * scanner/tool User-Agent strings.
     *
     * Known signatures: nmap, nikto, sqlmap, masscan, zgrab, nuclei,
     * dirbuster, gobuster, wfuzz, burpsuite, hydra, metasploit, nessus,
     * openvas, python-requests (commonly used in scripts/scanners)
     *
     * @param user_agent    User-Agent header value
     * @return              true if a scanner signature is found
     */
    static bool isScannerUserAgent(const std::string& user_agent);

    /**
     * @brief Check if a URL path contains path traversal patterns.
     *
     * Detects both raw and URL-encoded variants:
     *  Raw:     ../  ..\ 
     *  Encoded: %2e%2e%2f  %2e%2e/  ..%2f  %252e (double-encoded)
     *
     * @param path  URL path string (decoded or raw)
     * @return      true if a traversal pattern is found
     */
    static bool hasPathTraversal(const std::string& path);

    /**
     * @brief Check if a string contains basic SQL injection patterns.
     *
     * Detects common SQLi patterns in query strings or POST bodies:
 *  - Quote + logic: ' OR, ' AND
 *  - Union-based:   UNION SELECT
 *  - Comment-based: --, #, C-style block comments
 *  - Stacked:       ; DROP, ; INSERT
     *
     * Note: This is a signature-based check, not a full parser.
     * False positives are possible for legitimate SQL in query strings.
     *
     * @param input  String to check (query string or body)
     * @return       true if SQLi pattern detected
     */
    static bool hasSQLInjection(const std::string& input);


private:
    /**
     * @brief Parse HTTP request line: "METHOD /path?query HTTP/1.1"
     * @param line      First line of the HTTP message
     * @param out       HTTPPacket to populate
     * @return          true if parsed successfully
     */
    static bool parseRequestLine(const std::string& line, HTTPPacket& out);

    /**
     * @brief Parse HTTP status line: "HTTP/1.1 200 OK"
     * @param line      First line of the HTTP message
     * @param out       HTTPPacket to populate
     * @return          true if parsed successfully
     */
    static bool parseStatusLine(const std::string& line, HTTPPacket& out);

    /**
     * @brief Parse HTTP headers into the headers map.
     *
     * Reads lines until an empty line (\r\n\r\n) or end of data.
     * Keys are lowercased for case-insensitive lookup.
     *
     * @param data      Pointer to start of headers section
     * @param length    Number of bytes available
     * @param out       HTTPPacket to populate (headers map + shortcuts)
     * @return          Byte offset past the end of the headers section
     *                  (where the body begins), or 0 if no header terminator found
     */
    static size_t parseHeaders(const char* data, size_t length, HTTPPacket& out);

    /**
     * @brief Lowercase a string in-place.
     * @param s     String to convert
     * @return      Lowercased copy
     */
    static std::string toLower(std::string s);
};
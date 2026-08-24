/**
 * @file    HTTPParser.cpp
 * @brief   Implementation of HTTPParser — HTTP/1.x parsing from TCP payloads.
 *
 * @author  Ash
 * @project SentinelX
 */

// memmem() is a POSIX.1-2008 / GNU extension; declare it before includes
// so the parser builds even without libpcap's headers pulling it in.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "HTTPParser.h"

#include <sstream>
#include <algorithm>
#include <cctype>
#include <cstring>


// ============================================================================
//  KNOWN HTTP METHODS
//  Used to identify whether the first line is a request line.
// ============================================================================

static const char* HTTP_METHODS[] = {
    "GET", "POST", "PUT", "DELETE", "HEAD",
    "OPTIONS", "PATCH", "CONNECT", "TRACE", "TRACK",
    nullptr     // sentinel
};

// ============================================================================
//  KNOWN SCANNER USER-AGENT SUBSTRINGS (lowercase for case-insensitive match)
// ============================================================================

static const char* SCANNER_UA_SIGNATURES[] = {
    "nmap", "nikto", "sqlmap", "masscan", "zgrab",
    "nuclei", "dirbuster", "gobuster", "wfuzz",
    "burpsuite", "burp suite", "hydra", "metasploit",
    "nessus", "openvas", "python-requests",
    "go-http-client",   // common in Go-based scanners
    "curl/",            // curl is often used in automated probing
    "libwww-perl",      // legacy scanner/script UA
    nullptr
};

// ============================================================================
//  PATH TRAVERSAL PATTERNS (raw and encoded)
// ============================================================================

static const char* TRAVERSAL_PATTERNS[] = {
    "../",      "..\\",         // raw traversal
    "%2e%2e%2f", "%2e%2e/",     // URL-encoded dots, raw slash
    "..%2f",    "..%5c",        // raw dots, encoded slash/backslash
    "%252e",                    // double-encoded dot (evasion)
    "/etc/passwd",              // direct target
    "/etc/shadow",
    "/proc/self",
    "\\windows\\system32",      // Windows targets
    nullptr
};

// ============================================================================
//  SQL INJECTION PATTERNS (lowercase for case-insensitive match)
// ============================================================================

static const char* SQLI_PATTERNS[] = {
    "' or ",    "' and ",       // classic logic injection
    "\" or ",   "\" and ",
    "union select",             // union-based extraction
    "union all select",
    "or 1=1",   "or '1'='1",   // tautology
    "drop table", "drop database",
    "; insert",  "; update",    // stacked queries
    "exec(",     "execute(",    // stored procedure execution
    "xp_cmdshell",              // MSSQL RCE
    "information_schema",       // schema enumeration
    nullptr
};


// ============================================================================
//  HTTPParser::parse
// ============================================================================

std::optional<HTTPPacket> HTTPParser::parse(const RawPacket& pkt,
                                             const TCPPacket& tcp) {

    // ── Empty payload check ──────────────────────────────────────────────
    if (tcp.payload_length == 0) {
        return std::nullopt;    // SYN/ACK/FIN — no payload
    }

    // ── Bounds check ─────────────────────────────────────────────────────
    if (tcp.payload_offset + tcp.payload_length > pkt.capture_length) {
        return std::nullopt;    // payload claims more bytes than we have
    }

    // ── Get payload as char pointer ───────────────────────────────────────
    const char* payload     = reinterpret_cast<const char*>(
        pkt.data + tcp.payload_offset
    );
    size_t payload_len      = tcp.payload_length;

    // ── Find end of first line ────────────────────────────────────────────
    // HTTP lines end with \r\n. Search for the first occurrence.
    const char* crlf = static_cast<const char*>(
        memmem(payload, payload_len, "\r\n", 2)
    );

    if (crlf == nullptr) {
        return std::nullopt;    // no line terminator — not HTTP
    }

    std::string first_line(payload, crlf - payload);

    // ── Determine message type ────────────────────────────────────────────
    // Requests start with an HTTP method: "GET ", "POST ", etc.
    // Responses start with HTTP version: "HTTP/1.0 ", "HTTP/1.1 "
    HTTPPacket result;
    result.raw_first_line = first_line;

    bool is_request  = false;
    bool is_response = false;

    // Check for response
    if (first_line.rfind("HTTP/", 0) == 0) {
        is_response = true;
    } else {
        // Check for request method
        for (int i = 0; HTTP_METHODS[i] != nullptr; ++i) {
            std::string prefix = std::string(HTTP_METHODS[i]) + " ";
            if (first_line.rfind(prefix, 0) == 0) {
                is_request = true;
                break;
            }
        }
    }

    if (!is_request && !is_response) {
        // Doesn't look like the start of an HTTP message
        // Likely mid-stream TCP segment — not parseable without reassembly
        return std::nullopt;
    }

    // ── Parse first line ──────────────────────────────────────────────────
    if (is_request) {
        result.message_type = HTTPMessageType::REQUEST;
        if (!parseRequestLine(first_line, result)) {
            return std::nullopt;
        }
    } else {
        result.message_type = HTTPMessageType::RESPONSE;
        if (!parseStatusLine(first_line, result)) {
            return std::nullopt;
        }
    }

    // ── Parse headers ─────────────────────────────────────────────────────
    // Headers start immediately after the first \r\n
    const char* headers_start   = crlf + 2;
    size_t      headers_avail   = payload_len - (headers_start - payload);

    size_t body_offset = parseHeaders(headers_start, headers_avail, result);

    // ── Extract body preview ──────────────────────────────────────────────
    // We grab up to 256 bytes of body for YARA scanning
    if (body_offset > 0 && body_offset < headers_avail) {
        const char* body_start  = headers_start + body_offset;
        size_t      body_avail  = headers_avail - body_offset;
        size_t      preview_len = std::min(body_avail, static_cast<size_t>(256));
        result.body_preview     = std::string(body_start, preview_len);
    }

    return result;
}


// ============================================================================
//  HTTPParser::parseRequestLine
// ============================================================================

/**
 * Parses: "GET /path?query HTTP/1.1"
 *
 * Robust split: the FIRST space ends the method, the LAST space ends the
 * protocol version; everything between is the URL target. Real-world
 * (and attacking) requests sometimes carry literal spaces inside the
 * URL — istringstream >> splitting would break those into 4+ tokens and
 * reject the line, so the target is allowed to contain spaces.
 *
 * Separates path from query string at the '?' character.
 */
bool HTTPParser::parseRequestLine(const std::string& line, HTTPPacket& out) {
    const size_t first_space = line.find(' ');
    if (first_space == std::string::npos || first_space == 0) {
        return false;
    }
    const size_t last_space = line.rfind(' ');
    if (last_space <= first_space) {
        return false;  // fewer than 3 tokens
    }

    const std::string method  = line.substr(0, first_space);
    const std::string url     =
        line.substr(first_space + 1, last_space - first_space - 1);
    const std::string version = line.substr(last_space + 1);

    if (url.empty() || version.empty()) {
        return false;
    }

    out.method       = method;
    out.http_version = version;

    // Split URL into path and query string
    auto q_pos = url.find('?');
    if (q_pos != std::string::npos) {
        out.path         = url.substr(0, q_pos);
        out.query_string = url.substr(q_pos + 1);
    } else {
        out.path = url;
    }

    return true;
}


// ============================================================================
//  HTTPParser::parseStatusLine
// ============================================================================

/**
 * Parses: "HTTP/1.1 200 OK"
 *         "HTTP/1.0 404 Not Found"
 *
 * Splits on spaces:
 *   token[0] = HTTP version
 *   token[1] = status code (integer)
 *   token[2..] = reason phrase (may contain spaces — "Not Found", "Internal Server Error")
 */
bool HTTPParser::parseStatusLine(const std::string& line, HTTPPacket& out) {
    std::istringstream iss(line);
    std::string version, code_str, reason;

    if (!(iss >> version >> code_str)) {
        return false;
    }

    // Parse status code
    try {
        out.status_code = std::stoi(code_str);
    } catch (...) {
        return false;   // non-numeric status code
    }

    out.http_version = version;

    // Reason phrase is the rest of the line after the status code
    std::getline(iss, reason);
    // Trim leading space
    if (!reason.empty() && reason[0] == ' ') {
        reason = reason.substr(1);
    }
    out.status_message = reason;

    return true;
}


// ============================================================================
//  HTTPParser::parseHeaders
// ============================================================================

/**
 * Reads HTTP headers line by line until an empty line (\r\n\r\n).
 *
 * Each header line format: "Header-Name: value\r\n"
 * Keys are stored in lowercase for case-insensitive lookup.
 *
 * Returns the byte offset past the header terminator (\r\n\r\n),
 * which is where the body begins. Returns 0 if no terminator found.
 *
 * Special handling:
 *  - "user-agent" → also stored in out.user_agent
 *  - "host"       → also stored in out.host
 *  - "content-type" → also stored in out.content_type
 *  - "content-length" → parsed as int64 and stored in out.content_length
 */
size_t HTTPParser::parseHeaders(const char* data, size_t length,
                                 HTTPPacket& out) {
    size_t pos = 0;

    while (pos < length) {
        // Find end of this header line
        const char* line_start = data + pos;
        size_t      remaining  = length - pos;

        const char* crlf = static_cast<const char*>(
            memmem(line_start, remaining, "\r\n", 2)
        );

        if (crlf == nullptr) {
            // No more CRLF — headers might be truncated
            break;
        }

        size_t line_len = crlf - line_start;

        // Empty line = end of headers
        if (line_len == 0) {
            return pos + 2;     // +2 to skip the \r\n terminator
        }

        // Parse "Name: Value"
        std::string header_line(line_start, line_len);
        auto colon = header_line.find(':');

        if (colon != std::string::npos) {
            std::string key   = toLower(header_line.substr(0, colon));
            std::string value = header_line.substr(colon + 1);

            // Trim leading whitespace from value
            size_t val_start = value.find_first_not_of(" \t");
            if (val_start != std::string::npos) {
                value = value.substr(val_start);
            }

            out.headers[key] = value;

            // Populate convenience shortcuts
            if (key == "user-agent")     out.user_agent     = value;
            if (key == "host")           out.host           = value;
            if (key == "content-type")   out.content_type   = value;
            if (key == "content-length") {
                try {
                    out.content_length = std::stoll(value);
                } catch (...) {
                    out.content_length = -1;
                }
            }
        }

        pos += line_len + 2;    // +2 for \r\n
    }

    return 0;   // header terminator not found — truncated
}


// ============================================================================
//  HTTPParser::isHTTPPort
// ============================================================================

bool HTTPParser::isHTTPPort(uint16_t port) {
    return port == HTTP_PORT || port == HTTP_ALT || port == HTTP_ALT2;
}


// ============================================================================
//  HTTPParser::isScannerUserAgent
// ============================================================================

/**
 * Case-insensitive substring search.
 * Lowercases the input once, then checks all signatures.
 */
bool HTTPParser::isScannerUserAgent(const std::string& user_agent) {
    std::string lower_ua = toLower(user_agent);

    for (int i = 0; SCANNER_UA_SIGNATURES[i] != nullptr; ++i) {
        if (lower_ua.find(SCANNER_UA_SIGNATURES[i]) != std::string::npos) {
            return true;
        }
    }
    return false;
}


// ============================================================================
//  URL decoding (for signature matching)
// ============================================================================

/**
 * Minimal percent-decoding (%XX → byte, '+' → space) used for signature
 * matching. Encoded attack payloads (%27%20OR%201=1--) would otherwise
 * slip past plain-text patterns. Invalid sequences pass through unchanged;
 * this is NOT a general-purpose decoder (no charset handling).
 */
static std::string urlDecodeForMatch(const std::string& in) {
    auto hexval = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };

    std::string out;
    out.reserve(in.size());
    for (size_t i = 0; i < in.size(); ++i) {
        if (in[i] == '%' && i + 2 < in.size()) {
            const int hi = hexval(in[i + 1]);
            const int lo = hexval(in[i + 2]);
            if (hi >= 0 && lo >= 0) {
                out.push_back(static_cast<char>((hi << 4) | lo));
                i += 2;
                continue;
            }
        }
        out.push_back(in[i] == '+' ? ' ' : in[i]);
    }
    return out;
}


// ============================================================================
//  HTTPParser::hasPathTraversal
// ============================================================================

/**
 * Case-insensitive substring search against known traversal patterns.
 * Checks both the raw path and a lowercased version.
 */
bool HTTPParser::hasPathTraversal(const std::string& path) {
    std::string lower_path = toLower(path);

    for (int i = 0; TRAVERSAL_PATTERNS[i] != nullptr; ++i) {
        if (lower_path.find(TRAVERSAL_PATTERNS[i]) != std::string::npos) {
            return true;
        }
    }

    // One decoding pass catches doubly-encoded traversal
    // ("%252e%252e%252f" → "%2e%2e%2f" → "../").
    std::string decoded = toLower(urlDecodeForMatch(path));
    if (decoded != lower_path) {
        for (int i = 0; TRAVERSAL_PATTERNS[i] != nullptr; ++i) {
            if (decoded.find(TRAVERSAL_PATTERNS[i]) != std::string::npos) {
                return true;
            }
        }
    }
    return false;
}


// ============================================================================
//  HTTPParser::hasSQLInjection
// ============================================================================

/**
 * Case-insensitive substring search against common SQLi patterns.
 */
bool HTTPParser::hasSQLInjection(const std::string& input) {
    std::string lower_input = toLower(input);

    for (int i = 0; SQLI_PATTERNS[i] != nullptr; ++i) {
        if (lower_input.find(SQLI_PATTERNS[i]) != std::string::npos) {
            return true;
        }
    }

    // Encoded payloads: decode once and rescan ("%27%20OR%201=1--" →
    // "' or 1=1--"). Only re-scan when decoding actually changed the
    // string (avoids the copy cost for the common clean-traffic case).
    std::string decoded = toLower(urlDecodeForMatch(input));
    if (decoded != lower_input) {
        for (int i = 0; SQLI_PATTERNS[i] != nullptr; ++i) {
            if (decoded.find(SQLI_PATTERNS[i]) != std::string::npos) {
                return true;
            }
        }
    }
    return false;
}


// ============================================================================
//  HTTPParser::toLower
// ============================================================================

std::string HTTPParser::toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return s;
}
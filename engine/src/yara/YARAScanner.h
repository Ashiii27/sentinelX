/**
 * @file    YARAScanner.h
 * @brief   Signature-based payload scanning with libyara.
 *
 * YARAScanner loads a directory of YARA rule files (*.yar) and scans raw
 * packet payloads against them. Every match becomes a YARA_MATCH alert
 * carrying the rule name, source file, matched string identifiers, and
 * the SHA-256 of the scanned payload.
 *
 * ── Rule Metadata Contract ───────────────────────────────────────────────
 *
 * SentinelX reads three optional meta fields from each rule. They are
 * OPTIONAL — a rule without them still works and gets sensible defaults:
 *
 *   meta:
 *       severity = "HIGH"      // LOW | MEDIUM | HIGH | CRITICAL
 *                               // (default: HIGH)
 *       mitre    = "T1059"     // ATT&CK technique id the rule maps to
 *                               // (default: T1059, from the alert factory)
 *       mitre_name = "Command and Scripting Interpreter"
 *                               // (default: technique id)
 *       description = "..."    // human-readable rule purpose (evidence)
 *
 * This lets rule authors — who may not be C++ developers — control how a
 * match appears in the dashboard without touching engine code.
 *
 * ── Hot Reloading ────────────────────────────────────────────────────────
 *
 * reload() recompiles the rule set from disk and atomically swaps it in.
 * The engine's main loop checks for a reload request (set by a signal
 * handler or the backend's rules API) after every batch of packets, so a
 * rule update takes effect without restarting the engine.
 *
 * ── Build-Time Optional ──────────────────────────────────────────────────
 *
 * The engine can be built WITHOUT libyara (SENTINELX_WITH_YARA undefined).
 * In that mode loadRules() logs a warning and scan() returns no matches —
 * every other detector keeps working. CI uses this to test the non-YARA
 * code paths on hosts without the library.
 *
 * @author  Ash
 * @project SentinelX
 */

#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>

#include "../alerts/Alert.h"     // YaraMatch, Severity


#ifdef SENTINELX_WITH_YARA
#include <yara.h>
#endif


// ============================================================================
//  SCAN RESULT
// ============================================================================

/**
 * @struct YaraScanMatch
 * @brief One matched YARA rule for a scanned payload.
 *
 * Populated by YARAScanner::scan(). The pipeline wraps it in an
 * Alert (YARA_MATCH type) via makeYARAMatchAlert().
 */
struct YaraScanMatch {
    std::string              rule_name;       // YARA rule identifier
    std::string              rule_file;       // file the rule was loaded from
    std::vector<std::string> matched_strings; // $identifiers that matched
    std::string              description;     // meta: description (may be empty)

    // Meta-driven alert fields (parsed from rule meta)
    Severity    severity     = Severity::HIGH;
    std::string mitre_id;    // meta: mitre ("" → factory default T1059)
    std::string mitre_name;  // meta: mitre_name ("" → mitre_id)
};


// ============================================================================
//  SCANNER
// ============================================================================

/**
 * @class YARAScanner
 * @brief Loads YARA rules and scans payloads against them.
 *
 * Thread safety: a single pipeline thread owns the scanner. reload()
 * must not be called concurrently with scan().
 *
 * Usage:
 * @code
 *   YARAScanner yara;
 *   if (yara.loadRules("/etc/sentinelx/rules/")) {
 *       for (auto& m : yara.scan(payload.data(), payload.size())) {
 *           // build alert...
 *       }
 *   }
 * @endcode
 */
class YARAScanner {
public:

    YARAScanner() = default;
    ~YARAScanner();

    YARAScanner(const YARAScanner&)            = delete;
    YARAScanner& operator=(const YARAScanner&) = delete;

    /**
     * @brief Load (or reload) all *.yar files from a directory.
     *
     * Files are processed in sorted order (deterministic compile order).
     * A single file with a syntax error is SKIPPED with an error message
     * — the rest of the ruleset still loads. This matches operational
     * expectations: one bad rule pushed by an analyst should not take
     * down the whole engine.
     *
     * @param dir   Directory containing .yar / .yara files
     * @return      true if at least one rule loaded successfully
     */
    bool loadRules(const std::string& dir);

    /**
     * @brief Scan a memory buffer against the loaded rules.
     *
     * @param data  Pointer to the payload bytes
     * @param len   Payload length
     * @return      All matching rules (empty = no matches / no rules /
     *              YARA disabled at build time)
     */
    std::vector<YaraScanMatch> scan(const uint8_t* data, size_t len) const;

    // ── Diagnostics ─────────────────────────────────────────────────────

    /// True if YARA support was compiled in.
    static bool supported() {
#ifdef SENTINELX_WITH_YARA
        return true;
#else
        return false;
#endif
    }

    /// Total number of loaded rules.
    size_t ruleCount() const;

    /// List of loaded rule files (basenames), for the dashboard.
    std::vector<std::string> ruleFiles() const { return m_rule_files; }

    /// Number of payloads scanned since construction.
    uint64_t scannedCount() const { return m_scanned; }

    /// Number of matches found since construction.
    uint64_t matchesFound() const { return m_matches; }

    /// Directory the current rules were loaded from ("" if none).
    const std::string& rulesDir() const { return m_rules_dir; }

#ifdef SENTINELX_WITH_YARA
    // ── Per-rule meta info harvested at load time (severity/mitre/desc).
    //    Public (not a design choice — it is referenced by file-local
    //    compile helpers in the .cpp that are not member functions). ──
    struct RuleMeta {
        std::string severity;
        std::string mitre;
        std::string mitre_name;
        std::string description;
    };
#endif

private:

#ifdef SENTINELX_WITH_YARA
    // ── YARA 4.x scan callback: collect matches into the scan output ─────
    // Signature matches YR_CALLBACK_FUNC in <yara/libyara.h> (YARA >= 4.2):
    //   message_data is a YR_RULE* when message == CALLBACK_MSG_RULE_MATCHING.
    static int ruleCallback(YR_SCAN_CONTEXT* context,
                            int message,
                            void* message_data,
                            void* user_data);

    /// Per-scan accumulator passed to ruleCallback via the scanner's
    /// user_data pointer (re-pointed before every scan).
    struct ScanOut {
        std::vector<YaraScanMatch> matches;
        const std::unordered_map<std::string, std::string>* rule_to_file;
        const std::unordered_map<std::string, RuleMeta>*    meta;
    };

    void freeRuleset();
#endif

    std::string m_rules_dir;
    std::vector<std::string> m_rule_files;          // basenames, load order
    std::unordered_map<std::string, std::string> m_rule_to_file;  // name→file
    // mutable: diagnostic counters, incremented from const scan()
    mutable uint64_t m_scanned  = 0;
    mutable uint64_t m_matches  = 0;

#ifdef SENTINELX_WITH_YARA
    // One ruleset + scanner PER FILE: YARA's compiler does not reset its
    // error state between add_file() calls, so per-file compilation is
    // the only way to keep one bad file from sinking the whole ruleset.
    std::vector<YR_RULES*>   m_rulesets;
    std::vector<YR_SCANNER*> m_scanners;   // m_scanners[i] scans m_rulesets[i]
    std::unordered_map<std::string, RuleMeta> m_rule_meta;
#endif
};

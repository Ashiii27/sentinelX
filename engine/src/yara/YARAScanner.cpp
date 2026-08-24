/**
 * @file    YARAScanner.cpp
 * @brief   libyara integration: rule loading, scanning, meta harvesting.
 *
 * Uses the YARA 4.x C API (scanner-based):
 *   - yr_compiler_*               to compile *.yar files into one YR_RULES
 *   - yr_scanner_*                to run scans with a match callback
 *   - yr_rule_metas_foreach       to harvest severity / mitre meta per rule
 *
 * @author  Ash
 * @project SentinelX
 */

#include "YARAScanner.h"

#include <cstdio>
#include <cstring>
#include <algorithm>
#include <cctype>
#include <filesystem>

#include "../util/SHA256.h"


#ifdef SENTINELX_WITH_YARA

// ============================================================================
//  CONSTRUCTION / DESTRUCTION
// ============================================================================

YARAScanner::~YARAScanner() {
    freeRuleset();
}


void YARAScanner::freeRuleset() {
    for (YR_SCANNER* sc : m_scanners) {
        if (sc) yr_scanner_destroy(sc);
    }
    m_scanners.clear();
    for (YR_RULES* rs : m_rulesets) {
        if (rs) yr_rules_destroy(rs);
    }
    m_rulesets.clear();
    m_rule_meta.clear();
    m_rule_to_file.clear();
    m_rule_files.clear();
    m_rules_dir.clear();
}


// ============================================================================
//  RULE LOADING
// ============================================================================

/**
 * @brief Harvest meta (severity/mitre/description) from a compiled rule.
 */
static void harvestMeta(const YR_RULE* rule, YARAScanner::RuleMeta& out) {
    YR_META* meta;
    yr_rule_metas_foreach(rule, meta) {
        const std::string id = meta->identifier ? meta->identifier : "";
        if (meta->type != META_TYPE_STRING || !meta->string) {
            continue;
        }
        if (id == "severity") {
            out.severity = meta->string;
        } else if (id == "mitre") {
            out.mitre = meta->string;
        } else if (id == "mitre_name") {
            out.mitre_name = meta->string;
        } else if (id == "description") {
            out.description = meta->string;
        }
    }
}


namespace fs = std::filesystem;

/// YARA 4.2.x distro builds ship YR_CONFIG_MAX_STRINGS_PER_RULE
/// zero-initialized (observed: 'too many strings in rule (limit: 0)'
/// on every rule). Restore the upstream default once, lazily, on first
/// load.
static void ensureYaraConfig() {
    static bool done = false;
    if (done) {
        return;
    }
    done = true;

    uint32_t cur = 0;
    int rc = yr_get_configuration_uint32(YR_CONFIG_MAX_STRINGS_PER_RULE,
                                         &cur);
    if (rc != ERROR_SUCCESS || cur == 0) {
        yr_set_configuration_uint32(YR_CONFIG_MAX_STRINGS_PER_RULE,
                                    DEFAULT_MAX_STRINGS_PER_RULE);
    }

    uint32_t stack = 0;
    rc = yr_get_configuration_uint32(YR_CONFIG_STACK_SIZE, &stack);
    if (rc != ERROR_SUCCESS || stack == 0) {
        // A zeroed stack makes every scan fail with
        // ERROR_EXEC_STACK_OVERFLOW (25) immediately.
        yr_set_configuration_uint32(YR_CONFIG_STACK_SIZE,
                                    DEFAULT_STACK_SIZE);
    }
}


/// Fetch the compiler's last error message into a std::string.
static std::string compilerErrMsg(YR_COMPILER* compiler) {
    char buf[512] = {0};
    char* msg = yr_compiler_get_error_message(compiler, buf,
                                              static_cast<int>(sizeof(buf) - 1));
    return msg ? msg : "unknown error";
}

/**
 * @brief Compile ONE rules file into its own YR_RULES set.
 *
 * A dedicated compiler per file is REQUIRED: YARA's compiler does not
 * reset its error state between yr_compiler_add_file() calls (the
 * "compiler->errors == 0" assert in compiler.c proves it), so a single
 * bad file must be quarantined in its own compiler — the rest of the
 * ruleset directory still loads.
 *
 * @return true on success, *out_rules owns the ruleset
 */
static bool compileOneFile(const fs::path& file,
                           YR_RULES** out_rules,
                           std::string& error_out) {
    *out_rules = nullptr;

    FILE* fh = std::fopen(file.string().c_str(), "r");
    if (!fh) {
        error_out = "cannot open file";
        return false;
    }

    YR_COMPILER* compiler = nullptr;
    bool ok = false;

    if (yr_compiler_create(&compiler) == ERROR_SUCCESS) {
        const int err_add = yr_compiler_add_file(compiler, fh, nullptr,
                                                 file.filename().string().c_str());
        if (err_add == ERROR_SUCCESS) {
            const int err_rules = yr_compiler_get_rules(compiler, out_rules);
            if (err_rules == ERROR_SUCCESS) {
                ok = true;
            } else {
                error_out = "compile: " + compilerErrMsg(compiler);
            }
        } else {
            error_out = "parse: " + compilerErrMsg(compiler);
        }
        yr_compiler_destroy(compiler);
    }
    std::fclose(fh);
    return ok;
}

bool YARAScanner::loadRules(const std::string& dir) {
    // Tear down any existing ruleset first (hot-reload semantics).
    freeRuleset();

    ensureYaraConfig();

    namespace fs = std::filesystem;

    // ── Collect rule files (sorted for deterministic load order) ────────
    std::vector<fs::path> files;
    std::error_code ec;
    for (const auto& entry : fs::directory_iterator(dir, ec)) {
        if (!entry.is_regular_file()) continue;
        const std::string ext = entry.path().extension().string();
        if (ext == ".yar" || ext == ".yara") {
            files.push_back(entry.path());
        }
    }
    std::sort(files.begin(), files.end());

    if (files.empty()) {
        std::fprintf(stderr, "[yara] no .yar files found in %s\n", dir.c_str());
        return false;
    }

    // ── Compile each file in its own compiler (per-file fault isolation) ─
    for (const auto& f : files) {
        YR_RULES* ruleset = nullptr;
        std::string ferror;
        if (!compileOneFile(f, &ruleset, ferror)) {
            // One bad rule pushed by an analyst must not take down the
            // whole engine — skip this file, keep the rest.
            std::fprintf(stderr,
                         "[yara] skipping %s: %s\n",
                         f.filename().string().c_str(), ferror.c_str());
            continue;
        }

        YR_SCANNER* scanner = nullptr;
        if (yr_scanner_create(ruleset, &scanner) != ERROR_SUCCESS) {
            std::fprintf(stderr,
                         "[yara] yr_scanner_create failed for %s\n",
                         f.filename().string().c_str());
            yr_rules_destroy(ruleset);
            continue;
        }
        // 100ms timeout per scan: a pathological rule against a
        // pathological payload must never wedge the pipeline.
        yr_scanner_set_timeout(scanner, 100);

        // Harvest meta + attribute every rule in this file to the file.
        YR_RULE* rule;
        yr_rules_foreach(ruleset, rule) {
            if (!rule->identifier) continue;
            m_rule_to_file[rule->identifier] = f.filename().string();
            YARAScanner::RuleMeta rm;
            harvestMeta(rule, rm);
            m_rule_meta[rule->identifier] = std::move(rm);
        }

        m_rulesets.push_back(ruleset);
        m_scanners.push_back(scanner);
        m_rule_files.push_back(f.filename().string());
    }

    if (m_rulesets.empty()) {
        std::fprintf(stderr,
                     "[yara] failed to load any rule from %s\n", dir.c_str());
        freeRuleset();
        return false;
    }

    m_rules_dir = dir;
    std::fprintf(stderr,
                 "[yara] loaded %zu rule(s) from %zu file(s) in %s\n",
                 m_rule_to_file.size(), m_rule_files.size(), dir.c_str());
    return true;
}


// ============================================================================
//  SCANNING
// ============================================================================

int YARAScanner::ruleCallback(YR_SCAN_CONTEXT* context,
                              int message,
                              void* message_data,
                              void* user_data) {
    if (message != CALLBACK_MSG_RULE_MATCHING) {
        return CALLBACK_CONTINUE;
    }

    auto* out = static_cast<ScanOut*>(user_data);
    if (!out) {
        return CALLBACK_CONTINUE;
    }

    YR_RULE* rule = static_cast<YR_RULE*>(message_data);
    if (!rule || !rule->identifier) {
        return CALLBACK_CONTINUE;
    }

    YaraScanMatch m;
    m.rule_name = rule->identifier;

    if (out->rule_to_file) {
        auto it = out->rule_to_file->find(m.rule_name);
        if (it != out->rule_to_file->end()) {
            m.rule_file = it->second;
        }
    }

    // Matched string identifiers ($nop_sled, $int3, ...)
    YR_STRING* s;
    yr_rule_strings_foreach(rule, s) {
        bool any_match = false;
        YR_MATCH* match;
        yr_string_matches_foreach(context, s, match) {
            any_match = true;
            break;  // only need to know the string matched
        }
        if (any_match && s->identifier) {
            m.matched_strings.push_back(s->identifier);
        }
    }

    // Meta-driven alert fields
    if (out->meta) {
        auto it = out->meta->find(m.rule_name);
        if (it != out->meta->end()) {
            m.description = it->second.description;
            m.mitre_id    = it->second.mitre;
            m.mitre_name  = it->second.mitre_name;

            std::string sev = it->second.severity;
            std::transform(sev.begin(), sev.end(), sev.begin(),
                           [](unsigned char c) { return std::toupper(c); });
            if (sev == "LOW") {
                m.severity = Severity::LOW;
            } else if (sev == "MEDIUM") {
                m.severity = Severity::MEDIUM;
            } else if (sev == "CRITICAL") {
                m.severity = Severity::CRITICAL;
            } else {
                m.severity = Severity::HIGH;  // default for unmatched meta
            }
        }
    }

    out->matches.push_back(std::move(m));
    return CALLBACK_CONTINUE;
}


std::vector<YaraScanMatch> YARAScanner::scan(const uint8_t* data,
                                             size_t len) const {
    std::vector<YaraScanMatch> out;
    if (m_rulesets.empty() || !data || len == 0) {
        return out;
    }

    m_scanned++;  // const_cast-free: diagnostics counter

    // One ScanOut shared by all per-file scanners; each scanner's
    // callback user_data is re-pointed before its scan (YARA 4.x keeps
    // the callback + user_data on the scanner, so it must be refreshed
    // per scan to point at a fresh accumulator).
    ScanOut ctx;
    ctx.rule_to_file = &m_rule_to_file;
    ctx.meta         = &m_rule_meta;

    for (size_t i = 0; i < m_scanners.size(); ++i) {
        ctx.matches.clear();
        yr_scanner_set_callback(m_scanners[i], ruleCallback, &ctx);

        const int err = yr_scanner_scan_mem(m_scanners[i], data, len);
        if (err != ERROR_SUCCESS && err != ERROR_SCAN_TIMEOUT &&
            err != ERROR_TOO_MANY_MATCHES) {
            // Unexpected scan failure (error code from <yara/error.h>) —
            // log, keep the pipeline moving.
            std::fprintf(stderr, "[yara] scan error code %d (file %zu)\n",
                         err, i);
        }
        for (auto& m : ctx.matches) {
            out.push_back(std::move(m));
        }
    }

    if (!out.empty()) {
        m_matches += out.size();  // diagnostics counter
    }
    return out;
}


// ============================================================================
//  DIAGNOSTICS
// ============================================================================

size_t YARAScanner::ruleCount() const {
    return m_rule_to_file.size();
}

#else  // !SENTINELX_WITH_YARA — build without libyara

// ============================================================================
//  NO-YARA FALLBACK
//  The engine still builds and runs; signature detection is disabled and
//  a warning is logged on first load attempt.
// ============================================================================

YARAScanner::~YARAScanner() = default;

bool YARAScanner::loadRules(const std::string& dir) {
    std::fprintf(stderr,
                 "[yara] YARA support not compiled in — rules in %s ignored "
                 "(rebuild with libyara to enable signature detection)\n",
                 dir.c_str());
    m_rules_dir = dir;
    return false;
}

std::vector<YaraScanMatch> YARAScanner::scan(const uint8_t*, size_t) const {
    return {};
}

size_t YARAScanner::ruleCount() const { return 0; }

#endif  // SENTINELX_WITH_YARA

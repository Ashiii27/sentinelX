/**
 * @file    test_framework.h
 * @brief   Minimal assertion framework for SentinelX engine tests.
 *
 * Deliberately dependency-free (no GTest): the engine's CI should not
 * download a test framework just to run ~100 assertions. Each test file
 * is a standalone executable that returns non-zero on any failure, so
 * CTest works with plain `add_test(NAME x COMMAND x)`.
 *
 * Usage:
 * @code
 *   #include "test_framework.h"
 *
 *   int main() {
 *       CHECK(1 + 1 == 2);
 *       CHECK_EQ(std::string("a"), std::string("a"));
 *       CHECK_GT(10, 5);
 *       return test_summary("test_example");
 *   }
 * @endcode
 *
 * @author  Ash
 * @project SentinelX
 */

#pragma once

#include <cstdio>
#include <cstdlib>
#include <string>
#include <type_traits>
#include <utility>


namespace testfw {

inline int& checks() {
    static int c = 0;
    return c;
}
inline int& failures() {
    static int f = 0;
    return f;
}

template <typename T>
std::string repr(const T& v) {
    if constexpr (std::is_same_v<T, std::string>) {
        return "\"" + v + "\"";
    } else if constexpr (std::is_same_v<T, const char*>) {
        return std::string("\"") + v + "\"";
    } else if constexpr (std::is_enum_v<T>) {
        return std::to_string(static_cast<std::underlying_type_t<T>>(v));
    } else {
        return std::to_string(v);
    }
}

inline int summary(const char* name) {
    std::fprintf(stderr, "[%s] %d checks, %d failed\n", name, checks(),
                 failures());
    return failures() == 0 ? 0 : 1;
}

}  // namespace testfw


#define CHECK(cond)                                                         \
    do {                                                                    \
        testfw::checks()++;                                                 \
        if (!(cond)) {                                                      \
            testfw::failures()++;                                           \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,    \
                         #cond);                                            \
        }                                                                   \
    } while (0)


#define CHECK_EQ(a, b)                                                      \
    do {                                                                    \
        auto va = (a);                                                      \
        auto vb = (b);                                                      \
        testfw::checks()++;                                                 \
        if (!(va == vb)) {                                                  \
            testfw::failures()++;                                           \
            std::fprintf(stderr, "FAIL %s:%d: %s == %s  (got %s vs %s)\n",  \
                         __FILE__, __LINE__, #a, #b,                        \
                         testfw::repr(va).c_str(), testfw::repr(vb).c_str());\
        }                                                                   \
    } while (0)


#define CHECK_NE(a, b)                                                      \
    do {                                                                    \
        auto va = (a);                                                      \
        auto vb = (b);                                                      \
        testfw::checks()++;                                                 \
        if (va == vb) {                                                     \
            testfw::failures()++;                                           \
            std::fprintf(stderr, "FAIL %s:%d: %s != %s  (both %s)\n",       \
                         __FILE__, __LINE__, #a, #b,                        \
                         testfw::repr(va).c_str());                         \
        }                                                                   \
    } while (0)


#define CHECK_GT(a, b)                                                      \
    do {                                                                    \
        auto va = (a);                                                      \
        auto vb = (b);                                                      \
        testfw::checks()++;                                                 \
        if (!(va > vb)) {                                                   \
            testfw::failures()++;                                           \
            std::fprintf(stderr, "FAIL %s:%d: %s > %s  (got %s vs %s)\n",   \
                         __FILE__, __LINE__, #a, #b,                        \
                         testfw::repr(va).c_str(), testfw::repr(vb).c_str());\
        }                                                                   \
    } while (0)


#define CHECK_GE(a, b)                                                      \
    do {                                                                    \
        auto va = (a);                                                      \
        auto vb = (b);                                                      \
        testfw::checks()++;                                                 \
        if (!(va >= vb)) {                                                  \
            testfw::failures()++;                                           \
            std::fprintf(stderr, "FAIL %s:%d: %s >= %s  (got %s vs %s)\n",  \
                         __FILE__, __LINE__, #a, #b,                        \
                         testfw::repr(va).c_str(), testfw::repr(vb).c_str());\
        }                                                                   \
    } while (0)


#define CHECK_CONTAINS(haystack, needle)                                    \
    do {                                                                    \
        auto h = (haystack);                                                \
        auto n = (needle);                                                  \
        testfw::checks()++;                                                 \
        if (h.find(n) == std::string::npos) {                               \
            testfw::failures()++;                                           \
            std::fprintf(stderr,                                           \
                         "FAIL %s:%d: %s does not contain %s\n",            \
                         __FILE__, __LINE__, #haystack, #needle);           \
        }                                                                   \
    } while (0)


/// Print a labeled failure (for message-based failures without a cond).
#define CHECK_MSG(cond, msg)                                                \
    do {                                                                    \
        testfw::checks()++;                                                 \
        if (!(cond)) {                                                      \
            testfw::failures()++;                                           \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,    \
                         msg);                                              \
        }                                                                   \
    } while (0)

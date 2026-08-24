# ============================================================================
#  SentinelX — C++ detection engine
# ============================================================================
#
#  Targets:
#    sentinelx_core   — static library: capture, parsers, detectors, YARA,
#                       alerts, utilities (no main)
#    sentinelx        — the engine executable (main.cpp)
#    test_*           — unit tests (CTest)
#
#  Options:
#    SENTINELX_ENABLE_TESTS   — build the test suite (default ON)
#
#  Dependencies:
#    libpcap   — required for LIVE capture. If not found, the engine is
#                built WITHOUT live capture (replay mode still works).
#                apt: libpcap-dev
#    libyara   — required for signature detection. If not found, the
#                YARA scanner compiles in its disabled fallback.
#                apt: libyara-dev
#    nlohmann/json — vendored single header in third_party/ (no install)
#
#  CI builds a matrix:
#    full    : -DCMAKE_BUILD_TYPE=Release (pcap + yara present)
#    minimal : -DSENTINELX_FORCE_MINIMAL=ON   (no pcap, no yara)
# ============================================================================

cmake_minimum_required(VERSION 3.16)
project(sentinelx VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

option(SENTINELX_ENABLE_TESTS "Build unit tests" ON)
option(SENTINELX_FORCE_MINIMAL
       "Build without libpcap and libyara (replay-only, no YARA)" OFF)

# ── Compiler warnings ─────────────────────────────────────────────────────
add_compile_options(-Wall -Wextra -Wno-unused-parameter)
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_compile_options(-O2)
else()
    add_compile_options(-g -O0)
endif()


# ── Dependencies ──────────────────────────────────────────────────────────
#
# find_library/find_path are probed; a found-but-broken install is caught
# by the try_compile check below.

set(SENTINELX_WITH_LIBPCAP OFF)
set(SENTINELX_WITH_YARA OFF)

if(NOT SENTINELX_FORCE_MINIMAL)
    # ── libpcap ─────────────────────────────────────────────────────────
    find_path(PCAP_INCLUDE_DIR pcap/pcap.h)
    find_library(PCAP_LIBRARY NAMES pcap)

    if(PCAP_INCLUDE_DIR AND PCAP_LIBRARY)
        include(CheckCXXSourceCompiles)
        set(CMAKE_REQUIRED_INCLUDES ${PCAP_INCLUDE_DIR})
        set(CMAKE_REQUIRED_LIBRARIES ${PCAP_LIBRARY})
        check_cxx_source_compiles("
            #include <pcap/pcap.h>
            int main() {
                char errbuf[PCAP_ERRBUF_SIZE];
                pcap_t* h = pcap_open_live(\"lo\", 65535, 0, 1000, errbuf);
                if (h) pcap_close(h);
                return 0;
            }" SENTINELX_PCAP_OK)
        unset(CMAKE_REQUIRED_INCLUDES)
        unset(CMAKE_REQUIRED_LIBRARIES)
        if(SENTINELX_PCAP_OK)
            set(SENTINELX_WITH_LIBPCAP ON)
        else()
            message(WARNING "libpcap found but compile check failed — "
                            "building WITHOUT live capture")
        endif()
    else()
        message(STATUS "libpcap not found — building WITHOUT live capture "
                       "(replay mode still available)")
    endif()

    # ── libyara ─────────────────────────────────────────────────────────
    find_path(YARA_INCLUDE_DIR yara.h)
    find_library(YARA_LIBRARY NAMES yara)

    if(YARA_INCLUDE_DIR AND YARA_LIBRARY)
        include(CheckCXXSourceCompiles)
        set(CMAKE_REQUIRED_INCLUDES ${YARA_INCLUDE_DIR})
        set(CMAKE_REQUIRED_LIBRARIES ${YARA_LIBRARY})
        check_cxx_source_compiles("
            #include <yara.h>
            int main() { return YR_MAJOR_VERSION; }" SENTINELX_YARA_OK)
        unset(CMAKE_REQUIRED_INCLUDES)
        unset(CMAKE_REQUIRED_LIBRARIES)
        if(SENTINELX_YARA_OK)
            set(SENTINELX_WITH_YARA ON)
        else()
            message(WARNING "libyara found but compile check failed — "
                            "building with YARA DISABLED")
        endif()
    else()
        message(STATUS "libyara not found — building with YARA DISABLED")
    endif()
endif()

message(STATUS "SentinelX build: libpcap=${SENTINELX_WITH_LIBPCAP} "
               "yara=${SENTINELX_WITH_YARA} tests=${SENTINELX_ENABLE_TESTS}")


# ── Core library ──────────────────────────────────────────────────────────

add_library(sentinelx_core STATIC
    src/capture/PacketCapture.cpp
    src/capture/PcapReplayer.cpp
    src/parsers/IPParser.cpp
    src/parsers/TCPParser.cpp
    src/parsers/HTTPParser.cpp
    src/detectors/PortScanDetector.cpp
    src/detectors/SYNFloodDetector.cpp
    src/detectors/HTTPAnomalyDetector.cpp
    src/detectors/HoneypotDetector.cpp
    src/yara/YARAScanner.cpp
    src/alerts/AlertEmitter.cpp
)

target_include_directories(sentinelx_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party
)

find_package(Threads REQUIRED)
target_link_libraries(sentinelx_core PUBLIC Threads::Threads)

if(UNIX)
    target_link_libraries(sentinelx_core PUBLIC ${CMAKE_DL_LIBS})
endif()

if(SENTINELX_WITH_LIBPCAP)
    target_compile_definitions(sentinelx_core PUBLIC SENTINELX_WITH_LIBPCAP=1)
    target_include_directories(sentinelx_core PUBLIC ${PCAP_INCLUDE_DIR})
    target_link_libraries(sentinelx_core PUBLIC ${PCAP_LIBRARY})
endif()

if(SENTINELX_WITH_YARA)
    target_compile_definitions(sentinelx_core PUBLIC SENTINELX_WITH_YARA=1)
    target_include_directories(sentinelx_core PUBLIC ${YARA_INCLUDE_DIR})
    target_link_libraries(sentinelx_core PUBLIC ${YARA_LIBRARY})
endif()


# ── Engine executable ─────────────────────────────────────────────────────

add_executable(sentinelx src/main.cpp)
target_link_libraries(sentinelx PRIVATE sentinelx_core)


# ── Tests ─────────────────────────────────────────────────────────────────

if(SENTINELX_ENABLE_TESTS)
    enable_testing()

    set(SENTINELX_TESTS
        test_parsers
        test_port_scan
        test_syn_flood
        test_http_anomaly
        test_honeypot
        test_alert_json
        test_pcap_replayer
    )

    foreach(test ${SENTINELX_TESTS})
        add_executable(${test} tests/${test}.cpp)
        target_link_libraries(${test} PRIVATE sentinelx_core)
        target_include_directories(${test} PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/tests)
        add_test(NAME ${test} COMMAND ${test})
    endforeach()

    # YARA test is only meaningful when YARA is compiled in.
    if(SENTINELX_WITH_YARA)
        add_executable(test_yara tests/test_yara.cpp)
        target_link_libraries(test_yara PRIVATE sentinelx_core)
        target_include_directories(test_yara PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/tests)
        add_test(NAME test_yara COMMAND test_yara
                 ${CMAKE_CURRENT_SOURCE_DIR}/rules)
    endif()
endif()

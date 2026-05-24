# CMakeLists.txt — CORRECTED for NS-3.43 build_exec() API
# Fix: include dirs passed via target_include_directories AFTER build_exec,
#      not inside INCLUDE_DIRECTORIES_TO_INCLUDE (which NS-3.43 mishandles
#      for raw filesystem paths).

cmake_minimum_required(VERSION 3.16)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)
endif()

# ---------------------------------------------------------------------------
# Project-wide include directories
# ---------------------------------------------------------------------------
set(UAV_PROJECT_ROOT ${CMAKE_CURRENT_SOURCE_DIR})

set(UAV_INCLUDE_DIRS
    ${UAV_PROJECT_ROOT}
    ${UAV_PROJECT_ROOT}/apps
    ${UAV_PROJECT_ROOT}/crypto
    ${UAV_PROJECT_ROOT}/headers
    ${UAV_PROJECT_ROOT}/mobility
    ${UAV_PROJECT_ROOT}/routing
    ${UAV_PROJECT_ROOT}/metrics
    ${UAV_PROJECT_ROOT}/visualization
    ${UAV_PROJECT_ROOT}/utils
)

# ---------------------------------------------------------------------------
# OpenSSL
# ---------------------------------------------------------------------------
find_package(OpenSSL REQUIRED)
message(STATUS "OpenSSL version : ${OPENSSL_VERSION}")

# ---------------------------------------------------------------------------
# Boost (header-only Multiprecision)
# ---------------------------------------------------------------------------
find_package(Boost 1.74 REQUIRED)
message(STATUS "Boost           : ${Boost_VERSION}")

find_file(BOOST_MULTIPRECISION_HEADER
    NAMES "cpp_int.hpp"
    PATHS ${Boost_INCLUDE_DIRS}
    PATH_SUFFIXES "boost/multiprecision"
    REQUIRED
)
message(STATUS "Boost.Multiprecision: FOUND")

# ---------------------------------------------------------------------------
# nlohmann/json (header-only)
# ---------------------------------------------------------------------------
find_path(NLOHMANN_JSON_INCLUDE_DIR
    NAMES "nlohmann/json.hpp"
    PATHS /usr/include /usr/local/include
    REQUIRED
)
message(STATUS "nlohmann/json   : ${NLOHMANN_JSON_INCLUDE_DIR}")

# ---------------------------------------------------------------------------
# Threads
# ---------------------------------------------------------------------------
find_package(Threads REQUIRED)

# ---------------------------------------------------------------------------
# Source collection
# ---------------------------------------------------------------------------
file(GLOB_RECURSE UTILS_SOURCES         "${UAV_PROJECT_ROOT}/utils/*.cc")
file(GLOB_RECURSE CRYPTO_SOURCES        "${UAV_PROJECT_ROOT}/crypto/*.cc")
file(GLOB_RECURSE HEADERS_SOURCES       "${UAV_PROJECT_ROOT}/headers/*.cc")
file(GLOB_RECURSE ROUTING_SOURCES       "${UAV_PROJECT_ROOT}/routing/*.cc")
file(GLOB_RECURSE MOBILITY_SOURCES      "${UAV_PROJECT_ROOT}/mobility/*.cc")
file(GLOB_RECURSE APPS_SOURCES          "${UAV_PROJECT_ROOT}/apps/*.cc")
file(GLOB_RECURSE METRICS_SOURCES       "${UAV_PROJECT_ROOT}/metrics/*.cc")
file(GLOB_RECURSE VISUALIZATION_SOURCES "${UAV_PROJECT_ROOT}/visualization/*.cc")

# Exclude test files from simulation binary
file(GLOB_RECURSE TEST_SOURCES "${UAV_PROJECT_ROOT}/tests/*.cc")

set(UAV_ALL_SOURCES
    ${UAV_PROJECT_ROOT}/main.cc
    ${UTILS_SOURCES}
    ${CRYPTO_SOURCES}
    ${HEADERS_SOURCES}
    ${ROUTING_SOURCES}
    ${MOBILITY_SOURCES}
    ${APPS_SOURCES}
    ${METRICS_SOURCES}
    ${VISUALIZATION_SOURCES}
)

# Remove test sources if accidentally globbed
list(REMOVE_ITEM UAV_ALL_SOURCES ${TEST_SOURCES})

# ---------------------------------------------------------------------------
# NS-3.43 scratch target via build_exec()
# CRITICAL FIX: Do NOT pass raw directories to LIBRARIES_TO_LINK.
# Include dirs are added AFTER build_exec via target_include_directories.
# ---------------------------------------------------------------------------
if(COMMAND build_exec)

    build_exec(
        EXECNAME     uav-secure-fanet
        SOURCE_FILES ${UAV_ALL_SOURCES}
        LIBRARIES_TO_LINK
            ${libcore}
            ${libnetwork}
            ${libinternet}
            ${libwifi}
            ${libcsma}
            ${libmobility}
            ${libolsr}
            ${libapplications}
            ${libflow-monitor}
            ${libnetanim}
            ${libenergy}
            ${libpropagation}
            ${libstats}
            OpenSSL::SSL
            OpenSSL::Crypto
            Threads::Threads
        # DO NOT put directory paths here — that caused the warnings
    )

    # Apply include dirs to the target NS-3.43 creates.
    # NS-3.43 cmake names scratch targets: scratch_<dirname>_<execname>
    set(UAV_TARGET scratch_uav-secure-fanet_uav-secure-fanet)

    target_include_directories(${UAV_TARGET} PRIVATE
        ${UAV_INCLUDE_DIRS}
        ${OPENSSL_INCLUDE_DIR}
        ${Boost_INCLUDE_DIRS}
        ${NLOHMANN_JSON_INCLUDE_DIR}
    )

    target_compile_definitions(${UAV_TARGET} PRIVATE
        UAV_PROJECT_VERSION="1.0.0"
        UAV_LOG_DIR="logs"
        UAV_OUTPUT_DIR="output"
        UAV_JSON_DIR="json"
        UAV_PCAP_DIR="pcap"

    # FIX: NS-3.43 build_exec() empty output path bug
    set_target_properties(${UAV_TARGET} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY
        "${CMAKE_BINARY_DIR}/scratch/uav-secure-fanet"
    )
    )

else()
    # Standalone fallback (no NS-3 cmake macros)
    message(WARNING "build_exec() not found. Use ./ns3 build from NS-3 root.")

    add_executable(uav-secure-fanet-standalone ${UAV_ALL_SOURCES})

    target_include_directories(uav-secure-fanet-standalone PRIVATE
        ${UAV_INCLUDE_DIRS}
        ${OPENSSL_INCLUDE_DIR}
        ${Boost_INCLUDE_DIRS}
        ${NLOHMANN_JSON_INCLUDE_DIR}
    )

    target_compile_definitions(uav-secure-fanet-standalone PRIVATE
        UAV_PROJECT_VERSION="1.0.0"
        UAV_LOG_DIR="logs"
        UAV_OUTPUT_DIR="output"
        UAV_JSON_DIR="json"
        UAV_PCAP_DIR="pcap"

    # FIX: NS-3.43 build_exec() empty output path bug
    set_target_properties(${UAV_TARGET} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY
        "${CMAKE_BINARY_DIR}/scratch/uav-secure-fanet"
    )
        STANDALONE_BUILD=1
    )

    target_link_libraries(uav-secure-fanet-standalone PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
        Threads::Threads
    )
endif()

# ---------------------------------------------------------------------------
# Unit test (standalone — no NS-3)
# ---------------------------------------------------------------------------
if(EXISTS "${UAV_PROJECT_ROOT}/tests/test_build_system.cc")
    add_executable(test_build_system
        ${UAV_PROJECT_ROOT}/tests/test_build_system.cc
    )
    target_include_directories(test_build_system PRIVATE
        ${UAV_INCLUDE_DIRS}
        ${OPENSSL_INCLUDE_DIR}
        ${Boost_INCLUDE_DIRS}
        ${NLOHMANN_JSON_INCLUDE_DIR}
    )
    target_link_libraries(test_build_system PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
        Threads::Threads
    )
    message(STATUS "Unit test: test_build_system REGISTERED")
endif()

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
message(STATUS "")
message(STATUS "=== UAV Secure FANET Build Summary ===")
message(STATUS "C++ standard    : C++17")
message(STATUS "Build type      : ${CMAKE_BUILD_TYPE}")
message(STATUS "OpenSSL         : ${OPENSSL_VERSION}")
message(STATUS "Boost           : ${Boost_VERSION}")
message(STATUS "Module 2 (fixed): CONFIGURED")
message(STATUS "=======================================")

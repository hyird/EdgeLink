# Third-party dependency management via FetchContent
# This file coordinates all third-party dependencies for EdgeLink
#
# Order matters! Dependencies must be fetched before dependents.

include(FetchContent)

# =============================================================================
# FetchContent Global Options
# =============================================================================
set(FETCHCONTENT_QUIET OFF)

# Cache dependencies to avoid re-downloading
set(FETCHCONTENT_BASE_DIR "${CMAKE_SOURCE_DIR}/.deps" CACHE PATH "Dependencies cache directory")

# =============================================================================
# 1. Simple Dependencies (no inter-dependencies)
# =============================================================================
message(STATUS "Fetching nlohmann_json...")
include(${CMAKE_CURRENT_LIST_DIR}/nlohmann_json.cmake)

message(STATUS "Fetching spdlog...")
include(${CMAKE_CURRENT_LIST_DIR}/spdlog.cmake)

message(STATUS "Fetching toml++...")
include(${CMAKE_CURRENT_LIST_DIR}/tomlplusplus.cmake)

# SQLite3 - only needed for controller
if(BUILD_CONTROLLER)
    message(STATUS "Fetching sqlite3...")
    include(${CMAKE_CURRENT_LIST_DIR}/sqlite3.cmake)
endif()

# =============================================================================
# 2. LZ4 (fast compression for frame payloads)
# =============================================================================
message(STATUS "Fetching LZ4...")
include(${CMAKE_CURRENT_LIST_DIR}/lz4.cmake)

# =============================================================================
# 3. BoringSSL (needed by jwt-cpp and Boost.Beast)
#    BoringSSL is Google's fork of OpenSSL with better security and CMake support
# =============================================================================
message(STATUS "Fetching BoringSSL...")
include(${CMAKE_CURRENT_LIST_DIR}/boringssl.cmake)

# =============================================================================
# 4. libsodium
# =============================================================================
message(STATUS "Fetching libsodium...")
include(${CMAKE_CURRENT_LIST_DIR}/libsodium.cmake)

# =============================================================================
# 5. jwt-cpp (depends on nlohmann-json, BoringSSL for OpenSSL-compatible API)
# =============================================================================
message(STATUS "Fetching jwt-cpp...")
include(${CMAKE_CURRENT_LIST_DIR}/jwt_cpp.cmake)

# =============================================================================
# 6. Boost (includes Beast for WebSocket support)
# =============================================================================
message(STATUS "Fetching Boost...")
include(${CMAKE_CURRENT_LIST_DIR}/boost.cmake)

# =============================================================================
# Thread support (system)
# =============================================================================
find_package(Threads REQUIRED)

message(STATUS "All third-party dependencies configured")

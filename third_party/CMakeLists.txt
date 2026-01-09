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

# SQLite3 - only needed for controller
if(BUILD_CONTROLLER)
    message(STATUS "Fetching sqlite3...")
    include(${CMAKE_CURRENT_LIST_DIR}/sqlite3.cmake)
endif()

# =============================================================================
# 2. OpenSSL (needed by jwt-cpp and gRPC)
# =============================================================================
message(STATUS "Fetching OpenSSL...")
include(${CMAKE_CURRENT_LIST_DIR}/openssl.cmake)

# =============================================================================
# 3. libsodium
# =============================================================================
message(STATUS "Fetching libsodium...")
include(${CMAKE_CURRENT_LIST_DIR}/libsodium.cmake)

# =============================================================================
# 4. jwt-cpp (depends on nlohmann-json, OpenSSL)
# =============================================================================
message(STATUS "Fetching jwt-cpp...")
include(${CMAKE_CURRENT_LIST_DIR}/jwt_cpp.cmake)

# =============================================================================
# 5. Boost
# =============================================================================
message(STATUS "Fetching Boost...")
include(${CMAKE_CURRENT_LIST_DIR}/boost.cmake)

# =============================================================================
# 6. gRPC + protobuf (most complex, has many dependencies)
# =============================================================================
message(STATUS "Fetching gRPC and dependencies...")
include(${CMAKE_CURRENT_LIST_DIR}/grpc.cmake)

# =============================================================================
# Thread support (system)
# =============================================================================
find_package(Threads REQUIRED)

message(STATUS "All third-party dependencies configured")

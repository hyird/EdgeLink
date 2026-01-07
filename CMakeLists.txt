cmake_minimum_required(VERSION 3.20...3.31)
project(edgelink VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Options
option(BUILD_CONTROLLER "Build the controller" ON)
option(BUILD_SERVER "Build the relay/stun server" ON)
option(BUILD_CLIENT "Build the client" ON)
option(BUILD_TESTS "Build tests" ON)
option(BUILD_SHARED_LIBS "Build shared libraries" OFF)
option(EDGELINK_STATIC "Build fully static binaries (Linux musl)" OFF)

# Suppress CMP0167 warning for FindBoost (if available)
if(POLICY CMP0167)
    cmake_policy(SET CMP0167 OLD)
endif()

# =============================================================================
# Platform Detection
# =============================================================================
if(WIN32)
    message(STATUS "Building for Windows")
    set(EDGELINK_PLATFORM "windows")
    add_definitions(-D_WIN32_WINNT=0x0A00)  # Windows 10+
    add_definitions(-DNOMINMAX)
    add_definitions(-DWIN32_LEAN_AND_MEAN)
    
    # Static runtime for MSVC (use x64-windows-static triplet)
    if(MSVC)
        set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
        # Disable MSVC warnings, enable big object files, UTF-8 source
        add_compile_options(/W3 /wd4996 /bigobj /utf-8)
    endif()
elseif(APPLE)
    message(STATUS "Building for macOS")
    set(EDGELINK_PLATFORM "macos")
else()
    message(STATUS "Building for Linux")
    set(EDGELINK_PLATFORM "linux")
    
    # Detect musl libc
    execute_process(
        COMMAND ${CMAKE_C_COMPILER} -dumpmachine
        OUTPUT_VARIABLE TARGET_TRIPLE
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    if(TARGET_TRIPLE MATCHES "musl" OR EXISTS "/etc/alpine-release")
        set(EDGELINK_MUSL ON)
        message(STATUS "Detected musl libc environment")
    endif()
    
    # Full static linking for Linux (use x64-linux or x64-linux-release triplet)
    if(NOT BUILD_SHARED_LIBS)
        set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
        if(EDGELINK_STATIC OR EDGELINK_MUSL)
            # Full static linking with musl
            set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")
            message(STATUS "Enabled full static linking")
        else()
            # Partial static (libgcc/libstdc++ only)
            set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libgcc -static-libstdc++")
        endif()
    endif()
endif()

# =============================================================================
# Dependencies
# =============================================================================

# Static linking options (only when explicitly enabled via cmake flags)
# Example: cmake -DBoost_USE_STATIC_LIBS=ON ...
if(Boost_USE_STATIC_LIBS)
    message(STATUS "Using static Boost libraries")
endif()

if(OPENSSL_USE_STATIC_LIBS)
    message(STATUS "Using static OpenSSL libraries")
endif()

find_package(Boost 1.81 REQUIRED COMPONENTS json)
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)
find_package(spdlog REQUIRED)
find_package(nlohmann_json REQUIRED)

# SQLite3 - only needed for controller
if(BUILD_CONTROLLER)
    find_package(SQLite3 REQUIRED)
endif()

# libsodium - platform specific finding
if(WIN32)
    # vcpkg handles this
    find_package(unofficial-sodium CONFIG REQUIRED)
    set(SODIUM_LIBRARIES unofficial-sodium::sodium)
    set(SODIUM_INCLUDE_DIRS "")
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(SODIUM REQUIRED libsodium)
endif()

# jwt-cpp (header-only, bundled in third_party)
set(JWT_CPP_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/jwt-cpp/include)
set(PICOJSON_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/picojson/include)

# Wintun for Windows client
if(WIN32 AND BUILD_CLIENT)
    set(WINTUN_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/wintun)
endif()

# =============================================================================
# Common Library
# =============================================================================
add_library(edgelink-common STATIC
    src/common/protocol.cpp
    src/common/frame.cpp
    src/common/config.cpp
    src/common/log.cpp
    src/common/jwt.cpp
    src/common/crypto/x25519.cpp
    src/common/crypto/chacha20.cpp
    src/common/crypto/ed25519.cpp
    src/common/crypto/hkdf.cpp
)

target_include_directories(edgelink-common PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${SODIUM_INCLUDE_DIRS}
    ${JWT_CPP_INCLUDE_DIR}
    ${PICOJSON_INCLUDE_DIR}
)

target_link_libraries(edgelink-common PUBLIC
    Boost::headers
    Boost::json
    OpenSSL::SSL
    OpenSSL::Crypto
    spdlog::spdlog
    nlohmann_json::nlohmann_json
    ${SODIUM_LIBRARIES}
    Threads::Threads
)

if(WIN32)
    target_link_libraries(edgelink-common PUBLIC
        ws2_32
        mswsock
        bcrypt
        crypt32
    )
endif()

# =============================================================================
# Controller (Linux only for now)
# =============================================================================
if(BUILD_CONTROLLER)
    if(WIN32)
        message(STATUS "Controller build is disabled on Windows")
    else()
        add_executable(edgelink-controller
            src/controller/main.cpp
            src/controller/commands.cpp
            src/controller/db/database.cpp
            src/controller/db/migrations.cpp
            src/controller/api/http_server.cpp
            src/controller/api/services.cpp
            src/controller/api/control_handler.cpp
            src/controller/services/path_service.cpp
            src/controller/builtin_relay.cpp
            src/controller/builtin_stun.cpp
        )

        target_link_libraries(edgelink-controller PRIVATE
            edgelink-common
            SQLite::SQLite3
        )
    endif()
endif()

# =============================================================================
# Relay/STUN Server (Linux only for now)
# =============================================================================
if(BUILD_SERVER)
    if(WIN32)
        message(STATUS "Server build is disabled on Windows")
    else()
        add_executable(edgelink-server
            src/server/main.cpp
            src/server/relay_server.cpp
            src/server/relay_session.cpp
            src/server/stun_server.cpp
            src/server/controller_client.cpp
            src/server/mesh_manager.cpp
            src/server/mesh_client.cpp
            src/server/mesh_session.cpp
            src/server/node_location_cache.cpp
        )

        target_link_libraries(edgelink-server PRIVATE
            edgelink-common
        )
    endif()
endif()

# =============================================================================
# Client (Cross-platform)
# =============================================================================
if(BUILD_CLIENT)
    # Platform-specific TUN source
    if(WIN32)
        set(TUN_SOURCE src/client/tun_windows.cpp)
    elseif(APPLE)
        set(TUN_SOURCE src/client/tun_macos.cpp)
    else()
        set(TUN_SOURCE src/client/tun.cpp)
    endif()

    add_executable(edgelink-client
        src/client/main.cpp
        src/client/control_channel.cpp
        src/client/relay_manager.cpp
        src/client/crypto_engine.cpp
        src/client/route_manager.cpp
        src/client/endpoint_manager.cpp
        src/client/p2p_manager.cpp
        src/client/client.cpp
        ${TUN_SOURCE}
    )

    target_link_libraries(edgelink-client PRIVATE
        edgelink-common
    )

    if(WIN32)
        target_include_directories(edgelink-client PRIVATE ${WINTUN_INCLUDE_DIR})
        target_link_libraries(edgelink-client PRIVATE
            iphlpapi
            ntdll
        )
    endif()
endif()

# =============================================================================
# Tests
# =============================================================================
if(BUILD_TESTS)
    enable_testing()
    find_package(GTest QUIET)
    
    if(GTest_FOUND)
        add_executable(edgelink-tests
            tests/test_protocol.cpp
            tests/test_crypto.cpp
        )
        
        target_link_libraries(edgelink-tests PRIVATE
            edgelink-common
            GTest::gtest_main
        )
        
        include(GoogleTest)
        gtest_discover_tests(edgelink-tests)
    else()
        message(STATUS "GTest not found, tests will not be built")
    endif()
endif()

# =============================================================================
# Install
# =============================================================================
if(BUILD_CONTROLLER AND NOT WIN32)
    install(TARGETS edgelink-controller
        RUNTIME DESTINATION bin
    )
endif()

if(BUILD_SERVER AND NOT WIN32)
    install(TARGETS edgelink-server
        RUNTIME DESTINATION bin
    )
endif()

if(BUILD_CLIENT)
    install(TARGETS edgelink-client
        RUNTIME DESTINATION bin
    )
endif()

install(DIRECTORY config/
    DESTINATION etc/edgelink
    FILES_MATCHING PATTERN "*.example.json"
)

# =============================================================================
# Summary
# =============================================================================
message(STATUS "")
message(STATUS "EdgeLink Build Configuration:")
message(STATUS "  Platform:      ${EDGELINK_PLATFORM}")
message(STATUS "  Build Type:    ${CMAKE_BUILD_TYPE}")
message(STATUS "  Shared Libs:   ${BUILD_SHARED_LIBS}" )
if(EDGELINK_MUSL)
message(STATUS "  Libc:          musl (full static)")
elseif(EDGELINK_STATIC)
message(STATUS "  Static:        full static linking")
endif()
message(STATUS "  Controller:    ${BUILD_CONTROLLER}")
message(STATUS "  Server:        ${BUILD_SERVER}")
message(STATUS "  Client:        ${BUILD_CLIENT}")
message(STATUS "  Tests:         ${BUILD_TESTS}")
if(MSVC)
message(STATUS "  MSVC Runtime:  ${CMAKE_MSVC_RUNTIME_LIBRARY}")
endif()
if(DEFINED VCPKG_TARGET_TRIPLET)
message(STATUS "  vcpkg Triplet: ${VCPKG_TARGET_TRIPLET}")
endif()
message(STATUS "")

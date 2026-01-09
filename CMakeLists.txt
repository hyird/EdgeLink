cmake_minimum_required(VERSION 3.20...3.31)
project(edgelink VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Options
option(BUILD_CONTROLLER "Build the controller" ON)
option(BUILD_SERVER "Build the relay/stun server" ON)
option(BUILD_CLIENT "Build the client" ON)
option(BUILD_SHARED_LIBS "Build shared libraries" OFF)
option(EDGELINK_STATIC "Build fully static binaries" OFF)

# =============================================================================
# Platform Detection
# =============================================================================
if(WIN32)
    message(STATUS "Building for Windows")
    set(EDGELINK_PLATFORM "windows")
    add_definitions(-D_WIN32_WINNT=0x0A00)  # Windows 10+
    add_definitions(-DNOMINMAX)
    add_definitions(-DWIN32_LEAN_AND_MEAN)

    # MinGW settings
    if(MINGW)
        message(STATUS "Using MinGW compiler")
        # Enable static linking of libgcc and libstdc++
        if(NOT BUILD_SHARED_LIBS)
            set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libgcc -static-libstdc++")
            if(EDGELINK_STATIC)
                set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")
            endif()
        endif()
        # Suppress some MinGW warnings
        add_compile_options(-Wno-deprecated-declarations)
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

    # Full static linking for Linux
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
# Third-Party Dependencies via FetchContent
# =============================================================================
include(third_party/CMakeLists.txt)

# =============================================================================
# Common Library
# =============================================================================
add_library(edgelink-common STATIC
    src/common/protocol.cpp
    src/common/frame.cpp
    src/common/config.cpp
    src/common/log.cpp
    src/common/jwt.cpp
    src/common/ws_client.cpp
    src/common/ws_server.cpp
    src/common/crypto/x25519.cpp
    src/common/crypto/chacha20.cpp
    src/common/crypto/ed25519.cpp
    src/common/crypto/hkdf.cpp
)

target_include_directories(edgelink-common PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(edgelink-common PUBLIC
    Boost::asio
    Boost::beast
    Boost::json
    Boost::url
    OpenSSL::SSL
    OpenSSL::Crypto
    spdlog::spdlog
    nlohmann_json::nlohmann_json
    unofficial-sodium::sodium
    jwt-cpp::jwt-cpp
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

# Precompiled header for faster builds
target_precompile_headers(edgelink-common PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src/pch.hpp
)

# =============================================================================
# Controller
# =============================================================================
if(BUILD_CONTROLLER)
    add_executable(edgelink-controller
        src/controller/main.cpp
        src/controller/commands.cpp
        src/controller/db/database.cpp
        src/controller/db/migrations.cpp
        src/controller/api/ws_server.cpp
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
    target_precompile_headers(edgelink-controller REUSE_FROM edgelink-common)
endif()

# =============================================================================
# Relay/STUN Server
# =============================================================================
if(BUILD_SERVER)
    add_executable(edgelink-server
        src/server/main.cpp
        src/server/ws_relay_server.cpp
        src/server/stun_server.cpp
        src/server/controller_client.cpp
        src/server/node_location_cache.cpp
    )

    target_link_libraries(edgelink-server PRIVATE
        edgelink-common
    )
    target_precompile_headers(edgelink-server REUSE_FROM edgelink-common)
endif()

# =============================================================================
# Client (Cross-platform)
# =============================================================================
if(BUILD_CLIENT)
    # Common client source files
    set(CLIENT_SOURCE
        src/client/main.cpp
        src/client/control_channel.cpp
        src/client/ws_relay_manager.cpp
        src/client/crypto_engine.cpp
        src/client/route_manager.cpp
        src/client/endpoint_manager.cpp
        src/client/p2p_manager.cpp
        src/client/ipc_server.cpp
        src/client/client.cpp
    )

    # Platform-specific TUN source
    if(WIN32)
        list(APPEND CLIENT_SOURCE src/client/tun_windows.cpp)

        # Optionally embed wintun.dll (only works with MSVC resource compiler)
        # For MinGW, we'll load wintun.dll from the same directory at runtime
        if(NOT MINGW AND DEFINED WINTUN_DLL_PATH AND EXISTS "${WINTUN_DLL_PATH}")
            message(STATUS "Embedding wintun.dll from: ${WINTUN_DLL_PATH}")

            string(REPLACE "\\" "/" WINTUN_DLL_PATH_ESCAPED "${WINTUN_DLL_PATH}")

            set(WINTUN_RC_FILE "${CMAKE_CURRENT_BINARY_DIR}/wintun.rc")
            file(WRITE ${WINTUN_RC_FILE}
                "// Embedded wintun.dll\n"
                "#define IDR_WINTUN_DLL 301\n"
                "IDR_WINTUN_DLL RCDATA \"${WINTUN_DLL_PATH_ESCAPED}\"\n"
            )

            list(APPEND CLIENT_SOURCE ${WINTUN_RC_FILE})
            set(EDGELINK_WINTUN_EMBEDDED TRUE)
        else()
            message(STATUS "Wintun DLL not embedded. Will load from exe directory at runtime.")
        endif()
    elseif(APPLE)
        list(APPEND CLIENT_SOURCE src/client/tun_macos.cpp)
    else()
        list(APPEND CLIENT_SOURCE src/client/tun.cpp)
    endif()

    add_executable(edgelink-client ${CLIENT_SOURCE})

    target_link_libraries(edgelink-client PRIVATE
        edgelink-common
    )
    target_precompile_headers(edgelink-client REUSE_FROM edgelink-common)

    if(WIN32)
        target_include_directories(edgelink-client PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src/client
        )
        target_link_libraries(edgelink-client PRIVATE
            iphlpapi
            ntdll
            setupapi
        )

        if(EDGELINK_WINTUN_EMBEDDED)
            target_compile_definitions(edgelink-client PRIVATE EDGELINK_WINTUN_EMBEDDED=1)
        endif()
    endif()
endif()

# =============================================================================
# Install
# =============================================================================
if(BUILD_CONTROLLER)
    install(TARGETS edgelink-controller
        RUNTIME DESTINATION bin
    )
endif()

if(BUILD_SERVER)
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
message(STATUS "  Shared Libs:   ${BUILD_SHARED_LIBS}")
if(EDGELINK_MUSL)
message(STATUS "  Libc:          musl (full static)")
elseif(EDGELINK_STATIC)
message(STATUS "  Static:        full static linking")
endif()
message(STATUS "  Controller:    ${BUILD_CONTROLLER}")
message(STATUS "  Server:        ${BUILD_SERVER}")
message(STATUS "  Client:        ${BUILD_CLIENT}")
if(MINGW)
message(STATUS "  Compiler:      MinGW")
endif()
message(STATUS "  Dependencies:  FetchContent")
message(STATUS "")

cmake_minimum_required(VERSION 3.20...3.31)
project(edgelink VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Options
option(BUILD_CONTROLLER "Build the controller" ON)
option(BUILD_SERVER "Build the relay/stun server" ON)
option(BUILD_CLIENT "Build the client" ON)
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

# libsodium - use vcpkg's unofficial-sodium on all platforms
find_package(unofficial-sodium CONFIG REQUIRED)
set(SODIUM_LIBRARIES unofficial-sodium::sodium)
set(SODIUM_INCLUDE_DIRS "")

# jwt-cpp (header-only, from vcpkg)
find_package(jwt-cpp CONFIG REQUIRED)

# gRPC and Protocol Buffers
find_package(protobuf CONFIG REQUIRED)
find_package(gRPC CONFIG REQUIRED)

# Get protoc and grpc_cpp_plugin executables
find_program(_PROTOBUF_PROTOC protoc)
find_program(_GRPC_CPP_PLUGIN_EXECUTABLE grpc_cpp_plugin)

# =============================================================================
# Proto Library (generated from .proto files)
# =============================================================================
set(PROTO_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/proto")
set(PROTO_GEN_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated")
file(MAKE_DIRECTORY ${PROTO_GEN_DIR})

# Define proto file
set(PROTO_FILE "${PROTO_SRC_DIR}/edgelink.proto")

# Generated file paths
set(PROTO_SRCS "${PROTO_GEN_DIR}/edgelink.pb.cc")
set(PROTO_HDRS "${PROTO_GEN_DIR}/edgelink.pb.h")
set(GRPC_SRCS "${PROTO_GEN_DIR}/edgelink.grpc.pb.cc")
set(GRPC_HDRS "${PROTO_GEN_DIR}/edgelink.grpc.pb.h")

# Custom command to generate protobuf and gRPC source files
add_custom_command(
    OUTPUT "${PROTO_SRCS}" "${PROTO_HDRS}" "${GRPC_SRCS}" "${GRPC_HDRS}"
    COMMAND ${_PROTOBUF_PROTOC}
    ARGS --grpc_out "${PROTO_GEN_DIR}"
         --cpp_out "${PROTO_GEN_DIR}"
         -I "${PROTO_SRC_DIR}"
         --plugin=protoc-gen-grpc="${_GRPC_CPP_PLUGIN_EXECUTABLE}"
         "${PROTO_FILE}"
    DEPENDS "${PROTO_FILE}"
    COMMENT "Generating gRPC and protobuf C++ sources from ${PROTO_FILE}"
)

# Create proto library
add_library(edgelink-proto STATIC
    ${PROTO_SRCS}
    ${GRPC_SRCS}
)

target_include_directories(edgelink-proto PUBLIC
    ${PROTO_GEN_DIR}
)

target_link_libraries(edgelink-proto PUBLIC
    protobuf::libprotobuf
    gRPC::grpc++
    gRPC::grpc++_reflection
)

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
)

target_link_libraries(edgelink-common PUBLIC
    Boost::headers
    Boost::json
    OpenSSL::SSL
    OpenSSL::Crypto
    spdlog::spdlog
    nlohmann_json::nlohmann_json
    ${SODIUM_LIBRARIES}
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
        src/controller/api/grpc_server.cpp
        src/controller/api/services.cpp
        src/controller/api/control_handler.cpp
        src/controller/services/path_service.cpp
        src/controller/builtin_relay.cpp
        src/controller/builtin_stun.cpp
    )

    target_link_libraries(edgelink-controller PRIVATE
        edgelink-common
        edgelink-proto
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
        src/server/grpc_relay_server.cpp
        src/server/stun_server.cpp
        src/server/controller_client.cpp
        src/server/node_location_cache.cpp
    )

    target_link_libraries(edgelink-server PRIVATE
        edgelink-common
        edgelink-proto
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
        src/client/grpc_relay_manager.cpp
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
        
        # Optionally embed wintun.dll
        # Use: cmake -DWINTUN_DLL_PATH=/path/to/wintun.dll
        if(DEFINED WINTUN_DLL_PATH AND EXISTS "${WINTUN_DLL_PATH}")
            message(STATUS "Embedding wintun.dll from: ${WINTUN_DLL_PATH}")
            
            # Convert Windows backslashes to forward slashes for RC file
            # This prevents escape sequence issues (e.g., \a being interpreted as bell character)
            string(REPLACE "\\" "/" WINTUN_DLL_PATH_ESCAPED "${WINTUN_DLL_PATH}")
            
            # Generate resource file
            set(WINTUN_RC_FILE "${CMAKE_CURRENT_BINARY_DIR}/wintun.rc")
            file(WRITE ${WINTUN_RC_FILE}
                "// Embedded wintun.dll\n"
                "#define IDR_WINTUN_DLL 301\n"
                "IDR_WINTUN_DLL RCDATA \"${WINTUN_DLL_PATH_ESCAPED}\"\n"
            )
            
            list(APPEND CLIENT_SOURCE ${WINTUN_RC_FILE})
            set(EDGELINK_WINTUN_EMBEDDED TRUE)
        else()
            message(STATUS "Wintun DLL not embedded. Will load from exe directory or system.")
            message(STATUS "  To embed: cmake -DWINTUN_DLL_PATH=/path/to/wintun.dll ...")
        endif()
    elseif(APPLE)
        list(APPEND CLIENT_SOURCE src/client/tun_macos.cpp)
    else()
        list(APPEND CLIENT_SOURCE src/client/tun.cpp)
    endif()

    add_executable(edgelink-client ${CLIENT_SOURCE})

    target_link_libraries(edgelink-client PRIVATE
        edgelink-common
        edgelink-proto
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
message(STATUS "  Shared Libs:   ${BUILD_SHARED_LIBS}" )
if(EDGELINK_MUSL)
message(STATUS "  Libc:          musl (full static)")
elseif(EDGELINK_STATIC)
message(STATUS "  Static:        full static linking")
endif()
message(STATUS "  Controller:    ${BUILD_CONTROLLER}")
message(STATUS "  Server:        ${BUILD_SERVER}")
message(STATUS "  Client:        ${BUILD_CLIENT}")
if(MSVC)
message(STATUS "  MSVC Runtime:  ${CMAKE_MSVC_RUNTIME_LIBRARY}")
endif()
if(DEFINED VCPKG_TARGET_TRIPLET)
message(STATUS "  vcpkg Triplet: ${VCPKG_TARGET_TRIPLET}")
endif()
message(STATUS "")

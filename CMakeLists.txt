cmake_minimum_required(VERSION 3.20)
project(edgelink VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Options
option(BUILD_CONTROLLER "Build the controller" ON)
option(BUILD_SERVER "Build the relay/stun server" ON)
option(BUILD_CLIENT "Build the client" ON)
option(BUILD_TESTS "Build tests" ON)

# Suppress CMP0167 warning for FindBoost (if available)
if(POLICY CMP0167)
    cmake_policy(SET CMP0167 OLD)
endif()

# Dependencies - Boost 1.82+ has header-only system
find_package(Boost 1.81 REQUIRED COMPONENTS json)
find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)
find_package(Threads REQUIRED)

# Try to find spdlog
find_package(spdlog REQUIRED)

# nlohmann/json
find_package(nlohmann_json REQUIRED)

# libsodium for crypto
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)

# jwt-cpp (header-only, bundled in third_party)
set(JWT_CPP_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/jwt-cpp/include)
set(PICOJSON_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/picojson/include)

# Common library
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

# Controller
if(BUILD_CONTROLLER)
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

# Relay/STUN Server
if(BUILD_SERVER)
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

# Client
if(BUILD_CLIENT)
    add_executable(edgelink-client
        src/client/main.cpp
        src/client/control_channel.cpp
        src/client/relay_manager.cpp
        src/client/crypto_engine.cpp
        src/client/tun.cpp
        src/client/route_manager.cpp
        src/client/endpoint_manager.cpp
        src/client/p2p_manager.cpp
        src/client/client.cpp
    )

    target_link_libraries(edgelink-client PRIVATE
        edgelink-common
    )
endif()

# Tests
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
    endif()
endif()

# Install
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

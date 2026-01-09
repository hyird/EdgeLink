# OpenSSL: TLS/SSL and crypto library
# https://www.openssl.org/
#
# Uses Configure script for both Unix and MinGW builds.

include(FetchContent)
include(ExternalProject)

# Allow legacy FetchContent_Populate for non-CMake projects
cmake_policy(SET CMP0169 OLD)

set(OPENSSL_VERSION "3.3.2")

FetchContent_Declare(
    openssl_src
    URL https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz
    URL_HASH SHA256=2e8a40b01979afe8be0bbfb3de5dc1c6709fedb46d6c89c10da114ab5fc3d281
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)

FetchContent_GetProperties(openssl_src)
if(NOT openssl_src_POPULATED)
    FetchContent_Populate(openssl_src)
endif()

set(OPENSSL_INSTALL_DIR "${CMAKE_BINARY_DIR}/openssl-install")

if(WIN32)
    # Windows MinGW: Use Configure mingw64 via MSYS2 shell
    find_program(BASH_EXECUTABLE bash HINTS "D:/msys64/usr/bin" "C:/msys64/usr/bin" "C:/mingw64/bin")
    find_program(PERL_EXECUTABLE perl HINTS "D:/msys64/usr/bin" "C:/msys64/usr/bin" "C:/Strawberry/perl/bin")

    if(BASH_EXECUTABLE AND PERL_EXECUTABLE)
        # Convert paths to Unix style for MSYS2
        string(REPLACE "\\" "/" OPENSSL_SRC_UNIX "${openssl_src_SOURCE_DIR}")
        string(REPLACE "\\" "/" OPENSSL_INSTALL_UNIX "${OPENSSL_INSTALL_DIR}")

        ExternalProject_Add(openssl_build
            SOURCE_DIR "${openssl_src_SOURCE_DIR}"
            CONFIGURE_COMMAND ${BASH_EXECUTABLE} -c
                "cd '${OPENSSL_SRC_UNIX}' && ./Configure mingw64 --prefix='${OPENSSL_INSTALL_UNIX}' --openssldir='${OPENSSL_INSTALL_UNIX}/ssl' no-shared no-tests"
            BUILD_COMMAND ${BASH_EXECUTABLE} -c
                "cd '${OPENSSL_SRC_UNIX}' && make -j$ENV{NUMBER_OF_PROCESSORS}"
            INSTALL_COMMAND ${BASH_EXECUTABLE} -c
                "cd '${OPENSSL_SRC_UNIX}' && make install_sw"
            BUILD_IN_SOURCE TRUE
            BUILD_BYPRODUCTS
                "${OPENSSL_INSTALL_DIR}/lib/libssl.a"
                "${OPENSSL_INSTALL_DIR}/lib/libcrypto.a"
        )

        set(OPENSSL_SSL_LIBRARY "${OPENSSL_INSTALL_DIR}/lib/libssl.a")
        set(OPENSSL_CRYPTO_LIBRARY "${OPENSSL_INSTALL_DIR}/lib/libcrypto.a")
    else()
        message(FATAL_ERROR "bash or perl not found. Please install MSYS2 with perl.")
    endif()
else()
    # Unix: Build using Configure + make
    ExternalProject_Add(openssl_build
        SOURCE_DIR "${openssl_src_SOURCE_DIR}"
        CONFIGURE_COMMAND "${openssl_src_SOURCE_DIR}/Configure"
            --prefix=${OPENSSL_INSTALL_DIR}
            --openssldir=${OPENSSL_INSTALL_DIR}/ssl
            no-shared
            no-tests
            "CFLAGS=-fPIC"
        BUILD_COMMAND make -j${CMAKE_BUILD_PARALLEL_LEVEL}
        INSTALL_COMMAND make install_sw
        BUILD_BYPRODUCTS
            "${OPENSSL_INSTALL_DIR}/lib/libssl.a"
            "${OPENSSL_INSTALL_DIR}/lib/libcrypto.a"
    )

    set(OPENSSL_SSL_LIBRARY "${OPENSSL_INSTALL_DIR}/lib/libssl.a")
    set(OPENSSL_CRYPTO_LIBRARY "${OPENSSL_INSTALL_DIR}/lib/libcrypto.a")
endif()

# Create imported targets
add_library(openssl_ssl STATIC IMPORTED GLOBAL)
set_target_properties(openssl_ssl PROPERTIES
    IMPORTED_LOCATION "${OPENSSL_SSL_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${OPENSSL_INSTALL_DIR}/include"
)
add_dependencies(openssl_ssl openssl_build)

add_library(openssl_crypto STATIC IMPORTED GLOBAL)
set_target_properties(openssl_crypto PROPERTIES
    IMPORTED_LOCATION "${OPENSSL_CRYPTO_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${OPENSSL_INSTALL_DIR}/include"
)
add_dependencies(openssl_crypto openssl_build)

# Platform-specific dependencies
if(WIN32)
    set_target_properties(openssl_crypto PROPERTIES
        INTERFACE_LINK_LIBRARIES "ws2_32;crypt32"
    )
else()
    find_package(Threads REQUIRED)
    set_target_properties(openssl_crypto PROPERTIES
        INTERFACE_LINK_LIBRARIES "Threads::Threads;${CMAKE_DL_LIBS}"
    )
endif()

# Link SSL to Crypto
set_target_properties(openssl_ssl PROPERTIES
    INTERFACE_LINK_LIBRARIES "openssl_crypto"
)

# Create aliases for compatibility
add_library(OpenSSL::SSL ALIAS openssl_ssl)
add_library(OpenSSL::Crypto ALIAS openssl_crypto)

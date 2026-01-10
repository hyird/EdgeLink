# BoringSSL: Google's fork of OpenSSL with CMake support
# https://github.com/google/boringssl
#
# BoringSSL is API-compatible with OpenSSL for most use cases.

include(FetchContent)

# BoringSSL build options
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
# Disable assembly optimizations (requires NASM)
set(OPENSSL_NO_ASM ON CACHE BOOL "" FORCE)
# Disable testing (prevents benchmark regex issues on MinGW)
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
# Additional benchmark options in case it's still included
set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(BENCHMARK_ENABLE_GTEST_TESTS OFF CACHE BOOL "" FORCE)
set(BENCHMARK_INSTALL_DOCS OFF CACHE BOOL "" FORCE)
set(BENCHMARK_ENABLE_INSTALL OFF CACHE BOOL "" FORCE)

FetchContent_Declare(
    boringssl
    GIT_REPOSITORY https://github.com/google/boringssl.git
    GIT_TAG        main
    GIT_SHALLOW    TRUE
)

FetchContent_MakeAvailable(boringssl)

# Disable -Werror for BoringSSL targets to fix format warnings on MinGW
# The bssl tool has format string issues that cause build failures with -Werror
if(MINGW)
    if(TARGET bssl)
        target_compile_options(bssl PRIVATE -Wno-error=format)
    endif()
endif()

# Get BoringSSL source and binary directories
FetchContent_GetProperties(boringssl SOURCE_DIR BORINGSSL_SOURCE_DIR BINARY_DIR BORINGSSL_BINARY_DIR)

# Create OpenSSL-compatible aliases
# BoringSSL provides 'ssl' and 'crypto' targets
if(NOT TARGET OpenSSL::SSL)
    add_library(OpenSSL::SSL ALIAS ssl)
endif()
if(NOT TARGET OpenSSL::Crypto)
    add_library(OpenSSL::Crypto ALIAS crypto)
endif()

# Set OpenSSL variables for find_package compatibility
# This allows jwt-cpp and other packages to find our BoringSSL
set(OPENSSL_FOUND TRUE CACHE BOOL "" FORCE)
set(OPENSSL_VERSION "1.1.1" CACHE STRING "" FORCE)
set(OPENSSL_INCLUDE_DIR "${BORINGSSL_SOURCE_DIR}/include" CACHE PATH "" FORCE)
set(OPENSSL_SSL_LIBRARY ssl CACHE STRING "" FORCE)
set(OPENSSL_CRYPTO_LIBRARY crypto CACHE STRING "" FORCE)
set(OPENSSL_LIBRARIES ssl crypto CACHE STRING "" FORCE)

# Also set OPENSSL_ROOT_DIR for packages that use it
set(OPENSSL_ROOT_DIR "${BORINGSSL_SOURCE_DIR}" CACHE PATH "" FORCE)

# Mark OpenSSL as found so find_package doesn't search again
set(OpenSSL_FOUND TRUE CACHE BOOL "" FORCE)

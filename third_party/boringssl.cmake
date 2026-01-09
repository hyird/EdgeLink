# BoringSSL: Google's fork of OpenSSL with CMake support
# https://github.com/google/boringssl
#
# BoringSSL is API-compatible with OpenSSL for most use cases.

include(FetchContent)

# BoringSSL build options
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
# Disable assembly optimizations (requires NASM)
set(OPENSSL_NO_ASM ON CACHE BOOL "" FORCE)

FetchContent_Declare(
    boringssl
    GIT_REPOSITORY https://github.com/google/boringssl.git
    GIT_TAG        main
    GIT_SHALLOW    TRUE
)

FetchContent_MakeAvailable(boringssl)

# Create OpenSSL-compatible aliases
# BoringSSL provides 'ssl' and 'crypto' targets
add_library(OpenSSL::SSL ALIAS ssl)
add_library(OpenSSL::Crypto ALIAS crypto)

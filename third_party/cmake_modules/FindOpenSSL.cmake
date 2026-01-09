# FindOpenSSL.cmake shim for BoringSSL compatibility
#
# This shim intercepts find_package(OpenSSL) calls and returns
# the BoringSSL targets that were already created by boringssl.cmake.
#
# BoringSSL provides OpenSSL-compatible API, so jwt-cpp and other
# libraries that depend on OpenSSL can use BoringSSL transparently.

# Check if BoringSSL targets are available
if(TARGET ssl AND TARGET crypto)
    # Create OpenSSL imported targets pointing to BoringSSL
    if(NOT TARGET OpenSSL::Crypto)
        add_library(OpenSSL::Crypto ALIAS crypto)
    endif()

    if(NOT TARGET OpenSSL::SSL)
        add_library(OpenSSL::SSL ALIAS ssl)
    endif()

    # Get BoringSSL include directory
    get_target_property(_BORINGSSL_INCLUDE_DIR crypto INTERFACE_INCLUDE_DIRECTORIES)
    if(_BORINGSSL_INCLUDE_DIR)
        set(OPENSSL_INCLUDE_DIR "${_BORINGSSL_INCLUDE_DIR}" CACHE PATH "OpenSSL include directory" FORCE)
    endif()

    # Set standard FindOpenSSL variables
    set(OPENSSL_FOUND TRUE)
    set(OpenSSL_FOUND TRUE)
    set(OPENSSL_VERSION "1.1.1" CACHE STRING "OpenSSL version (BoringSSL compatible)" FORCE)
    set(OPENSSL_SSL_LIBRARY ssl)
    set(OPENSSL_CRYPTO_LIBRARY crypto)
    set(OPENSSL_LIBRARIES ssl crypto)

    # Mark as found in parent scope
    set(OPENSSL_FOUND TRUE PARENT_SCOPE)
    set(OpenSSL_FOUND TRUE PARENT_SCOPE)

    if(NOT OpenSSL_FIND_QUIETLY)
        message(STATUS "Found OpenSSL: BoringSSL (compatible)")
    endif()
else()
    # BoringSSL not available, fail if REQUIRED
    if(OpenSSL_FIND_REQUIRED)
        message(FATAL_ERROR "OpenSSL not found and BoringSSL targets not available. "
                           "Ensure boringssl.cmake is included before packages that require OpenSSL.")
    endif()
    set(OPENSSL_FOUND FALSE)
    set(OpenSSL_FOUND FALSE)
endif()
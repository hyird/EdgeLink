# Boost: Peer-reviewed portable C++ source libraries
# https://www.boost.org/
# Using Boost 1.86+ with official CMake support

include(FetchContent)

FetchContent_Declare(
    Boost
    URL https://github.com/boostorg/boost/releases/download/boost-1.86.0/boost-1.86.0-cmake.tar.xz
    URL_HASH SHA256=2c5ec5edcdff47ff55e27ed9560b0a0b94b07bd07ed9928b476150e16b0efc57
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)

# Only build what we need (asio is header-only, json needs compilation)
set(BOOST_INCLUDE_LIBRARIES asio json system endian CACHE STRING "" FORCE)
set(BOOST_ENABLE_CMAKE ON CACHE BOOL "" FORCE)

# Disable building tests and examples
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(BOOST_RUNTIME_LINK static CACHE STRING "" FORCE)

FetchContent_MakeAvailable(Boost)

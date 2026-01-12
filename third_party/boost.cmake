# Boost: Peer-reviewed portable C++ source libraries
# https://www.boost.org/
# Using Boost 1.90+ with official CMake support

include(FetchContent)

FetchContent_Declare(
    Boost
    URL https://github.com/boostorg/boost/releases/download/boost-1.90.0/boost-1.90.0-cmake.tar.xz
    URL_HASH SHA256=aca59f889f0f32028ad88ba6764582b63c916ce5f77b31289ad19421a96c555f
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)

# Build what we need - asio and beast have many dependencies
set(BOOST_INCLUDE_LIBRARIES
    asio
    beast
    json
    system
    endian
    url
    # asio/beast dependencies
    bind
    date_time
    regex
    coroutine
    context
    CACHE STRING "" FORCE
)
set(BOOST_ENABLE_CMAKE ON CACHE BOOL "" FORCE)

# Disable building tests and examples
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(BOOST_RUNTIME_LINK static CACHE STRING "" FORCE)

FetchContent_MakeAvailable(Boost)

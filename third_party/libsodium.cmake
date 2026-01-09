# libsodium: A modern, portable, easy to use crypto library
# https://github.com/jedisct1/libsodium
#
# Uses libsodium-cmake wrapper for pure CMake/FetchContent build.

include(FetchContent)

# Use libsodium-cmake which provides CMake support
set(SODIUM_DISABLE_TESTS ON CACHE BOOL "" FORCE)
set(SODIUM_MINIMAL OFF CACHE BOOL "" FORCE)

FetchContent_Declare(
    libsodium
    GIT_REPOSITORY https://github.com/robinlinden/libsodium-cmake.git
    GIT_TAG        master
)

FetchContent_MakeAvailable(libsodium)

# Create alias for vcpkg compatibility
if(NOT TARGET unofficial-sodium::sodium)
    add_library(unofficial-sodium::sodium ALIAS sodium)
endif()

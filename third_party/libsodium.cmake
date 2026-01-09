# libsodium: A modern, portable, easy to use crypto library
# https://github.com/jedisct1/libsodium
#
# Uses autotools/configure for both Unix and MinGW builds.

include(FetchContent)
include(ExternalProject)

# Allow legacy FetchContent_Populate for non-CMake projects
cmake_policy(SET CMP0169 OLD)

set(SODIUM_VERSION "1.0.20")

FetchContent_Declare(
    libsodium_src
    URL https://download.libsodium.org/libsodium/releases/libsodium-${SODIUM_VERSION}.tar.gz
    URL_HASH SHA256=ebb65ef6ca439333c2bb41a0c1990587288da07f6c7fd07cb3a18cc18d30ce19
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)

FetchContent_GetProperties(libsodium_src)
if(NOT libsodium_src_POPULATED)
    FetchContent_Populate(libsodium_src)
endif()

set(SODIUM_INSTALL_DIR "${CMAKE_BINARY_DIR}/libsodium-install")

if(WIN32)
    # Windows MinGW: Use configure/make via MSYS2 shell
    # This assumes MinGW environment with bash available
    find_program(BASH_EXECUTABLE bash HINTS "D:/msys64/usr/bin" "C:/msys64/usr/bin" "C:/mingw64/bin")

    if(BASH_EXECUTABLE)
        # Convert paths to Unix style for MSYS2
        string(REPLACE "\\" "/" SODIUM_SRC_UNIX "${libsodium_src_SOURCE_DIR}")
        string(REPLACE "\\" "/" SODIUM_INSTALL_UNIX "${SODIUM_INSTALL_DIR}")

        ExternalProject_Add(libsodium_build
            SOURCE_DIR "${libsodium_src_SOURCE_DIR}"
            CONFIGURE_COMMAND ${BASH_EXECUTABLE} -c
                "cd '${SODIUM_SRC_UNIX}' && ./configure --prefix='${SODIUM_INSTALL_UNIX}' --enable-static --disable-shared --with-pic CFLAGS='-O3'"
            BUILD_COMMAND ${BASH_EXECUTABLE} -c
                "cd '${SODIUM_SRC_UNIX}' && make -j$ENV{NUMBER_OF_PROCESSORS}"
            INSTALL_COMMAND ${BASH_EXECUTABLE} -c
                "cd '${SODIUM_SRC_UNIX}' && make install"
            BUILD_IN_SOURCE TRUE
            BUILD_BYPRODUCTS "${SODIUM_INSTALL_DIR}/lib/libsodium.a"
        )

        set(SODIUM_LIBRARY "${SODIUM_INSTALL_DIR}/lib/libsodium.a")
    else()
        message(FATAL_ERROR "bash not found. Please install MSYS2 or use MinGW with bash.")
    endif()
else()
    # Unix: Build using autotools
    ExternalProject_Add(libsodium_build
        SOURCE_DIR "${libsodium_src_SOURCE_DIR}"
        CONFIGURE_COMMAND "${libsodium_src_SOURCE_DIR}/configure"
            --prefix=${SODIUM_INSTALL_DIR}
            --enable-static
            --disable-shared
            --with-pic
            "CFLAGS=-O3"
        BUILD_COMMAND make -j${CMAKE_BUILD_PARALLEL_LEVEL}
        INSTALL_COMMAND make install
        BUILD_BYPRODUCTS "${SODIUM_INSTALL_DIR}/lib/libsodium.a"
    )

    set(SODIUM_LIBRARY "${SODIUM_INSTALL_DIR}/lib/libsodium.a")
endif()

# Create imported target
add_library(sodium STATIC IMPORTED GLOBAL)
set_target_properties(sodium PROPERTIES
    IMPORTED_LOCATION "${SODIUM_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${SODIUM_INSTALL_DIR}/include"
)
add_dependencies(sodium libsodium_build)

# Create alias for vcpkg compatibility
add_library(unofficial-sodium::sodium ALIAS sodium)

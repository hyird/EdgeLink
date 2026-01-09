# LZ4 - Fast compression library
# Used for frame payload compression (COMPRESSED flag)

FetchContent_Declare(
    lz4
    GIT_REPOSITORY https://github.com/lz4/lz4.git
    GIT_TAG        v1.9.4
    GIT_SHALLOW    TRUE
    SOURCE_SUBDIR  build/cmake
)

# LZ4 options
set(LZ4_BUILD_CLI OFF CACHE BOOL "" FORCE)
set(LZ4_BUILD_LEGACY_LZ4C OFF CACHE BOOL "" FORCE)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(BUILD_STATIC_LIBS ON CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(lz4)

# Alias for consistent naming
if(NOT TARGET lz4::lz4)
    add_library(lz4::lz4 ALIAS lz4_static)
endif()

# Protocol Buffers dependency
# Google's protocol buffers for efficient serialization

FetchContent_Declare(
    protobuf
    GIT_REPOSITORY https://github.com/protocolbuffers/protobuf.git
    GIT_TAG        v29.3
    GIT_SHALLOW    TRUE
    GIT_PROGRESS   TRUE
)

# Protobuf build options
set(protobuf_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(protobuf_BUILD_CONFORMANCE OFF CACHE BOOL "" FORCE)
set(protobuf_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(protobuf_BUILD_PROTOBUF_BINARIES ON CACHE BOOL "" FORCE)
set(protobuf_BUILD_PROTOC_BINARIES ON CACHE BOOL "" FORCE)
set(protobuf_BUILD_LIBPROTOC ON CACHE BOOL "" FORCE)
set(protobuf_BUILD_LIBUPB OFF CACHE BOOL "" FORCE)
set(protobuf_BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(protobuf_INSTALL OFF CACHE BOOL "" FORCE)
set(protobuf_MSVC_STATIC_RUNTIME OFF CACHE BOOL "" FORCE)

# Let protobuf use its bundled Abseil
set(protobuf_ABSL_PROVIDER "module" CACHE STRING "" FORCE)

# Disable warnings for protobuf
set(protobuf_DISABLE_RTTI OFF CACHE BOOL "" FORCE)

# Fix MinGW compatibility: abseil's time_zone_lookup.cc uses WinRT APIs
# (WindowsCreateStringReference, etc.) that are not available in MinGW headers.
# We need to define NTDDI_VERSION to below Windows 10 to disable WinRT usage.
if(MINGW)
    # Save original compile definitions
    get_directory_property(_original_compile_defs COMPILE_DEFINITIONS)
    # Add NTDDI_VERSION for Windows 8.1 to disable WinRT API usage
    add_compile_definitions(NTDDI_VERSION=0x06030000)
endif()

FetchContent_MakeAvailable(protobuf)

if(MINGW)
    # Restore original compile definitions
    set_directory_properties(PROPERTIES COMPILE_DEFINITIONS "${_original_compile_defs}")
endif()

# Create alias targets for compatibility
if(NOT TARGET protobuf::libprotobuf)
    add_library(protobuf::libprotobuf ALIAS libprotobuf)
endif()

if(NOT TARGET protobuf::protoc)
    add_executable(protobuf::protoc ALIAS protoc)
endif()

message(STATUS "Protobuf configured successfully")

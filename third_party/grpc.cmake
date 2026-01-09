# gRPC: A high performance, open source, general RPC framework
# https://github.com/grpc/grpc
#
# gRPC manages its own dependencies via submodules.
# We only need to set configuration options.

include(FetchContent)

# Fix compatibility with older CMakeLists.txt in submodules (c-ares, etc.)
set(CMAKE_POLICY_VERSION_MINIMUM 3.5 CACHE STRING "" FORCE)

# =============================================================================
# gRPC Configuration Options
# =============================================================================

# Disable features we don't need
set(gRPC_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(gRPC_BUILD_CSHARP_EXT OFF CACHE BOOL "" FORCE)
set(gRPC_BUILD_GRPC_CSHARP_PLUGIN OFF CACHE BOOL "" FORCE)
set(gRPC_BUILD_GRPC_NODE_PLUGIN OFF CACHE BOOL "" FORCE)
set(gRPC_BUILD_GRPC_OBJECTIVE_C_PLUGIN OFF CACHE BOOL "" FORCE)
set(gRPC_BUILD_GRPC_PHP_PLUGIN OFF CACHE BOOL "" FORCE)
set(gRPC_BUILD_GRPC_PYTHON_PLUGIN OFF CACHE BOOL "" FORCE)
set(gRPC_BUILD_GRPC_RUBY_PLUGIN OFF CACHE BOOL "" FORCE)
set(gRPC_INSTALL OFF CACHE BOOL "" FORCE)

# Let gRPC manage its own dependencies via submodules
set(gRPC_ABSL_PROVIDER "module" CACHE STRING "" FORCE)
set(gRPC_CARES_PROVIDER "module" CACHE STRING "" FORCE)
set(gRPC_PROTOBUF_PROVIDER "module" CACHE STRING "" FORCE)
set(gRPC_RE2_PROVIDER "module" CACHE STRING "" FORCE)
set(gRPC_SSL_PROVIDER "package" CACHE STRING "" FORCE)  # Use system OpenSSL
set(gRPC_ZLIB_PROVIDER "module" CACHE STRING "" FORCE)

# =============================================================================
# Dependency Configuration (for gRPC's submodules)
# =============================================================================

# Abseil
set(ABSL_PROPAGATE_CXX_STD ON CACHE BOOL "" FORCE)
set(ABSL_BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(ABSL_ENABLE_INSTALL OFF CACHE BOOL "" FORCE)

# c-ares
set(CARES_STATIC ON CACHE BOOL "" FORCE)
set(CARES_SHARED OFF CACHE BOOL "" FORCE)
set(CARES_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(CARES_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(CARES_INSTALL OFF CACHE BOOL "" FORCE)

# RE2
set(RE2_BUILD_TESTING OFF CACHE BOOL "" FORCE)

# Protobuf
set(protobuf_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(protobuf_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(protobuf_BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(protobuf_INSTALL OFF CACHE BOOL "" FORCE)
set(protobuf_ABSL_PROVIDER "module" CACHE STRING "" FORCE)
set(utf8_range_ENABLE_INSTALL OFF CACHE BOOL "" FORCE)

# zlib
set(ZLIB_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)

# =============================================================================
# Fetch gRPC (with submodules)
# =============================================================================

FetchContent_Declare(
    grpc
    GIT_REPOSITORY https://github.com/grpc/grpc.git
    GIT_TAG        v1.68.1
    GIT_SHALLOW    TRUE
    GIT_SUBMODULES_RECURSE TRUE
)

FetchContent_MakeAvailable(grpc)

# =============================================================================
# Export Variables for Proto Generation
# =============================================================================

set(EDGELINK_PROTOC_EXECUTABLE $<TARGET_FILE:protoc> CACHE INTERNAL "Path to protoc")
set(EDGELINK_GRPC_CPP_PLUGIN $<TARGET_FILE:grpc_cpp_plugin> CACHE INTERNAL "Path to grpc_cpp_plugin")

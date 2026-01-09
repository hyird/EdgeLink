# Proto Generation Helper for EdgeLink
#
# This module provides functions for generating gRPC/protobuf C++ sources
# from .proto files.

# Generate protobuf and gRPC sources from a proto file
#
# Usage:
#   edgelink_generate_proto(TARGET_NAME PROTO_FILE)
#
# Arguments:
#   TARGET_NAME - Name of the static library target to create
#   PROTO_FILE  - Path to the .proto file
#
# Creates a static library with the generated sources, linked to
# protobuf and gRPC libraries.
#
function(edgelink_generate_proto TARGET_NAME PROTO_FILE)
    get_filename_component(PROTO_NAME ${PROTO_FILE} NAME_WE)
    get_filename_component(PROTO_DIR ${PROTO_FILE} DIRECTORY)
    get_filename_component(PROTO_FILE_ABS ${PROTO_FILE} ABSOLUTE)

    # Output directory for generated files
    set(PROTO_GEN_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated")
    file(MAKE_DIRECTORY ${PROTO_GEN_DIR})

    # Generated file paths
    set(PROTO_SRCS "${PROTO_GEN_DIR}/${PROTO_NAME}.pb.cc")
    set(PROTO_HDRS "${PROTO_GEN_DIR}/${PROTO_NAME}.pb.h")
    set(GRPC_SRCS "${PROTO_GEN_DIR}/${PROTO_NAME}.grpc.pb.cc")
    set(GRPC_HDRS "${PROTO_GEN_DIR}/${PROTO_NAME}.grpc.pb.h")

    # Custom command to generate protobuf and gRPC source files
    add_custom_command(
        OUTPUT "${PROTO_SRCS}" "${PROTO_HDRS}" "${GRPC_SRCS}" "${GRPC_HDRS}"
        COMMAND protoc
        ARGS --grpc_out "${PROTO_GEN_DIR}"
             --cpp_out "${PROTO_GEN_DIR}"
             -I "${PROTO_DIR}"
             --plugin=protoc-gen-grpc=$<TARGET_FILE:grpc_cpp_plugin>
             "${PROTO_FILE_ABS}"
        DEPENDS "${PROTO_FILE_ABS}" protoc grpc_cpp_plugin
        COMMENT "Generating gRPC/protobuf sources for ${PROTO_NAME}"
        VERBATIM
    )

    # Create static library from generated sources
    add_library(${TARGET_NAME} STATIC
        ${PROTO_SRCS}
        ${GRPC_SRCS}
    )

    target_include_directories(${TARGET_NAME} PUBLIC
        ${PROTO_GEN_DIR}
    )

    target_link_libraries(${TARGET_NAME} PUBLIC
        protobuf::libprotobuf
        gRPC::grpc++
        gRPC::grpc++_reflection
    )

    # Suppress warnings in generated code
    if(MSVC)
        target_compile_options(${TARGET_NAME} PRIVATE /W0)
    else()
        target_compile_options(${TARGET_NAME} PRIVATE -w)
    endif()
endfunction()

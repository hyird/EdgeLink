# jwt-cpp: A header only library for creating and validating JSON Web Tokens
# https://github.com/Thalhammer/jwt-cpp
# Depends on: nlohmann-json, BoringSSL (must be fetched first)

include(FetchContent)

# Suppress CMP0135 deprecation warning from jwt-cpp
# CMP0135 controls timestamp handling for URL downloads
set(CMAKE_POLICY_DEFAULT_CMP0135 NEW)

FetchContent_Declare(
    jwt_cpp
    GIT_REPOSITORY https://github.com/Thalhammer/jwt-cpp.git
    GIT_TAG        v0.7.1
    GIT_SHALLOW    TRUE
)

set(JWT_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(JWT_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(JWT_DISABLE_PICOJSON ON CACHE BOOL "" FORCE)  # Use nlohmann-json instead
set(JWT_EXTERNAL_NLOHMANN_JSON ON CACHE BOOL "" FORCE)

# Use our FindOpenSSL shim to provide BoringSSL as OpenSSL
# This must be prepended to CMAKE_MODULE_PATH before jwt-cpp runs find_package(OpenSSL)
list(PREPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake_modules")

FetchContent_MakeAvailable(jwt_cpp)

# Restore CMAKE_MODULE_PATH
list(REMOVE_ITEM CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake_modules")

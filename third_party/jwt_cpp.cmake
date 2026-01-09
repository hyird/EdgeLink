# jwt-cpp: A header only library for creating and validating JSON Web Tokens
# https://github.com/Thalhammer/jwt-cpp
# Depends on: nlohmann-json, BoringSSL (must be fetched first)

include(FetchContent)

FetchContent_Declare(
    jwt_cpp
    GIT_REPOSITORY https://github.com/Thalhammer/jwt-cpp.git
    GIT_TAG        v0.7.0
    GIT_SHALLOW    TRUE
)

set(JWT_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(JWT_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(JWT_DISABLE_PICOJSON ON CACHE BOOL "" FORCE)  # Use nlohmann-json instead
set(JWT_EXTERNAL_NLOHMANN_JSON ON CACHE BOOL "" FORCE)

# Skip OpenSSL search - we already have targets from BoringSSL
set(CMAKE_DISABLE_FIND_PACKAGE_OpenSSL TRUE CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(jwt_cpp)

# Restore the find package setting
unset(CMAKE_DISABLE_FIND_PACKAGE_OpenSSL CACHE)

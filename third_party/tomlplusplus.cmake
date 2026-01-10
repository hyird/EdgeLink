# toml++ - Header-only TOML config file parser for C++17
# https://github.com/marzer/tomlplusplus

FetchContent_Declare(
    tomlplusplus
    GIT_REPOSITORY https://github.com/marzer/tomlplusplus.git
    GIT_TAG        v3.4.0
    GIT_SHALLOW    TRUE
)

FetchContent_MakeAvailable(tomlplusplus)

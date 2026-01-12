# SQLite3: Embedded SQL database engine
# https://www.sqlite.org/

include(FetchContent)

# Allow legacy FetchContent_Populate for non-CMake projects
# CMP0169 was introduced in CMake 3.30
if(POLICY CMP0169)
    cmake_policy(SET CMP0169 OLD)
endif()

FetchContent_Declare(
    sqlite3
    URL https://www.sqlite.org/2026/sqlite-amalgamation-3510200.zip
    URL_HASH SHA3_256=9a9dd4eef7a97809bfacd84a7db5080a5c0eff7aaf1fc1aca20a6dc9a0c26f96
)

FetchContent_GetProperties(sqlite3)
if(NOT sqlite3_POPULATED)
    FetchContent_Populate(sqlite3)

    # Create SQLite3 static library
    add_library(sqlite3 STATIC
        ${sqlite3_SOURCE_DIR}/sqlite3.c
    )

    target_include_directories(sqlite3 PUBLIC
        ${sqlite3_SOURCE_DIR}
    )

    # SQLite configuration
    target_compile_definitions(sqlite3 PRIVATE
        SQLITE_ENABLE_COLUMN_METADATA
        SQLITE_ENABLE_FTS5
        SQLITE_ENABLE_JSON1
        SQLITE_ENABLE_RTREE
        SQLITE_THREADSAFE=2
        SQLITE_DQS=0
    )

    # Platform-specific configuration
    if(WIN32)
        target_compile_definitions(sqlite3 PRIVATE SQLITE_OS_WIN)
    else()
        target_compile_definitions(sqlite3 PRIVATE SQLITE_OS_UNIX)
        find_package(Threads REQUIRED)
        target_link_libraries(sqlite3 PRIVATE Threads::Threads ${CMAKE_DL_LIBS})
    endif()

    # Suppress warnings
    if(MSVC)
        target_compile_options(sqlite3 PRIVATE /W0)
    else()
        target_compile_options(sqlite3 PRIVATE -w)
    endif()
endif()

# Create alias for compatibility
add_library(SQLite::SQLite3 ALIAS sqlite3)

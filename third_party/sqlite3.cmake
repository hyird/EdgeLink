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
    URL https://www.sqlite.org/2024/sqlite-amalgamation-3460100.zip
    URL_HASH SHA256=77823cb110929c2bcb0f5d48e4833b5c59a8a6e40cdea3936b99e199dbbe5784
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

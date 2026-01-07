# Third-Party Dependencies

This directory contains header-only third-party libraries used by EdgeLink.

## Directory Structure

```
third_party/
├── jwt-cpp/           # JWT token creation and validation
│   ├── include/
│   │   └── jwt-cpp/
│   │       └── jwt.h
│   └── README.md
├── picojson/          # JSON parser (jwt-cpp backend)
│   ├── include/
│   │   └── picojson/
│   │       └── picojson.h
│   └── README.md
└── README.md          # This file
```

## Current State

**Note**: The current implementations are **stub files** for compilation testing.
For production deployment, replace these with the actual library implementations.

## Adding New Libraries

When adding a new third-party library:

1. Create a directory: `third_party/<library-name>/`
2. Add include files: `third_party/<library-name>/include/<library-name>/`
3. Add a README.md with source URL and license info
4. Update CMakeLists.txt to include the new path:

```cmake
set(NEW_LIB_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/<library-name>/include)
target_include_directories(edgelink-common PUBLIC ${NEW_LIB_INCLUDE_DIR})
```

## License Information

| Library   | License      | URL |
|-----------|--------------|-----|
| jwt-cpp   | MIT          | https://github.com/Thalhammer/jwt-cpp |
| picojson  | BSD 2-Clause | https://github.com/kazuho/picojson |

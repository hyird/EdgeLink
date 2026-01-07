#!/bin/bash
# =============================================================================
# EdgeLink Linux Build Script (vcpkg + musl full static)
# =============================================================================
# Usage: ./scripts/build-linux.sh [--release|--debug] [--clean]
#
# Requirements:
#   - Alpine Linux (for musl libc)
#   - vcpkg installed at $VCPKG_ROOT
#   - cmake, ninja, git, build-base
#
# vcpkg Triplets:
#   - x64-linux: Official triplet, static libraries (recommended)
#   - arm64-linux: ARM64 static libraries (community)
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_TYPE="Release"
CLEAN_BUILD=0
TRIPLET="x64-linux"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --release)
            BUILD_TYPE="Release"
            shift
            ;;
        --debug)
            BUILD_TYPE="Debug"
            shift
            ;;
        --clean)
            CLEAN_BUILD=1
            shift
            ;;
        --triplet)
            TRIPLET="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

echo "=== EdgeLink Linux Build ==="
echo "Build Type: $BUILD_TYPE"
echo "Triplet: $TRIPLET"
echo "Project: $PROJECT_DIR"

# Check vcpkg
if [ -z "$VCPKG_ROOT" ]; then
    if [ -d "/opt/vcpkg" ]; then
        export VCPKG_ROOT="/opt/vcpkg"
    elif [ -d "$HOME/vcpkg" ]; then
        export VCPKG_ROOT="$HOME/vcpkg"
    else
        echo "Error: VCPKG_ROOT not set and vcpkg not found"
        echo "Install vcpkg: git clone https://github.com/microsoft/vcpkg.git && ./vcpkg/bootstrap-vcpkg.sh"
        exit 1
    fi
fi
echo "vcpkg: $VCPKG_ROOT"

# Clean if requested
if [ $CLEAN_BUILD -eq 1 ]; then
    echo "Cleaning build directory..."
    rm -rf "$PROJECT_DIR/build"
    rm -rf "$PROJECT_DIR/vcpkg_installed"
fi

cd "$PROJECT_DIR"

# Configure with CMake
echo ""
echo "=== Configuring ==="
cmake -B build -G Ninja \
    -DCMAKE_BUILD_TYPE=$BUILD_TYPE \
    -DCMAKE_TOOLCHAIN_FILE="$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake" \
    -DVCPKG_TARGET_TRIPLET=$TRIPLET \
    -DVCPKG_HOST_TRIPLET=$TRIPLET \
    -DBUILD_SHARED_LIBS=OFF \
    -DEDGELINK_STATIC=ON \
    -DBUILD_CONTROLLER=ON \
    -DBUILD_SERVER=ON \
    -DBUILD_CLIENT=ON \
    -DBUILD_TESTS=OFF

# Build
echo ""
echo "=== Building ==="
cmake --build build --config $BUILD_TYPE -j$(nproc)

# Strip binaries in release mode
if [ "$BUILD_TYPE" = "Release" ]; then
    echo ""
    echo "=== Stripping binaries ==="
    strip build/edgelink-controller build/edgelink-server build/edgelink-client 2>/dev/null || true
fi

# Verify
echo ""
echo "=== Build Results ==="
ls -lh build/edgelink-*

echo ""
echo "=== Binary Analysis ==="
file build/edgelink-controller
file build/edgelink-server
file build/edgelink-client

echo ""
echo "=== Dynamic Dependencies ==="
ldd build/edgelink-controller 2>&1 || echo "(statically linked)"

echo ""
echo "=== Build Complete ==="
echo "Binaries are in: $PROJECT_DIR/build/"

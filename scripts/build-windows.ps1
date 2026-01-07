# =============================================================================
# EdgeLink Windows Build Script (vcpkg + MSVC static)
# =============================================================================
# Usage: .\scripts\build-windows.ps1 [-Release] [-Debug] [-Clean]
#
# Requirements:
#   - Visual Studio 2022 with C++ Desktop workload
#   - vcpkg installed at $env:VCPKG_ROOT
#   - CMake 3.20+
#
# vcpkg Triplets:
#   - x64-windows-static: Static libraries + static CRT (/MT)
#   - arm64-windows-static: ARM64 static (for ARM Windows)
# =============================================================================

param(
    [switch]$Release,
    [switch]$Debug,
    [switch]$Clean,
    [string]$Triplet = "x64-windows-static",
    [string]$Arch = "x64"
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir = Split-Path -Parent $ScriptDir

# Determine build type
if ($Debug) {
    $BuildType = "Debug"
} else {
    $BuildType = "Release"
}

Write-Host "=== EdgeLink Windows Build ===" -ForegroundColor Cyan
Write-Host "Build Type: $BuildType"
Write-Host "Triplet: $Triplet"
Write-Host "Architecture: $Arch"
Write-Host "Project: $ProjectDir"

# Check vcpkg
if (-not $env:VCPKG_ROOT) {
    if (Test-Path "C:\vcpkg") {
        $env:VCPKG_ROOT = "C:\vcpkg"
    } elseif (Test-Path "$env:USERPROFILE\vcpkg") {
        $env:VCPKG_ROOT = "$env:USERPROFILE\vcpkg"
    } else {
        Write-Host "Error: VCPKG_ROOT not set and vcpkg not found" -ForegroundColor Red
        Write-Host "Install vcpkg:"
        Write-Host "  git clone https://github.com/microsoft/vcpkg.git C:\vcpkg"
        Write-Host "  C:\vcpkg\bootstrap-vcpkg.bat"
        exit 1
    }
}
Write-Host "vcpkg: $env:VCPKG_ROOT"

# Clean if requested
if ($Clean) {
    Write-Host "Cleaning build directory..." -ForegroundColor Yellow
    if (Test-Path "$ProjectDir\build") {
        Remove-Item -Recurse -Force "$ProjectDir\build"
    }
    if (Test-Path "$ProjectDir\vcpkg_installed") {
        Remove-Item -Recurse -Force "$ProjectDir\vcpkg_installed"
    }
}

Set-Location $ProjectDir

# Configure with CMake
Write-Host ""
Write-Host "=== Configuring ===" -ForegroundColor Cyan
$cmakeArgs = @(
    "-B", "build",
    "-G", "Visual Studio 17 2022",
    "-A", $Arch,
    "-DCMAKE_BUILD_TYPE=$BuildType",
    "-DCMAKE_TOOLCHAIN_FILE=$env:VCPKG_ROOT\scripts\buildsystems\vcpkg.cmake",
    "-DVCPKG_TARGET_TRIPLET=$Triplet",
    "-DVCPKG_HOST_TRIPLET=$Triplet",
    "-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded",
    "-DBUILD_SHARED_LIBS=OFF",
    "-DBUILD_CONTROLLER=ON",
    "-DBUILD_SERVER=ON",
    "-DBUILD_CLIENT=ON",
    "-DBUILD_TESTS=OFF"
)

& cmake @cmakeArgs
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# Build
Write-Host ""
Write-Host "=== Building ===" -ForegroundColor Cyan
& cmake --build build --config $BuildType --parallel
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# Results
Write-Host ""
Write-Host "=== Build Results ===" -ForegroundColor Cyan
$outputDir = "build\$BuildType"
Get-ChildItem "$outputDir\edgelink-*.exe" | ForEach-Object {
    Write-Host "$($_.Name) - $([math]::Round($_.Length / 1MB, 2)) MB"
}

Write-Host ""
Write-Host "=== Build Complete ===" -ForegroundColor Green
Write-Host "Binaries in: $ProjectDir\$outputDir\"
Write-Host "  - edgelink-controller.exe"
Write-Host "  - edgelink-server.exe"
Write-Host "  - edgelink-client.exe (wintun statically linked)"
Write-Host ""
Write-Host "Note: Run client as Administrator to create virtual network adapter"

# Linux Build Guide

本文档说明如何在 Linux 上编译 EdgeLink，生成完全静态的二进制文件。

## 构建环境

推荐使用 **Alpine Linux** 配合 vcpkg 构建全静态二进制。

## 前置条件

```bash
# 安装构建依赖
apk add --no-cache \
    build-base cmake ninja git curl zip unzip tar \
    pkgconfig linux-headers musl-dev perl bash python3 \
    autoconf automake libtool

# 验证 Linux 头文件已安装 (vcpkg openssl 需要)
test -f /usr/include/linux/version.h || echo "WARNING: linux-headers may not be installed correctly"
```

## 安装 vcpkg

```bash
# 克隆 vcpkg
git clone --depth 1 https://github.com/microsoft/vcpkg.git /opt/vcpkg
cd /opt/vcpkg
./bootstrap-vcpkg.sh -disableMetrics

# 设置环境变量
export VCPKG_ROOT=/opt/vcpkg
export PATH="$VCPKG_ROOT:$PATH"

# 重要：Alpine/musl 环境必须设置此变量，强制使用系统的 cmake/ninja
export VCPKG_FORCE_SYSTEM_BINARIES=1
```

## 使用构建脚本

```bash
# 添加执行权限
chmod +x scripts/build-linux.sh

# Release 构建 (默认)
./scripts/build-linux.sh

# Debug 构建
./scripts/build-linux.sh --debug

# 清理后重新构建
./scripts/build-linux.sh --clean

# 指定其他 triplet
./scripts/build-linux.sh --triplet arm64-linux-release
```

## 手动构建

```bash
# 配置 (使用自定义 x64-linux-musl triplet)
cmake -B build -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_TOOLCHAIN_FILE=$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake \
    -DVCPKG_OVERLAY_TRIPLETS=./triplets \
    -DVCPKG_TARGET_TRIPLET=x64-linux-musl \
    -DVCPKG_HOST_TRIPLET=x64-linux-musl \
    -DBUILD_SHARED_LIBS=OFF \
    -DEDGELINK_STATIC=ON \
    -DBUILD_CONTROLLER=ON \
    -DBUILD_SERVER=ON \
    -DBUILD_CLIENT=ON \
    -DBUILD_TESTS=OFF

# 构建
cmake --build build --config Release -j$(nproc)

# Strip 二进制文件
strip build/edgelink-*
```

## 验证静态链接

```bash
file edgelink-controller
# 输出: edgelink-controller: ELF 64-bit LSB executable, x86-64, ... statically linked

ldd edgelink-controller
# 输出: not a dynamic executable (或类似提示)
```

## vcpkg Triplet 说明

| Triplet | 描述 |
|---------|------|
| `x64-linux-musl` | 自定义 triplet，x64 静态库，只构建 Release (推荐用于 Alpine) |
| `x64-linux` | 官方 triplet，x64 静态库 (debug 构建可能在 Alpine 上失败) |
| `arm64-linux` | 社区 triplet，ARM64 静态库 |

使用自定义 `x64-linux-musl` triplet 可以避免 boost-context 等库在 musl 上的 debug 构建问题。

**注意**: 自定义 triplet 位于 `triplets/` 目录中，使用 `--overlay-triplets` 参数启用。

## 为什么使用 Alpine + vcpkg?

1. **musl libc** - Alpine 使用 musl 而非 glibc，支持真正的静态链接
2. **vcpkg** - 统一管理所有 C++ 依赖，确保一致性
3. **可移植性** - 生成的二进制可在任何 Linux 发行版上运行
4. **体积小** - 静态链接后无需携带运行时库

## 输出文件

构建完成后，二进制文件位于 `build/` 目录：

```
build/
├── edgelink-controller   # 控制器
├── edgelink-server       # 中继/STUN 服务器
└── edgelink-client       # 客户端
```

## 运行

客户端需要 root 权限来创建 TUN 设备：

```bash
sudo ./edgelink-client -c config/client.json
```

服务器和控制器通常也需要 root 权限来绑定特权端口：

```bash
sudo ./edgelink-controller -c config/controller.json
sudo ./edgelink-server -c config/server.json
```

## 故障排除

### vcpkg 下载的 cmake 无法运行 (Alpine/musl)

错误信息：
```
error: cmake --version failed with exit code 127
sh: cmake: not found
```

原因：vcpkg 默认下载 glibc 链接的二进制文件，无法在 musl 环境运行。

解决方案：
```bash
export VCPKG_FORCE_SYSTEM_BINARIES=1
```

### boost-context 构建失败

错误信息：
```
error: building boost-context:x64-linux failed with: BUILD_FAILED
```

原因：boost-context 的 debug 构建在 Alpine 上有问题。

解决方案：使用自定义 x64-linux-musl triplet (只构建 release)：
```bash
-DVCPKG_OVERLAY_TRIPLETS=./triplets
-DVCPKG_TARGET_TRIPLET=x64-linux-musl
```

### vcpkg 依赖安装失败

确保网络连接正常，vcpkg 需要从 GitHub 下载源码和补丁。

### 编译错误：找不到头文件

确保使用了 vcpkg toolchain file：
```bash
-DCMAKE_TOOLCHAIN_FILE=$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake
```

### 链接错误：undefined reference

确保使用了正确的 triplet 并启用了静态链接：
```bash
-DVCPKG_OVERLAY_TRIPLETS=./triplets
-DVCPKG_TARGET_TRIPLET=x64-linux-musl
-DBUILD_SHARED_LIBS=OFF
-DEDGELINK_STATIC=ON
```

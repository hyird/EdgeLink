# Linux Build Guide

本文档说明如何在 Linux 上编译 EdgeLink，生成完全静态的二进制文件。

## 构建方式

有两种方式可以构建全静态二进制：

1. **Docker 构建** (推荐) - 使用 Alpine 容器 + vcpkg
2. **本地构建** - 在 Alpine Linux 上使用 vcpkg

## 方式一：Docker 构建 (推荐)

最简单的方式是使用 Docker，无需在本地配置任何依赖。

### 构建所有组件

```bash
# 构建全静态 Docker 镜像
docker build -f Dockerfile.static -t edgelink-static .

# 或构建特定 target
docker build -f Dockerfile.static --target controller -t edgelink-controller .
docker build -f Dockerfile.static --target server -t edgelink-server .
docker build -f Dockerfile.static --target client -t edgelink-client .
```

### 提取二进制文件

```bash
# 创建临时容器并复制二进制文件
docker create --name tmp edgelink-static
docker cp tmp:/edgelink-controller .
docker cp tmp:/edgelink-server .
docker cp tmp:/edgelink-client .
docker rm tmp

# 或使用 binaries target 一次性提取
docker build -f Dockerfile.static --target binaries -o out .
ls out/
```

### 验证静态链接

```bash
file edgelink-controller
# 输出: edgelink-controller: ELF 64-bit LSB executable, x86-64, ... statically linked

ldd edgelink-controller
# 输出: not a dynamic executable (或类似提示)
```

## 方式二：本地构建 (Alpine Linux)

在 Alpine Linux 上本地构建。

### 前置条件

```bash
# 安装构建依赖
apk add --no-cache \
    build-base cmake ninja git curl zip unzip tar \
    pkgconfig linux-headers perl bash python3
```

### 安装 vcpkg

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

### 使用构建脚本

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
./scripts/build-linux.sh --triplet arm64-linux
```

### 手动构建

```bash
# 配置
cmake -B build -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_TOOLCHAIN_FILE=$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake \
    -DVCPKG_TARGET_TRIPLET=x64-linux \
    -DVCPKG_HOST_TRIPLET=x64-linux \
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

## vcpkg Triplet 说明

| Triplet | 描述 |
|---------|------|
| `x64-linux` | 官方 triplet，x64 静态库 |
| `arm64-linux` | 社区 triplet，ARM64 静态库 |

使用这些 triplet 配合 Alpine (musl libc) 可以生成完全静态的二进制文件。

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
-DVCPKG_TARGET_TRIPLET=x64-linux
-DBUILD_SHARED_LIBS=OFF
-DEDGELINK_STATIC=ON
```

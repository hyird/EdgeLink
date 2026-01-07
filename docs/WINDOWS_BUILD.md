# Windows Build Guide

本文档说明如何在 Windows 上编译和运行 EdgeLink 客户端。

## 前置条件

1. **Visual Studio 2022** (带 C++ 桌面开发工作负载)
2. **CMake** 3.20+
3. **Git**
4. **vcpkg**

## 安装 vcpkg

```powershell
# 克隆 vcpkg
git clone https://github.com/microsoft/vcpkg.git C:\vcpkg
cd C:\vcpkg

# 引导安装
.\bootstrap-vcpkg.bat

# 设置环境变量
[Environment]::SetEnvironmentVariable("VCPKG_ROOT", "C:\vcpkg", "User")
$env:VCPKG_ROOT = "C:\vcpkg"
```

## 编译 (使用构建脚本)

推荐使用提供的构建脚本：

```powershell
# Release 构建 (默认)
.\scripts\build-windows.ps1

# Debug 构建
.\scripts\build-windows.ps1 -Debug

# 清理后重新构建
.\scripts\build-windows.ps1 -Clean
```

## 手动编译

### 使用 vcpkg x64-windows-static triplet

```powershell
# 配置 (构建所有组件，静态链接)
cmake -B build -G "Visual Studio 17 2022" -A x64 `
    -DCMAKE_TOOLCHAIN_FILE="$env:VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake" `
    -DVCPKG_TARGET_TRIPLET=x64-windows-static `
    -DVCPKG_HOST_TRIPLET=x64-windows-static `
    -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded `
    -DBUILD_SHARED_LIBS=OFF `
    -DBUILD_CONTROLLER=ON `
    -DBUILD_SERVER=ON `
    -DBUILD_CLIENT=ON `
    -DBUILD_TESTS=OFF

# 编译
cmake --build build --config Release

# 输出文件在 build/Release/
#   - edgelink-controller.exe
#   - edgelink-server.exe
#   - edgelink-client.exe
```

## vcpkg Triplet 说明

| Triplet | 描述 |
|---------|------|
| `x64-windows-static` | 64位 Windows，静态库 + 静态 CRT (/MT) |
| `arm64-windows-static` | ARM64 Windows，静态库 + 静态 CRT |

## 静态编译说明

使用 `x64-windows-static` triplet 后，所有可执行文件不依赖额外的 DLL 文件：

- 无需安装 Visual C++ Redistributable
- 无需复制其他依赖 DLL
- Wintun 驱动静态链接到客户端可执行文件中
- 可执行文件体积会增大，但部署更简单

## Wintun 驱动嵌入 (可选)

默认情况下，客户端会使用系统已安装的 Wintun 驱动。如果要将 Wintun 驱动嵌入到可执行文件中实现单文件部署：

1. 从 https://www.wintun.net/ 下载 wintun
2. 解压后使用 `-DWINTUN_DRIVER_DIR` 参数指定驱动目录：

```powershell
cmake -B build -G "Visual Studio 17 2022" -A x64 `
    -DWINTUN_DRIVER_DIR="C:\path\to\wintun\bin\amd64" `
    ... 其他参数
```

嵌入后，客户端启动时会自动提取并安装驱动。

如果不嵌入驱动，请确保系统已安装 Wintun 驱动，或者将驱动文件（wintun.sys, wintun.inf, wintun.cat）放在可执行文件同目录。

## 运行

运行客户端需要**管理员权限**（创建虚拟网卡和安装驱动需要）。

1. 准备配置文件 `client.json`
2. 以管理员权限运行：

```powershell
# 使用管理员 PowerShell
.\edgelink-client.exe -c client.json
```

## 配置示例

`client.json`:
```json
{
  "node_id": "client-001",
  "network_id": "net-001",
  "controller_url": "wss://controller.example.com:8443/control",
  "auth_token": "your-jwt-token",
  "tun": {
    "name": "EdgeLink",
    "ip": "10.100.0.10",
    "prefix_len": 24,
    "mtu": 1400
  },
  "log_level": "info"
}
```

## 故障排除

### 无法加载 wintun.dll
- 确保 `wintun.dll` 在可执行文件同目录或 PATH 中
- 确保使用的是 64 位版本的 wintun.dll

### 权限错误
- 必须以管理员权限运行
- 右键点击 PowerShell -> "以管理员身份运行"

### 虚拟网卡无法创建
- 检查 Windows Defender 防火墙设置
- 确保 Windows 网络服务正常运行

## 防火墙配置

允许 EdgeLink 通过防火墙：

```powershell
# 管理员 PowerShell
New-NetFirewallRule -DisplayName "EdgeLink Client" `
    -Direction Inbound `
    -Program "C:\path\to\edgelink-client.exe" `
    -Action Allow
```

## GitHub Actions CI/CD

项目已配置 GitHub Actions 自动构建（静态编译）：

- **Linux**: 构建所有组件 (controller, server, client)，使用 `-static-libgcc -static-libstdc++`
- **Windows**: 仅构建客户端，使用 `/MT` 静态运行时 + vcpkg 静态库

每次推送到 `main`/`master`/`develop` 分支或创建 Pull Request 时自动触发构建。

发布 tag (格式 `v*`) 会自动创建 GitHub Release 并上传构建产物。

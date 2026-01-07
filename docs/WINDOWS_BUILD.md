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

## 安装依赖

```powershell
# 安装所需的包
vcpkg install boost-asio:x64-windows
vcpkg install boost-json:x64-windows
vcpkg install boost-beast:x64-windows
vcpkg install openssl:x64-windows
vcpkg install spdlog:x64-windows
vcpkg install nlohmann-json:x64-windows
vcpkg install libsodium:x64-windows
```

或者使用项目的 `vcpkg.json` 清单模式自动安装。

## 下载 Wintun

1. 从 https://www.wintun.net/ 下载 wintun
2. 解压并复制到 `third_party/wintun/`:
   ```
   third_party/wintun/
   ├── wintun.h    (从 include/ 复制)
   └── wintun.dll  (从 bin/amd64/ 复制)
   ```

## 编译

```powershell
# 配置 (只编译客户端)
cmake -B build -G "Visual Studio 17 2022" -A x64 `
    -DCMAKE_TOOLCHAIN_FILE="$env:VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake" `
    -DBUILD_CONTROLLER=OFF `
    -DBUILD_SERVER=OFF `
    -DBUILD_CLIENT=ON `
    -DBUILD_TESTS=OFF

# 编译
cmake --build build --config Release

# 输出文件在 build/Release/edgelink-client.exe
```

## 运行

运行客户端需要**管理员权限**（创建虚拟网卡需要）。

1. 确保 `wintun.dll` 与 `edgelink-client.exe` 在同一目录
2. 准备配置文件 `client.json`
3. 以管理员权限运行：

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

### 依赖缺失
如果提示 DLL 缺失，可以：
1. 安装 [Visual C++ Redistributable](https://aka.ms/vs/17/release/vc_redist.x64.exe)
2. 将所需 DLL 复制到可执行文件目录

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

项目已配置 GitHub Actions 自动构建：

- **Linux**: 构建所有组件 (controller, server, client)
- **Windows**: 仅构建客户端 (使用 wintun)
- **macOS**: 仅构建客户端 (utun)

每次推送到 `main`/`master`/`develop` 分支或创建 Pull Request 时自动触发构建。

发布 tag (格式 `v*`) 会自动创建 GitHub Release 并上传构建产物。

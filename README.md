# EdgeLink

EdgeLink 是一个跨平台的 P2P VPN 解决方案，支持 NAT 穿透和端到端加密。

## 特性

- P2P 直连，支持 NAT 穿透（STUN/打洞）
- 端到端加密（X25519 + ChaCha20-Poly1305）
- 跨平台支持（Linux、Windows）
- 轻量级，静态编译，无运行时依赖
- 支持 Relay 中继回退

## 安装

### Linux 一键安装

```bash
# 安装 Release 版本（客户端 + 控制器）
curl -fsSL https://raw.githubusercontent.com/hyird/EdgeLink/main/scripts/install.sh | bash

# 安装 Debug 版本
curl -fsSL https://raw.githubusercontent.com/hyird/EdgeLink/main/scripts/install.sh | bash -s -- --debug

# 仅安装客户端
curl -fsSL https://raw.githubusercontent.com/hyird/EdgeLink/main/scripts/install.sh | bash -s -- --client-only

# 仅安装控制器
curl -fsSL https://raw.githubusercontent.com/hyird/EdgeLink/main/scripts/install.sh | bash -s -- --controller-only

# 卸载
curl -fsSL https://raw.githubusercontent.com/hyird/EdgeLink/main/scripts/install.sh | bash -s -- --uninstall
```

安装路径：
- 二进制文件：`/usr/local/bin/`
- 配置目录：`/etc/edgelink/`

### 手动下载

从 [Releases](https://github.com/hyird/EdgeLink/releases/tag/autobuild) 页面下载预编译的二进制文件。

### 从源码构建

```bash
# 依赖：CMake 3.20+, Ninja, C++23 编译器

# 配置
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release

# 构建
cmake --build build -j$(nproc)
```

## 配置

安装后，配置文件位于 `/etc/edgelink/`：

- `client.toml` - 客户端配置
- `controller.toml` - 控制器配置

参考示例配置文件 `*.toml.example` 进行配置。

## 使用

### 启动服务

```bash
# 启动客户端
sudo systemctl start edgelink-client

# 启动控制器
sudo systemctl start edgelink-controller

# 设置开机启动
sudo systemctl enable edgelink-client
sudo systemctl enable edgelink-controller
```

### 命令行运行

```bash
# 客户端
edgelink-client --config /etc/edgelink/client.toml

# 控制器
edgelink-controller --config /etc/edgelink/controller.toml
```

## Docker

```bash
# 客户端
docker pull hyird/edgelink-client:latest

# 控制器
docker pull hyird/edgelink-controller:latest
```

## 开发

项目使用 C++23 和 Boost.Asio 协程实现异步网络操作。

### 目录结构

```
src/
├── common/          # 公共库（协议、加密、配置等）
├── client/          # 客户端实现
└── controller/      # 控制器实现
```

## License

MIT

# EdgeLink 重构计划：Tailscale 风格 CLI + Protobuf 消息

## 概述

本文档描述 EdgeLink 的两阶段重构计划：
1. **阶段 1**：Tailscale 风格 CLI（服务管理 + set 命令 + prefs 存储）
2. **阶段 2**：Protobuf 消息协议重构

---

## 实现状态 (2026-01-16 更新)

### 阶段 1: ✅ 完成

| 步骤 | 状态 | 说明 |
|------|------|------|
| PrefsStore 类 | ✅ | `src/client/prefs_store.hpp/cpp` |
| ServiceManager (Windows) | ✅ | `src/client/service_manager_win.cpp` |
| ServiceManager (Linux) | ✅ | `src/client/service_manager_linux.cpp` |
| ServiceManager (macOS) | ✅ | `src/client/service_manager_mac.cpp` |
| set 命令扩展 | ✅ | `src/client/main.cpp` cmd_set() |
| IPC PREFS_UPDATE | ✅ | `src/client/ipc_server.cpp` |

### 阶段 2: ✅ 基础设施完成

| 步骤 | 状态 | 说明 |
|------|------|------|
| 2.1 添加 protobuf 依赖 | ✅ | `third_party/protobuf.cmake` |
| 2.2 创建 proto 文件 | ✅ | `proto/edgelink.proto` (package: `edgelink.pb`) |
| 2.3 message.hpp 类型别名 | ✅ | 添加 PROTOBUF_ERROR 枚举 |
| 2.4 保留 message.cpp | ✅ | 保留二进制协议以兼容渐进迁移 |
| 2.5 更新 frame.hpp/cpp | ✅ | 添加 protobuf 模板函数 |
| 2.6 命名空间冲突解决 | ✅ | proto package 改为 `edgelink.pb` |
| 2.7 类型转换辅助函数 | ✅ | `src/common/proto_convert.hpp` |
| 2.8 Client/Controller 迁移 | 📋 | 可选，按需逐步迁移 |

### Protobuf 集成说明

**当前状态**：✅ Protobuf 基础设施已完成，命名空间冲突已解决。

**解决方案**：
- Proto package 改为 `edgelink.pb`（原 `edgelink`）
- Protobuf 类型现在在 `edgelink::pb::` 命名空间
- C++ 原生类型保持在 `edgelink::` 命名空间
- 添加了 `proto_convert.hpp` 提供类型转换函数

**命名空间对照**：
| 类型 | C++ 原生 | Protobuf |
|------|----------|----------|
| IPv4Address | `edgelink::IPv4Address` | `edgelink::pb::IPv4Address` |
| Endpoint | `edgelink::Endpoint` | `edgelink::pb::Endpoint` |
| PeerInfo | `edgelink::PeerInfo` | `edgelink::pb::PeerInfo` |
| ... | ... | ... |

**使用方法**：

```cpp
// 1. 包含必要头文件
#include "common/proto_convert.hpp"
#include "edgelink.pb.h"

// 2. 使用 FrameCodec 编码/解码 protobuf 消息
edgelink::pb::Ping ping;
ping.set_timestamp(now());
ping.set_seq_num(seq++);
auto result = FrameCodec::encode_protobuf(FrameType::PING, ping);

// 3. 解码 protobuf 消息
auto msg = FrameCodec::decode_protobuf<edgelink::pb::Pong>(frame.data());

// 4. C++ 类型与 Protobuf 类型互转
edgelink::IPv4Address cpp_ip = ...;
edgelink::pb::IPv4Address pb_ip;
to_proto(cpp_ip, &pb_ip);  // C++ -> Protobuf

edgelink::IPv4Address cpp_ip2;
from_proto(pb_ip, &cpp_ip2);  // Protobuf -> C++
```

**迁移路径**：
1. 新功能直接使用 `edgelink::pb::*` 类型
2. 现有代码可逐步迁移，使用 `to_proto()`/`from_proto()` 转换
3. 最终可完全替换为 protobuf 序列化

---

## 现有代码状况分析

### 已有功能（可复用）

| 功能 | 状态 | 位置 | 说明 |
|------|------|------|------|
| CLI 命令系统 | ✅ 完善 | `main.cpp` | 8 个命令：up/down/status/peers/routes/ping/config/version |
| IPC 通信框架 | ✅ 完善 | `ipc_server.cpp` | 11 种请求类型，JSON 格式 |
| TOML 配置加载 | ✅ 完善 | `config.cpp` | 完整的配置解析和验证 |
| 配置写入 | ✅ 完善 | `config_writer.cpp` | TOML 格式写入 |
| 热重载系统 | ✅ 完善 | `config_applier.cpp` | 支持不同级别的热重载 |
| 消息序列化 | ✅ 完善 | `message.cpp` | 自定义二进制格式，45+ 消息类型 |

### 需要新增

| 功能 | 状态 | 计划位置 |
|------|------|----------|
| 服务管理模块 | ❌ 缺失 | `service_manager.hpp/cpp` |
| Prefs 存储 | ❌ 缺失 | `prefs_store.hpp/cpp` |
| `set` 命令 | ❌ 缺失 | `main.cpp` 扩展 |
| Protobuf 支持 | ❌ 缺失 | `proto/edgelink.proto` |

---

## Part 1: Tailscale 风格 CLI

### 1.1 目标

- `edgelink up` 启动时自动注册为系统服务
- `edgelink set` 命令设置运行时配置
- 配置保存到 `prefs.toml`（与 `config.toml` 分离）
- `edgelink down` 停止服务

### 1.2 命令设计

#### 现有命令（保留）

```bash
edgelink up [options]           # 启动客户端
edgelink down                   # 停止客户端
edgelink status [--json]        # 查看状态
edgelink peers [--json]         # 查看节点列表
edgelink routes [--json]        # 查看路由
edgelink ping <peer>            # ping 节点
edgelink config <subcommand>    # 配置管理
edgelink version                # 版本信息
```

#### 新增 `set` 命令

```bash
# 设置出口节点
edgelink set --exit-node=peer-name

# 广播路由
edgelink set --advertise-routes=192.168.1.0/24,10.0.0.0/8

# 声明为出口节点
edgelink set --advertise-exit-node

# 接受路由
edgelink set --accept-routes

# 组合设置
edgelink set --exit-node=gateway --accept-routes

# 清除出口节点
edgelink set --exit-node=
```

### 1.3 配置文件分离策略

**设计原则**：将静态配置与动态配置分离

| 文件 | 用途 | 修改方式 | 示例配置项 |
|------|------|---------|-----------|
| `config.toml` | 静态配置 | 手动编辑 | controller_url, tls, p2p, tun |
| `prefs.toml` | 动态配置 | `set` 命令 | exit_node, advertise_routes, accept_routes |

**prefs.toml 存储位置**：
- Windows: `%LOCALAPPDATA%\EdgeLink\prefs.toml`
- Linux: `/var/lib/edgelink/prefs.toml`
- macOS: `~/Library/Application Support/EdgeLink/prefs.toml`

**prefs.toml 结构**：
```toml
# EdgeLink 动态配置（由 edgelink set 命令管理）
# 手动编辑可能会被覆盖

[routing]
exit_node = "peer-name"
advertise_exit_node = false
advertise_routes = ["192.168.1.0/24"]
accept_routes = true

[network]
# 保留用于未来扩展
```

### 1.4 服务管理

#### 启动流程

```
edgelink up --controller=ctrl.example.com --authkey=tskey-xxx
```

1. 解析命令行参数
2. 加载 `config.toml`（如果存在）
3. 加载 `prefs.toml`（如果存在）
4. 命令行参数覆盖配置文件
5. 保存更新到 `prefs.toml`
6. 检查服务状态
   - 已运行：提示并退出
   - 未安装：安装服务
   - 已安装未运行：启动服务

#### 平台特定实现

**Windows Service**：
- 服务名: `EdgeLinkClient`
- 显示名: `EdgeLink Client`
- 启动类型: 自动（延迟启动）
- API: `CreateService()` / `StartService()`

**Linux systemd**：
```ini
# /etc/systemd/system/edgelink-client.service
[Unit]
Description=EdgeLink Client
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/edgelink-client daemon
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

**macOS launchd**：
```xml
<!-- ~/Library/LaunchAgents/com.edgelink.client.plist -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "...">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.edgelink.client</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/edgelink-client</string>
        <string>daemon</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
```

### 1.5 实现方案

#### PrefsStore 类

**文件**: `src/client/prefs_store.hpp`

```cpp
#pragma once

#include <filesystem>
#include <string>
#include <vector>
#include <optional>

namespace edgelink {

/// 动态配置存储（prefs.toml）
class PrefsStore {
public:
    explicit PrefsStore(const std::filesystem::path& state_dir);

    /// 加载配置文件
    bool load();

    /// 保存配置文件
    bool save();

    /// 获取配置文件路径
    const std::filesystem::path& path() const { return prefs_path_; }

    // ========== Routing 配置 ==========

    std::optional<std::string> exit_node() const;
    void set_exit_node(const std::string& node);
    void clear_exit_node();

    bool advertise_exit_node() const;
    void set_advertise_exit_node(bool value);

    std::vector<std::string> advertise_routes() const;
    void set_advertise_routes(const std::vector<std::string>& routes);

    bool accept_routes() const;
    void set_accept_routes(bool value);

    /// 合并到 ClientConfig
    void apply_to(ClientConfig& config) const;

private:
    std::filesystem::path prefs_path_;
    toml::table prefs_;
};

/// 获取平台特定的状态目录
std::filesystem::path get_state_dir();

} // namespace edgelink
```

#### ServiceManager 类

**文件**: `src/client/service_manager.hpp`

```cpp
#pragma once

#include <filesystem>
#include <string>

namespace edgelink {

/// 跨平台服务管理器
class ServiceManager {
public:
    /// 检查服务是否已安装
    static bool is_installed();

    /// 检查服务是否正在运行
    static bool is_running();

    /// 安装服务
    static bool install(const std::filesystem::path& exe_path);

    /// 卸载服务
    static bool uninstall();

    /// 启动服务
    static bool start();

    /// 停止服务
    static bool stop();

    /// 获取服务名称
    static std::string service_name();

private:
#ifdef _WIN32
    static bool install_windows(const std::filesystem::path& exe_path);
    static bool uninstall_windows();
    static bool start_windows();
    static bool stop_windows();
    static bool is_installed_windows();
    static bool is_running_windows();
#elif defined(__linux__)
    static bool install_systemd(const std::filesystem::path& exe_path);
    static bool uninstall_systemd();
    static bool start_systemd();
    static bool stop_systemd();
    static bool is_installed_systemd();
    static bool is_running_systemd();
#elif defined(__APPLE__)
    static bool install_launchd(const std::filesystem::path& exe_path);
    static bool uninstall_launchd();
    static bool start_launchd();
    static bool stop_launchd();
    static bool is_installed_launchd();
    static bool is_running_launchd();
#endif
};

} // namespace edgelink
```

#### main.cpp 修改

**cmd_set 函数**：

```cpp
int cmd_set(int argc, char* argv[]) {
    // 解析参数
    std::optional<std::string> exit_node;
    std::optional<bool> advertise_exit_node;
    std::optional<std::vector<std::string>> advertise_routes;
    std::optional<bool> accept_routes;

    for (int i = 0; i < argc; ++i) {
        std::string arg = argv[i];
        if (starts_with(arg, "--exit-node=")) {
            exit_node = arg.substr(12);
        } else if (arg == "--advertise-exit-node") {
            advertise_exit_node = true;
        } else if (arg == "--no-advertise-exit-node") {
            advertise_exit_node = false;
        } else if (starts_with(arg, "--advertise-routes=")) {
            advertise_routes = split(arg.substr(19), ',');
        } else if (arg == "--accept-routes") {
            accept_routes = true;
        } else if (arg == "--no-accept-routes") {
            accept_routes = false;
        }
    }

    // 1. 更新 prefs.toml
    PrefsStore prefs(get_state_dir());
    prefs.load();

    if (exit_node) {
        if (exit_node->empty()) {
            prefs.clear_exit_node();
        } else {
            prefs.set_exit_node(*exit_node);
        }
    }
    if (advertise_exit_node) {
        prefs.set_advertise_exit_node(*advertise_exit_node);
    }
    if (advertise_routes) {
        prefs.set_advertise_routes(*advertise_routes);
    }
    if (accept_routes) {
        prefs.set_accept_routes(*accept_routes);
    }

    prefs.save();

    // 2. 如果服务运行中，通过 IPC 热更新
    if (ServiceManager::is_running()) {
        IpcClient client;
        if (client.connect()) {
            // 发送配置更新请求
            client.send_prefs_update(prefs);
        }
    }

    std::cout << "Configuration updated\n";
    return 0;
}
```

#### IPC 扩展

**新增请求类型**：

```cpp
enum class IpcRequestType : uint8_t {
    // ... 现有类型 ...
    PREFS_UPDATE = 0x20,  // 更新 prefs 配置
    PREFS_GET = 0x21,     // 获取 prefs 配置
};
```

### 1.6 文件清单

| 文件 | 操作 | 说明 |
|------|------|------|
| `src/client/prefs_store.hpp` | 新建 | Prefs 存储声明 |
| `src/client/prefs_store.cpp` | 新建 | Prefs 存储实现 |
| `src/client/service_manager.hpp` | 新建 | 服务管理声明 |
| `src/client/service_manager_win.cpp` | 新建 | Windows 服务实现 |
| `src/client/service_manager_linux.cpp` | 新建 | Linux systemd 实现 |
| `src/client/service_manager_mac.cpp` | 新建 | macOS launchd 实现 |
| `src/client/main.cpp` | 修改 | 添加 set 命令，修改 up 命令 |
| `src/client/ipc_server.hpp` | 修改 | 添加 PREFS_UPDATE/GET 请求 |
| `src/client/ipc_server.cpp` | 修改 | 实现新 IPC 处理 |
| `CMakeLists.txt` | 修改 | 添加新文件，Windows 链接 advapi32 |

---

## Part 2: Protobuf 消息协议重构

### 2.1 现有消息类型（完整列表）

根据 `src/common/types.hpp` 中的 `FrameType` 枚举：

```cpp
// Authentication (0x01-0x0F)
AUTH_REQUEST        = 0x01,
AUTH_RESPONSE       = 0x02,
AUTH_CHALLENGE      = 0x03,
AUTH_VERIFY         = 0x04,

// Configuration (0x10-0x1F)
CONFIG              = 0x10,
CONFIG_UPDATE       = 0x11,
CONFIG_ACK          = 0x12,

// Data (0x20-0x2F)
DATA                = 0x20,
DATA_ACK            = 0x21,

// Heartbeat (0x30-0x3F)
PING                = 0x30,
PONG                = 0x31,
LATENCY_REPORT      = 0x32,
CONNECTION_METRICS  = 0x33,
PATH_SELECTION      = 0x34,
PEER_PATH_REPORT    = 0x35,
PEER_ROUTING_UPDATE = 0x36,
RELAY_LATENCY_REPORT= 0x37,

// P2P (0x40-0x4F)
P2P_INIT            = 0x40,
P2P_ENDPOINT        = 0x41,
P2P_PING            = 0x42,
P2P_PONG            = 0x43,
P2P_KEEPALIVE       = 0x44,
P2P_STATUS          = 0x45,
ENDPOINT_UPDATE     = 0x46,
ENDPOINT_ACK        = 0x47,

// Server (0x50-0x5F)
SERVER_REGISTER     = 0x50,
SERVER_REGISTER_RESP= 0x51,
SERVER_NODE_LOC     = 0x52,
SERVER_BLACKLIST    = 0x53,
SERVER_HEARTBEAT    = 0x54,
SERVER_RELAY_LIST   = 0x55,
SERVER_LATENCY_REPORT= 0x56,

// Relay Auth (0x60-0x6F)
RELAY_AUTH          = 0x60,
RELAY_AUTH_RESP     = 0x61,

// Mesh (0x70-0x7F)
MESH_HELLO          = 0x70,
MESH_HELLO_ACK      = 0x71,
MESH_FORWARD        = 0x72,
MESH_PING           = 0x73,
MESH_PONG           = 0x74,

// Routing (0x80-0x8F)
ROUTE_ANNOUNCE      = 0x80,
ROUTE_UPDATE        = 0x81,
ROUTE_WITHDRAW      = 0x82,
ROUTE_ACK           = 0x83,

// Security (0x90-0x9F)
NODE_REVOKE         = 0x90,
NODE_REVOKE_ACK     = 0x91,
NODE_REVOKE_BATCH   = 0x92,

// Lifecycle (0xA0-0xAF)
SHUTDOWN_NOTIFY     = 0xA0,
SHUTDOWN_ACK        = 0xA1,

// Generic (0xF0-0xFF)
GENERIC_ACK         = 0xFE,
FRAME_ERROR         = 0xFF,
```

### 2.2 Proto 文件设计

**文件**: `proto/edgelink.proto`

```protobuf
syntax = "proto3";
package edgelink;

option cc_enable_arenas = true;

// ============================================================================
// 基础类型
// ============================================================================

message IPv4Address {
  fixed32 addr = 1;  // Network byte order
}

message IPv6Address {
  bytes addr = 1;    // 16 bytes
}

message Endpoint {
  EndpointType type = 1;
  IpType ip_type = 2;
  bytes address = 3;       // 4 bytes for IPv4, 16 for IPv6
  uint32 port = 4;
  uint32 priority = 5;
}

enum IpType {
  IP_UNKNOWN = 0;
  IP_V4 = 4;
  IP_V6 = 6;
}

enum EndpointType {
  ENDPOINT_UNKNOWN = 0;
  ENDPOINT_LAN = 1;
  ENDPOINT_STUN = 2;
  ENDPOINT_UPNP = 3;
  ENDPOINT_RELAY = 4;
}

message SubnetInfo {
  IpType ip_type = 1;
  bytes prefix = 2;        // 4 or 16 bytes
  uint32 prefix_len = 3;
}

message RouteInfo {
  IpType ip_type = 1;
  bytes prefix = 2;
  uint32 prefix_len = 3;
  uint32 gateway_node = 4;
  uint32 metric = 5;
  uint32 flags = 6;        // RouteFlags
}

message PeerInfo {
  uint32 node_id = 1;
  IPv4Address virtual_ip = 2;
  bytes node_key = 3;              // X25519 public key (32 bytes)
  bool online = 4;
  bool exit_node = 5;
  string name = 6;
  repeated Endpoint endpoints = 7;
  repeated SubnetInfo allowed_subnets = 8;
}

message RelayInfo {
  uint32 server_id = 1;
  string hostname = 2;
  repeated Endpoint endpoints = 3;
  uint32 priority = 4;
  string region = 5;
}

message StunInfo {
  string hostname = 1;
  uint32 port = 2;
}

message LatencyEntry {
  uint32 server_id = 1;
  uint32 latency_ms = 2;
  uint32 jitter_ms = 3;
  uint32 packet_loss = 4;      // 0-100
}

// ============================================================================
// 认证消息 (0x01-0x04)
// ============================================================================

enum AuthType {
  AUTH_UNKNOWN = 0;
  AUTH_USER = 1;
  AUTH_AUTHKEY = 2;
  AUTH_MACHINE = 3;
}

message AuthRequest {
  AuthType auth_type = 1;
  bytes auth_data = 2;
  bytes machine_key = 3;       // ED25519 public key (32 bytes)
  bytes node_key = 4;          // X25519 public key (32 bytes)
  string hostname = 5;
  string os = 6;
  string arch = 7;
  string version = 8;
  uint32 connection_id = 9;
  bool exit_node = 10;
  bytes signature = 11;        // ED25519 signature (64 bytes)
}

message AuthResponse {
  bool success = 1;
  uint32 node_id = 2;
  IPv4Address virtual_ip = 3;
  uint32 network_id = 4;
  bytes auth_token = 5;
  bytes relay_token = 6;
  uint32 error_code = 7;
  string error_msg = 8;
}

message AuthChallenge {
  uint32 challenge_type = 1;   // ChallengeType
  bytes challenge_data = 2;
  uint32 expires_at = 3;
}

message AuthVerify {
  bytes response_data = 1;
  bytes signature = 2;
}

// ============================================================================
// 配置消息 (0x10-0x12)
// ============================================================================

message Config {
  uint64 version = 1;
  uint32 network_id = 2;
  IPv4Address subnet = 3;
  uint32 subnet_mask = 4;
  string network_name = 5;
  repeated PeerInfo peers = 6;
  repeated RelayInfo relays = 7;
  repeated StunInfo stuns = 8;
  repeated RouteInfo routes = 9;
  bytes relay_token = 10;
  uint64 relay_token_expires = 11;
}

message ConfigUpdate {
  uint64 version = 1;
  uint32 update_flags = 2;     // ConfigUpdateFlags
  repeated PeerInfo add_peers = 3;
  repeated uint32 del_peer_ids = 4;
  repeated RouteInfo add_routes = 5;
  repeated RouteInfo del_routes = 6;
  repeated RelayInfo add_relays = 7;
  repeated uint32 del_relay_ids = 8;
  bytes relay_token = 9;
  uint64 relay_token_expires = 10;
}

message ConfigAck {
  uint64 version = 1;
  uint32 status = 2;           // ConfigAckStatus
  repeated ConfigErrorItem errors = 3;
}

message ConfigErrorItem {
  uint32 item_type = 1;        // ConfigErrorItemType
  uint32 item_id = 2;
  uint32 error_code = 3;
  string error_msg = 4;
}

// ============================================================================
// 数据消息 (0x20-0x21)
// ============================================================================

message DataPayload {
  uint32 src_node = 1;
  uint32 dst_node = 2;
  bytes encrypted_data = 3;
}

message DataAck {
  uint32 seq = 1;
  uint32 flags = 2;            // DataAckFlags
}

// ============================================================================
// 心跳和延迟消息 (0x30-0x37)
// ============================================================================

message Ping {
  uint64 timestamp = 1;
  uint32 seq_num = 2;
}

message Pong {
  uint64 timestamp = 1;
  uint32 seq_num = 2;
}

message LatencyReport {
  uint64 timestamp = 1;
  repeated LatencyEntry entries = 2;
}

message ConnectionMetrics {
  uint32 connection_id = 1;
  uint32 rtt_ms = 2;
  uint32 packet_loss = 3;      // 0-100
}

message PathSelection {
  uint32 peer_node = 1;
  uint32 path_type = 2;        // PathType
  uint32 relay_id = 3;
  uint32 connection_id = 4;
}

message PeerPathEntry {
  uint32 peer_node = 1;
  uint32 relay_id = 2;
  uint32 connection_id = 3;
  uint32 latency_ms = 4;
  uint32 packet_loss = 5;
}

message PeerPathReport {
  uint64 timestamp = 1;
  repeated PeerPathEntry entries = 2;
}

message PeerRoutingEntry {
  uint32 peer_node = 1;
  uint32 path_type = 2;        // PathType
  uint32 relay_id = 3;
  uint32 connection_id = 4;
}

message PeerRoutingUpdate {
  repeated PeerRoutingEntry entries = 1;
}

message RelayLatencyEntry {
  uint32 relay_id = 1;
  uint32 connection_id = 2;
  uint32 latency_ms = 3;
  uint32 packet_loss = 4;
}

message RelayLatencyReport {
  uint64 timestamp = 1;
  repeated RelayLatencyEntry entries = 2;
}

// ============================================================================
// P2P 消息 (0x40-0x47)
// ============================================================================

message P2PInit {
  uint32 target_node = 1;
  uint32 init_seq = 2;
}

message P2PEndpoint {
  uint32 init_seq = 1;
  uint32 peer_node = 2;
  bytes peer_key = 3;          // X25519 public key
  repeated Endpoint endpoints = 4;
}

message P2PPing {
  uint64 timestamp = 1;
  uint32 seq = 2;
}

message P2PPong {
  uint64 timestamp = 1;
  uint32 seq = 2;
}

message P2PKeepalive {
  uint64 timestamp = 1;
}

message P2PStatus {
  uint32 status = 1;           // P2PStatus enum
  uint32 peer_node = 2;
}

message EndpointUpdate {
  uint32 request_id = 1;
  repeated Endpoint endpoints = 2;
}

message EndpointAck {
  uint32 request_id = 1;
  bool success = 2;
  uint32 endpoint_count = 3;
}

// ============================================================================
// Server 消息 (0x50-0x56)
// ============================================================================

message ServerRegister {
  uint32 server_id = 1;
  string hostname = 2;
  repeated Endpoint endpoints = 3;
  string region = 4;
  uint32 capacity = 5;
}

message ServerRegisterResp {
  bool success = 1;
  uint32 server_id = 2;
  uint32 error_code = 3;
  string error_msg = 4;
}

message ServerNodeLoc {
  uint32 node_id = 1;
  uint32 server_id = 2;
}

message ServerBlacklist {
  repeated uint32 node_ids = 1;
  uint32 duration_sec = 2;
}

message ServerHeartbeat {
  uint64 timestamp = 1;
  uint32 active_connections = 2;
  uint32 bandwidth_mbps = 3;
}

message ServerRelayList {
  repeated RelayInfo relays = 1;
}

message ServerLatencyReport {
  uint64 timestamp = 1;
  repeated LatencyEntry entries = 2;
}

// ============================================================================
// Relay Auth 消息 (0x60-0x61)
// ============================================================================

message RelayAuth {
  uint32 node_id = 1;
  bytes relay_token = 2;
}

message RelayAuthResp {
  bool success = 1;
  uint32 error_code = 2;
  string error_msg = 3;
}

// ============================================================================
// Mesh 消息 (0x70-0x74)
// ============================================================================

message MeshHello {
  uint32 server_id = 1;
  string region = 2;
  uint32 protocol_version = 3;
}

message MeshHelloAck {
  bool accepted = 1;
  uint32 server_id = 2;
}

message MeshForward {
  uint32 src_server = 1;
  uint32 dst_server = 2;
  bytes payload = 3;
}

message MeshPing {
  uint64 timestamp = 1;
  uint32 seq = 2;
}

message MeshPong {
  uint64 timestamp = 1;
  uint32 seq = 2;
}

// ============================================================================
// Routing 消息 (0x80-0x83)
// ============================================================================

message RouteAnnounce {
  uint32 request_id = 1;
  repeated RouteInfo routes = 2;
}

message RouteUpdate {
  repeated RouteInfo add_routes = 1;
  repeated RouteInfo del_routes = 2;
}

message RouteWithdraw {
  uint32 request_id = 1;
  repeated RouteInfo routes = 2;
}

message RouteAck {
  uint32 request_id = 1;
  bool success = 2;
  uint32 error_code = 3;
  string error_msg = 4;
}

// ============================================================================
// Security 消息 (0x90-0x92)
// ============================================================================

message NodeRevoke {
  uint32 node_id = 1;
  string reason = 2;
  uint64 revoke_time = 3;
}

message NodeRevokeAck {
  uint32 node_id = 1;
  bool success = 2;
}

message NodeRevokeBatch {
  repeated NodeRevoke revokes = 1;
}

// ============================================================================
// Lifecycle 消息 (0xA0-0xA1)
// ============================================================================

message ShutdownNotify {
  string reason = 1;
  uint32 grace_period_sec = 2;
}

message ShutdownAck {
  bool acknowledged = 1;
}

// ============================================================================
// Generic 消息 (0xFE-0xFF)
// ============================================================================

message GenericAck {
  uint32 request_id = 1;
  bool success = 2;
}

message FrameError {
  uint32 error_code = 1;
  uint32 request_type = 2;
  uint32 request_id = 3;
  string error_msg = 4;
}
```

### 2.3 帧格式

保持简单的帧头设计：

```
+--------+--------+--------+------------------+
| Type   | Flags  | Length | Protobuf Payload |
| 1 byte | 1 byte | 2 bytes| N bytes          |
+--------+--------+--------+------------------+
```

- **Type**: `FrameType` 枚举值（保持现有值）
- **Flags**: `FrameFlags`（NEED_ACK, COMPRESSED, ENCRYPTED 等）
- **Length**: Payload 长度（big-endian uint16）
- **Payload**: Protobuf 序列化的消息

### 2.4 迁移策略

**全面替换**（不保留兼容性）：

1. **添加 protobuf 依赖**
2. **创建 proto 文件**
3. **替换 message.hpp/cpp**：
   - 删除所有手动序列化代码
   - 直接使用 protobuf 生成的类
4. **更新 frame.hpp/cpp**：
   - Payload 直接为 protobuf 序列化数据
   - 移除旧的解析逻辑
5. **更新所有消息使用方**：
   - client.cpp, channel.cpp, session_impl.hpp 等

### 2.5 message.hpp 重写示例

```cpp
#pragma once

// 包含 protobuf 生成的头文件
#include "edgelink.pb.h"

namespace edgelink {

// 直接使用 protobuf 生成的类，无需额外封装
// 类型别名保持代码兼容性（可选）

using AuthRequest = edgelink::proto::AuthRequest;
using AuthResponse = edgelink::proto::AuthResponse;
using Config = edgelink::proto::Config;
using ConfigUpdate = edgelink::proto::ConfigUpdate;
using ConfigAck = edgelink::proto::ConfigAck;
using DataPayload = edgelink::proto::DataPayload;
using Ping = edgelink::proto::Ping;
using Pong = edgelink::proto::Pong;
// ... 其他消息类型

// 辅助函数：序列化消息到 buffer
template<typename T>
inline std::vector<uint8_t> serialize_message(const T& msg) {
    std::vector<uint8_t> buffer(msg.ByteSizeLong());
    msg.SerializeToArray(buffer.data(), buffer.size());
    return buffer;
}

// 辅助函数：从 buffer 解析消息
template<typename T>
inline bool parse_message(T& msg, const uint8_t* data, size_t size) {
    return msg.ParseFromArray(data, size);
}

} // namespace edgelink
```

### 2.6 frame.cpp 修改示例

```cpp
// 发送消息
template<typename T>
void send_frame(FrameType type, const T& msg, FrameFlags flags = FrameFlags::NONE) {
    // 序列化 protobuf 消息
    std::string payload;
    msg.SerializeToString(&payload);

    // 构建帧头
    std::vector<uint8_t> frame;
    frame.push_back(static_cast<uint8_t>(type));
    frame.push_back(static_cast<uint8_t>(flags));
    frame.push_back((payload.size() >> 8) & 0xFF);
    frame.push_back(payload.size() & 0xFF);

    // 追加 payload
    frame.insert(frame.end(), payload.begin(), payload.end());

    // 发送
    send_raw(frame);
}

// 接收消息
template<typename T>
bool recv_frame(FrameType expected_type, T& msg) {
    auto [type, flags, payload] = recv_raw();
    if (type != expected_type) return false;
    return msg.ParseFromString(payload);
}
```

### 2.7 CMakeLists.txt 修改

```cmake
# 添加 protobuf 依赖
find_package(Protobuf REQUIRED)

# 生成 protobuf 代码
set(PROTO_FILES
    ${CMAKE_SOURCE_DIR}/proto/edgelink.proto
)

protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS ${PROTO_FILES})

# 添加到 edgelink-common
target_sources(edgelink-common PRIVATE ${PROTO_SRCS})
target_include_directories(edgelink-common PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(edgelink-common PRIVATE protobuf::libprotobuf)
```

### 2.8 文件清单

| 文件 | 操作 | 说明 |
|------|------|------|
| `proto/edgelink.proto` | 新建 | Protobuf 消息定义 |
| `CMakeLists.txt` | 修改 | 添加 protobuf 依赖和代码生成 |
| `src/common/message.hpp` | **重写** | 删除手动序列化，改用 protobuf 类型别名 |
| `src/common/message.cpp` | **删除** | 不再需要手动序列化代码 |
| `src/common/frame.hpp` | 修改 | 简化为 protobuf payload |
| `src/common/frame.cpp` | 修改 | 移除旧解析逻辑 |
| `src/client/client.cpp` | 修改 | 使用 protobuf 消息类 |
| `src/client/channel.cpp` | 修改 | 使用 protobuf 消息类 |
| `src/controller/session_impl.hpp` | 修改 | 使用 protobuf 消息类 |
| `src/controller/session_impl.cpp` | 修改 | 使用 protobuf 消息类 |

---

## 实施顺序

### 阶段 1：Tailscale 风格 CLI（优先）

| 步骤 | 任务 | 依赖 |
|------|------|------|
| 1.1 | 实现 `PrefsStore` 类 | 无 |
| 1.2 | 实现 `cmd_set()` 命令 | 1.1 |
| 1.3 | 扩展 IPC 支持 PREFS_UPDATE | 1.1 |
| 1.4 | 实现 `ServiceManager` (Windows) | 无 |
| 1.5 | 实现 `ServiceManager` (Linux) | 无 |
| 1.6 | 实现 `ServiceManager` (macOS) | 无 |
| 1.7 | 修改 `cmd_up()` 集成服务管理 | 1.4-1.6 |
| 1.8 | 测试和文档 | 全部 |

### 阶段 2：Protobuf 消息重构

| 步骤 | 任务 | 依赖 |
|------|------|------|
| 2.1 | 添加 protobuf 依赖到 CMakeLists.txt | 无 |
| 2.2 | 创建 `proto/edgelink.proto` | 无 |
| 2.3 | 重写 `message.hpp`（类型别名指向 protobuf 类） | 2.1, 2.2 |
| 2.4 | 删除 `message.cpp` | 2.3 |
| 2.5 | 更新 `frame.hpp/cpp`（protobuf payload） | 2.3 |
| 2.6 | 更新 Client 端代码（client.cpp, channel.cpp） | 2.5 |
| 2.7 | 更新 Controller 端代码（session_impl.*） | 2.5 |
| 2.8 | 编译测试，修复编译错误 | 2.6, 2.7 |

---

## 风险和注意事项

### Protobuf 迁移

1. **协议版本**：更新 `PROTOCOL_VERSION` 常量，标识为 protobuf 版本
2. **全量替换**：Client 和 Controller 需同时更新，不支持混合部署
3. **编译依赖**：需要 protoc 编译器和 protobuf 运行时库

### 平台特定

1. **Windows Service**：
   - 需要管理员权限安装服务
   - 链接 `advapi32.lib`
   - 处理 SCM (Service Control Manager) 错误

2. **Linux systemd**：
   - 需要 root 权限写入 `/etc/systemd/system/`
   - 用户模式可写入 `~/.config/systemd/user/`

3. **macOS launchd**：
   - 用户级服务写入 `~/Library/LaunchAgents/`
   - 系统级服务需要 root

### 测试要点

1. **服务生命周期**：安装 → 启动 → 停止 → 卸载
2. **配置热更新**：`set` 命令后服务立即生效
3. **持久化**：重启后配置保持
4. **错误处理**：权限不足、服务已存在等场景

---

## 验证清单

### 阶段 1 验证

- [ ] `edgelink up --controller=... --authkey=...` 首次运行安装服务
- [ ] `edgelink status` 显示服务运行状态
- [ ] `edgelink set --exit-node=peer` 更新 prefs.toml 并热更新
- [ ] `edgelink set --advertise-routes=...` 路由广播生效
- [ ] `edgelink down` 停止服务
- [ ] 系统重启后服务自动启动
- [ ] prefs.toml 格式正确且可读

### 阶段 2 验证

- [ ] proto 文件编译通过，生成 C++ 代码
- [ ] Protobuf 消息正确序列化/反序列化
- [ ] Client 连接 Controller 成功
- [ ] 认证流程正常（AUTH_REQUEST/RESPONSE）
- [ ] 配置下发正常（CONFIG/CONFIG_UPDATE）
- [ ] 数据转发正常（DATA）
- [ ] P2P 打洞正常（P2P_INIT/ENDPOINT）
- [ ] 性能测试：吞吐量和延迟

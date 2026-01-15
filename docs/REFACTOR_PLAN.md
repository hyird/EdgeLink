# EdgeLink 重构计划：Tailscale 风格 CLI + Protobuf 消息

## 目标

1. **Tailscale 风格 CLI**：
   - `edgelink up` 启动时自动注册为系统服务
   - 所有配置通过 `edgelink set` CLI 命令设置
   - 配置保存到状态目录的 JSON 文件，无需 TOML 配置文件
   - `edgelink down` 停止服务

2. **Protobuf 消息协议**：
   - 使用 protobuf 替代当前自定义的二进制消息格式
   - 更好的版本兼容性和可扩展性
   - 自动生成序列化/反序列化代码

## 主要功能

### 1. 自动服务注册

**启动流程**：
```
edgelink up --controller=ctrl.example.com --authkey=tskey-xxx
```
- 首次运行时自动注册并启动系统服务
- Windows: 注册为 Windows Service
- Linux: 生成 systemd unit 文件并启用
- macOS: 生成 launchd plist 并加载

**停止流程**：
```
edgelink down
```
- 停止运行中的服务（不卸载服务）

### 2. CLI 配置命令

**新增 `set` 命令**（Tailscale 风格）：
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
```

**保留的命令**：
- `edgelink status` - 查看状态
- `edgelink peers` - 查看节点列表
- `edgelink routes` - 查看路由
- `edgelink ping <peer>` - ping 节点

### 3. 配置持久化

**存储位置**：
- Windows: `%LOCALAPPDATA%\EdgeLink\prefs.json`
- Linux: `/var/lib/edgelink/prefs.json`
- macOS: `~/Library/Application Support/EdgeLink/prefs.json`

**prefs.json 结构**：
```json
{
  "controller_url": "wss://ctrl.example.com",
  "authkey": "tskey-xxx",
  "tls": true,
  "exit_node": "peer-name",
  "advertise_exit_node": false,
  "advertise_routes": ["192.168.1.0/24"],
  "accept_routes": true,
  "enable_tun": true,
  "tun_mtu": 1420,
  "log_level": "info"
}
```

## 实现方案

### 1. 新增服务管理模块

**文件**: `src/client/service_manager.hpp/cpp`

```cpp
class ServiceManager {
public:
    // 安装服务（首次 up 时调用）
    static bool install_service(const std::string& exe_path);

    // 启动服务
    static bool start_service();

    // 停止服务
    static bool stop_service();

    // 检查服务是否已安装
    static bool is_service_installed();

    // 检查服务是否正在运行
    static bool is_service_running();

    // 卸载服务
    static bool uninstall_service();

private:
    // 平台特定实现
    static bool install_windows_service(const std::string& exe_path);
    static bool install_systemd_service(const std::string& exe_path);
    static bool install_launchd_service(const std::string& exe_path);
};
```

### 2. 新增配置存储模块

**文件**: `src/client/prefs_store.hpp/cpp`

```cpp
class PrefsStore {
public:
    explicit PrefsStore(const std::string& state_dir);

    // 加载配置
    bool load();

    // 保存配置
    bool save();

    // 获取/设置各项配置
    std::string controller_url() const;
    void set_controller_url(const std::string& url);

    std::string exit_node() const;
    void set_exit_node(const std::string& node);

    std::vector<std::string> advertise_routes() const;
    void set_advertise_routes(const std::vector<std::string>& routes);

    bool advertise_exit_node() const;
    void set_advertise_exit_node(bool value);

    bool accept_routes() const;
    void set_accept_routes(bool value);

    // ... 其他配置项

    // 转换为 ClientConfig
    ClientConfig to_client_config() const;

private:
    std::string prefs_path_;
    boost::json::object prefs_;
};
```

### 3. 修改 main.cpp

**up 命令改造**：
```cpp
int cmd_up(int argc, char* argv[]) {
    // 1. 解析命令行参数
    std::string controller_url;
    std::string authkey;
    // ... 解析 --controller, --authkey 等

    // 2. 加载或创建 prefs
    PrefsStore prefs(get_state_dir());
    prefs.load();

    // 3. 更新 prefs（命令行参数优先）
    if (!controller_url.empty()) {
        prefs.set_controller_url(controller_url);
    }
    if (!authkey.empty()) {
        prefs.set_authkey(authkey);
    }
    prefs.save();

    // 4. 检查是否已有服务运行
    if (ServiceManager::is_service_running()) {
        std::cout << "EdgeLink is already running\n";
        return 0;
    }

    // 5. 安装服务（如果未安装）
    if (!ServiceManager::is_service_installed()) {
        ServiceManager::install_service(get_exe_path());
    }

    // 6. 启动服务
    ServiceManager::start_service();

    std::cout << "EdgeLink started\n";
    return 0;
}
```

**新增 set 命令**：
```cpp
int cmd_set(int argc, char* argv[]) {
    // 解析 --exit-node, --advertise-routes 等参数

    // 通过 IPC 发送配置更新到运行中的 daemon
    // 同时更新 prefs.json

    return 0;
}
```

### 4. IPC 扩展

**新增 IPC 请求类型**：
```cpp
enum class IpcRequestType {
    // ... 现有类型
    PREFS_SET,      // 设置配置项
    PREFS_GET,      // 获取配置项
    SERVICE_INFO,   // 获取服务信息
};
```

## 修改文件清单

| 文件 | 修改内容 |
|------|----------|
| `src/client/service_manager.hpp` | 新建 - 服务管理声明 |
| `src/client/service_manager.cpp` | 新建 - 服务管理实现（Windows/Linux/macOS） |
| `src/client/prefs_store.hpp` | 新建 - 配置存储声明 |
| `src/client/prefs_store.cpp` | 新建 - 配置存储实现 |
| `src/client/main.cpp` | 改造 up 命令，新增 set 命令 |
| `src/client/ipc_server.hpp` | 新增 IPC 请求类型 |
| `src/client/ipc_server.cpp` | 实现新的 IPC 处理 |
| `CMakeLists.txt` | 添加新文件，链接服务 API |

## 平台特定实现

### Windows Service
- 使用 `CreateService()` / `OpenService()` API
- 服务名: `EdgeLinkClient`
- 启动类型: 自动（延迟启动）

### Linux systemd
- 生成 `/etc/systemd/system/edgelink-client.service`
- `systemctl enable/start edgelink-client`

### macOS launchd
- 生成 `~/Library/LaunchAgents/com.edgelink.client.plist`
- `launchctl load/unload`

## 验证步骤

1. **首次启动**：
   ```bash
   edgelink up --controller=ctrl.example.com --authkey=tskey-xxx
   # 应该：安装服务 → 启动服务 → 输出 "EdgeLink started"
   ```

2. **配置更改**：
   ```bash
   edgelink set --exit-node=gateway
   edgelink set --advertise-routes=192.168.1.0/24
   # 应该：更新 prefs.json → 通知 daemon 热更新
   ```

3. **状态检查**：
   ```bash
   edgelink status
   # 应该：显示连接状态、当前配置
   ```

4. **停止服务**：
   ```bash
   edgelink down
   # 应该：停止 daemon 进程
   ```

5. **重启后自动启动**：
   - 系统重启后服务应自动启动（因为已注册为系统服务）

---

## Part 2: Protobuf 消息协议重构

### 当前消息类型（需要转换为 protobuf）

根据 `src/common/types.hpp` 中的 FrameType：
- AUTH_REQUEST (0x01)
- AUTH_RESPONSE (0x02)
- CONFIG (0x10)
- CONFIG_UPDATE (0x11)
- CONFIG_ACK (0x12)
- ROUTE_UPDATE (0x20)
- ROUTE_ANNOUNCE (0x21)
- ROUTE_WITHDRAW (0x22)
- ROUTE_ACK (0x23)
- PEER_ROUTING_UPDATE (0x24)
- DATA (0x30)
- PING (0x31)
- PONG (0x32)
- LATENCY_REPORT (0x33)
- PEER_PATH_REPORT (0x35)
- RELAY_LATENCY_REPORT (0x37)
- P2P_INIT (0x40)
- P2P_ENDPOINT (0x41)
- ENDPOINT_UPDATE (0x42)
- ENDPOINT_ACK (0x43)
- RELAY_AUTH (0x50)
- RELAY_AUTH_RESP (0x51)
- FRAME_ERROR (0xFF)

### Proto 文件设计

**文件**: `proto/edgelink.proto`

```protobuf
syntax = "proto3";
package edgelink;

// ============================================================================
// 基础类型
// ============================================================================

message IPv4Address {
  fixed32 addr = 1;  // Network byte order
}

message Endpoint {
  bytes address = 1;    // 4 bytes for IPv4
  uint32 port = 2;
  EndpointType type = 3;
}

enum EndpointType {
  ENDPOINT_UNKNOWN = 0;
  ENDPOINT_LOCAL = 1;
  ENDPOINT_STUN = 2;
  ENDPOINT_UPNP = 3;
  ENDPOINT_MANUAL = 4;
}

message PeerInfo {
  uint64 node_id = 1;
  IPv4Address virtual_ip = 2;
  bytes node_key = 3;     // X25519 public key (32 bytes)
  bool online = 4;
  bool exit_node = 5;
  string name = 6;
  repeated Endpoint endpoints = 7;
  repeated SubnetInfo allowed_subnets = 8;
}

message SubnetInfo {
  IPv4Address subnet = 1;
  uint32 prefix_len = 2;
}

message RouteInfo {
  IPv4Address subnet = 1;
  uint32 prefix_len = 2;
  uint64 gateway_node = 3;
  uint32 metric = 4;
  bool exit_node = 5;
}

message RelayInfo {
  uint64 server_id = 1;
  string hostname = 2;
  uint32 priority = 3;
  string region = 4;
}

message StunInfo {
  string hostname = 1;
  uint32 port = 2;
}

// ============================================================================
// 认证消息
// ============================================================================

message AuthRequest {
  AuthType auth_type = 1;
  bytes auth_data = 2;
  bytes machine_key = 3;   // ED25519 public key (32 bytes)
  bytes node_key = 4;      // X25519 public key (32 bytes)
  string hostname = 5;
  string os = 6;
  string arch = 7;
  string version = 8;
  uint64 connection_id = 9;
  bool exit_node = 10;
  bytes signature = 11;    // ED25519 signature (64 bytes)
}

enum AuthType {
  AUTH_UNKNOWN = 0;
  AUTH_AUTHKEY = 1;
  AUTH_MACHINE = 2;
}

message AuthResponse {
  bool success = 1;
  uint64 node_id = 2;
  IPv4Address virtual_ip = 3;
  uint64 network_id = 4;
  bytes auth_token = 5;
  bytes relay_token = 6;
  uint32 error_code = 7;
  string error_msg = 8;
}

// ============================================================================
// 配置消息
// ============================================================================

message Config {
  uint64 version = 1;
  uint64 network_id = 2;
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
  uint32 update_flags = 2;
  repeated PeerInfo add_peers = 3;
  repeated uint64 del_peer_ids = 4;
  repeated RouteInfo add_routes = 5;
  repeated RouteInfo del_routes = 6;
}

message ConfigAck {
  uint64 version = 1;
  ConfigAckStatus status = 2;
}

enum ConfigAckStatus {
  CONFIG_ACK_OK = 0;
  CONFIG_ACK_PARTIAL = 1;
  CONFIG_ACK_FAILED = 2;
}

// ============================================================================
// 路由消息
// ============================================================================

message RouteAnnounce {
  uint32 request_id = 1;
  repeated RouteInfo routes = 2;
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

message RouteUpdate {
  repeated RouteInfo add_routes = 1;
  repeated RouteInfo del_routes = 2;
}

message PeerRoutingUpdate {
  repeated PeerRoute routes = 1;
}

message PeerRoute {
  uint64 peer_node = 1;
  PathType path_type = 2;
  uint64 relay_id = 3;
  uint64 connection_id = 4;
}

enum PathType {
  PATH_UNKNOWN = 0;
  PATH_RELAY = 1;
  PATH_P2P = 2;
}

// ============================================================================
// 数据和延迟消息
// ============================================================================

message DataPayload {
  uint64 src_node = 1;
  uint64 dst_node = 2;
  bytes encrypted_data = 3;
}

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

message LatencyEntry {
  uint64 peer_node_id = 1;
  uint32 latency_ms = 2;
  uint32 path_type = 3;
}

message PeerPathReport {
  uint64 timestamp = 1;
  repeated PeerPathEntry entries = 2;
}

message PeerPathEntry {
  uint64 peer_node_id = 1;
  uint64 relay_id = 2;
  uint64 connection_id = 3;
  uint32 latency_ms = 4;
  uint32 packet_loss = 5;
}

message RelayLatencyReport {
  uint64 timestamp = 1;
  repeated RelayLatencyEntry entries = 2;
}

message RelayLatencyEntry {
  uint64 relay_id = 1;
  uint64 connection_id = 2;
  uint32 latency_ms = 3;
  uint32 packet_loss = 4;
}

// ============================================================================
// P2P 消息
// ============================================================================

message P2PInit {
  uint64 target_node = 1;
  uint32 init_seq = 2;
}

message P2PEndpoint {
  uint32 init_seq = 1;
  uint64 peer_node = 2;
  bytes peer_key = 3;
  repeated Endpoint endpoints = 4;
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
// Relay 消息
// ============================================================================

message RelayAuth {
  uint64 node_id = 1;
  bytes relay_token = 2;
}

message RelayAuthResp {
  bool success = 1;
  uint32 error_code = 2;
  string error_msg = 3;
}

// ============================================================================
// 错误消息
// ============================================================================

message FrameError {
  uint32 error_code = 1;
  uint32 request_type = 2;
  uint32 request_id = 3;
  string error_msg = 4;
}
```

### Frame 格式

帧格式保持简单：
```
+--------+--------+------------------+
| Type   | Length | Protobuf Payload |
| 1 byte | 2 bytes| N bytes          |
+--------+--------+------------------+
```

- Type: 消息类型（保持现有枚举值）
- Length: Payload 长度（big-endian）
- Payload: Protobuf 序列化的消息

### 实现步骤

1. **添加 protobuf 依赖**
   - CMakeLists.txt 添加 `find_package(Protobuf)`
   - 配置 protoc 生成 C++ 代码

2. **创建 proto 文件**
   - `proto/edgelink.proto`

3. **替换 message.hpp/cpp**
   - 删除手动序列化代码
   - 使用生成的 protobuf 类

4. **更新所有使用消息的代码**
   - channel.cpp
   - client.cpp
   - session_impl.hpp
   - 等

### 修改文件清单（Protobuf 部分）

| 文件 | 修改内容 |
|------|----------|
| `proto/edgelink.proto` | 新建 - protobuf 定义 |
| `CMakeLists.txt` | 添加 protobuf 依赖和代码生成 |
| `src/common/message.hpp` | 删除手动序列化，改用 protobuf |
| `src/common/message.cpp` | 大部分删除，保留辅助函数 |
| `src/common/frame.hpp/cpp` | 修改为使用 protobuf payload |
| `src/client/channel.cpp` | 更新消息构造和解析 |
| `src/client/client.cpp` | 更新消息处理 |
| `src/controller/session_impl.hpp` | 更新消息处理 |

---

## 实施顺序

建议分两个阶段实施：

### 阶段 1：Protobuf 消息重构
1. 添加 protobuf 依赖
2. 创建 proto 文件
3. 替换消息序列化代码
4. 测试 client-controller 通信

### 阶段 2：Tailscale 风格 CLI
1. 实现 PrefsStore
2. 实现 ServiceManager
3. 改造 up/down/set 命令
4. 测试服务注册和配置

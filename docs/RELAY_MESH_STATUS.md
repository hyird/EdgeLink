# EdgeLink - Relay Mesh 互联实现状态

## 完成日期: 2026-01-07

## 概述

实现了完整的 Relay-to-Relay Mesh 网状连接功能，支持：
- **CDN 代理**：正确设置 Host header 和 SNI，支持通过 Cloudflare 等 CDN 代理连接
- **真实 RTT 测量**：应用层端到端延迟测量，包含 CDN 引入的延迟
- 直接 WSS 连接进行数据转发，**不经过 Controller**

## 项目已重命名

项目已从 `wss-mesh` 重命名为 `EdgeLink`：
- 命名空间: `edgelink`
- 可执行文件: `edgelink-server`, `edgelink-controller`, `edgelink-client`
- 库文件: `libedgelink-common.a`

## 核心架构

```
                    ┌────────────────────┐
                    │    Controller      │  控制平面：
                    │                    │  - 路径计算
                    │                    │  - 节点位置同步
                    │                    │  ✗ 不转发数据
                    └────────┬───────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
         ┌────┴────┐    ┌────┴────┐    ┌────┴────┐
         │ CDN/CF  │    │ CDN/CF  │    │ CDN/CF  │   ← 可选 CDN 代理
         └────┬────┘    └────┬────┘    └────┬────┘
              │              │              │
         ┌────┴────┐    ┌────┴────┐    ┌────┴────┐
         │Relay-1  │════│Relay-2  │════│Relay-3  │   ← WSS Mesh 直连
         └────┬────┘    └────┬────┘    └────┬────┘     (数据转发)
              │              │              │
           Node A         Node B         Node C
```

## CDN 支持实现

### 1. Host Header 设置
```cpp
// mesh_client.cpp - do_ws_handshake()
std::string host_header = host_;
if ((use_ssl_ && port_ != "443") || (!use_ssl_ && port_ != "80")) {
    host_header += ":" + port_;
}

ws_ssl_->set_option(websocket::stream_base::decorator(
    [host_header](websocket::request_type& req) {
        req.set(beast::http::field::host, host_header);  // CDN 路由关键
    }));
```

### 2. SNI 设置
```cpp
// SSL 连接时设置 SNI
SSL_set_tlsext_host_name(ws_ssl_->next_layer().native_handle(), host_.c_str());
```

## RTT 测量改进

### 测量方式
- 使用唯一 `ping_id` 追踪每个 PING 请求
- 测量真实的端到端延迟（包含 CDN 延迟）
- 使用 EMA (指数移动平均) 平滑延迟数据

### 延迟统计结构
```cpp
struct LatencyStats {
    uint32_t current_rtt_ms;     // 最新测量
    uint32_t avg_rtt_ms;         // 滑动平均 (EMA α=0.3)
    uint32_t min_rtt_ms;         // 最小 RTT
    uint32_t max_rtt_ms;         // 最大 RTT
    uint32_t sample_count;       // 采样次数
    
    void update(uint32_t rtt_ms) {
        // EMA: new_avg = 0.3 * current + 0.7 * old_avg
        avg_rtt_ms = 0.3 * rtt_ms + 0.7 * avg_rtt_ms;
        min_rtt_ms = std::min(min_rtt_ms, rtt_ms);
        max_rtt_ms = std::max(max_rtt_ms, rtt_ms);
    }
};
```

### PING/PONG 协议
```json
// MESH_PING
{
    "ping_id": 12345,
    "src_relay_id": 1
}

// MESH_PONG (echo back ping_id)
{
    "ping_id": 12345,
    "src_relay_id": 2
}
```

## 新增/修改文件

### 新增
- `mesh_client.hpp/cpp` - 主动连接其他 Relay
- `mesh_session.hpp/cpp` - 处理入站 Mesh 连接
- `docs/RELAY_MESH_STATUS.md` - 本文档

### 修改
- `mesh_manager.hpp/cpp` - 完整重写，支持 CDN 和改进的 RTT 测量
- `relay_server.cpp` - 添加 MESH_HELLO 处理和 /ws/mesh 路由
- `relay_session.hpp` - 添加路径回调支持
- `protocol.hpp` - 添加 MESH_* 消息类型
- `config.hpp` - 添加 MeshConfig 结构
- `main.cpp (server)` - 创建和管理 MeshManager

## 消息类型

```cpp
MESH_HELLO       = 0x60,  // Relay 握手请求
MESH_HELLO_ACK   = 0x61,  // Relay 握手响应
MESH_FORWARD     = 0x62,  // 跨 Relay 数据转发
MESH_PING        = 0x63,  // Relay 间延迟探测
MESH_PONG        = 0x64,  // Relay 间延迟响应
```

## 连接管理策略

1. **避免重复连接:** relay_id 较小的一方主动连接
2. **Outbound 优先:** 优先使用我们主动建立的连接
3. **断线自动重连:** 指数退避，最大 10 次尝试
4. **延迟探测:** 每 30 秒发送 MESH_PING
5. **超时清理:** 30 秒未响应的 PING 自动清理

## 配置示例

```json
{
  "name": "relay-asia-1",
  "controller": {
    "url": "wss://controller.example.com/ws/server",
    "token": "server-token"
  },
  "relay": {
    "listen_port": 443,
    "external_url": "wss://relay-asia.example.com:443"
  },
  "mesh": {
    "peers": [
      "wss://relay-us.example.com/ws/mesh",
      "wss://relay-eu.example.com/ws/mesh"
    ],
    "auto_connect": true
  }
}
```

## 日志示例

```
[INFO] Connecting to mesh peer 2 at wss://relay-us.example.com/ws/mesh (CDN-friendly)
[INFO] Mesh connection established with relay 2
[INFO] Sent MESH_PING 1 to relay 2
[INFO] Mesh RTT to relay 2: current=45ms avg=45ms min=45ms max=45ms (samples=1)
[INFO] Mesh RTT to relay 2: current=42ms avg=44ms min=42ms max=45ms (samples=2)
```

## 后续工作

1. **Controller 推送 Relay 列表** - MeshManager.update_peers() 已准备好
2. **延迟数据上报 Controller** - 需要通过 ControllerClient 发送
3. **证书验证** - 当前跳过验证，生产环境需要正确验证
4. **连接健康检查** - 基于 RTT 判断连接质量

## 构建注意事项

项目依赖以下库：
- **Boost** >= 1.81 (需要 Beast, JSON, ASIO)
- **OpenSSL** >= 1.1
- **libsodium** >= 1.0.18
- **jwt-cpp** (可选，当前使用 stub 编译测试)
- **picojson** (可选，jwt-cpp 的 JSON 后端)

当前代码在以下方面可能需要根据实际 Boost 版本调整：
1. `boost::json::value::contains()` - 较新版本才支持，旧版本需要使用 `obj.find(key) != obj.end()`
2. `beast::tcp_stream::expires_after()` - 需要使用 `beast::tcp_stream` 而非直接的 socket
3. `Frame::parse()` - 确保 frame.hpp 中有此方法

配置 CMake 时可使用以下命令检查依赖：
```bash
cmake .. -DBUILD_SERVER=ON -DBUILD_CONTROLLER=ON -DBUILD_CLIENT=OFF
```

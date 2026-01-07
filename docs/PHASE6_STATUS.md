# EdgeLink Phase 6: P2P 直连 & 完整消息处理

## Status: COMPLETED ✅

## 1. P2P 直连

### P2PManager (`src/client/p2p_manager.hpp/cpp`)

**连接状态:**
- `DISCONNECTED` - 无 P2P 连接
- `INITIATING` - 已发送打洞请求
- `EXCHANGING` - 交换端点中
- `PUNCHING` - UDP 打洞中
- `HANDSHAKING` - P2P 握手中
- `CONNECTED` - P2P 已连接
- `FAILED` - P2P 失败，使用 Relay

**数据包类型:**
```
P2P_PACKET_PUNCH     = 0x01  // 打洞包
P2P_PACKET_PING      = 0x02  // P2P ping
P2P_PACKET_PONG      = 0x03  // P2P pong
P2P_PACKET_KEEPALIVE = 0x04  // NAT keepalive
P2P_PACKET_DATA      = 0x10  // 加密数据
```

### NAT 兼容性矩阵
```
              │ Full │ Restricted │ Port Restr │ Symmetric │
──────────────┼──────┼────────────┼────────────┼───────────┤
Full          │  ✅  │     ✅     │     ✅     │    ✅     │
Restricted    │  ✅  │     ✅     │     ✅     │    ✅     │
Port Restr    │  ✅  │     ✅     │     ✅     │    ⚠️     │
Symmetric     │  ✅  │     ✅     │     ⚠️     │    ❌     │
```

## 2. 完整 WebSocket 消息处理

### Controller → 节点
| 消息类型 | 说明 |
|---------|------|
| `config_update` | 配置推送 |
| `peer_online` / `peer_offline` | Peer 状态变化 |
| `token_refresh` | Token 刷新 |
| `p2p_response` / `p2p_init` | P2P 端点信息 |
| `pong` | 心跳响应 |
| `error` | 错误消息 |

### 节点 → Controller
| 消息类型 | 说明 |
|---------|------|
| `auth` | 认证请求 |
| `heartbeat` / `ping` | 心跳 |
| `endpoint_report` | 端点上报 |
| `latency_report` | 延迟测量 |
| `relay_connect` / `relay_disconnect` | Relay 连接状态 |
| `p2p_request` | P2P 连接请求 |
| `key_rotation` | 密钥轮换 |

### Controller ↔ Relay
| 消息类型 | 说明 |
|---------|------|
| `register` | Relay 注册 |
| `heartbeat` | 心跳 |
| `stats` | 统计上报 |
| `mesh_forward` | 跨 Relay 转发请求 |
| `mesh_data` | 跨 Relay 转发数据 |
| `SERVER_NODE_LOC` | 节点位置同步 |
| `SERVER_BLACKLIST` | Token 黑名单 |

### Relay ↔ 客户端
| 消息类型 | 说明 |
|---------|------|
| `RELAY_AUTH` | 客户端认证 |
| `DATA` | 数据转发 |
| `PING` / `PONG` | 心跳 |

## 3. 跨 Relay Mesh 转发

### 数据流
```
Node A (Relay 1)              Controller              Node B (Relay 2)
    │                            │                         │
    │ DATA to Node B             │                         │
    │──────────────────────────► │                         │
    │ (Node B not local)         │                         │
    │                            │                         │
    │ mesh_forward               │                         │
    │──────────────────────────► │                         │
    │                            │ mesh_data               │
    │                            │────────────────────────►│
    │                            │                         │
    │                            │                 Forward │
    │                            │                to Node B│
```

### 实现位置
- `RelayServer::forward_data()` - 检测跨 Relay 转发
- `ServerProtocolHandler::handle_mesh_forward()` - Controller 处理转发
- `ControllerClient::handle_control_message()` - Relay 接收转发数据

## 4. 编译状态

所有组件编译成功:
- `edgelink-controller` ✅
- `edgelink-server` ✅
- `edgelink-client` ✅

## 5. 文件变更

### 新增
- `src/client/p2p_manager.hpp/cpp`

### 修改
- `src/client/client.hpp/cpp` - P2P 集成
- `src/client/control_channel.hpp/cpp` - P2P 回调
- `src/server/relay_server.hpp/cpp` - Mesh 转发
- `src/server/controller_client.hpp/cpp` - mesh_data 处理
- `src/controller/api/control_handler.hpp/cpp` - mesh_forward 处理
- `src/controller/api/http_server.cpp` - mesh_forward 回调设置
- `CMakeLists.txt`

## 下一阶段

**Phase 7: Exit Node & 流量路由**
- Exit node 配置
- Internet 流量路由
- DNS over mesh
- 流量策略和 ACL

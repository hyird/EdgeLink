# EdgeLink WebSocket 消息处理完成状态

## 日期: 2026-01-07

## 总体状态: ✅ 完整实现

---

## 1. Controller WebSocket 消息处理

### 1.1 客户端控制通道 (`/ws/control`)

| 消息类型 | 方向 | 状态 | 说明 |
|---------|------|------|------|
| `auth` / `authenticate` | C→S | ✅ | 节点认证，返回 config_update |
| `heartbeat` / `ping` | C→S | ✅ | 心跳，返回 pong |
| `endpoint_report` | C→S | ✅ | 端点上报 |
| `latency_report` | C→S | ✅ | 延迟测量上报（支持批量） |
| `key_rotation` | C→S | ✅ | 密钥轮换通知 |
| `relay_connect` | C→S | ✅ | 通知已连接到某个 relay |
| `relay_disconnect` | C→S | ✅ | 通知已断开某个 relay |
| `config_update` | S→C | ✅ | 配置更新推送 |
| `peer_online` | S→C | ✅ | peer 上线通知 |
| `peer_offline` | S→C | ✅ | peer 下线通知 |
| `token_refresh` | S→C | ✅ | token 刷新 |
| `peer_key_update` | S→C | ✅ | peer 密钥更新通知 |
| `latency_request` | S→C | ✅ | 请求延迟测量 |
| `error` | S→C | ✅ | 错误响应 |

### 1.2 服务器控制通道 (`/ws/server`)

| 消息类型 | 方向 | 状态 | 说明 |
|---------|------|------|------|
| `register` | S→C | ✅ | Relay/STUN 服务器注册 |
| `heartbeat` / `ping` | S→C | ✅ | 心跳 |
| `stats` | S→C | ✅ | 统计数据上报 |
| `register_response` | C→S | ✅ | 注册响应 |
| `pong` | C→S | ✅ | 心跳响应 |

### 1.3 广播功能

| 功能 | 状态 | 说明 |
|------|------|------|
| `broadcast_to_network()` | ✅ | 广播到网络内所有节点 |
| `broadcast_to_servers()` | ✅ | 广播到所有服务器 |
| `push_config_update()` | ✅ | 推送配置到指定节点 |
| `push_config_update_to_network()` | ✅ | 推送配置到网络内所有节点 |
| `notify_peer_status()` | ✅ | peer 上下线通知 |

---

## 2. Client WebSocket 消息处理

### 2.1 ControlChannel (连接 Controller)

| 消息类型 | 方向 | 状态 | 说明 |
|---------|------|------|------|
| `auth_response` | 接收 | ✅ | 认证响应处理 |
| `config_update` | 接收 | ✅ | 配置更新处理（含 base64 解码） |
| `pong` | 接收 | ✅ | 心跳响应 |
| `peer_online` | 接收 | ✅ | peer 上线回调 |
| `peer_offline` | 接收 | ✅ | peer 下线回调 |
| `token_refresh` | 接收 | ✅ | token 刷新回调 |
| `peer_key_update` | 接收 | ✅ | peer 密钥更新（含 base64 解码） |
| `latency_request` | 接收 | ✅ | 延迟测量请求回调 |
| `error` | 接收 | ✅ | 错误处理 |
| `authenticate` | 发送 | ✅ | 发送认证请求 |
| `ping` | 发送 | ✅ | 发送心跳 |
| `latency_report` | 发送 | ✅ | 发送延迟上报（批量） |
| `relay_connect` | 发送 | ✅ | 通知 relay 连接 |
| `relay_disconnect` | 发送 | ✅ | 通知 relay 断开 |
| `endpoint_report` | 发送 | ✅ | 发送端点上报 |
| `key_rotation` | 发送 | ✅ | 发送密钥轮换 |

### 2.2 RelayManager (连接 Relay)

| 消息类型 | 方向 | 状态 | 说明 |
|---------|------|------|------|
| `RELAY_AUTH` | 发送 | ✅ | Relay 认证 |
| `RELAY_AUTH_RESP` | 接收 | ✅ | 认证响应 |
| `DATA` | 双向 | ✅ | 数据转发 |
| `PING` | 发送 | ✅ | 心跳 |
| `PONG` | 接收 | ✅ | 心跳响应 |

---

## 3. Relay Server WebSocket 消息处理

### 3.1 RelaySession (数据通道)

| 消息类型 | 状态 | 说明 |
|---------|------|------|
| `RELAY_AUTH` | ✅ | 客户端认证，JWT 验证 |
| `DATA` | ✅ | 数据转发（本地转发完成） |
| `PING` | ✅ | 心跳响应 |
| `ERROR_MSG` | ✅ | 错误响应 |

### 3.2 转发功能

| 功能 | 状态 | 说明 |
|------|------|------|
| 本地转发 | ✅ | 同一 Relay 上的节点间转发 |
| 跨 Relay mesh | ⏳ | 不同 Relay 间的转发（框架已有） |

---

## 4. 消息格式示例

### 4.1 config_update (Controller → Client)

```json
{
  "type": "config_update",
  "success": true,
  "network": {
    "id": 1,
    "name": "default",
    "cidr": "10.100.0.0/16",
    "mtu": 1400
  },
  "node": {
    "id": 1,
    "virtual_ip": "10.100.0.1"
  },
  "auth_token": "auth.1.xxx",
  "relay_token": "relay.1.xxx",
  "peers": [
    {
      "node_id": 2,
      "hostname": "node-2",
      "virtual_ip": "10.100.0.2",
      "node_key_pub": "base64...",
      "online": true,
      "nat_type": "full_cone",
      "path": {
        "available": true,
        "type": "direct_relay",
        "total_latency_ms": 45,
        "hop_count": 1,
        "hops": [...]
      }
    }
  ],
  "relays": [
    {
      "server_id": 1,
      "name": "relay-1",
      "region": "asia",
      "url": "wss://relay.example.com/ws/data",
      "latency_ms": 22
    }
  ],
  "recommended_relay_id": 1
}
```

### 4.2 latency_report (Client → Controller)

```json
{
  "type": "latency_report",
  "measurements": [
    {"server_id": 1, "rtt_ms": 22},
    {"server_id": 2, "rtt_ms": 45, "peer_id": 2}
  ]
}
```

### 4.3 peer_online (Controller → Clients)

```json
{
  "type": "peer_online",
  "node_id": 2,
  "hostname": "node-2",
  "virtual_ip": "10.100.0.2"
}
```

---

## 5. 本次修复内容

1. **Base64 解码修复**
   - 添加 `decode_base64()` 函数到 control_channel.cpp
   - 修复 peer.node_key_pub 解码
   - 修复 peer_key_update 消息的公钥解码

2. **配置更新处理完善**
   - 实现已连接状态下的 config_update 解析
   - 正确解析 peers、relays、tokens

3. **配置推送功能**
   - `WebSocketSession::send_config_update()` - 推送配置给单个节点
   - `WebSocketManager::push_config_update()` - 推送给指定节点
   - `WebSocketManager::push_config_update_to_network()` - 推送给整个网络

4. **API 可见性调整**
   - `ControlProtocolHandler::generate_config_update()` 改为 public

---

## 6. 待完成功能 (Phase 6)

- 跨 Relay mesh 数据转发
- P2P 直连消息 (P2P_INIT, P2P_ENDPOINT, P2P_PING 等)
- UDP STUN 消息处理

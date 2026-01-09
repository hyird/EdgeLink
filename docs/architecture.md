# EdgeLink 架构设计文档

> **版本**: 2.0
> **更新日期**: 2026-01-09
> **协议版本**: 0x02

## 目录

- [1. 系统概述](#1-系统概述)
- [2. 通信协议](#2-通信协议)
- [3. 状态机设计](#3-状态机设计)
- [4. 核心业务流程](#4-核心业务流程)
- [5. 数据安全设计](#5-数据安全设计)
- [6. 子网路由设计](#6-子网路由设计)
- [7. 组件详细设计](#7-组件详细设计)
- [8. 高并发设计要求](#8-高并发设计要求)
- [9. 开发约束](#9-开发约束)
- [10. 错误码定义](#10-错误码定义)
- [11. 配置项定义](#11-配置项定义)
- [12. 性能指标要求](#12-性能指标要求)
- [附录](#附录)

---

## 1. 系统概述

EdgeLink 是一个去中心化的 Mesh VPN 系统，支持节点间 P2P 直连和中继转发。

### 1.1 系统架构图

```
                           ┌─────────────────┐
                           │   Controller    │
                           │   (控制中心)     │
                           └────────┬────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    │               │               │
                    ▼               ▼               ▼
             ┌───────────┐   ┌───────────┐   ┌───────────┐
             │  Relay A  │◄─►│  Relay B  │◄─►│  Relay C  │
             │  (东京)    │   │  (新加坡)  │   │  (法兰克福)│
             └─────┬─────┘   └─────┬─────┘   └─────┬─────┘
                   │               │               │
         ┌─────────┴───┐     ┌─────┴─────┐   ┌─────┴─────┐
         ▼             ▼     ▼           ▼   ▼           ▼
    ┌────────┐   ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐
    │Client A│◄─►│Client B│ │Client C│ │Client D│ │Client E│
    └────────┘   └────────┘ └────────┘ └────────┘ └────────┘
         │           │
         └─── P2P ───┘  (直连优先)
```

### 1.2 组件职责

| 组件             | 职责                                                     |
| ---------------- | -------------------------------------------------------- |
| **Controller**   | 网络拓扑管理、节点认证授权、配置分发、路径计算、JWT 签发 |
| **Relay Server** | 数据中继、STUN 服务、Relay Mesh 网络、延迟上报           |
| **Client**       | TUN 虚拟网卡、P2P 直连、加密通信、路由管理、端点发现     |

### 1.3 设计原则

| 原则           | 说明                                                       |
| -------------- | ---------------------------------------------------------- |
| **端到端加密** | 数据在源节点加密，仅目标节点可解密，中继服务器无法读取明文 |
| **二进制协议** | 所有 WSS 消息采用紧凑二进制格式，减少传输体积              |
| **状态机驱动** | 各组件使用明确的 FSM 管理连接和会话生命周期                |
| **零信任中继** | Relay 仅转发密文，不参与密钥交换                           |

---

## 2. 通信协议

### 2.1 传输层

| 通道                | 协议            | 端点路径          | 用途     | 消息格式 |
| ------------------- | --------------- | ----------------- | -------- | -------- |
| Client ↔ Controller | WebSocket (WSS) | `/api/v1/control` | 控制面   | 二进制   |
| Client ↔ Relay      | WebSocket (WSS) | `/relay`          | 数据面   | 二进制   |
| Relay ↔ Controller  | WebSocket (WSS) | `/api/v1/server`  | 服务面   | 二进制   |
| Relay ↔ Relay       | WebSocket (WSS) | `/mesh`           | Mesh 面  | 二进制   |
| Client ↔ Client     | UDP             | N/A               | P2P 直连 | 二进制   |

### 2.2 二进制消息帧格式

所有 WebSocket 消息使用 Binary 模式传输，采用以下紧凑格式：

#### 2.2.1 帧头格式 (5 字节)

```
┌──────────┬──────────┬──────────┬─────────────────┐
│ Version  │   Type   │  Flags   │  Payload Length │
│  (1 B)   │  (1 B)   │  (1 B)   │    (2 B BE)     │
└──────────┴──────────┴──────────┴─────────────────┘
```

| 字段    | 大小   | 说明                              |
| ------- | ------ | --------------------------------- |
| Version | 1 字节 | 协议版本，当前 `0x02`             |
| Type    | 1 字节 | 消息类型                          |
| Flags   | 1 字节 | 标志位                            |
| Length  | 2 字节 | Payload 长度 (大端序)，最大 65530 |

#### 2.2.2 Flags 标志位

| 位   | 名称       | 说明                        |
| ---- | ---------- | --------------------------- |
| 0x01 | NEED_ACK   | 需要确认                    |
| 0x02 | COMPRESSED | Payload 已压缩 (LZ4)        |
| 0x04 | ENCRYPTED  | Payload 已加密 (控制面 E2E) |
| 0x08 | FRAGMENTED | 分片消息                    |

#### 2.2.3 完整帧结构

```
┌─────────────────────────────────────────────────────┐
│                    Frame Header (5B)                │
├─────────────────────────────────────────────────────┤
│                    Payload (变长)                   │
│              (二进制结构化数据)                      │
└─────────────────────────────────────────────────────┘
```

### 2.3 消息类型定义

#### 认证类 (0x01-0x0F)

| 类型码 | 名称           | 方向                | Payload 格式      |
| ------ | -------------- | ------------------- | ----------------- |
| 0x01   | AUTH_REQUEST   | Client → Controller | AuthRequest       |
| 0x02   | AUTH_RESPONSE  | Controller → Client | AuthResponse      |
| 0x03   | AUTH_CHALLENGE | Controller → Client | Challenge         |
| 0x04   | AUTH_VERIFY    | Client → Controller | ChallengeResponse |

#### 配置类 (0x10-0x1F)

| 类型码 | 名称          | 方向                | Payload 格式 |
| ------ | ------------- | ------------------- | ------------ |
| 0x10   | CONFIG        | Controller → Client | Config       |
| 0x11   | CONFIG_UPDATE | Controller → Client | ConfigUpdate |
| 0x12   | CONFIG_ACK    | Client → Controller | ConfigAck    |

#### 数据类 (0x20-0x2F)

| 类型码 | 名称     | 方向 | Payload 格式  |
| ------ | -------- | ---- | ------------- |
| 0x20   | DATA     | 双向 | EncryptedData |
| 0x21   | DATA_ACK | 双向 | DataAck       |

#### 心跳类 (0x30-0x3F)

| 类型码 | 名称           | 方向                | Payload 格式  |
| ------ | -------------- | ------------------- | ------------- |
| 0x30   | PING           | 双向                | Ping          |
| 0x31   | PONG           | 双向                | Pong          |
| 0x32   | LATENCY_REPORT | Client → Controller | LatencyReport |

#### P2P 类 (0x40-0x4F)

| 类型码 | 名称          | 方向                  | Payload 格式 |
| ------ | ------------- | --------------------- | ------------ |
| 0x40   | P2P_INIT      | Client → Controller   | P2PInit      |
| 0x41   | P2P_ENDPOINT  | Controller → Client   | P2PEndpoint  |
| 0x42   | P2P_PING      | Client ↔ Client (UDP) | P2PPing      |
| 0x43   | P2P_PONG      | Client ↔ Client (UDP) | P2PPong      |
| 0x44   | P2P_KEEPALIVE | Client ↔ Client (UDP) | P2PKeepalive |
| 0x45   | P2P_STATUS    | Client → Controller   | P2PStatus    |

#### 服务器类 (0x50-0x5F)

| 类型码 | 名称                  | 方向               | Payload 格式        |
| ------ | --------------------- | ------------------ | ------------------- |
| 0x50   | SERVER_REGISTER       | Relay → Controller | ServerRegister      |
| 0x51   | SERVER_REGISTER_RESP  | Controller → Relay | ServerRegisterResp  |
| 0x52   | SERVER_NODE_LOC       | Controller → Relay | ServerNodeLoc       |
| 0x53   | SERVER_BLACKLIST      | Controller → Relay | ServerBlacklist     |
| 0x54   | SERVER_HEARTBEAT      | Relay → Controller | ServerHeartbeat     |
| 0x55   | SERVER_RELAY_LIST     | Controller → Relay | ServerRelayList     |
| 0x56   | SERVER_LATENCY_REPORT | Relay → Controller | ServerLatencyReport |

#### 中继认证类 (0x60-0x6F)

| 类型码 | 名称            | 方向           | Payload 格式  |
| ------ | --------------- | -------------- | ------------- |
| 0x60   | RELAY_AUTH      | Client → Relay | RelayAuth     |
| 0x61   | RELAY_AUTH_RESP | Relay → Client | RelayAuthResp |

#### Mesh 类 (0x70-0x7F)

| 类型码 | 名称           | 方向          | Payload 格式 |
| ------ | -------------- | ------------- | ------------ |
| 0x70   | MESH_HELLO     | Relay → Relay | MeshHello    |
| 0x71   | MESH_HELLO_ACK | Relay → Relay | MeshHelloAck |
| 0x72   | MESH_FORWARD   | Relay → Relay | MeshForward  |
| 0x73   | MESH_PING      | Relay → Relay | MeshPing     |
| 0x74   | MESH_PONG      | Relay → Relay | MeshPong     |

#### 路由类 (0x80-0x8F)

| 类型码 | 名称           | 方向                | Payload 格式  |
| ------ | -------------- | ------------------- | ------------- |
| 0x80   | ROUTE_ANNOUNCE | Client → Controller | RouteAnnounce |
| 0x81   | ROUTE_UPDATE   | Controller → Client | RouteUpdate   |
| 0x82   | ROUTE_WITHDRAW | Client → Controller | RouteWithdraw |

#### 错误类 (0xF0-0xFF)

| 类型码 | 名称  | 方向 | Payload 格式 |
| ------ | ----- | ---- | ------------ |
| 0xFF   | ERROR | 双向 | Error        |

### 2.4 二进制 Payload 结构定义

所有 Payload 采用固定字段 + 变长字段的紧凑二进制格式。

#### 2.4.1 通用编码规则

| 类型           | 编码方式                       |
| -------------- | ------------------------------ |
| uint8/16/32/64 | 大端序 (Big Endian)            |
| string         | 2 字节长度前缀 + UTF-8 数据    |
| bytes          | 2 字节长度前缀 + 原始数据      |
| array          | 2 字节元素数量 + 元素序列      |
| bool           | 1 字节 (0x00=false, 0x01=true) |
| IPv4           | 4 字节                         |
| IPv6           | 16 字节                        |

#### 2.4.2 AUTH_REQUEST Payload

```
┌────────────┬────────────┬────────────┬────────────┐
│ auth_type  │ machine_key│  node_key  │  hostname  │
│   (1 B)    │  (32 B)    │  (32 B)    │ (len+str)  │
├────────────┼────────────┼────────────┼────────────┤
│    os      │   arch     │  version   │ timestamp  │
│ (len+str)  │ (len+str)  │ (len+str)  │   (8 B)    │
├────────────┼────────────┴────────────┴────────────┤
│ signature  │  auth_data (可选，取决于 auth_type)   │
│  (64 B)    │         (变长)                       │
└────────────┴──────────────────────────────────────┘
```

| 字段        | 大小 | 说明                                       |
| ----------- | ---- | ------------------------------------------ |
| auth_type   | 1 B  | 0x01=user, 0x02=authkey, 0x03=machine      |
| machine_key | 32 B | Ed25519 公钥                               |
| node_key    | 32 B | X25519 公钥                                |
| hostname    | 变长 | 主机名                                     |
| os          | 变长 | 操作系统                                   |
| arch        | 变长 | CPU 架构                                   |
| version     | 变长 | 客户端版本                                 |
| timestamp   | 8 B  | Unix 时间戳 (毫秒)                         |
| signature   | 64 B | Ed25519 签名                               |
| auth_data   | 变长 | user: username+password_hash, authkey: key |

#### 2.4.3 AUTH_RESPONSE Payload

```
┌────────────┬────────────┬────────────┬────────────┐
│  success   │  node_id   │ virtual_ip │ network_id │
│   (1 B)    │   (4 B)    │   (4 B)    │   (4 B)    │
├────────────┼────────────┴────────────┴────────────┤
│ auth_token │           relay_token                │
│ (len+bytes)│          (len+bytes)                 │
├────────────┼──────────────────────────────────────┤
│error_code  │           error_msg                  │
│   (2 B)    │          (len+str)                   │
└────────────┴──────────────────────────────────────┘
```

#### 2.4.4 CONFIG Payload

```
┌────────────┬────────────┬────────────┬────────────┐
│  version   │ network_id │   subnet   │subnet_mask │
│   (8 B)    │   (4 B)    │   (4 B)    │   (1 B)    │
├────────────┼────────────┴────────────┴────────────┤
│relay_count │           relays[]                   │
│   (2 B)    │    (RelayInfo 数组)                  │
├────────────┼──────────────────────────────────────┤
│ stun_count │           stuns[]                    │
│   (2 B)    │    (STUNInfo 数组)                   │
├────────────┼──────────────────────────────────────┤
│ peer_count │           peers[]                    │
│   (2 B)    │    (PeerInfo 数组)                   │
├────────────┼──────────────────────────────────────┤
│route_count │           routes[]                   │
│   (2 B)    │    (RouteInfo 数组)                  │
├────────────┼────────────┬────────────┬────────────┤
│  relay_    │  expires   │   网络     │            │
│  token     │    (8 B)   │   名称     │            │
│(len+bytes) │            │ (len+str)  │            │
└────────────┴────────────┴────────────┴────────────┘
```

#### 2.4.5 DATA Payload (端到端加密)

```
┌────────────┬────────────┬────────────┬────────────────────────┬────────────┐
│  src_node  │  dst_node  │   nonce    │   encrypted_payload    │  auth_tag  │
│   (4 B)    │   (4 B)    │  (12 B)    │       (变长)           │  (16 B)    │
└────────────┴────────────┴────────────┴────────────────────────┴────────────┘
```

| 字段              | 大小 | 说明                            |
| ----------------- | ---- | ------------------------------- |
| src_node          | 4 B  | 源节点 ID                       |
| dst_node          | 4 B  | 目标节点 ID                     |
| nonce             | 12 B | 随机数 (4B random + 8B counter) |
| encrypted_payload | 变长 | ChaCha20-Poly1305 加密的 IP 包  |
| auth_tag          | 16 B | AEAD 认证标签                   |

#### 2.4.6 PeerInfo 结构

```
┌────────────┬────────────┬────────────┬────────────┐
│  node_id   │ virtual_ip │  node_key  │   online   │
│   (4 B)    │   (4 B)    │  (32 B)    │   (1 B)    │
├────────────┼────────────┴────────────┴────────────┤
│   name     │         endpoints[]                  │
│ (len+str)  │   (EndpointInfo 数组)                │
├────────────┼──────────────────────────────────────┤
│ allowed_   │          (CIDR 数组)                 │
│ subnets    │   该节点可路由的子网列表              │
└────────────┴──────────────────────────────────────┘
```

#### 2.4.7 RouteInfo 结构

```
┌────────────┬────────────┬────────────┬────────────┬────────────┐
│   prefix   │prefix_len  │gateway_node│  priority  │   weight   │
│   (4/16 B) │   (1 B)    │   (4 B)    │   (2 B)    │   (2 B)    │
├────────────┼────────────┼────────────┼────────────┼────────────┤
│  enabled   │   metric   │   flags    │            │            │
│   (1 B)    │   (4 B)    │   (1 B)    │            │            │
└────────────┴────────────┴────────────┴────────────┴────────────┘
```

#### 2.4.8 EndpointInfo 结构

```
┌────────────┬────────────┬────────────┬────────────┐
│    type    │  ip_type   │     ip     │    port    │
│   (1 B)    │   (1 B)    │ (4/16 B)   │   (2 B)    │
├────────────┼────────────┼────────────┼────────────┤
│  priority  │ discovered │            │            │
│   (1 B)    │   (8 B)    │            │            │
└────────────┴────────────┴────────────┴────────────┘
```

---

## 3. 状态机设计

### 3.1 Client 连接状态机

```
                          ┌─────────────────────────────────────────┐
                          │                                         │
                          ▼                                         │
    ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐   │
    │          │    │          │    │          │    │          │   │
    │  INIT    ├───►│CONNECTING├───►│  AUTH    ├───►│CONNECTED │   │
    │          │    │          │    │          │    │          │   │
    └──────────┘    └────┬─────┘    └────┬─────┘    └────┬─────┘   │
                         │               │               │         │
                         │ timeout/      │ auth_fail     │ disconnect
                         │ error         │               │         │
                         │               │               │         │
                         ▼               ▼               ▼         │
                    ┌──────────────────────────────────────────┐   │
                    │              RECONNECTING                │───┘
                    │         (指数退避重连)                    │
                    └──────────────────────────────────────────┘
                                        │
                                        │ max_retries
                                        ▼
                                  ┌──────────┐
                                  │ DISABLED │
                                  └──────────┘
```

| 状态         | 说明                    | 允许的事件                       |
| ------------ | ----------------------- | -------------------------------- |
| INIT         | 初始状态                | connect()                        |
| CONNECTING   | 正在建立 WebSocket 连接 | connected, timeout, error        |
| AUTH         | 正在进行认证            | auth_success, auth_fail, timeout |
| CONNECTED    | 已连接，正常工作        | disconnect, error, config_update |
| RECONNECTING | 断线重连中              | connected, max_retries           |
| DISABLED     | 已禁用，不再重连        | enable()                         |

#### 状态转换表

| 当前状态     | 事件         | 下一状态     | 动作                     |
| ------------ | ------------ | ------------ | ------------------------ |
| INIT         | connect()    | CONNECTING   | 发起 WSS 连接            |
| CONNECTING   | ws_connected | AUTH         | 发送 AUTH_REQUEST        |
| CONNECTING   | timeout      | RECONNECTING | 记录错误，启动重连定时器 |
| CONNECTING   | error        | RECONNECTING | 记录错误，启动重连定时器 |
| AUTH         | auth_success | CONNECTED    | 保存 token，请求配置     |
| AUTH         | auth_fail    | RECONNECTING | 清除凭据，延迟重试       |
| AUTH         | timeout      | RECONNECTING | 启动重连定时器           |
| CONNECTED    | disconnect   | RECONNECTING | 清理会话，启动重连       |
| CONNECTED    | error        | RECONNECTING | 清理会话，启动重连       |
| RECONNECTING | ws_connected | AUTH         | 发送 AUTH_REQUEST        |
| RECONNECTING | max_retries  | DISABLED     | 通知用户                 |
| DISABLED     | enable()     | INIT         | 重置重试计数             |

### 3.2 P2P 连接状态机 (每个对端)

```
    ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
    │          │    │          │    │          │    │          │
    │   IDLE   ├───►│RESOLVING ├───►│ PUNCHING ├───►│CONNECTED │
    │          │    │          │    │          │    │          │
    └──────────┘    └────┬─────┘    └────┬─────┘    └────┬─────┘
         ▲               │               │               │
         │               │ no_endpoints  │ timeout       │ timeout/
         │               │               │               │ error
         │               ▼               ▼               │
         │          ┌─────────────────────────┐         │
         └──────────┤       RELAY_ONLY        │◄────────┘
                    │   (仅通过 Relay 通信)    │
                    └─────────────────────────┘
```

| 状态       | 说明                 | 超时时间   |
| ---------- | -------------------- | ---------- |
| IDLE       | 空闲，未尝试 P2P     | -          |
| RESOLVING  | 正在获取对端端点     | 5s         |
| PUNCHING   | 正在进行 NAT 穿透    | 10s        |
| CONNECTED  | P2P 直连已建立       | -          |
| RELAY_ONLY | 穿透失败，仅用 Relay | 60s 后重试 |

#### P2P 打洞流程详细状态

```
PUNCHING 子状态:

    ┌──────────┐    ┌──────────┐    ┌──────────┐
    │ SEND_    │    │ WAIT_    │    │ VERIFY   │
    │ PROBES   ├───►│ RESPONSE ├───►│ BIDIR    │
    └──────────┘    └──────────┘    └──────────┘
         │               │               │
         │ all_sent      │ pong_recv     │ both_ok
         │               │               │
         ▼               ▼               ▼
    ┌──────────────────────────────────────────┐
    │              SUCCESS / FAIL              │
    └──────────────────────────────────────────┘
```

### 3.3 Relay 会话状态机

```
    ┌──────────┐    ┌──────────┐    ┌──────────┐
    │          │    │          │    │          │
    │  INIT    ├───►│  AUTH    ├───►│  ACTIVE  │
    │          │    │          │    │          │
    └──────────┘    └────┬─────┘    └────┬─────┘
                         │               │
                         │ auth_fail     │ close/error
                         │               │
                         ▼               ▼
                    ┌──────────────────────────┐
                    │          CLOSED          │
                    └──────────────────────────┘
```

### 3.4 Relay Server 注册状态机

```
    ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
    │          │    │          │    │          │    │          │
    │  INIT    ├───►│CONNECTING├───►│REGISTERING───►│REGISTERED│
    │          │    │          │    │          │    │          │
    └──────────┘    └────┬─────┘    └────┬─────┘    └────┬─────┘
                         │               │               │
                         │               │               │ heartbeat
                         │               │               │ timeout
                         ▼               ▼               ▼
                    ┌──────────────────────────────────────────┐
                    │              RECONNECTING                │
                    └──────────────────────────────────────────┘
```

### 3.5 Mesh 连接状态机 (Relay 间)

```
    ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
    │          │    │          │    │          │    │          │
    │  INIT    ├───►│CONNECTING├───►│ HANDSHAKE├───►│  READY   │
    │          │    │          │    │          │    │          │
    └──────────┘    └────┬─────┘    └────┬─────┘    └────┬─────┘
                         │               │               │
                         ▼               ▼               ▼
                    ┌──────────────────────────────────────────┐
                    │                 FAILED                   │
                    │            (延迟后重试)                   │
                    └──────────────────────────────────────────┘
```

---

## 4. 核心业务流程

### 4.1 客户端认证流程

支持三种认证方式：

1. **用户登录认证** - 用户名密码登录，适用于个人用户
2. **AuthKey 认证** - 预共享密钥认证，适用于无人值守设备
3. **机器认证** - 已注册节点自动重连

#### 方式一：用户登录认证

```
Client                         Controller
  │                                │
  │    状态: INIT → CONNECTING     │
  ├─── WebSocket 连接 ────────────►│
  │                                │
  │    状态: CONNECTING → AUTH     │
  ├─── AUTH_REQUEST ──────────────►│
  │    [Binary: auth_type=0x01,    │
  │     machine_key, node_key,     │
  │     username, password_hash,   │
  │     timestamp, signature]      │
  │                                │
  │         ┌──────────────────────┤
  │         │ 1. 验证用户名密码      │
  │         │ 2. 验证签名           │
  │         │ 3. 查找/创建节点       │
  │         │ 4. 绑定用户与节点      │
  │         │ 5. 分配虚拟 IP        │
  │         │ 6. 生成 JWT Token     │
  │         └──────────────────────┤
  │                                │
  │    状态: AUTH → CONNECTED      │
  │◄─── AUTH_RESPONSE ─────────────┤
  │    [Binary: success=1,         │
  │     node_id, virtual_ip,       │
  │     auth_token, relay_token]   │
  │                                │
  │◄─── CONFIG ────────────────────┤
  │    [Binary: 完整网络配置]       │
  │                                │
```

#### 方式二：AuthKey 认证

```
Client                         Controller
  │                                │
  ├─── WebSocket 连接 ────────────►│
  │                                │
  ├─── AUTH_REQUEST ──────────────►│
  │    [Binary: auth_type=0x02,    │
  │     machine_key, node_key,     │
  │     auth_key="tskey-...",      │
  │     timestamp, signature]      │
  │                                │
  │         ┌──────────────────────┤
  │         │ 1. 验证 AuthKey 有效  │
  │         │ 2. 验证签名           │
  │         │ 3. 检查使用次数/过期   │
  │         │ 4. 查找/创建节点       │
  │         │ 5. 分配虚拟 IP        │
  │         │ 6. 生成 JWT Token     │
  │         │ 7. 增加 AuthKey 计数  │
  │         └──────────────────────┤
  │                                │
  │◄─── AUTH_RESPONSE ─────────────┤
  │◄─── CONFIG ────────────────────┤
  │                                │
```

#### 方式三：已注册节点重连

```
Client                         Controller
  │                                │
  ├─── WebSocket 连接 ────────────►│
  │                                │
  ├─── AUTH_REQUEST ──────────────►│
  │    [Binary: auth_type=0x03,    │
  │     machine_key, node_key,     │  (无需密码或 AuthKey)
  │     timestamp, signature]      │
  │                                │
  │         ┌──────────────────────┤
  │         │ 1. 通过 machine_key   │
  │         │    查找已注册节点      │
  │         │ 2. 验证签名           │
  │         │ 3. 检查节点授权状态    │
  │         │ 4. 生成 JWT Token     │
  │         └──────────────────────┤
  │                                │
  │◄─── AUTH_RESPONSE ─────────────┤
  │◄─── CONFIG ────────────────────┤
  │                                │
```

### 4.2 中继连接流程

```
Client                           Relay
  │                                │
  │    状态: INIT → AUTH           │
  ├─── WebSocket 连接 /relay ─────►│
  │                                │
  ├─── RELAY_AUTH ────────────────►│
  │    [Binary: relay_token]       │
  │                                │
  │         ┌──────────────────────┤
  │         │ 验证 JWT Token        │
  │         │ 检查黑名单            │
  │         └──────────────────────┤
  │                                │
  │    状态: AUTH → ACTIVE         │
  │◄─── RELAY_AUTH_RESP ───────────┤
  │    [Binary: success, node_id]  │
  │                                │
  │◄════ DATA 双向传输 (E2E加密) ══►│
  │                                │
```

### 4.3 数据传输路径选择

优先级从高到低:

1. P2P 直连 (UDP) - 最低延迟
2. 单跳 Relay 转发 - 中等延迟
3. 多跳 Mesh 转发 - 最高延迟

#### 路径选择算法

```
选择最佳路径(目标节点):
    1. 检查 P2P 连接状态
       - 如果 P2P_STATE == CONNECTED 且 RTT < 阈值
         → 使用 P2P

    2. 检查单跳 Relay
       - 查找目标节点连接的 Relay
       - 如果本地也连接同一 Relay
         → 使用该 Relay

    3. 计算多跳路径
       - 使用 Dijkstra 计算最短路径
       - 权重 = Relay 间延迟
       → 使用多跳 Mesh
```

#### P2P 直连流程

```
Client A           Controller           Client B
    │                  │                    │
    │  P2P_STATE:      │      P2P_STATE:    │
    │  IDLE→RESOLVING  │      IDLE→RESOLVING│
    ├── P2P_INIT ─────►│◄───── P2P_INIT ───┤
    │                  │                    │
    │◄─ P2P_ENDPOINT ──┤──► P2P_ENDPOINT ──►│
    │  [Binary: peer_id,                    │
    │   endpoints[],                        │
    │   nat_type]       │                   │
    │                  │                    │
    │  P2P_STATE:      │      P2P_STATE:    │
    │  RESOLVING→PUNCHING    RESOLVING→PUNCHING
    │◄══════════ UDP Hole Punching ═══════►│
    │  P2P_PING / P2P_PONG                  │
    │                  │                    │
    │  P2P_STATE:      │      P2P_STATE:    │
    │  PUNCHING→CONNECTED   PUNCHING→CONNECTED
    │◄═══════ P2P UDP E2E加密通信 ═════════►│
    │                  │                    │
    ├── P2P_STATUS ───►│◄───── P2P_STATUS ──┤
    │  [Binary: connected=true, rtt_ms]     │
```

#### 中继转发流程 (E2E 加密)

```
Client A      Relay A      Relay B      Client B
    │            │            │             │
    │ 加密数据    │            │             │
    ├─ DATA ────►│            │             │
    │ [E2E加密]  │ 无法解密   │             │
    │            ├─ MESH_FWD ►│             │
    │            │ [原样转发] │ 无法解密    │
    │            │            ├── DATA ────►│
    │            │            │  [E2E加密]  │ 解密数据
```

### 4.4 Relay 注册流程

```
Relay                          Controller
  │                                │
  │    状态: INIT → CONNECTING     │
  ├─── WebSocket 连接 ────────────►│
  │    /api/v1/server              │
  │                                │
  │    状态: CONNECTING → REGISTERING
  ├─── SERVER_REGISTER ───────────►│
  │    [Binary:                    │
  │      server_token,             │
  │      name="relay-tokyo",       │
  │      capabilities=0x03,        │
  │      region="ap-northeast",    │
  │      relay_url, stun_ip,       │
  │      stun_port]                │
  │                                │
  │         ┌──────────────────────┤
  │         │ 1. 验证 server_token  │
  │         │ 2. 注册/更新服务器信息 │
  │         │ 3. 分配 server_id     │
  │         └──────────────────────┤
  │                                │
  │    状态: REGISTERING → REGISTERED
  │◄─── SERVER_REGISTER_RESP ──────┤
  │    [Binary: success, server_id]│
  │                                │
  │◄─── SERVER_RELAY_LIST ─────────┤
  │    [Binary: 其他 Relay 列表]    │
  │                                │
  │◄─── SERVER_NODE_LOC ───────────┤
  │    [Binary: 节点位置信息]       │
  │                                │
  │════ 定期心跳 ══════════════════►│
  │    SERVER_HEARTBEAT (30s)      │
  │                                │
```

### 4.5 Relay Mesh 建立流程

```
Relay A              Controller              Relay B
   │                     │                      │
   │ 状态: INIT          │          状态: INIT  │
   ├── SERVER_REGISTER ──►│◄── SERVER_REGISTER ─┤
   │                     │                      │
   │◄─ SERVER_REG_RESP ──┤──► SERVER_REG_RESP ─►│
   │◄─ SERVER_RELAY_LIST─┤──► SERVER_RELAY_LIST─►│
   │   [包含对方地址]     │    [包含对方地址]    │
   │                     │                      │
   │ 状态: INIT → CONNECTING                    │
   ├─────────── WSS 连接 /mesh ────────────────►│
   │                                            │
   │ 状态: CONNECTING → HANDSHAKE               │
   ├─────────── MESH_HELLO ───────────────────►│
   │  [Binary: server_id, server_token]        │
   │                                            │
   │◄────────── MESH_HELLO_ACK ────────────────┤
   │  [Binary: server_id]                      │
   │                                            │
   │ 状态: HANDSHAKE → READY                    │
   │◄═══════════ Mesh 通道就绪 ════════════════►│
   │                                            │
   │◄═══════════ MESH_PING/PONG ══════════════►│
   │            (延迟测量)                       │
```

---

## 5. 数据安全设计

### 5.1 端到端加密架构

```
┌─────────────────────────────────────────────────────────────────┐
│                     端到端加密数据流                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Client A                Relay               Client B           │
│  ┌───────┐              ┌───────┐           ┌───────┐          │
│  │明文IP包│              │       │           │明文IP包│          │
│  └───┬───┘              │       │           └───▲───┘          │
│      │                  │       │               │              │
│      ▼ 加密             │       │          解密 │              │
│  ┌───────┐   传输       │ 转发  │    传输   ┌───────┐          │
│  │密文数据├────────────►│ 密文  ├──────────►│密文数据│          │
│  └───────┘              │(无法  │           └───────┘          │
│                         │ 解密) │                              │
│                         └───────┘                              │
│                                                                 │
│  Session Key = HKDF(ECDH(A.node_key, B.node_key))              │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 5.2 密钥体系

| 密钥类型      | 算法      | 大小    | 用途            | 生命周期          |
| ------------- | --------- | ------- | --------------- | ----------------- |
| Machine Key   | Ed25519   | 256 bit | 设备身份签名    | 永久 (设备绑定)   |
| Node Key      | X25519    | 256 bit | ECDH 密钥交换   | 可轮换 (默认 24h) |
| Session Key   | HKDF 派生 | 256 bit | 数据加密        | 每对节点独立      |
| Ephemeral Key | X25519    | 256 bit | 前向保密 (可选) | 每次会话          |

### 5.3 密钥交换与派生

#### 5.3.1 Session Key 派生

```
1. ECDH 密钥交换:
   shared_secret = X25519(my_node_key_priv, peer_node_key_pub)

2. HKDF 派生:
   输入:
     - IKM: shared_secret (32 bytes)
     - Salt: sort(my_node_id, peer_node_id) 拼接 (8 bytes)
     - Info: "edgelink-session-v2"

   输出:
     - Session Key (32 bytes)
     - Send Nonce Base (12 bytes)
     - Recv Nonce Base (12 bytes)
```

#### 5.3.2 Nonce 构造

```
┌────────────────┬────────────────────────┐
│  Random Part   │     Counter Part       │
│    (4 bytes)   │      (8 bytes)         │
└────────────────┴────────────────────────┘

- Random Part: 会话初始化时随机生成
- Counter Part: 每发送一个包 +1，大端序
- 发送方和接收方使用不同的 Nonce Base
```

### 5.4 加密数据包格式

```
┌───────────┬───────────┬──────────┬─────────────────────┬──────────┐
│ Src Node  │ Dst Node  │  Nonce   │  Encrypted Payload  │ Auth Tag │
│   (4 B)   │   (4 B)   │  (12 B)  │     (Variable)      │  (16 B)  │
└───────────┴───────────┴──────────┴─────────────────────┴──────────┘
         │                    │                │               │
         └── 明文 (路由用) ────┴──── 认证加密 ──┴───────────────┘
```

| 字段              | 加密 | 认证 | 说明               |
| ----------------- | ---- | ---- | ------------------ |
| Src Node          | 否   | 是   | 用于路由和密钥查找 |
| Dst Node          | 否   | 是   | 用于路由和密钥查找 |
| Nonce             | 否   | 是   | 防重放             |
| Encrypted Payload | 是   | 是   | 实际 IP 包数据     |
| Auth Tag          | -    | -    | AEAD 认证标签      |

### 5.5 加密规格

| 项目       | 规格                     |
| ---------- | ------------------------ |
| 加密算法   | ChaCha20-Poly1305 (AEAD) |
| 密钥长度   | 256 bit                  |
| Nonce 长度 | 96 bit (12 bytes)        |
| Auth Tag   | 128 bit (16 bytes)       |
| 重放保护   | 2048 位滑动窗口          |
| 最大包大小 | 65535 - 36 = 65499 bytes |

### 5.6 重放攻击防护

```
滑动窗口算法:

窗口大小: 2048 bits
最高已见序号: max_seq

收到包 (seq):
    if seq > max_seq:
        # 新序号，接受并更新窗口
        shift = seq - max_seq
        window <<= shift
        window |= 1
        max_seq = seq
        return ACCEPT

    if seq <= max_seq - 2048:
        # 太旧，拒绝
        return REJECT_OLD

    bit_pos = max_seq - seq
    if window & (1 << bit_pos):
        # 重复包
        return REJECT_REPLAY

    # 标记为已见
    window |= (1 << bit_pos)
    return ACCEPT
```

### 5.7 JWT Token 设计

#### Auth Token (有效期 24 小时)

```
Header: { "alg": "HS256", "typ": "JWT" }
Payload:
{
    "node_id": 12345,
    "network_id": 1,
    "type": "auth",
    "iat": 1704787200,
    "exp": 1704873600
}
```

#### Relay Token (有效期 90 分钟)

```
Header: { "alg": "HS256", "typ": "JWT" }
Payload:
{
    "node_id": 12345,
    "network_id": 1,
    "type": "relay",
    "jti": "unique-token-id",  // 用于黑名单
    "iat": 1704787200,
    "exp": 1704792600
}
```

### 5.8 控制面加密 (可选)

对于敏感的控制消息，可启用控制面端到端加密：

```
Client A                Controller
    │                       │
    │  使用 Controller 的   │
    │  公钥加密控制消息      │
    ├── [ENCRYPTED FLAG] ──►│
    │   AUTH_REQUEST        │
    │   (加密的 Payload)    │
    │                       │
```

设置 Flags 的 ENCRYPTED 位 (0x04) 表示 Payload 已加密。

---

## 6. 子网路由设计

### 6.1 概述

EdgeLink 支持子网路由功能，允许节点将其本地网络暴露给 VPN 网络中的其他节点。

```
┌─────────────────────────────────────────────────────────────────┐
│                        子网路由示例                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   办公室 A (192.168.1.0/24)         办公室 B (192.168.2.0/24)   │
│   ┌─────────────────────┐           ┌─────────────────────┐    │
│   │  ┌───┐ ┌───┐ ┌───┐ │           │ ┌───┐ ┌───┐ ┌───┐  │    │
│   │  │PC1│ │PC2│ │PC3│ │           │ │PC4│ │PC5│ │PC6│  │    │
│   │  └─┬─┘ └─┬─┘ └─┬─┘ │           │ └─┬─┘ └─┬─┘ └─┬─┘  │    │
│   │    └─────┼─────┘   │           │   └─────┼─────┘    │    │
│   │          │         │           │         │          │    │
│   │    ┌─────┴─────┐   │           │   ┌─────┴─────┐    │    │
│   │    │  Gateway  │   │           │   │  Gateway  │    │    │
│   │    │  Client A │   │           │   │  Client B │    │    │
│   │    │ 10.0.0.1  │   │           │   │ 10.0.0.2  │    │    │
│   │    └─────┬─────┘   │           │   └─────┬─────┘    │    │
│   └──────────┼─────────┘           └──────────┼─────────┘    │
│              │                                │              │
│              └────────── EdgeLink VPN ────────┘              │
│                        (10.0.0.0/24)                         │
│                                                              │
│   路由表:                                                     │
│   - 192.168.1.0/24 → via 10.0.0.1 (Client A)                │
│   - 192.168.2.0/24 → via 10.0.0.2 (Client B)                │
│                                                              │
└─────────────────────────────────────────────────────────────────┘
```

### 6.2 路由类型

| 类型         | 说明                   | 使用场景            |
| ------------ | ---------------------- | ------------------- |
| **节点路由** | 单个节点的虚拟 IP      | 默认，自动创建      |
| **子网路由** | 通过网关节点访问的子网 | 办公室/数据中心互联 |
| **默认路由** | 0.0.0.0/0 全流量       | Exit Node 模式      |
| **排除路由** | 不走 VPN 的网段        | 本地网络排除        |

### 6.3 路由数据结构

#### 6.3.1 RouteInfo 二进制格式

```
┌────────────┬────────────┬────────────┬────────────┬────────────┐
│  ip_type   │   prefix   │ prefix_len │gateway_node│  priority  │
│   (1 B)    │ (4/16 B)   │   (1 B)    │   (4 B)    │   (2 B)    │
├────────────┼────────────┼────────────┼────────────┼────────────┤
│   weight   │   metric   │   flags    │  tag_len   │    tag     │
│   (2 B)    │   (4 B)    │   (1 B)    │   (1 B)    │  (变长)    │
└────────────┴────────────┴────────────┴────────────┴────────────┘
```

| 字段         | 说明                                     |
| ------------ | ---------------------------------------- |
| ip_type      | 0x04=IPv4, 0x06=IPv6                     |
| prefix       | 网络前缀                                 |
| prefix_len   | 前缀长度 (0-32 for IPv4, 0-128 for IPv6) |
| gateway_node | 网关节点 ID                              |
| priority     | 优先级 (越小越优先，默认 100)            |
| weight       | 权重 (用于负载均衡，默认 100)            |
| metric       | 路由度量值                               |
| flags        | 路由标志                                 |
| tag          | 路由标签 (用于策略路由)                  |

#### 6.3.2 路由标志 (flags)

| 位   | 名称      | 说明                |
| ---- | --------- | ------------------- |
| 0x01 | ENABLED   | 路由已启用          |
| 0x02 | AUTO      | 自动发现的路由      |
| 0x04 | STATIC    | 静态配置的路由      |
| 0x08 | EXIT_NODE | Exit Node 路由      |
| 0x10 | EXCLUDE   | 排除路由 (不走 VPN) |
| 0x20 | PRIMARY   | 主路由              |
| 0x40 | FAILOVER  | 故障转移路由        |

### 6.4 路由通告流程

#### 6.4.1 子网路由通告

```
Client (Gateway)           Controller           Other Clients
      │                        │                      │
      │  配置子网路由           │                      │
      │  192.168.1.0/24        │                      │
      │                        │                      │
      ├── ROUTE_ANNOUNCE ─────►│                      │
      │   [Binary:             │                      │
      │    prefix=192.168.1.0, │                      │
      │    prefix_len=24,      │                      │
      │    flags=ENABLED]      │                      │
      │                        │                      │
      │        ┌───────────────┤                      │
      │        │ 1. 验证权限    │                      │
      │        │ 2. 检查冲突    │                      │
      │        │ 3. 更新路由表  │                      │
      │        └───────────────┤                      │
      │                        │                      │
      │                        ├── CONFIG_UPDATE ────►│
      │                        │   [Binary:           │
      │                        │    route_updates[]:  │
      │                        │    ADD 192.168.1.0/24│
      │                        │    via node_id]      │
      │                        │                      │
      │                        │◄─── CONFIG_ACK ──────┤
      │                        │                      │
```

#### 6.4.2 路由撤销

```
Client (Gateway)           Controller           Other Clients
      │                        │                      │
      │  移除子网路由           │                      │
      │                        │                      │
      ├── ROUTE_WITHDRAW ─────►│                      │
      │   [Binary:             │                      │
      │    prefix=192.168.1.0, │                      │
      │    prefix_len=24]      │                      │
      │                        │                      │
      │                        ├── CONFIG_UPDATE ────►│
      │                        │   [Binary:           │
      │                        │    route_updates[]:  │
      │                        │    REMOVE            │
      │                        │    192.168.1.0/24]   │
      │                        │                      │
```

### 6.5 路由选择算法

```
路由查找(目标 IP):
    candidates = []

    for route in routing_table:
        if not route.enabled:
            continue
        if not matches(目标 IP, route.prefix, route.prefix_len):
            continue
        if route.flags & EXCLUDE:
            return LOCAL  # 不走 VPN
        candidates.append(route)

    if candidates.empty():
        return DEFAULT_ROUTE or DROP

    # 最长前缀匹配
    candidates.sort(by=prefix_len, descending=true)
    best_prefix_len = candidates[0].prefix_len
    candidates = filter(c.prefix_len == best_prefix_len)

    # 优先级排序
    candidates.sort(by=priority, ascending=true)
    best_priority = candidates[0].priority
    candidates = filter(c.priority == best_priority)

    # 检查网关节点在线状态
    online_candidates = filter(gateway_online(c.gateway_node))
    if online_candidates.empty():
        # 所有网关离线，等待或丢弃
        return UNREACHABLE

    # 加权负载均衡
    if online_candidates.size() > 1:
        return weighted_random_select(online_candidates)

    return online_candidates[0]
```

### 6.6 Exit Node 功能

Exit Node 允许将所有互联网流量通过指定节点转发。

#### 6.6.1 Exit Node 配置

```
# Client 配置为 Exit Node
exit_node:
  enabled: true
  advertise: true  # 通告给其他节点
  allowed_users: []  # 空表示允许所有

# Client 使用 Exit Node
use_exit_node:
  enabled: true
  node_id: 12345  # 或 "auto" 自动选择
```

#### 6.6.2 Exit Node 路由

```
Exit Node 通告:
  - 0.0.0.0/0 (IPv4 默认路由)
  - ::/0 (IPv6 默认路由)
  - flags = EXIT_NODE | ENABLED

使用 Exit Node 的客户端:
  - 安装 0.0.0.0/0 路由指向 Exit Node
  - 排除 Controller/Relay 地址
  - 排除本地子网
```

### 6.7 路由冲突处理

| 场景             | 处理策略                     |
| ---------------- | ---------------------------- |
| 子网重叠         | 拒绝后通告的路由，返回 ERROR |
| 相同子网不同网关 | 允许，用于冗余/负载均衡      |
| 更具体路由       | 允许，最长前缀匹配           |
| 节点离线         | 自动故障转移到备用路由       |

### 6.8 子网路由数据库表

```sql
CREATE TABLE routes (
    id INTEGER PRIMARY KEY,
    network_id INTEGER NOT NULL,
    prefix BLOB NOT NULL,           -- 4 或 16 字节
    prefix_len INTEGER NOT NULL,    -- 0-128
    gateway_node_id INTEGER NOT NULL,
    priority INTEGER DEFAULT 100,
    weight INTEGER DEFAULT 100,
    metric INTEGER DEFAULT 0,
    flags INTEGER DEFAULT 1,        -- ENABLED
    tag TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY (network_id) REFERENCES networks(id),
    FOREIGN KEY (gateway_node_id) REFERENCES nodes(id),
    UNIQUE (network_id, prefix, prefix_len, gateway_node_id)
);

CREATE INDEX idx_routes_network ON routes(network_id);
CREATE INDEX idx_routes_gateway ON routes(gateway_node_id);
```

---

## 7. 组件详细设计

### 7.1 Controller

#### 功能模块

| 模块           | 职责                                            |
| -------------- | ----------------------------------------------- |
| WsServer       | WebSocket 服务器，接受连接并路由到对应 Session  |
| SessionManager | 管理所有活动会话，支持按 node_id/server_id 查找 |
| ControlSession | 处理单个客户端 WebSocket 连接                   |
| ServerSession  | 处理单个 Relay WebSocket 连接                   |
| AuthService    | 认证、JWT 签发与验证                            |
| ConfigService  | 配置生成与分发                                  |
| NodeService    | 节点生命周期管理                                |
| RouteService   | 路由管理与计算                                  |
| PathService    | 路径计算与延迟优化                              |
| Database       | SQLite 持久化                                   |
| BuiltinRelay   | 可选的内置 Relay 功能                           |
| BuiltinSTUN    | 可选的内置 STUN 功能                            |

#### 数据表

| 表名            | 用途               |
| --------------- | ------------------ |
| users           | 用户账号           |
| networks        | 网络定义           |
| nodes           | 节点信息           |
| servers         | Relay/STUN 服务器  |
| routes          | 子网路由           |
| auth_keys       | AuthKey 认证密钥   |
| latency_reports | 延迟数据           |
| p2p_connections | P2P 连接状态       |
| endpoints       | 节点端点           |
| user_nodes      | 用户与节点绑定关系 |

#### 节点表 (nodes) 字段

| 字段         | 类型      | 说明                 |
| ------------ | --------- | -------------------- |
| id           | uint32    | 节点 ID              |
| network_id   | uint32    | 所属网络             |
| machine_key  | blob(32)  | Ed25519 公钥         |
| node_key     | blob(32)  | X25519 公钥          |
| virtual_ip   | uint32    | 虚拟 IP (网络字节序) |
| hostname     | string    | 主机名               |
| os           | string    | 操作系统             |
| is_exit_node | bool      | 是否为 Exit Node     |
| is_gateway   | bool      | 是否为子网网关       |
| last_seen    | timestamp | 最后在线时间         |
| created_at   | timestamp | 创建时间             |

#### 用户表 (users) 字段

| 字段          | 类型      | 说明                |
| ------------- | --------- | ------------------- |
| id            | uint32    | 用户 ID             |
| username      | string    | 用户名 (唯一)       |
| password_hash | string    | 密码哈希 (Argon2id) |
| email         | string    | 邮箱                |
| role          | string    | 角色: admin/user    |
| enabled       | bool      | 是否启用            |
| created_at    | timestamp | 创建时间            |
| last_login    | timestamp | 最后登录时间        |

#### AuthKey 表 (auth_keys) 字段

| 字段        | 类型      | 说明                            |
| ----------- | --------- | ------------------------------- |
| id          | uint32    | 密钥 ID                         |
| key         | string    | 密钥值 (格式: tskey-xxxx-xxxxx) |
| network_id  | uint32    | 所属网络                        |
| user_id     | uint32    | 创建者用户 ID                   |
| description | string    | 描述                            |
| ephemeral   | bool      | 临时节点 (断开后删除)           |
| reusable    | bool      | 可重复使用                      |
| max_uses    | uint32    | 最大使用次数 (0=无限)           |
| use_count   | uint32    | 已使用次数                      |
| expires_at  | timestamp | 过期时间                        |
| created_at  | timestamp | 创建时间                        |

### 7.2 Relay Server

#### 功能模块

| 模块                | 职责                     |
| ------------------- | ------------------------ |
| WsRelayServer       | WebSocket 服务器         |
| RelaySessionManager | 管理客户端和 Mesh 会话   |
| RelaySession        | 处理单个客户端数据连接   |
| MeshSession         | 处理 Relay 间 Mesh 连接  |
| ControllerClient    | 连接到 Controller        |
| STUNServer          | UDP STUN 服务 (RFC 5389) |
| NodeLocationCache   | 节点位置缓存             |

#### 路由决策

```
收到 DATA 包 (dst_node_id):
    1. 检查目标节点是否本地连接
       if local_sessions.contains(dst_node_id):
           → 直接转发给该 Session

    2. 查询节点位置缓存
       relay_id = node_location_cache.get(dst_node_id)
       if relay_id != 0:
           → 通过 Mesh 转发到 relay_id

    3. 节点位置未知
       → 暂存包，向 Controller 查询
       → 或直接丢弃并返回错误
```

### 7.3 Client

#### 功能模块

| 模块            | 职责                                 |
| --------------- | ------------------------------------ |
| Client          | 主协调器，整合所有子模块，管理状态机 |
| ControlChannel  | 到 Controller 的 WebSocket 连接      |
| RelayManager    | 多 Relay 连接管理，路径选择          |
| P2PManager      | UDP P2P 直连，NAT 穿透，状态机管理   |
| CryptoEngine    | 密钥管理，Session Key 派生，加密解密 |
| TunDevice       | 虚拟网卡 (平台相关)                  |
| RouteManager    | 路由表管理，子网路由                 |
| EndpointManager | 端点发现，STUN 查询                  |
| IPCServer       | 本地 CLI 控制接口                    |

#### TUN 平台实现

| 平台    | 实现         |
| ------- | ------------ |
| Linux   | /dev/net/tun |
| Windows | Wintun       |
| macOS   | utun         |

---

## 8. 高并发设计要求

### 8.1 并发模型

- 使用 Boost.Asio + Boost.Coroutine (awaitable)
- 每个线程独立 io_context (thread-per-core 模型)
- 连接通过 round-robin 分配到各线程
- 每个 WebSocket 连接对应一个协程
- 连接生命周期内所有操作在同一线程完成

### 8.2 线程亲和性设计

| 原则       | 说明                                     |
| ---------- | ---------------------------------------- |
| 连接绑定   | 每个连接固定在一个线程，不迁移           |
| 数据本地化 | 会话状态、缓冲区等数据存储在连接所属线程 |
| 避免跨线程 | 同线程内的连接间通信直接调用，无需加锁   |
| 必要跨线程 | 仅在跨线程转发数据时使用无锁队列         |

### 8.3 跨线程通信场景

| 场景              | 方案                                  |
| ----------------- | ------------------------------------- |
| 数据转发 (同线程) | 直接调用目标 Session 的发送方法       |
| 数据转发 (跨线程) | 通过 MPSC 无锁队列投递到目标线程      |
| 广播消息          | 每个线程维护本地会话列表，各自广播    |
| 全局统计          | 各线程本地统计，定期汇总或使用 atomic |

### 8.4 无锁设计要求

| 数据结构       | 无锁方案                           |
| -------------- | ---------------------------------- |
| 跨线程消息队列 | MPSC 无锁队列 (每线程一个入口队列) |
| 线程本地会话表 | 无需加锁 (单线程访问)              |
| 全局统计计数   | std::atomic                        |
| 节点位置缓存   | 每线程本地副本 + 定期同步          |

### 8.5 协程使用规范

- 所有 IO 操作必须使用 co_await
- 禁止在协程中进行阻塞调用
- 使用 use_awaitable 作为 completion token
- 使用 co_spawn 启动协程

### 8.6 内存管理

- Session 使用 shared_ptr 管理
- SessionManager 持有 weak_ptr 避免循环引用
- 大缓冲区使用对象池复用

---

## 9. 开发约束

### 9.1 编码规范

| 项目     | 约束                         |
| -------- | ---------------------------- |
| 语言标准 | C++23                        |
| 禁止使用 | lambda 表达式                |
| 异步模型 | Boost.Asio + Boost.Coroutine |
| 错误处理 | std::expected                |
| 日志     | spdlog                       |

### 9.2 命名规范

| 类型     | 规范                     | 示例                   |
| -------- | ------------------------ | ---------------------- |
| 命名空间 | 小写加下划线             | edgelink::controller   |
| 类名     | 大驼峰                   | WsServer, RelaySession |
| 函数名   | 小写加下划线             | do_read, handle_auth   |
| 成员变量 | 小写加下划线，尾随下划线 | node*id*, sessions\_   |
| 常量     | 全大写加下划线           | MAX_FRAME_SIZE         |

### 9.3 文件组织

| 目录            | 内容                            |
| --------------- | ------------------------------- |
| src/common/     | 共享代码 (协议、帧、加密、配置) |
| src/controller/ | Controller 代码                 |
| src/server/     | Relay Server 代码               |
| src/client/     | Client 代码                     |
| docs/           | 文档                            |
| config/         | 配置文件示例                    |

### 9.4 依赖库

| 库        | 版本要求 | 用途                           |
| --------- | -------- | ------------------------------ |
| Boost     | >= 1.82  | Asio, Beast, JSON, Coroutine   |
| BoringSSL | -        | TLS (Google's fork of OpenSSL) |
| libsodium | -        | 加密                           |
| spdlog    | -        | 日志                           |
| jwt-cpp   | -        | JWT                            |
| SQLite3   | -        | 数据库                         |
| LZ4       | -        | 压缩 (可选)                    |

---

## 10. 错误码定义

### 10.1 错误码范围

| 范围      | 类别       |
| --------- | ---------- |
| 0-99      | 通用错误   |
| 1000-1999 | 认证错误   |
| 2000-2999 | 协议错误   |
| 3000-3999 | 路由错误   |
| 4000-4999 | 服务器错误 |
| 5000-5999 | 加密错误   |

### 10.2 主要错误码

| 码值 | 名称                | 说明                     |
| ---- | ------------------- | ------------------------ |
| 0    | SUCCESS             | 成功                     |
| 1    | UNKNOWN             | 未知错误                 |
| 2    | INVALID_ARGUMENT    | 无效参数                 |
| 3    | NOT_CONNECTED       | 未连接                   |
| 4    | ALREADY_EXISTS      | 已存在                   |
| 5    | TIMEOUT             | 超时                     |
| 6    | CANCELLED           | 已取消                   |
| 1001 | INVALID_TOKEN       | 无效 Token               |
| 1002 | TOKEN_EXPIRED       | Token 过期               |
| 1003 | TOKEN_BLACKLISTED   | Token 已列入黑名单       |
| 1004 | INVALID_SIGNATURE   | 无效签名                 |
| 1005 | INVALID_CREDENTIALS | 无效凭据                 |
| 1006 | NODE_NOT_AUTHORIZED | 节点未授权               |
| 1007 | AUTH_FAILED         | 认证失败                 |
| 1008 | AUTHKEY_EXPIRED     | AuthKey 已过期           |
| 1009 | AUTHKEY_LIMIT       | AuthKey 使用次数已达上限 |
| 2001 | INVALID_FRAME       | 无效帧格式               |
| 2002 | INVALID_MESSAGE     | 无效消息                 |
| 2003 | UNSUPPORTED_VERSION | 不支持的协议版本         |
| 2004 | MESSAGE_TOO_LARGE   | 消息过大                 |
| 3001 | NODE_NOT_FOUND      | 节点未找到               |
| 3002 | NODE_OFFLINE        | 节点离线                 |
| 3003 | ROUTE_NOT_FOUND     | 路由未找到               |
| 3004 | ROUTE_CONFLICT      | 路由冲突                 |
| 3005 | NO_RELAY_AVAILABLE  | 无可用 Relay             |
| 3006 | PATH_NOT_FOUND      | 路径未找到               |
| 4001 | INTERNAL_ERROR      | 内部错误                 |
| 4002 | SERVICE_UNAVAILABLE | 服务不可用               |
| 4003 | RATE_LIMITED        | 请求频率超限             |
| 5001 | DECRYPTION_FAILED   | 解密失败                 |
| 5002 | REPLAY_DETECTED     | 检测到重放攻击           |
| 5003 | KEY_NOT_FOUND       | 密钥未找到               |

---

## 11. 配置项定义

### 11.1 Controller 配置

| 配置项                | 类型   | 默认值    | 说明                     |
| --------------------- | ------ | --------- | ------------------------ |
| http.listen_address   | string | "0.0.0.0" | 监听地址                 |
| http.listen_port      | uint16 | 8080      | 监听端口                 |
| http.enable_tls       | bool   | false     | 启用 TLS                 |
| tls.cert_path         | string | -         | 证书路径                 |
| tls.key_path          | string | -         | 私钥路径                 |
| jwt.secret            | string | -         | JWT 密钥                 |
| jwt.auth_token_ttl    | uint32 | 1440      | Auth Token 有效期(分钟)  |
| jwt.relay_token_ttl   | uint32 | 90        | Relay Token 有效期(分钟) |
| database.path         | string | -         | 数据库路径               |
| builtin_relay.enabled | bool   | false     | 启用内置 Relay           |
| builtin_stun.enabled  | bool   | false     | 启用内置 STUN            |
| builtin_stun.ip       | string | ""        | 公网 IP (NAT 检测)       |

### 11.2 Relay 配置

| 配置项               | 类型   | 默认值    | 说明               |
| -------------------- | ------ | --------- | ------------------ |
| relay.listen_address | string | "0.0.0.0" | 监听地址           |
| relay.listen_port    | uint16 | 8081      | 监听端口           |
| relay.tls.enabled    | bool   | false     | 启用 TLS           |
| relay.tls.cert_file  | string | -         | 证书路径           |
| relay.tls.key_file   | string | -         | 私钥路径           |
| stun.enabled         | bool   | true      | 启用 STUN          |
| stun.listen_port     | uint16 | 3478      | STUN 端口          |
| stun.ip              | string | ""        | 公网 IP (NAT 检测) |
| controller.url       | string | -         | Controller WSS URL |
| controller.token     | string | -         | 服务器 Token       |

### 11.3 Client 配置

| 配置项            | 类型     | 默认值 | 说明                |
| ----------------- | -------- | ------ | ------------------- |
| controller_url    | string   | -      | Controller WSS URL  |
| auth_key          | string   | ""     | 认证密钥 (首次注册) |
| data_dir          | string   | -      | 数据目录            |
| log_level         | string   | "info" | 日志级别            |
| routes.advertise  | []string | []     | 通告的子网路由      |
| routes.accept     | []string | ["*"]  | 接受的子网路由      |
| exit_node.enabled | bool     | false  | 启用 Exit Node      |
| exit_node.use     | string   | ""     | 使用指定 Exit Node  |

---

## 12. 性能指标要求

| 指标              | 要求                   |
| ----------------- | ---------------------- |
| 单 Relay 并发连接 | >= 10,000              |
| 单连接吞吐量      | >= 100 Mbps            |
| 控制消息延迟      | < 100 ms (P99)         |
| 数据转发延迟      | < 10 ms (本地 Relay)   |
| 内存占用          | < 100 MB (10K 连接)    |
| CPU 占用          | < 50% (10K 连接, 4 核) |
| 加密吞吐量        | >= 500 Mbps (单核)     |
| P2P 打洞成功率    | >= 80% (非对称 NAT)    |

---

## 附录

### 附录 A: NAT 类型定义

| 类型            | 值  | P2P 难度 | 说明               |
| --------------- | --- | -------- | ------------------ |
| UNKNOWN         | 0   | -        | 未检测             |
| OPEN            | 1   | 无 NAT   | 公网 IP            |
| FULL_CONE       | 2   | 简单     | 任意外部主机可访问 |
| RESTRICTED_CONE | 3   | 中等     | 需先发包           |
| PORT_RESTRICTED | 4   | 困难     | 需先发包到同端口   |
| SYMMETRIC       | 5   | 非常困难 | 每个目标不同映射   |

### 附录 B: 服务器能力标志

| 标志位 | 值   | 说明           |
| ------ | ---- | -------------- |
| RELAY  | 0x01 | 支持数据中继   |
| STUN   | 0x02 | 支持 STUN 服务 |

### 附录 C: 端点类型优先级

| 类型  | 值   | 优先级 | 说明                      |
| ----- | ---- | ------ | ------------------------- |
| LAN   | 0x01 | 1      | 本地网络地址 (最优先)     |
| STUN  | 0x02 | 2      | STUN 检测地址             |
| UPNP  | 0x03 | 2      | UPnP 映射地址             |
| RELAY | 0x04 | 3      | Relay 观测地址 (最低优先) |

### 附录 D: 客户端认证类型

| 类型    | 值   | 说明           |
| ------- | ---- | -------------- |
| user    | 0x01 | 用户名密码登录 |
| authkey | 0x02 | AuthKey 认证   |
| machine | 0x03 | 已注册节点重连 |

### 附录 E: AuthKey 格式

格式: `tskey-<type>-<random>`

| 部分   | 说明                                                   |
| ------ | ------------------------------------------------------ |
| tskey  | 固定前缀                                               |
| type   | 类型: auth (普通), reusable (可重用), ephemeral (临时) |
| random | 24 字符随机字符串 (Base62)                             |

示例:

- `tskey-auth-k3vM8Qp2xNwL9rJhYbTc5G`
- `tskey-reusable-a7Bn4Kp9zQwX2mLj8RvC6`
- `tskey-ephemeral-f2Hs5Np8yTwK3xLm9QvB7`

### 附录 F: 用户角色权限

| 角色  | 权限                                       |
| ----- | ------------------------------------------ |
| admin | 管理用户、网络、节点、AuthKey、Relay、路由 |
| user  | 管理自己的节点、创建 AuthKey、通告子网路由 |

### 附录 G: 协议版本历史

| 版本 | 日期    | 变更                                           |
| ---- | ------- | ---------------------------------------------- |
| 0x01 | 2024-01 | 初始版本，JSON Payload                         |
| 0x02 | 2026-01 | 二进制 Payload，消息类型重新编号，增加路由消息 |

### 附录 H: 二进制编码示例

#### AUTH_REQUEST 编码示例

```
输入:
  auth_type = 0x01 (user)
  machine_key = [32 bytes]
  node_key = [32 bytes]
  hostname = "my-laptop"
  os = "linux"
  arch = "amd64"
  version = "1.0.0"
  timestamp = 1704787200000 (ms)
  signature = [64 bytes]
  username = "admin"
  password_hash = [32 bytes]

编码:
  01                          # auth_type
  [32 bytes machine_key]      # machine_key
  [32 bytes node_key]         # node_key
  00 09 6D 79 2D 6C 61 70 74 6F 70  # hostname (len=9 + "my-laptop")
  00 05 6C 69 6E 75 78        # os (len=5 + "linux")
  00 05 61 6D 64 36 34        # arch (len=5 + "amd64")
  00 05 31 2E 30 2E 30        # version (len=5 + "1.0.0")
  00 00 01 8D 5B 1B A8 00     # timestamp (8 bytes BE)
  [64 bytes signature]        # signature
  00 05 61 64 6D 69 6E        # username (len=5 + "admin")
  [32 bytes password_hash]    # password_hash

总大小: 1 + 32 + 32 + 11 + 7 + 7 + 7 + 8 + 64 + 7 + 32 = 208 bytes
```

# EdgeLink 架构设计文档

> **版本**: 2.5
> **更新日期**: 2026-01-10
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
- [9. 日志系统设计](#9-日志系统设计)
- [10. 开发约束](#10-开发约束)
- [11. 错误码定义](#11-错误码定义)
- [12. 配置项定义](#12-配置项定义)
- [13. 性能指标要求](#13-性能指标要求)
- [14. CLI 命令参考](#14-cli-命令参考)
- [15. 构建系统](#15-构建系统)
- [附录](#附录)

---

## 1. 系统概述

EdgeLink 是一个**数据面去中心化、控制面中心化**的 Mesh VPN 系统，支持节点间 P2P 直连和中继转发。

### 1.1 系统架构图

```
                           ┌─────────────────┐
                           │   Controller    │
                           │  (控制面中心)    │
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
         └─── P2P ───┘  (直连优先，数据面去中心化)
```

### 1.2 组件职责

| 组件           | 可执行文件           | 职责                                                     |
| -------------- | -------------------- | -------------------------------------------------------- |
| **Controller** | `edgelink-controller`| 网络拓扑管理、节点认证授权、配置分发、路径计算、JWT 签发（控制面中心，可做 HA） |
| **Relay**      | `edgelink-relay`     | 数据中继、STUN 服务、Relay Mesh 网络、延迟上报（数据面组件） |
| **Client**     | `edgelink-client`    | TUN 虚拟网卡、P2P 直连、加密通信、路由管理、端点发现（数据面去中心化） |

### 1.3 设计原则

| 原则           | 说明                                                       |
| -------------- | ---------------------------------------------------------- |
| **端到端加密** | 数据在源节点加密，仅目标节点可解密，中继服务器无法读取明文 |
| **二进制协议** | 所有 WSS 消息采用紧凑二进制格式，减少传输体积              |
| **状态机驱动** | 各组件使用明确的 FSM 管理连接和会话生命周期                |
| **零信任中继** | Relay 仅转发密文，不参与密钥交换                           |
| **控制面中心化** | Controller 作为控制中心管理认证与配置，支持高可用部署    |
| **数据面去中心化** | 节点间优先 P2P 直连，Relay 仅作为回退路径              |

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

| 字段    | 大小   | 说明                                     |
| ------- | ------ | ---------------------------------------- |
| Version | 1 字节 | 协议版本，当前 `0x02`                    |
| Type    | 1 字节 | **消息类型** (Frame Type)，见 2.3 节     |
| Flags   | 1 字节 | 标志位                                   |
| Length  | 2 字节 | Payload 长度 (大端序)，最大 **65530**    |

> **Length 上限说明**：虽然 2 字节大端序理论最大值为 65535，但协议限制为 **65530** 字节，预留 5 字节用于未来帧头扩展。实现时若 Length > 65530 应视为协议错误。

> **术语约定**：
> - **Frame Type (消息类型)**：帧头中的 Type 字段，标识消息种类（如 AUTH_REQUEST=0x01）
> - **auth_type (认证方式)**：AUTH_REQUEST Payload 中的字段，标识认证方式（如 authkey=0x02）
> - 两者不可混用

#### 2.2.2 Flags 标志位

| 位   | 名称       | 说明                                |
| ---- | ---------- | ----------------------------------- |
| 0x01 | NEED_ACK   | 需要确认，见 2.5.2 节               |
| 0x02 | COMPRESSED | Payload 已压缩 (LZ4)，见 2.5.3 节   |
| 0x04 | ENCRYPTED  | Payload 帧级加密（保留位，见下文）  |
| 0x08 | FRAGMENTED | 分片消息，见 2.5.1 节               |

**ENCRYPTED 标志位说明**：

此标志位当前**保留未使用**。协议中的加密分层如下：

| 层级         | 加密方式                         | 说明                              |
| ------------ | -------------------------------- | --------------------------------- |
| 传输层       | TLS (WSS)                        | 所有 WebSocket 通道均强制使用 TLS |
| 应用层 DATA  | ChaCha20-Poly1305 端到端加密     | DATA (0x20) 类型消息，见 5.3 节   |
| 帧级 Payload | 保留 (ENCRYPTED flag)            | 用于未来控制面消息加密扩展        |

当前控制面消息 (AUTH/CONFIG/P2P 等) 依赖 TLS 传输层加密保护，DATA 消息使用端到端 AEAD 加密（与 ENCRYPTED flag 无关）。

若未来启用 ENCRYPTED flag，将在协议扩展中定义：
- 适用的消息类型范围
- 密钥协商与派生方式
- 与 COMPRESSED flag 的处理顺序

#### 2.2.3 完整帧结构

```
┌─────────────────────────────────────────────────────┐
│                    Frame Header (5B)                │
├─────────────────────────────────────────────────────┤
│          [Fragment Header (9B)] (仅分片时)          │
├─────────────────────────────────────────────────────┤
│                    Payload (变长)                   │
│              (二进制结构化数据)                      │
└─────────────────────────────────────────────────────┘
```

### 2.3 消息类型定义 (Frame Type)

> **重要**：以下 Type 值是 Frame Header 中的消息类型，与 Payload 内部字段（如 auth_type）无关。

#### 认证类 (0x01-0x0F)

| Type  | 名称           | 方向                | Payload 格式      |
| ----- | -------------- | ------------------- | ----------------- |
| 0x01  | AUTH_REQUEST   | Client → Controller | AuthRequest       |
| 0x02  | AUTH_RESPONSE  | Controller → Client | AuthResponse      |
| 0x03  | AUTH_CHALLENGE | Controller → Client | Challenge         |
| 0x04  | AUTH_VERIFY    | Client → Controller | ChallengeResponse |

#### 配置类 (0x10-0x1F)

| Type  | 名称          | 方向                | Payload 格式 |
| ----- | ------------- | ------------------- | ------------ |
| 0x10  | CONFIG        | Controller → Client | Config       |
| 0x11  | CONFIG_UPDATE | Controller → Client | ConfigUpdate |
| 0x12  | CONFIG_ACK    | Client → Controller | ConfigAck    |

#### 数据类 (0x20-0x2F)

| Type  | 名称     | 方向 | Payload 格式  |
| ----- | -------- | ---- | ------------- |
| 0x20  | DATA     | 双向 | EncryptedData |
| 0x21  | DATA_ACK | 双向 | DataAck       |

#### 心跳类 (0x30-0x3F)

| Type  | 名称           | 方向                | Payload 格式  |
| ----- | -------------- | ------------------- | ------------- |
| 0x30  | PING           | 双向                | Ping          |
| 0x31  | PONG           | 双向                | Pong          |
| 0x32  | LATENCY_REPORT | Client → Controller | LatencyReport |

#### P2P 类 (0x40-0x4F)

| Type  | 名称          | 方向                  | Payload 格式 |
| ----- | ------------- | --------------------- | ------------ |
| 0x40  | P2P_INIT      | Client → Controller   | P2PInit      |
| 0x41  | P2P_ENDPOINT  | Controller → Client   | P2PEndpoint  |
| 0x42  | P2P_PING      | Client ↔ Client (UDP) | P2PPing      |
| 0x43  | P2P_PONG      | Client ↔ Client (UDP) | P2PPong      |
| 0x44  | P2P_KEEPALIVE | Client ↔ Client (UDP) | P2PKeepalive |
| 0x45  | P2P_STATUS    | Client → Controller   | P2PStatus    |

#### 服务器类 (0x50-0x5F)

| Type  | 名称                  | 方向               | Payload 格式        |
| ----- | --------------------- | ------------------ | ------------------- |
| 0x50  | SERVER_REGISTER       | Relay → Controller | ServerRegister      |
| 0x51  | SERVER_REGISTER_RESP  | Controller → Relay | ServerRegisterResp  |
| 0x52  | SERVER_NODE_LOC       | Controller → Relay | ServerNodeLoc       |
| 0x53  | SERVER_BLACKLIST      | Controller → Relay | ServerBlacklist     |
| 0x54  | SERVER_HEARTBEAT      | Relay → Controller | ServerHeartbeat     |
| 0x55  | SERVER_RELAY_LIST     | Controller → Relay | ServerRelayList     |
| 0x56  | SERVER_LATENCY_REPORT | Relay → Controller | ServerLatencyReport |

#### 中继认证类 (0x60-0x6F)

| Type  | 名称            | 方向           | Payload 格式  |
| ----- | --------------- | -------------- | ------------- |
| 0x60  | RELAY_AUTH      | Client → Relay | RelayAuth     |
| 0x61  | RELAY_AUTH_RESP | Relay → Client | RelayAuthResp |

#### Mesh 类 (0x70-0x7F)

| Type  | 名称           | 方向          | Payload 格式 |
| ----- | -------------- | ------------- | ------------ |
| 0x70  | MESH_HELLO     | Relay → Relay | MeshHello    |
| 0x71  | MESH_HELLO_ACK | Relay → Relay | MeshHelloAck |
| 0x72  | MESH_FORWARD   | Relay → Relay | MeshForward  |
| 0x73  | MESH_PING      | Relay → Relay | MeshPing     |
| 0x74  | MESH_PONG      | Relay → Relay | MeshPong     |

#### 路由类 (0x80-0x8F)

| Type  | 名称           | 方向                | Payload 格式  |
| ----- | -------------- | ------------------- | ------------- |
| 0x80  | ROUTE_ANNOUNCE | Client → Controller | RouteAnnounce |
| 0x81  | ROUTE_UPDATE   | Controller → Client | RouteUpdate   |
| 0x82  | ROUTE_WITHDRAW | Client → Controller | RouteWithdraw |
| 0x83  | ROUTE_ACK      | 双向                | RouteAck      |

#### 通用类 (0xF0-0xFF)

| Type  | 名称      | 方向 | Payload 格式 |
| ----- | --------- | ---- | ------------ |
| 0xFE  | GENERIC_ACK | 双向 | GenericAck |
| 0xFF  | ERROR     | 双向 | Error        |

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
| IPv4           | 4 字节，网络字节序             |
| IPv6           | 16 字节，网络字节序            |

**字节对齐规则**：所有字段紧密排列，无填充字节。

#### 2.4.1.1 协议通用常量定义

以下常量在整个协议中统一使用：

**ip_type 取值**：

| 值   | 名称 | 说明                |
| ---- | ---- | ------------------- |
| 0x04 | IPv4 | IPv4 地址 (4 字节)  |
| 0x06 | IPv6 | IPv6 地址 (16 字节) |

**endpoint_type 取值**：

| 值   | 名称  | 说明                        |
| ---- | ----- | --------------------------- |
| 0x01 | LAN   | 本地网络发现的端点          |
| 0x02 | STUN  | STUN 探测发现的公网端点     |
| 0x03 | UPNP  | UPnP 映射的端点             |
| 0x04 | RELAY | Relay 服务器端点            |

**path_type 取值**：

| 值   | 名称  | 说明              |
| ---- | ----- | ----------------- |
| 0x01 | LAN   | 局域网直连        |
| 0x02 | STUN  | STUN 穿透直连     |
| 0x03 | RELAY | 通过 Relay 中继   |

**p2p_status 取值**：

| 值   | 名称       | 说明              |
| ---- | ---------- | ----------------- |
| 0x00 | DISCONNECTED | 未连接          |
| 0x01 | P2P        | P2P 直连          |
| 0x02 | RELAY_ONLY | 仅 Relay 通信     |

#### 2.4.2 AUTH_REQUEST Payload (Type=0x01)

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

| 字段        | 偏移  | 大小 | 说明                                                      |
| ----------- | ----- | ---- | --------------------------------------------------------- |
| auth_type   | 0     | 1 B  | **认证方式**: 0x01=user, 0x02=authkey, 0x03=machine       |
| machine_key | 1     | 32 B | Ed25519 公钥                                              |
| node_key    | 33    | 32 B | X25519 公钥                                               |
| hostname    | 65    | 变长 | 主机名 (2B 长度 + UTF-8)                                  |
| os          | 变长  | 变长 | 操作系统                                                  |
| arch        | 变长  | 变长 | CPU 架构                                                  |
| version     | 变长  | 变长 | 客户端版本                                                |
| timestamp   | 变长  | 8 B  | Unix 时间戳 (毫秒)                                        |
| signature   | 变长  | 64 B | Ed25519 签名                                              |
| auth_data   | 变长  | 变长 | user: username+password_hash, authkey: key, machine: 空   |

**签名覆盖范围**：signature 字段对除 signature 本身外的所有字段进行签名，即从 auth_type 到 auth_data（含）的所有字节。

**签名数据序列化顺序**：
```
signed_data = auth_type (1B)
            || machine_key (32B)
            || node_key (32B)
            || hostname (2B len + UTF-8)
            || os (2B len + UTF-8)
            || arch (2B len + UTF-8)
            || version (2B len + UTF-8)
            || timestamp (8B)
            || auth_data (变长，格式取决于 auth_type)
```

签名时将上述字段按顺序拼接为连续字节流，然后使用 machine_key 对应的私钥进行 Ed25519 签名。

> **安全说明**：auth_data 必须纳入签名范围，防止中间人在不破坏签名的情况下篡改认证材料。

**auth_type 值定义**：

| auth_type 值 | 名称    | auth_data 内容                          |
| ------------ | ------- | --------------------------------------- |
| 0x01         | user    | username (len+str) + password_hash (32B)|
| 0x02         | authkey | key (len+str)                           |
| 0x03         | machine | 空 (已注册节点重连)                     |

#### 2.4.3 AUTH_RESPONSE Payload (Type=0x02)

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

| 字段        | 大小 | 说明                           |
| ----------- | ---- | ------------------------------ |
| success     | 1 B  | 0x00=失败, 0x01=成功           |
| node_id     | 4 B  | 分配的节点 ID (成功时有效)     |
| virtual_ip  | 4 B  | 分配的虚拟 IP (成功时有效)     |
| network_id  | 4 B  | 网络 ID                        |
| auth_token  | 变长 | JWT Auth Token (成功时有效)    |
| relay_token | 变长 | JWT Relay Token (成功时有效)   |
| error_code  | 2 B  | 错误码 (失败时有效)            |
| error_msg   | 变长 | 错误消息 (失败时有效)          |

#### 2.4.4 CONFIG Payload (Type=0x10)

```
┌────────────┬────────────┬────────────┬────────────┐
│  version   │ network_id │   subnet   │subnet_mask │
│   (8 B)    │   (4 B)    │   (4 B)    │   (1 B)    │
├────────────┼────────────┬────────────┼────────────┤
│network_name│relay_count │ stun_count │ peer_count │
│ (len+str)  │   (2 B)    │   (2 B)    │   (2 B)    │
├────────────┼────────────┼────────────┼────────────┤
│route_count │  relays[]  │  stuns[]   │  peers[]   │
│   (2 B)    │  (数组)    │  (数组)    │  (数组)    │
├────────────┼────────────┼────────────┴────────────┤
│  routes[]  │relay_token │   expires               │
│  (数组)    │(len+bytes) │    (8 B)                │
└────────────┴────────────┴─────────────────────────┘
```

#### 2.4.4.1 CONFIG_UPDATE Payload (Type=0x11)

增量配置更新消息，用于推送配置变更而无需重传完整配置。

```
┌────────────┬────────────┬────────────┬────────────┐
│  version   │update_flags│ relay_count│ peer_count │
│   (8 B)    │   (2 B)    │   (2 B)    │   (2 B)    │
├────────────┼────────────┼────────────┼────────────┤
│route_count │add_relays[]│del_relay_ids│add_peers[] │
│   (2 B)    │  (数组)    │  (数组)    │  (数组)    │
├────────────┼────────────┼────────────┴────────────┤
│del_peer_ids│add_routes[]│del_routes[]             │
│  (数组)    │ (RouteInfo)│(RouteIdentifier)        │
└────────────┴────────────┴─────────────────────────┘
```

| 字段           | 大小 | 说明                                      |
| -------------- | ---- | ----------------------------------------- |
| version        | 8 B  | 配置版本号，必须大于当前版本              |
| update_flags   | 2 B  | 更新标志位 (见下表)                       |
| relay_count    | 2 B  | 新增 Relay 数量                           |
| peer_count     | 2 B  | 新增 Peer 数量                            |
| route_count    | 2 B  | 新增 Route 数量                           |
| add_relays[]   | 变长 | 新增的 RelayInfo 数组                     |
| del_relay_ids[]| 变长 | 删除的 Relay ID 数组 (2B count + 4B IDs)  |
| add_peers[]    | 变长 | 新增的 PeerInfo 数组                      |
| del_peer_ids[] | 变长 | 删除的 Peer ID 数组 (2B count + 4B IDs)   |
| add_routes[]   | 变长 | 新增的 RouteInfo 数组                     |
| del_routes[]   | 变长 | 删除的 RouteIdentifier 数组               |

**update_flags 标志位**：

| 位     | 名称            | 说明                    |
| ------ | --------------- | ----------------------- |
| 0x0001 | RELAY_CHANGED   | Relay 列表有变更        |
| 0x0002 | PEER_CHANGED    | Peer 列表有变更         |
| 0x0004 | ROUTE_CHANGED   | Route 列表有变更        |
| 0x0008 | TOKEN_REFRESH   | 包含新的 relay_token    |
| 0x0010 | FULL_SYNC       | 需要全量同步 (忽略增量) |

#### 2.4.5 DATA Payload (Type=0x20，端到端加密)

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
| nonce             | 12 B | 见 5.3.2 节 Nonce 构造规范      |
| encrypted_payload | 变长 | ChaCha20-Poly1305 加密的 IP 包  |
| auth_tag          | 16 B | AEAD 认证标签                   |

**最大加密载荷**：65530 (Frame.Length 上限) - 4 - 4 - 12 - 16 = **65494 字节**

#### 2.4.6 DATA_ACK Payload (Type=0x21)

```
┌────────────┬────────────┬────────────┬────────────┐
│  src_node  │  dst_node  │ ack_nonce  │  ack_flags │
│   (4 B)    │   (4 B)    │  (12 B)    │   (1 B)    │
└────────────┴────────────┴────────────┴────────────┘
```

| 字段      | 大小 | 说明                                    |
| --------- | ---- | --------------------------------------- |
| src_node  | 4 B  | 确认方节点 ID                           |
| dst_node  | 4 B  | 被确认方节点 ID                         |
| ack_nonce | 12 B | 被确认的 DATA 包的 nonce                |
| ack_flags | 1 B  | 0x01=成功接收, 0x02=解密失败, 0x04=重复 |

#### 2.4.7 ERROR Payload (Type=0xFF)

```
┌────────────┬────────────┬────────────┬────────────┐
│ error_code │ request_type│ request_id │ error_msg  │
│   (2 B)    │   (1 B)    │   (4 B)    │ (len+str)  │
└────────────┴────────────┴────────────┴────────────┘
```

| 字段         | 大小 | 说明                           |
| ------------ | ---- | ------------------------------ |
| error_code   | 2 B  | 错误码，见第 11 章             |
| request_type | 1 B  | 导致错误的请求消息类型         |
| request_id   | 4 B  | 请求标识符 (如有)，用于关联    |
| error_msg    | 变长 | 人类可读的错误消息             |

#### 2.4.8 GENERIC_ACK Payload (Type=0xFE)

```
┌────────────┬────────────┬────────────┐
│ request_type│ request_id │   status   │
│   (1 B)    │   (4 B)    │   (1 B)    │
└────────────┴────────────┴────────────┘
```

| 字段         | 大小 | 说明                           |
| ------------ | ---- | ------------------------------ |
| request_type | 1 B  | 被确认的请求消息类型           |
| request_id   | 4 B  | 请求标识符                     |
| status       | 1 B  | 0x00=成功, 其他=错误码低 8 位  |

#### 2.4.9 PING/PONG Payload (Type=0x30/0x31)

```
┌────────────┬────────────┐
│ timestamp  │  seq_num   │
│   (8 B)    │   (4 B)    │
└────────────┴────────────┘
```

| 字段      | 大小 | 说明                     |
| --------- | ---- | ------------------------ |
| timestamp | 8 B  | 发送时间戳 (毫秒)        |
| seq_num   | 4 B  | 序列号，PONG 原样返回    |

> **时间戳单位约定**：本协议中所有 timestamp 字段统一使用**毫秒**为单位 (Unix epoch 毫秒)，包括但不限于 AUTH_REQUEST、PING/PONG、P2P_PING/PONG 等消息。

#### 2.4.10 P2P_INIT Payload (Type=0x40)

```
┌────────────┬────────────┐
│ target_node│  init_seq  │
│   (4 B)    │   (4 B)    │
└────────────┴────────────┘
```

| 字段        | 大小 | 说明                |
| ----------- | ---- | ------------------- |
| target_node | 4 B  | 目标节点 ID         |
| init_seq    | 4 B  | 初始化序列号        |

#### 2.4.11 P2P_ENDPOINT Payload (Type=0x41)

```
┌────────────┬────────────┬────────────┬────────────┐
│ init_seq   │ peer_node  │ peer_key   │endpoint_cnt│
│   (4 B)    │   (4 B)    │  (32 B)    │   (2 B)    │
├────────────┴────────────┴────────────┴────────────┤
│                    endpoints[]                    │
│                  (EndpointInfo 数组)              │
└───────────────────────────────────────────────────┘
```

#### 2.4.12 P2P_PING/PONG Payload (Type=0x42/0x43，UDP)

```
┌────────────┬────────────┬────────────┬────────────┐
│   magic    │ src_node   │ dst_node   │   nonce    │
│   (4 B)    │   (4 B)    │   (4 B)    │  (12 B)    │
├────────────┼────────────┼────────────┼────────────┤
│ timestamp  │  seq_num   │ signature  │            │
│   (8 B)    │   (4 B)    │  (64 B)    │            │
└────────────┴────────────┴────────────┴────────────┘
```

| 字段      | 大小 | 说明                                   |
| --------- | ---- | -------------------------------------- |
| magic     | 4 B  | 固定值 0x454C4E4B ("ELNK")             |
| src_node  | 4 B  | 源节点 ID                              |
| dst_node  | 4 B  | 目标节点 ID                            |
| nonce     | 12 B | 随机数，用于防重放                     |
| timestamp | 8 B  | 发送时间戳 (毫秒)                      |
| seq_num   | 4 B  | 序列号                                 |
| signature | 64 B | Ed25519 签名 (签名范围: magic 到 seq_num) |

#### 2.4.13 P2P_STATUS Payload (Type=0x45)

```
┌────────────┬────────────┬────────────┬────────────┐
│ peer_node  │   status   │  latency   │   path     │
│   (4 B)    │   (1 B)    │   (2 B)    │   (1 B)    │
└────────────┴────────────┴────────────┴────────────┘
```

| 字段      | 大小 | 说明                                      |
| --------- | ---- | ----------------------------------------- |
| peer_node | 4 B  | 对端节点 ID                               |
| status    | 1 B  | 0x00=断开, 0x01=P2P连接, 0x02=仅Relay     |
| latency   | 2 B  | 延迟 (毫秒)                               |
| path      | 1 B  | 路径类型: 0x01=LAN, 0x02=STUN, 0x03=Relay |

#### 2.4.14 ROUTE_ANNOUNCE Payload (Type=0x80)

```
┌────────────┬────────────┬────────────┬────────────┐
│ request_id │ route_count│  routes[]  │            │
│   (4 B)    │   (2 B)    │ (RouteInfo)│            │
└────────────┴────────────┴────────────┴────────────┘
```

#### 2.4.15 ROUTE_UPDATE Payload (Type=0x81)

```
┌────────────┬────────────┬────────────┬────────────┐
│  version   │ add_count  │ del_count  │ add_routes │
│   (8 B)    │   (2 B)    │   (2 B)    │ (RouteInfo)│
├────────────┴────────────┴────────────┴────────────┤
│                    del_routes[]                   │
│              (RouteIdentifier 数组)               │
└───────────────────────────────────────────────────┘
```

#### 2.4.16 ROUTE_WITHDRAW Payload (Type=0x82)

```
┌────────────┬────────────┬────────────┐
│ request_id │ route_count│  routes[]  │
│   (4 B)    │   (2 B)    │(RouteIdent)│
└────────────┴────────────┴────────────┘
```

#### 2.4.17 ROUTE_ACK Payload (Type=0x83)

```
┌────────────┬────────────┬────────────┐
│ request_id │   status   │error_count │
│   (4 B)    │   (1 B)    │   (2 B)    │
├────────────┴────────────┴────────────┤
│              error_routes[]          │
│        (RouteIdentifier + error_code)│
└──────────────────────────────────────┘
```

#### 2.4.18 RouteInfo 结构 (统一定义)

```
┌────────────┬────────────┬────────────┬────────────┬────────────┐
│  ip_type   │   prefix   │ prefix_len │gateway_node│  priority  │
│   (1 B)    │ (4/16 B)   │   (1 B)    │   (4 B)    │   (2 B)    │
├────────────┼────────────┼────────────┼────────────┼────────────┤
│   weight   │   metric   │   flags    │  tag_len   │    tag     │
│   (2 B)    │   (4 B)    │   (1 B)    │   (2 B)    │  (变长)    │
└────────────┴────────────┴────────────┴────────────┴────────────┘
```

| 字段         | 大小   | 说明                               |
| ------------ | ------ | ---------------------------------- |
| ip_type      | 1 B    | 0x04=IPv4, 0x06=IPv6               |
| prefix       | 4/16 B | 网络前缀 (根据 ip_type)            |
| prefix_len   | 1 B    | 前缀长度 (0-32 或 0-128)           |
| gateway_node | 4 B    | 网关节点 ID                        |
| priority     | 2 B    | 优先级 (值越小越优先)              |
| weight       | 2 B    | 权重 (负载均衡)                    |
| metric       | 4 B    | 路由度量                           |
| flags        | 1 B    | 标志位 (见下表)                    |
| tag_len      | 2 B    | 标签长度                           |
| tag          | 变长   | 可选标签 (如 "office-a")           |

**RouteInfo.flags 标志位**：

| 位   | 名称      | 说明                    |
| ---- | --------- | ----------------------- |
| 0x01 | ENABLED   | 路由已启用              |
| 0x02 | PRIMARY   | 主路由                  |
| 0x04 | EXIT_NODE | Exit Node 路由          |
| 0x08 | AUTO      | 自动创建 (节点虚拟 IP)  |

#### 2.4.19 RouteIdentifier 结构

```
┌────────────┬────────────┬────────────┬────────────┐
│  ip_type   │   prefix   │ prefix_len │gateway_node│
│   (1 B)    │ (4/16 B)   │   (1 B)    │   (4 B)    │
└────────────┴────────────┴────────────┴────────────┘
```

#### 2.4.20 PeerInfo 结构

```
┌────────────┬────────────┬────────────┬────────────┐
│  node_id   │ virtual_ip │  node_key  │   online   │
│   (4 B)    │   (4 B)    │  (32 B)    │   (1 B)    │
├────────────┼────────────┼────────────┼────────────┤
│   name     │endpoint_cnt│ endpoints[]│subnet_cnt  │
│ (len+str)  │   (2 B)    │ (数组)     │   (2 B)    │
├────────────┴────────────┴────────────┴────────────┤
│                 allowed_subnets[]                 │
│                  (SubnetInfo 数组)                │
└───────────────────────────────────────────────────┘
```

#### 2.4.21 EndpointInfo 结构

```
┌────────────┬────────────┬────────────┬────────────┐
│    type    │  ip_type   │     ip     │    port    │
│   (1 B)    │   (1 B)    │ (4/16 B)   │   (2 B)    │
├────────────┼────────────┼────────────┼────────────┤
│  priority  │ discovered │            │            │
│   (1 B)    │   (8 B)    │            │            │
└────────────┴────────────┴────────────┴────────────┘
```

| 字段       | 大小   | 说明                                  |
| ---------- | ------ | ------------------------------------- |
| type       | 1 B    | 端点类型: 0x01=LAN, 0x02=STUN, 0x03=UPNP, 0x04=RELAY |
| ip_type    | 1 B    | 0x04=IPv4, 0x06=IPv6                  |
| ip         | 4/16 B | IP 地址                               |
| port       | 2 B    | 端口号                                |
| priority   | 1 B    | 优先级 (1=最高)                       |
| discovered | 8 B    | 发现时间戳 (毫秒)                     |

#### 2.4.22 SubnetInfo 结构

```
┌────────────┬────────────┬────────────┐
│  ip_type   │   prefix   │ prefix_len │
│   (1 B)    │ (4/16 B)   │   (1 B)    │
└────────────┴────────────┴────────────┘
```

| 字段       | 大小   | 说明                                  |
| ---------- | ------ | ------------------------------------- |
| ip_type    | 1 B    | 0x04=IPv4, 0x06=IPv6                  |
| prefix     | 4/16 B | 网络前缀地址 (根据 ip_type)           |
| prefix_len | 1 B    | 前缀长度 (IPv4: 0-32, IPv6: 0-128)    |

**编码示例**：

```
allowed_subnets 示例: ["192.168.1.0/24", "10.0.0.0/8"]

二进制编码:
  00 02                 # subnet_cnt = 2

  # 第一个 SubnetInfo (192.168.1.0/24)
  04                    # ip_type = 0x04 (IPv4)
  C0 A8 01 00           # prefix = 192.168.1.0
  18                    # prefix_len = 24

  # 第二个 SubnetInfo (10.0.0.0/8)
  04                    # ip_type = 0x04 (IPv4)
  0A 00 00 00           # prefix = 10.0.0.0
  08                    # prefix_len = 8
```

### 2.5 协议子规范

#### 2.5.1 分片规范 (FRAGMENTED)

当消息 Payload 超过单帧承载能力时，启用分片传输。

**Fragment Header (9 字节)**：

```
┌────────────┬────────────┬────────────┬────────────┐
│ message_id │ frag_index │ frag_total │ orig_type  │
│   (4 B)    │   (2 B)    │   (2 B)    │   (1 B)    │
└────────────┴────────────┴────────────┴────────────┘
```

| 字段       | 大小 | 说明                         |
| ---------- | ---- | ---------------------------- |
| message_id | 4 B  | 消息唯一标识符               |
| frag_index | 2 B  | 当前分片索引 (从 0 开始)     |
| frag_total | 2 B  | 总分片数                     |
| orig_type  | 1 B  | 原始消息类型                 |

**Payload 区定义**：当 FRAGMENTED=1 时，Fragment Header 被视为 Payload 的一部分。即：Frame Header (5B) 之后的所有内容均为 Payload，Length 字段表示该 Payload 区的总长度。

**分片规则**：

| 规则           | 说明                                       |
| -------------- | ------------------------------------------ |
| 触发条件       | 原始业务 Payload > 65521 字节 (65530 - 9)  |
| 每片最大业务数据 | 65521 字节 (Length 上限 65530 减去 Fragment Header 9B) |
| Frame.Type     | 分片帧的 Type 保持原始消息类型             |
| Frame.Flags    | 设置 FRAGMENTED (0x08) 标志                |
| Length 字段    | Fragment Header (9B) + 本片业务数据长度    |
| 重组超时       | 30 秒内未收齐所有分片则丢弃                |
| 重组缓冲区     | 每个 message_id 独立缓冲                   |

**解析流程**：
1. 读取 Frame Header (5B)，获取 Length 和 Flags
2. 按 Length 读取 Payload 区
3. 若 Flags & FRAGMENTED，则 Payload[0..9] 为 Fragment Header，Payload[9..] 为本片业务数据
4. 收齐所有分片后，按 frag_index 顺序拼接业务数据，按 orig_type 解析

#### 2.5.2 确认机制 (NEED_ACK)

当消息需要可靠传输确认时，设置 NEED_ACK 标志。

**机制说明**：

| 项目           | 说明                                        |
| -------------- | ------------------------------------------- |
| 适用消息       | 控制面消息 (非 DATA)                        |
| 关联方式       | 通过 request_id 字段关联请求与响应          |
| ACK 消息       | 使用 GENERIC_ACK (0xFE) 或专用 ACK 类型     |
| 重传策略       | 初始 1s，指数退避，最大 3 次                |
| 超时判定       | 3 次重传无响应后报告失败                    |

**request_id 生成规则**：

| 规则       | 说明                                     |
| ---------- | ---------------------------------------- |
| 唯一性     | 每个连接内单调递增                       |
| 范围       | 32 位无符号整数，溢出后回绕              |
| 保留值     | 0 表示无需确认                           |

#### 2.5.3 压缩规范 (COMPRESSED)

**处理顺序**：**先压缩，后加密**（如同时启用）

| 项目           | 说明                                   |
| -------------- | -------------------------------------- |
| 压缩算法       | LZ4 (frame format)                     |
| 适用条件       | 原始 Payload > 256 字节                |
| 压缩收益检查   | 压缩后 >= 原始大小则不压缩             |
| Frame.Flags    | 压缩后设置 COMPRESSED (0x02) 标志      |

**压缩帧格式**：

```
┌─────────────────────────────────────────────────────┐
│               Frame Header (5B)                     │
│           Flags 含 COMPRESSED (0x02)                │
├─────────────────────────────────────────────────────┤
│             original_length (4B)                    │
├─────────────────────────────────────────────────────┤
│           LZ4 Compressed Data (变长)                │
└─────────────────────────────────────────────────────┘
```

| 字段            | 大小 | 说明                |
| --------------- | ---- | ------------------- |
| original_length | 4 B  | 压缩前原始长度      |
| compressed_data | 变长 | LZ4 压缩后的数据    |

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
| CONNECTED  | P2P 直连已建立       | 见下文     |
| RELAY_ONLY | 穿透失败，仅用 Relay | 60s 后重试 |

#### P2P CONNECTED 状态维持与超时

**Keepalive 机制**：

| 参数                   | 默认值 | 说明                                 |
| ---------------------- | ------ | ------------------------------------ |
| keepalive_interval     | 15s    | P2P_KEEPALIVE 发送间隔               |
| keepalive_timeout      | 45s    | 未收到任何包的超时时间 (3x interval) |
| keepalive_miss_limit   | 3      | 连续丢失次数阈值                     |

**状态转换条件**：

| 条件                                    | 目标状态    | 说明                        |
| --------------------------------------- | ----------- | --------------------------- |
| 超过 45s 未收到任何 P2P 包              | RELAY_ONLY  | 超时，降级到 Relay          |
| 连续 3 次 KEEPALIVE 无响应              | RELAY_ONLY  | 探测失败，降级到 Relay      |
| 收到 P2P 数据包或 KEEPALIVE_ACK         | CONNECTED   | 保持连接，重置超时计时器    |
| 对端主动发送断开通知                    | IDLE        | 对端主动断开                |

**超时计算**：

```
last_recv_time: 最后收到 P2P 包的时间戳
current_time: 当前时间

if (current_time - last_recv_time) > keepalive_timeout:
    state = RELAY_ONLY
    schedule_retry(60s)
```

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

### 3.4 Relay 注册状态机

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
                    └──────────────────────────────────────────┘
```

---

## 4. 核心业务流程

### 4.1 客户端首次认证流程 (AuthKey)

```
Client                          Controller
  │                                │
  │    状态: INIT → CONNECTING     │
  ├─── WebSocket 连接 ────────────►│
  │    /api/v1/control             │
  │                                │
  │    状态: CONNECTING → AUTH     │
  ├─── AUTH_REQUEST ──────────────►│
  │    [Frame Header:              │
  │      version=0x02,             │
  │      type=0x01 (AUTH_REQUEST), │  ← Frame Type
  │      flags=0x00,               │
  │      length=...]               │
  │    [Payload:                   │
  │      auth_type=0x02 (authkey), │  ← 认证方式
  │      machine_key, node_key,    │
  │      hostname, os, arch,       │
  │      version, timestamp,       │
  │      signature,                │
  │      auth_data="tskey-xxx"]    │
  │                                │
  │         ┌──────────────────────┤
  │         │ 1. 验证 AuthKey 有效  │
  │         │ 2. 验证签名           │
  │         │ 3. 分配 virtual_ip    │
  │         │ 4. 生成 JWT tokens    │
  │         │ 5. 创建节点记录       │
  │         └──────────────────────┤
  │                                │
  │    状态: AUTH → CONNECTED      │
  │◄─── AUTH_RESPONSE ─────────────┤
  │    [Frame Header:              │
  │      type=0x02 (AUTH_RESPONSE)]│
  │    [Payload:                   │
  │      success=0x01,             │
  │      node_id, virtual_ip,      │
  │      network_id,               │
  │      auth_token, relay_token]  │
  │                                │
  │◄─── CONFIG ────────────────────┤
  │    [type=0x10, 完整网络配置]    │
  │                                │
  ├─── CONFIG_ACK ────────────────►│
  │    [type=0x12]                 │
  │                                │
```

> **术语说明**：
> - `type=0x01` 是 Frame Header 中的消息类型 (AUTH_REQUEST)
> - `auth_type=0x02` 是 Payload 中的认证方式字段 (authkey)
> - 两者是不同层级的概念，不可混用

### 4.2 数据传输流程 (通过 Relay)

```
Client A         Relay           Client B
    │              │                 │
    │  DATA        │                 │
    ├─────────────►│                 │
    │ [type=0x20,  │                 │
    │  src=A,      │                 │
    │  dst=B,      │   DATA          │
    │  nonce,      ├────────────────►│
    │  encrypted,  │                 │
    │  auth_tag]   │                 │
    │              │                 │
    │              │    DATA_ACK     │
    │   DATA_ACK   │◄────────────────┤
    │◄─────────────┤  [type=0x21,    │
    │              │   ack_nonce]    │
    │              │                 │
```

### 4.3 P2P 直连建立流程

```
Client A              Controller              Client B
    │                     │                      │
    │  P2P_INIT           │                      │
    ├────────────────────►│                      │
    │  [type=0x40,        │                      │
    │   target=B]         │                      │
    │                     │                      │
    │                     │     P2P_ENDPOINT     │
    │                     ├─────────────────────►│
    │                     │  [type=0x41,         │
    │                     │   A 的端点列表]       │
    │                     │                      │
    │    P2P_ENDPOINT     │                      │
    │◄────────────────────┤                      │
    │  [B 的端点列表]      │                      │
    │                     │                      │
    │═══════════════ UDP P2P_PING ══════════════►│
    │  [type=0x42, magic, nonce, timestamp, sig] │
    │◄══════════════ UDP P2P_PONG ═══════════════│
    │  [type=0x43]                               │
    │                                            │
    │═══════════ P2P 直连建立 ══════════════════►│
    │                                            │
    │  P2P_STATUS         │                      │
    ├────────────────────►│                      │
    │  [type=0x45,        │                      │
    │   peer=B,           │                      │
    │   status=0x01]      │                      │
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
  │    [type=0x50,                 │
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
  │    [type=0x51,                 │
  │      success, server_id]       │
  │                                │
  │◄─── SERVER_RELAY_LIST ─────────┤
  │    [type=0x55, 其他 Relay 列表] │
  │                                │
  │◄─── SERVER_NODE_LOC ───────────┤
  │    [type=0x52, 节点位置信息]    │
  │                                │
  │════ 定期心跳 ══════════════════►│
  │    SERVER_HEARTBEAT (30s)      │
  │    [type=0x54]                 │
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
   │  [type=0x70, server_id, server_token]     │
   │                                            │
   │◄────────── MESH_HELLO_ACK ────────────────┤
   │  [type=0x71, server_id]                   │
   │                                            │
   │ 状态: HANDSHAKE → READY                    │
   │◄═══════════ Mesh 通道就绪 ════════════════►│
   │                                            │
   │◄═══════════ MESH_PING/PONG ══════════════►│
   │  [type=0x73/0x74, 延迟测量]                │
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

2. HKDF 派生 (使用 SHA-256):
   输入:
     - IKM: shared_secret (32 bytes)
     - Salt: sort(my_node_id, peer_node_id) 拼接 (8 bytes)
     - Info: "edgelink-session-v2"

   输出 (总 56 bytes):
     - Session Key (32 bytes)
     - Send Nonce Base (12 bytes)
     - Recv Nonce Base (12 bytes)
```

#### 5.3.2 Nonce 构造规范

**采用方案**：Nonce Base XOR Counter

```
nonce (12 bytes) = nonce_base XOR padded_counter

其中:
- nonce_base: HKDF 派生的 Send/Recv Nonce Base (12 bytes)
- counter: 64-bit 单调递增计数器 (从 0 开始)
- padded_counter: counter 左填充 0 至 12 bytes (大端序)
```

**双向 Nonce 隔离**：

| 方向     | 使用的 Nonce Base | 说明                          |
| -------- | ----------------- | ----------------------------- |
| A → B    | A 的 Send Base    | 等于 B 的 Recv Base           |
| B → A    | B 的 Send Base    | 等于 A 的 Recv Base           |

**DATA 包中的 nonce 字段**：

| 字段   | 内容                                         |
| ------ | -------------------------------------------- |
| nonce  | 计算后的 12 字节 nonce 值 (base XOR counter) |

> **注意**：DATA 包中传输的是完整的 12 字节 nonce，而非单独的 counter。接收方使用收到的 nonce 直接解密，并通过重放窗口检查 nonce 的唯一性。

**接收端恢复 counter 的方法**：

若接收端需要基于 counter 进行滑动窗口或乱序容忍判断，应按以下公式恢复 counter：

```
padded_counter = received_nonce XOR recv_nonce_base
counter = padded_counter 的低 8 字节 (大端序解析为 uint64)
```

其中 `recv_nonce_base` 为 HKDF 派生的接收方 Nonce Base（等于发送方的 Send Nonce Base）。

**实现要点**：
- 接收端必须持有正确的 `recv_nonce_base`，否则无法正确恢复 counter
- 恢复的 counter 用于滑动窗口算法判断是否为重放包
- 若 `padded_counter` 的高 4 字节非零，说明 nonce 异常或被篡改，应拒绝该包

#### 5.3.3 会话重建安全规则

**核心原则**：每次会话重建必须产生不同的密钥材料，防止 Nonce 重用。

**会话重建触发条件**：

| 场景                   | 处理方式                              |
| ---------------------- | ------------------------------------- |
| 网络断开重连           | 必须重新执行 ECDH 密钥交换            |
| P2P 路径切换           | 复用现有 Session Key（路径无关）      |
| 对端 node_key 变更     | 必须重新执行 ECDH 密钥交换            |
| Counter 溢出 (2^64-1)  | 必须重新执行 ECDH 密钥交换            |

**密钥派生唯一性保证**：

HKDF 的 Salt 包含双方 node_id 排序拼接，确保：
- 同一对节点每次 ECDH 使用不同的 ephemeral key，产生不同的 shared_secret
- 不同的 shared_secret 派生出不同的 Session Key 和 Nonce Base
- 即使 Counter 从 0 重新开始，由于 Nonce Base 不同，实际 Nonce 也不会重复

**实现要求**：

| 要求                     | 说明                                          |
| ------------------------ | --------------------------------------------- |
| Ephemeral Key 一次性     | 每次密钥交换必须生成新的 X25519 临时密钥对    |
| Counter 不持久化         | Counter 不保存到磁盘，重启后从 0 开始         |
| 会话状态隔离             | 每个 (src_node, dst_node) 对独立维护会话状态  |

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

**AEAD 附加认证数据 (AAD)**：Src Node (4B) + Dst Node (4B) = 8 bytes

### 5.5 加密规格

| 项目       | 规格                                            |
| ---------- | ----------------------------------------------- |
| 加密算法   | ChaCha20-Poly1305 (AEAD)                        |
| 密钥长度   | 256 bit                                         |
| Nonce 长度 | 96 bit (12 bytes)                               |
| Auth Tag   | 128 bit (16 bytes)                              |
| 重放保护   | 2048 位滑动窗口                                 |
| 最大加密载荷 | 65530 - 4 - 4 - 12 - 16 = **65494 bytes**     |

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

> **seq 提取**：从 nonce 中提取 counter 部分 (低 8 字节，大端序转换为 uint64) 作为 seq。

### 5.7 JWT Token 设计

#### 5.7.1 签名算法

| 算法   | 说明                                          | 推荐场景            |
| ------ | --------------------------------------------- | ------------------- |
| ES256  | ECDSA P-256 + SHA-256 (非对称，**推荐**)      | 生产环境默认        |
| HS256  | HMAC-SHA256 (对称，仅开发环境)                | 单机开发/测试       |

**安全说明**：
- **ES256 (推荐)**：Controller 持有私钥签发 Token，Relay 仅持有公钥验证。即使 Relay 被攻破，攻击者也无法伪造 Token。
- **HS256**：Controller 和 Relay 共享密钥，任一方泄露则整个系统受损。仅用于开发环境。

配置项 `jwt.algorithm` 控制使用的算法，默认 `ES256`。

#### 5.7.2 Auth Token (有效期 24 小时)

```
Header: { "alg": "ES256", "typ": "JWT" }
Payload:
{
    "node_id": 12345,
    "network_id": 1,
    "type": "auth",
    "iat": 1704787200,
    "exp": 1704873600
}
```

#### 5.7.3 Relay Token (有效期 90 分钟)

```
Header: { "alg": "ES256", "typ": "JWT" }
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

#### 5.7.4 Token 刷新机制

Client 需在 Token 过期前主动刷新，避免断连：

| Token 类型 | 有效期   | 刷新时机            | 刷新方式                  |
| ---------- | -------- | ------------------- | ------------------------- |
| Auth Token | 24 小时  | 过期前 1 小时       | 发送 AUTH_REQUEST (type=machine) |
| Relay Token| 90 分钟  | 过期前 10 分钟      | 从 CONFIG_UPDATE 获取     |

**刷新流程**：
1. Client 定时检查 Token 过期时间
2. 接近过期时通过现有连接请求刷新
3. Controller 验证后签发新 Token 通过 CONFIG_UPDATE 推送
4. Client 使用新 Token 重新连接 Relay (如需要)

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
│   │    └─────┬─────┘   │           │   └─────┴─────┘    │    │
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

RouteInfo 结构定义见 2.4.18 节，全局统一使用该定义。

### 6.4 路由通告流程

```
Client A               Controller               Client B
    │                      │                       │
    │  配置:               │                       │
    │  advertise:          │                       │
    │    192.168.1.0/24    │                       │
    │                      │                       │
    ├── ROUTE_ANNOUNCE ───►│                       │
    │   [type=0x80,        │                       │
    │    request_id=1,     │                       │
    │    routes=[{         │                       │
    │      ip_type=0x04,   │                       │
    │      prefix=192.168.1.0,                     │
    │      prefix_len=24,  │                       │
    │      gateway=self,   │                       │
    │      flags=0x01}]]   │                       │
    │                      │                       │
    │         ┌────────────┤                       │
    │         │ 1. 验证权限 │                       │
    │         │ 2. 检查冲突 │                       │
    │         │ 3. 存储路由 │                       │
    │         └────────────┤                       │
    │                      │                       │
    │◄─── ROUTE_ACK ───────┤                       │
    │   [type=0x83,        │                       │
    │    request_id=1,     │                       │
    │    status=0x00]      │                       │
    │                      │                       │
    │                      ├── ROUTE_UPDATE ──────►│
    │                      │   [type=0x81,         │
    │                      │    新增路由:          │
    │                      │    192.168.1.0/24    │
    │                      │    via 10.0.0.1]     │
    │                      │                       │
```

### 6.5 路由接受策略

客户端可配置接受哪些子网路由：

| 配置示例                             | 说明               |
| ------------------------------------ | ------------------ |
| `accept = ["*"]`                     | 接受所有路由       |
| `accept = ["192.168.0.0/16"]`        | 仅接受特定子网     |
| `accept = ["*", "!172.16.0.0/12"]`   | 接受所有但排除某些 |

### 6.6 Exit Node 模式

| 步骤               | 说明                         |
| ------------------ | ---------------------------- |
| 启用 Exit Node     | 节点通告 0.0.0.0/0 路由      |
| 配置转发           | 节点启用 IP 转发和 NAT       |
| 使用 Exit Node     | Client 选择并安装默认路由    |
| 排除地址           | 排除 Controller/Relay 和本地子网 |

### 6.7 路由冲突处理

| 场景             | 处理策略                     |
| ---------------- | ---------------------------- |
| 子网重叠         | 拒绝后通告的路由，返回 ERROR |
| 相同子网不同网关 | 允许，用于冗余/负载均衡      |
| 更具体路由       | 允许，最长前缀匹配           |
| 节点离线         | 自动故障转移到备用路由       |

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

### 7.2 Relay

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

### 8.2 Listener 设计

#### Linux 平台

| 方案        | 说明                                    |
| ----------- | --------------------------------------- |
| SO_REUSEPORT | 每个 IO 线程独立 acceptor              |
| 负载分发    | 内核自动在多个 acceptor 间分发连接     |
| 无锁设计    | 连接在 accept 时即绑定到目标线程       |

#### Windows 平台

| 方案        | 说明                                    |
| ----------- | --------------------------------------- |
| 单 Acceptor | 主线程单个 acceptor                    |
| IOCP 分发   | Accept 后将 socket move 到目标 io_context |
| Strand      | 使用 strand 确保线程安全               |

#### 分发算法

| 算法        | 说明                                    |
| ----------- | --------------------------------------- |
| Round-Robin | 默认，简单均匀                         |
| 最少连接    | 可选，适合长连接场景                   |
| 连接亲和性  | 基于 client IP hash，保持会话粘性       |

### 8.3 线程亲和性设计

| 原则       | 说明                                     |
| ---------- | ---------------------------------------- |
| 连接绑定   | 每个连接固定在一个线程，不迁移           |
| 数据本地化 | 会话状态、缓冲区等数据存储在连接所属线程 |
| 避免跨线程 | 同线程内的连接间通信直接调用，无需加锁   |
| 必要跨线程 | 仅在跨线程转发数据时使用无锁队列         |

### 8.4 跨线程通信场景

| 场景              | 方案                                  |
| ----------------- | ------------------------------------- |
| 数据转发 (同线程) | 直接调用目标 Session 的发送方法       |
| 数据转发 (跨线程) | 通过 MPSC 无锁队列投递到目标线程      |
| 广播消息          | 每个线程维护本地会话列表，各自广播    |
| 全局统计          | 各线程本地统计，定期汇总或使用 atomic |

### 8.4.1 背压机制

**MPSC 队列背压策略**：

| 参数                   | 默认值 | 说明                                |
| ---------------------- | ------ | ----------------------------------- |
| queue_capacity         | 65536  | 队列最大容量 (条消息)               |
| high_watermark         | 80%    | 高水位线，触发背压                  |
| low_watermark          | 50%    | 低水位线，恢复正常                  |
| drop_policy            | oldest | 满时丢弃策略: oldest/newest/reject  |

**背压处理流程**：

```
队列状态:
    if queue.size() >= high_watermark:
        enter_backpressure_mode()
        log_warn("Queue high watermark reached")

    if in_backpressure_mode && queue.size() <= low_watermark:
        exit_backpressure_mode()

消息入队:
    if queue.full():
        if drop_policy == "oldest":
            queue.pop_front()  # 丢弃最旧
            dropped_counter++
        elif drop_policy == "newest":
            return false       # 丢弃新消息
            dropped_counter++
        else:  # reject
            return false       # 拒绝，由调用方处理

        log_warn("Queue overflow, dropped: {}", dropped_counter)

    queue.push(msg)
```

**监控指标**：

| 指标                          | 类型      | 说明                |
| ----------------------------- | --------- | ------------------- |
| `queue_size`                  | Gauge     | 当前队列大小        |
| `queue_capacity`              | Gauge     | 队列容量            |
| `queue_dropped_total`         | Counter   | 累计丢弃消息数      |
| `backpressure_active`         | Gauge     | 是否处于背压状态    |
| `backpressure_duration_sec`   | Histogram | 背压持续时间        |

### 8.5 无锁设计要求

| 数据结构       | 无锁方案                           |
| -------------- | ---------------------------------- |
| 跨线程消息队列 | MPSC 无锁队列 (每线程一个入口队列) |
| 线程本地会话表 | 无需加锁 (单线程访问)              |
| 全局统计计数   | std::atomic                        |
| 节点位置缓存   | 每线程本地副本 + 定期同步          |

### 8.6 NodeLocationCache 设计

#### 缓存策略

| 项目         | 规格                                    |
| ------------ | --------------------------------------- |
| 存储结构     | 每线程本地 HashMap<node_id, relay_id>  |
| TTL          | 60 秒，过期后需重新查询                 |
| 最大条目     | 100,000 条/线程                         |
| 淘汰策略     | LRU                                     |

#### 同步机制

| 触发条件       | 动作                                    |
| -------------- | --------------------------------------- |
| Controller 推送 | SERVER_NODE_LOC 消息更新所有线程缓存   |
| 定期拉取       | 每 30 秒从 Controller 拉取增量更新     |
| 缓存未命中     | 向 Controller 查询，结果广播到所有线程 |
| 节点迁移       | Controller 推送位置变更通知            |
| 节点断开       | Controller 推送删除通知，立即失效      |

#### 一致性保证

| 场景           | 处理方式                                |
| -------------- | --------------------------------------- |
| 陈旧数据       | 允许短暂不一致，转发失败后触发更新     |
| 节点快速迁移   | 使用版本号，拒绝旧版本更新             |
| 网络分区恢复   | 全量同步，覆盖本地缓存                 |

### 8.7 协程使用规范

- 所有 IO 操作必须使用 co_await
- 禁止在协程中进行阻塞调用
- 使用 use_awaitable 作为 completion token
- 使用 co_spawn 启动协程

### 8.8 内存管理

- Session 使用 shared_ptr 管理
- SessionManager 持有 weak_ptr 避免循环引用
- 大缓冲区使用对象池复用

---

## 9. 日志系统设计

### 9.1 概述

EdgeLink 使用 spdlog 作为日志后端，但**禁止直接使用 `SPDLOG_LOGGER_*` 宏**，必须通过统一的日志封装层调用。日志系统支持**运行时动态调整日志等级**。

### 9.2 日志等级定义

| 等级    | 数值 | 说明                                     | 使用场景                         |
| ------- | ---- | ---------------------------------------- | -------------------------------- |
| TRACE   | 0    | 最详细的跟踪信息                         | 协议解析细节、状态机转换         |
| DEBUG   | 1    | 调试信息 (详见 9.2.1)                    | 每个消息、每个步骤的详细日志     |
| INFO    | 2    | 一般信息 (默认)                          | 启动/停止、连接建立/断开         |
| WARN    | 3    | 警告信息                                 | 非致命错误、配置问题、性能警告   |
| ERROR   | 4    | 错误信息                                 | 可恢复错误、操作失败             |
| FATAL   | 5    | 致命错误                                 | 不可恢复错误，程序即将退出       |
| OFF     | 6    | 关闭日志                                 | 禁用所有日志输出                 |

#### 9.2.1 DEBUG 级别日志规范

**核心原则**：DEBUG 级别必须记录**每一个消息**和**每一个处理步骤**的详细信息，确保问题可追溯。

**消息收发日志要求**：

| 场景                | 必须记录的内容                                                |
| ------------------- | ------------------------------------------------------------- |
| 发送消息            | 消息类型、目标地址/节点ID、Payload 关键字段、序列化后字节数   |
| 接收消息            | 消息类型、来源地址/节点ID、Payload 关键字段、原始字节数       |
| 消息解析            | 解析结果、各字段值（敏感信息脱敏）                            |
| 消息序列化          | 序列化前结构、序列化后字节数                                  |

**步骤跟踪日志要求**：

| 场景                | 必须记录的内容                                                |
| ------------------- | ------------------------------------------------------------- |
| 状态机转换          | 当前状态、触发事件、目标状态、转换原因                        |
| 认证流程            | 每个认证步骤的开始/结束、验证结果、token 生成/验证            |
| 密钥协商            | ECDH 开始/完成、HKDF 派生、密钥ID (非密钥本身)                |
| P2P 打洞            | 每个候选端点、探测发送/接收、NAT 类型判断                     |
| 路由处理            | 路由添加/删除/更新、匹配结果、转发决策                        |
| 数据转发            | 源/目标节点、数据包大小、转发路径选择                         |

**DEBUG 日志格式示例**：

```
[DEBUG] [client.control] Sending AUTH_REQUEST: auth_type=authkey, hostname="my-pc", timestamp=1704877825123
[DEBUG] [client.control] AUTH_REQUEST serialized: 156 bytes
[DEBUG] [relay.session] Received DATA: src_node=1001, dst_node=1002, nonce=0x..., payload_size=1420
[DEBUG] [relay.forward] Forwarding decision: dst=1002, path=direct, relay_id=null
[DEBUG] [client.p2p] NAT traversal step: trying endpoint 203.0.113.5:45678, attempt=1/3
[DEBUG] [client.p2p] P2P_PING sent: dst_node=1002, endpoint=203.0.113.5:45678, seq=42
[DEBUG] [client.p2p] P2P_PONG received: src_node=1002, rtt=23ms, seq=42
[DEBUG] [controller.route] Route announce: node=1001, subnet=192.168.1.0/24, priority=100
```

**敏感信息处理**：

| 字段类型     | 处理方式                    |
| ------------ | --------------------------- |
| 密钥/Token   | 仅记录前 8 字符 + `...`     |
| 密码/AuthKey | 使用 `[REDACTED]` 替代      |
| 加密数据     | 仅记录长度，不记录内容      |
| IP 地址      | 内网 IP 完整显示，公网 IP 可配置脱敏 |

### 9.3 日志模块划分

每个组件按功能模块划分独立的 Logger，支持分模块设置日志等级：

#### Controller 日志模块

| 模块名              | 说明             |
| ------------------- | ---------------- |
| `controller`        | 主模块           |
| `controller.ws`     | WebSocket 服务器 |
| `controller.auth`   | 认证服务         |
| `controller.config` | 配置服务         |
| `controller.route`  | 路由服务         |
| `controller.db`     | 数据库操作       |

#### Relay 日志模块

| 模块名           | 说明             |
| ---------------- | ---------------- |
| `relay`          | 主模块           |
| `relay.ws`       | WebSocket 服务器 |
| `relay.session`  | 会话管理         |
| `relay.mesh`     | Mesh 网络        |
| `relay.stun`     | STUN 服务        |
| `relay.forward`  | 数据转发         |

#### Client 日志模块

| 模块名           | 说明           |
| ---------------- | -------------- |
| `client`         | 主模块         |
| `client.control` | 控制通道       |
| `client.relay`   | Relay 连接     |
| `client.p2p`     | P2P 直连       |
| `client.crypto`  | 加密引擎       |
| `client.tun`     | TUN 设备       |
| `client.route`   | 路由管理       |

### 9.4 日志格式

#### 标准格式

```
[时间戳] [等级] [模块] [线程ID] 消息内容
```

#### 格式示例

```
[2026-01-10 14:30:25.123] [INFO ] [controller.auth] [T:1234] User 'admin' authenticated successfully
[2026-01-10 14:30:25.456] [DEBUG] [relay.forward] [T:5678] Forwarding packet: src=1001, dst=1002, size=1420
[2026-01-10 14:30:25.789] [WARN ] [client.p2p] [T:9012] NAT traversal timeout for peer 10.0.0.5, falling back to relay
```

### 9.5 日志接口设计

#### 9.5.1 Logger 类接口

| 方法                                       | 说明                   |
| ------------------------------------------ | ---------------------- |
| `Logger::get(module_name)`                 | 获取指定模块的 Logger  |
| `logger.trace(fmt, args...)`               | 输出 TRACE 级别日志    |
| `logger.debug(fmt, args...)`               | 输出 DEBUG 级别日志    |
| `logger.info(fmt, args...)`                | 输出 INFO 级别日志     |
| `logger.warn(fmt, args...)`                | 输出 WARN 级别日志     |
| `logger.error(fmt, args...)`               | 输出 ERROR 级别日志    |
| `logger.fatal(fmt, args...)`               | 输出 FATAL 级别日志    |
| `logger.set_level(level)`                  | 设置该 Logger 的日志等级 |
| `logger.get_level()`                       | 获取当前日志等级       |

#### 9.5.2 全局日志管理接口

| 方法                                       | 说明                     |
| ------------------------------------------ | ------------------------ |
| `LogManager::init(config)`                 | 初始化日志系统           |
| `LogManager::set_global_level(level)`      | 设置全局日志等级         |
| `LogManager::set_module_level(module, level)` | 设置指定模块日志等级  |
| `LogManager::get_module_level(module)`     | 获取指定模块日志等级     |
| `LogManager::reload_config()`              | 重新加载配置             |
| `LogManager::flush()`                      | 刷新所有缓冲区           |
| `LogManager::shutdown()`                   | 关闭日志系统             |

### 9.6 运行时日志等级调整

#### 9.6.1 调整方式

| 方式         | 说明                                |
| ------------ | ----------------------------------- |
| 命令行参数   | 启动时通过 `--log-level` 指定       |
| 配置文件     | 通过配置文件设置，支持热重载        |
| IPC 命令     | 通过 Unix Socket 发送命令动态调整   |
| HTTP API     | Controller 提供 REST API 调整       |
| 信号处理     | SIGUSR1 提升等级，SIGUSR2 降低等级  |

#### 9.6.2 配置优先级

| 优先级 | 来源       | 说明                           |
| ------ | ---------- | ------------------------------ |
| 1 (高) | CLI 参数   | `--log-level` 覆盖一切         |
| 2      | IPC/API    | 运行时动态调整，不持久化       |
| 3      | 配置文件   | `[log]` 段，支持热重载         |
| 4 (低) | 默认值     | INFO                           |

#### 9.6.3 IPC 命令格式

| 命令                               | 说明                   |
| ---------------------------------- | ---------------------- |
| `log level <level>`                | 设置全局日志等级       |
| `log level <module> <level>`       | 设置指定模块日志等级   |
| `log show`                         | 显示当前所有模块等级   |

#### 9.6.4 HTTP API (仅 Controller)

| 端点                          | 方法  | 说明                 |
| ----------------------------- | ----- | -------------------- |
| `/api/v1/admin/log/level`     | GET   | 获取所有模块日志等级 |
| `/api/v1/admin/log/level`     | PUT   | 设置全局日志等级     |
| `/api/v1/admin/log/level/:module` | PUT | 设置指定模块日志等级 |

### 9.7 日志输出目标

| 目标类型     | 说明                             | 配置项           |
| ------------ | -------------------------------- | ---------------- |
| 控制台       | 输出到 stdout/stderr             | `log.console`    |
| 文件         | 输出到文件，支持滚动             | `log.file`       |
| 系统日志     | 输出到 syslog (Linux)            | `log.syslog`     |

### 9.8 日志文件管理

| 配置项                | 默认值       | 说明                     |
| --------------------- | ------------ | ------------------------ |
| `log.file.path`       | -            | 日志文件路径             |
| `log.file.max_size`   | `100MB`      | 单个文件最大大小         |
| `log.file.max_files`  | `10`         | 保留的历史文件数量       |
| `log.file.rotate_on_open` | `false`  | 启动时是否轮转           |

### 9.9 禁用规则

#### 9.9.1 禁止使用的宏

以下 spdlog 宏**禁止在代码中直接使用**：

| 禁止使用                 | 原因                           |
| ------------------------ | ------------------------------ |
| `SPDLOG_LOGGER_TRACE`    | 绕过日志封装层，无法统一管理   |
| `SPDLOG_LOGGER_DEBUG`    | 绕过日志封装层，无法统一管理   |
| `SPDLOG_LOGGER_INFO`     | 绕过日志封装层，无法统一管理   |
| `SPDLOG_LOGGER_WARN`     | 绕过日志封装层，无法统一管理   |
| `SPDLOG_LOGGER_ERROR`    | 绕过日志封装层，无法统一管理   |
| `SPDLOG_LOGGER_CRITICAL` | 绕过日志封装层，无法统一管理   |
| `SPDLOG_TRACE`           | 使用默认 logger，不支持模块划分 |
| `SPDLOG_DEBUG`           | 使用默认 logger，不支持模块划分 |
| `SPDLOG_INFO`            | 使用默认 logger，不支持模块划分 |
| `SPDLOG_WARN`            | 使用默认 logger，不支持模块划分 |
| `SPDLOG_ERROR`           | 使用默认 logger，不支持模块划分 |
| `SPDLOG_CRITICAL`        | 使用默认 logger，不支持模块划分 |
| `spdlog::info()` 等      | 全局函数，不支持模块划分       |

#### 9.9.2 必须使用的方式

所有日志输出必须通过项目封装的 Logger 类：

```
正确: Logger::get("relay.forward").info("Packet forwarded: {} -> {}", src, dst);
错误: SPDLOG_INFO("Packet forwarded: {} -> {}", src, dst);
错误: spdlog::info("Packet forwarded: {} -> {}", src, dst);
```

### 9.10 性能考虑

| 项目             | 要求                                       |
| ---------------- | ------------------------------------------ |
| 异步日志         | 默认启用，避免 IO 阻塞业务线程             |
| 等级检查         | 在格式化前检查等级，避免无效的字符串构造   |
| 缓冲区复用       | 使用线程本地缓冲区，减少内存分配           |
| 批量刷新         | 定期或满缓冲区时批量刷新，减少 IO 次数     |

### 9.11 结构化日志格式

支持 JSON 格式输出，便于日志分析系统（ELK/Loki/Splunk）处理。

#### 9.11.1 日志上下文字段

```cpp
struct LogContext {
    std::string trace_id;      // 分布式追踪 ID (可选)
    std::string span_id;       // 当前操作 ID (可选)
    uint32_t node_id;          // 节点 ID (如适用)
    uint32_t network_id;       // 网络 ID
    std::string component;     // 组件名: controller/relay/client
    std::string module;        // 模块名: auth/routing/p2p/mesh
};
```

#### 9.11.2 JSON 格式输出

通过 `log.format = "json"` 配置启用：

```json
{
  "ts": "2026-01-10T10:23:45.123Z",
  "level": "info",
  "component": "controller",
  "module": "auth",
  "thread": 1234,
  "trace_id": "abc123def456",
  "node_id": 12345,
  "network_id": 1,
  "msg": "node authenticated",
  "auth_type": "authkey",
  "virtual_ip": "10.0.0.5",
  "latency_ms": 23
}
```

#### 9.11.3 文本格式输出 (默认)

```
[2026-01-10 10:23:45.123] [INFO ] [controller.auth] [T:1234] [trace:abc123] node authenticated: node_id=12345, auth_type=authkey, virtual_ip=10.0.0.5
```

### 9.12 关键日志点定义

以下操作**必须**记录日志，级别和字段不可更改。

#### 9.12.1 Controller 关键日志点

| 事件             | 级别  | 必须包含的字段                                              |
| ---------------- | ----- | ----------------------------------------------------------- |
| 节点认证请求     | INFO  | node_id, auth_type, machine_key(前8字节), remote_ip         |
| 认证成功         | INFO  | node_id, virtual_ip, auth_type, network_id                  |
| 认证失败         | WARN  | remote_ip, auth_type, error_code, reason                    |
| 节点离线         | INFO  | node_id, reason, session_duration_sec                       |
| 路由变更         | INFO  | network_id, prefix, action(add/remove/update), gateway_node |
| Relay 注册       | INFO  | server_id, name, region, capabilities                       |
| Relay 离线       | WARN  | server_id, reason                                           |
| Token 刷新       | DEBUG | node_id, token_type, old_exp, new_exp                       |
| 配置推送         | DEBUG | node_id, config_version                                     |
| 数据库错误       | ERROR | operation, error_msg                                        |

#### 9.12.2 Relay 关键日志点

| 事件             | 级别  | 必须包含的字段                                    |
| ---------------- | ----- | ------------------------------------------------- |
| 客户端连接       | INFO  | node_id, remote_ip                                |
| 客户端断开       | INFO  | node_id, reason, bytes_relayed, session_duration  |
| 客户端认证失败   | WARN  | remote_ip, error_code, reason                     |
| Mesh 连接建立    | INFO  | peer_server_id, peer_region, peer_url             |
| Mesh 连接断开    | WARN  | peer_server_id, reason                            |
| 数据转发         | TRACE | src_node, dst_node, size, path_type(local/mesh)   |
| 节点位置查询     | DEBUG | dst_node, result(found/not_found/mesh_forward)    |
| 限流触发         | WARN  | node_id, current_rate, limit, action              |
| Controller 重连  | WARN  | attempt, reason, next_retry_sec                   |

#### 9.12.3 Client 关键日志点

| 事件             | 级别  | 必须包含的字段                                    |
| ---------------- | ----- | ------------------------------------------------- |
| 状态机转换       | DEBUG | from_state, to_state, trigger, reason             |
| 连接 Controller  | INFO  | url, attempt                                      |
| 认证成功         | INFO  | node_id, virtual_ip, network_id                   |
| 认证失败         | ERROR | error_code, reason                                |
| 连接 Relay       | INFO  | relay_id, relay_url                               |
| P2P 尝试         | DEBUG | peer_node, endpoints_count, endpoints             |
| P2P 成功         | INFO  | peer_node, endpoint, nat_type, rtt_ms             |
| P2P 失败         | WARN  | peer_node, reason, fallback(relay)                |
| P2P 断开         | INFO  | peer_node, reason, duration_sec                   |
| 路由安装         | INFO  | prefix, gateway_node, interface                   |
| 路由删除         | INFO  | prefix, reason                                    |
| 密钥协商完成     | INFO  | peer_node, key_id(前8字节)                        |
| 密钥轮换         | INFO  | peer_node, old_key_id(前8字节), new_key_id(前8字节) |
| 加解密失败       | ERROR | peer_node, operation, error_msg                   |

### 9.13 安全日志要求

#### 9.13.1 禁止记录的敏感信息

| 敏感信息类型           | 说明                              |
| ---------------------- | --------------------------------- |
| 完整密钥材料           | machine_key, node_key, session_key 完整值 |
| 密码和密码哈希         | 用户密码、password_hash           |
| JWT Token 完整内容     | auth_token, relay_token 完整值    |
| AuthKey 完整值         | tskey-xxxx 完整密钥               |
| 解密后的数据包内容     | 明文 IP 包数据                    |
| 私钥文件内容           | TLS 私钥等                        |

#### 9.13.2 允许记录的脱敏信息

| 信息类型     | 脱敏方式                               | 示例                    |
| ------------ | -------------------------------------- | ----------------------- |
| 密钥         | 前 8 字节十六进制                      | `key=a1b2c3d4...`       |
| Token        | jti 字段或前 16 字符                   | `token=eyJhbGci...`     |
| AuthKey      | 类型和前缀                             | `tskey-auth-****`       |
| 密码         | 固定占位符                             | `[REDACTED]`            |
| 公网 IP      | 可配置：完整/最后一段掩码/完全掩码     | `203.0.113.***`         |

#### 9.13.3 审计日志要求

以下操作**必须记录且不可通过配置关闭**：

| 操作类型           | 说明                              |
| ------------------ | --------------------------------- |
| 认证成功/失败      | 所有认证尝试                      |
| 权限变更           | 节点权限、路由权限变更            |
| 配置变更           | 运行时配置修改                    |
| 节点授权状态变更   | 节点启用/禁用                     |
| 管理 API 调用      | 所有管理接口访问                  |

#### 9.13.4 日志文件安全

| 要求             | 说明                              |
| ---------------- | --------------------------------- |
| 文件权限         | 600 (仅 owner 读写)               |
| 目录权限         | 700 (仅 owner 访问)               |
| 归档加密         | 可选，压缩归档时加密              |
| 远程传输         | 使用 TLS 加密传输到日志服务器     |

### 9.14 分布式追踪支持

#### 9.14.1 Trace ID 规范

| 项目           | 规范                                |
| -------------- | ----------------------------------- |
| 格式           | 16 字节随机数，Base64 编码 (22 字符) |
| 生成时机       | 外部请求入口点 (认证、P2P 初始化等) |
| 传递方式       | 日志上下文传递，不修改协议帧        |
| 有效范围       | 单次请求的完整处理链路              |

#### 9.14.2 Trace ID 传递

```
Client 发起认证请求:
  [trace:abc123] AUTH_REQUEST sent
    ↓
Controller 处理:
  [trace:abc123] AUTH_REQUEST received
  [trace:abc123] Validating authkey
  [trace:abc123] Allocating virtual IP
  [trace:abc123] AUTH_RESPONSE sent
    ↓
Client 收到响应:
  [trace:abc123] AUTH_RESPONSE received
  [trace:abc123] Authentication completed
```

#### 9.14.3 跨组件追踪

对于涉及多组件的操作（如数据转发），trace_id 通过内部机制关联：

| 场景              | 追踪方式                              |
| ----------------- | ------------------------------------- |
| Client→Relay→Client | Relay 日志记录 src_node+dst_node+时间戳关联 |
| Client→Controller | 请求响应通过 request_id 关联          |
| Relay→Controller  | 心跳和状态上报独立追踪                |

### 9.15 日志性能指标

| 指标                   | 要求                                 |
| ---------------------- | ------------------------------------ |
| 异步队列溢出策略       | 丢弃最旧日志，记录丢弃计数           |
| 单条日志最大长度       | 4096 字节，超出截断并标记 `[TRUNCATED]` |
| TRACE 级别开销         | 关闭时零开销 (编译期条件或快速路径检查) |
| 日志写入延迟 (异步)    | < 1μs (P99)                          |
| 日志写入延迟 (同步)    | < 100μs (P99)                        |
| 异步队列大小           | 默认 8192 条，可配置                 |
| 刷新间隔               | 默认 1000ms，可配置                  |

### 9.16 运维集成

#### 9.16.1 Prometheus 指标

日志系统暴露以下 Prometheus 指标：

| 指标名                          | 类型    | 说明                    |
| ------------------------------- | ------- | ----------------------- |
| `edgelink_log_messages_total`   | Counter | 各级别日志消息计数      |
| `edgelink_log_dropped_total`    | Counter | 队列溢出丢弃的日志数    |
| `edgelink_log_write_latency_us` | Histogram | 日志写入延迟          |

#### 9.16.2 日志采集配置示例

**Filebeat (ELK)**:
```yaml
filebeat.inputs:
  - type: log
    paths:
      - /var/log/edgelink/*.log
    json.keys_under_root: true
    json.add_error_key: true
```

**Promtail (Loki)**:
```yaml
scrape_configs:
  - job_name: edgelink
    static_configs:
      - targets: [localhost]
        labels:
          job: edgelink
          __path__: /var/log/edgelink/*.log
    pipeline_stages:
      - json:
          expressions:
            level: level
            component: component
            module: module
```

---

## 10. 开发约束

### 10.1 编码规范

| 项目     | 约束                         |
| -------- | ---------------------------- |
| 语言标准 | C++23                        |
| Lambda   | 允许用于简单 glue code（见 10.6） |
| 异步模型 | Boost.Asio + Boost.Coroutine |
| 错误处理 | std::expected                |
| 日志     | 封装的 Logger 类 (基于 spdlog) |

### 10.2 命名规范

| 类型     | 规范                     | 示例                   |
| -------- | ------------------------ | ---------------------- |
| 命名空间 | 小写加下划线             | edgelink::controller   |
| 类名     | 大驼峰                   | WsServer, RelaySession |
| 函数名   | 小写加下划线             | do_read, handle_auth   |
| 成员变量 | 小写加下划线，尾随下划线 | node_id_, sessions_    |
| 常量     | 全大写加下划线           | MAX_FRAME_SIZE         |

### 10.3 文件组织

| 目录            | 内容                            |
| --------------- | ------------------------------- |
| src/common/     | 共享代码 (协议、帧、加密、日志、配置) |
| src/controller/ | Controller 代码                 |
| src/relay/      | Relay 代码                      |
| src/client/     | Client 代码                     |
| cmake/          | CMake 模块和工具链              |
| docs/           | 文档                            |
| config/         | 配置文件示例                    |

### 10.4 依赖库

| 库        | 版本要求      | 用途                           |
| --------- | ------------- | ------------------------------ |
| Boost     | >= 1.84.0     | Asio, Beast, JSON, Coroutine   |
| BoringSSL | 固定 commit   | TLS (Google's fork of OpenSSL) |
| libsodium | >= 1.0.19     | 加密                           |
| spdlog    | >= 1.13.0     | 日志后端 (通过封装层使用)      |
| jwt-cpp   | >= 0.7.0      | JWT                            |
| SQLite3   | >= 3.45.0     | 数据库                         |
| LZ4       | >= 1.9.4      | 压缩 (可选)                    |

> **注意**: 
> - 所有依赖通过 CMake FetchContent 引入，详见 [15. 构建系统](#15-构建系统)
> - BoringSSL 必须锁定到特定 commit hash，禁止使用 master 分支

### 10.5 BoringSSL 版本管理

| 要求           | 说明                                          |
| -------------- | --------------------------------------------- |
| 版本锁定       | 必须指定 commit hash，禁止使用 branch         |
| 升级流程       | 1) 评估 changelog 2) 本地测试 3) CI 验证      |
| 记录要求       | 在 cmake/dependencies.cmake 中注释升级日期和原因 |
| 兼容性验证     | TLS 1.3 握手、证书验证、密钥派生              |

### 10.6 Lambda 使用规范

| 场景           | 允许 | 说明                                          |
| -------------- | ---- | --------------------------------------------- |
| Asio handler   | ✓    | 简单的 completion handler                     |
| 立即调用       | ✓    | IIFE 用于初始化                              |
| STL 算法       | ✓    | 如 std::find_if, std::transform              |
| 业务逻辑       | ✗    | 禁止在 lambda 中编写复杂业务逻辑             |
| 状态机转换     | ✗    | 必须使用命名函数                             |
| 跨生命周期捕获 | ✗    | 禁止捕获引用跨越 await                       |

**允许的 Lambda 示例**：

| 用途               | 说明                           |
| ------------------ | ------------------------------ |
| 简单回调           | 无状态或仅捕获值类型           |
| 单行表达式         | 逻辑清晰，无副作用             |
| 临时包装           | 将成员函数包装为可调用对象     |

**禁止的 Lambda 示例**：

| 用途               | 说明                           |
| ------------------ | ------------------------------ |
| 多层嵌套           | 超过 2 层嵌套                  |
| 复杂捕获           | 捕获超过 3 个变量              |
| 长函数体           | 超过 10 行                     |
| 业务逻辑           | 协议解析、状态管理等           |

---

## 11. 错误码定义

### 11.1 错误码范围

| 范围      | 类别       |
| --------- | ---------- |
| 0-99      | 通用错误   |
| 1000-1999 | 认证错误   |
| 2000-2999 | 协议错误   |
| 3000-3999 | 路由错误   |
| 4000-4999 | 服务器错误 |
| 5000-5999 | 加密错误   |

### 11.2 主要错误码

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
| 2005 | FRAGMENT_TIMEOUT    | 分片重组超时             |
| 2006 | FRAGMENT_INVALID    | 无效分片                 |
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

## 12. 配置项定义

### 12.0 URL 配置规范

**重要约定**：所有配置文件中的 URL 字段**仅包含协议、主机和端口**，不包含路径 (path)。路径由代码内部根据连接类型自动拼接。

**配置格式示例**：

```toml
# 正确 - 不带 path
controller_url = "wss://controller.example.com:8080"
controller.url = "wss://10.0.0.1:8080"

# 错误 - 不应包含 path
controller_url = "wss://controller.example.com:8080/api/v1/control"  # 禁止
```

**路径拼接规则**：

| 连接类型            | 配置 URL 示例                    | 代码拼接后完整 URL                           |
| ------------------- | -------------------------------- | -------------------------------------------- |
| Client → Controller | `wss://ctrl.example.com:8080`    | `wss://ctrl.example.com:8080/api/v1/control` |
| Relay → Controller  | `wss://ctrl.example.com:8080`    | `wss://ctrl.example.com:8080/api/v1/server`  |
| Client → Relay      | `wss://relay.example.com:8081`   | `wss://relay.example.com:8081/relay`         |
| Relay → Relay       | `wss://relay-b.example.com:8081` | `wss://relay-b.example.com:8081/mesh`        |

**设计理由**：
- 避免用户配置错误（如遗漏或拼写错误路径）
- 协议版本升级时仅需修改代码，无需更新所有配置
- 简化配置验证逻辑

### 12.1 Controller 配置

| 配置项                   | 类型   | 默认值    | 说明                     |
| ------------------------ | ------ | --------- | ------------------------ |
| http.listen_address      | string | "0.0.0.0" | 监听地址                 |
| http.listen_port         | uint16 | 8080      | 监听端口                 |
| http.enable_tls          | bool   | false     | 启用 TLS                 |
| tls.cert_path            | string | -         | 证书路径                 |
| tls.key_path             | string | -         | 私钥路径                 |
| jwt.secret               | string | -         | JWT 密钥                 |
| jwt.auth_token_ttl       | uint32 | 1440      | Auth Token 有效期(分钟)  |
| jwt.relay_token_ttl      | uint32 | 90        | Relay Token 有效期(分钟) |
| database.path            | string | -         | 数据库路径               |
| builtin_relay.enabled    | bool   | false     | 启用内置 Relay           |
| builtin_stun.enabled     | bool   | false     | 启用内置 STUN            |
| builtin_stun.ip          | string | ""        | 公网 IP (NAT 检测)       |
| log.level                | string | "info"    | 全局日志等级             |
| log.format               | string | 见 9.4    | 日志格式模板             |
| log.console.enabled      | bool   | true      | 启用控制台输出           |
| log.console.color        | bool   | true      | 启用彩色输出             |
| log.file.enabled         | bool   | false     | 启用文件输出             |
| log.file.path            | string | -         | 日志文件路径             |
| log.file.max_size        | string | "100MB"   | 单文件最大大小           |
| log.file.max_files       | uint32 | 10        | 保留文件数量             |
| log.syslog.enabled       | bool   | false     | 启用 syslog 输出         |
| log.async                | bool   | true      | 启用异步日志             |
| log.modules.<name>       | string | 继承全局  | 指定模块的日志等级       |
| worker_threads           | uint32 | 0         | 工作线程数 (0=CPU核心数) |
| heartbeat.interval       | uint32 | 30        | 心跳发送间隔 (秒)        |
| heartbeat.timeout        | uint32 | 90        | 心跳超时时间 (秒)        |
| queue.capacity           | uint32 | 65536     | 消息队列最大容量         |
| queue.high_watermark     | float  | 0.8       | 高水位线 (触发背压)      |
| queue.low_watermark      | float  | 0.5       | 低水位线 (恢复正常)      |
| queue.drop_policy        | string | "oldest"  | 溢出策略: oldest/newest/reject |

### 12.2 Relay 配置

| 配置项                   | 类型   | 默认值    | 说明                     |
| ------------------------ | ------ | --------- | ------------------------ |
| relay.listen_address     | string | "0.0.0.0" | 监听地址                 |
| relay.listen_port        | uint16 | 8081      | 监听端口                 |
| relay.tls.enabled        | bool   | false     | 启用 TLS                 |
| relay.tls.cert_file      | string | -         | 证书路径                 |
| relay.tls.key_file       | string | -         | 私钥路径                 |
| stun.enabled             | bool   | true      | 启用 STUN                |
| stun.listen_port         | uint16 | 3478      | STUN 端口                |
| stun.ip                  | string | ""        | 公网 IP (NAT 检测)       |
| controller.url           | string | -         | Controller WSS URL       |
| controller.token         | string | -         | 服务器 Token             |
| server.name              | string | hostname  | 服务器名称               |
| server.region            | string | ""        | 区域标识                 |
| log.level                | string | "info"    | 全局日志等级             |
| log.console.enabled      | bool   | true      | 启用控制台输出           |
| log.file.enabled         | bool   | false     | 启用文件输出             |
| log.file.path            | string | -         | 日志文件路径             |
| log.file.max_size        | string | "100MB"   | 单文件最大大小           |
| log.file.max_files       | uint32 | 10        | 保留文件数量             |
| log.modules.<name>       | string | 继承全局  | 指定模块的日志等级       |
| worker_threads           | uint32 | 0         | 工作线程数 (0=CPU核心数) |
| heartbeat.interval       | uint32 | 30        | 心跳发送间隔 (秒)        |
| heartbeat.timeout        | uint32 | 90        | 心跳超时时间 (秒)        |
| reconnect.initial_delay  | uint32 | 1000      | 重连初始延迟 (毫秒)      |
| reconnect.max_delay      | uint32 | 60000     | 重连最大延迟 (毫秒)      |
| reconnect.multiplier     | float  | 2.0       | 重连延迟倍数             |
| queue.capacity           | uint32 | 65536     | 消息队列最大容量         |
| queue.high_watermark     | float  | 0.8       | 高水位线 (触发背压)      |
| queue.low_watermark      | float  | 0.5       | 低水位线 (恢复正常)      |
| queue.drop_policy        | string | "oldest"  | 溢出策略: oldest/newest/reject |

### 12.3 Client 配置

| 配置项                   | 类型     | 默认值    | 说明                       |
| ------------------------ | -------- | --------- | -------------------------- |
| controller_url           | string   | -         | Controller WSS URL         |
| auth_key                 | string   | ""        | 认证密钥 (见 12.4)         |
| data_dir                 | string   | -         | 数据目录                   |
| routes.advertise         | []string | []        | 通告的子网路由             |
| routes.accept            | []string | ["*"]     | 接受的子网路由             |
| exit_node.enabled        | bool     | false     | 启用 Exit Node             |
| exit_node.use            | string   | ""        | 使用指定 Exit Node         |
| log.level                | string   | "info"    | 全局日志等级               |
| log.console.enabled      | bool     | true      | 启用控制台输出             |
| log.console.color        | bool     | true      | 启用彩色输出               |
| log.file.enabled         | bool     | false     | 启用文件输出               |
| log.file.path            | string   | -         | 日志文件路径               |
| log.modules.<name>       | string   | 继承全局  | 指定模块的日志等级         |
| worker_threads           | uint32   | 0         | 工作线程数 (0=CPU核心数)   |
| heartbeat.interval       | uint32   | 30        | 心跳发送间隔 (秒)          |
| heartbeat.timeout        | uint32   | 90        | 心跳超时时间 (秒)          |
| reconnect.initial_delay  | uint32   | 1000      | 重连初始延迟 (毫秒)        |
| reconnect.max_delay      | uint32   | 60000     | 重连最大延迟 (毫秒)        |
| reconnect.multiplier     | float    | 2.0       | 重连延迟倍数               |
| p2p.enabled              | bool     | true      | 启用 P2P 直连              |
| p2p.keepalive_interval   | uint32   | 15        | P2P keepalive 间隔 (秒)    |
| p2p.keepalive_timeout    | uint32   | 45        | P2P keepalive 超时 (秒)    |
| p2p.keepalive_miss_limit | uint32   | 3         | P2P keepalive 丢失次数阈值 |
| p2p.stun_timeout         | uint32   | 5000      | STUN 探测超时 (毫秒)       |
| p2p.hole_punch_attempts  | uint32   | 5         | 打洞尝试次数               |
| queue.capacity           | uint32   | 65536     | 消息队列最大容量           |
| queue.high_watermark     | float    | 0.8       | 高水位线 (触发背压)        |
| queue.low_watermark      | float    | 0.5       | 低水位线 (恢复正常)        |
| queue.drop_policy        | string   | "oldest"  | 溢出策略: oldest/newest/reject |

### 12.4 AuthKey 生命周期

| 阶段           | 说明                                          |
| -------------- | --------------------------------------------- |
| 配置来源       | CLI `--auth-key` 或配置文件 `auth_key`        |
| 优先级         | CLI 参数 > 配置文件                           |
| 使用时机       | 仅首次注册时使用                              |
| 注册成功后     | node_id、machine_key、node_key 保存到 data_dir |
| 重连时         | 使用 machine_key 签名认证 (auth_type=0x03)    |
| 配置文件处理   | 注册成功后可选择从配置文件中移除              |
| 安全建议       | 不建议将 AuthKey 持久化到配置文件             |

---

## 13. 性能指标要求

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

## 14. CLI 命令参考

### 14.1 edgelink-controller

Controller 控制中心服务。

#### 基本用法

```
edgelink-controller [选项]
edgelink-controller <子命令> [选项]
```

#### 全局选项

| 选项          | 简写 | 默认值                          | 说明                                   |
| ------------- | ---- | ------------------------------- | -------------------------------------- |
| `--config`    | `-c` | `/etc/edgelink/controller.toml` | 配置文件路径                           |
| `--log-level` | `-l` | `info`                          | 日志级别 (覆盖配置文件)                |
| `--log-file`  |      | -                               | 日志文件路径 (覆盖配置文件)            |

#### 子命令

##### `edgelink-controller serve`

启动 Controller 服务。

| 选项              | 默认值          | 说明                    |
| ----------------- | --------------- | ----------------------- |
| `--listen`        | `0.0.0.0`       | 监听地址                |
| `--port`          | `8080`          | 监听端口                |
| `--tls`           | `false`         | 启用 TLS                |
| `--cert`          | -               | TLS 证书路径            |
| `--key`           | -               | TLS 私钥路径            |
| `--db`            | `./edgelink.db` | SQLite 数据库路径       |
| `--jwt-secret`    | -               | JWT 签名密钥 (必需)     |
| `--builtin-relay` | `false`         | 启用内置 Relay          |
| `--builtin-stun`  | `false`         | 启用内置 STUN           |
| `--public-ip`     | -               | 公网 IP (用于 NAT 检测) |

##### `edgelink-controller init`

初始化数据库和创建管理员账号。

| 选项         | 说明                      |
| ------------ | ------------------------- |
| `--db`       | 数据库路径                |
| `--admin`    | 管理员用户名 (默认 admin) |
| `--password` | 管理员密码 (交互式输入)   |

##### `edgelink-controller user`

用户管理命令。

| 操作     | 说明         |
| -------- | ------------ |
| `list`   | 列出所有用户 |
| `add`    | 添加用户     |
| `delete` | 删除用户     |
| `passwd` | 修改密码     |
| `role`   | 设置角色     |

##### `edgelink-controller authkey`

AuthKey 管理命令。

| 操作     | 说明             |
| -------- | ---------------- |
| `create` | 创建新 AuthKey   |
| `list`   | 列出所有 AuthKey |
| `revoke` | 撤销 AuthKey     |

| 选项            | 说明                      |
| --------------- | ------------------------- |
| `--reusable`    | 可重复使用                |
| `--ephemeral`   | 临时节点 (断开后删除)     |
| `--expires`     | 过期时间 (如 `24h`, `7d`) |
| `--max-uses`    | 最大使用次数              |
| `--description` | 描述                      |

##### `edgelink-controller node`

节点管理命令。

| 操作     | 说明             |
| -------- | ---------------- |
| `list`   | 列出所有节点     |
| `delete` | 删除节点         |
| `expire` | 强制节点重新认证 |

##### `edgelink-controller log`

运行时日志管理命令。

| 操作                    | 说明                   |
| ----------------------- | ---------------------- |
| `level`                 | 显示当前日志等级       |
| `level <level>`         | 设置全局日志等级       |
| `level <module> <level>`| 设置指定模块日志等级   |

##### `edgelink-controller version`

显示版本信息。

---

### 14.2 edgelink-relay

Relay 中继服务。

#### 基本用法

```
edgelink-relay [选项]
edgelink-relay <子命令> [选项]
```

#### 全局选项

| 选项          | 简写 | 默认值                     | 说明                    |
| ------------- | ---- | -------------------------- | ----------------------- |
| `--config`    | `-c` | `/etc/edgelink/relay.toml` | 配置文件路径            |
| `--log-level` | `-l` | `info`                     | 日志级别 (覆盖配置文件) |

#### 子命令

##### `edgelink-relay serve`

启动 Relay 服务。

| 选项           | 默认值    | 说明                         |
| -------------- | --------- | ---------------------------- |
| `--listen`     | `0.0.0.0` | 监听地址                     |
| `--port`       | `8081`    | WebSocket 监听端口           |
| `--tls`        | `false`   | 启用 TLS                     |
| `--cert`       | -         | TLS 证书路径                 |
| `--key`        | -         | TLS 私钥路径                 |
| `--controller` | -         | Controller WSS URL (必需)    |
| `--token`      | -         | 服务器认证 Token (必需)      |
| `--name`       | hostname  | 服务器名称                   |
| `--region`     | -         | 区域标识 (如 `ap-northeast`) |
| `--stun`       | `true`    | 启用 STUN 服务               |
| `--stun-port`  | `3478`    | STUN 监听端口                |
| `--public-ip`  | -         | 公网 IP (用于 STUN 响应)     |

##### `edgelink-relay log`

运行时日志管理命令。

| 操作                    | 说明                   |
| ----------------------- | ---------------------- |
| `level`                 | 显示当前日志等级       |
| `level <level>`         | 设置全局日志等级       |
| `level <module> <level>`| 设置指定模块日志等级   |

##### `edgelink-relay version`

显示版本信息。

---

### 14.3 edgelink-client

客户端守护进程和 CLI 工具。

#### 基本用法

```
edgelink-client [选项]
edgelink-client <子命令> [选项]
```

#### 全局选项

| 选项          | 简写 | 默认值                           | 说明                     |
| ------------- | ---- | -------------------------------- | ------------------------ |
| `--config`    | `-c` | `~/.config/edgelink/config.toml` | 配置文件路径             |
| `--data-dir`  | `-d` | `~/.local/share/edgelink`        | 数据目录                 |
| `--socket`    | `-s` | `/var/run/edgelink.sock`         | IPC socket 路径          |
| `--log-level` | `-l` | `info`                           | 日志级别 (覆盖配置文件)  |

#### 子命令

##### `edgelink-client up`

启动客户端并连接到网络。

| 选项              | 默认值  | 说明                    |
| ----------------- | ------- | ----------------------- |
| `--controller`    | -       | Controller WSS URL      |
| `--auth-key`      | -       | AuthKey (仅首次注册)    |
| `--hostname`      | 系统    | 自定义主机名            |
| `--accept-routes` | `true`  | 接受子网路由            |
| `--foreground`    | `false` | 前台运行 (不 daemonize) |

##### `edgelink-client down`

断开连接并停止客户端。

##### `edgelink-client status`

显示连接状态。

| 选项     | 说明          |
| -------- | ------------- |
| `--json` | JSON 格式输出 |

**输出示例:**

```
Status: Connected
  Network:     MyNetwork (10.0.0.0/24)
  Virtual IP:  10.0.0.5
  Controller:  wss://controller.example.com (latency: 15ms)
  Relay:       relay-tokyo (latency: 8ms)
  P2P:         2 direct connections

Peers:
  10.0.0.1   alice-laptop    P2P (direct)    3ms
  10.0.0.2   bob-desktop     P2P (direct)    5ms
  10.0.0.3   office-gateway  Relay           25ms
```

##### `edgelink-client peers`

列出所有对端节点。

| 选项       | 说明           |
| ---------- | -------------- |
| `--json`   | JSON 格式输出  |
| `--online` | 仅显示在线节点 |

##### `edgelink-client ping`

Ping 指定对端节点。

| 参数/选项 | 说明                       |
| --------- | -------------------------- |
| `<目标>`  | 目标 IP、节点名称或节点 ID |
| `--count` | Ping 次数 (默认 4)         |

##### `edgelink-client route`

路由管理命令。

| 操作        | 说明           |
| ----------- | -------------- |
| `list`      | 列出当前路由表 |
| `advertise` | 通告本地子网   |
| `withdraw`  | 撤销子网通告   |

##### `edgelink-client exit-node`

Exit Node 管理。

| 操作        | 说明                 |
| ----------- | -------------------- |
| `list`      | 列出可用 Exit Node   |
| `use`       | 使用指定 Exit Node   |
| `off`       | 停止使用 Exit Node   |
| `advertise` | 将本机设为 Exit Node |

##### `edgelink-client log`

运行时日志管理命令。

| 操作                    | 说明                   |
| ----------------------- | ---------------------- |
| `level`                 | 显示当前日志等级       |
| `level <level>`         | 设置全局日志等级       |
| `level <module> <level>`| 设置指定模块日志等级   |

##### `edgelink-client logout`

注销当前设备 (删除本地凭据)。

##### `edgelink-client version`

显示版本信息。

**输出示例:**

```
EdgeLink Client 1.0.0
  Protocol:   0x02
  Build:      2026-01-10 (abc1234)
  Go/C++:     C++23
  Platform:   linux/amd64
```

---

### 14.4 命令行交互示例

#### 完整部署流程

```
# 1. 初始化 Controller
edgelink-controller init --admin admin --db /var/lib/edgelink/db.sqlite
edgelink-controller serve --jwt-secret "$(openssl rand -hex 32)" &

# 2. 创建 AuthKey
edgelink-controller authkey create --reusable --description "公司设备"
# 输出: tskey-reusable-a7Bn4Kp9zQwX2mLj8RvC6

# 3. 启动 Relay
edgelink-relay serve \
    --controller wss://localhost:8080/api/v1/server \
    --token "relay-token" \
    --name relay-tokyo \
    --region ap-northeast &

# 4. 在客户端设备上连接 (首次注册)
edgelink-client up \
    --controller wss://controller.example.com/api/v1/control \
    --auth-key tskey-reusable-a7Bn4Kp9zQwX2mLj8RvC6

# 5. 后续重连 (无需 auth-key)
edgelink-client up

# 6. 检查状态
edgelink-client status
edgelink-client peers
```

#### 运行时调整日志等级

```
# 调整全局日志等级为 debug
edgelink-client log level debug

# 仅调整 P2P 模块为 trace
edgelink-client log level client.p2p trace

# 查看当前日志等级
edgelink-client log level
```

#### 子网路由配置

```
# 在网关设备上通告本地子网
edgelink-client route advertise 192.168.1.0/24

# 在其他设备上查看路由
edgelink-client route list
```

---

## 15. 构建系统

### 15.1 概述

EdgeLink 使用 CMake 作为构建系统，所有第三方依赖**必须**通过 `FetchContent` 方式引入，禁止使用系统安装的库或 Git Submodule。

### 15.2 CMake 要求

| 项目       | 要求                             |
| ---------- | -------------------------------- |
| CMake 版本 | >= 3.25                          |
| C++ 标准   | C++23                            |
| 编译器     | GCC 13+ / Clang 17+ / MSVC 2022+ |

### 15.3 FetchContent 依赖管理

#### 15.3.1 依赖版本约束

| 库        | 最低版本 | 推荐版本              | 用途                           |
| --------- | -------- | --------------------- | ------------------------------ |
| Boost     | 1.82.0   | 1.84.0                | Asio, Beast, JSON, Coroutine   |
| BoringSSL | -        | commit hash (见下文)  | TLS (Google's fork of OpenSSL) |
| libsodium | 1.0.18   | 1.0.19                | ChaCha20-Poly1305, X25519      |
| spdlog    | 1.12.0   | 1.13.0                | 日志后端                       |
| jwt-cpp   | 0.6.0    | 0.7.0                 | JWT 签发与验证                 |
| SQLite3   | 3.40.0   | 3.45.0                | 数据库                         |
| LZ4       | 1.9.0    | 1.9.4                 | 压缩 (可选)                    |

#### 15.3.2 BoringSSL 版本锁定

| 项目         | 要求                                          |
| ------------ | --------------------------------------------- |
| 版本指定     | 必须使用 `GIT_TAG` 指定 commit hash           |
| 禁止使用     | master 分支、origin/master-with-bazel         |
| 示例         | `GIT_TAG ae223d6138807a13006342edfeef32e813f4`|
| 更新记录     | 在 cmake 文件中注释更新日期和原因             |

#### 15.3.3 依赖声明位置

所有依赖在 `cmake/dependencies.cmake` 中统一声明。

### 15.4 构建指令

#### 15.4.1 基本构建

```
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
sudo cmake --install build
```

#### 15.4.2 开发构建

```
cmake -B build \
    -DCMAKE_BUILD_TYPE=Debug \
    -DEDGELINK_BUILD_TESTS=ON \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON

cmake --build build -j$(nproc)
ctest --test-dir build --output-on-failure
```

#### 15.4.3 交叉编译

```
cmake -B build-arm64 \
    -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/aarch64-linux-gnu.cmake \
    -DCMAKE_BUILD_TYPE=Release

cmake --build build-arm64 -j$(nproc)
```

#### 15.4.4 仅构建特定组件

```
# 仅构建 Client
cmake -B build \
    -DEDGELINK_BUILD_CONTROLLER=OFF \
    -DEDGELINK_BUILD_RELAY=OFF \
    -DEDGELINK_BUILD_CLIENT=ON

cmake --build build -j$(nproc)
```

### 15.5 构建选项

| 选项                       | 默认值 | 说明               |
| -------------------------- | ------ | ------------------ |
| `EDGELINK_BUILD_CONTROLLER`| ON     | 构建 Controller    |
| `EDGELINK_BUILD_RELAY`     | ON     | 构建 Relay         |
| `EDGELINK_BUILD_CLIENT`    | ON     | 构建 Client        |
| `EDGELINK_BUILD_TESTS`     | OFF    | 构建测试           |
| `EDGELINK_ENABLE_LZ4`      | ON     | 启用 LZ4 压缩      |

### 15.6 依赖缓存

为避免重复下载，可设置依赖缓存目录：

```
export FETCHCONTENT_BASE_DIR=~/.cmake-deps
cmake -B build -DFETCHCONTENT_BASE_DIR=/path/to/cache
```

### 15.7 注意事项

| 项目               | 说明                                                  |
| ------------------ | ----------------------------------------------------- |
| **禁止系统库**     | 不使用 `find_package()` 查找系统安装的依赖            |
| **禁止 Submodule** | 不使用 Git Submodule 管理依赖                         |
| **版本锁定**       | 所有依赖必须指定明确的版本或 commit hash              |
| **URL Hash**       | 使用 URL 下载时必须提供 `URL_HASH` 校验               |
| **浅克隆**         | Git 依赖启用 `GIT_SHALLOW TRUE` 加速下载              |
| **离线构建**       | 可预先下载依赖到 `FETCHCONTENT_BASE_DIR` 实现离线构建 |

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

### 附录 D: 客户端认证方式 (auth_type)

| auth_type | 值   | 说明           |
| --------- | ---- | -------------- |
| user      | 0x01 | 用户名密码登录 |
| authkey   | 0x02 | AuthKey 认证   |
| machine   | 0x03 | 已注册节点重连 |

> **注意**：auth_type 是 AUTH_REQUEST Payload 中的字段，不是 Frame Header 中的 Type。

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

**总帧长度计算**：`总长度 = Frame Header (5 bytes) + Payload (Length 字段值)`

#### AUTH_REQUEST 编码示例

**总帧长度**：5 + 208 = 213 bytes

```
Frame Header (5 bytes):
  02                          # version = 0x02
  01                          # type = 0x01 (AUTH_REQUEST)
  00                          # flags = 0x00
  00 D0                       # length = 208 (大端序)

Payload (208 bytes):
  02                          # auth_type = 0x02 (authkey)
  [32 bytes machine_key]      # Ed25519 公钥
  [32 bytes node_key]         # X25519 公钥
  00 09 6D 79 2D 6C 61 70 74 6F 70  # hostname (len=9 + "my-laptop")
  00 05 6C 69 6E 75 78        # os (len=5 + "linux")
  00 05 61 6D 64 36 34        # arch (len=5 + "amd64")
  00 05 31 2E 30 2E 30        # version (len=5 + "1.0.0")
  00 00 01 8D 5B 1B A8 00     # timestamp (8 bytes BE, 毫秒)
  [64 bytes signature]        # Ed25519 签名 (覆盖 auth_type 到 timestamp)
  00 1A 74 73 6B 65 79 2D ... # auth_data: authkey (len=26 + "tskey-...")
```

#### DATA 编码示例

**总帧长度**：5 + 1472 = 1477 bytes

```
Frame Header (5 bytes):
  02                          # version = 0x02
  20                          # type = 0x20 (DATA)
  00                          # flags = 0x00
  05 C0                       # length = 1472 (大端序)

Payload (1472 bytes):
  00 00 03 E9                 # src_node = 1001
  00 00 03 EA                 # dst_node = 1002
  [12 bytes nonce]            # nonce = base XOR counter
  [1436 bytes encrypted]      # 加密后的 IP 包
  [16 bytes auth_tag]         # AEAD 认证标签
```

### 附录 I: 配置文件示例

#### Controller 配置 (controller.toml)

```toml
[http]
listen_address = "0.0.0.0"
listen_port = 8080
enable_tls = true

[tls]
cert_path = "/etc/edgelink/cert.pem"
key_path = "/etc/edgelink/key.pem"

[jwt]
secret = "your-secret-key-here"
auth_token_ttl = 1440
relay_token_ttl = 90

[database]
path = "/var/lib/edgelink/db.sqlite"

[builtin_relay]
enabled = false

[builtin_stun]
enabled = false
ip = ""

[log]
level = "info"
format = "[{time}] [{level}] [{name}] [{thread}] {message}"

[log.console]
enabled = true
color = true

[log.file]
enabled = true
path = "/var/log/edgelink/controller.log"
max_size = "100MB"
max_files = 10

[log.modules]
"controller.auth" = "debug"
"controller.db" = "warn"
```

#### Relay 配置 (relay.toml)

```toml
[relay]
listen_address = "0.0.0.0"
listen_port = 8081

[relay.tls]
enabled = true
cert_file = "/etc/edgelink/cert.pem"
key_file = "/etc/edgelink/key.pem"

[stun]
enabled = true
listen_port = 3478
ip = "203.0.113.10"

[controller]
url = "wss://controller.example.com/api/v1/server"
token = "your-server-token"

[server]
name = "relay-tokyo"
region = "ap-northeast"

[log]
level = "info"

[log.console]
enabled = true

[log.file]
enabled = true
path = "/var/log/edgelink/relay.log"
max_size = "100MB"
max_files = 10

[log.modules]
"relay.forward" = "debug"
```

#### Client 配置 (config.toml)

```toml
controller_url = "wss://controller.example.com/api/v1/control"
data_dir = "~/.local/share/edgelink"

# AuthKey 仅用于首次注册，注册成功后可移除
# auth_key = "tskey-reusable-a7Bn4Kp9zQwX2mLj8RvC6"

[routes]
advertise = ["192.168.1.0/24"]
accept = ["*"]

[exit_node]
enabled = false
use = ""

[log]
level = "info"

[log.console]
enabled = true
color = true

[log.file]
enabled = false

[log.modules]
"client.p2p" = "debug"
```

### 附录 J: 数据库表定义

Controller 使用 SQLite 持久化存储，以下为核心表结构。

#### users 表

| 列名           | 类型      | 约束                      | 说明                    |
| -------------- | --------- | ------------------------- | ----------------------- |
| id             | INTEGER   | PRIMARY KEY AUTOINCREMENT | 用户 ID                 |
| username       | TEXT      | UNIQUE NOT NULL           | 用户名                  |
| password_hash  | TEXT      | NOT NULL                  | 密码哈希 (Argon2id)     |
| role           | TEXT      | NOT NULL DEFAULT 'user'   | 角色: admin/user        |
| created_at     | INTEGER   | NOT NULL                  | 创建时间 (毫秒时间戳)   |
| updated_at     | INTEGER   | NOT NULL                  | 更新时间 (毫秒时间戳)   |

#### networks 表

| 列名           | 类型      | 约束                      | 说明                    |
| -------------- | --------- | ------------------------- | ----------------------- |
| id             | INTEGER   | PRIMARY KEY AUTOINCREMENT | 网络 ID                 |
| name           | TEXT      | UNIQUE NOT NULL           | 网络名称                |
| cidr           | TEXT      | NOT NULL                  | 网络 CIDR (如 10.0.0.0/8) |
| owner_id       | INTEGER   | REFERENCES users(id)      | 所有者用户 ID           |
| created_at     | INTEGER   | NOT NULL                  | 创建时间 (毫秒时间戳)   |

#### nodes 表

| 列名           | 类型      | 约束                      | 说明                    |
| -------------- | --------- | ------------------------- | ----------------------- |
| id             | INTEGER   | PRIMARY KEY               | 节点 ID (node_id)       |
| network_id     | INTEGER   | NOT NULL REFERENCES networks(id) | 所属网络        |
| user_id        | INTEGER   | REFERENCES users(id)      | 所属用户                |
| machine_key    | BLOB      | UNIQUE NOT NULL           | Ed25519 公钥 (32 bytes) |
| node_key       | BLOB      | NOT NULL                  | X25519 公钥 (32 bytes)  |
| virtual_ip     | TEXT      | NOT NULL                  | 虚拟 IP 地址            |
| hostname       | TEXT      | NOT NULL                  | 主机名                  |
| os             | TEXT      |                           | 操作系统                |
| arch           | TEXT      |                           | CPU 架构                |
| version        | TEXT      |                           | 客户端版本              |
| last_seen      | INTEGER   |                           | 最后在线时间 (毫秒时间戳) |
| created_at     | INTEGER   | NOT NULL                  | 创建时间 (毫秒时间戳)   |

#### servers 表 (Relay)

| 列名           | 类型      | 约束                      | 说明                    |
| -------------- | --------- | ------------------------- | ----------------------- |
| id             | INTEGER   | PRIMARY KEY               | 服务器 ID               |
| name           | TEXT      | NOT NULL                  | 服务器名称              |
| region         | TEXT      |                           | 区域标识                |
| public_ip      | TEXT      | NOT NULL                  | 公网 IP 地址            |
| public_port    | INTEGER   | NOT NULL                  | 公网端口                |
| stun_port      | INTEGER   |                           | STUN 端口 (如启用)      |
| capabilities   | INTEGER   | NOT NULL DEFAULT 0        | 能力标志位              |
| online         | INTEGER   | NOT NULL DEFAULT 0        | 在线状态 (0/1)          |
| last_seen      | INTEGER   |                           | 最后心跳时间 (毫秒时间戳) |
| created_at     | INTEGER   | NOT NULL                  | 创建时间 (毫秒时间戳)   |

#### authkeys 表

| 列名           | 类型      | 约束                      | 说明                    |
| -------------- | --------- | ------------------------- | ----------------------- |
| id             | INTEGER   | PRIMARY KEY AUTOINCREMENT | AuthKey ID              |
| key            | TEXT      | UNIQUE NOT NULL           | AuthKey 字符串          |
| user_id        | INTEGER   | NOT NULL REFERENCES users(id) | 创建者用户 ID       |
| network_id     | INTEGER   | NOT NULL REFERENCES networks(id) | 目标网络         |
| type           | TEXT      | NOT NULL                  | 类型: auth/reusable/ephemeral |
| use_count      | INTEGER   | NOT NULL DEFAULT 0        | 已使用次数              |
| max_uses       | INTEGER   |                           | 最大使用次数 (NULL=无限)|
| expires_at     | INTEGER   |                           | 过期时间 (毫秒时间戳)   |
| created_at     | INTEGER   | NOT NULL                  | 创建时间 (毫秒时间戳)   |

#### routes 表

| 列名           | 类型      | 约束                      | 说明                    |
| -------------- | --------- | ------------------------- | ----------------------- |
| id             | INTEGER   | PRIMARY KEY AUTOINCREMENT | 路由 ID                 |
| network_id     | INTEGER   | NOT NULL REFERENCES networks(id) | 所属网络         |
| prefix         | TEXT      | NOT NULL                  | 路由前缀 (CIDR)         |
| gateway_node   | INTEGER   | NOT NULL REFERENCES nodes(id) | 网关节点 ID         |
| metric         | INTEGER   | NOT NULL DEFAULT 100      | 路由优先级              |
| is_exit        | INTEGER   | NOT NULL DEFAULT 0        | 是否 Exit Node 路由     |
| created_at     | INTEGER   | NOT NULL                  | 创建时间 (毫秒时间戳)   |

#### endpoints 表

| 列名           | 类型      | 约束                      | 说明                    |
| -------------- | --------- | ------------------------- | ----------------------- |
| id             | INTEGER   | PRIMARY KEY AUTOINCREMENT | 端点 ID                 |
| node_id        | INTEGER   | NOT NULL REFERENCES nodes(id) | 所属节点            |
| type           | INTEGER   | NOT NULL                  | 端点类型 (见 endpoint_type) |
| ip_type        | INTEGER   | NOT NULL                  | IP 类型 (0x04/0x06)     |
| ip             | BLOB      | NOT NULL                  | IP 地址 (4 或 16 bytes) |
| port           | INTEGER   | NOT NULL                  | 端口号                  |
| priority       | INTEGER   | NOT NULL                  | 优先级                  |
| updated_at     | INTEGER   | NOT NULL                  | 更新时间 (毫秒时间戳)   |

#### latency_reports 表

| 列名           | 类型      | 约束                      | 说明                    |
| -------------- | --------- | ------------------------- | ----------------------- |
| id             | INTEGER   | PRIMARY KEY AUTOINCREMENT | 记录 ID                 |
| node_id        | INTEGER   | NOT NULL REFERENCES nodes(id) | 报告节点            |
| server_id      | INTEGER   | NOT NULL REFERENCES servers(id) | 目标服务器        |
| latency_ms     | INTEGER   | NOT NULL                  | 延迟 (毫秒)             |
| reported_at    | INTEGER   | NOT NULL                  | 报告时间 (毫秒时间戳)   |

#### 索引定义

```sql
CREATE INDEX idx_nodes_network ON nodes(network_id);
CREATE INDEX idx_nodes_user ON nodes(user_id);
CREATE INDEX idx_nodes_virtual_ip ON nodes(virtual_ip);
CREATE INDEX idx_routes_network ON routes(network_id);
CREATE INDEX idx_routes_prefix ON routes(prefix);
CREATE INDEX idx_authkeys_user ON authkeys(user_id);
CREATE INDEX idx_authkeys_network ON authkeys(network_id);
CREATE INDEX idx_endpoints_node ON endpoints(node_id);
CREATE INDEX idx_latency_node_server ON latency_reports(node_id, server_id);
```

### 附录 K: 术语表

| 术语           | 说明                                              |
| -------------- | ------------------------------------------------- |
| Frame Type     | 帧头中的消息类型字段 (1 字节)，标识消息种类        |
| auth_type      | AUTH_REQUEST Payload 中的认证方式字段             |
| Nonce Base     | HKDF 派生的 12 字节值，用于构造 Nonce             |
| Session Key    | 两节点间通信使用的对称加密密钥                    |
| Machine Key    | 设备永久身份密钥对 (Ed25519)                      |
| Node Key       | 节点密钥交换密钥对 (X25519)，可轮换               |
| AuthKey        | 一次性或可重用的节点注册凭据                      |
| Exit Node      | 提供默认路由 (0.0.0.0/0) 的特殊节点               |

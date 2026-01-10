# EdgeLink 架构设计文档

> **版本**: 2.9
> **更新日期**: 2026-01-10
> **协议版本**: 0x02

## 目录

- [1. 系统概述](#1-系统概述)
- [2. 高并发设计要求](#2-高并发设计要求)
- [3. 通信协议](#3-通信协议)
- [4. 状态机设计](#4-状态机设计)
- [5. 核心业务流程](#5-核心业务流程)
- [6. 数据安全设计](#6-数据安全设计)
- [7. 子网路由设计](#7-子网路由设计)
- [8. 组件详细设计](#8-组件详细设计)
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
| **Controller** | `edgelink-controller`| 网络拓扑管理、节点认证授权、配置分发、路径计算、JWT 签发（控制面中心，单点部署） |
| **Relay**      | `edgelink-relay`     | 数据中继、STUN 服务、Relay Mesh 网络、延迟上报（数据面组件） |
| **Client**     | `edgelink-client`    | TUN 虚拟网卡、P2P 直连、加密通信、路由管理、端点发现（数据面去中心化） |

### 1.3 设计原则

| 原则           | 说明                                                       |
| -------------- | ---------------------------------------------------------- |
| **端到端加密** | 数据在源节点加密，仅目标节点可解密，中继服务器无法读取明文 |
| **二进制协议** | 所有 WSS 消息采用紧凑二进制格式，减少传输体积              |
| **状态机驱动** | 各组件使用明确的 FSM 管理连接和会话生命周期                |
| **零信任中继** | Relay 仅转发密文，不参与密钥交换                           |
| **控制面中心化** | Controller 作为控制中心管理认证与配置（单点部署，无状态设计便于故障恢复） |
| **数据面去中心化** | 节点间优先 P2P 直连，Relay 仅作为回退路径              |

### 1.4 Controller 故障恢复

Controller 采用单点部署设计，通过以下机制实现快速故障恢复：

**故障影响分析**：

| Controller 状态 | 已连接节点                         | 新连接节点              |
| --------------- | ---------------------------------- | ----------------------- |
| 正常运行        | 正常通信                           | 正常认证                |
| 临时故障 (<5min)| 继续使用缓存配置，P2P/Relay 正常   | 无法认证，排队等待      |
| 长时间故障      | Relay 保持转发，P2P 缓存有效期内正常 | 无法加入网络            |

**故障恢复策略**：

| 策略               | 说明                                               |
| ------------------ | -------------------------------------------------- |
| 无状态设计         | Controller 不保存会话状态，重启后节点自动重连重认证 |
| SQLite 数据库      | 数据持久化到本地 SQLite，支持快速启动              |
| 定期备份           | 建议每小时备份 data_dir，保留最近 7 天备份         |
| 客户端重连策略     | 指数退避重连 (1s→2s→4s...→60s)，支持多 Controller URL |

**多 Controller URL 配置**：

客户端支持配置多个 Controller URL，按优先级顺序尝试连接：

```toml
[controller]
urls = [
  "wss://controller1.example.com/api/v1/control",
  "wss://controller2.example.com/api/v1/control"  # 备用
]
failover_timeout = 5000  # 切换超时 (毫秒)
```

**注意**：多 URL 仅用于 DNS 故障或网络分区场景的客户端容错，不提供 Controller 自身的高可用。生产环境建议配合外部监控和快速恢复流程。

---

## 2. 高并发设计要求

### 2.1 并发模型

- 使用 Boost.Asio + C++20 Coroutines (awaitable)
- **单 io_context + 多线程** 模型
- 多个线程共同运行同一个 io_context
- 每个 WebSocket 连接对应独立的 read_loop 和 write_loop 协程
- Session 的操作可能在任意线程执行

```
┌─────────────────────────────────────────┐
│           单个 io_context                │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐   │
│  │ Thread 1│ │ Thread 2│ │ Thread N│   │
│  │  run()  │ │  run()  │ │  run()  │   │
│  └─────────┘ └─────────┘ └─────────┘   │
│         ↓         ↓         ↓          │
│  ┌─────────────────────────────────┐   │
│  │    任意 session 的任意操作       │   │
│  │    可能在任意线程执行            │   │
│  └─────────────────────────────────┘   │
└─────────────────────────────────────────┘
```

### 2.2 跨线程通信设计

由于同一 session 的操作可能在不同线程执行，跨 session 通信需要线程安全的机制。

#### concurrent_channel 方案

使用 `boost::asio::experimental::concurrent_channel` 实现无锁线程安全的消息传递：

| 组件         | 说明                                        |
| ------------ | ------------------------------------------- |
| WriteChannel | 每个 Session 拥有一个 concurrent_channel    |
| 生产者       | 任意线程调用 `try_send()` 投递数据          |
| 消费者       | write_loop 协程调用 `async_receive()` 接收  |
| 容量         | 默认 1024 条消息缓冲                        |

```cpp
// Session 写入通道定义
using WriteChannel = asio::experimental::concurrent_channel<
    void(boost::system::error_code, std::vector<uint8_t>)>;
WriteChannel write_channel_;

// 发送数据 (任意线程，无锁)
void send_raw(std::span<const uint8_t> data) {
    write_channel_.try_send(ec, std::vector<uint8_t>(data));
}

// 写入循环 (协程)
awaitable<void> write_loop() {
    while (ws_.is_open()) {
        auto [ec, data] = co_await write_channel_.async_receive();
        co_await ws_.async_write(asio::buffer(data));
    }
}
```

#### 设计优势

| 特性         | 说明                                        |
| ------------ | ------------------------------------------- |
| 无锁         | concurrent_channel 内部使用无锁算法         |
| 类型安全     | 编译期检查消息类型                          |
| 协程友好     | 原生支持 awaitable                          |
| 背压支持     | 通道满时 try_send 返回 false                |

### 2.3 Listener 设计

#### 跨平台方案

| 平台    | 方案                                         |
| ------- | -------------------------------------------- |
| Linux   | 单 acceptor，io_context 多线程自动负载均衡   |
| Windows | 单 acceptor，IOCP 自动分发到工作线程         |
| macOS   | 单 acceptor，kqueue 自动负载均衡             |

### 2.4 背压机制

**concurrent_channel 背压策略**：

| 参数             | 默认值 | 说明                                |
| ---------------- | ------ | ----------------------------------- |
| channel_capacity | 1024   | 通道最大容量 (条消息)               |
| try_send 失败    | 丢弃   | 通道满时丢弃新消息并记录警告        |

**监控指标**：

| 指标                          | 类型      | 说明                |
| ----------------------------- | --------- | ------------------- |
| `channel_full_count`          | Counter   | 通道满导致丢弃次数  |
| `messages_sent_total`         | Counter   | 累计发送消息数      |
| `messages_received_total`     | Counter   | 累计接收消息数      |

### 2.5 无锁设计要求

| 数据结构         | 无锁方案                               |
| ---------------- | -------------------------------------- |
| Session 写入队列 | concurrent_channel (无锁线程安全)      |
| SessionManager   | std::shared_mutex (读多写少场景)       |
| 全局统计计数     | std::atomic                            |
| 配置版本号       | std::atomic<uint64_t>                  |

### 2.7 NodeLocationCache 设计

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

#### 快速迁移优化

为减少节点迁移 (切换 Relay) 时的路由不一致窗口：

**主动通知机制**：

```
节点迁移时:
1. 新 Relay 接受连接后，立即通知 Controller 位置变更
2. Controller 增加位置版本号 (location_version++)
3. Controller 向所有相关 Peer 推送 NODE_LOCATION_UPDATE
4. Peer 收到后立即更新本地缓存 (无需等待 TTL)
```

**版本号比对**：

| 字段             | 说明                                      |
| ---------------- | ----------------------------------------- |
| location_version | 每次迁移递增，拒绝旧版本更新              |
| relay_id         | 当前所在 Relay 的 server_id               |
| timestamp        | 位置更新时间戳                            |

**配置项**：

| 配置项                    | 类型   | 默认值 | 说明                        |
| ------------------------- | ------ | ------ | --------------------------- |
| cache.location_ttl        | uint32 | 60     | 位置缓存 TTL (秒)           |
| cache.location_pull_interval | uint32 | 30  | 增量拉取间隔 (秒)           |
| cache.fast_migration      | bool   | true   | 启用快速迁移通知            |

> **最坏情况**: 快速迁移通知丢失时，仍依赖 TTL (60s) 或转发失败触发更新。

### 2.8 协程使用规范

- 所有 IO 操作必须使用 co_await
- 禁止在协程中进行阻塞调用
- 使用 use_awaitable 作为 completion token
- 使用 co_spawn 启动协程

### 2.9 内存管理

- Session 使用 shared_ptr 管理
- SessionManager 持有 weak_ptr 避免循环引用
- 大缓冲区使用对象池复用

---

## 3. 通信协议

### 3.1 传输层

| 通道                | 协议            | 端点路径          | 用途     | 消息格式 |
| ------------------- | --------------- | ----------------- | -------- | -------- |
| Client ↔ Controller | WebSocket (WSS) | `/api/v1/control` | 控制面   | 二进制   |
| Client ↔ Relay      | WebSocket (WSS) | `/api/v1/relay`   | 数据面   | 二进制   |
| Relay ↔ Controller  | WebSocket (WSS) | `/api/v1/server`  | 服务面   | 二进制   |
| Relay ↔ Relay       | WebSocket (WSS) | `/api/v1/mesh`    | Mesh 面  | 二进制   |
| Client ↔ Client     | UDP             | N/A               | P2P 直连 | 二进制   |

### 3.2 二进制消息帧格式

所有 WebSocket 消息使用 Binary 模式传输，采用以下紧凑格式：

#### 3.2.1 帧头格式 (5 字节)

```
┌──────────┬──────────┬──────────┬─────────────────┐
│ Version  │   Type   │  Flags   │  Payload Length │
│  (1 B)   │  (1 B)   │  (1 B)   │    (2 B BE)     │
└──────────┴──────────┴──────────┴─────────────────┘
```

| 字段    | 大小   | 说明                                     |
| ------- | ------ | ---------------------------------------- |
| Version | 1 字节 | 协议版本，当前 `0x02`                    |
| Type    | 1 字节 | **消息类型** (Frame Type)，见 3.3 节     |
| Flags   | 1 字节 | 标志位                                   |
| Length  | 2 字节 | Payload 长度 (大端序)，最大 **65535**    |

> **Length 上限说明**：Length 字段使用完整的 16 位范围，最大值为 **65535** 字节。未来协议扩展应通过版本号升级处理，而非预留空间。

**Payload 长度限制汇总表**：

| 场景               | 长度限制                 | 计算公式/说明                        |
| ------------------ | ------------------------ | ------------------------------------ |
| 帧 Payload 最大值  | **65535 bytes**          | Length 字段 16 位上限                |
| 分片触发阈值       | **65526 bytes**          | 65535 - 9 (Fragment Header)          |
| 每片最大业务数据   | **65526 bytes**          | 65535 - 9 (Fragment Header)          |
| 加密后最大 Payload | **65499 bytes**          | 65535 - 4 - 4 - 12 - 16 (头部+认证)  |
| DATA 明文最大值    | **65499 bytes**          | 加密 Payload 上限                    |

> **说明**：加密头部包括 Src Node (4B) + Dst Node (4B) + Nonce (12B) + Auth Tag (16B) = 36 bytes。

> **术语约定**：
> - **Frame Type (消息类型)**：帧头中的 Type 字段，标识消息种类（如 AUTH_REQUEST=0x01）
> - **auth_type (认证方式)**：AUTH_REQUEST Payload 中的字段，标识认证方式（如 authkey=0x02）
> - 两者不可混用

#### 3.2.2 Flags 标志位

| 位   | 名称       | 说明                                |
| ---- | ---------- | ----------------------------------- |
| 0x01 | NEED_ACK   | 需要确认，见 3.5.2 节               |
| 0x02 | COMPRESSED | Payload 已压缩 (LZ4)，见 3.5.3 节   |
| 0x04 | ENCRYPTED  | Payload 帧级加密（保留位，见下文）  |
| 0x08 | FRAGMENTED | 分片消息，见 3.5.1 节               |

**ENCRYPTED 标志位说明**：

此标志位当前**保留未使用**。协议中的加密分层如下：

| 层级         | 加密方式                         | 说明                              |
| ------------ | -------------------------------- | --------------------------------- |
| 传输层       | TLS (WSS)                        | 所有 WebSocket 通道均强制使用 TLS |
| 应用层 DATA  | ChaCha20-Poly1305 端到端加密     | DATA (0x20) 类型消息，见 6.3 节   |
| 帧级 Payload | 保留 (ENCRYPTED flag)            | 用于未来控制面消息加密扩展        |

当前控制面消息 (AUTH/CONFIG/P2P 等) 依赖 TLS 传输层加密保护，DATA 消息使用端到端 AEAD 加密（与 ENCRYPTED flag 无关）。

若未来启用 ENCRYPTED flag，将在协议扩展中定义：
- 适用的消息类型范围
- 密钥协商与派生方式
- 与 COMPRESSED flag 的处理顺序

#### 3.2.3 完整帧结构

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

#### 3.2.4 版本兼容性

**版本检查规则**：

| 场景                 | 处理方式                                      |
| -------------------- | --------------------------------------------- |
| Version = 当前版本   | 正常处理                                      |
| Version > 当前版本   | 返回 `UNSUPPORTED_VERSION (2003)` 并关闭连接  |
| Version < 当前版本   | 尝试兼容处理 (见下文)                         |

**向后兼容策略**：

服务端 (Controller/Relay) 应尽可能支持低版本协议：

1. **消息类型兼容**：未识别的 Type 返回 `UNKNOWN_MESSAGE_TYPE (2002)`，但不断开连接
2. **Payload 字段兼容**：
   - 新增字段位于 Payload 末尾，旧版本可忽略
   - 旧版本发送的短 Payload 使用默认值填充缺失字段
3. **功能协商**：通过 CONFIG 消息中的 `capabilities` 字段协商可用功能

**客户端行为**：

- 收到 `UNSUPPORTED_VERSION` 时应提示用户升级
- 不支持版本降级 (客户端不发送低于自身版本的消息)

**版本升级流程**：

新版本发布时，Controller 通过 CONFIG_UPDATE 推送升级建议，客户端可选择：
1. 立即升级重连
2. 继续使用当前版本 (在兼容期内)

### 3.3 消息类型定义 (Frame Type)

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

#### 安全类 (0x90-0x9F)

| Type  | 名称          | 方向                | Payload 格式  |
| ----- | ------------- | ------------------- | ------------- |
| 0x90  | NODE_REVOKE   | Controller → All    | NodeRevoke    |
| 0x91  | NODE_REVOKE_ACK | All → Controller  | NodeRevokeAck |
| 0x92  | NODE_REVOKE_BATCH | Controller → All | NodeRevokeBatch |

#### 生命周期类 (0xA0-0xAF)

| Type  | 名称             | 方向                | Payload 格式     |
| ----- | ---------------- | ------------------- | ---------------- |
| 0xA0  | SHUTDOWN_NOTIFY  | Any → Any           | ShutdownNotify   |
| 0xA1  | SHUTDOWN_ACK     | Any → Any           | ShutdownAck      |

#### 通用类 (0xF0-0xFF)

| Type  | 名称      | 方向 | Payload 格式 |
| ----- | --------- | ---- | ------------ |
| 0xFE  | GENERIC_ACK | 双向 | GenericAck |
| 0xFF  | ERROR     | 双向 | Error        |

### 3.4 二进制 Payload 结构定义

所有 Payload 采用固定字段 + 变长字段的紧凑二进制格式。

#### 3.4.1 通用编码规则

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

#### 3.4.1.1 协议通用常量定义

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

#### 3.4.2 AUTH_REQUEST Payload (Type=0x01)

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
| 0x01         | user    | username (len+str) + password_verifier (32B) |
| 0x02         | authkey | key (len+str)                           |
| 0x03         | machine | 空 (已注册节点重连)                     |

**用户名密码认证流程 (auth_type=0x01)**：

采用挑战-响应机制防止 pass-the-hash 攻击：

```
Client                              Controller
   │  AUTH_REQUEST                       │
   │  [auth_type=0x01,                   │
   │   username, client_nonce]           │
   │─────────────────────────────────────>│
   │                                      │
   │           AUTH_CHALLENGE             │
   │     [server_nonce, salt]             │
   │<─────────────────────────────────────│
   │                                      │
   │           AUTH_VERIFY                │
   │  [password_verifier]                 │
   │─────────────────────────────────────>│
   │                                      │
   │           AUTH_RESPONSE              │
   │     [success, tokens...]             │
   │<─────────────────────────────────────│
```

**password_verifier 计算**：
```
derived_key = PBKDF2-SHA256(password, salt, iterations=100000)
password_verifier = HMAC-SHA256(derived_key, client_nonce || server_nonce)
```

**安全说明**：
- 客户端从不直接发送密码或密码 hash
- 每次认证使用新的 nonce，防止重放攻击
- salt 由服务端针对每个用户生成并存储

**时间戳验证要求**：

| 参数                   | 值       | 说明                                    |
| ---------------------- | -------- | --------------------------------------- |
| 允许时钟偏差           | ±5 分钟  | timestamp 与服务器时间差值上限          |
| 时钟偏差过大错误码     | 1010     | CLOCK_SKEW_TOO_LARGE                    |
| 时间戳防重放窗口       | 10 分钟  | 拒绝超过此时间的旧请求                  |

**验证流程**：
1. 检查 `abs(timestamp - server_time) <= 5 minutes`
2. 若超出范围，返回错误码 1010 并附带服务器时间供客户端参考
3. 检查 (machine_key, timestamp) 对是否已见过（防重放）

**客户端时钟同步建议**：
- 客户端应使用 NTP 同步本地时钟
- 若收到 CLOCK_SKEW_TOO_LARGE 错误，可选择：
  1. 调整本地时钟后重试
  2. 使用服务器返回的时间戳计算偏移量进行补偿

#### 3.4.3 AUTH_RESPONSE Payload (Type=0x02)

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
| virtual_ip  | 4 B  | 分配的虚拟 IPv4 地址 (成功时有效) |
| network_id  | 4 B  | 网络 ID                        |

| auth_token  | 变长 | JWT Auth Token (成功时有效)    |
| relay_token | 变长 | JWT Relay Token (成功时有效)   |
| error_code  | 2 B  | 错误码 (失败时有效)            |
| error_msg   | 变长 | 错误消息 (失败时有效)          |

> **设计说明**: 虚拟网络 IP 地址固定为 IPv4 (4 字节)。这是有意设计：
> - VPN 虚拟网络使用 100.64.0.0/10 (CGNAT) 或 10.0.0.0/8 私有地址空间
> - IPv4 地址空间对于虚拟网络足够使用 (单网络最大 1600 万地址)
> - 简化地址分配和路由表管理
> - SubnetInfo/RouteInfo 中的 IPv6 支持用于通告**物理网络**的子网路由

#### 3.4.3.1 AUTH_CHALLENGE Payload (Type=0x03)

用于双因素认证或额外验证场景。

```
┌────────────┬────────────┬────────────┬────────────┐
│challenge_id│challenge_ty│  expires   │  challenge │
│   (4 B)    │   (1 B)    │   (8 B)    │  (变长)    │
└────────────┴────────────┴────────────┴────────────┘
```

| 字段         | 大小 | 说明                                |
| ------------ | ---- | ----------------------------------- |
| challenge_id | 4 B  | 挑战标识符                          |
| challenge_ty | 1 B  | 挑战类型: 0x01=TOTP, 0x02=SMS, 0x03=Email |
| expires      | 8 B  | 过期时间戳 (毫秒)                   |
| challenge    | 变长 | 挑战数据 (如加密的 nonce)           |

#### 3.4.3.2 AUTH_VERIFY Payload (Type=0x04)

客户端对挑战的响应。

```
┌────────────┬────────────┬────────────┐
│challenge_id│response_len│  response  │
│   (4 B)    │   (2 B)    │  (变长)    │
└────────────┴────────────┴────────────┘
```

| 字段         | 大小 | 说明                      |
| ------------ | ---- | ------------------------- |
| challenge_id | 4 B  | 对应的挑战标识符          |
| response_len | 2 B  | 响应数据长度              |
| response     | 变长 | 响应数据 (如 TOTP 验证码) |

#### 3.4.4 CONFIG Payload (Type=0x10)

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

| 字段         | 大小 | 说明                                |
| ------------ | ---- | ----------------------------------- |
| version      | 8 B  | 配置版本号                          |
| network_id   | 4 B  | 网络 ID                             |
| subnet       | 4 B  | 网络地址 (如 10.0.0.0)              |
| subnet_mask  | 1 B  | 子网掩码位数 (如 8)                 |
| network_name | 变长 | 网络名称                            |
| relay_count  | 2 B  | Relay 服务器数量                    |
| stun_count   | 2 B  | STUN 服务器数量                     |
| peer_count   | 2 B  | Peer 节点数量                       |
| route_count  | 2 B  | 路由数量                            |
| relays[]     | 变长 | RelayInfo 数组 (见 3.4.37)          |
| stuns[]      | 变长 | STUNInfo 数组 (见 3.4.38)           |
| peers[]      | 变长 | PeerInfo 数组 (见 3.4.20)           |
| routes[]     | 变长 | RouteInfo 数组 (见 3.4.18)          |
| relay_token  | 变长 | JWT Relay Token                     |
| expires      | 8 B  | relay_token 过期时间戳 (毫秒)       |

**relay_token 来源说明**：

| 场景                   | relay_token 来源                       | 说明                          |
| ---------------------- | -------------------------------------- | ----------------------------- |
| 首次认证成功           | AUTH_RESPONSE 中的 relay_token         | 初始 token                    |
| 配置推送               | CONFIG 中的 relay_token                | 覆盖已有 token                |
| Token 即将过期刷新     | CONFIG_UPDATE + UPDATE_RELAY_TOKEN 标志 | 仅更新 token，不重发全配置    |

**处理规则**：
- 客户端应始终使用最新收到的 relay_token
- CONFIG 中的 relay_token 优先级高于 AUTH_RESPONSE
- Token 刷新通过 CONFIG_UPDATE (设置 UPDATE_RELAY_TOKEN=0x01) 单独推送

#### 3.4.4.1 CONFIG_UPDATE Payload (Type=0x11)

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

**TOKEN_REFRESH 附加字段**：

当 `update_flags & TOKEN_REFRESH` 时，Payload 末尾追加以下字段：

```
┌────────────────────────────┬────────────┐
│        relay_token         │  expires   │
│      (1B len + bytes)      │   (8 B)    │
└────────────────────────────┴────────────┘
```

| 字段        | 大小 | 说明                               |
| ----------- | ---- | ---------------------------------- |
| relay_token | 变长 | 新的 Relay 访问令牌 (1B 长度前缀)  |
| expires     | 8 B  | 令牌过期时间 (毫秒时间戳)          |

#### 3.4.4.2 CONFIG_ACK Payload (Type=0x12)

客户端确认配置已应用。

```
┌────────────┬────────────┬────────────┬────────────┐
│  version   │   status   │error_count │ error_items│
│   (8 B)    │   (1 B)    │   (2 B)    │  (变长)    │
└────────────┴────────────┴────────────┴────────────┘
```

| 字段        | 大小 | 说明                                  |
| ----------- | ---- | ------------------------------------- |
| version     | 8 B  | 确认的配置版本号                      |
| status      | 1 B  | 0x00=成功, 0x01=部分失败, 0x02=全部失败 |
| error_count | 2 B  | 失败项数量                            |
| error_items | 变长 | 失败项数组 (见下表)                   |

**error_items 结构**：

```
┌────────────┬────────────┬────────────┐
│ item_type  │  item_id   │ error_code │
│   (1 B)    │   (4 B)    │   (2 B)    │
└────────────┴────────────┴────────────┘
```

| item_type | 说明        |
| --------- | ----------- |
| 0x01      | Relay 配置  |
| 0x02      | Peer 配置   |
| 0x03      | Route 配置  |

#### 3.4.5 DATA Payload (Type=0x20，端到端加密)

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
| nonce             | 12 B | 见 6.3.2 节 Nonce 构造规范      |
| encrypted_payload | 变长 | ChaCha20-Poly1305 加密的 IP 包  |
| auth_tag          | 16 B | AEAD 认证标签                   |

**最大加密载荷**：65535 (Frame.Length 上限) - 4 - 4 - 12 - 16 = **65499 字节**

#### 3.4.6 DATA_ACK Payload (Type=0x21)

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

#### 3.4.7 ERROR Payload (Type=0xFF)

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

#### 3.4.8 GENERIC_ACK Payload (Type=0xFE)

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

#### 3.4.9 PING/PONG Payload (Type=0x30/0x31)

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

#### 3.4.9.1 LATENCY_REPORT Payload (Type=0x32)

客户端向 Controller 报告到各 Relay 的延迟。

```
┌────────────┬────────────┬────────────────────────────┐
│ report_cnt │  reports[] │                            │
│   (2 B)    │  (数组)    │                            │
└────────────┴────────────┴────────────────────────────┘
```

**LatencyEntry 结构**：

```
┌────────────┬────────────┬────────────┬────────────┐
│ server_id  │ latency_ms │  jitter_ms │ packet_loss│
│   (4 B)    │   (2 B)    │   (2 B)    │   (1 B)    │
└────────────┴────────────┴────────────┴────────────┘
```

| 字段        | 大小 | 说明                           |
| ----------- | ---- | ------------------------------ |
| report_cnt  | 2 B  | 报告条目数量                   |
| server_id   | 4 B  | Relay 服务器 ID                |
| latency_ms  | 2 B  | 平均延迟 (毫秒)                |
| jitter_ms   | 2 B  | 延迟抖动 (毫秒)                |
| packet_loss | 1 B  | 丢包率 (0-100)                 |

#### 3.4.10 P2P_INIT Payload (Type=0x40)

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

#### 3.4.11 P2P_ENDPOINT Payload (Type=0x41)

```
┌────────────┬────────────┬────────────┬────────────┐
│ init_seq   │ peer_node  │ peer_key   │endpoint_cnt│
│   (4 B)    │   (4 B)    │  (32 B)    │   (2 B)    │
├────────────┴────────────┴────────────┴────────────┤
│                    endpoints[]                    │
│                  (EndpointInfo 数组)              │
└───────────────────────────────────────────────────┘
```

#### 3.4.12 P2P_PING/PONG Payload (Type=0x42/0x43，UDP)

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

#### 3.4.13 P2P_STATUS Payload (Type=0x45)

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

#### 3.4.13.1 P2P_KEEPALIVE Payload (Type=0x44，UDP)

P2P 连接保活消息，双向发送。

```
┌────────────┬────────────┬────────────┬────────────┐
│ timestamp  │  seq_num   │   flags    │    mac     │
│   (8 B)    │   (4 B)    │   (1 B)    │  (16 B)    │
└────────────┴────────────┴────────────┴────────────┘
```

| 字段      | 大小  | 说明                           |
| --------- | ----- | ------------------------------ |
| timestamp | 8 B   | 发送时间戳 (毫秒)              |
| seq_num   | 4 B   | 序列号                         |
| flags     | 1 B   | 标志: 0x01=请求响应, 0x02=响应 |
| mac       | 16 B  | Poly1305 MAC 认证码            |

**MAC 计算**：
- 使用 P2P Session Key 的派生子密钥 (HKDF: info="keepalive-mac")
- 输入: timestamp (8B) + seq_num (4B) + flags (1B) = 13 字节
- 算法: Poly1305 (与数据加密使用相同密钥族)

**安全说明**：MAC 字段防止攻击者伪造 keepalive 包维持虚假连接状态。

**行为规范**：
- 发送间隔: 15 秒 (可配置)
- 超时判定: 连续 3 次无响应视为断开
- 收到 flags=0x01 时，应立即发送 flags=0x02 响应
- MAC 验证失败时丢弃包并记录警告日志

#### 3.4.14 ROUTE_ANNOUNCE Payload (Type=0x80)

```
┌────────────┬────────────┬────────────┬────────────┐
│ request_id │ route_count│  routes[]  │            │
│   (4 B)    │   (2 B)    │ (RouteInfo)│            │
└────────────┴────────────┴────────────┴────────────┘
```

#### 3.4.15 ROUTE_UPDATE Payload (Type=0x81)

```
┌────────────┬────────────┬────────────┬────────────┐
│  version   │ add_count  │ del_count  │ add_routes │
│   (8 B)    │   (2 B)    │   (2 B)    │ (RouteInfo)│
├────────────┴────────────┴────────────┴────────────┤
│                    del_routes[]                   │
│              (RouteIdentifier 数组)               │
└───────────────────────────────────────────────────┘
```

#### 3.4.16 ROUTE_WITHDRAW Payload (Type=0x82)

```
┌────────────┬────────────┬────────────┐
│ request_id │ route_count│  routes[]  │
│   (4 B)    │   (2 B)    │(RouteIdent)│
└────────────┴────────────┴────────────┘
```

#### 3.4.17 ROUTE_ACK Payload (Type=0x83)

```
┌────────────┬────────────┬────────────┐
│ request_id │   status   │error_count │
│   (4 B)    │   (1 B)    │   (2 B)    │
├────────────┴────────────┴────────────┤
│              error_routes[]          │
│        (RouteIdentifier + error_code)│
└──────────────────────────────────────┘
```

#### 3.4.17.1 NODE_REVOKE Payload (Type=0x90)

节点撤销通知，Controller 广播给所有相关节点。

```
┌────────────┬────────────┬────────────┬────────────┐
│revoke_node │  reason    │expires_at  │  signature │
│   (4 B)    │   (1 B)    │   (8 B)    │  (64 B)    │
└────────────┴────────────┴────────────┴────────────┘
```

| 字段        | 大小 | 说明                                        |
| ----------- | ---- | ------------------------------------------- |
| revoke_node | 4 B  | 被撤销的节点 ID                             |
| reason      | 1 B  | 撤销原因 (见下表)                           |
| expires_at  | 8 B  | 撤销生效时间戳 (毫秒)，0=立即生效           |
| signature   | 64 B | Controller 签名 (验证撤销合法性)            |

**撤销原因 (reason)**：

| 值   | 名称            | 说明                        |
| ---- | --------------- | --------------------------- |
| 0x01 | KEY_COMPROMISED | 密钥泄露                    |
| 0x02 | ADMIN_REVOKE    | 管理员主动撤销              |
| 0x03 | POLICY_VIOLATION| 违反安全策略                |
| 0x04 | NODE_REPLACED   | 节点被替换 (重新注册)       |

**签名覆盖范围**：revoke_node + reason + expires_at

**接收方处理**：
1. 验证 signature 使用 Controller 公钥
2. 立即废弃与 revoke_node 的所有 Session Key
3. 将 revoke_node 加入本地黑名单
4. 发送 NODE_REVOKE_ACK 确认

#### 3.4.17.2 NODE_REVOKE_ACK Payload (Type=0x91)

```
┌────────────┬────────────┬────────────┐
│revoke_node │   status   │  node_id   │
│   (4 B)    │   (1 B)    │   (4 B)    │
└────────────┴────────────┴────────────┘
```

| 字段        | 大小 | 说明                        |
| ----------- | ---- | --------------------------- |
| revoke_node | 4 B  | 被撤销的节点 ID             |
| status      | 1 B  | 0x00=已处理, 0x01=签名无效  |
| node_id     | 4 B  | 响应方节点 ID               |

**广播效率优化**：

大规模网络中直接广播会给 Controller 造成压力，采用以下策略：

| 策略               | 说明                                               |
| ------------------ | -------------------------------------------------- |
| Relay 转发         | Controller 发送给 Relay，由 Relay 转发给本地客户端 |
| 增量推送           | 仅推送给与被撤销节点有过通信的节点                 |
| 批量合并           | 短时间内多次撤销合并为单条消息 (revoke_nodes[])    |
| ACK 超时重试       | 未收到 ACK 的节点重试 3 次后标记为离线             |

**扩展: NODE_REVOKE_BATCH Payload (Type=0x92)**：

用于批量撤销场景 (网络安全事件)：

```
┌────────────┬────────────┬────────────┐
│   count    │revoke_nodes│  signature │
│   (2 B)    │ (变长数组) │  (64 B)    │
└────────────┴────────────┴────────────┘
```

每个 revoke_node 条目包含: node_id (4B) + reason (1B) + expires_at (8B) = 13 bytes

#### 3.4.17.3 SHUTDOWN_NOTIFY Payload (Type=0xA0)

用于节点优雅关闭时通知对端，允许对端提前切换路径：

```
┌────────────┬────────────┬────────────┬────────────┐
│  node_id   │   reason   │ drain_time │ timestamp  │
│   (4 B)    │   (1 B)    │   (2 B)    │   (8 B)    │
└────────────┴────────────┴────────────┴────────────┘
```

| 字段       | 大小 | 说明                                   |
| ---------- | ---- | -------------------------------------- |
| node_id    | 4 B  | 即将关闭的节点 ID                      |
| reason     | 1 B  | 关闭原因 (见下表)                      |
| drain_time | 2 B  | 建议迁移时间 (秒)，对端应在此时间内切换 |
| timestamp  | 8 B  | 发送时间戳 (毫秒)                      |

**reason 枚举值**：

| 值   | 名称        | 说明                          |
| ---- | ----------- | ----------------------------- |
| 0x01 | ADMIN       | 管理员主动关闭                |
| 0x02 | UPGRADE     | 软件升级                      |
| 0x03 | MAINTENANCE | 计划维护                      |
| 0x04 | RESOURCE    | 资源不足 (内存/连接数)        |
| 0x05 | FATAL       | 致命错误，即将崩溃            |

**处理流程**：

1. 节点计划关闭时发送 SHUTDOWN_NOTIFY 给所有活跃对端和 Controller
2. 对端收到后在 drain_time 内切换到备用路径 (其他 Relay 或重新打洞)
3. 等待 drain_time 后，发送方可安全关闭连接
4. Controller 收到后标记节点为 draining 状态，不再分配新连接

**配置项**：

| 配置项                    | 类型   | 默认值 | 说明                    |
| ------------------------- | ------ | ------ | ----------------------- |
| shutdown.drain_time       | uint16 | 30     | 默认 drain 时间 (秒)    |
| shutdown.notify_enabled   | bool   | true   | 启用关闭通知            |
| shutdown.wait_for_ack     | bool   | false  | 等待对端 ACK 后再关闭   |

#### 3.4.17.4 SHUTDOWN_ACK Payload (Type=0xA1)

```
┌────────────┬────────────┐
│  node_id   │   status   │
│   (4 B)    │   (1 B)    │
└────────────┴────────────┘
```

| 字段    | 大小 | 说明                              |
| ------- | ---- | --------------------------------- |
| node_id | 4 B  | 响应方节点 ID                     |
| status  | 1 B  | 0x00=收到, 0x01=已切换备用路径    |

#### 3.4.18 RouteInfo 结构 (统一定义)

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

#### 3.4.19 RouteIdentifier 结构

```
┌────────────┬────────────┬────────────┬────────────┐
│  ip_type   │   prefix   │ prefix_len │gateway_node│
│   (1 B)    │ (4/16 B)   │   (1 B)    │   (4 B)    │
└────────────┴────────────┴────────────┴────────────┘
```

#### 3.4.20 PeerInfo 结构

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

#### 3.4.21 EndpointInfo 结构

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

#### 3.4.22 SubnetInfo 结构

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

#### 3.4.23 SERVER_REGISTER Payload (Type=0x50)

Relay 向 Controller 注册。

```
┌────────────┬────────────┬────────────┬────────────┐
│server_token│   name     │   region   │capabilities│
│ (len+bytes)│ (len+str)  │ (len+str)  │   (2 B)    │
├────────────┼────────────┼────────────┼────────────┤
│ public_ip  │public_port │ stun_port  │  version   │
│ (ip_type+ip)│   (2 B)   │   (2 B)    │ (len+str)  │
└────────────┴────────────┴────────────┴────────────┘
```

| 字段         | 大小 | 说明                              |
| ------------ | ---- | --------------------------------- |
| server_token | 变长 | 服务器注册令牌 (JWT)              |
| name         | 变长 | 服务器名称                        |
| region       | 变长 | 区域标识                          |
| capabilities | 2 B  | 能力标志 (0x01=RELAY, 0x02=STUN)  |
| public_ip    | 变长 | 公网 IP (1B ip_type + 4/16B ip)   |
| public_port  | 2 B  | 公网端口                          |
| stun_port    | 2 B  | STUN 端口 (0=未启用)              |
| version      | 变长 | 软件版本                          |

#### 3.4.24 SERVER_REGISTER_RESP Payload (Type=0x51)

```
┌────────────┬────────────┬────────────┬────────────┐
│  success   │ server_id  │ error_code │ error_msg  │
│   (1 B)    │   (4 B)    │   (2 B)    │ (len+str)  │
└────────────┴────────────┴────────────┴────────────┘
```

| 字段       | 大小 | 说明                         |
| ---------- | ---- | ---------------------------- |
| success    | 1 B  | 0x00=失败, 0x01=成功         |
| server_id  | 4 B  | 分配的服务器 ID              |
| error_code | 2 B  | 错误码 (失败时有效)          |
| error_msg  | 变长 | 错误消息 (失败时有效)        |

#### 3.4.25 SERVER_NODE_LOC Payload (Type=0x52)

Controller 通知 Relay 节点位置信息。

```
┌────────────┬────────────┬────────────────────────────┐
│  node_cnt  │  nodes[]   │                            │
│   (2 B)    │  (数组)    │                            │
└────────────┴────────────┴────────────────────────────┘
```

**NodeLocation 结构**：

```
┌────────────┬────────────┬────────────┐
│  node_id   │ server_id  │   flags    │
│   (4 B)    │   (4 B)    │   (1 B)    │
└────────────┴────────────┴────────────┘
```

| 字段      | 大小 | 说明                                |
| --------- | ---- | ----------------------------------- |
| node_id   | 4 B  | 节点 ID                             |
| server_id | 4 B  | 节点连接的 Relay ID (0=未连接)      |
| flags     | 1 B  | 0x01=在线, 0x02=仅此Relay可达       |

#### 3.4.26 SERVER_BLACKLIST Payload (Type=0x53)

Controller 推送黑名单更新。

```
┌────────────┬────────────┬────────────┬────────────┐
│  action    │ entry_cnt  │  entries[] │            │
│   (1 B)    │   (2 B)    │  (数组)    │            │
└────────────┴────────────┴────────────┴────────────┘
```

**BlacklistEntry 结构**：

```
┌────────────┬────────────┬────────────┐
│ entry_type │   value    │ expires_at │
│   (1 B)    │ (变长)     │   (8 B)    │
└────────────┴────────────┴────────────┘
```

| 字段       | 大小 | 说明                                  |
| ---------- | ---- | ------------------------------------- |
| action     | 1 B  | 0x01=添加, 0x02=删除, 0x03=全量替换   |
| entry_type | 1 B  | 0x01=node_id, 0x02=jti, 0x03=ip       |
| value      | 变长 | 根据 entry_type 变化                  |
| expires_at | 8 B  | 过期时间戳 (毫秒, 0=永久)             |

#### 3.4.27 SERVER_HEARTBEAT Payload (Type=0x54)

Relay 向 Controller 发送心跳。

```
┌────────────┬────────────┬────────────┬────────────┐
│ timestamp  │ conn_count │ bandwidth  │  cpu_usage │
│   (8 B)    │   (4 B)    │   (4 B)    │   (1 B)    │
├────────────┼────────────┼────────────┼────────────┤
│ mem_usage  │ queue_len  │            │            │
│   (1 B)    │   (4 B)    │            │            │
└────────────┴────────────┴────────────┴────────────┘
```

| 字段       | 大小 | 说明                     |
| ---------- | ---- | ------------------------ |
| timestamp  | 8 B  | 发送时间戳 (毫秒)        |
| conn_count | 4 B  | 当前连接数               |
| bandwidth  | 4 B  | 当前带宽 (Kbps)          |
| cpu_usage  | 1 B  | CPU 使用率 (0-100)       |
| mem_usage  | 1 B  | 内存使用率 (0-100)       |
| queue_len  | 4 B  | 消息队列长度             |

#### 3.4.28 SERVER_RELAY_LIST Payload (Type=0x55)

Controller 向 Relay 推送其他 Relay 列表。

```
┌────────────┬────────────┬────────────────────────────┐
│ relay_cnt  │  relays[]  │                            │
│   (2 B)    │ (RelayInfo)│                            │
└────────────┴────────────┴────────────────────────────┘
```

#### 3.4.29 SERVER_LATENCY_REPORT Payload (Type=0x56)

Relay 向 Controller 报告到其他 Relay 的延迟。

```
┌────────────┬────────────┬────────────────────────────┐
│ report_cnt │  reports[] │                            │
│   (2 B)    │  (数组)    │                            │
└────────────┴────────────┴────────────────────────────┘
```

**RelayLatencyEntry 结构**：

```
┌────────────┬────────────┬────────────┐
│ server_id  │ latency_ms │   status   │
│   (4 B)    │   (2 B)    │   (1 B)    │
└────────────┴────────────┴────────────┘
```

| 字段       | 大小 | 说明                           |
| ---------- | ---- | ------------------------------ |
| server_id  | 4 B  | 目标 Relay ID                  |
| latency_ms | 2 B  | 平均延迟 (毫秒)                |
| status     | 1 B  | 0x00=不可达, 0x01=可达         |

#### 3.4.30 RELAY_AUTH Payload (Type=0x60)

客户端向 Relay 认证。

```
┌────────────┬────────────┬────────────┐
│relay_token │  node_id   │  node_key  │
│ (len+bytes)│   (4 B)    │  (32 B)    │
└────────────┴────────────┴────────────┘
```

| 字段        | 大小 | 说明                     |
| ----------- | ---- | ------------------------ |
| relay_token | 变长 | JWT Relay Token          |
| node_id     | 4 B  | 客户端节点 ID            |
| node_key    | 32 B | X25519 公钥              |

#### 3.4.31 RELAY_AUTH_RESP Payload (Type=0x61)

```
┌────────────┬────────────┬────────────┐
│  success   │ error_code │ error_msg  │
│   (1 B)    │   (2 B)    │ (len+str)  │
└────────────┴────────────┴────────────┘
```

| 字段       | 大小 | 说明                  |
| ---------- | ---- | --------------------- |
| success    | 1 B  | 0x00=失败, 0x01=成功  |
| error_code | 2 B  | 错误码 (失败时有效)   |
| error_msg  | 变长 | 错误消息 (失败时有效) |

#### 3.4.32 MESH_HELLO Payload (Type=0x70)

Relay 之间建立 Mesh 连接。

```
┌────────────┬────────────┬────────────┬────────────┬────────────┬────────────┐
│ server_id  │mesh_token  │capabilities│  version   │ timestamp  │ signature  │
│   (4 B)    │ (len+bytes)│   (2 B)    │ (len+str)  │   (8 B)    │  (64 B)    │
└────────────┴────────────┴────────────┴────────────┴────────────┴────────────┘
```

| 字段         | 大小 | 说明                               |
| ------------ | ---- | ---------------------------------- |
| server_id    | 4 B  | 发起方 Relay ID                    |
| mesh_token   | 变长 | Mesh 认证令牌 (JWT)                |
| capabilities | 2 B  | 能力标志                           |
| version      | 变长 | 协议版本                           |
| timestamp    | 8 B  | 请求时间戳 (毫秒)                  |
| signature    | 64 B | Ed25519 签名 (Relay Machine Key)   |

**签名计算**：
- 签名覆盖: server_id + mesh_token + capabilities + version + timestamp
- 算法: Ed25519 (使用 Relay 的 Machine Key)

**验证流程**：
1. 验证 mesh_token (JWT) 有效性
2. 验证 signature 使用发起方 Relay 的公钥
3. 检查 timestamp 在 ±5 分钟内

**安全说明**：即使 mesh_token 泄露，攻击者也无法伪造 MESH_HELLO，因为需要 Relay 的 Machine Key 签名。

#### 3.4.33 MESH_HELLO_ACK Payload (Type=0x71)

```
┌────────────┬────────────┬────────────┬────────────┐
│  success   │ server_id  │capabilities│ error_msg  │
│   (1 B)    │   (4 B)    │   (2 B)    │ (len+str)  │
└────────────┴────────────┴────────────┴────────────┘
```

| 字段         | 大小 | 说明                     |
| ------------ | ---- | ------------------------ |
| success      | 1 B  | 0x00=失败, 0x01=成功     |
| server_id    | 4 B  | 响应方 Relay ID          |
| capabilities | 2 B  | 能力标志                 |
| error_msg    | 变长 | 错误消息 (失败时有效)    |

#### 3.4.34 MESH_FORWARD Payload (Type=0x72)

Relay 之间转发数据。

```
┌────────────┬────────────┬────────────┬────────────┐
│  src_node  │  dst_node  │  hop_count │  payload   │
│   (4 B)    │   (4 B)    │   (1 B)    │  (变长)    │
└────────────┴────────────┴────────────┴────────────┘
```

| 字段      | 大小 | 说明                        |
| --------- | ---- | --------------------------- |
| src_node  | 4 B  | 源节点 ID                   |
| dst_node  | 4 B  | 目标节点 ID                 |
| hop_count | 1 B  | 跳数 (防环路，最大 3)       |
| payload   | 变长 | 原始 DATA Payload (加密后)  |

#### 3.4.35 MESH_PING Payload (Type=0x73)

```
┌────────────┬────────────┐
│ timestamp  │  seq_num   │
│   (8 B)    │   (4 B)    │
└────────────┴────────────┘
```

#### 3.4.36 MESH_PONG Payload (Type=0x74)

```
┌────────────┬────────────┐
│ timestamp  │  seq_num   │
│   (8 B)    │   (4 B)    │
└────────────┴────────────┘
```

| 字段      | 大小 | 说明                  |
| --------- | ---- | --------------------- |
| timestamp | 8 B  | 发送时间戳 (毫秒)     |
| seq_num   | 4 B  | 序列号，PONG 原样返回 |

#### 3.4.37 RelayInfo 结构

CONFIG 和 CONFIG_UPDATE 中使用的 Relay 信息结构。

```
┌────────────┬────────────┬────────────┬────────────┐
│ server_id  │   name     │   region   │capabilities│
│   (4 B)    │ (len+str)  │ (len+str)  │   (2 B)    │
├────────────┼────────────┼────────────┼────────────┤
│ public_ip  │public_port │ stun_port  │  priority  │
│(ip_type+ip)│   (2 B)    │   (2 B)    │   (1 B)    │
└────────────┴────────────┴────────────┴────────────┘
```

| 字段         | 大小 | 说明                              |
| ------------ | ---- | --------------------------------- |
| server_id    | 4 B  | 服务器 ID                         |
| name         | 变长 | 服务器名称                        |
| region       | 变长 | 区域标识                          |
| capabilities | 2 B  | 能力标志 (0x01=RELAY, 0x02=STUN)  |
| public_ip    | 变长 | 公网 IP (1B ip_type + 4/16B ip)   |
| public_port  | 2 B  | Relay 端口                        |
| stun_port    | 2 B  | STUN 端口 (0=未启用)              |
| priority     | 1 B  | 优先级 (1=最高)                   |

#### 3.4.38 STUNInfo 结构

CONFIG 中使用的 STUN 服务器信息。

```
┌────────────┬────────────┬────────────┐
│  ip_type   │     ip     │    port    │
│   (1 B)    │ (4/16 B)   │   (2 B)    │
└────────────┴────────────┴────────────┘
```

| 字段    | 大小   | 说明                   |
| ------- | ------ | ---------------------- |
| ip_type | 1 B    | 0x04=IPv4, 0x06=IPv6   |
| ip      | 4/16 B | STUN 服务器 IP         |
| port    | 2 B    | STUN 端口 (默认 3478)  |

### 3.5 协议子规范

#### 3.5.1 分片规范 (FRAGMENTED)

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

**message_id 生成规则**：
- **作用域**: 每个连接独立维护 message_id 计数器
- **生成方式**: 单调递增，每发送一个完整消息（可能分多片）递增 1
- **唯一性键**: (connection_id, src_node, message_id) 构成全局唯一标识
- **回绕处理**: 32 位计数器回绕后从 1 重新开始 (0 保留)
- **并发安全**: 同一连接的 message_id 分配需原子操作

**Payload 区定义**：当 FRAGMENTED=1 时，Fragment Header 被视为 Payload 的一部分。即：Frame Header (5B) 之后的所有内容均为 Payload，Length 字段表示该 Payload 区的总长度。

**分片规则**：

| 规则           | 说明                                       |
| -------------- | ------------------------------------------ |
| 触发条件       | 原始业务 Payload > 65526 字节 (65535 - 9)  |
| 每片最大业务数据 | 65526 字节 (Length 上限 65535 减去 Fragment Header 9B) |
| Frame.Type     | 分片帧的 Type 保持原始消息类型             |
| orig_type      | Fragment Header 中重复记录原始类型 (用于校验) |
| Frame.Flags    | 设置 FRAGMENTED (0x08) 标志                |
| Length 字段    | Fragment Header (9B) + 本片业务数据长度    |
| 重组超时       | 30 秒内未收齐所有分片则丢弃                |
| 重组缓冲区     | 每个 message_id 独立缓冲                   |

**分片内存攻击防护**：

| 限制参数                         | 默认值 | 说明                                |
| -------------------------------- | ------ | ----------------------------------- |
| max_pending_fragments_per_conn   | 10     | 单连接最大未完成分片消息数量        |
| max_fragment_buffer_size_global  | 100MB  | 全局分片缓冲区内存上限              |
| max_fragment_buffer_size_per_conn| 10MB   | 单连接分片缓冲区内存上限            |

**防护策略**：

| 场景                           | 处理方式                              |
| ------------------------------ | ------------------------------------- |
| 超出单连接分片消息数量限制     | 丢弃最旧的未完成分片消息              |
| 超出单连接缓冲区限制           | 返回错误码 2007 (FRAGMENT_LIMIT)      |
| 超出全局缓冲区限制             | 拒绝新分片，返回错误码 4003 (RATE_LIMITED) |
| 收到大量分片首包但无后续       | 30 秒超时后自动清理                   |
| 同一 message_id 分片索引重复   | 丢弃重复分片，记录警告日志            |

**首片预检 (Early Reject)**：

收到首片 (frag_index=0) 时进行预检，防止恶意大 frag_total 导致资源耗尽：

```
on_first_fragment(frag_total, first_payload_len):
    estimated_size = frag_total * 65526  # 最大估算

    if estimated_size > max_fragment_buffer_size_per_conn:
        reject(FRAGMENT_LIMIT, 2007)
        return

    if global_fragment_buffer_used + estimated_size > max_fragment_buffer_size_global:
        reject(RATE_LIMITED, 4003)
        return

    # 预留空间 (实际按需分配)
    reserve_buffer(message_id, min(estimated_size, first_payload_len * frag_total))
```

**解析流程**：
1. 读取 Frame Header (5B)，获取 Length 和 Flags
2. 按 Length 读取 Payload 区
3. 若 Flags & FRAGMENTED，则 Payload[0..9] 为 Fragment Header，Payload[9..] 为本片业务数据
4. 收齐所有分片后，按 frag_index 顺序拼接业务数据，按 orig_type 解析

#### 3.5.2 确认机制 (NEED_ACK)

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

#### 3.5.3 压缩规范 (COMPRESSED)

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

## 4. 状态机设计

### 4.1 Client 连接状态机

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

#### DNS 解析刷新机制

Client 支持定时检查 Controller URL 的 DNS 解析变化，以支持动态 DNS 场景（如服务器 IP 变更、故障转移等）。

**工作流程**：

```
运行中状态:
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│  dns_refresh_loop() 协程                                    │
│                                                             │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐              │
│  │ 等待     │    │ DNS      │    │ 比较     │              │
│  │ 定时器   ├───►│ 解析     ├───►│ 结果     │              │
│  │ (60s)    │    │          │    │          │              │
│  └──────────┘    └──────────┘    └────┬─────┘              │
│                                       │                     │
│                      ┌────────────────┼────────────────┐    │
│                      │ 未变化         │ 已变化         │    │
│                      ▼                ▼                │    │
│                  继续循环        触发 reconnect()      │    │
│                                                        │    │
└────────────────────────────────────────────────────────┘    │
```

**配置参数**：

| 参数                 | 默认值 | 说明                              |
| -------------------- | ------ | --------------------------------- |
| dns_refresh_interval | 60s    | DNS 解析检查间隔 (0 = 禁用)       |

**触发重连条件**：
- 新解析的 IP 地址列表与缓存的不同
- 仅在 `auto_reconnect = true` 时触发重连

**实现细节**：
- 使用异步 DNS 解析 (`tcp::resolver::async_resolve`)
- 解析结果序列化为 "ip:port,ip:port,..." 格式进行比较
- 重连时清空 DNS 缓存，重连成功后重新初始化
- 定时器在 `stop()` 时取消

### 4.2 P2P 连接状态机 (每个对端)

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

#### P2P 发起方决策规则

当双方同时需要通信时，需要确定唯一的打洞发起方，避免重复请求和资源浪费：

```
发起方决策算法:

if self.node_id < peer.node_id:
    role = INITIATOR
    initiate_p2p()
else:
    role = RESPONDER
    wait_for_peer_init(timeout=5s)
    if timeout:
        initiate_p2p()  # 降级为主动发起 (对端可能离线)
```

| 角色        | 行为                                    |
| ----------- | --------------------------------------- |
| INITIATOR   | 主动向 Controller 请求端点，发起打洞   |
| RESPONDER   | 等待对端发起，收到 P2P_PING 后响应     |
| 超时降级    | RESPONDER 等待 5s 无响应则升级为发起方 |

**并发安全**：
- 使用 `min(self.node_id, peer.node_id)` 作为连接锁的 key
- 避免双方同时进入 RESOLVING 状态

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

#### 4.2.1 NAT 类型检测与穿透策略

**NAT 类型检测流程**：

```
1. Client 向 STUN 服务器发送 Binding Request
2. 比较本地地址与 STUN 响应中的映射地址：
   - 相同 → OPEN (无 NAT)
   - 不同 → 继续检测
3. 向不同 STUN 服务器发送请求，比较映射地址：
   - 相同 → Cone NAT (需进一步区分)
   - 不同 → SYMMETRIC NAT
4. 对于 Cone NAT，通过端口变化测试区分类型
```

**不同 NAT 组合穿透策略**：

| 发起方 NAT     | 目标方 NAT     | 穿透难度 | 策略                          |
| -------------- | -------------- | -------- | ----------------------------- |
| OPEN/FULL_CONE | 任意           | 简单     | 直接连接目标端点              |
| RESTRICTED     | OPEN/FULL_CONE | 简单     | 发起方先发包打开映射          |
| RESTRICTED     | RESTRICTED     | 中等     | 双方同时发包                  |
| PORT_RESTRICTED| PORT_RESTRICTED| 困难     | 需精确端口预测 + 多端口探测   |
| SYMMETRIC      | SYMMETRIC      | 极困难   | 放弃穿透，使用 Relay          |
| SYMMETRIC      | 其他           | 困难     | 尝试端口预测，超时后用 Relay  |

**穿透尝试参数**：

| 参数                     | 默认值 | 说明                          |
| ------------------------ | ------ | ----------------------------- |
| hole_punch_attempts      | 5      | 每个端点穿透尝试次数          |
| hole_punch_interval_ms   | 200    | 探测包发送间隔                |
| port_prediction_range    | 10     | Symmetric NAT 端口预测范围    |
| simultaneous_open_delay  | 100ms  | 双方同时发包的同步延迟        |

**穿透失败判定**：

| 条件                           | 处理                          |
| ------------------------------ | ----------------------------- |
| 所有候选端点均超时             | 转入 RELAY_ONLY 状态          |
| 双方均为 SYMMETRIC NAT         | 立即放弃穿透，使用 Relay      |
| 穿透耗时超过 10 秒             | 超时，转入 RELAY_ONLY         |

**P2P 端点优先级规则**：

| 端点类型 | priority 值 | 说明                        |
| -------- | ----------- | --------------------------- |
| LAN      | 1 (最高)    | 本地网络，延迟最低          |
| STUN     | 2           | STUN 探测的公网地址         |
| UPNP     | 3           | UPnP 映射地址               |
| RELAY    | 4 (最低)    | Relay 观测地址，仅作备选    |

**优先级选择算法**：

```
1. 按 priority 升序排列候选端点
2. 同优先级时，优先选择最近发现的 (discovered 时间戳)
3. 同时向多个端点发送探测包
4. 使用首个成功响应的端点建立连接
```

### 4.3 Relay 会话状态机

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

### 4.4 Relay 注册状态机

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

### 4.5 Mesh 连接状态机 (Relay 间)

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

## 5. 核心业务流程

### 5.1 客户端首次认证流程 (AuthKey)

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

### 5.2 数据传输流程 (通过 Relay)

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

### 5.3 P2P 直连建立流程

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

### 5.4 Relay 注册流程

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

### 5.5 Relay Mesh 建立流程

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

## 6. 数据安全设计

### 6.1 端到端加密架构

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

### 6.2 密钥体系

| 密钥类型      | 算法      | 大小    | 用途            | 生命周期          |
| ------------- | --------- | ------- | --------------- | ----------------- |
| Machine Key   | Ed25519   | 256 bit | 设备身份签名    | 永久 (设备绑定)   |
| Node Key      | X25519    | 256 bit | ECDH 密钥交换   | 可轮换 (默认 24h) |
| Session Key   | HKDF 派生 | 256 bit | 数据加密        | 每对节点独立      |
| Ephemeral Key | X25519    | 256 bit | 前向保密 (可选) | 每次会话          |

### 6.3 密钥交换与派生

#### 6.3.1 Session Key 派生

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

#### 6.3.2 Nonce 构造规范

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

#### 6.3.3 会话重建安全规则

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

#### 6.3.4 密钥轮换机制

**Node Key 主动轮换**：

| 触发条件               | 说明                                          |
| ---------------------- | --------------------------------------------- |
| 时间周期               | 默认每 24 小时轮换一次 Node Key               |
| Counter 接近溢出       | 当 Counter 超过 2^63 时提前触发轮换           |
| 管理员强制             | 通过 CLI 命令 `edgelink-client rotate-key`    |
| 安全事件               | 检测到异常时主动触发                          |

**轮换流程**：

```
1. 客户端生成新的 Node Key 对
2. 通过 AUTH_REQUEST (auth_type=machine) 上报新 node_key
3. Controller 验证 Machine Key 签名后更新记录
4. Controller 通过 CONFIG_UPDATE 通知所有相关 Peer 新的 node_key
5. Peer 收到更新后废弃旧 Session Key，使用新 node_key 重新派生
```

**新旧密钥并存期**：

| 参数                     | 默认值 | 说明                                    |
| ------------------------ | ------ | --------------------------------------- |
| key_overlap_period       | 60s    | 新旧密钥并存时间                        |
| old_key_grace_period     | 30s    | 旧密钥仅接收不发送的宽限期              |

**并存期处理规则**：

| 阶段         | 发送使用   | 接收处理                              |
| ------------ | ---------- | ------------------------------------- |
| 新密钥生效前 | 旧密钥     | 仅旧密钥                              |
| 并存期       | 新密钥     | 新旧密钥均可解密                      |
| 宽限期       | 新密钥     | 旧密钥仅接收，收到旧密钥包时提示对端更新 |
| 完全切换后   | 新密钥     | 仅新密钥，旧密钥数据包丢弃            |

**轮换失败回退策略**：

| 失败场景                   | 处理方式                              |
| -------------------------- | ------------------------------------- |
| Controller 无响应          | 保持旧密钥，指数退避重试 (最大 5 分钟)|
| Peer 未收到更新            | 对端使用旧密钥，在宽限期内仍可通信    |
| Session Key 派生失败       | 降级到 Relay 转发，记录错误日志       |

**配置项**：

| 配置项                     | 类型   | 默认值 | 说明                    |
| -------------------------- | ------ | ------ | ----------------------- |
| crypto.key_rotation_interval | uint32 | 86400  | 密钥轮换间隔 (秒)       |
| crypto.key_overlap_period  | uint32 | 60     | 新旧密钥并存时间 (秒)   |
| crypto.key_grace_period    | uint32 | 30     | 旧密钥宽限期 (秒)       |
| crypto.session_key_ttl     | uint32 | 7200   | Session Key 有效期 (秒，默认 2h) |
| crypto.session_rekey_margin | uint32 | 300   | 提前多久开始协商新 Session Key (秒) |

#### 6.3.5 Session Key 独立轮换

除了跟随 Node Key 轮换外，Session Key 还支持独立轮换以增强前向保密：

**触发条件**：

| 条件                   | 说明                                           |
| ---------------------- | ---------------------------------------------- |
| 时间到期               | 超过 session_key_ttl (默认 2h)                 |
| 数据量阈值             | 单 Session 加密超过 1TB 数据                   |
| 提前协商               | 到期前 session_rekey_margin (默认 5min) 开始   |
| 手动触发               | API 调用强制重协商                             |

**轮换流程**：

```
Session Key 轮换 (无需更换 Node Key):

1. 发起方生成新的 Ephemeral X25519 密钥对
2. 发送 REKEY_REQUEST (ephemeral_pub, timestamp, signature)
3. 响应方验证签名，生成响应 Ephemeral Key
4. 双方使用新 Ephemeral Key 执行 ECDH，派生新 Session Key
5. 新旧 Session Key 并存 60s，之后废弃旧密钥
```

**REKEY_REQUEST Payload (Type=0x28)**：

```
┌────────────┬────────────┬────────────┬────────────┐
│ephemeral_pk│ timestamp  │  old_nonce │ signature  │
│   (32 B)   │   (8 B)    │   (12 B)   │   (64 B)   │
└────────────┴────────────┴────────────┴────────────┘
```

| 字段         | 说明                                      |
| ------------ | ----------------------------------------- |
| ephemeral_pk | 新的临时 X25519 公钥                      |
| timestamp    | 请求时间戳 (毫秒)                         |
| old_nonce    | 当前会话最后使用的 nonce (防止重放)       |
| signature    | Ed25519 签名 (使用 Machine Key)           |

**前向保密保证**：
- 每次 Rekey 使用全新 Ephemeral Key，泄露旧 Session Key 不影响新会话
- 参考 WireGuard: 每 2 分钟或 2^60 消息后自动 Rekey

### 6.4 加密数据包格式

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

### 6.5 加密规格

| 项目       | 规格                                            |
| ---------- | ----------------------------------------------- |
| 加密算法   | ChaCha20-Poly1305 (AEAD)                        |
| 密钥长度   | 256 bit                                         |
| Nonce 长度 | 96 bit (12 bytes)                               |
| Auth Tag   | 128 bit (16 bytes)                              |
| 重放保护   | 滑动窗口 (默认 2048 位，可配置)                 |
| 最大加密载荷 | 65535 - 4 - 4 - 12 - 16 = **65499 bytes**     |

**滑动窗口配置**：

| 配置项                      | 默认值 | 范围        | 说明                            |
| --------------------------- | ------ | ----------- | ------------------------------- |
| crypto.replay_window_size   | 2048   | 256-65536   | 滑动窗口大小 (位)               |
| crypto.replay_window_auto   | false  | true/false  | 根据 RTT 自动调整窗口大小       |

**动态窗口调整**：当 `replay_window_auto=true` 时，根据 RTT 动态调整：
- RTT < 50ms: 窗口 = 2048
- RTT 50-200ms: 窗口 = 4096
- RTT > 200ms: 窗口 = 8192

### 6.6 重放攻击防护

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

### 6.7 JWT Token 设计

#### 6.7.1 签名算法

| 算法   | 说明                                          | 推荐场景            |
| ------ | --------------------------------------------- | ------------------- |
| ES256  | ECDSA P-256 + SHA-256 (非对称，**推荐**)      | 生产环境默认        |
| HS256  | HMAC-SHA256 (对称，仅开发环境)                | 单机开发/测试       |

**安全说明**：
- **ES256 (推荐)**：Controller 持有私钥签发 Token，Relay 仅持有公钥验证。即使 Relay 被攻破，攻击者也无法伪造 Token。
- **HS256**：Controller 和 Relay 共享密钥，任一方泄露则整个系统受损。仅用于开发环境。

配置项 `jwt.algorithm` 控制使用的算法，默认 `ES256`。

**HS256 生产环境禁用检查**：

| 配置项                  | 默认值 | 说明                                  |
| ----------------------- | ------ | ------------------------------------- |
| jwt.allow_hs256_prod    | false  | 是否允许生产环境使用 HS256            |
| runtime.environment     | prod   | 运行环境: dev/staging/prod            |

**启动时检查**：
```
if jwt.algorithm == "HS256" && runtime.environment == "prod" && !jwt.allow_hs256_prod:
    log_error("HS256 is not allowed in production environment")
    log_error("Set jwt.algorithm=ES256 or jwt.allow_hs256_prod=true to override")
    exit(1)
```

**安全建议**：生产环境强制使用 ES256，`jwt.allow_hs256_prod` 仅用于特殊场景（需明确记录原因）。

#### 6.7.2 Auth Token (有效期 24 小时)

```
Header: { "alg": "ES256", "typ": "JWT" }
Payload:
{
    "node_id": 12345,
    "network_id": 1,
    "type": "auth",
    "jti": "unique-token-id",  // 用于黑名单
    "iat": 1704787200,
    "exp": 1704873600
}
```

#### 6.7.3 Relay Token (有效期 90 分钟)

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

**jti (JWT ID) 生成规则**：

| 要求           | 说明                                          |
| -------------- | --------------------------------------------- |
| 格式           | UUID v4 (RFC 4122)                            |
| 生成时机       | 每次签发 Token 时生成新的 jti                 |
| 唯一性保证     | 全局唯一，用于 Token 吊销和防重放             |
| 存储           | Auth Token 和 Relay Token 均包含 jti          |

**示例**：`"jti": "550e8400-e29b-41d4-a716-446655440000"`

#### 6.7.4 Token 刷新机制

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

**刷新失败处理策略**：

```
Relay Token 刷新状态机:

[NORMAL] ──过期前10min──► [REFRESHING]
    ▲                          │
    │                    成功   │ 失败
    │◄─────────────────────────┘   │
    │                              ▼
    │                      [RETRY_BACKOFF]
    │                          │
    │   成功                    │ 重试 (1s, 2s, 4s, 8s...)
    │◄─────────────────────────┤
    │                          │ 距过期 < 2min
    │                          ▼
    │                   [RECONNECTING]
    │                          │
    │                          │ 使用 Auth Token 重新认证
    │                          ▼
    │                   [FULL_REAUTH]
    │◄─────────────────────────┘
```

| 状态          | 触发条件            | 处理方式                         |
| ------------- | ------------------- | -------------------------------- |
| REFRESHING    | 过期前 10 分钟      | 发送刷新请求                     |
| RETRY_BACKOFF | 刷新失败            | 指数退避重试 (1s, 2s, 4s, 8s...) |
| RECONNECTING  | 距过期 < 2 分钟     | 断开 Relay，准备重新认证         |
| FULL_REAUTH   | Relay Token 已过期  | 使用 Auth Token 重新完整认证     |

**配置项**：

| 配置项                       | 类型   | 默认值 | 说明                      |
| ---------------------------- | ------ | ------ | ------------------------- |
| token.relay_refresh_margin   | uint32 | 600    | 提前刷新时间 (秒)         |
| token.refresh_retry_max      | uint32 | 5      | 最大重试次数              |
| token.refresh_critical_margin| uint32 | 120    | 紧急重连阈值 (秒)         |

#### 6.7.5 Token 黑名单机制

用于主动吊销尚未过期的 Token (如设备丢失、权限变更)。

**存储方式**：

| 方案         | 说明                                              | 适用场景            |
| ------------ | ------------------------------------------------- | ------------------- |
| 内存 (LRU)   | 基于 `jti` 的 LRU 缓存，默认容量 10000 条         | 开发/测试环境       |
| 数据库       | 持久化存储，支持过期自动清理，重启后自动恢复      | 生产环境（推荐）    |

**黑名单表结构** (数据库方案)：

```sql
CREATE TABLE token_blacklist (
    jti        TEXT      PRIMARY KEY,     -- Token 唯一标识
    node_id    INTEGER   NOT NULL,        -- 关联节点
    reason     TEXT,                       -- 吊销原因
    expires_at INTEGER   NOT NULL,        -- Token 原过期时间
    created_at INTEGER   NOT NULL         -- 加入黑名单时间
);
CREATE INDEX idx_blacklist_expires ON token_blacklist(expires_at);
```

**Controller 重启恢复**：
- Controller 启动时从数据库加载未过期的黑名单到内存缓存
- 新增黑名单时同步写入数据库和本地缓存
- 定时任务清理已过期的黑名单条目 (Token.expires_at < now)
- 重启后所有客户端会自动重连，无需人工干预

**验证流程**：
1. 验证 JWT 签名和过期时间
2. 检查 `jti` 是否在黑名单中
3. 黑名单命中返回错误码 `TOKEN_BLACKLISTED (1003)`

---

## 7. 子网路由设计

### 7.1 概述

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

### 7.2 路由类型

| 类型         | 说明                   | 使用场景            |
| ------------ | ---------------------- | ------------------- |
| **节点路由** | 单个节点的虚拟 IP      | 默认，自动创建      |
| **子网路由** | 通过网关节点访问的子网 | 办公室/数据中心互联 |
| **默认路由** | 0.0.0.0/0 全流量       | Exit Node 模式      |
| **排除路由** | 不走 VPN 的网段        | 本地网络排除        |

### 7.3 路由数据结构

RouteInfo 结构定义见 3.4.18 节，全局统一使用该定义。

### 7.4 路由通告流程

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

### 7.5 路由接受策略

客户端可配置接受哪些子网路由：

| 配置示例                             | 说明               |
| ------------------------------------ | ------------------ |
| `accept = ["*"]`                     | 接受所有路由       |
| `accept = ["192.168.0.0/16"]`        | 仅接受特定子网     |
| `accept = ["*", "!172.16.0.0/12"]`   | 接受所有但排除某些 |

### 7.6 Exit Node 模式

| 步骤               | 说明                         |
| ------------------ | ---------------------------- |
| 启用 Exit Node     | 节点通告 0.0.0.0/0 路由      |
| 配置转发           | 节点启用 IP 转发和 NAT       |
| 使用 Exit Node     | Client 选择并安装默认路由    |
| 排除地址           | 排除 Controller/Relay 和本地子网 |

#### Exit Node 智能选择

当网络中存在多个 Exit Node 时，客户端使用以下算法选择最优出口：

**选择算法**：

```
计算每个 Exit Node 的加权分数:

score = latency * 0.6 + load * 0.3 + distance * 0.1

其中:
- latency: 归一化延迟 (0-100), 基于 LATENCY_REPORT 数据
- load: 归一化负载 (0-100), 基于当前连接数/最大容量
- distance: 归一化地理距离 (0-100), 基于 region 计算

选择 score 最低的 Exit Node
```

**选择模式**：

| 模式          | 说明                                         |
| ------------- | -------------------------------------------- |
| auto          | 自动选择最优 Exit Node (默认)                |
| manual        | 用户手动指定 Exit Node                       |
| nearest       | 仅按延迟选择最近的                           |
| load_balance  | 轮询使用所有可用 Exit Node                   |

**配置项**：

| 配置项                     | 类型   | 默认值 | 说明                       |
| -------------------------- | ------ | ------ | -------------------------- |
| exit_node.selection_mode   | string | "auto" | 选择模式                   |
| exit_node.preferred_region | string | ""     | 优先选择的区域             |
| exit_node.reselect_interval| uint32 | 300    | 重新评估间隔 (秒)          |

**切换策略**：
- 当前 Exit Node 离线时立即切换到次优
- 定期重新评估，避免抖动 (需分数差 > 20% 才切换)

### 7.7 路由冲突处理

| 场景             | 处理策略                     |
| ---------------- | ---------------------------- |
| 子网重叠         | 拒绝后通告的路由，返回 ERROR |
| 相同子网不同网关 | 允许，用于冗余/负载均衡      |
| 更具体路由       | 允许，最长前缀匹配           |
| 节点离线         | 自动故障转移到备用路由       |

**路由通告处理 (Controller 端)**：

检测发生在 Controller 端，使用数据库事务保证原子性：

```sql
-- 原子性检查与插入
BEGIN TRANSACTION;

SELECT gateway_node, enabled FROM routes
WHERE network_id = :network_id
  AND prefix = :prefix
  AND prefix_len = :prefix_len
FOR UPDATE;

-- 根据查询结果决策
-- 若存在且 gateway_node 在线: 拒绝 (ROUTE_CONFLICT 3004)
-- 若存在但离线超过 grace_period: 允许接管
-- 若不存在: 直接插入

COMMIT;
```

**竞争处理规则**：

| 场景                        | 处理方式                                     |
| --------------------------- | -------------------------------------------- |
| 两节点同时通告相同子网      | 先到者获胜 (数据库锁保证)                    |
| 原持有者在线                | 拒绝新通告，返回 ROUTE_CONFLICT (3004)       |
| 原持有者离线 < grace_period | 拒绝新通告，等待原节点可能恢复               |
| 原持有者离线 > grace_period | 允许接管，标记旧路由为 pending_removal       |

**配置项**：

| 配置项                      | 类型   | 默认值 | 说明                        |
| --------------------------- | ------ | ------ | --------------------------- |
| route.conflict_grace_period | uint32 | 60     | 节点离线后路由保留时间 (秒) |
| route.takeover_enabled      | bool   | true   | 是否允许路由接管            |

---

## 8. 组件详细设计

### 8.1 Controller

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
| BuiltinRelay   | 可选的内置 Relay 功能 (不参与 Mesh)             |
| BuiltinSTUN    | 可选的内置 STUN 功能                            |

#### 数据表

| 表名            | 用途               |
| --------------- | ------------------ |
| users           | 用户账号           |
| networks        | 网络定义           |
| nodes           | 节点信息           |
| servers         | Relay/STUN 服务器  |
| routes          | 子网路由           |
| authkeys        | AuthKey 认证密钥   |
| latency_reports | 延迟数据           |
| p2p_connections | P2P 连接状态       |
| endpoints       | 节点端点           |
| user_nodes      | 用户与节点绑定关系 |

#### 数据库配置要求

**SQLite 运行模式**：

| 配置项           | 值          | 说明                                |
| ---------------- | ----------- | ----------------------------------- |
| journal_mode     | WAL         | Write-Ahead Logging，提高并发性能   |
| synchronous      | NORMAL      | 平衡性能与数据安全                  |
| busy_timeout     | 5000        | 锁等待超时 (毫秒)                   |
| foreign_keys     | ON          | 启用外键约束                        |
| cache_size       | -64000      | 64MB 页面缓存                       |

**事务隔离级别**：SQLite 在 WAL 模式下默认使用 SERIALIZABLE 隔离级别。

**并发写入处理**：
- SQLite 同一时间仅允许一个写事务
- 使用连接池管理，写操作排队执行
- 读操作可并发进行（WAL 模式）

**数据库备份策略**：

| 场景               | 备份方式                          |
| ------------------ | --------------------------------- |
| 定期备份           | 使用 SQLite `.backup` 命令        |
| 实时备份           | 复制 WAL 文件 + 主数据库文件      |
| 备份频率           | 建议每日一次完整备份              |
| 备份保留           | 保留最近 7 天备份                 |

**启动时初始化**：

```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA busy_timeout = 5000;
PRAGMA foreign_keys = ON;
PRAGMA cache_size = -64000;
```

#### 节点表 (nodes) 字段

| 字段         | 类型      | 说明                 |
| ------------ | --------- | -------------------- |
| id           | uint32    | 节点 ID              |
| network_id   | uint32    | 所属网络             |
| machine_key  | blob(32)  | Ed25519 公钥         |
| node_key     | blob(32)  | X25519 公钥          |
| virtual_ip   | string    | 虚拟 IP (如 "10.0.0.5")  |
| hostname     | string    | 主机名               |
| os           | string    | 操作系统             |
| arch         | string    | CPU 架构             |
| version      | string    | 客户端版本           |
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

#### AuthKey 表 (authkeys)

> 详细字段定义见 [附录 J: 数据库表定义](#附录-j-数据库表定义) 中的 authkeys 表。

### 8.2 Relay

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

### 8.3 Client

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

| 字段类型     | 处理方式                                |
| ------------ | --------------------------------------- |
| 密钥/Token   | 仅记录前 8 字符 + `...`                 |
| 密码/AuthKey | 使用 `[REDACTED]` 替代                  |
| 加密数据     | 仅记录长度，不记录内容                  |
| IP 地址      | 内网 IP 完整显示，公网 IP **默认脱敏**  |

**IP 脱敏配置**：

| 配置项                    | 默认值 | 说明                                |
| ------------------------- | ------ | ----------------------------------- |
| log.mask_public_ip        | true   | 是否脱敏公网 IP (默认开启)          |
| log.mask_format           | "x.x"  | 脱敏格式: "x.x" → 1.2.x.x           |
| log.mask_exceptions       | []     | 不脱敏的 IP 列表 (调试用)           |

**脱敏示例**：
- 原始: `203.0.113.42` → 脱敏后: `203.0.x.x`
- 内网 IP (`10.x`, `192.168.x`, `172.16-31.x`) 不脱敏
- IPv6 默认显示前 64 位，后 64 位脱敏

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

#### 9.6.5 健康检查端点

Controller、Relay 均提供以下健康检查 HTTP 端点：

| 端点                | 方法 | 说明                                    |
| ------------------- | ---- | --------------------------------------- |
| `/health`           | GET  | 基本存活检查，返回 200 表示进程运行     |
| `/health/live`      | GET  | 存活探针 (Liveness)，进程是否需要重启   |
| `/health/ready`     | GET  | 就绪探针 (Readiness)，是否可接受流量    |

**响应格式**：

```json
{
  "status": "healthy",
  "version": "1.0.0",
  "uptime_seconds": 3600,
  "checks": {
    "database": "ok",
    "controller_connection": "ok"
  }
}
```

**就绪检查依赖项**：

| 组件       | 检查项                                    |
| ---------- | ----------------------------------------- |
| Controller | 数据库连接正常                            |
| Relay      | 数据库 (如有) + Controller 连接正常       |
| Client     | Controller 连接正常 + TUN 设备就绪        |

**HTTP 状态码**：

| 状态码 | 含义                    |
| ------ | ----------------------- |
| 200    | 健康                    |
| 503    | 不健康/未就绪           |

**Kubernetes 集成示例**：

```yaml
livenessProbe:
  httpGet:
    path: /health/live
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 10

readinessProbe:
  httpGet:
    path: /health/ready
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 5
```

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

**通用指标** (所有组件)：

| 指标名                              | 类型      | 标签                    | 说明                    |
| ----------------------------------- | --------- | ----------------------- | ----------------------- |
| `edgelink_info`                     | Gauge     | version, component      | 版本信息 (值恒为 1)     |
| `edgelink_uptime_seconds`           | Gauge     | -                       | 进程运行时间            |
| `edgelink_log_messages_total`       | Counter   | level                   | 各级别日志消息计数      |
| `edgelink_log_dropped_total`        | Counter   | -                       | 队列溢出丢弃的日志数    |

**Controller 指标**：

| 指标名                                    | 类型      | 标签              | 说明                    |
| ----------------------------------------- | --------- | ----------------- | ----------------------- |
| `edgelink_controller_connections_active`  | Gauge     | type=client/relay | 当前活跃连接数          |
| `edgelink_controller_nodes_total`         | Gauge     | status=online/offline | 节点总数            |
| `edgelink_controller_auth_requests_total` | Counter   | result, auth_type | 认证请求计数            |
| `edgelink_controller_config_pushes_total` | Counter   | type              | 配置推送计数            |
| `edgelink_controller_db_queries_total`    | Counter   | operation         | 数据库查询计数          |
| `edgelink_controller_db_latency_seconds`  | Histogram | operation         | 数据库操作延迟          |

**Relay 指标**：

| 指标名                                  | 类型      | 标签              | 说明                    |
| --------------------------------------- | --------- | ----------------- | ----------------------- |
| `edgelink_relay_connections_active`     | Gauge     | type=client/mesh  | 当前活跃连接数          |
| `edgelink_relay_data_bytes_total`       | Counter   | direction=tx/rx   | 传输数据量              |
| `edgelink_relay_packets_total`          | Counter   | direction=tx/rx   | 传输数据包数            |
| `edgelink_relay_forward_latency_seconds`| Histogram | path=local/mesh   | 转发延迟                |
| `edgelink_relay_auth_requests_total`    | Counter   | result            | 客户端认证请求          |
| `edgelink_relay_controller_connected`   | Gauge     | -                 | Controller 连接状态 (0/1)|
| `edgelink_relay_mesh_peers_total`       | Gauge     | -                 | Mesh 连接的 Relay 数量  |

**Client 指标**：

| 指标名                                  | 类型      | 标签              | 说明                    |
| --------------------------------------- | --------- | ----------------- | ----------------------- |
| `edgelink_client_state`                 | Gauge     | state             | 当前状态 (枚举值)       |
| `edgelink_client_peers_total`           | Gauge     | status=p2p/relay  | 对端节点数              |
| `edgelink_client_p2p_success_rate`      | Gauge     | -                 | P2P 打洞成功率          |
| `edgelink_client_data_bytes_total`      | Counter   | direction, path   | 传输数据量              |
| `edgelink_client_latency_seconds`       | Histogram | peer_node, path   | 到各节点延迟            |
| `edgelink_client_controller_latency_seconds` | Gauge | -                | Controller RTT          |
| `edgelink_client_relay_latency_seconds` | Gauge     | relay_id          | Relay RTT               |

**Prometheus 端点**：

| 端点             | 说明                    |
| ---------------- | ----------------------- |
| `/metrics`       | Prometheus 格式指标     |
| 默认端口         | 与主服务同端口          |

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
| 1010 | CLOCK_SKEW_TOO_LARGE| 时钟偏差过大             |
| 2001 | INVALID_FRAME       | 无效帧格式               |
| 2002 | UNKNOWN_MESSAGE_TYPE| 未知消息类型             |
| 2003 | UNSUPPORTED_VERSION | 不支持的协议版本         |
| 2004 | MESSAGE_TOO_LARGE   | 消息过大                 |
| 2005 | FRAGMENT_TIMEOUT    | 分片重组超时             |
| 2006 | FRAGMENT_INVALID    | 无效分片                 |
| 2007 | FRAGMENT_LIMIT      | 分片缓冲区超限           |
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
| Client → Relay      | `wss://relay.example.com:8081`   | `wss://relay.example.com:8081/api/v1/relay`  |
| Relay → Relay       | `wss://relay-b.example.com:8081` | `wss://relay-b.example.com:8081/api/v1/mesh` |

**设计理由**：
- 避免用户配置错误（如遗漏或拼写错误路径）
- 协议版本升级时仅需修改代码，无需更新所有配置
- 简化配置验证逻辑

### 12.1 Controller 配置

| 配置项                   | 类型   | 默认值    | 说明                     |
| ------------------------ | ------ | --------- | ------------------------ |
| http.listen_address      | string | "0.0.0.0" | 监听地址                 |
| http.listen_port         | uint16 | 8080      | 监听端口                 |
| http.public_url          | string | -         | 对外公开 URL (CDN/反代场景) |
| http.enable_tls          | bool   | false     | 启用 TLS                 |
| tls.cert_path            | string | -         | 证书路径                 |
| tls.key_path             | string | -         | 私钥路径                 |
| jwt.algorithm            | string | "ES256"   | 签名算法: ES256(推荐)/HS256 |
| jwt.private_key_path     | string | -         | ES256 私钥路径           |
| jwt.public_key_path      | string | -         | ES256 公钥路径           |
| jwt.secret               | string | -         | HS256 密钥 (开发环境)    |
| jwt.auth_token_ttl       | uint32 | 1440      | Auth Token 有效期(分钟)  |
| jwt.relay_token_ttl      | uint32 | 90        | Relay Token 有效期(分钟) |
| database.path            | string | -         | 数据库路径               |
| builtin_relay.enabled    | bool   | false     | 启用内置 Relay (不参与 Mesh) |
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

**log.modules 配置示例**：

```toml
[log]
level = "info"  # 全局默认等级

[log.modules]
"controller.auth" = "debug"     # 认证模块调试
"controller.ws" = "warn"        # WebSocket 只记录警告
"controller.db" = "info"        # 数据库正常级别
```

| 配置项                   | 类型   | 默认值    | 说明                     |
| ------------------------ | ------ | --------- | ------------------------ |
| worker_threads           | uint32 | 0         | 工作线程数 (0=CPU核心数) |
| control_heartbeat.interval | uint32 | 30      | 控制通道心跳发送间隔 (秒) |
| control_heartbeat.timeout  | uint32 | 90      | 控制通道心跳超时时间 (秒) |
| queue.capacity           | uint32 | 65536     | 消息队列最大容量         |
| queue.high_watermark     | float  | 0.8       | 高水位线 (触发背压)      |
| queue.low_watermark      | float  | 0.5       | 低水位线 (恢复正常)      |
| queue.drop_policy        | string | "oldest"  | 溢出策略: oldest/newest/reject |

### 12.2 Relay 配置

| 配置项                   | 类型   | 默认值    | 说明                     |
| ------------------------ | ------ | --------- | ------------------------ |
| relay.listen_address     | string | "0.0.0.0" | 监听地址                 |
| relay.listen_port        | uint16 | 8081      | 监听端口                 |
| relay.public_url         | string | -         | 对外公开 URL (CDN/反代场景) |
| relay.tls.enabled        | bool   | false     | 启用 TLS                 |
| relay.tls.cert_file      | string | -         | 证书路径                 |
| relay.tls.key_file       | string | -         | 私钥路径                 |
| stun.enabled             | bool   | true      | 启用 STUN                |
| stun.listen_address      | string | "0.0.0.0" | STUN 监听地址            |
| stun.listen_port         | uint16 | 3478      | STUN 监听端口            |
| stun.public_ip           | string | -         | STUN 公网 IP (绕过 CDN)  |
| stun.public_port         | uint16 | -         | STUN 公网端口 (NAT 映射) |
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
| control_heartbeat.interval | uint32 | 30      | 控制通道心跳发送间隔 (秒) |
| control_heartbeat.timeout  | uint32 | 90      | 控制通道心跳超时时间 (秒) |
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
| control_heartbeat.interval | uint32 | 30        | 控制通道心跳发送间隔 (秒)  |
| control_heartbeat.timeout  | uint32 | 90        | 控制通道心跳超时时间 (秒)  |
| reconnect.initial_delay  | uint32   | 1000      | 重连初始延迟 (毫秒)        |
| reconnect.max_delay      | uint32   | 60000     | 重连最大延迟 (毫秒)        |
| reconnect.multiplier     | float    | 2.0       | 重连延迟倍数               |
| p2p.enabled              | bool     | true      | 启用 P2P 直连              |
| p2p.keepalive_interval   | uint32   | 15        | P2P keepalive 间隔 (秒)    |
| p2p.keepalive_timeout    | uint32   | 45        | P2P keepalive 超时 (秒)    |
| p2p.keepalive_miss_limit | uint32   | 3         | P2P keepalive 丢失次数阈值 |
| p2p.stun_timeout         | uint32   | 5000      | STUN 探测超时 (毫秒)       |
| p2p.hole_punch_attempts  | uint32   | 5         | 打洞尝试次数               |
| p2p.hole_punch_interval  | uint32   | 200       | 打洞尝试间隔 (毫秒)        |
| dns_refresh_interval     | uint32   | 60        | DNS 解析刷新间隔 (秒, 0=禁用) |
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

### 12.5 CDN/反向代理部署

当 Controller 或 Relay 部署在 CDN 或反向代理后时，需配置对外公开的 URL。

#### 部署架构

```
  ┌──────────┐                                           ┌──────────┐
  │ Client A │                                           │ Client B │
  └────┬─────┘                                           └────┬─────┘
       │                                                      │
       │ ┌──────────────────────────────────────────────────┐ │
       │ │              CDN (CloudFlare 等)                 │ │
       │ │  ┌─────────────────────────────────────────────┐ │ │
       │ └──┤  WSS 全链路加速                              ├─┘ │
       │    │  • 控制面: Client ↔ Controller              │   │
       │    │  • 数据面: Client ↔ Relay ↔ Client          │   │
       │    └─────────────────┬───────────────────────────┘   │
       │                      │                               │
       │    ┌─────────────────┼───────────────────┐           │
       │    ▼                 ▼                   ▼           │
       │  ┌──────────┐   ┌──────────┐      ┌───────────┐      │
       │  │Controller│   │  Relay   │      │   Relay   │      │
       │  │ :8080    │   │  :8081   │      │   :8081   │      │
       │  └──────────┘   └────┬─────┘      └───────────┘      │
       │                      │                               │
       │                      │ UDP (STUN 直连, 绕过 CDN)     │
       │                      ▼                               │
       │               ┌────────────┐                         │
       │               │ 公网 IP    │◄────────────────────────┘
       │               │ :3478      │   P2P 打洞
       │               └────────────┘
       │                      │
       └──────────────────────┘
              P2P 直连 (打洞成功后)
```

#### 配置说明

| 组件       | 配置项                | 说明                                  |
| ---------- | --------------------- | ------------------------------------- |
| Controller | `http.public_url`     | 客户端连接 URL，下发给客户端配置      |
| Relay      | `relay.public_url`    | 数据链路 URL，注册时上报给 Controller |
| Relay      | `stun.public_ip`      | STUN 公网 IP，绕过 CDN 直连           |
| Relay      | `stun.public_port`    | STUN 公网端口 (如有 NAT 映射)         |

#### 关键约束

1. **WebSocket 全链路可走 CDN**：
   - 控制面：Client ↔ Controller
   - 数据面：Client ↔ Relay ↔ Client (中继转发)
2. **STUN 必须直连**：UDP 打洞需要真实公网 IP，不能走 CDN/代理
3. **P2P 直连不走 CDN**：打洞成功后 Client ↔ Client 直连通信
4. **URL 自动传播**：
   - Controller 的 `public_url` 通过 CONFIG 下发给 Client
   - Relay 的 `public_url` 在 SERVER_REGISTER 时上报，Controller 分发给 Client

#### 示例：CloudFlare CDN 部署

```toml
# controller.toml
[http]
listen_address = "0.0.0.0"
listen_port = 8080
public_url = "wss://vpn.example.com"    # CloudFlare 代理的域名

# relay.toml
[relay]
listen_address = "0.0.0.0"
listen_port = 8081
public_url = "wss://relay-tokyo.example.com"  # CDN 代理 (数据面)

[stun]
enabled = true
listen_port = 3478
public_ip = "203.0.113.10"             # 真实公网 IP (绕过 CDN)
public_port = 3478
```

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
| `--jwt-algorithm` | `ES256`         | JWT 算法: ES256/HS256   |
| `--jwt-private-key`| -              | ES256 私钥路径          |
| `--jwt-public-key` | -              | ES256 公钥路径          |
| `--jwt-secret`    | -               | HS256 密钥 (开发环境)   |
| `--builtin-relay` | `false`         | 启用内置 Relay (不参与 Mesh) |
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
  Language:   C++23
  Platform:   linux/amd64
```

---

### 14.4 命令行交互示例

#### 完整部署流程

```
# 1. 生成 JWT 密钥对 (ES256)
openssl ecparam -genkey -name prime256v1 -out /etc/edgelink/jwt-private.pem
openssl ec -in /etc/edgelink/jwt-private.pem -pubout -out /etc/edgelink/jwt-public.pem

# 2. 初始化并启动 Controller
edgelink-controller init --admin admin --db /var/lib/edgelink/db.sqlite
edgelink-controller serve \
    --jwt-private-key /etc/edgelink/jwt-private.pem \
    --jwt-public-key /etc/edgelink/jwt-public.pem &

# 开发环境可使用 HS256:
# edgelink-controller serve --jwt-algorithm HS256 --jwt-secret "$(openssl rand -hex 32)" &

# 2. 创建 AuthKey
edgelink-controller authkey create --reusable --description "公司设备"
# 输出: tskey-reusable-a7Bn4Kp9zQwX2mLj8RvC6

# 3. 启动 Relay
edgelink-relay serve \
    --controller wss://localhost:8080 \
    --token "relay-token" \
    --name relay-tokyo \
    --region ap-northeast &

# 4. 在客户端设备上连接 (首次注册)
edgelink-client up \
    --controller wss://controller.example.com:8080 \
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
| 示例         | `GIT_TAG ae223d6138807a13006342edfeef32e813f4b9`|
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
# CDN/反向代理场景: 配置对外公开的 URL
# public_url = "wss://vpn.example.com"

[tls]
cert_path = "/etc/edgelink/cert.pem"
key_path = "/etc/edgelink/key.pem"

[jwt]
algorithm = "ES256"                    # 生产环境推荐
private_key_path = "/etc/edgelink/jwt-private.pem"
public_key_path = "/etc/edgelink/jwt-public.pem"
# secret = "your-secret-key-here"     # HS256 开发环境使用
auth_token_ttl = 1440
relay_token_ttl = 90

[database]
path = "/var/lib/edgelink/db.sqlite"

[builtin_relay]
enabled = false                        # 内置 Relay 不参与 Mesh 网络

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
# CDN/反向代理场景: 配置对外公开的 URL (数据链路走 CDN)
# public_url = "wss://relay.example.com"

[relay.tls]
enabled = true
cert_file = "/etc/edgelink/cert.pem"
key_file = "/etc/edgelink/key.pem"

[stun]
enabled = true
listen_address = "0.0.0.0"
listen_port = 3478
# STUN 必须配置真实公网 IP (UDP 打洞不走 CDN)
public_ip = "203.0.113.10"
# 如有 NAT 映射，配置外部端口
# public_port = 3478

[controller]
url = "wss://controller.example.com:8080"
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
controller_url = "wss://controller.example.com:8080"
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
| email          | TEXT      |                           | 邮箱地址                |
| role           | TEXT      | NOT NULL DEFAULT 'user'   | 角色: admin/user        |
| enabled        | INTEGER   | NOT NULL DEFAULT 1        | 是否启用 (0/1)          |
| last_login     | INTEGER   |                           | 最后登录时间 (毫秒时间戳) |
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
| is_exit_node   | INTEGER   | NOT NULL DEFAULT 0        | 是否为 Exit Node        |
| is_gateway     | INTEGER   | NOT NULL DEFAULT 0        | 是否为子网网关          |
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
| description    | TEXT      |                           | 描述 (可选)             |
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
| enabled        | INTEGER   | NOT NULL DEFAULT 1        | 是否启用 (0/1)          |
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

#### user_nodes 表 (用户-节点绑定)

| 列名           | 类型      | 约束                      | 说明                    |
| -------------- | --------- | ------------------------- | ----------------------- |
| id             | INTEGER   | PRIMARY KEY AUTOINCREMENT | 绑定 ID                 |
| user_id        | INTEGER   | NOT NULL REFERENCES users(id) | 用户 ID             |
| node_id        | INTEGER   | NOT NULL REFERENCES nodes(id) | 节点 ID             |
| role           | TEXT      | NOT NULL DEFAULT 'owner'  | 角色: owner/admin/viewer |
| created_at     | INTEGER   | NOT NULL                  | 创建时间 (毫秒时间戳)   |

> UNIQUE 约束: (user_id, node_id) 防止重复绑定。

#### p2p_connections 表

| 列名           | 类型      | 约束                      | 说明                    |
| -------------- | --------- | ------------------------- | ----------------------- |
| id             | INTEGER   | PRIMARY KEY AUTOINCREMENT | 连接 ID                 |
| node_a         | INTEGER   | NOT NULL REFERENCES nodes(id) | 节点 A ID           |
| node_b         | INTEGER   | NOT NULL REFERENCES nodes(id) | 节点 B ID           |
| state          | INTEGER   | NOT NULL                  | 状态枚举 (见下表)       |
| method         | INTEGER   |                           | 打洞方式枚举 (见下表)   |
| relay_id       | INTEGER   | REFERENCES servers(id)    | 中继服务器 (如使用)     |
| rtt_ms         | INTEGER   |                           | 最近测量的 RTT (毫秒)   |
| established_at | INTEGER   |                           | 建立时间 (毫秒时间戳)   |
| last_activity  | INTEGER   |                           | 最后活动时间 (毫秒时间戳) |
| created_at     | INTEGER   | NOT NULL                  | 创建时间 (毫秒时间戳)   |

> UNIQUE 约束: (node_a, node_b) 其中 node_a < node_b (规范化存储)。

**state 枚举值**：

| 值 | 名称        | 说明           |
| -- | ----------- | -------------- |
| 0  | attempting  | 正在尝试连接   |
| 1  | established | 连接已建立     |
| 2  | failed      | 连接失败       |

**method 枚举值**：

| 值 | 名称   | 说明                 |
| -- | ------ | -------------------- |
| 0  | direct | 直接连接 (同一 LAN)  |
| 1  | stun   | STUN 打洞成功        |
| 2  | relay  | 通过 Relay 中继      |

#### 索引定义

```sql
CREATE INDEX idx_nodes_network ON nodes(network_id);
CREATE INDEX idx_nodes_user ON nodes(user_id);
CREATE INDEX idx_nodes_virtual_ip ON nodes(virtual_ip);
CREATE INDEX idx_routes_network ON routes(network_id);
CREATE INDEX idx_routes_prefix ON routes(prefix);
CREATE INDEX idx_authkeys_user ON authkeys(user_id);
CREATE INDEX idx_authkeys_network ON authkeys(network_id);
CREATE UNIQUE INDEX idx_authkeys_key ON authkeys(key);
CREATE INDEX idx_endpoints_node ON endpoints(node_id);
CREATE INDEX idx_latency_node_server ON latency_reports(node_id, server_id);
CREATE UNIQUE INDEX idx_user_nodes_unique ON user_nodes(user_id, node_id);
CREATE INDEX idx_user_nodes_user ON user_nodes(user_id);
CREATE INDEX idx_user_nodes_node ON user_nodes(node_id);
CREATE UNIQUE INDEX idx_p2p_connections_unique ON p2p_connections(node_a, node_b);
CREATE INDEX idx_p2p_connections_node ON p2p_connections(node_a);
CREATE INDEX idx_p2p_connections_state ON p2p_connections(state);
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

### 附录 L: 协议版本升级迁移指南

#### L.1 版本兼容性策略

| 策略             | 说明                                        |
| ---------------- | ------------------------------------------- |
| 向后兼容期       | 新版本发布后，支持旧版本协议至少 6 个月     |
| 版本协商         | 客户端发送支持的最高版本，服务端选择双方支持的最高版本 |
| 强制升级通知     | 低于最低支持版本时，返回 UNSUPPORTED_VERSION (2003) |

#### L.2 从 v0x01 迁移到 v0x02

**主要变更**：

| 变更项           | v0x01                 | v0x02                 |
| ---------------- | --------------------- | --------------------- |
| Payload 格式     | JSON                  | 二进制                |
| 消息类型编号     | 0x01-0x0F             | 按类别分段 (0x00-0xFF)|
| 路由消息         | 不支持                | 新增 ROUTE_* 系列     |
| 分片支持         | 不支持                | 支持 (Flags 0x08)     |

**迁移步骤**：

```
1. 升级 Controller 到支持 v0x02 的版本
   - Controller 自动支持 v0x01 和 v0x02 客户端

2. 逐步升级 Relay 节点
   - 可按区域分批升级
   - 升级后的 Relay 同时支持两种版本

3. 升级客户端
   - 客户端升级后自动使用 v0x02
   - 若 Relay 不支持 v0x02，自动降级到 v0x01

4. 结束兼容期
   - 确认所有客户端已升级后
   - Controller 配置 min_protocol_version = 0x02
   - 拒绝 v0x01 连接
```

**数据库迁移**：v0x01 到 v0x02 无数据库 schema 变更。

#### L.3 版本检测配置

| 配置项                   | 类型   | 默认值 | 说明                    |
| ------------------------ | ------ | ------ | ----------------------- |
| min_protocol_version     | uint8  | 0x01   | 最低支持协议版本        |
| max_protocol_version     | uint8  | 0x02   | 最高支持协议版本        |
| deprecation_warning      | bool   | true   | 向低版本客户端发送升级提示 |

### 附录 M: 故障排查指南

#### M.1 认证失败排查

| 症状                       | 可能原因                | 排查步骤                          |
| -------------------------- | ----------------------- | --------------------------------- |
| 错误码 1001 INVALID_TOKEN  | Token 格式错误          | 检查 Token 是否完整复制           |
| 错误码 1002 TOKEN_EXPIRED  | Token 已过期            | 检查客户端时钟，刷新 Token        |
| 错误码 1004 INVALID_SIGNATURE | 签名验证失败         | 检查 Machine Key 是否匹配         |
| 错误码 1008 AUTHKEY_EXPIRED| AuthKey 已过期          | 创建新的 AuthKey                  |
| 错误码 1010 CLOCK_SKEW     | 时钟偏差过大            | 同步客户端时钟 (NTP)              |

**诊断命令**：

```bash
# 检查客户端状态
edgelink-client status --json

# 查看认证相关日志
edgelink-client log level client.control debug
edgelink-client up 2>&1 | grep -i auth
```

#### M.2 P2P 连接失败排查

| 症状                       | 可能原因                | 排查步骤                          |
| -------------------------- | ----------------------- | --------------------------------- |
| 所有连接走 Relay           | NAT 类型不兼容          | 检查两端 NAT 类型                 |
| 打洞超时                   | 防火墙阻断 UDP          | 检查 UDP 端口是否开放             |
| STUN 查询失败              | STUN 服务器不可达       | 检查 STUN 服务器配置和网络        |
| 间歇性断开                 | NAT 映射超时            | 调整 keepalive 间隔               |

**诊断命令**：

```bash
# 查看对端连接状态
edgelink-client peers --json

# 启用 P2P 调试日志
edgelink-client log level client.p2p trace

# 手动测试 STUN
edgelink-client stun-test <stun-server>
```

#### M.3 延迟异常排查

| 症状                       | 可能原因                | 排查步骤                          |
| -------------------------- | ----------------------- | --------------------------------- |
| 延迟突然升高               | P2P 降级到 Relay        | 检查 P2P 连接状态                 |
| 延迟持续高                 | Relay 选择不优          | 检查延迟上报，手动选择 Relay      |
| 延迟抖动大                 | 网络拥塞                | 检查中间网络质量                  |

**诊断命令**：

```bash
# Ping 指定节点
edgelink-client ping <node-ip> --count 10

# 查看路径选择
edgelink-client status --verbose
```

#### M.4 常用日志模式

| 问题类型         | 建议日志配置                              |
| ---------------- | ----------------------------------------- |
| 认证问题         | `controller.auth=debug`, `client.control=debug` |
| P2P 问题         | `client.p2p=trace`, `relay.stun=debug`    |
| 路由问题         | `controller.route=debug`, `client.route=debug` |
| 性能问题         | `relay.forward=debug`, 启用 Prometheus    |

### 附录 N: 安全加固清单

#### N.1 部署前检查

| 检查项                     | 要求                                    | 验证方法                |
| -------------------------- | --------------------------------------- | ----------------------- |
| TLS 证书有效期             | 剩余有效期 > 30 天                      | `openssl x509 -enddate` |
| TLS 证书链完整             | 包含中间证书                            | SSL Labs 测试           |
| 私钥文件权限               | 600 (仅 owner 可读写)                   | `ls -la`                |
| JWT 密钥安全               | ES256 密钥或足够强度的 HS256 密钥       | 密钥长度检查            |
| 数据库文件权限             | 600 (仅 owner 可读写)                   | `ls -la`                |
| 日志目录权限               | 700 (仅 owner 可访问)                   | `ls -la`                |

#### N.2 运行时安全

| 检查项                     | 要求                                    | 验证方法                |
| -------------------------- | --------------------------------------- | ----------------------- |
| 日志脱敏                   | 无完整密钥/Token 输出                   | 检查日志内容            |
| Token 过期时间             | Auth Token ≤ 24h, Relay Token ≤ 2h      | 检查配置                |
| 认证失败限流               | 启用并配置合理阈值                      | 检查配置                |
| 节点撤销机制               | 可快速撤销泄露节点                      | 测试撤销流程            |

#### N.3 网络安全

| 检查项                     | 要求                                    | 验证方法                |
| -------------------------- | --------------------------------------- | ----------------------- |
| Controller 端口            | 仅开放必要端口 (8080)                   | `netstat`/`ss`          |
| Relay 端口                 | WSS (8081) + STUN UDP (3478)            | `netstat`/`ss`          |
| 防火墙规则                 | 限制源 IP (如适用)                      | 检查防火墙配置          |
| DDoS 防护                  | 启用 CDN 或云防护                       | 检查部署架构            |

#### N.4 监控告警

| 告警项                     | 阈值建议                                |
| -------------------------- | --------------------------------------- |
| 认证失败率                 | > 10% 触发告警                          |
| Controller 响应延迟        | P99 > 500ms 触发告警                    |
| Relay 连接数               | > 80% 容量触发告警                      |
| 证书过期                   | 剩余 < 14 天触发告警                    |
| 磁盘空间 (日志)            | 剩余 < 20% 触发告警                     |

#### N.5 定期审计

| 审计项                     | 频率       | 内容                              |
| -------------------------- | ---------- | --------------------------------- |
| 访问日志审计               | 每日       | 检查异常认证尝试                  |
| 节点清单审计               | 每周       | 确认所有节点为授权设备            |
| AuthKey 审计               | 每月       | 清理过期/未使用的 AuthKey         |
| 依赖库安全更新             | 每月       | 检查并更新有漏洞的依赖            |
| 密钥轮换                   | 每年       | 轮换 JWT 签名密钥                 |

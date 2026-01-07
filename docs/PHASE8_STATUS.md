# Phase 8: Controller 内置功能实现状态

## 完成日期: 2026-01-07

## 概述

Phase 8 实现了 Controller 的内置 Relay 和 STUN 功能，以及完整的 CLI 管理命令（内置到 controller/client），适用于小规模部署场景（< 50 节点）。

## 新增文件

### 1. 内置服务

#### `src/controller/builtin_relay.hpp` / `.cpp`
内置 Relay 实现：
- WebSocket 数据通道 (/ws/data)
- JWT Token 验证 (relay_token)
- 节点会话管理
- 数据帧转发

#### `src/controller/builtin_stun.hpp` / `.cpp`
内置 STUN 实现：
- UDP 3478 端口监听
- STUN Binding Request/Response
- XOR-MAPPED-ADDRESS 属性
- OTHER-ADDRESS 属性 (双 IP NAT 检测)

### 2. CLI 管理命令

#### `src/controller/commands.hpp` / `.cpp`
Controller 内置 CLI 命令：
- 网络管理 (network)
- 节点管理 (node)
- 服务器管理 (server)
- 路由管理 (route)
- Token 管理 (token)
- 状态查看 (status, latency)
- 配置生成 (init)

#### `src/client/main.cpp` (Client CLI)
Client 内置 CLI 命令：
- 连接服务 (connect)
- 密钥生成 (keygen)
- 配置生成 (init)
- 状态查看 (status)

## 修改文件

### 1. `src/controller/main.cpp`
- 添加 CLI 命令路由
- serve 命令启动服务
- 支持静默模式 (-q)

### 2. `src/controller/api/http_server.hpp` / `.cpp`
- 添加 BuiltinRelay 集成
- /ws/data 路径转发到 BuiltinRelay
- HttpSession 传递 BuiltinRelay 指针

### 3. `CMakeLists.txt`
- 添加 commands.cpp
- 移除单独的 edgelink-ctl

## CLI 命令概览

### Controller
```bash
edgelink-controller [options] <command> [args...]

Commands:
  serve         启动服务 (默认)
  network       网络管理 (list, create, show, delete)
  node          节点管理 (list, show, authorize, deauthorize, rename, delete)
  server        服务器管理 (list, add, show, enable, disable, token, delete)
  route         路由管理 (list, add, enable, disable, delete)
  token         Token 管理 (generate, blacklist)
  status        系统状态
  latency       延迟矩阵
  init          生成配置文件

Options:
  -c, --config  配置文件路径
  --db          数据库路径
  -q, --quiet   静默模式
```

### Client
```bash
edgelink-client [options] <command>

Commands:
  connect       连接网络 (默认)
  keygen        生成密钥对
  init          生成配置文件
  status        查看状态

Options:
  -c, --config  配置文件路径
  -u, --url     Controller URL
  -d, --daemon  后台运行
  -q, --quiet   静默模式
```

## 使用示例

```bash
# Controller 端
./edgelink-controller init --output controller.json
./edgelink-controller serve -c controller.json

# 管理操作 (另一终端)
./edgelink-controller -q network create --name main --subnet 10.100.0.0/16
./edgelink-controller -q status
./edgelink-controller -q node list

# Client 端
./edgelink-client keygen
./edgelink-client init --output client.json --url ws://SERVER:8080/ws/control
sudo ./edgelink-client connect -c client.json

# 授权节点
./edgelink-controller -q node authorize 1
```

## 部署架构

```
小规模部署 (< 50 节点):

┌─────────────────────────────────────────┐
│           Controller                     │
│                                         │
│  ┌─────────────┐  ┌─────────────┐       │
│  │ HTTP/WS API │  │ Control WS  │       │
│  │   :8080     │  │ /ws/control │       │
│  └─────────────┘  └─────────────┘       │
│                                         │
│  ┌─────────────┐  ┌─────────────┐       │
│  │BuiltinRelay│  │BuiltinSTUN  │       │
│  │ /ws/data   │  │ UDP :3478   │       │
│  └─────────────┘  └─────────────┘       │
│                                         │
└─────────────────────────────────────────┘
         │                    │
         │ WSS               │ UDP
         ▼                    ▼
    ┌─────────┐          ┌─────────┐
    │ Client A│          │ Client B│
    └─────────┘          └─────────┘
```

## 完成清单

- [x] 内置 Relay 服务
- [x] 内置 STUN 服务
- [x] HTTP Server WebSocket 升级集成 (/ws/data → BuiltinRelay)
- [x] CLI 命令内置到 Controller
- [x] CLI 命令内置到 Client
- [x] 静默模式支持

## 待完善

1. **自动注册到数据库**
   - 内置 Relay/STUN 自动注册到 servers 表

2. **统计信息 API**
   - 暴露内置服务统计数据

3. **JSON 输出格式**
   - CLI 添加 `--json` 选项支持脚本解析

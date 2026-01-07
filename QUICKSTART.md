# EdgeLink 快速开始指南

## 编译

```bash
# 安装依赖 (Ubuntu 24.04)
sudo apt-get install -y cmake build-essential \
  libboost-all-dev libssl-dev libsqlite3-dev \
  libspdlog-dev nlohmann-json3-dev libsodium-dev pkg-config

# 编译
cd edgelink
mkdir build && cd build
cmake ..
make -j$(nproc)
```

## 产出文件

| 文件 | 说明 |
|------|------|
| `edgelink-controller` | 控制器 (服务 + CLI 管理命令) |
| `edgelink-server` | 独立 Relay/STUN 服务器 |
| `edgelink-client` | 客户端 (连接 + CLI 工具) |

## 快速部署 (小规模)

### 1. 初始化 Controller

```bash
# 生成配置（会自动生成 server_token）
./edgelink-controller init --output controller.json
# 输出: Server Token (for relay registration): xxxx

# 编辑配置（设置 external_ip）
vim controller.json

# 启动服务
./edgelink-controller serve -c controller.json
```

### 2. 创建 Auth Key（用于客户端注册）

```bash
# 创建可重复使用的 auth key
./edgelink-controller -q authkey create --network 1 --reusable

# 创建有效期 24 小时的 auth key
./edgelink-controller -q authkey create --network 1 --expires 24

# 查看所有 auth keys
./edgelink-controller -q authkey list
```

### 3. 客户端连接

```bash
# 生成密钥对
./edgelink-client keygen

# 使用 auth key 连接并自动注册
sudo ./edgelink-client connect \
  -u ws://CONTROLLER_IP:8080/ws/control \
  --auth-key YOUR_AUTH_KEY
```

## 注册流程

### 客户端注册（需要 Auth Key）

1. **管理员创建 Auth Key**：
   ```bash
   ./edgelink-controller authkey create --network 1 --reusable
   # 输出: Key: Yiaw1ZJMkdCk78IuvhQOtAMHCrZG81Jt
   ```

2. **分发 Auth Key** 给需要连接的用户

3. **用户使用 Auth Key 连接**：
   ```bash
   ./edgelink-client connect -u ws://controller:8080/ws/control --auth-key YOUR_KEY
   ```

4. **自动完成**: 节点自动注册、分配 IP、无需手动授权

### Relay 服务器注册（需要 Server Token）

Relay 服务器使用配置文件中的 `server_token` 自动注册，无需手动添加：

1. **获取 Server Token**（从 Controller 配置）：
   ```bash
   # Controller 初始化时会生成并显示 server_token
   ./edgelink-controller init --output controller.json
   # 或查看配置文件中的 security.server_token
   ```

2. **配置 Relay 服务器**（server.json）：
   ```json
   {
     "name": "relay-us-west",
     "controller": {
       "url": "ws://controller:8080/ws/server",
       "token": "YOUR_SERVER_TOKEN"
     },
     "relay": {
       "listen_port": 443,
       "external_url": "wss://relay.example.com/ws/data",
       "region": "us-west"
     }
   }
   ```

3. **启动 Relay**：
   ```bash
   ./edgelink-server -c server.json
   # 自动向 Controller 注册
   ```

## CLI 命令

### Controller CLI

```bash
# 系统状态
./edgelink-controller -q status

# 网络管理
./edgelink-controller -q network list
./edgelink-controller -q network create --name prod --subnet 10.200.0.0/16

# Auth Key 管理（用于客户端注册）
./edgelink-controller -q authkey create --network 1 --reusable
./edgelink-controller -q authkey list
./edgelink-controller -q authkey show 1
./edgelink-controller -q authkey delete 1

# 节点管理
./edgelink-controller -q node list [--online]
./edgelink-controller -q node show <id>
./edgelink-controller -q node rename <id> --name "gateway-1"

# 服务器管理（查看自动注册的 Relay）
./edgelink-controller -q server list

# 路由管理
./edgelink-controller -q route list
./edgelink-controller -q route add --cidr 192.168.1.0/24 --node <id>
```

### Client CLI

```bash
# 生成密钥对
./edgelink-client keygen

# 生成配置
./edgelink-client init --output client.json --url ws://controller:8080/ws/control

# 连接（使用 auth key 自动注册）
sudo ./edgelink-client connect -c client.json --auth-key YOUR_KEY

# 后台运行
sudo ./edgelink-client connect -c client.json -d

# 查看状态
./edgelink-client status -c client.json
```

## Auth Key 选项

| 选项 | 说明 |
|------|------|
| `--reusable` | 可多次使用 |
| `--max-uses N` | 最多使用 N 次（需配合 --reusable） |
| `--expires N` | N 小时后过期 |
| `--ephemeral` | 临时节点（离线后自动删除） |

## 架构图

```
┌─────────────────────────────────────────────┐
│              Controller (:8080)              │
│  ┌────────────┐ ┌────────────┐ ┌──────────┐ │
│  │  REST API  │ │Control WS  │ │ Data WS  │ │
│  │  /api/*    │ │/ws/control │ │ /ws/data │ │
│  └────────────┘ └────────────┘ └──────────┘ │
│        │              │              │       │
│        ▼              ▼              ▼       │
│  ┌──────────────────────────────────────┐   │
│  │            SQLite Database            │   │
│  └──────────────────────────────────────┘   │
│                                             │
│  ┌─────────────┐      ┌─────────────┐      │
│  │BuiltinRelay│      │BuiltinSTUN  │      │
│  │ (内置转发)  │      │ (UDP:3478)  │      │
│  └─────────────┘      └─────────────┘      │
└─────────────────────────────────────────────┘
              │                  │
              │ WSS             │ UDP
              ▼                  ▼
        ┌──────────┐      ┌──────────┐
        │ Client A │◄────►│ Client B │
        │(10.100.0.1)     │(10.100.0.2)
        └──────────┘      └──────────┘
```

## 更多文档

- [设计文档](docs/wss-mesh-design.md)

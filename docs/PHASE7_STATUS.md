# Phase 7: 子网路由实现状态

## 完成日期: 2026-01-07

## 概述

Phase 7 实现了完整的子网路由功能，支持：
- 多网关宣告相同子网
- 优先级和权重路由选择
- 最长前缀匹配
- 网关故障转移
- 加权随机负载均衡

## 路由选择算法

按照设计文档实现的路由选择流程：

```
1. 查找所有匹配路由（最长前缀匹配）
2. 按最高优先级筛选
3. 过滤离线网关
4. 同优先级时加权随机选择
```

## 新增/修改文件

### 客户端

1. **`src/client/route_manager.cpp`** - 增强路由查找算法
   - 实现完整的 `lookup()` 函数
   - 最长前缀匹配
   - 优先级筛选
   - 网关在线状态检查
   - 加权随机负载均衡

2. **`src/client/control_channel.hpp`** - 添加子网路由结构
   - `SubnetRouteInfo` 结构体
   - `ConfigUpdate` 添加 `subnet_routes` 和 `recommended_relay_id`

3. **`src/client/control_channel.cpp`** - 解析子网路由
   - `parse_config_update()` 添加 `subnet_routes` 解析

4. **`src/client/client.cpp`** - 处理子网路由
   - `on_config_received()` 添加 `update_subnet_routes()` 调用

### 控制器

5. **`src/controller/api/control_handler.cpp`** - 发送子网路由
   - `generate_config_update()` 添加 `subnet_routes` 数组
   - 包含网关在线状态

## 数据结构

### SubnetRouteInfo (客户端)
```cpp
struct SubnetRouteInfo {
    std::string cidr;           // "192.168.1.0/24"
    uint32_t via_node_id;       // 网关节点ID
    std::string gateway_ip;     // 网关虚拟IP
    uint16_t priority;          // 优先级 (越大越优先)
    uint16_t weight;            // 权重 (同优先级负载均衡)
    bool gateway_online;        // 网关是否在线
};
```

### RouteEntry (客户端路由表)
```cpp
struct RouteEntry {
    std::string network;        // "192.168.1.0"
    uint8_t prefix_len;         // 24
    uint32_t via_node_id;       // 下一跳节点ID
    uint16_t metric;            // 度量值
    bool active;                // 是否激活
    uint16_t weight;            // 权重
    uint16_t priority;          // 优先级
};
```

### NodeRoute (数据库)
```cpp
struct NodeRoute {
    uint32_t id;
    uint32_t node_id;           // 宣告此路由的节点
    std::string cidr;           // "192.168.1.0/24"
    uint16_t priority;          // 默认 100
    uint16_t weight;            // 默认 100
    bool enabled;               // 是否启用
    int64_t created_at;
};
```

## 协议消息

### Config Update (Controller → Client)
```json
{
  "type": "config_update",
  "network": { "cidr": "10.100.0.0/16" },
  "peers": [...],
  "relays": [...],
  "subnet_routes": [
    {
      "cidr": "192.168.1.0/24",
      "via_node_id": 5,
      "gateway_ip": "10.100.0.5",
      "priority": 100,
      "weight": 50,
      "gateway_online": true
    },
    {
      "cidr": "192.168.1.0/24",
      "via_node_id": 6,
      "gateway_ip": "10.100.0.6",
      "priority": 100,
      "weight": 50,
      "gateway_online": true
    },
    {
      "cidr": "192.168.1.0/24",
      "via_node_id": 7,
      "gateway_ip": "10.100.0.7",
      "priority": 50,
      "weight": 100,
      "gateway_online": true
    }
  ],
  "recommended_relay_id": 1
}
```

## 路由选择示例

### 场景：多网关负载均衡

```
Gateway1: 192.168.1.0/24 (priority=100, weight=50, online)
Gateway2: 192.168.1.0/24 (priority=100, weight=50, online)  
Backup:   192.168.1.0/24 (priority=50, weight=100, online)

目标 IP: 192.168.1.100

选择过程:
1. 匹配路由: Gateway1, Gateway2, Backup (全部匹配)
2. 最长前缀: 全部 /24，相同
3. 最高优先级: Gateway1, Gateway2 (priority=100)
4. 网关在线: Gateway1, Gateway2 都在线
5. 加权随机: 50% Gateway1, 50% Gateway2
```

### 场景：故障转移

```
Gateway1: 192.168.1.0/24 (priority=100, OFFLINE)
Backup:   192.168.1.0/24 (priority=50, online)

选择过程:
1. 匹配路由: Gateway1, Backup
2. 最高优先级候选: Gateway1
3. 过滤离线网关: 空
4. 回退到所有候选: Backup
5. 结果: 使用 Backup
```

## 加权随机算法

```cpp
// 计算总权重
uint32_t total_weight = 0;
for (const auto* r : candidates) {
    total_weight += r->weight > 0 ? r->weight : 1;
}

// 随机选择
uint32_t rand_val = rng() % total_weight;
uint32_t cumulative = 0;

for (const auto* r : candidates) {
    cumulative += r->weight > 0 ? r->weight : 1;
    if (rand_val < cumulative) {
        return r->via_node_id;
    }
}
```

## 编译结果

```bash
$ cd /home/claude/edgelink/build && make -j2
[ 29%] Built target edgelink-common
[ 50%] Built target edgelink-server
[ 76%] Built target edgelink-controller
[100%] Built target edgelink-client
```

## 配置和测试

### 1. 添加子网路由（通过API）

```bash
# 添加主网关路由
curl -X POST http://localhost:18080/api/v1/routes \
  -H "Content-Type: application/json" \
  -d '{
    "node_id": 5,
    "cidr": "192.168.1.0/24",
    "priority": 100,
    "weight": 50
  }'

# 添加备份网关路由
curl -X POST http://localhost:18080/api/v1/routes \
  -H "Content-Type: application/json" \
  -d '{
    "node_id": 7,
    "cidr": "192.168.1.0/24",
    "priority": 50,
    "weight": 100
  }'
```

### 2. 查看路由

```bash
# 查看所有路由
curl http://localhost:18080/api/v1/routes

# 查看客户端路由表
# 在客户端日志中观察：
# [info] Updated 3 subnet routes from controller
```

### 3. 测试故障转移

```bash
# 模拟网关离线
# 1. 停止主网关客户端
# 2. 等待心跳超时（约30秒）
# 3. 观察流量自动切换到备份网关
```

## 后续改进

1. **路由缓存**
   - 缓存最近的路由查找结果
   - 定期刷新或基于事件刷新

2. **路由度量**
   - 基于延迟的动态度量
   - 自动调整权重

3. **路由收敛**
   - 更快的故障检测
   - 预计算备用路径

4. **IPv6 支持**
   - 扩展路由表支持 IPv6
   - 双栈网络支持

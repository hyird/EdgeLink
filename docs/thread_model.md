# EdgeLink 线程模型

## 概述

EdgeLink 采用基于 Boost.Asio 的多线程异步架构，结合 Actor 模式实现高并发和任务隔离。

---

## Controller 线程模型

### 架构

**多线程 I/O 线程池模型**

```
┌─────────────────────────────────────────────────────────┐
│                  asio::io_context                       │
│             (concurrency_hint = num_threads)            │
└─────────────────────────────────────────────────────────┘
                         │
        ┌────────────────┼────────────────┐
        │                │                │
   ┌────▼────┐     ┌────▼────┐     ┌────▼────┐
   │ Thread 0│     │ Thread 1│ ... │ Thread N│
   │ (Main)  │     │         │     │         │
   └─────────┘     └─────────┘     └─────────┘
        │                │                │
        └────────────────┼────────────────┘
                         │
            所有线程共享同一个 io_context
```

### 实现细节 (src/controller/main.cpp:672-762)

```cpp
// 1. 创建多线程 io_context
asio::io_context ioc(static_cast<int>(cfg.num_threads));

// 2. 线程数自动检测
if (cfg.num_threads == 0) {
    cfg.num_threads = std::thread::hardware_concurrency();
    if (cfg.num_threads == 0) cfg.num_threads = 4;
}

// 3. 启动工作线程池
std::vector<std::thread> threads;
threads.reserve(cfg.num_threads - 1);

for (size_t i = 1; i < cfg.num_threads; ++i) {
    threads.emplace_back([&ioc] {
        ioc.run();
    });
}

// 4. 主线程也参与工作
ioc.run();

// 5. 等待所有线程
for (auto& t : threads) {
    t.join();
}
```

### 线程配置

**默认值**: `std::thread::hardware_concurrency()` (通常为 CPU 核心数)

**配置方式**:
- 命令行: `--threads N` 或 `-t N`
- 配置文件: `num_threads = N`
- 环境变量: 不支持

**推荐配置**:
- **轻量负载** (< 100 客户端): 2-4 线程
- **中等负载** (100-1000 客户端): 4-8 线程
- **高负载** (> 1000 客户端): 8-16 线程

### 线程安全

**并发机制**:
- **Session**: 每个客户端一个 Session Actor，使用独立 strand 串行化
- **SessionManager**: 使用 `concurrent_channel` 跨线程安全通信
- **Database**: SQLite 使用内部锁，支持多线程读写
- **WebSocket**: 每个连接的读写操作由 strand 保护

**无需加锁的场景**:
- 单个 Session 内的操作（strand 保证）
- Actor 邮箱操作（concurrent_channel 内部线程安全）

**需要加锁的场景**:
- SessionManager 的全局状态访问（已使用 mutex）
- 数据库访问（SQLite 内部已处理）

---

## Client 线程模型

### 架构

**单线程事件循环模型**

```
┌─────────────────────────────────────────────────────────┐
│                  asio::io_context                       │
│                  (单线程运行)                            │
└─────────────────────────────────────────────────────────┘
                         │
                    ┌────▼────┐
                    │  Main   │
                    │ Thread  │
                    └─────────┘
                         │
        ┌────────────────┼────────────────┐
        │                │                │
    ┌───▼───┐       ┌───▼───┐       ┌───▼───┐
    │Control│       │ Relay │       │ P2P   │
    │ Actor │       │ Actor │       │Manager│
    └───────┘       └───────┘       └───────┘
        │                │                │
        └────────────────┼────────────────┘
                         │
              所有 Actor 共享单线程
```

### 实现细节 (src/client/main.cpp:891-1083)

```cpp
// 1. 创建单线程 io_context
asio::io_context ioc;  // 默认 concurrency_hint = 1

// 2. 使用 work_guard 防止提前退出
auto work_guard = asio::make_work_guard(ioc);

// 3. 启动所有协程和 Actor
asio::co_spawn(ioc, client->start(), asio::detached);
asio::co_spawn(ioc, event_handler_1(), asio::detached);
asio::co_spawn(ioc, event_handler_2(), asio::detached);
// ...

// 4. 在主线程运行事件循环
ioc.run();  // 阻塞直到所有工作完成
```

### 线程配置

**当前实现**: 硬编码单线程
**配置方式**: 无配置选项（未来可扩展）

### 为什么使用单线程？

**优点**:
1. **简化设计**: 无需考虑跨线程同步
2. **性能充足**:
   - 单个客户端通常只需处理少量连接（1-2 Controller + N Peers）
   - I/O 密集而非 CPU 密集
   - 协程天然高并发，单线程可轻松处理数千并发操作
3. **更低延迟**: 避免线程切换开销
4. **调试友好**: 单线程更容易调试和追踪

**局限性**:
- CPU 密集型任务会阻塞整个事件循环
- 无法利用多核 CPU（但客户端通常不需要）

---

## ActorSystem 线程模型（框架实现）

虽然 Controller 和 Client 当前**未使用** ActorSystem，但框架已实现完整的多线程 Actor 系统供未来扩展。

### 架构

**双层线程池模型**

```
┌────────────────────────────────────────────────────────────┐
│                    ActorSystem                             │
├────────────────────────────────────────────────────────────┤
│                                                            │
│  通用工作线程池 (Worker Threads)                           │
│  ┌────────┬────────┬────────┬────────┐                    │
│  │Thread 0│Thread 1│Thread 2│Thread N│                    │
│  └────────┴────────┴────────┴────────┘                    │
│              所有 Actor 默认在此运行                        │
│                                                            │
│  高优先级线程池 (High-Priority Threads)                    │
│  ┌────────┐                                               │
│  │  HP-0  │  独立 io_context，用于 DataPlane             │
│  └────────┘                                               │
│                                                            │
│  ActorRouter (消息路由表)                                  │
│  ┌──────────────────────────────────────┐                │
│  │ /client/control → ControlActor       │                │
│  │ /client/data    → DataPlaneActor     │                │
│  │ /server/session → SessionActor       │                │
│  └──────────────────────────────────────┘                │
└────────────────────────────────────────────────────────────┘
```

### 实现细节 (src/common/actor_system.hpp:115-295)

```cpp
struct Config {
    size_t worker_threads = std::thread::hardware_concurrency();
    size_t high_priority_threads = 1;
    bool enable_cpu_affinity = false;
};

void start() {
    // 1. 启动通用工作线程池
    for (size_t i = 0; i < config_.worker_threads; ++i) {
        workers_.emplace_back([this, i]() {
            set_thread_name("actor-worker-" + std::to_string(i));
            ioc_.run();
        });
    }

    // 2. 启动高优先级线程（独立 io_context）
    for (size_t i = 0; i < config_.high_priority_threads; ++i) {
        high_priority_workers_.emplace_back([this, i]() {
            set_thread_name("actor-hp-" + std::to_string(i));
            set_thread_priority_high();  // Windows: THREAD_PRIORITY_ABOVE_NORMAL

            asio::io_context high_priority_ioc(1);
            asio::io_context::work work(high_priority_ioc);
            high_priority_ioc.run();
        });
    }
}
```

### 特性

**线程亲和性** (Linux only):
- 可选启用 `enable_cpu_affinity = true`
- 将工作线程绑定到特定 CPU 核心
- 提高缓存局部性

**线程优先级**:
- 高优先级线程使用 `THREAD_PRIORITY_ABOVE_NORMAL` (Windows)
- 用于关键路径（如 DataPlaneActor）

**命名线程**:
- `actor-worker-N`: 通用工作线程
- `actor-hp-N`: 高优先级线程
- 方便调试和性能分析

---

## Actor 并发模型

### Strand 隔离

每个 Actor 拥有独立的 strand，保证消息串行处理：

```cpp
class ActorBase {
    asio::strand<asio::io_context::executor_type> strand_;

    asio::awaitable<void> message_loop() {
        while (running_) {
            auto msg = co_await mailbox_.receive();  // 阻塞等待消息
            // 在 strand 中串行处理，无需加锁
            co_await handle_message(msg);
        }
    }
};
```

**特性**:
- 同一 Actor 的消息处理永远不会并发
- 不同 Actor 可以在不同线程并发执行
- 避免锁竞争，无需手动同步

### Channel 通信

**两种 Channel**:

1. **channel** (单线程场景):
   ```cpp
   asio::experimental::channel<void(error_code, MessageType)>
   ```
   - 无锁，零拷贝
   - 只能在同一个 executor 中使用
   - 性能最佳

2. **concurrent_channel** (跨线程场景):
   ```cpp
   asio::experimental::concurrent_channel<void(error_code, MessageType)>
   ```
   - 线程安全的内部队列
   - 可在不同 strand/线程间通信
   - 轻微性能开销（~10-20ns）

**使用原则**:
- 同 strand 内 Actor 通信 → 使用 `channel`
- 跨 strand Actor 通信 → 使用 `concurrent_channel`
- 主循环与 Actor 通信 → 使用 `concurrent_channel`

---

## 性能对比

| 场景 | Controller (多线程) | Client (单线程) | ActorSystem (可选) |
|------|-------------------|----------------|-------------------|
| **并发客户端** | 1000+ | 1 | 可扩展 |
| **CPU 利用率** | 多核 100% | 单核 100% | 多核可配置 |
| **延迟** | 50-100μs | 20-50μs | 50-100μs |
| **吞吐** | > 100K ops/s | > 10K ops/s | > 50K ops/s |
| **内存开销** | ~8MB/线程 | ~4MB | ~8MB/线程 |
| **线程切换** | 频繁 | 无 | 可控 |
| **调试复杂度** | 高 | 低 | 中 |

---

## 最佳实践

### Controller 端

1. **根据负载调整线程数**:
   ```bash
   # 轻量场景
   edgelink-controller serve -t 2

   # 高负载场景
   edgelink-controller serve -t 16
   ```

2. **避免阻塞操作**:
   - 所有 I/O 使用异步接口（Boost.Asio）
   - 长时间计算使用 `asio::post` 到后台线程
   - 数据库操作已优化（SQLite 多线程模式）

3. **监控线程池饱和度**:
   - 使用 `perf top` 查看 CPU 使用率
   - 如果所有线程 100% 忙碌，考虑增加线程数

### Client 端

1. **保持单线程简洁**:
   - 避免 CPU 密集型计算（如大数据加密）
   - 使用协程而非回调（更易理解）

2. **合理设置 Channel 容量**:
   ```cpp
   // DataPlane 高吞吐
   data_plane_event_ch_ = std::make_unique<...>(ioc_, 256);

   // 控制消息低频
   control_event_ch_ = std::make_unique<...>(ioc_, 128);
   ```

3. **避免阻塞主事件循环**:
   - TUN 读写使用异步接口
   - 避免同步 DNS 解析（使用 asio::async_resolve）

### Actor 开发

1. **选择正确的 Channel**:
   ```cpp
   // 同 strand 内
   asio::experimental::channel<...>

   // 跨 strand
   asio::experimental::concurrent_channel<...>
   ```

2. **控制邮箱容量**:
   - 高频消息：256-512
   - 中频消息：64-128
   - 低频消息：16-32

3. **避免死锁**:
   - Actor 间通信只能单向或使用 request/response 模式
   - 避免循环等待（A 等 B，B 等 A）

---

## 未来扩展

### Client 多线程支持（规划）

```cpp
struct ClientConfig {
    size_t num_threads = 1;  // 默认单线程
    bool enable_data_plane_thread = false;  // 独立数据面线程
};

// 如果启用多线程：
// Thread 0: 控制面 (Control, Relay)
// Thread 1: 数据面 (DataPlane, TUN, P2P)
```

**优点**:
- 控制面和数据面完全隔离
- 数据面不受控制消息影响

**实现步骤**:
1. 创建独立 io_context 用于数据面
2. DataPlaneActor 迁移到新 io_context
3. 使用 concurrent_channel 跨线程通信

### Controller 动态线程池（规划）

```cpp
// 根据负载动态调整线程数
if (active_sessions > 1000 && threads < 8) {
    add_worker_thread();
}

if (active_sessions < 100 && threads > 2) {
    remove_worker_thread();
}
```

---

## 总结

| 组件 | 模型 | 线程数 | 适用场景 |
|------|------|--------|---------|
| **Controller** | 多线程 I/O 池 | auto (CPU 核心数) | 高并发服务端 |
| **Client** | 单线程事件循环 | 1 (固定) | 单用户客户端 |
| **ActorSystem** | 双层线程池 | 可配置 | 框架支持（未使用） |

**核心设计理念**:
- Controller: 多线程最大化吞吐和并发处理能力
- Client: 单线程最小化复杂度和延迟
- Actor 模式: Strand + Channel 实现安全并发

**性能关键路径**:
- 数据转发：DataPlaneActor (可配置高优先级线程)
- TUN 读写：TunDeviceActor (可配置独立线程)
- P2P 收发：P2PManagerActor (UDP 高性能)

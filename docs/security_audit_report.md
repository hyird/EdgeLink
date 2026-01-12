# EdgeLink 安全审计报告 - UAF/Double-Free/竞态条件

## 审计日期: 2026-01-12

## 执行摘要

在多线程实现后进行的全面代码审计中，发现了 **11 个严重的内存安全问题**，主要涉及：
- Use-After-Free (UAF)
- 潜在的 Double-Free
- 多线程竞态条件

所有问题都与 **裸指针 `this` 在异步上下文中的捕获** 有关。

## 问题分类

### 严重级别: CRITICAL (需要立即修复)

#### 1. client_actor.cpp - 5 个 Detached 协程 UAF

**位置**: src/client/client_actor.cpp:371-389

**代码**:
```cpp
asio::co_spawn(ioc_, [this]() -> asio::awaitable<void> {
    co_await control_actor_->start();
}, asio::detached);

asio::co_spawn(ioc_, [this]() -> asio::awaitable<void> {
    co_await relay_actor_->start();
}, asio::detached);

asio::co_spawn(ioc_, [this]() -> asio::awaitable<void> {
    co_await data_plane_actor_->start();
}, asio::detached);

asio::co_spawn(ioc_, [this]() -> asio::awaitable<void> {
    co_await p2p_actor_->start();
}, asio::detached);

asio::co_spawn(ioc_, [this]() -> asio::awaitable<void> {
    co_await tun_actor_->start();
}, asio::detached);
```

**问题**:
- `ClientActor` 对象可能在协程完成前析构
- 多线程环境下，`ioc.stop()` 强制停止时触发 UAF
- 访问已销毁的 `control_actor_`, `relay_actor_` 等成员

**影响**:
- SEGFAULT (signal 11)
- 内存损坏
- 进程崩溃

**修复**:
```cpp
asio::co_spawn(ioc_, [self = this->shared_from_this()]() -> asio::awaitable<void> {
    co_await self->control_actor_->start();
}, asio::detached);
```

---

#### 2. ipc_server.cpp - Detached 协程 UAF

**位置**: src/client/ipc_server.cpp:367-370

**代码**:
```cpp
asio::co_spawn(ioc_, [this, ip, promise]() -> asio::awaitable<void> {
    uint16_t latency = co_await client_.ping_ip(ip);
    promise->set_value(latency);
}, asio::detached);
```

**问题**:
- `IpcServer` 对象可能在 ping 完成前析构
- 访问已销毁的 `client_` 引用

**影响**:
- UAF 在 CLI 命令执行期间
- 可能影响 `edgelink-client ping` 命令

**修复**:
```cpp
asio::co_spawn(ioc_, [self = shared_from_this(), ip, promise]() -> asio::awaitable<void> {
    uint16_t latency = co_await self->client_.ping_ip(ip);
    promise->set_value(latency);
}, asio::detached);
```

---

#### 3. tun_windows.cpp - 线程 UAF (最危险)

**位置**: src/client/tun_windows.cpp:193-195

**代码**:
```cpp
read_thread_ = std::thread([this]() {
    read_loop();
});
```

**问题**:
- `WinTunDevice` 是 `unique_ptr` 持有，不是 `shared_ptr`
- `stop_read()` 只等待线程 join，但线程可能在 `TunDevice` 析构后继续访问成员
- Windows 事件同步可能失败，导致线程卡住

**影响**:
- **最危险的 UAF**：线程生命周期独立于对象
- 可能导致持续的内存访问错误
- Windows 特定问题，难以在 Linux 上复现

**修复方案**:
1. **立即修复**: 使用 `std::shared_ptr<WinTunDevice>` 并捕获
2. **长期方案**: 重构为无线程架构（使用 Asio 异步 I/O）

**临时修复**:
```cpp
// 需要改造 TunDevice 为 shared_ptr 管理
auto self = shared_from_this(); // 需要继承 enable_shared_from_this
read_thread_ = std::thread([self]() {
    self->read_loop();
});
```

---

#### 4. tun_windows.cpp - asio::post UAF

**位置**: src/client/tun_windows.cpp:302-306

**代码**:
```cpp
asio::post(ioc_, [this, data = std::move(data)]() {
    if (packet_channel_) {
        packet_channel_->try_send(boost::system::error_code{}, std::move(const_cast<std::vector<uint8_t>&>(data)));
    }
});
```

**问题**:
- `WinTunDevice` 可能在 `post` 执行前析构
- 访问已销毁的 `packet_channel_`

**影响**:
- TUN 数据包接收时崩溃
- 高吞吐场景下更容易触发

**修复**: 同样需要 `shared_from_this()`

---

#### 5. tun.cpp (Linux) - async_read_some 回调 UAF

**位置**: src/client/tun.cpp:243-255

**代码**:
```cpp
fd_.async_read_some(
    asio::buffer(read_buffer_),
    [this](const boost::system::error_code& ec, size_t bytes) {
        if (ec) { ... }
        if (packet_channel_) {
            packet_channel_->try_send(...);
        }
        start_read(); // 递归调用
    }
);
```

**问题**:
- `TunDevice` 析构后，异步读回调可能被触发
- 访问 `packet_channel_` 和 `read_buffer_`

**影响**:
- Linux 特定 UAF
- 递归调用 `start_read()` 加剧问题

**修复**: 需要 `shared_from_this()`

---

#### 6. tun_macos.cpp (macOS) - async_read_some 回调 UAF

**位置**: src/client/tun_macos.cpp:230-242

**代码**: 与 tun.cpp 相同

**问题**: 与 tun.cpp 相同

**影响**: macOS 特定 UAF

**修复**: 需要 `shared_from_this()`

---

### 严重级别: HIGH (存在风险但影响有限)

#### 7. p2p_manager.cpp - 局部 Lambda (低风险)

**位置**: src/client/p2p_manager.cpp:72

**代码**:
```cpp
auto reset_starting = [this]() { starting_ = false; };
```

**问题**:
- 这是一个局部 lambda，不会跨线程或异步边界使用
- **但风险在于**：如果未来被传递到异步上下文，会成为 UAF

**影响**: 当前低风险，但代码维护隐患

**建议**: 改为 `[self = shared_from_this()]` 以防万一

---

#### 8. control_channel_actor.cpp - std::visit Lambda

**位置**: src/client/control_channel_actor.cpp:115

**代码**:
```cpp
co_await std::visit([this, &log](auto&& m) -> asio::awaitable<void> {
    using T = std::decay_t<decltype(m)>;
    // ...
}, msg);
```

**问题**:
- 在协程内部使用 `[this]`
- 由于是 `co_await` 同步等待，理论上安全
- **但多线程下仍有风险**：外层协程被取消时

**影响**: 中等风险

**建议**: 改为捕获外层的 `self`

---

#### 9. p2p_manager_actor.cpp - async_send_to 回调

**位置**: src/client/p2p_manager_actor.cpp:658

**代码**:
```cpp
socket_.async_send_to(
    asio::buffer(encrypted_data),
    to,
    [this, to](const boost::system::error_code& ec, std::size_t /*bytes_sent*/) {
        if (ec) {
            log().error("P2P send failed to {}: {}", to.address().to_string(), ec.message());
        }
    }
);
```

**问题**:
- P2PManagerActor 析构后，回调可能被触发

**影响**: 日志访问 UAF

**修复**: `[self = shared_from_this(), to]`

---

#### 10. tun_device_actor.cpp - 内部协程

**位置**: src/client/tun_device_actor.cpp:249

**代码**:
```cpp
asio::co_spawn(
    ioc_,
    [this]() -> asio::awaitable<void> {
        co_await read_loop();
    },
    asio::detached
);
```

**问题**: 同类型的 detached 协程 UAF

**修复**: `[self = shared_from_this()]`

---

## 根本原因分析

### 1. 多线程环境放大了问题

在单线程模式下，这些问题较少触发，因为：
- `ioc.run()` 顺序执行所有操作
- 析构通常在所有操作完成后

**多线程模式下**：
- 多个线程并发执行协程
- `ioc.stop()` 强制终止时，协程可能在任意状态
- 对象可能在一个线程析构，协程在另一个线程访问

### 2. `enable_shared_from_this` 未正确使用

虽然很多类继承了 `enable_shared_from_this`，但代码中大量使用 `[this]` 而不是 `[self = shared_from_this()]`。

### 3. TunDevice 不是 shared_ptr 管理

**关键问题**：
```cpp
// src/client/client.hpp:293
std::unique_ptr<TunDevice> tun_;
```

`TunDevice` 使用 `unique_ptr`，无法使用 `shared_from_this()`。这导致：
- Windows 线程无法安全捕获
- Linux/macOS 异步回调无法安全捕获

**需要重构为**：
```cpp
std::shared_ptr<TunDevice> tun_;
```

## 修复优先级

### P0 (立即修复 - 已知崩溃)
1. ✅ client.cpp:692, 1610 - 已在前一个 commit 修复
2. ❌ client_actor.cpp:371-389 - 5 个协程
3. ❌ ipc_server.cpp:367
4. ❌ tun_windows.cpp:193, 302 - **最危险**

### P1 (高优先级 - 潜在崩溃)
5. ❌ tun.cpp:243
6. ❌ tun_macos.cpp:230
7. ❌ p2p_manager_actor.cpp:658
8. ❌ tun_device_actor.cpp:249

### P2 (中优先级 - 防御性修复)
9. ❌ control_channel_actor.cpp:115
10. ❌ p2p_manager.cpp:72

## 修复计划

### 阶段 1: 立即修复已知 UAF (本 commit)
- client_actor.cpp - 5 个协程
- ipc_server.cpp - 1 个协程

### 阶段 2: TunDevice 重构为 shared_ptr (下一个 commit)
- 修改 `Client::tun_` 为 `shared_ptr`
- TunDevice 继承 `enable_shared_from_this`
- 修复所有 TUN 相关的 UAF

### 阶段 3: 其他组件修复
- P2PManagerActor 异步回调
- 其他防御性修复

## 测试验证

### 必须测试的场景
1. **多线程高负载**:
   ```bash
   edgelink-client up --threads 4 --config test.toml
   # 持续大流量 TUN 数据包传输
   ```

2. **快速停止/重启**:
   ```bash
   for i in {1..100}; do
       systemctl start edgelink-client
       sleep 1
       systemctl stop edgelink-client
   done
   ```

3. **强制超时停止**:
   - 让优雅停止超时（>5 秒），触发 `ioc.stop()`

4. **内存检查**:
   ```bash
   valgrind --leak-check=full --track-origins=yes edgelink-client up --config test.toml
   # 或使用 AddressSanitizer
   cmake -DCMAKE_CXX_FLAGS="-fsanitize=address" ...
   ```

### 预期结果
- 无 SEGFAULT (signal 11)
- 无内存泄漏
- 无 data race (TSan)
- 优雅停止 < 5 秒

## 相关文档
- docs/graceful_shutdown.md - 优雅停止机制
- docs/thread_model.md - 多线程架构
- 前一个 commit: 7c40156 - Fix SEGFAULT in detached coroutines

## 结论

在多线程模式下，**11 个严重的内存安全问题**需要修复。其中：
- **2 个已修复** (client.cpp)
- **9 个待修复** (本审计发现)

最危险的是 **tun_windows.cpp 的线程 UAF**，因为它涉及跨线程的生命周期问题，且 `TunDevice` 不是 shared_ptr 管理。

**行动项**：
1. 立即修复 P0 问题（本 commit）
2. 重构 TunDevice 为 shared_ptr（下一个 commit）
3. 完整的 AddressSanitizer 测试（QA 阶段）

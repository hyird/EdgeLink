# EdgeLink 优雅停止机制

## 概述

EdgeLink 客户端实现了完善的优雅停止（Graceful Shutdown）机制，确保在收到 SIGTERM/SIGINT 信号时能够正确清理资源并在合理时间内退出，避免 systemctl 停止服务时卡住。

## 停止流程

### 1. 信号处理（main.cpp:1066-1084）

```cpp
asio::signal_set signals(ioc, SIGINT, SIGTERM);
signals.async_wait([&](const boost::system::error_code&, int sig) {
    log.info("Received signal {}, shutting down gracefully...", sig);

    // Step 1: 重置 work_guard，允许 io_context 在无工作时退出
    work_guard.reset();

    // Step 2: 启动优雅停止协程
    asio::co_spawn(ioc, client->stop(), asio::detached);

    // Step 3: 设置超时保护（5 秒）
    auto shutdown_timer = std::make_shared<asio::steady_timer>(ioc);
    shutdown_timer->expires_after(std::chrono::seconds(5));
    shutdown_timer->async_wait([&ioc, &log, shutdown_timer](const boost::system::error_code& ec) {
        if (!ec) {
            log.warn("Graceful shutdown timeout, forcing io_context stop");
            ioc.stop();  // 强制停止所有 io_context 操作
        }
    });
});
```

**关键点**：
- **work_guard.reset()**: 允许 io_context 在所有挂起操作完成后自然退出
- **超时保护**: 如果 5 秒内未完成优雅停止，强制调用 `ioc.stop()` 终止所有操作
- **多线程退出**: 所有工作线程都会在 `ioc.run()` 返回后自动 join

### 2. Client 停止流程（client.cpp:870-918）

```cpp
asio::awaitable<void> Client::stop() {
    log().info("Stopping client...");

    // 1. 取消所有定时器
    log().debug("Cancelling timers...");
    keepalive_timer_.cancel();
    reconnect_timer_.cancel();
    dns_refresh_timer_.cancel();
    latency_timer_.cancel();
    route_announce_timer_.cancel();

    // 2. 停止 P2P 管理器
    if (p2p_mgr_) {
        log().debug("Stopping P2P manager...");
        co_await p2p_mgr_->stop();
        log().debug("P2P manager stopped");
    }

    // 3. 停止路由管理器（移除系统路由）
    if (route_mgr_) {
        log().debug("Stopping route manager...");
        route_mgr_->stop();
        route_mgr_.reset();
        log().debug("Route manager stopped");
    }

    // 4. 关闭 TUN 设备
    log().debug("Tearing down TUN device...");
    teardown_tun();
    log().debug("TUN device torn down");

    // 5. 关闭 Relay 通道（有 3 秒超时保护）
    if (relay_) {
        log().debug("Closing relay channel...");
        co_await relay_->close();
        log().debug("Relay channel closed");
    }

    // 6. 关闭 Control 通道（有 3 秒超时保护）
    if (control_) {
        log().debug("Closing control channel...");
        co_await control_->close();
        log().debug("Control channel closed");
    }

    state_ = ClientState::STOPPED;
    log().info("Client stopped successfully");

    if (events_.disconnected) {
        events_.disconnected->try_send(boost::system::error_code{});
    }
}
```

**关键组件停止顺序**：
1. **定时器** - 立即取消，无阻塞
2. **P2P 管理器** - 取消定时器、关闭 UDP socket、清理上下文
3. **路由管理器** - 移除系统路由（Windows/Linux/macOS）
4. **TUN 设备** - 关闭虚拟网卡
5. **Relay 通道** - WebSocket 优雅关闭（3 秒超时）
6. **Control 通道** - WebSocket 优雅关闭（3 秒超时）

### 3. WebSocket 优雅关闭（channel.cpp:379-431, 983-1035）

每个 WebSocket 连接的关闭都有 **3 秒超时保护**：

```cpp
asio::awaitable<void> ControlChannel::close() {
    if (state_ == ChannelState::DISCONNECTED) {
        co_return;
    }

    state_ = ChannelState::DISCONNECTED;

    try {
        asio::steady_timer timeout_timer(ioc_);
        timeout_timer.expires_after(std::chrono::seconds(3));

        bool closed = false;

        if (use_tls_ && tls_ws_ && tls_ws_->is_open()) {
            // 尝试优雅关闭，但有超时保护
            auto result = co_await (
                tls_ws_->async_close(websocket::close_code::normal, asio::use_awaitable)
                || timeout_timer.async_wait(asio::use_awaitable)
            );

            if (result.index() == 0) {
                closed = true;
            } else {
                log().warn("Control channel close timeout, forcing close");
            }
        }

        // 如果超时或失败，强制关闭底层 socket
        if (!closed) {
            boost::system::error_code ec;
            if (use_tls_ && tls_ws_) {
                tls_ws_->next_layer().next_layer().close(ec);
            } else if (ws_) {
                ws_->next_layer().close(ec);
            }
        }

    } catch (const std::exception& e) {
        log().error("Control channel close error: {}", e.what());
    }

    log().info("Control channel closed");
}
```

**关键点**：
- 使用 `operator||` 实现超时竞争
- 超时后强制关闭底层 TCP socket
- 异常安全：捕获所有异常，确保清理完成

## 超时配置

| 组件 | 超时时间 | 说明 |
|------|---------|------|
| WebSocket 关闭 | 3 秒 | ControlChannel, RelayChannel |
| 整体优雅停止 | 5 秒 | 主信号处理器的强制超时 |
| systemd TimeoutStopSec | 默认 90 秒 | systemd 等待时间 |

**计算**：
- WebSocket 关闭: 最多 3 秒 × 2 = 6 秒（Control + Relay）
- 其他清理: < 1 秒（定时器取消、socket 关闭）
- **总优雅停止时间**: < 5 秒（在超时保护内）

## systemd 集成

### 示例 Service 文件

```ini
[Unit]
Description=EdgeLink VPN Client
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/edgelink-client up --config /etc/edgelink/client.toml
Restart=on-failure
RestartSec=5s

# 优雅停止配置
KillMode=mixed
KillSignal=SIGTERM
TimeoutStopSec=10s
SendSIGKILL=yes

# 日志配置
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

**配置说明**：
- `KillMode=mixed`: 先向主进程发送 SIGTERM，然后向子进程发送 SIGKILL
- `KillSignal=SIGTERM`: 使用 SIGTERM 作为停止信号（触发优雅停止）
- `TimeoutStopSec=10s`: 10 秒超时（略大于客户端的 5 秒超时）
- `SendSIGKILL=yes`: 超时后发送 SIGKILL 强制终止

### 测试优雅停止

```bash
# 启动服务
sudo systemctl start edgelink-client

# 测试优雅停止（应该 < 5 秒完成）
sudo systemctl stop edgelink-client

# 查看停止日志
sudo journalctl -u edgelink-client -n 50

# 预期日志输出：
# [info] Received signal 15, shutting down gracefully...
# [debug] Cancelling timers...
# [debug] Stopping P2P manager...
# [debug] P2P manager stopped
# [debug] Stopping route manager...
# [debug] Route manager stopped
# [debug] Tearing down TUN device...
# [debug] TUN device torn down
# [debug] Closing relay channel...
# [debug] Relay channel closed
# [debug] Closing control channel...
# [debug] Control channel closed
# [info] Client stopped successfully
```

## 故障排查

### 问题：停止仍然超时

**可能原因**：
1. 某个协程卡在非 Asio 操作上（如阻塞的系统调用）
2. Channel 队列满导致无法发送关闭消息
3. 底层 socket 异常未被捕获

**诊断方法**：
1. 检查日志，找到最后一条 "debug" 日志，确定卡在哪个步骤
2. 使用 `strace -p <pid>` 查看进程在等待什么系统调用
3. 检查 TUN 设备是否正常关闭（`ip link show`）

**解决方法**：
- 如果超过 5 秒，超时保护会强制调用 `ioc.stop()`
- 如果超过 10 秒（systemd 超时），会收到 SIGKILL 强制终止
- 确保所有异步操作都使用 Asio 原语，避免阻塞系统调用

### 问题：日志显示 "Graceful shutdown timeout"

**含义**：
- 优雅停止超过 5 秒，触发了强制超时保护
- `ioc.stop()` 已被调用，所有协程会被取消

**处理**：
- 检查是否有组件（P2P, Relay, Control）的停止日志缺失
- 检查 WebSocket 关闭是否超时（应该有 "close timeout" 警告）
- 这是正常的保护机制，确保进程不会无限期挂起

## 多线程优雅停止

在多线程模式下（`num_threads > 1`），优雅停止流程：

1. **信号处理器**（在某个工作线程中触发）
   - 重置 work_guard
   - 启动 stop() 协程
   - 设置超时定时器

2. **stop() 协程**（可能在任意工作线程中执行）
   - 执行清理操作
   - 完成后，如果没有其他挂起操作，io_context 会停止

3. **所有工作线程退出**
   - `ioc.run()` 返回（工作完成或被 stop()）
   - 主线程 join 所有工作线程
   - 进程退出

**线程安全**：
- 所有操作通过 Asio strand 或 channel 同步
- `ioc.stop()` 是线程安全的，可以从任意线程调用
- 工作线程会在 `ioc.run()` 返回时自动退出

## 最佳实践

1. **始终使用 systemd 或类似的进程管理器**
   - 不要手动 `kill -9`，应该使用 `systemctl stop`
   - 让优雅停止机制完成清理工作

2. **设置合理的超时**
   - systemd `TimeoutStopSec` 应该略大于客户端超时（推荐 10 秒）
   - 对于高负载场景，可以增加到 15-20 秒

3. **监控日志**
   - 关注 "Graceful shutdown timeout" 警告
   - 检查所有组件是否正常停止

4. **避免在 stop() 中添加阻塞操作**
   - 所有清理操作应该是异步的或快速完成的
   - 耗时操作应该有自己的超时保护

## 相关文件

- `src/client/main.cpp:1066-1084` - 信号处理和超时保护
- `src/client/client.cpp:870-918` - Client::stop() 实现
- `src/client/channel.cpp:379-431` - ControlChannel::close()
- `src/client/channel.cpp:983-1035` - RelayChannel::close()
- `src/client/p2p_manager.cpp:115-139` - P2PManager::stop()

## 参考

- [Boost.Asio Signal Handling](https://www.boost.org/doc/libs/release/doc/html/boost_asio/reference/signal_set.html)
- [systemd Service 配置](https://www.freedesktop.org/software/systemd/man/systemd.service.html)
- [WebSocket 优雅关闭](https://datatracker.ietf.org/doc/html/rfc6455#section-7.1.1)

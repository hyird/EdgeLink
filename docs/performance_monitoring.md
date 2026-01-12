# EdgeLink 性能监控

## 概述

EdgeLink 在 Phase 5 中集成了全面的性能监控系统，用于跟踪关键性能指标和队列统计。

## 监控点

### DataPlaneActor

**计数器**:
- `DataPlane.PacketsSent` - 发送的数据包总数
- `DataPlane.BytesSent` - 发送的字节总数
- `DataPlane.PacketsViaP2P` - 通过 P2P 发送的数据包数
- `DataPlane.PacketsViaRelay` - 通过 Relay 发送的数据包数
- `DataPlane.NoPathErrors` - 无可用路径错误次数
- `DataPlane.SendErrors` - 发送错误次数

**延迟统计**:
- `DataPlane.SendPacket` - 数据包发送延迟 (微秒)

**队列统计**:
- `DataPlane.Mailbox` - Actor 邮箱队列 (容量 64)

### TunDeviceActor

**计数器**:
- `TunDevice.PacketsRead` - 从 TUN 设备读取的数据包数
- `TunDevice.BytesRead` - 从 TUN 设备读取的字节数
- `TunDevice.PacketsWritten` - 写入 TUN 设备的数据包数
- `TunDevice.BytesWritten` - 写入 TUN 设备的字节数
- `TunDevice.ReadErrors` - TUN 读取错误次数
- `TunDevice.WriteErrors` - TUN 写入错误次数

**延迟统计**:
- `TunDevice.WritePacket` - 数据包写入延迟 (微秒)

**队列统计**:
- `TunDevice.Mailbox` - Actor 邮箱队列 (容量 64)
- `TunDevice.PacketQueue` - 数据包接收队列 (容量 128)

### P2PManagerActor

**计数器**:
- `P2P.PacketsSent` - 通过 P2P 发送的数据包数
- `P2P.BytesSent` - 通过 P2P 发送的字节数
- `P2P.PacketsReceived` - 通过 P2P 接收的数据包数
- `P2P.BytesReceived` - 通过 P2P 接收的字节数
- `P2P.ConnectionsEstablished` - 成功建立的 P2P 连接数
- `P2P.SendNotConnected` - 发送时未连接的次数
- `P2P.EncryptErrors` - 加密错误次数
- `P2P.SendErrors` - 发送错误次数
- `P2P.RecvErrors` - 接收错误次数

**延迟统计**:
- `P2P.SendData` - P2P 数据发送延迟 (微秒)

**队列统计**:
- `P2PManager.Mailbox` - Actor 邮箱队列 (容量 128)

## 使用方法

### 1. 自动监控输出

客户端每 60 秒自动打印一次性能摘要到日志：

```
[2026-01-12 12:00:00] [client] [info]
=== EdgeLink Performance Summary ===

Counters:
  DataPlane.PacketsSent                     : 1234
  DataPlane.BytesSent                       : 1048576
  TunDevice.PacketsRead                     : 1234
  P2P.ConnectionsEstablished                : 2

Latencies (microseconds):
  Name                                      Count        Min        Avg        Max
  ----------------------------------------------------------------------------------
  DataPlane.SendPacket                       1234         10         25        150
  TunDevice.WritePacket                      1234         15         30        200
  P2P.SendData                                500          5         12         80

Queue Stats:
  Name                          Capacity   Current   Usage%    Enqueued    Dequeued      Drops  HWM Hits
  -----------------------------------------------------------------------------------------------------
  DataPlane.Mailbox                   64        12     18.8%        1234        1222          0         0
  TunDevice.PacketQueue              128        45     35.2%        1234        1189          0         0
  P2PManager.Mailbox                 128         8      6.2%         567         559          0         0

====================================
```

### 2. 手动查询（编程接口）

```cpp
#include "common/performance_monitor.hpp"

using namespace edgelink::perf;

// 获取单个计数器值
auto packets_sent = PerformanceMonitor::instance().counter("DataPlane.PacketsSent").get();

// 获取延迟统计
auto& latency = PerformanceMonitor::instance().latency("DataPlane.SendPacket");
std::cout << "Min: " << latency.min_us() << " us\n";
std::cout << "Avg: " << latency.avg_us() << " us\n";
std::cout << "Max: " << latency.max_us() << " us\n";

// 获取队列统计
auto* queue = PerformanceMonitor::instance().get_queue("DataPlane.Mailbox");
if (queue) {
    std::cout << "Queue usage: " << (queue->usage_ratio() * 100) << "%\n";
    std::cout << "Drops: " << queue->drops.load() << "\n";
}

// 获取完整摘要
auto summary = PerformanceMonitor::instance().get_summary();
std::cout << summary << "\n";

// 重置所有统计
PerformanceMonitor::instance().reset_all();
```

### 3. 添加自定义监控点

```cpp
#include "common/performance_monitor.hpp"

// 计数器
PERF_INCREMENT("MyComponent.Events");
PERF_ADD("MyComponent.BytesProcessed", 1024);

// 延迟测量（RAII）
{
    PERF_MEASURE_LATENCY("MyComponent.ProcessData");
    // 你的代码...
} // 离开作用域时自动记录延迟

// 队列统计（在 Actor 的 on_start 中注册）
perf::PerformanceMonitor::instance().register_queue("MyComponent.Mailbox", 64);

// 在队列操作时更新统计
auto* stats = perf::PerformanceMonitor::instance().get_queue("MyComponent.Mailbox");
if (stats) {
    stats->on_enqueue();  // 入队时调用
    stats->on_dequeue();  // 出队时调用
    stats->on_drop();     // 丢弃时调用
}
```

## 性能影响

- **计数器**: 使用 `std::atomic` with `memory_order_relaxed`，开销极小（~1-2 纳秒）
- **延迟测量**: 使用 `std::chrono::steady_clock`，开销约 20-50 纳秒
- **队列统计**: 无锁原子操作，开销极小

总体性能影响 < 1%，可安全在生产环境中启用。

## 配置参数

性能参数在 `src/common/performance_config.hpp` 中集中配置：

```cpp
struct ChannelCapacity {
    static constexpr size_t CLIENT_CONTROL_EVENT = 128;
    static constexpr size_t CLIENT_DATA_PLANE_EVENT = 256;  // 高优先级
    static constexpr size_t CLIENT_TUN_EVENT = 256;         // 高吞吐
    static constexpr size_t DATA_TUN_PACKET = 512;          // 最大吞吐
};

struct BackpressureConfig {
    static constexpr float HIGH_WATERMARK = 0.75f;  // 75% 触发警告
    static constexpr float LOW_WATERMARK = 0.25f;   // 25% 恢复正常
};
```

## 故障排查

### 高队列使用率 (> 75%)

- **原因**: 生产速度超过消费速度
- **解决**: 增加队列容量或优化消费者性能

### 频繁丢包 (Drops > 0)

- **原因**: 队列满且使用 DROP_OLDEST 策略
- **解决**: 增加队列容量或使用背压控制

### 高延迟 (> 1ms)

- **原因**: 过载、锁竞争或 I/O 阻塞
- **解决**: 检查日志、优化热路径、使用性能分析工具

## 未来改进

Phase 5 已完成的优化：
- ✅ 集中化性能配置
- ✅ 无锁性能监控框架
- ✅ 关键路径监控点
- ✅ 队列容量优化

后续可考虑的改进：
- 批量发送优化（配置已定义，实现待完成）
- Prometheus 导出器
- 自适应队列容量
- 热点函数 CPU 性能分析

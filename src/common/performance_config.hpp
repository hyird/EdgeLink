// EdgeLink 性能配置
// 定义所有 Channel 容量和性能参数

#pragma once

#include <cstddef>
#include <chrono>

namespace edgelink::perf {

// ============================================================================
// Channel 容量配置
// ============================================================================

struct ChannelCapacity {
    // Client 端 Actor 事件通道
    static constexpr size_t CLIENT_CONTROL_EVENT = 128;      // 控制事件（优化：64 -> 128）
    static constexpr size_t CLIENT_RELAY_EVENT = 128;        // 中继事件（优化：64 -> 128）
    static constexpr size_t CLIENT_DATA_PLANE_EVENT = 256;   // 数据面事件（优化：64 -> 256，高优先级）
    static constexpr size_t CLIENT_P2P_EVENT = 128;          // P2P 事件（优化：64 -> 128）
    static constexpr size_t CLIENT_TUN_EVENT = 256;          // TUN 事件（优化：128 -> 256，高吞吐）

    // Actor 命令通道（ActorBase 内部）
    static constexpr size_t ACTOR_COMMAND = 128;             // 通用 Actor 命令队列

    // 数据通道（高吞吐路径）
    static constexpr size_t DATA_RELAY = 256;                // 中继数据（优化：64 -> 256）
    static constexpr size_t DATA_P2P = 256;                  // P2P 数据（优化：64 -> 256）
    static constexpr size_t DATA_TUN_PACKET = 512;           // TUN 数据包（优化：128 -> 512，最大吞吐）

    // 控制消息通道（低频）
    static constexpr size_t CONTROL_AUTH = 8;                // 认证（4 -> 8）
    static constexpr size_t CONTROL_CONFIG = 8;              // 配置（4 -> 8）
    static constexpr size_t CONTROL_ROUTE = 32;              // 路由更新（16 -> 32）
    static constexpr size_t CONTROL_P2P_ENDPOINT = 64;       // P2P 端点（32 -> 64）
    static constexpr size_t CONTROL_ERROR = 16;              // 错误（8 -> 16）
    static constexpr size_t CONTROL_STATUS = 8;              // 状态（4 -> 8）

    // Controller 端
    static constexpr size_t SESSION_WRITE = 2048;            // Session 写队列（优化：1024 -> 2048）
    static constexpr size_t SESSION_MANAGER_EVENT = 128;     // SessionManager 事件
    static constexpr size_t SERVER_CLIENT_EVENT = 128;       // 客户端事件（64 -> 128）

    // STUN
    static constexpr size_t STUN_RESPONSE = 32;              // STUN 响应（16 -> 32）
};

// ============================================================================
// 超时配置
// ============================================================================

struct Timeouts {
    // 连接超时
    static constexpr auto CONNECT_TIMEOUT = std::chrono::seconds(10);
    static constexpr auto AUTH_TIMEOUT = std::chrono::seconds(15);
    static constexpr auto WEBSOCKET_HANDSHAKE = std::chrono::seconds(10);

    // 心跳超时
    static constexpr auto PING_INTERVAL = std::chrono::seconds(30);
    static constexpr auto PING_TIMEOUT = std::chrono::seconds(60);
    static constexpr auto SESSION_IDLE_TIMEOUT = std::chrono::seconds(120);

    // P2P 超时
    static constexpr auto P2P_PUNCH_TIMEOUT = std::chrono::seconds(10);
    static constexpr auto P2P_KEEPALIVE_INTERVAL = std::chrono::seconds(15);
    static constexpr auto P2P_KEEPALIVE_TIMEOUT = std::chrono::seconds(45);

    // 重试间隔
    static constexpr auto RECONNECT_MIN_INTERVAL = std::chrono::seconds(1);
    static constexpr auto RECONNECT_MAX_INTERVAL = std::chrono::seconds(60);
    static constexpr auto STUN_RETRY_INTERVAL = std::chrono::milliseconds(500);
};

// ============================================================================
// 批量发送配置
// ============================================================================

struct BatchConfig {
    // 批量大小
    static constexpr size_t RELAY_WRITE_BATCH = 16;          // Relay 批量写入数量
    static constexpr size_t P2P_WRITE_BATCH = 16;            // P2P 批量写入数量
    static constexpr size_t TUN_WRITE_BATCH = 32;            // TUN 批量写入数量

    // 批量等待时间（避免过度延迟）
    static constexpr auto MAX_BATCH_WAIT = std::chrono::microseconds(100);

    // 批量大小阈值（字节）
    static constexpr size_t MAX_BATCH_BYTES = 65536;         // 64KB
};

// ============================================================================
// 背压控制配置
// ============================================================================

struct BackpressureConfig {
    // 队列满时的策略
    enum class DropPolicy {
        BLOCK,          // 阻塞（等待队列有空间）
        DROP_OLDEST,    // 丢弃最旧的消息
        DROP_NEWEST,    // 丢弃最新的消息（当前消息）
        DROP_LOWEST_PRIORITY, // 丢弃优先级最低的消息
    };

    // 数据通道使用 DROP_OLDEST（避免积压旧数据）
    static constexpr DropPolicy DATA_CHANNEL_POLICY = DropPolicy::DROP_OLDEST;

    // 控制通道使用 BLOCK（确保可靠传递）
    static constexpr DropPolicy CONTROL_CHANNEL_POLICY = DropPolicy::BLOCK;

    // 高水位标记（触发背压警告）
    static constexpr float HIGH_WATERMARK = 0.75f;  // 75% 满时触发警告
    static constexpr float LOW_WATERMARK = 0.25f;   // 25% 满时恢复
};

// ============================================================================
// 性能监控配置
// ============================================================================

struct MonitoringConfig {
    // 统计间隔
    static constexpr auto STATS_INTERVAL = std::chrono::seconds(60);

    // 性能指标采样
    static constexpr size_t LATENCY_SAMPLES = 1000;          // 延迟采样数量
    static constexpr bool ENABLE_DETAILED_STATS = true;      // 启用详细统计

    // 日志级别阈值
    static constexpr auto SLOW_OPERATION_THRESHOLD = std::chrono::milliseconds(100);
    static constexpr size_t CHANNEL_FULL_LOG_THRESHOLD = 10; // 队列满事件日志阈值
};

// ============================================================================
// 零拷贝配置
// ============================================================================

struct ZeroCopyConfig {
    // 使用 shared_ptr 传递的最小数据大小
    static constexpr size_t MIN_SHARED_PTR_SIZE = 1024;      // 1KB 以上使用 shared_ptr

    // 内存池配置
    static constexpr size_t BUFFER_POOL_SIZE = 512;          // 缓冲池大小
    static constexpr size_t BUFFER_SIZE_SMALL = 2048;        // 2KB
    static constexpr size_t BUFFER_SIZE_MEDIUM = 4096;       // 4KB
    static constexpr size_t BUFFER_SIZE_LARGE = 8192;        // 8KB
};

// ============================================================================
// 工具函数
// ============================================================================

// 检查队列是否达到高水位
inline bool is_high_watermark(size_t current, size_t capacity) {
    return current >= capacity * BackpressureConfig::HIGH_WATERMARK;
}

// 检查队列是否低于低水位
inline bool is_low_watermark(size_t current, size_t capacity) {
    return current <= capacity * BackpressureConfig::LOW_WATERMARK;
}

// 计算队列使用率
inline float queue_usage_ratio(size_t current, size_t capacity) {
    return capacity > 0 ? static_cast<float>(current) / capacity : 0.0f;
}

} // namespace edgelink::perf

#pragma once

#include "client/multi_relay_manager.hpp"
#include "common/types.hpp"
#include "common/message.hpp"
#include "client/peer_manager.hpp"
#include <memory>
#include <map>
#include <shared_mutex>
#include <chrono>
#include <boost/cobalt.hpp>
#include <boost/cobalt/channel.hpp>

namespace cobalt = boost::cobalt;

namespace edgelink::client {

// 延迟测量配置
struct LatencyMeasureConfig {
    std::chrono::seconds measure_interval{30};      // 测量间隔
    std::chrono::seconds report_interval{60};       // 上报间隔
    uint32_t ping_timeout_ms = 5000;                // PING 超时
    uint32_t samples_per_measurement = 3;           // 每次测量发送的 PING 数
};

// 单条延迟测量数据
struct LatencyMeasurement {
    NodeId peer_node_id = 0;
    ServerId relay_id = 0;
    ConnectionId connection_id = 0;
    uint16_t latency_ms = 0;
    uint8_t packet_loss = 0;
    uint64_t last_update = 0;
    uint32_t sample_count = 0;
};

// ============================================================================
// PeerLatencyMeasurer - 测量 Client 间延迟
// ============================================================================

class PeerLatencyMeasurer : public std::enable_shared_from_this<PeerLatencyMeasurer> {
public:
    using ReportCallback = std::function<void(const PeerPathReport&)>;

    PeerLatencyMeasurer(asio::io_context& ioc,
                        MultiRelayManager& relay_mgr,
                        PeerManager& peers,
                        const LatencyMeasureConfig& config);

    // 启动测量循环
    cobalt::task<void> start();

    // 停止测量 (异步等待循环退出)
    cobalt::task<void> stop();

    // 设置上报回调（用于发送 PEER_PATH_REPORT）
    void set_report_callback(ReportCallback callback);

    // 获取最新的测量报告
    PeerPathReport get_report() const;

    // 获取到指定 Peer 经过指定 Relay 的延迟
    std::optional<uint16_t> get_latency(NodeId peer_id, ServerId relay_id) const;

    // 记录收到的 PONG 响应（用于 RTT 计算）
    // seq: 从 PONG 消息中提取的序列号（包含 relay_id 编码）
    // send_time: 从 PONG 消息中提取的发送时间戳
    void record_pong(NodeId peer_id, uint32_t seq, uint64_t send_time);

    // 是否正在运行
    bool is_running() const { return running_; }

private:
    // 测量循环
    cobalt::task<void> measure_loop();

    // 上报循环
    cobalt::task<void> report_loop();

    // 测量所有 (peer, relay) 组合
    cobalt::task<void> measure_all_paths();

    // 测量单条路径
    cobalt::task<uint16_t> measure_single_path(
        NodeId peer_id,
        std::shared_ptr<RelayConnectionPool> relay_pool);

    // 更新延迟数据
    void update_latency(NodeId peer_id, ServerId relay_id,
                        ConnectionId conn_id, uint16_t latency_ms);

    asio::io_context& ioc_;
    MultiRelayManager& relay_mgr_;
    PeerManager& peers_;
    LatencyMeasureConfig config_;

    // 延迟数据（key = (peer_id, relay_id)）
    mutable std::shared_mutex mutex_;
    std::map<std::pair<NodeId, ServerId>, LatencyMeasurement> measurements_;

    // 上报回调
    ReportCallback report_callback_;

    // 运行状态
    bool running_ = false;
    std::unique_ptr<asio::steady_timer> measure_timer_;
    std::unique_ptr<asio::steady_timer> report_timer_;

    // 循环完成通知 (用于同步 stop)
    using CompletionChannel = cobalt::channel<void>;
    std::unique_ptr<CompletionChannel> measure_done_ch_;
    std::unique_ptr<CompletionChannel> report_done_ch_;

    // PING 追踪（用于计算 RTT）
    struct PendingPing {
        NodeId peer_id;
        ServerId relay_id;
        ConnectionId connection_id;
        uint64_t send_time;
    };
    mutable std::mutex ping_mutex_;
    std::unordered_map<uint32_t, PendingPing> pending_pings_;  // seq -> info
    uint32_t ping_seq_ = 0;
};

} // namespace edgelink::client

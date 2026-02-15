#pragma once

#include "client/relay_pool.hpp"
#include "client/peer_routing_table.hpp"
#include "common/types.hpp"
#include "common/message.hpp"
#include "common/crypto.hpp"
#include "client/peer_manager.hpp"
#include <memory>
#include <unordered_map>
#include <shared_mutex>
#include <chrono>
#include <boost/cobalt.hpp>

namespace cobalt = boost::cobalt;

namespace edgelink::client {

// 多 Relay 管理配置
struct MultiRelayConfig {
    bool enabled = true;
    uint32_t max_connections_per_relay = 3;         // 每个 Relay 最大连接数
    std::chrono::seconds rtt_measure_interval{5};   // RTT 测量间隔
    std::chrono::seconds metrics_report_interval{30}; // 指标上报间隔
    uint16_t rtt_switch_threshold_ms = 30;          // RTT 切换阈值
};

// ============================================================================
// MultiRelayManager - 管理所有 Relay 连接
// ============================================================================

class MultiRelayManager : public std::enable_shared_from_this<MultiRelayManager> {
public:
    MultiRelayManager(asio::io_context& ioc, ssl::context& ssl_ctx,
                      CryptoEngine& crypto, PeerManager& peers,
                      const MultiRelayConfig& config);

    // 初始化所有 Relay 连接（relays 来自 CONFIG 消息）
    // controller_hostname: 控制器地址，当 relay hostname 为 "builtin" 或空时使用
    cobalt::task<bool> initialize(const std::vector<RelayInfo>& relays,
                                      const std::vector<uint8_t>& relay_token,
                                      bool use_tls,
                                      const std::string& controller_hostname);

    // 停止所有连接
    cobalt::task<void> stop();

    // 获取发送到指定 Peer 的最优连接
    std::shared_ptr<RelayChannel> get_channel_for_peer(NodeId peer_id);

    // 获取指定 Relay 的连接池
    std::shared_ptr<RelayConnectionPool> get_relay_pool(ServerId relay_id);

    // 所有 Relay 连接池
    std::vector<std::shared_ptr<RelayConnectionPool>> all_relay_pools();

    // 更新路由表（收到 PEER_ROUTING_UPDATE 时调用）
    void handle_peer_routing_update(const PeerRoutingUpdate& update);

    // 获取当前路由表
    const PeerRoutingTable& routing_table() const { return routing_table_; }
    PeerRoutingTable& routing_table() { return routing_table_; }

    // 获取所有连接的指标（用于生成 PeerPathReport）
    std::vector<std::pair<ServerId, ConnectionId>> get_all_connections() const;

    // 获取指定 Relay 的活跃连接
    std::shared_ptr<RelayChannel> get_active_relay_channel(ServerId relay_id);

    // 是否有可用连接
    bool has_available_connection() const;

    // 连接数量统计
    size_t total_connection_count() const;

    // 设置事件通道（转发给所有 Relay）
    void set_event_channel(events::RelayEventChannel* ch);

private:
    // 启动 RTT 测量循环
    cobalt::task<void> rtt_measure_loop();

    asio::io_context& ioc_;
    ssl::context& ssl_ctx_;
    CryptoEngine& crypto_;
    PeerManager& peers_;
    MultiRelayConfig config_;

    // Relay 连接池管理（线程安全）
    mutable std::shared_mutex mutex_;
    std::unordered_map<ServerId, std::shared_ptr<RelayConnectionPool>> relay_pools_;

    // Peer 路由表
    PeerRoutingTable routing_table_;

    // 事件通道
    events::RelayEventChannel* event_ch_ = nullptr;

    // 运行状态
    bool running_ = false;
    std::unique_ptr<asio::steady_timer> rtt_timer_;

    // RTT 循环完成通知 (用于同步 stop)
    using CompletionChannel = cobalt::channel<void>;
    std::unique_ptr<CompletionChannel> rtt_loop_done_ch_;
};

} // namespace edgelink::client
